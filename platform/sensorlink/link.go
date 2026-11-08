package sensorlink

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"time"

	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/event"
	"otsec.local/otsec/contracts/netobs"
	"otsec.local/otsec/contracts/node"
	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/modules/detection/netdetect"
)

// Config is what the node's network_sensor section and layout give the
// link.
type Config struct {
	NodeID        node.ID
	SensorID      string
	EvidenceClass asset.EvidenceClass
	OutageHours   int
	// ObservationQuota is store.quotas.network-observation, the Q of the
	// unresolved budget.
	ObservationQuota int64
	// Stream is the sensor's network-observation stream.
	Stream c5.StreamID
}

// Appender commits records to the observation stream: the node's c5.Log
// for the network database, and the stream's last committed seq.
type Appender interface {
	Append(ctx context.Context, rec c5.Record) (c5.Receipt, error)
	AppendBatch(ctx context.Context, recs []c5.Record) ([]c5.Receipt, error)
	LastCommitted(ctx context.Context) (uint64, error)
}

// Options are the link's seams.
type Options struct {
	// Assets are the node's C1 records, for the resolver.
	Assets []asset.Asset
	Store  Appender
	// Monotonic is the node's monotonic clock, which runs the unresolved
	// budget. The test clock replaces it.
	Monotonic func() time.Duration
	// Received is the node's received time for a C4 event.
	Received func() event.Received
	// Hold is the intake hold (hold.go). With no node addresses nothing
	// is held.
	Hold HoldConfig
}

// Reasons a record is refused (sensor-record-refused), beside the C13
// validation code of a record that fails C13's own checks.
const (
	RefusedSensorID        = "sensor-id"        // another sensor's ID
	RefusedSeq             = "seq"              // a seq at or below the run's last
	RefusedCounterDecrease = "counter-decrease" // a heartbeat counter below the run's last (C13 section 6)
	RefusedStored          = "stored"           // the stored form failed C13 or C4's bounds
)

// Reasons an accepted observation is dropped before it is stored. Each
// dropped observation is counted under exactly one (docs/phase4/D5-c5-0.9.md
// section 4).
const (
	DropUnresolvedBudget = "unresolved-budget" // the node's refusal, before the store
	DropClassFull        = "class-full"        // the store's CodeQuotaReached
	DropRecordCap        = "record-cap"        // the store's CodeRecordTooLarge
	DropStore            = "store"             // any other store refusal, such as drain-only
)

// Stats are the link's counts since it was made.
type Stats struct {
	// RunID is the sensor run the link is reading, and LastSeq the last
	// seq it took in that run.
	RunID   string
	LastSeq uint64
	// RunChanges counts the times the run changed after the first run the
	// link read. Each resets the seq and heartbeat checks, so a sensor that
	// rotates its run_id shows here (D3 on #553).
	RunChanges uint64
	// LastCommittedSeq is the last seq of the run whose observation is
	// committed, so a restart shows where it resumes (D1 on #542).
	LastCommittedSeq uint64
	// SeqGaps counts the seqs never received: losses on the channel.
	SeqGaps uint64
	// FramesTooLarge counts frames above MaxChannelFrame, each of which
	// closed the channel.
	FramesTooLarge uint64
	Committed      uint64
	Refused        map[string]uint64
	Dropped        map[string]uint64
	// DroppedByAsset counts the same dropped observations by destination
	// asset, with one bucket, netobs.AssetUnresolved, for every unresolved
	// destination, so a flood that mimics a known pair shows against the
	// asset it starves (baseline note section 8). Its keys are the node's
	// own asset IDs, so it is bounded by the enrolled assets plus one.
	DroppedByAsset map[string]uint64
	// Heartbeat is the last heartbeat accepted in the run, or nil.
	Heartbeat *netobs.Heartbeat
	// Hold is the intake hold's counts.
	Hold HoldStats
}

// Link reads one sensor's channel.
type Link struct {
	cfg      Config
	opt      Options
	resolver *Resolver

	// cmu orders every commit to the stream with the hold's changes, so a
	// release's batch and its saved state agree with what came before and
	// after it. It is taken before mu.
	cmu  sync.Mutex
	hold *hold

	mu     sync.Mutex
	stats  Stats
	budget *budget
}

// New makes a link. The unresolved budget starts empty (D5-c5-0.9 section 4).
func New(cfg Config, opt Options) (*Link, error) {
	switch {
	case !netobs.ValidUUID(cfg.SensorID):
		return nil, fmt.Errorf("sensorlink: sensor ID %q is not a lowercase UUID", cfg.SensorID)
	case cfg.OutageHours < 1:
		return nil, fmt.Errorf("sensorlink: outage hours %d is below 1", cfg.OutageHours)
	case cfg.ObservationQuota < 1:
		return nil, errors.New("sensorlink: no observation quota")
	case opt.Store == nil || opt.Monotonic == nil || opt.Received == nil:
		return nil, errors.New("sensorlink: Store, Monotonic and Received are required")
	}
	h, err := newHold(opt.Hold)
	if err != nil {
		return nil, err
	}
	return &Link{cfg: cfg, opt: opt, resolver: NewResolver(cfg.NodeID, opt.Assets), hold: h,
		stats:  Stats{Refused: map[string]uint64{}, Dropped: map[string]uint64{}, DroppedByAsset: map[string]uint64{}},
		budget: newBudget(cfg.ObservationQuota, cfg.OutageHours, opt.Monotonic())}, nil
}

// Stats returns a copy of the counts.
func (l *Link) Stats() Stats {
	l.mu.Lock()
	defer l.mu.Unlock()
	s := l.stats
	s.Refused, s.Dropped, s.DroppedByAsset = clone(s.Refused), clone(s.Dropped), clone(s.DroppedByAsset)
	return s
}

func clone(m map[string]uint64) map[string]uint64 {
	out := make(map[string]uint64, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// Serve reads records from r until it ends, ctx ends, or a frame is longer
// than MaxChannelFrame, which closes the channel and is counted. It returns
// nil at a clean end of the stream.
func (l *Link) Serve(ctx context.Context, r io.Reader) error {
	for ctx.Err() == nil {
		b, err := netobs.ReadFrame(r)
		switch {
		case errors.Is(err, netobs.ErrFrameTooLarge):
			l.mu.Lock()
			l.stats.FramesTooLarge++
			l.mu.Unlock()
			return err
		case err == io.EOF:
			return nil
		case err != nil:
			return err
		}
		l.handle(ctx, b)
	}
	return ctx.Err()
}

// handle checks one record and, for an observation, stores it.
func (l *Link) handle(ctx context.Context, b []byte) {
	rec, err := netobs.DecodeChannel(b)
	if rec == nil {
		l.refuse(codeOf(err))
		return
	}
	var sensor, run, seq string
	if h := rec.Heartbeat; h != nil {
		sensor, run, seq = h.SensorID, h.RunID, h.Seq
	} else {
		sensor, run, seq = rec.Observation.SensorID, rec.Observation.RunID, rec.Observation.Seq
	}
	if sensor != l.cfg.SensorID {
		l.refuse(RefusedSensorID)
		return
	}
	n, perr := strconv.ParseUint(seq, 10, 64)
	if !netobs.ValidUUID(run) || perr != nil || n == 0 {
		l.refuse(codeOf(err))
		return
	}
	// A record that decoded strictly takes its seq even when a later check
	// refuses it, so a gap counts only records the channel lost.
	ok, newRun := l.takeSeq(run, n)
	if newRun {
		l.cmu.Lock()
		l.giveWay(ctx, true)
		l.syncHold()
		l.cmu.Unlock()
	}
	if !ok {
		l.refuse(RefusedSeq)
		return
	}
	if err != nil {
		l.refuse(codeOf(err))
		return
	}
	if h := rec.Heartbeat; h != nil {
		l.mu.Lock()
		if err := h.Follows(l.stats.Heartbeat); err != nil {
			l.stats.Refused[RefusedCounterDecrease]++
			l.mu.Unlock()
			return
		}
		l.stats.Heartbeat = h
		l.mu.Unlock()
		if degraded(h.Coverage) {
			l.cmu.Lock()
			l.giveWay(ctx, false)
			l.syncHold()
			l.cmu.Unlock()
		}
		return
	}
	l.observe(ctx, rec.Observation, n)
}

// takeSeq records seq n of run, counting the seqs skipped. A new run starts
// afresh from 0. It reports false for a seq at or below the run's last, and
// whether run replaced another.
func (l *Link) takeSeq(run string, n uint64) (ok, newRun bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	s := &l.stats
	if run != s.RunID {
		if s.RunID != "" {
			s.RunChanges++
			newRun = true
		}
		s.RunID, s.LastSeq, s.LastCommittedSeq, s.Heartbeat = run, 0, 0, nil
	}
	if n <= s.LastSeq {
		return false, newRun
	}
	s.SeqGaps += n - s.LastSeq - 1
	s.LastSeq = n
	return true, newRun
}

func (l *Link) refuse(reason string) {
	l.mu.Lock()
	l.stats.Refused[reason]++
	l.mu.Unlock()
}

// drop counts a dropped observation under its reason and its destination
// asset. The caller holds l.mu.
func (l *Link) drop(reason, dstAsset string) {
	l.stats.Dropped[reason]++
	l.stats.DroppedByAsset[dstAsset]++
}

// codeOf is the reason for a C13 validation failure: its first code.
func codeOf(err error) string {
	if cs := netobs.Codes(err); len(cs) > 0 {
		return string(cs[0])
	}
	return string(netobs.CodeDecode)
}

// observe adds the node object to o, and holds it (hold.go) or commits
// it untied, or drops and counts it.
func (l *Link) observe(ctx context.Context, o *netobs.Observation, seq uint64) {
	nd, _ := l.nodeObject(o)
	var capture *c5.Capture
	if o.FirstSight {
		c, err := firstSightCapture(o)
		if err != nil {
			l.refuse(RefusedStored)
			return
		}
		capture = c
		nd.StoredCapture = c.SHA256
	}
	stored := *o
	stored.Frames, stored.Node = nil, nd
	if err := stored.ValidateStored(); err != nil {
		l.refuse(RefusedStored)
		return
	}
	body, err := json.Marshal(&stored)
	if err != nil || len(body) > event.MaxNetobsBytes {
		l.refuse(RefusedStored)
		return
	}
	hr := HeldRecord{RunID: o.RunID, Seq: seq, Observation: body, Capture: capture, Received: l.opt.Received()}
	l.cmu.Lock()
	defer l.cmu.Unlock()
	defer l.syncHold()
	if degraded(o.Coverage) {
		l.giveWay(ctx, false)
	}
	if l.takeHeld(ctx, &stored, hr) {
		return
	}
	l.commitOne(ctx, hr, nil, "")
}

// record builds hr's C4 event with tie, if any, and reports its
// destination asset and whether neither end resolved, so it draws on the
// unresolved budget (C13 section 5).
func (l *Link) record(hr HeldRecord, tie *netobs.PlatformSession) (c5.Record, string, bool, error) {
	body := hr.Observation
	var st netobs.Observation
	if err := json.Unmarshal(body, &st); err != nil || st.Node == nil {
		return c5.Record{}, "", false, fmt.Errorf("sensorlink: a held record does not decode: %v", err)
	}
	nd := st.Node
	if tie != nil {
		nd.PlatformSession = tie
		b, err := json.Marshal(&st)
		if err != nil || len(b) > event.MaxNetobsBytes {
			return c5.Record{}, "", false, fmt.Errorf("sensorlink: the tied record does not fit: %v", err)
		}
		body = b
	}
	e := event.Event{Schema: event.Identifier, ID: event.EventID{NodeID: l.cfg.NodeID, Stream: event.Stream(l.cfg.Stream)},
		Origin: event.OriginPlatform, Kind: event.KindNetworkObservation, Source: event.Source{OriginAuth: event.AuthPlatform},
		Received: hr.Received, Netobs: body}
	if nd.DstAsset == netobs.AssetUnresolved {
		e.Flags = []string{"asset-unresolved"}
	} else {
		e.Source.Asset = &event.AssetRef{ID: nd.DstAsset, Binding: event.Binding{Method: event.BindObservedAddress, Confidence: event.ConfidenceInferred}}
	}
	eb, err := json.Marshal(e)
	if err != nil {
		return c5.Record{}, "", false, err
	}
	rec := c5.Record{Stream: l.cfg.Stream, Class: c5.ClassNetworkObservation, Event: eb, Capture: hr.Capture}
	return rec, nd.DstAsset, nd.SrcAsset == netobs.AssetUnresolved && nd.DstAsset == netobs.AssetUnresolved, nil
}

// commitOne commits one record with tie, if any, or drops and counts it.
// The caller holds cmu.
func (l *Link) commitOne(ctx context.Context, hr HeldRecord, tie *netobs.PlatformSession, _ string) {
	rec, dst, unresolved, err := l.record(hr, tie)
	if err != nil {
		l.refuse(RefusedStored)
		return
	}
	l.mu.Lock()
	if unresolved && !l.budget.take(rec.Bytes(), l.opt.Monotonic()) {
		l.drop(DropUnresolvedBudget, dst)
		l.mu.Unlock()
		return
	}
	l.mu.Unlock()

	_, err = l.opt.Store.Append(ctx, rec)

	l.mu.Lock()
	defer l.mu.Unlock()
	if err != nil {
		if unresolved {
			l.budget.giveBack(rec.Bytes())
		}
		l.storeDrop(err, dst)
		return
	}
	l.committed(hr)
}

// commitBatch commits a release's records in one batch, in order, so a
// restart can tell whether it committed (RecoverHold). A record the budget
// refuses is dropped and counted; a batch the store refuses drops and
// counts each. The caller holds cmu.
func (l *Link) commitBatch(ctx context.Context, rel []Release) {
	var recs []c5.Record
	var held []HeldRecord
	var dsts []string
	var bytes []int64 // the budget each unresolved record took
	l.mu.Lock()
	for _, r := range rel {
		rec, dst, unresolved, err := l.record(r.Record, r.Tie)
		if err != nil {
			l.stats.Refused[RefusedStored]++
			continue
		}
		var took int64
		if unresolved {
			if !l.budget.take(rec.Bytes(), l.opt.Monotonic()) {
				l.drop(DropUnresolvedBudget, dst)
				continue
			}
			took = rec.Bytes()
		}
		recs, held, dsts, bytes = append(recs, rec), append(held, r.Record), append(dsts, dst), append(bytes, took)
	}
	l.mu.Unlock()
	if len(recs) == 0 {
		return
	}
	_, err := l.opt.Store.AppendBatch(ctx, recs)
	l.mu.Lock()
	defer l.mu.Unlock()
	for i := range recs {
		if err != nil {
			l.budget.giveBack(bytes[i])
			l.storeDrop(err, dsts[i])
			continue
		}
		l.committed(held[i])
	}
}

// storeDrop counts a record the store refused. The caller holds l.mu.
func (l *Link) storeDrop(err error, dst string) {
	switch {
	case errors.Is(err, &c5.Error{Code: c5.CodeQuotaReached}):
		l.drop(DropClassFull, dst)
	case errors.Is(err, &c5.Error{Code: c5.CodeRecordTooLarge}):
		l.drop(DropRecordCap, dst)
	default:
		l.drop(DropStore, dst)
	}
}

// committed counts a committed record. The caller holds l.mu.
func (l *Link) committed(hr HeldRecord) {
	l.stats.Committed++
	if l.stats.RunID == hr.RunID && hr.Seq > l.stats.LastCommittedSeq {
		l.stats.LastCommittedSeq = hr.Seq
	}
}

// nodeObject builds the node object, all but stored_capture, and reports
// whether neither end resolved, so the observation draws on the unresolved
// budget (C13 section 5). The platform_session tie is the hold's (hold.go).
func (l *Link) nodeObject(o *netobs.Observation) (*netobs.Node, bool) {
	nd := &netobs.Node{SrcAsset: netobs.AssetUnresolved, DstAsset: netobs.AssetUnresolved, ResolvedBy: "none",
		EvidenceClass: string(l.cfg.EvidenceClass)}
	if o.IP != nil {
		src, srcKnown := l.resolve(o.IP.Src)
		dst, dstKnown := l.resolve(o.IP.Dst)
		// Each end resolves on its own: an end on an address two assets
		// share stays unresolved, and the other end keeps its asset (D3 on
		// #553, D1's ruling (a)).
		if srcKnown && src != "" {
			nd.SrcAsset = src
		}
		if dstKnown && dst != "" {
			nd.DstAsset = dst
		}
		switch {
		case (srcKnown && src == "") || (dstKnown && dst == ""):
			nd.ResolvedBy = "ip-ambiguous"
		case srcKnown || dstKnown:
			nd.ResolvedBy = "ip"
		}
	}
	if f := o.Function; o.Kind == netobs.KindFunction && f != nil {
		row := netdetect.Classify(o.Protocol, f.Code, f.Sub, f.Objects)
		nd.FunctionClass, nd.FunctionTable = row.Class, netdetect.Table
		// An absent sa is "" and never sets the flag; failed never does.
		if o.Protocol == "dnp3" && f.SA == netobs.SANone && slices.Contains(netobs.NoSAClasses, row.Class) {
			t := true
			nd.DNP3NoSA = &t
		}
	}
	return nd, nd.SrcAsset == netobs.AssetUnresolved && nd.DstAsset == netobs.AssetUnresolved
}

func (l *Link) resolve(s string) (string, bool) {
	a, err := netip.ParseAddr(s)
	if err != nil {
		return "", false // C13 has checked the form already
	}
	return l.resolver.Resolve(a)
}

// firstSightCapture builds a first sight's stored capture from its frames,
// which C13 has checked against their hashes.
func firstSightCapture(o *netobs.Observation) (*c5.Capture, error) {
	frames := make([]pcapFrame, len(o.Frames))
	for i, f := range o.Frames {
		data, err := base64.StdEncoding.Strict().DecodeString(f.Data)
		if err != nil {
			return nil, err
		}
		ts, err := time.Parse(time.RFC3339Nano, f.TS)
		if err != nil {
			return nil, err
		}
		frames[i] = pcapFrame{TS: ts, Data: data, WireLen: o.Citation.Frames[i].WireLen}
	}
	b, err := buildPcap(frames)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(b)
	return &c5.Capture{SHA256: hex.EncodeToString(sum[:]), Bytes: b}, nil
}
