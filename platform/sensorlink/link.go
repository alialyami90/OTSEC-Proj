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
	"sync/atomic"
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
	// The 0.2 intake's seams (conn.go), each read only by ServeConn and
	// WriteOwed: the observation stream's source cursor, the kept
	// pinned_by, the node's wall clock, the status alarms, the owed health
	// events, and CH-4's waits.
	Cursor   CursorStore
	Pins     PinStore
	Now      func() time.Time
	Raise    func(alarm, detail string)
	Owed     func(ctx context.Context, o Owed) error
	Timeouts ConnTimeouts
	// LateBound is late_bound_s (CH-23); zero is DefaultLateBound.
	LateBound time.Duration
	// BacklogTie is backlog_tie_s (CH-39); zero is DefaultBacklogTie, and
	// it is from zero to MaxBacklogTie.
	BacklogTie time.Duration
	// BlindAfter is blind_after_s (CH-31); zero is DefaultBlindAfter.
	BlindAfter time.Duration
	// Health is the sensor's health events (health.go): with it, Owed
	// defaults to its WriteOwed, the heartbeat baselines are judged, and
	// the pool's alarms make their event due.
	Health *Health
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
	// Heartbeats counts the heartbeats accepted, in every run, and
	// HeartbeatMono is the monotonic time the last one was accepted at,
	// for the node's sensor-unreachable (D4-73).
	Heartbeats    uint64
	HeartbeatMono time.Duration
	// Hold is the intake hold's counts.
	Hold HoldStats
	// DispatchTimeouts and ResultTimeouts count the scheduler calls that
	// did not have the link's lock within HoldLockWait, or panicked, so
	// their run went on untied (section 1.9 items 4 and 9); an Abandon is
	// counted with the results. LockWaitMax is the longest any scheduler
	// call waited for the lock. SchedPanics counts the panics recovered in
	// them, and LastSchedPanic is the last one's text, capped.
	DispatchTimeouts uint64
	ResultTimeouts   uint64
	LockWaitMax      time.Duration
	SchedPanics      uint64
	LastSchedPanic   string
}

// Link reads one sensor's channel.
type Link struct {
	cfg      Config
	opt      Options
	resolver *Resolver

	// cmu orders every commit to the stream with the hold's changes, so a
	// release's batch and its saved state agree with what came before and
	// after it. It is taken before mu. The scheduler's calls go first
	// (fairlock.go).
	cmu  fairLock
	hold *hold

	mu     sync.Mutex
	stats  Stats
	budget *budget

	// The 0.2 intake (conn.go). curMu orders a connection's frames with
	// WriteOwed, is held while a frame is acted on and never across a read
	// or a write of the connection, and is taken before cmu; inflight is
	// under cmu; conn under mu.
	guard    connGuard
	curMu    sync.Mutex
	inflight *inflight
	conn     ConnStats
	// gapRaised is the excess of G over D last raised for gapRun, so
	// sensor-gap-undeclared rises once for each rise of it (CH-15). It is
	// kept in memory, not in the cursor (D1's ruling 6952181701 on #732,
	// option (b)): after a node start an excess that stands is raised once
	// more. Under curMu.
	gapRun    string
	gapRaised uint64

	// The 0.2 position a release moves (section 1.4 items 2 and 3), all
	// under cmu: pos is the cursor as last written, nil until read;
	// curOpen is set while the 0.2 path holds a cursor in memory (a
	// connection, WriteOwed); moved is what releases changed since that
	// cursor last took their changes. unsaved is what releases changed
	// whose save failed: their totals and unmarks, never their T, so it
	// moves no duplicate check and no ack; every later write of the
	// position carries it (D3's B1 on #742).
	pos     *Cursor
	posRead bool
	curOpen bool
	moved   *posMove
	unsaved *posMove
	// writeNo is the run file's last write number, which every write of
	// the position carries (section 1.1). Under cmu.
	writeNo uint64
	// egressRun is the run for which sensor-egress-absent was last raised
	// with no baseline held, so it rises once a run. Under curMu.
	egressRun string
	// skew is the 0.2 intake's skew estimate and capture floor (skew.go),
	// under its own leaf lock.
	skew skew
	// startRun is the run seen from its start in this process, "" when
	// none, so a resume with no gap keeps it (CH-27; D4's N1 on #747).
	// Under curMu.
	startRun string
	// lateShortDue: sensor-late-index-short is due, raised by Result
	// once it has left the link's lock.
	lateShortDue atomic.Bool
	// gmu orders the gap model's changes of the gap open and the record
	// that waits with their writes (gap.go). It is taken after curMu and
	// before cmu; the node's tick only tries it.
	gmu sync.Mutex
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
	case opt.BacklogTie < 0:
		return nil, fmt.Errorf("sensorlink: backlog_tie_s %s is below zero", opt.BacklogTie)
	case opt.BacklogTie > MaxBacklogTie:
		return nil, fmt.Errorf("sensorlink: backlog_tie_s %s is above %s", opt.BacklogTie, MaxBacklogTie)
	}
	h, err := newHold(opt.Hold)
	if err != nil {
		return nil, err
	}
	h.mono = opt.Monotonic
	if opt.Health != nil && opt.Owed == nil {
		opt.Owed = opt.Health.WriteOwed
	}
	l := &Link{cfg: cfg, opt: opt, resolver: NewResolver(cfg.NodeID, opt.Assets), hold: h,
		stats:  Stats{Refused: map[string]uint64{}, Dropped: map[string]uint64{}, DroppedByAsset: map[string]uint64{}},
		conn:   ConnStats{Closes: map[string]uint64{}},
		budget: newBudget(cfg.ObservationQuota, cfg.OutageHours, opt.Monotonic())}
	h.off = l.offNow
	if opt.Health != nil && opt.Health.cfg.File != nil {
		opt.Health.cfg.File.addLink(l)
	}
	if opt.Health != nil && opt.Cursor != nil {
		opt.Health.watched = l.watchedCopy
	}
	return l, nil
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
		l.stats.Heartbeats++
		l.stats.HeartbeatMono = l.opt.Monotonic()
		l.mu.Unlock()
		if degraded(h.Coverage) {
			l.cmu.Lock()
			l.giveWay(ctx, false)
			l.syncHold()
			l.cmu.Unlock()
		}
		return
	}
	l.observe(ctx, rec.Observation, n, nil, false)
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
	defer l.mu.Unlock() // commitOne's path: a recovered panic never leaves l.mu held
	l.stats.Refused[reason]++
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

// observe adds the node object to o, with lost as node.lost (CH-40), and
// holds it (hold.go) or commits it untied, or drops and counts it.
func (l *Link) observe(ctx context.Context, o *netobs.Observation, seq uint64, lost []netobs.Span, late bool) {
	nd, _ := l.nodeObject(o)
	nd.Lost, nd.Late = lost, late
	// A backlog record the break refuses takes no tie and carries
	// node.backlog, and not node.skewed, whatever else refuses it (CH-39).
	bk := l.breakRefuses(o.MadeUTC)
	// Committed while no tie is made for skew: marked, whatever the hold
	// does with it (CH-41). A record held now and released later is marked
	// by its release instead.
	nd.Backlog, nd.Skewed = bk, !bk && l.marks(l.standing())
	if bk {
		l.skew.mu.Lock()
		l.skew.stats.Backlog++
		l.skew.mu.Unlock()
	}
	if afterMarkSeam != nil {
		afterMarkSeam()
	}
	var capture *c5.Capture
	if o.FirstSight {
		c, err := firstSightCapture(o)
		if err != nil {
			l.refuseStored()
			return
		}
		capture = c
		nd.StoredCapture = c.SHA256
	}
	stored := *o
	stored.Frames, stored.Node = nil, nd
	if err := stored.ValidateStored(); err != nil {
		l.refuseStored()
		return
	}
	body, err := json.Marshal(&stored)
	if err != nil || len(body) > event.MaxNetobsBytes {
		l.refuseStored()
		return
	}
	hr := HeldRecord{RunID: o.RunID, Seq: seq, Observation: body, Capture: capture, Received: l.opt.Received()}
	l.cmu.Lock()
	defer l.cmu.Unlock()
	defer l.syncHold()
	if f := l.inflight; f.mine(hr) && l.pos != nil && l.pos.RunID == hr.RunID && hr.Seq <= l.pos.Taken {
		// A release saved a position past this seq since the frame was
		// placed: the resend of a record it disposed of (section 1.4 item
		// 4). The position saved now, not what a fold left in l.moved, so
		// a flush that took the release's change in between hides nothing
		// (D6's B2 on #742); a release whose save failed moves no T.
		l.mu.Lock()
		l.stats.Dropped[RefusedDuplicate]++
		l.mu.Unlock()
		f.outcome = outDuplicate
		return
	}
	if degraded(o.Coverage) {
		l.giveWay(ctx, false)
	}
	if l.takeHeld(ctx, &stored, hr, bk) {
		return
	}
	l.commitOne(ctx, hr, nil, "")
}

// record builds hr's C4 event with tie, if any, and reports its
// destination asset and whether neither end resolved, so it draws on the
// unresolved budget (C13 section 5).
func (l *Link) record(hr HeldRecord, tie *netobs.PlatformSession, skewed bool) (c5.Record, string, bool, error) {
	body := hr.Observation
	var st netobs.Observation
	if err := json.Unmarshal(body, &st); err != nil || st.Node == nil {
		return c5.Record{}, "", false, fmt.Errorf("sensorlink: a held record does not decode: %v", err)
	}
	nd := st.Node
	if skewed && tie == nil && !nd.Skewed {
		b, err := nodeBody(body, "skewed", true)
		if err != nil || len(b) > event.MaxNetobsBytes {
			return c5.Record{}, "", false, fmt.Errorf("sensorlink: the marked record does not fit: %v", err)
		}
		body = b
	}
	if tie != nil {
		b, err := tieBody(body, tie)
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

// tieBody sets node.platform_session in a held observation's raw JSON and
// keeps every other field as it was, so a held body of a later minor keeps
// the fields this build's type does not know, such as C13 0.3's counts
// (CH-35's bridge item 5, kept for a later minor by C13 0.3 section 1.2).
// Re-encoding it through netobs.Observation would drop them for good.
func tieBody(body json.RawMessage, tie *netobs.PlatformSession) ([]byte, error) {
	return nodeBody(body, "platform_session", tie)
}

// nodeBody sets the node object's key to v in a held observation's raw
// JSON, every other field kept as it was (tieBody).
func nodeBody(body json.RawMessage, key string, v any) ([]byte, error) {
	var top, node map[string]json.RawMessage
	if err := json.Unmarshal(body, &top); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(top["node"], &node); err != nil {
		return nil, err
	}
	ps, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	node[key] = ps
	if top["node"], err = json.Marshal(node); err != nil {
		return nil, err
	}
	return json.Marshal(top)
}

// refuseStored refuses the record being stored, and notes it for the 0.2
// path.
func (l *Link) refuseStored() {
	l.refuse(RefusedStored)
	l.cmu.Lock()
	if l.inflight != nil {
		l.inflight.outcome = outRefused
	}
	l.cmu.Unlock()
}

// commitOne commits one record with tie, if any, or drops and counts it.
// The record the 0.2 path is taking carries the cursor in the same commit
// (CH-17), and its outcome is noted. The caller holds cmu.
func (l *Link) commitOne(ctx context.Context, hr HeldRecord, tie *netobs.PlatformSession, _ string) {
	f := l.inflight
	if !f.mine(hr) {
		f = nil
	}
	note := func(o outcome) {
		if f != nil {
			f.outcome = o
		}
	}
	rec, dst, unresolved, err := l.record(hr, tie, false)
	var folded *Cursor
	if err == nil && f != nil {
		rec.SourceCursor = f.cursor
		if l.moved != nil || l.unsaved != nil || f.marked.WriteNo < l.writeNo {
			// A release moved the position since f's cursor was encoded, or
			// its own save failed, or the run file was written: the commit
			// carries each, so it never writes T, a total or the write
			// number back.
			folded = f.marked.clone()
			l.moved.apply(folded)
			l.unsaved.apply(folded)
			folded.WriteNo = l.writeNo
			b, err := l.encode(folded)
			if err != nil {
				note(outStoreError) // not taken: T stays, the record is resent
				return
			}
			rec.SourceCursor = b
		}
	}
	if err != nil {
		l.refuse(RefusedStored)
		note(outRefused)
		return
	}
	if !l.takeBudget(unresolved, rec.Bytes(), dst) {
		note(outDropped)
		return
	}
	_, err = l.opt.Store.Append(ctx, rec)

	l.mu.Lock()
	defer l.mu.Unlock()
	if err != nil {
		if unresolved {
			l.budget.giveBack(rec.Bytes())
		}
		if f != nil && !finalStoreError(err) {
			note(outStoreError) // not final: not counted, the record is resent
			return
		}
		l.storeDrop(err, dst)
		note(outDropped)
		return
	}
	l.committed(hr)
	if f != nil {
		if folded != nil {
			f.marked, l.moved, l.unsaved = folded, nil, nil
		}
		l.pos, l.posRead = f.marked.clone(), true
	}
	note(outCommitted)
}

// finalStoreError reports whether a store refusal is a final outcome: a
// full class or the record cap (CH-17).
func finalStoreError(err error) bool {
	return errors.Is(err, &c5.Error{Code: c5.CodeQuotaReached}) || errors.Is(err, &c5.Error{Code: c5.CodeRecordTooLarge})
}

// takeBudget takes an unresolved record's bytes from the budget, or drops
// and counts it. It unlocks l.mu with defer, so a recovered panic never
// leaves it held (D3's B1 on #676).
func (l *Link) takeBudget(unresolved bool, n int64, dst string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if unresolved && !l.budget.take(n, l.opt.Monotonic()) {
		l.drop(DropUnresolvedBudget, dst)
		return false
	}
	return true
}

// commitBatch commits a release's records in one batch, in order, so a
// restart can tell whether it committed (RecoverHold). A record the budget
// refuses is dropped and counted; a batch the store refuses drops and
// counts each. As soon as the batch returns, taken gets the largest seq
// of its receipts, when any record committed: past that point its records
// are in the store, whatever happens next (release). The caller holds cmu.
//
// With a 0.2 position (section 1.4 items 2 and 3), the batch's last record
// carries the position moved past every released record of the position's
// run, with the totals of those the release did not store; when it stores
// nothing, the cursor is saved on its own. An earlier run's record never
// moves T.
func (l *Link) commitBatch(ctx context.Context, rel []Release, taken func(last uint64)) {
	var recs []c5.Record
	var held []HeldRecord
	var dsts []string
	var bytes []int64 // the budget each unresolved record took
	mv := l.releaseMove()
	func() {
		l.mu.Lock()
		defer l.mu.Unlock() // a recovered panic never leaves l.mu held (D3's B1 on #676)
		for _, r := range rel {
			rec, dst, unresolved, err := l.record(r.Record, r.Tie, r.Skewed)
			if err != nil {
				l.stats.Refused[RefusedStored]++
				mv.dispose(r.Record, true)
				continue
			}
			var took int64
			if unresolved {
				if !l.budget.take(rec.Bytes(), l.opt.Monotonic()) {
					l.drop(DropUnresolvedBudget, dst)
					mv.dispose(r.Record, false)
					continue
				}
				took = rec.Bytes()
			}
			recs, held, dsts, bytes = append(recs, rec), append(held, r.Record), append(dsts, dst), append(bytes, took)
		}
	}()
	if len(recs) == 0 {
		l.saveMove(ctx, mv)
		return
	}
	stored := mv.with(held)
	b := l.moveCursor(stored)
	if b != nil {
		recs[len(recs)-1].SourceCursor = b
	}
	rcs, err := l.opt.Store.AppendBatch(ctx, recs)
	if err == nil && len(rcs) > 0 {
		var last uint64
		for _, rc := range rcs {
			last = max(last, uint64(rc.Key().Seq))
		}
		taken(last)
	}
	if err == nil {
		l.tookMove(stored, b != nil) // an encode that failed is raised by moveCursor
	}
	func() {
		l.mu.Lock()
		defer l.mu.Unlock() // a recovered panic never leaves l.mu held (D3's N4 on #742)
		for i := range recs {
			if err != nil {
				l.budget.giveBack(bytes[i])
				l.storeDrop(err, dsts[i])
				mv.dispose(held[i], false)
				continue
			}
			l.committed(held[i])
		}
	}()
	if err != nil {
		l.saveMove(ctx, mv)
	}
}

// readPos reads the 0.2 position once, before a release begins. A release
// that cannot read it begins nothing, as for the stream's head: the run
// stays held, and the next tick tries again (D6's N3 on #742). The caller
// holds cmu.
func (l *Link) readPos(ctx context.Context) error {
	if l.opt.Cursor == nil || l.posRead {
		return nil
	}
	c, err := l.loadCursor(ctx)
	if err != nil {
		return err
	}
	l.pos, l.posRead = c, true
	l.tookWriteNo(c)
	return nil
}

// releaseMove is a release's change to the 0.2 position, nil when the link
// keeps none (the 0.1 path, or no position saved yet). The release has
// read the position (readPos). The caller holds cmu.
func (l *Link) releaseMove() *posMove {
	if l.opt.Cursor == nil || l.pos == nil {
		return nil
	}
	return &posMove{run: l.pos.RunID}
}

// dispose counts r, which the release does not store: a record of the
// position's run moves T past it, and its node.lost windows are unmarked
// (D4's N3 on #732).
func (m *posMove) dispose(r HeldRecord, refused bool) {
	if m == nil {
		return
	}
	if refused {
		m.refused++
	} else {
		m.dropped++
	}
	if r.RunID != m.run {
		return
	}
	m.taken = max(m.taken, r.Seq)
	var o struct {
		Node struct {
			Lost []netobs.Span `json:"lost"`
		} `json:"node"`
	}
	if json.Unmarshal(r.Observation, &o) == nil {
		m.unmark = append(m.unmark, o.Node.Lost...)
	}
}

// with is m with the records rs stored as well.
func (m *posMove) with(rs []HeldRecord) *posMove {
	if m == nil {
		return nil
	}
	n := *m
	n.unmark = slices.Clone(m.unmark)
	for _, r := range rs {
		if r.RunID == n.run {
			n.taken = max(n.taken, r.Seq)
		}
	}
	return &n
}

// moveCursor is the position with what earlier releases did not save and
// m applied, encoded, or nil when there is nothing to carry. The caller
// holds cmu.
func (l *Link) moveCursor(m *posMove) []byte {
	if m == nil {
		return nil
	}
	c := l.pos.clone()
	l.unsaved.apply(c)
	m.apply(c)
	c.WriteNo = max(c.WriteNo, l.writeNo)
	b, err := l.encode(c)
	if err != nil {
		l.raise(AlarmPositionNotSaved, fmt.Sprintf("sensor %s: the position moved by a release was not saved: %v", l.cfg.SensorID, err))
		return nil
	}
	return b
}

// tookMove records m. Written, it is in the position with what earlier
// releases did not save, and goes to the cursor the 0.2 path holds in
// memory, which takes it at its next frame. Not written, only its totals
// and unmarks are kept, in l.unsaved, for the next write of the position:
// its T moves no duplicate check and no ack, so a resend of a record whose
// drop was not saved is stored, an over-count that is loud (D3's B1 on
// #742). The caller holds cmu.
func (l *Link) tookMove(m *posMove, written bool) {
	if m == nil {
		return
	}
	if !written {
		if !m.empty() {
			l.unsaved = l.unsaved.merge(&posMove{run: m.run, refused: m.refused, dropped: m.dropped, unmark: m.unmark})
		}
		return
	}
	if l.unsaved != nil {
		m, l.unsaved = l.unsaved.merge(m), nil
	}
	if m.empty() {
		return
	}
	m.apply(l.pos)
	if !l.curOpen {
		return
	}
	if l.moved == nil {
		l.moved = &posMove{run: m.run}
	}
	if l.moved.run != m.run {
		// The cursor in memory moved to a newer run: only the totals carry.
		m = &posMove{run: l.moved.run, refused: m.refused, dropped: m.dropped}
	}
	l.moved.taken = max(l.moved.taken, m.taken)
	l.moved.refused += m.refused
	l.moved.dropped += m.dropped
	l.moved.unmark = append(l.moved.unmark, m.unmark...)
}

// saveMove saves the position moved by a release that stored nothing, so
// that no ack passes a count that is not saved (section 1.4 item 3). A
// save that fails raises sensor-position-not-saved, and the move is kept
// as not written (tookMove). The caller holds cmu.
func (l *Link) saveMove(ctx context.Context, m *posMove) {
	if m.empty() {
		return
	}
	b := l.moveCursor(m)
	written := false
	if b != nil {
		if err := l.opt.Cursor.SaveSourceCursor(ctx, b); err != nil {
			l.raise(AlarmPositionNotSaved, fmt.Sprintf("sensor %s: the position moved by a release was not saved: %v", l.cfg.SensorID, err))
		} else {
			written = true
		}
	}
	l.tookMove(m, written)
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
		row := netdetect.ClassifyFunction(o.Protocol, f)
		nd.FunctionClass, nd.FunctionTable = row.Class, netdetect.Table
		// An absent sa is "" and never sets a flag; failed never does. sa
		// unknown sets dnp3_sa_unknown, never dnp3_no_sa (C13 0.3 §15.2).
		if o.Protocol == "dnp3" && slices.Contains(netobs.NoSAClasses, row.Class) {
			t := true
			switch f.SA {
			case netobs.SANone:
				nd.DNP3NoSA = &t
			case netobs.SAUnknown:
				nd.DNP3SAUnknown = &t
			}
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
