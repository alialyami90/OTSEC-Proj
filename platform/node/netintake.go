package node

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"time"

	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/audit"
	"otsec.local/otsec/contracts/event"
	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/platform/sensorlink"
)

// IntakeSchema is the intake hold's record (C5 0.9 netcheckpoint.intake,
// D4-72): the node's wrapping of a sensorlink.RunRecord. The schema is its
// first field, so a reader that looks for another otsec. document by its
// prefix passes over it (D1 on #571).
const IntakeSchema = "otsec.netcheckpoint.intake/0.1"

// Status values of a collection.run the start repair writes.
const (
	// RunNotCommitted is a repaired run's status: its release committed,
	// the node stopped before its result did (D1 in D4-72).
	RunNotCommitted = "not-committed"
	// RepairedFromIntake is a repaired run's repaired_from detail.
	RepairedFromIntake = "netcheckpoint.intake"
)

// Alarms of the intake hold.
const (
	// AlarmIntakeCheckpointFailed: a hold record was not saved, so a flow
	// committed untied (its own-session rules may alert on it).
	AlarmIntakeCheckpointFailed = "intake-checkpoint-failed"
	// AlarmIntakeNotRemoved: a run's older hold records were not removed;
	// they stay in the configuration class until the next try.
	AlarmIntakeNotRemoved = "intake-record-not-removed"
	// AlarmIntakeRepairRefused: a release whose collection.run is missing
	// names a run with no allowed collector.request after its dispatch, so
	// no collection.run is written for it (D3's R1).
	AlarmIntakeRepairRefused = "intake-repair-refused"
)

// intakeDoc is a netcheckpoint.intake document.
type intakeDoc struct {
	Schema string `json:"schema"`
	// HealthHead and AuditHead are the health and audit streams' last seq
	// when the record was written, so the start repair reads only what
	// came after the run's dispatch.
	HealthHead uint64 `json:"health_head"`
	AuditHead  uint64 `json:"audit_head"`
	sensorlink.RunRecord
}

// decodeIntake decodes and checks a netcheckpoint.intake document.
func decodeIntake(document []byte) (intakeDoc, error) {
	var d intakeDoc
	if err := decodeExact(document, &d, "intake hold record"); err != nil {
		return d, err
	}
	switch {
	case d.Schema != IntakeSchema:
		return d, fmt.Errorf("intake hold record: schema %q", d.Schema)
	case !slices.Contains([]string{sensorlink.HoldHolding, sensorlink.HoldWaiting, sensorlink.HoldReleasing, sensorlink.HoldReleased}, d.State):
		return d, fmt.Errorf("intake hold record: state %q", d.State)
	case d.Run.RequestID == "":
		return d, errors.New("intake hold record: run.request_id is empty")
	case !asset.ValidAssetID(d.Run.AssetID):
		return d, fmt.Errorf("intake hold record: run.asset_id %q", d.Run.AssetID)
	}
	return d, nil
}

// checkIntakeRecord is ConfigDocuments' check of a hold record.
func checkIntakeRecord(document []byte, capture *c5.Capture) (c5.DocumentInfo, error) {
	if capture != nil {
		return c5.DocumentInfo{}, errors.New("configuration document: an intake hold record has no capture")
	}
	if _, err := decodeIntake(document); err != nil {
		return c5.DocumentInfo{}, err
	}
	return c5.DocumentInfo{Kind: c5.DocumentWorkingState, Series: c5.SeriesNetCheckpointIntake}, nil
}

// intakeRun is what the node keeps of one run's hold records.
type intakeRun struct {
	seqs       []c5.Seq // its records, oldest first
	healthHead uint64   // of its first record
	auditHead  uint64
	newest     sensorlink.RunRecord
	// recorded: its collection.run committed, so its records may go.
	recorded bool
}

// intakeRecords are the hold records in the stream, by run. Its own mutex
// guards it: the link saves through it while it holds its own lock.
type intakeRecords struct {
	mu     sync.Mutex
	runs   map[string]*intakeRun
	newest c5.Seq // the series' newest record, which is never removed
	// removing is the alarm raised for a removal that failed.
	removing bool
	// repaired and repairRefused count the start repair's runs.
	repaired, repairRefused uint64
}

func (ir *intakeRecords) note(seq c5.Seq, d intakeDoc) {
	ir.mu.Lock()
	defer ir.mu.Unlock()
	if ir.runs == nil {
		ir.runs = map[string]*intakeRun{}
	}
	r := ir.runs[d.Run.RequestID]
	if r == nil {
		r = &intakeRun{healthHead: d.HealthHead, auditHead: d.AuditHead}
		ir.runs[d.Run.RequestID] = r
	}
	r.seqs, r.newest, ir.newest = append(r.seqs, seq), d.RunRecord, max(ir.newest, seq)
}

// intakeStream is the stream the hold's records are on.
func (r *Runtime) intakeStream() c5.StreamID { return NetBaselineStream(r.cfg.NetworkSensor.SensorID) }

// lastSeq is stream's last committed seq, or 0 when it can't be read.
func (r *Runtime) lastSeq(ctx context.Context, stream c5.StreamID) uint64 {
	db := r.Store(stream)
	if db == nil {
		return 0
	}
	seq, err := db.LastCommitted(ctx, stream)
	if err != nil {
		return 0
	}
	return seq
}

// saveIntake is the hold's HoldConfig.Save: it commits rec as a
// netcheckpoint.intake document before the change takes effect.
func (r *Runtime) saveIntake(ctx context.Context, rec sensorlink.RunRecord) error {
	d := intakeDoc{Schema: IntakeSchema, HealthHead: r.lastSeq(ctx, HealthStream), AuditHead: r.lastSeq(ctx, AuditStream), RunRecord: rec}
	b, err := json.Marshal(d)
	if err != nil {
		return err
	}
	stream := r.intakeStream()
	log, db := r.Log(stream), r.Store(stream)
	if log == nil || db == nil {
		return errors.New("node: the configuration database is not open")
	}
	// Item 3's ceiling holds the network series too (D5-c5-0.9 section 8):
	// a write above it is refused, so the flow commits untied and is
	// counted, and configuration monitoring keeps its floor (D3's I3).
	used, err := db.ClassBytes(ctx, c5.ClassConfiguration)
	if err != nil {
		return err
	}
	if ceiling := r.cfg.Item3Ceiling(); used+int64(len(b)) > ceiling {
		return fmt.Errorf("node: an intake hold record of %d bytes is over item 3's ceiling (%d of %d bytes used)", len(b), used, ceiling)
	}
	rc, err := log.Append(ctx, c5.Record{Stream: stream, Class: c5.ClassConfiguration, Event: b})
	if err != nil {
		return err
	}
	r.intake.note(rc.Key().Seq, d)
	return nil
}

// loadIntake reads the hold records in the stream and returns what the hold
// starts from: the newest record of each run not released, then the newest
// record of all, whose open table the hold takes (HoldConfig.Restore).
func (r *Runtime) loadIntake(ctx context.Context) ([]sensorlink.RunRecord, error) {
	stream := r.intakeStream()
	db := r.Store(stream)
	if db == nil {
		return nil, errors.New("the configuration database is not open")
	}
	var newest *intakeDoc
	var after c5.Seq
	for {
		got, err := db.Read(ctx, stream, after, 64)
		if err != nil {
			return nil, err
		}
		for _, st := range got {
			after = st.Key.Seq
			if !bytes.HasPrefix(st.Event, []byte(`{"schema":"`+IntakeSchema)) {
				continue
			}
			d, err := decodeIntake(st.Event)
			if err != nil {
				return nil, fmt.Errorf("intake hold record %d: %w", st.Key.Seq, err)
			}
			r.intake.note(st.Key.Seq, d)
			newest = &d
		}
		if len(got) < 64 {
			break
		}
	}
	if newest == nil {
		return nil, nil
	}
	// The runs not released, in the order they were dispatched, so the
	// newest holding run to an endpoint stays the newest (runFor), then the
	// newest record of all unless it is the last of those already.
	var runs []*intakeRun
	for _, run := range r.intake.runs {
		if run.newest.State != sensorlink.HoldReleased {
			runs = append(runs, run)
		}
	}
	slices.SortFunc(runs, func(a, b *intakeRun) int { return cmp.Compare(a.seqs[0], b.seqs[0]) })
	var out []sensorlink.RunRecord
	for _, run := range runs {
		out = append(out, run.newest)
	}
	if n := len(runs); n == 0 || runs[n-1].seqs[len(runs[n-1].seqs)-1] != r.intake.newest {
		out = append(out, newest.RunRecord)
	}
	return out, nil
}

// holdEndpoint is the address the hold watches for a scheduled run: the
// collection's endpoint when its host is an IP literal on a transport the
// sensor sees, TCP for a session and UDP for SNMPv3.
func (c *Config) holdEndpoint(col Collection) (netip.AddrPort, string, bool) {
	a, ok := c.Asset(col.AssetID)
	if !ok {
		return netip.AddrPort{}, "", false
	}
	ep, ok := endpoint(a, col.Endpoint)
	if !ok || ep.Port < 1 || ep.Port > 65535 {
		return netip.AddrPort{}, "", false
	}
	addr, err := netip.ParseAddr(ep.Host)
	if err != nil {
		return netip.AddrPort{}, "", false
	}
	l4 := "tcp"
	switch ep.Transport {
	case asset.SSH, asset.Telnet:
	case asset.SNMPv3:
		l4 = "udp"
	default:
		return netip.AddrPort{}, "", false
	}
	return netip.AddrPortFrom(addr.Unmap().WithZone(""), uint16(ep.Port)), l4, true
}

// heldRun is a scheduled run the hold watches.
type heldRun struct{ run sensorlink.HoldRun }

// dispatchHold starts holding the run's endpoint, before the request is
// sent. It returns nil when the hold doesn't watch the run. A save that
// fails holds nothing: the run's flows commit untied, counted in status.
func (s *Scheduler) dispatchHold(ctx context.Context, col Collection, requestID string) *heldRun {
	in := s.rt.sensor
	if in == nil {
		return nil
	}
	ep, l4, ok := s.rt.cfg.holdEndpoint(col)
	if !ok {
		return nil
	}
	h := &heldRun{run: sensorlink.HoldRun{RequestID: requestID, AssetID: col.AssetID, Endpoint: ep, L4: l4}}
	_ = in.link.Dispatch(ctx, h.run)
	return h
}

// abandonHold releases a run that ended without a result, untied.
func (s *Scheduler) abandonHold(ctx context.Context, h *heldRun) {
	if h == nil {
		return
	}
	_, _ = s.rt.sensor.link.Abandon(ctx, h.run.RequestID)
	s.rt.pruneIntake(ctx, "")
}

// resultHold ties the run's held flows by its result's session and commits
// them, and returns the session details its collection.run carries, so
// the run's session can be rebuilt from the committed record (D1 on the
// split of PR B). It returns nil when the hold doesn't watch the run, or
// when the observation stream's head can't be read.
func (s *Scheduler) resultHold(ctx context.Context, h *heldRun, invocationID string, res sessionResult) map[string]string {
	if h == nil {
		return nil
	}
	sess := sensorlink.Session{InvocationID: invocationID, Connected: res.Connected}
	sess.StartedAt, _ = time.Parse(time.RFC3339Nano, res.StartedAt)
	sess.EndedAt, _ = time.Parse(time.RFC3339Nano, res.EndedAt)
	if res.LocalAddr != "" {
		sess.Local, _ = netip.ParseAddrPort(res.LocalAddr)
	}
	if res.ConnectedAt != "" {
		sess.ConnectedAt, _ = time.Parse(time.RFC3339Nano, res.ConnectedAt)
	}
	rel, err := s.rt.sensor.link.Result(ctx, h.run.RequestID, sess)
	if err != nil {
		return nil
	}
	return sessionDetails(h.run, sess, rel)
}

// sessionResult is what resultHold takes from a C2 result.
type sessionResult struct {
	Connected              bool
	StartedAt, EndedAt     string
	LocalAddr, ConnectedAt string
}

// sessionDetails are a collection.run's session details: every field a
// detector session needs, besides the asset and invocation, which the run
// record carries already.
func sessionDetails(run sensorlink.HoldRun, s sensorlink.Session, rel sensorlink.Released) map[string]string {
	d := map[string]string{
		"endpoint":   run.Endpoint.String(),
		"l4":         run.L4,
		"started_at": s.StartedAt.UTC().Format(time.RFC3339Nano),
		"ended_at":   s.EndedAt.UTC().Format(time.RFC3339Nano),
		"connected":  strconv.FormatBool(s.Connected),
		"open_flow":  strconv.FormatBool(rel.OpenFlow),
		"after_seq":  strconv.FormatUint(rel.AfterSeq, 10),
	}
	if s.Local.IsValid() {
		d["local_addr"] = s.Local.String()
	}
	if !s.ConnectedAt.IsZero() {
		d["connected_at"] = s.ConnectedAt.UTC().Format(time.RFC3339Nano)
	}
	return d
}

// RunSession is a run's session as its committed collection.run records
// it: what the node hands the detector (netdetect.Session), with the seq it
// follows.
type RunSession struct {
	Seq          uint64 // the collection.run's seq on the health stream
	InvocationID string
	AssetID      string
	Endpoint     netip.AddrPort
	L4           string
	Local        netip.AddrPort
	Connected    bool
	StartedUTC   string
	EndedUTC     string
	OpenFlow     bool
	AfterSeq     uint64
}

// runSessionOf rebuilds a run's session from its committed collection.run.
// ok is false for a run the hold didn't watch, whose record has no session.
func runSessionOf(st c5.Stored) (RunSession, bool, error) {
	ev, err := event.Decode(st.Event)
	if err != nil {
		return RunSession{}, false, err
	}
	h := ev.Health
	if h == nil || h.Type != HealthCollectionRun {
		return RunSession{}, false, nil
	}
	d := h.Details
	if _, ok := d["after_seq"]; !ok {
		return RunSession{}, false, nil
	}
	s := RunSession{Seq: st.Key.Seq, InvocationID: d["invocation_id"], AssetID: d["asset_id"], L4: d["l4"],
		StartedUTC: d["started_at"], EndedUTC: d["ended_at"]}
	var errs []error
	if s.Endpoint, err = netip.ParseAddrPort(d["endpoint"]); err != nil {
		errs = append(errs, err)
	}
	if v, ok := d["local_addr"]; ok {
		if s.Local, err = netip.ParseAddrPort(v); err != nil {
			errs = append(errs, err)
		}
	}
	if s.Connected, err = strconv.ParseBool(d["connected"]); err != nil {
		errs = append(errs, err)
	}
	if s.OpenFlow, err = strconv.ParseBool(d["open_flow"]); err != nil {
		errs = append(errs, err)
	}
	if s.AfterSeq, err = strconv.ParseUint(d["after_seq"], 10, 64); err != nil {
		errs = append(errs, err)
	}
	if err := errors.Join(errs...); err != nil {
		return RunSession{}, false, fmt.Errorf("collection.run %d: %w", st.Key.Seq, err)
	}
	return s, true, nil
}

// recordedRun removes the run's older hold records once the health stream
// holds a record of the run: its collection.run, or the outcome-unknown
// record of a result the node quarantined. Otherwise they stay for the
// start repair.
func (s *Scheduler) recordedRun(ctx context.Context, h *heldRun) {
	if h == nil {
		return
	}
	id := h.run.RequestID
	s.rt.intake.mu.Lock()
	run := s.rt.intake.runs[id]
	var head uint64
	if run != nil {
		head = run.healthHead
	}
	s.rt.intake.mu.Unlock()
	if run == nil {
		return
	}
	if seen, err := s.rt.healthNames(ctx, head, id); err != nil || !seen {
		return
	}
	s.rt.pruneIntake(ctx, id)
}

// pruneIntake removes the hold records of every released run whose
// collection.run committed (recorded names one that just did) or that had
// no result, so no start repair needs them. The series' newest record
// stays, as it carries the open table. A removal that fails raises its
// alarm once and is tried again at the next.
func (r *Runtime) pruneIntake(ctx context.Context, recorded string) {
	ir := &r.intake
	ir.mu.Lock()
	defer ir.mu.Unlock()
	if run := ir.runs[recorded]; run != nil {
		run.recorded = true
	}
	stream := r.intakeStream()
	db := r.Store(stream)
	for _, id := range slices.Sorted(maps.Keys(ir.runs)) {
		run := ir.runs[id]
		if run.newest.State != sensorlink.HoldReleased || (run.newest.Session != nil && !run.recorded) {
			continue
		}
		seqs := slices.DeleteFunc(slices.Clone(run.seqs), func(q c5.Seq) bool { return q == ir.newest })
		for len(seqs) > 0 && db != nil {
			step := seqs[:min(len(seqs), c5.RemoveConfigStep)]
			if _, err := db.RemoveConfig(ctx, stream, c5.SeriesNetCheckpointIntake, step); err != nil {
				if !ir.removing {
					ir.removing = true
					r.opt.Status.Raise(run.newest.Run.AssetID, AlarmIntakeNotRemoved, fmt.Sprintf("run %s's intake hold records %v not removed, so they stay in the configuration class until the next try: %v", id, step, err))
				}
				return
			}
			ir.removing = false
			seqs = seqs[len(step):]
		}
		if db == nil {
			return
		}
		if slices.Contains(run.seqs, ir.newest) {
			run.seqs = []c5.Seq{ir.newest}
			continue
		}
		delete(ir.runs, id)
	}
}

// repairIntake is the start repair (D1 in D4-72, D3's R1 and R2): a run
// whose release committed but whose collection.run did not gets one, from
// the session facts its release record holds, with after_seq the
// observation stream's head now and status RunNotCommitted. It runs once,
// at start, after RecoverHold and before the detector restores. A run is
// repaired only when the audit stream has an allowed collector.request
// for its request after its dispatch, so a repair never invents a run, and
// only when the health stream has no record of the run after its
// dispatch, so a run is repaired at most once.
func (r *Runtime) repairIntake(ctx context.Context) {
	ir := &r.intake
	ir.mu.Lock()
	var todo []string
	for _, id := range slices.Sorted(maps.Keys(ir.runs)) {
		run := ir.runs[id]
		if run.newest.State == sensorlink.HoldReleased && run.newest.Session != nil && !run.recorded {
			todo = append(todo, id)
		}
	}
	ir.mu.Unlock()
	for _, id := range todo {
		ir.mu.Lock()
		run := ir.runs[id]
		rec, healthHead, auditHead := run.newest, run.healthHead, run.auditHead
		ir.mu.Unlock()
		seen, err := r.healthNames(ctx, healthHead, id)
		if err != nil {
			continue // tried again at the next start
		}
		if seen {
			r.pruneIntake(ctx, id)
			continue
		}
		allowed, err := r.allowedRequest(ctx, auditHead, id)
		if err != nil {
			continue
		}
		if allowed == nil {
			ir.mu.Lock()
			ir.repairRefused++
			ir.mu.Unlock()
			r.opt.Status.Raise(rec.Run.AssetID, AlarmIntakeRepairRefused, "run "+id+"'s release committed with no collection.run, and the audit stream has no allowed collector.request for it, so none is written")
			continue
		}
		s := *rec.Session
		openFlow := slices.ContainsFunc(rec.Open, func(o sensorlink.OpenFlow) bool {
			return o.InvocationID == s.InvocationID && o.Key == sensorlink.FlowKey{Node: s.Local, Peer: rec.Run.Endpoint, L4: rec.Run.L4}
		})
		d := sessionDetails(rec.Run, s, sensorlink.Released{AfterSeq: r.lastSeq(ctx, NetObservationStream(r.cfg.NetworkSensor.SensorID)), OpenFlow: openFlow})
		d["asset_id"], d["request_id"], d["invocation_id"] = rec.Run.AssetID, id, s.InvocationID
		d["schedule"], d["operation"] = allowed.Actor.ID, allowed.OperationID
		d["status"], d["events"], d["repaired_from"] = RunNotCommitted, "0", RepairedFromIntake
		hr, err := r.healthRecord(HealthStream, HealthCollectionRun, d)
		log := r.Log(HealthStream)
		if err == nil && log == nil {
			err = errors.New("the health database is not open")
		}
		if err == nil {
			_, err = log.Append(ctx, hr)
		}
		if err != nil {
			r.opt.Status.Raise(rec.Run.AssetID, AlarmEvidenceNotStored, "the repaired collection.run of run "+id+": "+err.Error())
			continue
		}
		ir.mu.Lock()
		ir.repaired++
		ir.mu.Unlock()
		r.pruneIntake(ctx, id)
	}
}

// healthNames reports whether the health stream has a record of the run
// requestID after seq after.
func (r *Runtime) healthNames(ctx context.Context, after uint64, requestID string) (bool, error) {
	db := r.Store(HealthStream)
	if db == nil {
		return false, errors.New("the health database is not open")
	}
	want := []byte(`"request_id":` + strconv.Quote(requestID))
	for {
		got, err := db.Read(ctx, HealthStream, after, 500)
		if err != nil {
			return false, err
		}
		for _, st := range got {
			after = st.Key.Seq
			if !bytes.Contains(st.Event, want) {
				continue
			}
			ev, err := event.Decode(st.Event)
			if err == nil && ev.Health != nil && ev.Health.Details["request_id"] == requestID {
				return true, nil
			}
		}
		if len(got) < 500 {
			return false, nil
		}
	}
}

// allowedRequest is the allowed collector.request record of requestID
// after seq after on the audit stream, or nil.
func (r *Runtime) allowedRequest(ctx context.Context, after uint64, requestID string) (*audit.Record, error) {
	db := r.Store(AuditStream)
	if db == nil {
		return nil, errors.New("the audit database is not open")
	}
	want := []byte(strconv.Quote(requestID))
	for {
		got, err := db.Read(ctx, AuditStream, after, 500)
		if err != nil {
			return nil, err
		}
		for _, st := range got {
			after = st.Key.Seq
			if !bytes.Contains(st.Event, want) {
				continue
			}
			rec, err := audit.ParseRecord(st.Event)
			if err == nil && rec.Action == audit.ActionCollectorRequest && rec.Outcome == audit.OutcomeAllowed && rec.CorrelationID == requestID {
				return rec, nil
			}
		}
		if len(got) < 500 {
			return nil, nil
		}
	}
}
