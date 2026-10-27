package node

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"strconv"
	"sync"
	"time"

	"otsec.local/otsec/contracts/adapter"
	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/audit"
	"otsec.local/otsec/contracts/authz"
	"otsec.local/otsec/contracts/event"
	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/modules/security/collectorclient"
	"otsec.local/otsec/modules/security/collectorwire"
	"otsec.local/otsec/modules/telemetry/normalize"
)

// Collector is the node's side of C7. *collectorclient.Client implements it.
type Collector interface {
	Do(ctx context.Context, req *authz.CollectorRequest) (collectorclient.Response, error)
}

// Health event types the scheduler writes. Each run ends with exactly one
// of them on platform/health; a quarantine also goes to the asset's
// quarantine stream.
const (
	HealthCollectionRun            = "collection.run"
	HealthCollectionRefused        = "collection.refused"
	HealthCollectionNoDecision     = "collection.no-decision"
	HealthCollectionOutcomeUnknown = "collection.outcome-unknown"
	HealthCollectionQuarantined    = "collection.quarantined"
	HealthQuarantineReason         = "collection.quarantine-reason"
)

// QuarantineRoom is the room the adapter-evidence class must have left
// before a run is sent: one outcome frame of the largest size the client
// reads, plus its reason and the two events that name them. A run whose
// outcome could not be quarantined is not sent (A6 on the quarantine plan),
// because the outcome most worth keeping is the one that failed.
const QuarantineRoom = collectorwire.MaxOutcomeBytes + maxReasonBytes + 16<<10

// maxReasonBytes bounds the stored reason of a quarantine. A longer reason
// is cut and says so.
const maxReasonBytes = 16 << 10

// Scheduler runs the configured collections one at a time, so the node
// never holds more than one device session (AP-13, SC-9). Each run is
// audited before it is sent (D1-11), its outcome and audit records are
// committed through C5, and a good result goes to A4's normalizer.
type Scheduler struct {
	rt    *Runtime
	c     Collector
	now   func() time.Time
	newID func() string

	mu     sync.Mutex
	halted map[string]string // asset ID: why its collection is stopped
	node   string            // non-empty: every run on the node is stopped, level 0 included
	quiet  map[string]bool   // alarm codes already raised for the current condition

	susp      map[string]asset.Suspension // asset ID: its suspension (suspend.go)
	through   uint64                      // audit seq the suspensions were loaded through
	unaudited []unaudited                 // suspensions not yet in the audit stream
	fileStale bool                        // the checkpoint does not hold susp
	settleMu  sync.Mutex                  // serializes settle, so records apply once in order
	cs        collectorState              // the collector's keys and numbering (seqreset.go)
	collHold  string                      // why no request is sent to the collector, from collectorHold
	collClear map[string]string           // asset ID: ref of a clear the collector has not accepted (assetclear.go)
	clearFile *clearSuspension            // the clear-suspension.json checkClear last read, nil when none
	results   map[string]AssetResult      // asset ID: its last sent run (results.go)
	quar      map[string]*quarantineEntry // manifest SHA-256: a recorded export (quarantine.go)
	quarDone  map[string]bool             // manifest SHA-256: its range stores nothing now
	relayed   map[string]relayEntry       // request ID: the collector's decision on a relayed admin request (adminrelay.go)
	// adminShown is the admin-request files as status last showed them.
	adminShown []AdminRequestStatus
	// reloadSusp: the suspensions were not loaded because the audit
	// database was not open; reload loads them once it is (P3-A5).
	reloadSusp bool
	// haltUnread: assets held as halted because their quarantine stream
	// could not be read, the evidence database not being open; reload
	// reads it once it is (P3-A5).
	haltUnread map[string]bool
}

// NewScheduler returns a scheduler over rt. It reads every asset's
// quarantine stream first: an asset with a quarantined unauthorized line
// stays stopped across restarts, until an administrator's audited export
// and clear removes it (quarantine.go).
func NewScheduler(ctx context.Context, rt *Runtime, c Collector) (*Scheduler, error) {
	s := &Scheduler{rt: rt, c: c, now: rt.opt.Now, newID: newRequestID, halted: map[string]string{}, quiet: map[string]bool{},
		susp: map[string]asset.Suspension{}, collClear: map[string]string{}, results: map[string]AssetResult{}, haltUnread: map[string]bool{},
		quar: map[string]*quarantineEntry{}, quarDone: map[string]bool{}, relayed: map[string]relayEntry{}}
	if err := s.loadSuspensions(ctx); err != nil {
		// Unknown suspensions: any asset may hold one (A1).
		s.node = AlarmSuspensionsUnknown
		s.reloadSusp = errors.Is(err, errAuditNotOpen)
		rt.opt.Status.Raise("", AlarmSuspensionsUnknown, "suspensions could not be read or rebuilt; every run on this node is stopped: "+err.Error())
	} else {
		// Writes a suspension the checkpoint lists as unaudited, or holds
		// the node until it can.
		s.settle(ctx)
	}
	for _, col := range rt.cfg.Schedule {
		if _, done := s.halted[col.AssetID]; done {
			continue
		}
		halted, err := s.durableHalt(ctx, col.AssetID)
		if err != nil {
			// Unreadable quarantine: the asset may hold a halt, so it is
			// treated as holding one.
			s.haltUnread[col.AssetID] = errors.Is(err, errEvidenceNotOpen)
			halted, err = true, fmt.Errorf("quarantine of %s unreadable: %w", col.AssetID, err)
			rt.opt.Status.Raise(col.AssetID, AlarmCollectionDisabled, err.Error())
		}
		if halted {
			s.halted[col.AssetID] = AlarmUnauthorizedLine
			if err == nil {
				rt.opt.Status.Raise(col.AssetID, AlarmCollectionDisabled, "a quarantined run of this asset sent a line the register does not permit; collection stays stopped")
			}
		}
	}
	// A clear stopped partway holds its asset from the first run on; the
	// ticks finish it from the chain's record (quarantine.go).
	s.refreshQuarantine(ctx)
	s.publishHold()
	return s, nil
}

// publishHold records the node-wide hold in status, so health shows
// whether it is still current.
func (s *Scheduler) publishHold() {
	s.mu.Lock()
	h := s.node
	s.mu.Unlock()
	s.rt.opt.Status.SetRunsHeld(h)
}

// durableHalt reports whether the asset's quarantine stream holds an
// unauthorized-line quarantine.
func (s *Scheduler) durableHalt(ctx context.Context, assetID string) (bool, error) {
	db := s.rt.Store(QuarantineStream(assetID))
	if db == nil {
		return false, errEvidenceNotOpen
	}
	var after c5.Seq
	for {
		got, err := db.Read(ctx, QuarantineStream(assetID), after, 500)
		if err != nil {
			return false, err
		}
		for _, st := range got {
			e, err := event.Decode(st.Event)
			if err != nil {
				return false, err
			}
			if e.Health != nil && e.Health.Type == HealthCollectionQuarantined && e.Health.Details["unauthorized_line"] == "true" {
				return true, nil
			}
			after = st.Key.Seq
		}
		if len(got) < 500 {
			return false, nil
		}
	}
}

func newRequestID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err) // crypto/rand does not fail on supported systems
	}
	return "req-" + hex.EncodeToString(b[:])
}

// Run runs the schedule until ctx ends. The first run of each entry waits
// MinIntervalSeconds after start, so a node that restarts in a loop never
// polls a device faster than the minimum interval. A run that falls behind
// is not repeated to catch up. However the schedule is written, a device
// gets at least MinIntervalSeconds between the end of one session and the
// start of the next (plan). Between runs, and before each, it relays the
// administrator's signed requests every RelayEverySeconds (adminrelay.go).
func (s *Scheduler) Run(ctx context.Context) error {
	var p *plan
	if sched := s.rt.cfg.Schedule; len(sched) > 0 {
		p = newPlan(sched, s.now())
	}
	s.relayAdmin(ctx)
	for {
		wait, run := RelayEverySeconds*time.Second, -1
		if p != nil {
			if i, at := p.due(); at.Sub(s.now()) <= wait {
				wait, run = at.Sub(s.now()), i
			}
		}
		if wait > 0 {
			t := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				t.Stop()
				return ctx.Err()
			case <-t.C:
			}
		} else if err := ctx.Err(); err != nil {
			return err
		}
		s.relayAdmin(ctx)
		if run < 0 {
			continue
		}
		began := s.now()
		s.RunOnce(ctx, run)
		p.done(run, began, s.now())
	}
}

// plan is the scheduler's timetable. Each entry is due one interval after
// its last run began. An asset is also kept quiet for MinIntervalSeconds
// after its last session ended, whichever entry ran it, so two entries for
// one asset, or a run longer than its interval, never poll a device faster
// than the minimum (A6 review of #92).
type plan struct {
	sched   []Collection
	next    []time.Time
	lastEnd map[string]time.Time
}

func newPlan(sched []Collection, start time.Time) *plan {
	p := &plan{sched: sched, next: make([]time.Time, len(sched)), lastEnd: map[string]time.Time{}}
	for i := range p.next {
		p.next[i] = start.Add(MinIntervalSeconds * time.Second)
	}
	return p
}

// due returns the entry to run next and the earliest time it may start.
// Ties go to the entry listed first.
func (p *plan) due() (int, time.Time) {
	best, bestAt := -1, time.Time{}
	for j, c := range p.sched {
		at := p.next[j]
		if end, ok := p.lastEnd[c.AssetID]; ok {
			if quiet := end.Add(MinIntervalSeconds * time.Second); quiet.After(at) {
				at = quiet
			}
		}
		if best < 0 || at.Before(bestAt) {
			best, bestAt = j, at
		}
	}
	return best, bestAt
}

// done records that entry i ran from began to ended.
func (p *plan) done(i int, began, ended time.Time) {
	p.lastEnd[p.sched[i].AssetID] = ended
	p.next[i] = began.Add(time.Duration(p.sched[i].EverySeconds) * time.Second)
}

// Report is what one run did.
type Report struct {
	RequestID string
	// Sent is true when the request left the node, which happens only after
	// its collector.request record holds a receipt.
	Sent bool
	// Decision is the collector's reply status, empty when none was read.
	Decision authz.ReplyStatus
	// Outcome is "ok", "unknown" or "quarantined" for an accepted run.
	Outcome string
	// Events is the number of SER events committed.
	Events int
	// Alarm is the collection alarm the run raised, if any.
	Alarm string
	// Code is the outcome's C2 error code, empty for a run without one.
	Code adapter.Code
	// Refusal is the collector's refusal code for a refused run.
	Refusal string
	// Detail is the error detail of an outcome that passed its checks:
	// the collector's own words, never device text (C2).
	Detail string
}

// RunOnce runs schedule entry i once. Calls must not overlap: the node
// runs its schedule from one goroutine (Run), and a run's suspension
// decisions assume the state no other run is changing.
func (s *Scheduler) RunOnce(ctx context.Context, i int) Report {
	rep := s.runOnce(ctx, i)
	s.publishHold()
	if rep.Sent {
		// The run's records are in the audit stream now. Fold them, so that
		// status shows the collector's numbering after this run, not only
		// before the next one (A6 on #118).
		s.settle(ctx)
		s.recordResult(s.rt.cfg.Schedule[i].AssetID, rep)
		s.rt.opt.Status.Write(string(s.rt.cfg.NodeID))
	}
	return rep
}

func (s *Scheduler) runOnce(ctx context.Context, i int) Report {
	col := s.rt.cfg.Schedule[i]
	s.reload(ctx)
	s.settle(ctx)
	s.checkClear(ctx)
	s.checkAck(ctx)
	s.mu.Lock()
	s.collHold = "" // collectorHold below decides again
	s.mu.Unlock()
	if why := s.stopped(col.AssetID); why != "" {
		return Report{Alarm: AlarmCollectionDisabled}
	}
	if s.suspended(col.AssetID) {
		return Report{Alarm: AlarmAssetSuspended}
	}
	if s.clearing(col.AssetID) {
		return Report{Alarm: AlarmQuarantineClearIncomplete}
	}
	if code, detail := s.collectorHold(ctx); code != "" {
		s.raiseOnceKey("collector "+code, "", code, detail)
		return Report{Alarm: code}
	}
	for _, c := range []string{AlarmInstallKeyUnreadable, AlarmCollectorReset, AlarmCollectorRestored, AlarmAuditUnavailable} {
		s.clearQuietKey("collector " + c)
	}
	if !s.clearAtCollector(ctx, col.AssetID) {
		return Report{Alarm: AlarmCollectorStillSuspended}
	}
	if code, detail := s.cannotKeep(ctx); code != "" {
		s.raiseOnce(col.AssetID, code, detail)
		return Report{Alarm: code}
	}
	s.clearQuiet(col.AssetID)

	rep := Report{RequestID: s.newID()}
	req := s.rt.cfg.runRequest(i, rep.RequestID)
	sent, err := s.requestRecord(req, audit.OutcomeInfo, "", 0)
	if err != nil {
		return s.alarm(ctx, rep, col.AssetID, AlarmAuditUnavailable, "collector.request record: "+err.Error())
	}
	var resp collectorclient.Response
	var doErr error
	err = c5.AuditBeforeAct(ctx, s.rt.Log(AuditStream), sent, func(c5.Receipt) error {
		rep.Sent = true
		resp, doErr = s.c.Do(ctx, req)
		return nil
	})
	if err != nil {
		return s.alarm(ctx, rep, col.AssetID, AlarmAuditUnavailable, "run not sent: "+err.Error())
	}
	rep.Decision = resp.Reply.Status

	switch {
	case resp.Reply.Status == "":
		// No decision was read. If the collector made one, its
		// collector_seq shows as a gap in the chain (VerifyCollectorSeq).
		s.health(ctx, HealthCollectionNoDecision, col, rep.RequestID, "", nil)
		return s.alarm(ctx, rep, col.AssetID, AlarmNoDecision, noDecisionDetail(doErr))
	case !resp.Reply.Accepted():
		code := string(authz.RefuseUnknown)
		if resp.Reply.Refusal != nil {
			code = string(resp.Reply.Refusal.Code.Normalize())
		}
		rep.Refusal = code
		if rec, err := s.requestRecord(req, audit.OutcomeDenied, code, resp.Reply.CollectorSeq); err == nil {
			s.appendAudit(ctx, col.AssetID, append(s.resetFirst(resp.Reply.CollectorSeq), rec))
		} else {
			s.rt.opt.Status.Raise(col.AssetID, AlarmAuditUnavailable, "collector.request denied record: "+err.Error())
		}
		s.health(ctx, HealthCollectionRefused, col, rep.RequestID, "", map[string]string{"refusal": code})
		if s.adopt(ctx, col.AssetID, resp.Reply) {
			rep.Alarm = AlarmAssetSuspended
			return rep
		}
		return s.alarm(ctx, rep, col.AssetID, AlarmCollectorRefused, "collector refused the run: "+code)
	}

	// Accepted: the decision, then every collector-reported record the
	// node holds, in one audit batch, whatever happens to the outcome.
	// A reply numbered at or below the epoch's high, from a collector whose
	// key changed since the check before the request, is a reset; its
	// record goes first (seqreset.go).
	recs := s.resetFirst(resp.Reply.CollectorSeq)
	if rec, err := s.requestRecord(req, audit.OutcomeAllowed, "", resp.Reply.CollectorSeq); err == nil {
		recs = append(recs, rec)
	} else {
		s.rt.opt.Status.Raise(col.AssetID, AlarmAuditUnavailable, "collector.request allowed record: "+err.Error())
	}
	var pending []collectorclient.PendingRecord
	switch {
	case resp.Outcome != nil:
		pending = resp.Outcome.Audit
	case resp.Quarantine != nil:
		pending = resp.Quarantine.Audit
	}
	for _, p := range pending {
		recs = append(recs, c5.Record{Stream: AuditStream, Class: c5.ClassAudit, Event: p.Raw})
	}
	if len(recs) > 0 {
		s.appendAudit(ctx, col.AssetID, recs)
	}
	inv := resp.Reply.InvocationID
	// The outcome code's suspension is recorded before anything else is
	// decided, whatever becomes of the outcome (A1).
	rep.Code = outcomeCode(resp)
	s.suspend(ctx, col.AssetID, inv, rep.Code)

	switch {
	case resp.Quarantine != nil:
		rep.Outcome = "quarantined"
		q := resp.Quarantine
		code := AlarmOutcomeUnknown
		if q.UnauthorizedLine || errors.Is(doErr, collectorclient.ErrUnauthorizedLine) {
			code = AlarmUnauthorizedLine
		}
		s.quarantine(ctx, rep, col, inv, q.Raw, q.Reason, code == AlarmUnauthorizedLine)
		s.health(ctx, HealthCollectionOutcomeUnknown, col, rep.RequestID, inv, map[string]string{"quarantined": "true"})
		if code == AlarmUnauthorizedLine {
			s.halt(col.AssetID)
			return s.alarm(ctx, rep, col.AssetID, code, "the outcome holds a line the node's register does not permit for this run; outcome quarantined, collection from this asset stopped")
		}
		return s.alarm(ctx, rep, col.AssetID, code, "the outcome failed verification and was quarantined")
	case resp.Outcome == nil:
		rep.Outcome = "unknown"
		s.health(ctx, HealthCollectionOutcomeUnknown, col, rep.RequestID, inv, nil)
		return s.alarm(ctx, rep, col.AssetID, AlarmOutcomeUnknown, "no outcome arrived for the accepted run")
	}
	rep.Outcome = "ok"
	return s.commitResult(ctx, rep, col, resp.Outcome)
}

// commitResult normalizes a checked outcome and commits it: the SER events
// with their capture and alignment state in one batch, then the health
// events, then, for a read that changed the state without adding events,
// the state on its own (A4's order).
func (s *Scheduler) commitResult(ctx context.Context, rep Report, col Collection, o *collectorclient.Outcome) Report {
	a, _ := s.rt.cfg.Asset(col.AssetID)
	stream := SERStream(col.AssetID)
	db := s.rt.Store(stream)
	cursor, err := db.SourceCursor(ctx, stream)
	if err != nil {
		return s.alarm(ctx, rep, col.AssetID, AlarmEvidenceNotStored, "read the alignment state: "+err.Error())
	}
	var prev []string
	if cursor != nil {
		if prev, err = normalize.DecodeState(cursor); err != nil {
			return s.alarm(ctx, rep, col.AssetID, AlarmEvidenceNotStored, "alignment state unreadable: "+err.Error())
		}
	}
	profile := ""
	if a.Profile != nil {
		profile = a.Profile.ID
	}
	inv := adapter.Invocation{InvocationID: o.InvocationID, PrincipalRef: col.ID, AssetID: col.AssetID, EndpointID: col.Endpoint,
		ProfileID: profile, OperationID: col.Operation, Params: col.Params, CredentialRef: col.CredentialRef}
	rx := s.rt.received()
	out, err := normalize.Normalize(o.Result, inv, a, normalize.Input{Node: s.rt.cfg.NodeID, Stream: event.Stream(stream),
		HealthStream: event.Stream(HealthStream), ClockResolutionNS: rx.ResolutionNS, Clock: rx.Clock, Prev: prev})
	if err != nil {
		// A refused result is kept as quarantine, never as events.
		rep.Outcome = "quarantined"
		s.quarantine(ctx, rep, col, o.InvocationID, o.ResultJSON, err.Error(), false)
		s.health(ctx, HealthCollectionOutcomeUnknown, col, rep.RequestID, o.InvocationID, map[string]string{"quarantined": "true"})
		return s.alarm(ctx, rep, col.AssetID, AlarmResultRefused, "the normalizer refused the result; kept as quarantine")
	}
	// The detail is kept only once the result has passed every check,
	// the collector's and the normalizer's (A1 and A3 on #136).
	if o.Result.Error != nil {
		rep.Detail = o.Result.Error.Detail
	}
	ser, hl, err := out.Records(event.Stream(stream), event.Stream(HealthStream))
	if err != nil {
		return s.alarm(ctx, rep, col.AssetID, AlarmEvidenceNotStored, err.Error())
	}
	carried := len(out.Capture.Bytes) == 0
	for _, r := range append(append([]c5.Record{}, ser...), hl...) {
		carried = carried || r.Capture != nil
	}
	run, err := s.runRecord(HealthStream, HealthCollectionRun, col, rep.RequestID, o.InvocationID, map[string]string{
		"status": string(o.Result.Status), "events": strconv.Itoa(len(ser)),
	})
	if err != nil {
		return s.alarm(ctx, rep, col.AssetID, AlarmEvidenceNotStored, err.Error())
	}
	if !carried {
		// A read that added nothing still keeps its transcript, which the
		// session close record names (D1-25).
		c := out.Capture
		run.Capture = &c
	}
	hl = append(hl, run)

	log := s.rt.Log(stream)
	if log == nil {
		return s.alarm(ctx, rep, col.AssetID, AlarmEvidenceNotStored, "evidence database not open")
	}
	if len(ser) > 0 {
		if _, err := log.AppendBatch(ctx, ser); err != nil {
			return s.alarm(ctx, rep, col.AssetID, AlarmEvidenceNotStored, "SER events: "+err.Error())
		}
		rep.Events = len(ser)
	}
	if _, err := log.AppendBatch(ctx, hl); err != nil {
		return s.alarm(ctx, rep, col.AssetID, AlarmEvidenceNotStored, "health events: "+err.Error())
	}
	if len(ser) == 0 && out.StateChanged {
		b, err := normalize.EncodeState(out.State)
		if err == nil {
			err = db.SaveSourceCursor(ctx, stream, b)
		}
		if err != nil {
			return s.alarm(ctx, rep, col.AssetID, AlarmEvidenceNotStored, "alignment state: "+err.Error())
		}
	}
	return rep
}

// quarantine commits evidence that is not a result, on the asset's
// quarantine stream, in one batch: the bytes exactly as received, then the
// reason, each as the capture of its own event. The reason can quote a
// device line, so it is kept here and never in status or a log. If the
// batch cannot be committed, every run on the node stops, level 0 included,
// because evidence of a failed run would otherwise be lost.
func (s *Scheduler) quarantine(ctx context.Context, rep Report, col Collection, invocationID string, raw []byte, reason string, unauthorized bool) {
	if len(reason) > maxReasonBytes {
		reason = reason[:maxReasonBytes] + " [cut at 16 KiB]"
	}
	stream := QuarantineStream(col.AssetID)
	ref := c5.EvidenceRef(digest(raw))
	frame, err := s.runRecord(stream, HealthCollectionQuarantined, col, rep.RequestID, invocationID, map[string]string{
		"unauthorized_line": strconv.FormatBool(unauthorized), "frame": ref,
	})
	var why c5.Record
	if err == nil {
		frame.Capture = &c5.Capture{SHA256: digest(raw), Bytes: raw}
		why, err = s.runRecord(stream, HealthQuarantineReason, col, rep.RequestID, invocationID, map[string]string{"frame": ref})
		why.Capture = &c5.Capture{SHA256: digest([]byte(reason)), Bytes: []byte(reason)}
	}
	if err == nil {
		if log := s.rt.Log(stream); log == nil {
			err = errors.New("evidence database not open")
		} else {
			_, err = log.AppendBatch(ctx, []c5.Record{frame, why})
		}
	}
	if err != nil {
		s.mu.Lock()
		s.node = AlarmQuarantineNotStored
		s.mu.Unlock()
		s.rt.opt.Status.Raise(col.AssetID, AlarmQuarantineNotStored, "quarantine not stored; every run on this node is stopped: "+err.Error())
		s.rt.audit(ctx, audit.ActionPolicyApply, audit.OutcomeFailed, "quarantine_not_stored", "quarantine of asset "+col.AssetID+" not stored; collection stopped on this node")
	}
}

func digest(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// runRecord is a health event about one run of col, on stream.
func (s *Scheduler) runRecord(stream c5.StreamID, typ string, col Collection, requestID, invocationID string, extra map[string]string) (c5.Record, error) {
	d := map[string]string{"asset_id": col.AssetID, "schedule": col.ID, "operation": col.Operation, "request_id": requestID}
	if invocationID != "" {
		d["invocation_id"] = invocationID
	}
	maps.Copy(d, extra)
	return s.rt.healthRecord(stream, typ, d)
}

// health commits a run health event, best effort: a failure is a store
// alarm, which status already holds.
func (s *Scheduler) health(ctx context.Context, typ string, col Collection, requestID, invocationID string, extra map[string]string) {
	rec, err := s.runRecord(HealthStream, typ, col, requestID, invocationID, extra)
	if log := s.rt.Log(HealthStream); err == nil && log != nil {
		_, err = log.Append(ctx, rec)
	}
	if err != nil {
		s.rt.opt.Status.Raise(col.AssetID, AlarmEvidenceNotStored, typ+": "+err.Error())
	}
}

// requestRecord is the C8 collector.request record of req, a run or an
// asset clear: info before it is sent, then allowed or denied with the
// collector's number.
func (s *Scheduler) requestRecord(req *authz.CollectorRequest, outcome audit.Outcome, reason string, seq uint64) (c5.Record, error) {
	rec := audit.Record{Contract: audit.ContractID, NodeID: string(s.rt.cfg.NodeID), Time: s.rt.received(),
		Actor:  audit.Actor{Type: req.OnBehalfOf.Type, ID: req.OnBehalfOf.ID, Role: authz.RoleCollector},
		Action: audit.ActionCollectorRequest, Outcome: outcome, ReasonCode: reason,
		PolicyVersion: req.PolicyVersion, CorrelationID: req.RequestID, CollectorSeq: seq}
	switch {
	case req.Run != nil:
		rec.Target = &audit.Target{AssetID: req.Run.AssetID, CredentialRef: req.Run.CredentialRef}
		rec.OperationID, rec.RegisterRevision = req.Run.OperationID, req.Run.RegisterVersion
	case req.AssetClearSusp != nil:
		rec.Target = &audit.Target{AssetID: req.AssetClearSusp.AssetID}
		rec.Detail = "asset.clear_suspension of suspension " + req.AssetClearSusp.Ref
	}
	b, err := json.Marshal(rec)
	if err != nil {
		return c5.Record{}, err
	}
	if _, err := audit.ValidatePending(b); err != nil {
		return c5.Record{}, err
	}
	return c5.Record{Stream: AuditStream, Class: c5.ClassAudit, Event: b}, nil
}

func (s *Scheduler) appendAudit(ctx context.Context, assetID string, recs []c5.Record) {
	log := s.rt.Log(AuditStream)
	if log == nil {
		s.rt.opt.Status.Raise(assetID, AlarmAuditUnavailable, "audit database not open; collector records not written")
		return
	}
	if _, err := log.AppendBatch(ctx, recs); err != nil {
		s.rt.opt.Status.Raise(assetID, AlarmAuditUnavailable, fmt.Sprintf("%d collector records not written: %v", len(recs), err))
	}
}

func (s *Scheduler) alarm(ctx context.Context, rep Report, assetID, code, detail string) Report {
	rep.Alarm = code
	s.rt.opt.Status.Raise(assetID, code, detail)
	s.rt.opt.Status.Write(string(s.rt.cfg.NodeID))
	return rep
}

func (s *Scheduler) halt(assetID string) {
	s.mu.Lock()
	s.halted[assetID] = AlarmUnauthorizedLine
	s.mu.Unlock()
}

func (s *Scheduler) stopped(assetID string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.node != "" {
		return s.node
	}
	if s.collHold != "" {
		return s.collHold
	}
	return s.halted[assetID]
}

// Halted reports why collection from the asset is stopped, empty if it is
// not.
func (s *Scheduler) Halted(assetID string) string { return s.stopped(assetID) }

// cannotKeep reports why a run's outcome could not be kept, if it could
// not: the evidence database does not accept events, or the adapter
// evidence class has less than QuarantineRoom left once confirmed events
// are pruned (Prune). It raises AlarmQuarantineRoomLow once when the class
// holds WarnFraction of what runs may use, so the warning comes before
// runs stop whatever the quota (A6, V-S9).
func (s *Scheduler) cannotKeep(ctx context.Context) (code, detail string) {
	if m := s.rt.Mode(EvidenceDB); !m.AcceptsEvents() {
		return AlarmEvidenceNotStored, "evidence database is " + string(m) + "; runs are not sent"
	}
	quota := s.rt.cfg.Store.Quotas[string(c5.ClassAdapterEvidence)]
	used, err := s.evidenceBytes(ctx)
	if err == nil && used+QuarantineRoom > quota {
		s.rt.Prune(ctx)
		used, err = s.evidenceBytes(ctx)
	}
	if err != nil {
		return AlarmEvidenceNotStored, "adapter-evidence usage unreadable: " + err.Error()
	}
	if room := quota - QuarantineRoom; float64(used) >= s.rt.cfg.Store.WarnFraction*float64(room) {
		s.raiseOnceKey("quarantine room low", "", AlarmQuarantineRoomLow, fmt.Sprintf("adapter-evidence holds %d bytes; runs stop at %d (the quota %d less %d for a quarantine) while its events are not confirmed upstream", used, room, quota, QuarantineRoom))
	} else {
		s.clearQuietKey("quarantine room low")
	}
	if used+QuarantineRoom > quota {
		return AlarmNoQuarantineRoom, fmt.Sprintf("adapter-evidence holds %d of %d bytes, less than %d left for a quarantine, after confirmed events were pruned; runs are not sent until more are confirmed upstream", used, quota, QuarantineRoom)
	}
	return "", ""
}

func (s *Scheduler) evidenceBytes(ctx context.Context) (int64, error) {
	db := s.rt.Store(HealthStream)
	if db == nil {
		return 0, errors.New("evidence database not open")
	}
	return db.ClassBytes(ctx, c5.ClassAdapterEvidence)
}

// raiseOnce raises a skip alarm once per condition, not once per run.
func (s *Scheduler) raiseOnce(assetID, code, detail string) {
	s.raiseOnceKey(assetID+" "+code, assetID, code, detail)
}

// raiseOnceKey is raiseOnce for a condition named by k.
func (s *Scheduler) raiseOnceKey(k, assetID, code, detail string) {
	s.mu.Lock()
	seen := s.quiet[k]
	s.quiet[k] = true
	s.mu.Unlock()
	if !seen {
		s.rt.opt.Status.Raise(assetID, code, detail)
		s.rt.opt.Status.Write(string(s.rt.cfg.NodeID))
	}
}

func (s *Scheduler) clearQuietKey(k string) {
	s.mu.Lock()
	delete(s.quiet, k)
	s.mu.Unlock()
}

func (s *Scheduler) clearQuiet(assetID string) {
	s.mu.Lock()
	for _, c := range []string{AlarmEvidenceNotStored, AlarmNoQuarantineRoom} {
		delete(s.quiet, assetID+" "+c)
	}
	s.mu.Unlock()
}

// noDecisionDetail names the kind of failure without quoting the reply,
// which came from the other side of the boundary.
func noDecisionDetail(err error) string {
	switch {
	case err == nil:
		return "no reply"
	case errors.Is(err, collectorclient.ErrProtocol):
		return "the collector's reply breaks C7"
	case errors.Is(err, collectorwire.ErrPeerRefused):
		return "the collector's identity was refused"
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return "no reply before the deadline"
	}
	return "no reply: " + err.Error()
}

// runRequest is the C7 run request of schedule entry i.
func (c *Config) runRequest(i int, requestID string) *authz.CollectorRequest {
	s := c.Schedule[i]
	params := maps.Clone(s.Params)
	if params == nil {
		params = map[string]string{}
	}
	return &authz.CollectorRequest{Contract: authz.ContractID, Kind: authz.KindRun, RequestID: requestID,
		OnBehalfOf:    authz.Principal{Type: authz.PrincipalSchedule, ID: s.ID},
		PolicyVersion: c.PolicyVersion,
		Run: &authz.RunBody{AssetID: s.AssetID, OperationID: s.Operation, Params: params,
			CredentialRef: s.CredentialRef, RegisterVersion: c.RegisterVersion}}
}
