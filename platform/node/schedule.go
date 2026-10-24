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
	node   string            // non-empty: every credentialed run is stopped
	quiet  map[string]bool   // alarm codes already raised for the current condition
}

// NewScheduler returns a scheduler over rt. It reads every asset's
// quarantine stream first: an asset with a quarantined unauthorized line
// stays stopped across restarts, until an audited operator action clears
// it (not in Phase 2).
func NewScheduler(ctx context.Context, rt *Runtime, c Collector) (*Scheduler, error) {
	s := &Scheduler{rt: rt, c: c, now: rt.opt.Now, newID: newRequestID, halted: map[string]string{}, quiet: map[string]bool{}}
	for _, col := range rt.cfg.Schedule {
		if _, done := s.halted[col.AssetID]; done {
			continue
		}
		halted, err := s.durableHalt(ctx, col.AssetID)
		if err != nil {
			// Unreadable quarantine: the asset may hold a halt, so it is
			// treated as holding one.
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
	return s, nil
}

// durableHalt reports whether the asset's quarantine stream holds an
// unauthorized-line quarantine.
func (s *Scheduler) durableHalt(ctx context.Context, assetID string) (bool, error) {
	db := s.rt.Store(QuarantineStream(assetID))
	if db == nil {
		return false, errors.New("evidence database not open")
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
// is not repeated to catch up: the next run is one interval after the last
// one started, or now if that has passed.
func (s *Scheduler) Run(ctx context.Context) error {
	sched := s.rt.cfg.Schedule
	if len(sched) == 0 {
		<-ctx.Done()
		return ctx.Err()
	}
	next := make([]time.Time, len(sched))
	start := s.now()
	for i := range next {
		next[i] = start.Add(MinIntervalSeconds * time.Second)
	}
	for {
		i := 0
		for j := range next {
			if next[j].Before(next[i]) {
				i = j
			}
		}
		if d := next[i].Sub(s.now()); d > 0 {
			t := time.NewTimer(d)
			select {
			case <-ctx.Done():
				t.Stop()
				return ctx.Err()
			case <-t.C:
			}
		}
		began := s.now()
		s.RunOnce(ctx, i)
		next[i] = began.Add(time.Duration(sched[i].EverySeconds) * time.Second)
		if now := s.now(); next[i].Before(now) {
			next[i] = now
		}
	}
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
}

// RunOnce runs schedule entry i once.
func (s *Scheduler) RunOnce(ctx context.Context, i int) Report {
	col := s.rt.cfg.Schedule[i]
	if why := s.stopped(col.AssetID); why != "" {
		return Report{Alarm: AlarmCollectionDisabled}
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
		if rec, err := s.requestRecord(req, audit.OutcomeDenied, code, resp.Reply.CollectorSeq); err == nil {
			s.appendAudit(ctx, col.AssetID, []c5.Record{rec})
		} else {
			s.rt.opt.Status.Raise(col.AssetID, AlarmAuditUnavailable, "collector.request denied record: "+err.Error())
		}
		s.health(ctx, HealthCollectionRefused, col, rep.RequestID, "", map[string]string{"refusal": code})
		return s.alarm(ctx, rep, col.AssetID, AlarmCollectorRefused, "collector refused the run: "+code)
	}

	// Accepted: the decision, then every collector-reported record the
	// node holds, in one audit batch, whatever happens to the outcome.
	recs := []c5.Record{}
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
		return s.alarm(ctx, rep, col.AssetID, AlarmResultRefused, "the normalizer refused the result; kept as quarantine")
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
// batch cannot be committed, every credentialed run on the node stops,
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
		s.rt.opt.Status.Raise(col.AssetID, AlarmQuarantineNotStored, "quarantine not stored; every credentialed run on this node is stopped: "+err.Error())
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

// requestRecord is the C8 collector.request record of req: info before it
// is sent, then allowed or denied with the collector's number.
func (s *Scheduler) requestRecord(req *authz.CollectorRequest, outcome audit.Outcome, reason string, seq uint64) (c5.Record, error) {
	rec := audit.Record{Contract: audit.ContractID, NodeID: string(s.rt.cfg.NodeID), Time: s.rt.received(),
		Actor:  audit.Actor{Type: req.OnBehalfOf.Type, ID: req.OnBehalfOf.ID, Role: authz.RoleCollector},
		Action: audit.ActionCollectorRequest, Outcome: outcome, ReasonCode: reason,
		Target:      &audit.Target{AssetID: req.Run.AssetID, CredentialRef: req.Run.CredentialRef},
		OperationID: req.Run.OperationID, RegisterRevision: req.Run.RegisterVersion, PolicyVersion: req.PolicyVersion,
		CorrelationID: req.RequestID, CollectorSeq: seq}
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
	return s.halted[assetID]
}

// Halted reports why collection from the asset is stopped, empty if it is
// not.
func (s *Scheduler) Halted(assetID string) string { return s.stopped(assetID) }

// cannotKeep reports why a run's outcome could not be kept, if it could
// not: the evidence database does not accept events, or the adapter
// evidence class has less than QuarantineRoom left.
func (s *Scheduler) cannotKeep(ctx context.Context) (code, detail string) {
	if m := s.rt.Mode(EvidenceDB); !m.AcceptsEvents() {
		return AlarmEvidenceNotStored, "evidence database is " + string(m) + "; runs are not sent"
	}
	db := s.rt.Store(HealthStream)
	used, err := db.ClassBytes(ctx, c5.ClassAdapterEvidence)
	if err != nil {
		return AlarmEvidenceNotStored, "adapter-evidence usage unreadable: " + err.Error()
	}
	if quota := s.rt.cfg.Store.Quotas[string(c5.ClassAdapterEvidence)]; used+QuarantineRoom > quota {
		return AlarmNoQuarantineRoom, fmt.Sprintf("adapter-evidence holds %d of %d bytes, less than %d left for a quarantine; runs are not sent", used, quota, QuarantineRoom)
	}
	return "", ""
}

// raiseOnce raises a skip alarm once per condition, not once per run.
func (s *Scheduler) raiseOnce(assetID, code, detail string) {
	s.mu.Lock()
	k := assetID + " " + code
	seen := s.quiet[k]
	s.quiet[k] = true
	s.mu.Unlock()
	if !seen {
		s.rt.opt.Status.Raise(assetID, code, detail)
		s.rt.opt.Status.Write(string(s.rt.cfg.NodeID))
	}
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
