package node

import (
	"context"
	"errors"
	"fmt"
	"time"

	"otsec.local/otsec/contracts/audit"
	"otsec.local/otsec/contracts/authz"
	"otsec.local/otsec/contracts/baseline"
	"otsec.local/otsec/contracts/config"
	c5 "otsec.local/otsec/contracts/store"
)

// The node's part of the two configuration kinds (C7 0.6, C8 0.5; the
// interface agreed with C3 on #381). The collector verified the signature,
// the key's kinds and the approval's window, spent the nonce and numbered
// the decision. The node then records what a person decided, once:
//
//   - node.change_approval: config.change_approved, succeeded when the
//     baseline it names is the asset's acknowledged configuration baseline,
//     else denied ReasonBaselineNotAcknowledged. The configuration-read
//     writer folds a succeeded one from the chain (configchain.go).
//   - node.baseline_ack: config.baseline_acknowledged, succeeded when the
//     asset's configuration stream holds a baseline of the kind whose
//     stored bytes have the digest (a C9 snapshot of the asset for kind
//     configuration, a C10 baseline of the asset for kind event), and for
//     an event baseline when it is the one recorded and awaiting
//     acknowledgement; else denied ReasonBaselineNotHeld or
//     ReasonBaselineNotNext. A succeeded one names the baseline it replaces
//     as previous_digest. Right after its receipt the node takes the holds
//     it justifies (the new baseline held, the one it replaces held as
//     superseded, and, for a configuration baseline, the changes it ends
//     held as acknowledged), and an event baseline goes to the lifecycle,
//     which activates it.
//
// decision_seq is the collector_seq of the first acceptance (its repeat_of
// on a repeat answer). The record's payload_sha256 is the verified one, so
// the node knows from the chain which requests it has recorded and does
// not record one twice. An acknowledgement of the baseline that is already
// the asset's is nothing to do, and is not recorded (previous_digest would
// name itself).

// Reason codes of the node's denied configuration records.
const (
	// ReasonBaselineNotHeld: the asset's configuration stream holds no
	// baseline of the kind whose stored bytes have the digest.
	ReasonBaselineNotHeld = "baseline_not_held"
	// ReasonBaselineNotNext: an event baseline that is not the one the
	// node recorded and awaits acknowledgement of (B4 on #250).
	ReasonBaselineNotNext = "baseline_not_next"
	// ReasonBaselineNotAcknowledged: an approval against a baseline that is
	// not the asset's acknowledged configuration baseline.
	ReasonBaselineNotAcknowledged = "baseline_not_acknowledged"
)

// applyConfigPart does the node's part of an accepted node.change_approval
// or node.baseline_ack, from p, the payload the collector verified, with
// settleMu held and the chain folded.
func (s *Scheduler) applyConfigPart(ctx context.Context, f *adminFile, e relayEntry, p *authz.AdminRequest) adminPart {
	ch := s.configChain()
	if err := ch.sync(ctx, s.rt.Store(AuditStream)); err != nil {
		return adminPart{state: partPending, detail: "the audit stream could not be read: " + err.Error()}
	}
	sum := e.Verified.PayloadSHA256
	if o, ok := ch.parts[sum]; ok {
		return recordedPart(o)
	}
	if o, ok := s.configParts[sum]; ok {
		return recordedPart(o)
	}
	decision := e.CollectorSeq
	if e.RepeatOf != 0 {
		decision = e.RepeatOf
	}
	var (
		rec     *audit.Record
		assetID string
		kind    authz.BaselineKind
		why     string
	)
	switch p.Kind {
	case authz.KindNodeChangeApproval:
		b := p.NodeChangeApproval
		if b == nil || b.Validate() != nil {
			return s.notApplied(f, "the accepted payload has no valid node_change_approval body")
		}
		assetID = b.AssetID
		st := ch.asset(assetID)
		if err := ch.findBaseline(ctx, st, assetID); err != nil {
			return adminPart{state: partPending, detail: "the asset's held baseline could not be read: " + err.Error()}
		}
		reason := ""
		if st.baseline != b.BaselineDigest {
			reason, why = ReasonBaselineNotAcknowledged, fmt.Sprintf("baseline %s is not the asset's acknowledged configuration baseline (%s)", b.BaselineDigest, digestOrNone(st.baseline))
		}
		rec = s.decisionRecord(f, e, audit.ActionConfigChangeApproved, reason, assetID, &audit.Config{DecisionSeq: decision, PayloadSHA256: sum,
			BaselineDigest: b.BaselineDigest, WindowStart: b.WindowStart, WindowEnd: b.WindowEnd, Reason: b.Reason})
	case authz.KindNodeBaselineAck:
		b := p.NodeBaselineAck
		if b == nil || b.Validate() != nil {
			return s.notApplied(f, "the accepted payload has no valid node_baseline_ack body")
		}
		assetID, kind = b.AssetID, b.Kind
		previous, reason, detail, err := s.ackCheck(ctx, ch, b)
		if err != nil {
			return adminPart{state: partPending, detail: err.Error()}
		}
		if reason == "" && previous == b.BaselineDigest {
			return adminPart{state: partNothing, detail: b.BaselineDigest + " is already the asset's " + string(b.Kind) + " baseline"}
		}
		why = detail
		if reason != "" {
			previous = ""
		}
		rec = s.decisionRecord(f, e, audit.ActionConfigBaselineAcknowledge, reason, assetID, &audit.Config{DecisionSeq: decision, PayloadSHA256: sum,
			Kind: b.Kind, BaselineDigest: b.BaselineDigest, PreviousDigest: previous})
	default:
		return s.notApplied(f, "the node does no part of "+string(p.Kind))
	}
	ref, err := s.appendConfigRecord(ctx, rec)
	if err != nil {
		return adminPart{state: partPending, detail: string(rec.Action) + " not written: " + err.Error()}
	}
	s.configParts[sum] = rec.Outcome
	if rec.Outcome == audit.OutcomeDenied {
		return s.neverApplied(f, why+"; recorded as denied "+rec.ReasonCode+". Sign the request again once it applies")
	}
	if rec.Action == audit.ActionConfigBaselineAcknowledge {
		s.holdAcknowledged(ctx, assetID, ref)
		if kind == authz.BaselineEvent && s.events != nil {
			at, _ := time.Parse(time.RFC3339Nano, rec.Time.UTC)
			s.events.life.acknowledged(assetID, rec.Config.BaselineDigest, at)
		}
	}
	return adminPart{state: partDone}
}

func recordedPart(o audit.Outcome) adminPart {
	if o == audit.OutcomeDenied {
		return adminPart{state: partRefused, detail: "recorded as denied in the audit stream"}
	}
	return adminPart{state: partDone}
}

func digestOrNone(d string) string {
	if d == "" {
		return "none acknowledged"
	}
	return d
}

// ackCheck decides an acknowledgement: the baseline it replaces, or a
// denial's reason code with its explanation. An error is a store that
// could not be read, so nothing is decided yet.
func (s *Scheduler) ackCheck(ctx context.Context, ch *configChain, b *authz.NodeBaselineAckBody) (previous, reason, why string, err error) {
	notHeld := func(what string) (string, string, string, error) {
		return "", ReasonBaselineNotHeld, fmt.Sprintf("the node holds no %s baseline %s of asset %s: %s", b.Kind, b.BaselineDigest, b.AssetID, what), nil
	}
	if _, ok := s.rt.cfg.Asset(b.AssetID); !ok {
		return notHeld("the asset is not in the node's configuration")
	}
	stream := ConfigStream(b.AssetID)
	db := s.rt.Store(stream)
	if db == nil {
		return notHeld("the node has no configuration stream for it")
	}
	found, err := locate(ctx, db, stream, map[string]bool{b.BaselineDigest: true})
	if err != nil {
		return "", "", "", fmt.Errorf("the configuration stream could not be read: %w", err)
	}
	seq, ok := found[b.BaselineDigest]
	if !ok {
		return notHeld("no stored record has that digest")
	}
	got, err := db.Read(ctx, stream, seq-1, 1)
	if err != nil || len(got) != 1 {
		return "", "", "", fmt.Errorf("the configuration stream could not be read: %v", errors.Join(err, errors.New("record not returned")))
	}
	doc := got[0].Event
	switch b.Kind {
	case authz.BaselineConfiguration:
		snap, err := config.DecodeSnapshot(doc)
		if err != nil || snap.AssetID != b.AssetID {
			return notHeld("the record with that digest is not a configuration snapshot of the asset")
		}
		st := ch.asset(b.AssetID)
		if err := ch.findBaseline(ctx, st, b.AssetID); err != nil {
			return "", "", "", fmt.Errorf("the asset's held baseline could not be read: %w", err)
		}
		return st.baseline, "", "", nil
	case authz.BaselineEvent:
		bl, err := baseline.Decode(doc)
		if err != nil || bl.AssetID != b.AssetID {
			return notHeld("the record with that digest is not an event baseline of the asset")
		}
		active, recorded := s.eventBaselines(b.AssetID)
		if active == b.BaselineDigest {
			return active, "", "", nil
		}
		if recorded != b.BaselineDigest {
			return "", ReasonBaselineNotNext, fmt.Sprintf("event baseline %s is not the one recorded and awaiting acknowledgement (%s)", b.BaselineDigest, digestOrNone(recorded)), nil
		}
		return active, "", "", nil
	}
	return notHeld("unknown kind")
}

// eventBaselines are the asset's active event baseline and the one
// recorded and awaiting acknowledgement, each "" when none is.
func (s *Scheduler) eventBaselines(assetID string) (active, recorded string) {
	if s.events == nil {
		return "", ""
	}
	a := s.events.life.asset(assetID)
	if a == nil {
		return "", ""
	}
	if !a.unrecorded {
		recorded = a.recordedHash
	}
	return a.active, recorded
}

// decisionRecord is the node's C8 record of a person's decision: the actor
// is the verified person, the outcome succeeded, or denied with reason.
func (s *Scheduler) decisionRecord(f *adminFile, e relayEntry, action audit.Action, reason, assetID string, c *audit.Config) *audit.Record {
	outcome := audit.OutcomeSucceeded
	if reason != "" {
		outcome = audit.OutcomeDenied
	}
	return &audit.Record{Contract: audit.ContractID, NodeID: string(s.rt.cfg.NodeID), Time: s.rt.received(),
		Actor:  audit.Actor{Type: authz.PrincipalHuman, ID: e.Verified.Principal, Role: authz.RoleAdmin},
		Action: action, Outcome: outcome, ReasonCode: reason, Target: &audit.Target{AssetID: assetID}, CorrelationID: f.id,
		Detail: fmt.Sprintf("%s (signed by %s, collector_seq %d)", f.name, e.Verified.Principal, e.CollectorSeq), Config: c}
}

// holdAcknowledged takes, right after an acknowledgement's receipt (ref),
// the holds the chain now justifies in the asset's configuration stream:
// what reconcileHolds would add or correct, without its alarms, which are
// for a crash or tampering. A hold not taken raises AlarmEvidenceNotStored;
// the next start's reconcile takes it, and until then HoldsConsumer keeps
// the acknowledgement from being pruned.
func (s *Scheduler) holdAcknowledged(ctx context.Context, assetID string, ref c5.Seq) {
	stream := ConfigStream(assetID)
	fail := func(err error) {
		s.rt.opt.Status.Raise(assetID, AlarmEvidenceNotStored, fmt.Sprintf("the holds of the acknowledgement (audit record %d) not taken in %s: %v; the next start's reconcile takes them", ref, stream, err))
	}
	adb, cdb := s.rt.Store(AuditStream), s.rt.Store(stream)
	if adb == nil || cdb == nil {
		fail(errors.New("database not open"))
		return
	}
	if err := holdFault(holdFaults.ack); err != nil {
		fail(err)
		return
	}
	recs, err := configAuditRecords(ctx, adb)
	if err != nil {
		fail(err)
		return
	}
	pruned, err := auditPruned(ctx, adb)
	if err != nil {
		fail(err)
		return
	}
	p, err := s.rt.planStream(ctx, cdb, stream, foldHolds(recs)[assetID])
	if err != nil {
		fail(err)
		return
	}
	replace := p.replace
	if pruned {
		replace = prunedReplace(replace)
	}
	todo := append(p.add, replace...)
	for _, pl := range todo {
		if err := cdb.Hold(ctx, c5.Hold{Stream: stream, Seq: pl.seq, Reason: reasonOf(s.rt.cfg.NodeID, pl.w)}); err != nil {
			fail(err)
		}
	}
	for _, w := range p.missing {
		s.rt.opt.Status.Raise(assetID, AlarmBaselineNotStored, fmt.Sprintf("%s (%s) is not in stream %s, so nothing holds it", w.why, w.digest, stream))
	}
}
