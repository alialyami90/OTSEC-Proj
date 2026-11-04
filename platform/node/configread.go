package node

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"otsec.local/otsec/contracts/adapter"
	"otsec.local/otsec/contracts/audit"
	"otsec.local/otsec/contracts/authz"
	"otsec.local/otsec/contracts/config"
	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/modules/security/collectorclient"
	"otsec.local/otsec/platform/store"
)

// The configuration-read writer (D4-40 item 2, docs/phase4/C5-config-writer.md).
// An accepted configuration read whose outcome passed the client's checks
// becomes a C9 snapshot, stored in config/<asset> with its transcript as
// the capture. It is then compared with the asset's acknowledged
// configuration baseline, and the result is one C8 record, with its holds
// taken after the record's Receipt. Everything the record names comes from
// the audit chain, which configChain folds.

// ConfigRules maps an asset profile to the C9 rule its configuration reads
// are tokenized by. A configuration read of an asset whose profile is not
// here is refused at load.
var ConfigRules = map[string]string{"sel-751-ascii": config.RuleSEL751SHO.ID}

// AlarmConfigNotCompared is raised for an asset when a stored snapshot cannot
// be compared with its baseline: the baseline does not decode or compare,
// nothing in the retained chain bounds the change, or the acknowledgement
// that set the baseline was pruned from the audit stream. The snapshot stays
// stored and unheld; the next read compares again. Level 0.
const AlarmConfigNotCompared = "config-not-compared"

// AlarmUnapprovedChange is raised once for each config.change_detected the
// node writes with reason unapproved_change: the asset's configuration
// differs from its acknowledged baseline and no approval covers it. A
// config.baseline_restored or a configuration acknowledgement ends it in
// the chain. Level 0.
const AlarmUnapprovedChange = "config-unapproved-change"

// configRule is the C9 rule of an asset's configuration reads.
func (c *Config) configRule(assetID string) (string, bool) {
	a, ok := c.Asset(assetID)
	if !ok || a.Profile == nil {
		return "", false
	}
	rule, ok := ConfigRules[a.Profile.ID]
	return rule, ok
}

// commitConfigRead stores an accepted configuration read and writes its
// result. readSeq is the collector's decision on the read.
func (s *Scheduler) commitConfigRead(ctx context.Context, rep Report, col Collection, o *collectorclient.Outcome, readSeq uint64) Report {
	a, _ := s.rt.cfg.Asset(col.AssetID)
	inv := adapter.Invocation{InvocationID: o.InvocationID, PrincipalRef: col.ID, AssetID: col.AssetID, EndpointID: col.Endpoint,
		ProfileID: a.Profile.ID, OperationID: col.Operation, Params: col.Params, CredentialRef: col.CredentialRef}
	tr := o.Result.Transcript
	run := map[string]string{"status": string(o.Result.Status), "events": "0"}
	if o.Result.Status != adapter.StatusOK {
		// A failed read has no snapshot. It is still a run of the operation
		// that the next detection's unchanged_read_seq may name.
		if o.Result.Error != nil {
			rep.Detail = o.Result.Error.Detail
		}
		rec, err := s.runRecord(HealthStream, HealthCollectionRun, col, rep.RequestID, o.InvocationID, run)
		if err == nil && len(tr.Data) > 0 {
			rec.Capture = &c5.Capture{SHA256: tr.SHA256, Bytes: tr.Data}
		}
		return s.storeRun(ctx, rep, col, rec, err)
	}
	rule, _ := s.rt.cfg.configRule(col.AssetID)
	snap, err := config.FromResult(rule, s.rt.commands, inv, o.Result)
	if err == nil {
		err = snap.CheckAgainst(tr)
	}
	var doc []byte
	if err == nil {
		doc, err = snap.Encode()
	}
	if err != nil {
		// A refused result is kept as quarantine, never as a snapshot.
		rep.Outcome = "quarantined"
		s.quarantine(ctx, rep, col, o.InvocationID, o.ResultJSON, "configuration snapshot refused: "+err.Error(), false)
		rep.stored = s.health(ctx, HealthCollectionOutcomeUnknown, col, rep.RequestID, o.InvocationID, map[string]string{"quarantined": "true"})
		return s.alarm(ctx, rep, col.AssetID, AlarmResultRefused, "the configuration snapshot was refused; kept as quarantine")
	}
	stream := ConfigStream(col.AssetID)
	snapSeq, err := s.storeConfig(ctx, stream, doc, &c5.Capture{SHA256: tr.SHA256, Bytes: tr.Data})
	if err != nil {
		return s.alarm(ctx, rep, col.AssetID, AlarmEvidenceNotStored, "configuration snapshot: "+err.Error())
	}
	snapDigest := config.Digest(doc)
	run["snapshot_seq"], run["snapshot_digest"] = fmt.Sprint(snapSeq), snapDigest
	rec, err := s.runRecord(HealthStream, HealthCollectionRun, col, rep.RequestID, o.InvocationID, run)
	if rep = s.storeRun(ctx, rep, col, rec, err); rep.Alarm != "" {
		return rep
	}
	return s.compareConfig(ctx, rep, col, readSeq, doc, snapSeq, snapDigest)
}

// storeRun commits a configuration read's run health event.
func (s *Scheduler) storeRun(ctx context.Context, rep Report, col Collection, rec c5.Record, err error) Report {
	log := s.rt.Log(HealthStream)
	if err == nil && log == nil {
		err = errors.New("evidence database not open")
	}
	if err == nil {
		_, err = log.AppendBatch(ctx, []c5.Record{rec})
	}
	if err != nil {
		return s.alarm(ctx, rep, col.AssetID, AlarmEvidenceNotStored, "health events: "+err.Error())
	}
	rep.stored = true
	return rep
}

// storeConfig commits one configuration document and returns its seq.
// AppendBatch returns only once the commit has, so an error never leaves a
// document stored behind it that a retry would store again.
func (s *Scheduler) storeConfig(ctx context.Context, stream c5.StreamID, doc []byte, capture *c5.Capture) (c5.Seq, error) {
	log := s.rt.Log(stream)
	if log == nil {
		return 0, errors.New("configuration database not open")
	}
	r, err := log.AppendBatch(ctx, []c5.Record{{Stream: stream, Class: c5.ClassConfiguration, Event: doc, Capture: capture}})
	if err != nil {
		return 0, err
	}
	return r[0].Key().Seq, nil
}

// compareConfig compares a stored snapshot with the asset's acknowledged
// baseline and writes the result (the design note's table, section 1).
func (s *Scheduler) compareConfig(ctx context.Context, rep Report, col Collection, readSeq uint64, doc []byte, snapSeq c5.Seq, snapDigest string) Report {
	// notCompared raises AlarmConfigNotCompared once per asset and cause
	// (C4 on #390): a cause that persists would raise it at every read and
	// push older alarms out of status. A comparison that succeeds clears it.
	notCompared := func(cause, why string) Report {
		rep.Alarm = AlarmConfigNotCompared
		s.raiseOnceKey(notComparedKey(col.AssetID, cause), col.AssetID, AlarmConfigNotCompared, "snapshot "+snapDigest+" stored and not compared: "+why)
		return rep
	}
	ch := s.configChain()
	if err := ch.sync(ctx, s.rt.Store(AuditStream)); err != nil {
		return notCompared("chain", "the audit chain could not be read: "+err.Error())
	}
	stream := ConfigStream(col.AssetID)
	cdb := s.rt.Store(stream)
	st := ch.asset(col.AssetID)
	if err := ch.findBaseline(ctx, st, col.AssetID); err != nil {
		return notCompared("holds", err.Error())
	}
	if st.baseline == "" {
		return rep // the snapshot awaits an acknowledgement
	}
	if !ch.hasRun(col.AssetID, col.Operation, readSeq) {
		return s.alarm(ctx, rep, col.AssetID, AlarmAuditUnavailable, fmt.Sprintf("snapshot %s stored without a result: the decision %d on its read is not in the audit chain", snapDigest, readSeq))
	}
	base, err := readDigest(ctx, cdb, stream, st.baseline)
	if err != nil {
		return notCompared("baseline", err.Error())
	}
	if base == nil {
		return s.alarm(ctx, rep, col.AssetID, AlarmBaselineNotStored, fmt.Sprintf("the acknowledged baseline %s is not in stream %s; snapshot %s stored and not compared", st.baseline, stream, snapDigest))
	}
	d, err := config.Compare(base, doc)
	// A valid difference over C9's MaxDifferenceBytes comes back with
	// ErrDifferenceTooLarge (C9 0.4): the change is real, and is recorded
	// without its difference (D4-42).
	tooLarge := errors.Is(err, config.ErrDifferenceTooLarge)
	if err != nil && !tooLarge {
		return notCompared("compare", err.Error())
	}
	c := &audit.Config{BaselineDigest: st.baseline, SnapshotDigest: snapDigest, ReadSeq: readSeq}
	switch {
	case len(d.Changes) == 0 && st.last == nil:
		c.SnapshotSeq = uint64(snapSeq)
		_, err = s.writeConfigRecord(ctx, rep, col, audit.ActionConfigReadCompared, audit.OutcomeInfo, audit.ReasonNoDifference, c)
		return s.recorded(ctx, rep, col, err)
	case len(d.Changes) == 0:
		if _, err := s.writeConfigRecord(ctx, rep, col, audit.ActionConfigBaselineRestored, audit.OutcomeInfo, "", c); err != nil {
			return s.recorded(ctx, rep, col, err)
		}
		s.restoreHolds(ctx, col.AssetID, append(slices.Clone(st.open), st.approved...))
		for _, ref := range st.open {
			s.clearQuietKey(fmt.Sprintf("unapproved %s %d", col.AssetID, ref))
		}
		return s.recorded(ctx, rep, col, nil)
	case st.last != nil && d.ChangesDigest() == st.last.changes:
		c.SnapshotSeq, c.ChangeSeq, c.ChangesDigest = uint64(snapSeq), uint64(st.last.seq), st.last.changes
		_, err = s.writeConfigRecord(ctx, rep, col, audit.ActionConfigReadCompared, audit.OutcomeInfo, audit.ReasonSameChange, c)
		return s.recorded(ctx, rep, col, err)
	}
	prior, at, ok := ch.unchanged(col.AssetID, col.Operation, readSeq)
	if !ok {
		return notCompared("unbounded", "neither an earlier run of the operation nor a collector reset in the retained chain bounds the change")
	}
	// A difference too large to store is not stored, and the record says so
	// with no difference_digest (C8 0.10, D4-42). The change is still
	// recorded and alarmed, never hidden behind a storage alarm (C1 on
	// #390), and the read's snapshot is held, so the difference is C9's
	// Compare of the held baseline and snapshot.
	var diffSeq c5.Seq
	what := ""
	if tooLarge {
		c.DifferenceTooLarge = true
		what = fmt.Sprintf("difference not stored: too large (over %d bytes)", config.MaxDifferenceBytes)
	} else {
		diff, err := d.Encode()
		if err != nil {
			return notCompared("encode", err.Error())
		}
		if diffSeq, err = s.storeConfig(ctx, stream, diff, nil); err != nil {
			return s.alarm(ctx, rep, col.AssetID, AlarmEvidenceNotStored, "configuration difference: "+err.Error())
		}
		c.DifferenceDigest = config.Digest(diff)
		what = "difference " + c.DifferenceDigest
	}
	c.ChangesDigest, c.UnchangedReadSeq, c.UnchangedAt = d.ChangesDigest(), prior, at
	rec := s.configRecord(col.AssetID, rep.RequestID, audit.ActionConfigChangeDetected, audit.OutcomeWarning, audit.ReasonUnapprovedChange, c)
	if !st.alarmed {
		// Once an unapproved difference is open against this baseline, no
		// approval silences a later one (audit.VerifyConfig).
		for _, ap := range slices.Backward(ch.approvals[col.AssetID]) {
			c.ApprovalSeq = ap.Config.DecisionSeq
			if audit.ApprovalCovers(ap, rec) == nil {
				rec.Outcome, rec.ReasonCode = audit.OutcomeInfo, audit.ReasonApprovedChange
				break
			}
			c.ApprovalSeq = 0
		}
	}
	seq, err := s.appendConfigRecord(ctx, rec)
	if err != nil {
		return s.recorded(ctx, rep, col, err)
	}
	code := c5.HoldApprovedDifference
	if c.ApprovalSeq == 0 {
		code = c5.HoldUnapprovedDifference
	}
	s.holdConfig(ctx, col.AssetID, stream, snapSeq, code, seq)
	if diffSeq != 0 {
		s.holdConfig(ctx, col.AssetID, stream, diffSeq, code, seq)
	}
	switch {
	case c.ApprovalSeq == 0:
		s.raiseOnceKey(fmt.Sprintf("unapproved %s %d", col.AssetID, seq), col.AssetID, AlarmUnapprovedChange,
			fmt.Sprintf("the configuration differs from baseline %s and no approval covers it: %s, audit record %d", st.baseline, what, seq))
	case tooLarge:
		s.raiseOnceKey(fmt.Sprintf("difference %s %d", col.AssetID, seq), col.AssetID, AlarmEvidenceNotStored,
			fmt.Sprintf("the approved change of audit record %d (approval %d): %s", seq, c.ApprovalSeq, what))
	}
	return s.recorded(ctx, rep, col, nil)
}

func notComparedKey(assetID, cause string) string { return "not-compared " + assetID + " " + cause }

// clearNotCompared ends every config-not-compared cause of the asset, so
// one that returns is raised again.
func (s *Scheduler) clearNotCompared(assetID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k := range s.quiet {
		if strings.HasPrefix(k, notComparedKey(assetID, "")) {
			delete(s.quiet, k)
		}
	}
}

// recorded reports a result record that could not be written. The stored
// records stay unheld, and the next read compares again. A result written
// ends the asset's config-not-compared causes.
func (s *Scheduler) recorded(ctx context.Context, rep Report, col Collection, err error) Report {
	if err != nil {
		return s.alarm(ctx, rep, col.AssetID, AlarmAuditUnavailable, "configuration read result not written: "+err.Error())
	}
	s.clearNotCompared(col.AssetID)
	return rep
}

// configRecord is a node-written C8 configuration record of the read the
// run with requestID made.
func (s *Scheduler) configRecord(assetID, requestID string, action audit.Action, outcome audit.Outcome, reason string, c *audit.Config) *audit.Record {
	node := string(s.rt.cfg.NodeID)
	return &audit.Record{Contract: audit.ContractID, NodeID: node, Time: s.rt.received(),
		Actor: audit.Actor{Type: authz.PrincipalNode, ID: node}, Action: action, Outcome: outcome, ReasonCode: reason,
		Target: &audit.Target{AssetID: assetID}, CorrelationID: requestID, Config: c}
}

func (s *Scheduler) writeConfigRecord(ctx context.Context, rep Report, col Collection, action audit.Action, outcome audit.Outcome, reason string, c *audit.Config) (c5.Seq, error) {
	return s.appendConfigRecord(ctx, s.configRecord(col.AssetID, rep.RequestID, action, outcome, reason, c))
}

// appendConfigRecord validates and commits one C8 record and returns its
// seq in the audit stream. AppendBatch, so an error is never a record that
// committed anyway (C4 on #384).
func (s *Scheduler) appendConfigRecord(ctx context.Context, rec *audit.Record) (c5.Seq, error) {
	b, err := json.Marshal(rec)
	if err != nil {
		return 0, err
	}
	if _, err := audit.ValidatePending(b); err != nil {
		return 0, err
	}
	log := s.rt.Log(AuditStream)
	if log == nil {
		return 0, errors.New("audit database not open")
	}
	r, err := log.AppendBatch(ctx, []c5.Record{{Stream: AuditStream, Class: c5.ClassAudit, Event: b}})
	if err != nil {
		return 0, err
	}
	return r[0].Key().Seq, nil
}

// holdConfig holds one configuration record for ref, the C8 record that
// justifies it. A hold not taken is taken by the next start's reconcile,
// which rebuilds the holds from the chain.
func (s *Scheduler) holdConfig(ctx context.Context, assetID string, stream c5.StreamID, seq c5.Seq, code c5.HoldCode, ref c5.Seq) {
	db := s.rt.Store(stream)
	err := errors.New("configuration database not open")
	if db != nil {
		err = db.Hold(ctx, c5.Hold{Stream: stream, Seq: seq, Reason: c5.HoldReason{Code: code, Ref: c5.Key{NodeID: s.rt.cfg.NodeID, Stream: AuditStream, Seq: ref}}})
	}
	if err != nil {
		s.rt.opt.Status.Raise(assetID, AlarmEvidenceNotStored, fmt.Sprintf("%s seq %d not held as %s: %v; the next start's reconcile holds it", stream, seq, code, err))
	}
}

// restoreHolds moves the holds of the changes a return to the baseline
// ends, refs, to restored-difference, keeping each one's ref: the open
// unapproved ones (D4-19) and the approved ones (D4-43).
func (s *Scheduler) restoreHolds(ctx context.Context, assetID string, refs []c5.Seq) {
	stream := ConfigStream(assetID)
	db := s.rt.Store(stream)
	held, err := db.Held(ctx, stream)
	if err != nil {
		s.rt.opt.Status.Raise(assetID, AlarmEvidenceNotStored, fmt.Sprintf("%s holds not read, so the restored change keeps its hold code until the next start's reconcile: %v", stream, err))
		return
	}
	for _, h := range held {
		if (h.Reason.Code == c5.HoldUnapprovedDifference || h.Reason.Code == c5.HoldApprovedDifference) && slices.Contains(refs, h.Reason.Ref.Seq) {
			s.holdConfig(ctx, assetID, stream, h.Seq, c5.HoldRestoredDifference, h.Reason.Ref.Seq)
		}
	}
}

// readDigest returns the stored bytes in stream whose digest is digest, or
// nil when none is.
func readDigest(ctx context.Context, db *store.DB, stream c5.StreamID, digest string) ([]byte, error) {
	found, err := locate(ctx, db, stream, map[string]bool{digest: true})
	if err != nil {
		return nil, err
	}
	seq, ok := found[digest]
	if !ok {
		return nil, nil
	}
	got, err := db.Read(ctx, stream, seq-1, 1)
	if err != nil {
		return nil, err
	}
	if len(got) != 1 || got[0].Key.Seq != seq {
		return nil, fmt.Errorf("%s seq %d is no longer stored", stream, seq)
	}
	return got[0].Event, nil
}
