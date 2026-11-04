package node

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"otsec.local/otsec/contracts/adapter"
	"otsec.local/otsec/contracts/audit"
	"otsec.local/otsec/contracts/authz"
	"otsec.local/otsec/contracts/config"
	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/modules/security/collectorclient"
	"otsec.local/otsec/platform/node/nodeconfigtest"
)

// cfgNode is a node with a scheduled configuration read of the relay
// (collection 1), a fake collector that accepts each run with the next
// collector_seq and answers it with next, and helpers that put a person's
// decisions in the chain as the collector's acceptance and the node's record
// of it.
type cfgNode struct {
	t    *testing.T
	r    *Runtime
	st   *Status
	s    *Scheduler
	f    *fakeCollector
	seq  uint64
	next adapter.Result
}

func newCfgNode(t *testing.T) *cfgNode {
	t.Helper()
	c, dir := schedConfig(t, withConfigRead(t, nil))
	r, st, _ := start(t, c, dir)
	t.Cleanup(func() { r.Close() })
	n := &cfgNode{t: t, r: r, st: st, seq: 10}
	n.f = &fakeCollector{answer: func(req *authz.CollectorRequest) (collectorclient.Response, error) {
		n.seq++
		raw, err := json.Marshal(n.next)
		if err != nil {
			t.Fatal(err)
		}
		return collectorclient.Response{Reply: accepted(req, n.seq),
			Outcome: &collectorclient.Outcome{InvocationID: okInvocation, Result: n.next, ResultJSON: raw}}, nil
	}}
	n.s = newScheduler(t, r, n.f)
	return n
}

// result is a C2 configuration read result fixture.
func cfgResult(t *testing.T, name string) adapter.Result {
	t.Helper()
	r, err := adapter.DecodeResult(contractFile(t, "adapter/testdata/config/results/valid/"+name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// read runs the configuration read with the fixture's result.
func (n *cfgNode) read(name string) Report {
	n.t.Helper()
	n.next = cfgResult(n.t, name)
	rep := n.s.RunOnce(bg, 1)
	if !rep.Sent || rep.Outcome == "" {
		n.t.Fatalf("read %s: %+v", name, rep)
	}
	return rep
}

// snapshotOf is the stored snapshot digest the fixture's read gives.
func (n *cfgNode) snapshotOf(name string) string {
	n.t.Helper()
	m := n.r.commands
	inv := adapter.Invocation{InvocationID: okInvocation, PrincipalRef: "sch-cfg", AssetID: relayID, EndpointID: "port1-telnet",
		ProfileID: "sel-751-ascii", OperationID: "sel.config.read_all", CredentialRef: nodeconfigtest.TestCredentialRef}
	s, err := config.FromResult(config.RuleSEL751SHO.ID, m, inv, cfgResult(n.t, name))
	if err != nil {
		n.t.Fatal(err)
	}
	b, err := s.Encode()
	if err != nil {
		n.t.Fatal(err)
	}
	return config.Digest(b)
}

// decide puts a person's decision in the chain: the collector's acceptance,
// numbered next, then the node's record of it.
func (n *cfgNode) decide(kind authz.RequestKind, rec *audit.Record) c5.Seq {
	n.t.Helper()
	n.seq++
	payload := strings.Repeat("ab", 32)
	actor := audit.Actor{Type: authz.PrincipalHuman, ID: "admin@site-a", Role: authz.RoleAdmin}
	acc := &audit.Record{Actor: actor, Action: audit.ActionCollectorRequest, Outcome: audit.OutcomeAllowed, PolicyVersion: 3,
		CorrelationID: "req-decision", CollectorSeq: n.seq,
		Verified: &audit.Admin{AdminKeyID: "ed25519-183d5080d1a2ef2b", Principal: actor.ID, Nonce: "AAECAwQFBgcICQoLDA0ODw", PayloadSHA256: payload, Kind: kind}}
	rec.Actor, rec.Outcome, rec.CorrelationID, rec.Target = actor, audit.OutcomeSucceeded, "req-decision", &audit.Target{AssetID: relayID}
	rec.Config.DecisionSeq, rec.Config.PayloadSHA256 = n.seq, payload
	return n.inject(acc, rec)[1]
}

func (n *cfgNode) inject(recs ...*audit.Record) []c5.Seq {
	n.t.Helper()
	var out []c5.Record
	for _, rec := range recs {
		rec.Contract, rec.NodeID, rec.Time = audit.ContractID, string(n.r.cfg.NodeID), n.r.received()
		b, err := json.Marshal(rec)
		if err != nil {
			n.t.Fatal(err)
		}
		out = append(out, c5.Record{Stream: AuditStream, Class: c5.ClassAudit, Event: b})
	}
	got, err := n.r.Log(AuditStream).AppendBatch(bg, out)
	if err != nil {
		n.t.Fatal(err)
	}
	var seqs []c5.Seq
	for _, g := range got {
		seqs = append(seqs, g.Key().Seq)
	}
	return seqs
}

// ack acknowledges digest as the baseline and holds it, as the node side of
// node.baseline_ack will.
func (n *cfgNode) ack(digest, previous string) {
	n.t.Helper()
	ref := n.decide(authz.KindNodeBaselineAck, &audit.Record{Action: audit.ActionConfigBaselineAcknowledge,
		Config: &audit.Config{Kind: authz.BaselineConfiguration, BaselineDigest: digest, PreviousDigest: previous}})
	stream := ConfigStream(relayID)
	db := n.r.Store(stream)
	found, err := locate(bg, db, stream, map[string]bool{digest: true})
	if err != nil || found[digest] == 0 {
		n.t.Fatalf("baseline %s not stored: %v", digest, err)
	}
	if err := db.Hold(bg, c5.Hold{Stream: stream, Seq: found[digest], Reason: reasonAt(n.r, ref, c5.HoldBaseline)}); err != nil {
		n.t.Fatal(err)
	}
}

func (n *cfgNode) approve(baseline string) {
	now := time.Now().UTC()
	n.approveWindow(baseline, now.Add(-time.Hour), now.Add(time.Hour))
}

func (n *cfgNode) approveWindow(baseline string, start, end time.Time) {
	n.decide(authz.KindNodeChangeApproval, &audit.Record{Action: audit.ActionConfigChangeApproved,
		Config: &audit.Config{BaselineDigest: baseline, WindowStart: start.Format(time.RFC3339),
			WindowEnd: end.Format(time.RFC3339), Reason: "Replace CT ratio (work order 4711)"}})
}

// results are the chain's configuration read results, and the chain must
// verify (audit.VerifyConfig).
func (n *cfgNode) results() []*audit.Record {
	n.t.Helper()
	all := auditRecords(n.t, n.r)
	if err := audit.VerifyConfig(all); err != nil {
		n.t.Fatalf("the chain does not verify: %v", err)
	}
	var out []*audit.Record
	for _, r := range all {
		switch r.Action {
		case audit.ActionConfigReadCompared, audit.ActionConfigChangeDetected, audit.ActionConfigBaselineRestored:
			out = append(out, r)
		}
	}
	return out
}

func (n *cfgNode) holds() map[c5.Seq]c5.HoldCode {
	n.t.Helper()
	held, err := n.r.Store(ConfigStream(relayID)).Held(bg, ConfigStream(relayID))
	if err != nil {
		n.t.Fatal(err)
	}
	out := map[c5.Seq]c5.HoldCode{}
	for _, h := range held {
		out[h.Seq] = h.Reason.Code
	}
	return out
}

// stored is the number of records in the asset's configuration stream.
func (n *cfgNode) stored() int {
	n.t.Helper()
	got, err := n.r.Store(ConfigStream(relayID)).Read(bg, ConfigStream(relayID), 0, 100)
	if err != nil {
		n.t.Fatal(err)
	}
	return len(got)
}

// Without an acknowledged baseline a read is stored, with its transcript as
// the capture, and has no result: it awaits an acknowledgement.
func TestConfigReadAwaitsAcknowledgement(t *testing.T) {
	n := newCfgNode(t)
	if rep := n.read("ok"); rep.Alarm != "" || !rep.stored {
		t.Fatalf("%+v", rep)
	}
	got, err := n.r.Store(ConfigStream(relayID)).Read(bg, ConfigStream(relayID), 0, 10)
	if err != nil || len(got) != 1 {
		t.Fatalf("stored %d, %v", len(got), err)
	}
	capture, err := n.r.Store(ConfigStream(relayID)).ReadCapture(bg, got[0].EvidenceRef)
	if config.Digest(got[0].Event) != n.snapshotOf("ok") || err != nil || capture.SHA256 != cfgResult(t, "ok").Transcript.SHA256 {
		t.Fatalf("stored %s with capture %q: %v", config.Digest(got[0].Event), got[0].EvidenceRef, err)
	}
	if res := n.results(); len(res) != 0 || len(n.holds()) != 0 {
		t.Fatalf("results %d, holds %v", len(res), n.holds())
	}
}

// Each row of the design note's table, in one chain that verifies.
func TestConfigReadResults(t *testing.T) {
	n := newCfgNode(t)
	base := n.snapshotOf("ok")
	n.read("ok") // seq 1, the baseline
	n.ack(base, "")

	// The same configuration, read again: no difference.
	if rep := n.read("ok-with-echo"); rep.Alarm != "" {
		t.Fatalf("%+v", rep)
	}
	res := n.results()
	if len(res) != 1 || res[0].Action != audit.ActionConfigReadCompared || res[0].ReasonCode != audit.ReasonNoDifference ||
		res[0].Config.SnapshotSeq != 2 || res[0].Config.BaselineDigest != base {
		t.Fatalf("no difference: %+v", res)
	}
	if h := n.holds(); len(h) != 1 || h[1] != c5.HoldBaseline {
		t.Fatalf("a no-difference read is held: %v", h)
	}

	// A change no approval covers: the difference is stored, both are held
	// unapproved-difference, and the alarm is raised.
	rep := n.read("ok-all-present")
	if rep.Alarm != "" || countAlarms(n.st, AlarmUnapprovedChange) != 1 {
		t.Fatalf("%+v, alarms %+v", rep, n.st.Snapshot("x").Alarms)
	}
	res = n.results()
	det := res[1]
	if det.Action != audit.ActionConfigChangeDetected || det.ReasonCode != audit.ReasonUnapprovedChange || det.Config.ApprovalSeq != 0 ||
		det.Config.SnapshotDigest != n.snapshotOf("ok-all-present") || det.Config.UnchangedReadSeq != 13 {
		t.Fatalf("detected: %+v %+v", det, det.Config)
	}
	if h := n.holds(); len(h) != 3 || h[3] != c5.HoldUnapprovedDifference || h[4] != c5.HoldUnapprovedDifference {
		t.Fatalf("holds %v", h)
	}

	// The same change read again: same_change, naming it.
	n.read("ok-all-present")
	res = n.results()
	if r := res[2]; r.Action != audit.ActionConfigReadCompared || r.ReasonCode != audit.ReasonSameChange ||
		r.Config.ChangeSeq != det.Seq || r.Config.ChangesDigest != det.Config.ChangesDigest {
		t.Fatalf("same change: %+v %+v", r, r.Config)
	}
	if countAlarms(n.st, AlarmUnapprovedChange) != 1 {
		t.Fatal("the same change raised the alarm again")
	}

	// Back to the baseline: restored, and the change's holds move to
	// restored-difference.
	n.read("ok")
	res = n.results()
	if r := res[3]; r.Action != audit.ActionConfigBaselineRestored || r.Config.BaselineDigest != base {
		t.Fatalf("restored: %+v", r)
	}
	if h := n.holds(); len(h) != 3 || h[3] != c5.HoldRestoredDifference || h[4] != c5.HoldRestoredDifference {
		t.Fatalf("holds after the restore %v", h)
	}
	if n.stored() != 6 { // five snapshots and one difference
		t.Fatalf("stored %d records", n.stored())
	}
}

// A change an approval covers is recorded info approved_change, naming the
// approval, and held approved-difference with no alarm. After an
// unapproved one is open, a later approval silences nothing.
func TestConfigReadApprovedChange(t *testing.T) {
	n := newCfgNode(t)
	base := n.snapshotOf("ok")
	n.read("ok")
	n.ack(base, "")
	n.approve(base)
	approval := n.seq
	n.read("ok-all-present")
	res := n.results()
	if len(res) != 1 || res[0].ReasonCode != audit.ReasonApprovedChange || res[0].Outcome != audit.OutcomeInfo || res[0].Config.ApprovalSeq != approval {
		t.Fatalf("approved: %+v", res)
	}
	if h := n.holds(); len(h) != 3 || h[2] != c5.HoldApprovedDifference || h[3] != c5.HoldApprovedDifference {
		t.Fatalf("holds %v", h)
	}
	if countAlarms(n.st, AlarmUnapprovedChange) != 0 {
		t.Fatal("an approved change raised the alarm")
	}
}

func TestConfigReadApprovalAfterTheAlarm(t *testing.T) {
	n := newCfgNode(t)
	base := n.snapshotOf("ok")
	n.read("ok")
	n.ack(base, "")
	n.read("ok-all-present") // unapproved
	n.approve(base)
	n.read("ok-with-echo") // no changes: restored
	n.read("ok-all-present")
	res := n.results()
	if len(res) != 3 || res[2].ReasonCode != audit.ReasonApprovedChange {
		t.Fatalf("after the restore the approval covers the change again: %+v", res)
	}

	m := newCfgNode(t)
	m.read("ok")
	m.ack(base, "")
	m.read("ok-all-present") // unapproved, still open
	m.approve(base)
	m.read("ok-all-present") // the same change
	m.read("ok")             // restored
	if res := m.results(); len(res) != 3 || res[1].ReasonCode != audit.ReasonSameChange {
		t.Fatalf("%+v", res)
	}
}

// The writer's holds and the start-up reconcile agree, and an open change's
// alarm is raised again at start.
func TestConfigReadHoldsAfterRestart(t *testing.T) {
	c, dir := schedConfig(t, withConfigRead(t, nil))
	r, _, _ := start(t, c, dir)
	n := &cfgNode{t: t, r: r, seq: 10}
	n.f = &fakeCollector{answer: func(req *authz.CollectorRequest) (collectorclient.Response, error) {
		n.seq++
		raw, _ := json.Marshal(n.next)
		return collectorclient.Response{Reply: accepted(req, n.seq), Outcome: &collectorclient.Outcome{InvocationID: okInvocation, Result: n.next, ResultJSON: raw}}, nil
	}}
	n.s = newScheduler(t, r, n.f)
	base := n.snapshotOf("ok")
	n.read("ok")
	n.ack(base, "")
	n.read("ok-all-present")
	before := n.holds()
	r.Close()

	r, st, _ := start(t, c, dir)
	defer r.Close()
	if reconciled(st.Snapshot("x").Alarms) != 0 {
		t.Fatalf("the reconcile corrected the writer's holds: %+v", st.Snapshot("x").Alarms)
	}
	n.r, n.st = r, st
	if got := n.holds(); len(got) != len(before) || got[2] != before[2] || got[3] != before[3] {
		t.Fatalf("holds %v, before %v", got, before)
	}
	newScheduler(t, r, n.f)
	if countAlarms(st, AlarmUnapprovedChange) != 1 {
		t.Fatalf("the open change is not raised at start: %+v", st.Snapshot("x").Alarms)
	}
}

// A result the snapshot refuses is kept as quarantine, and nothing is stored
// in config/<asset> (condition 3: a read whose lines differ from the run
// fails whole).
func TestConfigReadRefusedSnapshot(t *testing.T) {
	n := newCfgNode(t)
	r := cfgResult(t, "ok")
	r.Records = r.Records[:len(r.Records)-1]
	n.next = r
	rep := n.s.RunOnce(bg, 1)
	if rep.Outcome != "quarantined" || rep.Alarm != AlarmResultRefused {
		t.Fatalf("%+v", rep)
	}
	if n.stored() != 0 {
		t.Fatal("a refused read stored a snapshot")
	}
	r = cfgResult(t, "ok")
	r.Transcript.Data = append([]byte{}, r.Transcript.Data...)
	r.Transcript.Data[r.Records[0].Span.Offset] ^= 1 // the reply no longer matches its record
	n.next = r
	if rep := n.s.RunOnce(bg, 1); rep.Outcome != "quarantined" || n.stored() != 0 {
		t.Fatalf("%+v, stored %d", rep, n.stored())
	}
}

// A failed read stores no snapshot, and is still a run that bounds the next
// change.
func TestConfigReadFailedRun(t *testing.T) {
	n := newCfgNode(t)
	base := n.snapshotOf("ok")
	n.read("ok")
	n.ack(base, "")
	failed := n.seq + 1
	if rep := n.read("failed.timeout-in-run"); rep.Alarm != "" || n.stored() != 1 {
		t.Fatalf("%+v, stored %d", rep, n.stored())
	}
	n.read("ok-all-present")
	if res := n.results(); len(res) != 1 || res[0].Config.UnchangedReadSeq != failed {
		t.Fatalf("%+v", res[0].Config)
	}
}

// The chain fold: the last run of the operation before the read bounds a
// change; with none in the epoch, the reset that began it does; a reset
// also ends the epoch's runs and approvals.
func TestConfigChainUnchanged(t *testing.T) {
	ch := &configChain{runs: map[assetOp][]chainRun{}, approvals: map[string][]*audit.Record{}, assets: map[string]*chainAsset{}}
	run := func(seq uint64, op, at string) *audit.Record {
		return &audit.Record{Action: audit.ActionCollectorRequest, Outcome: audit.OutcomeAllowed, CollectorSeq: seq, OperationID: op,
			Target: &audit.Target{AssetID: relayID}, Time: audit.Time{UTC: at}}
	}
	ch.apply(1, run(5, "sel.config.read_all", "t5"))
	ch.apply(2, run(6, "sel.ser.read_all", "t6"))
	ch.apply(3, run(7, "sel.config.read_all", "t7"))
	if seq, at, ok := ch.unchanged(relayID, "sel.config.read_all", 7); seq != 5 || at != "t5" || !ok {
		t.Fatalf("got %d %s %t", seq, at, ok)
	}
	if _, _, ok := ch.unchanged(relayID, "sel.config.read_all", 5); ok {
		t.Fatal("the first epoch's first read is bounded by nothing")
	}
	ch.apply(4, &audit.Record{Action: audit.ActionConfigChangeApproved, Outcome: audit.OutcomeSucceeded, Target: &audit.Target{AssetID: relayID}, Config: &audit.Config{}})
	ch.apply(5, &audit.Record{Action: audit.ActionCollectorSeqReset, Time: audit.Time{UTC: "t-reset"}})
	ch.apply(6, run(2, "sel.config.read_all", "t2"))
	if seq, at, ok := ch.unchanged(relayID, "sel.config.read_all", 2); seq != 0 || at != "t-reset" || !ok || len(ch.approvals[relayID]) != 0 {
		t.Fatalf("after a reset: %d %s %t, approvals %d", seq, at, ok, len(ch.approvals[relayID]))
	}
	if !ch.hasRun(relayID, "sel.config.read_all", 2) || ch.hasRun(relayID, "sel.config.read_all", 7) {
		t.Fatal("hasRun sees another epoch's runs")
	}
}

// A snapshot stored without its result (a crash between the two) leaves a
// chain that verifies, and the next read compares again.
func TestConfigReadSnapshotWithoutResult(t *testing.T) {
	n := newCfgNode(t)
	base := n.snapshotOf("ok")
	n.read("ok")
	n.ack(base, "")
	doc, capture := configRead(t, "2")
	if _, err := n.r.Log(ConfigStream(relayID)).AppendBatch(bg, []c5.Record{{Stream: ConfigStream(relayID), Class: c5.ClassConfiguration, Event: doc, Capture: &capture}}); err != nil {
		t.Fatal(err)
	}
	n.read("ok-all-present")
	if res := n.results(); len(res) != 1 || res[0].Action != audit.ActionConfigChangeDetected {
		t.Fatalf("%+v", res)
	}
}

// A hold the writer did not take (a crash between the record and the hold)
// is taken by the reconcile at the next start, with the same code.
func TestConfigReadHoldRepairedAtStart(t *testing.T) {
	c, dir := schedConfig(t, withConfigRead(t, nil))
	r, _, _ := start(t, c, dir)
	n := &cfgNode{t: t, r: r, seq: 10}
	n.f = &fakeCollector{answer: func(req *authz.CollectorRequest) (collectorclient.Response, error) {
		n.seq++
		raw, _ := json.Marshal(n.next)
		return collectorclient.Response{Reply: accepted(req, n.seq), Outcome: &collectorclient.Outcome{InvocationID: okInvocation, Result: n.next, ResultJSON: raw}}, nil
	}}
	n.s = newScheduler(t, r, n.f)
	base := n.snapshotOf("ok")
	n.read("ok")
	n.ack(base, "")
	n.approve(base)
	n.read("ok-all-present")
	db := r.Store(ConfigStream(relayID))
	for _, seq := range []c5.Seq{2, 3} {
		if err := db.Release(bg, ConfigStream(relayID), seq); err != nil {
			t.Fatal(err)
		}
	}
	r.Close()
	r, st, _ := start(t, c, dir)
	defer r.Close()
	n.r = r
	if h := n.holds(); h[2] != c5.HoldApprovedDifference || h[3] != c5.HoldApprovedDifference || reconciled(st.Snapshot("x").Alarms) != 2 {
		t.Fatalf("holds %v, alarms %+v", h, st.Snapshot("x").Alarms)
	}
}

// An acknowledged baseline that is not stored: the read is stored, has no
// result, and the alarm names the baseline.
func TestConfigReadBaselineNotStored(t *testing.T) {
	n := newCfgNode(t)
	missing := "sha256:" + strings.Repeat("0", 64)
	n.read("ok")
	n.decide(authz.KindNodeBaselineAck, &audit.Record{Action: audit.ActionConfigBaselineAcknowledge,
		Config: &audit.Config{Kind: authz.BaselineConfiguration, BaselineDigest: missing}})
	if rep := n.read("ok-all-present"); rep.Alarm != AlarmBaselineNotStored || n.stored() != 2 || len(n.results()) != 0 {
		t.Fatalf("%+v, stored %d", rep, n.stored())
	}
}

// After a prune that took the acknowledgement, a read is stored and not
// compared, with the alarm: the baseline hold shows that one was made.
func TestConfigReadPrunedAcknowledgement(t *testing.T) {
	n := newCfgNode(t)
	n.read("ok")
	db := n.r.Store(ConfigStream(relayID))
	if err := db.Hold(bg, c5.Hold{Stream: ConfigStream(relayID), Seq: 1, Reason: reasonAt(n.r, 2, c5.HoldBaseline)}); err != nil {
		t.Fatal(err)
	}
	// The fold as a pruned stream leaves it: records before 1000 are gone.
	n.s.chain = &configChain{pruned: true, first: 1000, through: 999,
		runs: map[assetOp][]chainRun{}, approvals: map[string][]*audit.Record{}, assets: map[string]*chainAsset{}}
	if rep := n.read("ok-all-present"); rep.Alarm != AlarmConfigNotCompared || n.stored() != 2 {
		t.Fatalf("%+v", rep)
	}
}

// A configuration read of an asset whose profile has no rule is refused at
// load.
func TestConfigReadNeedsARule(t *testing.T) {
	saved := ConfigRules
	ConfigRules = map[string]string{}
	t.Cleanup(func() { ConfigRules = saved })
	nc := nodeconfigtest.New("site-a-node1", t.TempDir()).AddSEL751(relayID, "", 2323, 300)
	withConfigRead(t, nil)(nc)
	if _, err := ParseConfig(nc.Bytes()); err == nil || !strings.Contains(err.Error(), "no configuration rule") {
		t.Fatalf("got %v", err)
	}
}

// Once an unapproved change is open against the baseline, an approval
// accepted after it silences no other change either (audit.VerifyConfig).
func TestConfigReadOpenAlarmBlocksApproval(t *testing.T) {
	n := newCfgNode(t)
	base := n.snapshotOf("ok")
	n.read("ok")
	first := n.seq
	n.ack(base, "")
	n.read("failed.timeout-in-run")
	failed := n.seq
	var at string
	for _, r := range auditRecords(t, n.r) {
		if r.Action == audit.ActionCollectorRequest && r.CollectorSeq == first {
			at = r.Time.UTC
		}
	}
	// An earlier unapproved change, with other changes than the next read's.
	n.inject(&audit.Record{Actor: audit.Actor{Type: authz.PrincipalNode, ID: string(n.r.cfg.NodeID)}, Action: audit.ActionConfigChangeDetected,
		Outcome: audit.OutcomeWarning, ReasonCode: audit.ReasonUnapprovedChange, Target: &audit.Target{AssetID: relayID}, CorrelationID: "req-earlier",
		Config: &audit.Config{BaselineDigest: base, SnapshotDigest: "sha256:" + strings.Repeat("1", 64), DifferenceDigest: "sha256:" + strings.Repeat("2", 64),
			ChangesDigest: changesDigest, ReadSeq: failed, UnchangedReadSeq: first, UnchangedAt: at}})
	n.approve(base)
	n.read("ok-all-present")
	res := n.results()
	if r := res[len(res)-1]; r.Action != audit.ActionConfigChangeDetected || r.ReasonCode != audit.ReasonUnapprovedChange || r.Config.ApprovalSeq != 0 {
		t.Fatalf("%+v %+v", r, r.Config)
	}
}

// A read whose decision is not in the chain (its allowed record was not
// written) is stored without a result.
func TestConfigReadDecisionNotInChain(t *testing.T) {
	n := newCfgNode(t)
	base := n.snapshotOf("ok")
	n.read("ok")
	n.ack(base, "")
	ch := n.s.configChain()
	if err := ch.sync(bg, n.r.Store(AuditStream)); err != nil {
		t.Fatal(err)
	}
	ch.through += 1000 // the next run's records are not folded
	if rep := n.read("ok-all-present"); rep.Alarm != AlarmAuditUnavailable || len(n.results()) != 0 {
		t.Fatalf("%+v", rep)
	}
}

// An approval whose window ended before the last unchanged read covers
// nothing: the change is unapproved.
func TestConfigReadApprovalWindowEnded(t *testing.T) {
	n := newCfgNode(t)
	base := n.snapshotOf("ok")
	n.read("ok")
	n.ack(base, "")
	n.approveWindow(base, time.Now().Add(-3*time.Hour), time.Now().Add(-2*time.Hour))
	n.read("ok-all-present")
	if res := n.results(); len(res) != 1 || res[0].ReasonCode != audit.ReasonUnapprovedChange || res[0].Config.ApprovalSeq != 0 {
		t.Fatalf("%+v", res)
	}
}
