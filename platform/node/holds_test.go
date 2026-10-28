package node

import (
	"encoding/json"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/audit"
	"otsec.local/otsec/contracts/authz"
	"otsec.local/otsec/contracts/config"
	c5 "otsec.local/otsec/contracts/store"
)

// The configuration records the holds rest on (C8 0.5). The digests are of
// fixed texts, so the pure tests need no store.
const (
	hBase  = "sha256:ee1d5cd04fcee7fd33c68453b7fb6a9ec1f7124bf9e88b03f1a4bb6640310e89"
	hSnap  = "sha256:2b4627fd426546888575da7c26ef571798f2d583d0027e686f016ed6b1de60ef"
	hDiff  = "sha256:c5e3dc4f27577c98a210d2eed87dc6294382624e4ac9a02811831fb8a866beb6"
	hEvent = "sha256:82fa24899a1607be48de01641e58ec3add0b30db75eada80ec4da264b3d4c439"
)

func ackRec(kind authz.BaselineKind, digest string) *audit.Record {
	return &audit.Record{Action: audit.ActionConfigBaselineAcknowledge, Outcome: audit.OutcomeSucceeded,
		Target: &audit.Target{AssetID: relayID}, Config: &audit.Config{Kind: kind, BaselineDigest: digest}}
}

func detectedRec(baseline, snap, diff string, approved bool) *audit.Record {
	c := &audit.Config{BaselineDigest: baseline, SnapshotDigest: snap, DifferenceDigest: diff}
	if approved {
		c.ApprovalSeq = 5
	}
	return &audit.Record{Action: audit.ActionConfigChangeDetected, Target: &audit.Target{AssetID: relayID}, Config: c}
}

func restoredRec(baseline string) *audit.Record {
	return &audit.Record{Action: audit.ActionConfigBaselineRestored, Target: &audit.Target{AssetID: relayID},
		Config: &audit.Config{BaselineDigest: baseline, SnapshotDigest: baseline}}
}

func chain(recs ...*audit.Record) []auditRec {
	out := make([]auditRec, len(recs))
	for i, r := range recs {
		out[i] = auditRec{c5.Seq(10 + i), r}
	}
	return out
}

func wantsOf(t *testing.T, recs ...*audit.Record) []wantHold {
	t.Helper()
	a := foldHolds(chain(recs...))[relayID]
	if a == nil {
		return nil
	}
	return a.wants()
}

func digests(ws []wantHold) []string {
	var out []string
	for _, w := range ws {
		out = append(out, string(w.code)+" "+w.digest[7:13]+" ref "+string(rune('0'+w.ref%10)))
	}
	return out
}

// What C8 justifies: an acknowledged baseline of each kind, and a change no
// approval covered, until a return to the baseline or a new baseline ends it.
func TestFoldHolds(t *testing.T) {
	cfg, ev := authz.BaselineConfiguration, authz.BaselineEvent
	for name, tc := range map[string]struct {
		recs []*audit.Record
		want []string
	}{
		"nothing":                  {nil, nil},
		"a configuration baseline": {[]*audit.Record{ackRec(cfg, hBase)}, []string{"baseline " + hBase[7:13] + " ref 0"}},
		"both kinds, configuration first": {[]*audit.Record{ackRec(ev, hEvent), ackRec(cfg, hBase)},
			[]string{"baseline " + hBase[7:13] + " ref 1", "baseline " + hEvent[7:13] + " ref 0"}},
		"a denied acknowledgement holds nothing": {[]*audit.Record{func() *audit.Record {
			r := ackRec(cfg, hBase)
			r.Outcome = audit.OutcomeDenied
			return r
		}()}, nil},
		"an unapproved change holds its snapshot and difference": {
			[]*audit.Record{ackRec(cfg, hBase), detectedRec(hBase, hSnap, hDiff, false)},
			[]string{"baseline " + hBase[7:13] + " ref 0", "unapproved-difference " + hSnap[7:13] + " ref 1", "unapproved-difference " + hDiff[7:13] + " ref 1"}},
		"an approved change holds nothing more": {
			[]*audit.Record{ackRec(cfg, hBase), detectedRec(hBase, hSnap, hDiff, true)},
			[]string{"baseline " + hBase[7:13] + " ref 0"}},
		"a return to the baseline ends the alarm": {
			[]*audit.Record{ackRec(cfg, hBase), detectedRec(hBase, hSnap, hDiff, false), restoredRec(hBase)},
			[]string{"baseline " + hBase[7:13] + " ref 0"}},
		"a new baseline makes the alarm not wanted, and is the one held": {
			[]*audit.Record{ackRec(cfg, hBase), detectedRec(hBase, hSnap, hDiff, false), ackRec(cfg, hSnap)},
			[]string{"baseline " + hSnap[7:13] + " ref 2"}},
		"a second acknowledgement of the same baseline keeps the alarm (B6 on #305)": {
			[]*audit.Record{ackRec(cfg, hBase), detectedRec(hBase, hSnap, hDiff, false), ackRec(cfg, hBase)},
			[]string{"baseline " + hBase[7:13] + " ref 2", "unapproved-difference " + hSnap[7:13] + " ref 1", "unapproved-difference " + hDiff[7:13] + " ref 1"}},
		"going to another baseline and back wants the alarm again (B6 on #305)": {
			[]*audit.Record{ackRec(cfg, hBase), detectedRec(hBase, hSnap, hDiff, false), ackRec(cfg, hEvent), ackRec(cfg, hBase)},
			[]string{"baseline " + hBase[7:13] + " ref 3", "unapproved-difference " + hSnap[7:13] + " ref 1", "unapproved-difference " + hDiff[7:13] + " ref 1"}},
		"a return to the baseline ends it for good, even after a second acknowledgement": {
			[]*audit.Record{ackRec(cfg, hBase), detectedRec(hBase, hSnap, hDiff, false), restoredRec(hBase), ackRec(cfg, hBase)},
			[]string{"baseline " + hBase[7:13] + " ref 3"}},
		"an event baseline's acknowledgement leaves the alarm open": {
			[]*audit.Record{ackRec(cfg, hBase), detectedRec(hBase, hSnap, hDiff, false), ackRec(ev, hEvent)},
			[]string{"baseline " + hBase[7:13] + " ref 0", "baseline " + hEvent[7:13] + " ref 2", "unapproved-difference " + hSnap[7:13] + " ref 1", "unapproved-difference " + hDiff[7:13] + " ref 1"}},
		"a change against a baseline that is not the active one is not held": {
			[]*audit.Record{ackRec(cfg, hSnap), detectedRec(hBase, hEvent, hDiff, false)},
			[]string{"baseline " + hSnap[7:13] + " ref 0"}},
		"a record wanted twice is held once, as the baseline": {
			[]*audit.Record{ackRec(cfg, hBase), detectedRec(hBase, hEvent, hDiff, false), ackRec(ev, hEvent)},
			[]string{"baseline " + hBase[7:13] + " ref 0", "baseline " + hEvent[7:13] + " ref 2", "unapproved-difference " + hDiff[7:13] + " ref 1"}},
	} {
		t.Run(name, func(t *testing.T) {
			got := digests(wantsOf(t, tc.recs...))
			if strings.Join(got, "|") != strings.Join(tc.want, "|") {
				t.Errorf("got %q\nwant %q", got, tc.want)
			}
		})
	}
}

// holdsNode is a node over three stored documents: seq 1 and 2 are C9
// snapshots, 3 their difference, and 4 a C10 baseline.
type holdsNode struct {
	t              *testing.T
	c              *Config
	dir            string
	snap1, snap2   []byte
	diff, baseline []byte
	open           *Runtime
}

func newHoldsNode(t *testing.T) *holdsNode {
	c, dir := configNode(t, nil)
	h := &holdsNode{t: t, c: c, dir: dir,
		diff:     contractFile(t, "config/testdata/valid/difference-1-2.json"),
		baseline: contractFile(t, "baseline/testdata/valid/baseline-synthetic.json")}
	r, _, _ := start(t, c, dir)
	defer r.Close()
	_, log, _ := r.view(r.find(ConfigDB))
	stream := ConfigStream(relayID)
	snap1, cap1 := configRead(t, "1")
	snap2, cap2 := configRead(t, "2")
	h.snap1, h.snap2 = snap1, snap2
	for _, rc := range []c5.Record{
		{Stream: stream, Class: c5.ClassConfiguration, Event: snap1, Capture: &cap1},
		{Stream: stream, Class: c5.ClassConfiguration, Event: snap2, Capture: &cap2},
		{Stream: stream, Class: c5.ClassConfiguration, Event: h.diff},
		{Stream: stream, Class: c5.ClassConfiguration, Event: h.baseline},
	} {
		if _, err := log.Append(bg, rc); err != nil {
			t.Fatal(err)
		}
	}
	return h
}

// restart opens the node, lets mod write C8 records and holds, closes it,
// and opens it again, returning that second start's holds and alarms.
func (h *holdsNode) restart(mod func(*Runtime)) (map[c5.Seq]c5.HoldReason, []StatusAlarm, *Runtime) {
	h.t.Helper()
	if h.open != nil {
		h.open.Close()
		h.open = nil
	}
	if mod != nil {
		r, _, _ := start(h.t, h.c, h.dir)
		mod(r)
		r.Close()
	}
	r, st, _ := start(h.t, h.c, h.dir)
	h.open = r
	h.t.Cleanup(func() { r.Close() })
	held, err := r.Store(ConfigStream(relayID)).Held(bg, ConfigStream(relayID))
	if err != nil {
		h.t.Fatal(err)
	}
	got := map[c5.Seq]c5.HoldReason{}
	for _, x := range held {
		got[x.Seq] = x.Reason
	}
	return got, st.Snapshot("n").Alarms, r
}

// put writes a configuration C8 record to the audit stream and returns its
// seq.
func putAudit(t *testing.T, r *Runtime, rec *audit.Record) c5.Seq {
	t.Helper()
	rec.Contract, rec.NodeID, rec.Time = audit.ContractID, string(r.cfg.NodeID), r.received()
	switch rec.Action {
	case audit.ActionConfigBaselineAcknowledge:
		rec.Actor = audit.Actor{Type: authz.PrincipalHuman, ID: "admin@site-a", Role: authz.RoleAdmin}
		rec.CorrelationID = "req-1"
		rec.Config.DecisionSeq, rec.Config.PayloadSHA256 = 7, strings.Repeat("ab", 32)
	case audit.ActionConfigChangeDetected, audit.ActionConfigBaselineRestored:
		rec.Actor = audit.Actor{Type: authz.PrincipalNode, ID: string(r.cfg.NodeID)}
		rec.CorrelationID = "6f1c2d3e-4a5b-4c6d-8e7f-9a0b1c2d3e4f"
		rec.Config.ReadSeq = 11
		if rec.Action == audit.ActionConfigChangeDetected {
			rec.Outcome, rec.ReasonCode = audit.OutcomeWarning, audit.ReasonUnapprovedChange
			rec.Config.UnchangedAt, rec.Config.UnchangedReadSeq = "2026-10-26T14:00:00Z", 6
		} else {
			rec.Outcome = audit.OutcomeInfo
		}
	}
	if rec.Outcome == "" {
		rec.Outcome = audit.OutcomeSucceeded
	}
	b, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := audit.ValidatePending(b); err != nil {
		t.Fatalf("%s: %v", rec.Action, err)
	}
	_, log, _ := r.view(r.find(AuditDB))
	rc, err := log.Append(bg, c5.Record{Stream: AuditStream, Class: c5.ClassAudit, Event: b})
	if err != nil {
		t.Fatal(err)
	}
	return rc.Key().Seq
}

func reasonAt(r *Runtime, seq c5.Seq, code c5.HoldCode) c5.HoldReason {
	return c5.HoldReason{Code: code, Ref: c5.Key{NodeID: r.cfg.NodeID, Stream: AuditStream, Seq: seq}}
}

func reconciled(alarms []StatusAlarm) (n int) {
	for _, a := range alarms {
		if a.Code == string(c5.AlarmHoldsReconciled) {
			n++
		}
	}
	return n
}

// The holds are rebuilt from C8 at start. An acknowledgement and a change
// recorded before a crash, with no hold taken, are held by the next start
// (audit before act, section 2 of the C5 0.4 proposal); a second start finds
// nothing to correct.
func TestHoldsAreRebuiltFromAuditAtStart(t *testing.T) {
	h := newHoldsNode(t)
	var ackCfg, ackEv, det c5.Seq
	got, alarms, r := h.restart(func(r *Runtime) {
		ackCfg = putAudit(t, r, ackRec(authz.BaselineConfiguration, config.Digest(h.snap1)))
		ackEv = putAudit(t, r, ackRec(authz.BaselineEvent, config.Digest(h.baseline)))
		det = putAudit(t, r, detectedRec(config.Digest(h.snap1), config.Digest(h.snap2), config.Digest(h.diff), false))
	})
	want := map[c5.Seq]c5.HoldReason{
		1: reasonAt(r, ackCfg, c5.HoldBaseline),
		2: reasonAt(r, det, c5.HoldUnapprovedDifference),
		3: reasonAt(r, det, c5.HoldUnapprovedDifference),
		4: reasonAt(r, ackEv, c5.HoldBaseline),
	}
	if len(got) != len(want) {
		t.Fatalf("holds %v, want %v", got, want)
	}
	for s, w := range want {
		if got[s] != w {
			t.Errorf("seq %d held as %+v, want %+v", s, got[s], w)
		}
	}
	if n := reconciled(alarms); n != 4 {
		t.Errorf("%d reconcile alarms, want 4: %+v", n, alarms)
	}
	var recorded bool
	for _, a := range auditActions(t, r) {
		recorded = recorded || a == audit.ActionStorageAlarm
	}
	if !recorded {
		t.Error("no storage.alarm record of the reconcile")
	}

	_, alarms, _ = h.restart(nil)
	if n := reconciled(alarms); n != 0 {
		t.Errorf("the next start corrected %d holds: %+v", n, alarms)
	}
}

// A hold no C8 record justifies is released, one with the wrong reason is
// corrected, and each is an alarm; the records that justify the rest stay.
func TestUnjustifiedHoldsAreReleasedAtStart(t *testing.T) {
	h := newHoldsNode(t)
	stream := ConfigStream(relayID)
	var ack, det c5.Seq
	got, alarms, r := h.restart(func(r *Runtime) {
		ack = putAudit(t, r, ackRec(authz.BaselineConfiguration, config.Digest(h.snap1)))
		det = putAudit(t, r, detectedRec(config.Digest(h.snap1), config.Digest(h.snap2), config.Digest(h.diff), false))
		db := r.Store(stream)
		// seq 1 held for the wrong reason, seq 2 and 3 unjustified (as they
		// would be if the alarm had ended and the release never ran), seq 4
		// never acknowledged.
		for _, hd := range []c5.Hold{
			{Stream: stream, Seq: 1, Reason: reasonAt(r, det, c5.HoldUnapprovedDifference)},
			{Stream: stream, Seq: 4, Reason: reasonAt(r, ack, c5.HoldBaseline)},
		} {
			if err := db.Hold(bg, hd); err != nil {
				t.Fatal(err)
			}
		}
	})
	want := map[c5.Seq]c5.HoldReason{
		1: reasonAt(r, ack, c5.HoldBaseline),
		2: reasonAt(r, det, c5.HoldUnapprovedDifference),
		3: reasonAt(r, det, c5.HoldUnapprovedDifference),
	}
	if len(got) != len(want) {
		t.Fatalf("holds %v, want %v", got, want)
	}
	for s, w := range want {
		if got[s] != w {
			t.Errorf("seq %d held as %+v, want %+v", s, got[s], w)
		}
	}
	// One correction of seq 1, two additions, one release of seq 4.
	if n := reconciled(alarms); n != 4 {
		t.Errorf("%d reconcile alarms, want 4: %+v", n, alarms)
	}
}

// A return to the baseline ends the alarm: the snapshot and the difference
// are released, the baseline stays. An approval accepted afterwards would
// not have (audit.VerifyConfig), so the fold ignores it.
func TestReturnToBaselineReleasesTheDifference(t *testing.T) {
	h := newHoldsNode(t)
	_, _, _ = h.restart(func(r *Runtime) {
		putAudit(t, r, ackRec(authz.BaselineConfiguration, config.Digest(h.snap1)))
		putAudit(t, r, detectedRec(config.Digest(h.snap1), config.Digest(h.snap2), config.Digest(h.diff), false))
	})
	got, alarms, r := h.restart(func(r *Runtime) {
		putAudit(t, r, restoredRec(config.Digest(h.snap1)))
	})
	if len(got) != 1 || got[1].Code != c5.HoldBaseline {
		t.Fatalf("holds %+v, want the baseline alone", got)
	}
	if n := reconciled(alarms); n != 2 {
		t.Errorf("%d reconcile alarms, want 2 releases: %+v", n, alarms)
	}
	_ = r
}

// An acknowledged baseline the node cannot find is an alarm for the asset,
// and holds nothing.
func TestAcknowledgedBaselineNotStored(t *testing.T) {
	h := newHoldsNode(t)
	got, alarms, _ := h.restart(func(r *Runtime) {
		putAudit(t, r, ackRec(authz.BaselineConfiguration, hBase))
	})
	if len(got) != 0 {
		t.Fatalf("holds %+v", got)
	}
	var seen bool
	for _, a := range alarms {
		if a.Code == AlarmBaselineNotStored && a.Asset == relayID && strings.Contains(a.Detail, hBase) {
			seen = true
		}
	}
	if !seen {
		t.Errorf("no %s alarm: %+v", AlarmBaselineNotStored, alarms)
	}
}

// When a record C8 says to hold is not there, the holds the node has are
// the evidence it has left: the old baseline stays held, with the alarm
// (B6 on #305).
func TestMissingBaselineKeepsTheOtherHolds(t *testing.T) {
	h := newHoldsNode(t)
	var ackA c5.Seq
	got, alarms, r := h.restart(func(r *Runtime) {
		ackA = putAudit(t, r, ackRec(authz.BaselineConfiguration, config.Digest(h.snap1)))
	})
	if len(got) != 1 || got[1] != reasonAt(r, ackA, c5.HoldBaseline) {
		t.Fatalf("holds %+v", got)
	}
	got, alarms, r = h.restart(func(r *Runtime) {
		putAudit(t, r, ackRec(authz.BaselineConfiguration, hBase)) // B, never stored
	})
	if len(got) != 1 || got[1] != reasonAt(r, ackA, c5.HoldBaseline) {
		t.Fatalf("after the acknowledgement of a baseline that is not stored, holds %+v: the old baseline must stay", got)
	}
	var seen bool
	for _, a := range alarms {
		seen = seen || (a.Code == AlarmBaselineNotStored && strings.Contains(a.Detail, hBase))
	}
	if !seen {
		t.Errorf("no %s alarm: %+v", AlarmBaselineNotStored, alarms)
	}
}
