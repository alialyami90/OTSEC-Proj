package node

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

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
		"a return to the baseline ends the alarm and keeps the evidence (D4-19)": {
			[]*audit.Record{ackRec(cfg, hBase), detectedRec(hBase, hSnap, hDiff, false), restoredRec(hBase)},
			[]string{"baseline " + hBase[7:13] + " ref 0", "restored-difference " + hSnap[7:13] + " ref 1", "restored-difference " + hDiff[7:13] + " ref 1"}},
		"a new baseline ends the alarm, is the one held, and the difference stays held (D4-18)": {
			[]*audit.Record{ackRec(cfg, hBase), detectedRec(hBase, hSnap, hDiff, false), ackRec(cfg, hSnap)},
			[]string{"baseline " + hSnap[7:13] + " ref 2", "acknowledged-difference " + hDiff[7:13] + " ref 1"}},
		"another baseline ends the alarm and both documents stay held (D4-18)": {
			[]*audit.Record{ackRec(cfg, hBase), detectedRec(hBase, hSnap, hDiff, false), ackRec(cfg, hEvent)},
			[]string{"baseline " + hEvent[7:13] + " ref 2", "acknowledged-difference " + hSnap[7:13] + " ref 1", "acknowledged-difference " + hDiff[7:13] + " ref 1"}},
		"a second acknowledgement of the same baseline ends the alarm too (D4-18)": {
			[]*audit.Record{ackRec(cfg, hBase), detectedRec(hBase, hSnap, hDiff, false), ackRec(cfg, hBase)},
			[]string{"baseline " + hBase[7:13] + " ref 2", "acknowledged-difference " + hSnap[7:13] + " ref 1", "acknowledged-difference " + hDiff[7:13] + " ref 1"}},
		"going to another baseline and back does not bring the alarm back (D4-18)": {
			[]*audit.Record{ackRec(cfg, hBase), detectedRec(hBase, hSnap, hDiff, false), ackRec(cfg, hEvent), ackRec(cfg, hBase)},
			[]string{"baseline " + hBase[7:13] + " ref 3", "acknowledged-difference " + hSnap[7:13] + " ref 1", "acknowledged-difference " + hDiff[7:13] + " ref 1"}},
		"a restored change stays restored after a later acknowledgement (D4-19)": {
			[]*audit.Record{ackRec(cfg, hBase), detectedRec(hBase, hSnap, hDiff, false), restoredRec(hBase), ackRec(cfg, hBase)},
			[]string{"baseline " + hBase[7:13] + " ref 3", "restored-difference " + hSnap[7:13] + " ref 1", "restored-difference " + hDiff[7:13] + " ref 1"}},
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
		baseline: canonicalBaseline(t)}
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

// A return to the baseline ends the alarm and not the evidence (D4-19): the
// snapshot and the difference are re-reasoned to restored-difference with the
// change record as Ref, the baseline stays, and a second start corrects
// nothing. An approval accepted afterwards would not have ended the alarm
// (audit.VerifyConfig), so the fold ignores it.
func TestReturnToBaselineKeepsTheDifference(t *testing.T) {
	h := newHoldsNode(t)
	var det c5.Seq
	_, _, _ = h.restart(func(r *Runtime) {
		putAudit(t, r, ackRec(authz.BaselineConfiguration, config.Digest(h.snap1)))
		det = putAudit(t, r, detectedRec(config.Digest(h.snap1), config.Digest(h.snap2), config.Digest(h.diff), false))
	})
	got, alarms, r := h.restart(func(r *Runtime) {
		putAudit(t, r, restoredRec(config.Digest(h.snap1)))
	})
	if len(got) != 3 || got[1].Code != c5.HoldBaseline ||
		got[2] != reasonAt(r, det, c5.HoldRestoredDifference) || got[3] != reasonAt(r, det, c5.HoldRestoredDifference) {
		t.Fatalf("holds %+v, want the baseline and the two documents as restored-difference", got)
	}
	if n := reconciled(alarms); n != 2 {
		t.Errorf("%d reconcile alarms, want 2 reason corrections: %+v", n, alarms)
	}
	_, alarms, _ = h.restart(nil)
	if n := reconciled(alarms); n != 0 {
		t.Errorf("the next start corrected %d holds: %+v", n, alarms)
	}
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

// A configuration acknowledgement ends an alarm and not the evidence
// (D4-18): the snapshot and the difference stay held as
// acknowledged-difference with the change record as Ref, the old baseline is
// released, and a second start corrects nothing (B6 on #305).
func TestAcknowledgedDifferenceStaysHeld(t *testing.T) {
	h := newHoldsNode(t)
	var det, ackB c5.Seq
	got, _, r := h.restart(func(r *Runtime) {
		putAudit(t, r, ackRec(authz.BaselineConfiguration, config.Digest(h.snap1)))
		det = putAudit(t, r, detectedRec(config.Digest(h.snap1), config.Digest(h.snap2), config.Digest(h.diff), false))
	})
	if len(got) != 3 {
		t.Fatalf("with the alarm open, holds %v", got)
	}
	// B is the C10 document's digest: any stored record can be acknowledged.
	got, _, r = h.restart(func(r *Runtime) {
		ackB = putAudit(t, r, ackRec(authz.BaselineConfiguration, config.Digest(h.baseline)))
	})
	want := map[c5.Seq]c5.HoldReason{
		2: reasonAt(r, det, c5.HoldAcknowledgedDifference),
		3: reasonAt(r, det, c5.HoldAcknowledgedDifference),
		4: reasonAt(r, ackB, c5.HoldBaseline),
	}
	if len(got) != len(want) {
		t.Fatalf("holds %v, want %v", got, want)
	}
	for s, w := range want {
		if got[s] != w {
			t.Errorf("seq %d held as %+v, want %+v", s, got[s], w)
		}
	}
	_, alarms, _ := h.restart(nil)
	if n := reconciled(alarms); n != 0 {
		t.Errorf("the next start corrected %d holds: %+v", n, alarms)
	}
}

// A hold of a code this node does not know is kept as it is, whatever the
// records say (C5 0.6): not released, not given a new reason, not added over.
func TestUnknownHoldCodeIsKept(t *testing.T) {
	node := c5.NodeID("n")
	ref := func(seq c5.Seq) c5.Key { return c5.Key{NodeID: node, Stream: AuditStream, Seq: seq} }
	have := []c5.HeldRecord{
		{Seq: 1, Reason: c5.HoldReason{Code: "future-code", Ref: ref(9)}},   // wanted, as a baseline
		{Seq: 2, Reason: c5.HoldReason{Code: "future-code", Ref: ref(9)}},   // not wanted at all
		{Seq: 3, Reason: c5.HoldReason{Code: c5.HoldBaseline, Ref: ref(9)}}, // not wanted: released
	}
	wants := []wantHold{{digest: "d1", code: c5.HoldBaseline, ref: 4}}
	p := planHolds(node, wants, map[string]c5.Seq{"d1": 1}, have)
	if len(p.unknown) != 2 || len(p.add) != 0 || len(p.replace) != 0 || len(p.release) != 1 || p.release[0].Seq != 3 {
		t.Fatalf("plan %+v", p)
	}
}

// An audit stream that has been pruned past the acknowledgement and the
// detection no longer shows what the holds came from, and the reconcile
// releases and corrects nothing (B6 on #305). Fails without the pruned check:
// all three holds are released as unjustified.
func TestPrunedAuditKeepsEveryHold(t *testing.T) {
	h := newHoldsNode(t)
	h.restart(func(r *Runtime) {
		putAudit(t, r, ackRec(authz.BaselineConfiguration, config.Digest(h.snap1)))
		putAudit(t, r, detectedRec(config.Digest(h.snap1), config.Digest(h.snap2), config.Digest(h.diff), false))
	})
	want, _, _ := h.restart(nil)
	if len(want) != 3 {
		t.Fatalf("before the prune, holds %v", want)
	}
	h.restart(func(r *Runtime) {
		fwd := c5.Consumer{ID: "fwd", Stream: AuditStream, Delivery: c5.Required}
		db := r.Store(AuditStream)
		last, err := db.LastCommitted(bg, AuditStream)
		if err != nil {
			t.Fatal(err)
		}
		// The forwarder has confirmed the whole stream, and the suspension
		// checkpoint (which pruneConsumers adds) has reached it.
		for _, id := range []c5.ConsumerID{fwd.ID, SuspensionConsumer} {
			if err := db.SaveCursor(bg, c5.Cursor{Consumer: id, Stream: AuditStream, Through: last}); err != nil {
				t.Fatal(err)
			}
		}
		b, err := c5.ComputeBoundary(bg, db, db, pruneConsumers([]c5.Consumer{fwd}), AuditStream, c5.ClassAudit, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if n, err := db.PruneStep(bg, b, 1000); err != nil || n == 0 {
			t.Fatalf("pruned %d: %v", n, err)
		}
	})
	got, alarms, _ := h.restart(nil)
	if len(got) != len(want) {
		t.Fatalf("after the prune, holds %v, want %v", got, want)
	}
	for s, w := range want {
		if got[s] != w {
			t.Errorf("seq %d held as %+v, want %+v", s, got[s], w)
		}
	}
	var said bool
	for _, a := range alarms {
		if a.Code == string(c5.AlarmHoldsReconciled) && strings.Contains(a.Detail, "pruned") {
			said = true
		}
	}
	if !said {
		t.Errorf("no alarm says the audit stream is pruned: %+v", alarms)
	}
}
