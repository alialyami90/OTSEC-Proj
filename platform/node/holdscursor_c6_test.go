package node

import (
	"database/sql"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"

	"otsec.local/otsec/contracts/audit"
	"otsec.local/otsec/contracts/authz"
	c5 "otsec.local/otsec/contracts/store"
)

// C6's probes on #408 (HoldsConsumer, D4-41), adopted from C6 as written.
// Evidence class: simulated.

// c6Difference acknowledges "ok", lets the holds cursor pass it, then reads
// "ok-all-present", whose difference the writer holds. It returns the cursor
// before the read, the writer's record and the held configuration record.
func c6Difference(t *testing.T, n *signedCfgNode) (before, writer, held c5.Seq) {
	t.Helper()
	n.read("ok")
	n.ackSigned(authz.BaselineConfiguration, n.snapshotOf("ok"))
	n.r.advanceHolds(bg)
	before = n.holdsCursor()
	if before < n.lastSeq(audit.ActionConfigBaselineAcknowledge) {
		t.Fatalf("holds cursor %d before the acknowledgement", before)
	}
	n.read("ok-all-present")
	writer = n.lastSeq(audit.ActionConfigChangeDetected)
	for s, c := range n.holds() {
		if c == c5.HoldUnapprovedDifference && s > held {
			held = s
		}
	}
	if held == 0 {
		t.Fatalf("holds %v: no unapproved difference", n.holds())
	}
	return before, writer, held
}

func (n *signedCfgNode) c6Behind(t *testing.T, before, writer c5.Seq, what string) {
	t.Helper()
	n.r.advanceHolds(bg)
	if c := n.holdsCursor(); c != before || c >= writer {
		t.Fatalf("holds cursor %d (was %d), writer record %d: it passed %s", c, before, writer, what)
	}
	if k := n.raised(AlarmHoldsNotTaken); k != 1 {
		t.Fatalf("%d %s alarms, want 1", k, AlarmHoldsNotTaken)
	}
}

// The writer's hold not taken (D4-41's "a writer record at N-1 whose hold is
// still being taken"): the cursor does not pass the writer's record, though
// a later acknowledgement's holds are all taken.
func TestC6ProbeWriterHoldNotTaken(t *testing.T) {
	n := newCursorNode(t)
	before, writer, held := c6Difference(t, n)
	if err := n.r.Store(ConfigStream(relayID)).Release(bg, ConfigStream(relayID), held); err != nil {
		t.Fatal(err)
	}
	n.ackSigned(authz.BaselineConfiguration, n.snapshotOf("ok"))
	n.c6Behind(t, before, writer, "a difference whose hold is not taken")
}

// A hold with the wrong reason on a full view is not taken (H3c).
func TestC6ProbeWrongReasonFullView(t *testing.T) {
	n := newCursorNode(t)
	before, writer, held := c6Difference(t, n)
	if err := n.r.Store(ConfigStream(relayID)).Hold(bg, c5.Hold{Stream: ConfigStream(relayID), Seq: held,
		Reason: c5.HoldReason{Code: c5.HoldApprovedDifference, Ref: c5.Key{NodeID: n.r.cfg.NodeID, Stream: AuditStream, Seq: writer}}}); err != nil {
		t.Fatal(err)
	}
	n.c6Behind(t, before, writer, "a hold with the wrong reason")
}

// A C8 record whose configuration record is not stored keeps the cursor
// (H3b).
func TestC6ProbeRecordNotStored(t *testing.T) {
	n := newCursorNode(t)
	before, writer, held := c6Difference(t, n)
	paths, _ := filepath.Glob(filepath.Join(n.c.Store.Dir, "*.db"))
	k := int64(0)
	for _, p := range paths {
		db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(p)+"?_pragma=busy_timeout(5000)")
		if err != nil {
			t.Fatal(err)
		}
		if res, err := db.Exec(`DELETE FROM events WHERE stream = ? AND seq = ?`, string(ConfigStream(relayID)), int64(held)); err == nil {
			d, _ := res.RowsAffected()
			k += d
		}
		db.Close()
	}
	if k != 1 {
		t.Fatalf("deleted %d records", k)
	}
	n.c6Behind(t, before, writer, "a record not stored")
}

// c6PrunedView acknowledges "ok" and prunes the audit stream past it.
func c6PrunedView(t *testing.T, n *signedCfgNode) {
	t.Helper()
	n.read("ok")
	n.ackSigned(authz.BaselineConfiguration, n.snapshotOf("ok"))
	ack := n.lastSeq(audit.ActionConfigBaselineAcknowledge)
	n.fill()
	n.r.Prune(bg)
	if f := n.firstAudit(); f <= ack {
		t.Fatalf("first retained %d: the view is not pruned past %d", f, ack)
	}
	n.read("ok")
}

func (n *signedCfgNode) c6Unapproved(t *testing.T) []c5.Seq {
	t.Helper()
	var out []c5.Seq
	for s, c := range n.holds() {
		if c == c5.HoldUnapprovedDifference {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		t.Fatalf("holds %v: no unapproved difference", n.holds())
	}
	return out
}

// On a pruned view a difference hold with another reason counts as taken,
// as the reconcile corrects no other reason there (H6, H11): the cursor
// passes it, and the reconcile leaves the reason.
func TestC6ProbeWrongReasonPrunedView(t *testing.T) {
	n := newCursorNode(t)
	c6PrunedView(t, n)
	// A baseline acknowledged in the view, and a change against it.
	n.read("ok-all-present")
	n.ackSigned(authz.BaselineConfiguration, n.snapshotOf("ok-all-present"))
	n.read("ok")
	writer := n.lastSeq(audit.ActionConfigChangeDetected)
	before := n.holds()
	var held c5.Seq
	for s, c := range before {
		if c == c5.HoldUnapprovedDifference && s > held {
			held = s
		}
	}
	if held == 0 {
		t.Fatalf("holds %v", before)
	}
	if err := n.r.Store(ConfigStream(relayID)).Hold(bg, c5.Hold{Stream: ConfigStream(relayID), Seq: held,
		Reason: c5.HoldReason{Code: c5.HoldApprovedDifference, Ref: c5.Key{NodeID: n.r.cfg.NodeID, Stream: AuditStream, Seq: writer}}}); err != nil {
		t.Fatal(err)
	}
	n.r.advanceHolds(bg)
	if c := n.holdsCursor(); c < writer {
		t.Fatalf("holds cursor %d not past the writer record %d", c, writer)
	}
	if k := n.raised(AlarmHoldsNotTaken); k != 0 {
		t.Fatalf("%d %s alarms", k, AlarmHoldsNotTaken)
	}
	n.restart()
	if h := n.holds(); h[held] != c5.HoldApprovedDifference {
		t.Fatalf("holds %v (were %v): the pruned reconcile corrected a reason other than the baseline", h, before)
	}
}

// A crash between a change record's Receipt and its holds, on a view pruned
// past the baseline's acknowledgement: D4-41 says the cursor covers the
// writer's differences, so it must not pass the change record, and the next
// start's reconcile must take its holds.
func TestC6ProbePrunedWriterHoldNotTaken(t *testing.T) {
	n := newCursorNode(t)
	c6PrunedView(t, n)
	n.r.advanceHolds(bg)
	before := n.holdsCursor()
	n.read("ok-all-present")
	writer := n.lastSeq(audit.ActionConfigChangeDetected)
	held := n.c6Unapproved(t)
	for _, s := range held {
		if err := n.r.Store(ConfigStream(relayID)).Release(bg, ConfigStream(relayID), s); err != nil {
			t.Fatal(err)
		}
	}
	n.r.advanceHolds(bg)
	if c := n.holdsCursor(); c >= writer {
		t.Fatalf("holds cursor %d (was %d) passed the change record %d whose holds %v are not taken", c, before, writer, held)
	}
	n.restart()
	h := n.holds()
	for _, s := range held {
		if h[s] != c5.HoldUnapprovedDifference {
			t.Fatalf("holds %v: the reconcile did not take the change's hold on %d", h, s)
		}
	}
}

// C6's re-check probe on #408 at 1d85c13 (N4c), adopted as written.
// P6: TestHoldsCursorPrunedRestoreReCode for an unapproved change (D4-19):
// on a pruned view, a return whose re-code of an open change fails, with
// the change's detection already pruned. The cursor does not pass the
// return, and the next start's reconcile moves the change to
// restored-difference.
func TestC6ProbePrunedRestoreReCodeUnapproved(t *testing.T) {
	n := newCursorNode(t)
	base := n.snapshotOf("ok")
	n.read("ok")
	n.ackSigned(authz.BaselineConfiguration, base)
	n.fill()
	n.r.Prune(bg)
	n.read("ok")
	n.read("ok-all-present")
	det := n.lastSeq(audit.ActionConfigChangeDetected)
	open := n.c6Unapproved(t)
	n.fill()
	n.r.Prune(bg)
	if f := n.firstAudit(); f <= det {
		t.Fatalf("first retained %d: the detection at %d is not pruned", f, det)
	}
	holdFaults.restore = func() error { return errFault }
	n.read("ok")
	restored := n.lastSeq(audit.ActionConfigBaselineRestored)
	holdFaults.restore = nil
	for _, s := range open {
		if h := n.holds(); h[s] != c5.HoldUnapprovedDifference {
			t.Fatalf("holds %v: the fault did not stop the re-code", h)
		}
	}
	n.r.advanceHolds(bg)
	if c := n.holdsCursor(); c >= restored {
		t.Fatalf("holds cursor %d at or past the return at %d whose re-code failed", c, restored)
	}
	n.restart()
	for _, s := range open {
		if h := n.holds(); h[s] != c5.HoldRestoredDifference {
			t.Fatalf("holds %v: the reconcile did not move %d to restored-difference", h, s)
		}
	}
	if c := n.holdsCursor(); c < restored {
		t.Fatalf("holds cursor %d not past the return at %d", c, restored)
	}
}
