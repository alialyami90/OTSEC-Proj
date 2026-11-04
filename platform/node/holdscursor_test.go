package node

import (
	"fmt"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/audit"
	"otsec.local/otsec/contracts/authz"
	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/platform/node/nodeconfigtest"
)

// The holds cursor's tests (D4-41). Evidence class: simulated.

const holdsAuditQuota = 64 << 10

// newCursorNode is a signedCfgNode whose audit stream is forwarded, so its
// prune consumers include HoldsConsumer, and whose audit quota is small
// enough to fill.
func newCursorNode(t *testing.T) *signedCfgNode {
	t.Helper()
	n := newSignedCfgNode(t, func(nc *nodeconfigtest.Config) {
		nc.AddRELPTarget("central", "127.0.0.1", 2514, "test-ca", "test-client", "test/durable-ack", true)
		nc.Store.Quotas["audit"] = holdsAuditQuota
	})
	t.Cleanup(func() { holdFaults.ack, holdFaults.reconcile = nil, nil })
	return n
}

// restart closes the node and starts it again, as after a crash.
func (n *signedCfgNode) restart() {
	n.t.Helper()
	n.r.Close()
	r, st, _ := start(n.t, n.c, n.dir)
	n.t.Cleanup(func() { r.Close() })
	n.r, n.st = r, st
	n.s = newScheduler(n.t, r, n.mux)
}

// confirm moves every audit consumer but HoldsConsumer to the stream's last
// record: the scheduler writes its suspension checkpoint and the forwarder
// confirms the stream, so only the holds cursor bounds a prune.
func (n *signedCfgNode) confirm() c5.Seq {
	n.t.Helper()
	n.s.settle(bg)
	db := n.r.Store(AuditStream)
	last, err := db.LastCommitted(bg, AuditStream)
	if err != nil {
		n.t.Fatal(err)
	}
	for _, c := range n.r.find(AuditDB).policy.Consumers {
		if c.ID == HoldsConsumer || c.ID == SuspensionConsumer {
			continue
		}
		if err := db.SaveCursor(bg, c5.Cursor{Consumer: c.ID, Stream: AuditStream, Through: last}); err != nil {
			n.t.Fatal(err)
		}
	}
	return last
}

// fill appends audit records until the class is over its prune target, and
// confirms them.
func (n *signedCfgNode) fill() {
	n.t.Helper()
	d := n.r.find(AuditDB)
	for i := 0; ; i++ {
		over, err := n.r.overTarget(bg, d, n.r.Store(AuditStream))
		if err != nil {
			n.t.Fatal(err)
		}
		if over {
			break
		}
		if i == 1000 {
			n.t.Fatal("the audit class is not over its target")
		}
		n.r.audit(bg, audit.ActionStorageAlarm, audit.OutcomeWarning, "filler", fmt.Sprintf("filler %d %s", i, strings.Repeat("x", 400)))
	}
	n.confirm()
}

func (n *signedCfgNode) holdsCursor() c5.Seq {
	n.t.Helper()
	cs, err := n.r.Store(AuditStream).LoadCursors(bg, AuditStream)
	if err != nil {
		n.t.Fatal(err)
	}
	for _, c := range cs {
		if c.Consumer == HoldsConsumer {
			return c.Through
		}
	}
	return 0
}

func (n *signedCfgNode) firstAudit() c5.Seq {
	n.t.Helper()
	first, err := n.r.Store(AuditStream).FirstRetained(bg, AuditStream)
	if err != nil {
		n.t.Fatal(err)
	}
	return first
}

func (n *signedCfgNode) raised(code string) int {
	k := 0
	for _, a := range n.st.Snapshot("n").Alarms {
		if a.Code == code {
			k++
		}
	}
	return k
}

// An acknowledgement followed by an audit prune in the same run: the hold is
// taken after the Receipt, so the prune may pass the acknowledgement, and
// after a restart the baseline is still the one held.
func TestHoldsCursorAcknowledgementThenPrune(t *testing.T) {
	n := newCursorNode(t)
	if !strings.Contains(fmt.Sprint(n.r.find(AuditDB).policy.Consumers), string(HoldsConsumer)) {
		t.Fatalf("no holds consumer: %+v", n.r.find(AuditDB).policy.Consumers)
	}
	base := n.snapshotOf("ok")
	n.read("ok")
	n.ackSigned(authz.BaselineConfiguration, base)
	ack := n.lastSeq(audit.ActionConfigBaselineAcknowledge)
	if h := n.holds(); h[1] != c5.HoldBaseline {
		t.Fatalf("holds %v", h)
	}
	n.fill()
	n.r.Prune(bg)
	if c, first := n.holdsCursor(), n.firstAudit(); c <= ack || first <= ack {
		t.Fatalf("holds cursor %d, first retained %d: the prune did not pass the acknowledgement at %d", c, first, ack)
	}
	n.restart()
	if h := n.holds(); h[1] != c5.HoldBaseline {
		t.Fatalf("holds after the restart %v", h)
	}
	n.read("ok")
	if res := n.pruned(); len(res) == 0 || res[len(res)-1].Action != audit.ActionConfigReadCompared || res[len(res)-1].Config.BaselineDigest != base {
		t.Fatalf("results %+v", res)
	}

	// A second acknowledgement on the pruned view, of a snapshot already
	// held as an unapproved difference: it is held as the baseline at once,
	// though a pruned view corrects no other reason, so once the prune
	// passes the acknowledgement the node still compares against it. The
	// first baseline keeps its hold, and the newer Ref wins (D4-41).
	next := n.snapshotOf("ok-all-present")
	n.read("ok-all-present")
	n.ackSigned(authz.BaselineConfiguration, next)
	second := n.lastSeq(audit.ActionConfigBaselineAcknowledge)
	if h := n.holds(); h[3] != c5.HoldBaseline {
		t.Fatalf("holds %v: the acknowledged snapshot is not held as the baseline", h)
	}
	n.fill()
	n.r.Prune(bg)
	if c, first := n.holdsCursor(), n.firstAudit(); c <= second || first <= second {
		t.Fatalf("holds cursor %d, first retained %d: the prune did not pass the second acknowledgement at %d", c, first, second)
	}
	n.restart()
	n.read("ok-all-present")
	if res := n.pruned(); res[len(res)-1].Action != audit.ActionConfigReadCompared || res[len(res)-1].Config.BaselineDigest != next {
		t.Fatalf("last result %+v %+v", res[len(res)-1], res[len(res)-1].Config)
	}
	if k := n.raised(AlarmHoldsNotTaken); k != 0 {
		t.Fatalf("%d %s alarms", k, AlarmHoldsNotTaken)
	}
}

// A crash between the acknowledgement's Receipt and its hold, then a
// start-up prune: the holds cursor stays before the acknowledgement, so
// neither the runtime prune nor the start-up prune passes it, and the next
// start's reconcile takes the hold. A reconcile that cannot take it leaves
// the cursor where it was.
func TestHoldsCursorCrashBeforeTheHold(t *testing.T) {
	n := newCursorNode(t)
	base := n.snapshotOf("ok")
	n.read("ok")
	holdFaults.ack = func() error { return errFault }
	n.ackSigned(authz.BaselineConfiguration, base)
	ack := n.lastSeq(audit.ActionConfigBaselineAcknowledge)
	if h := n.holds(); h[1] == c5.HoldBaseline {
		t.Fatalf("holds %v: the fault did not stop the hold", h)
	}
	before := n.holdsCursor()
	if before >= ack {
		t.Fatalf("holds cursor %d at or past the acknowledgement at %d", before, ack)
	}
	n.fill()
	n.r.Prune(bg)
	n.r.Prune(bg)
	if c, first := n.holdsCursor(), n.firstAudit(); c != before || first > ack {
		t.Fatalf("holds cursor %d (was %d), first retained %d: the runtime prune passed the acknowledgement at %d", c, before, first, ack)
	}
	if first := n.firstAudit(); first <= 1 {
		t.Fatalf("first retained %d: nothing was pruned, so the bound is not shown", first)
	}
	if k := n.raised(AlarmHoldsNotTaken); k != 1 {
		t.Fatalf("%d %s alarms, want 1", k, AlarmHoldsNotTaken)
	}

	// The crash. The next start's reconcile cannot take the hold either.
	holdFaults.ack = nil
	holdFaults.reconcile = func() error { return errFault }
	n.fill()
	n.restart()
	if c, first := n.holdsCursor(), n.firstAudit(); c != before || first > ack {
		t.Fatalf("holds cursor %d (was %d), first retained %d: the start-up prune passed the acknowledgement at %d", c, before, first, ack)
	}
	if k := n.raised(AlarmHoldsNotTaken); k != 1 {
		t.Fatalf("%d %s alarms, want 1", k, AlarmHoldsNotTaken)
	}

	// Then one that can.
	holdFaults.reconcile = nil
	n.fill()
	n.restart()
	if first := n.firstAudit(); first > ack {
		t.Fatalf("first retained %d: the start-up prune passed the acknowledgement at %d", first, ack)
	}
	if h := n.holds(); h[1] != c5.HoldBaseline {
		t.Fatalf("holds %v: the reconcile did not take the hold", h)
	}
	if c := n.holdsCursor(); c <= ack {
		t.Fatalf("holds cursor %d not past the acknowledgement at %d once its hold is taken", c, ack)
	}
	n.fill()
	n.r.Prune(bg)
	if first := n.firstAudit(); first <= ack {
		t.Fatalf("first retained %d: the acknowledgement at %d is still kept once its hold is taken", first, ack)
	}
}

// On a pruned view, a crash between an acknowledgement's Receipt and its
// hold leaves the acknowledged snapshot held as an unapproved difference;
// the next start's reconcile holds it as the baseline, and only then does
// the cursor pass the acknowledgement.
func TestHoldsCursorPrunedReconcileTakesTheBaseline(t *testing.T) {
	n := newCursorNode(t)
	base, next := n.snapshotOf("ok"), n.snapshotOf("ok-all-present")
	n.read("ok")
	n.ackSigned(authz.BaselineConfiguration, base)
	first := n.lastSeq(audit.ActionConfigBaselineAcknowledge)
	n.fill()
	n.r.Prune(bg)
	if f := n.firstAudit(); f <= first {
		t.Fatalf("first retained %d: the view is not pruned past the first acknowledgement at %d", f, first)
	}
	// A read in the retained chain bounds the change (C3 on #390).
	n.read("ok")
	n.read("ok-all-present")
	holdFaults.ack = func() error { return errFault }
	n.ackSigned(authz.BaselineConfiguration, next)
	ack := n.lastSeq(audit.ActionConfigBaselineAcknowledge)
	if h := n.holds(); h[3] != c5.HoldUnapprovedDifference {
		t.Fatalf("holds %v", h)
	}
	if c := n.holdsCursor(); c >= ack {
		t.Fatalf("holds cursor %d at or past the acknowledgement at %d", c, ack)
	}
	holdFaults.ack = nil
	n.restart()
	if h := n.holds(); h[3] != c5.HoldBaseline {
		t.Fatalf("holds %v: the reconcile did not hold the acknowledged snapshot as the baseline", h)
	}
	if c := n.holdsCursor(); c <= ack {
		t.Fatalf("holds cursor %d not past the acknowledgement at %d", c, ack)
	}
}
