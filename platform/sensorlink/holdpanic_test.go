package sensorlink

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"otsec.local/otsec/contracts/netobs"
)

// The release paths' faults found in the re-reviews of #676's 98aa92e8.
// Desk only: no sensor and no device; the store is on the local disk.

// D3's B1 and D6's B2: the record that reaches the record cap while the
// stream's head can't be read is not lost. The release does not begin, so
// takeHeld reports false, and the read loop commits the record untied at
// once; record_cap_releases counts no release, and the run's held records
// stay held until the deadline commits them untied. D3's probe. Control:
// takeHeld's release error ignored (it returns true), as at 98aa92e8,
// under which seq 24 is never committed.
func TestRecordCapHeadUnreadCommitted(t *testing.T) {
	s := &gatedStore{}
	g := gatedRig(t, s)
	g.dispatch("req-1")
	g.send(g.obs("start", 40001, 0))
	for heldCount(g.l.hold.runs["req-1"].rec) < HoldRecordCap {
		g.send(g.obs("function", 40001, time.Second))
	}
	s.headFail.Store(true)
	g.send(g.obs("function", 40001, 2*time.Second)) // seq HoldRecordCap+1 reaches the cap
	s.headFail.Store(false)
	st := g.l.Stats().Hold
	if c := g.committed(); len(c) != 1 || c[0] != (tied{seq: HoldRecordCap + 1}) || st.RecordCapReleases != 0 || st.HeadUnread != 1 || st.Held != HoldRecordCap {
		t.Fatalf("at the cap with no head: committed %+v, %+v; want seq %d alone, untied, no release counted, %d held",
			c, st, HoldRecordCap+1, HoldRecordCap)
	}
	g.wall = g.wall.Add(HoldRunLimit + time.Hour)
	g.l.TickHold(bg)
	if c := g.committed(); len(c) != HoldRecordCap+1 {
		t.Fatalf("after the deadline: %d committed, want %d", len(c), HoldRecordCap+1)
	}
}

// D6's B2: a waiting dial's end while the stream's head can't be read is
// not lost, and its staged tie never reaches a later release. The end (seq
// 5) commits untied at once, the waiting dial's seq 3 stays held until its
// wait releases it untied, and tied counts only the two flows the result
// tied. D6's probe. Control: takeHeld's release error ignored, as at
// 98aa92e8, under which seq 5 is never committed and tied reads 3.
func TestWaitingEndHeadUnreadCommitted(t *testing.T) {
	s := &gatedStore{}
	g := gatedRig(t, s)
	g.dispatch("req-1")
	g.send(g.obs("start", 40001, 0), g.obs("syn", 40001, time.Second), g.obs("start", 40002, 2*time.Second), g.obs("start", 40003, 3*time.Second))
	if _, err := g.l.Result(bg, "req-1", session09(inv1, 40003, 3*time.Second)); err != nil {
		t.Fatal(err)
	}
	s.headFail.Store(true)
	g.send(g.obs("syn", 40002, 5*time.Second)) // seq 5, the waiting dial's end
	s.headFail.Store(false)
	if p := g.l.hold.pendingTied; p != 0 || len(g.l.hold.pending) != 0 {
		t.Fatalf("staged after a release not begun: pendingTied %d, %d pending; want none", p, len(g.l.hold.pending))
	}
	want(t, g.committed(), tied{1, inv1, TieWindow}, tied{2, inv1, TieWindow}, tied{4, inv1, TieConnection}, tied{seq: 5})
	g.wall = g.wall.Add(HoldDialLimit + netobs.DefaultFlowIdleS*time.Second + time.Hour)
	g.l.TickHold(bg)
	want(t, g.committed(), tied{1, inv1, TieWindow}, tied{2, inv1, TieWindow}, tied{4, inv1, TieConnection}, tied{seq: 5}, tied{seq: 3})
	if st := g.l.Stats().Hold; st.Tied != 2 || st.Runs != 0 {
		t.Fatalf("after the wait: %+v; want tied 2 and no run", st)
	}
}

// D6's N1, D4's condition (ii): a panic inside the batch before it commits
// is before the receipts. The Result times out, the run stays held, and
// its deadline commits the flow untied, once. Control: the receipts taken
// just before AppendBatch is called, under which the release finishes with
// nothing committed and the flow is lost.
func TestPanicInBatchBeforeCommit(t *testing.T) {
	s := &gatedStore{}
	g := gatedRig(t, s)
	g.dispatch("run-1")
	g.send(g.obs("start", 40001, time.Second))
	s.panicBatch.Store(true)
	if _, err := g.l.Result(bg, "run-1", session09(inv1, 40001, 2*time.Second)); !errors.Is(err, ErrHoldTimeout) {
		t.Fatalf("result with a panic in the batch: %v; want ErrHoldTimeout", err)
	}
	if c := g.committed(); len(c) != 0 || g.l.hold.runs["run-1"] == nil {
		t.Fatalf("after the panic: committed %+v, still held %v; want nothing, held", c, g.l.hold.runs["run-1"] != nil)
	}
	g.wall = g.wall.Add(HoldRunLimit + time.Hour)
	g.l.TickHold(bg)
	want(t, g.committed(), tied{seq: 1})
}

// D3's B2 and D4's note: after a panic before the receipts, the run's
// holding record is saved again over its releasing record, so a restart
// before the deadline finds the run holding, and RecoverHold commits
// nothing tied to the session the Result never handed on. The deadline
// then commits seq 1 once, untied. D3's probe, with the restart. Control:
// no re-save, as at 98aa92e8, under which RecoverHold commits seq 1 tied
// to inv1.
func TestPanicBeforeBatchRestartUntied(t *testing.T) {
	s := &gatedStore{}
	g := gatedRig(t, s)
	g.dispatch("run-1")
	g.send(g.obs("start", 40001, time.Second))
	s.panicBatch.Store(true)
	if _, err := g.l.Result(bg, "run-1", session09(inv1, 40001, 2*time.Second)); !errors.Is(err, ErrHoldTimeout) {
		t.Fatalf("result with a panic in the batch: %v; want ErrHoldTimeout", err)
	}
	if n := g.l.Stats().Hold.CheckpointFailures; n != 0 {
		t.Fatalf("%d checkpoint failures after a re-save that succeeded", n)
	}
	g.l = g.link(g.restore()) // the restart
	g.l.opt.Store = s
	if err := g.l.RecoverHold(bg); err != nil {
		t.Fatal(err)
	}
	if c := g.committed(); len(c) != 0 {
		t.Fatalf("committed at the restart: %+v; want nothing", c)
	}
	g.wall = g.wall.Add(HoldRunLimit + time.Hour)
	g.l.TickHold(bg)
	want(t, g.committed(), tied{seq: 1})
}

// The re-save's own faults: a re-save that fails, or panics, is counted in
// checkpoint_failures, and the first panic is still taken as a timeout, so
// the state is as with no re-save. Control: the re-save's recover removed,
// under which its panic replaces the first one and nothing is counted.
func TestPanicBeforeBatchResaveFails(t *testing.T) {
	for _, mode := range []string{"error", "panic"} {
		t.Run(mode, func(t *testing.T) {
			s := &gatedStore{}
			g := gatedRig(t, s)
			g.dispatch("run-1")
			g.send(g.obs("start", 40001, time.Second))
			save := g.l.hold.cfg.Save
			g.l.hold.cfg.Save = func(ctx context.Context, rec RunRecord) error {
				if rec.State == HoldHolding {
					if mode == "panic" {
						panic("sensorlink test: a fault in the re-save")
					}
					return errors.New("sensorlink test: the re-save fails")
				}
				return save(ctx, rec)
			}
			s.panicBatch.Store(true)
			_, err := g.l.Result(bg, "run-1", session09(inv1, 40001, 2*time.Second))
			g.l.hold.cfg.Save = save
			st := g.l.Stats()
			if !errors.Is(err, ErrHoldTimeout) || st.ResultTimeouts != 1 || st.Hold.CheckpointFailures != 1 ||
				st.SchedPanics != 1 || !strings.Contains(st.LastSchedPanic, "before it commits") {
				t.Fatalf("a re-save that fails by %s: %v, %d timeouts, %d checkpoint failures, panic %q", mode, err, st.ResultTimeouts, st.Hold.CheckpointFailures, st.LastSchedPanic)
			}
			if h := g.l.hold.runs["run-1"]; h == nil || h.rec.State != HoldHolding {
				t.Fatal("the run is not held in memory after the panic")
			}
		})
	}
}

// D6's N3: Abandon has result's phased clean-up. A panic in the save after
// its batch finishes the release: Abandon returns the receipts' seq, the
// run leaves the hold, the panic is counted as a checkpoint failure, and
// the deadline commits nothing again. Control: Abandon without the
// deferred endPhase, under which it times out and the deadline commits
// seq 1 a second time.
func TestAbandonPanicAfterBatchFinished(t *testing.T) {
	g := newHoldRig(t)
	g.dispatch("run-1")
	g.send(g.obs("start", 40001, time.Second))
	save := g.l.hold.cfg.Save
	g.l.hold.cfg.Save = func(ctx context.Context, rec RunRecord) error {
		if rec.State == HoldReleased {
			panic("sensorlink test: a fault in the save after the batch")
		}
		return save(ctx, rec)
	}
	head, err := g.l.Abandon(bg, "run-1")
	g.l.hold.cfg.Save = save
	if err != nil || head != 1 {
		t.Fatalf("abandon with a panic after the batch: head %d, %v; want 1", head, err)
	}
	if st := g.l.Stats(); g.l.hold.runs["run-1"] != nil || st.SchedPanics != 1 || st.ResultTimeouts != 0 || st.Hold.CheckpointFailures != 1 {
		t.Fatalf("still held %v, %d panics, %d timeouts, %d checkpoint failures", g.l.hold.runs["run-1"] != nil, st.SchedPanics, st.ResultTimeouts, st.Hold.CheckpointFailures)
	}
	g.wall = g.wall.Add(HoldRunLimit + time.Hour)
	g.l.TickHold(bg)
	want(t, g.committed(), tied{seq: 1})
}
