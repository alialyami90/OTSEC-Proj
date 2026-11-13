package sensorlink

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	c5 "otsec.local/otsec/contracts/store"
)

// The link's lock and the scheduler's calls (docs/phase4/D5-sensor-node.md
// section 1.9 items 4 and 9; F-027's F4). Desk only: no sensor and no
// device; the store is on the local disk.

// gatedStore is a netStore whose appends a test can slow or hold, and
// whose head read it can make fail.
type gatedStore struct {
	netStore
	delay    time.Duration
	gate     chan struct{} // when set, an append waits for it to close
	entered  chan struct{} // closed at the first append that waits
	once     sync.Once
	headFail atomic.Bool
}

func (s *gatedStore) wait() {
	if s.gate != nil {
		s.once.Do(func() { close(s.entered) })
		<-s.gate
	}
	time.Sleep(s.delay)
}

func (s *gatedStore) Append(ctx context.Context, rec c5.Record) (c5.Receipt, error) {
	s.wait()
	return s.netStore.Append(ctx, rec)
}

func (s *gatedStore) AppendBatch(ctx context.Context, recs []c5.Record) ([]c5.Receipt, error) {
	s.wait()
	return s.netStore.AppendBatch(ctx, recs)
}

func (s *gatedStore) LastCommitted(ctx context.Context) (uint64, error) {
	if s.headFail.Load() {
		return 0, errors.New("test: the network database is swapped out")
	}
	return s.netStore.LastCommitted(ctx)
}

// gatedRig is a hold rig whose link commits through a gatedStore.
func gatedRig(t *testing.T, s *gatedStore) *holdRig {
	t.Helper()
	g := newHoldRig(t)
	s.netStore = g.s
	l, err := New(g.l.cfg, g.l.opt)
	if err != nil {
		t.Fatal(err)
	}
	l.opt.Store = s
	g.l = l
	return g
}

// others are resolved flows to the relay from an address not the node's,
// so each commits at once, untied, on the read loop.
func others(g *holdRig, n int) []any {
	var out []any
	for range n {
		g.seq++
		o := flow(g.seq, "192.0.2.30", endpoint.Addr().String())
		o.RunID, o.Citation.CaptureID = g.run, "ring:"+g.run+":3"
		out = append(out, o)
	}
	return out
}

// The scheduler goes first: while the read loop commits a flood at 100 ms
// a record, and the manager's TickHold takes the lock as often as it can,
// each Dispatch waits for at most about the one record in commit, and none
// times out. Each woken call checks the lock only after the first check
// Lock makes after the lock was freed (orderAfterLock), so the order is
// the test's, not the Go scheduler's. Control 2 (the fairness rule
// removed: Lock does not yield to a waiting scheduler call) then lets the
// read loop or TickHold take the lock before a waiting call every time,
// so the first call waits out HoldLockWait.
func TestSchedulerFirstOnLinkLock(t *testing.T) {
	s := &gatedStore{delay: 100 * time.Millisecond}
	g := gatedRig(t, s)
	orderAfterLock(&g.l.cmu)
	recs := others(g, 60)
	ctx, cancel := context.WithCancel(bg)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- g.l.Serve(bg, stream(t, recs...)) }()
	go func() {
		for ctx.Err() == nil {
			g.l.TickHold(ctx)
		}
	}()
	for g.l.Stats().Committed == 0 {
		time.Sleep(5 * time.Millisecond)
	}
	var worst time.Duration
	for i := range 10 {
		from := time.Now()
		if err := g.l.Dispatch(bg, HoldRun{RequestID: "run-" + string(rune('a'+i)), AssetID: relay, Endpoint: endpoint, L4: "tcp"}); err != nil {
			t.Fatalf("dispatch %d: %v", i, err)
		}
		worst = max(worst, time.Since(from))
		time.Sleep(30 * time.Millisecond)
	}
	st := g.l.Stats()
	if worst > 250*time.Millisecond || st.DispatchTimeouts != 0 {
		t.Fatalf("a dispatch waited %s (status %s), %d timed out; want at most about one record in commit (100 ms), none", worst, st.LockWaitMax, st.DispatchTimeouts)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// orderAfterLock sets f's seams so that a scheduler call woken from its
// wait checks the lock only once Lock has checked since the last signal,
// and under the same hold of f.mu as that finding. A caller of Lock that
// runs hot (here TickHold) checks soon, so the wait ends.
func orderAfterLock(f *fairLock) {
	tried := make(chan struct{}, 1)
	f.tried = func() {
		select {
		case tried <- struct{}{}:
		default:
		}
	}
	f.woken = func() {
		for {
			f.mu.Lock()
			if f.checks > f.signalled {
				return // with f.mu held
			}
			f.mu.Unlock()
			<-tried
		}
	}
}

// The fairness rule itself: a holder that takes the lock again the moment
// it frees it, as a read loop running hot does, yields to a waiting
// scheduler call, which has the lock within about one hold. Control 2 (the
// rule removed) lets the holder take it again first every time, so the
// call waits out HoldLockWait.
func TestFairLockSchedulerFirst(t *testing.T) {
	var f fairLock
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			f.Lock()
			time.Sleep(20 * time.Millisecond)
			f.Unlock()
		}
	}()
	time.Sleep(50 * time.Millisecond)
	for i := range 10 {
		from := time.Now()
		if !f.lockSched(HoldLockWait) {
			t.Fatalf("call %d: the lock was not had within %s", i, HoldLockWait)
		}
		took := time.Since(from)
		f.Unlock()
		if took > 200*time.Millisecond {
			t.Fatalf("call %d waited %s, want about one hold (20 ms)", i, took)
		}
	}
}

// A scheduler call that does not have the lock within HoldLockWait gives
// up: Dispatch returns ErrHoldTimeout and holds nothing, Result the same,
// so the run goes on untied, and each is counted. The lock is free again
// after the read loop's commit, and the next call works. Control: a
// scheduler call that waits for the lock with no bound, which returns only
// when the commit is let go.
func TestSchedulerCallTimesOut(t *testing.T) {
	s := &gatedStore{gate: make(chan struct{}), entered: make(chan struct{})}
	g := gatedRig(t, s)
	g.dispatch("held")
	done := make(chan error, 1)
	go func() { done <- g.l.Serve(bg, stream(t, others(g, 1)...)) }()
	<-s.entered
	release := sync.OnceFunc(func() { close(s.gate) })
	go func() { time.Sleep(5 * HoldLockWait); release() }() // so a control ends
	from := time.Now()
	err := g.l.Dispatch(bg, HoldRun{RequestID: "late", AssetID: relay, Endpoint: endpoint, L4: "tcp"})
	took := time.Since(from)
	if !errors.Is(err, ErrHoldTimeout) || took < HoldLockWait || took > HoldLockWait+time.Second {
		t.Fatalf("dispatch after %s: %v; want ErrHoldTimeout after %s", took, err, HoldLockWait)
	}
	if _, err := g.l.Result(bg, "held", Session{}); !errors.Is(err, ErrHoldTimeout) {
		t.Fatalf("result: %v", err)
	}
	if _, err := g.l.Abandon(bg, "held"); !errors.Is(err, ErrHoldTimeout) {
		t.Fatalf("abandon: %v", err)
	}
	st := g.l.Stats()
	if st.DispatchTimeouts != 1 || st.ResultTimeouts != 2 || st.LockWaitMax < HoldLockWait {
		t.Fatalf("%d dispatch and %d result timeouts, longest wait %s", st.DispatchTimeouts, st.ResultTimeouts, st.LockWaitMax)
	}
	if g.l.hold.runs["late"] != nil || g.l.hold.runs["held"] == nil {
		t.Fatal("the timed-out dispatch holds its run, or the held run was released")
	}
	release()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	g.dispatch("next")
}

// Item 9's recover in a scheduler call: a panic inside Result, while it
// holds the lock (here in the hold's save, as the node's would run it), is
// recovered and taken as a timeout. The lock is released, so the read loop
// and the next call go on. Control: no recover, which ends the process.
func TestSchedulerCallPanicRecovered(t *testing.T) {
	g := newHoldRig(t)
	g.dispatch("run-1")
	g.send(g.obs("start", 40001, time.Second))
	save := g.l.hold.cfg.Save
	g.l.hold.cfg.Save = func(ctx context.Context, rec RunRecord) error {
		if rec.State == HoldReleasing {
			panic("sensorlink test: a fault in the release")
		}
		return save(ctx, rec)
	}
	_, err := g.l.Result(bg, "run-1", session09(inv1, 40001, 2*time.Second))
	st := g.l.Stats()
	if !errors.Is(err, ErrHoldTimeout) || st.ResultTimeouts != 1 || st.SchedPanics != 1 || st.LastSchedPanic == "" {
		t.Fatalf("result: %v; %d timeouts, %d panics", err, st.ResultTimeouts, st.SchedPanics)
	}
	g.l.hold.cfg.Save = save
	g.send(others(g, 1)...)
	g.dispatch("run-2")
}

// D6's note 1 on #663: a Result whose stream head can't be read after the
// release, as while the node's network database is swapped out for a
// Resume, returns an error and no after_seq, so no session is handed on
// with after_seq 0. Control: the head's error dropped, as before, which
// returns after_seq 0 and no error.
func TestResultHeadUnknownNoAfterSeq(t *testing.T) {
	s := &gatedStore{}
	g := gatedRig(t, s)
	g.dispatch("run-1")
	g.send(g.obs("start", 40001, time.Second))
	s.headFail.Store(true)
	rel, err := g.l.Result(bg, "run-1", session09(inv1, 40001, 2*time.Second))
	if err == nil || errors.Is(err, ErrHoldTimeout) {
		t.Fatalf("result with no head: after_seq %d, %v; want the head's error", rel.AfterSeq, err)
	}
}
