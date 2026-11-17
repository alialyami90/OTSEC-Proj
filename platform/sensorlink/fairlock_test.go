package sensorlink

import (
	"context"
	"errors"
	"fmt"
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
	// headFailAfter makes the head fail from the first batch on.
	headFailAfter atomic.Bool
	// panicBatch makes the next batch panic before it commits anything.
	panicBatch atomic.Bool
	// writes counts the appends and batches begun.
	writes atomic.Int64
}

func (s *gatedStore) wait() {
	s.writes.Add(1)
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
	if s.panicBatch.CompareAndSwap(true, false) {
		panic("sensorlink test: a fault in the batch before it commits")
	}
	rcs, err := s.netStore.AppendBatch(ctx, recs)
	if s.headFailAfter.Load() {
		s.headFail.Store(true)
	}
	return rcs, err
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
// Lock never takes the lock while a Dispatch waits for it, so each waits
// for at most the holder's turn in progress. The rule is counted at Lock's
// take, not timed: on the hosted runners a woken call that waits for
// Lock's check (below) has twice measured over 400 ms under the rule,
// which is the runner's scheduling, not a turn taken from it. Each woken
// call checks the lock only after the first check Lock makes after the
// lock was freed (orderAfterLock), so the order is the test's, not the Go
// scheduler's. Control 2 (the fairness rule removed: Lock does not yield
// to a waiting scheduler call) then lets the read loop or TickHold take
// the lock before a waiting call every time, so the first call waits out
// HoldLockWait.
//
// A dispatch that times out with no take counted is the rule's own limit,
// not a break of it, only when one holder's turn, taken with Lock, held
// the lock through the whole of that dispatch's wait and made exactly one
// store write: the rule bounds a wait by the turn in progress, one record
// in commit for the read loop, and a commit that a loaded runner's disk
// slows can outlast HoldLockWait, which then gives up as designed and is
// counted (P4-NODE-FLK; job 133688900667 timed out before either figure
// was read). In this rig every Lock turn that writes is the read loop's
// commit of one record: the wall clock never moves, so TickHold releases
// nothing, and the flows are untied, so giveWay has nothing to release. A
// long turn of several writes, or of none, is a holding defect, not a slow
// disk (D3's and D6's B1 on #728, D1's ruling). So every dispatch is made,
// each Lock turn is timed and its writes counted (orderAfterLock's freed
// seam), and a failure says which it was: the rule broken (takes counted),
// or a timeout that no single one-write turn explains. The turns are read
// only once the read loop and TickHold have stopped, so the turn that held
// through the last dispatch's wait has ended and is counted; read earlier,
// it was still in progress and missing (run 44078255375, P4-LINK-SFL;
// TestLinkLockTurnReadOnceEnded). The 30 ms pauses between dispatches
// order nothing the test asserts: they let the read loop take the lock
// between calls, so more calls find a holder.
func TestSchedulerFirstOnLinkLock(t *testing.T) {
	s := &gatedStore{delay: 100 * time.Millisecond}
	g := gatedRig(t, s)
	lk := orderAfterLock(&g.l.cmu)
	lk.writes = &s.writes
	recs := others(g, 60)
	ctx, cancel := context.WithCancel(bg)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- g.l.Serve(bg, stream(t, recs...)) }()
	ticks := make(chan struct{})
	go func() {
		defer close(ticks)
		for ctx.Err() == nil {
			g.l.TickHold(ctx)
		}
	}()
	for g.l.Stats().Committed == 0 {
		time.Sleep(5 * time.Millisecond)
	}
	var worst time.Duration
	var timedOut []int
	var froms []time.Time
	for i := range 10 {
		from := time.Now()
		froms = append(froms, from)
		err := g.l.Dispatch(bg, HoldRun{RequestID: "run-" + string(rune('a'+i)), AssetID: relay, Endpoint: endpoint, L4: "tcp"})
		if errors.Is(err, ErrHoldTimeout) {
			timedOut = append(timedOut, i)
		} else if err != nil {
			t.Fatalf("dispatch %d: %v", i, err)
		}
		worst = max(worst, time.Since(from))
		time.Sleep(30 * time.Millisecond)
	}
	cancel()
	<-ticks
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	st := g.l.Stats()
	n, turn, long, open := lk.read(&g.l.cmu)
	if open {
		t.Fatal("a Lock turn is still in progress with the read loop and TickHold stopped")
	}
	t.Logf("worst dispatch %s (status %s), longest Lock turn %s, dispatches timed out %v", worst, st.LockWaitMax, turn, timedOut)
	if n != 0 {
		t.Fatalf("the rule is broken: Lock took the lock %d times while a dispatch waited; dispatches %v timed out (%d counted), longest wait %s, longest Lock turn %s", n, timedOut, st.DispatchTimeouts, st.LockWaitMax, turn)
	}
	if st.DispatchTimeouts != uint64(len(timedOut)) {
		t.Fatalf("%d dispatch timeouts counted, %d returned", st.DispatchTimeouts, len(timedOut))
	}
	for _, i := range timedOut {
		if !heldThrough(long, froms[i]) {
			t.Fatalf("dispatch %d timed out with no take counted, and no single Lock turn of one store write held the lock through its wait (turns of %s or more, with their writes: %v; longest wait %s): neither the rule broken nor a slow holder", i, HoldLockWait/2, long, st.LockWaitMax)
		}
		t.Logf("dispatch %d timed out on a slow holder: one Lock turn of one store write held the lock through its wait (turns of %s or more, with their writes: %v)", i, HoldLockWait/2, long)
	}
}

// P4-LINK-SFL (run 44078255375): a dispatch that times out on one Lock
// turn of one store write is excused only once that turn has ended. The
// read loop's commit of one record is held in its write (the store's gate)
// through a dispatch's whole wait. Read while the turn is in progress, as
// TestSchedulerFirstOnLinkLock read before it stopped the read loop, the
// turn is reported open and is not among the long turns, so heldThrough
// cannot excuse the timeout: the CI failure, whose timed-out dispatch was
// the last. Read once the commit is let go and Serve has returned, the
// turn is there, of one write, and held through the wait.
func TestLinkLockTurnReadOnceEnded(t *testing.T) {
	s := &gatedStore{gate: make(chan struct{}), entered: make(chan struct{})}
	g := gatedRig(t, s)
	lk := orderAfterLock(&g.l.cmu)
	lk.writes = &s.writes
	done := make(chan error, 1)
	go func() { done <- g.l.Serve(bg, stream(t, others(g, 1)...)) }()
	<-s.entered
	release := sync.OnceFunc(func() { close(s.gate) })
	defer release()
	from := time.Now()
	if err := g.l.Dispatch(bg, HoldRun{RequestID: "late", AssetID: relay, Endpoint: endpoint, L4: "tcp"}); !errors.Is(err, ErrHoldTimeout) {
		t.Fatalf("dispatch with the commit held: %v; want ErrHoldTimeout", err)
	}
	if _, _, long, open := lk.read(&g.l.cmu); !open || heldThrough(long, from) {
		t.Fatalf("read with the commit still held: open %v, long turns %v; want the turn open and not yet counted", open, long)
	}
	release()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	n, _, long, open := lk.read(&g.l.cmu)
	if n != 0 || open || !heldThrough(long, from) {
		t.Fatalf("read once Serve returned: %d takes while the dispatch waited, open %v, long turns %v; want one turn of one write held through the wait", n, open, long)
	}
}

// lockCounts are orderAfterLock's counts, kept under the lock's f.mu:
// Lock's takes while a scheduler call waited, the longest turn of a holder
// that took the lock with Lock, and each such turn of HoldLockWait/2 or
// more. writes, when set, counts the store's writes; w0 is its count at
// the take.
type lockCounts struct {
	bypassed int64
	takenAt  time.Time
	longest  time.Duration
	long     []turn
	writes   *atomic.Int64
	w0       int64
}

// turn is a holder's turn, from its take to its Unlock, and the store
// writes begun in it.
type turn struct {
	from, to time.Time
	writes   int64
}

func (u turn) String() string { return fmt.Sprintf("%s/%d writes", u.to.Sub(u.from), u.writes) }

// nWrites is the writes count, 0 when unset.
func (c *lockCounts) nWrites() int64 {
	if c.writes == nil {
		return 0
	}
	return c.writes.Load()
}

// read returns the counts, under f.mu, and whether a Lock turn is in
// progress, whose time is not yet counted.
func (c *lockCounts) read(f *fairLock) (int64, time.Duration, []turn, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return c.bypassed, c.longest, append([]turn(nil), c.long...), !c.takenAt.IsZero()
}

// heldThrough reports whether one of long, a turn of exactly one store
// write, held the lock through a wait of HoldLockWait that began at from,
// to within the clock's step: a scheduler call that timed out under the
// rule waited on the one turn it found, one record in commit.
func heldThrough(long []turn, from time.Time) bool {
	const step = 50 * time.Millisecond
	for _, u := range long {
		if u.writes == 1 && !u.from.After(from.Add(step)) && !u.to.Before(from.Add(HoldLockWait-step)) {
			return true
		}
	}
	return false
}

// orderAfterLock sets f's seams so that a scheduler call woken from its
// wait checks the lock only once Lock has checked since the last signal,
// and under the same hold of f.mu as that finding. A caller of Lock that
// runs hot (here TickHold) checks soon, so the wait ends. It counts Lock's
// takes while a scheduler call waited, and times each turn of a holder
// that took the lock with Lock, from its take to its Unlock.
func orderAfterLock(f *fairLock) *lockCounts {
	c := &lockCounts{}
	tried := make(chan struct{}, 1)
	f.tried = func(took bool) { // under f.mu
		if took {
			c.takenAt, c.w0 = time.Now(), c.nWrites()
			if f.waiting > 0 {
				c.bypassed++
			}
		}
		select {
		case tried <- struct{}{}:
		default:
		}
	}
	f.freed = func() { // under f.mu
		if !c.takenAt.IsZero() {
			u := turn{c.takenAt, time.Now(), c.nWrites() - c.w0}
			c.longest = max(c.longest, u.to.Sub(u.from))
			if u.to.Sub(u.from) >= HoldLockWait/2 {
				c.long = append(c.long, u)
			}
			c.takenAt = time.Time{}
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
	return c
}

// The fairness rule itself: a holder that takes the lock again the moment
// it frees it, as a read loop running hot does, yields to a waiting
// scheduler call. Each call is made only while the holder holds the lock,
// and the holder frees it only once the call waits (f.waiting), so every
// call waits and every free is followed at once by the holder's Lock; no
// sleep orders the two (D4-115 item 7). orderAfterLock makes the woken
// call check only after Lock's first check after the free, and counts
// Lock's takes while a call waited. Each call must be had after exactly
// one wake, the holder's Unlock: a call had at its own timeout, after its
// wake was lost, is not the rule's bound (D6's B1 on #733). Control 2 (the
// rule removed: Lock does not yield to a waiting scheduler call) lets the
// holder take the lock again before the waiting call, so the take is
// counted and the call waits out HoldLockWait. Control FL-M1 (Unlock does
// not signal while a scheduler call waits) leaves the call to its timer,
// so no wake is counted. A liveness break fails by name within
// HoldLockWait at the wait for the holder, not at go test's -timeout.
func TestFairLockSchedulerFirst(t *testing.T) {
	var f fairLock
	lk := orderAfterLock(&f)
	wakes := 0 // written only in the calling goroutine, in lockSched
	woken := f.woken
	f.woken = func() { woken(); wakes++ }
	stop := make(chan struct{})
	defer close(stop)
	held := make(chan struct{})
	go func() {
		f.Lock()
		for {
			select {
			case held <- struct{}{}:
			case <-stop:
				f.Unlock()
				return
			}
			for { // hold until a scheduler call waits
				f.mu.Lock()
				w := f.waiting
				f.mu.Unlock()
				if w > 0 {
					break
				}
				select {
				case <-stop:
					f.Unlock()
					return
				default:
				}
				time.Sleep(time.Millisecond)
			}
			f.Unlock()
			f.Lock()
		}
	}()
	for i := range 10 {
		select {
		case <-held:
		case <-time.After(HoldLockWait):
			t.Fatalf("call %d: the holder did not take the lock again within %s", i, HoldLockWait)
		}
		w0 := wakes
		if !f.lockSched(HoldLockWait) {
			n, _, _, _ := lk.read(&f)
			t.Fatalf("call %d: the lock was not had within %s; Lock took it %d times while a call waited", i, HoldLockWait, n)
		}
		f.Unlock()
		if n := wakes - w0; n != 1 {
			t.Fatalf("call %d had the lock after %d wakes, want 1: not woken by the holder's Unlock", i, n)
		}
	}
	if n, _, _, _ := lk.read(&f); n != 0 {
		t.Fatalf("the rule is broken: Lock took the lock %d times while a scheduler call waited", n)
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

// D3's B1 on #676: a panic while l.mu is held, in commitBatch's first
// section, neither hangs the call nor leaves l.mu held. A Result returns
// within the bound with the recovered panic taken as a timeout, and a
// TickHold's panic reaches its caller (the node's managerStep, which
// recovers it); Stats does not block after either. The panic is injected
// as D3's probe does: a held record that decodes with no node object, so
// commitBatch counts a refusal, into a nil map. Control: commitBatch's
// plain unlock, under which syncHold's lock of l.mu in the deferred calls
// blocks, so neither returns within 5 s.
func TestPanicUnderLinkMuReleased(t *testing.T) {
	for _, name := range []string{"result", "tickhold"} {
		t.Run(name, func(t *testing.T) {
			g := newHoldRig(t)
			g.dispatch("run-1")
			g.send(g.obs("start", 40001, time.Second))
			g.l.hold.runs["run-1"].rec.Flows[0].Records[0].Observation = []byte("{}")
			g.l.mu.Lock()
			refused := g.l.stats.Refused
			g.l.stats.Refused = nil
			g.l.mu.Unlock()
			done := make(chan any, 1)
			go func() {
				if name == "result" {
					_, err := g.l.Result(bg, "run-1", session09(inv1, 40001, 2*time.Second))
					done <- err
					return
				}
				defer func() { done <- recover() }()
				g.wall = g.wall.Add(time.Hour)
				g.l.TickHold(bg)
			}()
			var got any
			select {
			case got = <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("the call did not return within 5 s after a panic under l.mu")
			}
			if err, _ := got.(error); name == "result" && !errors.Is(err, ErrHoldTimeout) {
				t.Fatalf("result: %v; want the recovered panic as ErrHoldTimeout", got)
			}
			if name == "tickhold" && got == nil {
				t.Fatal("TickHold returned; want its panic to reach the caller")
			}
			stats := make(chan Stats, 1)
			go func() { stats <- g.l.Stats() }()
			select {
			case <-stats:
			case <-time.After(5 * time.Second):
				t.Fatal("Stats blocked: l.mu is still held")
			}
			g.l.mu.Lock()
			g.l.stats.Refused = refused
			g.l.mu.Unlock()
		})
	}
}

// D6's note 1 on #663, and the fallback of D1's ruling on #676: a Result
// whose stream head can't be read before its release, as while the node's
// network database is swapped out for a Resume, returns the head's error
// and begins nothing: nothing is committed or saved as releasing, the run
// stays held, head_unread counts it, and its deadline then commits its
// flow untied, for the base rules. Control: the head's error dropped, as
// before, which saves a releasing record with head 0 and commits the flow
// tied with no session handed on.
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
	if c := g.committed(); len(c) != 0 || g.l.hold.runs["run-1"] == nil || g.l.Stats().Hold.HeadUnread != 1 {
		t.Fatalf("after a Result with no head: committed %+v, still held %v, %+v", c, g.l.hold.runs["run-1"] != nil, g.l.Stats().Hold)
	}
	// The deadline with the head still unread begins nothing either, and
	// is not counted as a release (D6's N2 on #676's 98aa92e8; control:
	// DeadlineReleases counted before the error is tested).
	g.wall = g.wall.Add(HoldRunLimit + time.Hour)
	g.l.TickHold(bg)
	if st := g.l.Stats().Hold; len(g.committed()) != 0 || st.DeadlineReleases != 0 || st.HeadUnread != 2 {
		t.Fatalf("a deadline with no head: committed %+v, %+v; want nothing, deadline_releases 0, head_unread 2", g.committed(), st)
	}
	s.headFail.Store(false)
	g.l.TickHold(bg)
	want(t, g.committed(), tied{seq: 1})
	if st := g.l.Stats().Hold; st.DeadlineReleases != 1 {
		t.Fatalf("deadline_releases %d once the head reads, want 1", st.DeadlineReleases)
	}
}

// D3's B2 and D6's B1 on #676, as D1 ruled: the after_seq is the largest
// seq of the batch's receipts, so a head that can't be read after the
// batch no longer matters. The Result succeeds with after_seq 1, and the
// flow committed tied to it is handed on with its session. Control: the
// head read again after the batch, as at 7f9a79a7, which returns its error
// with the flow committed tied and no session handed on.
func TestResultAfterSeqFromReceipts(t *testing.T) {
	s := &gatedStore{}
	g := gatedRig(t, s)
	g.dispatch("run-1")
	g.send(g.obs("start", 40001, time.Second))
	s.headFailAfter.Store(true)
	rel, err := g.l.Result(bg, "run-1", session09(inv1, 40001, 2*time.Second))
	if err != nil || rel.AfterSeq != 1 {
		t.Fatalf("result with the head failing after the batch: after_seq %d, %v; want 1", rel.AfterSeq, err)
	}
	want(t, g.committed(), tied{seq: 1, invocation: inv1, tie: TieConnection})
}

// D3's B3 on #676: a recovered panic in a release's save, before its
// batch is in the store, rolls the staged re-point back and clears the
// hold-wide staged state, so the open flow's later records tie to the
// invocation whose session was handed on (inv1), even after another run's
// release. D3's probe, with that later release added. Controls: the
// rollback left to a save that returns an error, as at 7f9a79a7; and the
// staged state not cleared, which the next release applies.
func TestRepointSavePanicRolledBack(t *testing.T) {
	g := newHoldRig(t)
	g.dispatch("req-1")
	g.send(g.obs("start", 40001, 0))
	if _, err := g.l.Result(bg, "req-1", session09(inv1, 40001, 0)); err != nil {
		t.Fatal(err)
	}
	g.wall = g.wall.Add(time.Minute)
	g.dispatch("req-2")
	save := g.l.hold.cfg.Save
	g.l.hold.cfg.Save = func(ctx context.Context, rec RunRecord) error {
		if rec.Run.RequestID == "req-2" && rec.State != HoldHolding {
			panic("sensorlink test: a fault in the release's save")
		}
		return save(ctx, rec)
	}
	if _, err := g.l.Result(bg, "req-2", session09(inv2, 40001, time.Minute)); !errors.Is(err, ErrHoldTimeout) {
		t.Fatalf("result with a panic in the save: %v", err)
	}
	g.l.hold.cfg.Save = save
	g.dispatch("req-3")
	if _, err := g.l.Result(bg, "req-3", Session{InvocationID: "33333333-3333-4333-8333-333333333333"}); err != nil {
		t.Fatal(err)
	}
	g.send(g.obs("function", 40001, 2*time.Minute))
	c := g.committed()
	if last := c[len(c)-1]; last.invocation != inv1 {
		t.Fatalf("the open flow's later record ties to %q, want %s, whose session was handed on: %+v", last.invocation, inv1, c)
	}
}

// D3's N1 on #676, as D1 ruled: a recovered panic in the save after the
// batch, whose records are in the store, finishes the release as a failed
// save does. The Result returns the receipts' after_seq, the run leaves
// the hold, and its deadline commits nothing again: seq 1 is committed
// once, tied. The panic is counted. Control: the rollback in every case
// (the receipts' branch removed), under which the Result times out with
// the flow committed tied, and the deadline commits it a second time,
// untied.
func TestPanicAfterBatchFinished(t *testing.T) {
	g := newHoldRig(t)
	g.dispatch("run-1")
	g.send(g.obs("start", 40001, time.Second))
	save := g.l.hold.cfg.Save
	g.l.hold.cfg.Save = func(ctx context.Context, rec RunRecord) error {
		if rec.State == HoldReleased || rec.State == HoldWaiting {
			panic("sensorlink test: a fault in the save after the batch")
		}
		return save(ctx, rec)
	}
	rel, err := g.l.Result(bg, "run-1", session09(inv1, 40001, 2*time.Second))
	g.l.hold.cfg.Save = save
	if err != nil || rel.AfterSeq != 1 {
		t.Fatalf("result with a panic after the batch: after_seq %d, %v; want 1", rel.AfterSeq, err)
	}
	if st := g.l.Stats(); g.l.hold.runs["run-1"] != nil || st.SchedPanics != 1 || st.ResultTimeouts != 0 {
		t.Fatalf("still held %v, %d panics, %d timeouts", g.l.hold.runs["run-1"] != nil, st.SchedPanics, st.ResultTimeouts)
	}
	g.wall = g.wall.Add(HoldRunLimit + time.Hour)
	g.l.TickHold(bg)
	want(t, g.committed(), tied{seq: 1, invocation: inv1, tie: TieConnection})
}
