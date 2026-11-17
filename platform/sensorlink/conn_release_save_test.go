package sensorlink

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"otsec.local/otsec/contracts/netobs"
	c5 "otsec.local/otsec/contracts/store"
)

// The reviews of #742 at 64cfb264 (D3's B1, D6's B1 to B3 and N3, D4's
// B1), desk only: the tests hand the link an in-memory pipe and a restored
// hold; no sensor and no device.

// hookCursor is the rig's cursor store with a hook run once before a read,
// and reads made to fail.
type hookCursor struct {
	CursorStore
	mu       sync.Mutex
	before   func()
	failRead int
}

func (h *hookCursor) SourceCursor(ctx context.Context) ([]byte, error) {
	h.mu.Lock()
	f := h.before
	h.before = nil
	fail := h.failRead > 0
	if fail {
		h.failRead--
	}
	h.mu.Unlock()
	if f != nil {
		f()
	}
	if fail {
		return nil, errors.New("test: the cursor was not read")
	}
	return h.CursorStore.SourceCursor(ctx)
}

func (h *hookCursor) arm(before func(), failRead int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.before, h.failRead = before, failRead
}

// batchFail fails the next AppendBatch calls with an error that is not
// final.
type batchFail struct {
	Appender
	mu sync.Mutex
	n  int
}

func (b *batchFail) AppendBatch(ctx context.Context, recs []c5.Record) ([]c5.Receipt, error) {
	b.mu.Lock()
	fail := b.n > 0
	if fail {
		b.n--
	}
	b.mu.Unlock()
	if fail {
		return nil, errors.New("test: the database is closed")
	}
	return b.Appender.AppendBatch(ctx, recs)
}

func (b *batchFail) failNext(n int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.n = n
}

// cursor9 is run 5's saved cursor at T 9.
func cursor9() *Cursor {
	return &Cursor{Generation: 2, RunCounter: 5, RunID: testRun, Taken: 9, Digest: testDigest}
}

// heldLate restarts the link with record seq of run 5 held, its run due in
// a second, and c saved as the cursor.
func heldLate(t *testing.T, r *rig, hs *holdSaves, seq uint64, unresolved bool, lost []netobs.Span, c *Cursor) {
	t.Helper()
	hr := heldOne(t, r, hs, 1)
	late := withBody(t, hr, "", seq, unresolved, lost)
	hold := RunRecord{State: HoldHolding, Run: HoldRun{RequestID: "req-m", AssetID: relay, Endpoint: endpoint, L4: "tcp",
		Deadline: r.now().Add(time.Second)}, Flows: []HeldFlow{{Records: []HeldRecord{late}}}}
	saveTestCursor(t, r, c)
	restartHeld(t, r, hs, []RunRecord{hold})
}

// heldDue restarts the link with heldOne's record 1 held, unresolved when
// asked so the empty budget drops it at its release, and its run past its
// deadline with no tick yet.
func heldDue(t *testing.T, r *rig, hs *holdSaves, unresolved bool) {
	t.Helper()
	hr := heldOne(t, r, hs, 1)
	rec := hs.last()
	if unresolved {
		rec.Flows[0].Records[0] = withBody(t, hr, "", 0, true, nil)
	}
	restartHeld(t, r, hs, []RunRecord{rec})
	r.addWall(HoldRunLimit + time.Minute)
}

// noSeq is a frame refused before its seq is read: a change pending.
var noSeq = []byte(`{"type":"nonsense"}`)

func checkCursor(t *testing.T, r *rig, taken, dropped uint64) {
	t.Helper()
	if c := cursorNow(t, r.cs); c.Taken != taken || c.Dropped != dropped {
		t.Fatalf("saved T %d, dropped %d; want %d and %d", c.Taken, c.Dropped, taken, dropped)
	}
}

func storedCount(t *testing.T, r *rig) int { return len(storedObs(t, r.s)) }

// D3's and D6's B1 on #742: a release whose cursor is not saved raises
// sensor-position-not-saved, raises no cn.saved, and answers no duplicate
// check; its totals go into the position's next write. Controls: the fold
// as it was at 64cfb264 (a move not written recorded as written): ack 10
// over a saved T 9, the resend dropped as a duplicate, no raise; and
// commitBatch's tookMove(stored, true).
func TestReleaseSaveFailedNotSaved(t *testing.T) {
	t.Run("the ack after a drop whose save failed", func(t *testing.T) {
		r, hs := holdRig02(t)
		heldLate(t, r, hs, 10, true, nil, cursor9())
		p := r.accepted(resume(4, 20)) // T 9, L 3
		r.addWall(time.Minute)
		r.cs.failNext(1 << 20) // every cursor save fails from here
		r.l.TickHold(bg)       // the empty budget drops 10
		if n := r.al.count(AlarmPositionNotSaved); n != 1 {
			t.Fatalf("%d raises of %s", n, AlarmPositionNotSaved)
		}
		r.tickAfter(p, tick02(20, 10, 0))
		p.ack(9) // never 10: no saved cursor holds the drop
		r.cs.failNext(0)
		checkCursor(t, r, 9, 0)
		p.end() // the closing save carries the drop's count
		checkCursor(t, r, 10, 1)
	})
	t.Run("the resend of a record whose drop was not saved is stored", func(t *testing.T) {
		r, hs := holdRig02(t)
		heldLate(t, r, hs, 10, true, nil, cursor9())
		p := r.accepted(resume(10, 20)) // T 9, L 9
		r.addWall(time.Minute)
		r.cs.failNext(1)
		r.l.TickHold(bg)
		if n := r.al.count(AlarmPositionNotSaved); n != 1 {
			t.Fatalf("%d raises", n)
		}
		p.send(nodeFlow02(10))
		p.ack(10)
		if n, d := storedCount(t, r), r.l.Stats().Dropped[RefusedDuplicate]; n != 1 || d != 0 {
			t.Fatalf("stored %d, duplicates %d; want 1 and 0", n, d)
		}
		checkCursor(t, r, 10, 1) // the drop counted as well: an over-count, loud
	})
	t.Run("no connection open", func(t *testing.T) {
		r, hs := holdRig02(t)
		hr := withBody(t, heldOne(t, r, hs, 1), "", 0, true, nil)
		r.cs.failNext(1) // the release's own save
		restartHeld(t, r, hs, []RunRecord{releasing([]HeldRecord{hr}, head(t, r))})
		if n := r.al.count(AlarmPositionNotSaved); n != 1 {
			t.Fatalf("%d raises", n)
		}
		checkCursor(t, r, 0, 0)
		p := r.accepted(resume(1, 20))
		checkCursor(t, r, 0, 1) // the hello's save carries it
		p.send(nodeFlow02(1))
		p.ack(1)
		if n, d := storedCount(t, r), r.l.Stats().Dropped[RefusedDuplicate]; n != 1 || d != 0 {
			t.Fatalf("stored %d, duplicates %d; want 1 and 0", n, d)
		}
	})
	t.Run("a batch whose cursor did not encode", func(t *testing.T) {
		r, hs := holdRig02(t)
		heldLate(t, r, hs, 10, false, nil, cursor9()) // resolved: the release stores it
		p := r.accepted(resume(4, 20))
		r.addWall(time.Minute)
		fail := true
		cursorEncodeFault = func(c *Cursor) error {
			if fail && c.Taken == 10 {
				fail = false
				return errors.New("test: the release's cursor cannot be encoded")
			}
			return nil
		}
		t.Cleanup(func() { cursorEncodeFault = nil })
		r.cs.failNext(1 << 20)
		r.l.TickHold(bg)
		if n, a := storedCount(t, r), r.al.count(AlarmPositionNotSaved); n != 1 || a != 1 {
			t.Fatalf("stored %d, raises %d", n, a)
		}
		r.tickAfter(p, tick02(20, 10, 0))
		p.ack(9)
		r.cs.failNext(0)
		checkCursor(t, r, 9, 0)
	})
	t.Run("a batch the store refuses, not finally", func(t *testing.T) {
		bf := &batchFail{}
		r, hs := holdRig02With(t, func(o *Options) { bf.Appender = o.Store; o.Store = bf })
		heldLate(t, r, hs, 10, false, nil, cursor9())
		p := r.accepted(resume(4, 20))
		r.addWall(time.Minute)
		bf.failNext(1)
		r.cs.failNext(1 << 20) // the same store: the release's save fails too
		r.l.TickHold(bg)
		if d, a := r.l.Stats().Dropped[DropStore], r.al.count(AlarmPositionNotSaved); d != 1 || a != 1 {
			t.Fatalf("dropped under store %d, raises %d", d, a)
		}
		r.tickAfter(p, tick02(20, 10, 0))
		p.ack(9)
		r.cs.failNext(0)
		p.end()
		checkCursor(t, r, 10, 1)
	})
}

// D6's B2 on #742: a release that lands while a record's cursor is built
// (the seam cursorEncodeFault, at the record's encode), with a change
// pending so the hold's flush runs. Controls: observe's duplicate check
// off (record 1 stored twice); commitOne's fold off, or the flush after
// the encode as at 64cfb264 (the drop's count written back to 0).
func TestReleaseAtRecordEncode(t *testing.T) {
	at := func(t *testing.T, r *rig, seq uint64) *bool {
		fired := false
		cursorEncodeFault = func(c *Cursor) error {
			if !fired && c.RunID == testRun && c.Taken == seq {
				fired = true
				r.l.TickHold(bg)
			}
			return nil
		}
		t.Cleanup(func() { cursorEncodeFault = nil })
		return &fired
	}
	t.Run("the resend released at its encode is a duplicate", func(t *testing.T) {
		r, hs := holdRig02(t)
		heldDue(t, r, hs, false)
		p := r.accepted(resume(1, 20)) // T 0
		p.send(noSeq)
		p.taken()
		fired := at(t, r, 1)
		p.send(nodeFlow02(1))
		p.taken()
		if !*fired {
			t.Fatal("the seam did not run")
		}
		if n, d := storedCount(t, r), r.l.Stats().Dropped[RefusedDuplicate]; n != 1 || d != 1 {
			t.Fatalf("stored %d, duplicates %d; want 1 and 1", n, d)
		}
	})
	t.Run("a drop released at the encode keeps its count", func(t *testing.T) {
		r, hs := holdRig02(t)
		heldDue(t, r, hs, true)
		p := r.accepted(resume(2, 20)) // T 1: the held record is below it
		p.send(noSeq)
		p.taken()
		fired := at(t, r, 2)
		p.send(obs02(2))
		p.ack(2)
		if !*fired {
			t.Fatal("the seam did not run")
		}
		if d := r.l.Stats().Dropped[DropUnresolvedBudget]; d != 1 {
			t.Fatalf("dropped %d", d)
		}
		checkCursor(t, r, 2, 1)
	})
}

// D6's B3 on #742: a release between the connection's start and its read
// of the cursor is counted once. The hook runs at the hello's read: with
// that read under cmu, the release waits for it. Control: the start and
// the read as two steps, as at 64cfb264 (the saved total 2).
func TestReleaseAtCursorOpenCountedOnce(t *testing.T) {
	var hc *hookCursor
	r, hs := holdRig02With(t, func(o *Options) { hc = &hookCursor{CursorStore: o.Cursor}; o.Cursor = hc })
	heldDue(t, r, hs, true)
	done := make(chan struct{})
	hc.arm(func() {
		r.l.cmu.mu.Lock()
		held := r.l.cmu.held
		r.l.cmu.mu.Unlock()
		if held {
			go func() { r.l.TickHold(bg); close(done) }()
			return
		}
		r.l.TickHold(bg)
		close(done)
	}, 0)
	p := r.accepted(resume(1, 20))
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("the release did not run")
	}
	p.end()
	if d := r.l.Stats().Dropped[DropUnresolvedBudget]; d != 1 {
		t.Fatalf("dropped %d", d)
	}
	checkCursor(t, r, 1, 1)
}

// D6's B3 on #742, its two further legs: a live release's totals are
// counted once across the connection's later saves, and once at the next
// connection. Controls: saveCursor keeping l.moved after a save (the run-5
// drop counted twice in run 6's total); closeCursor and openCursor both
// keeping l.moved (counted again at the next hello).
func TestLiveReleaseCountedOnce(t *testing.T) {
	t.Run("across the connection's saves", func(t *testing.T) {
		var hook func()
		r, hs := holdRig02With(t, func(o *Options) {
			o.Owed = func(context.Context, Owed) error {
				if h := hook; h != nil {
					hook = nil
					h() // the release lands while run 6's hello is acted on, before its save
				}
				return nil
			}
		})
		heldDue(t, r, hs, true)
		c := cursorNow(t, r.cs)
		c.Prior = &HeldPrior{PreviousEnd: "clean", StartedBy: "agent", Owed: true} // run 5 owes: run 6's hello writes it first
		saveTestCursor(t, r, c)
		hook = func() { r.l.TickHold(bg) }
		p := r.accepted(run6())
		o := obs02(1)
		o.RunID, o.Citation.CaptureID = testRun2, "ring:"+testRun2+":3"
		p.send(o)
		p.ack(1)
		if hook != nil {
			t.Fatal("the hook did not run")
		}
		if c := cursorNow(t, r.cs); c.RunID != testRun2 || c.Dropped != 1 {
			t.Fatalf("run 6's cursor %+v: want run 5's drop once", c)
		}
	})
	t.Run("at the next connection", func(t *testing.T) {
		r, hs := holdRig02(t)
		heldLate(t, r, hs, 10, true, nil, cursor9())
		p := r.accepted(resume(10, 20))
		r.addWall(time.Minute)
		r.l.TickHold(bg)
		checkCursor(t, r, 10, 1)
		p.end()
		r.accepted(resume(11, 20)).end()
		checkCursor(t, r, 10, 1)
	})
}

// D4's B1 on #742: D4's N3 on #732 with the connection open. A held record
// that carries node.lost, dropped by a release while the connection is
// open, leaves its window unmarked in the connection's cursor, so the
// connection's next stored observation carries it. Control: tookMove's
// append of the unmarks to l.moved removed (the next observation carries
// no node.lost).
func TestHeldLostDroppedLiveMarksNext(t *testing.T) {
	r, hs := holdRig02(t)
	w := lspan("09:00:00", "09:00:05")
	c := cursor9()
	c.Spans = []HeldSpan{{FromUTC: w.FromUTC, ToUTC: w.ToUTC, CutUTC: w.ToUTC, Marked: true}}
	heldLate(t, r, hs, 10, true, []netobs.Span{w}, c)
	p := r.accepted(resume(10, 20))
	r.addWall(time.Minute)
	r.l.TickHold(bg)
	p.send(obs02(11))
	p.ack(11)
	got := storedObs(t, r.s)
	if len(got) != 1 || len(got[0].Node.Lost) != 1 || got[0].Node.Lost[0] != w {
		t.Fatalf("the next stored observation carries %+v", got)
	}
}

// D6's N3 on #742: a release that cannot read the saved position begins
// nothing, as for the stream's head; the next tick releases it with T
// moved, so the resend is a duplicate. Control: the release committed as
// on the 0.1 path, as at 64cfb264 (record 1 stored twice).
func TestReleasePositionUnreadBeginsNothing(t *testing.T) {
	var hc *hookCursor
	r, hs := holdRig02With(t, func(o *Options) { hc = &hookCursor{CursorStore: o.Cursor}; o.Cursor = hc })
	heldDue(t, r, hs, false)
	hc.arm(nil, 1)
	r.l.TickHold(bg)
	if st := r.l.Stats().Hold; storedCount(t, r) != 0 || st.HeadUnread != 1 || st.Runs != 1 {
		t.Fatalf("stored %d, hold %+v", storedCount(t, r), st)
	}
	r.l.TickHold(bg)
	checkCursor(t, r, 1, 0)
	p := r.accepted(resume(1, 1))
	p.send(nodeFlow02(1))
	p.taken()
	if n, d := storedCount(t, r), r.l.Stats().Dropped[RefusedDuplicate]; n != 1 || d != 1 {
		t.Fatalf("stored %d, duplicates %d; want 1 and 1", n, d)
	}
}

// D6's N4 item 5 on #742: a tick whose span Unix nanoseconds cannot hold
// closes store with sensor-position-not-saved raised, as the hello does.
// Control: the raise removed.
func TestTickSpanUnsavedRaised(t *testing.T) {
	r := newRig(t, nil)
	p := r.accepted(hello02())
	tk := tick02(20, 0, 1)
	tk.Lost = []netobs.Span{{FromUTC: "2300-01-01T00:00:00Z", ToUTC: "2300-01-01T00:00:01Z"}}
	r.tickAfter(p, tk)
	if got := p.closed(); got != netobs.CloseStore || r.al.count(AlarmPositionNotSaved) != 1 {
		t.Fatalf("close %q, raises %v", got, r.al.list)
	}
}

// A release whose save fails, then a second whose save succeeds, with no
// connection open, then the hello: each drop is counted once in the saved
// cursor (D6's N7 on #742, from its probe P9). Controls: moveCursor leaving
// out l.unsaved gives dropped 1; a written release keeping l.unsaved gives 3.
func TestReleaseUnsavedThenWrittenCountedOnce(t *testing.T) {
	r, hs := holdRig02(t)
	hr := heldOne(t, r, hs, 1)
	a := withBody(t, hr, "", 10, true, nil)
	b := withBody(t, hr, "", 11, true, nil)
	ra := RunRecord{State: HoldHolding, Run: HoldRun{RequestID: "req-a", AssetID: relay, Endpoint: endpoint, L4: "tcp",
		Deadline: r.now().Add(time.Second)}, Flows: []HeldFlow{{Records: []HeldRecord{a}}}}
	rb := RunRecord{State: HoldHolding, Run: HoldRun{RequestID: "req-b", AssetID: relay, Endpoint: endpoint, L4: "tcp",
		Deadline: r.now().Add(time.Hour)}, Flows: []HeldFlow{{Records: []HeldRecord{b}}}}
	saveTestCursor(t, r, &Cursor{Generation: 2, RunCounter: 5, RunID: testRun, Taken: 9, Digest: testDigest})
	restartHeld(t, r, hs, []RunRecord{ra, rb})
	r.addWall(time.Minute)
	r.cs.failNext(1)
	r.l.TickHold(bg) // releases a; its save fails
	if n := r.al.count(AlarmPositionNotSaved); n != 1 {
		t.Fatalf("%d raises", n)
	}
	r.addWall(2 * time.Hour)
	r.l.TickHold(bg) // releases b; its save succeeds
	r.accepted(resume(12, 20)).end()
	c := cursorNow(t, r.cs)
	t.Logf("saved T %d dropped %d; stats %v", c.Taken, c.Dropped, r.l.Stats().Dropped)
	if c.Dropped != 2 {
		t.Fatalf("two drops, the saved total %d", c.Dropped)
	}
}
