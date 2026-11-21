package sensorlink

import (
	"net/netip"
	"testing"
	"time"

	"otsec.local/otsec/contracts/netobs"
)

// C13 0.2 T-13, no tie across a move of either clock (SL-17; CH-22,
// CH-41; D5-sensor-node.md section 1.5's TestTieStoredTimeAfterNodeStep,
// TestTieRecordBeforeSensorStep, TestTieNodeMovedSinceSample and
// TestSkewCountPrecedence), without (a)'s alert-key leg (INT-D5b's).
// Desk only: the test-only source (sim_test.go) on the rig's clocks. On
// the test clock ticks come every 10 s, tie_grace_s is 30 s unless a case
// says otherwise, and each dial that fails puts its session in the late
// index. In every case committed untied the test asserts the one
// skew_*_windows count that took it, that no other moved, and the
// sensor's capture floor after the case.
//
// The controls that a seam gives run here; the others are named mutants,
// applied one at a time with the test that kills each (the PR's body).

// Indexes into windows(): the counting order.
const (
	cLatest = iota
	cAlarm
	cMoved
	cPrestart
	cSpan
)

// t13 is T-13's rig: tie_grace_s g, pre run before the sensor connects,
// the sensor connected with nothing buffered and a minute of ticks read.
func t13(t *testing.T, g time.Duration, pre func(*sim), opt func(*Options)) (*rig, *sim, *holdSaves) {
	r, hs := holdRig02With(t, func(o *Options) {
		o.Hold.TieGrace = g
		if opt != nil {
			opt(o)
		}
	})
	s := newSim(r)
	if pre != nil {
		pre(s)
	}
	s.connect(true)
	s.pass(time.Minute)
	return r, s, hs
}

func skewedUntied(t *testing.T, nd *netobs.Node) {
	t.Helper()
	if nd.PlatformSession != nil || !nd.Skewed || nd.Backlog {
		t.Fatalf("want untied with node.skewed: %+v", nd)
	}
}

// refusedBy checks the one count that took the refusal, and that the
// floor stands above the record's capture time capt, raised by by.
func refusedBy(t *testing.T, r *rig, i int, by string, capt time.Time) {
	t.Helper()
	st := r.l.SkewStats()
	noOtherWindows(t, st, i, 1)
	if by != "" && (st.FloorBy != by || st.Floor.Before(capt)) {
		t.Fatalf("floor %s by %q, want at or above %s by %q", st.Floor, st.FloorBy, capt, by)
	}
}

// TestTieStoredTimeAfterNodeStep: T-13 (a), (b) and (c), and two legs for
// D6's mutants X2 and X4 (the stored-time half's session check and its
// node-start check). Controls: a node with no first half, its stored
// times compared as they are (skewNoStored), which ties (a) and (b); for
// (c), a node that ties by the late index rebuilt at a start.
func TestTieStoredTimeAfterNodeStep(t *testing.T) {
	// (a): tie_grace_s 60 s; a failing dial recorded as [X, X + 10 s];
	// 2 s after it both clocks stepped back 300 s; 340 s after the dial's
	// end, true time, a session from the node's address to the relay,
	// stamped about X + 50 s, past the capture floor.
	a := func(t *testing.T) (*rig, time.Time) {
		r, s, _ := t13(t, 60*time.Second, nil, nil)
		s.dialFails(1, 10*time.Second)
		s.pass(2 * time.Second)
		s.step(-300*time.Second, -300*time.Second)
		s.pass(338 * time.Second)
		at := s.now()
		s.synEnd(40001, at, time.Time{})
		return r, at
	}
	t.Run("(a)", func(t *testing.T) {
		r, at := a(t)
		skewedUntied(t, r.one(40001))
		refusedBy(t, r, cMoved, skewMoved, time.Time{})
		if f := r.l.SkewStats().Floor; !f.Before(at) {
			t.Fatalf("the floor %s is not below the session's %s", f, at)
		}
		t.Run("control: no first half", func(t *testing.T) {
			withSeam(t, &skewNoStored)
			r, _ := a(t)
			tiedTo(t, r.one(40001), 1)
		})
	})
	// (b): tie_grace_s 60 s; both clocks 300 s ahead; a failing dial
	// recorded as [X - 10 s, X]; 2 s after X the node's clock alone stepped
	// back 300 s, and 2 s later the source's; 340 s after the dial's end a
	// session placed at about X + 40 s. Its variant: the same correction on
	// both clocks together in steps of 1,900 ms, one every 2 s, and the
	// session 345 s after the dial's end, placed at about X + 45 s.
	b := func(t *testing.T, steps bool) *rig {
		r, s, _ := t13(t, 60*time.Second, func(s *sim) { s.step(300*time.Second, 300*time.Second) }, nil)
		s.dialFails(1, 10*time.Second)
		after := 340 * time.Second
		if steps {
			left := 300 * time.Second
			for left > 0 {
				s.pass(2 * time.Second)
				d := min(left, 1900*time.Millisecond)
				s.step(-d, -d)
				left -= d
			}
			after = 345*time.Second - 2*time.Second*158
		} else {
			s.pass(2 * time.Second)
			s.step(-300*time.Second, 0)
			s.pass(2 * time.Second)
			s.step(0, -300*time.Second)
			after -= 4 * time.Second
		}
		s.pass(after)
		s.synEnd(40001, s.now(), time.Time{})
		return r
	}
	for name, steps := range map[string]bool{"(b)": false, "(b), in steps of 1,900 ms": true} {
		t.Run(name, func(t *testing.T) {
			r := b(t, steps)
			skewedUntied(t, r.one(40001))
			refusedBy(t, r, cMoved, skewMoved, time.Time{})
			t.Run("control: no first half", func(t *testing.T) {
				withSeam(t, &skewNoStored)
				tiedTo(t, b(t, steps).one(40001), 1)
			})
		})
	}
	// (c): tie_grace_s 600 s, both clocks true; a failing dial that ended
	// 30 s before the node stops for one minute, the sensor running; 60 s
	// after the first hello after the start, a session placed in the
	// dial's window widened by 600 s, past the start's floor. The index is
	// empty at the start (section 1.6, D5's choice), so the flow commits
	// untied under its own key and no skew count moves, where C13's T-13
	// (c) counted skew_prestart_windows for a rebuilt entry.
	c := func(t *testing.T, rebuild bool) *rig {
		r, s, _ := t13(t, 600*time.Second, nil, nil)
		s.dialFails(1, 2*time.Second)
		s.pass(30 * time.Second)
		s.cut()
		old := r.l.hold.late
		r.restart()
		if rebuild {
			r.l.hold.late = old // as recorded, live: the control's rebuild
		}
		s.pass(time.Minute)
		s.connect(true)
		s.pass(time.Minute)
		s.synEnd(40001, s.now(), time.Time{})
		return r
	}
	t.Run("(c)", func(t *testing.T) {
		r := c(t, false)
		untiedOwnKey(t, r.one(40001))
		noOtherWindows(t, r.l.SkewStats(), -1, 0)
		t.Run("control: the late index rebuilt at the start", func(t *testing.T) {
			tiedTo(t, c(t, true).one(40001), 1)
		})
	})
	// X2: both clocks stepped 300 s ahead 1 s after a Dispatch and back
	// 3 s later, inside one tick interval, so no sample sees the move; the
	// collector records the dial on the stepped clock, as [D + 301 s,
	// D + 303 s], and its Result comes after the step back, with the
	// node's offsets at Dispatch and Result in agreement. The session's
	// times lie past the node's wall time at the Result: its window is
	// refused, and it enters no late index; a flow the sensor stamped on
	// its stepped clock inside that window, read later, commits untied.
	t.Run("X2: the session's times against Dispatch and Result", func(t *testing.T) {
		r, s, _ := t13(t, 30*time.Second, nil, nil)
		s.manual = true
		s.tick()
		if err := r.l.Dispatch(bg, HoldRun{RequestID: "req-1", AssetID: relay, Endpoint: endpoint, L4: "tcp"}); err != nil {
			t.Fatal(err)
		}
		d := r.now()
		s.hold = true
		s.pass(time.Second)
		s.step(300*time.Second, 300*time.Second)
		s.synEnd(40001, s.now().Add(time.Second), time.Time{})
		s.pass(3 * time.Second)
		s.step(-300*time.Second, -300*time.Second)
		s.pass(time.Second)
		rel, err := r.l.Result(bg, "req-1", Session{InvocationID: inv(1), StartedAt: d.Add(301 * time.Second), EndedAt: d.Add(303 * time.Second)})
		if err != nil || !rel.Skewed {
			t.Fatalf("released %+v, %v: the window was not refused", rel, err)
		}
		s.pass(5 * time.Second)
		s.tick()
		s.flush()
		untiedOwnKey(t, r.one(40001))
		if r.l.Stats().Hold.Late != 0 {
			t.Fatal("a refused window entered the late index")
		}
	})
	// X4: a run held across a node start, its Result after the start: the
	// window was recorded before the start and ties nothing, counted
	// skew_prestart_windows.
	t.Run("X4: a run held across a node start", func(t *testing.T) {
		r, s, hs := t13(t, 30*time.Second, nil, nil)
		if err := r.l.Dispatch(bg, HoldRun{RequestID: "req-1", AssetID: relay, Endpoint: endpoint, L4: "tcp"}); err != nil {
			t.Fatal(err)
		}
		from := r.now()
		s.flow(40001, from, time.Time{}, false)
		s.pass(time.Second)
		s.cut()
		restartHeld(t, r, hs, []RunRecord{hs.last()})
		s.connect(true)
		rel, err := r.l.Result(bg, "req-1", Session{InvocationID: inv(1), StartedAt: from, EndedAt: r.now(), Connected: true,
			Local: netip.AddrPortFrom(netip.MustParseAddr(nodeAddr), 40001), ConnectedAt: from})
		if err != nil || !rel.Skewed {
			t.Fatalf("released %+v, %v", rel, err)
		}
		skewedUntied(t, r.one(40001))
		noOtherWindows(t, r.l.SkewStats(), cPrestart, 1)
	})
}

// TestTieRecordBeforeSensorStep: T-13 (d) to (g), (i) to (q) and (s), in
// C13's order. Each record is placed inside a failing dial's window after
// a move of the sensor's clock, and is refused by the capture floor.
// Controls: a node with the first half alone (no capture floor), which
// ties (d), (e) and (f); for (q), M read as none; the others are named
// mutants (the PR's body).
func TestTieRecordBeforeSensorStep(t *testing.T) {
	ahead := func(s *sim) { s.off = 300 * time.Second }
	// (d): the sensor's clock 300 s ahead, the alarm standing; a session
	// at T stamped T + 300 s, its start record numbered at once; the
	// sensor's clock stepped back 300 s at T + 5 s; the record sent at
	// T + 305 s behind a queue; a failing dial at T + 300 s.
	d := func(t *testing.T) *rig {
		r, s, _ := t13(t, 30*time.Second, ahead, nil)
		s.hold = true
		s.synEnd(40001, s.now(), time.Time{})
		s.pass(5 * time.Second)
		s.step(0, -300*time.Second)
		s.pass(295 * time.Second)
		s.dialFails(1, 2*time.Second)
		s.pass(3 * time.Second)
		s.flush()
		return r
	}
	// (e): both clocks true until T + 5 s, then stepped back 300 s
	// together; the session stamped T; the dial at T + 300 s, true time.
	e := func(t *testing.T) *rig {
		r, s, _ := t13(t, 30*time.Second, nil, nil)
		s.hold = true
		s.synEnd(40001, s.now(), time.Time{})
		s.pass(5 * time.Second)
		s.step(-300*time.Second, -300*time.Second)
		s.pass(295 * time.Second)
		s.dialFails(1, 2*time.Second)
		s.pass(3 * time.Second)
		s.flush()
		return r
	}
	// (f): (d) with the session's start record written at its end, after
	// the dial, numbered after the first tick that shows the correction.
	f := func(t *testing.T, held bool) *rig {
		var hs *holdingStore
		opt := func(o *Options) {}
		if held {
			hs = &holdingStore{}
			opt = func(o *Options) { hs.Appender = o.Store; o.Store = hs }
		}
		r, s, _ := t13(t, 30*time.Second, ahead, opt)
		at := s.now()
		s.pass(5 * time.Second)
		s.step(0, -300*time.Second)
		if held {
			// (j): the first tick after the correction at T + 10 s, the
			// read loop held 3 s at a tick at T + 20 s, and a tick on time
			// after it.
			s.pass(5 * time.Second)
			s.manual = true
			s.pass(10 * time.Second)
			heldTick(t, s, hs)
			s.manual = false
			s.tickAt = s.r.trueNow().Add(10 * time.Second)
		}
		s.pass(at.Add(-300 * time.Second).Add(300 * time.Second).Sub(s.r.trueNow()))
		s.dialFails(1, 2*time.Second)
		s.pass(time.Second)
		s.synEnd(40001, at, time.Time{})
		return r
	}
	for name, run := range map[string]func(*testing.T) *rig{"(d)": d, "(e)": e, "(f)": func(t *testing.T) *rig { return f(t, false) }} {
		t.Run(name, func(t *testing.T) {
			r := run(t)
			skewedUntied(t, r.one(40001))
			refusedBy(t, r, cMoved, skewMoved, time.Time{})
			t.Run("control: the first half alone", func(t *testing.T) {
				withSeam(t, &skewNoFloor)
				tiedTo(t, run(t).one(40001), 1)
			})
		})
	}
	// (g): the sensor's clock 300 s ahead, a session at T stamped T +
	// 300 s, the connection reset at T + 10 s, the sensor's clock stepped
	// back 300 s at T + 20 s, the next hello at T + 40 s, a failing dial at
	// T + 300 s, the session's start record written at its end, numbered
	// after the hello's newest_seq. K is kept across the connections, so
	// the hello's K raises the floor. Mutant: K's baseline taken afresh at
	// each hello, which ties it.
	t.Run("(g)", func(t *testing.T) {
		r, s, _ := t13(t, 30*time.Second, ahead, nil)
		at := s.now()
		s.pass(10 * time.Second)
		s.cut()
		s.pass(10 * time.Second)
		s.step(0, -300*time.Second)
		s.pass(20 * time.Second)
		s.connect(true)
		s.pass(260 * time.Second)
		s.dialFails(1, 2*time.Second)
		s.pass(time.Second)
		s.synEnd(40001, at, time.Time{})
		skewedUntied(t, r.one(40001))
		refusedBy(t, r, cMoved, skewMoved, at)
	})
	// (i): both clocks true, tie_grace_s 3 s; a tick sent at R - 3 s and
	// read at R after a read loop held 3 s; a session at R + 5 s stamped
	// so; both clocks stepped back 1.5 s at R + 5.5 s and at R + 6.5 s;
	// the next tick at R + 7 s, on time; a failing dial at R + 9 s for 2 s,
	// recorded as [R + 6 s, R + 8 s]; the session's start record read
	// after it, placed at R + 5 s. The floor rises to about R + 9 s at the
	// tick of R + 7 s. Mutant (X9, X10): a K read after a held loop taken
	// as the baseline, which ties it.
	t.Run("(i)", func(t *testing.T) {
		hs := &holdingStore{}
		r, s, _ := t13(t, 3*time.Second, nil, func(o *Options) { hs.Appender = o.Store; o.Store = hs })
		s.manual = true
		s.pass(10 * time.Second)
		heldTick(t, s, hs)
		rt := r.now()
		s.pass(5 * time.Second)
		at := s.now()
		s.pass(500 * time.Millisecond)
		s.step(-1500*time.Millisecond, -1500*time.Millisecond)
		s.pass(time.Second)
		s.step(-1500*time.Millisecond, -1500*time.Millisecond)
		s.pass(500 * time.Millisecond)
		s.tick()
		if f := r.l.SkewStats().Floor; f.Before(rt.Add(9*time.Second)) || f.After(rt.Add(9500*time.Millisecond)) {
			t.Fatalf("floor %s, want about R + 9 s (%s)", f, rt.Add(9*time.Second))
		}
		s.pass(2 * time.Second)
		ss := s.dialFails(1, 2*time.Second)
		if !ss.StartedAt.Equal(rt.Add(6*time.Second)) || !ss.EndedAt.Equal(rt.Add(8*time.Second)) {
			t.Fatalf("the dial was recorded as [%s, %s], want [R + 6 s, R + 8 s]", ss.StartedAt, ss.EndedAt)
		}
		s.synEnd(40001, at, time.Time{})
		skewedUntied(t, r.one(40001))
		refusedBy(t, r, cMoved, skewMoved, at)
		if r.l.SkewStats().SamplesAfterHold != 1 {
			t.Fatal("the held sample was not counted")
		}
	})
	// (j): (f) with the read loop held 3 s at a tick after the correction
	// and before the record is read, and a tick on time between that tick
	// and the record's read, so the latest sample is inside max_skew_ms.
	// The floor never falls. Mutant: a node that sets the floor to each
	// raise's value, which ties it.
	t.Run("(j)", func(t *testing.T) {
		r := f(t, true)
		skewedUntied(t, r.one(40001))
		refusedBy(t, r, cMoved, skewMoved, time.Time{})
		if st := r.l.SkewStats(); st.SamplesAfterHold != 1 || absDur(st.Latest) > MaxSkew {
			t.Fatalf("stats %+v: want one held sample and the latest inside", st)
		}
	})
	// (k): both clocks true; a session at T stamped T and held open; at
	// T + 10 s both clocks stepped back 600 s, seen at the next tick and
	// saved at once in M; the node stopped at T + 60 s and started one
	// minute later; a failing dial at T + 600 s, true time; the session's
	// start record read once the backlog is through. Mutant: no M, the
	// floor in memory only, which ties it.
	k := func(t *testing.T, rekey, noM bool) *rig {
		r, s, _ := t13(t, 30*time.Second, nil, nil)
		at := s.now()
		s.pass(10 * time.Second)
		s.step(-600*time.Second, -600*time.Second)
		s.pass(50 * time.Second)
		s.cut()
		if noM {
			c := cursorNow(t, r.cs)
			c.M = time.Time{}
			saveTestCursor(t, r, c)
		}
		r.restart()
		s.pass(time.Minute)
		if rekey {
			// (q): a rekey applied at T + 30 s: the new generation's run 1
			// is the first run read after the start.
			s.en = Enrolment{SensorID: testSensor, Generation: 3, Began: 3, ConfigDigest: testDigest}
			s.run, s.counter, s.newRun, s.seq, s.sent = testRun2, 1, true, 0, 0
		}
		s.connect(true)
		s.pass(at.Add(600 * time.Second).Sub(s.r.trueNow()))
		s.dialFails(1, 2*time.Second)
		s.pass(time.Second)
		s.synEnd(40001, at, time.Time{})
		return r
	}
	for name, rekey := range map[string]bool{"(k)": false, "(q)": true} {
		t.Run(name, func(t *testing.T) {
			r := k(t, rekey, false)
			skewedUntied(t, r.one(40001))
			refusedBy(t, r, cPrestart, skewPrestart, time.Time{})
			if rekey {
				t.Run("control: M read as none with the lower generation's position", func(t *testing.T) {
					tiedTo(t, k(t, true, true).one(40001), 1)
				})
			}
		})
	}
	// (l): both clocks true, the sensor's heartbeats on; a session at T
	// stamped T and held open; the node stopped at T + 20 s for one
	// minute, both clocks stepped back 300 s during the stop; after the
	// start a failing dial at T on the new clocks; the session's start
	// record written at its end, after the hello. Mutant: a node that
	// starts with no floor, no M and no raise from the first break's
	// heartbeats, which ties it.
	t.Run("(l)", func(t *testing.T) {
		r, s, _ := t13(t, 30*time.Second, nil, nil)
		s.beat()
		at := s.now()
		s.pass(20 * time.Second)
		s.cut()
		r.restart()
		s.pass(30 * time.Second)
		s.step(-300*time.Second, -300*time.Second)
		s.pass(30 * time.Second)
		s.connect(true)
		s.pass(at.Add(300 * time.Second).Sub(s.r.trueNow()))
		s.dialFails(1, 2*time.Second)
		s.pass(time.Second)
		s.synEnd(40001, at, time.Time{})
		skewedUntied(t, r.one(40001))
		refusedBy(t, r, cPrestart, skewPrestart, at)
	})
	// (m): both clocks true, heartbeats on; the node stopped for ten
	// minutes from S; a session at S + 5 min stamped so; both clocks
	// stepped back 600 s at S + 6 min; the node started at S + 10 min; a
	// failing dial at S + 15 min, true time. The first break's heartbeats
	// raise the floor to about S + 382 s. Mutant: M but no raise from the
	// first break's heartbeats, which ties it.
	t.Run("(m)", func(t *testing.T) {
		r, s, _ := t13(t, 30*time.Second, nil, nil)
		s.beat()
		start := s.now()
		s.cut()
		s.pass(5 * time.Minute)
		at := s.now()
		s.pass(time.Minute)
		s.step(-600*time.Second, -600*time.Second)
		s.pass(4 * time.Minute)
		r.restart()
		s.connect(true)
		s.pass(start.Add(15 * time.Minute).Sub(s.r.trueNow()))
		s.dialFails(1, 2*time.Second)
		s.pass(time.Second)
		s.synEnd(40001, at, time.Time{})
		skewedUntied(t, r.one(40001))
		refusedBy(t, r, cPrestart, skewPrestart, at)
	})
	// (n): (m)'s stop with the agent restarted at S + 1 min, a new run
	// begun while the old run holds records above taken; a session at
	// S + 3 min; both clocks stepped back 600 s at S + 6 min; the node
	// started at S + 10 min, its first hello the old run's, current false,
	// then the new run's; a failing dial at S + 13 min, true time; the
	// floor at about S + 382 s. Mutant: a node that raises the floor only
	// from the heartbeats of the first hello's run, which ties it.
	t.Run("(n)", func(t *testing.T) {
		r, s, _ := t13(t, 30*time.Second, nil, nil)
		s.beat()
		start := s.now()
		s.cut()
		s.pass(time.Minute)
		s.beats = false // the agent restarted: the old run makes no more
		n := newSim(r)
		n.run, n.counter = testRun2, 6
		n.beat()
		n.pass(2 * time.Minute)
		at := n.now()
		n.pass(3 * time.Minute)
		n.step(-600*time.Second, 0)
		n.off -= 600 * time.Second
		s.off = n.off
		n.pass(4 * time.Minute)
		r.restart()
		s.connect(false)
		s.cut()
		n.connect(true)
		n.pass(start.Add(13 * time.Minute).Sub(n.r.trueNow()))
		n.dialFails(1, 2*time.Second)
		n.pass(time.Second)
		n.synEnd(40001, at, time.Time{})
		skewedUntied(t, r.one(40001))
		refusedBy(t, r, cPrestart, skewPrestart, at)
	})
	// (o), (p) and (s): both clocks true, heartbeats on; the node stopped
	// for ten minutes from S; a session at S + 3 min; the source evicts
	// every record made from S + 2 min to S + 7 min, heartbeats included,
	// and states that span with the rise in drops_channel that pays for
	// it; both clocks stepped back 900 s at S + 6 min; the node started at
	// S + 10 min; a failing dial at S + 18 min, true time. The span's upper
	// end is about S + 360 s, so the floor is about S + 392 s, raised by
	// the span. (o): the span stated in the first hello. (p): the first
	// hello states none; the eviction is made during the drain, once every
	// record made before S + 2 min is taken, and its span is first stated
	// in the next tick. (s): the eviction is made just before the session's
	// start record is sent, so its span is first stated in the last tick
	// before that record, read before the next tick. Mutants: (o) a node
	// that raises no floor from a stated span; (p) one that raises it only
	// from spans stated up to the first current hello; (s) one that applies
	// a tick's spans only at the following tick; each ties it.
	span := func(t *testing.T, leg string) *rig {
		r, s, _ := t13(t, 30*time.Second, nil, nil)
		s.beat()
		start := s.now()
		s.cut()
		s.pass(3 * time.Minute)
		at := s.now()
		s.pass(3 * time.Minute)
		s.step(-900*time.Second, -900*time.Second)
		s.pass(4 * time.Minute)
		evict := func() { s.evict(start.Add(2*time.Minute), start.Add(7*time.Minute)) }
		r.restart()
		s.hold = leg != "(o)"
		switch leg {
		case "(o)":
			evict()
			s.connect(true)
		case "(p)":
			s.connect(true)
			n := 0
			for n < len(s.bufAt) && s.bufAt[n].Before(start.Add(2*time.Minute)) {
				n++
			}
			s.sendN(n)
			evict()
			s.tick()
			s.flush()
			s.hold = false
		case "(s)":
			s.connect(true)
			n := 0
			for n < len(s.bufAt) && s.bufAt[n].Before(start.Add(2*time.Minute)) {
				n++
			}
			s.sendN(n)
			s.manual = true
		}
		s.pass(start.Add(18 * time.Minute).Sub(s.r.trueNow()))
		s.dialFails(1, 2*time.Second)
		s.pass(time.Second)
		s.synEnd(40001, at, time.Time{})
		if leg == "(s)" {
			evict()
			s.pass(5 * time.Second)
			s.tick()
			s.flush()
		}
		if hi := parseUTC(s.spans[0].ToUTC); hi.Before(start.Add(350*time.Second)) || hi.After(start.Add(370*time.Second)) {
			t.Fatalf("the span's upper end %s, want about S + 360 s", hi)
		}
		return r
	}
	for _, leg := range []string{"(o)", "(p)", "(s)"} {
		t.Run(leg, func(t *testing.T) {
			r := span(t, leg)
			skewedUntied(t, r.one(40001))
			refusedBy(t, r, cSpan, skewSpan, time.Time{})
		})
	}
}

// heldTick sends a record whose commit holds the read loop 3 s on both of
// the rig's clocks, and a tick made before it is sent: the tick is read
// 3 s late, after a held loop.
func heldTick(t *testing.T, s *sim, hs *holdingStore) {
	t.Helper()
	s.hold = true
	s.write(obs02(0))
	s.hold = false
	tk := tick02(s.seq, s.seq, s.drops)
	tk.RunID, tk.SensorUTC, tk.Lost = s.run, canonUTC(s.now()), append([]netobs.Span{}, s.spans...)
	hs.hold(func() { s.r.pass(3 * time.Second) })
	s.p.send(s.buf[0], tk)
	s.sent, s.buf, s.bufAt = s.seq, nil, nil
	s.p.taken()
}

// TestTieNodeMovedSinceSample: T-13 (h), the closure for the node's side:
// the two clocks in agreement; a session at T stamped T and held open; at
// T + 297 s, 3 s after a tick's receipt, the node's clock alone stepped
// back 300 s; at T + 298 s a dial that fails for 2 s, recorded as
// [T - 2 s, T] on the new clock; the session's start record read at
// T + 301 s, before the next tick, no heartbeat and no node tick between
// the step and the tie. The closure stands: the dial is refused at its
// Dispatch, counted skew_moved_windows, and the record commits untied and
// marked. Mutant: a node without the closure, which ties it. The step-
// check variant, counted under skew_latest_windows, needs the step check
// of the gap model (2e).
func TestTieNodeMovedSinceSample(t *testing.T) {
	r, s, _ := t13(t, 30*time.Second, nil, nil)
	s.manual = true
	s.tick()
	at := s.now().Add(-294 * time.Second)
	s.pass(3 * time.Second)
	s.step(-300*time.Second, 0)
	s.pass(time.Second)
	ss := s.dialFails(1, 2*time.Second)
	if !ss.StartedAt.Equal(at.Add(-2*time.Second)) || !ss.EndedAt.Equal(at) {
		t.Fatalf("the dial was recorded as [%s, %s], want [T - 2 s, T]", ss.StartedAt, ss.EndedAt)
	}
	s.pass(time.Second)
	s.synEnd(40001, at, time.Time{})
	skewedUntied(t, r.one(40001))
	refusedBy(t, r, cMoved, "", time.Time{})
}

// TestSkewCountPrecedence: T-13 (r), which count takes a refusal when two
// causes refuse (CH-41's order; D1's ruling 6849345925 on #645), each leg
// with a failing dial and a session from the node's address inside its
// window, its start record written at its end, the first hello read more
// than a minute before. (r1): the sensor's clock 3,000 ms ahead since
// before the hello: the alarm stands and the latest sample is outside;
// the dial is refused at its Dispatch, counted once under
// skew_latest_windows. (r2): 2,500 ms ahead until the alarm stands, then
// 1,800 ms ahead, so the latest sample is inside and the alarm stands
// (|E| above 1,500 ms); both clocks stepped back 300 s at T + 5 s, which
// raises the floor past T; the dial at T + 300 s: counted once under
// skew_alarm_windows. (r3): the node's clock 1,000 ms ahead of the
// sensor's; the dial recorded as [X - 10 s, X]; the session at X + 5 s;
// at X + 10 s the source evicts the records made from X - 20 s, none yet
// sent, and states the span in the next tick, which raises the floor; at
// X + 20 s the node's clock alone stepped back 2,500 ms, which moves the
// dial's stored window and leaves the latest sample inside once the next
// tick is read; the record read at X + 25 s: counted once under
// skew_moved_windows. Mutants: the alarm before the latest sample (r1);
// the capture floor before the rule on the two clocks (r3); a refusal
// counted under every cause that refuses it (r1, r3).
func TestSkewCountPrecedence(t *testing.T) {
	t.Run("(r1)", func(t *testing.T) {
		r, s, _ := t13(t, 30*time.Second, func(s *sim) { s.off = 3 * time.Second }, nil)
		s.pass(time.Minute)
		at := s.now()
		s.dialFails(1, 2*time.Second)
		s.pass(time.Second)
		s.synEnd(40001, at, time.Time{})
		skewedUntied(t, r.one(40001))
		refusedBy(t, r, cLatest, "", time.Time{})
	})
	t.Run("(r2)", func(t *testing.T) {
		r, s, _ := t13(t, 30*time.Second, func(s *sim) { s.off = 2500 * time.Millisecond }, nil)
		s.step(0, -700*time.Millisecond)
		s.pass(time.Minute)
		at := s.now()
		s.pass(5 * time.Second)
		s.step(-300*time.Second, -300*time.Second)
		s.pass(295 * time.Second)
		if st := r.l.SkewStats(); !st.Alarm || absDur(st.Latest) > MaxSkew {
			t.Fatalf("want the alarm alone: %+v", st)
		}
		s.dialFails(1, 2*time.Second)
		s.pass(time.Second)
		s.synEnd(40001, at, time.Time{})
		skewedUntied(t, r.one(40001))
		refusedBy(t, r, cAlarm, skewMoved, at)
	})
	t.Run("(r3)", func(t *testing.T) {
		r, s, _ := t13(t, 30*time.Second, func(s *sim) { s.step(time.Second, 0) }, nil)
		s.beat()
		s.manual = true
		s.tick()
		s.pass(time.Second)
		s.hold = true
		ss := s.dialFails(1, 10*time.Second) // [X - 10 s, X]
		x := ss.EndedAt
		s.pass(5 * time.Second)
		at := s.now() // the session at X + 5 s, on the sensor's clock
		s.pass(5 * time.Second)
		s.evict(s.r.trueNow().Add(-30*time.Second), s.r.trueNow())
		s.tick()
		s.hold = false
		s.flush()
		s.pass(10 * time.Second)
		s.step(-2500*time.Millisecond, 0)
		s.pass(time.Second)
		s.tick()
		s.pass(4 * time.Second)
		s.synEnd(40001, at, time.Time{})
		skewedUntied(t, r.one(40001))
		refusedBy(t, r, cMoved, skewSpan, at)
		if st := r.l.SkewStats(); absDur(st.Latest) > MaxSkew || st.Alarm || st.Floor.Before(x.Add(40*time.Second)) {
			t.Fatalf("stats %+v: want the latest inside, no alarm, the floor about X + 42 s", st)
		}
	})
}
