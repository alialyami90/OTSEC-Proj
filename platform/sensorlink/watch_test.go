package sensorlink

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"otsec.local/otsec/contracts/event"
	"otsec.local/otsec/contracts/netobs"
)

// INT-D5 2e-1 (watch.go; docs/phase4/D5-sensor-node.md sections 1.4 and
// 1.9 item 5): W, R, the capture check, the step check, time.node-stepped
// and the run file's copy. Desk only: the in-memory pipe and the rig's
// test clocks, both of the node's clocks moved together (rig.pass) unless
// a case steps the wall clock.

// beatAt sends heartbeat h a second after the frame before was acted on,
// and waits for its ack.
func (r *healthRig) beatAt(p *peer, h *netobs.Heartbeat) {
	r.t.Helper()
	p.taken()
	r.pass(time.Second)
	p.send(h)
	p.ack(num(h.Seq))
}

// at sets a heartbeat's at_utc.
func at(t time.Time) func(*netobs.Heartbeat) {
	return func(h *netobs.Heartbeat) { h.AtUTC = canonUTC(t) }
}

// pk sets the one interface's packets, and the run total with it.
func pk(n uint64, carrier string) func(*netobs.Heartbeat) {
	return func(h *netobs.Heartbeat) {
		h.Interfaces[0].Packets, h.Interfaces[0].Carrier = n, carrier
		h.Counters.Packets, h.Counters.Bytes = n, n*90
	}
}

// resumeAt is resume(first, newest) stamped with the node's wall clock,
// so its sample's o is 0.
func (r *healthRig) resumeAt(first, newest int) *netobs.SensorHello {
	h := resume(first, newest)
	h.SensorUTC = canonUTC(r.now())
	return h
}

func hbWith(seq int, fs ...func(*netobs.Heartbeat)) *netobs.Heartbeat {
	h := hb(seq, nil)
	for _, f := range fs {
		f(h)
	}
	return h
}

func wantW(t *testing.T, r *healthRig, w, rr time.Time, what string) {
	t.Helper()
	gw, gr := r.l.watchNow()
	if !gw.Equal(w) || !gr.Equal(rr) {
		t.Fatalf("%s: W %s and R %s, want %s and %s", what, gw, gr, w, rr)
	}
}

// TestWPlacedAtCurrentHeartbeat: W moves at each current heartbeat that
// shows capture, R at each in which an interface's packets rose with its
// carrier not down, each to the earlier of the receipt and at_utc + E and
// never later than the wall clock. The first heartbeat of a run accepted
// as new shows capture by the run's start and raises no R; a late
// heartbeat, one whose only interface has its carrier down, one flat for
// more than blind_after_s, one of a run the hello names as not current,
// and one read in a backlog not yet through move neither. Control
// (V-16's fifth case's placement half): a node that places W and R at
// their receipts, which places a heartbeat delayed 120 s at its receipt.
func TestWPlacedAtCurrentHeartbeat(t *testing.T) {
	// Each heartbeat is made 120 s before its receipt, a second after the
	// frame before is acted on.
	run := func(t *testing.T, check bool) *healthRig {
		r := newHealthRig(t)
		p := r.accepted(live02()) // E is the hello's o, 0
		r.pass(5 * time.Minute)
		d := r.now().Add(-119 * time.Second)
		r.beatAt(p, hbWith(1, at(d), pk(100, "up")))
		if check {
			wantW(t, r, d, time.Time{}, "the run's first heartbeat")
		}
		d = r.now().Add(-119 * time.Second)
		r.beatAt(p, hbWith(2, at(d), pk(200, "up")))
		if check {
			wantW(t, r, d, d, "a rise")
		}
		p.end()
		return r
	}
	r := run(t, true)
	t.Run("control: placed at the receipt", func(t *testing.T) {
		withSeam(t, &placeAtReceipt)
		r := run(t, false)
		if w, _ := r.l.watchNow(); !w.Equal(r.now()) {
			t.Fatalf("W %s, the control places it at the receipt %s", w, r.now())
		}
	})
	p := r.dial(enrolment())
	p.send(r.resumeAt(3, 2))
	p.ack(2)
	recv := r.now().Add(time.Second)
	r.beatAt(p, hbWith(3, at(recv.Add(300*time.Second)), pk(300, "up")))
	wantW(t, r, recv, recv, "a sensor clock 300 s ahead: the receipt")
	held := recv
	for i, c := range []struct {
		what string
		f    []func(*netobs.Heartbeat)
		wait time.Duration
	}{
		{"late (CH-23)", []func(*netobs.Heartbeat){pk(400, "up"), func(h *netobs.Heartbeat) { h.AtUTC = canonUTC(r.now().Add(-200 * time.Second)) }}, 0},
		{"its carrier down", []func(*netobs.Heartbeat){pk(500, "down"), func(h *netobs.Heartbeat) { h.AtUTC = canonUTC(r.now()) }}, 0},
		{"flat past blind_after_s", []func(*netobs.Heartbeat){pk(500, "up"), func(h *netobs.Heartbeat) { h.AtUTC = canonUTC(r.now().Add(DefaultBlindAfter + time.Second)) }}, DefaultBlindAfter},
	} {
		r.pass(c.wait)
		h := hbWith(4+i, c.f...)
		if c.wait > 0 {
			h.AtUTC = canonUTC(r.now().Add(time.Second))
		}
		r.beatAt(p, h)
		wantW(t, r, held, held, c.what)
	}
	if r.l.SkewStats().Late != 1 {
		t.Fatalf("late %d", r.l.SkewStats().Late)
	}
	// Flat but within blind_after_s of the last rise: W moves, R does not.
	r.beatAt(p, hbWith(7, at(r.now().Add(time.Second)), pk(600, "up")))
	w7 := r.now()
	wantW(t, r, w7, w7, "a rise again")
	r.pass(time.Minute)
	r.beatAt(p, hbWith(8, at(r.now().Add(time.Second)), pk(600, "up")))
	wantW(t, r, r.now(), w7, "flat within blind_after_s")
	w8 := r.now()
	p.end()
	// A run named not current, and a backlog not through.
	notCurrent := r.resumeAt(9, 8)
	notCurrent.Current = ptr(false)
	p = r.dial(enrolment())
	p.send(notCurrent)
	p.ack(8)
	r.beatAt(p, hbWith(9, at(r.now().Add(time.Second)), pk(700, "up")))
	wantW(t, r, w8, w7, "a run named not current")
	p.end()
	p = r.dial(enrolment())
	p.send(r.resumeAt(10, 20))
	p.ack(9)
	r.beatAt(p, hbWith(10, at(r.now().Add(time.Second)), pk(800, "up")))
	wantW(t, r, w8, w7, "a backlog not through")
}

// TestK1FallingPacketsAcrossRestart: C13 K-1 across a node restart. The
// packets kept with W are the run's baseline after a start: a heartbeat of
// the run whose interface's packets fall below them is refused as order by
// Follows and counted counter-decrease; one at or above them is taken.
// A new run's counts are judged against nothing kept from another run.
// Control: a node that judges a heartbeat against the previous heartbeat
// of this process only, which takes the fall after a restart.
func TestK1FallingPacketsAcrossRestart(t *testing.T) {
	run := func(t *testing.T) *healthRig {
		r := newHealthRig(t)
		p := r.accepted(live02())
		r.beatAt(p, hbWith(1, pk(100, "up")))
		r.beatAt(p, hbWith(2, pk(200, "up")))
		p.end()
		if c := cursorNow(t, r.cs); len(c.Ifaces) != 1 || c.Ifaces[0].Packets != 200 || c.WSeq != 2 {
			t.Fatalf("the cursor keeps %+v with W at seq %d", c.Ifaces, c.WSeq)
		}
		r.restart()
		p = r.dial(enrolment())
		p.send(resume(3, 2))
		p.ack(2)
		r.pass(time.Second)
		p.send(hbWith(3, pk(150, "up")))
		p.taken()
		return r
	}
	r := run(t)
	if n := refused(r.l, RefusedCounterDecrease); n != 1 {
		t.Fatalf("counter-decrease %d, want 1", n)
	}
	t.Run("control: the previous heartbeat of this process only", func(t *testing.T) {
		withSeam(t, &k1ProcessOnly)
		if n := refused(run(t).l, RefusedCounterDecrease); n != 0 {
			t.Fatalf("counter-decrease %d under the control", n)
		}
	})
	// Another run: the packets kept are the run's own, so a new run's first
	// counts, below the old run's, are taken across a restart.
	r = newHealthRig(t)
	p := r.accepted(live02())
	r.beatAt(p, hbWith(1, pk(200, "up")))
	p.end()
	h6 := run6()
	h6.FirstSeq, h6.NewestSeq, h6.SensorUTC = "1", "0", canonUTC(r.now())
	p = r.accepted(h6)
	p.end()
	if c := cursorNow(t, r.cs); c.RunID != testRun2 || len(c.Ifaces) != 0 {
		t.Fatalf("run 6's cursor keeps %+v", c.Ifaces)
	}
	r.restart()
	h6 = run6()
	h6.Prior, h6.FirstSeq, h6.NewestSeq = nil, "1", "0"
	p = r.dial(enrolment())
	p.send(h6)
	p.ack(0)
	h := hbWith(1, pk(10, "up"))
	h.RunID = testRun2
	r.beatAt(p, h)
	if n := refused(r.l, RefusedCounterDecrease); n != 0 {
		t.Fatalf("a new run's count judged against the old run's: %d", n)
	}
	p.end()
	// At or above the kept value: taken.
	r = newHealthRig(t)
	p = r.accepted(live02())
	r.beatAt(p, hbWith(1, pk(100, "up")))
	p.end()
	r.restart()
	p = r.dial(enrolment())
	p.send(resume(2, 1))
	p.ack(1)
	r.beatAt(p, hbWith(2, pk(100, "up")))
	if n := refused(r.l, RefusedCounterDecrease); n != 0 {
		t.Fatalf("an equal count refused: %d", n)
	}
}

// runFileCopy is the run file's copy of the earlier of W and R.
func runFileCopy(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var d runFileDoc
	if err := json.Unmarshal(b, &d); err != nil {
		t.Fatal(err)
	}
	if e := d.Sensors[testSensor]; e != nil {
		return e.Copy
	}
	return ""
}

// TestStepCheckThreshold: the step check acts only on a step back of more
// than max_skew_ms between two checks (V-9's eleventh case, at the link;
// its gap half is 2e-2's). The wall clock running slow by 0.5 ms each
// second for ten minutes, checked every second, and then one step back of
// 1,900 ms, move nothing and write nothing. One step back of 3 s moves W
// and R back by it, saves them in the cursor and the run file's copy at
// once, and writes time.node-stepped once. Control: a node that acts on
// any backward difference, which moves W through the slew.
func TestStepCheckThreshold(t *testing.T) {
	setup := func(t *testing.T) (*healthRig, time.Time) {
		r := newHealthRig(t)
		p := r.accepted(live02())
		r.beatAt(p, hbWith(1, at(r.now().Add(time.Second)), pk(100, "up")))
		r.beatAt(p, hbWith(2, at(r.now().Add(time.Second)), pk(200, "up")))
		w := r.now()
		wantW(t, r, w, w, "placed")
		r.l.CheckStep(bg)
		for range 600 {
			r.pass(time.Second)
			r.addWall(-500 * time.Microsecond)
			r.l.CheckStep(bg)
		}
		r.addWall(-1900 * time.Millisecond)
		r.l.CheckStep(bg)
		return r, w
	}
	r, w := setup(t)
	wantW(t, r, w, w, "a slew and a step of 1,900 ms")
	if n := r.sink.count(event.HealthTimeNodeStepped); n != 0 {
		t.Fatalf("time.node-stepped %d", n)
	}
	t.Run("control: any backward difference", func(t *testing.T) {
		withSeam(t, &stepAnyBack)
		r, w := setup(t)
		if gw, _ := r.l.watchNow(); !gw.Before(w) {
			t.Fatalf("W %s not moved under the control", gw)
		}
	})
	r.pass(time.Second)
	r.addWall(-3 * time.Second)
	r.l.CheckStep(bg)
	moved := w.Add(-3 * time.Second)
	wantW(t, r, moved, moved, "a step back of 3 s")
	if c := cursorNow(t, r.cs); !c.W.Equal(moved) || !c.R.Equal(moved) {
		t.Fatalf("the cursor holds W %s and R %s", c.W, c.R)
	}
	if got := runFileCopy(t, r.path); got != canonUTC(moved) {
		t.Fatalf("the run file's copy %q, want %s", got, canonUTC(moved))
	}
	r.pass(time.Second)
	r.l.CheckStep(bg)
	d := r.sink.of(event.HealthTimeNodeStepped)
	if len(d) != 1 || d[0]["step_back_ms"] != "3000" || d[0]["sensor_id"] != testSensor {
		t.Fatalf("time.node-stepped: %v", d)
	}
}

// TestRunFileCopyEarlierOfWR: the run file's copy is the earlier of W and
// R as the link holds them when the file is written; with the sensor
// database lost at a start the link holds none, and the copy the file had
// is written again, never dropped.
func TestRunFileCopyEarlierOfWR(t *testing.T) {
	r := newHealthRig(t)
	p := r.accepted(live02())
	r.beatAt(p, hbWith(1, at(r.now().Add(time.Second)), pk(100, "up")))
	r.beatAt(p, hbWith(2, at(r.now().Add(time.Second)), pk(200, "up")))
	rAt := r.now()
	r.beatAt(p, hbWith(3, at(r.now().Add(time.Second)), pk(200, "up"))) // flat: W moves, R does not
	r.settleFile()
	if got := runFileCopy(t, r.path); got != canonUTC(rAt) {
		t.Fatalf("the copy %q, want R %s", got, canonUTC(rAt))
	}
	p.end()
	r.loseDatabase()
	r.restart()
	if got := runFileCopy(t, r.path); got != canonUTC(rAt) {
		t.Fatalf("after a start with the database lost, the copy %q, want %s", got, canonUTC(rAt))
	}
}

// TestStepCheckAtReceipt: the step check runs before a heartbeat's receipt
// is taken, not only at the node's tick (V-9's eighth case, at the link;
// its gap half is 2e-2's). R placed at a heartbeat with a rise, the wall
// clock stepped back 5 s, and the next heartbeat flat with no node tick
// between: R is moved back by the step once that heartbeat is read.
// Control: a node that runs the check only at its tick, which keeps R on
// the old clock, later than that heartbeat's receipt.
func TestStepCheckAtReceipt(t *testing.T) {
	run := func(t *testing.T) (*healthRig, time.Time) {
		r := newHealthRig(t)
		p := r.accepted(live02())
		r.beatAt(p, hbWith(1, at(r.now().Add(time.Second)), pk(100, "up")))
		r.beatAt(p, hbWith(2, at(r.now().Add(time.Second)), pk(200, "up")))
		rAt := r.now()
		r.addWall(-5 * time.Second)
		r.beatAt(p, hbWith(3, at(r.now().Add(time.Second)), pk(200, "up")))
		return r, rAt
	}
	r, rAt := run(t)
	if _, got := r.l.watchNow(); !got.Equal(rAt.Add(-5 * time.Second)) {
		t.Fatalf("R %s, want %s", got, rAt.Add(-5*time.Second))
	}
	t.Run("control: the check at the tick only", func(t *testing.T) {
		withSeam(t, &stepTickOnly)
		r, rAt := run(t)
		if _, got := r.l.watchNow(); !got.Equal(rAt) {
			t.Fatalf("R %s under the control, want %s", got, rAt)
		}
	})
}

// TestStepCapsWAtWallClock: a step back the check cannot measure, here
// 1,900 ms, below max_skew_ms, right after W's placement, leaves W and R
// later than the wall clock: the check takes the wall-clock time for each,
// saves it, and writes time.node-stepped for it. Before W's first
// placement since the start a check only measures (the node-start gap's
// close, 2e-3's).
func TestStepCapsWAtWallClock(t *testing.T) {
	r := newHealthRig(t)
	p := r.accepted(live02())
	r.beatAt(p, hbWith(1, at(r.now().Add(time.Second)), pk(100, "up")))
	r.beatAt(p, hbWith(2, at(r.now().Add(time.Second)), pk(200, "up")))
	r.addWall(-1900 * time.Millisecond)
	r.l.CheckStep(bg)
	wantW(t, r, r.now(), r.now(), "capped")
	if c := cursorNow(t, r.cs); !c.W.Equal(r.now()) {
		t.Fatalf("the cursor holds W %s", c.W)
	}
	if d := r.sink.of(event.HealthTimeNodeStepped); len(d) != 1 || d[0]["step_back_ms"] != "1900" {
		t.Fatalf("time.node-stepped: %v", d)
	}
}

// TestWatchBoundaries: the step check acts on a step back of more than
// max_skew_ms, not on one of exactly 2,000 ms; and a flat heartbeat
// read exactly blind_after_s after the last rise still shows capture, one
// read a nanosecond later does not.
func TestWatchBoundaries(t *testing.T) {
	r := newHealthRig(t)
	p := r.accepted(live02())
	r.beatAt(p, hbWith(1, at(r.now().Add(time.Second)), pk(100, "up")))
	r.beatAt(p, hbWith(2, at(r.now().Add(time.Second)), pk(200, "up")))
	rise := r.now()
	p.taken()
	r.pass(DefaultBlindAfter)
	p.send(hbWith(3, at(r.now()), pk(200, "up")))
	p.taken()
	wantW(t, r, r.now(), rise, "flat, read blind_after_s after the rise")
	w := r.now()
	r.pass(time.Nanosecond)
	p.send(hbWith(4, at(r.now()), pk(200, "up")))
	p.taken()
	wantW(t, r, w, rise, "flat, read past blind_after_s")
	r.pass(10 * time.Second)
	r.l.CheckStep(bg)
	r.addWall(-MaxSkew)
	r.l.CheckStep(bg)
	wantW(t, r, w, rise, "a step back of exactly max_skew_ms")
	r.addWall(-MaxSkew - time.Nanosecond)
	r.l.CheckStep(bg)
	back := MaxSkew + time.Nanosecond
	wantW(t, r, w.Add(-back), rise.Add(-back), "a step back of max_skew_ms and a nanosecond")
}

// TestStepSaveFails: a step found at a heartbeat's receipt whose cursor
// save fails closes the connection store before the heartbeat is taken,
// and the next check saves W and R as moved; time.node-stepped is written
// once.
func TestStepSaveFails(t *testing.T) {
	r := newHealthRig(t)
	p := r.accepted(live02())
	r.beatAt(p, hbWith(1, at(r.now().Add(time.Second)), pk(100, "up")))
	r.beatAt(p, hbWith(2, at(r.now().Add(time.Second)), pk(200, "up")))
	w := r.now()
	p.taken()
	r.pass(time.Second)
	r.addWall(-5 * time.Second)
	r.cs.failNext(1)
	p.send(hbWith(3, at(r.now()), pk(200, "up")))
	if got := p.closed(); got != netobs.CloseStore {
		t.Fatalf("closed %q, want store", got)
	}
	if c := cursorNow(t, r.cs); !c.W.Equal(w) || c.Taken != 2 {
		t.Fatalf("after the failed save the cursor holds W %s at T %d", c.W, c.Taken)
	}
	r.l.CheckStep(bg)
	if c := cursorNow(t, r.cs); !c.W.Equal(w.Add(-5 * time.Second)) {
		t.Fatalf("the next check saved W %s", c.W)
	}
	if n := r.sink.count(event.HealthTimeNodeStepped); n != 1 {
		t.Fatalf("time.node-stepped %d", n)
	}
}

// The fix to D1's rulings 7057035425 on #774 (D4-122): a test for each
// blocking finding, with its control, and D6's probes P3, P4 and P8 to P11
// as tests that kill the named mutants.

// placed2 is a rig with run 5 accepted as new and heartbeats 1 and 2
// placed, the second with a rise: W and R are its receipt.
func placed2(t *testing.T) (*healthRig, *peer, time.Time) {
	r := newHealthRig(t)
	p := r.accepted(live02())
	r.beatAt(p, hbWith(1, at(r.now().Add(time.Second)), pk(100, "up")))
	r.beatAt(p, hbWith(2, at(r.now().Add(time.Second)), pk(200, "up")))
	w := r.now()
	wantW(t, r, w, w, "placed")
	return r, p, w
}

// TestStepFoundOnceAcrossGoroutines (D6's B1, P1, on #774): the step
// check reads both clocks under the skew's lock. A check that has read
// the clocks is held; the wall clock steps back 5 s and a second passes; a
// second check runs; then the first; a second later a third. One step of
// 5 s is found once: W and R 5 s back and one time.node-stepped. Control:
// the clocks read before the lock, under which the first check measures
// itself against the second and the third finds the step again: W and R
// 10 s back and two events.
func TestStepFoundOnceAcrossGoroutines(t *testing.T) {
	run := func(t *testing.T) (*healthRig, time.Time) {
		r, p, w := placed2(t)
		p.end()
		r.l.CheckStep(bg)
		r.pass(time.Second)
		hold := r.clk.holdNext()
		a, b := make(chan struct{}), make(chan struct{})
		go func() { r.l.CheckStep(bg); close(a) }()
		<-hold.reached
		r.addWall(-5 * time.Second)
		r.pass(time.Second)
		go func() { r.l.CheckStep(bg); close(b) }()
		if stepClocksBeforeLock {
			<-b // the second check is not held by the first's lock
		}
		close(hold.release)
		<-a
		<-b
		r.pass(time.Second)
		r.l.CheckStep(bg)
		return r, w
	}
	r, w := run(t)
	wantW(t, r, w.Add(-5*time.Second), w.Add(-5*time.Second), "one step of 5 s")
	if d := r.sink.of(event.HealthTimeNodeStepped); len(d) != 1 || d[0]["step_back_ms"] != "5000" {
		t.Fatalf("time.node-stepped: %v", d)
	}
	t.Run("control: the clocks read before the lock", func(t *testing.T) {
		withSeam(t, &stepClocksBeforeLock)
		r, w := run(t)
		wantW(t, r, w.Add(-10*time.Second), w.Add(-10*time.Second), "the step handled twice")
		if n := r.sink.count(event.HealthTimeNodeStepped); n != 2 {
			t.Fatalf("time.node-stepped %d under the control, want 2", n)
		}
	})
}

// TestStepCheckBesidePlacement (D3's B2 on #774): the tick's check has read
// the clocks and is held; a second later a heartbeat with a rise is read.
// No clock stepped, so no time.node-stepped is written, and W and R are
// that heartbeat's receipt. Control: the clocks read before the lock,
// under which the held check finds W later than its stale wall clock and
// writes time.node-stepped of 1,000 ms.
func TestStepCheckBesidePlacement(t *testing.T) {
	run := func(t *testing.T) (*healthRig, time.Time) {
		r, p, _ := placed2(t)
		p.taken()
		r.l.CheckStep(bg)
		hold := r.clk.holdNext()
		a := make(chan struct{})
		go func() { r.l.CheckStep(bg); close(a) }()
		<-hold.reached
		r.pass(time.Second)
		recv := r.now()
		p.send(hbWith(3, at(recv), pk(300, "up")))
		if stepClocksBeforeLock {
			p.ack(3) // placed while the check is held before its lock
		}
		close(hold.release)
		<-a
		if !stepClocksBeforeLock {
			p.ack(3)
		}
		return r, recv
	}
	r, recv := run(t)
	if d := r.sink.of(event.HealthTimeNodeStepped); len(d) != 0 {
		t.Fatalf("time.node-stepped with no step: %v", d)
	}
	wantW(t, r, recv, recv, "the heartbeat's receipt")
	t.Run("control: the clocks read before the lock", func(t *testing.T) {
		withSeam(t, &stepClocksBeforeLock)
		r, _ := run(t)
		if d := r.sink.of(event.HealthTimeNodeStepped); len(d) != 1 || d[0]["step_back_ms"] != "1000" {
			t.Fatalf("time.node-stepped under the control: %v", d)
		}
	})
}

// ifs sets the coverage statement's interfaces and the heartbeat's
// together, each carrier up, and the run's totals to their sum.
func ifs(names []string, packets []uint64) func(*netobs.Heartbeat) {
	return func(h *netobs.Heartbeat) {
		h.Coverage.Interfaces, h.Interfaces = nil, nil
		var sum uint64
		for i, n := range names {
			h.Coverage.Interfaces = append(h.Coverage.Interfaces, netobs.Interface{Name: n, Attachment: "span", LAN: "single"})
			h.Interfaces = append(h.Interfaces, netobs.InterfaceCount{Name: n, Carrier: "up", Packets: packets[i]})
			sum += packets[i]
		}
		h.Counters.Packets, h.Counters.Bytes = sum, sum*90
	}
}

// TestCaptureStateByName (D3's B1 on #774): CH-31's state is kept by
// interface name, and the run's start counts only for the names of its
// first heartbeat read here. Run 5 accepted as new, every named
// interface's packets flat for 31 minutes, a heartbeat a minute: W moves
// within blind_after_s of the run's start and then stays, and R never
// moves, when the interface count alternates ({eth1}, {eth1, eth2}) and
// when, at a fixed count, the names alternate ({eth1: 100, eth2: 0},
// {eth0: 0, eth1: 100}). Control: a change of the interface set starts the
// run's began again, under which W moves through the flat stretch.
func TestCaptureStateByName(t *testing.T) {
	for _, c := range []struct {
		what string
		set  func(i int) func(*netobs.Heartbeat)
	}{
		{"the count alternating", func(i int) func(*netobs.Heartbeat) {
			if i%2 == 0 {
				return ifs([]string{"eth1"}, []uint64{100})
			}
			return ifs([]string{"eth1", "eth2"}, []uint64{100, 0})
		}},
		{"the names alternating", func(i int) func(*netobs.Heartbeat) {
			if i%2 == 0 {
				return ifs([]string{"eth1", "eth2"}, []uint64{100, 0})
			}
			return ifs([]string{"eth0", "eth1"}, []uint64{0, 100})
		}},
	} {
		run := func(t *testing.T) (r *healthRig, last, want time.Time) {
			r = newHealthRig(t)
			p := r.accepted(live02())
			r.beatAt(p, hbWith(1, at(r.now().Add(time.Second)), c.set(0)))
			began := r.now()
			want = began
			for i := 1; i <= 31; i++ {
				r.pass(59 * time.Second)
				r.beatAt(p, hbWith(1+i, at(r.now().Add(time.Second)), c.set(i)))
				if r.now().Sub(began) <= DefaultBlindAfter {
					want = r.now()
				}
			}
			if n := r.l.Stats().Heartbeats; n != 32 {
				t.Fatalf("%d heartbeats taken, want 32", n)
			}
			return r, r.now(), want
		}
		t.Run(c.what, func(t *testing.T) {
			r, _, want := run(t)
			wantW(t, r, want, time.Time{}, "flat for 31 minutes")
			t.Run("control: began again at a set change", func(t *testing.T) {
				withSeam(t, &watchSetResets)
				r, last, _ := run(t)
				if w, _ := r.l.watchNow(); !w.Equal(last) {
					t.Fatalf("W %s under the control, want it moved to %s", w, last)
				}
			})
		})
	}
}

// TestCaptureNewNameWithinRun: the two halves of the rule by name. A name
// first seen within the run gets no grace of the run's start: run 5's
// first heartbeat has eth1 alone with its carrier down, and the next, 30 s
// later, adds eth2 up and flat; W stays unplaced. A name absent from a
// heartbeat is dropped: eth2 at 50, then absent, then back at 80 shows no
// rise, so R stays unplaced (eth1 carries the run's totals with its
// carrier down, so they do not fall and raise no R). Mutants (the PR's comment): the run's start
// counted for every name, and absent names kept, each of which moves one.
func TestCaptureNewNameWithinRun(t *testing.T) {
	down := func(h *netobs.Heartbeat) { h.Interfaces[0].Carrier = "down" }
	r := newHealthRig(t)
	p := r.accepted(live02())
	r.beatAt(p, hbWith(1, at(r.now().Add(time.Second)), ifs([]string{"eth1"}, []uint64{100}), down))
	r.pass(29 * time.Second)
	r.beatAt(p, hbWith(2, at(r.now().Add(time.Second)), ifs([]string{"eth1", "eth2"}, []uint64{100, 0}), down))
	wantW(t, r, time.Time{}, time.Time{}, "a name first seen within the run, flat")
	if n := r.l.Stats().Heartbeats; n != 2 {
		t.Fatalf("%d heartbeats taken, want 2", n)
	}
	r = newHealthRig(t)
	p = r.accepted(live02())
	r.beatAt(p, hbWith(1, at(r.now().Add(time.Second)), ifs([]string{"eth1", "eth2"}, []uint64{100, 50})))
	r.beatAt(p, hbWith(2, at(r.now().Add(time.Second)), ifs([]string{"eth1"}, []uint64{150}), down))
	r.beatAt(p, hbWith(3, at(r.now().Add(time.Second)), ifs([]string{"eth1", "eth2"}, []uint64{150, 80}), down))
	if n := r.l.Stats().Heartbeats; n != 3 {
		t.Fatalf("%d heartbeats taken, want 3", n)
	}
	if _, gr := r.l.watchNow(); !gr.IsZero() {
		t.Fatalf("R %s: a name seen again read as a rise", gr)
	}
}

// TestStepMovesFileCopyWithNoW (D3's B3 on #774): with W and R placed and
// the run file's copy settled, the sensor database lost and the node
// started, the link holds no W or R; a step back of an hour found by the
// check moves the file's copy back by it, and time.node-stepped is
// written once. Control: a copy the step leaves where it was.
func TestStepMovesFileCopyWithNoW(t *testing.T) {
	run := func(t *testing.T) (*healthRig, time.Time) {
		r, p, w := placed2(t)
		r.settleFile()
		if got := runFileCopy(t, r.path); got != canonUTC(w) {
			t.Fatalf("the copy %q, want %s", got, canonUTC(w))
		}
		p.end()
		r.loseDatabase()
		r.restart()
		r.l.CheckStep(bg)
		r.pass(time.Second)
		r.addWall(-time.Hour)
		r.l.CheckStep(bg)
		return r, w
	}
	r, w := run(t)
	if gw, gr := r.l.watchNow(); !gw.IsZero() || !gr.IsZero() {
		t.Fatalf("the link holds W %s and R %s", gw, gr)
	}
	if got := runFileCopy(t, r.path); got != canonUTC(w.Add(-time.Hour)) {
		t.Fatalf("the copy %q, want %s", got, canonUTC(w.Add(-time.Hour)))
	}
	if d := r.sink.of(event.HealthTimeNodeStepped); len(d) != 1 || d[0]["step_back_ms"] != "3600000" {
		t.Fatalf("time.node-stepped: %v", d)
	}
	t.Run("control: the copy unmoved", func(t *testing.T) {
		withSeam(t, &stepCopyUnmoved)
		r, w := run(t)
		if got := runFileCopy(t, r.path); got != canonUTC(w) {
			t.Fatalf("the copy %q under the control, want %s", got, canonUTC(w))
		}
	})
}

// TestK1ResendAfterStart (D6's B2, P6b, on #774): heartbeats 1 and 2
// saved; 3 and 4 read within the cursor's spacing; the run file written,
// which saves the position as last written (T 2) with W at 4; the node
// killed before the close's save. After the start the sensor resends 3
// (300 packets) and 4: both are taken, since a heartbeat at or below W's
// is a resend. Control: the kept packets judged at any seq, which refuses
// 3 as counter-decrease.
func TestK1ResendAfterStart(t *testing.T) {
	run := func(t *testing.T) *healthRig {
		r := newHealthRig(t)
		p := r.accepted(live02())
		r.beat(p, hbWith(1, at(r.now()), pk(100, "up")))
		r.beat(p, hbWith(2, at(r.now().Add(cursorSpacing)), pk(200, "up")))
		p.taken()
		p.send(hbWith(3, at(r.now()), pk(300, "up")), hbWith(4, at(r.now()), pk(400, "up")))
		p.taken()
		r.settleFile()
		if c := cursorNow(t, r.cs); c.Taken != 2 || c.WSeq != 4 {
			t.Fatalf("the cursor holds T %d and W at seq %d, want 2 and 4", c.Taken, c.WSeq)
		}
		r.cs.failNext(1) // killed before the close's save
		p.end()
		r.restart()
		p = r.dial(enrolment())
		p.send(r.resumeAt(3, 4))
		p.ack(2)
		p.send(hbWith(3, at(r.now()), pk(300, "up")), hbWith(4, at(r.now()), pk(400, "up")))
		p.taken()
		return r
	}
	if n := refused(run(t).l, RefusedCounterDecrease); n != 0 {
		t.Fatalf("counter-decrease %d for a resend", n)
	}
	t.Run("control: the kept packets at any seq", func(t *testing.T) {
		withSeam(t, &k1KeptAnySeq)
		if n := refused(run(t).l, RefusedCounterDecrease); n != 1 {
			t.Fatalf("counter-decrease %d under the control, want 1", n)
		}
	})
}

// TestK1AtWSeqNotJudged: the boundary of TestK1ResendAfterStart's rule.
// Heartbeats 1 to 3 saved, 4 read within the cursor's spacing, the run
// file written (T 3, W at 4 with 400 packets), the node killed before the
// close's save; after the start the first heartbeat is 4 again, at 350
// packets: numbered at W's, it is not judged against the kept packets and
// is taken. Mutant (the PR's comment): the rule with < in place of <=,
// which refuses it. TestK1FallingPacketsAcrossRestart holds the other
// side: a heartbeat numbered one above W's is judged.
func TestK1AtWSeqNotJudged(t *testing.T) {
	r := newHealthRig(t)
	p := r.accepted(live02())
	r.beat(p, hbWith(1, at(r.now()), pk(100, "up")))
	for i := 2; i <= 3; i++ {
		r.beat(p, hbWith(i, at(r.now().Add(cursorSpacing)), pk(uint64(100*i), "up")))
	}
	p.taken()
	p.send(hbWith(4, at(r.now()), pk(400, "up")))
	p.taken()
	r.settleFile()
	if c := cursorNow(t, r.cs); c.Taken != 3 || c.WSeq != 4 {
		t.Fatalf("the cursor holds T %d and W at seq %d, want 3 and 4", c.Taken, c.WSeq)
	}
	r.cs.failNext(1) // killed before the close's save
	p.end()
	r.restart()
	p = r.dial(enrolment())
	p.send(r.resumeAt(4, 4))
	p.ack(3)
	p.send(hbWith(4, at(r.now()), pk(350, "up")))
	p.taken()
	if n := refused(r.l, RefusedCounterDecrease); n != 0 {
		t.Fatalf("counter-decrease %d at W's seq", n)
	}
}

// TestStepNoCapBeforePlacement (D6's P3 on #774; kills M1, the cap with
// no placement guard): W saved, the wall clock stepped back 10 minutes
// across the stop, and two checks after the start: W, R and the cursor
// are unchanged, and no time.node-stepped is written, since before W's
// first placement since the start a check only measures.
func TestStepNoCapBeforePlacement(t *testing.T) {
	r, p, w := placed2(t)
	p.end()
	r.addWall(-10 * time.Minute)
	r.restart()
	r.l.CheckStep(bg)
	r.pass(time.Second)
	r.l.CheckStep(bg)
	wantW(t, r, w, w, "after the start")
	if c := cursorNow(t, r.cs); !c.W.Equal(w) || !c.R.Equal(w) {
		t.Fatalf("the cursor holds W %s and R %s, want %s", c.W, c.R, w)
	}
	if n := r.sink.count(event.HealthTimeNodeStepped); n != 0 {
		t.Fatalf("time.node-stepped %d", n)
	}
}

// TestWPlacedWithMovedSamples (D6's P4 on #774; kills M2, W placed with
// E's samples as taken): the node's clock alone stepped back 300 s; a
// heartbeat made before the step, queued 60 s, is read after it and before
// any tick. W is its at_utc + E moved, 300 s before the moment it was
// made, not its receipt.
func TestWPlacedWithMovedSamples(t *testing.T) {
	r, p, _ := placed2(t)
	p.taken()
	made := r.now()
	r.pass(60 * time.Second)
	r.addWall(-300 * time.Second)
	p.send(hbWith(3, at(made), pk(300, "up")))
	p.ack(3)
	want := made.Add(-300 * time.Second)
	wantW(t, r, want, want, "placed with the moved samples")
}

// TestK1NewRunInProcess (D6's P8 on #774; kills M3, the kept packets
// judged without their run): run 5 with W at 300 packets, then run 6
// accepted in the same process; its heartbeats at 10 and 20 packets,
// numbered above W's, are taken.
func TestK1NewRunInProcess(t *testing.T) {
	r := newHealthRig(t)
	p := r.accepted(live02())
	for i := 1; i <= 3; i++ {
		r.beatAt(p, hbWith(i, at(r.now().Add(time.Second)), pk(uint64(100*i), "up")))
	}
	p.end()
	h6 := run6()
	h6.FirstSeq, h6.NewestSeq, h6.SensorUTC = "4", "3", canonUTC(r.now())
	p = r.accepted(h6)
	for i, n := range []uint64{10, 20} {
		h := hbWith(4+i, at(r.now().Add(time.Second)), pk(n, "up"))
		h.RunID = testRun2
		r.beatAt(p, h)
	}
	if n := refused(r.l, RefusedCounterDecrease); n != 0 {
		t.Fatalf("run 6 judged against run 5's packets: counter-decrease %d", n)
	}
}

// TestResumedRunStartNotCounted (D6's P9 on #774; kills M4, the run's start
// counted for a run not accepted as new in this process): run 5 accepted
// with no heartbeat, the node started, the run resumed and two flat
// heartbeats read: neither shows capture, so W stays unplaced.
func TestResumedRunStartNotCounted(t *testing.T) {
	r := newHealthRig(t)
	p := r.accepted(live02())
	p.end()
	r.restart()
	p = r.dial(enrolment())
	p.send(r.resumeAt(1, 0))
	p.ack(0)
	r.beatAt(p, hbWith(1, at(r.now().Add(time.Second)), pk(100, "up")))
	r.beatAt(p, hbWith(2, at(r.now().Add(time.Second)), pk(100, "up")))
	wantW(t, r, time.Time{}, time.Time{}, "a resumed run, flat")
}

// TestK1PreviousAfterStart (D6's P10 on #774; kills M5, the kept packets
// preferred to the previous heartbeat): after a start, heartbeat 3 at 500
// packets with its carrier down is taken and W stays at 2; heartbeat 4 at
// 450 falls below 3's and is refused as counter-decrease.
func TestK1PreviousAfterStart(t *testing.T) {
	r, p, _ := placed2(t)
	p.end()
	r.restart()
	p = r.dial(enrolment())
	p.send(r.resumeAt(3, 2))
	p.ack(2)
	r.beatAt(p, hbWith(3, at(r.now().Add(time.Second)), pk(500, "down")))
	if c := cursorNow(t, r.cs); c.WSeq != 2 {
		t.Fatalf("W at seq %d, want 2", c.WSeq)
	}
	r.beatAt(p, hbWith(4, at(r.now().Add(time.Second)), pk(450, "up")))
	if n := refused(r.l, RefusedCounterDecrease); n != 1 {
		t.Fatalf("counter-decrease %d, want 1", n)
	}
}

// TestFileCopyCheckFirst (D6's P11 on #774; kills M10, the run file's copy
// taken without the step check): a step back of 5 s, and the run file
// written before any other check: its copy is W moved back by the step.
func TestFileCopyCheckFirst(t *testing.T) {
	r, p, w := placed2(t)
	p.taken()
	r.l.CheckStep(bg)
	r.addWall(-5 * time.Second)
	r.settleFile()
	if got := runFileCopy(t, r.path); got != canonUTC(w.Add(-5*time.Second)) {
		t.Fatalf("the copy %q, want %s", got, canonUTC(w.Add(-5*time.Second)))
	}
}

// TestHeartbeatLateWithMovedE (D3's N1 on #774): the step check runs
// before a heartbeat's lateness is judged, and lateness reads E's samples
// moved. The node's clock alone stepped back 5 s; a heartbeat made
// late_bound_s + 3 s before its receipt, true time, is read before any
// tick: it is counted late. Mutant (the PR's comment): the check after
// the lateness, or lateness with E unmoved, which reads it 2 s inside.
func TestHeartbeatLateWithMovedE(t *testing.T) {
	r, p, _ := placed2(t)
	p.taken()
	r.pass(time.Second)
	r.addWall(-5 * time.Second)
	// The sensor's clock reads the node's + 5 s now.
	made := r.now().Add(5*time.Second - DefaultLateBound - 3*time.Second)
	p.send(hbWith(3, at(made), pk(300, "up")))
	p.ack(3)
	if n := r.l.SkewStats().Late; n != 1 {
		t.Fatalf("late %d, want 1", n)
	}
}
