package sensorlink

import (
	"context"
	"errors"
	"math"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"otsec.local/otsec/contracts/netobs"
	c5 "otsec.local/otsec/contracts/store"
)

// The skew estimate's rows (C13 0.2 section 15: T-4, T-6's node mark,
// T-10 without its alert-key leg; docs/phase4/D5-sensor-node.md section
// 1.5 and its tests), desk only: an in-memory pipe and the test clock; no
// sensor and no device.

// agreeTick and agreeHello state the rig's wall clock as the message's
// sensor_utc: a sensor clock in agreement with the node's, so the skew
// gate stands for nothing in a test about something else.
func (r *rig) agreeTick(t *netobs.Tick) *netobs.Tick {
	t.SensorUTC = canonUTC(r.now())
	return t
}

func (r *rig) agreeHello(h *netobs.SensorHello) *netobs.SensorHello {
	h.SensorUTC = canonUTC(r.now())
	return h
}

// pass moves the node's wall and monotonic clocks together by d: time
// passing, with no step of either.
func (r *rig) pass(d time.Duration) {
	r.clk.add(d)
	r.addWall(d)
}

// helloO is run 5's hello from a sensor whose clock reads o behind the
// node's (CH-22's sign: o is the node's time less the sensor's).
func (r *rig) helloO(o time.Duration) *netobs.SensorHello {
	h := live02()
	h.SensorUTC = canonUTC(r.now().Add(-o))
	return h
}

// tickO waits for every frame sent, lets TickMinSpacing and a second pass
// on both clocks, and sends a tick from a sensor whose clock reads o
// behind the node's.
func (r *rig) tickO(p *peer, o time.Duration, newest, sent int) {
	r.t.Helper()
	p.taken()
	r.pass(netobs.TickMinSpacing + time.Second)
	tk := tick02(newest, sent, 0)
	tk.SensorUTC = canonUTC(r.now().Add(-o))
	p.send(tk)
	p.taken()
}

// ownFlow02 is a record of the node's own flow from port sport to
// endpoint, captured at at on the sensor's clock: its start, or with end
// its end (fin, not syn-only).
func ownFlow02(seq, sport int, at time.Time, end bool) *netobs.Observation {
	o := nodeFlow02(seq)
	o.IP.Sport = ptr(sport)
	if end {
		o.Flow.Phase, o.Flow.End, o.Flow.SynOnly = "end", "fin", ptr(false)
	}
	o.FirstUTC = canonUTC(at)
	o.LastUTC = o.FirstUTC
	return o
}

// withSeam sets a control seam for one test.
func withSeam(t *testing.T, seam *bool) {
	*seam = true
	t.Cleanup(func() { *seam = false })
}

// windows is the refusal counts, in counting order.
func windows(s SkewStats) [5]uint64 {
	return [5]uint64{s.LatestWindows, s.AlarmWindows, s.MovedWindows, s.PrestartWindows, s.SpanWindows}
}

// holdingStore holds the read loop: the next commit armed lets d pass on
// both of the rig's clocks inside it, as a commit held by the store does
// (F4; F-016's 3 s on the hosted Windows runner).
type holdingStore struct {
	Appender
	mu  sync.Mutex
	arm func()
}

func (s *holdingStore) hold(f func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.arm = f
}

func (s *holdingStore) Append(ctx context.Context, rec c5.Record) (c5.Receipt, error) {
	s.mu.Lock()
	f := s.arm
	s.arm = nil
	s.mu.Unlock()
	if f != nil {
		f()
	}
	return s.Appender.Append(ctx, rec)
}

// TestSkewEstimateTakesLeastDelay: E is the hello's o until the first
// tick, then the least o of the connection's last 6 ticks (CH-22).
// TestSkewAlarmHysteresis's figures ride on it: sensor-clock-skew rises
// above 2,000 ms and clears at 1,500 ms or less, and rises again only on
// a new crossing.
func TestSkewEstimateTakesLeastDelay(t *testing.T) {
	r := newRig(t, nil)
	p := r.accepted(r.helloO(2500 * time.Millisecond))
	if s := r.l.SkewStats(); s.E != 2500*time.Millisecond || !s.Alarm || r.al.count(AlarmClockSkew) != 1 {
		t.Fatalf("after the hello: %+v, %d raises", s, r.al.count(AlarmClockSkew))
	}
	r.tickO(p, 1800*time.Millisecond, 20, 0) // the hello's sample leaves: E 1.8 s, the alarm stands
	if s := r.l.SkewStats(); s.E != 1800*time.Millisecond || !s.Alarm {
		t.Fatalf("at 1.8 s: %+v", s)
	}
	r.tickO(p, 1500*time.Millisecond, 20, 0) // E 1.5 s: cleared
	if s := r.l.SkewStats(); s.E != 1500*time.Millisecond || s.Alarm {
		t.Fatalf("at 1.5 s: %+v", s)
	}
	for range 5 {
		r.tickO(p, 2100*time.Millisecond, 20, 0) // the 1.5 s sample is still among the last six
	}
	if s := r.l.SkewStats(); s.E != 1500*time.Millisecond || s.Alarm || r.al.count(AlarmClockSkew) != 1 {
		t.Fatalf("with 1.5 s among six: %+v", s)
	}
	r.tickO(p, 2100*time.Millisecond, 20, 0) // six of 2.1 s: raised again
	if s := r.l.SkewStats(); s.E != 2100*time.Millisecond || !s.Alarm || r.al.count(AlarmClockSkew) != 2 {
		t.Fatalf("six of 2.1 s: %+v, %d raises", s, r.al.count(AlarmClockSkew))
	}
	for _, o := range []time.Duration{4 * time.Second, 300 * time.Millisecond, 3 * time.Second} {
		r.tickO(p, o, 20, 0)
	}
	// Raised once for each crossing (X8 of D6's B3 on #748): the 4 s tick
	// came while the alarm stood.
	if s := r.l.SkewStats(); s.E != 300*time.Millisecond || s.Latest != 3*time.Second || r.al.count(AlarmClockSkew) != 2 {
		t.Fatalf("the least delay: %+v, %d raises", s, r.al.count(AlarmClockSkew))
	}
}

// E is the connection's (X7 and X16 of D6's B3 on #748): the first tick
// replaces the hello's o, and a hello starts the samples afresh, whatever
// the previous connection took. Controls (mutants X7, X16): a first tick
// that adds to the hello's o, and a hello that adds to the last
// connection's samples, each of which keeps E at 0.
func TestSkewSamplesPerConnection(t *testing.T) {
	r := newRig(t, nil)
	p := r.accepted(r.agreeHello(live02()))
	r.tickO(p, 2500*time.Millisecond, 20, 0)
	if s := r.l.SkewStats(); s.E != 2500*time.Millisecond || !s.Alarm {
		t.Fatalf("after the first tick: %+v", s)
	}
	r.tickO(p, 0, 20, 0)
	p.end()
	h := resume(1, 20)
	h.SensorUTC = canonUTC(r.now().Add(-2500 * time.Millisecond))
	r.accepted(h)
	if s := r.l.SkewStats(); s.E != 2500*time.Millisecond {
		t.Fatalf("after the next connection's hello: %+v", s)
	}
}

// F3 (b) of D4's review of #748: a heartbeat is never a skew sample
// (CH-22): one whose at_utc is an hour off leaves E, the latest sample,
// the alarm and K as they were. Control (mutant H1): a node that samples
// heartbeats, which raises the alarm.
func TestSkewIgnoresHeartbeat(t *testing.T) {
	r := newRig(t, nil)
	p := r.accepted(r.agreeHello(live02()))
	r.tickO(p, 0, 20, 0)
	k := func() [2]time.Time {
		r.l.skew.mu.Lock()
		defer r.l.skew.mu.Unlock()
		return [2]time.Time{r.l.skew.base, r.l.skew.maxK}
	}
	before, kBefore := r.l.SkewStats(), k()
	hb := heartbeat02(1, 10)
	hb.AtUTC = canonUTC(r.now().Add(time.Hour))
	p.send(hb)
	p.taken()
	after := r.l.SkewStats()
	if after.E != before.E || after.Latest != before.Latest || after.Alarm || k() != kBefore {
		t.Fatalf("a heartbeat moved the estimate: %+v to %+v, K %v to %v", before, after, kBefore, k())
	}
}

// X1 of D6's B3 on #748, and section 1.5's TestSkewTiesNothing: while a
// cause stands at Dispatch, here the alarm alone (the latest sample
// inside), nothing is held, and the run's own flow, which comes after the
// alarm clears, is committed untied; the Result reports the window refused
// and the run is counted once, under skew_alarm_windows. Control (mutant
// X1): a Dispatch that holds while a cause stands, which ties the flow.
func TestSkewTiesNothing(t *testing.T) {
	r, _ := holdRig02(t)
	p := r.accepted(r.helloO(2500 * time.Millisecond))
	r.tickO(p, 1800*time.Millisecond, 20, 0)
	if c := r.l.standing(); c != skewAlarm {
		t.Fatalf("standing %q, want the alarm alone", c)
	}
	if err := r.l.Dispatch(bg, HoldRun{RequestID: "req-1", AssetID: relay, Endpoint: endpoint, L4: "tcp"}); err != nil {
		t.Fatal(err)
	}
	r.tickO(p, 1400*time.Millisecond, 20, 0) // E 1.4 s: the alarm clears
	if c := r.l.standing(); c != "" {
		t.Fatalf("standing %q, want none", c)
	}
	start := r.now()
	p.send(ownFlow02(1, 40001, start.Add(time.Second), false))
	p.taken()
	r.pass(30 * time.Second)
	s := session09(inv1, 40001, 0)
	s.StartedAt, s.ConnectedAt, s.EndedAt = start, start, start.Add(20*time.Second)
	rel, err := r.l.Result(bg, "req-1", s)
	if err != nil {
		t.Fatal(err)
	}
	got := storedObs(t, r.s)
	if len(got) != 1 || got[0].Node.PlatformSession != nil || !rel.Skewed {
		t.Fatalf("stored %d, the first %+v; released %+v", len(got), got[0].Node, rel)
	}
	if w := windows(r.l.SkewStats()); w != [5]uint64{0, 1, 0, 0, 0} {
		t.Fatalf("window counts %v, want one skew_alarm_windows", w)
	}
}

// T-6, the node's mark (D4's A4): each observation committed while
// sensor-clock-skew stands carries node.skewed. The sensor's clock 2.5 s
// ahead at the hello, then 1.8 s ahead: the latest sample is inside
// max_skew_ms and the alarm stands on E, so the alarm alone marks.
// Control: no mark while the alarm stands.
func TestSkewAlarmMarksObservations(t *testing.T) {
	run := func(t *testing.T) []*netobs.Observation {
		r := newRig(t, nil)
		p := r.accepted(r.helloO(-2500 * time.Millisecond))
		r.tickO(p, -1800*time.Millisecond, 20, 0)
		if s := r.l.SkewStats(); !s.Alarm || absDur(s.Latest) > MaxSkew {
			t.Fatalf("the alarm alone should stand: %+v", s)
		}
		p.send(obs02(1), obs02(2))
		p.ack(2)
		return storedObs(t, r.s)
	}
	got := run(t)
	if len(got) != 2 || !got[0].Node.Skewed || !got[1].Node.Skewed {
		t.Fatalf("stored unmarked while the alarm stands: %+v", got)
	}
	t.Run("control: no mark while the alarm stands", func(t *testing.T) {
		withSeam(t, &skewNoMarkAlarm)
		if got := run(t); got[0].Node.Skewed {
			t.Fatal("the control marked")
		}
	})
}

// T-10, without its alert-key leg (D4's B3 on #633; D5-p44int-split.md
// section 2.3): a latest sample above 2,000 ms with E below, from a
// stepped clock and from a read loop held 3 s by a commit seam: no tie is
// made, the observations committed then carry node.skewed (the run's own
// flow among them, untied, and its Result reports the window refused),
// sensor-clock-skew is not raised, and status counts skew_latest_windows,
// and skew_samples_after_hold for the held read, no other window count
// moving. Control: marking only while the alarm stands, under which the
// flows commit unmarked.
func TestSkewLatestSampleMarks(t *testing.T) {
	type outcome struct {
		stored []*netobs.Observation
		rel    Released
		st     SkewStats
		raised int
	}
	run := func(t *testing.T, held bool) outcome {
		hs := &holdingStore{}
		r, _ := holdRig02With(t, func(o *Options) {
			hs.Appender = o.Store
			o.Store = hs
		})
		p := r.accepted(r.agreeHello(live02()))
		r.tickO(p, 0, 20, 0)
		r.tickO(p, 0, 20, 0)
		if held {
			// The tick is made when it is sent; the commit before it holds
			// the read loop 3 s, so the tick is read 3 s late.
			p.taken()
			r.pass(netobs.TickMinSpacing + time.Second)
			hs.hold(func() { r.pass(3 * time.Second) })
			tk := r.agreeTick(tick02(20, 1, 0))
			p.send(obs02(1), tk)
			p.taken()
		} else {
			r.tickO(p, 3*time.Second, 20, 0) // the sensor's clock stepped back 3 s
		}
		if s := r.l.SkewStats(); s.Latest != 3*time.Second || absDur(s.E) > MaxSkew {
			t.Fatalf("want the latest sample alone outside: %+v", s)
		}
		if err := r.l.Dispatch(bg, HoldRun{RequestID: "req-1", AssetID: relay, Endpoint: endpoint, L4: "tcp"}); err != nil {
			t.Fatal(err)
		}
		n := 2
		if !held {
			n = 1
		}
		p.send(nodeFlow02(n), obs02(n+1))
		p.ack(uint64(n + 1))
		rel, err := r.l.Result(bg, "req-1", session09("0e4d8a2c-6b1f-4c3e-9a5d-7f2b1c0d9e8f", 40000+n, 0))
		if err != nil {
			t.Fatal(err)
		}
		return outcome{stored: storedObs(t, r.s), rel: rel, st: r.l.SkewStats(), raised: r.al.count(AlarmClockSkew)}
	}
	for _, held := range []bool{false, true} {
		name := map[bool]string{false: "a stepped clock", true: "a read loop held 3 s"}[held]
		t.Run(name, func(t *testing.T) {
			o := run(t, held)
			own := o.stored[len(o.stored)-2]
			for _, s := range o.stored[len(o.stored)-2:] {
				if !s.Node.Skewed {
					t.Fatalf("an observation committed unmarked: %+v", s.Node)
				}
			}
			if own.Node.PlatformSession != nil || !o.rel.Skewed {
				t.Fatalf("the own flow tied (%+v) or the window not refused (%+v)", own.Node.PlatformSession, o.rel)
			}
			if o.raised != 0 {
				t.Fatalf("%s raised %d times", AlarmClockSkew, o.raised)
			}
			if w := windows(o.st); w != [5]uint64{1, 0, 0, 0, 0} {
				t.Fatalf("window counts %v, want skew_latest_windows alone", w)
			}
			if want := map[bool]uint64{false: 0, true: 1}[held]; o.st.SamplesAfterHold != want {
				t.Fatalf("skew_samples_after_hold %d, want %d", o.st.SamplesAfterHold, want)
			}
		})
		t.Run(name+", control: marking only while the alarm stands", func(t *testing.T) {
			withSeam(t, &skewMarkAlarmOnly)
			o := run(t, held)
			if o.stored[len(o.stored)-2].Node.Skewed {
				t.Fatal("the control marked")
			}
		})
	}
}

// T-4 (CH-23): lateness uses E. With the sensor 10 minutes ahead, a
// record made 5 minutes before its receipt is late; with the sensor 10
// minutes behind, a record made at its receipt is not; sensor-records-late
// is raised once for the connection, and no record is refused or dropped.
// Control: lateness without E, which gets both wrong.
func TestLateUsesE(t *testing.T) {
	run := func(t *testing.T, o time.Duration, made time.Duration) (late []bool, raised int, st Stats) {
		r := newRig(t, nil)
		p := r.accepted(r.helloO(o))
		for i := 1; i <= 2; i++ {
			ob := obs02(i)
			ob.MadeUTC = canonUTC(r.now().Add(-o - made)) // on the sensor's clock
			p.send(ob)
		}
		p.ack(2)
		for _, s := range storedObs(t, r.s) {
			late = append(late, s.Node.Late)
		}
		return late, r.al.count(AlarmRecordsLate), r.l.Stats()
	}
	check := func(t *testing.T, ctl bool) {
		ahead, raised, st := run(t, -10*time.Minute, 5*time.Minute)
		behind, raisedB, stB := run(t, 10*time.Minute, 0)
		if len(ahead) != 2 || len(behind) != 2 || len(st.Refused)+len(st.Dropped)+len(stB.Refused)+len(stB.Dropped) != 0 {
			t.Fatalf("stored %d and %d; refused or dropped %v %v %v %v", len(ahead), len(behind), st.Refused, st.Dropped, stB.Refused, stB.Dropped)
		}
		ok := ahead[0] && ahead[1] && !behind[0] && !behind[1] && raised == 1 && raisedB == 0
		if ok == ctl {
			t.Fatalf("late %v and %v, raised %d and %d (control %v)", ahead, behind, raised, raisedB, ctl)
		}
	}
	check(t, false)
	t.Run("control: lateness without E", func(t *testing.T) {
		withSeam(t, &lateWithoutE)
		check(t, true)
	})
}

// D5-sensor-node.md section 1.5's TestSkewCorrectionAddsE: a sensor 1.5 s
// behind, a tie grace narrowed to 1 s: a flow the sensor stamps 1.5 s
// before the session's start, at the start on the node's clock, ties.
// Control: t_sensor - E, which pushes it 3 s out of the window.
func TestSkewCorrectionAddsE(t *testing.T) {
	run := func(t *testing.T) *netobs.PlatformSession {
		r, _ := holdRig02With(t, func(o *Options) { o.Hold.TieGrace = time.Second })
		p := r.accepted(r.helloO(1500 * time.Millisecond))
		if err := r.l.Dispatch(bg, HoldRun{RequestID: "req-1", AssetID: relay, Endpoint: endpoint, L4: "tcp"}); err != nil {
			t.Fatal(err)
		}
		start := r.now().Add(time.Second)
		f := nodeFlow02(1)
		f.FirstUTC = canonUTC(start.Add(-1500 * time.Millisecond))
		f.LastUTC = f.FirstUTC
		p.send(f)
		p.taken()
		r.pass(30 * time.Second)
		s := session09("0e4d8a2c-6b1f-4c3e-9a5d-7f2b1c0d9e8f", 40001, 0)
		s.StartedAt, s.ConnectedAt, s.EndedAt = start, start, start.Add(20*time.Second)
		if _, err := r.l.Result(bg, "req-1", s); err != nil {
			t.Fatal(err)
		}
		return storedObs(t, r.s)[0].Node.PlatformSession
	}
	if run(t) == nil {
		t.Fatal("the flow at the session's start did not tie")
	}
	t.Run("control: t_sensor - E", func(t *testing.T) {
		withSeam(t, &skewSubtractE)
		if run(t) != nil {
			t.Fatal("the control tied")
		}
	})
}

// D5-sensor-node.md section 1.5's TestSkewStepBackTiesNothing: the
// sensor's clock stepped back 5 s after five ticks in agreement: from the
// first tick outside the bound no tie is made, though E, the least of six,
// keeps the alarm down; a flow captured past the capture floor the move
// raised is refused by the latest sample alone. Control: ties gated on E
// alone, which ties.
func TestSkewStepBackTiesNothing(t *testing.T) {
	run := func(t *testing.T) (*netobs.PlatformSession, SkewStats) {
		r, _ := holdRig02(t)
		p := r.accepted(r.agreeHello(live02()))
		for range 5 {
			r.tickO(p, 0, 20, 0)
		}
		r.tickO(p, 5*time.Second, 20, 0)
		// The move raised the capture floor to 2 s past the stepped tick's
		// time on the old clock; the session is 8 s later, so its flow,
		// captured on the new clock, is past the floor and only the latest
		// sample refuses it.
		r.pass(8 * time.Second)
		if err := r.l.Dispatch(bg, HoldRun{RequestID: "req-1", AssetID: relay, Endpoint: endpoint, L4: "tcp"}); err != nil {
			t.Fatal(err)
		}
		start := r.now()
		f := nodeFlow02(1)
		f.FirstUTC = canonUTC(start.Add(-5 * time.Second).Add(500 * time.Millisecond)) // on the stepped clock
		f.LastUTC = f.FirstUTC
		p.send(f)
		p.taken()
		r.pass(30 * time.Second)
		s := session09("0e4d8a2c-6b1f-4c3e-9a5d-7f2b1c0d9e8f", 40001, 0)
		s.StartedAt, s.ConnectedAt, s.EndedAt = start, start, start.Add(20*time.Second)
		if _, err := r.l.Result(bg, "req-1", s); err != nil {
			t.Fatal(err)
		}
		return storedObs(t, r.s)[0].Node.PlatformSession, r.l.SkewStats()
	}
	tie, st := run(t)
	if tie != nil || st.Alarm || st.LatestWindows != 1 {
		t.Fatalf("tie %+v, stats %+v", tie, st)
	}
	t.Run("control: ties gated on E alone", func(t *testing.T) {
		withSeam(t, &skewGateEOnly)
		if tie, _ := run(t); tie == nil {
			t.Fatal("the control made no tie")
		}
	})
}

// The capture floor (section 1.5): a K that moves by more than
// max_skew_ms raises it, counted by what raised it, and it never falls; a
// stated span raises it to its upper end plus HeartbeatGapMax plus
// max_skew_ms; each raise is saved at once in the cursor's M; after a
// node start the floor is the M saved, the start bound is M plus
// HeartbeatGapMax plus max_skew_ms, and a heartbeat of the first break
// raises it until the first current hello's newest_seq is read.
func TestCaptureFloorAcrossStart(t *testing.T) {
	r := newRig(t, nil)
	p := r.accepted(r.agreeHello(live02()))
	before := r.now()
	r.tickO(p, 300*time.Second, 20, 0) // the sensor's clock alone stepped back 300 s
	st := r.l.SkewStats()
	want := before.Add(netobs.TickMinSpacing + time.Second + MaxSkew) // the highest K before the move, placed now, plus max_skew_ms
	if !st.Floor.Equal(want) || st.FloorBy != skewMoved {
		t.Fatalf("floor %s by %q, want %s by moved", st.Floor, st.FloorBy, want)
	}
	if c := cursorNow(t, r.cs); c.M.Before(st.Floor) {
		t.Fatalf("M %s saved below the floor %s", c.M, st.Floor)
	}
	r.tickO(p, 0, 20, 0) // the clock put right: the floor does not fall
	if got := r.l.SkewStats().Floor; !got.Equal(want) {
		t.Fatalf("the floor fell to %s", got)
	}
	// A span stated to an hour ahead raises it, saved at once.
	p.taken()
	r.pass(netobs.TickMinSpacing + time.Second)
	tk := r.agreeTick(tick02(20, 0, 1))
	span := netobs.Span{FromUTC: canonUTC(r.now().Add(-time.Minute)), ToUTC: canonUTC(r.now().Add(time.Hour))}
	tk.Lost = []netobs.Span{span}
	p.send(tk)
	p.taken()
	spanFloor := parseUTC(span.ToUTC).Add(HeartbeatGapMax + MaxSkew)
	if st := r.l.SkewStats(); !st.Floor.Equal(spanFloor) || st.FloorBy != skewSpan {
		t.Fatalf("after the span: %s by %q", st.Floor, st.FloorBy)
	}
	m := cursorNow(t, r.cs).M
	if m.Before(spanFloor) {
		t.Fatalf("M %s, below the span's floor %s", m, spanFloor)
	}
	p.end()
	// The node restarted: the floor is the M saved, and the start bound.
	r.restart()
	h := r.agreeHello(resume(1, 30))
	h.Current, h.DropsChannel, h.Lost = ptr(true), "1", []netobs.Span{span}
	p = r.accepted(h)
	st = r.l.SkewStats()
	if !st.Floor.Equal(m) || st.FloorBy != skewPrestart || !st.StartBound.Equal(m.Add(HeartbeatGapMax+MaxSkew)) {
		t.Fatalf("after the start: floor %s by %q, bound %s; M was %s", st.Floor, st.FloorBy, st.StartBound, m)
	}
	// A heartbeat of the first break, stated past the floor, raises it
	// (prestart); once the hello's newest_seq is read, none does.
	hb := heartbeat02(29, 10)
	far := m.Add(time.Hour)
	hb.AtUTC = canonUTC(far)
	p.send(hb)
	p.taken()
	if st := r.l.SkewStats(); !st.Floor.Equal(far.Add(HeartbeatGapMax+MaxSkew)) || st.FloorBy != skewPrestart {
		t.Fatalf("the first break's heartbeat: %s by %q", st.Floor, st.FloorBy)
	}
	hb = heartbeat02(30, 11)
	hb.AtUTC = canonUTC(far)
	p.send(hb)
	hb = heartbeat02(31, 12)
	hb.AtUTC = canonUTC(far.Add(time.Hour))
	p.send(hb)
	p.taken()
	if st := r.l.SkewStats(); !st.Floor.Equal(far.Add(HeartbeatGapMax + MaxSkew)) {
		t.Fatalf("a heartbeat after the first break raised the floor to %s", st.Floor)
	}
}

// The race between observe's mark and the hold (forced by a seam): the
// node's wall clock stepped 3 s after observe read no cause and before the
// hold takes the record, which the run's endpoint would hold. The closure
// then refuses: the record commits untied, marked, and counted once under
// skew_moved_windows. Control: a hold that commits it without the mark.
func TestSkewCauseAfterMarkStillMarks(t *testing.T) {
	run := func(t *testing.T) (*netobs.Observation, SkewStats) {
		r, _ := holdRig02(t)
		p := r.accepted(r.agreeHello(live02()))
		if err := r.l.Dispatch(bg, HoldRun{RequestID: "req-1", AssetID: relay, Endpoint: endpoint, L4: "tcp"}); err != nil {
			t.Fatal(err)
		}
		afterMarkSeam = func() { r.addWall(3 * time.Second) }
		t.Cleanup(func() { afterMarkSeam = nil })
		p.send(nodeFlow02(1))
		p.ack(1)
		return storedObs(t, r.s)[0], r.l.SkewStats()
	}
	o, st := run(t)
	if !o.Node.Skewed || o.Node.PlatformSession != nil || windows(st) != [5]uint64{0, 0, 1, 0, 0} {
		t.Fatalf("stored %+v; window counts %v", o.Node, windows(st))
	}
	t.Run("control: committed without the mark", func(t *testing.T) {
		withSeam(t, &skewTakeHeldUnmarked)
		if o, _ := run(t); o.Node.Skewed {
			t.Fatal("the control marked")
		}
	})
}

// The bounds, each at its value and one nanosecond past it (self-check
// item 2): the alarm rises above max_skew_ms, not at it; the latest
// sample refuses above it; the closure refuses a move above it; a record
// is late above late_bound_s; a read-loop step above AckMaxDelay marks the
// next sample held; the capture floor and the start bound refuse a
// capture at or before them, not after.
func TestSkewBounds(t *testing.T) {
	ns := time.Nanosecond
	for _, c := range []struct {
		o     time.Duration
		alarm bool
	}{{MaxSkew, false}, {MaxSkew + ns, true}, {-MaxSkew, false}, {-MaxSkew - ns, true}} {
		r := newRig(t, nil)
		r.accepted(r.helloO(c.o))
		st := r.l.SkewStats()
		if st.Alarm != c.alarm || (r.l.standing() == skewLatest) != c.alarm {
			t.Errorf("o %s: alarm %v, standing %q", c.o, st.Alarm, r.l.standing())
		}
	}
	for _, c := range []struct {
		step  time.Duration
		moved bool
	}{{MaxSkew, false}, {MaxSkew + ns, true}, {-MaxSkew, false}, {-MaxSkew - ns, true}} {
		r := newRig(t, nil)
		r.accepted(r.agreeHello(live02()))
		r.addWall(c.step)
		if got := r.l.standing() == skewMoved; got != c.moved {
			t.Errorf("a step of %s: moved %v", c.step, got)
		}
	}
	for _, c := range []struct {
		lateness time.Duration
		late     bool
	}{{DefaultLateBound, false}, {DefaultLateBound + ns, true}} {
		r := newRig(t, nil)
		p := r.accepted(r.agreeHello(live02()))
		o := obs02(1)
		o.MadeUTC = canonUTC(r.now().Add(-c.lateness))
		p.send(o)
		p.ack(1)
		if got := storedObs(t, r.s)[0].Node.Late; got != c.late {
			t.Errorf("lateness %s: late %v", c.lateness, got)
		}
	}
	for _, c := range []struct {
		step time.Duration
		held uint64
	}{{AckMaxDelay, 0}, {AckMaxDelay + ns, 1}} {
		hs := &holdingStore{}
		r := newRig(t, func(o *Options) { hs.Appender = o.Store; o.Store = hs })
		p := r.accepted(r.agreeHello(live02()))
		r.tickO(p, 0, 20, 0)
		r.pass(netobs.TickMinSpacing + time.Second)
		hs.hold(func() { r.clk.add(c.step) }) // the monotonic clock alone: the sample's o is unchanged
		p.send(obs02(1), r.agreeTick(tick02(20, 1, 0)))
		p.taken()
		if got := r.l.SkewStats().SamplesAfterHold; got != c.held {
			t.Errorf("a step of %s: %d samples after a hold", c.step, got)
		}
	}
	// A sensor clock 300 years ahead, past what a Duration holds (D3's B1
	// on #748): the alarm, the latest sample and K's move. Control: an
	// absDur that wraps, which sees none of them.
	far := func(t *testing.T) (SkewStats, string) {
		r := newRig(t, nil)
		p := r.accepted(r.agreeHello(live02()))
		p.taken()
		r.pass(netobs.TickMinSpacing + time.Second)
		tk := tick02(20, 0, 0)
		tk.SensorUTC = canonUTC(r.now().AddDate(300, 0, 0))
		p.send(tk)
		p.taken()
		return r.l.SkewStats(), r.l.standing()
	}
	if st, c := far(t); !st.Alarm || c != skewLatest || st.FloorBy != skewMoved {
		t.Errorf("300 years ahead: alarm %v, standing %q, floor by %q", st.Alarm, c, st.FloorBy)
	}
	// The time Go reads as zero, 0001-01-01T00:00:00Z, is sampled too
	// (D3's B2 on #748). Control (mutant Z1): no sample at a zero time.
	{
		r := newRig(t, nil)
		p := r.accepted(r.agreeHello(live02()))
		p.taken()
		r.pass(netobs.TickMinSpacing + time.Second)
		tk := tick02(20, 0, 0)
		tk.SensorUTC = "0001-01-01T00:00:00Z"
		p.send(tk)
		p.taken()
		if st := r.l.SkewStats(); !st.Alarm || r.l.standing() != skewLatest {
			t.Errorf("a tick at year 1: alarm %v, standing %q", st.Alarm, r.l.standing())
		}
	}
	t.Run("control: an absDur that wraps", func(t *testing.T) {
		withSeam(t, &absDurWraps)
		if st, c := far(t); st.Alarm || c != "" {
			t.Fatalf("the control saw it: alarm %v, standing %q", st.Alarm, c)
		}
	})
	r := newRig(t, nil)
	f := t0.Add(time.Hour)
	r.l.skew.floor, r.l.skew.floorBy, r.l.skew.startBound = f, skewSpan, f.Add(-time.Minute)
	for _, c := range []struct {
		capt time.Time
		want string
	}{{f, skewSpan}, {f.Add(ns), ""}, {f.Add(-time.Minute), skewPrestart}, {f.Add(-time.Minute + ns), skewSpan}} {
		if got := r.l.floorRefusal(c.capt); got != c.want {
			t.Errorf("a capture at %s: %q, want %q", c.capt, got, c.want)
		}
	}
}

// The capture floor at a run's Result (section 1.5): a run's own flow
// held, then a tick stating a lost span whose upper end plus
// HeartbeatGapMax plus max_skew_ms is past the flow's capture, paid for by
// a rise of drops_channel, with no clock moved: the flow is refused by the
// floor alone, committed untied with node.skewed, counted once under
// skew_span_windows. The floor refuses the flow, not the run's window, so
// the Result does not report the window refused (section 1.5: "a run whose
// window is refused is marked skewed"). Control: a gate with no capture
// floor, which ties it.
func TestCaptureFloorRefusesHeldFlow(t *testing.T) {
	run := func(t *testing.T) (*netobs.Observation, Released, SkewStats) {
		r, _ := holdRig02(t)
		p := r.accepted(r.agreeHello(live02()))
		if err := r.l.Dispatch(bg, HoldRun{RequestID: "req-1", AssetID: relay, Endpoint: endpoint, L4: "tcp"}); err != nil {
			t.Fatal(err)
		}
		start := r.now()
		f := nodeFlow02(1)
		f.FirstUTC = canonUTC(start.Add(time.Second))
		f.LastUTC = f.FirstUTC
		p.send(f)
		p.taken()
		r.pass(netobs.TickMinSpacing + time.Second)
		tk := r.agreeTick(tick02(20, 1, 1))
		tk.Lost = []netobs.Span{{FromUTC: canonUTC(start.Add(-time.Minute)), ToUTC: canonUTC(start.Add(-25 * time.Second))}}
		p.send(tk)
		p.taken()
		r.pass(30 * time.Second)
		s := session09("0e4d8a2c-6b1f-4c3e-9a5d-7f2b1c0d9e8f", 40001, 0)
		s.StartedAt, s.ConnectedAt, s.EndedAt = start, start, start.Add(20*time.Second)
		rel, err := r.l.Result(bg, "req-1", s)
		if err != nil {
			t.Fatal(err)
		}
		return storedObs(t, r.s)[0], rel, r.l.SkewStats()
	}
	o, rel, st := run(t)
	if o.Node.PlatformSession != nil || !o.Node.Skewed || rel.Skewed || windows(st) != [5]uint64{0, 0, 0, 0, 1} {
		t.Fatalf("stored %+v, released %+v, window counts %v, floor %s by %q", o.Node, rel, windows(st), st.Floor, st.FloorBy)
	}
	t.Run("control: no capture floor", func(t *testing.T) {
		withSeam(t, &skewNoFloor)
		if o, _, _ := run(t); o.Node.PlatformSession == nil {
			t.Fatal("the control made no tie")
		}
	})
}

// A hello's stated spans raise the floor, prior.lost included (X11 and
// X12 of D6's B3 on #748; section 1.5): each to its upper end plus
// HeartbeatGapMax plus max_skew_ms, by span. Controls (mutants X11, X12):
// a hello whose prior.lost, or whose lost, raises nothing.
func TestCaptureFloorFromHello(t *testing.T) {
	for _, prior := range []bool{false, true} {
		name := map[bool]string{false: "lost", true: "prior.lost"}[prior]
		t.Run(name, func(t *testing.T) {
			r := newRig(t, nil)
			h := r.agreeHello(live02())
			sp := lspan("09:30:00", "09:31:00")
			if prior {
				h.Prior.RecordsLost, h.Prior.Lost = "3", []netobs.Span{sp}
			} else {
				h.DropsChannel, h.Lost = "1", []netobs.Span{sp}
			}
			r.accepted(h)
			want := parseUTC(sp.ToUTC).Add(HeartbeatGapMax + MaxSkew)
			if st := r.l.SkewStats(); !st.Floor.Equal(want) || st.FloorBy != skewSpan {
				t.Fatalf("floor %s by %q, want %s by span", st.Floor, st.FloorBy, want)
			}
		})
	}
}

// A raise of the floor is saved at once (X14 and X15 of D6's B3 on #748;
// section 1.5), by a heartbeat of the first break and by a tick, each read
// inside cursorSpacing of the cursor's last save, so no flush after the
// frame saves it: M carries the new floor before any other write.
// Controls (mutants X14, X15): a raise not saved at once.
func TestCaptureFloorSavedAtOnce(t *testing.T) {
	t.Run("a heartbeat of the first break", func(t *testing.T) {
		r := newRig(t, nil)
		p := r.accepted(r.agreeHello(hello02()))
		hb := heartbeat02(1, 10)
		hb.AtUTC = canonUTC(r.now().Add(time.Hour))
		hb2 := heartbeat02(2, 20)
		hb2.AtUTC = canonUTC(r.now().Add(2 * time.Hour))
		p.send(hb, hb2)
		p.taken()
		st := r.l.SkewStats()
		if want := parseUTC(hb2.AtUTC).Add(HeartbeatGapMax + MaxSkew); !st.Floor.Equal(want) {
			t.Fatalf("floor %s, want %s", st.Floor, want)
		}
		if m := cursorNow(t, r.cs).M; m.Before(st.Floor) {
			t.Fatalf("M %s saved below the floor %s", m, st.Floor)
		}
	})
	t.Run("a tick", func(t *testing.T) {
		r := newRig(t, nil)
		p := r.accepted(r.agreeHello(live02()))
		// The first tick after the hello, read with no time passed since
		// the hello's save: the sensor's clock alone stepped back.
		tk := tick02(20, 0, 0)
		tk.SensorUTC = canonUTC(r.now().Add(-300 * time.Second))
		p.send(tk)
		p.taken()
		st := r.l.SkewStats()
		if st.FloorBy != skewMoved {
			t.Fatalf("floor %s by %q, want moved", st.Floor, st.FloorBy)
		}
		if m := cursorNow(t, r.cs).M; m.Before(st.Floor) {
			t.Fatalf("M %s saved below the floor %s", m, st.Floor)
		}
	})
}

// sensor-records-late is raised once for each connection, and a late
// heartbeat is counted (X17 and X18 of D6's B3 on #748; CH-23): a late
// observation and a late heartbeat on one connection, then a late
// observation on the next. Controls (mutants X17, X18): raised once for
// the process, and a heartbeat not judged.
func TestLateRaisedPerConnection(t *testing.T) {
	r := newRig(t, nil)
	p := r.accepted(r.agreeHello(live02()))
	old := canonUTC(r.now().Add(-10 * time.Minute))
	o := obs02(1)
	o.MadeUTC = old
	hb := heartbeat02(2, 10)
	hb.AtUTC = old
	p.send(o, hb)
	p.taken()
	if st := r.l.SkewStats(); st.Late != 2 || r.al.count(AlarmRecordsLate) != 1 {
		t.Fatalf("the first connection: %d late, %d raises", st.Late, r.al.count(AlarmRecordsLate))
	}
	p.end()
	p = r.accepted(r.agreeHello(resume(3, 20)))
	o = obs02(3)
	o.MadeUTC = canonUTC(r.now().Add(-10 * time.Minute))
	p.send(o)
	p.taken()
	if st := r.l.SkewStats(); st.Late != 3 || r.al.count(AlarmRecordsLate) != 2 {
		t.Fatalf("the second connection: %d late, %d raises", st.Late, r.al.count(AlarmRecordsLate))
	}
}

// Part (b)'s window at a later record's read uses t_sensor + E (X13 of
// D6's B3 on #748): a sensor 1.5 s behind, a tie grace of 1 s; a dial of a
// 0.8 run that connected with no local address waits, and its end, read
// after the Result, takes the window tie, its start stamped 1.5 s before
// the session's start. Control (mutant X13): f.Start without E, 1.5 s
// before the session and outside the 1 s grace, which ties nothing.
func TestSkewLaterWindowAddsE(t *testing.T) {
	r, _ := holdRig02With(t, func(o *Options) { o.Hold.TieGrace = time.Second })
	p := r.accepted(r.helloO(1500 * time.Millisecond))
	if err := r.l.Dispatch(bg, HoldRun{RequestID: "req-1", AssetID: relay, Endpoint: endpoint, L4: "tcp"}); err != nil {
		t.Fatal(err)
	}
	start := r.now().Add(time.Second)
	p.send(ownFlow02(1, 40001, start.Add(-1500*time.Millisecond), false))
	p.taken()
	r.pass(5 * time.Second)
	s := Session{InvocationID: inv1, StartedAt: start, ConnectedAt: start, EndedAt: start.Add(2 * time.Second), Connected: true}
	if _, err := r.l.Result(bg, "req-1", s); err != nil {
		t.Fatal(err)
	}
	if n := len(storedObs(t, r.s)); n != 0 {
		t.Fatalf("%d stored at the Result: the dial does not wait", n)
	}
	p.send(ownFlow02(2, 40001, r.now(), true))
	p.taken()
	got := storedObs(t, r.s)
	if len(got) != 2 {
		t.Fatalf("stored %d after the end, want the flow's 2", len(got))
	}
	for _, o := range got {
		if ps := o.Node.PlatformSession; ps == nil || ps.Tie != TieWindow || ps.InvocationID != inv1 {
			t.Fatalf("stored %+v, want the window tie", o.Node)
		}
	}
}

// Section 1.5 item 2: at the onset of a cause that refuses every tie,
// every run the hold keeps gives way untied at once: a held own flow is
// committed at the tick that shows the step, marked node.skewed, and the
// run's Result, which still comes, reports its window refused, ties
// nothing and commits nothing twice. The run is counted once, under the
// cause that stands (D4's F1, D6's B1 on #748): a flow to its endpoint
// while the cause stands, and a later record of the flow held after the
// cause clears, are committed untied and marked, and counted no more. Control: a node that releases nothing
// at the onset, which still holds the record after that tick.
func TestSkewOnsetReleasesHeld(t *testing.T) {
	var st SkewStats
	run := func(t *testing.T) (atOnset int, rel Released, got []*netobs.Observation) {
		r, _ := holdRig02(t)
		defer func() { st = r.l.SkewStats() }()
		p := r.accepted(r.agreeHello(live02()))
		r.tickO(p, 0, 20, 0)
		if err := r.l.Dispatch(bg, HoldRun{RequestID: "req-1", AssetID: relay, Endpoint: endpoint, L4: "tcp"}); err != nil {
			t.Fatal(err)
		}
		start := r.now()
		f := nodeFlow02(1)
		f.FirstUTC = canonUTC(start.Add(time.Second))
		f.LastUTC = f.FirstUTC
		p.send(f)
		p.taken()
		if n := len(storedObs(t, r.s)); n != 0 {
			t.Fatalf("%d stored before the onset: not held", n)
		}
		r.tickO(p, 3*time.Second, 20, 1) // the sensor's clock stepped back 3 s
		atOnset = len(storedObs(t, r.s))
		if skewNoOnset {
			return atOnset, Released{}, nil
		}
		// While the cause stands, a flow to the run's endpoint commits
		// untied at the hold. Then the clock put right: the cause clears,
		// and a later record of the flow, past the floor the step raised,
		// is held by the run.
		p.send(ownFlow02(2, 40002, r.now(), false))
		r.tickO(p, 0, 20, 2)
		p.send(ownFlow02(3, 40001, r.now(), false))
		p.taken()
		if n := len(storedObs(t, r.s)); n != 2 || r.l.Stats().Hold.Held != 1 {
			t.Fatalf("%d stored before the Result: the later record not held: %+v", n, r.l.Stats())
		}
		r.pass(30 * time.Second)
		s := session09("0e4d8a2c-6b1f-4c3e-9a5d-7f2b1c0d9e8f", 40001, 0)
		s.StartedAt, s.ConnectedAt, s.EndedAt = start, start, start.Add(20*time.Second)
		rel, err := r.l.Result(bg, "req-1", s)
		if err != nil {
			t.Fatal(err)
		}
		return atOnset, rel, storedObs(t, r.s)
	}
	n, rel, got := run(t)
	if n != 1 || !rel.Skewed || len(got) != 3 {
		t.Fatalf("stored %d at the onset; released %+v; stored after %d", n, rel, len(got))
	}
	for _, o := range got {
		if o.Node.PlatformSession != nil || !o.Node.Skewed {
			t.Fatalf("stored tied or unmarked: %+v", o.Node)
		}
	}
	// One run refused at the onset, while the latest sample stood.
	if w := windows(st); w != [5]uint64{1, 0, 0, 0, 0} {
		t.Fatalf("window counts %v, want one skew_latest_windows", w)
	}
	t.Run("control: no release at the onset", func(t *testing.T) {
		withSeam(t, &skewNoOnset)
		if n, _, _ := run(t); n != 0 {
			t.Fatalf("the control committed %d at the onset", n)
		}
	})
}

// D6's B4 on #748 (its probe P10): a run the onset refused ties nothing
// through part (c) either. After the onset, with no cause standing, a new
// flow to the run's endpoint is held; the run's Result, a 0.8 session that
// connected with no local address, sets it to wait, and its end, read
// later, is committed untied and marked, the run counted once. Control
// (mutant B4): a waiting branch that does not read the onset, which ties
// both records by window.
func TestSkewOnsetRunWaitsUntied(t *testing.T) {
	r, _ := holdRig02(t)
	p := r.accepted(r.agreeHello(live02()))
	r.tickO(p, 0, 20, 0)
	if err := r.l.Dispatch(bg, HoldRun{RequestID: "req-1", AssetID: relay, Endpoint: endpoint, L4: "tcp"}); err != nil {
		t.Fatal(err)
	}
	start := r.now()
	p.send(ownFlow02(1, 40001, start.Add(time.Second), false))
	p.taken()
	r.tickO(p, 3*time.Second, 20, 1) // the onset
	r.tickO(p, 0, 20, 1)             // the clock put right
	if c := r.l.standing(); c != "" {
		t.Fatalf("standing %q, want none", c)
	}
	at := r.now()
	p.send(ownFlow02(2, 40002, at, false))
	p.taken()
	r.pass(5 * time.Second)
	s := Session{InvocationID: inv1, StartedAt: at.Add(-time.Second), ConnectedAt: at, EndedAt: at.Add(2 * time.Second), Connected: true}
	rel, err := r.l.Result(bg, "req-1", s)
	if err != nil || !rel.Skewed {
		t.Fatalf("released %+v, %v", rel, err)
	}
	p.send(ownFlow02(3, 40002, r.now(), true))
	p.taken()
	got := storedObs(t, r.s)
	if len(got) != 3 {
		t.Fatalf("stored %d, want 3", len(got))
	}
	for _, o := range got {
		if o.Node.PlatformSession != nil || !o.Node.Skewed {
			t.Fatalf("stored tied or unmarked: %+v", o.Node)
		}
	}
	if w := windows(r.l.SkewStats()); w != [5]uint64{1, 0, 0, 0, 0} {
		t.Fatalf("window counts %v, want the onset's one", w)
	}
}

// D4's F3 (a), D6's N3 on #748: the onset ends a holding run whose empty
// record is then not saved. Its Result still reports the window refused.
// N3 (b): a run refused at Dispatch and then abandoned leaves nothing for
// a Result that never comes.
func TestSkewRunMarkKept(t *testing.T) {
	t.Run("the onset's save fails", func(t *testing.T) {
		var failEmpty atomic.Bool
		r, _ := holdRig02With(t, func(o *Options) {
			save := o.Hold.Save
			o.Hold.Save = func(ctx context.Context, rec RunRecord) error {
				if failEmpty.Load() && rec.State == HoldHolding && len(rec.Flows) == 0 {
					return errors.New("test: the save fails")
				}
				return save(ctx, rec)
			}
		})
		p := r.accepted(r.agreeHello(live02()))
		r.tickO(p, 0, 20, 0)
		if err := r.l.Dispatch(bg, HoldRun{RequestID: "req-1", AssetID: relay, Endpoint: endpoint, L4: "tcp"}); err != nil {
			t.Fatal(err)
		}
		start := r.now()
		f := nodeFlow02(1)
		f.FirstUTC = canonUTC(start.Add(time.Second))
		f.LastUTC = f.FirstUTC
		p.send(f)
		p.taken()
		failEmpty.Store(true)
		r.tickO(p, 3*time.Second, 20, 1)
		failEmpty.Store(false)
		s := session09("0e4d8a2c-6b1f-4c3e-9a5d-7f2b1c0d9e8f", 40001, 0)
		s.StartedAt, s.ConnectedAt, s.EndedAt = start, start, start.Add(20*time.Second)
		rel, err := r.l.Result(bg, "req-1", s)
		if err != nil || !rel.Skewed {
			t.Fatalf("released %+v, %v: the window's refusal lost", rel, err)
		}
	})
	t.Run("abandoned", func(t *testing.T) {
		r, _ := holdRig02(t)
		r.accepted(r.helloO(3 * time.Second))
		if err := r.l.Dispatch(bg, HoldRun{RequestID: "req-1", AssetID: relay, Endpoint: endpoint, L4: "tcp"}); err != nil {
			t.Fatal(err)
		}
		if _, err := r.l.Abandon(bg, "req-1"); err != nil {
			t.Fatal(err)
		}
		if n := len(r.l.hold.skewed); n != 0 {
			t.Fatalf("%d runs kept for a Result that never comes", n)
		}
	})
}

// openTied has run req-1 tie the node's own flow from port 40001, whose
// start the sensor stamps start, by its Result; the flow stays open, in the
// open table under inv1 (part (d)).
func (r *rig) openTied(p *peer) (start time.Time) {
	r.t.Helper()
	if err := r.l.Dispatch(bg, HoldRun{RequestID: "req-1", AssetID: relay, Endpoint: endpoint, L4: "tcp"}); err != nil {
		r.t.Fatal(err)
	}
	start = r.now()
	p.send(ownFlow02(1, 40001, start.Add(time.Second), false))
	p.taken()
	r.pass(30 * time.Second)
	s := session09(inv1, 40001, 0)
	s.StartedAt, s.ConnectedAt, s.EndedAt = start, start, start.Add(20*time.Second)
	if rel, err := r.l.Result(bg, "req-1", s); err != nil || r.l.Stats().Hold.Open != 1 {
		r.t.Fatalf("released %+v, %v; hold %+v: the flow is not open", rel, err, r.l.Stats().Hold)
	}
	return start
}

// endTie sends the end of the open flow and returns its stored record.
func (r *rig) endTie(p *peer, seq int, at time.Time) *netobs.Observation {
	r.t.Helper()
	p.send(ownFlow02(seq, 40001, at, true))
	p.taken()
	got := storedObs(r.t, r.s)
	return got[len(got)-1]
}

// X5 of D6's B3 on #748: a later record read through the open table while
// a cause stands takes no tie: it is committed untied, marked and counted
// once (section 1.5; openTie). Control (mutant X5): an open table that
// ties whatever the gate says.
func TestSkewOpenTableRefused(t *testing.T) {
	r, _ := holdRig02(t)
	p := r.accepted(r.agreeHello(live02()))
	r.tickO(p, 0, 20, 0)
	r.openTied(p)
	r.tickO(p, 3*time.Second, 20, 1) // the sensor's clock stepped back 3 s: the latest sample stands
	o := r.endTie(p, 2, r.now())
	if o.Node.PlatformSession != nil || !o.Node.Skewed {
		t.Fatalf("the end through the open table: %+v", o.Node)
	}
	if w := windows(r.l.SkewStats()); w != [5]uint64{1, 0, 0, 0, 0} {
		t.Fatalf("window counts %v, want one skew_latest_windows", w)
	}
}

// D6's N1 on #748: a Result's re-point of an open entry is a tie, gated
// as one. Run 1 ties the node's flow, which stays open, and run 2 is
// dispatched on the same connection. Under the closure (the node's wall
// clock alone stepped 3 s, no sample since), run 2's Result makes no
// re-point and counts it once under skew_moved_windows; with the wall clock
// put back, the flow's end ties to run 1's invocation, not run 2's. At an
// onset, the run's count is the onset's alone. Control (mutant N1-a): a
// re-point made whatever the gate says, which ties the end to run 2.
func TestSkewRepointGated(t *testing.T) {
	type out struct {
		rel Released
		end *netobs.Observation
		w   [5]uint64
	}
	run := func(t *testing.T, onset bool) out {
		r, _ := holdRig02(t)
		p := r.accepted(r.agreeHello(live02()))
		r.tickO(p, 0, 20, 0)
		r.openTied(p)
		if err := r.l.Dispatch(bg, HoldRun{RequestID: "req-2", AssetID: relay, Endpoint: endpoint, L4: "tcp"}); err != nil {
			t.Fatal(err)
		}
		if onset {
			r.tickO(p, 3*time.Second, 20, 1) // the latest sample stands
		} else {
			r.addWall(3 * time.Second) // the closure stands
		}
		s := session09(inv2, 40001, 0)
		s.StartedAt, s.ConnectedAt, s.EndedAt = r.now().Add(-time.Second), r.now(), r.now()
		rel, err := r.l.Result(bg, "req-2", s)
		if err != nil {
			t.Fatal(err)
		}
		var end *netobs.Observation
		if !onset {
			r.addWall(-3 * time.Second)
			end = r.endTie(p, 2, r.now())
		}
		return out{rel, end, windows(r.l.SkewStats())}
	}
	o := run(t, false)
	if o.rel.OpenFlow || !o.rel.Skewed || o.w != [5]uint64{0, 0, 1, 0, 0} {
		t.Fatalf("under the closure: released %+v, window counts %v", o.rel, o.w)
	}
	if ps := o.end.Node.PlatformSession; ps == nil || ps.InvocationID != inv1 {
		t.Fatalf("the end's tie %+v, want run 1's", ps)
	}
	if o := run(t, true); o.rel.OpenFlow || !o.rel.Skewed || o.w != [5]uint64{1, 0, 0, 0, 0} {
		t.Fatalf("at the onset: released %+v, window counts %v", o.rel, o.w)
	}
}

// D6's N5 on #748: an open entry's offset is taken on the link's clock,
// the clock offNow compares it with. With the hold's clock 5 s off the
// link's, a flow tied and still open ties its end. Control (mutant N5):
// the offset taken on the hold's clock, which refuses the end as a move.
func TestOpenEntryOffOnLinkClock(t *testing.T) {
	r, _ := holdRig02With(t, func(o *Options) {
		now := o.Hold.Now
		o.Hold.Now = func() time.Time { return now().Add(5 * time.Second) }
	})
	p := r.accepted(r.agreeHello(live02()))
	r.tickO(p, 0, 20, 0)
	r.openTied(p)
	if o := r.endTie(p, 2, r.now()); o.Node.PlatformSession == nil || o.Node.Skewed {
		t.Fatalf("the end through the open table: %+v; window counts %v", o.Node, windows(r.l.SkewStats()))
	}
}

// helloAnswer dials, sends h, and returns "" when the node acks it, or
// the reason it closed.
func (r *rig) helloAnswer(h *netobs.SensorHello) string {
	r.t.Helper()
	p := r.dial(enrolment())
	p.send(h)
	select {
	case _, ok := <-p.acks:
		if ok {
			p.end()
			return ""
		}
		return p.closed()
	case <-time.After(20 * time.Second):
		r.t.Fatal("the hello was neither acked nor closed")
		return ""
	}
}

// D3's B2 on #748, option (a) (D1's ruling): one time from the sensor past
// what M's field holds (Unix nanoseconds, to 2262), a tick's sensor_utc
// 300 years ahead or a stated span's upper end 250 years ahead. M is
// clamped when written, so once the sensor's clock is put right its next
// hello is acked; the floor in memory stays past 2262 and refuses every
// tie. Control: M written unclamped, whose save fails, so the corrected
// hello closes position-not-saved.
func TestSkewFarClockRecovers(t *testing.T) {
	type leg struct {
		name string
		tick func(r *rig) *netobs.Tick
	}
	legs := []leg{
		{"a tick 300 years ahead", func(r *rig) *netobs.Tick {
			tk := tick02(20, 0, 0)
			tk.SensorUTC = canonUTC(r.now().AddDate(300, 0, 0))
			return tk
		}},
		{"a span to 250 years ahead", func(r *rig) *netobs.Tick {
			tk := r.agreeTick(tick02(20, 0, 1))
			tk.Lost = []netobs.Span{{FromUTC: canonUTC(r.now().Add(-time.Minute)), ToUTC: canonUTC(r.now().AddDate(250, 0, 0))}}
			return tk
		}},
	}
	run := func(t *testing.T, l leg) (answer string, r *rig) {
		r = newRig(t, nil)
		p := r.accepted(r.agreeHello(live02()))
		p.taken()
		r.pass(netobs.TickMinSpacing + time.Second)
		p.send(l.tick(r))
		p.taken()
		p.end()
		r.pass(time.Minute)
		return r.helloAnswer(r.agreeHello(resume(1, 20))), r
	}
	for _, l := range legs {
		t.Run(l.name, func(t *testing.T) {
			answer, r := run(t, l)
			if answer != "" {
				t.Fatalf("the corrected hello closed %q", answer)
			}
			if m := cursorNow(t, r.cs).M; !m.Equal(time.Unix(0, math.MaxInt64)) {
				t.Fatalf("M saved %s, want the field's largest", m)
			}
			if r.l.floorRefusal(r.now()) == "" {
				t.Fatalf("the floor %s refuses nothing now", r.l.SkewStats().Floor)
			}
		})
		t.Run(l.name+", control: M unclamped", func(t *testing.T) {
			withSeam(t, &mNoClamp)
			if answer, _ := run(t, l); answer != netobs.ClosePositionNotSaved {
				t.Fatalf("the control's corrected hello: %q", answer)
			}
		})
	}
}
