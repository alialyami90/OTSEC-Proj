package sensorlink

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"otsec.local/otsec/contracts/netobs"
)

// P4-4-INT-D5-BLIND (blind.go; C13 CH-31, CH-44, CH-45;
// docs/phase4/D5-sensor-node.md section 1.8): the node halves of K-2, K-3
// and K-4, and the brief's tests, each with its control. Desk only: the
// in-memory pipe and the rig's test clocks, a test source in place of the
// sensor, the health stream an in-memory sink. No sensor produced the
// records and no device was contacted.

// stick sends a sensor tick on the live connection, sent_seq sent and
// newest_seq the source's last made, its sensor_utc the source's clock.
func (g *gsrc) stick(sent int) {
	g.t.Helper()
	tk := tick02(g.seq, sent, 0)
	tk.RunID = g.run
	tk.SensorUTC = canonUTC(g.r.now().Add(g.ahead))
	g.send(tk)
}

// two makes the source's heartbeats carry eth1 at the source's packets
// and carrier, and eth2 at *e2, up, from now on.
func (g *gsrc) two(e2 *uint64) {
	g.f = func(h *netobs.Heartbeat) {
		ifs([]string{"eth1", "eth2"}, []uint64{g.pk, *e2})(h)
		h.Interfaces[0].Carrier = g.carrier
	}
}

// blindN is the sensor-blind status alarms raised.
func (g *gsrc) blindN() int { return g.r.al.count(AlarmBlind) }

// named is the interfaces BlindStatus names.
func (g *gsrc) named() []string { return g.r.l.BlindStatus().Blind }

// events flushes the pool and returns the events of typ written.
func (g *gsrc) events(typ string) []map[string]string {
	g.t.Helper()
	if err := g.r.h.Flush(bg); err != nil {
		g.t.Fatal(err)
	}
	return g.r.sink.of(typ)
}

// K-2's node half and the off-by-one on blind_after_s: eth1 rising, eth2
// flat from the run's first current heartbeat T0. At T0 + 300 s nothing;
// at T0 + 310 s sensor-blind naming eth2 alone, and no gap. Then both
// flat: sensor-blind still once, naming both, and 2e's blind gap opens.
// Controls: blind at blind_after_s exactly (raised at T0 + 300 s); blind
// only when every interface is (K-2's control: none for eth2 alone).
func TestBlindOneOfTwo(t *testing.T) {
	run := func(t *testing.T) *gsrc {
		g := newGsrc(t)
		var e2 uint64
		g.two(&e2)
		g.live(1, true) // T0
		g.live(30, true)
		return g
	}
	g := run(t)
	if n := g.blindN(); n != 0 {
		t.Fatalf("at T0 + 300 s: %d sensor-blind, want 0", n)
	}
	g.live(1, true)
	if n := g.blindN(); n != 1 || !g.r.raised(AlarmBlind, "eth2") || g.r.raised(AlarmBlind, "eth1") {
		t.Fatalf("at T0 + 310 s: %d sensor-blind %v, want one naming eth2 alone", n, g.r.al.list)
	}
	if !slices.Equal(g.named(), []string{"eth2"}) || len(g.gaps()) != 0 || g.r.l.GapStatus().Open {
		t.Fatalf("named %v, gaps %v open %v: want eth2 and no gap", g.named(), g.gaps(), g.r.l.GapStatus().Open)
	}
	g.live(31, false) // eth1 flat too
	if n := g.blindN(); n != 1 || !slices.Equal(g.named(), []string{"eth1", "eth2"}) {
		t.Fatalf("both flat: %d sensor-blind, named %v; want one stretch naming both", n, g.named())
	}
	if d := g.openRecord(); d == nil || d["cause"] != CauseBlind {
		t.Fatalf("both flat: gaps %v, want 2e's blind gap open", g.gaps())
	}
	t.Run("control: blind at blind_after_s exactly", func(t *testing.T) {
		withSeam(t, &blindAtLimit)
		if g := run(t); g.blindN() == 0 {
			t.Fatal("the control raised nothing at T0 + 300 s")
		}
	})
	t.Run("control: blind only when every interface is", func(t *testing.T) {
		withSeam(t, &blindAllOnly)
		g := run(t)
		g.live(1, true)
		if g.blindN() != 0 {
			t.Fatal("the control raised sensor-blind for eth2 alone")
		}
	})
}

// K-3's node half: eth1's carrier down while its packets rise: blind at
// the first current heartbeat that states it, eth2 still within
// blind_after_s of the run's start. Control: the carrier ignored.
func TestBlindCarrierDown(t *testing.T) {
	run := func(t *testing.T) *gsrc {
		g := newGsrc(t)
		var e2 uint64
		g.two(&e2)
		g.live(3, true)
		g.carrier = "down"
		g.live(1, true)
		return g
	}
	if g := run(t); g.blindN() != 1 || !slices.Equal(g.named(), []string{"eth1"}) {
		t.Fatalf("%d sensor-blind, named %v; want one naming eth1", g.blindN(), g.named())
	}
	t.Run("control: the carrier ignored", func(t *testing.T) {
		withSeam(t, &blindCarrierIgnored)
		if g := run(t); g.blindN() != 0 {
			t.Fatal("the control raised sensor-blind")
		}
	})
}

// K-4's node half, the link's part: only CH-44's accepted frames move
// Stats.Accepted, which resets the node's sensor-unreachable timer. A
// failed hello, a refused record and an early tick move nothing; an
// accepted tick, a heartbeat taken and an observation committed each
// count one. Control: every frame read counts.
func TestBlindAcceptedFrames(t *testing.T) {
	run := func(t *testing.T) (*healthRig, []uint64) {
		r := newHealthRig(t)
		var got []uint64
		note := func() { got = append(got, r.l.Stats().Accepted) }
		note()
		bad := live02()
		bad.SensorID = "00000000-0000-4000-8000-000000000000"
		p := r.dial(enrolment())
		p.send(bad)
		<-p.done
		note() // a failed hello
		p = r.accepted(live02())
		note()
		r.pass(10 * time.Second)
		refused := hb(1, nil)
		refused.Coverage.ConfigDigest = strings.Repeat("0", len(testDigest))
		p.send(refused)
		p.taken()
		note() // a refused record
		tk := r.agreeTick(tick02(1, 1, 0))
		p.send(tk)
		p.taken()
		note() // an accepted tick
		p.send(r.agreeTick(tick02(1, 1, 0)))
		p.taken()
		note() // an early tick
		r.pass(10 * time.Second)
		p.send(hb(2, at(r.now())))
		p.taken()
		note() // a heartbeat taken
		p.send(obs02(3))
		p.ack(3)
		note() // an observation committed
		return r, got
	}
	if _, got := run(t); !slices.Equal(got, []uint64{0, 0, 0, 0, 1, 1, 2, 3}) {
		t.Fatalf("Accepted after each step %v, want [0 0 0 0 1 1 2 3]", got)
	}
	t.Run("control: every frame read counts", func(t *testing.T) {
		withSeam(t, &acceptedAnyFrame)
		if _, got := run(t); got[1] == 0 && got[3] == got[2] {
			t.Fatalf("the control counted no refused frame: %v", got)
		}
	})
}

// K-4's node half, sensor-no-heartbeat, and the off-by-one on its 60 s:
// the last current heartbeat at T, then accepted ticks only: nothing at
// T + 55 s; at T + 60 s sensor-no-heartbeat and coverage unknown; at
// T + 70 s still one (once a stretch). A current heartbeat ends the
// stretch, and 60 s more of ticks raise it again. Controls: raised only
// past 60 s; raised at every tick.
func TestBlindNoHeartbeat(t *testing.T) {
	run := func(t *testing.T) *gsrc {
		g := newGsrc(t)
		g.live(3, true) // T
		for range 5 {
			g.r.pass(10 * time.Second)
			g.stick(g.seq)
		}
		g.r.pass(5 * time.Second)
		g.stick(g.seq) // T + 55 s
		return g
	}
	g := run(t)
	if g.r.al.count(AlarmNoHeartbeat) != 0 || g.r.l.BlindStatus().CoverageUnknown {
		t.Fatalf("at T + 55 s: %v, want nothing", g.r.al.list)
	}
	g.r.pass(5 * time.Second)
	g.stick(g.seq) // T + 60 s
	if g.r.al.count(AlarmNoHeartbeat) != 1 || !g.r.l.BlindStatus().CoverageUnknown {
		t.Fatalf("at T + 60 s: %v, want sensor-no-heartbeat and coverage unknown", g.r.al.list)
	}
	g.r.pass(10 * time.Second)
	g.stick(g.seq) // T + 70 s
	if n := g.r.al.count(AlarmNoHeartbeat); n != 1 {
		t.Fatalf("at T + 70 s: %d sensor-no-heartbeat, want 1 a stretch", n)
	}
	g.live(1, true)
	if g.r.l.BlindStatus().CoverageUnknown {
		t.Fatal("a current heartbeat did not end coverage unknown")
	}
	for range 6 {
		g.r.pass(10 * time.Second)
		g.stick(g.seq)
	}
	if n := g.r.al.count(AlarmNoHeartbeat); n != 2 {
		t.Fatalf("a second stretch: %d sensor-no-heartbeat, want 2", n)
	}
	if n := len(g.events(AlarmNoHeartbeat)); n != 2 {
		t.Fatalf("%d sensor-no-heartbeat events, want 2", n)
	}
	t.Run("control: raised only past 60 s", func(t *testing.T) {
		withSeam(t, &noHbPastLimit)
		g := run(t)
		g.r.pass(5 * time.Second)
		g.stick(g.seq)
		if g.r.al.count(AlarmNoHeartbeat) != 0 {
			t.Fatal("the control raised it at T + 60 s")
		}
	})
	t.Run("control: raised at every tick", func(t *testing.T) {
		withSeam(t, &noHbEachTick)
		g := run(t)
		for range 2 {
			g.r.pass(5 * time.Second)
			g.stick(g.seq)
		}
		if g.r.al.count(AlarmNoHeartbeat) < 2 {
			t.Fatal("the control raised it once")
		}
	})
}

// Accepted ticks for 60 s with late heartbeats, and again with backlog
// heartbeats that are not late: sensor-no-heartbeat, coverage unknown, and
// neither kind ends the stretch; the first current heartbeat does.
// Control: any heartbeat ends it, which raises nothing.
func TestBlindNoHeartbeatLateAndBacklog(t *testing.T) {
	late := func(t *testing.T) *gsrc {
		g := newGsrc(t)
		g.live(6, true)
		g.queue(24, true) // 240 s, nothing sent
		for range 8 {     // one late heartbeat and a tick each 10 s
			g.r.pass(10 * time.Second)
			g.buf = append(g.buf, g.mk(true))
			h := g.buf[0]
			g.buf = g.buf[1:]
			g.send(h)
			g.stick(g.seq - len(g.buf))
		}
		return g
	}
	backlog := func(t *testing.T) *gsrc {
		g := newGsrc(t)
		g.live(6, true)
		g.cut()
		g.buffer(12, true) // 120 s: delivered 120 s late, under late_bound_s
		first := g.seq - len(g.buf) + 1
		g.p = g.r.dial(enrolment())
		g.send(g.hello(first, false))
		for range 8 { // one backlog heartbeat and a tick each 10 s
			g.r.pass(10 * time.Second)
			g.buf = append(g.buf, g.mk(true))
			h := g.buf[0]
			g.buf = g.buf[1:]
			g.send(h)
			g.stick(int(num(h.(*netobs.Heartbeat).Seq)))
		}
		return g
	}
	for _, c := range []struct {
		what string
		run  func(*testing.T) *gsrc
	}{{"late", late}, {"backlog", backlog}} {
		t.Run(c.what, func(t *testing.T) {
			g := c.run(t)
			if g.r.al.count(AlarmNoHeartbeat) != 1 || !g.r.l.BlindStatus().CoverageUnknown {
				t.Fatalf("%v, want sensor-no-heartbeat once and coverage unknown", g.r.al.list)
			}
			t.Run("control: any heartbeat ends it", func(t *testing.T) {
				withSeam(t, &noHbAnyEnds)
				if g := c.run(t); g.r.al.count(AlarmNoHeartbeat) != 0 {
					t.Fatal("the control raised it")
				}
			})
		})
	}
	g := backlog(t)
	for len(g.buf) > 0 { // the rest of the backlog, then current ones
		g.r.pass(10 * time.Second)
		g.buf = append(g.buf, g.mk(true))
		h := g.buf[0]
		g.buf = g.buf[1:]
		g.send(h)
		if !g.r.l.BlindStatus().CoverageUnknown {
			break
		}
	}
	if g.r.l.BlindStatus().CoverageUnknown || g.r.al.count(AlarmNoHeartbeat) != 1 {
		t.Fatalf("after the backlog: %v, coverage unknown %v; want it ended by a current heartbeat", g.r.al.list, g.r.l.BlindStatus().CoverageUnknown)
	}
}

// A sensor-blind that stands when coverage unknown begins stays standing
// through it, and the current heartbeat after it does not raise it again.
// Control: its stretch ended when coverage unknown begins.
func TestBlindStandsThroughUnknown(t *testing.T) {
	run := func(t *testing.T) *gsrc {
		g := newGsrc(t)
		var e2 uint64
		g.two(&e2)
		g.live(32, true) // eth2 blind
		for range 7 {
			g.r.pass(10 * time.Second)
			g.stick(g.seq)
		}
		return g
	}
	g := run(t)
	if !g.r.l.BlindStatus().CoverageUnknown || !slices.Equal(g.named(), []string{"eth2"}) {
		t.Fatalf("coverage unknown %v, named %v; want eth2 standing through it", g.r.l.BlindStatus().CoverageUnknown, g.named())
	}
	g.live(1, true)
	if n := g.blindN(); n != 1 {
		t.Fatalf("%d sensor-blind, want the one stretch", n)
	}
	t.Run("control: ended when coverage unknown begins", func(t *testing.T) {
		withSeam(t, &blindClearsAtUnknown)
		if g := run(t); len(g.named()) != 0 {
			t.Fatalf("the control kept %v", g.named())
		}
	})
}

// A late or a backlog heartbeat neither raises nor clears sensor-blind.
// eth2 flat from T0: late heartbeats (and, in the second case, backlog
// heartbeats not late) read past T0 + 300 s raise nothing; with eth2's
// stretch standing, late or backlog heartbeats in which eth2 rises clear
// nothing. Controls: judged from every heartbeat that is not late (the
// backlog case), and from every heartbeat that is not a backlog's (the
// late case).
func TestBlindNotFromLateOrBacklog(t *testing.T) {
	// late sends n queued heartbeats of the source, each made 10 s apart
	// and read at once, about four minutes late.
	late := func(g *gsrc, n int, rise2 func()) {
		for range 32 {
			g.r.pass(10 * time.Second)
			g.tick()
			if rise2 != nil {
				rise2()
			}
			g.buf = append(g.buf, g.mk(true))
		}
		for _, h := range g.buf[:n] {
			g.r.pass(100 * time.Millisecond)
			g.send(h)
		}
		g.buf = g.buf[n:]
	}
	// backlog reconnects after a cut of 16 heartbeats and reads n of them,
	// one each 10 s, 160 s after each was made.
	backlog := func(g *gsrc, n int, rise2 func()) {
		g.cut()
		for range 16 {
			g.r.pass(10 * time.Second)
			g.tick()
			if rise2 != nil {
				rise2()
			}
			g.buf = append(g.buf, g.mk(true))
		}
		first := g.seq - len(g.buf) + 1
		g.p = g.r.dial(enrolment())
		g.send(g.hello(first, false))
		for _, h := range g.buf[:n] {
			g.r.pass(10 * time.Second)
			g.send(h)
		}
		g.buf = g.buf[n:]
	}
	raises := []struct {
		what string
		seam *bool
		run  func(t *testing.T) *gsrc
	}{
		{"late", &blindLateCounts, func(t *testing.T) *gsrc {
			g := newGsrc(t)
			var e2 uint64
			g.two(&e2)
			g.live(1, true) // T0
			late(g, 12, nil)
			return g
		}},
		{"backlog", &blindBacklogCounts, func(t *testing.T) *gsrc {
			g := newGsrc(t)
			var e2 uint64
			g.two(&e2)
			g.live(1, true) // T0
			backlog(g, 15, nil)
			return g
		}},
	}
	for _, c := range raises {
		t.Run("raises nothing: "+c.what, func(t *testing.T) {
			if g := c.run(t); g.blindN() != 0 {
				t.Fatalf("%v: a %s heartbeat raised sensor-blind", g.r.al.list, c.what)
			}
			t.Run("control", func(t *testing.T) {
				withSeam(t, c.seam)
				if g := c.run(t); g.blindN() == 0 {
					t.Fatal("the control raised nothing")
				}
			})
		})
	}
	clears := []struct {
		what string
		seam *bool
		run  func(t *testing.T) *gsrc
	}{
		{"late", &blindLateCounts, func(t *testing.T) *gsrc {
			g := newGsrc(t)
			var e2 uint64
			g.two(&e2)
			g.live(32, true) // eth2 blind
			late(g, 12, func() { e2 += 50 })
			return g
		}},
		{"backlog", &blindBacklogCounts, func(t *testing.T) *gsrc {
			g := newGsrc(t)
			var e2 uint64
			g.two(&e2)
			g.live(32, true) // eth2 blind
			backlog(g, 15, func() { e2 += 50 })
			return g
		}},
	}
	for _, c := range clears {
		t.Run("clears nothing: "+c.what, func(t *testing.T) {
			if g := c.run(t); !slices.Equal(g.named(), []string{"eth2"}) {
				t.Fatalf("named %v: a %s heartbeat cleared sensor-blind", g.named(), c.what)
			}
			t.Run("control", func(t *testing.T) {
				withSeam(t, c.seam)
				if g := c.run(t); len(g.named()) != 0 {
					t.Fatalf("the control kept %v", g.named())
				}
			})
		})
	}
}

// An interface that goes blind inside another's stretch is named in that
// stretch: one status alarm, BlindStatus naming both, and the pool's last
// sensor-blind event naming both. Control: only the first named.
func TestBlindSecondInStretch(t *testing.T) {
	run := func(t *testing.T) *gsrc {
		g := newGsrc(t)
		var e2 uint64
		g.two(&e2)
		g.live(32, true) // eth2 blind
		g.carrier = "down"
		g.live(1, true) // eth1 blind
		return g
	}
	g := run(t)
	ev := g.events(AlarmBlind)
	if g.blindN() != 1 || !slices.Equal(g.named(), []string{"eth1", "eth2"}) || len(ev) == 0 ||
		!strings.Contains(ev[len(ev)-1]["detail"], "eth1, eth2") {
		t.Fatalf("%d status alarms, named %v, events %v; want one alarm and both named", g.blindN(), g.named(), ev)
	}
	t.Run("control: only the first named", func(t *testing.T) {
		withSeam(t, &blindFirstOnly)
		if g := run(t); slices.Contains(g.named(), "eth1") {
			t.Fatalf("the control named %v", g.named())
		}
	})
}

// The comparison starts again at a new run: eth2 flat 250 s into run 5,
// then run 6 from its first current heartbeat: nothing within
// blind_after_s of it. Control: the comparison carried across runs.
func TestBlindNewRun(t *testing.T) {
	run := func(t *testing.T) *gsrc {
		g := newGsrc(t)
		var e2 uint64
		g.two(&e2)
		g.live(26, true) // eth2 flat 250 s
		g.cut()
		g.restartSensor()
		g.reconnect(true)
		g.live(12, true) // run 6, 120 s
		return g
	}
	if g := run(t); g.blindN() != 0 {
		t.Fatalf("%v: raised within blind_after_s of the new run", g.r.al.list)
	}
	t.Run("control: carried across runs", func(t *testing.T) {
		withSeam(t, &blindAcrossRuns)
		if g := run(t); g.blindN() == 0 {
			t.Fatal("the control raised nothing")
		}
	})
}

// Each alarm once a stretch, not once a heartbeat (self-check item 6):
// eth2 blind for twenty heartbeats raises sensor-blind once. Control:
// raised at every current heartbeat that finds one blind.
func TestBlindOnceAStretch(t *testing.T) {
	run := func(t *testing.T) *gsrc {
		g := newGsrc(t)
		var e2 uint64
		g.two(&e2)
		g.live(52, true)
		return g
	}
	if g := run(t); g.blindN() != 1 || len(g.events(AlarmBlind)) != 1 {
		t.Fatalf("%d sensor-blind, %d events; want one each", g.blindN(), len(g.events(AlarmBlind)))
	}
	t.Run("control: raised at every heartbeat", func(t *testing.T) {
		withSeam(t, &blindEachHeartbeat)
		if g := run(t); g.blindN() < 2 {
			t.Fatal("the control raised it once")
		}
	})
}

// K-4's sensor.past-blind from late heartbeats: the link live, then
// eth1's packets flat for ten minutes in heartbeats read at once after
// them, the first forty or so later than late_bound_s: one
// sensor.past-blind, naming eth1, once a current heartbeat ends the
// stretch. Control: no past stretch recorded.
func TestBlindPastFromLate(t *testing.T) {
	run := func(t *testing.T) *gsrc {
		g := newGsrc(t)
		g.live(6, true)
		g.queue(60, false)
		g.flush()
		g.live(3, true)
		return g
	}
	g := run(t)
	ev := g.events(EventPastBlind)
	if len(ev) != 1 || !strings.Contains(ev[0]["detail"], "eth1") || strings.Contains(ev[0]["detail"], "merged") {
		t.Fatalf("past-blind events %v, want one naming eth1", ev)
	}
	t.Run("control: no past stretch", func(t *testing.T) {
		withSeam(t, &pastBlindOff)
		if g := run(t); len(g.events(EventPastBlind)) != 0 {
			t.Fatal("the control wrote one")
		}
	})
}

// sensor.past-blind is written once the backlog drains: a cut, the
// backlog flat for 350 s then rising, read in part: the stretch has ended
// in the backlog and nothing is written while it is on; once it is
// through, one event at the node's tick. Control: due at the stretch's
// end, backlog or not.
func TestBlindPastAfterBacklog(t *testing.T) {
	run := func(t *testing.T) *gsrc {
		g := newGsrc(t)
		g.live(6, true)
		g.cut()
		g.buffer(35, false)
		g.buffer(5, true)
		first := g.seq - len(g.buf) + 1
		g.p = g.r.dial(enrolment())
		g.send(g.hello(first, false))
		for _, h := range g.buf[:37] {
			g.r.pass(100 * time.Millisecond)
			g.send(h)
		}
		g.buf = g.buf[37:]
		return g
	}
	g := run(t)
	if n := len(g.events(EventPastBlind)); n != 0 {
		t.Fatalf("%d past-blind written while the backlog is on, want 0", n)
	}
	g.flush()
	g.tick()
	if n := len(g.events(EventPastBlind)); n != 1 {
		t.Fatalf("%d past-blind after the backlog, want 1", n)
	}
	t.Run("control: due at the stretch's end", func(t *testing.T) {
		withSeam(t, &pastBlindAtOnce)
		if g := run(t); len(g.events(EventPastBlind)) == 0 {
			t.Fatal("the control waited for the backlog")
		}
	})
}

// The pool's per-name cap and waiting order for the three names (CH-45):
// each due ten times in an hour is written at most four times; with the
// pool spent and sensor.counters, sensor.run-loss, the three and
// sensor.redial-granted due together, room for four writes
// sensor.redial-granted and the three, and the other two wait. Controls:
// no per-name cap; the waiting order by name alone.
func TestBlindPoolCapAndOrder(t *testing.T) {
	names := []string{AlarmBlind, AlarmNoHeartbeat, EventPastBlind}
	capRun := func(p *Pool) map[string]int {
		got := map[string]int{}
		for i := range 10 {
			now := time.Duration(i) * 5 * time.Minute
			for _, n := range names {
				p.Due(HeldEvent{Name: n})
			}
			_ = p.Write(bg, now, func(_ context.Context, e *HeldEvent) error { got[e.Name]++; return nil })
		}
		return got
	}
	for n, c := range capRun(NewPool()) {
		if c != PoolPerName {
			t.Fatalf("%s written %d times in the hour, want %d", n, c, PoolPerName)
		}
	}
	orderRun := func(p *Pool) []string {
		for i := range PoolPerHour {
			p.Due(HeldEvent{Name: "x" + itoa(i/PoolPerName)})
			_ = p.Write(bg, time.Duration(i)*time.Minute, func(context.Context, *HeldEvent) error { return nil })
		}
		for _, n := range append([]string{EventCounters, EventRunLoss, EventRedialGranted}, names...) {
			p.Due(HeldEvent{Name: n, Key: "k"})
		}
		var got []string
		_ = p.Write(bg, time.Hour+3*time.Minute+30*time.Second, func(_ context.Context, e *HeldEvent) error {
			got = append(got, e.Name)
			return nil
		})
		return got
	}
	want := []string{EventRedialGranted, AlarmBlind, AlarmNoHeartbeat, EventPastBlind}
	if got := orderRun(NewPool()); !slices.Equal(got, want) {
		t.Fatalf("written %v, want %v", got, want)
	}
	t.Run("control: no per-name cap", func(t *testing.T) {
		p := NewPool()
		p.perName = PoolPerHour
		if got := capRun(p); got[AlarmBlind] <= PoolPerName {
			t.Fatalf("the control wrote %v", got)
		}
	})
	t.Run("control: the order by name alone", func(t *testing.T) {
		p := NewPool()
		p.rankOf = func(string) int { return 0 }
		if got := orderRun(p); slices.Equal(got, want) {
			t.Fatalf("the control wrote %v", got)
		}
	})
}
