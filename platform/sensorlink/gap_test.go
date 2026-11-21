package sensorlink

import (
	"strconv"
	"testing"
	"time"

	"otsec.local/otsec/contracts/netobs"
)

// INT-D5 2e-2 (gap.go; docs/phase4/D5-sensor-node.md section 1.9 item 5;
// C13 CH-39, CH-45): the gaps while the node runs, C8-7's legs V-2 to
// V-8, V-10's first three cases, V-13, V-16, V-17 (the gap only), V-9's
// third and eleventh cases and V-14's fourth to seventh, each with its
// control. Desk only: the in-memory pipe and the rig's test clocks, a
// test source in place of the sensor, and the health stream an in-memory
// sink. No sensor produced the records and no device was contacted.

// gsrc is the test source: one sensor run, a heartbeat every 10 s of the
// node's clock, its at_utc the node's wall clock plus ahead.
type gsrc struct {
	t       *testing.T
	r       *healthRig
	p       *peer
	run     string
	counter int
	seq     int
	pk      uint64
	ahead   time.Duration
	carrier string
	// f, when set, changes each heartbeat made.
	f   func(*netobs.Heartbeat)
	buf []any
}

// newGsrc accepts run 5 as new with nothing buffered.
func newGsrc(t *testing.T) *gsrc {
	r := newHealthRig(t)
	return &gsrc{t: t, r: r, p: r.accepted(live02()), run: testRun, counter: 5, carrier: "up"}
}

// mk is the next heartbeat, made now, its packets 100 above the last when
// rise.
func (g *gsrc) mk(rise bool) *netobs.Heartbeat {
	g.seq++
	if rise {
		g.pk += 100
	}
	h := hbWith(g.seq, at(g.r.now().Add(g.ahead)), pk(g.pk, g.carrier))
	h.RunID = g.run
	if g.f != nil {
		g.f(h)
	}
	return h
}

// send sends frames and waits until the link has acted on them.
func (g *gsrc) send(vs ...any) {
	g.t.Helper()
	g.p.send(vs...)
	g.p.taken()
}

// tick is the node's tick: the step check and the gap model's due work.
func (g *gsrc) tick() { g.r.l.CheckStep(bg) }

// live makes n heartbeats 10 s apart, each read at once, with a node tick
// before each.
func (g *gsrc) live(n int, rise bool) {
	g.t.Helper()
	for range n {
		g.r.pass(10 * time.Second)
		g.tick()
		g.send(g.mk(rise))
	}
}

// idle lets d pass with a node tick every 10 s and no heartbeat made.
func (g *gsrc) idle(d time.Duration) {
	for e := time.Duration(0); e < d; e += 10 * time.Second {
		g.r.pass(10 * time.Second)
		g.tick()
	}
}

// cut ends the connection from the sensor's side.
func (g *gsrc) cut() {
	g.t.Helper()
	g.p.end()
}

// buffer makes n heartbeats 10 s apart while the link is down, with a
// node tick before each.
func (g *gsrc) buffer(n int, rise bool) {
	for range n {
		g.r.pass(10 * time.Second)
		g.tick()
		g.buf = append(g.buf, g.mk(rise))
	}
}

// hello is the source's hello for a resume from first.
func (g *gsrc) hello(first int, newRun bool) *netobs.SensorHello {
	h := hello02()
	h.RunID, h.RunCounter = g.run, strconv.Itoa(g.counter)
	h.FirstSeq, h.NewestSeq = itoa(first), itoa(g.seq)
	h.SensorUTC = canonUTC(g.r.now().Add(g.ahead))
	if !newRun {
		h.Prior = nil
	} else {
		h.Prior.RunsSkipped = "0"
	}
	return h
}

// reconnect dials, sends the hello and the buffered records a tenth of a
// second apart.
func (g *gsrc) reconnect(newRun bool) {
	g.t.Helper()
	first := g.seq - len(g.buf) + 1
	g.p = g.r.dial(enrolment())
	g.send(g.hello(first, newRun))
	for _, b := range g.buf {
		g.r.pass(100 * time.Millisecond)
		g.send(b)
	}
	g.buf = nil
}

// restartSensor begins a new run, as a sensor host's restart does.
func (g *gsrc) restartSensor() {
	g.run, g.counter, g.seq, g.pk = testRun2, g.counter+1, 0, 0
	g.buf = nil
}

// gaps is the coverage gaps of causes other than lost written.
func (g *gsrc) gaps() []map[string]string {
	var out []map[string]string
	for _, d := range g.r.sink.of(EventCoverageGap) {
		if d["cause"] != "lost" {
			out = append(out, d)
		}
	}
	return out
}

// lastGap is the last gap record written, nil when none.
func (g *gsrc) lastGap() map[string]string {
	gs := g.gaps()
	if len(gs) == 0 {
		return nil
	}
	return gs[len(gs)-1]
}

// anyCovered reports whether any gap record was written covered.
func (g *gsrc) anyCovered() bool {
	for _, d := range g.gaps() {
		if d["covered"] == "true" {
			return true
		}
	}
	return false
}

// w is W as the link holds it.
func (g *gsrc) w() time.Time {
	w, _ := g.r.l.watchNow()
	return w
}

func fromOf(d map[string]string) time.Time { return parseUTC(d["from_utc"]) }

// cutCovered is V-2's shape: 6 live heartbeats, a cut of d with a heartbeat
// every 10 s buffered, the reconnect with the backlog, then 3 live ones.
// It returns W before the cut.
func cutCovered(g *gsrc, d time.Duration, rise bool) time.Time {
	g.t.Helper()
	g.live(6, true)
	w := g.w()
	g.cut()
	g.buffer(int(d/(10*time.Second)), rise)
	g.reconnect(false)
	g.live(3, true)
	return w
}

// TestGapLinkCutCovered (V-2): the link cut for ten minutes while the
// sensor captures, one run, a heartbeat every interval and an observation
// beside each: the link gap from W is written open once it has stood 60 s,
// and closes as covered once the backlog is through; nothing is written
// unwatched. Control: a gap closed at the reconnect, before the backlog is
// through.
func TestGapLinkCutCovered(t *testing.T) {
	run := func(t *testing.T) (*gsrc, time.Time, int) {
		g := newGsrc(t)
		g.live(6, true)
		w := g.w()
		g.cut()
		for range 60 {
			g.r.pass(10 * time.Second)
			g.tick()
			g.seq++
			g.buf = append(g.buf, obs02(g.seq))
			g.buf = append(g.buf, g.mk(true))
		}
		first := g.seq - len(g.buf) + 1
		g.p = g.r.dial(enrolment())
		g.send(g.hello(first, false))
		var atFirst int
		for i, b := range g.buf {
			g.r.pass(100 * time.Millisecond)
			g.send(b)
			if i == 1 {
				atFirst = len(g.gaps())
			}
		}
		g.buf = nil
		g.live(3, true)
		return g, w, atFirst
	}
	g, w, atFirst := run(t)
	gs := g.gaps()
	if len(gs) != 2 || gs[0]["state"] != "open" || gs[0]["cause"] != CauseLink || !fromOf(gs[0]).Equal(w) ||
		gs[1]["state"] != "closed" || gs[1]["covered"] != "true" || !fromOf(gs[1]).Equal(w) {
		t.Fatalf("records %v, want link open and closed covered from W %s", gs, w)
	}
	if atFirst != 1 {
		t.Fatalf("%d records by the backlog's first heartbeat, want the open one alone", atFirst)
	}
	t.Run("control: closed at the reconnect", func(t *testing.T) {
		withSeam(t, &gapCloseAtReconnect)
		_, _, atFirst := run(t)
		if atFirst != 2 {
			t.Fatalf("%d records by the backlog's first heartbeat: the control did not close it there", atFirst)
		}
	})
}

// TestGapQuietLinkCovered (V-3): the same cut with no observation at all,
// every interface's packets rising: closed as covered on the heartbeats.
// Control: a gap closed only by observations, which is never closed as
// covered here.
func TestGapQuietLinkCovered(t *testing.T) {
	g := newGsrc(t)
	w := cutCovered(g, 10*time.Minute, true)
	if d := g.lastGap(); d == nil || d["covered"] != "true" || !fromOf(d).Equal(w) {
		t.Fatalf("last record %v, want closed covered from %s", d, w)
	}
	t.Run("control: closed only by observations", func(t *testing.T) {
		withSeam(t, &gapNeedsObservation)
		g := newGsrc(t)
		cutCovered(g, 10*time.Minute, true)
		if g.anyCovered() {
			t.Fatalf("records %v: the control closed it as covered", g.gaps())
		}
	})
}

// TestGapHostStoppedStaysOpen (V-4): the link cut for ten minutes with the
// sensor host stopped for five of them; the new run's heartbeats are
// buffered and read after its hello. The whole ten minutes stay one gap,
// from W, with restart among its causes, closed unwatched. Control: a gap
// closed at the reconnect.
func TestGapHostStoppedStaysOpen(t *testing.T) {
	run := func(t *testing.T) (*gsrc, time.Time) {
		g := newGsrc(t)
		g.live(6, true)
		w := g.w()
		g.cut()
		g.idle(5 * time.Minute) // the host stopped: nothing made
		g.restartSensor()
		g.buffer(30, true)
		g.reconnect(true)
		g.live(3, true)
		return g, w
	}
	g, w := run(t)
	d := g.lastGap()
	if d == nil || d["covered"] != "false" || !fromOf(d).Equal(w) || d["causes"] != "link restart" || g.anyCovered() {
		t.Fatalf("records %v, want the last closed unwatched from %s with causes link restart, and none covered", g.gaps(), w)
	}
	t.Run("control: closed at the reconnect", func(t *testing.T) {
		withSeam(t, &gapCloseAtReconnect)
		g, _ := run(t)
		if !g.anyCovered() {
			t.Fatalf("records %v: the control did not close it as covered", g.gaps())
		}
	})
}

// TestGapRestartInLongBreak (V-5): a ten-minute break with a sensor restart
// inside it after 20 s, the new run's heartbeats stating times that fill
// the break: the whole break stays open, restart among its causes, and
// closes unwatched. Control: a chain that runs across the new run, judged
// on the heartbeats' stated times, which closes it as covered.
func TestGapRestartInLongBreak(t *testing.T) {
	run := func(t *testing.T) *gsrc {
		g := newGsrc(t)
		g.live(6, true)
		g.cut()
		g.buffer(2, true)
		g.buf = nil // the old run's tail is never read
		g.restartSensor()
		g.buffer(58, true)
		g.reconnect(true)
		g.live(3, true)
		return g
	}
	if d := run(t).lastGap(); d == nil || d["covered"] != "false" || d["causes"] != "link restart" {
		t.Fatalf("last record %v, want closed unwatched with causes link restart", d)
	}
	t.Run("control: a chain across the new run", func(t *testing.T) {
		withSeams(t, &gapChainAnyRun, &gapRiseNoTotal)
		if d := run(t).lastGap(); d == nil || d["covered"] != "true" {
			t.Fatalf("last record %v: the control did not close it as covered", d)
		}
	})
}

// TestGapSilentEngineStaysOpen (V-7): a ten-minute break in one run whose
// seqs are unbroken, with no heartbeat for eight minutes of it: closed
// unwatched. And a 40 s silence just before the reconnect, between the
// last buffered heartbeat and the first live one: unwatched. Controls: a
// chain judged by its seqs alone, which closes the first as covered; and a
// chain with no spacing check, which closes the second as covered.
func TestGapSilentEngineStaysOpen(t *testing.T) {
	eight := func(t *testing.T) *gsrc {
		g := newGsrc(t)
		g.live(6, true)
		g.cut()
		g.buffer(6, true)
		g.idle(8 * time.Minute)
		g.buffer(6, true)
		g.reconnect(false)
		g.live(3, true)
		return g
	}
	forty := func(t *testing.T) *gsrc {
		g := newGsrc(t)
		g.live(6, true)
		g.cut()
		g.buffer(56, true)
		g.idle(40 * time.Second)
		g.reconnect(false)
		g.r.pass(time.Second)
		g.send(g.mk(true))
		g.live(2, true)
		return g
	}
	for _, c := range []struct {
		what string
		run  func(*testing.T) *gsrc
		seam *bool
	}{{"eight minutes", eight, &gapChainSeqOnly}, {"40 s before the reconnect", forty, &gapChainNoSpacing}} {
		t.Run(c.what, func(t *testing.T) {
			if d := c.run(t).lastGap(); d == nil || d["covered"] != "false" {
				t.Fatalf("last record %v, want closed unwatched", d)
			}
			t.Run("control", func(t *testing.T) {
				withSeam(t, c.seam)
				if d := c.run(t).lastGap(); d == nil || d["covered"] != "true" {
					t.Fatalf("last record %v: the control did not close it as covered", d)
				}
			})
		})
	}
}

// TestGapChainCount (V-8): a ten-minute gap with the sensor's clock at
// half speed: 15 heartbeats 20 s apart by at_utc, one every 40 s of the
// node's clock: closed unwatched, since 20 are needed at 30 s. Control: a
// chain with no count, checked by spacing alone, which closes it as
// covered.
func TestGapChainCount(t *testing.T) {
	run := func(t *testing.T) *gsrc {
		g := newGsrc(t)
		g.live(6, true)
		start := g.r.now()
		half := func() { g.ahead = start.Add(g.r.now().Sub(start) / 2).Sub(g.r.now()) }
		g.cut()
		for range 15 {
			g.r.pass(40 * time.Second)
			g.tick()
			half()
			g.buf = append(g.buf, g.mk(true))
		}
		g.r.pass(10 * time.Second)
		half()
		g.reconnect(false)
		g.live(1, true)
		return g
	}
	if d := run(t).lastGap(); d == nil || d["covered"] != "false" {
		t.Fatalf("last record %v, want closed unwatched", d)
	}
	t.Run("control: no count", func(t *testing.T) {
		withSeam(t, &gapChainNoCount)
		if d := run(t).lastGap(); d == nil || d["covered"] != "true" {
			t.Fatalf("last record %v: the control did not close it as covered", d)
		}
	})
}
