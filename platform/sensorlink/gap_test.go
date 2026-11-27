package sensorlink

import (
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"testing"
	"time"

	"otsec.local/otsec/contracts/netobs"
)

// INT-D5 2e-2 (gap.go; docs/phase4/D5-sensor-node.md section 1.9 item 5;
// C13 CH-39, CH-45): the gaps while the node runs, C8-7's legs V-2 to
// V-8, V-10's first three cases, V-13, V-16 but its fifth case's step,
// V-17 but its fifth case (the gap only), V-9's third and eleventh cases
// and V-14's fourth to seventh, each with its control; and D1's rulings 1
// to 3 on #781. Desk only: the in-memory pipe and the rig's test clocks, a
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
	base    time.Duration // the sensor's clock less the node's, as a step leaves it
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
	g.counter++
	g.run, g.seq, g.pk = fmt.Sprintf("1c9e4c6d-1a2f-4e3b-8c7d-%012x", g.counter), 0, 0
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

// openWithin reports whether the first record written is an open record of
// cause from at most from, written no later than by: 60 s plus one node
// tick from W.
func (g *gsrc) openRecord() map[string]string {
	for _, d := range g.gaps() {
		if d["state"] == "open" {
			return d
		}
	}
	return nil
}

// TestGapNeverBackOpen (V-10): the link cut and never restored: a link gap
// from W is in the health stream as open within 60 s plus one node tick
// of W, and stays open. Second case: no heartbeat after the last current
// one, and the connection reset 20 s after its receipt: from_utc is that
// receipt, cause link. Third case: every packets flat from four minutes
// before W, then the connection reset at W and never restored: open
// within 60 s plus one tick of W, from R. Controls: a node that writes a
// gap only when it closes (nothing in the stream); a gap from the moment
// it opens (20 s late); a gap from W (four minutes late).
func TestGapNeverBackOpen(t *testing.T) {
	never := func(t *testing.T) (*gsrc, time.Time) {
		g := newGsrc(t)
		g.live(6, true)
		w := g.w()
		g.cut()
		g.idle(50 * time.Second)
		if len(g.gaps()) != 0 {
			t.Fatalf("written before 60 s: %v", g.gaps())
		}
		g.idle(20 * time.Second) // 60 s plus one tick
		return g, w
	}
	g, w := never(t)
	if d := g.openRecord(); d == nil || d["cause"] != CauseLink || !fromOf(d).Equal(w) {
		t.Fatalf("records %v, want link open from %s", g.gaps(), w)
	}
	g.idle(30 * time.Minute)
	if len(g.gaps()) != 1 || !g.r.l.GapStatus().Open {
		t.Fatalf("records %v: the gap did not stay open", g.gaps())
	}
	t.Run("control: written only at the close", func(t *testing.T) {
		withSeam(t, &gapOpenNever)
		if g, _ := never(t); len(g.gaps()) != 0 {
			t.Fatalf("records %v under the control", g.gaps())
		}
	})
	reset20 := func(t *testing.T) (*gsrc, time.Time) {
		g := newGsrc(t)
		g.live(6, true)
		recv := g.r.now()
		g.r.pass(20 * time.Second)
		g.cut()
		g.idle(70 * time.Second)
		return g, recv
	}
	t.Run("reset 20 s after the receipt", func(t *testing.T) {
		g, recv := reset20(t)
		if d := g.openRecord(); d == nil || d["cause"] != CauseLink || fromOf(d).After(recv) {
			t.Fatalf("records %v, want link from no later than %s", g.gaps(), recv)
		}
		t.Run("control: from the open", func(t *testing.T) {
			withSeam(t, &gapAtOpen)
			if g, recv := reset20(t); g.openRecord() == nil || !fromOf(g.openRecord()).After(recv) {
				t.Fatalf("records %v: the control did not start it late", g.gaps())
			}
		})
	})
	flat := func(t *testing.T) (*gsrc, time.Time, time.Time) {
		g := newGsrc(t)
		g.live(6, true)
		_, rr := g.r.l.watchNow()
		g.live(24, false) // four minutes flat, within blind_after_s
		w := g.w()
		g.cut()
		g.idle(70 * time.Second)
		return g, rr, w
	}
	t.Run("flat from four minutes before W", func(t *testing.T) {
		g, rr, w := flat(t)
		if !w.After(rr.Add(3 * time.Minute)) {
			t.Fatalf("W %s and R %s: W did not move through the flat stretch", w, rr)
		}
		if d := g.openRecord(); d == nil || !fromOf(d).Equal(rr) {
			t.Fatalf("records %v, want open from R %s", g.gaps(), rr)
		}
		t.Run("control: from W", func(t *testing.T) {
			withSeam(t, &gapFromW)
			if g, _, w := flat(t); g.openRecord() == nil || !fromOf(g.openRecord()).Equal(w) {
				t.Fatalf("records %v: the control did not start it at W", g.gaps())
			}
		})
	})
}

// TestGapSensorFailedOpen (V-13): a recovered panic stops the sensor's
// work: a sensor-failed gap is written open at the panic, and nothing
// closes it. The panic 20 s after the last current heartbeat's receipt:
// from_utc is that receipt. Controls: a node that writes a gap only when
// it closes, which leaves nothing until its next start; a gap from the
// panic, 20 s late.
func TestGapSensorFailedOpen(t *testing.T) {
	run := func(t *testing.T) (*gsrc, time.Time) {
		g := newGsrc(t)
		g.live(6, true)
		recv := g.r.now()
		g.r.pass(20 * time.Second)
		g.r.l.SensorFailed(bg)
		return g, recv
	}
	g, recv := run(t)
	if d := g.openRecord(); d == nil || d["cause"] != CauseSensorFailed || !fromOf(d).Equal(recv) {
		t.Fatalf("records %v, want sensor-failed open from %s at the panic", g.gaps(), recv)
	}
	g.live(3, true) // later heartbeats close nothing (D6's M7 and PF on #781)
	g.cut()
	g.idle(10 * time.Minute)
	if len(g.gaps()) != 1 || !g.r.l.GapStatus().Open {
		t.Fatalf("records %v: the gap did not stay open", g.gaps())
	}
	t.Run("control: written only at the close", func(t *testing.T) {
		withSeam(t, &gapOpenNever)
		if g, _ := run(t); len(g.gaps()) != 0 {
			t.Fatalf("records %v under the control", g.gaps())
		}
	})
	t.Run("control: from the panic", func(t *testing.T) {
		withSeam(t, &gapAtOpen)
		if g, recv := run(t); g.openRecord() == nil || !fromOf(g.openRecord()).After(recv) {
			t.Fatalf("records %v: the control did not start it late", g.gaps())
		}
	})
}

// queue makes n heartbeats 10 s apart on the live link without sending
// them: an engine whose heartbeats wait behind records.
func (g *gsrc) queue(n int, rise bool) {
	for range n {
		g.r.pass(10 * time.Second)
		g.tick()
		g.buf = append(g.buf, g.mk(rise))
	}
}

// flush sends what the queue holds, a tenth of a second apart.
func (g *gsrc) flush() {
	g.t.Helper()
	for _, b := range g.buf {
		g.r.pass(100 * time.Millisecond)
		g.send(b)
	}
	g.buf = nil
}

// TestGapHeartbeatSilence (V-16): a heartbeat silence on a link that stays
// up, the node ticking every 10 s.
//   - No heartbeat for five minutes, then heartbeats again in the same
//     run: a silent gap from W, open within 60 s plus one tick of W, closed
//     unwatched. Control: no silent cause, which writes nothing.
//   - Heartbeats made every 10 s and delivered four minutes late: closed as
//     covered once the chain is read.
//   - Delivered two minutes late, inside late_bound_s, then on time:
//     covered at the first heartbeat whose lateness is under
//     HeartbeatGapMax. Control: the cause ended at the first current
//     heartbeat, whose chain is too short: unwatched.
//   - Flat from four minutes before W, silent for two minutes, then flat:
//     blind joins the gap, from R. Control: a gap from W.
//   - The floor: the heartbeats after the stall arrive 25 s late, so the
//     gap closes unwatched at t1, the receipt of the first; one heartbeat
//     later the link is cut for two minutes and restored with a full
//     chain: the link gap is covered, from no earlier than t1. Control: no
//     floor, which starts it about 15 s before t1.
//   - The second case's control: a silent gap closed only unwatched. The
//     fifth and eighth cases, and three of D6's probes on #781 (PJ, PM and
//     the cause's end at its bound), as each subtest states.
func TestGapHeartbeatSilence(t *testing.T) {
	five := func(t *testing.T) (*gsrc, time.Time) {
		g := newGsrc(t)
		g.live(6, true)
		w := g.w()
		g.idle(70 * time.Second)
		if d := g.openRecord(); d == nil || d["cause"] != CauseSilent || !fromOf(d).Equal(w) {
			t.Fatalf("records %v, want silent open from %s within 60 s plus a tick", g.gaps(), w)
		}
		g.idle(230 * time.Second)
		g.live(3, true)
		return g, w
	}
	g, w := five(t)
	if d := g.lastGap(); d == nil || d["state"] != "closed" || d["covered"] != "false" || !fromOf(d).Equal(w) {
		t.Fatalf("records %v, want silent closed unwatched from %s", g.gaps(), w)
	}
	t.Run("control: no silent cause", func(t *testing.T) {
		withSeam(t, &gapSilentOff)
		g := newGsrc(t)
		g.live(6, true)
		g.idle(5 * time.Minute)
		g.live(3, true)
		if len(g.gaps()) != 0 {
			t.Fatalf("records %v under the control", g.gaps())
		}
	})
	fourLate := func(t *testing.T) *gsrc {
		g := newGsrc(t)
		g.live(6, true)
		g.queue(24, true)
		g.flush()
		g.live(3, true)
		return g
	}
	t.Run("four minutes late", func(t *testing.T) {
		if g := fourLate(t); g.lastGap() == nil || g.lastGap()["covered"] != "true" || g.r.l.GapStatus().Open {
			t.Fatalf("records %v, want closed covered", g.gaps())
		}
		t.Run("control: silent closed only unwatched", func(t *testing.T) {
			withSeam(t, &gapSilentNeverCovered)
			if g := fourLate(t); g.anyCovered() {
				t.Fatalf("records %v: the control closed it as covered", g.gaps())
			}
		})
	})
	twoLate := func(t *testing.T) *gsrc {
		g := newGsrc(t)
		g.live(6, true)
		g.queue(12, true)
		for range 6 { // two minutes late, one delivered for each made
			g.r.pass(10 * time.Second)
			g.tick()
			g.buf = append(g.buf, g.mk(true))
			b := g.buf[0]
			g.buf = g.buf[1:]
			g.send(b)
		}
		g.flush()
		g.r.pass(time.Second)
		g.send(g.mk(true))
		return g
	}
	t.Run("two minutes late, then on time", func(t *testing.T) {
		g := twoLate(t)
		if d := g.lastGap(); d == nil || d["covered"] != "true" {
			t.Fatalf("records %v, want closed covered", g.gaps())
		}
		t.Run("control: ended at the first current heartbeat", func(t *testing.T) {
			withSeam(t, &gapSilentEndsAtCurrent)
			if g := twoLate(t); g.lastGap() == nil || g.lastGap()["covered"] != "false" {
				t.Fatalf("records %v: the control did not close it unwatched", g.gaps())
			}
		})
	})
	flatStall := func(t *testing.T) (*gsrc, time.Time, time.Time) {
		g := newGsrc(t)
		g.live(6, true)
		_, rr := g.r.l.watchNow()
		g.live(24, false)
		w := g.w()
		g.idle(2 * time.Minute)
		g.live(3, false)
		return g, rr, w
	}
	t.Run("flat across the stall", func(t *testing.T) {
		g, rr, _ := flatStall(t)
		st := g.r.l.GapStatus()
		if !st.Open || st.Causes != "silent blind" || !st.From.Equal(rr) {
			t.Fatalf("gap %+v, want silent blind from R %s", st, rr)
		}
		t.Run("control: from W", func(t *testing.T) {
			withSeam(t, &gapFromW)
			if g, _, w := flatStall(t); !g.r.l.GapStatus().From.Equal(w) {
				t.Fatalf("gap %+v: the control did not start it at W %s", g.r.l.GapStatus(), w)
			}
		})
	})
	floor := func(t *testing.T) (*gsrc, time.Time) {
		g := newGsrc(t)
		g.live(6, true)
		g.idle(2 * time.Minute)
		g.ahead = -25 * time.Second
		g.live(1, true)
		t1 := g.r.now()
		g.live(1, true)
		g.cut()
		g.buffer(12, true)
		g.reconnect(false)
		g.live(3, true)
		return g, t1
	}
	t.Run("no move back below the floor", func(t *testing.T) {
		g, t1 := floor(t)
		gs := g.gaps()
		if len(gs) != 4 || gs[1]["cause"] != CauseSilent || gs[1]["covered"] != "false" || !parseUTC(gs[1]["to_utc"]).Equal(t1) {
			t.Fatalf("records %v, want the silent gap closed unwatched at %s first", gs, t1)
		}
		d := g.lastGap()
		if d["cause"] != CauseLink || d["covered"] != "true" || fromOf(d).Before(t1) {
			t.Fatalf("records %v, want the link gap covered from no earlier than %s", gs, t1)
		}
		t.Run("control: no floor", func(t *testing.T) {
			withSeam(t, &gapNoFloor)
			if g, t1 := floor(t); !fromOf(g.lastGap()).Before(t1) {
				t.Fatalf("records %v: the control did not start the link gap before %s", g.gaps(), t1)
			}
		})
	})
	// The reset at once after t1, before any later heartbeat: the link gap
	// from no earlier than t1 (D6's M5 and PJ on #781).
	t.Run("the reset at once after the close", func(t *testing.T) {
		g := newGsrc(t)
		g.live(6, true)
		g.idle(2 * time.Minute)
		g.ahead = -25 * time.Second
		g.live(1, true)
		t1 := g.r.now()
		g.cut()
		g.idle(70 * time.Second)
		if d := g.lastGap(); d == nil || d["cause"] != CauseLink || fromOf(d).Before(t1) {
			t.Fatalf("records %v, want the link gap from no earlier than %s", g.gaps(), t1)
		}
	})
	// A 40 s silence with no node tick before the next heartbeat: the
	// silent gap opens at that heartbeat and closes unwatched, part 3
	// failing (D6's M35 and PM on #781).
	t.Run("40 s with no tick", func(t *testing.T) {
		g := newGsrc(t)
		g.live(6, true)
		w := g.w()
		g.r.pass(40 * time.Second)
		g.send(g.mk(true))
		if d := g.lastGap(); d == nil || d["cause"] != CauseSilent || d["covered"] != "false" || !fromOf(d).Equal(w) {
			t.Fatalf("records %v, want silent closed unwatched from %s", g.gaps(), w)
		}
	})
	// The cause's end at its bound: a heartbeat exactly HeartbeatGapMax
	// late leaves the gap open, and one 1 ns less late closes it (D6's M3
	// on #781).
	t.Run("the end at its bound", func(t *testing.T) {
		g := newGsrc(t)
		g.live(6, true)
		g.idle(70 * time.Second)
		g.ahead = -HeartbeatGapMax
		g.live(1, true)
		if st := g.r.l.GapStatus(); !st.Open || st.Cause != CauseSilent {
			t.Fatalf("gap %+v: closed by a heartbeat HeartbeatGapMax late", st)
		}
		g.ahead = -HeartbeatGapMax + 1
		g.live(1, true)
		if st := g.r.l.GapStatus(); st.Open {
			t.Fatalf("gap %+v: not closed by a heartbeat less late", st)
		}
	})
	// Fifth case: the delay raised by 10 s a heartbeat to 120 s, then no
	// heartbeat made while those held are sent; ticks at 10 s, 20 s and
	// 45 s after the last receipt: the silent gap is open by the tick at
	// 45 s, from no later than the last heartbeat's at_utc + E (E is 0
	// here). Controls: W and R at their receipts, about 120 s late; W at its
	// receipt and R as built, from_utc passes but the record is not yet due.
	lateStopped := func(t *testing.T) (*gsrc, time.Time) {
		g := newGsrc(t)
		g.live(3, true)
		q, lastAt := g.ramp(6, nil)
		g.drain(q)
		for _, d := range []time.Duration{10, 10, 25} {
			g.r.pass(d * time.Second)
			g.tick()
		}
		return g, lastAt
	}
	t.Run("fifth: late, then stopped", func(t *testing.T) {
		g, lastAt := lateStopped(t)
		if d := g.openRecord(); d == nil || d["cause"] != CauseSilent || fromOf(d).After(lastAt) {
			t.Fatalf("records %v, want silent open from no later than %s", g.gaps(), lastAt)
		}
		t.Run("control: W and R at their receipts", func(t *testing.T) {
			withSeam(t, &placeAtReceipt)
			if g, lastAt := lateStopped(t); !g.r.l.GapStatus().From.After(lastAt.Add(time.Minute)) {
				t.Fatalf("gap %+v: the control did not start it late", g.r.l.GapStatus())
			}
		})
		t.Run("control: W at its receipt", func(t *testing.T) {
			withSeam(t, &gapWAtReceipt)
			if g, _ := lateStopped(t); g.openRecord() != nil {
				t.Fatalf("records %v: the control wrote it by the tick at 45 s", g.gaps())
			}
		})
	})
	// Eighth case: the floor case with the node's wall clock stepped back
	// 60 s, 5 s before t1, and no tick between: the silent record carries
	// clock_stepped, time.node-stepped is written once, and the link gap is
	// from no earlier than t1. Control: the step check at the tick only,
	// which writes the silent record unmarked and starts the link gap
	// before t1.
	stepAtClose := func(t *testing.T) (*gsrc, time.Time) {
		g := newGsrc(t)
		g.live(6, true)
		g.idle(2 * time.Minute)
		g.ahead = -25 * time.Second
		g.r.pass(5 * time.Second)
		g.r.addWall(-time.Minute) // the node's clock alone
		g.ahead += time.Minute
		g.r.pass(5 * time.Second)
		g.send(g.mk(true)) // t1, no tick since the step
		t1 := g.r.now()
		g.live(1, true)
		g.cut()
		g.buffer(12, true)
		g.reconnect(false)
		g.live(3, true)
		return g, t1
	}
	t.Run("eighth: a step found at the close", func(t *testing.T) {
		g, t1 := stepAtClose(t)
		gs := g.gaps()
		if len(gs) != 4 || gs[1]["cause"] != CauseSilent || gs[1]["clock_stepped"] != "true" || g.r.sink.count("time.node-stepped") != 1 {
			t.Fatalf("records %v and %d steps, want the silent record marked and one step", gs, g.r.sink.count("time.node-stepped"))
		}
		if d := g.lastGap(); d["cause"] != CauseLink || fromOf(d).Before(t1) {
			t.Fatalf("records %v, want the link gap from no earlier than %s", gs, t1)
		}
		t.Run("control: the step check at the tick only", func(t *testing.T) {
			withSeam(t, &stepTickOnly)
			g, t1 := stepAtClose(t)
			if g.gaps()[1]["clock_stepped"] == "true" || !fromOf(g.lastGap()).Before(t1) {
				t.Fatalf("records %v: the control marked the record or started the link gap at %s", g.gaps(), t1)
			}
		})
	})
}

// pend is a heartbeat made and held by the source until due.
type pend struct {
	due time.Time
	h   *netobs.Heartbeat
}

// ramp makes heartbeats every 10 s, a node tick before each, raising
// their delay by 10 s a heartbeat to 120 s, and sends each once due: 12
// rising to reach 120 s, then n more. rise, when set, is called before the
// i-th of the n is made, and says whether its packets rise; nil, they
// rise. It returns what the source still holds and the at_utc of the last
// made.
func (g *gsrc) ramp(n int, rise func(i int) bool) (q []pend, lastAt time.Time) {
	d := time.Duration(0)
	for i := range 12 + n {
		g.r.pass(10 * time.Second)
		g.tick()
		up := true
		if rise != nil && i >= 12 {
			up = rise(i - 12)
		}
		h := g.mk(up)
		lastAt = parseUTC(h.AtUTC)
		d = min(d+10*time.Second, 120*time.Second)
		q = append(q, pend{g.r.now().Add(d), h})
		q = g.due(q)
	}
	return q, lastAt
}

// due sends what q holds that is due now.
func (g *gsrc) due(q []pend) []pend {
	for len(q) > 0 && !q[0].due.After(g.r.now()) {
		g.send(q[0].h)
		q = q[1:]
	}
	return q
}

// drain sends what q holds as each falls due, a node tick every 10 s.
func (g *gsrc) drain(q []pend) {
	for len(q) > 0 {
		g.r.pass(10 * time.Second)
		g.tick()
		q = g.due(q)
	}
}

// TestGapFlatCountsCarrierUp (V-17; its sensor.past-blind half is
// P4-4-INT-D5-BLIND's, blind.go).
//   - A ten-minute cut, one run, every carrier up and every packets flat
//     for the whole cut: closed unwatched. Control: a chain that checks the
//     carrier alone, which closes it as covered. And one sensor.past-blind
//     naming eth1, written once the backlog drains. Control: no past
//     stretch recorded.
//   - The blind close: the link current, flat for blind_after_s, then
//     rising: a blind gap written open from R, closed unwatched at the
//     first heartbeat that rises. Control: a gap from the moment the node
//     finds every interface blind, blind_after_s late.
//   - Every carrier down for 60 s inside the cut, packets rising: unwatched,
//     and one sensor.past-blind.
//   - Every packets flat for seven minutes inside the cut: unwatched, and
//     one sensor.past-blind.
//   - Flat from four minutes before W, no restart: from R. Control: a gap
//     from W.
//   - The cables pulled after W's heartbeat: the next heartbeat's packets
//     rose, every carrier down: a blind gap from W. Control: R taken at any
//     rise, whatever its carrier, and the gap from R.
//   - The third and fourth cases' control: a chain judged on stretches as
//     long as blind_after_s. The ninth case, as its subtest states.
func TestGapFlatCountsCarrierUp(t *testing.T) {
	flatCut := func(t *testing.T) *gsrc {
		g := newGsrc(t)
		g.live(6, true)
		g.cut()
		g.buffer(60, false)
		g.reconnect(false)
		g.live(3, true)
		return g
	}
	if d := flatCut(t).lastGap(); d == nil || d["covered"] != "false" {
		t.Fatalf("last record %v, want closed unwatched", d)
	}
	if ev := flatCut(t).events(EventPastBlind); len(ev) != 1 || !strings.Contains(ev[0]["detail"], "eth1") {
		t.Fatalf("past-blind events %v, want one naming eth1", ev)
	}
	t.Run("control: no past stretch", func(t *testing.T) {
		withSeam(t, &pastBlindOff)
		if ev := flatCut(t).events(EventPastBlind); len(ev) != 0 {
			t.Fatalf("the control wrote %v", ev)
		}
	})
	t.Run("control: the carrier alone", func(t *testing.T) {
		withSeam(t, &gapChainCarrierOnly)
		if g := flatCut(t); !g.anyCovered() {
			t.Fatalf("records %v: the control did not close it as covered", g.gaps())
		}
	})
	blind := func(t *testing.T) (*gsrc, time.Time) {
		g := newGsrc(t)
		g.live(6, true)
		_, rr := g.r.l.watchNow()
		g.live(31, false)
		return g, rr
	}
	t.Run("the blind close", func(t *testing.T) {
		g, rr := blind(t)
		d := g.openRecord()
		if d == nil || d["cause"] != CauseBlind || !fromOf(d).Equal(rr) {
			t.Fatalf("records %v, want blind open from R %s", g.gaps(), rr)
		}
		g.live(1, true)
		if d := g.lastGap(); d["state"] != "closed" || d["covered"] != "false" || !parseUTC(d["to_utc"]).Equal(g.r.now()) {
			t.Fatalf("records %v, want blind closed unwatched at the rise", g.gaps())
		}
		t.Run("control: from the open", func(t *testing.T) {
			withSeam(t, &gapAtOpen)
			g, rr := blind(t)
			if d := g.openRecord(); d == nil || !fromOf(d).After(rr.Add(DefaultBlindAfter)) {
				t.Fatalf("records %v: the control did not start it blind_after_s late", g.gaps())
			}
		})
	})
	inside := func(t *testing.T, mid func(g *gsrc)) *gsrc {
		g := newGsrc(t)
		g.live(6, true)
		g.cut()
		g.buffer(10, true)
		mid(g)
		g.buffer(10, true)
		g.reconnect(false)
		g.live(3, true)
		return g
	}
	// The third and fourth cases' control: a chain judged on stretches as
	// long as blind_after_s (D6's N3 on #781).
	down60 := func(g *gsrc) {
		g.carrier = "down"
		g.buffer(6, true)
		g.carrier = "up"
	}
	flat7 := func(g *gsrc) { g.buffer(42, false) }
	for _, c := range []struct {
		what string
		mid  func(*gsrc)
	}{{"carrier down for 60 s", down60}, {"flat for seven minutes", flat7}} {
		t.Run(c.what, func(t *testing.T) {
			g := inside(t, c.mid)
			if d := g.lastGap(); d == nil || d["covered"] != "false" {
				t.Fatalf("records %v, want closed unwatched", d)
			}
			if ev := g.events(EventPastBlind); len(ev) != 1 {
				t.Fatalf("past-blind events %v, want one", ev)
			}
			t.Run("control: stretches as long as blind_after_s", func(t *testing.T) {
				withSeam(t, &gapChainStretch)
				if g := inside(t, c.mid); !g.anyCovered() {
					t.Fatalf("records %v: the control did not close it as covered", g.gaps())
				}
			})
		})
	}
	flatBefore := func(t *testing.T) (*gsrc, time.Time, time.Time) {
		g := newGsrc(t)
		g.live(6, true)
		_, rr := g.r.l.watchNow()
		g.live(24, false)
		w := g.w()
		g.cut()
		g.buffer(12, false)
		g.reconnect(false)
		g.live(3, true)
		return g, rr, w
	}
	t.Run("flat from four minutes before W", func(t *testing.T) {
		g, rr, _ := flatBefore(t)
		if d := g.lastGap(); d == nil || d["covered"] != "false" || !fromOf(d).Equal(rr) {
			t.Fatalf("records %v, want closed unwatched from R %s", g.gaps(), rr)
		}
		t.Run("control: from W", func(t *testing.T) {
			withSeam(t, &gapFromW)
			if g, _, w := flatBefore(t); !fromOf(g.lastGap()).Equal(w) {
				t.Fatalf("records %v: the control did not start it at W", g.gaps())
			}
		})
	})
	pulled := func(t *testing.T) (*gsrc, time.Time) {
		g := newGsrc(t)
		g.live(6, true)
		w := g.w()
		g.carrier = "down"
		g.live(1, true)
		return g, w
	}
	t.Run("the cables pulled", func(t *testing.T) {
		g, w := pulled(t)
		if d := g.openRecord(); d == nil || d["cause"] != CauseBlind || fromOf(d).After(w) {
			t.Fatalf("records %v, want blind open from no later than W %s", g.gaps(), w)
		}
		t.Run("control: R at any rise, the gap from R", func(t *testing.T) {
			withSeam(t, &gapBlindFromAnyRise)
			if g, w := pulled(t); g.openRecord() == nil || !fromOf(g.openRecord()).After(w) {
				t.Fatalf("records %v: the control did not start it after W %s", g.gaps(), w)
			}
		})
	})
	// Ninth case: the delay raised by 10 s a heartbeat to 120 s, the link
	// current; every carrier down 3 s after the heartbeat made at h, whose
	// packets rose: the blind gap from no later than h's at_utc + E (E is
	// 0 here). Control: W and R at their receipts, about 120 s late. Its
	// second half: every packets flat, carrier up, from h until the
	// carriers go down 60 s later: the same. Control: R at its receipt and
	// W as built, from W, about 60 s late.
	lateBlind := func(t *testing.T, flat int) (*gsrc, time.Time) {
		g := newGsrc(t)
		g.live(3, true)
		var h time.Time
		q, _ := g.ramp(flat+3, func(i int) bool {
			if i == 0 {
				h = g.r.now().Add(-10 * time.Second) // the last made, which rose
			}
			if i >= flat {
				g.carrier = "down"
			}
			return i >= flat
		})
		g.drain(q)
		return g, h
	}
	t.Run("ninth: R with heartbeats late", func(t *testing.T) {
		g, h := lateBlind(t, 0)
		if d := g.openRecord(); d == nil || d["cause"] != CauseBlind || fromOf(d).After(h) {
			t.Fatalf("records %v, want blind open from no later than %s", g.gaps(), h)
		}
		t.Run("control: W and R at their receipts", func(t *testing.T) {
			withSeam(t, &placeAtReceipt)
			if g, h := lateBlind(t, 0); g.openRecord() == nil || !fromOf(g.openRecord()).After(h.Add(time.Minute)) {
				t.Fatalf("records %v: the control did not start it late", g.gaps())
			}
		})
		t.Run("flat for 60 s from h", func(t *testing.T) {
			g, h := lateBlind(t, 6)
			if d := g.openRecord(); d == nil || d["cause"] != CauseBlind || fromOf(d).After(h) {
				t.Fatalf("records %v, want blind open from no later than %s", g.gaps(), h)
			}
			t.Run("control: R at its receipt", func(t *testing.T) {
				withSeam(t, &gapRAtReceipt)
				if g, h := lateBlind(t, 6); g.openRecord() == nil || !fromOf(g.openRecord()).After(h.Add(30*time.Second)) {
					t.Fatalf("records %v: the control did not start it late", g.gaps())
				}
			})
		})
	})
}

// twoIf makes the source's heartbeats carry eth1 and eth2 from now on,
// eth1 at the source's packets with carrier c1 and eth2 flat at 0, up.
func (g *gsrc) twoIf(c1 string) {
	g.f = func(h *netobs.Heartbeat) {
		ifs([]string{"eth1", "eth2"}, []uint64{g.pk, 0})(h)
		h.Interfaces[0].Carrier = c1
	}
}

// TestGapChainNoRiseHeld (D6's N4 on #774, D1's ruling on #781, from D6's
// PR3): a name first seen within a run holds no rise, so the chain counts
// it only once its own packets rise. eth2 is first seen at the run's
// second heartbeat, flat and up; W is placed there on eth1's rise; through
// a three-minute cut eth1's carrier is down, so only eth2 could show
// capture: closed unwatched. Control: a name's rise_utc kept as the
// heartbeat it was first seen in, which carries the chain on eth2 and
// closes it as covered. Second case: a name changed inside the chain
// fails it. Control: a chain that takes a new name as it comes. And two
// of D6's probes on #781: a name dropped (PL) and a seq skipped (PG) inside
// the chain, each unwatched.
func TestGapChainNoRiseHeld(t *testing.T) {
	run := func(t *testing.T) *gsrc {
		g := newGsrc(t)
		g.live(1, true)
		g.twoIf("up")
		g.live(1, true)
		g.cut()
		g.twoIf("down")
		g.buffer(18, false)
		g.twoIf("up")
		g.reconnect(false)
		g.live(3, true)
		return g
	}
	if g := run(t); g.lastGap() == nil || g.anyCovered() {
		t.Fatalf("records %v, want closed unwatched", g.gaps())
	}
	t.Run("control: rise_utc at the first sight", func(t *testing.T) {
		withSeam(t, &gapRiseFirstSeen)
		if g := run(t); !g.anyCovered() {
			t.Fatalf("records %v: the control did not close it as covered", g.gaps())
		}
	})
	names := func(t *testing.T) *gsrc {
		g := newGsrc(t)
		g.live(6, true)
		g.cut()
		g.buffer(10, true)
		g.f = func(h *netobs.Heartbeat) { ifs([]string{"eth1", "eth3"}, []uint64{g.pk, 0})(h) }
		g.buffer(1, true)
		g.f = nil
		g.buffer(10, true)
		g.reconnect(false)
		g.live(3, true)
		return g
	}
	t.Run("a name changed in the chain", func(t *testing.T) {
		if g := names(t); g.lastGap() == nil || g.anyCovered() {
			t.Fatalf("records %v, want closed unwatched", g.gaps())
		}
		t.Run("control: any names", func(t *testing.T) {
			withSeam(t, &gapChainAnyNames)
			if g := names(t); !g.anyCovered() {
				t.Fatalf("records %v: the control did not close it as covered", g.gaps())
			}
		})
	})
	// A name dropped for one heartbeat inside the chain, eth2 flat at 0:
	// unwatched (D6's M11 and PL on #781).
	t.Run("a name dropped in the chain", func(t *testing.T) {
		g := newGsrc(t)
		two := func(h *netobs.Heartbeat) { ifs([]string{"eth1", "eth2"}, []uint64{g.pk, 0})(h) }
		g.f = two
		g.live(6, true)
		g.cut()
		g.buffer(10, true)
		g.f = func(h *netobs.Heartbeat) { ifs([]string{"eth1"}, []uint64{g.pk})(h) }
		g.buffer(1, true)
		g.f = two
		g.buffer(10, true)
		g.reconnect(false)
		g.live(3, true)
		if g.lastGap() == nil || g.anyCovered() {
			t.Fatalf("records %v, want closed unwatched", g.gaps())
		}
	})
	// One seq skipped inside an otherwise full chain: part 1 fails (D6's
	// M1 and PG on #781).
	t.Run("a seq skipped in the chain", func(t *testing.T) {
		g := newGsrc(t)
		g.live(6, true)
		g.cut()
		g.buffer(30, true)
		g.buf = append(g.buf[:15], g.buf[16:]...)
		g.buffer(29, true)
		g.reconnect(false)
		g.live(3, true)
		if g.lastGap() == nil || g.anyCovered() {
			t.Fatalf("records %v, want closed unwatched", g.gaps())
		}
	})
}

// TestCaptureShuffleNotARise (D3's N-b on #774, D1's ruling on #781, from
// D3's two probes): a sensor that moves packets between names across a
// drop, the run's counters.packets flat at 200, eth1 flat. W stops at the
// run's start plus blind_after_s, and R never moves. Control: a rise
// counted without a rise of counters.packets, under which W moves through
// the flat total, to within a cycle of the probe's end.
func TestCaptureShuffleNotARise(t *testing.T) {
	withSeam(t, &gapsOff) // W and R alone
	probes := map[string]func(i int) func(*netobs.Heartbeat){
		"re-added lower": func(i int) func(*netobs.Heartbeat) {
			switch i % 3 {
			case 0:
				return ifs([]string{"eth1", "eth2"}, []uint64{100, 100})
			case 1:
				return ifs([]string{"eth1", "eth3"}, []uint64{100, 100})
			}
			return func(h *netobs.Heartbeat) {
				ifs([]string{"eth1", "eth2", "eth3"}, []uint64{100, 0, 100})(h)
			}
		},
		"a fresh name each cycle": func(i int) func(*netobs.Heartbeat) {
			a, b := "eth"+itoa(10+i), "eth"+itoa(11+i)
			if i%2 == 0 {
				return ifs([]string{"eth1", a}, []uint64{100, 100})
			}
			return ifs([]string{"eth1", a, b}, []uint64{100, 100, 0})
		},
	}
	for name, set := range probes {
		run := func(t *testing.T) (*healthRig, time.Time, time.Time) {
			r := newHealthRig(t)
			p := r.accepted(live02())
			r.beatAt(p, hbWith(1, at(r.now().Add(time.Second)), set(0)))
			began, want := r.now(), r.now()
			for i := 1; i <= 31; i++ {
				r.pass(59 * time.Second)
				r.beatAt(p, hbWith(1+i, at(r.now().Add(time.Second)), set(i)))
				if r.now().Sub(began) <= DefaultBlindAfter {
					want = r.now()
				}
			}
			return r, r.now(), want
		}
		t.Run(name, func(t *testing.T) {
			r, _, want := run(t)
			wantW(t, r, want, time.Time{}, "the total flat for 31 minutes")
			t.Run("control: a rise without the total", func(t *testing.T) {
				withSeam(t, &gapRiseNoTotal)
				r, _, want := run(t)
				if w, _ := r.l.watchNow(); !w.After(want.Add(20 * time.Minute)) {
					t.Fatalf("W %s under the control, want it moved through the flat total", w)
				}
			})
		})
	}
}

// TestGapClockStepped (V-9's third and eleventh cases, with the node
// running): a ten-minute cut in one run with a full chain.
//   - The wall clock stepped back fifteen minutes five minutes in: closed
//     unwatched with clock_stepped, and time.node-stepped written once.
//     Control: a chain that closes a stepped gap, which writes covered.
//   - Stepped forward thirty minutes: closed as covered, since its length
//     is taken on the monotonic clock.
//   - The wall clock slewed 0.5 ms a second throughout: covered, with no
//     clock_stepped and no time.node-stepped; and one step back of 3 s:
//     unwatched with clock_stepped. Control: a check that acts on any
//     backward difference, which marks the slewed gap.
//   - The second controls: the length taken from the wall clock, which
//     leaves the forward case unwatched; a step acted on only at a minute
//     or more, which closes the 3 s case as covered.
func TestGapClockStepped(t *testing.T) {
	stepped := func(t *testing.T, step time.Duration, slew bool) *gsrc {
		g := newGsrc(t)
		g.live(6, true)
		g.cut()
		for i := range 60 {
			g.r.pass(10 * time.Second)
			if slew {
				g.r.addWall(-5 * time.Millisecond)
				g.ahead += 5 * time.Millisecond
			}
			if i == 30 && step != 0 {
				g.r.addWall(step) // the node's clock alone: the sensor's runs on
				g.ahead -= step
			}
			g.tick()
			g.buf = append(g.buf, g.mk(true))
		}
		g.reconnect(false)
		g.live(3, true)
		return g
	}
	stepEvents := func(g *gsrc) int { return g.r.sink.count("time.node-stepped") }
	g := stepped(t, -15*time.Minute, false)
	if d := g.lastGap(); d == nil || d["covered"] != "false" || d["clock_stepped"] != "true" || stepEvents(g) != 1 {
		t.Fatalf("records %v and %d steps, want unwatched with clock_stepped and one step", g.gaps(), stepEvents(g))
	}
	t.Run("control: the chain closes a stepped gap", func(t *testing.T) {
		withSeam(t, &gapChainIgnoresStep)
		if g := stepped(t, -15*time.Minute, false); !g.anyCovered() {
			t.Fatalf("records %v: the control did not close it as covered", g.gaps())
		}
	})
	t.Run("forward thirty minutes", func(t *testing.T) {
		if g := stepped(t, 30*time.Minute, false); !g.anyCovered() || g.lastGap()["clock_stepped"] != "" {
			t.Fatalf("records %v, want closed covered", g.gaps())
		}
		t.Run("control: the length from the wall clock", func(t *testing.T) {
			withSeam(t, &gapLengthWall)
			if g := stepped(t, 30*time.Minute, false); g.anyCovered() {
				t.Fatalf("records %v: the control closed it as covered", g.gaps())
			}
		})
	})
	t.Run("slewed", func(t *testing.T) {
		g := stepped(t, 0, true)
		if !g.anyCovered() || g.lastGap()["clock_stepped"] != "" || stepEvents(g) != 0 {
			t.Fatalf("records %v and %d steps, want covered and none", g.gaps(), stepEvents(g))
		}
		t.Run("control: any backward difference", func(t *testing.T) {
			withSeam(t, &stepAnyBack)
			if g := stepped(t, 0, true); g.lastGap()["clock_stepped"] != "true" {
				t.Fatalf("records %v: the control did not mark it", g.gaps())
			}
		})
	})
	t.Run("one step back of 3 s", func(t *testing.T) {
		g := stepped(t, -3*time.Second, false)
		if d := g.lastGap(); d["covered"] != "false" || d["clock_stepped"] != "true" || stepEvents(g) != 1 {
			t.Fatalf("records %v and %d steps, want unwatched with clock_stepped and one step", g.gaps(), stepEvents(g))
		}
		t.Run("control: a threshold of a minute", func(t *testing.T) {
			withSeam(t, &stepMinuteOnly)
			if g := stepped(t, -3*time.Second, false); !g.anyCovered() {
				t.Fatalf("records %v: the control did not close it as covered", g.gaps())
			}
		})
	})
}

// restartGap is one gap closed unwatched within a few seconds: the
// connection cut, the sensor restarted, the new run's first heartbeat read
// at once.
func (g *gsrc) restartGap() {
	g.t.Helper()
	g.cut()
	g.r.pass(time.Second)
	g.restartSensor()
	g.reconnect(true)
	g.live(1, true)
}

// TestGapLostOwnBudget (V-6). First case: the connection killed again and
// again, the source beginning a new run at each kill, the budget of the
// other causes spent, and then a run that declares a loss: its lost gap is
// written. Control: one budget for every cause, which the other gaps
// spend, so the lost gap waits. Second case, a merge under the budget:
// the budget spent but for one record; a link gap stands two minutes and
// is written open with that record; the node's wall clock is stepped back
// five minutes while it is open; it closes unwatched past the budget, and
// two more gaps follow, each closing unwatched within seconds with a
// sensor restart inside it: once the budget allows, one record holds the
// three, from the first gap's start, merged 3, covered false and
// clock_stepped, pairing with the first gap's open record. Controls: a
// merge from the last gap's start, which leaves the open record unpaired;
// a merge that keeps the last gap's mark only, which writes no
// clock_stepped. The third case is TestLostGapNotBehindOtherGaps.
func TestGapLostOwnBudget(t *testing.T) {
	lost := func(t *testing.T) *gsrc {
		g := newGsrc(t)
		g.live(1, true)
		for range 6 {
			g.restartGap()
		}
		g.cut()
		g.restartSensor()
		h := g.hello(1, true)
		from := g.r.now().Add(-time.Minute)
		h.Prior.RecordsLost, h.Prior.PreviousEnd = "3", "unclean"
		h.Prior.Lost = []netobs.Span{{FromUTC: canonUTC(from), ToUTC: canonUTC(from.Add(10 * time.Second))}}
		g.p = g.r.dial(enrolment())
		g.send(h)
		g.live(1, true)
		return g
	}
	lostGaps := func(g *gsrc) int { return g.r.sink.count(EventCoverageGap) - len(g.gaps()) }
	g := lost(t)
	if n := len(g.gaps()); n != 4 || lostGaps(g) != 1 {
		t.Fatalf("%d gaps of other causes and %d lost, want 4 and 1", n, lostGaps(g))
	}
	t.Run("control: one budget", func(t *testing.T) {
		withSeam(t, &gapOneBudget)
		if g := lost(t); lostGaps(g) != 0 {
			t.Fatalf("%d lost gaps written under the control", lostGaps(g))
		}
	})
	merge := func(t *testing.T) (*gsrc, time.Time) {
		g := newGsrc(t)
		g.live(1, true)
		for range 3 {
			g.restartGap()
		}
		g.live(6, true)
		w := g.w()
		g.cut()
		g.idle(2 * time.Minute)
		g.r.addWall(-5 * time.Minute)
		g.ahead += 5 * time.Minute
		g.idle(20 * time.Second)
		g.restartSensor()
		g.reconnect(true)
		g.live(1, true)
		g.restartGap()
		g.restartGap()
		return g, w
	}
	t.Run("a merge under the budget", func(t *testing.T) {
		g, w := merge(t)
		if n := len(g.gaps()); n != 4 {
			t.Fatalf("%d records before the hour, want 4: %v", n, g.gaps())
		}
		if st := g.r.l.GapStatus(); st.Waiting == nil || st.Waiting.Gaps != 3 {
			t.Fatalf("waiting %+v, want three gaps held", st.Waiting)
		}
		g.r.pass(time.Hour)
		g.tick()
		d := g.gaps()[4] // then a silent gap, the source quiet for the hour
		if d["merged"] != "3" || d["covered"] != "false" || d["clock_stepped"] != "true" || !fromOf(d).Equal(w) ||
			!fromOf(g.gaps()[3]).Equal(w) || g.gaps()[3]["state"] != "open" {
			t.Fatalf("records %v, want the open record from %s paired by one merged record of three", g.gaps(), w)
		}
		t.Run("control: from the last gap's start", func(t *testing.T) {
			withSeam(t, &gapMergeLastStart)
			g, w := merge(t)
			g.r.pass(time.Hour)
			g.tick()
			if fromOf(g.lastGap()).Equal(w) {
				t.Fatalf("records %v: the control paired the open record", g.gaps())
			}
		})
		t.Run("control: the last gap's mark only", func(t *testing.T) {
			withSeam(t, &gapMergeLastMark)
			g, _ := merge(t)
			g.r.pass(time.Hour)
			g.tick()
			if g.gaps()[4]["clock_stepped"] == "true" {
				t.Fatalf("records %v: the control marked the merged record", g.gaps())
			}
		})
	})
}

// held is V-14's fourth case: the health class refusing every coverage gap
// (the ceiling) from before t1; a silent gap from R0 closes unwatched at
// t1, the heartbeats after the stall 25 s late; heartbeats current after
// it, rising; a second silent gap opens at S2 and closes unwatched at t2
// the same way while the first waits; one heartbeat after t2 the
// connection is cut and restored with a full chain. mid runs between t1
// and S2's stall, and during S2's stall when during is set.
func held(t *testing.T, mid func(g *gsrc), during func(g *gsrc)) (g *gsrc, r0, t1, t2, link time.Time) {
	g = newGsrc(t)
	g.live(6, true)
	r0 = g.w()
	g.r.sink.refuse = func(typ string, _ map[string]string) bool { return typ == EventCoverageGap }
	stall := func() time.Time {
		g.ahead = g.base
		g.idle(2 * time.Minute)
		g.ahead = g.base - 25*time.Second
		g.live(1, true)
		return g.r.now()
	}
	t1 = stall()
	g.live(3, true)
	if mid != nil {
		mid(g)
	}
	g.ahead = g.base
	g.idle(time.Minute)
	if during != nil {
		during(g)
	}
	g.ahead = g.base
	g.idle(time.Minute)
	g.ahead = g.base - 25*time.Second
	g.live(1, true)
	t2 = g.r.now()
	g.live(1, true)
	g.cut()
	g.buffer(12, true)
	link = g.r.l.GapStatus().From
	g.reconnect(false)
	g.live(3, true)
	return g, r0, t1, t2, link
}

// TestGapHeldInW (V-14's fourth to seventh cases).
//   - Fourth, a merge into the held gap: while the class refuses, the
//     cursor holds one gap from R0 to t2 carrying 2, and no record is
//     written; the link gap is from no earlier than t2, and closes as
//     covered, never written; once room returns, one record holds both, R0
//     to t2, merged 2, covered false.
//     Control: no floor, which starts the link gap before t2.
//   - Fifth, the mark through a merge: the wall clock stepped back five
//     minutes between t1 and S2, found at a node tick while the first gap
//     is held and none is open: the merged record carries clock_stepped,
//     and time.node-stepped is written once. Control: a step that marks
//     only the gap open then.
//   - Sixth, the order and the pairing: only the held gap's closing record
//     refused; after t2, while the field is held, the node's wall clock
//     stepped back a minute, found at a tick; the connection reset and
//     never restored, so C opens between R0 and t2 by number; the second
//     gap's open record is never written, and the merged record, marked,
//     is written before C's open record, which it does not pair. Control:
//     later records written while a closing record waits.
//   - Seventh, a step while the second gap is open: the merged record
//     carries clock_stepped. Control: a step that marks only the gap open
//     then, and a merge that keeps only the held gap's mark.
func TestGapHeldInW(t *testing.T) {
	g, r0, _, t2, link := held(t, nil, nil)
	if link.Before(t2) {
		t.Fatalf("the link gap from %s, before t2 %s", link, t2)
	}
	c := cursorNow(t, g.r.cs)
	if c.Held == nil || !c.Held.From.Equal(r0) || !c.Held.To.Equal(t2) || c.Held.Gaps != 2 || len(g.r.sink.of(EventCoverageGap)) != 0 {
		t.Fatalf("cursor's held gap %+v and records %v, want R0 %s to t2 %s carrying 2, nothing written", c.Held, g.gaps(), r0, t2)
	}
	g.r.sink.refuse = nil
	g.tick()
	gs := g.gaps()
	if len(gs) < 1 || gs[0]["merged"] != "2" || gs[0]["covered"] != "false" || !fromOf(gs[0]).Equal(r0) || !parseUTC(gs[0]["to_utc"]).Equal(t2) {
		t.Fatalf("records %v, want first one merged record from %s to %s", gs, r0, t2)
	}
	if len(gs) != 1 {
		t.Fatalf("records %v, want the merged record alone", gs)
	}
	g.live(1, true) // the first save after the record clears it there
	if c := cursorNow(t, g.r.cs); c.Held != nil {
		t.Fatalf("the cursor still holds %+v after the record and a save", c.Held)
	}
	t.Run("control: no floor", func(t *testing.T) {
		withSeam(t, &gapNoFloor)
		if _, _, _, t2, link := held(t, nil, nil); !link.Before(t2) {
			t.Fatalf("the link gap from %s: the control did not start it before %s", link, t2)
		}
	})
	step := func(g *gsrc) {
		g.r.addWall(-5 * time.Minute) // the node's clock alone
		g.base += 5 * time.Minute
		g.tick()
	}
	marked := func(t *testing.T, mid, during func(*gsrc)) *gsrc {
		g, _, _, _, _ := held(t, mid, during)
		g.r.sink.refuse = nil
		g.tick()
		return g
	}
	t.Run("fifth: the mark through a merge", func(t *testing.T) {
		g := marked(t, step, nil)
		if d := g.gaps()[0]; d["merged"] != "2" || d["clock_stepped"] != "true" || g.r.sink.count("time.node-stepped") != 1 {
			t.Fatalf("records %v and %d steps, want the merged record marked and one step", g.gaps(), g.r.sink.count("time.node-stepped"))
		}
		t.Run("control: only the gap open", func(t *testing.T) {
			withSeam(t, &gapMarkOpenOnly)
			if g := marked(t, step, nil); g.gaps()[0]["clock_stepped"] == "true" {
				t.Fatalf("records %v: the control marked the held gap", g.gaps())
			}
		})
	})
	t.Run("seventh: a step while the second gap is open", func(t *testing.T) {
		g := marked(t, nil, step)
		if d := g.gaps()[0]; d["merged"] != "2" || d["clock_stepped"] != "true" {
			t.Fatalf("records %v, want the merged record marked", g.gaps())
		}
		t.Run("control: only the gap open, and the held gap's mark", func(t *testing.T) {
			withSeams(t, &gapMarkOpenOnly, &gapMergeHeldMark)
			if g := marked(t, nil, step); g.gaps()[0]["clock_stepped"] == "true" {
				t.Fatalf("records %v: the control marked the merged record", g.gaps())
			}
		})
	})
	order := func(t *testing.T) (*gsrc, time.Time, time.Time) {
		g := newGsrc(t)
		g.live(6, true)
		r0 := g.w()
		g.r.sink.refuse = func(typ string, d map[string]string) bool {
			return typ == EventCoverageGap && d["state"] == "closed" && parseUTC(d["from_utc"]).Equal(r0)
		}
		g.idle(2 * time.Minute)
		g.ahead = -25 * time.Second
		g.live(4, true)
		g.ahead = 0
		g.idle(2 * time.Minute) // the second gap, written open past 60 s if nothing holds it
		g.ahead = -25 * time.Second
		g.live(1, true)
		t2 := g.r.now()
		g.live(1, true)
		// While the field is held, the node's wall clock alone stepped back
		// a minute, more than the time since t2 and less than the time
		// since R0, found at a tick (D6's N4 and PI on #781).
		g.r.pass(time.Second)
		g.r.addWall(-time.Minute)
		g.ahead += time.Minute
		g.tick()
		g.cut()
		g.idle(90 * time.Second)
		g.r.sink.refuse = nil
		g.tick()
		return g, r0, t2
	}
	t.Run("sixth: the order and the pairing", func(t *testing.T) {
		g, r0, t2 := order(t)
		gs := g.gaps()
		// The first gap's open record, then the merged record, marked, then
		// C's open record, between R0 and t2 by number, which the merged
		// record does not pair.
		if len(gs) != 3 || gs[0]["state"] != "open" || gs[1]["merged"] != "2" || gs[1]["clock_stepped"] != "true" ||
			!fromOf(gs[1]).Equal(r0) || !parseUTC(gs[1]["to_utc"]).Equal(t2) || gs[2]["cause"] != CauseLink || gs[2]["state"] != "open" {
			t.Fatalf("records %v, want open, the merged record marked, and C open, in that order", gs)
		}
		if c := fromOf(gs[2]); !c.After(r0) || !c.Before(t2) {
			t.Fatalf("C from %s, want after R0 %s and before t2 %s", c, r0, t2)
		}
		t.Run("control: written behind", func(t *testing.T) {
			withSeam(t, &gapWriteBehind)
			g, _, _ := order(t)
			if len(g.gaps()) <= 3 {
				t.Fatalf("records %v: the control wrote nothing behind the held record", g.gaps())
			}
		})
	})
}

// TestGapRaiseSavedFirst (CH-18; V-14's second case's order, within one
// process): when an unwatched close's record reaches the health stream,
// the cursor already holds the raise and the gap held for the floor, so a
// kill between the two loses neither. Control: the record written before
// the raise is saved, which the cursor does not yet hold.
func TestGapRaiseSavedFirst(t *testing.T) {
	run := func(t *testing.T) *HeldGap {
		g := newGsrc(t)
		g.live(6, true)
		var seen *HeldGap
		g.r.sink.refuse = func(typ string, d map[string]string) bool {
			if typ == EventCoverageGap && d["state"] == "closed" && seen == nil {
				c := cursorNow(t, g.r.cs)
				seen = &HeldGap{}
				if c.Held != nil {
					seen = c.Held
				}
			}
			return false
		}
		g.idle(time.Minute)
		g.live(1, true)
		return seen
	}
	if h := run(t); h == nil || h.Gaps != 1 || h.Cause != CauseSilent {
		t.Fatalf("the cursor held %+v at the record, want the silent gap", h)
	}
	t.Run("control: the record first", func(t *testing.T) {
		withSeam(t, &gapRecordFirst)
		if h := run(t); h == nil || h.Gaps != 0 {
			t.Fatalf("the cursor held %+v at the record under the control", h)
		}
	})
}

// TestGapRCarriedPastClose (V-16's sixth case): W and R at R0, counts
// rising; no heartbeat for two minutes, so a silent gap opens from R0;
// heartbeats resume 40 s late with counts rising, then on time and flat,
// and the gap closes unwatched at t1, the chain failing its third part;
// 90 s later the connection is cut for two minutes, the backlog rising,
// and restored with a full chain: the link gap closes as covered, from no
// earlier than t1. Control: a close that raises nothing, which keeps R
// from before the silent gap and writes the covered gap from R0.
func TestGapRCarriedPastClose(t *testing.T) {
	run := func(t *testing.T) (*gsrc, time.Time, time.Time) {
		g := newGsrc(t)
		g.live(6, true)
		r0 := g.w()
		g.idle(2 * time.Minute)
		g.ahead = -40 * time.Second
		g.live(3, true)
		g.ahead = 0
		g.live(1, false)
		t1 := g.r.now()
		g.live(9, false)
		g.cut()
		g.buffer(12, true)
		g.reconnect(false)
		g.live(3, true)
		return g, r0, t1
	}
	g, _, t1 := run(t)
	d := g.lastGap()
	if d["cause"] != CauseLink || d["covered"] != "true" || fromOf(d).Before(t1) {
		t.Fatalf("records %v, want the link gap covered from no earlier than %s", g.gaps(), t1)
	}
	t.Run("control: a close that raises nothing", func(t *testing.T) {
		withSeam(t, &gapNoFloor)
		if g, r0, _ := run(t); !fromOf(g.lastGap()).Equal(r0) {
			t.Fatalf("records %v: the control did not write it from R0 %s", g.gaps(), r0)
		}
	})
}

// TestGapNewRunInFlatCut (V-17's eighth case): every interface flat, carrier
// up, from R, four minutes before W; the connection reset at W; the old
// run stays flat for three minutes more and its backlog is read; then a
// new run begins, its counts rising, read after its hello. The gap opens
// as link from R, takes restart at the new run's hello, and closes
// unwatched, from R. Control: a gap from W, four minutes late.
func TestGapNewRunInFlatCut(t *testing.T) {
	run := func(t *testing.T) (*gsrc, time.Time, time.Time) {
		g := newGsrc(t)
		g.live(6, true)
		_, rr := g.r.l.watchNow()
		g.live(24, false)
		w := g.w()
		g.cut()
		g.buffer(18, false)
		g.reconnect(false)
		g.cut()
		g.restartSensor()
		g.buffer(6, true)
		g.reconnect(true)
		g.live(2, true)
		return g, rr, w
	}
	g, rr, _ := run(t)
	d := g.lastGap()
	if d == nil || d["covered"] != "false" || d["causes"] != "link restart" || !fromOf(d).Equal(rr) {
		t.Fatalf("records %v, want link restart closed unwatched from R %s", g.gaps(), rr)
	}
	t.Run("control: from W", func(t *testing.T) {
		withSeam(t, &gapFromW)
		if g, _, w := run(t); !fromOf(g.lastGap()).Equal(w) {
			t.Fatalf("records %v: the control did not start it at W", g.gaps())
		}
	})
}

// TestGapRaiseNotSaved (self-check item 3): the save of an unwatched
// close's raise fails at the heartbeat that closes it: the connection
// closes store, and the record is written only once a later save holds
// the raise (here the save at the connection's end), and once. Control:
// the record written before the raise is saved, which the cursor does not
// hold when the record is written.
func TestGapRaiseNotSaved(t *testing.T) {
	run := func(t *testing.T) (g *gsrc, reason string, closed int, heldAtWrite bool) {
		g = newGsrc(t)
		g.live(6, true)
		g.idle(70 * time.Second)
		failed := false
		cursorEncodeFault = func(c *Cursor) error {
			if c.Held != nil && !failed {
				failed = true
				return errDown
			}
			return nil
		}
		t.Cleanup(func() { cursorEncodeFault = nil })
		g.r.sink.refuse = func(typ string, d map[string]string) bool {
			if typ == EventCoverageGap && d["state"] == "closed" {
				heldAtWrite = cursorNow(t, g.r.cs).Held != nil
			}
			return false
		}
		g.r.pass(10 * time.Second)
		g.send(g.mk(true))
		reason = g.p.end() // store when the node closed it first
		for _, d := range g.gaps() {
			if d["state"] == "closed" {
				closed++
			}
		}
		return g, reason, closed, heldAtWrite
	}
	_, reason, closed, held := run(t)
	if reason != netobs.CloseStore || closed != 1 || !held {
		t.Fatalf("reason %q, %d closed records, the cursor holding the gap at the write %v: want store, one, true", reason, closed, held)
	}
	t.Run("control: the record first", func(t *testing.T) {
		withSeam(t, &gapRecordFirst)
		if _, _, _, held := run(t); held {
			t.Fatal("the control's record was written with the raise saved")
		}
	})
}

// TestGapBoundaries (self-check item 2): each comparison of a time or a
// count in the gap model at its bound. The chain's spacing at exactly
// HeartbeatGapMax passes and 1 ns over fails; its count at exactly the
// length passes and 1 ns of length over fails; a silent gap opens at
// exactly HeartbeatGapMax from W's receipt and not 1 ns before; a link
// gap's open record is due at exactly 60 s from W and not 1 ns before;
// part 2 at both its bounds; a heartbeat read again is not counted again.
func TestGapBoundaries(t *testing.T) {
	blind := DefaultBlindAfter
	at0 := time.Date(2026, 11, 7, 10, 0, 0, 0, time.UTC)
	beat := func(seq int, at time.Time, packets uint64) *netobs.Heartbeat {
		return hbWith(seq, func(h *netobs.Heartbeat) { h.AtUTC = canonUTC(at) }, pk(packets, "up"))
	}
	chainAfter := func(gap time.Duration) bool {
		var s skew
		s.wt.live = map[string]*ifLive{"eth1": {riseAt: at0}}
		s.startChainLocked(nil, beat(1, at0, 100), at0, 0, blind)
		s.extendChainLocked(beat(2, at0.Add(gap), 200), at0.Add(gap), blind)
		return s.wt.ch.ok
	}
	if !chainAfter(HeartbeatGapMax) || chainAfter(HeartbeatGapMax+1) {
		t.Fatal("part 3 at its bound")
	}
	covers := func(length time.Duration) bool {
		var s skew
		cn := &conn{cur: &Cursor{RunID: testRun}}
		s.wt.ch = chain{ok: true, run: testRun, n: 2}
		s.wt.open = &openGap{cause: CauseLink, causes: gapCauseBit(CauseLink)}
		return s.chainCoversLocked(cn, time.Time{}, length)
	}
	if !covers(2*HeartbeatGapMax) || covers(2*HeartbeatGapMax+1) {
		t.Fatal("part 4 at its bound")
	}
	silentAt := func(since time.Duration) bool {
		var s skew
		s.wt.w, s.wt.placed, s.wt.current, s.wt.wRecv = at0, true, true, time.Hour
		return s.silentDueLocked(at0, time.Hour+since)
	}
	if !silentAt(HeartbeatGapMax) || silentAt(HeartbeatGapMax-1) {
		t.Fatal("the silent cause at its bound")
	}
	dueAt := func(since time.Duration) bool {
		var s skew
		s.wt.open = &openGap{from: at0, cause: CauseLink, causes: gapCauseBit(CauseLink), openMono: time.Hour, wMono: time.Hour}
		d, _ := s.nextRecordLocked(at0, time.Hour+since, false)
		return d != nil
	}
	if !dueAt(gapOpenAfter) || dueAt(gapOpenAfter-1) {
		t.Fatal("the open record's 60 s at its bound")
	}
	// Part 2 at both its bounds (D6's M2 on #781, D1's ruling 1): a rise
	// at the heartbeat's own at_utc and one blind before it count; one 1 ns
	// after it, or 1 ns more than blind before it, does not.
	shows := func(rise time.Time) bool {
		h := beat(1, at0, 100)
		return chainShows(h, map[string]*chainIf{"eth1": {rise: rise}}, at0, blind)
	}
	if !shows(at0) || !shows(at0.Add(-blind)) || shows(at0.Add(1)) || shows(at0.Add(-blind-1)) {
		t.Fatal("part 2 at its bounds")
	}
	// A heartbeat read again, as after a save that failed and a resume from
	// before the chain's last seq, is not counted again (D6's M6 on #781).
	var s skew
	s.wt.live = map[string]*ifLive{"eth1": {riseAt: at0}}
	s.startChainLocked(nil, beat(1, at0, 100), at0, 0, blind)
	two := beat(2, at0.Add(10*time.Second), 200)
	s.extendChainLocked(two, at0.Add(10*time.Second), blind)
	s.extendChainLocked(two, at0.Add(10*time.Second), blind)
	if s.wt.ch.n != 2 || !s.wt.ch.ok {
		t.Fatalf("chain %+v, want two heartbeats counted", s.wt.ch)
	}
}

// TestGapChainClockBack (D6's B1 on #781, D1's ruling 1; D6's probe PA):
// CH-39 part 2 counts a rise only at or before the heartbeat's own
// at_utc, and part 3 fails the chain when at_utc falls back. PA is V-17's
// fourth case, ten heartbeats rising, 42 flat and ten rising in one cut,
// with the sensor's clock stepped back five minutes just before the flat
// stretch: closed unwatched. Control: both parts read signed, which
// closes it as covered. Each one-line change is the control of a case of
// its own: the step inside a cut whose counts keep rising, where part 3
// alone fails the chain (control: at_utc let fall back); and the step just
// before W's heartbeat, which is flat, then rising through the cut, where
// part 2 alone fails it at W (control: part 2 read signed).
func TestGapChainClockBack(t *testing.T) {
	pa := func(t *testing.T) *gsrc {
		g := newGsrc(t)
		g.live(6, true)
		g.cut()
		g.buffer(10, true)
		g.ahead -= 5 * time.Minute // the sensor's clock alone
		g.buffer(42, false)
		g.buffer(10, true)
		g.reconnect(false)
		g.live(3, true)
		return g
	}
	if g := pa(t); g.lastGap() == nil || g.anyCovered() {
		t.Fatalf("records %v, want closed unwatched", g.gaps())
	}
	t.Run("control: both parts signed", func(t *testing.T) {
		withSeams(t, &gapChainSignedRise, &gapChainFallBackOK)
		if g := pa(t); !g.anyCovered() {
			t.Fatalf("records %v: the control did not close it as covered", g.gaps())
		}
	})
	rising := func(t *testing.T) *gsrc {
		g := newGsrc(t)
		g.live(6, true)
		g.cut()
		g.buffer(10, true)
		g.ahead -= 5 * time.Minute
		g.buffer(52, true)
		g.reconnect(false)
		g.live(3, true)
		return g
	}
	t.Run("part 3: the step with the counts rising", func(t *testing.T) {
		if g := rising(t); g.lastGap() == nil || g.anyCovered() {
			t.Fatalf("records %v, want closed unwatched", g.gaps())
		}
		t.Run("control: at_utc let fall back", func(t *testing.T) {
			withSeam(t, &gapChainFallBackOK)
			if g := rising(t); !g.anyCovered() {
				t.Fatalf("records %v: the control did not close it as covered", g.gaps())
			}
		})
	})
	atW := func(t *testing.T) *gsrc {
		g := newGsrc(t)
		g.live(6, true)
		g.ahead -= 2 * time.Minute
		g.live(1, false) // W's heartbeat: its last rise lies after its at_utc
		g.cut()
		g.buffer(20, true)
		g.reconnect(false)
		g.live(3, true)
		return g
	}
	t.Run("part 2: the step before W's heartbeat", func(t *testing.T) {
		if g := atW(t); g.lastGap() == nil || g.anyCovered() {
			t.Fatalf("records %v, want closed unwatched", g.gaps())
		}
		t.Run("control: part 2 signed", func(t *testing.T) {
			withSeam(t, &gapChainSignedRise)
			if g := atW(t); !g.anyCovered() {
				t.Fatalf("records %v: the control did not close it as covered", g.gaps())
			}
		})
	})
}

// TestGapLockReleasedAtPanic (D6's N1 on #781): a panic while a heartbeat
// is placed leaves gmu free, so SensorFailed, the end of a connection and
// the tick still run. Here the heartbeat is nil, which panics in place.
func TestGapLockReleasedAtPanic(t *testing.T) {
	g := newGsrc(t)
	g.live(6, true)
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("no panic")
			}
		}()
		_ = g.r.l.placeAndAct(bg, &conn{}, nil, false)
	}()
	if !g.r.l.gmu.TryLock() {
		t.Fatal("gmu held after the panic")
	}
	g.r.l.gmu.Unlock()
	g.r.l.SensorFailed(bg)
	if d := g.openRecord(); d == nil || d["cause"] != CauseSensorFailed {
		t.Fatalf("records %v, want sensor-failed open", g.gaps())
	}
}

// secondSensor is the second sensor of V-6's third case.
const secondSensor = "7a2d3b4c-5e6f-4a71-8b82-a3c4d5e6f708"

// spendLost writes four lost gaps under their budget and leaves a fifth
// waiting for it.
func spendLost(t *testing.T, h *Health) {
	t.Helper()
	span := func(m int) HeldSpan {
		f := time.Date(2026, 11, 7, 9, m, 0, 0, time.UTC)
		return HeldSpan{FromUTC: canonUTC(f), ToUTC: canonUTC(f.Add(time.Minute)), CutUTC: canonUTC(f.Add(time.Minute)), Owed: true}
	}
	for i := range GapLostPerHour {
		if err := h.WriteOwed(bg, Owed{Generation: 2, RunCounter: 5, RunID: testRun, Spans: []HeldSpan{span(2 * i)}}); err != nil {
			t.Fatal(err)
		}
	}
	if err := h.WriteOwed(bg, Owed{Generation: 2, RunCounter: 5, RunID: testRun, Spans: []HeldSpan{span(20)}}); !errors.Is(err, ErrHealthHeld) {
		t.Fatalf("a fifth lost gap: %v, want it waiting", err)
	}
}

// linkOpen is sensor's link gap's open record, nil when none.
func (g *gsrc) linkOpen(sensor string) map[string]string {
	for _, d := range g.r.sink.of(EventCoverageGap) {
		if d["cause"] == CauseLink && d["state"] == "open" && d["sensor_id"] == sensor {
			return d
		}
	}
	return nil
}

// secondOn is a second sensor's link and Health over g's health sink, or,
// for the control, over g's Health.
func secondOn(t *testing.T, g *gsrc, sharedHealth bool) *gsrc {
	r2 := newHealthRig(t)
	r2.sink = g.r.sink
	r2.rig.opt = func(o *Options) {
		r2.h = NewHealth(HealthConfig{SensorID: secondSensor, Sink: r2.sink, Monotonic: r2.clk.mono, Now: r2.now, Raise: o.Raise, File: r2.file})
		if sharedHealth {
			r2.h = g.r.h
		}
		o.Health, o.Owed = r2.h, nil
		o.Timeouts.Idle = r2.idleDeadline()
	}
	r2.rig.restart()
	return &gsrc{t: t, r: r2, p: r2.accepted(live02()), run: testRun, counter: 5, carrier: "up"}
}

// TestHealthRigIdleDeadline (D6's N6 on #788): a link made by newHealthRig,
// and one made by secondOn, runs with the rig's idle deadline, rigIdle,
// not the base rig's 10 s (D1's ruling 9), and rigIdle is longer than it.
func TestHealthRigIdleDeadline(t *testing.T) {
	if base := newRig(t, nil).l.timeouts().Idle; rigIdle <= base {
		t.Fatalf("rigIdle %s, want longer than the base rig's %s", rigIdle, base)
	}
	r := newHealthRig(t)
	if d := r.l.timeouts().Idle; d != rigIdle {
		t.Fatalf("newHealthRig's link: idle %s, want %s", d, rigIdle)
	}
	g := &gsrc{t: t, r: r, p: r.accepted(live02()), run: testRun, counter: 5, carrier: "up"}
	if d := secondOn(t, g, false).r.l.timeouts().Idle; d != rigIdle {
		t.Fatalf("secondOn's link: idle %s, want %s", d, rigIdle)
	}
}

// TestLostGapNotBehindOtherGaps (V-6's third case). The lost budget spent
// within the hour, so a fifth lost record waits; then a link gap of the
// same sensor stands 90 s: its open record is in the health stream within
// 60 s plus one node tick of its open. Control: one budget for every
// cause, which holds it behind the waiting lost record. Second half, in
// platform/sensorlink: a second sensor on the same health sink, its budget
// of the causes other than lost spent and its closing record waiting; a
// link gap of the first sensor that stands 90 s is written open within
// the same bound. Control: the two sensors' records under one Health, so
// one budget, which holds the first sensor's record behind the second's.
func TestLostGapNotBehindOtherGaps(t *testing.T) {
	same := func(t *testing.T) *gsrc {
		g := newGsrc(t)
		g.live(6, true)
		spendLost(t, g.r.h)
		g.cut()
		g.idle(70 * time.Second) // 60 s plus one tick
		return g
	}
	if g := same(t); g.linkOpen(testSensor) == nil {
		t.Fatalf("records %v, want the link gap open", g.gaps())
	}
	t.Run("control: one budget", func(t *testing.T) {
		withSeam(t, &gapOneBudget)
		if g := same(t); g.linkOpen(testSensor) != nil {
			t.Fatalf("records %v: the control wrote the link gap", g.gaps())
		}
	})
	other := func(t *testing.T, shared bool) (*gsrc, *gsrc) {
		g := newGsrc(t)
		g2 := secondOn(t, g, shared)
		g2.live(1, true)
		for range GapOtherPerHour + 1 {
			g2.restartGap()
		}
		g.live(6, true)
		g.cut()
		g.idle(70 * time.Second)
		return g, g2
	}
	t.Run("another sensor's record waits", func(t *testing.T) {
		g, g2 := other(t, false)
		if g2.r.l.GapStatus().Waiting == nil {
			t.Fatal("the second sensor's closing record does not wait")
		}
		if g.linkOpen(testSensor) == nil {
			t.Fatalf("records %v, want the first sensor's link gap open", g.r.sink.of(EventCoverageGap))
		}
		t.Run("control: one Health for both", func(t *testing.T) {
			if g, _ := other(t, true); g.linkOpen(testSensor) != nil {
				t.Fatalf("records %v: the control wrote the first sensor's link gap", g.r.sink.of(EventCoverageGap))
			}
		})
	})
	// The rig's control (D1's ruling 9 on #788): the first sensor's link
	// with an idle deadline shorter than the second sensor's setup, as the
	// base rig's 10 s were on a slow runner. The node closes it idle, and
	// the send the test makes next fails as run 45243152327's did.
	t.Run("control: sensor 1 idle past its deadline", func(t *testing.T) {
		r := newHealthRig(t)
		r.idle = 50 * time.Millisecond
		r.restartNoStart()
		g := &gsrc{t: t, r: r, p: r.accepted(live02()), run: testRun, counter: 5, carrier: "up"}
		g2 := secondOn(t, g, true)
		g2.live(1, true)
		for range GapOtherPerHour + 1 {
			g2.restartGap()
		}
		select {
		case why := <-g.p.done:
			if why != netobs.CloseIdle {
				t.Fatalf("sensor 1's connection closed %q, want %q", why, netobs.CloseIdle)
			}
		case <-time.After(20 * time.Second):
			t.Fatal("sensor 1's connection was not closed idle")
		}
		if err := netobs.WriteFrame(g.p.c, []byte("{}")); !errors.Is(err, io.ErrClosedPipe) {
			t.Fatalf("send: %v, want %v", err, io.ErrClosedPipe)
		}
	})
}

// TestGapMergeIntoCoveredWait (D6's M4 and PK on #781): a link gap written
// open closes as covered while the class refuses its closing record; a
// silent gap then closes unwatched and merges into it: the one record is
// covered false, merged 2.
func TestGapMergeIntoCoveredWait(t *testing.T) {
	g := newGsrc(t)
	g.live(6, true)
	g.cut()
	g.buffer(12, true) // two minutes: written open
	g.r.sink.refuse = func(typ string, d map[string]string) bool { return typ == EventCoverageGap && d["state"] == "closed" }
	g.reconnect(false)
	g.live(3, true)
	if st := g.r.l.GapStatus(); st.Waiting == nil {
		t.Fatalf("gap %+v, want the covered close waiting", st)
	}
	g.idle(2 * time.Minute)
	g.live(3, true)
	g.r.sink.refuse = nil
	g.tick()
	d := g.lastGap()
	if d == nil || d["state"] != "closed" || d["covered"] != "false" || d["merged"] != "2" || d["causes"] != "link silent" {
		t.Fatalf("records %v, want one closed record, covered false, merged 2", g.gaps())
	}
}
