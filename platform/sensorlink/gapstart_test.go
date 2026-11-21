package sensorlink

import (
	"os"
	"testing"
	"time"

	"otsec.local/otsec/contracts/event"
)

// INT-D5 2e-3 (gapstart.go; docs/phase4/D5-sensor-node.md section 1.9 item
// 5; C13 CH-39 part 4, CH-45 "At a start"): the gaps across a node start,
// C8-7's legs V-1, V-9's first, second (the copy's half) and fourth to
// tenth cases, V-10's fourth, V-14's first to third and eighth, and
// V-17's fifth, each with its control; D3's N2 and D6's N5 and N6 on #781.
// Desk only: the in-memory pipe and the rig's test clocks, a test source
// in place of the sensor, and the health stream an in-memory sink. A node
// stop is the connection's end and a new link over the same stores; a
// kill is a new link over the stores as last saved. No sensor produced
// the records and no device was contacted.

// down stops the node: the connection ends, and nothing of the link's
// memory survives but what it saved.
func (g *gsrc) down() { g.t.Helper(); g.cut() }

// up starts the node: a new link and Health over the same stores and run
// file, the file applied and the node-start gap opened.
func (g *gsrc) up() { g.t.Helper(); g.r.restart() }

// away lets n heartbeat intervals pass with the node down, the sensor
// buffering a heartbeat each when it runs. No node tick runs.
func (g *gsrc) away(n int, sensorRuns, rise bool) {
	for range n {
		g.r.pass(10 * time.Second)
		if sensorRuns {
			g.buf = append(g.buf, g.mk(rise))
		}
	}
}

// stepNode steps the node's wall clock by d, the sensor's clock running on.
func (g *gsrc) stepNode(d time.Duration) {
	g.r.addWall(d)
	g.ahead -= d
	g.base -= d
}

// writeFile writes sensorrun.json now, as the node's own writes do.
func (g *gsrc) writeFile() {
	g.t.Helper()
	if err := g.r.h.persistNow(bg); err != nil {
		g.t.Fatal(err)
	}
}

// startGaps is the node-start gap's records.
func (g *gsrc) startGaps() []map[string]string {
	var out []map[string]string
	for _, d := range g.gaps() {
		if d["cause"] == CauseNodeStart {
			out = append(out, d)
		}
	}
	return out
}

// startClosed is the node-start gap's closed record, nil when none.
func (g *gsrc) startClosed() map[string]string {
	for _, d := range g.startGaps() {
		if d["state"] == "closed" {
			return d
		}
	}
	return nil
}

// unpaired is the open records of gaps no later closed record pairs,
// read as CH-45 pairs them: a closed record pairs every open record of
// the sensor written before it and not yet paired whose from_utc equals
// its own. oneOnly pairs a closed record with one open record only (V-14's
// eighth case's control).
func unpaired(recs []map[string]string, oneOnly bool) []map[string]string {
	var open []map[string]string
	for _, d := range recs {
		if d["state"] == "open" {
			open = append(open, d)
			continue
		}
		var keep []map[string]string
		paired := false
		for _, o := range open {
			if o["from_utc"] == d["from_utc"] && !(oneOnly && paired) {
				paired = true
				continue
			}
			keep = append(keep, o)
		}
		open = keep
	}
	return open
}

// TestGapNodeAndSensorStopped (V-1): the node and the sensor stopped
// together for ten minutes, then started: one gap reaches from no later
// than the receipt of the last current heartbeat to the first heartbeat
// after the start that shows capture, unwatched. Second case, the source's
// clock five minutes ahead of the node's: from_utc is still no later than
// that receipt. Controls: a gap that begins at the node's start; and for
// the second case W kept as the heartbeat's at_utc.
func TestGapNodeAndSensorStopped(t *testing.T) {
	run := func(t *testing.T, ahead time.Duration) (*gsrc, time.Time, time.Time) {
		g := newGsrc(t)
		g.ahead, g.base = ahead, ahead
		g.live(6, true)
		last := g.r.now()
		g.down()
		g.away(60, false, false)
		start := g.r.now()
		g.up()
		g.restartSensor()
		g.reconnect(true)
		g.live(2, true)
		return g, last, start
	}
	for _, c := range []struct {
		name    string
		ahead   time.Duration
		control *bool
	}{{"first", 0, &startFromNow}, {"second, the source five minutes ahead", 5 * time.Minute, &placeAtSensor}} {
		t.Run(c.name, func(t *testing.T) {
			g, last, start := run(t, c.ahead)
			d := g.startClosed()
			if d == nil || fromOf(d).After(last) || parseUTC(d["to_utc"]).Before(start) || d["covered"] != "false" {
				t.Fatalf("records %v, want one node-start gap from no later than %s, closed unwatched after %s", g.gaps(), last, start)
			}
			if n := len(unpaired(g.gaps(), false)); n != 0 {
				t.Fatalf("records %v: %d open records unpaired", g.gaps(), n)
			}
			t.Run("control", func(t *testing.T) {
				withSeam(t, c.control)
				g, last, _ := run(t, c.ahead)
				if d := g.startClosed(); d == nil || !fromOf(d).After(last) {
					t.Fatalf("records %v: the control started no later than %s", g.gaps(), last)
				}
			})
		})
	}
}

// TestGapLostDatabaseReachesBack (V-9's first, second and fourth to tenth
// cases; its third and eleventh are TestGapClockStepped).
func TestGapLostDatabaseReachesBack(t *testing.T) {
	// First case: the sensor database deleted while the node and the
	// sensor are stopped for ten minutes: the gap reaches back to no later
	// than the run file's copy, with from_bound. The second case's run-file
	// half: with the file deleted too, to no bound later than the start.
	// Control: a gap that begins at the node's start.
	lost := func(t *testing.T, dropFile bool) (*gsrc, time.Time, time.Time) {
		g := newGsrc(t)
		g.live(6, true)
		g.writeFile()
		cp := parseUTC(runFileCopy(t, g.r.path))
		g.down()
		g.away(60, false, false)
		g.r.loseDatabase()
		if dropFile {
			_ = os.Remove(g.r.path)
		}
		start := g.r.now()
		g.up()
		g.restartSensor()
		g.reconnect(true)
		g.live(2, true)
		return g, cp, start
	}
	g, cp, _ := lost(t, false)
	if d := g.startClosed(); d == nil || fromOf(d).After(cp) || d["from_bound"] != "true" || d["covered"] != "false" {
		t.Fatalf("records %v, want the node-start gap from no later than the copy %s, from_bound", g.gaps(), cp)
	}
	t.Run("control: from the start", func(t *testing.T) {
		withSeam(t, &startFromNow)
		if g, cp, _ := lost(t, false); g.startClosed() == nil || !fromOf(g.startClosed()).After(cp) {
			t.Fatalf("records %v: the control started no later than the copy", g.gaps())
		}
	})
	t.Run("the run file deleted too", func(t *testing.T) {
		g, _, start := lost(t, true)
		if d := g.startClosed(); d == nil || fromOf(d).After(start) || d["from_bound"] != "true" {
			t.Fatalf("records %v, want from no later than the start %s, from_bound", g.gaps(), start)
		}
	})
	// A clock stepped back across the outage, the database kept: written
	// from the saved moment, never dropped, clock_stepped, and
	// time.node-stepped once. Control: a gap dropped when its end is
	// before its start.
	back := func(t *testing.T) (*gsrc, time.Time) {
		g := newGsrc(t)
		g.live(6, true)
		w := g.w()
		g.down()
		g.away(60, false, false)
		g.stepNode(-20 * time.Minute)
		g.up()
		g.restartSensor()
		g.reconnect(true)
		g.live(2, true)
		return g, w
	}
	t.Run("a step back across the outage", func(t *testing.T) {
		g, w := back(t)
		d := g.startClosed()
		if d == nil || !fromOf(d).Equal(w) || d["clock_stepped"] != "true" || !parseUTC(d["to_utc"]).Before(w) {
			t.Fatalf("records %v, want the gap from the saved %s, ending before it, clock_stepped", g.gaps(), w)
		}
		if n := g.r.sink.count(event.HealthTimeNodeStepped); n != 1 {
			t.Fatalf("time.node-stepped %d, want 1", n)
		}
		t.Run("control: dropped for its times", func(t *testing.T) {
			withSeam(t, &gapDropReversed)
			if g, _ := back(t); g.startClosed() != nil {
				t.Fatalf("records %v: the control wrote the closed record", g.gaps())
			}
		})
	})
}

// TestGapStepAcrossStart (V-9's fourth to tenth cases).
func TestGapStepAcrossStart(t *testing.T) {
	steps := func(g *gsrc) int { return g.r.sink.count(event.HealthTimeNodeStepped) }
	// Fourth: a step back of five minutes while the node runs, found at a
	// tick, which writes the run file with the copy moved back; two minutes
	// later the node and the sensor stop, and the database is deleted:
	// from_utc no later than the receipt, on the new clock, of the last
	// current heartbeat. Control: a step that moves nothing back, which
	// writes the copy on the old clock, about three minutes late.
	fourth := func(t *testing.T) (*gsrc, time.Time) {
		g := newGsrc(t)
		g.live(6, true)
		g.writeFile()
		g.live(6, true)
		g.stepNode(-5 * time.Minute)
		g.live(1, true) // its tick finds the step, and writes the run file
		// Nothing else writes the file before the stop (the leg's terms).
		runFileFault = func() error { return errDown }
		t.Cleanup(func() { runFileFault = nil })
		g.live(11, true)
		last := g.r.now()
		g.down()
		runFileFault = nil
		g.away(6, false, false)
		g.r.loseDatabase()
		g.up()
		g.restartSensor()
		g.reconnect(true)
		g.live(2, true)
		return g, last
	}
	t.Run("fourth: a step back while the node runs", func(t *testing.T) {
		g, last := fourth(t)
		if d := g.startClosed(); d == nil || fromOf(d).After(last) || d["from_bound"] != "true" || steps(g) != 1 {
			t.Fatalf("records %v and %d steps, want from_bound from no later than %s and one step", g.gaps(), steps(g), last)
		}
		t.Run("control: nothing moved back", func(t *testing.T) {
			withSeam(t, &stepKeepsOld)
			if g, last := fourth(t); g.startClosed() == nil || !fromOf(g.startClosed()).After(last) {
				t.Fatalf("records %v: the control started no later than %s", g.gaps(), last)
			}
		})
	})
	// Fifth: a silent gap closes unwatched one minute before a step back
	// of five minutes, heartbeats current after it; two minutes after the
	// step the node and the sensor stop and start, the database kept:
	// from_utc no later than the last receipt on the new clock. Control:
	// the floor not moved back, which holds W at it.
	fifth := func(t *testing.T) (*gsrc, time.Time) {
		g := newGsrc(t)
		g.live(6, true)
		g.idle(2 * time.Minute)
		g.ahead = g.base - 25*time.Second
		g.live(1, true)
		g.ahead = g.base
		g.live(6, true)
		g.stepNode(-5 * time.Minute)
		g.live(12, true)
		last := g.r.now()
		g.down()
		g.away(1, false, false)
		g.up()
		g.restartSensor()
		g.reconnect(true)
		g.live(2, true)
		return g, last
	}
	t.Run("fifth: the floor and a step back", func(t *testing.T) {
		g, last := fifth(t)
		if d := g.startClosed(); d == nil || fromOf(d).After(last) {
			t.Fatalf("records %v, want the node-start gap from no later than %s", g.gaps(), last)
		}
		t.Run("control: the floor unmoved", func(t *testing.T) {
			withSeam(t, &stepFloorUnmoved)
			if g, last := fifth(t); g.startClosed() == nil || !fromOf(g.startClosed()).After(last) {
				t.Fatalf("records %v: the control started no later than %s", g.gaps(), last)
			}
		})
	})
	// Sixth: the node alone stopped for one minute, the sensor capturing,
	// its clock stepped back five minutes during the stop; the node-start
	// gap, marked, closes unwatched once the backlog is through, and the
	// connection is reset 30 s after the close: the record carries covered
	// false and clock_stepped, and the link gap starts no later than the
	// last receipt before the reset. Controls: a chain that closes a
	// stepped gap as covered; a floor capped at no point and kept at the
	// later of its value and the close's end.
	sixth := func(t *testing.T) (*gsrc, time.Time, time.Time) {
		g := newGsrc(t)
		g.live(6, true)
		g.down()
		g.away(6, true, true)
		g.stepNode(-5 * time.Minute)
		g.up()
		g.buffer(7, true) // the sensor reconnects 70 s after the start: the gap is written open
		g.reconnect(false)
		g.live(3, true)
		last := g.r.now()
		g.r.pass(10 * time.Second)
		g.cut()
		return g, last, g.r.l.GapStatus().From
	}
	t.Run("sixth: the floor after a step during a stop", func(t *testing.T) {
		g, last, link := sixth(t)
		if d := g.startClosed(); d == nil || d["covered"] != "false" || d["clock_stepped"] != "true" || link.After(last) {
			t.Fatalf("records %v and the link gap from %s, want the start gap unwatched and marked, the link gap from no later than %s", g.gaps(), link, last)
		}
		t.Run("control: the chain closes a stepped gap", func(t *testing.T) {
			withSeam(t, &gapChainIgnoresStep)
			if g, _, _ := sixth(t); g.startClosed() == nil || g.startClosed()["covered"] != "true" {
				t.Fatalf("records %v: the control did not close it as covered", g.gaps())
			}
		})
		t.Run("control: the floor never capped", func(t *testing.T) {
			withSeam(t, &floorNoCap)
			if _, last, link := sixth(t); !link.After(last) {
				t.Fatalf("the link gap from %s: the control started no later than %s", link, last)
			}
		})
	})
	// Seventh: W and R capped. The node and the sensor stop for one minute,
	// the clock stepped back five minutes during the stop; the connection
	// reset 2 s after the receipt of the heartbeat that closes the
	// node-start gap: the link gap starts no later than that receipt.
	// Section 15's control, the floor capped but not W and R, is not
	// committed: the heartbeat that closes a gap unwatched shows capture,
	// so it places W at its receipt in the same step, and the cap of W and
	// R at the close is a second guard that no leg can tell apart (section
	// 1.14).
	g := newGsrc(t)
	g.live(6, true)
	g.down()
	g.away(6, false, false)
	g.stepNode(-5 * time.Minute)
	g.up()
	g.restartSensor()
	g.reconnect(true)
	g.live(1, true)
	closed := g.r.now()
	g.r.pass(2 * time.Second)
	g.cut()
	if link := g.r.l.GapStatus().From; link.IsZero() || link.After(closed) {
		t.Fatalf("seventh: the link gap from %s, want no later than %s", link, closed)
	}
	// Eighth: the wall clock stepped back five minutes 3 s after a
	// heartbeat's receipt, the connection reset 5 s after the step with no
	// tick and no heartbeat between: from_utc no later than that receipt
	// on the new clock, and time.node-stepped once. Controls: the step
	// check at the tick only; W and R moved to the wall clock at the open.
	eighth := func(t *testing.T) (*gsrc, time.Time) {
		g := newGsrc(t)
		g.live(6, true)
		recv := g.r.now()
		g.r.pass(3 * time.Second)
		g.stepNode(-5 * time.Minute)
		g.r.pass(5 * time.Second)
		g.cut()
		g.idle(70 * time.Second)
		return g, recv.Add(-5 * time.Minute)
	}
	t.Run("eighth: a step between two ticks", func(t *testing.T) {
		g, recv := eighth(t)
		if d := g.openRecord(); d == nil || d["cause"] != CauseLink || fromOf(d).After(recv) || steps(g) != 1 {
			t.Fatalf("records %v and %d steps, want the link gap from no later than %s and one step", g.gaps(), steps(g), recv)
		}
		for _, c := range []struct {
			name string
			seam *bool
		}{{"control: the check at the tick only", &stepTickOnly}, {"control: the start at the open", &gapAtOpen}} {
			t.Run(c.name, func(t *testing.T) {
				withSeam(t, c.seam)
				if g, recv := eighth(t); !g.r.l.GapStatus().From.After(recv) {
					t.Fatalf("gap %+v: the control started no later than %s", g.r.l.GapStatus(), recv)
				}
			})
		}
	})
	// Ninth: E's samples. The heartbeats' delay raised to 120 s, then none
	// made while those held are sent; the wall clock stepped back 60 s, 1 s
	// after a tick and 2 s before the receipt of the last held heartbeat,
	// with no tick between: the silent gap from no later than that
	// heartbeat's at_utc + E on the new clock. Control: the samples not
	// moved by the step.
	ninth := func(t *testing.T) (*gsrc, time.Time) {
		g := newGsrc(t)
		g.live(3, true)
		q, lastAt := g.ramp(6, nil)
		for len(q) > 1 {
			g.r.pass(10 * time.Second)
			g.tick()
			q = g.due(q)
		}
		g.r.pass(10 * time.Second)
		g.tick()
		g.r.pass(time.Second)
		g.stepNode(-time.Minute)
		for !q[0].due.Add(-time.Minute).Before(g.r.now().Add(2 * time.Second)) {
			g.r.pass(time.Second)
		}
		g.r.pass(2 * time.Second)
		q = g.due(append(q[:0:0], pend{g.r.now(), q[0].h}))
		for _, d := range []time.Duration{10, 10, 25} {
			g.r.pass(d * time.Second)
			g.tick()
		}
		return g, lastAt.Add(-time.Minute)
	}
	t.Run("ninth: E's samples", func(t *testing.T) {
		g, lastAt := ninth(t)
		if st := g.r.l.GapStatus(); !st.Open || st.From.After(lastAt) {
			t.Fatalf("gap %+v, want silent from no later than %s", st, lastAt)
		}
		t.Run("control: the samples unmoved", func(t *testing.T) {
			withSeam(t, &stepNoSamples)
			if g, lastAt := ninth(t); !g.r.l.GapStatus().From.After(lastAt) {
				t.Fatalf("gap %+v: the control started no later than %s", g.r.l.GapStatus(), lastAt)
			}
		})
	})
	// Tenth: the cap waits for the node-start gap's close. The node and
	// the sensor stop for one minute, the clock stepped back five minutes;
	// the node starts with the sensor still stopped, runs a tick and a
	// cursor save 10 s after the start, and is killed 20 s after it, before
	// the gap is written open; started again with the sensor running: the
	// gap is from the moment saved before the first stop, clock_stepped.
	// Control: W, R and the floor capped at the start and saved.
	tenth := func(t *testing.T) (*gsrc, time.Time) {
		g := newGsrc(t)
		g.live(6, true)
		w := g.w()
		g.down()
		g.away(6, false, false)
		g.stepNode(-5 * time.Minute)
		g.up()
		g.r.pass(10 * time.Second)
		g.tick()
		if err := g.r.l.saveMoved(bg); err != nil {
			t.Fatal(err)
		}
		g.r.pass(10 * time.Second)
		if g.openRecord() != nil {
			t.Fatalf("records %v: written open before the kill", g.gaps())
		}
		g.r.gen.dead.Store(true)
		g.up()
		g.restartSensor()
		g.reconnect(true)
		g.live(2, true)
		return g, w
	}
	t.Run("tenth: the cap waits for the close", func(t *testing.T) {
		g, w := tenth(t)
		if d := g.startClosed(); d == nil || !fromOf(d).Equal(w) || d["clock_stepped"] != "true" {
			t.Fatalf("records %v, want the gap from %s, clock_stepped", g.gaps(), w)
		}
		t.Run("control: capped at the start", func(t *testing.T) {
			withSeam(t, &startCapsAtOnce)
			if g, w := tenth(t); g.startClosed() == nil || fromOf(g.startClosed()).Equal(w) || g.startClosed()["clock_stepped"] == "true" {
				t.Fatalf("records %v: the control kept the gap at %s or marked it", g.gaps(), w)
			}
		})
	})
}

// TestGapNeverBackOpenStart (V-10's fourth case): the node and the sensor
// stop for one minute, the database kept, the clock stepped back five
// minutes during the stop, and the sensor never comes back: within 60 s
// plus one node tick of the start the node-start gap is open in the
// stream, from the saved moment, clock_stepped. Controls: the 60 s
// counted from W on the wall clock alone; the mark only at the cap.
func TestGapNeverBackOpenStart(t *testing.T) {
	run := func(t *testing.T) (*gsrc, time.Time) {
		g := newGsrc(t)
		g.live(6, true)
		w := g.w()
		g.down()
		g.away(6, false, false)
		g.stepNode(-5 * time.Minute)
		g.up()
		g.idle(70 * time.Second)
		return g, w
	}
	g, w := run(t)
	d := g.openRecord()
	if d == nil || d["cause"] != CauseNodeStart || !fromOf(d).Equal(w) || d["clock_stepped"] != "true" {
		t.Fatalf("records %v, want node-start open from %s, clock_stepped", g.gaps(), w)
	}
	t.Run("control: 60 s from W on the wall clock", func(t *testing.T) {
		withSeam(t, &gapOpenWallW)
		if g, _ := run(t); g.openRecord() != nil {
			t.Fatalf("records %v: the control wrote it within 70 s", g.gaps())
		}
	})
	t.Run("control: marked only at the cap", func(t *testing.T) {
		withSeam(t, &startMarkAtCapOnly)
		if g, _ := run(t); g.openRecord() == nil || g.openRecord()["clock_stepped"] == "true" {
			t.Fatalf("records %v: the control marked the open record", g.gaps())
		}
	})
}

// kill ends the node at once: the link's later writes to the stores and
// the stream are refused, and a new link starts over what was saved.
func (g *gsrc) kill() {
	g.t.Helper()
	g.r.gen.dead.Store(true)
	g.up()
}

// TestGapHeldInWStart (V-14's first to third and eighth cases).
func TestGapHeldInWStart(t *testing.T) {
	// First: a link gap whose records are refused past the ceiling, then
	// the sensor's new run read (its hello saves the cursor) and the node
	// restarted: the node-start gap is from the earlier of W and R; and the
	// same with sensorrun.json deleted before the start. Control: W and R
	// moved at the gap's open, which loses its start.
	first := func(t *testing.T, dropFile bool) (*gsrc, time.Time) {
		g := newGsrc(t)
		g.live(6, true)
		w := g.w()
		g.r.sink.refuse = func(typ string, _ map[string]string) bool { return typ == EventCoverageGap }
		g.r.pass(20 * time.Second) // the connection is reset 20 s after W's receipt
		g.cut()
		g.idle(2 * time.Minute)
		g.restartSensor()
		g.p = g.r.dial(enrolment())
		g.send(g.hello(1, true))
		g.down()
		g.r.sink.refuse = nil
		if dropFile {
			_ = os.Remove(g.r.path)
		}
		g.up()
		return g, w
	}
	for _, drop := range []bool{false, true} {
		g, w := first(t, drop)
		if d := g.openRecord(); d == nil || d["cause"] != CauseNodeStart || !fromOf(d).Equal(w) {
			t.Fatalf("first (file deleted %v): records %v, want node-start open from %s", drop, g.gaps(), w)
		}
	}
	t.Run("control: W moved at the open", func(t *testing.T) {
		withSeam(t, &gapWMovesAtOpen)
		if g, w := first(t, false); g.openRecord() == nil || !fromOf(g.openRecord()).After(w) {
			t.Fatalf("records %v: the control started no later than %s", g.gaps(), w)
		}
	})
	// Second: a silent gap from R0 closes unwatched at t1, heartbeats
	// current after it, and the node is killed at each write point from
	// that close to the first cursor save after it: (a) the raise saved,
	// the record refused; (b) the record written, no save since; (c) after
	// the next save. Started with the sensor running: wherever the closed
	// gap is in the stream at least once, the node-start gap is from no
	// earlier than t1, and R0 to t1 is in a gap at every point. Controls:
	// the record before the raise's save, killed between them; the raise
	// saved with no gap held for the floor, killed before the record.
	second := func(t *testing.T, point string) (g *gsrc, r0, t1, start time.Time) {
		g = newGsrc(t)
		g.live(6, true)
		r0 = g.w()
		switch point {
		case "a":
			g.r.sink.refuse = func(typ string, d map[string]string) bool {
				return typ == EventCoverageGap && d["state"] == "closed"
			}
		case "b":
			gen := g.r.gen
			g.r.sink.refuse = func(typ string, d map[string]string) bool {
				if typ == EventCoverageGap && d["state"] == "closed" {
					gen.dead.Store(true) // killed once the record commits
				}
				return false
			}
		}
		g.idle(2 * time.Minute)
		g.ahead = g.base - 25*time.Second
		g.live(1, true)
		t1 = g.r.now()
		if point == "c" {
			g.ahead = g.base
			g.live(1, true)
		}
		g.ahead = g.base
		g.kill()
		start = g.r.l.GapStatus().From
		g.r.sink.refuse = nil
		g.reconnect(false)
		g.live(2, true)
		return g, r0, t1, start
	}
	covers := func(g *gsrc, r0, t1 time.Time) bool {
		for _, d := range g.gaps() {
			if d["state"] == "closed" && !fromOf(d).After(r0) && !parseUTC(d["to_utc"]).Before(t1) {
				return true
			}
		}
		return false
	}
	for _, point := range []string{"a", "b", "c"} {
		g, r0, t1, start := second(t, point)
		if !covers(g, r0, t1) || start.Before(t1) {
			t.Fatalf("second, point %s: records %v and the start gap from %s, want R0 %s to t1 %s closed in the stream and the start gap from no earlier than t1", point, g.gaps(), start, r0, t1)
		}
	}
	t.Run("control: the record first", func(t *testing.T) {
		withSeam(t, &gapRecordFirst)
		if _, _, t1, start := second(t, "b"); !start.Before(t1) {
			t.Fatalf("the start gap from %s: the control started it no earlier than %s", start, t1)
		}
	})
	t.Run("control: no gap held for the floor", func(t *testing.T) {
		withSeam(t, &raiseNoHeld)
		if g, r0, t1, _ := second(t, "a"); covers(g, r0, t1) {
			t.Fatalf("records %v: the control kept R0 to t1 in a gap", g.gaps())
		}
	})
	// Third: the copy while a gap is held for the floor. The same close,
	// sensorrun.json written (1) between the raise and its save, the save
	// failing, or (2) between the save and the record's commit, the record
	// refused; the node killed, the database deleted: the node-start gap
	// from no later than R0. And at (2) with the wall clock stepped back by
	// more than the time since R0 before the write: no later than R0 moved
	// back by the step. Controls: the copy as the earlier of W and R alone;
	// the held start counted only from the raise's save; and for the step,
	// no hold on the copy's rising.
	third := func(t *testing.T, point int, step time.Duration) (*gsrc, time.Time) {
		g := newGsrc(t)
		g.live(6, true)
		g.writeFile()
		r0 := g.w()
		g.r.sink.refuse = func(typ string, d map[string]string) bool {
			return typ == EventCoverageGap && d["state"] == "closed"
		}
		g.idle(2 * time.Minute)
		if point == 1 {
			g.r.gen.beforeSave = func() { g.r.gen.dead.Store(true) } // the raise's save fails
		}
		g.ahead = g.base - 25*time.Second
		g.send(g.mk(true)) // the close; its tick ran before
		if step != 0 {
			g.stepNode(step)
		}
		g.r.gen.beforeSave = nil
		g.r.gen.dead.Store(false)
		g.writeFile()
		g.r.gen.dead.Store(true) // killed before the record's commit
		g.r.sink.refuse = nil
		g.r.loseDatabase()
		g.up()
		g.restartSensor()
		g.reconnect(true)
		g.live(2, true)
		return g, r0.Add(step)
	}
	for _, point := range []int{1, 2} {
		g, r0 := third(t, point, 0)
		if d := g.startClosed(); d == nil || fromOf(d).After(r0) {
			t.Fatalf("third, point %d: records %v, want the start gap from no later than R0 %s", point, g.gaps(), r0)
		}
	}
	t.Run("control: the copy W and R alone", func(t *testing.T) {
		withSeam(t, &copyHeldIgnored)
		for _, point := range []int{1, 2} {
			if g, r0 := third(t, point, 0); g.startClosed() == nil || !fromOf(g.startClosed()).After(r0) {
				t.Fatalf("point %d: records %v: the control started no later than R0", point, g.gaps())
			}
		}
	})
	t.Run("control: held only from the raise's save", func(t *testing.T) {
		withSeam(t, &copyHeldFromSave)
		if g, r0 := third(t, 1, 0); g.startClosed() == nil || !fromOf(g.startClosed()).After(r0) {
			t.Fatalf("records %v: the control started no later than R0", g.gaps())
		}
	})
	t.Run("a step before the write", func(t *testing.T) {
		g, r0 := third(t, 2, -5*time.Minute)
		if d := g.startClosed(); d == nil || fromOf(d).After(r0) {
			t.Fatalf("records %v, want the start gap from no later than R0 moved back, %s", g.gaps(), r0)
		}
		t.Run("control: no hold on the copy", func(t *testing.T) {
			withSeam(t, &copyNoHold)
			if g, r0 := third(t, 2, -5*time.Minute); g.startClosed() == nil || !fromOf(g.startClosed()).After(r0) {
				t.Fatalf("records %v: the control started no later than %s", g.gaps(), r0)
			}
		})
	})
	// Eighth: two open records of one from_utc across a node stop. A link
	// gap written open and still open when the node stops for one minute,
	// the sensor running; the node-start gap opens from the same moment and
	// is written open; its close pairs both. Control: a reader that pairs a
	// closed record with one open record only.
	g := newGsrc(t)
	g.live(6, true)
	g.cut()
	g.buffer(9, true)
	g.away(6, true, true)
	g.up()
	g.reconnect(false)
	g.live(3, true)
	gs := g.gaps()
	if len(gs) != 3 || gs[0]["cause"] != CauseLink || gs[1]["cause"] != CauseNodeStart || gs[0]["from_utc"] != gs[1]["from_utc"] || gs[2]["state"] != "closed" || len(unpaired(gs, false)) != 0 {
		t.Fatalf("eighth: records %v, want two open records of one from_utc and a closed record pairing both", gs)
	}
	if len(unpaired(gs, true)) != 1 {
		t.Fatalf("eighth: the control reader paired both")
	}
}

// TestGapFlatCountsCarrierUpStart (V-17's fifth case): every interface
// flat from four minutes before W, the link cut at W, the node alone
// restarted inside the cut, flat until two minutes after W, then rising,
// ten minutes in all: the gap closes unwatched, from no later than R.
// Controls: a chain that looks back only to its own first heartbeat,
// which closes it as covered; a gap from W, four minutes late.
func TestGapFlatCountsCarrierUpStart(t *testing.T) {
	run := func(t *testing.T) (*gsrc, time.Time, time.Time) {
		g := newGsrc(t)
		g.live(6, true)
		_, rr := g.r.l.watchNow()
		g.live(24, false)
		w := g.w()
		g.down()
		g.away(3, true, false)
		g.up()
		g.buffer(9, false)
		g.buffer(48, true)
		g.reconnect(false)
		g.live(3, true)
		return g, rr, w
	}
	g, rr, _ := run(t)
	if d := g.startClosed(); d == nil || d["covered"] != "false" || fromOf(d).After(rr) || g.anyCovered() {
		t.Fatalf("records %v, want the start gap closed unwatched from no later than R %s", g.gaps(), rr)
	}
	t.Run("control: the chain from its own first heartbeat", func(t *testing.T) {
		withSeam(t, &gapChainFromFirst)
		if g, _, _ := run(t); !g.anyCovered() {
			t.Fatalf("records %v: the control did not close it as covered", g.gaps())
		}
	})
	t.Run("control: from W", func(t *testing.T) {
		withSeam(t, &gapFromW)
		if g, _, w := run(t); g.startClosed() == nil || !fromOf(g.startClosed()).Equal(w) {
			t.Fatalf("records %v: the control did not start it at W %s", g.gaps(), w)
		}
	})
}

// TestGapStartRules: what 2e-3 owes from the reviews of #774 and #781.
func TestGapStartRules(t *testing.T) {
	// D3's N2 on #781: after a start, the link current and every interface
	// flat, the node-start gap stays open with blind added. Control: no
	// node-start gap (2e-2's state), which opens nothing.
	flat := func(t *testing.T) *gsrc {
		g := newGsrc(t)
		g.live(6, true)
		g.down()
		g.away(6, true, false)
		g.up()
		g.reconnect(false)
		g.live(6, false)
		return g
	}
	g := flat(t)
	if st := g.r.l.GapStatus(); !st.Open || st.Cause != CauseNodeStart || st.Causes != "node-start blind" {
		t.Fatalf("flat after a start: gap %+v, want node-start open with blind", st)
	}
	t.Run("control: no node-start gap", func(t *testing.T) {
		withSeam(t, &startGapOff)
		if st := flat(t).r.l.GapStatus(); st.Open {
			t.Fatalf("gap %+v: the control opened a gap", st)
		}
	})
	// D6's N6 and D4's N2 on #781: frozen clears when the node-start gap
	// closes, however it closes. The node alone stopped for a minute, the
	// sensor capturing: the gap closes as covered by a chain across the
	// start (CH-39 part 4), and W moves again. Control: frozen cleared
	// only at an unwatched close.
	covered := func(t *testing.T) (*gsrc, time.Time) {
		g := newGsrc(t)
		g.live(6, true)
		w := g.w()
		g.down()
		g.away(6, true, true)
		g.up()
		g.reconnect(false)
		g.live(3, true)
		return g, w
	}
	g, w := covered(t)
	if d := g.startClosed(); d == nil || d["covered"] != "true" || g.r.l.GapStatus().Open || !g.w().After(w) {
		t.Fatalf("covered start: records %v and W %s, want closed as covered and W past %s", g.gaps(), g.w(), w)
	}
	t.Run("control: frozen cleared only unwatched", func(t *testing.T) {
		withSeam(t, &frozenUnwatchedOnly)
		if g, w := covered(t); !g.w().Equal(w) {
			t.Fatalf("W %s: the control moved W from %s", g.w(), w)
		}
	})
	// D6's N5 on #781: a run whose first heartbeat read here was not
	// accepted as new here, its names not those kept with W, keeps every
	// name's rise_utc at the epoch until its own packets rise. Control: a
	// name's rise kept as the heartbeat it was first seen in.
	epoch := func(t *testing.T) *Cursor {
		g := newGsrc(t)
		g.live(6, true)
		g.down()
		g.away(1, false, false)
		g.up()
		g.twoIf("up")
		g.reconnect(false)
		g.live(2, true)
		g.down()
		return cursorNow(t, g.r.cs)
	}
	c := epoch(t)
	if len(c.Ifaces) != 2 || !c.Ifaces[1].RiseUTC.Equal(time.Unix(0, 0)) {
		t.Fatalf("kept %+v, want eth2's rise at the epoch", c.Ifaces)
	}
	t.Run("control: the rise at first sight", func(t *testing.T) {
		withSeam(t, &gapRiseFirstSeen)
		if c := epoch(t); len(c.Ifaces) != 2 || c.Ifaces[1].RiseUTC.Equal(time.Unix(0, 0)) {
			t.Fatalf("kept %+v: the control kept eth2's rise at the epoch", c.Ifaces)
		}
	})
	// D3's N3 on #774, its 2e-3 half (D4-122 item 3.3): a copy later than
	// the wall clock, from a step during the stop, is capped before it
	// serves: the gap from no later than the start, marked clock_stepped.
	// Control: the copy taken as it is.
	capped := func(t *testing.T) (*gsrc, time.Time) {
		g := newGsrc(t)
		g.live(6, true)
		g.writeFile()
		g.down()
		g.away(6, false, false)
		g.stepNode(-10 * time.Minute)
		g.r.loseDatabase()
		start := g.r.now()
		g.up()
		return g, start
	}
	g, start := capped(t)
	if st := g.r.l.GapStatus(); !st.Open || st.From.After(start) || !st.Stepped {
		t.Fatalf("a copy later than the clock: gap %+v, want from no later than %s, marked", st, start)
	}
	g.idle(20 * time.Second)
	if n := g.r.sink.count(event.HealthTimeNodeStepped); n != 1 {
		t.Fatalf("time.node-stepped %d for the copy's cap, want 1", n)
	}
	t.Run("control: the copy uncapped", func(t *testing.T) {
		withSeam(t, &startCopyUncapped)
		if g, start := capped(t); !g.r.l.GapStatus().From.After(start) {
			t.Fatalf("gap %+v: the control started no later than %s", g.r.l.GapStatus(), start)
		}
	})
}

// TestGapStartBoundaries (self-check items 2 and 3): each comparison of
// the start at its bound, and the start with what it reads failing.
func TestGapStartBoundaries(t *testing.T) {
	at0 := time.Date(2026, 11, 7, 10, 0, 0, 0, time.UTC)
	mono := time.Hour
	start := func(w, copyAt time.Time) *openGap {
		var s skew
		s.wt.w, s.wt.r = w, w
		s.startGapLocked(copyAt, at0, mono, DefaultBlindAfter)
		return s.wt.open
	}
	// The copy capped only when later than the wall clock, and marked.
	if g := start(time.Time{}, at0); !g.from.Equal(at0) || g.stepped || !g.bound {
		t.Fatalf("a copy at the wall clock: %+v", g)
	}
	if g := start(time.Time{}, at0.Add(1)); !g.from.Equal(at0) || !g.stepped {
		t.Fatalf("a copy 1 ns later than the wall clock: %+v", g)
	}
	// W marked only when later than the wall clock.
	if g := start(at0, time.Time{}); g.stepped || g.bound {
		t.Fatalf("W at the wall clock: %+v", g)
	}
	if g := start(at0.Add(1), time.Time{}); !g.stepped {
		t.Fatalf("W 1 ns later than the wall clock: %+v", g)
	}
	// The open record due at once when W is gapOpenAfter old, not 1 ns
	// less.
	due := func(age time.Duration) bool {
		var s skew
		s.wt.w, s.wt.r = at0.Add(-age), at0.Add(-age)
		s.startGapLocked(time.Time{}, at0, mono, DefaultBlindAfter)
		d, _ := s.nextRecordLocked(at0, mono, false)
		return d != nil
	}
	if !due(gapOpenAfter) || due(gapOpenAfter-1) {
		t.Fatal("the open record's 60 s from W across a start, at its bound")
	}
	// Part 2 at W across a start: a rise kept blind before W's at_utc, or
	// at it, shows; 1 ns earlier, or 1 ns after it, does not.
	shown := func(rise time.Time) bool {
		var s skew
		s.wt.w, s.wt.wAt, s.wt.run = at0, at0, testRun
		s.wt.kept = []IfaceMark{{Packets: 100, RiseUTC: rise}}
		s.startGapLocked(time.Time{}, at0, mono, DefaultBlindAfter)
		return s.wt.ch.ok
	}
	if !shown(at0) || !shown(at0.Add(-DefaultBlindAfter)) || shown(at0.Add(-DefaultBlindAfter-1)) || shown(at0.Add(1)) {
		t.Fatal("part 2 at W across a start, at its bounds")
	}
	// The run file unreadable at the start: no copy, so the gap reaches
	// back to no bound later than the start, from_bound.
	g := newGsrc(t)
	g.live(6, true)
	g.down()
	g.away(6, false, false)
	g.r.loseDatabase()
	if err := os.WriteFile(g.r.path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	at := g.r.now()
	g.r.restartNoStart()
	_ = g.r.file.Start(bg, g.r.l) // it reports the file unreadable
	if st := g.r.l.GapStatus(); !st.Open || st.From.After(at) {
		t.Fatalf("an unreadable run file: gap %+v, want from no later than %s", st, at)
	}
	// The cursor unreadable at the start: no W, so the gap reaches back to
	// the run file's copy, from_bound.
	g = newGsrc(t)
	g.live(6, true)
	g.writeFile()
	cp := parseUTC(runFileCopy(t, g.r.path))
	g.down()
	g.away(6, false, false)
	if err := g.r.cs.SaveSourceCursor(bg, []byte("sp2 unreadable")); err != nil {
		t.Fatal(err)
	}
	g.r.restartNoStart()
	_ = g.r.file.Start(bg, g.r.l)
	if st := g.r.l.GapStatus(); !st.Open || st.From.After(cp) {
		t.Fatalf("an unreadable cursor: gap %+v, want from no later than the copy %s", st, cp)
	}
}
