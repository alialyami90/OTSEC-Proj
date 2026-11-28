package sensorlink

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"otsec.local/otsec/contracts/event"
	"otsec.local/otsec/contracts/netobs"
)

// P4-NODE-PASTCAP (blind.go, gapstart.go; C13 CH-44, CH-45;
// docs/phase4/D5-sensor-node.md sections 1.8, 1.9 item 5 and 1.14): D6's
// B2 and N1 on #804 and its 7230756917 there, and D6's N8 on #788 under
// option (b). Desk only: the in-memory pipe and the rig's test clocks, a
// test source in place of the sensor, the health stream an in-memory sink.
// No sensor produced the records and no device was contacted.

// ifRange is n interface names from if<first>, two digits each.
func ifRange(first, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("if%02d", first+i)
	}
	return out
}

// D6's B2 on #804, its probe P1 as a committed test: six live heartbeats,
// a cut, then three backlog heartbeats of the same run naming if00 to
// if07, if08 to if15 and if16 to if23, carrier down and their packets
// summing to counters.packets, then one naming eth1 again, the resume and
// three live heartbeats. One sensor.past-blind, naming MaxInterfaces
// interfaces and counting the other 17 (16 ifNN and eth1, first seen in
// the stretch). Control: the open stretch uncapped, as pastLocked was at
// 5e5c8028 (25 names and no count).
func TestBlindPastNamesCapped(t *testing.T) {
	run := func(t *testing.T) string {
		g := newGsrc(t)
		g.live(6, true)
		g.cut()
		for i := range 3 {
			names := ifRange(8*i, 8)
			g.f = func(h *netobs.Heartbeat) {
				ifs(names, []uint64{100, 100, 100, 100, 100, 100, 100, 100})(h)
				for j := range h.Interfaces {
					h.Interfaces[j].Carrier = "down"
				}
			}
			g.buffer(1, false)
		}
		g.f, g.pk = nil, 1000 // eth1 again, counters.packets above the 800 before
		g.buffer(1, true)
		g.reconnect(false)
		g.live(3, true)
		ev := g.events(EventPastBlind)
		if len(ev) != 1 {
			t.Fatalf("past-blind events %v, want one", ev)
		}
		return ev[0]["detail"]
	}
	d := run(t)
	if !strings.Contains(d, "if07, and 17 more not listed") || strings.Contains(d, "if08") || strings.Contains(d, "eth1") {
		t.Fatalf("detail %q, want if00 to if07 named and 17 more counted", d)
	}
	t.Run("control: the open stretch uncapped", func(t *testing.T) {
		withSeam(t, &pastNamesUncapped)
		if d := run(t); !strings.Contains(d, "if23") || strings.Contains(d, "more not listed") {
			t.Fatalf("the control capped the detail %q", d)
		}
	})
}

// D6's 7230756917 on #804: a name past the cap is counted once a run, not
// once a stretch. In one run, three stretches end in one backlog: if00 to
// if07, then if08, then if08 again: eight names and one more. A stretch of
// a new run that names if08 counts it again (each once a run, as
// sensor-blind's over and overPrev). Control: endPastLocked as at
// 5e5c8028, which counts if08 once for each merged stretch (two in the
// first run).
func TestBlindPastCountOnceARun(t *testing.T) {
	run := func() (first, second *pastStretch) {
		b := &blindState{}
		at := t0
		// hb is one heartbeat that is not current, read in a backlog: the
		// names in down with carrier down, the rest up, every packets risen.
		hb := func(r string, names, down []string) {
			by := map[string]netobs.InterfaceCount{}
			for _, n := range names {
				by[n] = netobs.InterfaceCount{Name: n, Carrier: "up", Packets: uint64(at.Unix())}
			}
			for _, n := range down {
				by[n] = netobs.InterfaceCount{Name: n, Carrier: "down", Packets: uint64(at.Unix())}
			}
			b.pastLocked(r, names, by, at, 5*time.Minute, false, true)
			at = at.Add(10 * time.Second)
		}
		all := ifRange(0, 9)
		hb("run1", all, nil) // the run's first heartbeat: every name a baseline
		for _, down := range [][]string{ifRange(0, 8), ifRange(8, 1), ifRange(8, 1)} {
			hb("run1", all, down) // a stretch
			hb("run1", all, nil)  // none past-blind: it ends
		}
		first = &pastStretch{}
		*first = *b.pend
		hb("run2", ifRange(8, 1), ifRange(8, 1)) // a new run, if08 down
		b.endPastLocked()
		return first, b.pend
	}
	first, second := run()
	if len(first.names) != netobs.MaxInterfaces || first.more() != 1 || first.n != 3 {
		t.Fatalf("one run: %+v, want %d names, 1 more, 3 stretches", first, netobs.MaxInterfaces)
	}
	if second.more() != 2 {
		t.Fatalf("a second run: %+v, want 2 more", second)
	}
	t.Run("control: once for each merged stretch", func(t *testing.T) {
		withSeam(t, &pastCountEachStretch)
		if first, _ := run(); first.more() != 2 {
			t.Fatalf("the control counted %d more, want 2", first.more())
		}
	})
}

// D6's N1 on #804: the 60 s check at a late heartbeat, with no tick and no
// other frame. Six live heartbeats, then 240 s of heartbeats queued and
// nothing sent; the first of them, made 230 s before it is read and so
// later than late_bound_s, raises sensor-no-heartbeat and shows coverage
// unknown. Control: the mutant if !current && !late (noHbNotAtLate), which
// raises nothing.
func TestBlindNoHeartbeatAtLate(t *testing.T) {
	run := func(t *testing.T) *gsrc {
		g := newGsrc(t)
		g.live(6, true)
		g.queue(24, true)
		if n := g.r.al.count(AlarmNoHeartbeat); n != 0 {
			t.Fatalf("%d sensor-no-heartbeat before the late heartbeat", n)
		}
		late := g.r.l.SkewStats().Late
		g.send(g.buf[0])
		if g.r.l.SkewStats().Late != late+1 {
			t.Fatal("the heartbeat was not late")
		}
		return g
	}
	if g := run(t); g.r.al.count(AlarmNoHeartbeat) != 1 || !g.r.l.BlindStatus().CoverageUnknown {
		t.Fatalf("%v, coverage unknown %v; want sensor-no-heartbeat and coverage unknown", g.r.al.list, g.r.l.BlindStatus().CoverageUnknown)
	}
	t.Run("control: no check at a late heartbeat", func(t *testing.T) {
		withSeam(t, &noHbNotAtLate)
		if g := run(t); g.r.al.count(AlarmNoHeartbeat) != 0 {
			t.Fatal("the control raised it")
		}
	})
}

// TestGapCopyCapNoW (D6's N8 on #788, option (b); D3's condition,
// 7230895738 on #805): a start with no W whose copy is later than its wall
// clock opens the node-start gap from the epoch, from_bound and
// clock_stepped, and writes the epoch as the copy. Each leg's gap starts no
// later than the receipt, on the clock as it now is, of the last current
// heartbeat, last.
//   - N8's path: a step back of five minutes found at a tick, its record
//     written and the run file's write failing, as a kill between them
//     leaves it; the node stops for a minute and starts with the database
//     lost. Control: startCapFromWall, the code at 5e5c8028, which opens it
//     at the start, later than last.
//   - The wider case: the clock stepped back ten minutes while the node is
//     stopped for a minute, the database lost. Control: startCapFromWall.
//   - The kill after a refused open record: the wider case with the
//     ceiling refusing the start's open record, then a kill and a second
//     start, which serves the copy the first wrote. Control:
//     startCopyAtWall, the copy at the first start's wall clock, from
//     which the second start opens unmarked, later than last.
func TestGapCopyCapNoW(t *testing.T) {
	n8 := func(t *testing.T) (*gsrc, time.Time) {
		g := newGsrc(t)
		g.live(6, true)
		g.writeFile()
		g.live(6, true)
		runFileFault = func() error { return errDown }
		t.Cleanup(func() { runFileFault = nil })
		g.stepNode(-5 * time.Minute)
		g.live(1, true) // its tick finds the step: the record, then the file fails
		last := g.r.now()
		if n := g.r.sink.count(event.HealthTimeNodeStepped); n != 1 {
			t.Fatalf("time.node-stepped %d at the tick, want 1", n)
		}
		g.down()
		runFileFault = nil
		g.away(6, false, false)
		g.r.loseDatabase()
		g.up()
		return g, last
	}
	wider := func(t *testing.T) (*gsrc, time.Time) {
		g := newGsrc(t)
		g.live(6, true)
		g.writeFile()
		last := g.r.now().Add(-10 * time.Minute)
		g.down()
		g.away(6, false, false)
		g.stepNode(-10 * time.Minute)
		g.r.loseDatabase()
		g.up()
		return g, last
	}
	refused := func(t *testing.T) (*gsrc, time.Time) {
		g := newGsrc(t)
		g.live(6, true)
		g.writeFile()
		last := g.r.now().Add(-10 * time.Minute)
		g.down()
		g.away(6, false, false)
		g.stepNode(-10 * time.Minute)
		g.r.loseDatabase()
		g.r.sink.refuse = func(typ string, _ map[string]string) bool { return typ == EventCoverageGap }
		g.up()
		if g.openRecord() != nil || g.r.l.GapStatus().Written {
			t.Fatalf("records %v, gap %+v: want the open record refused", g.gaps(), g.r.l.GapStatus())
		}
		g.r.sink.refuse = nil
		g.r.pass(20 * time.Second)
		g.kill()
		return g, last
	}
	epoch := time.Unix(0, 0)
	for _, c := range []struct {
		name    string
		run     func(*testing.T) (*gsrc, time.Time)
		control *bool
	}{{"N8's path", n8, &startCapFromWall}, {"a step back while stopped", wider, &startCapFromWall}, {"a kill after a refused open record", refused, &startCopyAtWall}} {
		t.Run(c.name, func(t *testing.T) {
			g, last := c.run(t)
			st := g.r.l.GapStatus()
			if !st.Open || st.Cause != CauseNodeStart || !st.From.Equal(epoch) || !st.From.Before(last) {
				t.Fatalf("gap %+v, want node-start open from the epoch, before %s", st, last)
			}
			if got := runFileCopy(t, g.r.path); !parseUTC(got).Equal(epoch) {
				t.Fatalf("the run file's copy %q, want the epoch", got)
			}
			if c.control != &startCopyAtWall {
				if d := g.openRecord(); d == nil || d["from_bound"] != "true" || d["clock_stepped"] != "true" || !fromOf(d).Equal(epoch) {
					t.Fatalf("records %v, want open from the epoch, from_bound and clock_stepped, at the start", g.gaps())
				}
			}
			t.Run("control", func(t *testing.T) {
				withSeam(t, c.control)
				if g, last := c.run(t); !g.r.l.GapStatus().From.After(last) {
					t.Fatalf("gap %+v: the control started no later than %s", g.r.l.GapStatus(), last)
				}
			})
		})
	}
}
