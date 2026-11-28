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
			} else if d := g.openRecord(); d == nil || d["from_bound"] != "true" || !fromOf(d).Equal(epoch) {
				// D3's N2 on #806: the second start serves the epoch copy,
				// no later than its wall clock: from the bound, marked so.
				t.Fatalf("records %v, want the second start's open from the epoch, from_bound", g.gaps())
			}
			t.Run("control", func(t *testing.T) {
				withSeam(t, c.control)
				if g, last := c.run(t); !g.r.l.GapStatus().From.After(last) {
					t.Fatalf("gap %+v: the control started no later than %s", g.r.l.GapStatus(), last)
				}
			})
		})
	}

	// D3's N1 and D6's N3 (P5) on #806: a step back of five minutes found
	// at a tick 10 s after the wider case's start, while its gap from the
	// epoch stands, and the run file written: the copy stays the epoch, and
	// a kill and a start with the database lost open the gap from it.
	// Control: the copy moved by the step unclamped, before 1970.
	step := func(t *testing.T) (string, GapStatus) {
		g, _ := wider(t)
		g.r.pass(10 * time.Second)
		g.stepNode(-5 * time.Minute)
		g.tick()
		cp := runFileCopy(t, g.r.path)
		g.r.gen.dead.Store(true)
		g.r.loseDatabase()
		g.up()
		return cp, g.r.l.GapStatus()
	}
	t.Run("a step found while the gap stands", func(t *testing.T) {
		cp, st := step(t)
		if !parseUTC(cp).Equal(epoch) || !st.Open || !st.From.Equal(epoch) {
			t.Fatalf("copy %q, gap %+v: want both the epoch", cp, st)
		}
		t.Run("control: the copy moved before the epoch", func(t *testing.T) {
			withSeam(t, &copyBackUnclamped)
			if cp, st := step(t); !parseUTC(cp).Before(epoch) || !st.From.Before(epoch) {
				t.Fatalf("copy %q, gap %+v: the control kept the epoch", cp, st)
			}
		})
	})
}

// D1's ruling 7231553676 on #806 (option (i)), D3's B1 and D6's flood
// probe as a committed test: in one run, 100 heartbeats each naming 8 new
// interfaces, carrier down, read in a backlog (sensor.past-blind) and as
// current (sensor-blind). Each list keeps MaxInterfaces names and
// overBound past them, and marks the rest as not kept; sensor-blind's
// event is due again at each heartbeat that keeps a name and once at the
// first name not kept, then not again. Control: overUnbounded, both lists
// as at 31346346, which keep all 792.
func TestBlindOverBounded(t *testing.T) {
	const hbs = 100
	type out struct {
		past       *pastStretch
		over, dues int
		full       bool
	}
	run := func() out {
		b := &blindState{}
		at, dues := t0, 0
		for i := range hbs {
			names := make([]string, 8)
			by := map[string]netobs.InterfaceCount{}
			for j := range names {
				names[j] = fmt.Sprintf("if%03d", 8*i+j)
				by[names[j]] = netobs.InterfaceCount{Name: names[j], Carrier: "down"}
			}
			b.pastLocked("run1", names, by, at, 5*time.Minute, false, true)
			if _, due, _, _, _ := b.liveLocked("run1", names, by, time.Duration(i)*time.Second, at, 5*time.Minute); due {
				dues++
			}
			at = at.Add(10 * time.Second)
		}
		return out{past: b.open, over: len(b.over), dues: dues, full: b.overFull}
	}
	o := run()
	if len(o.past.names) != netobs.MaxInterfaces || len(o.past.over) != overBound || !o.past.full {
		t.Fatalf("sensor.past-blind keeps %d names and %d past them, full %v; want %d, %d, true", len(o.past.names), len(o.past.over), o.past.full, netobs.MaxInterfaces, overBound)
	}
	// The first heartbeat raises the stretch with 8 names; the next
	// overBound/8 each keep 8 past the cap; the one after's first name is
	// the first not kept.
	if o.over != overBound || !o.full || o.dues != overBound/8+1 {
		t.Fatalf("sensor-blind keeps %d past the cap, full %v, %d events due again; want %d, true, %d", o.over, o.full, o.dues, overBound, overBound/8+1)
	}
	t.Run("control: both lists as at 31346346", func(t *testing.T) {
		withSeam(t, &overUnbounded)
		all := hbs*8 - netobs.MaxInterfaces
		if o := run(); len(o.past.over) != all || o.over != all {
			t.Fatalf("the control kept %d and %d, want %d", len(o.past.over), o.over, all)
		}
	})
}

// D1's ruling on #806: the detail at overBound names past the cap and at
// one more. In one run, MaxInterfaces + k interfaces each blind once, for
// both lists: at k = overBound the detail counts them, "and 64 more not
// listed"; at k = overBound + 1 it says "and more than 64 not listed".
// Control: overUnbounded, which counts the 65th exactly.
func TestBlindOverBoundDetail(t *testing.T) {
	details := func(k int) (past, live string) {
		b := &blindState{}
		at := t0
		var named []string
		var more int
		var full bool
		for i := range netobs.MaxInterfaces + k {
			n := fmt.Sprintf("if%03d", i)
			by := map[string]netobs.InterfaceCount{n: {Name: n, Carrier: "down"}}
			b.pastLocked("run1", []string{n}, by, at, 5*time.Minute, false, true)
			_, _, named, more, full = b.liveLocked("run1", []string{n}, by, time.Duration(i)*time.Second, at, 5*time.Minute)
			at = at.Add(10 * time.Second)
		}
		return nameList(b.open.names, b.open.more(), b.open.full), nameList(named, more, full)
	}
	at := fmt.Sprintf(", and %d more not listed", overBound)
	past := fmt.Sprintf(", and more than %d not listed", overBound)
	for _, c := range []struct {
		k    int
		want string
	}{{overBound, at}, {overBound + 1, past}} {
		if p, l := details(c.k); !strings.HasSuffix(p, c.want) || !strings.HasSuffix(l, c.want) {
			t.Fatalf("at %d past the cap: %q and %q, want both to end %q", c.k, p, l, c.want)
		}
	}
	t.Run("control: both lists as at 31346346", func(t *testing.T) {
		withSeam(t, &overUnbounded)
		want := fmt.Sprintf(", and %d more not listed", overBound+1)
		if p, l := details(overBound + 1); !strings.HasSuffix(p, want) || !strings.HasSuffix(l, want) {
			t.Fatalf("the control gave %q and %q", p, l)
		}
	})
}

// pastHb is one heartbeat that is not current, read in a backlog, at the
// state level, naming down, each with carrier down; pastEnd is a current
// heartbeat, which ends the open stretch, the backlog still on.
func pastHb(b *blindState, at *time.Time, run string, down []string) {
	by := map[string]netobs.InterfaceCount{}
	for _, n := range down {
		by[n] = netobs.InterfaceCount{Name: n, Carrier: "down"}
	}
	b.pastLocked(run, down, by, *at, 5*time.Minute, false, true)
	*at = at.Add(10 * time.Second)
}

func pastEnd(b *blindState, at *time.Time, run string) {
	b.pastLocked(run, nil, nil, *at, 5*time.Minute, true, true)
	*at = at.Add(10 * time.Second)
}

// D6's N1 (P4) on #806: the names an ended stretch counted past its own
// cap are merged. In one run, at most 8 names a heartbeat: a stretch of
// if00 to if07 ends; a second, of if08 to if15 and then if16, ends after
// it. The merged stretches name 8 and count 9. Control: pastMergeNamesOnly,
// endPastLocked merging o.names alone, which drops if16.
func TestBlindPastMergeOver(t *testing.T) {
	run := func() *pastStretch {
		b := &blindState{}
		at := t0
		pastHb(b, &at, "run1", ifRange(0, 8))
		pastEnd(b, &at, "run1")
		pastHb(b, &at, "run1", ifRange(8, 8))
		pastHb(b, &at, "run1", ifRange(16, 1))
		pastEnd(b, &at, "run1")
		return b.pend
	}
	if p := run(); p == nil || len(p.names) != netobs.MaxInterfaces || p.more() != 9 || p.n != 2 {
		t.Fatalf("merged %+v, want %d names, 9 more, 2 stretches", p, netobs.MaxInterfaces)
	}
	t.Run("control: the names past the cap not merged", func(t *testing.T) {
		withSeam(t, &pastMergeNamesOnly)
		if p := run(); p.more() == 9 {
			t.Fatal("the control counted 9")
		}
	})
}

// D6's N2 on #806: pastDue's detail counts the names past the cap of every
// merged run. if00 to if07, then if08, blind in run1, both stretches
// ended; a stretch of run2 naming if08 again; one sensor.past-blind, whose
// detail counts 2 more (if08 once in each run). Control:
// pastDetailOverOnly, the detail from len(p.over), which counts 1.
func TestBlindPastDetailAcrossRuns(t *testing.T) {
	run := func(t *testing.T) string {
		g := newGsrc(t)
		g.live(6, true)
		b := &blindState{}
		at := t0
		pastHb(b, &at, "run1", ifRange(0, 8))
		pastEnd(b, &at, "run1")
		pastHb(b, &at, "run1", ifRange(8, 1))
		pastEnd(b, &at, "run1")
		pastHb(b, &at, "run2", ifRange(8, 1)) // a new run: if08 again
		b.endPastLocked()
		g.r.l.pastDue(b.pend)
		g.live(1, true)
		ev := g.events(EventPastBlind)
		if len(ev) != 1 {
			t.Fatalf("past-blind events %v, want one", ev)
		}
		return ev[0]["detail"]
	}
	if d := run(t); !strings.Contains(d, "if07, and 2 more not listed") || !strings.Contains(d, "3 stretches merged") {
		t.Fatalf("detail %q, want 2 more across the two runs", d)
	}
	t.Run("control: the detail from the last run alone", func(t *testing.T) {
		withSeam(t, &pastDetailOverOnly)
		if d := run(t); strings.Contains(d, "and 2 more") {
			t.Fatalf("the control counted 2: %q", d)
		}
	})
}
