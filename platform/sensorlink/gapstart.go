package sensorlink

import (
	"context"
	"fmt"
	"slices"
	"time"
)

// The gap model across a node start, INT-D5 2e-3 (docs/phase4/D5-sensor-node.md
// section 1.9 item 5; C13 CH-39 part 4, CH-45 "At a start"). The 0.2 intake
// only, as W is (watch.go). Not wired (F-027's gate): RunFile.Start calls
// nodeStart for each link it starts.
//
//   - At the start, after the run file is applied, any gap held for the
//     floor in the cursor is written first (takeWatch put it in wait), and
//     then the node-start gap opens from the earlier of W and R. With no W
//     (the sensor database lost, or a sensor never watched) it opens from
//     the bound, the run file's copy, with from_bound; with no copy either,
//     from the start's own time, which is no bound later than the start
//     (enrolled_at is P4-4-DE's).
//   - It is marked clock_stepped at once where W, R, the floor or the copy
//     it starts from is later than the wall clock. The mark moves nothing:
//     the cap of W, R and the floor waits for the gap's close (CH-45), and
//     the copy is capped only as the gap's start, never written back.
//   - While it is open nothing places W or R and no other gap opens: a
//     cause found joins it (link, restart, blind, sensor-failed).
//   - It closes as any gap does: as covered by a chain that runs from the
//     saved W across the start (CH-39 part 4: its length is the wall-clock
//     difference from the saved W), or unwatched at the first current
//     heartbeat that shows capture. The step check at its close caps W, R
//     and the floor at the wall clock before its to_utc is taken.

// Test seams, each false in the node: the controls of 2e-3's legs.
// startGapOff opens no node-start gap (2e-2's state); startFromNow starts
// it at the node's start, not at the earlier of W and R; startCapsAtOnce
// caps W, R and the floor at the start and saves them; startMarkAtCapOnly
// marks the gap clock_stepped only at the cap, at its close;
// startCopyUncapped starts a gap from a copy later than the wall clock
// as it is; gapOpenWallW counts the node-start gap's 60 s from W on the
// wall clock alone; gapChainFromFirst lets a chain across a start look
// back only to its own first heartbeat; frozenUnwatchedOnly clears frozen
// only at an unwatched close; gapDropReversed drops a closed record whose
// end is before its start; stepFloorUnmoved moves W, R and the copy back
// at a step, not the floor; capFloorOnly caps the floor but not W and R;
// floorNoCap caps the floor at no point and keeps it, at an unwatched
// close, as the later of its value and the close's to_utc; stepKeepsOld
// moves nothing back at a step; placeAtSensor places W and R at the
// heartbeat's at_utc; raiseNoHeld saves an unwatched close's raise with no
// gap held for the floor; gapWMovesAtOpen moves W to the wall clock at a
// gap's open.
var startGapOff, startFromNow, startCapsAtOnce, startMarkAtCapOnly, startCopyUncapped, gapOpenWallW, gapChainFromFirst bool
var frozenUnwatchedOnly, gapDropReversed, stepFloorUnmoved, capFloorOnly, floorNoCap, stepKeepsOld, placeAtSensor, raiseNoHeld, gapWMovesAtOpen bool

// The run file's copy (CH-45): copyHeldIgnored takes it as the earlier of
// W and R alone; copyHeldFromSave holds the held gap's start in it only
// once the raise is saved; copyNoHold lets it rise while a gap is held.
var copyHeldIgnored, copyHeldFromSave, copyNoHold bool

// nodeStart opens the node-start gap for the link at the node's start
// (CH-45, "At a start"): copyAt is the run file's copy, zero when the file
// holds none for the sensor. The gap held for the floor that takeWatch
// found is written first, by gapAct's order.
func (l *Link) nodeStart(ctx context.Context, copyAt time.Time) {
	if !l.skewOn() || startGapOff {
		return
	}
	l.gmu.Lock()
	defer l.gmu.Unlock()
	wall, mono := l.now(), l.opt.Monotonic()
	s := &l.skew
	s.mu.Lock()
	s.startGapLocked(copyAt, wall, mono, l.blindAfter())
	s.mu.Unlock()
	if startCapsAtOnce {
		s.mu.Lock()
		s.capLocked(wall)
		s.mu.Unlock()
		_ = l.actStep(ctx)
	}
	if err := l.gapAct(ctx, nil); err != nil {
		l.raise(AlarmPositionNotSaved, fmt.Sprintf("sensor %s: a gap's raise was not saved: %v", l.cfg.SensorID, err))
	}
}

// startGapLocked opens the node-start gap at wall and mono. The caller
// holds s.mu.
func (s *skew) startGapLocked(copyAt, wall time.Time, mono, blind time.Duration) {
	wt := &s.wt
	if gapsOff || wt.open != nil {
		return
	}
	from, bound, stepped := wt.earlierWR(), false, false
	if wt.w.IsZero() {
		// No W: the bound (CH-45), the run file's copy, capped at the
		// wall clock before it serves (D3's N3 on #774).
		from, bound = copyAt, true
		if from.After(wall) && !startCopyUncapped {
			wt.owedStep += from.Sub(wall)
			from, stepped = wall, true
		}
		if from.IsZero() {
			from = wall // no bound later than the start (enrolled_at is P4-4-DE's)
		}
	}
	if startFromNow {
		from, bound = wall, false
	}
	for _, t := range []time.Time{wt.w, wt.r, wt.floor} {
		if t.After(wall) && !startMarkAtCapOnly {
			stepped = true
		}
	}
	// The 60 s are counted from W, or from the bound, across the start on
	// the wall clock (CH-45, "When it is written"), and never past 60 s
	// after the open.
	wMono := min(mono-wall.Sub(from), mono)
	wt.open = &openGap{from: from, cause: CauseNodeStart, causes: gapCauseBit(CauseNodeStart), openMono: mono, wMono: wMono, stepped: stepped, bound: bound}
	wt.gapDue = true
	if !wt.w.IsZero() {
		s.startChainAcrossLocked(wall, mono, blind)
	}
}

// startChainAcrossLocked starts the chain at the saved W's heartbeat, from
// the values the cursor keeps with it (CH-39 part 2), its length counted
// from the saved W on the wall clock (part 4: across a restart, a
// wall-clock difference). The kept values are matched to the names of the
// run's first heartbeat read after the start, in their bytewise order, as
// place matches them (extendChainLocked). With no values kept for W's run
// the chain fails, so the gap cannot close as covered. The caller holds
// s.mu.
func (s *skew) startChainAcrossLocked(wall time.Time, mono, blind time.Duration) {
	wt := &s.wt
	ch := chain{run: wt.run, seq: wt.wSeq, at: wt.wAt, n: 1, wMono: mono - wall.Sub(wt.w), g: wt.startG, d: wt.startD}
	if wt.run == "" || len(wt.kept) == 0 {
		ch.reason = "nothing kept with W"
		wt.ch = ch
		return
	}
	ch.ok, ch.kept, ch.fromFirst = true, slices.Clone(wt.kept), gapChainFromFirst
	shown := false
	for _, k := range wt.kept {
		ch.total += k.Packets
		if !wt.wAt.Before(k.RiseUTC) && wt.wAt.Sub(k.RiseUTC) <= blind {
			shown = true
		}
	}
	switch {
	case shown || ch.fromFirst:
		ch.shown = wt.wAt
	case !gapChainStretch:
		ch.ok, ch.reason = false, "part 2 at W"
	}
	wt.ch = ch
}

// keptIfsLocked builds the chain's interfaces at the first heartbeat h of
// its run read after a start, from the values kept with W; false when the
// names do not match them one for one (CH-39 part 2). The caller holds
// s.mu.
func (ch *chain) keptIfs(names []string, at time.Time) bool {
	if len(names) != len(ch.kept) {
		return false
	}
	ch.ifs = map[string]*chainIf{}
	for i, n := range names {
		c := &chainIf{packets: ch.kept[i].Packets, rise: ch.kept[i].RiseUTC}
		if ch.fromFirst {
			c.rise = at // the control: no look back past its own first heartbeat
		}
		ch.ifs[n] = c
	}
	ch.kept = nil
	return true
}
