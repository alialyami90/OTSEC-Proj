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
//     then the node-start gap opens from the earlier of W and R; the lost
//     gaps the cursor owes come after, through WriteOwed (CH-40). With no W
//     (the sensor database lost, or a sensor never watched) it opens from
//     the bound, the run file's copy, with from_bound; with no copy either,
//     from the Unix epoch, with from_bound, until P4-4-DE replaces it with
//     enrolled_at (D1's ruling 7 on #788). Only the start's cursor read
//     takes W, R, G and D at W, the floor and the held gap: when it failed,
//     a later read takes only M and the kept interfaces (ruling 6).
//   - It is marked clock_stepped at once where W, R, the floor or the copy
//     it starts from is later than the wall clock. The mark moves nothing:
//     the cap of W, R and the floor waits for the gap's close (CH-45). The
//     copy the start writes is capped, W held or not, its step written
//     first, and does not rise while the gap stands (ruling 11).
//   - While it is open nothing places W or R and no other gap opens: a
//     cause found joins it (link, restart, blind, sensor-failed).
//   - It closes as any gap does: as covered by a chain that runs from the
//     saved W across the start, from G and D at W's heartbeat (CH-39 part
//     1; ruling 8; part 4: its length is the wall-clock difference from the
//     saved W), or unwatched at the first current
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
// at a step, and neither moves nor caps the floor; floorNoCap caps the
// floor at no point and keeps it, at an unwatched close, as the later of
// its value and the close's to_utc; stepKeepsOld neither moves nor caps
// anything at a step; placeAtSensor places W and R at the heartbeat's
// at_utc; raiseNoHeld saves an unwatched close's raise with no gap held
// for the floor; gapWMovesAtOpen moves W and R to the wall clock at a
// gap's open.
var startGapOff, startFromNow, startCapsAtOnce, startMarkAtCapOnly, startCopyUncapped, gapOpenWallW, gapChainFromFirst bool
var frozenUnwatchedOnly, gapDropReversed, stepFloorUnmoved, floorNoCap, stepKeepsOld, placeAtSensor, raiseNoHeld, gapWMovesAtOpen bool

// The run file's copy (CH-45): copyHeldIgnored takes it as the earlier of
// W and R alone; copyHeldFromSave holds the held gap's start in it only
// once the raise is saved; copyNoHold lets it rise while a gap is held.
var copyHeldIgnored, copyHeldFromSave, copyNoHold bool

// heldCoveredMemOnly holds a covered close waiting for its budget in
// memory only, 2e-2's rule (the control of D1's ruling on #788).
var heldCoveredMemOnly bool

// The controls of D1's rulings 1 to 4 on #788 (comment 7069112910), each
// the code at 2dcf1e19 or a reviewer's mutant: startDueFromWR counts the
// node-start gap's 60 s from the earlier of W and R; coveredNoClear saves
// no cursor once a covered close's record commits; startCopyKept writes
// the run file's copy uncapped and the copy's step at the next check;
// coveredNoSave writes a covered close's record before the cursor holds
// it (D6's MD); coveredRaisesFloor raises the floor to a covered wait's
// end at a start (MC); startChainZeroGD starts the chain across a start
// with G and D 0 (MF); startChainNoPart1 skips part 1 across a start
// (MP1); startChainFromStart counts part 4 across a start from the start,
// not from the saved W (MG).
var startDueFromWR, coveredNoClear, startCopyKept, coveredNoSave, coveredRaisesFloor bool
var startChainZeroGD, startChainNoPart1, startChainFromStart bool

// The controls of D1's rulings 6 to 8 on #788 (comment 7069502767), each
// the code at f596b82e: startLateTakesAll lets a cursor read after a
// failed start's read take W, R, the floor and the held gap;
// startNoBoundNow opens a gap with no W and no copy from the start's own
// time; startChainCursorGD starts the chain across a start from the
// cursor's G and D at the start, not at W's heartbeat.
var startLateTakesAll, startNoBoundNow, startChainCursorGD bool

// The controls of D1's ruling 11 on #788 (comment 7112875190), together
// the code at 4847722f: startCopyCapNoW caps the copy a start writes only
// where no W is held; startCopyRises lets a write of the run file raise
// the copy while the node-start gap stands. startStepTwice writes the
// step's record at the gap's close too, where the start wrote it.
var startCopyCapNoW, startCopyRises, startStepTwice bool

// nodeStart opens the node-start gap for the link at the node's start
// (CH-45, "At a start"): copyAt is the run file's copy, zero when the file
// holds none for the sensor. The gap held for the floor that takeWatch
// found is written first, by gapAct's order. It returns the copy capped at
// the wall clock when the cap moved it, zero otherwise: the start writes
// the file with it, so a kill after the cap loses nothing, and the cap's
// time.node-stepped is written here, before that write (D6's B2 on #788,
// option (a)).
func (l *Link) nodeStart(ctx context.Context, copyAt time.Time) (capped time.Time) {
	if !l.skewOn() || startGapOff {
		return time.Time{}
	}
	l.gmu.Lock()
	defer l.gmu.Unlock()
	wall, mono := l.now(), l.opt.Monotonic()
	s := &l.skew
	s.mu.Lock()
	if !s.wt.taken {
		s.wt.startPassed = true // the start's read failed (D6's B1 on #788)
	}
	capped = s.startGapLocked(copyAt, wall, mono, l.blindAfter())
	s.mu.Unlock()
	if startCopyKept {
		capped = time.Time{}
	} else if !capped.IsZero() {
		if err := l.actStep(ctx); err != nil {
			l.raise(AlarmPositionNotSaved, fmt.Sprintf("sensor %s: W and R moved by a step of the node's clock were not saved: %v", l.cfg.SensorID, err))
		}
	}
	if startCapsAtOnce {
		s.mu.Lock()
		s.capLocked(wall)
		s.mu.Unlock()
		_ = l.actStep(ctx)
	}
	if err := l.gapAct(ctx, nil); err != nil {
		l.raise(AlarmPositionNotSaved, fmt.Sprintf("sensor %s: a gap's raise was not saved: %v", l.cfg.SensorID, err))
	}
	return capped
}

// startGapLocked opens the node-start gap at wall and mono, and returns
// the copy as capped when the cap moved it. The caller holds s.mu.
func (s *skew) startGapLocked(copyAt, wall time.Time, mono, blind time.Duration) (capped time.Time) {
	wt := &s.wt
	if gapsOff || wt.open != nil {
		return time.Time{}
	}
	from, bound, stepped := wt.earlierWR(), false, false
	if wt.w.IsZero() {
		// No W: the bound (CH-45), the run file's copy, capped at the
		// wall clock before it serves (D3's N3 on #774).
		from, bound = copyAt, true
		if from.After(wall) && !startCopyUncapped {
			wt.owedStep += from.Sub(wall)
			from, stepped, capped = wall, true, wall
		}
		if from.IsZero() {
			// No copy either: the Unix epoch, the earliest the node can
			// state, until P4-4-DE replaces it with enrolled_at (CH-45;
			// D3's B1 on #788, D1's ruling 7).
			from = time.Unix(0, 0).UTC()
			if startNoBoundNow {
				from = wall
			}
		}
	} else if !startCopyCapNoW {
		// W held: the copy the start writes, the earlier of the file's and
		// the link's (Health.entry, while this gap stands), capped at the
		// wall clock too, so a start that next serves it never starts late
		// (D6's B3 on #788, D1's ruling 11). Its one record carries the
		// largest value the step put past the wall clock, and the cap at
		// the gap's close writes none (closeStartCapped).
		c, _ := s.copyLocked()
		if !copyAt.IsZero() && (c.IsZero() || copyAt.Before(c)) {
			c = copyAt
		}
		if c.After(wall) {
			step := c.Sub(wall)
			for _, t := range []time.Time{wt.w, wt.r, wt.floor} {
				step = max(step, t.Sub(wall))
			}
			wt.owedStep += step
			wt.startStepped, capped = true, wall // W is later too: marked below
		}
	}
	if startFromNow {
		from, bound = wall, false
	}
	if gapFromW && !wt.w.IsZero() {
		from = wt.w // the control: the gap from W, not the earlier of W and R
	}
	for _, t := range []time.Time{wt.w, wt.r, wt.floor} {
		if t.After(wall) && !startMarkAtCapOnly {
			stepped = true
		}
	}
	// The 60 s are counted from W when it is held, or else from the bound,
	// across the start on the wall clock (CH-45, "When it is written"; D4's
	// B1 on #788), and never past 60 s after the open.
	due := from
	if !wt.w.IsZero() && !startDueFromWR {
		due = wt.w
	}
	wMono := min(mono-wall.Sub(due), mono)
	// At a start the floor is where the gap begins (CH-45, "The floor"),
	// so a placement before the cap at its close is never below it.
	if from.After(wt.floor) {
		wt.floor = from
	}
	wt.open = &openGap{from: from, cause: CauseNodeStart, causes: gapCauseBit(CauseNodeStart), openMono: mono, wMono: wMono, stepped: stepped, bound: bound}
	wt.gapDue = true
	if !wt.w.IsZero() {
		s.startChainAcrossLocked(wall, mono, blind)
	}
	return capped
}

// startChainAcrossLocked starts the chain at the saved W's heartbeat, from
// the values the cursor keeps with it (CH-39 part 2) and G and D at that
// heartbeat (part 1; D1's ruling 8 on #788), its length counted
// from the saved W on the wall clock (part 4: across a restart, a
// wall-clock difference). The kept values are matched to the names of the
// run's first heartbeat read after the start, in their bytewise order, as
// place matches them (extendChainLocked). With no values kept for W's run
// the chain fails, so the gap cannot close as covered. The caller holds
// s.mu.
func (s *skew) startChainAcrossLocked(wall time.Time, mono, blind time.Duration) {
	wt := &s.wt
	ch := chain{run: wt.run, seq: wt.wSeq, at: wt.wAt, n: 1, wMono: mono - wall.Sub(wt.w), g: wt.wG, d: wt.wD}
	if startChainCursorGD {
		ch.g, ch.d = wt.startG, wt.startD
	}
	if startChainFromStart {
		ch.wMono = mono // MG: part 4 from the start
	}
	if startChainZeroGD {
		ch.g, ch.d = 0, 0 // MF
	}
	ch.noPart1 = startChainNoPart1 // MP1
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
