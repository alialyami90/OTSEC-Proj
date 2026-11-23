package sensorlink

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"time"

	"otsec.local/otsec/contracts/event"
	"otsec.local/otsec/contracts/netobs"
)

// The gap model's first part, INT-D5 2e-1 (docs/phase4/D5-sensor-node.md
// sections 1.4 and 1.9 item 5; C13 CH-31, CH-39). The 0.2 intake only, as
// the skew gate is (skewOn). Not wired (F-027's gate).
//
//   - W is the moment the node holds as accounted for. At each current
//     heartbeat that shows capture it moves to the earlier of the node's
//     receipt and the heartbeat's at_utc + E, E's samples moved back by
//     any step back found since each was taken; never later than the
//     node's wall clock. Current: read on a connection whose hello was
//     accepted, of the run the hello names as current, once the backlog is
//     through (CH-39), and not late (CH-23).
//   - Showing capture (CH-31 at the receipt): some interface's carrier is
//     not down and its packets rose within the last blind_after_s of the
//     node's monotonic time, or its run began within it and the interface
//     was named in the run's first heartbeat read here. A rise is packets
//     above the same name's in the run's heartbeat before, or above the
//     value kept with W after a node start. The state is kept by name: a
//     name absent from a heartbeat is dropped, and a name first seen
//     within a run shows capture only once its own packets rise.
//   - R is the last current heartbeat in which an interface's packets rose
//     with that interface's carrier not down, placed as W is.
//   - The cursor keeps, with W, each interface's packets at W's heartbeat
//     and the at_utc of its last rise in the run (or of the run's first
//     heartbeat for one that never rose), in the bytewise order of the
//     names. After a node start they are K-1's baseline for a heartbeat
//     numbered above W's: a falling packets in the run is refused as order
//     and counted counter-decrease. One at or below W's is a resend.
//   - The step check compares the wall clock with the monotonic clock since
//     the check before, both read under the skew's lock, as W's placement
//     reads them, so one step is handled once. It runs before a heartbeat's
//     lateness is judged and before its placement, before a
//     hello's or a tick's sample, before the run file's copy is taken, and
//     at the node's tick (CheckStep). It acts only on a step back of more
//     than MaxSkew: W, R, the copy and E's held samples move back by the
//     step, the cursor and the run file are saved at once, and
//     time.node-stepped is written once. Then W or R still later than the
//     wall clock takes the wall-clock time, acted on the same way; before
//     W's first placement since the start a check only measures, and the
//     node-start gap's close caps (gapstart.go). It never moves the capture
//     floor, M or the start bound (section 1.5).
//   - The run file's copy is the earliest of W, R and the start of the gap
//     held for the floor as the link holds them when the file is written,
//     never rising while a gap is held; with none held, the copy last
//     written.
//
// The gaps are gap.go's (2e-2) and gapstart.go's (2e-3).

// DefaultBlindAfter is blind_after_s's default (CH-31).
const DefaultBlindAfter = 300 * time.Second

// IfaceMark is one capture interface's values kept with W: its packets at
// W's heartbeat and the at_utc of its last rise in the run.
type IfaceMark struct {
	Packets uint64    `json:"packets"`
	RiseUTC time.Time `json:"rise_utc"`
}

// Test seams, each false in the node: the controls of 2e-1's rows.
// k1ProcessOnly judges a heartbeat's fall against the previous heartbeat
// of this process only; placeAtReceipt places W and R at their receipts;
// stepNoSamples moves no sample of E at a step; stepCapsCaptureFloor caps
// the capture floor and the start bound at the wall clock at every check;
// stepFoundOnly compares a stored time with the steps the check found
// alone; stepAnyBack acts on any backward difference; stepTickOnly runs
// the check only at the node's tick. The fix's controls (D1's 7057035425
// on #774): stepClocksBeforeLock reads both clocks before the skew's lock
// in the step check and W's placement; watchSetResets starts the run's
// began again, for every name, when the interface set changes;
// stepCopyUnmoved leaves the run file's copy where a step found it;
// k1KeptAnySeq judges any heartbeat after a start against the packets
// kept with W. sampleClocksBeforeLock reads both clocks before the skew's
// lock in E's sample (D1's 7058929380 on #774).
var k1ProcessOnly, placeAtReceipt, stepNoSamples, stepCapsCaptureFloor, stepFoundOnly, stepAnyBack, stepTickOnly bool
var stepClocksBeforeLock, watchSetResets, stepCopyUnmoved, k1KeptAnySeq, sampleClocksBeforeLock bool

// stepMinuteOnly acts only on a step back of a minute or more: V-9's
// eleventh case's second control (D6's N3 on #781).
var stepMinuteOnly bool

// ifLive is an interface's CH-31 state in this process.
type ifLive struct {
	packets  uint64
	riseAt   time.Time // sensor time: the last rise, or the run's first heartbeat
	riseMono time.Duration
	rose     bool // a rise was seen in this process
	// fromBegin: named in the run's first heartbeat read in this process,
	// so the run's start counts for it.
	fromBegin bool
}

// watch is W, R and the step check, under the skew's leaf lock.
type watch struct {
	w, wAt, r time.Time
	wSeq      uint64
	// run is the run kept's values belong to.
	run  string
	kept []IfaceMark
	// The CH-31 state of liveRun in this process, by interface name; began
	// is the receipt of the run's first heartbeat read here when the run
	// was accepted as new here, set once.
	liveRun  string
	live     map[string]*ifLive
	began    time.Duration
	beganOK  bool
	newRun   string // the run last accepted as new in this process
	taken    bool   // the cursor's values were taken
	placed   bool   // W was placed since the start: a check may cap
	chkWall  time.Time
	chkMono  time.Duration
	checked  bool
	unfound  time.Duration // the movement the checks did not act on (stepFoundOnly)
	owedStep time.Duration // found, its event not yet written
	owedSave bool          // found, the cursor and the run file not yet saved
	copyBack time.Duration // found, not yet applied to the run file's copy
	// liveTotal is the run's counters.packets at its heartbeat before, for
	// the rule that a rise counts only when it rose (D1's ruling on D3's
	// N-b, #781).
	liveTotal uint64
	// The gap model (gap.go, 2e-2): the gap open, the closing record that
	// waits, the gap floor; frozen: W and R were taken from the cursor
	// at the start and are not moved until a gap closes, the node-start
	// gap's close included (gapstart.go); heldSave: an unwatched close's raise is
	// not yet saved; gapDue: a record may be due; current: a connection
	// whose hello is current is live; wRecv and wMono: the receipt of W's
	// heartbeat and W itself on the monotonic clock; ch: the chain.
	open     *openGap
	wait     *waitRec
	floor    time.Time
	frozen   bool
	heldSave bool
	gapDue   bool
	current  bool
	wRecv    time.Duration
	wMono    time.Duration
	ch       chain
	obsSeen  bool // gapNeedsObservation's control only
	// wG and wD are G and D at W's heartbeat, kept with W in the cursor
	// for a chain across a start (D1's ruling 8 on #788, option (b));
	// startG and startD are the cursor's G and D at the start, read only
	// by startChainCursorGD's control (gapstart.go).
	wG, wD         uint64
	startG, startD uint64
	// startPassed: the node-start gap opened with no cursor read in this
	// process, so a later read takes only M and the kept interfaces (D1's
	// ruling 6 on #788, option (a)).
	startPassed bool
	// clearSave: a covered close's record committed while the cursor may
	// still hold it; the cursor is saved without it before any later gap
	// record (D3's B2 on #788).
	clearSave bool
	// startStepped: this process's start capped its copy with W held and
	// wrote the step's record, which the cap at the node-start gap's close
	// does not write again (D1's ruling 11 on #788). In memory only: after
	// a kill the close in the next process writes it a second time.
	startStepped bool
}

// blindAfter is blind_after_s.
func (l *Link) blindAfter() time.Duration {
	if l.opt.BlindAfter <= 0 {
		return DefaultBlindAfter
	}
	return l.opt.BlindAfter
}

// takeWatch takes the saved W, R and the kept interfaces at the first read
// of the cursor in this process, c nil when there is none.
func (l *Link) takeWatch(c *Cursor) {
	s := &l.skew
	s.mu.Lock()
	defer s.mu.Unlock()
	wt := &s.wt
	if wt.taken {
		return
	}
	wt.taken = true
	if c == nil {
		return // no cursor at the first read: nothing to take
	}
	if wt.startPassed && !startLateTakesAll {
		// Read after the start's read failed: W, R, G, D, the floor and the
		// held gap belong to the start, whose node-start gap stands from
		// the copy; only the kept interfaces, with their heartbeat's seq
		// for K-1's resend rule, are K-1's baseline (D6's B1 on #788).
		if len(c.Ifaces) > 0 {
			wt.run, wt.kept, wt.wSeq = c.RunID, slices.Clone(c.Ifaces), c.WSeq
		}
		return
	}
	wt.w, wt.wSeq, wt.wAt, wt.r = c.W, c.WSeq, c.WAtUTC, c.R
	wt.wG, wt.wD = c.WG, c.WD
	wt.startG, wt.startD = c.G, c.D
	// W and R saved before the stop are not moved by a placement until a
	// gap closes, so a gap after the start reaches back across the stop
	// (D1's 7056051455 on #770); the node-start gap is that gap.
	wt.frozen = !c.W.IsZero() || !c.R.IsZero()
	if c.Held != nil {
		// A gap held for the floor at the stop is written first (CH-45),
		// and so is a covered close that waited for its budget, which
		// raises nothing (D1's ruling on #788).
		g := *c.Held
		g.Covered = false
		wt.wait = &waitRec{HeldGap: g, covered: c.Held.Covered}
		if !c.Held.Covered || coveredRaisesFloor {
			wt.floor = c.Held.To
		}
	}
	if len(c.Ifaces) > 0 {
		wt.run, wt.kept = c.RunID, slices.Clone(c.Ifaces)
	}
}

// watchInto puts W, R and the kept interfaces in c, the interfaces only
// when they are of c's run.
func (l *Link) watchInto(c *Cursor) {
	s := &l.skew
	s.mu.Lock()
	defer s.mu.Unlock()
	wt := &s.wt
	c.W, c.WSeq, c.WAtUTC, c.R, c.Ifaces = wt.w, wt.wSeq, wt.wAt, wt.r, nil
	c.WG, c.WD = wt.wG, wt.wD
	c.Causes, c.Held = 0, nil
	if wt.open != nil {
		c.Causes = wt.open.causes
	}
	if w := wt.wait; w != nil && !(w.covered && heldCoveredMemOnly) && !(raiseNoHeld && !w.covered) {
		g := w.HeldGap
		g.Covered = w.covered
		c.Held = &g
	}
	if wt.w.IsZero() {
		c.WSeq, c.WAtUTC, c.WG, c.WD = 0, time.Time{}, 0, 0
	}
	if wt.run == c.RunID && len(wt.kept) > 0 {
		c.Ifaces = slices.Clone(wt.kept)
	}
}

// runBegan notes a run accepted as new in this process (CH-13 row 6).
func (l *Link) runBegan(run string) {
	s := &l.skew
	s.mu.Lock()
	defer s.mu.Unlock()
	s.wt.newRun = run
}

// keptHeartbeat is K-1's baseline after a node start: the packets kept with
// W, as a heartbeat of h's run, nil when none is kept for it, the
// interfaces do not match one for one, or h is numbered at or below W's
// heartbeat. Within a connection a seq at or below L is refused before
// this is reached, so such a heartbeat is a resend after a start, judged
// when first read (D6's B2 on #774). Its seq is 0, so only the counts are
// judged.
func (l *Link) keptHeartbeat(h *netobs.Heartbeat) *netobs.Heartbeat {
	if !l.skewOn() || k1ProcessOnly {
		return nil
	}
	names := ifaceNames(h)
	s := &l.skew
	s.mu.Lock()
	defer s.mu.Unlock()
	wt := &s.wt
	if wt.run != h.RunID || len(wt.kept) != len(names) || num(h.Seq) <= wt.wSeq && !k1KeptAnySeq {
		return nil
	}
	p := &netobs.Heartbeat{RunID: h.RunID, Seq: "0"}
	for i, n := range names {
		p.Interfaces = append(p.Interfaces, netobs.InterfaceCount{Name: n, Packets: wt.kept[i].Packets})
	}
	return p
}

// ifaceNames is h's interface names in bytewise order.
func ifaceNames(h *netobs.Heartbeat) []string {
	out := make([]string, 0, len(h.Interfaces))
	for _, i := range h.Interfaces {
		out = append(out, i.Name)
	}
	slices.Sort(out)
	return out
}

// place takes heartbeat h, read and taken: CH-31's state, and W and R when
// it is current. late: it is later than late_bound_s. CH-31's state is
// taken from every heartbeat read, late and backlog ones included: a rise
// first seen in one is placed at no later receipt, so R and the blind
// window only end sooner (D4's N1 on #774).
func (l *Link) place(cn *conn, h *netobs.Heartbeat, late bool) {
	if !l.skewOn() {
		return
	}
	var wall time.Time
	var mono time.Duration
	if stepClocksBeforeLock {
		wall, mono = l.now(), l.opt.Monotonic()
	}
	at := parseUTC(h.AtUTC)
	byName := map[string]netobs.InterfaceCount{}
	for _, i := range h.Interfaces {
		byName[i.Name] = i
	}
	names := ifaceNames(h)
	blind := l.blindAfter()
	current := cn.hello != nil && cn.hello.Current != nil && *cn.hello.Current && cn.hello.RunID == h.RunID
	s := &l.skew
	s.mu.Lock()
	defer s.mu.Unlock()
	if !stepClocksBeforeLock {
		// Under the lock, so a step check on another goroutine is wholly
		// before or after this placement (D3's B2, D6's B1 on #774).
		wall, mono = l.now(), l.opt.Monotonic()
	}
	wt := &s.wt
	epoch := time.Unix(0, 0).UTC()
	if wt.liveRun != h.RunID {
		// The run's first heartbeat read in this process.
		wt.liveRun, wt.live, wt.beganOK = h.RunID, map[string]*ifLive{}, false
		kept := wt.run == h.RunID && len(wt.kept) == len(names)
		newHere := wt.newRun == h.RunID
		wt.liveTotal = h.Counters.Packets
		if kept {
			wt.liveTotal = 0
		}
		for i, n := range names {
			if kept {
				wt.live[n] = &ifLive{packets: wt.kept[i].Packets, riseAt: wt.kept[i].RiseUTC, fromBegin: true}
				wt.liveTotal += wt.kept[i].Packets
				continue
			}
			// CH-31 starts again at the run's first heartbeat read. Its
			// at_utc is the run's first heartbeat's only when the run was
			// accepted as new here; otherwise no rise is held (D1's ruling
			// on D6's N4, #781).
			rise := at
			if !newHere && !gapRiseFirstSeen {
				rise = epoch
			}
			wt.live[n] = &ifLive{packets: byName[n].Packets, riseAt: rise, fromBegin: true}
		}
		if !kept && newHere {
			wt.began, wt.beganOK = mono, true
		}
	}
	changed := len(wt.live) != len(names)
	for n := range wt.live {
		if _, ok := byName[n]; !ok {
			delete(wt.live, n) // absent: a name seen again starts afresh
		}
	}
	for _, n := range names {
		if wt.live[n] == nil {
			// First seen within the run: no rise and no grace of the run's
			// start until its own packets rise (D3's B1 on #774), and no
			// rise held for the chain (D6's N4, #781).
			rise := epoch
			if gapRiseFirstSeen {
				rise = at
			}
			wt.live[n], changed = &ifLive{packets: byName[n].Packets, riseAt: rise}, true
		}
	}
	if watchSetResets && changed && wt.newRun == h.RunID {
		wt.began, wt.beganOK = mono, true
		for _, lv := range wt.live {
			lv.fromBegin = true
		}
	}
	// A rise counts only when the run's counters.packets rose too (D1's
	// ruling on D3's N-b, #781).
	totalRose := h.Counters.Packets > wt.liveTotal || gapRiseNoTotal
	wt.liveTotal = h.Counters.Packets
	capture, rose := false, false
	for _, n := range names {
		ic, lv := byName[n], wt.live[n]
		if ic.Packets > lv.packets && totalRose {
			lv.riseAt, lv.riseMono, lv.rose = at, mono, true
			rose = rose || ic.Carrier != "down" || gapBlindFromAnyRise
		}
		lv.packets = ic.Packets
		if ic.Carrier != "down" && (lv.rose && mono-lv.riseMono <= blind || lv.fromBegin && wt.beganOK && mono-wt.began <= blind) {
			capture = true
		}
	}
	s.extendChainLocked(h, at, blind)
	if g := wt.open; g != nil && gapCloseAtReconnect && cn.hello != nil {
		// The control: closed at the reconnect, before the backlog is through.
		s.closeLocked(true, wall)
	}
	if !current || late || s.bl.on {
		return
	}
	// A silent gap that fell due before this heartbeat opens first.
	s.silentDueLocked(wall, mono)
	if g := wt.open; g != nil {
		if !capture {
			g.causes |= gapCauseBit(CauseBlind)
		}
		lateness := wall.Sub(at.Add(s.movedELocked()))
		switch {
		case g.causes&gapCauseBit(CauseSensorFailed) != 0:
			return // nothing closes it in this process
		case g.causes&gapCauseBit(CauseSilent) != 0 && lateness >= HeartbeatGapMax && !gapSilentEndsAtCurrent:
			return // the silence's cause has not ended
		case g.causes&gapCauseBit(CauseBlind) != 0:
			if !rose {
				return
			}
			s.closeStartCapped(g, wall)
			s.closeLocked(false, wall)
		case (!gapSilentNeverCovered || g.causes&gapCauseBit(CauseSilent) == 0) && s.chainCoversLocked(cn, wall, mono):
			s.closeStartCapped(g, wall)
			s.closeLocked(true, wall)
		case capture:
			s.closeStartCapped(g, wall)
			s.closeLocked(false, wall)
		default:
			return
		}
	}
	// W and R are placed after any close, so a cap at the node-start
	// gap's close is in the placement (CH-45).
	p := wall
	if q := at.Add(s.movedELocked()); !placeAtReceipt && len(s.samples) > 0 && q.Before(p) {
		p = q
	}
	if placeAtSensor {
		p = at // the control: the heartbeat's at_utc kept as W
	}
	if unix0 := time.Unix(0, 0); p.Before(unix0) {
		p = unix0
	}
	if !gapNoFloor && p.Before(wt.floor) {
		p = wt.floor // never below the floor
	}
	if wt.frozen {
		return
	}
	if rose {
		wt.r = p
		if gapRAtReceipt {
			wt.r = wall
		}
	}
	if capture {
		if gapWAtReceipt {
			p = wall
		}
		wt.w, wt.wSeq, wt.wAt, wt.placed = p, num(h.Seq), at, true
		wt.wRecv, wt.wMono = mono, mono-wall.Sub(p)
		wt.run, wt.kept = h.RunID, make([]IfaceMark, len(names))
		for i, n := range names {
			wt.kept[i] = IfaceMark{Packets: wt.live[n].packets, RiseUTC: wt.live[n].riseAt}
		}
		s.startChainLocked(cn, h, at, wt.wMono, blind)
		wt.wG, wt.wD = wt.ch.g, wt.ch.d
		return
	}
	// Every interface blind: W stays, and a blind gap opens (CH-45).
	s.openLocked(CauseBlind, wall, mono)
}

// movedELocked is E with each sample moved back by the steps found since it
// was taken: the E W and R are placed with. The caller holds s.mu.
func (s *skew) movedELocked() time.Duration {
	if len(s.samples) == 0 {
		return 0
	}
	e := s.samples[0] - s.shift[0]
	for i := range s.samples[1:] {
		e = min(e, s.samples[i+1]-s.shift[i+1])
	}
	return e
}

// offStored is the node's offset the stored-time half compares a stored
// time with: offNow, or under stepFoundOnly the offset moved only by the
// steps the check found.
func (l *Link) offStored() int64 {
	off := l.offNow()
	if stepFoundOnly {
		s := &l.skew
		s.mu.Lock()
		off -= int64(s.wt.unfound)
		s.mu.Unlock()
	}
	return off
}

// measureStep runs the step check under the skew's lock and moves what a
// step back moves; what it found waits for actStep. It reports whether
// anything waits.
func (l *Link) measureStep() bool {
	if !l.skewOn() {
		return false
	}
	var wall time.Time
	var mono time.Duration
	if stepClocksBeforeLock {
		wall, mono = l.now(), l.opt.Monotonic()
	}
	s := &l.skew
	s.mu.Lock()
	defer s.mu.Unlock()
	if !stepClocksBeforeLock {
		// Under the lock: two checks, or a check and a placement, on
		// different goroutines never interleave their readings, so one step
		// is found once (D3's B2, D6's B1 on #774). The clocks take no lock
		// of the link's.
		wall, mono = l.now(), l.opt.Monotonic()
	}
	wt := &s.wt
	if wt.checked {
		diff := wall.Sub(wt.chkWall) - (mono - wt.chkMono)
		if back := -diff; back > MaxSkew && (!stepMinuteOnly || back >= time.Minute) || stepAnyBack && back > 0 {
			s.moveBackLocked(back)
		} else {
			wt.unfound += diff
		}
	}
	wt.chkWall, wt.chkMono, wt.checked = wall, mono, true
	if wt.placed {
		s.capLocked(wall)
	}
	if stepCapsCaptureFloor {
		for _, t := range []*time.Time{&s.floor, &s.startBound} {
			if t.After(wall) {
				*t = wall
			}
		}
	}
	return wt.owedSave || wt.owedStep > 0
}

// capLocked caps W, R and the floor at wall: a value still later than the
// wall clock is a step the check could not measure, which takes the
// wall-clock time and is marked and written as a step is (CH-45). The
// caller holds s.mu.
func (s *skew) capLocked(wall time.Time) {
	wt := &s.wt
	ts := []*time.Time{&wt.w, &wt.r, &wt.floor}
	switch {
	case stepKeepsOld:
		return
	case floorNoCap || stepFloorUnmoved:
		ts = ts[:2]
	}
	capped := time.Duration(0)
	for _, t := range ts {
		if t.After(wall) {
			capped = max(capped, t.Sub(wall))
			*t = wall
		}
	}
	if capped > 0 {
		wt.owedStep, wt.owedSave = wt.owedStep+capped, true
		s.markStepLocked()
	}
}

// closeStartCapped is the step check's cap at the node-start gap's close,
// before its to_utc is taken (CH-45: the cap waits for that close). A gap
// from a start that W and R were moved past by an unwatched close is
// capped too. Where the start capped its copy it wrote the step's record
// then, so this cap writes none (D1's ruling 11 on #788: once per step).
// The caller holds s.mu.
func (s *skew) closeStartCapped(g *openGap, wall time.Time) {
	if g.cause == CauseNodeStart && !startCapsAtOnce {
		wt := &s.wt
		owed := wt.owedStep
		s.capLocked(wall)
		if wt.startStepped && !startStepTwice {
			wt.owedStep = owed
		}
		wt.startStepped = false
	}
}

// moveBackLocked moves W, R, the run file's copy and E's held samples back
// by d; the copy is moved when the run file next takes it, whether or not
// W or R is held (D3's B3 on #774). The caller holds s.mu.
func (s *skew) moveBackLocked(d time.Duration) {
	wt := &s.wt
	ts := []*time.Time{&wt.w, &wt.r, &wt.floor}
	switch {
	case stepKeepsOld:
		ts = nil
	case stepFloorUnmoved:
		ts = ts[:2]
	}
	for _, t := range ts {
		if !t.IsZero() {
			*t = t.Add(-d)
		}
	}
	s.markStepLocked()
	if !stepCopyUnmoved && !stepKeepsOld {
		wt.copyBack += d
	}
	if !stepNoSamples {
		for i := range s.shift {
			s.shift[i] += d
		}
		s.latestShift += d
	}
	if stepCapsCaptureFloor {
		for _, t := range []*time.Time{&s.floor, &s.startBound} {
			if !t.IsZero() {
				*t = t.Add(-d)
			}
		}
	}
	wt.owedStep, wt.owedSave = wt.owedStep+d, true
}

// stepAt runs the step check before a time is taken, and acts on what it
// found. An error is a save that failed: the caller closes store, and the
// next check saves again.
func (l *Link) stepAt(ctx context.Context) error {
	if !l.measureStep() {
		return nil
	}
	return l.actStep(ctx)
}

// stepAtReceipt is the step check before a receipt's time is taken: a
// heartbeat's, a hello's or a tick's.
func (l *Link) stepAtReceipt(ctx context.Context) error {
	if stepTickOnly {
		return nil
	}
	return l.stepAt(ctx)
}

// CheckStep is the step check at the node's tick (section 1.9 item 5).
func (l *Link) CheckStep(ctx context.Context) {
	if err := l.stepAt(ctx); err != nil {
		l.raise(AlarmPositionNotSaved, fmt.Sprintf("sensor %s: W and R moved by a step of the node's clock were not saved: %v", l.cfg.SensorID, err))
	}
	if l.skewOn() {
		l.gapTick(ctx) // a silent gap due, and the gap records due (2e-2)
	}
}

// actStep saves the cursor and the run file with what a step moved, and
// writes time.node-stepped once for it.
func (l *Link) actStep(ctx context.Context) error {
	s := &l.skew
	s.mu.Lock()
	d, save := s.wt.owedStep, s.wt.owedSave
	s.wt.owedStep = 0
	s.mu.Unlock()
	h := l.opt.Health
	if d > 0 && h != nil {
		// The pool holds it until it is written: never lost, written once.
		_ = h.Event(ctx, event.HealthTimeNodeStepped, map[string]string{
			"step_back_ms": strconv.FormatInt(d.Milliseconds(), 10), "found_utc": canonUTC(l.now())})
	}
	if !save {
		return nil
	}
	err := l.saveMoved(ctx)
	if err == nil && h != nil {
		err = h.persistNow(ctx)
	}
	if err == nil {
		s.mu.Lock()
		s.wt.owedSave = false
		s.mu.Unlock()
	}
	return err
}

// saveMoved saves the position as last written with W and R as the link
// holds them now; nothing when no position is saved yet.
func (l *Link) saveMoved(ctx context.Context) error {
	l.cmu.Lock()
	defer l.cmu.Unlock()
	if l.opt.Cursor == nil {
		return nil
	}
	if err := l.readPos(ctx); err != nil {
		return err
	}
	if l.pos == nil {
		return nil
	}
	c := l.pos.clone()
	c.WriteNo = max(c.WriteNo, l.writeNo)
	b, err := l.encode(c)
	if err != nil {
		return err
	}
	if err := l.opt.Cursor.SaveSourceCursor(ctx, b); err != nil {
		return err
	}
	l.pos = c
	return nil
}

// watchedCopy is the run file's copy: the earliest of W, R and the start
// of the gap held for the floor, zero when none is held; back, the steps
// found since the last call, by which the file's own copy moves; and held,
// whether a gap is held for the floor or the node-start gap stands, while
// which the copy never rises (CH-45; Health.entry). The step check runs
// first, and moves them back if it finds a step; its event and the
// cursor's save wait for the next check that can act, since the run file
// is being written.
func (l *Link) watchedCopy() (c time.Time, back time.Duration, held bool) {
	if !stepTickOnly {
		l.measureStep()
	}
	s := &l.skew
	s.mu.Lock()
	defer s.mu.Unlock()
	back, s.wt.copyBack = s.wt.copyBack, 0
	c, held = s.copyLocked()
	return c, back, held
}

// copyLocked is the link's copy and whether it may not rise (watchedCopy).
// While the node-start gap stands the copy does not rise either, so the
// copy a start wrote capped is not raised back to a frozen W by a later
// write (D6's B3 on #788, D1's ruling 11). The caller holds s.mu.
func (s *skew) copyLocked() (c time.Time, held bool) {
	wt := &s.wt
	c = wt.earlierWR()
	if w := wt.wait; w != nil && !w.covered && !copyHeldIgnored && !(copyHeldFromSave && wt.heldSave) {
		// The gap held from the raise itself (CH-45).
		if c.IsZero() || w.From.Before(c) {
			c = w.From
		}
		held = !copyNoHold
	}
	if g := wt.open; g != nil && g.cause == CauseNodeStart && !startCopyRises {
		held = true
	}
	return c, held
}

// watchNow is W and R as the link holds them.
func (l *Link) watchNow() (w, r time.Time) {
	s := &l.skew
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.wt.w, s.wt.r
}
