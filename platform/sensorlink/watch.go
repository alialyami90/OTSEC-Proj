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
//     W's first placement since the start a check only measures (the
//     node-start gap's close is 2e-3's). It never moves the capture floor,
//     M or the start bound (section 1.5).
//   - The run file's copy is the earlier of W and R as the link holds them
//     when the file is written; with none held, the copy the file had.
//
// Not here (2e-2 and 2e-3): the gaps, their causes and the chain, the gap
// floor and the gap held for the floor, the budgets, the node-start gap
// and its cap, and the reach-back to the copy.

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
// kept with W.
var k1ProcessOnly, placeAtReceipt, stepNoSamples, stepCapsCaptureFloor, stepFoundOnly, stepAnyBack, stepTickOnly bool
var stepClocksBeforeLock, watchSetResets, stepCopyUnmoved, k1KeptAnySeq bool

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
}

// blindAfter is blind_after_s.
func (l *Link) blindAfter() time.Duration {
	if l.opt.BlindAfter <= 0 {
		return DefaultBlindAfter
	}
	return l.opt.BlindAfter
}

// takeWatch takes the saved W, R and the kept interfaces at the first read
// of the cursor in this process.
func (l *Link) takeWatch(c *Cursor) {
	s := &l.skew
	s.mu.Lock()
	defer s.mu.Unlock()
	wt := &s.wt
	if wt.taken {
		return
	}
	wt.taken = true
	wt.w, wt.wSeq, wt.wAt, wt.r = c.W, c.WSeq, c.WAtUTC, c.R
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
	if wt.w.IsZero() {
		c.WSeq, c.WAtUTC = 0, time.Time{}
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
	if wt.liveRun != h.RunID {
		// The run's first heartbeat read in this process.
		wt.liveRun, wt.live, wt.beganOK = h.RunID, map[string]*ifLive{}, false
		kept := wt.run == h.RunID && len(wt.kept) == len(names)
		for i, n := range names {
			if kept {
				wt.live[n] = &ifLive{packets: wt.kept[i].Packets, riseAt: wt.kept[i].RiseUTC, fromBegin: true}
			} else {
				// CH-31 starts again at the run's first heartbeat read.
				wt.live[n] = &ifLive{packets: byName[n].Packets, riseAt: at, fromBegin: true}
			}
		}
		if !kept && wt.newRun == h.RunID {
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
			// start until its own packets rise (D3's B1 on #774).
			wt.live[n], changed = &ifLive{packets: byName[n].Packets, riseAt: at}, true
		}
	}
	if watchSetResets && changed && wt.newRun == h.RunID {
		wt.began, wt.beganOK = mono, true
		for _, lv := range wt.live {
			lv.fromBegin = true
		}
	}
	capture, rose := false, false
	for _, n := range names {
		ic, lv := byName[n], wt.live[n]
		if ic.Packets > lv.packets {
			lv.riseAt, lv.riseMono, lv.rose = at, mono, true
			rose = rose || ic.Carrier != "down"
		}
		lv.packets = ic.Packets
		if ic.Carrier != "down" && (lv.rose && mono-lv.riseMono <= blind || lv.fromBegin && wt.beganOK && mono-wt.began <= blind) {
			capture = true
		}
	}
	if !current || late || s.bl.on {
		return
	}
	p := wall
	if q := at.Add(s.movedELocked()); !placeAtReceipt && len(s.samples) > 0 && q.Before(p) {
		p = q
	}
	if unix0 := time.Unix(0, 0); p.Before(unix0) {
		p = unix0
	}
	if rose {
		wt.r = p
	}
	if capture {
		wt.w, wt.wSeq, wt.wAt, wt.placed = p, num(h.Seq), at, true
		wt.run, wt.kept = h.RunID, make([]IfaceMark, len(names))
		for i, n := range names {
			wt.kept[i] = IfaceMark{Packets: wt.live[n].packets, RiseUTC: wt.live[n].riseAt}
		}
	}
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
		if back := -diff; back > MaxSkew || stepAnyBack && back > 0 {
			s.moveBackLocked(back)
		} else {
			wt.unfound += diff
		}
	}
	wt.chkWall, wt.chkMono, wt.checked = wall, mono, true
	if wt.placed {
		// A value still later than the wall clock is a step the check
		// could not measure: it takes the wall-clock time.
		capped := time.Duration(0)
		for _, t := range []*time.Time{&wt.w, &wt.r} {
			if t.After(wall) {
				capped = max(capped, t.Sub(wall))
				*t = wall
			}
		}
		if capped > 0 {
			wt.owedStep, wt.owedSave = wt.owedStep+capped, true
		}
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

// moveBackLocked moves W, R, the run file's copy and E's held samples back
// by d; the copy is moved when the run file next takes it, whether or not
// W or R is held (D3's B3 on #774). The caller holds s.mu.
func (s *skew) moveBackLocked(d time.Duration) {
	wt := &s.wt
	for _, t := range []*time.Time{&wt.w, &wt.r} {
		if !t.IsZero() {
			*t = t.Add(-d)
		}
	}
	if !stepCopyUnmoved {
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

// watchedCopy is the run file's copy: the earlier of W and R, zero when
// neither is held; and back, the steps found since the last call, by which
// the file's own copy moves. The step check runs first, and moves them
// back if it finds a step; its event and the cursor's save wait for the
// next check that can act, since the run file is being written.
func (l *Link) watchedCopy() (c time.Time, back time.Duration) {
	l.measureStep()
	s := &l.skew
	s.mu.Lock()
	defer s.mu.Unlock()
	w, r := s.wt.w, s.wt.r
	back, s.wt.copyBack = s.wt.copyBack, 0
	switch {
	case w.IsZero():
		return r, back
	case r.IsZero() || w.Before(r):
		return w, back
	}
	return r, back
}

// watchNow is W and R as the link holds them.
func (l *Link) watchNow() (w, r time.Time) {
	s := &l.skew
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.wt.w, s.wt.r
}
