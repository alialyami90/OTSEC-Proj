package sensorlink

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"otsec.local/otsec/contracts/netobs"
)

// The gap model while the node runs, INT-D5 2e-2 (docs/phase4/D5-sensor-node.md
// section 1.9 item 5; C13 CH-39, CH-45). The 0.2 intake only, as W is
// (watch.go). Not wired (F-027's gate).

// gapCauses is CH-45's closed set of causes, in the order of their bits in
// the cursor.
var gapCauses = []string{"node-start", "link", "restart", "held", "revoked", "sensor-failed", "silent", "lost", "blind"}

// The causes 2e-2 opens or adds.
const (
	CauseLink         = "link"
	CauseRestart      = "restart"
	CauseSensorFailed = "sensor-failed"
	CauseSilent       = "silent"
	CauseBlind        = "blind"
)

// gapCauseBit is cause's bit, 0 for a token outside the set.
func gapCauseBit(cause string) uint16 {
	for i, c := range gapCauses {
		if c == cause {
			return 1 << i
		}
	}
	return 0
}

// causeNames is bits as CH-45's causes detail: the tokens, space-separated,
// in gapCauses' order.
func causeNames(bits uint16) string {
	var out []string
	for i, c := range gapCauses {
		if bits&(1<<i) != 0 {
			out = append(out, c)
		}
	}
	return strings.Join(out, " ")
}

// HeldGap is the gap held for the floor (CH-18, CH-45): a gap closed
// unwatched whose raise of W, R and the floor is saved before its event
// commits, with every gap other than lost that closed unwatched while it
// waited merged into it.
type HeldGap struct {
	From    time.Time `json:"from"`
	To      time.Time `json:"to"`
	Cause   string    `json:"cause"`
	Causes  uint16    `json:"causes"`
	Gaps    uint64    `json:"gaps"`
	Stepped bool      `json:"stepped,omitempty"`
	Bound   bool      `json:"bound,omitempty"`
}

// gapOpenAfter is how long a link, silent or node-start gap stands before
// it is written open (CH-45, "When it is written").
const gapOpenAfter = 60 * time.Second

// Test seams, each false in the node: the controls of 2e-2's legs.
// gapChainSeqOnly judges a chain by part 1 alone; gapChainNoSpacing skips
// part 3; gapChainNoCount skips part 4; gapChainCarrierOnly reads part 2
// by the carrier alone; gapChainIgnoresStep lets the chain close a gap
// marked clock_stepped; gapCloseAtReconnect closes a link gap as covered
// at the first current heartbeat, before the backlog is through;
// gapSilentOff never opens a silent gap; gapAtOpen starts a gap at the
// moment it opens, not at the earlier of W and R; gapNoFloor never takes
// W or R up to the floor; gapOneBudget writes every cause under the lost
// budget; gapWriteBehind writes later records while a closing record
// waits; gapMergeLastStart writes a merged record from the last gap's
// start; gapRiseNoTotal counts a rise without a rise of counters.packets;
// gapRiseFirstSeen keeps a name's rise_utc as the heartbeat it was first
// seen in; gapFromW starts a gap at W, not at the earlier of W and R;
// gapChainAnyRun lets a chain run across a new run; gapOpenNever writes a
// gap only when it closes.
// gapNeedsObservation closes a gap as covered only once an observation
// was read after its open.
// gapSilentEndsAtCurrent ends a silent gap's cause at the first current
// heartbeat, whatever its lateness; gapChainAnyNames lets a chain run
// across a change of the names.
// gapMarkOpenOnly marks at a step only the gap open then;
// gapMergeHeldMark keeps at a merge only the held gap's mark.
// gapRecordFirst writes an unwatched close's record before its raise is
// saved.
// gapChainSignedRise reads part 2 signed, so a rise later than the
// heartbeat's own at_utc counts; gapChainFallBackOK lets at_utc fall back
// within a chain (D6's B1 on #781, D1's ruling 1).
var gapMarkOpenOnly, gapMergeHeldMark, gapRecordFirst, gapChainSignedRise, gapChainFallBackOK bool

// The named controls of section 15 committed as seams (D6's N3 on #781):
// gapChainStretch fails part 2 only on a stretch longer than blind with no
// heartbeat showing capture (V-17's third and fourth cases);
// gapBlindFromAnyRise takes R at any rise, whatever its carrier, and
// starts a gap from R (V-17's seventh); gapMergeLastMark keeps at a merge
// the last gap's mark only (V-6's second); gapLengthWall takes the
// chain's length from the wall clock (V-9's third); gapSilentNeverCovered
// closes a silent gap only unwatched (V-16's second); gapWAtReceipt places
// W at its receipt and R as built, gapRAtReceipt R at its receipt and W as
// built (V-16's fifth, V-17's ninth).
var gapChainStretch, gapBlindFromAnyRise, gapMergeLastMark, gapLengthWall, gapSilentNeverCovered, gapWAtReceipt, gapRAtReceipt bool
var gapFromW, gapChainAnyRun, gapOpenNever, gapNeedsObservation, gapSilentEndsAtCurrent, gapChainAnyNames bool
var gapChainSeqOnly, gapChainNoSpacing, gapChainNoCount, gapChainCarrierOnly, gapChainIgnoresStep, gapCloseAtReconnect bool

// gapsOff opens no gap: 2e-1's placement tests, whose heartbeats a
// minute apart would otherwise open silent gaps, test W and R alone.
var gapsOff bool
var gapSilentOff, gapAtOpen, gapNoFloor, gapOneBudget, gapWriteBehind, gapMergeLastStart, gapRiseNoTotal, gapRiseFirstSeen bool

// openGap is the gap open now: at most one for a sensor.
type openGap struct {
	from     time.Time
	cause    string
	causes   uint16
	openMono time.Duration
	// wMono is W on the monotonic clock at the open, from which the 60 s
	// and the chain's part 4 are counted.
	wMono   time.Duration
	stepped bool
	written bool // its open record is committed
}

// waitRec is a closing record that waits: the gap held for the floor when
// it is unwatched, or a covered close of a gap written open.
type waitRec struct {
	HeldGap
	covered bool
}

// chainIf is one interface in the chain: its packets and the at_utc of
// its last rise.
type chainIf struct {
	packets uint64
	rise    time.Time
}

// chain is CH-39's chain from W's heartbeat, extended by every heartbeat
// of its run read after it.
type chain struct {
	ok     bool
	run    string
	seq    uint64
	at     time.Time
	n      int
	g, d   uint64
	total  uint64
	ifs    map[string]*chainIf
	wMono  time.Duration
	reason string    // why it failed, for the tests
	shown  time.Time // gapChainStretch's control only: the last heartbeat that showed capture
}

// chainShows is CH-39's part 2 for one heartbeat, by at_utc: some
// interface's carrier is not down and its last rise is at or before at,
// within blind of it (D1's ruling 1 on #781).
func chainShows(h *netobs.Heartbeat, ifs map[string]*chainIf, at time.Time, blind time.Duration) bool {
	for _, i := range h.Interfaces {
		c := ifs[i.Name]
		if c == nil || i.Carrier == "down" {
			continue
		}
		if gapChainCarrierOnly || (gapChainSignedRise || !at.Before(c.rise)) && at.Sub(c.rise) <= blind {
			return true
		}
	}
	return false
}

// startChainLocked starts the chain at W's heartbeat h. The caller holds
// s.mu.
func (s *skew) startChainLocked(cn *conn, h *netobs.Heartbeat, at time.Time, wMono, blind time.Duration) {
	wt := &s.wt
	ch := chain{ok: true, run: h.RunID, seq: num(h.Seq), at: at, n: 1, total: h.Counters.Packets, ifs: map[string]*chainIf{}, wMono: wMono}
	if cn != nil && cn.cur != nil {
		ch.g, ch.d = cn.cur.G, cn.cur.D
	}
	for _, i := range h.Interfaces {
		lv := wt.live[i.Name]
		ch.ifs[i.Name] = &chainIf{packets: i.Packets, rise: lv.riseAt}
	}
	switch {
	case gapChainSeqOnly:
	case chainShows(h, ch.ifs, at, blind):
		ch.shown = at
	case !gapChainStretch:
		ch.ok, ch.reason = false, "part 2 at W"
	}
	wt.ch = ch
}

// extendChainLocked extends the chain by heartbeat h of its run, read
// after its last. The caller holds s.mu.
func (s *skew) extendChainLocked(h *netobs.Heartbeat, at time.Time, blind time.Duration) {
	ch := &s.wt.ch
	if !ch.ok || ch.run == "" {
		return
	}
	n := num(h.Seq)
	switch {
	case h.RunID != ch.run && gapChainAnyRun:
		ch.run = h.RunID
	case h.RunID != ch.run:
		ch.ok, ch.reason = false, "another run"
		return
	case n <= ch.seq:
		return
	}
	// The names must be the names kept with W, one for one (CH-39 part 2;
	// D1's ruling on D6's N4 on #781).
	if gapChainAnyNames {
		for _, i := range h.Interfaces {
			if ch.ifs[i.Name] == nil {
				ch.ifs[i.Name] = &chainIf{packets: i.Packets, rise: at}
			}
		}
	} else if len(h.Interfaces) != len(ch.ifs) {
		ch.ok, ch.reason = false, "names"
		return
	}
	for _, i := range h.Interfaces {
		if ch.ifs[i.Name] == nil {
			ch.ok, ch.reason = false, "names"
			return
		}
	}
	if gapChainSeqOnly {
		ch.total, ch.seq, ch.at = h.Counters.Packets, n, at
		ch.n++
		return
	}
	if !gapChainNoSpacing && at.Sub(ch.at) > HeartbeatGapMax {
		ch.ok, ch.reason = false, "part 3"
		return
	}
	if !gapChainFallBackOK && at.Before(ch.at) {
		ch.ok, ch.reason = false, "part 3, at_utc fell back" // D1's ruling 1 on #781
		return
	}
	totalRose := h.Counters.Packets > ch.total || gapRiseNoTotal
	for _, i := range h.Interfaces {
		c := ch.ifs[i.Name]
		if i.Packets > c.packets && totalRose {
			c.rise = at
		}
		c.packets = i.Packets
	}
	ch.total, ch.seq, ch.at = h.Counters.Packets, n, at
	ch.n++
	if chainShows(h, ch.ifs, at, blind) {
		ch.shown = at
	} else if !gapChainStretch || at.Sub(ch.shown) > blind {
		ch.ok, ch.reason = false, "part 2"
	}
}

// chainCoversLocked reports whether the chain closes the open gap as
// covered at a current heartbeat read at wall and mono (CH-39's four
// parts). The caller holds s.mu.
func (s *skew) chainCoversLocked(cn *conn, wall time.Time, mono time.Duration) bool {
	wt := &s.wt
	g, ch := wt.open, &wt.ch
	if g.causes&(gapCauseBit(CauseBlind)|gapCauseBit(CauseSensorFailed)) != 0 {
		return false
	}
	if g.stepped && !gapChainIgnoresStep {
		return false
	}
	if !ch.ok || ch.run == "" || cn == nil || cn.cur == nil || cn.cur.RunID != ch.run {
		return false
	}
	if gapNeedsObservation && !wt.obsSeen {
		return false
	}
	if !gapChainAnyRun && (cn.cur.G != ch.g || cn.cur.D != ch.d) {
		return false // part 1
	}
	if gapChainSeqOnly || gapChainNoCount {
		return true
	}
	length := mono - ch.wMono
	if gapLengthWall {
		length = wall.Sub(wt.w)
	}
	return time.Duration(ch.n)*HeartbeatGapMax >= length // part 4
}

// earlierWR is the earlier of W and R, zero when neither is held.
func (wt *watch) earlierWR() time.Time {
	switch {
	case wt.w.IsZero():
		return wt.r
	case wt.r.IsZero() || wt.w.Before(wt.r):
		return wt.w
	}
	return wt.r
}

// openLocked opens a gap of cause from the earlier of W and R, or adds
// cause to the gap open now. With neither held it opens nothing: a gap
// from a bound is 2e-3's and P4-4-DE's. The caller holds s.mu.
func (s *skew) openLocked(cause string, wall time.Time, mono time.Duration) {
	wt := &s.wt
	if gapsOff {
		return
	}
	if g := wt.open; g != nil {
		g.causes |= gapCauseBit(cause)
		return
	}
	from := wt.earlierWR()
	if gapFromW && !wt.w.IsZero() {
		from = wt.w
	}
	if gapBlindFromAnyRise && !wt.r.IsZero() {
		from = wt.r
	}
	if from.IsZero() {
		return
	}
	if gapAtOpen {
		from = wall
	}
	wMono := mono
	if wt.placed {
		wMono = min(wt.wMono, mono)
	}
	wt.obsSeen = false
	wt.open = &openGap{from: from, cause: cause, causes: gapCauseBit(cause), openMono: mono, wMono: wMono}
	wt.gapDue = true
}

// closeLocked closes the gap open now at to: as covered, or unwatched, in
// which case W, R and the floor are raised to to and the gap is held for
// the floor, merged into the record that waits if one does. The caller
// holds s.mu.
func (s *skew) closeLocked(covered bool, to time.Time) {
	wt := &s.wt
	g := wt.open
	wt.open = nil
	wt.gapDue = true
	if covered {
		if g.written {
			if wt.wait == nil {
				wt.wait = &waitRec{HeldGap: HeldGap{From: g.from, To: to, Cause: g.cause, Causes: g.causes, Gaps: 1, Stepped: g.stepped}, covered: true}
			} else {
				// Behind a waiting record: merged, and unwatched from the
				// first's start, which fails closed.
				s.mergeLocked(g, to)
			}
		}
		return
	}
	if wt.wait == nil {
		wt.wait = &waitRec{HeldGap: HeldGap{From: g.from, To: to, Cause: g.cause, Causes: g.causes, Gaps: 1, Stepped: g.stepped}}
	} else {
		s.mergeLocked(g, to)
	}
	if !gapNoFloor {
		for _, t := range []*time.Time{&wt.w, &wt.r} {
			if t.IsZero() || t.Before(to) {
				*t = to
			}
		}
		wt.floor = to
	}
	wt.frozen = false
	wt.heldSave = true
}

// mergeLocked merges the closed gap g, ending at to, into the record that
// waits: its start kept, its end, causes and count taken, the mark carried
// if either carries it (CH-45, "Budgets and merging").
func (s *skew) mergeLocked(g *openGap, to time.Time) {
	w := s.wt.wait
	if gapMergeLastStart {
		w.From = g.from
	}
	w.To, w.Causes, w.Gaps, w.covered = to, w.Causes|g.causes, w.Gaps+1, false
	switch {
	case gapMergeLastMark:
		w.Stepped = g.stepped
	case !gapMergeHeldMark:
		w.Stepped = w.Stepped || g.stepped
	}
}

// markStepLocked marks clock_stepped on the gap open and the record that
// waits (CH-45's step rule). The caller holds s.mu.
func (s *skew) markStepLocked() {
	if g := s.wt.open; g != nil {
		g.stepped = true
	}
	if w := s.wt.wait; w != nil && !gapMarkOpenOnly {
		w.Stepped = true
	}
	s.wt.gapDue = true
}

// silentDueLocked opens a silent gap when no current heartbeat has come
// for HeartbeatGapMax since W's heartbeat's receipt, on a current link with
// no gap open (CH-45). The caller holds s.mu.
func (s *skew) silentDueLocked(wall time.Time, mono time.Duration) bool {
	wt := &s.wt
	if gapSilentOff || wt.open != nil || !wt.current || !wt.placed || s.bl.on || mono-wt.wRecv < HeartbeatGapMax {
		return false
	}
	s.openLocked(CauseSilent, wall, mono)
	return true
}

// gapRecord is the details of a sensor.coverage-gap record of a cause
// other than lost.
func gapRecord(g HeldGap, state string, covered bool) map[string]string {
	d := map[string]string{"cause": g.Cause, "causes": causeNames(g.Causes), "state": state, "from_utc": canonUTC(g.From)}
	if state == "closed" {
		d["to_utc"] = canonUTC(g.To)
		d["covered"] = strconv.FormatBool(covered)
		if g.Gaps > 1 {
			d["merged"] = strconv.FormatUint(g.Gaps, 10)
		}
	}
	if g.Stepped {
		d["clock_stepped"] = "true"
	}
	if g.Bound {
		d["from_bound"] = "true"
	}
	return d
}

// nextRecordLocked is the next gap record due, and which: the record that
// waits first, once its raise is saved; then the open gap's open record,
// at its open for blind and sensor-failed and once it has stood
// gapOpenAfter from W otherwise, and never while a closing record waits
// (CH-45's order). The caller holds s.mu.
func (s *skew) nextRecordLocked(mono time.Duration, skipWait bool) (d map[string]string, wait bool) {
	wt := &s.wt
	if w := wt.wait; w != nil && !wt.heldSave && !skipWait {
		return gapRecord(w.HeldGap, "closed", w.covered), true
	}
	if wt.wait != nil && !gapWriteBehind {
		return nil, false
	}
	g := wt.open
	if g == nil || g.written || gapOpenNever {
		return nil, false
	}
	switch g.cause {
	case CauseLink, CauseSilent, "node-start":
		if mono-g.wMono < gapOpenAfter && mono-g.openMono < gapOpenAfter {
			return nil, false
		}
	}
	return gapRecord(HeldGap{From: g.from, Cause: g.cause, Causes: g.causes, Stepped: g.stepped}, "open", false), false
}

// gapAct saves the raise of an unwatched close, then writes the gap records
// due, in order. cn is the live connection, nil at a tick or a close. The
// caller holds gmu, which orders every change of the gap open and the
// record that waits with these writes. An error is a save that failed.
func (l *Link) gapAct(ctx context.Context, cn *conn) error {
	if !l.skewOn() {
		return nil
	}
	s := &l.skew
	if gapRecordFirst {
		s.mu.Lock()
		s.wt.heldSave = false
		s.mu.Unlock()
	}
	s.mu.Lock()
	save := s.wt.heldSave
	s.mu.Unlock()
	if save {
		// The raise and the gap held for the floor are saved before the
		// gap's event commits (CH-18).
		var err error
		if cn != nil && cn.cur != nil {
			if err = l.saveCursor(ctx, cn.cur); err == nil {
				cn.saved, cn.pending, cn.lastSave = cn.cur.Taken, false, l.opt.Monotonic()
			}
		} else {
			err = l.saveMoved(ctx)
		}
		if err != nil {
			return err
		}
		s.mu.Lock()
		s.wt.heldSave = false
		s.mu.Unlock()
	}
	h := l.opt.Health
	if h == nil {
		return nil
	}
	skip := false
	for {
		s.mu.Lock()
		d, wait := s.nextRecordLocked(l.opt.Monotonic(), skip)
		var snap waitRec
		if wait {
			snap = *s.wt.wait
		}
		s.mu.Unlock()
		if d == nil {
			return nil
		}
		if h.writeGap(ctx, d) != nil {
			if wait && gapWriteBehind {
				skip = true // the control: on to the later records
				continue
			}
			return nil // it waits for its budget or the ceiling, and is tried again
		}
		s.mu.Lock()
		if wait {
			// The next save of the cursor clears it there. A step found
			// while it was written marks it again, and it is written again
			// with the mark: twice, never without it.
			if w := s.wt.wait; w != nil && *w == snap {
				s.wt.wait = nil
			}
		} else if s.wt.open != nil {
			s.wt.open.written = true
		}
		s.mu.Unlock()
	}
}

// placeAndAct places W and R at heartbeat h and acts on the gap model
// under gmu, released by defer, so a panic in either leaves gmu free for
// SensorFailed, the connection's end and the tick (D6's N1 on #781).
func (l *Link) placeAndAct(ctx context.Context, cn *conn, h *netobs.Heartbeat, late bool) error {
	l.gmu.Lock()
	defer l.gmu.Unlock()
	l.place(cn, h, late)
	return l.gapAct(ctx, cn)
}

// GapStatus is the gap model's state, for status and the tests.
type GapStatus struct {
	Open     bool
	Cause    string
	Causes   string
	From     time.Time
	Written  bool
	Stepped  bool
	Waiting  *HeldGap
	Floor    time.Time
	ChainOK  bool
	ChainN   int
	ChainWhy string
}

// GapStatus returns the gap model's state.
func (l *Link) GapStatus() GapStatus {
	s := &l.skew
	s.mu.Lock()
	defer s.mu.Unlock()
	wt := &s.wt
	st := GapStatus{Floor: wt.floor, ChainOK: wt.ch.ok, ChainN: wt.ch.n, ChainWhy: wt.ch.reason}
	if g := wt.open; g != nil {
		st.Open, st.Cause, st.Causes, st.From, st.Written, st.Stepped = true, g.cause, causeNames(g.causes), g.from, g.written, g.stepped
	}
	if w := wt.wait; w != nil {
		c := w.HeldGap
		st.Waiting = &c
	}
	return st
}

// connEnded is the end of a connection: a link gap opens when its hello
// was accepted, or link joins the gap open (CH-45). When a silent gap
// falls due at the same evaluation, one gap opens, with cause link.
func (l *Link) connEnded(ctx context.Context, accepted bool) {
	if !l.skewOn() {
		return
	}
	l.gmu.Lock()
	defer l.gmu.Unlock()
	l.measureStep()
	wall, mono := l.now(), l.opt.Monotonic()
	s := &l.skew
	s.mu.Lock()
	s.wt.current = false
	if accepted {
		s.openLocked(CauseLink, wall, mono)
	}
	s.mu.Unlock()
	if err := l.gapAct(ctx, nil); err != nil {
		l.raise(AlarmPositionNotSaved, fmt.Sprintf("sensor %s: a gap's raise was not saved: %v", l.cfg.SensorID, err))
	}
}

// SensorFailed opens a sensor-failed gap at a recovered panic that stops
// the sensor's work until a restart, written open at once (CH-45). Nothing
// closes it in this process.
func (l *Link) SensorFailed(ctx context.Context) {
	if !l.skewOn() {
		return
	}
	l.gmu.Lock()
	defer l.gmu.Unlock()
	l.measureStep()
	wall, mono := l.now(), l.opt.Monotonic()
	s := &l.skew
	s.mu.Lock()
	s.wt.current = false
	s.openLocked(CauseSensorFailed, wall, mono)
	s.mu.Unlock()
	if err := l.gapAct(ctx, nil); err != nil {
		l.raise(AlarmPositionNotSaved, fmt.Sprintf("sensor %s: a gap's raise was not saved: %v", l.cfg.SensorID, err))
	}
}

// gapTick is the gap model at the node's tick: a silent gap that falls
// due, and the records due. It never waits for a frame: when a frame holds
// gmu, that frame writes what is due, and the next tick tries again.
func (l *Link) gapTick(ctx context.Context) {
	if !l.gmu.TryLock() {
		return
	}
	defer l.gmu.Unlock()
	wall, mono := l.now(), l.opt.Monotonic()
	s := &l.skew
	s.mu.Lock()
	s.silentDueLocked(wall, mono)
	s.mu.Unlock()
	if err := l.gapAct(ctx, nil); err != nil {
		l.raise(AlarmPositionNotSaved, fmt.Sprintf("sensor %s: a gap's raise was not saved: %v", l.cfg.SensorID, err))
	}
}

// gapNewRun is a new run's hello accepted: restart joins the gap open
// (CH-45), and the link is current when the hello says so.
func (l *Link) gapNewRun(newRun, current bool) {
	s := &l.skew
	s.mu.Lock()
	defer s.mu.Unlock()
	if g := s.wt.open; g != nil && newRun {
		g.causes |= gapCauseBit(CauseRestart)
	}
	s.wt.current = current
}

// sawObservation notes an observation read, for gapNeedsObservation.
func (l *Link) sawObservation() {
	s := &l.skew
	s.mu.Lock()
	defer s.mu.Unlock()
	s.wt.obsSeen = true
}
