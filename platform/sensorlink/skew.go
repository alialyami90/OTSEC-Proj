package sensorlink

import (
	"fmt"
	"math"
	"sync"
	"time"

	"otsec.local/otsec/contracts/netobs"
)

// The skew estimate and its gate on the hold's ties (C13 CH-22, CH-23,
// CH-41; docs/phase4/D5-sensor-node.md section 1.5). It serves the 0.2
// intake only (a link with a cursor store, Options.Cursor): the 0.1 path
// has no tick and keeps main's behaviour.
//
//   - E is the least o of the connection's last 6 ticks, the hello's o
//     until the first tick; o is the node's wall time at receipt less the
//     message's sensor_utc. sensor-clock-skew stands while |E| is above
//     MaxSkew and clears at SkewClear or less.
//   - No tie is made while the alarm stands, while the latest o is outside
//     MaxSkew, or while the node's wall clock has moved against its
//     monotonic clock by more than MaxSkew since the latest sample's
//     receipt (the closure). Every observation committed then carries
//     node.skewed.
//   - K is a sample's sensor_utc less the node's monotonic time at its
//     receipt. A K that differs from its baseline by more than MaxSkew
//     raises the capture floor, and no record captured at or before the
//     floor takes a tie. The cursor keeps M, so the floor survives a
//     start; a start holds a start bound of M + HeartbeatGapMax +
//     MaxSkew, and the first break's heartbeats and every stated span
//     raise the floor.
//   - A stored time (a run's window, an open-table entry) ties only while
//     the node's wall clock has not moved by more than MaxSkew against its
//     monotonic clock since it was recorded; one recorded before the
//     node's start ties nothing.
//
// Each refusal is counted once, under the first cause that refuses it in
// D1's order (D4-92): the latest sample, the alarm, the rule on the two
// clocks, then the capture floor by what last raised it.

const (
	// SkewClear: sensor-clock-skew clears at |E| at or below it (CH-22).
	SkewClear = 1500 * time.Millisecond
	// SkewSamples is the ticks E is the least of (CH-22).
	SkewSamples = 6
	// HeartbeatGapMax is three SensorTickIntervals (CH-39).
	HeartbeatGapMax = 30 * time.Second
	// AckMaxDelay: a read-loop step longer than it before a sample marks
	// that sample as read after a held loop (CH-9; section 1.5 item 6).
	AckMaxDelay = time.Second
	// DefaultLateBound is late_bound_s's default (CH-23).
	DefaultLateBound = 180 * time.Second
	// AlarmClockSkew and AlarmRecordsLate are CH-22's and CH-23's alarms.
	AlarmClockSkew   = "sensor-clock-skew"
	AlarmRecordsLate = "sensor-records-late"
)

// The causes a tie is refused for, in counting order (section 1.5 item 5).
const (
	skewLatest   = "latest"
	skewAlarm    = "alarm"
	skewMoved    = "moved"
	skewPrestart = "prestart"
	skewSpan     = "span"
)

var skewRank = map[string]int{skewLatest: 1, skewAlarm: 2, skewMoved: 3, skewPrestart: 4, skewSpan: 5}

// first is the cause that counts among cs: the lowest rank, "" when none.
func first(cs ...string) string {
	out := ""
	for _, c := range cs {
		if c != "" && (out == "" || skewRank[c] < skewRank[out]) {
			out = c
		}
	}
	return out
}

// Test seams, each false in the node: the controls of the skew rows.
// skewGateEOnly gates ties on E alone (no latest-sample gate);
// skewMarkAlarmOnly marks only while the alarm stands; skewNoMarkAlarm
// marks nothing for the alarm; skewSubtractE places a sensor time at
// t - E; lateWithoutE judges lateness without E; skewNoFloor makes no
// refusal by the capture floor or the start bound.
var skewGateEOnly, skewMarkAlarmOnly, skewNoMarkAlarm, skewSubtractE, lateWithoutE, skewNoFloor bool

// afterMarkSeam runs in observe after the record's mark is read and
// before the hold takes it; skewTakeHeldUnmarked is its control, a hold
// that commits a record refused there without its mark. Each nil or false
// in the node.
var (
	afterMarkSeam        func()
	skewTakeHeldUnmarked bool
	// skewNoOnset: the control of the onset's release, a node that
	// releases nothing at the onset.
	skewNoOnset bool
)

// SkewStats is what status shows of the estimate (section 1.5).
type SkewStats struct {
	// E and Latest are the estimate and the latest sample; HasE is false
	// until the first sample since the node's start.
	E, Latest time.Duration
	HasE      bool
	// Alarm: sensor-clock-skew stands.
	Alarm bool
	// Floor is the capture floor, zero when none, and FloorBy what last
	// raised it (prestart, span or moved); StartBound is the start's bound,
	// zero when none.
	Floor      time.Time
	FloorBy    string
	StartBound time.Time
	// The refusals by cause, one count each (section 1.5 item 5), and the
	// samples read after a held read loop (item 6).
	AlarmWindows, LatestWindows, MovedWindows, PrestartWindows, SpanWindows, SamplesAfterHold uint64
	// Late counts the records later than late_bound_s (CH-23).
	Late uint64
}

// skew is the link's estimate. Its mutex is a leaf: taken last.
type skew struct {
	mu sync.Mutex
	// samples is the connection's: the hello's o until the first tick,
	// then the last SkewSamples ticks'.
	samples []time.Duration
	ticked  bool
	// latestOff is the node's offset (wall less monotonic) at the latest
	// sample's receipt; has, that a sample was taken since the start.
	latest    time.Duration
	latestOff int64
	has       bool
	alarm     bool
	// K's baseline and the highest K from it on; kTaken: a K was taken
	// since the start (M uses it).
	base, maxK      time.Time
	hasBase, kTaken bool
	floor           time.Time
	floorBy         string
	startBound      time.Time
	mRead           bool
	// The first break after the start: its heartbeats raise the floor
	// until the newest_seq of the first hello whose current is true is read.
	firstBreak   bool
	fbKnown      bool
	fbRun        string
	fbEnd        uint64
	lateRaisedAt *conn // the connection sensor-records-late was raised for
	stats        SkewStats
}

// skewOn reports whether the gate applies: the 0.2 intake's link.
func (l *Link) skewOn() bool { return l.opt.Cursor != nil }

// offNow is the node's wall clock less its monotonic clock, in ns.
func (l *Link) offNow() int64 { return l.now().UnixNano() - int64(l.opt.Monotonic()) }

// absDur is |d|. math.MinInt64, where time.Time.Sub saturates for a
// sensor clock about 292 years or more ahead, has no negation: it is taken
// as math.MaxInt64 (D3's B1 on #748), so the alarm, the latest sample and
// K's move each see it. absDurWraps is the control, a negation that
// wraps; false in the node.
func absDur(d time.Duration) time.Duration {
	switch {
	case d == math.MinInt64 && !absDurWraps:
		return math.MaxInt64
	case d < 0:
		return -d
	}
	return d
}

var absDurWraps bool

// minE is the least sample.
func (s *skew) minE() time.Duration {
	e := s.samples[0]
	for _, o := range s.samples[1:] {
		e = min(e, o)
	}
	return e
}

// raiseFloor raises the capture floor to t by cause; it never falls.
func (s *skew) raiseFloor(t time.Time, by string) bool {
	if !t.After(s.floor) {
		return false
	}
	s.floor, s.floorBy = t, by
	return true
}

// takeM takes the saved M at the first read of the cursor in this process:
// the floor, and the start bound beside it (section 1.5).
func (l *Link) takeM(m time.Time) {
	s := &l.skew
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.mRead {
		return
	}
	s.mRead, s.firstBreak = true, true
	if !m.IsZero() {
		s.raiseFloor(m, skewPrestart)
		s.startBound = m.Add(HeartbeatGapMax + MaxSkew)
	}
}

// mNow is M: the later of the floor and, once a K has been taken since
// the start, the highest K from the baseline on plus the monotonic time
// now; zero before the sensor's first K.
func (l *Link) mNow() time.Time {
	s := &l.skew
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.floor
	if s.kTaken {
		if k := s.maxK.Add(l.opt.Monotonic()); k.After(m) {
			m = k
		}
	}
	return m
}

// sample takes a hello's or an accepted tick's o and K (CH-22; section
// 1.5). held: the read-loop step before it lasted longer than
// AckMaxDelay. It reports whether the capture floor rose, which the caller
// saves at once, and whether no tie can be made now where one could
// before (the onset).
func (l *Link) sample(sensorUTC string, hello, held bool) (raised, onset bool) {
	su := parseUTC(sensorUTC)
	if su.IsZero() {
		return false, false
	}
	wall, mono := l.now(), l.opt.Monotonic()
	o := wall.Sub(su)
	k := su.Add(-mono)
	s := &l.skew
	s.mu.Lock()
	before := l.standingLocked()
	switch {
	case hello:
		s.samples, s.ticked = []time.Duration{o}, false
	case !s.ticked:
		s.samples, s.ticked = []time.Duration{o}, true
	default:
		s.samples = append(s.samples, o)
		if len(s.samples) > SkewSamples {
			s.samples = s.samples[len(s.samples)-SkewSamples:]
		}
	}
	s.latest, s.latestOff, s.has = o, wall.UnixNano()-int64(mono), true
	e := s.minE()
	raise := false
	switch {
	case !s.alarm && absDur(e) > MaxSkew:
		s.alarm, raise = true, true
	case s.alarm && absDur(e) <= SkewClear:
		s.alarm = false
	}
	if held {
		s.stats.SamplesAfterHold++
	}
	switch {
	case !s.hasBase:
		if !held { // never a K read after a held loop as the baseline
			s.base, s.maxK, s.hasBase = k, k, true
		}
	case absDur(k.Sub(s.base)) > MaxSkew:
		// The highest K from the baseline on, the K that shows the change
		// excluded, plus the monotonic time now plus MaxSkew (D6's N5 on
		// #641).
		raised = s.raiseFloor(s.maxK.Add(mono+MaxSkew), skewMoved)
		if !held {
			s.base, s.maxK = k, k
		}
	default:
		if k.After(s.maxK) {
			s.maxK = k
		}
	}
	s.kTaken = s.kTaken || s.hasBase
	after := l.standingLocked()
	s.mu.Unlock()
	if raise {
		l.raise(AlarmClockSkew, fmt.Sprintf("sensor %s: the estimate E is %s, above %s", l.cfg.SensorID, e, MaxSkew))
	}
	return raised, before == "" && after != ""
}

// standingLocked is the cause that refuses every tie now, "" when none:
// the latest sample, the alarm, or the node's clock moved since the
// latest sample's receipt. Before any sample since the start none stands:
// a record reaches the hold only after its connection's hello, and a run
// held before the start is refused by its window (windowRefusal). The
// caller holds s.mu.
func (l *Link) standingLocked() string {
	s := &l.skew
	switch {
	case !s.has:
		return ""
	case absDur(s.latest) > MaxSkew && !skewGateEOnly:
		return skewLatest
	case s.alarm:
		return skewAlarm
	case absDur(time.Duration(l.offNow()-s.latestOff)) > MaxSkew:
		return skewMoved
	}
	return ""
}

// marks reports whether a record committed while cause c stands carries
// node.skewed: every cause marks (CH-41).
func (l *Link) marks(c string) bool {
	switch {
	case skewMarkAlarmOnly:
		l.skew.mu.Lock()
		defer l.skew.mu.Unlock()
		return l.skew.alarm
	case skewNoMarkAlarm && c == skewAlarm:
		return false
	}
	return c != ""
}

// standing is standingLocked under the lock, "" off the 0.2 path.
func (l *Link) standing() string {
	if !l.skewOn() {
		return ""
	}
	l.skew.mu.Lock()
	defer l.skew.mu.Unlock()
	return l.standingLocked()
}

// floorRefusal is the cause for which a record captured at capt takes no
// tie by the start bound or the capture floor, "" when neither refuses.
func (l *Link) floorRefusal(capt time.Time) string {
	if !l.skewOn() || skewNoFloor {
		return ""
	}
	s := &l.skew
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case !s.startBound.IsZero() && !capt.After(s.startBound):
		return skewPrestart // the start bound counts so whatever raised the floor
	case !s.floor.IsZero() && !capt.After(s.floor):
		return s.floorBy
	}
	return ""
}

// storedRefusal is the cause for which a time recorded with the offset
// off, and known since the start (live), ties nothing now.
func (l *Link) storedRefusal(off int64, live bool) string {
	switch {
	case !l.skewOn():
		return ""
	case !live:
		return skewPrestart
	case absDur(time.Duration(l.offNow()-off)) > MaxSkew:
		return skewMoved
	}
	return ""
}

// toNode places a sensor time on the node's clock: t + E (CH-22's sign).
func (l *Link) toNode(t time.Time) time.Time {
	if !l.skewOn() {
		return t
	}
	s := &l.skew
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.samples) == 0 {
		return t
	}
	if skewSubtractE {
		return t.Add(-s.minE())
	}
	return t.Add(s.minE())
}

// countRefusal counts one refusal under its cause.
func (l *Link) countRefusal(cause string) {
	s := &l.skew
	s.mu.Lock()
	defer s.mu.Unlock()
	switch cause {
	case skewLatest:
		s.stats.LatestWindows++
	case skewAlarm:
		s.stats.AlarmWindows++
	case skewMoved:
		s.stats.MovedWindows++
	case skewPrestart:
		s.stats.PrestartWindows++
	case skewSpan:
		s.stats.SpanWindows++
	}
}

// spansRaise raises the floor from every span a message states, prior's
// included: its upper end as stated plus HeartbeatGapMax plus MaxSkew
// (section 1.5). It reports whether the floor rose.
func (l *Link) spansRaise(lists ...[]netobs.Span) bool {
	if !l.skewOn() {
		return false
	}
	s := &l.skew
	s.mu.Lock()
	defer s.mu.Unlock()
	raised := false
	for _, list := range lists {
		for _, sp := range list {
			if t := parseUTC(sp.ToUTC); !t.IsZero() && s.raiseFloor(t.Add(HeartbeatGapMax+MaxSkew), skewSpan) {
				raised = true
			}
		}
	}
	return raised
}

// helloRead notes an accepted hello for the first break: the newest_seq of
// the first hello after the start whose current is true ends it.
func (l *Link) helloRead(h *netobs.SensorHello, taken uint64) {
	s := &l.skew
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.firstBreak || s.fbKnown || h.Current == nil || !*h.Current {
		return
	}
	s.fbKnown, s.fbRun, s.fbEnd = true, h.RunID, num(h.NewestSeq)
	if s.fbEnd <= taken {
		s.firstBreak = false
	}
}

// heartbeatRaise raises the floor from a heartbeat of the first break
// (prestart's cause) and ends the break at its end. It reports whether
// the floor rose.
func (l *Link) heartbeatRaise(h *netobs.Heartbeat, n uint64) bool {
	if !l.skewOn() {
		return false
	}
	s := &l.skew
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.firstBreak {
		return false
	}
	raised := false
	if t := parseUTC(h.AtUTC); !t.IsZero() {
		raised = s.raiseFloor(t.Add(HeartbeatGapMax+MaxSkew), skewPrestart)
	}
	s.recordRead(h.RunID, n)
	return raised
}

// recordRead ends the first break once its end is read. The caller holds
// s.mu.
func (s *skew) recordRead(run string, n uint64) {
	if s.fbKnown && run == s.fbRun && n >= s.fbEnd {
		s.firstBreak = false
	}
}

// observationRead is recordRead for an observation.
func (l *Link) observationRead(run string, n uint64) {
	s := &l.skew
	s.mu.Lock()
	defer s.mu.Unlock()
	s.recordRead(run, n)
}

// late judges a record's lateness against late_bound_s: the node's wall
// time at receipt less its made time less E (CH-23). It counts a late
// record and raises sensor-records-late once for each connection.
func (l *Link) late(cn *conn, made string) bool {
	m := parseUTC(made)
	if m.IsZero() {
		return false
	}
	bound := l.opt.LateBound
	if bound <= 0 {
		bound = DefaultLateBound
	}
	at := l.toNode(m)
	if lateWithoutE {
		at = m
	}
	if l.now().Sub(at) <= bound {
		return false
	}
	s := &l.skew
	s.mu.Lock()
	s.stats.Late++
	first := s.lateRaisedAt != cn
	s.lateRaisedAt = cn
	s.mu.Unlock()
	if first {
		l.raise(AlarmRecordsLate, fmt.Sprintf("sensor %s: a record made at %s is later than %s", l.cfg.SensorID, made, bound))
	}
	return true
}

// SkewStats returns the estimate's state and counts.
func (l *Link) SkewStats() SkewStats {
	s := &l.skew
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.stats
	out.Latest, out.HasE, out.Alarm = s.latest, len(s.samples) > 0, s.alarm
	if out.HasE {
		out.E = s.minE()
	}
	out.Floor, out.FloorBy, out.StartBound = s.floor, s.floorBy, s.startBound
	return out
}
