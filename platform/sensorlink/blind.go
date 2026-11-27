package sensorlink

import (
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"otsec.local/otsec/contracts/netobs"
)

// The blindness alarms, P4-4-INT-D5-BLIND (C13 CH-31, CH-44, CH-45;
// docs/phase4/D5-sensor-node.md section 1.8). The 0.2 intake only, as the
// skew gate is (skewOn). Not wired (F-027's gate). No gap rule is here:
// the blind gap is place's (watch.go).
//
//   - Current: a heartbeat on a connection whose hello is current, of the
//     hello's run, not late (CH-23), read while no backlog is on (CH-39).
//     Late and backlog heartbeats neither raise nor clear sensor-blind, nor
//     end coverage unknown; 2e's capture check takes them for W and R.
//   - sensor-blind (CH-31), judged at each current heartbeat on the node's
//     monotonic clock: an interface is blind when its carrier is down, or
//     its packets have not risen across the current heartbeats of more
//     than blind_after_s, or it was first seen within the comparison and
//     has not risen since. The comparison starts again at a new run's
//     first current heartbeat, where an interface named in a standing
//     stretch has no grace: the stretch stands until its packets rise in
//     the new run (D3's and D6's B1 on #802). One stretch per sensor: the
//     status alarm and
//     its pool event once, at the stretch's start, naming the interfaces
//     blind then; an interface that goes blind inside the stretch is named
//     in it, in BlindStatus and in a pool event that names every interface
//     of the stretch, with no second status alarm. The stretch ends at a
//     current heartbeat with no interface blind. Its names are at most
//     MaxInterfaces; past that, a count of the rest, once a run, goes in
//     the detail (D3's N4 on #802).
//   - sensor-no-heartbeat and coverage unknown (CH-44): at every accepted
//     frame that is not a current heartbeat (a tick that is not early, a
//     late or backlog heartbeat taken, an observation committed, held or
//     dropped by the budget; D3's N1 on #802), when no current heartbeat
//     has come for NoHeartbeatAfter (since the link was made, when none
//     has come), once a stretch; the stretch ends at a current heartbeat
//     only. A sensor-blind that stands when it begins stays standing
//     through it.
//   - sensor.past-blind (CH-44): every heartbeat, in the order read, keeps
//     each interface's packets and the at_utc of its last rise (or of the
//     run's first heartbeat read here); at a heartbeat that is not
//     current, an interface is past-blind as sensor-blind's rule says, on
//     the sensor's at_utc. A stretch of them ends at a heartbeat that is
//     not current with none past-blind, at a current heartbeat, or at a new
//     run; ended stretches are merged and made due in the pool, one event,
//     once no backlog is on, their names at most MaxInterfaces and a count
//     of the rest. Both are held in memory only: a node stop loses them.
//   - Accepted (CH-44's reset of sensor-unreachable): a tick that is not
//     early, a heartbeat taken, and an observation committed, held or
//     dropped by the budget count; a refused record, a failed hello, an
//     early tick, a duplicate and a connect do not. CH-17 counts a
//     duplicate as taken, so its exclusion is the stricter reading, towards
//     the alarm. The node's timer reads Stats.Accepted and
//     Stats.AcceptedMono.

// The alarms of this file (CH-45's pool list).
const (
	AlarmBlind       = "sensor-blind"
	AlarmNoHeartbeat = "sensor-no-heartbeat"
)

// NoHeartbeatAfter is CH-44's 60 s.
const NoHeartbeatAfter = 60 * time.Second

// Test seams, each false in the node: the controls of the brief's tests.
// blindBacklogCounts judges sensor-blind from every heartbeat that is not
// late; blindLateCounts from every heartbeat that is not a backlog's;
// blindAtLimit takes an interface blind at blind_after_s exactly;
// blindAllOnly raises sensor-blind only when every interface is blind;
// blindCarrierIgnored takes no interface blind for its carrier;
// blindFirstOnly names only the interfaces blind at the stretch's start;
// blindAcrossRuns carries the comparison across runs; blindEachHeartbeat
// raises at every current heartbeat that finds one blind; blindClearsAtUnknown
// ends sensor-blind's stretch when coverage unknown begins;
// noHbAnyEnds ends coverage unknown at any heartbeat; noHbPastLimit
// raises only past NoHeartbeatAfter; noHbEachTick raises at every tick of
// the stretch; pastBlindOff records no past stretch; pastBlindAtOnce makes
// it due at its end, backlog or not; acceptedAnyFrame counts every frame
// read, the hello included, as accepted; blindNewRunGrace gives every
// interface the grace at a new run, a named one included; noHbTicksOnly
// checks sensor-no-heartbeat at accepted ticks only; blindNamesUncapped
// keeps every name of a stretch.
var blindBacklogCounts, blindLateCounts, blindAtLimit, blindAllOnly, blindCarrierIgnored, blindFirstOnly, blindAcrossRuns bool
var blindEachHeartbeat, blindClearsAtUnknown, noHbAnyEnds, noHbPastLimit, noHbEachTick, pastBlindOff, pastBlindAtOnce, acceptedAnyFrame bool
var blindNewRunGrace, noHbTicksOnly, blindNamesUncapped bool

// ifBlind is one interface's state for sensor-blind (mono) or for
// sensor.past-blind (at).
type ifBlind struct {
	packets uint64
	mono    time.Duration // the last rise, or the comparison's start
	at      time.Time     // the same on the sensor's clock
	rose    bool          // a baseline is held: false for a name first seen within it
}

// pastStretch is one or more ended past-blind stretches, merged: at most
// MaxInterfaces names, and more counts those past it, once a stretch.
type pastStretch struct {
	from, to time.Time
	names    []string
	more     int
	n        int
}

// blindState is the file's state, under its own leaf lock.
type blindState struct {
	mu   sync.Mutex
	made time.Duration // the link's making, coverage unknown's base before any current heartbeat
	// sensor-blind: the run compared, its interfaces, and the stretch.
	run      string
	live     map[string]*ifBlind
	standing bool
	named    []string
	// over is the stretch's names past MaxInterfaces in this run, and
	// overPrev the count of those in earlier runs.
	over     []string
	overPrev int
	// Coverage unknown: the last current heartbeat's receipt.
	cur     time.Duration
	curSeen bool
	unknown bool
	// sensor.past-blind: the run, its interfaces, the stretch open and the
	// ended ones waiting for the backlog to drain.
	pastRun string
	past    map[string]*ifBlind
	open    *pastStretch
	pend    *pastStretch
}

// BlindStatus is what status shows of this file: the interfaces named in
// the standing sensor-blind stretch, and coverage unknown.
type BlindStatus struct {
	Blind           []string
	CoverageUnknown bool
}

// BlindStatus returns the blindness state.
func (l *Link) BlindStatus() BlindStatus {
	b := &l.blind
	b.mu.Lock()
	defer b.mu.Unlock()
	return BlindStatus{Blind: slices.Clone(b.named), CoverageUnknown: b.unknown}
}

// acceptedFrame counts a frame accepted under CH-44, which resets the
// node's sensor-unreachable timer.
func (l *Link) acceptedFrame() {
	m := l.opt.Monotonic()
	l.mu.Lock()
	l.stats.Accepted++
	l.stats.AcceptedMono = m
	l.mu.Unlock()
}

// acceptedRecord is an observation accepted under CH-44: it resets the
// node's timer, and is a frame that is not a current heartbeat.
func (l *Link) acceptedRecord() {
	l.acceptedFrame()
	l.noHeartbeat(false)
}

// frameRead is acceptedAnyFrame's control: every frame read counts.
func (l *Link) frameRead() {
	if acceptedAnyFrame {
		l.acceptedFrame()
	}
}

// blindIn is whether an interface is blind at t since its last rise,
// under CH-31's rule.
func blindIn(carrier string, rose bool, since, limit time.Duration) bool {
	if carrier == "down" && !blindCarrierIgnored {
		return true
	}
	if !rose {
		return true
	}
	if blindAtLimit {
		return since >= limit
	}
	return since > limit
}

// judgeBlind takes heartbeat h, taken: sensor-blind and the end of
// coverage unknown at a current one, the past-blind state at every one.
// late: it is later than late_bound_s.
func (l *Link) judgeBlind(cn *conn, h *netobs.Heartbeat, late bool) {
	if !l.skewOn() {
		return
	}
	s := &l.skew
	s.mu.Lock()
	backlog := s.bl.on
	s.mu.Unlock()
	hello := cn.hello != nil && cn.hello.Current != nil && *cn.hello.Current && cn.hello.RunID == h.RunID
	current := hello && !late && !backlog
	judged := hello && (!late || blindLateCounts) && (!backlog || blindBacklogCounts)
	m, at, limit := l.opt.Monotonic(), parseUTC(h.AtUTC), l.blindAfter()
	byName := map[string]netobs.InterfaceCount{}
	for _, i := range h.Interfaces {
		byName[i.Name] = i
	}
	names := ifaceNames(h)
	b := &l.blind
	b.mu.Lock()
	pastDue := b.pastLocked(h.RunID, names, byName, at, limit, current, backlog)
	if current || noHbAnyEnds {
		b.cur, b.curSeen, b.unknown = m, true, false
	}
	var raise, due bool
	var named []string
	var more int
	if judged {
		raise, due, named, more = b.liveLocked(h.RunID, names, byName, m, limit)
	}
	b.mu.Unlock()
	l.blindRaise(raise, due, named, more, limit)
	l.pastDue(pastDue)
	if !current {
		l.noHeartbeat(false)
	}
}

// liveLocked is sensor-blind at a current heartbeat: whether the stretch's
// alarm is raised, whether its event is due again for a name added, and
// the names it carries with the count past MaxInterfaces. The caller holds
// b.mu.
func (b *blindState) liveLocked(run string, names []string, byName map[string]netobs.InterfaceCount, m, limit time.Duration) (raise, due bool, named []string, more int) {
	if b.run != run && (!blindAcrossRuns || b.run == "") {
		// The run's first current heartbeat: the comparison starts again.
		// An interface named in a standing stretch has no grace, so the
		// stretch stands until it rises (D3's and D6's B1 on #802).
		b.run, b.live = run, map[string]*ifBlind{}
		for _, n := range names {
			inStretch := b.standing && slices.Contains(b.named, n) && !blindNewRunGrace
			b.live[n] = &ifBlind{packets: byName[n].Packets, mono: m, rose: !inStretch}
		}
		b.overPrev, b.over = b.overPrev+len(b.over), nil
	}
	b.run = run
	for n := range b.live {
		if _, ok := byName[n]; !ok {
			delete(b.live, n)
		}
	}
	var blind []string
	for _, n := range names {
		ic, lv := byName[n], b.live[n]
		if lv == nil {
			// First seen within the comparison: no grace until it rises.
			lv = &ifBlind{packets: ic.Packets}
			b.live[n] = lv
		} else if ic.Packets > lv.packets {
			lv.mono, lv.rose = m, true
		}
		lv.packets = ic.Packets
		if blindIn(ic.Carrier, lv.rose, m-lv.mono, limit) {
			blind = append(blind, n)
		}
	}
	if blindAllOnly && len(blind) < len(names) {
		blind = nil
	}
	switch {
	case len(blind) == 0:
		b.standing, b.named, b.over, b.overPrev = false, nil, nil, 0
	case !b.standing || blindEachHeartbeat:
		b.standing, b.named, b.over, b.overPrev = true, blind, nil, 0
		raise = true
	case !blindFirstOnly:
		for _, n := range blind {
			due = b.addName(n) || due
		}
	}
	return raise, due, slices.Clone(b.named), b.overPrev + len(b.over)
}

// addName names n in the standing stretch, or past MaxInterfaces names
// counts it once in this run; it reports whether either grew. The caller
// holds b.mu.
func (b *blindState) addName(n string) bool {
	switch {
	case slices.Contains(b.named, n) || slices.Contains(b.over, n):
		return false
	case len(b.named) < netobs.MaxInterfaces || blindNamesUncapped:
		b.named = append(b.named, n)
		slices.Sort(b.named)
	default:
		b.over = append(b.over, n)
	}
	return true
}

// nameList is names for a detail, with the count of those not listed.
func nameList(names []string, more int) string {
	s := strings.Join(names, ", ")
	if more > 0 {
		s += fmt.Sprintf(", and %d more not listed", more)
	}
	return s
}

// pastLocked keeps the past-blind state at heartbeat h of run, and returns
// the ended stretches to make due now, nil when none. The caller holds
// b.mu.
func (b *blindState) pastLocked(run string, names []string, byName map[string]netobs.InterfaceCount, at time.Time, limit time.Duration, current, backlog bool) (due *pastStretch) {
	if b.pastRun != run {
		b.endPastLocked()
		b.pastRun, b.past = run, map[string]*ifBlind{}
		for _, n := range names {
			b.past[n] = &ifBlind{packets: byName[n].Packets, at: at, rose: true}
		}
	}
	for n := range b.past {
		if _, ok := byName[n]; !ok {
			delete(b.past, n)
		}
	}
	var blind []string
	from := at
	for _, n := range names {
		ic, p := byName[n], b.past[n]
		if p == nil {
			p = &ifBlind{packets: ic.Packets, at: at}
			b.past[n] = p
		} else if ic.Packets > p.packets {
			p.at, p.rose = at, true
		}
		p.packets = ic.Packets
		if !current && blindIn(ic.Carrier, p.rose, at.Sub(p.at), limit) {
			blind = append(blind, n)
			if p.at.Before(from) {
				from = p.at
			}
		}
	}
	switch {
	case current || len(blind) == 0 || pastBlindOff:
		b.endPastLocked()
	case b.open == nil:
		b.open = &pastStretch{from: from, to: at, names: blind, n: 1}
	default:
		b.open.to = at
		for _, n := range blind {
			if !slices.Contains(b.open.names, n) {
				b.open.names = append(b.open.names, n)
			}
		}
		slices.Sort(b.open.names)
	}
	if b.pend != nil && (!backlog || pastBlindAtOnce) {
		due, b.pend = b.pend, nil
	}
	return due
}

// endPastLocked ends the open past stretch, merged into those waiting.
// The caller holds b.mu.
func (b *blindState) endPastLocked() {
	o := b.open
	if o == nil {
		return
	}
	b.open = nil
	if b.pend == nil {
		b.pend = o
		return
	}
	p := b.pend
	p.from, p.to, p.n, p.more = minTime(p.from, o.from), maxTime(p.to, o.to), p.n+o.n, p.more+o.more
	for _, n := range o.names {
		switch {
		case slices.Contains(p.names, n):
		case len(p.names) < netobs.MaxInterfaces || blindNamesUncapped:
			p.names = append(p.names, n)
		default:
			p.more++ // D3's N4 on #802: the names merged across runs are bounded
		}
	}
	slices.Sort(p.names)
}

func minTime(a, b time.Time) time.Time {
	if b.Before(a) {
		return b
	}
	return a
}

func maxTime(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

// blindRaise raises sensor-blind for the stretch, or makes its event due
// again for a name added inside it.
func (l *Link) blindRaise(raise, due bool, named []string, more int, limit time.Duration) {
	if !raise && !due {
		return
	}
	detail := fmt.Sprintf("sensor %s: interfaces blind in this stretch: %s (packets not risen across the current heartbeats of more than %s, or carrier down)",
		l.cfg.SensorID, nameList(named, more), limit)
	if raise {
		l.raise(AlarmBlind, detail)
		return
	}
	if h := l.opt.Health; h != nil {
		h.alarm(AlarmBlind, detail)
	}
}

// pastDue makes the past-blind stretches p due in the pool, one event.
func (l *Link) pastDue(p *pastStretch) {
	h := l.opt.Health
	if p == nil || h == nil {
		return
	}
	detail := fmt.Sprintf("sensor %s: interfaces %s showed no capture in late or backlog heartbeats from %s to %s (blind_after_s %s)",
		l.cfg.SensorID, nameList(p.names, p.more), canonUTC(p.from), canonUTC(p.to), l.blindAfter())
	if p.n > 1 {
		detail += fmt.Sprintf("; %d stretches merged", p.n)
	}
	h.alarm(EventPastBlind, detail)
}

// noHeartbeat is CH-44 at an accepted frame that is not a current
// heartbeat (tick: a tick that is not early): coverage unknown, and
// sensor-no-heartbeat once a stretch.
func (l *Link) noHeartbeat(tick bool) {
	if !l.skewOn() || noHbTicksOnly && !tick {
		return
	}
	m := l.opt.Monotonic()
	b := &l.blind
	b.mu.Lock()
	base := b.made
	if b.curSeen {
		base = b.cur
	}
	quiet := m - base
	due := quiet >= NoHeartbeatAfter
	if noHbPastLimit {
		due = quiet > NoHeartbeatAfter
	}
	raise := due && (!b.unknown || noHbEachTick)
	if due {
		b.unknown = true
		if blindClearsAtUnknown {
			b.standing, b.named = false, nil
		}
	}
	b.mu.Unlock()
	if raise {
		l.raise(AlarmNoHeartbeat, fmt.Sprintf("sensor %s: coverage unknown: frames are accepted, and no current heartbeat has come for %s", l.cfg.SensorID, quiet))
	}
}

// pastBlindTick makes the ended past-blind stretches due once no backlog
// is on, at the node's tick.
func (l *Link) pastBlindTick() {
	if !l.skewOn() {
		return
	}
	s := &l.skew
	s.mu.Lock()
	backlog := s.bl.on
	s.mu.Unlock()
	b := &l.blind
	b.mu.Lock()
	var p *pastStretch
	if b.pend != nil && !backlog {
		p, b.pend = b.pend, nil
	}
	b.mu.Unlock()
	l.pastDue(p)
}
