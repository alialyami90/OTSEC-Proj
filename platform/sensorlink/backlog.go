package sensorlink

import (
	"time"

	"otsec.local/otsec/contracts/netobs"
)

// The break and its backlog (C13 CH-39; docs/phase4/D5-sensor-node.md
// section 1.6). The 0.2 intake only, as the skew gate is (skewOn).
//
//   - A break runs, on the node's monotonic clock, from the last accepted
//     frame of a connection to the accepted hello of the next. After a
//     node start the first break is unknown, and counts as longer than
//     backlog_tie_s. Both ends are kept on both clocks.
//   - Its backlog is every record read from the break's end until it is
//     through. It is through at the first of (D1's ruling 7011321374 on
//     #748, option (c)): a record of run X at or above N, where X and N are
//     the run and newest_seq of the first hello after the break whose
//     current is true; run X's position at or above N (a tick's sent_seq
//     with the gap counted); a hello of another run or a later generation.
//     A sensor that holds run X open below N without sending stays a
//     backlog (AP-35's stall): it fails closed.
//   - A break that begins before a backlog is through extends it, and its
//     records are judged by the longest break of the backlog. N then
//     rises to the highest newest_seq of a hello of run X read while the
//     backlog is on, so the extended backlog, and the first break's floor
//     raise with it, are read through the records made in that break.
//   - After a break longer than backlog_tie_s, and after one whose length
//     on the wall clock differs from its length on the monotonic clock by
//     more than max_skew_ms, no backlog record takes a tie. After a shorter
//     one, a backlog record ties only if its made_utc + E falls between the
//     break's two ends on the wall clock, within max_skew_ms, and the
//     node's clock has not moved by more than max_skew_ms since the break's
//     end (a step found after the hello). Every backlog record refused is
//     committed untied with node.backlog and no node.skewed, and counted.
//   - The first backlog after a start is CH-22's first break: its
//     heartbeats raise the capture floor (skew.go).

const (
	// DefaultBacklogTie is backlog_tie_s's default, and MaxBacklogTie its
	// ceiling (CH-39).
	DefaultBacklogTie = 60 * time.Second
	MaxBacklogTie     = 120 * time.Second
)

// Test seams, each false in the node: the controls of CH-39's rows.
// breakNoMadeCheck ties a backlog record of a short break by the break's
// length alone; breakNoEnds judges a break by its monotonic length and
// made_utc only, with no rule on its two ends (the wall clock against the
// monotonic one, and a step after its end); backlogEndRecordOnly ends a
// backlog only at a record of run X at or above N (the rule before D1's
// ruling 7011321374); backlogLatestBreak judges a backlog by its latest
// break, not its longest; firstBreakKnown takes the first break after a
// start as a break of no length.
var breakNoMadeCheck, breakNoEnds, backlogEndRecordOnly, backlogLatestBreak, firstBreakKnown bool

// backlog is the break and backlog state, under the skew's leaf lock.
type backlog struct {
	// The last accepted frame of a connection, on both clocks; seen, that
	// one was accepted since the start.
	lastMono time.Duration
	lastWall time.Time
	seen     bool
	// on: a backlog is being read; first, it began with the first break
	// after the start.
	on, first bool
	// X, its generation and N, once the first current hello is read.
	known bool
	run   string
	gen   uint64
	end   uint64
	// long: a break of it is longer than backlog_tie_s, unknown, or on two
	// clocks. Otherwise from and to are its longest break's ends on the
	// wall clock, length that break's monotonic length, and toOff the
	// node's offset at its end.
	long     bool
	from, to time.Time
	length   time.Duration
	toOff    int64
}

// backlogTie is backlog_tie_s.
func (l *Link) backlogTie() time.Duration {
	if l.opt.BacklogTie <= 0 {
		return DefaultBacklogTie
	}
	return l.opt.BacklogTie
}

// frameAccepted notes a connection's accepted frame: the start of the next
// break, if the connection ends after it.
func (l *Link) frameAccepted() {
	if !l.skewOn() {
		return
	}
	wall, mono := l.now(), l.opt.Monotonic()
	s := &l.skew
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bl.lastMono, s.bl.lastWall, s.bl.seen = mono, wall, true
}

// breakEnd is an accepted hello: it ends a break and begins, or extends,
// its backlog; taken is the run's position after the hello.
func (l *Link) breakEnd(h *netobs.SensorHello, gen, taken uint64) {
	if !l.skewOn() {
		return
	}
	wall, mono, off := l.now(), l.opt.Monotonic(), l.offNow()
	bound := l.backlogTie()
	s := &l.skew
	s.mu.Lock()
	defer s.mu.Unlock()
	b := &s.bl
	long, length := !firstBreakKnown, time.Duration(0)
	if b.seen {
		length = mono - b.lastMono
		long = length > bound || (!breakNoEnds && absDur(wall.Sub(b.lastWall)-length) > MaxSkew)
	}
	if b.on && b.known && !backlogEndRecordOnly && (h.RunID != b.run || gen > b.gen) {
		b.on = false // a hello of another run or a later generation: through
	}
	switch {
	case !b.on:
		*b = backlog{lastMono: b.lastMono, lastWall: b.lastWall, seen: b.seen, on: true, first: !b.seen,
			long: long, from: b.lastWall, to: wall, length: length, toOff: off}
	case backlogLatestBreak:
		b.long, b.from, b.to, b.length, b.toOff = long, b.lastWall, wall, length, off
	case long:
		b.long = true
	case !b.long && length > b.length:
		b.from, b.to, b.length, b.toOff = b.lastWall, wall, length, off
	}
	switch n := num(h.NewestSeq); {
	case !b.known && h.Current != nil && *h.Current:
		b.known, b.run, b.gen, b.end = true, h.RunID, gen, n
	case b.known && h.RunID == b.run && gen == b.gen && n > b.end:
		// A break before the backlog was through: its records, numbered
		// past N, are read in the backlog it extends (D6's B1 on #770).
		b.end = n
	}
	b.through(h.RunID, taken)
}

// through ends the backlog when run's position or a record read reaches N.
// The caller holds the skew's lock.
func (b *backlog) through(run string, pos uint64) {
	if b.on && b.known && run == b.run && pos >= b.end {
		b.on = false
	}
}

// positionRead is a frame of run acted on, with the run's position after
// it: a record read at or above N, or a tick's sent_seq that moved the
// position to or past it, ends the backlog. Under backlogEndRecordOnly
// only a record read does.
func (l *Link) positionRead(run string, pos uint64, record bool) {
	if !l.skewOn() || (backlogEndRecordOnly && !record) {
		return
	}
	s := &l.skew
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bl.through(run, pos)
}

// breakRefuses reports whether a record made at made, read now, is a
// backlog record that takes no tie (CH-39). Off the 0.2 path, and outside
// a backlog, it is false.
func (l *Link) breakRefuses(made string) bool {
	if !l.skewOn() {
		return false
	}
	off := l.offNow()
	m := parseUTC(made)
	s := &l.skew
	s.mu.Lock()
	defer s.mu.Unlock()
	b := &s.bl
	switch {
	case !b.on:
		return false
	case b.long:
		return true
	case !breakNoEnds && absDur(time.Duration(off-b.toOff)) > MaxSkew:
		return true // a step found after the hello: the break's ends are on the old clock
	case breakNoMadeCheck:
		return false
	case m.IsZero():
		return true
	}
	at := s.toNodeLocked(m)
	return at.Before(b.from.Add(-MaxSkew)) || at.After(b.to.Add(MaxSkew))
}

// firstBreakLocked reports whether the first backlog after the start is
// being read: its heartbeats raise the capture floor (CH-22). The caller
// holds the skew's lock.
func (s *skew) firstBreakLocked() bool { return s.bl.on && s.bl.first }
