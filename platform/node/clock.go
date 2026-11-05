package node

import "time"

// clock is what a running node reads and waits on for the received clock
// and the store (RuntimeOptions.Now's default), the scheduler's wait
// (Scheduler.Run) and the TickInterval ticker (Run). It is the wall clock.
// Only a build tagged otsec_testclock can replace it, with the stepped test
// clock of testclock.go (D4-40). Transport, certificate and startup
// deadlines stay on the wall clock in every build.
type clock interface {
	Now() time.Time
	// NewTimer and NewTicker return the channel and the stop of a
	// time.Timer or a time.Ticker on this clock.
	NewTimer(d time.Duration) (<-chan time.Time, func() bool)
	NewTicker(d time.Duration) (<-chan time.Time, func())
}

var nodeClock clock = wallClock{}

type wallClock struct{}

func (wallClock) Now() time.Time { return time.Now() }

func (wallClock) NewTimer(d time.Duration) (<-chan time.Time, func() bool) {
	t := time.NewTimer(d)
	return t.C, t.Stop
}

func (wallClock) NewTicker(d time.Duration) (<-chan time.Time, func()) {
	t := time.NewTicker(d)
	return t.C, t.Stop
}

// absoluteTimer is a clock that can arm a timer at a time on itself, not
// after a duration from a time read earlier. The test clock is one: between
// a read of its time and the arming of a timer, a step can move it, and a
// duration would then fire one step late (C6 on #447).
type absoluteTimer interface {
	NewTimerAt(at time.Time) (<-chan time.Time, func() bool)
}

// timerAt returns a timer that fires at at. On a clock without
// NewTimerAt, the wall clock, it waits wait, which the caller computed as at
// less its own now: a test's RuntimeOptions.Now may differ from the wall
// clock, and a wait is what it has always been given.
func timerAt(at time.Time, wait time.Duration) (<-chan time.Time, func() bool) {
	if a, ok := nodeClock.(absoluteTimer); ok {
		return a.NewTimerAt(at)
	}
	return nodeClock.NewTimer(wait)
}
