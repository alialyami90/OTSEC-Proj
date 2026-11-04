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
