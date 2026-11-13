package sensorlink

import (
	"errors"
	"fmt"
	"runtime/debug"
	"sync"
	"time"
)

// The link's lock and its fairness rule (docs/phase4/D5-sensor-node.md
// section 1.9 item 4; F-027's F4). The read loop holds the lock through
// each network commit and each hold save, and the scheduler's calls
// (Dispatch, Result, Abandon) take it too. The scheduler goes first: while
// a scheduler call waits, the read loop does not take the lock again until
// that call has had it, so a scheduler call waits for at most the one
// record in commit. It waits at most HoldLockWait; past it the call gives
// up, holds and ties nothing, and the run goes on untied.

// HoldLockWait is the most a scheduler call waits for the link's lock
// (section 1.10; unmeasured).
const HoldLockWait = 2 * time.Second

// ErrHoldTimeout: a scheduler call did not get the link's lock within
// HoldLockWait, or panicked while it held it, which is taken as a timeout
// (section 1.9 item 9). The call held and tied nothing.
var ErrHoldTimeout = errors.New("sensorlink: the link's lock was not had within HoldLockWait")

// fairLock is a mutual exclusion lock that a scheduler call can wait for
// with a bound, and that the read loop yields to a waiting scheduler call.
type fairLock struct {
	mu   sync.Mutex
	held bool
	// waiting counts the scheduler calls waiting for the lock.
	waiting int
	// wake is closed, and replaced, at each change a waiter waits for.
	wake chan struct{}
	// checks counts the checks Lock makes of whether it may take the
	// lock, and signalled is checks at the last signal. tried and woken
	// are this package's test seams, nil in the node: tried runs, under
	// mu, at each of Lock's checks; woken runs in a scheduler call woken
	// from its wait, in place of its take of mu, and returns with mu held.
	// With them a test orders the call's check after the first check Lock
	// makes after the last signal, so which of the two goes first is not
	// left to the Go scheduler.
	checks, signalled uint64
	tried             func()
	woken             func()
}

// signal wakes every waiter. The caller holds f.mu.
func (f *fairLock) signal() {
	if f.wake != nil {
		close(f.wake)
	}
	f.wake = make(chan struct{})
	f.signalled = f.checks
}

// waitCh is the channel to wait on. The caller holds f.mu.
func (f *fairLock) waitCh() chan struct{} {
	if f.wake == nil {
		f.wake = make(chan struct{})
	}
	return f.wake
}

// Lock is the read loop's and the node's other callers' take: it waits
// while the lock is held or a scheduler call waits for it.
func (f *fairLock) Lock() {
	f.mu.Lock()
	for f.note(); f.held || f.waiting > 0; f.note() {
		w := f.waitCh()
		f.mu.Unlock()
		<-w
		f.mu.Lock()
	}
	f.held = true
	f.mu.Unlock()
}

// note counts one of Lock's checks and runs the tried seam. The caller
// holds f.mu.
func (f *fairLock) note() {
	f.checks++
	if f.tried != nil {
		f.tried()
	}
}

// lockSched is a scheduler call's take: it goes before the read loop, and
// reports false when the lock was not had within wait.
func (f *fairLock) lockSched(wait time.Duration) bool {
	timer := time.NewTimer(wait)
	defer timer.Stop()
	f.mu.Lock()
	f.waiting++
	for f.held {
		w := f.waitCh()
		f.mu.Unlock()
		select {
		case <-w:
			if f.woken != nil {
				f.woken() // returns with f.mu held
			} else {
				f.mu.Lock()
			}
		case <-timer.C:
			f.mu.Lock()
			if !f.held {
				// Freed as the timer fired: take it.
				break
			}
			f.waiting--
			f.signal() // the read loop may go now
			f.mu.Unlock()
			return false
		}
	}
	f.waiting--
	f.held = true
	f.mu.Unlock()
	return true
}

// Unlock frees the lock.
func (f *fairLock) Unlock() {
	f.mu.Lock()
	f.held = false
	f.signal()
	f.mu.Unlock()
}

// schedCall runs f under the link's lock as a scheduler call: it waits at
// most HoldLockWait for the lock, and recovers a panic in f, which is taken
// as a timeout. Either way it returns ErrHoldTimeout and counts it under
// *count; the lock is released with defer, so a recovered panic never
// leaves it held (section 1.9 items 4 and 9).
func (l *Link) schedCall(count *uint64, f func() error) (err error) {
	from := time.Now()
	if !l.cmu.lockSched(HoldLockWait) {
		l.noteWait(count, time.Since(from), true)
		return ErrHoldTimeout
	}
	l.noteWait(count, time.Since(from), false)
	defer func() {
		if p := recover(); p != nil {
			l.mu.Lock()
			*count++
			l.stats.SchedPanics++
			l.stats.LastSchedPanic = capDetail(fmt.Sprintf("%v\n%s", p, debug.Stack()))
			l.mu.Unlock()
			err = fmt.Errorf("%w: a panic in the call was recovered", ErrHoldTimeout)
		}
	}()
	defer l.cmu.Unlock()
	defer l.syncHold()
	return f()
}

// noteWait records a scheduler call's wait for the lock, and a timeout.
func (l *Link) noteWait(count *uint64, d time.Duration, timedOut bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if timedOut {
		*count++
	}
	if d > l.stats.LockWaitMax {
		l.stats.LockWaitMax = d
	}
}

// SchedPanicDetailBytes caps a recovered panic's text in Stats.
const SchedPanicDetailBytes = 2048

func capDetail(s string) string {
	if len(s) > SchedPanicDetailBytes {
		return s[:SchedPanicDetailBytes] + "..."
	}
	return s
}
