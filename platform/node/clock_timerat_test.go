//go:build otsec_testclock

package node

import (
	"testing"
	"time"
)

// A timer armed at the plan's due time fires at that time even when the
// clock was stepped between the scheduler's read of now and the arming,
// which a duration from the earlier read does not (C6 on #447). Evidence
// class: simulated.
func TestTestClockTimerAtFiresAtItsTimeAfterAStepBeforeArming(t *testing.T) {
	step := useClock(t, clockT0)
	at := clockT0.Add(time.Minute)
	wait := at.Sub(nodeClock.Now()) // the scheduler's read of now
	step(clockT0.Add(30 * time.Second))
	c, stop := timerAt(at, wait)
	defer stop()
	late, stopLate := nodeClock.NewTimer(wait) // the old arming, for contrast
	defer stopLate()
	select {
	case <-c:
		t.Fatal("fired before its time")
	case <-time.After(50 * time.Millisecond):
	}
	step(at)
	select {
	case <-c:
	case <-time.After(5 * time.Second):
		t.Fatalf("not fired with the clock at %v", at)
	}
	select {
	case <-late:
		t.Fatal("a duration armed after the step fired at the due time; this test no longer shows the gap")
	case <-time.After(50 * time.Millisecond):
	}
}

// A timer armed at a time the clock has already reached fires at once, and
// a stopped one never fires.
func TestTestClockTimerAtPastAndStopped(t *testing.T) {
	step := useClock(t, clockT0)
	c, _ := timerAt(clockT0, time.Second)
	select {
	case <-c:
	case <-time.After(5 * time.Second):
		t.Fatal("a timer at the clock's own time did not fire")
	}
	c, stop := timerAt(clockT0.Add(time.Minute), time.Minute)
	if !stop() {
		t.Fatal("stop of a pending timer reported none")
	}
	step(clockT0.Add(time.Hour))
	select {
	case <-c:
		t.Fatal("a stopped timer fired")
	case <-time.After(50 * time.Millisecond):
	}
}
