//go:build otsec_testclock

package node

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// UseTestClock puts the node on the stepped test clock held in path (D4-40,
// V-M4). The file holds one RFC 3339 time, which the harness replaces
// (write, then rename) to step the clock. The clock re-reads it every
// TestClockPoll of wall time and only moves forward: a time before the
// current one is refused, said on stderr, and the clock stays where it was.
// A timer or ticker fires when the clock reaches its time, so between steps
// nothing that waits on this clock moves. Only a build tagged
// otsec_testclock has this function; it must be called before Start.
//
// On Windows the rename is refused while the clock is reading the file
// (C5 on #400), so a harness retries it.
func UseTestClock(path string) error {
	at, err := readTestClock(path)
	if err != nil {
		return err
	}
	c := &fileClock{path: path, now: at}
	go c.poll()
	nodeClock = c
	return nil
}

// TestClockPoll is how often the test clock re-reads its file.
const TestClockPoll = 10 * time.Millisecond

func readTestClock(path string) (time.Time, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return time.Time{}, fmt.Errorf("test clock: %w", err)
	}
	at, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(string(b)))
	if err != nil {
		return time.Time{}, fmt.Errorf("test clock %s: %w", path, err)
	}
	return at, nil
}

type fileClock struct {
	path string

	mu     sync.Mutex
	now    time.Time
	waits  map[*clockWait]bool
	behind time.Time // the last time refused, said once
}

// clockWait is a timer (every zero) or a ticker on the test clock.
type clockWait struct {
	at    time.Time
	every time.Duration
	c     chan time.Time
}

func (c *fileClock) poll() {
	for range time.Tick(TestClockPoll) {
		if at, err := readTestClock(c.path); err == nil {
			c.set(at)
		}
	}
}

// set moves the clock to at and fires what is due, as a time.Timer or a
// time.Ticker would: a send that would block is dropped.
func (c *fileClock) set(at time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if at.Before(c.now) {
		if !at.Equal(c.behind) {
			c.behind = at
			fmt.Fprintf(os.Stderr, "otsec test clock: %s is before %s, so the clock is not moved\n", at.Format(time.RFC3339Nano), c.now.Format(time.RFC3339Nano))
		}
		return
	}
	c.now = at
	for w := range c.waits {
		if at.Before(w.at) {
			continue
		}
		select {
		case w.c <- at:
		default:
		}
		if w.every == 0 {
			delete(c.waits, w)
			continue
		}
		for !at.Before(w.at) {
			w.at = w.at.Add(w.every)
		}
	}
}

func (c *fileClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fileClock) add(d, every time.Duration) *clockWait {
	c.mu.Lock()
	defer c.mu.Unlock()
	w := &clockWait{at: c.now.Add(d), every: every, c: make(chan time.Time, 1)}
	if c.waits == nil {
		c.waits = map[*clockWait]bool{}
	}
	c.waits[w] = true
	return w
}

func (c *fileClock) stop(w *clockWait) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	was := c.waits[w]
	delete(c.waits, w)
	return was
}

func (c *fileClock) NewTimer(d time.Duration) (<-chan time.Time, func() bool) {
	w := c.add(d, 0)
	return w.c, func() bool { return c.stop(w) }
}

func (c *fileClock) NewTicker(d time.Duration) (<-chan time.Time, func()) {
	w := c.add(d, d)
	return w.c, func() { c.stop(w) }
}
