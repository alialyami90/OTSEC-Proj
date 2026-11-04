//go:build otsec_testclock

package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// A test build's -test-clock puts the collector's decisions, its state's
// admin clock and the SER transcript's received time on the stepped clock
// in that file (D4-40, V-M4). It is the file the node's -test-clock reads:
// one RFC 3339 time, replaced by the harness (write, then rename). Each
// reading re-reads it, and the clock only moves forward: an earlier time,
// or a file that cannot be read, leaves it where it was and is said on
// stderr. Run deadlines, socket deadlines, the credential store and
// provisioning stay on the wall clock. A release build has no such flag.
func init() {
	testFlags = func(fs *flag.FlagSet) func() error {
		path := fs.String("test-clock", "", "test builds only: a file holding the collector's time (RFC 3339), which the harness steps forward")
		return func() error {
			if *path == "" {
				return nil
			}
			at, err := readTestClock(*path)
			if err != nil {
				return err
			}
			c := &fileNow{path: *path, now: at}
			testNow = c.Now
			return nil
		}
	}
}

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

type fileNow struct {
	path string
	mu   sync.Mutex
	now  time.Time
}

func (c *fileNow) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	at, err := readTestClock(c.path)
	switch {
	case err != nil:
		fmt.Fprintf(os.Stderr, "otsec-collector test clock: %v; the clock is not moved\n", err)
	case at.Before(c.now):
		fmt.Fprintf(os.Stderr, "otsec-collector test clock: %s is before %s, so the clock is not moved\n", at.Format(time.RFC3339Nano), c.now.Format(time.RFC3339Nano))
	default:
		c.now = at
	}
	return c.now
}
