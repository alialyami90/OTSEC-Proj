package sensorlink

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// storeTime is the real time the package's tests spend in the store's
// calls (Append, AppendBatch, LastCommitted and the cursor's save and
// read), by top-level test. TestMain prints it after the run, with the cost
// of one synced file write measured on the same disk, so a job's log shows
// how much of the package's time is the disk's (D4-127 item 3.4 (a) and
// (d), brief P4-NODE-WINTIME). It measures and decides nothing.
var storeTime = struct {
	mu    sync.Mutex
	by    map[string]time.Duration
	calls int
	total time.Duration
	max   time.Duration
	maxBy string
	slow  []string // calls of a second or more, by test, the first 50
	nSlow int
}{by: map[string]time.Duration{}}

// timed counts the call that began at from under test name.
func timed(name string, from time.Time) {
	d := time.Since(from)
	top, _, _ := strings.Cut(name, "/")
	storeTime.mu.Lock()
	defer storeTime.mu.Unlock()
	storeTime.by[top] += d
	storeTime.calls++
	storeTime.total += d
	if d > storeTime.max {
		storeTime.max, storeTime.maxBy = d, name
	}
	if d >= time.Second {
		storeTime.nSlow++
		if len(storeTime.slow) < 50 {
			storeTime.slow = append(storeTime.slow, fmt.Sprintf("%.3f s %s", d.Seconds(), name))
		}
	}
}

func TestMain(m *testing.M) {
	code := m.Run()
	printStoreTime()
	os.Exit(code)
}

func printStoreTime() {
	storeTime.mu.Lock()
	defer storeTime.mu.Unlock()
	fmt.Printf("sensorlink store time: %d calls, %.1f s in all, longest %.3f s (%s), %d of a second or more\n",
		storeTime.calls, storeTime.total.Seconds(), storeTime.max.Seconds(), storeTime.maxBy, storeTime.nSlow)
	for _, s := range storeTime.slow {
		fmt.Printf("sensorlink store time: a call of %s\n", s)
	}
	names := make([]string, 0, len(storeTime.by))
	for n := range storeTime.by {
		names = append(names, n)
	}
	slices.SortFunc(names, func(a, b string) int { return int(storeTime.by[b] - storeTime.by[a]) })
	for _, n := range names[:min(15, len(names))] {
		fmt.Printf("sensorlink store time: %8.2f s %s\n", storeTime.by[n].Seconds(), n)
	}
	if d, err := syncCost(50); err != nil {
		fmt.Printf("sensorlink synced write: %v\n", err)
	} else {
		fmt.Printf("sensorlink synced write: %.2f ms each, the mean of 50\n", float64(d.Microseconds())/1000/50)
	}
}

// syncCost writes and syncs a small file n times in a temporary directory,
// as the run file's write does, and returns the time taken.
func syncCost(n int) (time.Duration, error) {
	dir, err := os.MkdirTemp("", "sensorlink-sync")
	if err != nil {
		return 0, err
	}
	defer os.RemoveAll(dir)
	from := time.Now()
	for i := range n {
		f, err := os.Create(filepath.Join(dir, fmt.Sprint(i)))
		if err != nil {
			return 0, err
		}
		_, err = f.Write([]byte(`{"copy":"2026-11-07T10:00:00Z"}`))
		if err == nil {
			err = f.Sync()
		}
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return 0, err
		}
	}
	return time.Since(from), nil
}
