//go:build otsec_testclock

package main

import (
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The collector's -test-clock (D4-40, V-M4): testNow reads the file at
// each call, moves only forward, and stays put when the file goes back or
// cannot be read. Evidence class: simulated.
func TestTestClockCollector(t *testing.T) {
	path := filepath.Join(t.TempDir(), "clock")
	t0 := time.Date(2030, 11, 4, 10, 0, 0, 0, time.UTC)
	write := func(s string) {
		if err := os.WriteFile(path, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(t0.Format(time.RFC3339Nano) + "\n")
	prev := testNow
	t.Cleanup(func() { testNow = prev })
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	use := testFlags(fs)
	if err := fs.Parse([]string{"-test-clock", path}); err != nil {
		t.Fatal(err)
	}
	if err := use(); err != nil {
		t.Fatal(err)
	}
	if got := testNow(); !got.Equal(t0) {
		t.Fatalf("Now %s, want %s", got, t0)
	}
	t1 := t0.Add(24 * time.Hour)
	write(t1.Format(time.RFC3339Nano))
	if got := testNow(); !got.Equal(t1) {
		t.Fatalf("after a step: %s, want %s", got, t1)
	}
	for _, bad := range []string{t0.Format(time.RFC3339Nano), "not a time"} {
		write(bad)
		if got := testNow(); !got.Equal(t1) {
			t.Fatalf("after %q: %s, want it left at %s", bad, got, t1)
		}
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if got := testNow(); !got.Equal(t1) {
		t.Fatalf("with no file: %s, want it left at %s", got, t1)
	}
}
