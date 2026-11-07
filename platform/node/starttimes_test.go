package node

import (
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

func atoi(s string) int { n, _ := strconv.Atoi(s); return n }

// startLineRE is the start timing line, its phases fixed and in order
// (P4-H2): CI and D6's workflows read these names.
var startLineRE = regexp.MustCompile(`^otsec node start: scope=(runtime|node) total=(\d+)ms` +
	` config=(\d+)ms scm=(\d+)ms store-lock=(\d+)ms store-open=(\d+)ms store-reserve=(\d+)ms store-startup=(\d+)ms store-adopt=(\d+)ms` +
	` register=(\d+)ms record-start=(\d+)ms holds=(\d+)ms status=(\d+)ms forwarding=(\d+)ms listening=(\d+)ms` +
	` node-keys=(\d+)ms scheduler=(\d+)ms listen=(\d+)ms first-check=(\d+)ms other=(\d+)ms` +
	` reserve-release=(\d+)ms reserve-write=(\d+)ms reserve-sync=(\d+)ms reserve-dirsync=(\d+)ms$`)

// checkStartLine checks the line's form, that its phases and other sum to
// its total, and that ReserveParts sum to store-reserve, each within a
// millisecond of rounding per value.
func checkStartLine(t *testing.T, line, scope string) {
	t.Helper()
	m := startLineRE.FindStringSubmatch(line)
	if m == nil || m[1] != scope {
		t.Fatalf("start line %q", line)
	}
	parts := len(m) - len(ReserveParts)
	sum := 0
	for _, v := range m[3:parts] {
		sum += atoi(v)
	}
	if d := atoi(m[2]) - sum; d < 0 || d > parts-3 {
		t.Fatalf("phases and other sum to %d ms, total %s ms: %q", sum, m[2], line)
	}
	reserve, split := atoi(m[3+slices.Index(StartPhases, "store-reserve")]), 0
	for _, v := range m[parts:] {
		split += atoi(v)
	}
	if d := reserve - split; d < 0 || d > len(ReserveParts) {
		t.Fatalf("the reserve parts sum to %d ms, store-reserve %d ms: %q", split, reserve, line)
	}
}

// Start times every one of its phases under the fixed names and no other,
// and its line names them in order, with total and other.
func TestStartLine(t *testing.T) {
	c, dir := runtimeConfig(t)
	r, _, _ := start(t, c, dir)
	defer r.Close()
	for p := range r.starts.d {
		if !slices.Contains(StartPhases, p) && !slices.Contains(ReserveParts, p) {
			t.Errorf("phase %q is not in StartPhases or ReserveParts", p)
		}
	}
	for _, p := range StartPhases[slices.Index(StartPhases, "store-lock") : slices.Index(StartPhases, "status")+1] {
		if _, ok := r.starts.d[p]; !ok && p != "store-reserve" {
			t.Errorf("Start did not time %s", p)
		}
	}
	checkStartLine(t, r.StartLine(), "runtime")
	if strings.Contains(r.StartLine(), dir) {
		t.Fatalf("the line names the store directory: %q", r.StartLine())
	}

	// other is the total less every phase, never below zero.
	st := &startTimes{began: time.Now().Add(-time.Second), d: map[string]time.Duration{"store-open": 300 * time.Millisecond, "holds": 200 * time.Millisecond}}
	checkStartLine(t, st.line("node"), "node")
	if o := regexp.MustCompile(` other=(\d+)ms `).FindStringSubmatch(st.line("node")); o == nil || atoi(o[1]) < 499 {
		t.Fatalf("other in %q", st.line("node"))
	}
	// Run with the zero PreStart counts from its own start.
	zero := newStartTimes()
	zero.from(PreStart{}, time.Now())
	if _, ok := zero.d["config"]; ok || !strings.Contains(zero.line("node"), " config=0ms scm=0ms ") {
		t.Fatalf("the zero PreStart: %q", zero.line("node"))
	}
	st.d["store-lock"] = 2 * time.Second
	if !strings.Contains(st.line("node"), " other=0ms ") {
		t.Fatalf("other below zero: %q", st.line("node"))
	}
}

// A restart releases each database's recovery reserve and creates it again
// (F-013), and store-reserve is exactly the sum of ReserveParts, each of
// which the restart times (P4-H4).
func TestReserveParts(t *testing.T) {
	c, dir := runtimeConfig(t)
	r, _, _ := start(t, c, dir)
	r.Close()
	r, _, _ = start(t, c, dir)
	defer r.Close()
	var sum time.Duration
	for _, p := range ReserveParts {
		d, ok := r.starts.d[p]
		if !ok && p != "reserve-dirsync" {
			t.Errorf("the restart did not time %s", p)
		}
		sum += d
	}
	if r.starts.d["reserve-release"] <= 0 || r.starts.d["reserve-write"] <= 0 || sum != r.starts.d["store-reserve"] {
		t.Fatalf("store-reserve %v, its parts %v", r.starts.d["store-reserve"], r.starts.d)
	}
}
