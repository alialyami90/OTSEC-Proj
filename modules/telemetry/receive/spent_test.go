package receive

import (
	"context"
	"math"
	"testing"
	"time"

	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/store"
)

// The budget at start is UnknownBytes less UnknownSpent; 0 is today's full
// budget, and a value below 0 or above UnknownBytes starts it empty without
// panicking (A1, conditions 1 and 3).
func TestStartBudget(t *testing.T) {
	const size = minUnknownBytes
	for _, tc := range []struct {
		spent int64
		want  float64
	}{
		{0, size},
		{1000, size - 1000},
		{size, 0},
		{size + 1, 0},
		{-1, 0},
		{math.MinInt64, 0},
		{math.MaxInt64, 0},
	} {
		b := startBudget(size, tc.spent, time.Now())
		if b.tokens != tc.want || b.last.IsZero() {
			t.Errorf("spent %d: %+v, want %v tokens refilling from now", tc.spent, b, tc.want)
		}
	}
	for _, spent := range []int64{-1, math.MaxInt64} {
		r, err := New(withSpent(spent))
		if err != nil {
			t.Fatal(err)
		}
		if r.spend(1) {
			t.Errorf("spent %d: a byte was spent from a budget that starts empty", spent)
		}
	}
}

func withSpent(spent int64) Config {
	c := Config{
		Node: testNode, ID: "lab", Stream: testStream, Transport: asset.SyslogUDP, Address: "127.0.0.1:0",
		Target: asset.Simulated, Plaintext: true, Senders: testSenders(), Log: noLog{}, Health: &sink{}, Received: received,
		Limits: Limits{UnknownBytes: minUnknownBytes, UnknownWindow: time.Hour}, UnknownSpent: spent,
	}
	return c
}

// spentRun serves one listener whose unknown budget is budget per window,
// started with spent already spent, floods it from an unknown sender for d
// or until until holds, and returns the unknown bytes it stored.
func spentRun(t *testing.T, budget int64, window time.Duration, spent int64, d time.Duration, until func(*rig) bool) int64 {
	t.Helper()
	g := newRig(t, asset.SyslogUDP, func(c *Config) {
		onlyA(c)
		c.Limits.UnknownBytes, c.Limits.UnknownWindow, c.UnknownSpent = budget, window, spent
	})
	flood := g.udp(addrB)
	defer flood.Close()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) && (until == nil || !until(g)) {
		flood.Write([]byte(unknownMsg))
		time.Sleep(time.Millisecond)
	}
	g.settled()
	n := int64(g.unknownBytes())
	g.stop()
	return n
}

func spentOut(g *rig) bool { return g.r.Status().Dropped[DropUnknownBudget] >= 10 }

// A restart inside the window adds no budget (A3, condition 4; A1,
// condition 2). An unknown sender fills the budget, the listener is
// restarted twice with what the node would count as spent, and nothing more
// is stored: at 256 KiB an hour the budget refills less than one record in
// the run. Without the count, the restart refills it.
func TestUnknownSpentRestart(t *testing.T) {
	const budget = minUnknownBytes
	first := spentRun(t, budget, time.Hour, 0, 5*time.Second, spentOut)
	if first == 0 || first > budget || budget-first > int64(len(unknownMsg))*2 {
		t.Fatalf("first run stored %d of %d", first, budget)
	}
	total := first
	for i := range 2 {
		n := spentRun(t, budget, time.Hour, total, 300*time.Millisecond, nil)
		if n != 0 {
			t.Errorf("restart %d inside the window stored %d more bytes", i+1, n)
		}
		total += n
	}
	if n := spentRun(t, budget, time.Hour, 0, 300*time.Millisecond, nil); n == 0 {
		t.Error("control: a listener started with nothing spent stored nothing, so the test cannot tell")
	}
}

// After restarts the budget still refills at UnknownBytes per window, and
// the total over the run keeps to UnknownBytes × (1 + T / UnknownWindow).
func TestUnknownSpentRefillBound(t *testing.T) {
	const (
		budget = minUnknownBytes
		window = 4 * time.Second
	)
	start := time.Now()
	first := spentRun(t, budget, window, 0, 5*time.Second, spentOut)
	total := first
	total += spentRun(t, budget, window, total, 200*time.Millisecond, nil)
	total += spentRun(t, budget, window, total, window/2, nil)
	elapsed := time.Since(start)
	bound := float64(budget) * (1 + elapsed.Seconds()/window.Seconds())
	if total <= first || float64(total) > bound {
		t.Errorf("stored %d in %v: want more than %d after the refill and at most %.0f", total, elapsed, first, bound)
	}
}

// noLog is an Appender for a receiver that is never served.
type noLog struct{}

func (noLog) AppendBatch(context.Context, []store.Record) ([]store.Receipt, error) { return nil, nil }
