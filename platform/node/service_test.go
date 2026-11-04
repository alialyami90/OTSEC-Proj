package node

import (
	"context"
	"slices"
	"sync"
	"testing"
	"time"

	"otsec.local/otsec/contracts/audit"
	"otsec.local/otsec/platform/node/nodeconfigtest"
)

// Run starts the node, writes status, and stops cleanly when ctx ends,
// with service.start and service.stop in the chain.
func TestRunStartsAndStops(t *testing.T) {
	c, dir := schedConfig(t, nil)
	// Stop once status says the node is collecting, not after a fixed time:
	// opening the stores can take longer than any short period on a slow
	// runner, and a Run cut off during start fails for that reason alone.
	ctx, cancel := context.WithCancel(bg)
	defer cancel()
	done := make(chan error, 1)
	// The OS log carries the alarm that says why a record was not
	// written: service.stop was missing once under go test -race ./...,
	// and 120 runs of this test alone did not reproduce it.
	var logMu sync.Mutex
	var oslog []string
	go func() {
		done <- Run(ctx, c, func(l string) { logMu.Lock(); oslog = append(oslog, l); logMu.Unlock() })
	}()
	var st StatusFile
	var err error
	began := time.Now()
	for deadline := began.Add(5 * time.Minute); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if st, err = ReadStatus(StatusPath(c)); err == nil && st.Collecting {
			break
		}
	}
	waited := time.Since(began)
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err != nil || !st.Collecting || st.Node != "site-a-node1" {
		t.Fatalf("after %s the last status read was %+v, read error: %v", waited.Round(time.Millisecond), st, err)
	}
	r, _, _ := start(t, c, dir)
	defer r.Close()
	acts := auditActions(t, r)
	if count(acts, audit.ActionServiceStart) != 2 || count(acts, audit.ActionServiceStop) != 1 {
		logMu.Lock()
		defer logMu.Unlock()
		t.Fatalf("audit: %v; OS log: %q", acts, oslog)
	}
	if ep := CollectorEndpoint(c); ep.Address != c.CollectorPipe || ep.Peer == "" {
		t.Fatalf("collector endpoint %+v", ep)
	}
}

// A node whose target's client certificate and listener's certificate are
// both outside their periods starts and runs: it is collecting, the two
// links are held back in status with their alarms, and it stops cleanly
// (HR-13, D4-11).
func TestRunStartsWithExpiredLinks(t *testing.T) {
	var nc *nodeconfigtest.Config
	c, _ := schedConfig(t, func(n *nodeconfigtest.Config) {
		nc = n
		p, err := n.WritePKIValid("127.0.0.1", "test-ca", "test-client", nodeconfigtest.Validity{Client: expired()})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := n.WriteListenerCredentialValid(p, "test-listener", "127.0.0.1", expired()); err != nil {
			t.Fatal(err)
		}
		n.AddRELPTarget("central", "127.0.0.1", 1, "test-ca", "test-client", "test/durable-ack", true)
		n.AddListener("lab-tls", "syslog-tls", "127.0.0.1:0")
		lockTLS(t, n)
	})
	locked := *nc
	t.Cleanup(func() { locked.UnlockTLS() })
	ctx, cancel := context.WithCancel(bg)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- Run(ctx, c, nil) }()
	// The wait is for the property, not a deadline of the test's own: a start
	// opens four databases with a WAL sync each, which took over 30 s on a
	// hosted Windows runner's disk (B6's #294, job 122647514280). The cap
	// only ends a test that would otherwise hang; Run returning early ends it
	// at once.
	var (
		st      StatusFile
		last    StatusFile // the last status read, held or not, for a miss
		lastErr error
		runDone bool
		runErr  error
	)
	began := time.Now()
	for deadline := began.Add(5 * time.Minute); time.Now().Before(deadline) && !runDone; time.Sleep(20 * time.Millisecond) {
		s, err := ReadStatus(StatusPath(c))
		if last, lastErr = s, err; err == nil && s.Collecting && s.Targets["central"].HeldBack != "" && s.Listeners["lab-tls"].HeldBack != "" {
			st = s
			break
		}
		select {
		case runErr = <-done:
			runDone = true
		default:
		}
	}
	waited := time.Since(began)
	cancel()
	if !runDone {
		runErr = <-done
	}
	if runErr != nil {
		t.Fatal(runErr)
	}
	if !st.Collecting || st.Targets["central"].HeldBack != "expired" || st.Listeners["lab-tls"].HeldBack != "expired" {
		t.Fatalf("after %s the last status read was %+v, read error: %v", waited.Round(time.Millisecond), last, lastErr)
	}
	var codes []string
	for _, a := range st.Alarms {
		codes = append(codes, a.Code)
	}
	if !slices.Contains(codes, AlarmTargetHeldBack) || !slices.Contains(codes, AlarmListenerHeldBack) {
		t.Fatalf("alarms %v", codes)
	}
}
