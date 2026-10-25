package node

import (
	"context"
	"sync"
	"testing"
	"time"

	"otsec.local/otsec/contracts/audit"
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
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if st, err = ReadStatus(StatusPath(c)); err == nil && st.Collecting {
			break
		}
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err != nil || !st.Collecting || st.Node != "site-a-node1" {
		t.Fatalf("status %+v: %v", st, err)
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
