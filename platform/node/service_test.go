package node

import (
	"context"
	"testing"
	"time"

	"otsec.local/otsec/contracts/audit"
)

// Run starts the node, writes status, and stops cleanly when ctx ends,
// with service.start and service.stop in the chain.
func TestRunStartsAndStops(t *testing.T) {
	c, dir := schedConfig(t, nil)
	ctx, cancel := context.WithTimeout(bg, 300*time.Millisecond)
	defer cancel()
	var lines []string
	if err := Run(ctx, c, func(s string) { lines = append(lines, s) }); err != nil {
		t.Fatal(err)
	}
	st, err := ReadStatus(StatusPath(c))
	if err != nil || !st.Collecting || st.Node != "site-a-node1" {
		t.Fatalf("status %+v: %v", st, err)
	}
	r, _, _ := start(t, c, dir)
	defer r.Close()
	acts := auditActions(t, r)
	if count(acts, audit.ActionServiceStart) != 2 || count(acts, audit.ActionServiceStop) != 1 {
		t.Fatalf("audit: %v", acts)
	}
	if ep := CollectorEndpoint(c); ep.Address != c.CollectorPipe || ep.Peer == "" {
		t.Fatalf("collector endpoint %+v", ep)
	}
}
