package node

import (
	"context"
	"os"
	"testing"
	"time"

	"otsec.local/otsec/platform/node/nodeconfigtest"
)

// No status file says the node is collecting before it shows a link held back
// for its certificate's period (HR-13, B6's note on the expired-links trace).
// The hold-back itself is decided in NewForwarding and NewListening, before
// the forwarder runs, the listener binds or the schedule starts; this is the
// report of it. The reader below takes every status the node writes while it
// starts, and none may have Collecting true with the two links not yet held.
func TestStatusNeverCollectsBeforeLinksAreHeldBack(t *testing.T) {
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
	var seen, collecting int
	var last []byte
	for deadline := time.Now().Add(5 * time.Minute); time.Now().Before(deadline); time.Sleep(time.Millisecond) {
		b, err := os.ReadFile(StatusPath(c))
		if err != nil || string(b) == string(last) {
			continue
		}
		last = b
		st, err := ReadStatus(StatusPath(c))
		if err != nil {
			continue
		}
		seen++
		if st.Collecting {
			collecting++
			if st.Targets["central"].HeldBack == "" || st.Listeners["lab-tls"].HeldBack == "" {
				t.Fatalf("status %d says collecting with a link not held back: targets %+v listeners %+v", seen, st.Targets, st.Listeners)
			}
			break
		}
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if collecting == 0 {
		t.Fatalf("no status said collecting (%d statuses seen)", seen)
	}
}

// Defer holds status writes back until Resume.
func TestStatusDeferWritesNothing(t *testing.T) {
	path := t.TempDir() + "/status.json"
	s := NewStatus(path, nil, nil)
	s.Defer()
	if err := s.Write("n1"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err == nil {
		t.Fatal("a deferred status was written")
	}
	s.Resume()
	if err := s.Write("n1"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
}
