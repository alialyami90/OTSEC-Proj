package security

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"otsec.local/otsec/platform/node"
	"otsec.local/otsec/platform/node/nodeconfigtest"
	"otsec.local/otsec/platform/store"
)

// HR-13, D4-11, #300 and #313, from the outside: a node whose forwarding
// target's client certificate and whose syslog-tls listener's certificate are
// both expired runs, and through its start and one full CheckInterval after
// it shows both links held back:
//
//   - no connection reaches the target's address (a listener the test owns);
//   - the listener's address is never bound (the test binds it itself, again
//     and again);
//   - no status file it writes says it is collecting without both links held
//     back.
//
// B6, written from HR-13 and D4-11 and B1's ask on #313, not from B5's
// statusorder_test.go. Evidence class: simulated (loopback only; the
// SEL-751 asset has no host, so nothing is collected).
func TestB6HeldLinksDialAndBindNothing(t *testing.T) {
	const asset = "6f1c2e8a-4b3d-4c5e-9f70-0a1b2c3d4e5f"
	// The target's address: a listener the test owns, counting accepts.
	tl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tl.Close()
	var accepts atomic.Int64
	go func() {
		for {
			c, err := tl.Accept()
			if err != nil {
				return
			}
			accepts.Add(1)
			c.Close()
		}
	}()
	// The listener's address: free when the node starts.
	pl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	lAddr := pl.Addr().String()
	pl.Close()

	dir := filepath.Join(t.TempDir(), "store")
	if err := store.CreateDir(dir, ""); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	gone := nodeconfigtest.Period{NotBefore: now.Add(-3 * time.Hour), NotAfter: now.Add(-time.Hour)}
	nc := nodeconfigtest.New("site-a-node1", dir).AddSEL751(asset, "", 2323, 300)
	p, err := nc.WritePKIValid("127.0.0.1", "test-ca", "test-client", nodeconfigtest.Validity{Client: gone})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := nc.WriteListenerCredentialValid(p, "test-listener", "127.0.0.1", gone); err != nil {
		t.Fatal(err)
	}
	nc.AddRELPTarget("central", "127.0.0.1", tl.Addr().(*net.TCPAddr).Port, "test-ca", "test-client", "test/durable-ack", true)
	nc.AddListener("lab-tls", "syslog-tls", lAddr)
	if err := nc.WriteInstallKey("ik_b6_held"); err != nil {
		t.Fatal(err)
	}
	if err := nc.LockTLS(); errors.Is(err, nodeconfigtest.ErrNeedsElevation) {
		if os.Getenv("GITHUB_ACTIONS") == "true" || os.Getenv("OTSEC_REQUIRE_ELEVATED") == "1" {
			t.Fatal(err)
		}
		t.Skip(err)
	} else if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { nc.UnlockTLS() })
	c, err := node.ParseConfig(nc.Bytes())
	if err != nil {
		t.Fatal(err)
	}

	// Every status the node writes, read as it starts and runs.
	var bad atomic.Pointer[string]
	var heldAt atomic.Int64
	var reads, writes atomic.Int64
	var lastWritten atomic.Int64
	stop := make(chan struct{})
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		for {
			select {
			case <-stop:
				return
			default:
			}
			st, err := node.ReadStatus(node.StatusPath(c))
			if err == nil {
				reads.Add(1)
				if w := st.Written.UnixNano(); w != lastWritten.Load() {
					lastWritten.Store(w)
					writes.Add(1)
				}
				held := st.Targets["central"].HeldBack != "" && st.Listeners["lab-tls"].HeldBack != ""
				if st.Collecting && !held && bad.Load() == nil {
					s := "collecting=true, target held " + strconv.Quote(st.Targets["central"].HeldBack) +
						", listener held " + strconv.Quote(st.Listeners["lab-tls"].HeldBack) + ", written " + st.Written.String()
					bad.Store(&s)
				}
				if st.Collecting && held && heldAt.Load() == 0 {
					heldAt.Store(time.Now().UnixNano())
				}
			}
			time.Sleep(time.Millisecond)
		}
	}()
	// The listener's address stays unbound: the test binds it in turn.
	var bindFails atomic.Int64
	var bindErr atomic.Pointer[string]
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			l, err := net.Listen("tcp", lAddr)
			if err != nil {
				bindFails.Add(1)
				s := err.Error()
				bindErr.Store(&s)
			} else {
				l.Close()
			}
			time.Sleep(25 * time.Millisecond)
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- node.Run(ctx, c, nil) }()
	// The property, then one full CheckInterval and a margin after it.
	var runErr error
	ran := false
	for limit := time.Now().Add(5 * time.Minute); heldAt.Load() == 0 && time.Now().Before(limit); time.Sleep(20 * time.Millisecond) {
		select {
		case runErr = <-done:
			ran = true
		default:
		}
		if ran {
			break
		}
	}
	if heldAt.Load() != 0 && !ran {
		time.Sleep(node.CheckInterval + 2*time.Second)
	}
	cancel()
	if !ran {
		runErr = <-done
	}
	close(stop)
	<-readerDone
	if runErr != nil {
		t.Fatalf("Run: %v", runErr)
	}
	if heldAt.Load() == 0 {
		t.Fatalf("no status showed the node collecting with both links held back (%d reads)", reads.Load())
	}
	if s := bad.Load(); s != nil {
		t.Errorf("a status said the node collects before both links were held back: %s", *s)
	}
	if n := accepts.Load(); n != 0 {
		t.Errorf("%d connections reached the held-back target's address", n)
	}
	if n := bindFails.Load(); n != 0 {
		t.Errorf("the held-back listener's address %s could not be bound %d times: %s", lAddr, n, *bindErr.Load())
	}
	t.Logf("%d status reads, %d distinct writes", reads.Load(), writes.Load())
}
