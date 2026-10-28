package node

import (
	"context"
	"fmt"
	"os"
	"runtime"
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

// A node whose target's client certificate and listener's certificate are
// both outside their periods starts and runs: it is collecting, the two
// links are held back in status with their alarms, and it stops cleanly
// (HR-13, D4-11).
// diagf writes a B6 diagnostic line to stderr and, when B6DIAG_FILE is
// set, appends it there (B6 DIAGNOSTIC, never merged).
func diagf(format string, a ...any) {
	line := fmt.Sprintf(format, a...)
	os.Stderr.WriteString(line)
	if p := os.Getenv("B6DIAG_FILE"); p != "" {
		if f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644); err == nil {
			f.WriteString(line)
			f.Close()
		}
	}
}

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
	var st StatusFile
	// B6 DIAGNOSTIC (never merged): the original 30 s wait, then on a miss
	// a goroutine dump and a further wait of up to 5 minutes, logging each
	// change of what the status file says, and how long Run takes to stop.
	t0 := time.Now()
	var last string
	note := func(s StatusFile, err error) {
		e := ""
		if err != nil {
			e = err.Error()
			if len(e) > 160 {
				e = e[:160]
			}
		}
		k := fmt.Sprintf("collecting=%v written=%s target=%q listener=%q alarms=%d err=%s", s.Collecting, s.Written.Format(time.RFC3339Nano),
			s.Targets["central"].HeldBack, s.Listeners["lab-tls"].HeldBack, len(s.Alarms), e)
		if k != last {
			diagf("B6DIAG %s +%v %s\n", t.Name(), time.Since(t0).Round(time.Millisecond), k)
			last = k
		}
	}
	ok := func(s StatusFile, err error) bool {
		return err == nil && s.Collecting && s.Targets["central"].HeldBack != "" && s.Listeners["lab-tls"].HeldBack != ""
	}
	missed := true
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		s, err := ReadStatus(StatusPath(c))
		note(s, err)
		if ok(s, err) {
			st, missed = s, false
			break
		}
	}
	if missed {
		buf := make([]byte, 8<<20)
		buf = buf[:runtime.Stack(buf, true)]
		diagf("B6DIAG %s MISSED at +%v; goroutines:\n%s\nB6DIAG END DUMP\n", t.Name(), time.Since(t0).Round(time.Millisecond), buf)
		for deadline := time.Now().Add(5 * time.Minute); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
			s, err := ReadStatus(StatusPath(c))
			note(s, err)
			if ok(s, err) {
				st = s
				diagf("B6DIAG %s reached at +%v\n", t.Name(), time.Since(t0).Round(time.Millisecond))
				break
			}
		}
	}
	tc := time.Now()
	cancel()
	err := <-done
	diagf("B6DIAG %s run returned after %v from cancel: %v (missed=%v)\n", t.Name(), time.Since(tc).Round(time.Millisecond), err, missed)
	if err != nil {
		t.Fatal(err)
	}
	if missed {
		t.Errorf("B6DIAG: the 30 s wait missed (the original test fails here)")
	}
	if !st.Collecting || st.Targets["central"].HeldBack != "expired" || st.Listeners["lab-tls"].HeldBack != "expired" {
		t.Fatalf("status %+v", st)
	}
	var codes []string
	for _, a := range st.Alarms {
		codes = append(codes, a.Code)
	}
	if !slices.Contains(codes, AlarmTargetHeldBack) || !slices.Contains(codes, AlarmListenerHeldBack) {
		t.Fatalf("alarms %v", codes)
	}
}
