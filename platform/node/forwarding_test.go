package node

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/modules/telemetry/forward/relptest"
	"otsec.local/otsec/platform/node/nodeconfigtest"
	"otsec.local/otsec/platform/store"
)

// forwardConfig is a node with one required, auditing relp-tls target at
// port, and its test PKI written to tls_dir.
func forwardConfig(t *testing.T, port int, mod func(*nodeconfigtest.Config)) (*nodeconfigtest.Config, *nodeconfigtest.PKI, string) {
	t.Helper()
	dir := t.TempDir()
	storeDir := filepath.Join(dir, "store")
	if err := store.CreateDir(storeDir, ""); err != nil {
		t.Fatal(err)
	}
	nc := nodeconfigtest.New("site-a-node1", storeDir).AddSEL751(relayID, "", 2323, 300)
	p, err := nc.WritePKI("127.0.0.1", "test-ca", "test-client")
	if err != nil {
		t.Fatal(err)
	}
	nc.AddRELPTarget("central", "127.0.0.1", port, "test-ca", "test-client", "test/durable-ack", true)
	if mod != nil {
		mod(nc)
	}
	return nc, p, dir
}

func parse(t *testing.T, nc *nodeconfigtest.Config) *Config {
	t.Helper()
	c, err := ParseConfig(nc.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// The node forwards every committed event of every stream the target
// carries, audit included, through A4's forwarder over mutual TLS to a
// collector that permits only this node's name, and status shows each
// stream's cursor at its last committed seq.
func TestNodeForwardsEveryStream(t *testing.T) {
	// The receiver needs the PKI and the target needs the receiver's port,
	// so the port is set after the receiver starts.
	nc, p, dir := forwardConfig(t, 1, nil)
	srv, err := relptest.Start(p.ServerTLS("site-a-node1"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	nc.Targets[0]["port"] = srv.Addr().Port
	c := parse(t, nc)
	r, st, _ := start(t, c, dir)
	defer r.Close()
	for i := 0; i < 5; i++ {
		r.health(bg, "test.forwarded", map[string]string{"n": string(rune('a' + i))})
	}
	fw, err := NewForwarding(r)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(bg)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); fw.Run(ctx) }()
	defer func() { cancel(); wg.Wait() }()

	want := 0
	for _, s := range []c5.StreamID{HealthStream, AuditStream} {
		n, _ := r.Store(s).LastCommitted(bg, s)
		want += int(n)
	}
	deadline := time.Now().Add(15 * time.Second)
	for len(srv.Acked()) < want && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if got := len(srv.Acked()); got < want {
		t.Fatalf("%d of %d events acknowledged; errors %v; status %+v", got, want, srv.Errors(), fw.targets[0].f.Status())
	}
	// Cursors are saved after the acknowledgement; give the last save time.
	for time.Now().Before(deadline) {
		fw.Check(bg)
		ts := st.Snapshot("site-a-node1").Targets["central"]
		done := len(ts.Streams) > 0
		for _, ss := range ts.Streams {
			done = done && ss.Cursor == ss.Last
		}
		if done {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	ts := st.Snapshot("site-a-node1").Targets["central"]
	if ts.Class != "required" || ts.Confirmed == 0 {
		t.Fatalf("target status %+v", ts)
	}
	for _, s := range []c5.StreamID{HealthStream, AuditStream, SERStream(relayID)} {
		ss, ok := ts.Streams[string(s)]
		if !ok || ss.Cursor != ss.Last || ss.Blocked != "" {
			t.Fatalf("stream %s: %+v (present %v)", s, ss, ok)
		}
	}
	if _, ok := ts.Streams[string(QuarantineStream(relayID))]; ok {
		t.Fatal("the quarantine stream is forwarded")
	}
}

// A bad TLS reference stops the node before anything is sent, and nothing
// falls back to another reference (D2-12).
func TestBadTLSReferenceStopsTheNode(t *testing.T) {
	cases := map[string]func(t *testing.T, nc *nodeconfigtest.Config){
		"missing trust anchors": func(t *testing.T, nc *nodeconfigtest.Config) {
			os.Remove(filepath.Join(nc.TLSDir, "test-ca.pem"))
		},
		"missing key": func(t *testing.T, nc *nodeconfigtest.Config) {
			os.Remove(filepath.Join(nc.TLSDir, "test-client.key"))
		},
		"another node's name": func(t *testing.T, nc *nodeconfigtest.Config) {
			nc.Targets[0]["durable_ack"].(map[string]any)["permitted_peer"] = "site-b-node1"
		},
		"key does not match": func(t *testing.T, nc *nodeconfigtest.Config) {
			other := nodeconfigtest.New("site-a-node1", filepath.Join(t.TempDir(), "store"))
			if _, err := other.WritePKI("127.0.0.1", "x", "x"); err != nil {
				t.Fatal(err)
			}
			b, err := os.ReadFile(filepath.Join(other.TLSDir, "x.key"))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(nc.TLSDir, "test-client.key"), b, 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"trust anchors hold a key": func(t *testing.T, nc *nodeconfigtest.Config) {
			b, _ := os.ReadFile(filepath.Join(nc.TLSDir, "test-client.key"))
			os.WriteFile(filepath.Join(nc.TLSDir, "test-ca.pem"), b, 0o600)
		},
	}
	if runtime.GOOS != "windows" {
		cases["key others can read"] = func(t *testing.T, nc *nodeconfigtest.Config) {
			os.Chmod(filepath.Join(nc.TLSDir, "test-client.key"), 0o644)
		}
		cases["key is a link"] = func(t *testing.T, nc *nodeconfigtest.Config) {
			k := filepath.Join(nc.TLSDir, "test-client.key")
			moved := filepath.Join(t.TempDir(), "k")
			os.Rename(k, moved)
			if err := os.Symlink(moved, k); err != nil {
				t.Fatal(err)
			}
		}
		cases["certificate is a link"] = func(t *testing.T, nc *nodeconfigtest.Config) {
			k := filepath.Join(nc.TLSDir, "test-client.crt")
			moved := filepath.Join(t.TempDir(), "c")
			os.Rename(k, moved)
			if err := os.Symlink(moved, k); err != nil {
				t.Fatal(err)
			}
		}
		cases["tls_dir is a link"] = func(t *testing.T, nc *nodeconfigtest.Config) {
			link := filepath.Join(t.TempDir(), "tls-link")
			if err := os.Symlink(nc.TLSDir, link); err != nil {
				t.Fatal(err)
			}
			nc.TLSDir = link
		}
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			nc, _, dir := forwardConfig(t, 2514, nil)
			mutate(t, nc)
			c := parse(t, nc)
			r, _, _ := start(t, c, dir)
			defer r.Close()
			_, err := NewForwarding(r)
			if err == nil {
				t.Fatal("forwarding built")
			}
			t.Log(err)
			r.Close()
			ctx, cancel := context.WithTimeout(bg, 2*time.Second)
			defer cancel()
			if err := Run(ctx, c, nil); err == nil {
				t.Fatal("the node ran")
			}
		})
	}
	// The unchanged PKI loads, so each case above fails for its own reason.
	nc, _, dir := forwardConfig(t, 2514, nil)
	r, _, _ := start(t, parse(t, nc), dir)
	defer r.Close()
	if _, err := NewForwarding(r); err != nil {
		t.Fatal(err)
	}
}

// A TLS reference is a file name in tls_dir, never a path; and a reference
// needs tls_dir.
func TestTLSReferenceIsAName(t *testing.T) {
	for name, mutate := range map[string]func(nc *nodeconfigtest.Config){
		"path in reference": func(nc *nodeconfigtest.Config) {
			nc.Targets[0]["tls"].(map[string]any)["client_credential_ref"] = "../store/evidence"
		},
		"separator":        func(nc *nodeconfigtest.Config) { nc.Targets[0]["tls"].(map[string]any)["trust_anchor_ref"] = `ca\x` },
		"no tls_dir":       func(nc *nodeconfigtest.Config) { nc.TLSDir = "" },
		"relative tls_dir": func(nc *nodeconfigtest.Config) { nc.TLSDir = "tls" },
	} {
		nc, _, _ := forwardConfig(t, 2514, mutate)
		if _, err := ParseConfig(nc.Bytes()); err == nil {
			t.Errorf("%s: loaded", name)
		}
	}
}

// A required target with events waiting and no confirmation for
// UnreachableAfter raises forward-unreachable once per outage, with a
// forward.unreachable health event.
func TestUnreachableRaisedOncePerOutage(t *testing.T) {
	nc, _, _ := forwardConfig(t, 9, nil) // the forwarder is never run
	c := parse(t, nc)
	var mu sync.Mutex
	now := time.Date(2026, 10, 25, 6, 0, 0, 0, time.UTC)
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	advance := func(d time.Duration) { mu.Lock(); now = now.Add(d); mu.Unlock() }
	st := NewStatus("", nil, clock)
	r, err := Start(bg, c, RuntimeOptions{Status: st, Now: clock, Group: c5.GroupOptions{MaxEvents: 10, MaxWait: 5 * time.Millisecond}})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	fw, err := NewForwarding(r)
	if err != nil {
		t.Fatal(err)
	}
	alarms := func() int {
		n := 0
		for _, a := range st.Snapshot("site-a-node1").Alarms {
			if a.Code == AlarmForwardUnreachable && a.Target == "central" {
				n++
			}
		}
		return n
	}
	fw.Check(bg)
	advance(UnreachableAfter - time.Second)
	fw.Check(bg)
	if alarms() != 0 {
		t.Fatal("raised before UnreachableAfter")
	}
	advance(2 * time.Second)
	fw.Check(bg)
	fw.Check(bg)
	advance(time.Hour)
	fw.Check(bg)
	if alarms() != 1 {
		t.Fatalf("%d forward-unreachable alarms for one outage", alarms())
	}
	if count(healthTypes(t, r), "forward.unreachable") != 1 {
		t.Fatalf("health events %v", healthTypes(t, r))
	}
}
