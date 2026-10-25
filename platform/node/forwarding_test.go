package node

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"otsec.local/otsec/contracts/event"
	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/modules/telemetry/forward"
	"otsec.local/otsec/modules/telemetry/forward/relptest"
	"otsec.local/otsec/platform/node/nodeconfigtest"
	"otsec.local/otsec/platform/store"
)

// forwardConfig is a node with one required, auditing relp-tls target at
// port, and its test PKI written to tls_dir, not yet locked (lockTLS).
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
	// The locked directory can only be removed once it is unlocked; the copy
	// keeps the path a test case may change.
	locked := *nc
	t.Cleanup(func() { locked.UnlockTLS() })
	nc.AddRELPTarget("central", "127.0.0.1", port, "test-ca", "test-client", "test/durable-ack", true)
	if mod != nil {
		mod(nc)
	}
	return nc, p, dir
}

// lockTLS gives tls_dir and its files the D2-12 rule: on Linux files 0400
// and the directory 0500; on Windows owner Administrators and read only for
// this account, which needs an elevated test. A non-elevated run skips,
// except under GitHub Actions (whose Windows runners are elevated) or with
// OTSEC_REQUIRE_ELEVATED=1, where it fails, so CI never passes these cases
// by skipping them (A6 #98).
func lockTLS(t *testing.T, nc *nodeconfigtest.Config) {
	t.Helper()
	if err := nc.LockTLS(); errors.Is(err, nodeconfigtest.ErrNeedsElevation) {
		if os.Getenv("GITHUB_ACTIONS") == "true" || os.Getenv("OTSEC_REQUIRE_ELEVATED") == "1" {
			t.Fatal(err)
		}
		t.Skip(err)
	} else if err != nil {
		t.Fatal(err)
	}
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
	lockTLS(t, nc)
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
// falls back to another reference (D2-12). Each case changes the files
// before tls_dir is locked, or loosens them after.
func TestBadTLSReferenceStopsTheNode(t *testing.T) {
	type change func(t *testing.T, nc *nodeconfigtest.Config)
	type tlsCase struct{ before, after change }
	loosen := func(name string) change {
		return func(t *testing.T, nc *nodeconfigtest.Config) {
			if err := nc.LoosenTLS(name); err != nil {
				t.Fatal(err)
			}
		}
	}
	cases := map[string]tlsCase{
		"missing trust anchors": {before: func(t *testing.T, nc *nodeconfigtest.Config) {
			os.Remove(filepath.Join(nc.TLSDir, "test-ca.pem"))
		}},
		"missing key": {before: func(t *testing.T, nc *nodeconfigtest.Config) {
			os.Remove(filepath.Join(nc.TLSDir, "test-client.key"))
		}},
		"another node's name": {before: func(t *testing.T, nc *nodeconfigtest.Config) {
			nc.Targets[0]["durable_ack"].(map[string]any)["permitted_peer"] = "site-b-node1"
		}},
		"key does not match": {before: func(t *testing.T, nc *nodeconfigtest.Config) {
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
		}},
		"trust anchors hold a key": {before: func(t *testing.T, nc *nodeconfigtest.Config) {
			b, _ := os.ReadFile(filepath.Join(nc.TLSDir, "test-client.key"))
			os.WriteFile(filepath.Join(nc.TLSDir, "test-ca.pem"), b, 0o600)
		}},
		"trust anchors too large": {before: func(t *testing.T, nc *nodeconfigtest.Config) {
			b, _ := os.ReadFile(filepath.Join(nc.TLSDir, "test-ca.pem"))
			big := make([]byte, 0, MaxTLSFileBytes+len(b))
			for len(big) <= MaxTLSFileBytes {
				big = append(big, b...)
			}
			os.WriteFile(filepath.Join(nc.TLSDir, "test-ca.pem"), big, 0o600)
		}},
		"key the node can write":           {after: loosen("test-client.key")},
		"certificate the node can write":   {after: loosen("test-client.crt")},
		"trust anchors the node can write": {after: loosen("test-ca.pem")},
		"tls_dir the node can write":       {after: loosen("")},
	}
	if runtime.GOOS == "windows" {
		own := func(name string) change {
			return func(t *testing.T, nc *nodeconfigtest.Config) {
				if err := nc.OwnTLS(name); err != nil {
					t.Fatal(err)
				}
			}
		}
		cases["key owned by the node"] = tlsCase{after: own("test-client.key")}
		cases["tls_dir owned by the node"] = tlsCase{after: own("")}
	} else {
		cases["key others can read"] = tlsCase{after: func(t *testing.T, nc *nodeconfigtest.Config) {
			os.Chmod(nc.TLSDir, 0o700)
			os.Chmod(filepath.Join(nc.TLSDir, "test-client.key"), 0o444)
			os.Chmod(nc.TLSDir, 0o500)
		}}
		link := func(name string) change {
			return func(t *testing.T, nc *nodeconfigtest.Config) {
				k := filepath.Join(nc.TLSDir, name)
				moved := filepath.Join(t.TempDir(), name)
				os.Rename(k, moved)
				os.Chmod(moved, 0o400)
				if err := os.Symlink(moved, k); err != nil {
					t.Fatal(err)
				}
			}
		}
		cases["key is a link"] = tlsCase{before: link("test-client.key")}
		cases["certificate is a link"] = tlsCase{before: link("test-client.crt")}
		cases["tls_dir is a link"] = tlsCase{after: func(t *testing.T, nc *nodeconfigtest.Config) {
			l := filepath.Join(t.TempDir(), "tls-link")
			if err := os.Symlink(nc.TLSDir, l); err != nil {
				t.Fatal(err)
			}
			nc.TLSDir = l
		}}
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			nc, _, dir := forwardConfig(t, 2514, nil)
			if tc.before != nil {
				tc.before(t, nc)
			}
			lockTLS(t, nc)
			if tc.after != nil {
				tc.after(t, nc)
			}
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
	// The unchanged, locked PKI loads, so each case above fails for its own
	// reason.
	nc, _, dir := forwardConfig(t, 2514, nil)
	lockTLS(t, nc)
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
		"separator": func(nc *nodeconfigtest.Config) { nc.Targets[0]["tls"].(map[string]any)["trust_anchor_ref"] = `ca\x` },
		"device name": func(nc *nodeconfigtest.Config) {
			nc.Targets[0]["tls"].(map[string]any)["client_credential_ref"] = "con"
		},
		"numbered device name": func(nc *nodeconfigtest.Config) { nc.Targets[0]["tls"].(map[string]any)["trust_anchor_ref"] = "com1" },
		"no tls_dir":           func(nc *nodeconfigtest.Config) { nc.TLSDir = "" },
		"relative tls_dir":     func(nc *nodeconfigtest.Config) { nc.TLSDir = "tls" },
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
	lockTLS(t, nc)
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

// A stream the forwarder holds raises forward-held once per reason, and its
// waiting events do not make the target unreachable (A4 #98).
func TestHeldStreamIsNotUnreachable(t *testing.T) {
	nc, _, _ := forwardConfig(t, 9, nil) // the forwarder is never run
	lockTLS(t, nc)
	c := parse(t, nc)
	var mu sync.Mutex
	now := time.Date(2026, 10, 25, 6, 0, 0, 0, time.UTC)
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
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
	tg := fw.targets[0]
	// Every stream with events is held, and the rest are confirmed through
	// their last seq.
	fs := forward.Status{Streams: map[c5.StreamID]forward.StreamStatus{}}
	for _, id := range tg.streams {
		last, _ := r.Store(id).LastCommitted(bg, id)
		if last > 0 {
			fs.Streams[id] = forward.StreamStatus{Blocked: "event does not fit"}
		}
	}
	if len(fs.Streams) == 0 {
		t.Fatal("no stream has events")
	}
	codes := func(code string) int {
		n := 0
		for _, a := range st.Snapshot("site-a-node1").Alarms {
			if a.Code == code && a.Target == "central" {
				n++
			}
		}
		return n
	}
	fw.check(bg, tg, fs)
	mu.Lock()
	now = now.Add(time.Hour)
	mu.Unlock()
	fw.check(bg, tg, fs)
	if n := codes(AlarmForwardHeld); n != len(fs.Streams) {
		t.Fatalf("%d forward-held alarms for %d held streams", n, len(fs.Streams))
	}
	if codes(AlarmForwardUnreachable) != 0 {
		t.Fatal("held streams raised forward-unreachable")
	}
	// Released, the same events are waiting, and an hour without a
	// confirmation is an outage.
	fs.Streams = nil
	fw.check(bg, tg, fs)
	if codes(AlarmForwardUnreachable) != 1 {
		t.Fatal("released streams did not raise forward-unreachable")
	}
}

// The forwarder's health events follow Runtime.health's rule: nothing is
// appended unless the health database accepts events (A4 #98).
func TestHealthSinkRefusesOutsideCollecting(t *testing.T) {
	nc, _, dir := forwardConfig(t, 9, nil)
	r, _, _ := start(t, parse(t, nc), dir)
	defer r.Close()
	h := healthSink{r}
	he := event.Health{Type: event.HealthForwardTextOmitted, Details: map[string]string{"target": "central"}}
	if _, err := h.Emit(bg, he); err != nil {
		t.Fatal(err)
	}
	before, _ := r.Store(HealthStream).LastCommitted(bg, HealthStream)
	d := r.dbFor(HealthStream)
	r.state.Lock()
	d.report.Mode = c5.ModeDrainOnly
	r.state.Unlock()
	if _, err := h.Emit(bg, he); err == nil {
		t.Fatal("emitted in drain-only")
	} else {
		t.Log(err)
	}
	if after, _ := r.Store(HealthStream).LastCommitted(bg, HealthStream); after != before {
		t.Fatalf("health stream went from %d to %d", before, after)
	}
}

// A best-effort target is built with each stream's commit index and
// forwards what was committed inside its replay window (A4 #94: a
// best-effort target needs Stream.Index).
func TestBestEffortTargetForwards(t *testing.T) {
	nc, p, dir := forwardConfig(t, 1, func(nc *nodeconfigtest.Config) {
		tg := nc.Targets[0]
		delete(tg, "durable_ack")
		delete(tg, "audit")
		tg["class"], tg["replay_seconds"], tg["max_message_octets"] = "best-effort", 3600, 2048
	})
	srv, err := relptest.Start(p.ServerTLS("site-a-node1"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	nc.Targets[0]["port"] = srv.Addr().Port
	lockTLS(t, nc)
	c := parse(t, nc)
	r, st, _ := start(t, c, dir)
	defer r.Close()
	r.health(bg, "test.forwarded", map[string]string{"n": "a"})
	fw, err := NewForwarding(r)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(bg)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); fw.Run(ctx) }()
	defer func() { cancel(); wg.Wait() }()
	want, _ := r.Store(HealthStream).LastCommitted(bg, HealthStream)
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		fw.Check(bg)
		if ss := st.Snapshot("site-a-node1").Targets["central"].Streams[string(HealthStream)]; ss.Cursor >= uint64(want) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	ts := st.Snapshot("site-a-node1").Targets["central"]
	if ts.Class != "best-effort" || ts.Streams[string(HealthStream)].Cursor < uint64(want) {
		t.Fatalf("target status %+v; receiver errors %v", ts, srv.Errors())
	}
}
