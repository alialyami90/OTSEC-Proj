package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/authz"
	"otsec.local/otsec/modules/security/collectorclient"
	"otsec.local/otsec/platform/node"
	"otsec.local/otsec/platform/node/nodeconfigtest"
	"otsec.local/otsec/platform/store"
)

const relayID = "2b7d4e10-8c3f-4a5b-9e21-7c4f0d6a8b13"

var bg = context.Background()

type quarantining struct{}

func (quarantining) Do(ctx context.Context, req *authz.CollectorRequest) (collectorclient.Response, error) {
	reply := authz.CollectorReply{Contract: authz.ContractID, RequestID: req.RequestID, Status: authz.ReplyAccepted,
		InvocationID: "6f1c2b9e-3d4a-4c1e-9b7a-2f0e8d5c1a30", CollectorSeq: 1}
	return collectorclient.Response{Reply: reply, Quarantine: &collectorclient.Quarantine{Raw: []byte("frame"), Reason: "LINE-TEXT", UnauthorizedLine: true}},
		fmt.Errorf("%w: %w", collectorclient.ErrOutcomeUnknown, collectorclient.ErrUnauthorizedLine)
}

// node prepares a node that ran once: a store with health and audit
// events, one quarantine and a status file. It returns the config path.
func ranNode(t *testing.T) (string, *node.Config) {
	t.Helper()
	dir := t.TempDir()
	storeDir := filepath.Join(dir, "store")
	if err := store.CreateDir(storeDir, ""); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "node.json")
	if err := nodeconfigtest.New("site-a-node1", storeDir).AddSEL751(relayID, "", 2323, 300).Write(path); err != nil {
		t.Fatal(err)
	}
	cfg, err := node.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	st := node.NewStatus(node.StatusPath(cfg), nil, nil)
	rt, err := node.Start(bg, cfg, node.RuntimeOptions{Status: st})
	if err != nil {
		t.Fatal(err)
	}
	s, err := node.NewScheduler(bg, rt, quarantining{})
	if err != nil {
		t.Fatal(err)
	}
	s.RunOnce(bg, 0)
	if err := rt.Close(); err != nil {
		t.Fatal(err)
	}
	st.Write("site-a-node1")
	return path, cfg
}

func otsec(t *testing.T, args ...string) (string, string, int) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(bg, args, &out, &errb)
	return out.String(), errb.String(), code
}

func snapshot(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	m := map[string][]byte{}
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), "-shm") {
			continue // shared memory index, rewritten by any reader
		}
		b, _ := os.ReadFile(filepath.Join(dir, e.Name()))
		m[e.Name()] = b
	}
	return m
}

func TestReadOnlyCommands(t *testing.T) {
	path, cfg := ranNode(t)
	before := snapshot(t, cfg.Store.Dir)

	out, errs, code := otsec(t, "assets", "-config", path)
	if code != 0 || !strings.Contains(out, relayID) || !strings.Contains(out, "telnet 127.0.0.1:2323") || !strings.Contains(out, "simulated") {
		t.Fatalf("assets: %d %s %s", code, out, errs)
	}

	out, errs, code = otsec(t, "events", "-config", path)
	if code != 0 || !strings.Contains(out, "platform/health") || !strings.Contains(out, "quarantine/"+relayID) || !strings.Contains(out, "not shown") {
		t.Fatalf("events list: %d %s %s", code, out, errs)
	}
	out, errs, code = otsec(t, "events", "-config", path, "-stream", "platform/health")
	if code != 0 || !strings.Contains(out, "store.mode-changed") || !strings.Contains(out, node.HealthCollectionOutcomeUnknown) {
		t.Fatalf("events health: %d %s %s", code, out, errs)
	}
	out, _, code = otsec(t, "events", "-config", path, "-stream", "platform/health", "-json", "-limit", "1")
	if code != 0 || strings.Count(out, "\n") != 1 || !strings.HasPrefix(out, "{") {
		t.Fatalf("events -json: %d %q", code, out)
	}
	for _, s := range []string{"audit", "quarantine/" + relayID} {
		if _, errs, code := otsec(t, "events", "-config", path, "-stream", s); code == 0 || !strings.Contains(errs, "not shown") {
			t.Errorf("events -stream %s: %d %s", s, code, errs)
		}
	}

	out, errs, code = otsec(t, "health", "-config", path)
	if code != 0 || !strings.Contains(out, "collecting: true") || !strings.Contains(out, node.AlarmUnauthorizedLine) || !strings.Contains(out, "QUARANTINE quarantine/"+relayID+": 2 records") {
		t.Fatalf("health: %d %s %s", code, out, errs)
	}
	if strings.Contains(out, "LINE-TEXT") {
		t.Fatalf("health prints the quarantine reason:\n%s", out)
	}

	after := snapshot(t, cfg.Store.Dir)
	for name, b := range before {
		if !bytes.Equal(after[name], b) {
			t.Errorf("%s changed under the read-only commands", name)
		}
	}
	// A SQLite reader of a WAL database creates the -wal file when the node
	// is stopped, empty and with the database file's mode. Nothing else may
	// appear.
	for name, b := range after {
		if _, ok := before[name]; ok {
			continue
		}
		fi, err := os.Stat(filepath.Join(cfg.Store.Dir, name))
		if !strings.HasSuffix(name, ".db-wal") || len(b) != 0 || err != nil || (runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600) {
			t.Errorf("%s created under the read-only commands: %d bytes, %v", name, len(b), fi.Mode())
		}
	}
	// The node starts on the store afterwards.
	st := node.NewStatus("", nil, nil)
	rt, err := node.Start(bg, cfg, node.RuntimeOptions{Status: st})
	if err != nil || !rt.Collecting() {
		t.Fatalf("node after the read-only commands: %v", err)
	}
	rt.Close()
}

func TestUsage(t *testing.T) {
	for _, args := range [][]string{nil, {"assets"}, {"shell", "-config", "x"}, {"events", "-config"}} {
		if _, _, code := otsec(t, args...); code != 2 && code != 1 {
			t.Errorf("%v: exit %d", args, code)
		}
	}
	if _, errs, code := otsec(t, "assets", "-config", filepath.Join(t.TempDir(), "missing.json")); code != 1 || errs == "" {
		t.Errorf("missing config: %d %s", code, errs)
	}
}

// health shows each forwarding target: confirmations, whether a session is
// open, the last session error, refused forward health events, each
// stream's cursor and hold, and the target's alarms.
func TestHealthShowsTargets(t *testing.T) {
	path, cfg := ranNode(t)
	st := node.NewStatus(node.StatusPath(cfg), nil, nil)
	st.SetTarget("central", node.TargetStatus{Class: "required", Confirmed: 3, LastErr: "dial refused",
		Unreported: 2, ReportErr: "mode drain-only",
		Streams: map[string]node.TargetStreamState{"platform/health": {Cursor: 4, Last: 6, Blocked: "too large"}}})
	st.RaiseTarget("central", node.AlarmForwardUnreachable, "no session open for 1m0s")
	st.Write("site-a-node1")
	out, errs, code := otsec(t, "health", "-config", path)
	if code != 0 {
		t.Fatalf("health: %d %s", code, errs)
	}
	for _, want := range []string{
		"target central (required): 3 confirmed, last never in this process",
		"  no session open",
		"  last session ended: dial refused",
		"  forward health events not yet recorded: 2 (last refusal: mode drain-only)",
		"  platform/health: cursor 4 of 6, HELD: too large",
		node.AlarmForwardUnreachable,
		"target central",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("health lacks %q:\n%s", want, out)
		}
	}
}
