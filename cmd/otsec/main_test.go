package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"otsec.local/otsec/contracts/asset"
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
	nc := nodeconfigtest.New("site-a-node1", storeDir).AddSEL751(relayID, "", 2323, 300)
	if err := nc.WriteInstallKey("ik_test_first"); err != nil {
		t.Fatal(err)
	}
	if err := nc.Write(path); err != nil {
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
// stream's confirmed position, cursor and hold, and the target's alarms.
func TestHealthShowsTargets(t *testing.T) {
	path, cfg := ranNode(t)
	st := node.NewStatus(node.StatusPath(cfg), nil, nil)
	st.SetTarget("central", node.TargetStatus{Class: "required", Confirmed: 3, LastErr: "dial refused",
		Unreported: 2, ReportErr: "mode drain-only",
		Streams: map[string]node.TargetStreamState{"platform/health": {Cursor: 3, Confirmed: 4, Last: 6, Blocked: "too large"}}})
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
		"  platform/health: confirmed 4 of 6, cursor 3, HELD: too large",
		node.AlarmForwardUnreachable,
		"target central",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("health lacks %q:\n%s", want, out)
		}
	}
}

// health lists each suspended asset with its reason and the ref an
// administrator's clear must name.
func TestHealthShowsSuspensions(t *testing.T) {
	path, cfg := ranNode(t)
	st := node.NewStatus(node.StatusPath(cfg), nil, nil)
	st.SetSuspensions(map[string]asset.Suspension{relayID: {Reason: asset.SuspendAuthFailed, Since: "2026-10-25T06:00:00Z", Ref: "inv-run-1"}})
	st.Write("site-a-node1")
	out, errs, code := otsec(t, "health", "-config", path)
	want := "SUSPENDED " + relayID + ": auth-failed since 2026-10-25T06:00:00Z; cleared only by an administrator naming ref inv-run-1"
	if code != 0 || !strings.Contains(out, want) {
		t.Fatalf("health: %d %s\n%s", code, errs, out)
	}
}

// health shows each node key register entry near or past expiry.
func TestHealthShowsNodeKeys(t *testing.T) {
	path, cfg := ranNode(t)
	st := node.NewStatus(node.StatusPath(cfg), nil, nil)
	st.SetNodeKeys([]node.NodeKeyExpiry{
		{Ref: "nodekey_client01", Kind: "tls-key", NotAfter: time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC)},
		{Ref: "nodekey_anchors01", Kind: "trust-anchors", NotAfter: time.Date(2100, 1, 2, 3, 4, 5, 0, time.UTC)},
	})
	st.Write("site-a-node1")
	out, errs, code := otsec(t, "health", "-config", path)
	for _, want := range []string{
		"NODE KEY CERTIFICATE EXPIRED nodekey_client01 (tls-key) at 2020-01-02T03:04:05Z: install a new version in the key register",
		"NODE KEY CERTIFICATE EXPIRES nodekey_anchors01 (trust-anchors) at 2100-01-02T03:04:05Z: install a new version in the key register",
	} {
		if code != 0 || !strings.Contains(out, want) {
			t.Errorf("health: %d %s, lacks %q:\n%s", code, errs, want, out)
		}
	}
}

// health prints the lab_tls_files posture with the references whose key is
// in a file (B3 on #176).
func TestHealthShowsLabTLSFiles(t *testing.T) {
	path, cfg := ranNode(t)
	st := node.NewStatus(node.StatusPath(cfg), nil, nil)
	st.SetLabTLSFiles([]string{"nodekey_client01"})
	st.Write("site-a-node1")
	out, errs, code := otsec(t, "health", "-config", path)
	want := "LAB TLS KEYS IN FILES: lab_tls_files is set, so TLS private keys may be read from files in tls_dir, not a key store (lab nodes only, D2-12); from files: nodekey_client01"
	if code != 0 || !strings.Contains(out, want) {
		t.Fatalf("health: %d %s\n%s", code, errs, out)
	}
}

// health shows the Go toolchain the node was built with (D3-10).
func TestHealthShowsGoVersion(t *testing.T) {
	path, cfg := ranNode(t)
	st := node.NewStatus(node.StatusPath(cfg), nil, nil)
	st.Write("site-a-node1")
	out, errs, code := otsec(t, "health", "-config", path)
	want := "node built with " + runtime.Version() + "\n"
	if code != 0 || !strings.Contains(out, want) {
		t.Fatalf("health: %d %s\n%s", code, errs, out)
	}
}

// A status file written by an older node has no go_version, and health
// prints no "node built with" line for it (B6 on #244).
func TestHealthWithoutGoVersionPrintsNoLine(t *testing.T) {
	path, cfg := ranNode(t)
	st := node.NewStatus(node.StatusPath(cfg), nil, nil)
	st.Write("site-a-node1")
	b, err := os.ReadFile(node.StatusPath(cfg))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["go_version"]; !ok {
		t.Fatalf("the status file has no go_version to remove: %s", b)
	}
	delete(m, "go_version")
	if b, err = json.Marshal(m); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(node.StatusPath(cfg), b, 0o600); err != nil {
		t.Fatal(err)
	}
	out, errs, code := otsec(t, "health", "-config", path)
	if code != 0 || strings.Contains(out, "node built with") {
		t.Fatalf("health: %d %s\n%s", code, errs, out)
	}
}

// health says when a node-wide hold is current, and says nothing once it
// has ended, though its alarm stays in the history (A3 on #147).
func TestHealthShowsRunsHeld(t *testing.T) {
	path, cfg := ranNode(t)
	st := node.NewStatus(node.StatusPath(cfg), nil, nil)
	st.SetRunsHeld(node.AlarmSuspensionsUnknown)
	st.Write("site-a-node1")
	out, errs, code := otsec(t, "health", "-config", path)
	want := "RUNS HELD: " + node.AlarmSuspensionsUnknown + "; every run on this node is stopped while this line shows"
	if code != 0 || !strings.Contains(out, want) {
		t.Fatalf("health: %d %s\n%s", code, errs, out)
	}
	st.SetRunsHeld("")
	st.Write("site-a-node1")
	if out, _, _ := otsec(t, "health", "-config", path); strings.Contains(out, "RUNS HELD") {
		t.Fatalf("health still shows a hold that ended:\n%s", out)
	}
}

// health shows each Syslog listener: whether it is open, its counts and
// last message, and any drop, hold or unknown sender (P3-A4).
func TestHealthShowsListeners(t *testing.T) {
	path, cfg := ranNode(t)
	at := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	st := node.NewStatus(node.StatusPath(cfg), nil, nil)
	st.SetListeners(map[string]node.ListenerStatus{
		"lab-udp": {Transport: "syslog-udp", Address: "127.0.0.1:5514", Plaintext: true, Open: true, Received: 7, Stored: 5, LastMessage: at,
			Dropped: map[string]int64{"store": 1, "rate-limit": 1}, UnknownSenders: 2, UnknownOverflow: true},
		"lab-tls": {Transport: "syslog-tls", Address: "127.0.0.1:6514", Held: true, Refused: map[string]int64{"tls": 3}, LastErr: "store: quota reached",
			Unknown:      &node.UnknownShare{HourlyBytes: 671088, BoundBytes: 16777200, QuotaBytes: 67108864, OutageHours: 24, StoredBytes: 20582, SpentAtStart: 4096},
			CertNotAfter: time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC)},
		"lab-tls2": {Transport: "syslog-tls", Address: "127.0.0.1:6515", CertNotAfter: time.Now().Add(10 * 24 * time.Hour).UTC().Truncate(time.Second)},
		"lab-tls3": {Transport: "syslog-tls", Address: "127.0.0.1:6516", CertNotAfter: time.Date(2100, 1, 2, 3, 4, 5, 0, time.UTC)},
	})
	st.Write("site-a-node1")
	out, errs, code := otsec(t, "health", "-config", path)
	if code != 0 {
		t.Fatalf("health: %d %s", code, errs)
	}
	for _, want := range []string{
		"listener lab-udp (syslog-udp 127.0.0.1:5514): open, 7 received, 5 stored, last message 2026-10-26T12:00:00Z",
		"  PLAINTEXT: no sender authentication or integrity; any host on the path can send or alter messages (D3-5)",
		"  DROPPED: rate-limit 1, store 1",
		"  UNKNOWN SENDERS: 2 and more not tracked; their messages are kept with no asset",
		"listener lab-tls (syslog-tls 127.0.0.1:6514): NOT OPEN, 0 received, 0 stored, last message never in this process",
		"  HELD: the store is not taking this listener's messages; senders are not read meanwhile",
		"  connections refused: tls 3",
		"  last error: store: quota reached",
		"  unknown senders stored 20582 bytes since start; budget 671088 bytes an hour, started 4096 bytes spent by the hour before start; with this class's other listeners at most 16777200 bytes, 24% of the 67108864-byte quota, over a 24 h outage (HR-11)",
		"  CERTIFICATE EXPIRED at 2020-01-02T03:04:05Z: the listener keeps running, and senders that check it refuse it",
		"listener lab-tls2 (syslog-tls 127.0.0.1:6515): NOT OPEN, 0 received, 0 stored, last message never in this process\n  CERTIFICATE EXPIRES at ",
		"listener lab-tls3 (syslog-tls 127.0.0.1:6516): NOT OPEN, 0 received, 0 stored, last message never in this process\n  certificate valid until 2100-01-02T03:04:05Z",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("health lacks %q:\n%s", want, out)
		}
	}
	if n := strings.Count(out, "PLAINTEXT"); n != 1 {
		t.Errorf("%d PLAINTEXT lines, want 1 (the TLS listener has none):\n%s", n, out)
	}
}

// health lists each clear the node has recorded that the collector has
// not yet accepted, and tells the administrator to keep the file in place.
func TestHealthShowsCollectorStillSuspended(t *testing.T) {
	path, cfg := ranNode(t)
	st := node.NewStatus(node.StatusPath(cfg), nil, nil)
	st.SetCollectorClears(map[string]string{relayID: "inv-run-1"})
	st.Write("site-a-node1")
	out, errs, code := otsec(t, "health", "-config", path)
	want := "COLLECTOR STILL SUSPENDED " + relayID + ": the node cleared ref inv-run-1, the collector has not accepted the clear yet; runs stay held, and " + node.ClearSuspensionFileName + " stays in place until this line is gone"
	if code != 0 || !strings.Contains(out, want) {
		t.Fatalf("health: %d %s\n%s", code, errs, out)
	}
}

// health shows each asset's last run and, when it failed, how many in a
// row (D2-17).
func TestHealthShowsAssetResults(t *testing.T) {
	path, cfg := ranNode(t)
	at := time.Date(2026, 10, 25, 6, 0, 0, 0, time.UTC)
	st := node.NewStatus(node.StatusPath(cfg), nil, nil)
	st.SetAssetResults(map[string]node.AssetResult{
		relayID:   {Code: "failed.identity_unreadable", Detail: "no FID line", At: at, Failures: 4},
		"relay-b": {Code: node.AlarmCollectorRefused, Refusal: "rate_limited", At: at, Failures: 1},
		"relay-c": {Code: "ok", At: at},
	})
	st.Write("site-a-node1")
	out, errs, code := otsec(t, "health", "-config", path)
	for _, want := range []string{
		"FAILING asset " + relayID + ": last run failed.identity_unreadable (no FID line) at 2026-10-25T06:00:00Z; 4 failed in a row since the node started",
		"FAILING asset relay-b: last run " + node.AlarmCollectorRefused + " at 2026-10-25T06:00:00Z (collector refused: rate_limited); 1 failed in a row since the node started",
		"\nasset relay-c: last run ok at 2026-10-25T06:00:00Z\n",
	} {
		if code != 0 || !strings.Contains(out, want) {
			t.Fatalf("health: %d %s\nwant %q in\n%s", code, errs, want, out)
		}
	}
}

// quarantine export writes the asset's quarantine to a new directory
// without changing the store, refuses a directory that exists, and says
// when it could not copy the manifest for the node.
func TestQuarantineExportCommand(t *testing.T) {
	path, cfg := ranNode(t)
	before := snapshot(t, cfg.Store.Dir)
	dir := filepath.Join(t.TempDir(), "export")
	out, errs, code := otsec(t, "quarantine", "export", "-config", path, relayID, dir)
	if code != 1 || !strings.Contains(errs, "the export is complete in "+dir) || !strings.Contains(errs, "no admin_dir") {
		t.Fatalf("export without admin_dir: %d %q %q", code, out, errs)
	}
	var m node.QuarantineManifest
	b, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil || json.Unmarshal(b, &m) != nil || len(m.Items) != 2 || m.AssetID != relayID {
		t.Fatalf("manifest: %v %+v", err, m)
	}
	after := snapshot(t, cfg.Store.Dir)
	for name, b := range before {
		if !bytes.Equal(after[name], b) {
			t.Errorf("%s changed under the export", name)
		}
	}
	if _, errs, code := otsec(t, "quarantine", "export", "-config", path, relayID, dir); code != 1 || !strings.Contains(errs, "exists") {
		t.Fatalf("export into an existing directory: %d %s", code, errs)
	}
	for _, args := range [][]string{{"quarantine"}, {"quarantine", "import", "-config", path, relayID, dir}, {"quarantine", "export", "-config", path, relayID}} {
		if _, _, code := otsec(t, args...); code != 2 {
			t.Fatalf("%v: exit %d, want 2", args, code)
		}
	}
}

// health shows each recorded export still to clear, and a clear whose
// removal is not done.
func TestHealthShowsQuarantine(t *testing.T) {
	path, cfg := ranNode(t)
	st := node.NewStatus(node.StatusPath(cfg), nil, nil)
	st.SetQuarantine([]node.QuarantineStatus{
		{AssetID: relayID, ManifestSHA256: strings.Repeat("a", 64), FirstSeq: 1, LastSeq: 18, Items: 18},
		{AssetID: relayID, ManifestSHA256: strings.Repeat("b", 64), FirstSeq: 19, LastSeq: 40, Items: 22, Clearing: true},
	})
	st.Write("site-a-node1")
	out, errs, code := otsec(t, "health", "-config", path)
	if code != 0 {
		t.Fatalf("health: %d %s", code, errs)
	}
	for _, want := range []string{
		"QUARANTINE EXPORTED, NOT CLEARED " + relayID + ": manifest " + strings.Repeat("a", 64) + ", seqs 1 to 18 (18 items); clear-quarantine.json naming it removes them",
		"QUARANTINE CLEAR INCOMPLETE " + relayID + ": manifest " + strings.Repeat("b", 64) + ", seqs 19 to 40; removing 16 per tick, and runs of this asset are held until it is done",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("health lacks %q:\n%s", want, out)
		}
	}
}

// health tells the administrator what a node-kind admin request still owes:
// the node's part pending (keep the file), done (the file may go), nothing to
// do, and refused (the node will not act on it; sign again).
func TestHealthShowsAdminRequestNodePart(t *testing.T) {
	path, cfg := ranNode(t)
	st := node.NewStatus(node.StatusPath(cfg), nil, nil)
	st.SetAdminRequests([]node.AdminRequestStatus{
		{File: "admin-request-a.json", Kind: "node.quarantine_clear", State: "accepted", CollectorSeq: 7, NodePart: "pending", Detail: "the chain holds no quarantine.exported record"},
		{File: "admin-request-b.json", Kind: "node.seq_reset_ack", State: "accepted", CollectorSeq: 8, NodePart: "done"},
		{File: "admin-request-c.json", Kind: "credential.revoke", State: "accepted", CollectorSeq: 9},
		{File: "admin-request-e.json", Kind: "node.quarantine_clear", State: "accepted", CollectorSeq: 11, NodePart: "refused", Detail: "accepted by a collector the node did not trust"},
		{File: "admin-request-f.json", Kind: "node.seq_reset_ack", State: "accepted", CollectorSeq: 12, NodePart: "nothing", Detail: "install key k is already the trusted key"},
	})
	st.Write("site-a-node1")
	out, errs, code := otsec(t, "health", "-config", path)
	if code != 0 {
		t.Fatalf("health: %d %s", code, errs)
	}
	for _, want := range []string{
		"ADMIN REQUEST ACCEPTED, NODE'S PART PENDING admin-request-a.json (node.quarantine_clear): accepted by the collector, collector_seq 7; the chain holds no quarantine.exported record. Leave the file in place until this line is gone",
		"admin request admin-request-b.json (node.seq_reset_ack): accepted by the collector, collector_seq 8, and applied by the node; the file may be removed",
		"admin request admin-request-c.json (credential.revoke): accepted by the collector, collector_seq 9; the file may be removed",
		"ADMIN REQUEST ACCEPTED, NOT APPLIED BY THE NODE admin-request-e.json (node.quarantine_clear): collector_seq 11; accepted by a collector the node did not trust; the node will not act on it. The file stays until it is replaced; sign a new request",
		"admin request admin-request-f.json (node.seq_reset_ack): accepted by the collector, collector_seq 12; nothing for the node to do (install key k is already the trusted key); the file may be removed",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("health lacks %q:\n%s", want, out)
		}
	}
}

// health says when a link is held back for its certificate's period
// (HR-13), and does not call a held listener's expired certificate a
// running one's.
func TestHealthShowsHeldBackLinks(t *testing.T) {
	path, cfg := ranNode(t)
	st := node.NewStatus(node.StatusPath(cfg), nil, nil)
	st.SetTarget("central", node.TargetStatus{Class: "required", HeldBack: "expired",
		CertNotAfter: time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC), Streams: map[string]node.TargetStreamState{}})
	st.SetTarget("other", node.TargetStatus{Class: "required",
		CertNotAfter: time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC), Streams: map[string]node.TargetStreamState{}})
	st.SetListeners(map[string]node.ListenerStatus{"lab-tls": {Transport: "syslog-tls", Address: "127.0.0.1:6514",
		HeldBack: "not-yet-valid", CertNotAfter: time.Date(2100, 1, 2, 3, 4, 5, 0, time.UTC)}})
	st.Write("site-a-node1")
	out, errs, code := otsec(t, "health", "-config", path)
	if code != 0 {
		t.Fatalf("health: %d %s", code, errs)
	}
	for _, want := range []string{
		"target central (required)",
		"  HELD BACK: the node's client certificate for this target is expired; no connection is made and its events wait in the store until the period is valid (HR-13)",
		"target other (required)",
		"  CLIENT CERTIFICATE EXPIRED at 2020-01-02T03:04:05Z: the target is still being tried; replace it and restart the node",
		"  HELD BACK: the listener certificate is not-yet-valid; the listener is not bound and receives nothing until the period is valid (HR-13)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("health lacks %q:\n%s", want, out)
		}
	}
	if strings.Count(out, "CLIENT CERTIFICATE EXPIRED") != 1 || strings.Contains(out, "certificate valid until 2100") {
		t.Errorf("a held-back link is shown with a running link's certificate line:\n%s", out)
	}
}

// The health line for write transactions is empty on a healthy node, shows
// a second or more, and says SLOW at the alarm's threshold (store-commit-slow).
func TestCommitLine(t *testing.T) {
	for name, tc := range map[string]struct {
		c    node.CommitStatus
		want []string
	}{
		"quiet":         {node.CommitStatus{Count: 10, MaxMS: 40, RecentMS: 12}, nil},
		"just a bit":    {node.CommitStatus{Count: 10, MaxMS: 999, RecentMS: 999}, nil},
		"over a second": {node.CommitStatus{Count: 10, MaxMS: 2100, RecentMS: 1500}, []string{"slowest 1500 ms", "2100 ms since the node started"}},
		"running now":   {node.CommitStatus{Count: 10, MaxMS: 200, RecentMS: 100, WaitingMS: 3000}, []string{"one has been running 3000 ms"}},
		"slow":          {node.CommitStatus{Count: 10, MaxMS: 31000, RecentMS: 26800}, []string{"SLOW"}},
	} {
		got := commitLine(tc.c)
		if len(tc.want) == 0 && got != "" {
			t.Errorf("%s: %q", name, got)
		}
		for _, w := range tc.want {
			if !strings.Contains(got, w) {
				t.Errorf("%s: %q lacks %q", name, got, w)
			}
		}
		if tc.want == nil || name != "slow" {
			if strings.Contains(got, "SLOW") && name != "slow" {
				t.Errorf("%s: says SLOW: %q", name, got)
			}
		}
	}
}

// A UDP listener's receive buffer is shown with what the OS granted, and a
// request the OS met only in part is called out (the node half of B4's
// Limits.ReadBuffer).
func TestHealthShowsReadBuffer(t *testing.T) {
	path, cfg := ranNode(t)
	st := node.NewStatus(node.StatusPath(cfg), nil, nil)
	st.SetListeners(map[string]node.ListenerStatus{
		"a-default": {Transport: "syslog-udp", Address: "127.0.0.1:5514", Open: true, ReadBuffer: 212992},
		"b-met":     {Transport: "syslog-udp", Address: "127.0.0.1:5515", Open: true, ReadBuffer: 2 << 20, ReadBufferAsked: 1 << 20},
		"c-short":   {Transport: "syslog-udp", Address: "127.0.0.1:5516", Open: true, ReadBuffer: 425984, ReadBufferAsked: 8 << 20},
		"d-unknown": {Transport: "syslog-udp", Address: "127.0.0.1:5517", Open: true, ReadBufferAsked: 1 << 20, ReadBufferErr: "not reported"},
	})
	st.Write("site-a-node1")
	out, errs, code := otsec(t, "health", "-config", path)
	if code != 0 {
		t.Fatalf("health: %d %s", code, errs)
	}
	for _, want := range []string{
		"  receive buffer: 212992 bytes (the OS default; read_buffer_bytes is not set)",
		"  receive buffer: 2097152 bytes granted (asked 1048576)",
		fmt.Sprintf("  receive buffer: 425984 bytes granted, SHORT of the %d expected for the 8388608 asked: datagrams that arrive while it is full are lost before the listener reads them, and only the OS counts them", node.ReadBufferExpected(runtime.GOOS, 8<<20)),
		"  receive buffer: the OS did not report it (not reported)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("health lacks %q:\n%s", want, out)
		}
	}
}
