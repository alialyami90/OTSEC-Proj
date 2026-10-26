package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/authz"
	"otsec.local/otsec/contracts/register"
	"otsec.local/otsec/modules/security/collectorclient"
	"otsec.local/otsec/modules/security/collectorwire"
	"otsec.local/otsec/modules/security/seal"
)

// canary is a test value (D2-5), never a device password.
var canary = []byte("Canary-7f3K")

const testNode = "site-a-node1"

// testAdminPriv is the test administrator's key (the C7 golden's seed), a
// test key only (D2-5).
var testAdminPriv = func() ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("otsec test admin key 1"))
	return ed25519.NewKeyFromSeed(seed[:])
}()

func testAdminPub() ed25519.PublicKey { return testAdminPriv.Public().(ed25519.PublicKey) }

// adminSigned returns req as the test administrator's request to this
// collector: its body moves into a signed payload bound to the node and the
// collector's install key.
func adminSigned(t testing.TB, req *authz.CollectorRequest, installKeyID string) *authz.CollectorRequest {
	t.Helper()
	nonce := make([]byte, authz.AdminNonceLen)
	rand.Read(nonce)
	now := time.Now().UTC()
	env, err := authz.SignAdminRequest(testAdminPriv, authz.AdminRequest{
		Format: authz.AdminRequestFormat, Kind: req.Kind, Principal: req.OnBehalfOf,
		AdminKeyID: authz.AdminKeyID(testAdminPub()), NodeID: testNode, InstallKeyID: installKeyID,
		Nonce: base64.RawURLEncoding.EncodeToString(nonce), IssuedAt: now.Format(time.RFC3339),
		ExpiresAt: now.Add(10 * time.Minute).Format(time.RFC3339), CredentialInstall: req.CredentialInstall,
		CredentialRevoke: req.CredentialRevoke, CredentialClearSusp: req.CredentialClearSusp, AssetClearSusp: req.AssetClearSusp,
	})
	if err != nil {
		t.Fatal(err)
	}
	out := *req
	out.CredentialInstall, out.CredentialRevoke, out.CredentialClearSusp, out.AssetClearSusp = nil, nil, nil, nil
	out.AdminSigned = env
	return &out
}

func fixture(t testing.TB, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// testConfig is a valid collector.json for the simulated SEL-751, with its
// endpoint on 127.0.0.1 and the register signed by a fresh release key.
func testConfig(t testing.TB, socket string) map[string]any {
	t.Helper()
	var a map[string]any
	json.Unmarshal(fixture(t, "sel-751-simulated.json"), &a)
	ep := a["endpoints"].([]any)[0].(map[string]any)
	// A loopback port nothing listens on, so a run that reaches the
	// adapter ends as failed.connect.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	ep["host"], ep["port"] = "127.0.0.1", port
	var p any
	json.Unmarshal(fixture(t, "profile-sel-751-ascii.json"), &p)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	payload := fixture(t, "register-sel-751.json")
	env := register.Envelope{Contract: register.ContractID, Algorithm: "ed25519", KeyID: "release-2026",
		Payload: payload, Signature: ed25519.Sign(priv, authz.RegisterSigningInput(payload))}
	uid := ""
	if runtime.GOOS != "windows" {
		uid = strconv.Itoa(os.Getuid())
	}
	return map[string]any{
		"format": ConfigFormat, "node_id": testNode, "policy_version": 3,
		"ipc":           map[string]any{"address": socket, "node_peer": uid},
		"assets":        []any{a},
		"profiles":      []any{p},
		"trust_anchors": []any{map[string]any{"key_id": "release-2026", "public_key": base64.StdEncoding.EncodeToString(pub), "status": "active"}},
		"registers":     []any{env},
		"admin_keys": []any{map[string]any{"key_id": authz.AdminKeyID(testAdminPub()),
			"public_key": base64.StdEncoding.EncodeToString(testAdminPub()), "principal": "admin@site-a", "status": "active"}},
	}
}

func marshal(t testing.TB, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseConfig(t *testing.T) {
	good := testConfig(t, "/run/otsec/collector.sock")
	c, err := parseConfig(marshal(t, good))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Assets) != 1 || len(c.Anchors) != 1 || len(c.Registers) != 1 || c.PolicyVersion != 3 ||
		len(c.AdminKeys) != 1 || !c.AdminKeys[0].PublicKey.Equal(testAdminPub()) || c.AdminKeys[0].Principal != "admin@site-a" {
		t.Fatalf("config %+v", c)
	}
	edit := func(m func(map[string]any)) []byte {
		var d map[string]any
		json.Unmarshal(marshal(t, good), &d)
		m(d)
		return marshal(t, d)
	}
	for name, b := range map[string][]byte{
		"unknown field":   edit(func(d map[string]any) { d["secret"] = "x" }),
		"case variant":    edit(func(d map[string]any) { d["NODE_ID"] = d["node_id"]; delete(d, "node_id") }),
		"format":          edit(func(d map[string]any) { d["format"] = "otsec.collector-config/0.2" }),
		"node id":         edit(func(d map[string]any) { d["node_id"] = "Site A" }),
		"policy 0":        edit(func(d map[string]any) { d["policy_version"] = 0 }),
		"bad asset":       edit(func(d map[string]any) { d["assets"].([]any)[0].(map[string]any)["asset_id"] = "x" }),
		"missing profile": edit(func(d map[string]any) { d["profiles"] = []any{} }),
		"profile version": edit(func(d map[string]any) {
			d["assets"].([]any)[0].(map[string]any)["profile"].(map[string]any)["version"] = "9.9"
		}),
		"anchor key":    edit(func(d map[string]any) { d["trust_anchors"].([]any)[0].(map[string]any)["public_key"] = "AAAA" }),
		"anchor status": edit(func(d map[string]any) { d["trust_anchors"].([]any)[0].(map[string]any)["status"] = "maybe" }),
		"admin key":     edit(func(d map[string]any) { d["admin_keys"].([]any)[0].(map[string]any)["public_key"] = "AAAA" }),
		"admin key id": edit(func(d map[string]any) {
			d["admin_keys"].([]any)[0].(map[string]any)["key_id"] = "ed25519-0000000000000000"
		}),
		"admin key twice": edit(func(d map[string]any) {
			k := d["admin_keys"].([]any)[0]
			d["admin_keys"] = []any{k, k}
		}),
		"admin key short": edit(func(d map[string]any) {
			// 31 bytes under its own derived ID: only the size check refuses it.
			short := testAdminPub()[:31]
			k := d["admin_keys"].([]any)[0].(map[string]any)
			k["public_key"], k["key_id"] = base64.StdEncoding.EncodeToString(short), authz.AdminKeyID(short)
		}),
		"admin principal": edit(func(d map[string]any) { d["admin_keys"].([]any)[0].(map[string]any)["principal"] = "" }),
		"admin status":    edit(func(d map[string]any) { d["admin_keys"].([]any)[0].(map[string]any)["status"] = "maybe" }),
		"admin extra":     edit(func(d map[string]any) { d["admin_keys"].([]any)[0].(map[string]any)["private_key"] = "x" }),
		"trailing data":   append(marshal(t, good), '{', '}'),
	} {
		if _, err := parseConfig(b); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if runtime.GOOS != "windows" {
		if _, err := parseConfig(edit(func(d map[string]any) { d["ipc"] = map[string]any{} })); !errors.Is(err, errMissingIPC) {
			t.Errorf("no ipc on Linux: %v", err)
		}
	}
}

func TestProvision(t *testing.T) {
	newData := func(t *testing.T) layout {
		l := newLayout(t.TempDir())
		for _, d := range []string{filepath.Dir(l.state), filepath.Dir(l.credentials)} {
			if err := os.MkdirAll(d, 0o700); err != nil {
				t.Fatal(err)
			}
		}
		return l
	}
	marker := func(t *testing.T, l layout) {
		if err := os.WriteFile(l.provision, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	l := newData(t)
	if _, err := provision(l, testNode, nil); !errors.Is(err, errLostState) {
		t.Fatalf("no marker: %v", err)
	}
	marker(t, l)
	if created, err := provision(l, testNode, nil); err != nil || !created {
		t.Fatalf("first start: %v %v", created, err)
	}
	if ok, _ := exists(l.provision); ok {
		t.Fatal("marker left behind")
	}
	if created, err := provision(l, testNode, nil); err != nil || created {
		t.Fatalf("second start: %v %v", created, err)
	}
	// A marker left by a crash after the stores were created goes at the
	// next start, so a later loss of both stores is refused, not a silent
	// first start (A6 on #106).
	marker(t, l)
	if created, err := provision(l, testNode, nil); err != nil || created {
		t.Fatalf("start with a leftover marker: %v %v", created, err)
	}
	if ok, _ := exists(l.provision); ok {
		t.Fatal("leftover marker kept")
	}
	saved := map[string][]byte{}
	for _, f := range []string{l.state, l.credentials} {
		saved[f], _ = os.ReadFile(f)
		os.Remove(f)
	}
	if _, err := provision(l, testNode, nil); !errors.Is(err, errLostState) {
		t.Fatalf("both stores lost after a leftover marker: %v", err)
	}
	for f, b := range saved {
		if err := os.WriteFile(f, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// One store lost: refused, even with a marker, and nothing is created.
	os.Remove(l.state)
	marker(t, l)
	if _, err := provision(l, testNode, nil); !errors.Is(err, errLostState) {
		t.Fatalf("one store lost: %v", err)
	}
	if ok, _ := exists(l.state); ok {
		t.Fatal("a lost state was recreated")
	}
}

func TestCheckTraceback(t *testing.T) {
	for v, ok := range map[string]bool{"": true, "single": true, "all": true, "crash": false, "CRASH": false, "wer": false} {
		t.Setenv("GOTRACEBACK", v)
		if got := checkTraceback() == nil; got != ok {
			t.Errorf("GOTRACEBACK=%q: %v", v, got)
		}
	}
}

// T-5 on Linux: after harden the process is not dumpable and its core limit
// is zero. It runs in a child, because it changes the process.
func TestHarden(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux controls; the Windows ones run on the site image (T-5)")
	}
	if os.Getenv("OTSEC_HARDEN_CHILD") == "1" {
		if err := harden(); err != nil {
			os.Exit(3)
		}
		os.Exit(hardenedExitCode())
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestHarden$")
	cmd.Env = append(os.Environ(), "OTSEC_HARDEN_CHILD=1", "GOTRACEBACK=")
	err := cmd.Run()
	var ee *exec.ExitError
	if err != nil && !(errors.As(err, &ee) && ee.ExitCode() == 0) {
		t.Fatalf("child: %v", err)
	}
}

// TestServe is the binary end to end over the real socket: first start from
// the installer's marker, the install key published, an install sealed to
// the published key and pinned to its fingerprint, and a run refused because
// no adapter is hosted yet. Then every byte the collector wrote, files and
// logs, is scanned for the secret (T-5, T-8 at this layer).
func TestServe(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the Windows service path needs the installer's WER exclusion and the service accounts (PC run)")
	}
	data := t.TempDir()
	l := newLayout(data)
	sockDir := filepath.Join(t.TempDir(), "run")
	for _, d := range []string{filepath.Dir(l.state), filepath.Dir(l.credentials), filepath.Dir(l.publicKey), sockDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	socket := filepath.Join(sockDir, "collector.sock")
	cfg := testConfig(t, socket)
	if err := os.WriteFile(l.config, marshal(t, cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(l.provision, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, nil))
	r, err := start(data, log)
	if err != nil {
		t.Fatal(err)
	}
	defer r.stop()

	var pub publishedKey
	b, err := os.ReadFile(l.publicKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &pub); err != nil || pub.Schema != installKeySchema || pub.KeyID == "" || pub.PublicKey == "" {
		t.Fatalf("install-key.json: %s (%v)", b, err)
	}
	if !strings.Contains(logs.String(), pub.Fingerprint) {
		t.Fatal("fingerprint not logged")
	}
	if _, err := os.Stat(l.publicKey + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("temporary file left: %v", err)
	}

	client := collectorclient.New(collectorwire.Endpoint{Address: socket, Peer: strconv.Itoa(os.Getuid())})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	admin := authz.Principal{Type: authz.PrincipalHuman, ID: "admin@site-a"}
	ref := authz.CredentialRef{
		ID: "cred_slice0001", AssetID: "2b7d4e10-8c3f-4a5b-9e21-7c4f0d6a8b13", NodeID: testNode, EndpointID: "port1-telnet",
		Transport: authz.TransportTelnet, Purpose: authz.PurposeCollectReadOnly, AccessLevel: "1",
		DownstreamSecurity: authz.DownstreamPlaintext, PlaintextScope: authz.PlaintextLabOnly,
		Version: 1, CreatedBy: admin, CreatedAt: "2026-10-24T12:00:00Z",
	}
	sealed, err := seal.Seal(seal.InstallKey{KeyID: pub.KeyID, PublicKey: pub.PublicKey}, pub.Fingerprint, ref, canary, nil)
	if err != nil {
		t.Fatal(err)
	}
	install := &authz.CollectorRequest{Contract: authz.ContractID, Kind: authz.KindCredentialInstall, RequestID: "req-install",
		OnBehalfOf: admin, PolicyVersion: 3, CredentialInstall: &authz.CredentialInstallBody{Ref: ref, Sealed: sealed}}
	// Unsigned, it is refused (C7 0.4); signed by the pinned admin key, it
	// is installed.
	resp, err := client.Do(ctx, install)
	if err != nil || resp.Reply.Refusal == nil || resp.Reply.Refusal.Code != authz.RefuseAdminUnverified || resp.Reply.Refusal.Check != authz.AdminCheckEnvelope {
		t.Fatalf("unsigned install: %+v %v", resp.Reply, err)
	}
	resp, err = client.Do(ctx, adminSigned(t, install, pub.KeyID))
	if err != nil || !resp.Reply.Accepted() {
		t.Fatalf("install: %+v %v", resp.Reply, err)
	}
	run := &authz.CollectorRequest{Contract: authz.ContractID, Kind: authz.KindRun, RequestID: "req-run",
		OnBehalfOf:    authz.Principal{Type: authz.PrincipalSchedule, ID: "sch-ser-751-feeder-3"},
		PolicyVersion: 3, Run: &authz.RunBody{AssetID: ref.AssetID, OperationID: "sel.ser.read_all", Params: map[string]string{}, CredentialRef: ref.ID, RegisterVersion: 2}}
	// A fresh install opens no session to any asset for the longest floor
	// (the fresh-state floor), so the run is refused before the hosted
	// SEL-751 adapter. The adapter's runs are tested in the collector
	// package (runner_sel751_test.go).
	resp, err = client.Do(ctx, run)
	if err != nil || resp.Reply.Refusal == nil || resp.Reply.Refusal.Code != authz.RefuseRateLimited {
		t.Fatalf("level 1 run on a fresh install: %+v %v", resp.Reply, err)
	}
	if err := r.stop(); err != nil {
		t.Fatal(err)
	}

	// Every byte the collector wrote.
	all := logs.Bytes()
	filepath.Walk(data, func(p string, fi os.FileInfo, err error) error {
		if err == nil && fi.Mode().IsRegular() {
			b, _ := os.ReadFile(p)
			all = append(all, b...)
		}
		return nil
	})
	if bytes.Contains(all, canary) {
		t.Fatal("the secret appears in a file or log the collector wrote")
	}
	// A restart opens the same stores, with no marker.
	r2, err := start(data, log)
	if err != nil {
		t.Fatalf("restart: %v", err)
	}
	r2.stop()
	_ = asset.Contract
}

// The node checks install-key.json before every request (D2-15), so a
// collector that cannot publish it does not start.
func TestStartNeedsPublicDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the Windows service path needs the installer's WER exclusion and the service accounts (PC run)")
	}
	data := t.TempDir()
	l := newLayout(data)
	sockDir := filepath.Join(t.TempDir(), "run")
	for _, d := range []string{filepath.Dir(l.state), filepath.Dir(l.credentials), sockDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(l.config, marshal(t, testConfig(t, filepath.Join(sockDir, "collector.sock"))), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(l.provision, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := start(data, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err == nil {
		r.stop()
		t.Fatal("started without the public directory")
	}
	if !strings.Contains(err.Error(), "install key not published") {
		t.Fatalf("refused for another reason: %v", err)
	}
}

func FuzzParseConfig(f *testing.F) {
	f.Add(marshal(f, testConfig(f, "/run/otsec/collector.sock")))
	f.Add([]byte(`{"format":"otsec.collector-config/0.1"}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		c, err := parseConfig(b)
		if err == nil && (c.NodeID == "" || c.PolicyVersion == 0) {
			t.Fatalf("accepted an incomplete config: %+v", c)
		}
	})
}
