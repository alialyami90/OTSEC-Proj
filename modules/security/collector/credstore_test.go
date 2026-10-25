package collector

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/authz"
	"otsec.local/otsec/contracts/register"
	"otsec.local/otsec/modules/security/seal"
)

// Every secret here is a test value (D2-5), never a device password.
var (
	canary      = []byte("Canary-7f3K")
	otherSecret = []byte("Other-9q2Lx")
)

const (
	testNode    = "site-a-node1"
	assetA      = "6f1c2d3e-4a5b-4c6d-8e7f-001122334455"
	assetB      = "6f1c2d3e-4a5b-4c6d-8e7f-001122334466"
	telnetEP    = "telnet0"
	sshEP       = "ssh0"
	testAdminID = "admin@site-a"
)

var testAdmin = authz.Principal{Type: authz.PrincipalHuman, ID: testAdminID}

func loadRegister(t testing.TB) *register.Package {
	t.Helper()
	b, err := os.ReadFile("testdata/register-sel-751.json")
	if err != nil {
		t.Fatal(err)
	}
	p, err := register.Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func enrolled(id string) *asset.Asset {
	return &asset.Asset{
		Schema:  asset.Contract,
		AssetID: id,
		NodeID:  testNode,
		Endpoints: []asset.Endpoint{
			{
				ID: telnetEP, Transport: asset.Telnet, Host: "127.0.0.1", Port: 2323, Target: asset.Simulated,
				DownstreamSecurity: asset.DownstreamSecurity{
					Level:           asset.PlaintextUnauthenticated,
					Acknowledgement: &asset.Acknowledgement{By: testAdminID, At: "2026-10-24T10:00:00Z", Reason: "lab slice (ADR-0005)", Scope: asset.LabOnly},
				},
			},
			{
				ID: sshEP, Transport: asset.SSH, Host: "127.0.0.1", Port: 2222, Target: asset.Simulated,
				DownstreamSecurity: asset.DownstreamSecurity{Level: asset.EncryptedAuthenticated},
			},
		},
	}
}

func telnetRef(id, assetID string, version uint32) authz.CredentialRef {
	return authz.CredentialRef{
		ID: id, AssetID: assetID, NodeID: testNode, EndpointID: telnetEP,
		Transport: authz.TransportTelnet, Purpose: authz.PurposeCollectReadOnly, AccessLevel: "1",
		DownstreamSecurity: authz.DownstreamPlaintext, PlaintextScope: authz.PlaintextLabOnly,
		Version: version, CreatedBy: testAdmin, CreatedAt: "2026-10-24T12:00:00Z",
	}
}

func sshRef(id, assetID string, version uint32) authz.CredentialRef {
	r := telnetRef(id, assetID, version)
	r.EndpointID, r.Transport, r.DownstreamSecurity, r.PlaintextScope = sshEP, authz.TransportSSH, authz.DownstreamEncryptedAuthenticated, ""
	return r
}

func telnetUse(assetID string) authz.Use {
	return authz.Use{NodeID: testNode, AssetID: assetID, EndpointID: telnetEP, Transport: authz.TransportTelnet, AckScope: authz.PlaintextLabOnly, AccessLevel: "1"}
}

type credFixture struct {
	path  string
	store *CredStore
	gens  *State // where the store's generation is recorded
	clock *clock
	pkg   *register.Package
}

func newCredStore(t *testing.T) *credFixture {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "credentials.json")
	c := &clock{t: time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)}
	if err := InitState(filepath.Join(dir, "state.json"), c.t.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	gens, err := OpenState(filepath.Join(dir, "state.json"), c.now)
	if err != nil {
		t.Fatal(err)
	}
	if err := InitCredStore(path, testNode, c.now); err != nil {
		t.Fatal(err)
	}
	s, err := OpenCredStore(path, CredStoreConfig{NodeID: testNode, Now: c.now, Generations: gens})
	if err != nil {
		t.Fatal(err)
	}
	return &credFixture{path: path, store: s, gens: gens, clock: c, pkg: loadRegister(t)}
}

// memGens is a GenerationLog for tests that open a store without a fixture.
type memGens struct{ g uint64 }

func (m *memGens) CredGeneration() uint64 { return m.g }
func (m *memGens) RaiseCredGeneration(g uint64) error {
	m.g = max(m.g, g)
	return nil
}

// sealFor seals secret to the fixture's collector, pinning the fingerprint
// the collector reports, as the admin's client does after commissioning.
func (f *credFixture) sealFor(t *testing.T, ref authz.CredentialRef, secret []byte) authz.SealedSecret {
	t.Helper()
	s, err := seal.Seal(f.store.InstallKey(), f.store.Fingerprint(), ref, secret, nil)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func (f *credFixture) install(t *testing.T, ref authz.CredentialRef, secret []byte) (InstallResult, error) {
	t.Helper()
	return f.store.Install(authz.CredentialInstallBody{Ref: ref, Sealed: f.sealFor(t, ref, secret)},
		InstallTarget{Asset: enrolled(ref.AssetID), Register: f.pkg})
}

func codeOf(err error) authz.RefusalCode {
	var r *authz.Refusal
	if errors.As(err, &r) {
		return r.Code
	}
	if errors.Is(err, ErrStateUnavailable) {
		return authz.RefuseStateUnavailable
	}
	return ""
}

// secretOf runs one Use on a handle and returns a copy of what it saw.
func secretOf(t *testing.T, h *SecretHandle) []byte {
	t.Helper()
	var got []byte
	if err := h.Use(func(b []byte) error { got = append([]byte(nil), b...); return nil }); err != nil {
		t.Fatal(err)
	}
	return got
}

func TestCredStoreInitAndOpen(t *testing.T) {
	f := newCredStore(t)
	pub, err := f.store.InstallKey().PublicKeyBytes()
	if err != nil {
		t.Fatal(err)
	}
	if f.store.Fingerprint() != seal.Fingerprint(pub) {
		t.Fatal("fingerprint does not belong to the published key")
	}
	if err := InitCredStore(f.path, testNode, nil); err == nil {
		t.Fatal("InitCredStore overwrote an existing store")
	}
	if err := InitCredStore(filepath.Join(t.TempDir(), "x.json"), "Not A Node", nil); err == nil {
		t.Fatal("invalid node id accepted")
	}
	// A reopened store has the same install key.
	again, err := OpenCredStore(f.path, CredStoreConfig{NodeID: testNode, Generations: f.gens})
	if err != nil {
		t.Fatal(err)
	}
	if again.InstallKey() != f.store.InstallKey() {
		t.Fatal("install key changed on reopen")
	}
	if fi, err := os.Stat(f.path); err == nil && fi.Mode().Perm()&0o077 != 0 && !isWindows() {
		t.Fatalf("store mode %v", fi.Mode().Perm())
	}
}

// Any doubt about the store file is collector_state_unavailable, never an
// empty or fresh store.
func TestOpenCredStoreFailsClosed(t *testing.T) {
	f := newCredStore(t)
	if _, err := f.install(t, telnetRef("cred_slice0001", assetA, 1), canary); err != nil {
		t.Fatal(err)
	}
	good, err := os.ReadFile(f.path)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(good, &doc); err != nil {
		t.Fatal(err)
	}
	edit := func(m func(map[string]any)) []byte {
		var d map[string]any
		json.Unmarshal(good, &d)
		m(d)
		b, _ := json.Marshal(d)
		return b
	}
	entry := func(d map[string]any) map[string]any { return d["entries"].([]any)[0].(map[string]any) }
	cases := map[string][]byte{
		"empty":            {},
		"truncated":        good[:len(good)/2],
		"trailing data":    append(append([]byte(nil), good...), []byte(" {}")...),
		"unknown field":    edit(func(d map[string]any) { d["extra"] = 1 }),
		"format":           edit(func(d map[string]any) { d["format"] = "otsec.collector-credentials/0.2" }),
		"node":             edit(func(d map[string]any) { d["node_id"] = "site-a-node2" }),
		"protection":       edit(func(d map[string]any) { d["key_protection"] = "plain" }),
		"store key":        edit(func(d map[string]any) { d["store_key"] = b64(make([]byte, storeKeyLen)) }),
		"no entries":       edit(func(d map[string]any) { delete(d, "entries") }),
		"install key id":   edit(func(d map[string]any) { d["install_key"].(map[string]any)["key_id"] = "x25519-0000000000000000" }),
		"install pub":      edit(func(d map[string]any) { d["install_key"].(map[string]any)["public_key"] = b64(make([]byte, 32)) }),
		"entry other node": edit(func(d map[string]any) { entry(d)["ref"].(map[string]any)["node_id"] = "site-a-node2" }),
		"status mismatch":  edit(func(d map[string]any) { entry(d)["status"].(map[string]any)["version"] = 2 }),
		"revoked with secret": edit(func(d map[string]any) {
			entry(d)["status"].(map[string]any)["state"] = "revoked"
			entry(d)["status"].(map[string]any)["reason"] = "operator"
		}),
		"active without secret": edit(func(d map[string]any) { delete(entry(d), "ciphertext") }),
		"duplicate version": edit(func(d map[string]any) {
			d["entries"] = append(d["entries"].([]any), d["entries"].([]any)[0])
		}),
	}
	for name, b := range cases {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "credentials.json")
			if err := os.WriteFile(p, b, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := OpenCredStore(p, CredStoreConfig{NodeID: testNode, Generations: &memGens{}}); !errors.Is(err, ErrStateUnavailable) {
				t.Fatalf("opened: %v", err)
			}
		})
	}
	if _, err := OpenCredStore(f.path, CredStoreConfig{NodeID: "site-a-node2", Generations: f.gens}); !errors.Is(err, ErrStateUnavailable) {
		t.Fatal("store opened for another node")
	}
	if _, err := OpenCredStore(filepath.Join(t.TempDir(), "missing.json"), CredStoreConfig{NodeID: testNode, Generations: f.gens}); !errors.Is(err, ErrStateUnavailable) {
		t.Fatal("missing store opened")
	}
}

func TestInstallAndAcquire(t *testing.T) {
	f := newCredStore(t)
	ref := telnetRef("cred_slice0001", assetA, 1)
	res, err := f.install(t, ref, canary)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status.State != authz.CredentialActive || res.Replaced != nil || res.SharedWith != 0 {
		t.Fatalf("result %+v", res)
	}
	if err := res.Status.Validate(); err != nil {
		t.Fatal(err)
	}
	h, got, err := f.store.Acquire(ref.ID, telnetUse(assetA), f.pkg)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	if got != ref {
		t.Fatalf("acquired %+v", got)
	}
	if !bytes.Equal(secretOf(t, h), canary) {
		t.Fatal("acquired another secret")
	}
	// The slot opens once per session (C7-A6-2).
	called := false
	if err := h.Use(func([]byte) error { called = true; return nil }); !errors.Is(err, ErrSecretUsed) || called {
		t.Fatalf("second Use: %v, called %v", err, called)
	}
	rx := append(append([]byte("Password: ?"), canary...), append([]byte("\r\n"), canary...)...)
	spans := h.EchoSpans(rx)
	if len(spans) != 2 || spans[0] != [2]int{11, 11 + len(canary)} || spans[1] != [2]int{13 + len(canary), 13 + 2*len(canary)} {
		t.Fatalf("echo spans %v", spans)
	}
	h.Close()
	if h.EchoSpans(rx) != nil {
		t.Fatal("closed handle still finds the secret")
	}
	if err := h.Use(func([]byte) error { return nil }); !errors.Is(err, ErrSecretClosed) {
		t.Fatalf("Use after Close: %v", err)
	}
	// The store survives a restart.
	again, err := OpenCredStore(f.path, CredStoreConfig{NodeID: testNode, Generations: f.gens})
	if err != nil {
		t.Fatal(err)
	}
	h2, _, err := again.Acquire(ref.ID, telnetUse(assetA), f.pkg)
	if err != nil {
		t.Fatal(err)
	}
	defer h2.Close()
	if !bytes.Equal(secretOf(t, h2), canary) {
		t.Fatal("reopened store gave another secret")
	}
}

// A reply cut inside an echo still has the cut part redacted, and the
// prompts a short partial match could touch are never covered (A3 on #99).
func TestEchoSpansPartial(t *testing.T) {
	h := &SecretHandle{b: []byte("Abc123xyz")}
	cases := []struct {
		rx   string
		want [][2]int
	}{
		{"\r\nAbc12", [][2]int{{2, 7}}},
		{"Abc123xyz\r\nAbc", [][2]int{{0, 9}, {11, 14}}},
		{"Abc123xyz", [][2]int{{0, 9}}},
		{"\r\nAb", nil},                    // under three bytes: not redacted
		{"xyzAbc123xy", [][2]int{{3, 11}}}, // the longest leading part
		{"Abc123xyzAbc123xyz", [][2]int{{0, 9}, {9, 18}}},
		{"Abc1", [][2]int{{0, 4}}},
		{"\r\n=>", nil},
	}
	for _, c := range cases {
		got := h.EchoSpans([]byte(c.rx))
		if fmt.Sprint(got) != fmt.Sprint(c.want) {
			t.Errorf("%q: spans %v, want %v", c.rx, got, c.want)
		}
	}
	// A secret that starts like a prompt still leaves a prompt alone: the
	// prompt's leading CR or LF is not in the secret.
	h = &SecretHandle{b: []byte("=>x9")}
	if got := h.EchoSpans([]byte("SER\r\n=>")); got != nil {
		t.Errorf("prompt redacted: %v", got)
	}
}

func TestUseCannotChangeStoredSecret(t *testing.T) {
	h := &SecretHandle{b: append([]byte(nil), canary...)}
	h.Use(func(b []byte) error { b[0] = 'X'; return nil })
	if len(h.EchoSpans(canary)) != 1 {
		t.Fatal("Use changed the stored bytes")
	}
}

// The install checks, in order (design section 4). Each refusal keeps
// nothing, and no refusal names the secret.
func TestInstallRefusals(t *testing.T) {
	f := newCredStore(t)
	other := newCredStore(t)
	base := telnetRef("cred_slice0001", assetA, 1)
	target := InstallTarget{Asset: enrolled(assetA), Register: f.pkg}

	type tc struct {
		name   string
		ref    authz.CredentialRef
		sealed func(ref authz.CredentialRef) authz.SealedSecret // nil: seal canary for ref
		target InstallTarget
		want   authz.RefusalCode
	}
	with := func(m func(*authz.CredentialRef)) authz.CredentialRef { r := base; m(&r); return r }
	withTarget := func(m func(*InstallTarget)) InstallTarget {
		t2 := InstallTarget{Asset: enrolled(assetA), Register: f.pkg}
		m(&t2)
		return t2
	}
	sealSecret := func(secret string) func(authz.CredentialRef) authz.SealedSecret {
		return func(ref authz.CredentialRef) authz.SealedSecret { return f.sealFor(t, ref, []byte(secret)) }
	}
	cases := []tc{
		{"invalid ref", with(func(r *authz.CredentialRef) { r.Version = 0 }), func(authz.CredentialRef) authz.SealedSecret { return f.sealFor(t, base, canary) }, target, authz.RefuseInvalid},
		{"other node", with(func(r *authz.CredentialRef) { r.NodeID = "site-a-node2" }), nil, target, authz.RefuseCredentialMismatch},
		{"not enrolled", base, nil, withTarget(func(t *InstallTarget) { t.Asset = nil }), authz.RefuseAssetNotEnrolled},
		{"another asset", base, nil, withTarget(func(t *InstallTarget) { t.Asset = enrolled(assetB) }), authz.RefuseAssetNotEnrolled},
		{"asset on another node", base, nil, withTarget(func(t *InstallTarget) { t.Asset.NodeID = "site-a-node2" }), authz.RefuseAssetNotEnrolled},
		{"no register", base, nil, withTarget(func(t *InstallTarget) { t.Register = nil }), authz.RefuseRegisterUnverified},
		{"level 2", with(func(r *authz.CredentialRef) { r.AccessLevel = "2" }), nil, target, authz.RefuseCredentialMismatch},
		{"level 2AC", with(func(r *authz.CredentialRef) { r.AccessLevel = "2AC" }), nil, target, authz.RefuseCredentialMismatch},
		{"no such endpoint", with(func(r *authz.CredentialRef) { r.EndpointID = "telnet9" }), nil, target, authz.RefuseCredentialMismatch},
		{"endpoint transport", base, nil, withTarget(func(t *InstallTarget) { t.Asset.Endpoints[0].Transport = asset.SSH }), authz.RefuseCredentialMismatch},
		{"endpoint label", base, nil, withTarget(func(t *InstallTarget) { t.Asset.Endpoints[0].DownstreamSecurity.Level = asset.EncryptedWeak }), authz.RefuseCredentialMismatch},
		{"no acknowledgement", base, nil, withTarget(func(t *InstallTarget) { t.Asset.Endpoints[0].DownstreamSecurity.Acknowledgement = nil }), authz.RefuseCredentialMismatch},
		{"first version 2", with(func(r *authz.CredentialRef) { r.Version = 2 }), nil, target, authz.RefuseInvalid},
		{"sealed to another collector", base, func(ref authz.CredentialRef) authz.SealedSecret { return other.sealFor(t, ref, canary) }, target, authz.RefuseCredentialMismatch},
		{"sealed for another reference", base, func(authz.CredentialRef) authz.SealedSecret {
			return f.sealFor(t, telnetRef("cred_slice0002", assetA, 1), canary)
		}, target, authz.RefuseSecretRejected},
		{"sealed for another version", base, func(authz.CredentialRef) authz.SealedSecret {
			return f.sealFor(t, telnetRef("cred_slice0001", assetA, 2), canary)
		}, target, authz.RefuseSecretRejected},
		// Secrets the register recognises (A6's re-check of #75; C7-A6-3).
		{"secret SER C", base, sealSecret("SER C"), target, authz.RefuseSecretRejected},
		{"secret ACC", base, sealSecret("ACC"), target, authz.RefuseSecretRejected},
		{"secret acc lower case", base, sealSecret("acc"), target, authz.RefuseSecretRejected},
		{"secret QUIT", base, sealSecret("QUIT"), target, authz.RefuseSecretRejected},
		{"secret quiet123", base, sealSecret("quiet123"), target, authz.RefuseSecretRejected},
		{"secret 2AC", base, sealSecret("2AC"), target, authz.RefuseSecretRejected},
		{"secret with space", base, sealSecret("Abc def1"), target, authz.RefuseSecretRejected},
		{"secret too long", base, sealSecret("Abcdefghijk12"), target, authz.RefuseSecretRejected},
		{"secret with CR", base, sealSecret("Abc\rdef1"), target, authz.RefuseSecretRejected},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sealed := c.sealed
			if sealed == nil {
				sealed = func(ref authz.CredentialRef) authz.SealedSecret { return f.sealFor(t, ref, canary) }
			}
			before, _ := os.ReadFile(f.path)
			_, err := f.store.Install(authz.CredentialInstallBody{Ref: c.ref, Sealed: sealed(c.ref)}, c.target)
			if got := codeOf(err); got != c.want {
				t.Fatalf("got %q (%v), want %q", got, err, c.want)
			}
			if strings.Contains(err.Error(), string(canary)) {
				t.Fatalf("refusal names the secret: %v", err)
			}
			after, _ := os.ReadFile(f.path)
			if !bytes.Equal(before, after) || f.store.Status(c.ref.ID) != nil {
				t.Fatal("a refused install changed the store")
			}
		})
	}
}

// The register's own lines are in the refusal detail only as the register
// writes them; the secret itself never is, whatever it is.
func TestRefusalNeverEchoesSecret(t *testing.T) {
	f := newCredStore(t)
	for _, s := range []string{"SER C", "ACC", "quiet123", "close!", "Abcdefghijk12", "Abc def1"} {
		ref := telnetRef("cred_echo00001", assetA, 1)
		_, err := f.store.Install(authz.CredentialInstallBody{Ref: ref, Sealed: f.sealFor(t, ref, []byte(s))}, InstallTarget{Asset: enrolled(assetA), Register: f.pkg})
		if err == nil {
			t.Fatalf("%q accepted", s)
		}
		var r *authz.Refusal
		if !errors.As(err, &r) {
			t.Fatalf("%q: %v", s, err)
		}
		if strings.Contains(r.Detail, s) {
			t.Fatalf("detail for %q names it: %s", s, r.Detail)
		}
	}
}

func TestRotation(t *testing.T) {
	f := newCredStore(t)
	v1 := telnetRef("cred_slice0001", assetA, 1)
	if _, err := f.install(t, v1, canary); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(f.path)
	var doc credDoc
	json.Unmarshal(before, &doc)
	v1Cipher := doc.Entries[0].Ciphertext

	v2 := telnetRef("cred_slice0001", assetA, 2)
	res, err := f.install(t, v2, otherSecret)
	if err != nil {
		t.Fatal(err)
	}
	if res.Replaced == nil || res.Replaced.Version != 1 || res.Replaced.State != authz.CredentialRevoked || res.Replaced.Reason != string(authz.RevokeRotated) {
		t.Fatalf("replaced %+v", res.Replaced)
	}
	after, _ := os.ReadFile(f.path)
	if bytes.Contains(after, []byte(v1Cipher)) {
		t.Fatal("rotated version's ciphertext is still in the store")
	}
	h, got, err := f.store.Acquire(v1.ID, telnetUse(assetA), f.pkg)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	if got.Version != 2 || !bytes.Equal(secretOf(t, h), otherSecret) {
		t.Fatal("acquire did not use the new version")
	}
	for name, c := range map[string]struct {
		ref  authz.CredentialRef
		want authz.RefusalCode
	}{
		"skipped version": {telnetRef(v1.ID, assetA, 4), authz.RefuseInvalid},
		"old version":     {telnetRef(v1.ID, assetA, 2), authz.RefuseInvalid},
		"other asset":     {telnetRef(v1.ID, assetB, 3), authz.RefuseCredentialMismatch},
		"other endpoint":  {sshRef(v1.ID, assetA, 3), authz.RefuseCredentialMismatch},
	} {
		if _, err := f.install(t, c.ref, canary); codeOf(err) != c.want {
			t.Errorf("%s: %v, want %s", name, err, c.want)
		}
	}
}

// T-6 and the reuse rule (design section 6).
func TestReuseRule(t *testing.T) {
	f := newCredStore(t)
	if _, err := f.install(t, telnetRef("cred_labaaaa1", assetA, 1), canary); err != nil {
		t.Fatal(err)
	}
	res, err := f.install(t, telnetRef("cred_labbbbb1", assetB, 1), canary)
	if err != nil {
		t.Fatal(err)
	}
	if res.SharedWith != 1 {
		t.Fatalf("shared with %d, want 1", res.SharedWith)
	}
	// The same secret without the lab-only scope is refused.
	if _, err := f.install(t, sshRef("cred_prodaaa1", assetA, 1), canary); codeOf(err) != authz.RefuseSecretRejected {
		t.Fatalf("lab-only secret reused as non-lab: %v", err)
	}
	// And the reverse: a non-lab secret cannot become a lab-only one.
	if _, err := f.install(t, sshRef("cred_prodaaa1", assetA, 1), otherSecret); err != nil {
		t.Fatal(err)
	}
	if _, err := f.install(t, telnetRef("cred_labcccc1", assetB, 1), otherSecret); codeOf(err) != authz.RefuseSecretRejected {
		t.Fatalf("non-lab secret reused as lab-only: %v", err)
	}
	// A revoked credential no longer counts.
	if _, err := f.store.Revoke(authz.CredentialRevokeBody{RefID: "cred_prodaaa1", Reason: authz.RevokeOperator}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.install(t, telnetRef("cred_labcccc1", assetB, 1), otherSecret); err != nil {
		t.Fatalf("revoked secret still blocks: %v", err)
	}
}

func TestRevoke(t *testing.T) {
	f := newCredStore(t)
	ref := telnetRef("cred_slice0001", assetA, 1)
	f.install(t, ref, canary)
	f.install(t, telnetRef(ref.ID, assetA, 2), otherSecret)
	changed, err := f.store.Revoke(authz.CredentialRevokeBody{RefID: ref.ID, Reason: authz.RevokeCompromised})
	if err != nil {
		t.Fatal(err)
	}
	if len(changed) != 1 || changed[0].Version != 2 || changed[0].Reason != string(authz.RevokeCompromised) {
		t.Fatalf("changed %+v", changed)
	}
	for _, st := range f.store.Status(ref.ID) {
		if st.State != authz.CredentialRevoked {
			t.Fatalf("version %d is %s", st.Version, st.State)
		}
	}
	var doc credDoc
	b, _ := os.ReadFile(f.path)
	json.Unmarshal(b, &doc)
	for _, e := range doc.Entries {
		if e.Ciphertext != "" || e.Nonce != "" || e.ReuseTag != "" {
			t.Fatal("revoked entry keeps secret material")
		}
	}
	if _, _, err := f.store.Acquire(ref.ID, telnetUse(assetA), f.pkg); codeOf(err) != authz.RefuseCredentialUnusable {
		t.Fatalf("acquire after revoke: %v", err)
	}
	if _, err := f.install(t, telnetRef(ref.ID, assetA, 3), canary); codeOf(err) != authz.RefuseCredentialUnusable {
		t.Fatalf("install on a revoked reference: %v", err)
	}
	if _, err := f.store.Revoke(authz.CredentialRevokeBody{RefID: ref.ID, Reason: authz.RevokeOperator}); codeOf(err) != authz.RefuseCredentialUnusable {
		t.Fatalf("second revoke: %v", err)
	}
	if _, err := f.store.Revoke(authz.CredentialRevokeBody{RefID: "cred_unknown01", Reason: authz.RevokeOperator}); codeOf(err) != authz.RefuseCredentialUnusable {
		t.Fatalf("revoke of unknown: %v", err)
	}
}

func TestSuspendAndClear(t *testing.T) {
	f := newCredStore(t)
	ref := telnetRef("cred_slice0001", assetA, 1)
	f.install(t, ref, canary)

	st, changed, err := f.store.Suspend(ref.ID, 1, authz.SuspendAuthFailed)
	if err != nil || !changed || st.State != authz.CredentialSuspended || st.Reason != string(authz.SuspendAuthFailed) {
		t.Fatalf("suspend: %+v %v %v", st, changed, err)
	}
	if _, _, err := f.store.Acquire(ref.ID, telnetUse(assetA), f.pkg); codeOf(err) != authz.RefuseCredentialUnusable {
		t.Fatalf("acquire while suspended: %v", err)
	}
	// A second fault keeps the first reason.
	if st, changed, _ := f.store.Suspend(ref.ID, 1, authz.SuspendUnexpectedLevel); changed || st.Reason != string(authz.SuspendAuthFailed) {
		t.Fatalf("second suspension replaced the reason: %+v", st)
	}
	if _, err := f.store.ClearSuspension(authz.CredentialClearSuspBody{RefID: ref.ID, Version: 2}); codeOf(err) != authz.RefuseInvalid {
		t.Fatalf("clear of another version: %v", err)
	}
	st, err = f.store.ClearSuspension(authz.CredentialClearSuspBody{RefID: ref.ID, Version: 1})
	if err != nil || st.State != authz.CredentialActive {
		t.Fatalf("clear: %+v %v", st, err)
	}
	if _, err := f.store.ClearSuspension(authz.CredentialClearSuspBody{RefID: ref.ID, Version: 1}); codeOf(err) != authz.RefuseInvalid {
		t.Fatalf("clear of an active credential: %v", err)
	}

	// identity-mismatch replaces another reason, and only a new version
	// clears it (T-7).
	f.store.Suspend(ref.ID, 1, authz.SuspendOperator)
	if st, changed, _ := f.store.Suspend(ref.ID, 1, authz.SuspendIdentityMismatch); !changed || st.Reason != string(authz.SuspendIdentityMismatch) {
		t.Fatalf("identity-mismatch did not replace the reason: %+v", st)
	}
	if _, err := f.store.ClearSuspension(authz.CredentialClearSuspBody{RefID: ref.ID, Version: 1}); codeOf(err) != authz.RefuseCredentialUnusable {
		t.Fatalf("identity-mismatch cleared in place: %v", err)
	}
	if _, err := f.install(t, telnetRef(ref.ID, assetA, 2), otherSecret); err != nil {
		t.Fatalf("rotation after identity-mismatch: %v", err)
	}
	if _, _, err := f.store.Suspend(ref.ID, 1, authz.SuspendAuthFailed); err == nil {
		t.Fatal("suspended a version that is not current")
	}
	h, _, err := f.store.Acquire(ref.ID, telnetUse(assetA), f.pkg)
	if err != nil {
		t.Fatalf("new version unusable: %v", err)
	}
	h.Close()
}

func TestAcquireChecksBinding(t *testing.T) {
	f := newCredStore(t)
	ref := telnetRef("cred_slice0001", assetA, 1)
	f.install(t, ref, canary)
	for name, m := range map[string]func(*authz.Use){
		"node":      func(u *authz.Use) { u.NodeID = "site-a-node2" },
		"asset":     func(u *authz.Use) { u.AssetID = assetB },
		"endpoint":  func(u *authz.Use) { u.EndpointID = sshEP },
		"transport": func(u *authz.Use) { u.Transport = authz.TransportSSH },
		"level":     func(u *authz.Use) { u.AccessLevel = "2" },
		"ack scope": func(u *authz.Use) { u.AckScope = "" },
	} {
		u := telnetUse(assetA)
		m(&u)
		if _, _, err := f.store.Acquire(ref.ID, u, f.pkg); codeOf(err) != authz.RefuseCredentialMismatch {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, _, err := f.store.Acquire(ref.ID, telnetUse(assetA), nil); codeOf(err) != authz.RefuseRegisterUnverified {
		t.Errorf("no register: %v", err)
	}
	if _, _, err := f.store.Acquire("cred_unknown01", telnetUse(assetA), f.pkg); codeOf(err) != authz.RefuseCredentialUnusable {
		t.Errorf("unknown: %v", err)
	}
}

// T-4: a stored ciphertext copied onto another reference does not decrypt,
// and the run is refused with credential_unusable.
func TestStoredCiphertextBoundToReference(t *testing.T) {
	f := newCredStore(t)
	f.install(t, telnetRef("cred_aaaaaaa1", assetA, 1), canary)
	f.install(t, telnetRef("cred_bbbbbbb1", assetB, 1), otherSecret)
	var doc credDoc
	b, _ := os.ReadFile(f.path)
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	doc.Entries[1].Nonce, doc.Entries[1].Ciphertext = doc.Entries[0].Nonce, doc.Entries[0].Ciphertext
	b, _ = json.Marshal(doc)
	if err := os.WriteFile(f.path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := OpenCredStore(f.path, CredStoreConfig{NodeID: testNode, Generations: f.gens})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Acquire("cred_bbbbbbb1", telnetUse(assetB), f.pkg); codeOf(err) != authz.RefuseCredentialUnusable {
		t.Fatalf("copied ciphertext: %v", err)
	}
	h, _, err := s.Acquire("cred_aaaaaaa1", telnetUse(assetA), f.pkg)
	if err != nil {
		t.Fatalf("original: %v", err)
	}
	h.Close()
}

// Part of T-5 and T-8 at the store layer: the secret is in no byte the
// store writes and in nothing it returns.
func TestStoreWritesNoSecret(t *testing.T) {
	f := newCredStore(t)
	res1, _ := f.install(t, telnetRef("cred_aaaaaaa1", assetA, 1), canary)
	res2, _ := f.install(t, telnetRef("cred_bbbbbbb1", assetB, 1), canary)
	f.store.Suspend("cred_aaaaaaa1", 1, authz.SuspendAuthFailed)
	f.install(t, telnetRef("cred_bbbbbbb1", assetB, 2), otherSecret)
	revoked, _ := f.store.Revoke(authz.CredentialRevokeBody{RefID: "cred_bbbbbbb1", Reason: authz.RevokeOperator})
	out, _ := json.Marshal([]any{res1, res2, revoked, f.store.Status("cred_aaaaaaa1"), f.store.InstallKey(), f.store.Fingerprint()})
	files, _ := filepath.Glob(filepath.Join(filepath.Dir(f.path), "*"))
	for _, p := range files {
		b, _ := os.ReadFile(p)
		out = append(out, b...)
	}
	for _, s := range [][]byte{canary, otherSecret} {
		if bytes.Contains(out, s) {
			t.Fatalf("%q found in what the store wrote or returned", s)
		}
	}
}

func TestBrokenCredStoreFailsClosed(t *testing.T) {
	f := newCredStore(t)
	ref := telnetRef("cred_slice0001", assetA, 1)
	f.install(t, ref, canary)
	if err := os.Mkdir(f.path+".tmp", 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := f.install(t, telnetRef("cred_bbbbbbb1", assetB, 1), otherSecret); !errors.Is(err, ErrStateUnavailable) {
		t.Fatalf("failed write: %v", err)
	}
	os.Remove(f.path + ".tmp")
	if _, _, err := f.store.Acquire(ref.ID, telnetUse(assetA), f.pkg); !errors.Is(err, ErrStateUnavailable) {
		t.Fatalf("broken store still serves: %v", err)
	}
	if _, err := f.store.Revoke(authz.CredentialRevokeBody{RefID: ref.ID, Reason: authz.RevokeOperator}); !errors.Is(err, ErrStateUnavailable) {
		t.Fatalf("broken store still revokes: %v", err)
	}
	// The file still holds the last good state.
	s, err := OpenCredStore(f.path, CredStoreConfig{NodeID: testNode, Generations: f.gens})
	if err != nil {
		t.Fatal(err)
	}
	if s.Status("cred_bbbbbbb1") != nil || len(s.Status(ref.ID)) != 1 {
		t.Fatal("the failed write reached the file")
	}
}

// A6 on #90: removal is logical, so a restored older copy of the store
// would bring a revoked secret back. The generation recorded in the State
// refuses it, after a restart too.
func TestRestoredStoreRefused(t *testing.T) {
	f := newCredStore(t)
	ref := telnetRef("cred_slice0001", assetA, 1)
	f.install(t, ref, canary)
	backup, err := os.ReadFile(f.path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.Revoke(authz.CredentialRevokeBody{RefID: ref.ID, Reason: authz.RevokeOperator}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.path, backup, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenCredStore(f.path, CredStoreConfig{NodeID: testNode, Generations: f.gens}); !errors.Is(err, ErrStateUnavailable) {
		t.Fatalf("restored copy opened: %v", err)
	}
	gens, err := OpenState(f.gens.path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenCredStore(f.path, CredStoreConfig{NodeID: testNode, Generations: gens}); !errors.Is(err, ErrStateUnavailable) {
		t.Fatalf("restored copy opened after a restart: %v", err)
	}
	// Without a record the store does not open at all.
	if _, err := OpenCredStore(f.path, CredStoreConfig{NodeID: testNode}); !errors.Is(err, ErrStateUnavailable) {
		t.Fatalf("opened without a generation record: %v", err)
	}
}

// A store ahead of its record, as after a crash between the two writes,
// opens and the record catches up; every write moves both forward.
func TestStoreAheadOfRecord(t *testing.T) {
	f := newCredStore(t)
	g := f.gens.CredGeneration()
	f.install(t, telnetRef("cred_slice0001", assetA, 1), canary)
	if f.gens.CredGeneration() != g+1 || f.store.doc.Generation != g+1 {
		t.Fatalf("after a write: record %d, store %d, want %d", f.gens.CredGeneration(), f.store.doc.Generation, g+1)
	}
	behind := &memGens{g: g}
	if _, err := OpenCredStore(f.path, CredStoreConfig{NodeID: testNode, Generations: behind}); err != nil {
		t.Fatal(err)
	}
	if behind.g != g+1 {
		t.Fatalf("record not raised: %d", behind.g)
	}
}

func FuzzOpenCredStore(f *testing.F) {
	dir := f.TempDir()
	path := filepath.Join(dir, "seed.json")
	if err := InitCredStore(path, testNode, nil); err != nil {
		f.Fatal(err)
	}
	seed, _ := os.ReadFile(path)
	f.Add(seed)
	f.Add([]byte(`{"format":"otsec.collector-credentials/0.1"}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		p := filepath.Join(t.TempDir(), "c.json")
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		s, err := OpenCredStore(p, CredStoreConfig{NodeID: testNode, Generations: &memGens{}})
		if err != nil {
			if !errors.Is(err, ErrStateUnavailable) {
				t.Fatalf("error not ErrStateUnavailable: %v", err)
			}
			return
		}
		if err := checkEntries(s.doc.Entries, testNode); err != nil {
			t.Fatalf("opened a store with bad entries: %v", err)
		}
	})
}

func isWindows() bool { return runtime.GOOS == "windows" }
