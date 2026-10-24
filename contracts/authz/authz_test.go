package authz

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/register"
)

func TestMatrixSeparatesDuties(t *testing.T) {
	// Only the collector reads devices, and nothing writes them.
	for _, r := range Roles {
		if Permits(r, ClassDeviceRead) != (r == RoleCollector) {
			t.Fatalf("device-read for %s: got %v", r, Permits(r, ClassDeviceRead))
		}
		if Permits(r, "device-write") {
			t.Fatalf("%s may write devices", r)
		}
	}
	// Audit is read only by the security auditor; the admin cannot read it.
	for _, r := range Roles {
		if Permits(r, ClassAuditRead) != (r == RoleSecurityAuditor) {
			t.Fatalf("audit-read for %s: got %v", r, Permits(r, ClassAuditRead))
		}
	}
	// The collector does nothing but device-read.
	for _, c := range Classes {
		if c != ClassDeviceRead && Permits(RoleCollector, c) {
			t.Fatalf("collector may %s", c)
		}
	}
	if Permits("root", ClassObserve) || Permits(RoleAdmin, "exec") {
		t.Fatal("unknown role or class permitted")
	}
}

func TestRoleSets(t *testing.T) {
	ok := []struct {
		t     PrincipalType
		roles []Role
	}{
		{PrincipalHuman, []Role{RoleMonitor}},
		{PrincipalHuman, []Role{RoleAdmin, RoleMonitor}},
		{PrincipalHuman, []Role{RoleSecurityAuditor, RoleMonitor}},
		{PrincipalSchedule, []Role{RoleCollector}},
	}
	for _, c := range ok {
		if err := ValidateRoleSet(c.t, c.roles); err != nil {
			t.Fatalf("%v %v: %v", c.t, c.roles, err)
		}
	}
	bad := []struct {
		t     PrincipalType
		roles []Role
	}{
		{PrincipalHuman, []Role{RoleAdmin, RoleEngineer}},
		{PrincipalHuman, []Role{RoleAdmin, RoleSecurityAuditor}},
		{PrincipalHuman, []Role{RoleEngineer, RoleSecurityAuditor}},
		{PrincipalHuman, []Role{RoleCollector}},
		{PrincipalSchedule, []Role{RoleCollector, RoleMonitor}},
		{PrincipalSchedule, []Role{RoleAdmin}},
		{PrincipalSystem, []Role{RoleAdmin}},
		{PrincipalHuman, []Role{RoleMonitor, RoleMonitor}},
		{PrincipalHuman, []Role{"root"}},
		{PrincipalHuman, nil},
	}
	for _, c := range bad {
		if err := ValidateRoleSet(c.t, c.roles); err == nil {
			t.Fatalf("%v %v accepted", c.t, c.roles)
		}
	}
}

func TestSecondApprover(t *testing.T) {
	if !RequiresSecondApprover(ClassRoleAdmin, RoleAdmin, false) || !RequiresSecondApprover(ClassRoleAdmin, RoleEngineer, false) ||
		!RequiresSecondApprover(ClassRoleAdmin, RoleSecurityAuditor, false) || RequiresSecondApprover(ClassRoleAdmin, RoleMonitor, false) {
		t.Fatal("role grants")
	}
	if !RequiresSecondApprover(ClassPolicyAdmin, "", true) || RequiresSecondApprover(ClassPolicyAdmin, "", false) {
		t.Fatal("policy widening")
	}
}

// No C7 type may have a field that could hold a secret (V-S11).
func TestNoSecretFields(t *testing.T) {
	forbidden := regexp.MustCompile(`(?i)secret|password|passwd|pwd|plaintext_value|key_material|private`)
	allowed := map[string]bool{"Sealed": true} // ciphertext only
	var walk func(reflect.Type, string)
	seen := map[reflect.Type]bool{}
	walk = func(ty reflect.Type, path string) {
		for ty.Kind() == reflect.Pointer || ty.Kind() == reflect.Slice || ty.Kind() == reflect.Map {
			ty = ty.Elem()
		}
		if ty.Kind() != reflect.Struct || seen[ty] {
			return
		}
		seen[ty] = true
		for i := 0; i < ty.NumField(); i++ {
			f := ty.Field(i)
			tag := strings.Split(f.Tag.Get("json"), ",")[0]
			if !allowed[f.Name] && (forbidden.MatchString(f.Name) || forbidden.MatchString(tag)) {
				t.Fatalf("%s.%s may hold a secret", path, f.Name)
			}
			walk(f.Type, path+"."+f.Name)
		}
	}
	for _, v := range []any{CollectorRequest{}, CollectorReply{}, CredentialRef{}, CredentialStatus{}} {
		walk(reflect.TypeOf(v), reflect.TypeOf(v).Name())
	}
}

func TestGoldenRequests(t *testing.T) {
	valid, _ := filepath.Glob("testdata/requests/valid/*.json")
	invalid, _ := filepath.Glob("testdata/requests/invalid/*.json")
	if len(valid) < 4 || len(invalid) < 15 {
		t.Fatalf("golden examples missing: %d valid, %d invalid", len(valid), len(invalid))
	}
	for _, p := range valid {
		data, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := DecodeRequest(data); err != nil {
			t.Fatalf("%s: %v", p, err)
		}
	}
	for _, p := range invalid {
		data, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		want := RefusalCode(strings.SplitN(filepath.Base(p), "__", 2)[0])
		_, err = DecodeRequest(data)
		var ref *Refusal
		if !errors.As(err, &ref) {
			t.Fatalf("%s: got %v, want refusal %s", p, err, want)
		}
		if ref.Code != want {
			t.Fatalf("%s: got %s (%s), want %s", p, ref.Code, ref.Detail, want)
		}
		if strings.Contains(ref.Detail, "hunter2") {
			t.Fatalf("%s: refusal detail leaks a secret", p)
		}
	}
}

func loadSEL751(t *testing.T) ([]byte, *register.Matcher) {
	t.Helper()
	data, err := os.ReadFile("../register/testdata/sel-751-phase0.json")
	if err != nil {
		t.Fatal(err)
	}
	pkg, err := register.Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	m, err := register.NewMatcher(pkg)
	if err != nil {
		t.Fatal(err)
	}
	return data, m
}

func TestRunAgainstRegister(t *testing.T) {
	_, m := loadSEL751(t)
	cases := []struct {
		op     string
		params map[string]string
		want   RefusalCode
	}{
		{"sel.ser.read_all", map[string]string{}, ""},
		{"sel.id", map[string]string{}, ""},
		{"sel.settings.show_port1", map[string]string{}, ""},
		{"sel.session.acc", map[string]string{}, RefuseUnknownOperation}, // session-control is never an operation (C-A2-1)
		{"sel.session.qui", map[string]string{}, RefuseUnknownOperation},
		{"sel.ser.clear", map[string]string{}, RefuseUnknownOperation}, // deny rules are never operations
		{"sel.tri", map[string]string{}, RefuseUnknownOperation},
		{"sel.ser.read_all", map[string]string{"row": "1"}, RefuseBadParams},
	}
	for _, c := range cases {
		b := RunBody{AssetID: "a1", OperationID: c.op, Params: c.params, CredentialRef: "cred_abcdefgh", RegisterVersion: 1}
		err := b.ValidateAgainst(m)
		var ref *Refusal
		if c.want == "" {
			if err != nil {
				t.Fatalf("%s %v: %v", c.op, c.params, err)
			}
			continue
		}
		if !errors.As(err, &ref) || ref.Code != c.want {
			t.Fatalf("%s %v: got %v, want %s", c.op, c.params, err, c.want)
		}
	}
	// A probe-only operation is sent by the transport before authentication;
	// a schedule cannot ask for it.
	data, _ := loadSEL751(t)
	pkg, err := register.Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	for i := range pkg.Operations {
		if pkg.Operations[i].ID == "sel.id" {
			pkg.Operations[i].Phases = []register.Phase{register.PhaseProbe}
		}
	}
	probeOnly, err := register.NewMatcher(pkg)
	if err != nil {
		t.Fatal(err)
	}
	b := RunBody{AssetID: "a1", OperationID: "sel.id", Params: map[string]string{}, CredentialRef: "cred_abcdefgh", RegisterVersion: 1}
	var ref *Refusal
	if err := b.ValidateAgainst(probeOnly); !errors.As(err, &ref) || ref.Code != RefuseNotInvocable {
		t.Fatalf("probe-only operation: %v", err)
	}
	b.OperationID = "sel.ser.read_all"
	if err := b.ValidateAgainst(nil); !errors.As(err, &ref) || ref.Code != RefuseRegisterUnverified {
		t.Fatalf("nil register: %v", err)
	}
}

func TestReplyFailsClosed(t *testing.T) {
	for _, raw := range []string{
		`{"contract":"otsec.authz/0.1","request_id":"r1","status":"accepted","invocation_id":"inv-1"}`,
		`{"contract":"otsec.authz/0.1","request_id":"r1","status":"ACCEPTED"}`,
		`{"contract":"otsec.authz/0.2","request_id":"r1","status":"maybe"}`,
		`{"contract":"otsec.authz/0.1","request_id":"r1","status":"accepted","refusal":{"code":"busy"}}`,
	} {
		var r CollectorReply
		if err := json.Unmarshal([]byte(raw), &r); err != nil {
			t.Fatal(err)
		}
		want := strings.Contains(raw, `"accepted","invocation_id"`)
		if r.Accepted() != want {
			t.Fatalf("%s: Accepted() = %v", raw, r.Accepted())
		}
	}
	if RefusalCode("new_in_0.2").Normalize() != RefuseUnknown || RefuseBusy.Normalize() != RefuseBusy {
		t.Fatal("normalize")
	}
}

func TestSecretPolicy(t *testing.T) {
	isLine := func(s string) bool {
		return regexp.MustCompile(`(?i)^\s*(SER|ACC|QUI|ID|SHO|TRI|2AC)\b.*`).MatchString(s)
	}
	table754ish := regexp.MustCompile(`^[A-Za-z0-9!#$%&()*+,\-./:;<=>?@\[\]^_{|}~]+$`) // stand-in; the real set comes from the register (S22 Table 7.54)
	p := SecretPolicy{MaxLen: 12, Allowed: table754ish}
	if err := ValidateSecret([]byte("Otter#2026"), p, isLine); err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"", "ThirteenChars", "has space", "tab\there", "line\r\n", "SER C", "TRI", "\xa5\xe0"} {
		err := ValidateSecret([]byte(s), p, isLine)
		if !errors.Is(err, ErrSecretRejected) {
			t.Fatalf("%q: got %v", s, err)
		}
		if s != "" && strings.Contains(err.Error(), s) {
			t.Fatalf("%q: error leaks the secret", s)
		}
	}
	if err := ValidateSecret([]byte("Otter#2026"), p, nil); err == nil {
		t.Fatal("missing register check accepted")
	}
}

func TestSealAADBindsReference(t *testing.T) {
	ref := CredentialRef{ID: "cred_abcdefgh", AssetID: "a1", NodeID: "n1", Transport: TransportTelnet, AccessLevel: "ACC", Version: 1}
	base := string(SealAAD(ref))
	for _, change := range []func(*CredentialRef){
		func(r *CredentialRef) { r.ID = "cred_abcdefgi" },
		func(r *CredentialRef) { r.Version = 2 },
		func(r *CredentialRef) { r.AssetID = "a2" },
		func(r *CredentialRef) { r.NodeID = "n2" },
		func(r *CredentialRef) { r.Transport = TransportSSH },
		func(r *CredentialRef) { r.AccessLevel = "2AC" },
	} {
		r := ref
		change(&r)
		if string(SealAAD(r)) == base {
			t.Fatalf("AAD unchanged by %+v", r)
		}
	}
}

func TestCredentialStatus(t *testing.T) {
	ok := []CredentialStatus{
		{RefID: "cred_abcdefgh", Version: 1, State: CredentialActive, Since: "2026-10-24T11:00:00Z"},
		{RefID: "cred_abcdefgh", Version: 1, State: CredentialSuspended, Reason: "auth-failed", Since: "2026-10-24T11:00:00Z"},
		{RefID: "cred_abcdefgh", Version: 1, State: CredentialRevoked, Reason: "compromised", Since: "2026-10-24T11:00:00Z"},
	}
	for _, s := range ok {
		if err := s.Validate(); err != nil {
			t.Fatalf("%+v: %v", s, err)
		}
	}
	bad := []CredentialStatus{
		{RefID: "cred_abcdefgh", Version: 1, State: CredentialSuspended, Since: "2026-10-24T11:00:00Z"},
		{RefID: "cred_abcdefgh", Version: 1, State: CredentialActive, Reason: "auth-failed", Since: "2026-10-24T11:00:00Z"},
		{RefID: "cred_abcdefgh", Version: 1, State: "paused", Since: "2026-10-24T11:00:00Z"},
		{RefID: "cred_abcdefgh", Version: 1, State: CredentialActive, Since: "2026-10-24T11:00:00+03:00"},
	}
	for _, s := range bad {
		if err := s.Validate(); err == nil {
			t.Fatalf("%+v accepted", s)
		}
	}
}

// --- register package verification ---

type signer struct {
	id   string
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

func newSigner(t *testing.T, id string, seed byte) signer {
	t.Helper()
	s := make([]byte, ed25519.SeedSize)
	for i := range s {
		s[i] = seed
	}
	priv := ed25519.NewKeyFromSeed(s)
	return signer{id: id, priv: priv, pub: priv.Public().(ed25519.PublicKey)}
}

func (s signer) seal(payload []byte) *register.Envelope {
	return &register.Envelope{Contract: register.ContractID, Algorithm: "ed25519", KeyID: s.id, Payload: payload,
		Signature: ed25519.Sign(s.priv, RegisterSigningInput(payload))}
}

// withRevision returns the package re-encoded with another revision, so a
// test can sign genuinely different packages.
func withRevision(t *testing.T, payload []byte, rev uint64) []byte {
	t.Helper()
	var p register.Package
	if err := json.Unmarshal(payload, &p); err != nil {
		t.Fatal(err)
	}
	p.Revision = rev
	out, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestRegisterPackageVerification(t *testing.T) {
	data, _ := loadSEL751(t)
	rel := newSigner(t, "release-2026-1", 1)
	old := newSigner(t, "release-2025-1", 2)
	attacker := newSigner(t, "release-2026-1", 3) // same key id, different key
	anchors := []TrustAnchor{
		{KeyID: rel.id, PublicKey: rel.pub, Status: KeyActive},
		{KeyID: old.id, PublicKey: old.pub, Status: KeyRevoked},
	}
	rev5, rev6 := withRevision(t, data, 5), withRevision(t, data, 6)

	pkg, floor, err := VerifyRegisterPackage(rel.seal(rev6), anchors, map[string]FamilyFloor{})
	if err != nil {
		t.Fatal(err)
	}
	if pkg.Family != "sel-751" || floor.Revision != 6 || floor.PayloadSHA256 != sha256.Sum256(rev6) {
		t.Fatalf("got %s %+v", pkg.Family, floor)
	}
	floors := map[string]FamilyFloor{"sel-751": floor}
	// Re-verifying the active package at startup passes.
	if _, _, err := VerifyRegisterPackage(rel.seal(rev6), anchors, floors); err != nil {
		t.Fatalf("re-verify: %v", err)
	}
	// Another family's floor does not apply.
	if _, _, err := VerifyRegisterPackage(rel.seal(rev5), anchors, map[string]FamilyFloor{"sel-rtac": {Revision: 9}}); err != nil {
		t.Fatalf("other family floor applied: %v", err)
	}

	// The firmware allowlist is inside the signed payload (C-A2-2): widening it
	// after signing breaks the signature.
	widened := bytes.Replace(rev6, []byte(`"status":"deny"`), []byte(`"status":"allow"`), 1)
	if bytes.Equal(widened, rev6) {
		t.Fatal("test did not change the allowlist")
	}
	sameRevDifferentBytes := bytes.Replace(rev6, []byte(`"owner":"`), []byte(`"owner":"x`), 1)

	cases := map[string]struct {
		env    *register.Envelope
		floors map[string]FamilyFloor
	}{
		"no envelope":                     {nil, nil},
		"empty signature":                 {func() *register.Envelope { e := rel.seal(rev6); e.Signature = nil; return e }(), nil},
		"truncated signature":             {func() *register.Envelope { e := rel.seal(rev6); e.Signature = e.Signature[:40]; return e }(), nil},
		"rolled back":                     {rel.seal(rev5), floors},
		"same revision, other bytes":      {rel.seal(sameRevDifferentBytes), floors},
		"allowlist widened after signing": {func() *register.Envelope { e := rel.seal(rev6); e.Payload = widened; return e }(), nil},
		"revoked key":                     {old.seal(rev6), nil},
		"unknown key":                     {newSigner(t, "release-x", 4).seal(rev6), nil},
		"attacker key, same id":           {attacker.seal(rev6), nil},
		"no domain separation": {func() *register.Envelope {
			e := rel.seal(rev6)
			e.Signature = ed25519.Sign(rel.priv, rev6)
			return e
		}(), nil},
		"algorithm none":             {func() *register.Envelope { e := rel.seal(rev6); e.Algorithm = "none"; return e }(), nil},
		"wrong envelope contract":    {func() *register.Envelope { e := rel.seal(rev6); e.Contract = "otsec.register/1.0"; return e }(), nil},
		"signed but invalid package": {rel.seal([]byte(`{"contract":"otsec.register/0.1"}`)), nil},
		"signed, duplicate key":      {rel.seal(bytes.Replace(rev6, []byte(`"family":"sel-751"`), []byte(`"family":"sel-751","family":"sel-751"`), 1)), nil},
		"oversize payload":           {rel.seal(make([]byte, MaxRegisterPayload+1)), nil},
	}
	for name, c := range cases {
		_, _, err := VerifyRegisterPackage(c.env, anchors, c.floors)
		if !errors.Is(err, ErrRegisterRejected) {
			t.Fatalf("%s: got %v", name, err)
		}
	}
	dup := append(append([]TrustAnchor{}, anchors...), TrustAnchor{KeyID: rel.id, PublicKey: attacker.pub, Status: KeyActive})
	if _, _, err := VerifyRegisterPackage(rel.seal(rev6), dup, nil); !errors.Is(err, ErrRegisterRejected) {
		t.Fatal("duplicate key id in trust anchors accepted")
	}
}

func TestDecodeRegisterEnvelopeStrict(t *testing.T) {
	good := `{"contract":"otsec.register/0.1","algorithm":"ed25519","key_id":"k","payload":"e30=","signature":"AA=="}`
	if _, err := DecodeRegisterEnvelope([]byte(good)); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{
		strings.Replace(good, `"key_id":"k"`, `"key_id":"k","key_id":"j"`, 1),
		strings.Replace(good, `"key_id":"k"`, `"key_id":"k","floor":0`, 1),
		good + `{}`,
		good + `]`,
	} {
		if _, err := DecodeRegisterEnvelope([]byte(bad)); !errors.Is(err, ErrRegisterRejected) {
			t.Fatalf("%s: got %v", bad, err)
		}
	}
}

func TestSchemasAreStrictJSON(t *testing.T) {
	files, _ := filepath.Glob("schema/*.json")
	if len(files) < 3 {
		t.Fatalf("schemas missing: %v", files)
	}
	for _, p := range files {
		data, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		var s map[string]any
		if err := json.Unmarshal(data, &s); err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		if s["$schema"] != "https://json-schema.org/draft/2020-12/schema" {
			t.Fatalf("%s: not JSON Schema 2020-12", p)
		}
		if strings.Contains(p, "collector-request") && !strings.Contains(string(data), `"unevaluatedProperties": false`) && !strings.Contains(string(data), `"additionalProperties": false`) {
			t.Fatalf("%s: collector requests must be strict", p)
		}
	}
}
