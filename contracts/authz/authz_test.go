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
	"time"

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
		ref    string
		want   RefusalCode
	}{
		{"sel.ser.read_all", map[string]string{}, "cred_abcdefgh", ""},
		{"sel.id", map[string]string{}, "", ""}, // level 0: sent before ACC, no credential (C7-A2-5)
		{"sel.settings.show_port1", map[string]string{}, "cred_abcdefgh", ""},
		{"sel.id", map[string]string{}, "cred_abcdefgh", RefuseCredentialMismatch}, // a password must not be resolved for level 0
		{"sel.ser.read_all", map[string]string{}, "", RefuseCredentialMismatch},
		{"sel.session.acc", map[string]string{}, "cred_abcdefgh", RefuseUnknownOperation}, // session-control is never an operation (C-A2-1)
		{"sel.session.qui", map[string]string{}, "cred_abcdefgh", RefuseUnknownOperation},
		{"sel.ser.clear", map[string]string{}, "cred_abcdefgh", RefuseUnknownOperation}, // deny rules are never operations
		{"sel.tri", map[string]string{}, "cred_abcdefgh", RefuseUnknownOperation},
		{"sel.ser.read_all", map[string]string{"row": "1"}, "cred_abcdefgh", RefuseBadParams},
	}
	for _, c := range cases {
		b := RunBody{AssetID: "a1", OperationID: c.op, Params: c.params, CredentialRef: c.ref, RegisterVersion: 1}
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
	b := RunBody{AssetID: "a1", OperationID: "sel.id", Params: map[string]string{}, RegisterVersion: 1}
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
		`{"contract":"otsec.authz/0.1","request_id":"r1","status":"accepted","invocation_id":"inv-1","collector_seq":7}`,
		`{"contract":"otsec.authz/0.1","request_id":"r1","status":"accepted","invocation_id":"inv-2"}`, // no collector_seq: unaccountable (C7-A5-2)
		`{"contract":"otsec.authz/0.1","request_id":"r1","status":"ACCEPTED"}`,
		`{"contract":"otsec.authz/0.2","request_id":"r1","status":"maybe"}`,
		`{"contract":"otsec.authz/0.1","request_id":"r1","status":"accepted","refusal":{"code":"busy"}}`,
	} {
		var r CollectorReply
		if err := json.Unmarshal([]byte(raw), &r); err != nil {
			t.Fatal(err)
		}
		want := strings.Contains(raw, `"collector_seq":7`)
		if r.Accepted() != want {
			t.Fatalf("%s: Accepted() = %v", raw, r.Accepted())
		}
	}
	if RefusalCode("new_in_0.2").Normalize() != RefuseUnknown || RefuseBusy.Normalize() != RefuseBusy {
		t.Fatal("normalize")
	}
}

func loadSEL751Package(t *testing.T) *register.Package {
	t.Helper()
	data, _ := loadSEL751(t)
	pkg, err := register.Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	return pkg
}

func TestSecretPolicy(t *testing.T) {
	pkg := loadSEL751Package(t)
	p := SecretPolicies["sel-751"]
	for _, s := range []string{"Otter#2026", "Wq7!mZ2p", "xyz-9"} {
		if err := ValidateSecret([]byte(s), p, pkg); err != nil {
			t.Fatalf("%q: %v", s, err)
		}
	}
	rejected := []string{"", "ThirteenChars", "has space", "tab\there", "line\r\n", "SER C", "TRI", "\xa5\xe0"}
	// A6's C7 probe (C7-A6-3): lower-case and longer forms of approved lines,
	// and command words the deny rules only match with an argument or a space.
	rejected = append(rejected, "OPEN", "open1234", "Trip1", "tri", "set", "pas", "2ac", "QUI", "qui", "quiet123",
		"acc", "accent12", "ser", "serial99", "id", "idle4now", "show1234", "close!", "his", "Dat3")
	for _, s := range rejected {
		err := ValidateSecret([]byte(s), p, pkg)
		if !errors.Is(err, ErrSecretRejected) {
			t.Fatalf("%q: got %v", s, err)
		}
		if s != "" && strings.Contains(err.Error(), s) {
			t.Fatalf("%q: error leaks the secret", s)
		}
	}
	if err := ValidateSecret([]byte("Otter#2026"), p, nil); err == nil {
		t.Fatal("missing register package accepted")
	}
	// The allowed set is matched against the whole secret, not a substring.
	if err := ValidateSecret([]byte("Wq7!mZ2 p"), p, pkg); !errors.Is(err, ErrSecretRejected) {
		t.Fatalf("space inside an otherwise allowed secret: %v", err)
	}
	// A policy must choose its mnemonic rule; zero is not whole-word mode.
	if err := ValidateSecret([]byte("Otter#2026"), SecretPolicy{MaxLen: 12}, pkg); !errors.Is(err, ErrSecretRejected) {
		t.Fatalf("policy with no mnemonic rule: %v", err)
	}
	// Whole-word mode, chosen explicitly: only the full command word is refused.
	whole := SecretPolicy{MaxLen: 12, WholeWord: true}
	if err := ValidateSecret([]byte("accent12"), whole, pkg); err != nil {
		t.Fatalf("whole-word mode: %v", err)
	}
	if err := ValidateSecret([]byte("acc"), whole, pkg); !errors.Is(err, ErrSecretRejected) {
		t.Fatalf("whole-word mode, acc: %v", err)
	}
}

func TestMnemonicsFromRegister(t *testing.T) {
	got := map[string]bool{}
	for _, m := range mnemonics(loadSEL751Package(t)) {
		got[m] = true
	}
	for _, want := range []string{"ID", "SER", "SHO", "ACC", "QUI", "2AC", "CAL", "TRI", "OPE", "CLO", "SET", "PAS", "R_S", "DAT", "TIM", "HSR", "PARTNO", "GOO", "FGS"} {
		if !got[want] {
			t.Errorf("mnemonic %s missing", want)
		}
	}
}

func TestCheckAccessLevel(t *testing.T) {
	pkg := loadSEL751Package(t)
	if err := CheckAccessLevel(pkg, "1"); err != nil {
		t.Fatal(err)
	}
	for _, level := range []string{"0", "2", "2AC", "ACC", ""} {
		var ref *Refusal
		if err := CheckAccessLevel(pkg, level); !errors.As(err, &ref) || ref.Code != RefuseCredentialMismatch {
			t.Errorf("level %q: got %v", level, err)
		}
	}
	var ref *Refusal
	if err := CheckAccessLevel(nil, "1"); !errors.As(err, &ref) || ref.Code != RefuseRegisterUnverified {
		t.Errorf("nil package: %v", err)
	}
	// Golden examples that decode but fail against the SEL-751 register.
	files, _ := filepath.Glob("testdata/requests/against-register/*.json")
	if len(files) == 0 {
		t.Fatal("no against-register examples")
	}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		req, err := DecodeRequest(raw)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		want := RefusalCode(strings.SplitN(filepath.Base(f), "__", 2)[0])
		if err := CheckAccessLevel(pkg, req.CredentialInstall.Ref.AccessLevel); !errors.As(err, &ref) || ref.Code != want {
			t.Errorf("%s: got %v, want %s", f, err, want)
		}
	}
}

func TestSealAADBindsReference(t *testing.T) {
	ref := CredentialRef{ID: "cred_abcdefgh", AssetID: "a1", NodeID: "n1", EndpointID: "port1-telnet", Transport: TransportTelnet, AccessLevel: "1", Version: 1}
	base := string(SealAAD(ref))
	for _, change := range []func(*CredentialRef){
		func(r *CredentialRef) { r.ID = "cred_abcdefgi" },
		func(r *CredentialRef) { r.Version = 2 },
		func(r *CredentialRef) { r.AssetID = "a2" },
		func(r *CredentialRef) { r.NodeID = "n2" },
		func(r *CredentialRef) { r.Transport = TransportSSH },
		func(r *CredentialRef) { r.EndpointID = "port2-telnet" },
		func(r *CredentialRef) { r.AccessLevel = "2" },
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

func TestFailedAuthFloor(t *testing.T) {
	for _, c := range []struct {
		tidle, want time.Duration
	}{
		{0, 31 * time.Minute}, // TIDLE unknown
		{-time.Minute, 31 * time.Minute},
		{31 * time.Minute, 31 * time.Minute}, // out of range
		{15 * time.Minute, 16 * time.Minute},
		{30 * time.Minute, 31 * time.Minute},
	} {
		if got := FailureFloor(c.tidle); got != c.want {
			t.Errorf("FailureFloor(%v) = %v, want %v", c.tidle, got, c.want)
		}
	}

	now := time.Date(2026, 10, 24, 15, 0, 0, 0, time.UTC)
	floor := FailureFloor(15 * time.Minute)
	for _, c := range []struct {
		last time.Time
		want bool
	}{
		{time.Time{}, false},
		{now.Add(-floor), false},
		{now.Add(-floor + time.Second), true},
		{now.Add(-15 * time.Minute), true}, // inside TIDLE plus one minute
		{now, true},
		{now.Add(time.Hour), true}, // stamped in the future: a clock stepped back must not reopen the floor
	} {
		if got := InsideFailureFloor(c.last, now, floor); got != c.want {
			t.Errorf("last failure %v: got %v, want %v", c.last, got, c.want)
		}
	}
}

func installedRef(t *testing.T) CredentialRef {
	t.Helper()
	raw, err := os.ReadFile("testdata/requests/valid/credential-install.json")
	if err != nil {
		t.Fatal(err)
	}
	req, err := DecodeRequest(raw)
	if err != nil {
		t.Fatal(err)
	}
	return req.CredentialInstall.Ref
}

func TestCredentialRefFields(t *testing.T) {
	ref := installedRef(t)
	if err := ref.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*CredentialRef){
		"level 0":             func(r *CredentialRef) { r.AccessLevel = register.ProbeAccessLevel }, // C7-A2-5
		"serial transport":    func(r *CredentialRef) { r.Transport = TransportSerial },             // out of 0.1
		"no endpoint":         func(r *CredentialRef) { r.EndpointID = "" },
		"upper-case endpoint": func(r *CredentialRef) { r.EndpointID = "Port1" },
		"upper-case node":     func(r *CredentialRef) { r.NodeID = "Site-A-Node-1" }, // C7-A5-1
		"64-character node":   func(r *CredentialRef) { r.NodeID = strings.Repeat("a", 64) },
		"node ends in hyphen": func(r *CredentialRef) { r.NodeID = "site-a-" },
		"node with a dot":     func(r *CredentialRef) { r.NodeID = "site-a.node-1" },
	} {
		r := ref
		change(&r)
		if r.Validate() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	r := ref
	r.NodeID = strings.Repeat("a", 63)
	if err := r.Validate(); err != nil {
		t.Errorf("63-character node: %v", err)
	}
}

func TestBinds(t *testing.T) {
	ref := installedRef(t)
	use := Use{NodeID: ref.NodeID, AssetID: ref.AssetID, EndpointID: ref.EndpointID, Transport: ref.Transport, AckScope: PlaintextLabOnly, AccessLevel: "1"}
	if err := ref.Binds(use); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*Use){
		"other node":            func(u *Use) { u.NodeID = "site-a-node-2" },
		"other asset":           func(u *Use) { u.AssetID = "c41f8a2d-6b0e-4e97-8d13-5a2c9f7b0e64" },
		"other endpoint":        func(u *Use) { u.EndpointID = "port2-telnet" }, // same asset, another port (C7-A2-6)
		"other transport":       func(u *Use) { u.Transport = TransportSerial },
		"higher level":          func(u *Use) { u.AccessLevel = "2" }, // a Level 1 credential never reaches 2AC (C7-A2-4)
		"level 0":               func(u *Use) { u.AccessLevel = register.ProbeAccessLevel },
		"no acknowledgement":    func(u *Use) { u.AckScope = "" }, // plaintext needs the endpoint's acknowledgement (C1-A3-3)
		"other acknowledgement": func(u *Use) { u.AckScope = "production" },
	} {
		u := use
		change(&u)
		var ref2 *Refusal
		if err := ref.Binds(u); !errors.As(err, &ref2) || ref2.Code != RefuseCredentialMismatch {
			t.Errorf("%s: got %v, want %s", name, err, RefuseCredentialMismatch)
		}
	}
}

// TestSchemaPatterns keeps the credential reference schema's shared
// identifier patterns equal to the ones the code enforces (C7-A5-1).
func TestSchemaPatterns(t *testing.T) {
	b, err := os.ReadFile("schema/credential-ref.json")
	if err != nil {
		t.Fatal(err)
	}
	var s struct {
		Properties map[string]struct{ Pattern string }
	}
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	for field, re := range map[string]*regexp.Regexp{
		"node_id":     nodeIDPattern,
		"asset_id":    assetIDPattern,
		"endpoint_id": endpointIDPattern,
	} {
		if got := s.Properties[field].Pattern; got != re.String() {
			t.Errorf("%s: schema pattern %q, code %q", field, got, re.String())
		}
	}
}
