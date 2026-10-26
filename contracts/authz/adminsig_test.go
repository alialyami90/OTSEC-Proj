package authz

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

// Test keys only (D2-5): derived from fixed seeds, used nowhere else.
var (
	testAdminPriv  = ed25519.NewKeyFromSeed(seed("otsec test admin key 1"))
	testOtherPriv  = ed25519.NewKeyFromSeed(seed("otsec test admin key 2"))
	testAdminNow   = time.Date(2026, 10, 26, 15, 0, 0, 0, time.UTC)
	testAdminBind  = AdminBinding{NodeID: "site-a-node-1", InstallKeyID: "site-a-node-1.collector-install.1"}
	testAdminNonce = "AAECAwQFBgcICQoLDA0ODw" // bytes 0 to 15
)

func seed(s string) []byte {
	sum := sha256.Sum256([]byte(s))
	return sum[:]
}

func testAdminKeys() []AdminKey {
	pub := testAdminPriv.Public().(ed25519.PublicKey)
	other := testOtherPriv.Public().(ed25519.PublicKey)
	return []AdminKey{
		{KeyID: AdminKeyID(pub), PublicKey: pub, Principal: "alice@site-a", Status: KeyActive},
		{KeyID: AdminKeyID(other), PublicKey: other, Principal: "bob@site-a", Status: KeyActive},
	}
}

// installBody is the 0.1 golden's body, the one an admin signs from 0.4.
func installBody(t *testing.T) *CredentialInstallBody {
	t.Helper()
	raw, err := os.ReadFile("testdata/requests/valid/credential-install.json")
	if err != nil {
		t.Fatal(err)
	}
	req, err := DecodeRequest(raw)
	if err != nil {
		t.Fatal(err)
	}
	return req.CredentialInstall
}

func adminPayload(t *testing.T, kind RequestKind) AdminRequest {
	t.Helper()
	p := AdminRequest{Format: AdminRequestFormat, Kind: kind, Principal: Principal{Type: PrincipalHuman, ID: "alice@site-a"},
		AdminKeyID: AdminKeyID(testAdminPriv.Public().(ed25519.PublicKey)), NodeID: testAdminBind.NodeID,
		InstallKeyID: testAdminBind.InstallKeyID, Nonce: testAdminNonce,
		IssuedAt: "2026-10-26T14:58:00Z", ExpiresAt: "2026-10-26T15:08:00Z"}
	switch kind {
	case KindCredentialInstall:
		p.CredentialInstall = installBody(t)
	case KindCredentialRevoke:
		p.CredentialRevoke = &CredentialRevokeBody{RefID: "cred_7f3k2m9q4x", Reason: RevokeRotated}
	case KindCredentialClearSusp:
		p.CredentialClearSusp = &CredentialClearSuspBody{RefID: "cred_7f3k2m9q4x", Version: 2}
	case KindAssetClearSusp:
		p.AssetClearSusp = &AssetClearSuspBody{AssetID: "2b7d4e10-8c3f-4a5b-9e21-7c4f0d6a8b13", Ref: "6f1c2e8a-0000-4000-8000-0000000000a1"}
	case KindNodeQuarantineClear:
		p.NodeQuarantineClear = &NodeQuarantineClearBody{AssetID: "2b7d4e10-8c3f-4a5b-9e21-7c4f0d6a8b13", ManifestSHA256: testManifestSHA256}
	case KindNodeSeqResetAck:
		p.NodeSeqResetAck = &NodeSeqResetAckBody{}
	}
	return p
}

// testManifestSHA256 is the SHA-256 of "otsec test quarantine manifest";
// no manifest has it.
const testManifestSHA256 = "47468d8ca5f3ebb058dc452f3669a7ed64c69b953a20294801b75147fd43f636"

func signedRequest(t *testing.T, priv ed25519.PrivateKey, p AdminRequest) *CollectorRequest {
	t.Helper()
	env, err := SignAdminRequest(priv, p)
	if err != nil {
		t.Fatal(err)
	}
	return &CollectorRequest{Contract: ContractID, Kind: p.Kind, RequestID: "req-20261026-0001",
		OnBehalfOf: p.Principal, PolicyVersion: 3, AdminSigned: env}
}

// roundTrip sends req through the wire format, as the collector reads it.
func roundTrip(t *testing.T, req *CollectorRequest) *CollectorRequest {
	t.Helper()
	b, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeRequest(b)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	return got
}

func TestAdminRequestVerifies(t *testing.T) {
	for kind := range adminKinds {
		t.Run(string(kind), func(t *testing.T) {
			p := adminPayload(t, kind)
			req := roundTrip(t, signedRequest(t, testAdminPriv, p))
			got, err := VerifyAdminRequest(req, testAdminKeys(), testAdminBind, testAdminNow)
			if err != nil {
				t.Fatal(err)
			}
			if got.Kind != kind || got.Nonce != testAdminNonce || !got.Expires().Equal(time.Date(2026, 10, 26, 15, 8, 0, 0, time.UTC)) {
				t.Fatalf("%+v", got)
			}
			if b, _ := json.Marshal(req); bytes.Contains(b, []byte(`"credential_install":`)) {
				t.Fatal("the body travels outside the signed payload")
			}
		})
	}
}

// Every way a signed request can fail, each refused with admin_unverified
// and a detail that names only the check.
func TestAdminRequestRefusals(t *testing.T) {
	type mut struct {
		name  string
		check AdminCheck
		req   func(t *testing.T) *CollectorRequest
		keys  func([]AdminKey) []AdminKey
		bind  *AdminBinding
		now   time.Time
	}
	signed := func(edit func(*AdminRequest)) func(t *testing.T) *CollectorRequest {
		return func(t *testing.T) *CollectorRequest {
			p := adminPayload(t, KindCredentialInstall)
			if edit != nil {
				edit(&p)
			}
			return signedRequest(t, testAdminPriv, p)
		}
	}
	envelope := func(edit func(*CollectorRequest)) func(t *testing.T) *CollectorRequest {
		return func(t *testing.T) *CollectorRequest {
			r := signed(nil)(t)
			edit(r)
			return r
		}
	}
	// rawSigned signs payload bytes as they are, under kind's prefix.
	rawSigned := func(kind RequestKind, payload func(t *testing.T) []byte, prefix func([]byte) []byte) func(t *testing.T) *CollectorRequest {
		return func(t *testing.T) *CollectorRequest {
			pl := payload(t)
			in := AdminSigningInput(kind, pl)
			if prefix != nil {
				in = prefix(pl)
			}
			return &CollectorRequest{Contract: ContractID, Kind: KindCredentialInstall, RequestID: "req-20261026-0001",
				OnBehalfOf: Principal{Type: PrincipalHuman, ID: "alice@site-a"}, PolicyVersion: 3,
				AdminSigned: &AdminSigned{KeyID: AdminKeyID(testAdminPriv.Public().(ed25519.PublicKey)), Algorithm: "ed25519",
					Payload: pl, Signature: ed25519.Sign(testAdminPriv, in)}}
		}
	}
	goodPayload := func(t *testing.T) []byte {
		b, _ := json.Marshal(adminPayload(t, KindCredentialInstall))
		return b
	}
	cases := []mut{
		{name: "unsigned", check: AdminCheckEnvelope, req: envelope(func(r *CollectorRequest) {
			r.AdminSigned = nil
			r.CredentialInstall = installBody(t)
		})},
		{name: "another algorithm", check: AdminCheckEnvelope, req: envelope(func(r *CollectorRequest) { r.AdminSigned.Algorithm = "none" })},
		{name: "no payload", check: AdminCheckEnvelope, req: envelope(func(r *CollectorRequest) { r.AdminSigned.Payload = nil })},
		{name: "oversize payload", check: AdminCheckEnvelope, req: envelope(func(r *CollectorRequest) {
			r.AdminSigned.Payload = bytes.Repeat([]byte(" "), MaxAdminPayload+1)
		})},
		{name: "short signature", check: AdminCheckEnvelope, req: envelope(func(r *CollectorRequest) { r.AdminSigned.Signature = r.AdminSigned.Signature[:63] })},
		{name: "unknown key", check: AdminCheckKey, req: envelope(func(r *CollectorRequest) { r.AdminSigned.KeyID = "ed25519-0000000000000000" })},
		{name: "revoked key", check: AdminCheckKey, req: signed(nil), keys: func(k []AdminKey) []AdminKey { k[0].Status = KeyRevoked; return k }},
		{name: "key pinned twice", check: AdminCheckKey, req: signed(nil), keys: func(k []AdminKey) []AdminKey { return append(k, k[0]) }},
		{name: "key id not derived from its key", check: AdminCheckKey, req: signed(nil), keys: func(k []AdminKey) []AdminKey {
			k[0].PublicKey = k[1].PublicKey
			return k
		}},
		{name: "key of the wrong size", check: AdminCheckKey, req: signed(nil), keys: func(k []AdminKey) []AdminKey {
			k[0].PublicKey = k[0].PublicKey[:31]
			return k
		}},
		// A key whose ID is derived from it but which is not 32 bytes would
		// make ed25519.Verify panic.
		{name: "short key pinned under its own id", check: AdminCheckKey, req: func(t *testing.T) *CollectorRequest {
			r := signed(nil)(t)
			r.AdminSigned.KeyID = AdminKeyID(testAdminPriv.Public().(ed25519.PublicKey)[:31])
			return r
		}, keys: func(k []AdminKey) []AdminKey {
			short := k[0].PublicKey[:31]
			return append(k, AdminKey{KeyID: AdminKeyID(short), PublicKey: short, Principal: "alice@site-a", Status: KeyActive})
		}},
		{name: "bad signature", check: AdminCheckSignature, req: envelope(func(r *CollectorRequest) { r.AdminSigned.Signature[0] ^= 1 })},
		{name: "sealed secret swapped under a genuine signature", check: AdminCheckSignature, req: envelope(func(r *CollectorRequest) {
			r.AdminSigned.Payload = bytes.Replace(r.AdminSigned.Payload, []byte("AwMDAwMD"), []byte("BAQEBAQE"), 1)
		})},
		{name: "signed by another admin's key under this key id", check: AdminCheckSignature, req: envelope(func(r *CollectorRequest) {
			r.AdminSigned.Signature = ed25519.Sign(testOtherPriv, AdminSigningInput(r.Kind, r.AdminSigned.Payload))
		})},
		{name: "signature for revoke presented as install", check: AdminCheckSignature, req: rawSigned(KindCredentialRevoke, goodPayload, nil)},
		{name: "signature under another contract's prefix", check: AdminCheckSignature, req: rawSigned(KindCredentialInstall, goodPayload, func(pl []byte) []byte {
			return append([]byte("otsec.authz/0.5 admin-request credential.install\n"), pl...)
		})},
		{name: "register-domain signature", check: AdminCheckSignature, req: rawSigned(KindCredentialInstall, goodPayload, RegisterSigningInput)},
		{name: "unknown payload field", check: AdminCheckPayload, req: rawSigned(KindCredentialInstall, func(t *testing.T) []byte {
			return append(goodPayload(t)[:len(goodPayload(t))-1], []byte(`,"extra":1}`)...)
		}, nil)},
		{name: "duplicate payload key", check: AdminCheckPayload, req: rawSigned(KindCredentialInstall, func(t *testing.T) []byte {
			return append(goodPayload(t)[:len(goodPayload(t))-1], []byte(`,"node_id":"site-b-node-1"}`)...)
		}, nil)},
		{name: "another format", check: AdminCheckPayload, req: signed(func(p *AdminRequest) { p.Format = "otsec.authz.admin-request/0.3" })},
		{name: "two bodies", check: AdminCheckPayload, req: signed(func(p *AdminRequest) {
			p.CredentialRevoke = &CredentialRevokeBody{RefID: "cred_7f3k2m9q4x", Reason: RevokeRotated}
		})},
		{name: "no body", check: AdminCheckPayload, req: signed(func(p *AdminRequest) { p.CredentialInstall = nil })},
		{name: "body for another kind", check: AdminCheckPayload, req: signed(func(p *AdminRequest) {
			p.CredentialInstall = nil
			p.CredentialRevoke = &CredentialRevokeBody{RefID: "cred_7f3k2m9q4x", Reason: RevokeRotated}
		})},
		{name: "ref created by someone else", check: AdminCheckPayload, req: signed(func(p *AdminRequest) {
			p.CredentialInstall.Ref.CreatedBy.ID = "mallory@site-a"
		})},
		{name: "a run signed as an admin request", check: AdminCheckPayload, req: rawSigned(KindCredentialInstall, func(t *testing.T) []byte {
			p := adminPayload(t, KindCredentialInstall)
			p.Kind = KindRun
			b, _ := json.Marshal(p)
			return b
		}, nil)},
		{name: "short nonce", check: AdminCheckPayload, req: signed(func(p *AdminRequest) { p.Nonce = "AAECAwQFBgcICQoLDA0O" })},
		// Go's base64 decoder skips CR and LF, so the shape is checked too.
		{name: "nonce with a line break", check: AdminCheckPayload, req: signed(func(p *AdminRequest) { p.Nonce = "AAECAwQFBgcI\nCQoLDA0ODw" })},
		{name: "padded nonce", check: AdminCheckPayload, req: signed(func(p *AdminRequest) { p.Nonce = "AAECAwQFBgcICQoLDA0ODw==" })},
		{name: "time not in UTC", check: AdminCheckPayload, req: signed(func(p *AdminRequest) { p.IssuedAt = "2026-10-26T16:58:00+02:00" })},
		{name: "bad admin key id", check: AdminCheckPayload, req: rawSigned(KindCredentialInstall, func(t *testing.T) []byte {
			p := adminPayload(t, KindCredentialInstall)
			p.AdminKeyID = "ED25519-X"
			b, _ := json.Marshal(p)
			return b
		}, nil)},
		{name: "signed kind differs from the request's", check: AdminCheckBinding, req: rawSigned(KindCredentialInstall, func(t *testing.T) []byte {
			p := adminPayload(t, KindCredentialRevoke)
			b, _ := json.Marshal(p)
			return b
		}, nil)},
		{name: "on_behalf_of is not the signer", check: AdminCheckBinding, req: envelope(func(r *CollectorRequest) { r.OnBehalfOf.ID = "bob@site-a" })},
		{name: "key speaks for another person", check: AdminCheckBinding, req: signed(nil), keys: func(k []AdminKey) []AdminKey {
			k[0].Principal = "carol@site-a"
			return k
		}},
		{name: "admin_key_id is another key", check: AdminCheckBinding, req: func(t *testing.T) *CollectorRequest {
			p := adminPayload(t, KindCredentialInstall)
			p.AdminKeyID = AdminKeyID(testOtherPriv.Public().(ed25519.PublicKey))
			b, _ := json.Marshal(p)
			return rawSigned(KindCredentialInstall, func(*testing.T) []byte { return b }, nil)(t)
		}},
		{name: "another node", check: AdminCheckBinding, req: signed(nil), bind: &AdminBinding{NodeID: "site-b-node-1", InstallKeyID: testAdminBind.InstallKeyID}},
		{name: "another install key", check: AdminCheckBinding, req: signed(nil), bind: &AdminBinding{NodeID: testAdminBind.NodeID, InstallKeyID: "site-a-node-1.collector-install.2"}},
		{name: "issued in the future", check: AdminCheckWindow, req: signed(func(p *AdminRequest) {
			p.IssuedAt, p.ExpiresAt = "2026-10-26T15:02:01Z", "2026-10-26T15:10:00Z"
		})},
		{name: "expired", check: AdminCheckWindow, req: signed(nil), now: time.Date(2026, 10, 26, 15, 8, 0, 0, time.UTC)},
		{name: "expires before it is issued", check: AdminCheckWindow, req: signed(func(p *AdminRequest) {
			p.IssuedAt, p.ExpiresAt = "2026-10-26T15:01:00Z", "2026-10-26T15:01:00Z"
		})},
		{name: "valid for longer than the maximum", check: AdminCheckWindow, req: signed(func(p *AdminRequest) {
			p.IssuedAt, p.ExpiresAt = "2026-10-26T14:50:00Z", "2026-10-26T15:05:01Z"
		})},
		// Within 15 minutes of issued_at, but issued 2 minutes ahead, so
		// more than 15 minutes ahead of the collector's clock.
		{name: "expires too far ahead of the collector's clock", check: AdminCheckWindow, req: signed(func(p *AdminRequest) {
			p.IssuedAt, p.ExpiresAt = "2026-10-26T15:02:00Z", "2026-10-26T15:16:00Z"
		})},
	}
	seenChecks := map[AdminCheck]bool{}
	var details []string
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := roundTrip(t, c.req(t))
			keys, bind, now := testAdminKeys(), testAdminBind, testAdminNow
			if c.keys != nil {
				keys = c.keys(keys)
			}
			if c.bind != nil {
				bind = *c.bind
			}
			if !c.now.IsZero() {
				now = c.now
			}
			got, err := VerifyAdminRequest(req, keys, bind, now)
			var rej *AdminRejected
			if got != nil || !errors.As(err, &rej) || rej.Check != c.check {
				t.Fatalf("got %+v, %v; want check %s", got, err, c.check)
			}
			ref := rej.Refusal()
			if ref.Code != RefuseAdminUnverified || ref.Detail != "admin signature not verified: "+string(c.check) || ref.Check != c.check || ref.Suspension != nil {
				t.Fatalf("refusal %+v", ref)
			}
			if strings.Contains(err.Error(), "AwMDAwMD") || strings.Contains(err.Error(), "BAQEBAQE") {
				t.Fatal("the reason holds the sealed secret")
			}
			seenChecks[c.check] = true
			details = append(details, ref.Detail)
		})
	}
	for _, ch := range AdminChecks {
		if !seenChecks[ch] && ch != AdminCheckReplay && ch != AdminCheckCapacity { // the collector's checks
			t.Errorf("no case for check %s", ch)
		}
	}
}

// Validate admits admin_signed only from 0.4, only for an admin kind, only
// on behalf of a person, and never beside a body.
func TestValidateAdminSigned(t *testing.T) {
	good := func(t *testing.T) *CollectorRequest {
		return signedRequest(t, testAdminPriv, adminPayload(t, KindCredentialInstall))
	}
	for _, c := range []struct {
		name string
		edit func(*CollectorRequest)
		want RefusalCode
	}{
		{"stamped 0.3", func(r *CollectorRequest) { r.Contract = "otsec.authz/0.3" }, RefuseInvalid},
		{"a run", func(r *CollectorRequest) { r.Kind = KindRun }, RefuseInvalid},
		{"beside a body", func(r *CollectorRequest) {
			r.CredentialRevoke = &CredentialRevokeBody{RefID: "cred_7f3k2m9q4x", Reason: RevokeRotated}
		}, RefuseInvalid},
		{"on behalf of the node", func(r *CollectorRequest) { r.OnBehalfOf = Principal{Type: PrincipalNode, ID: "site-a-node-1"} }, RefusePrincipal},
		{"on behalf of a schedule", func(r *CollectorRequest) { r.OnBehalfOf = Principal{Type: PrincipalSchedule, ID: "s1"} }, RefusePrincipal},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := good(t)
			c.edit(r)
			b, _ := json.Marshal(r)
			_, err := DecodeRequest(b)
			var ref *Refusal
			if !errors.As(err, &ref) || ref.Code != c.want {
				t.Fatalf("got %v, want %s", err, c.want)
			}
		})
	}
	// An asset clear signed by an admin is a person's request from 0.4;
	// in the clear it stays the node's.
	r := signedRequest(t, testAdminPriv, adminPayload(t, KindAssetClearSusp))
	if _, err := VerifyAdminRequest(roundTrip(t, r), testAdminKeys(), testAdminBind, testAdminNow); err != nil {
		t.Fatal(err)
	}
	// An unknown key ID or algorithm decodes, so that the verifier refuses
	// it with admin_unverified rather than the decoder with invalid.
	r = good(t)
	r.AdminSigned.KeyID, r.AdminSigned.Algorithm = "not a key id", "rsa"
	if _, err := VerifyAdminRequest(roundTrip(t, r), testAdminKeys(), testAdminBind, testAdminNow); err == nil {
		t.Fatal("verified")
	}
}

func TestSignAdminRequestNeedsItsKeyID(t *testing.T) {
	p := adminPayload(t, KindCredentialRevoke)
	if _, err := SignAdminRequest(testOtherPriv, p); err == nil {
		t.Fatal("signed with a key admin_key_id does not name")
	}
}

func TestAdminKeyID(t *testing.T) {
	id := AdminKeyID(testAdminPriv.Public().(ed25519.PublicKey))
	if !adminKeyIDPattern.MatchString(id) || id == AdminKeyID(testOtherPriv.Public().(ed25519.PublicKey)) {
		t.Fatal(id)
	}
}

// A request stamped before 0.4 does not know admin_unverified.
func TestAdminRefusalForOlderRequests(t *testing.T) {
	r := AdminRefusal(AdminCheckEnvelope)
	for contract, want := range map[string]RefusalCode{
		"otsec.authz/0.4": RefuseAdminUnverified, "otsec.authz/0.5": RefuseAdminUnverified,
		"otsec.authz/0.3": RefusePrincipal, "otsec.authz/0.1": RefusePrincipal,
	} {
		got := r.ForRequest(contract)
		if got.Code != want || got.Detail != r.Detail || (got.Check != "") != (want == RefuseAdminUnverified) {
			t.Errorf("%s: %+v, want %s", contract, got, want)
		}
	}
	if r.Code != RefuseAdminUnverified || r.Check != AdminCheckEnvelope {
		t.Error("ForRequest changed the refusal it was given")
	}
}

// The golden is the one a second implementation (A6's tests, an admin
// client) checks itself against: a fixed test key, payload and signature.
// OTSEC_UPDATE_GOLDEN=1 rewrites it.
func TestAdminSignedGolden(t *testing.T) {
	const path = "testdata/requests/valid/admin-signed-credential-install.json"
	req := signedRequest(t, testAdminPriv, adminPayload(t, KindCredentialInstall))
	// Stamped 0.4, as a 0.4 node sends it: a 0.5 reader decodes and
	// verifies it unchanged.
	req.Contract = "otsec.authz/0.4"
	want, err := json.MarshalIndent(req, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	want = append(want, '\n')
	if os.Getenv("OTSEC_UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile(path, want, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s differs from what the test key signs; rerun with OTSEC_UPDATE_GOLDEN=1 if the change is intended", path)
	}
	dec, err := DecodeRequest(got)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyAdminRequest(dec, testAdminKeys(), testAdminBind, testAdminNow); err != nil {
		t.Fatal(err)
	}
}

// The reply schema's check enum is exactly AdminChecks.
func TestReplySchemaChecks(t *testing.T) {
	raw, err := os.ReadFile("schema/collector-reply.json")
	if err != nil {
		t.Fatal(err)
	}
	var s struct {
		Properties struct {
			Refusal struct {
				Properties struct {
					Check struct{ Enum []AdminCheck }
				}
			}
		}
	}
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatal(err)
	}
	got := s.Properties.Refusal.Properties.Check.Enum
	if len(got) != len(AdminChecks) {
		t.Fatalf("schema checks %v, want %v", got, AdminChecks)
	}
	for i := range got {
		if got[i] != AdminChecks[i] {
			t.Fatalf("schema checks %v, want %v", got, AdminChecks)
		}
	}
}
