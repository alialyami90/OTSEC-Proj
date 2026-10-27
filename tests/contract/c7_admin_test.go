package contract

// C7 0.4 (#146, D2-11, P3-A3): A6's own cases against VerifyAdminRequest
// and the admin-signed golden. Expected outcomes come from the rule text
// (contracts/authz doc.go "Admin-signed requests", D2-11 and the P3-A3
// brief): a node can relay an admin-signed request but can neither
// originate nor change one; a signature for one operation never verifies
// for another; a request is bound to one node and one install key; every
// failure is the same refusal, admin_unverified, naming only the check.
// Keys are A6's own test keys from fixed seeds (D2-5), except the golden's,
// which is derived from the seed its test names and checked against the
// golden's own key ID with A6's derivation. Ground truth: GT-HAND.
//
// Replay after a restart is the collector's check (the nonce is spent
// durably), not the verifier's, which is stateless by design; this file
// checks what the contract owes the collector for it: the nonce is under
// the signature, the verifier returns it, and a request stops verifying at
// its expiry, which bounds how long a spent nonce must be kept. The
// restart case runs against the collector when its PR opens.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"otsec.local/otsec/contracts/authz"
)

func a6Seed(s string) []byte {
	sum := sha256.Sum256([]byte(s))
	return sum[:]
}

var (
	a6AdminPriv = ed25519.NewKeyFromSeed(a6Seed("a6 test admin key alice"))
	a6BobPriv   = ed25519.NewKeyFromSeed(a6Seed("a6 test admin key bob"))
	a6NodePriv  = ed25519.NewKeyFromSeed(a6Seed("a6 test key a compromised node holds"))
	a6Now       = time.Date(2026, 10, 26, 15, 0, 0, 0, time.UTC)
	a6Bind      = authz.AdminBinding{NodeID: "site-a-node-1", InstallKeyID: "site-a-node-1.collector-install.1"}
)

// a6KeyID is the key ID rule as doc.go states it, computed here: "ed25519-"
// and the first 16 hex digits of SHA-256 over the public key.
func a6KeyID(priv ed25519.PrivateKey) string {
	sum := sha256.Sum256(priv.Public().(ed25519.PublicKey))
	return "ed25519-" + hex.EncodeToString(sum[:])[:16]
}

func a6AdminKeys() []authz.AdminKey {
	return []authz.AdminKey{
		{KeyID: a6KeyID(a6AdminPriv), PublicKey: a6AdminPriv.Public().(ed25519.PublicKey), Principal: "alice@site-a", Status: authz.KeyActive},
		{KeyID: a6KeyID(a6BobPriv), PublicKey: a6BobPriv.Public().(ed25519.PublicKey), Principal: "bob@site-a", Status: authz.KeyActive},
	}
}

// a6Input is the signed input as A6 reads it from the golden: the prefix
// "otsec.authz/0.4 admin-request <kind>\n", then the payload's bytes.
func a6Input(kind authz.RequestKind, payload []byte) []byte {
	return append([]byte("otsec.authz/0.4 admin-request "+string(kind)+"\n"), payload...)
}

func a6Golden(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "contracts", "authz", "testdata", "requests", "valid", "admin-signed-credential-install.json"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// a6Payload is the golden's payload, decoded: its install body is the one
// an administrator signs, rebound to A6's alice key.
func a6Payload(t *testing.T, kind authz.RequestKind) map[string]any {
	t.Helper()
	req, err := authz.DecodeRequest(a6Golden(t))
	if err != nil {
		t.Fatal(err)
	}
	var p map[string]any
	if err := json.Unmarshal(req.AdminSigned.Payload, &p); err != nil {
		t.Fatal(err)
	}
	p["admin_key_id"] = a6KeyID(a6AdminPriv)
	p["nonce"] = "a6a6a6a6a6a6a6a6a6a6aw" // 16 bytes, base64url
	install := p["credential_install"]
	delete(p, "credential_install")
	p["kind"] = string(kind)
	switch kind {
	case authz.KindCredentialInstall:
		p["credential_install"] = install
	case authz.KindCredentialRevoke:
		p["credential_revoke"] = map[string]any{"ref_id": "cred_7f3k2m9q4x", "reason": "rotated"}
	case authz.KindCredentialClearSusp:
		p["credential_clear_suspension"] = map[string]any{"ref_id": "cred_7f3k2m9q4x", "version": 2}
	case authz.KindAssetClearSusp:
		p["asset_clear_suspension"] = map[string]any{"asset_id": "2b7d4e10-8c3f-4a5b-9e21-7c4f0d6a8b13", "ref": "6f1c2e8a-0000-4000-8000-0000000000a1"}
	}
	return p
}

func a6JSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// a6Signed signs payload bytes under signKind's prefix and wraps them in a
// request of reqKind, on behalf of alice.
func a6Signed(priv ed25519.PrivateKey, signKind, reqKind authz.RequestKind, payload []byte) *authz.CollectorRequest {
	return &authz.CollectorRequest{Contract: "otsec.authz/0.4", Kind: reqKind, RequestID: "req-a6-0001",
		OnBehalfOf: authz.Principal{Type: authz.PrincipalHuman, ID: "alice@site-a"}, PolicyVersion: 3,
		AdminSigned: &authz.AdminSigned{KeyID: a6KeyID(priv), Algorithm: "ed25519", Payload: payload,
			Signature: ed25519.Sign(priv, a6Input(signKind, payload))}}
}

func a6Check(err error) authz.AdminCheck {
	var r *authz.AdminRejected
	if errors.As(err, &r) {
		return r.Check
	}
	return ""
}

func TestC7AdminGoldenVerifiesIndependently(t *testing.T) {
	raw := a6Golden(t)
	req, err := authz.DecodeRequest(raw)
	if err != nil {
		t.Fatal(err)
	}
	priv := ed25519.NewKeyFromSeed(a6Seed("otsec test admin key 1"))
	if req.AdminSigned.KeyID != a6KeyID(priv) {
		t.Fatalf("golden key id %s, A6 derives %s", req.AdminSigned.KeyID, a6KeyID(priv))
	}
	pub := priv.Public().(ed25519.PublicKey)
	if !ed25519.Verify(pub, a6Input(req.Kind, req.AdminSigned.Payload), req.AdminSigned.Signature) {
		t.Fatal("the golden's signature does not verify over A6's reading of the signed input")
	}
	keys := []authz.AdminKey{{KeyID: a6KeyID(priv), PublicKey: pub, Principal: "alice@site-a", Status: authz.KeyActive}}
	p, err := authz.VerifyAdminRequest(req, keys, a6Bind, a6Now)
	if err != nil {
		t.Fatal(err)
	}
	if p.CredentialInstall == nil || p.CredentialInstall.Sealed.Ciphertext == "" || p.Nonce == "" {
		t.Fatalf("the verified payload carries no sealed secret or nonce: %+v", p)
	}
	// The body travels only inside the signed payload.
	if req.CredentialInstall != nil || strings.Contains(string(raw), `"credential_install"`) {
		t.Fatal("the golden carries a clear body beside the signed one")
	}
}

// A node that holds a genuine signed install cannot put its own guess
// under the signature: changing the sealed secret in any way, or moving
// another request's sealed secret in, fails the signature.
func TestC7AdminSwappedSealedSecret(t *testing.T) {
	keys := a6AdminKeys()
	p := a6Payload(t, authz.KindCredentialInstall)
	good := a6Signed(a6AdminPriv, authz.KindCredentialInstall, authz.KindCredentialInstall, a6JSON(t, p))
	if _, err := authz.VerifyAdminRequest(good, keys, a6Bind, a6Now); err != nil {
		t.Fatal(err)
	}
	other := a6Payload(t, authz.KindCredentialInstall)
	sealed := other["credential_install"].(map[string]any)["sealed"].(map[string]any)
	sealed["ciphertext"] = base64.StdEncoding.EncodeToString([]byte("a6 another secret, sealed......."))
	otherSigned := a6Signed(a6AdminPriv, authz.KindCredentialInstall, authz.KindCredentialInstall, a6JSON(t, other))
	if _, err := authz.VerifyAdminRequest(otherSigned, keys, a6Bind, a6Now); err != nil {
		t.Fatal(err)
	}
	for name, payload := range map[string][]byte{
		"ciphertext from another signed request": a6JSON(t, other),
		"one ciphertext character changed": []byte(strings.Replace(string(good.AdminSigned.Payload),
			`"ciphertext":"A`, `"ciphertext":"B`, 1)),
		"the same JSON, re-encoded with a space": []byte(strings.Replace(string(good.AdminSigned.Payload), `"sealed":{`, `"sealed": {`, 1)),
	} {
		if string(payload) == string(good.AdminSigned.Payload) {
			t.Fatalf("%s: the payload did not change", name)
		}
		swapped := *good
		env := *good.AdminSigned
		env.Payload = payload
		swapped.AdminSigned = &env
		if _, err := authz.VerifyAdminRequest(&swapped, keys, a6Bind, a6Now); a6Check(err) != authz.AdminCheckSignature {
			t.Errorf("%s: got %v, want the signature check", name, err)
		}
	}
	// A clear body beside the signed one is not a request at all.
	both := *good
	both.CredentialInstall = &authz.CredentialInstallBody{}
	if err := both.Validate(); refusalCode(err) != authz.RefuseInvalid {
		t.Errorf("signed and clear body together: %v", err)
	}
	// A node-built install, with no signature, is refused whatever it holds.
	clear := &authz.CollectorRequest{Contract: "otsec.authz/0.4", Kind: authz.KindCredentialInstall, RequestID: "req-a6-0002",
		OnBehalfOf: good.OnBehalfOf, PolicyVersion: 3}
	if _, err := authz.VerifyAdminRequest(clear, keys, a6Bind, a6Now); a6Check(err) != authz.AdminCheckEnvelope {
		t.Errorf("unsigned install: %v", err)
	}
	// A node that signs with its own key, claiming alice's key ID, fails the
	// signature; claiming a key ID of its own fails the key check.
	forged := a6Signed(a6NodePriv, authz.KindCredentialInstall, authz.KindCredentialInstall, a6JSON(t, p))
	if _, err := authz.VerifyAdminRequest(forged, keys, a6Bind, a6Now); a6Check(err) != authz.AdminCheckKey {
		t.Errorf("node's own key: %v", err)
	}
	forged.AdminSigned.KeyID = a6KeyID(a6AdminPriv)
	if _, err := authz.VerifyAdminRequest(forged, keys, a6Bind, a6Now); a6Check(err) != authz.AdminCheckSignature {
		t.Errorf("node's signature under alice's key id: %v", err)
	}
}

var a6AdminKinds = []authz.RequestKind{authz.KindCredentialInstall, authz.KindCredentialRevoke,
	authz.KindCredentialClearSusp, authz.KindAssetClearSusp}

// A signature for one operation never verifies for another: relabelling
// the request fails the signature, and a payload signed under another
// operation's prefix fails the binding. Neither verifies as, or from, a
// register package signature.
func TestC7AdminCrossOperation(t *testing.T) {
	keys := a6AdminKeys()
	for _, signed := range a6AdminKinds {
		payload := a6JSON(t, a6Payload(t, signed))
		if _, err := authz.VerifyAdminRequest(a6Signed(a6AdminPriv, signed, signed, payload), keys, a6Bind, a6Now); err != nil {
			t.Fatalf("%s: %v", signed, err)
		}
		for _, other := range a6AdminKinds {
			if other == signed {
				continue
			}
			relabelled := a6Signed(a6AdminPriv, signed, other, payload)
			if _, err := authz.VerifyAdminRequest(relabelled, keys, a6Bind, a6Now); a6Check(err) != authz.AdminCheckSignature {
				t.Errorf("%s signed, sent as %s: %v, want the signature check", signed, other, err)
			}
			underOther := a6Signed(a6AdminPriv, other, other, payload)
			if _, err := authz.VerifyAdminRequest(underOther, keys, a6Bind, a6Now); a6Check(err) != authz.AdminCheckBinding {
				t.Errorf("%s payload signed under %s's prefix: %v, want the binding check", signed, other, err)
			}
		}
		sig := ed25519.Sign(a6AdminPriv, a6Input(signed, payload))
		if ed25519.Verify(a6AdminPriv.Public().(ed25519.PublicKey), authz.RegisterSigningInput(payload), sig) {
			t.Errorf("%s: an admin signature verifies as a register package's", signed)
		}
		reg := a6Signed(a6AdminPriv, signed, signed, payload)
		reg.AdminSigned.Signature = ed25519.Sign(a6AdminPriv, authz.RegisterSigningInput(payload))
		if _, err := authz.VerifyAdminRequest(reg, keys, a6Bind, a6Now); a6Check(err) != authz.AdminCheckSignature {
			t.Errorf("%s: a register signature by an admin key: %v", signed, err)
		}
		bare := a6Signed(a6AdminPriv, signed, signed, payload)
		bare.AdminSigned.Signature = ed25519.Sign(a6AdminPriv, payload)
		if _, err := authz.VerifyAdminRequest(bare, keys, a6Bind, a6Now); a6Check(err) != authz.AdminCheckSignature {
			t.Errorf("%s: a signature over the payload alone: %v", signed, err)
		}
	}
	// Only the four admin kinds take an envelope.
	run := a6Signed(a6AdminPriv, authz.KindCredentialInstall, authz.KindRun, a6JSON(t, a6Payload(t, authz.KindCredentialInstall)))
	if err := run.Validate(); refusalCode(err) != authz.RefuseInvalid {
		t.Errorf("admin_signed on a run request: %v", err)
	}
}

// A request is bound to one node and one install key; a genuine request
// for another node, or for this node before its install key rotated, is
// refused. So are the principal mismatches a node could try.
func TestC7AdminWrongNode(t *testing.T) {
	keys := a6AdminKeys()
	for name, c := range map[string]struct {
		edit func(map[string]any)
		bind authz.AdminBinding
		obo  string
		want authz.AdminCheck
	}{
		"signed for another node":                {func(p map[string]any) { p["node_id"] = "site-b-node-1" }, a6Bind, "", authz.AdminCheckBinding},
		"genuine, presented to another node":     {nil, authz.AdminBinding{NodeID: "site-b-node-1", InstallKeyID: a6Bind.InstallKeyID}, "", authz.AdminCheckBinding},
		"signed for the old install key":         {nil, authz.AdminBinding{NodeID: a6Bind.NodeID, InstallKeyID: "site-a-node-1.collector-install.2"}, "", authz.AdminCheckBinding},
		"signed for another node's install key":  {func(p map[string]any) { p["install_key_id"] = "site-b-node-1.collector-install.1" }, a6Bind, "", authz.AdminCheckBinding},
		"node relays it on behalf of bob":        {nil, a6Bind, "bob@site-a", authz.AdminCheckBinding},
		"payload claims bob under alice's key":   {func(p map[string]any) { p["principal"] = map[string]any{"type": "human", "id": "bob@site-a"} }, a6Bind, "bob@site-a", authz.AdminCheckBinding},
		"admin_key_id names bob, alice signs":    {func(p map[string]any) { p["admin_key_id"] = a6KeyID(a6BobPriv) }, a6Bind, "", authz.AdminCheckBinding},
		"collector with no binding configured":   {nil, authz.AdminBinding{}, "", authz.AdminCheckBinding},
		"node_id empty in the signed payload":    {func(p map[string]any) { p["node_id"] = "" }, a6Bind, "", authz.AdminCheckPayload},
		"install_key_id empty in signed payload": {func(p map[string]any) { p["install_key_id"] = "" }, a6Bind, "", authz.AdminCheckPayload},
	} {
		p := a6Payload(t, authz.KindCredentialRevoke)
		if c.edit != nil {
			c.edit(p)
		}
		req := a6Signed(a6AdminPriv, authz.KindCredentialRevoke, authz.KindCredentialRevoke, a6JSON(t, p))
		if c.obo != "" {
			req.OnBehalfOf.ID = c.obo
		}
		if _, err := authz.VerifyAdminRequest(req, keys, c.bind, a6Now); a6Check(err) != c.want {
			t.Errorf("%s: got %v, want %s", name, err, c.want)
		}
	}
}

// What the contract owes the collector's replay check: the nonce is under
// the signature, so a relaying node cannot refresh it; the verifier hands
// it back for spending; and a request stops verifying at its expiry, never
// more than MaxAdminLifetime after the collector's now, so a spent nonce
// need be kept only that long, across restarts included.
func TestC7AdminReplayNeedsTheSignedNonce(t *testing.T) {
	keys := a6AdminKeys()
	p := a6Payload(t, authz.KindCredentialClearSusp)
	req := a6Signed(a6AdminPriv, authz.KindCredentialClearSusp, authz.KindCredentialClearSusp, a6JSON(t, p))
	got, err := authz.VerifyAdminRequest(req, keys, a6Bind, a6Now)
	if err != nil || got.Nonce != p["nonce"] {
		t.Fatalf("verified nonce %v, err %v", got, err)
	}
	// The verifier is stateless: the same bytes verify again, which is
	// why the collector must spend the nonce before any decision.
	if _, err := authz.VerifyAdminRequest(req, keys, a6Bind, a6Now.Add(time.Minute)); err != nil {
		t.Fatalf("second verification inside the window: %v", err)
	}
	fresh := *req
	env := *req.AdminSigned
	env.Payload = []byte(strings.Replace(string(env.Payload), p["nonce"].(string), "b6b6b6b6b6b6b6b6b6b6bw", 1))
	fresh.AdminSigned = &env
	if _, err := authz.VerifyAdminRequest(&fresh, keys, a6Bind, a6Now); a6Check(err) != authz.AdminCheckSignature {
		t.Errorf("nonce changed under the signature: %v", err)
	}
	expires, _ := time.Parse(time.RFC3339, p["expires_at"].(string))
	if _, err := authz.VerifyAdminRequest(req, keys, a6Bind, expires); a6Check(err) != authz.AdminCheckWindow {
		t.Errorf("at its expiry: %v", err)
	}
	// Window edges, from the rule text: issued at most 2 min ahead; valid
	// for at most 15 min from issued_at and from now.
	issued, _ := time.Parse(time.RFC3339, p["issued_at"].(string))
	for name, c := range map[string]struct {
		issued, expires time.Time
		now             time.Time
		ok              bool
	}{
		"issued exactly 2 min ahead":        {a6Now.Add(2 * time.Minute), a6Now.Add(10 * time.Minute), a6Now, true},
		"issued 2 min 1 s ahead":            {a6Now.Add(2*time.Minute + time.Second), a6Now.Add(10 * time.Minute), a6Now, false},
		"valid exactly 15 min":              {issued, issued.Add(15 * time.Minute), a6Now, true},
		"valid 15 min 1 s":                  {issued, issued.Add(15*time.Minute + time.Second), a6Now, false},
		"expires 15 min 1 s after now":      {a6Now.Add(time.Minute), a6Now.Add(15*time.Minute + time.Second), a6Now, false},
		"expires before issued":             {issued, issued.Add(-time.Second), a6Now, false},
		"one second before expiry":          {issued, issued.Add(10 * time.Minute), issued.Add(10*time.Minute - time.Second), true},
		"collector clock 1 h behind issued": {issued, issued.Add(10 * time.Minute), issued.Add(-time.Hour), false},
	} {
		q := a6Payload(t, authz.KindCredentialClearSusp)
		q["issued_at"] = c.issued.UTC().Format(time.RFC3339)
		q["expires_at"] = c.expires.UTC().Format(time.RFC3339)
		r := a6Signed(a6AdminPriv, authz.KindCredentialClearSusp, authz.KindCredentialClearSusp, a6JSON(t, q))
		_, err := authz.VerifyAdminRequest(r, keys, a6Bind, c.now)
		if c.ok != (err == nil) || (!c.ok && a6Check(err) != authz.AdminCheckWindow) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if r := authz.AdminRefusal(authz.AdminCheckReplay); r.Code != authz.RefuseAdminUnverified || r.Check != authz.AdminCheckReplay {
		t.Errorf("replay refusal: %+v", r)
	}
}

// No equality leak: every refusal is admin_unverified with a detail that
// names the check and nothing from the request, and requests that differ
// only in the secret they carry get byte-identical replies.
func TestC7AdminNoEqualityLeak(t *testing.T) {
	keys := a6AdminKeys()
	install := func(secret string) *authz.CollectorRequest {
		p := a6Payload(t, authz.KindCredentialInstall)
		p["credential_install"].(map[string]any)["sealed"].(map[string]any)["ciphertext"] = base64.StdEncoding.EncodeToString([]byte(secret))
		return a6Signed(a6NodePriv, authz.KindCredentialInstall, authz.KindCredentialInstall, a6JSON(t, p))
	}
	reply := func(req *authz.CollectorRequest, edit func(*authz.CollectorRequest)) (authz.AdminCheck, string) {
		if edit != nil {
			edit(req)
		}
		_, err := authz.VerifyAdminRequest(req, keys, a6Bind, a6Now)
		var rej *authz.AdminRejected
		if !errors.As(err, &rej) {
			t.Fatalf("not an AdminRejected: %v", err)
		}
		return rej.Check, string(a6JSON(t, rej.Refusal()))
	}
	edits := map[authz.AdminCheck]func(*authz.CollectorRequest){
		authz.AdminCheckEnvelope:  func(r *authz.CollectorRequest) { r.AdminSigned.Algorithm = "ecdsa" },
		authz.AdminCheckKey:       nil, // the node's own key
		authz.AdminCheckSignature: func(r *authz.CollectorRequest) { r.AdminSigned.KeyID = a6KeyID(a6AdminPriv) },
	}
	for check, edit := range edits {
		guess1, right := install("a6 guess one....................."), install("a6 the stored secret, sealed....")
		c1, r1 := reply(guess1, edit)
		c2, r2 := reply(right, edit)
		if c1 != check || c2 != check {
			t.Fatalf("%s: checks %s and %s", check, c1, c2)
		}
		if r1 != r2 {
			t.Errorf("%s: replies differ by the secret: %s / %s", check, r1, r2)
		}
		want := `{"code":"admin_unverified","detail":"admin signature not verified: ` + string(check) + `","check":"` + string(check) + `"}`
		if r1 != want {
			t.Errorf("%s: reply %s, want %s", check, r1, want)
		}
	}
	for _, check := range authz.AdminChecks {
		r := authz.AdminRefusal(check)
		if r.Code != authz.RefuseAdminUnverified || r.Detail != "admin signature not verified: "+string(check) || r.Check != check || r.Suspension != nil {
			t.Errorf("%s: %+v", check, r)
		}
		old := r.ForRequest("otsec.authz/0.3")
		if old.Code != authz.RefusePrincipal || old.Check != "" {
			t.Errorf("%s for a 0.3 request: %+v", check, old)
		}
		if old.Code == authz.RefuseSecretRejected || r.Code == authz.RefuseSecretRejected {
			t.Errorf("%s: secret_rejected before the signature verified", check)
		}
	}
}

// The signed payload is decoded strictly, after the signature: a field the
// contract does not name, a key given twice, two bodies, or a body for
// another kind are payload failures even under a good signature.
func TestC7AdminPayloadIsStrict(t *testing.T) {
	keys := a6AdminKeys()
	base := string(a6JSON(t, a6Payload(t, authz.KindCredentialRevoke)))
	for name, payload := range map[string]string{
		"unknown field":          strings.Replace(base, `{"admin_key_id"`, `{"a6_extra":1,"admin_key_id"`, 1),
		"node_id given twice":    strings.Replace(base, `{"admin_key_id"`, `{"node_id":"site-b-node-1","admin_key_id"`, 1),
		"two bodies":             strings.Replace(base, `{"admin_key_id"`, `{"credential_clear_suspension":{"ref_id":"cred_7f3k2m9q4x","version":2},"admin_key_id"`, 1),
		"format 0.3":             strings.Replace(base, "admin-request/0.4", "admin-request/0.3", 1),
		"time with an offset":    strings.Replace(base, `:00Z"`, `:00+00:00"`, 1),
		"nonce of 15 bytes":      strings.Replace(base, "a6a6a6a6a6a6a6a6a6a6aw", "a6a6a6a6a6a6a6a6a6a6", 1),
		"trailing data":          base + " {}",
		"payload is a JSON list": "[" + base + "]",
	} {
		if payload == base {
			t.Fatalf("%s: no change", name)
		}
		req := a6Signed(a6AdminPriv, authz.KindCredentialRevoke, authz.KindCredentialRevoke, []byte(payload))
		if _, err := authz.VerifyAdminRequest(req, keys, a6Bind, a6Now); a6Check(err) != authz.AdminCheckPayload {
			t.Errorf("%s: got %v, want the payload check", name, err)
		}
	}
	revoked := a6AdminKeys()
	revoked[0].Status = authz.KeyRevoked
	twice := append(a6AdminKeys(), a6AdminKeys()[0])
	misnamed := a6AdminKeys()
	misnamed[0].KeyID, misnamed[1].KeyID = misnamed[1].KeyID, misnamed[0].KeyID
	req := a6Signed(a6AdminPriv, authz.KindCredentialRevoke, authz.KindCredentialRevoke, []byte(base))
	for name, k := range map[string][]authz.AdminKey{"revoked": revoked, "pinned twice": twice, "id not derived from the key": misnamed, "none pinned": nil} {
		if _, err := authz.VerifyAdminRequest(req, k, a6Bind, a6Now); a6Check(err) != authz.AdminCheckKey {
			t.Errorf("key %s: %v", name, err)
		}
	}
}
