package seal

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/authz"
)

// testSecret is a test value (D2-5), never a device password.
var testSecret = []byte("t3st-Secr3t!")

func testRef() authz.CredentialRef {
	return authz.CredentialRef{
		ID:                 "cred_slice0001",
		AssetID:            "6f1c2d3e-4a5b-4c6d-8e7f-001122334455",
		NodeID:             "site-a-node1",
		EndpointID:         "telnet0",
		Transport:          authz.TransportTelnet,
		Purpose:            authz.PurposeCollectReadOnly,
		AccessLevel:        "1",
		DownstreamSecurity: authz.DownstreamPlaintext,
		PlaintextScope:     authz.PlaintextLabOnly,
		Version:            1,
		CreatedBy:          authz.Principal{Type: authz.PrincipalHuman, ID: "admin@site-a"},
		CreatedAt:          "2026-10-24T12:00:00Z",
	}
}

func newKey(t *testing.T) (*ecdh.PrivateKey, InstallKey) {
	t.Helper()
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.PublicKey().Bytes()
	return priv, InstallKey{KeyID: KeyID(pub), PublicKey: base64.StdEncoding.EncodeToString(pub)}
}

func TestSealOpenRoundTrip(t *testing.T) {
	priv, key := newKey(t)
	ref := testRef()
	s, err := Seal(key, Fingerprint(priv.PublicKey().Bytes()), ref, testSecret, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	got, err := Open(priv, ref, s)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, testSecret) {
		t.Fatal("round trip changed the secret")
	}
	for _, f := range []string{s.EphemeralPublicKey, s.Nonce, s.Ciphertext, s.RecipientKeyID} {
		if strings.Contains(f, string(testSecret)) {
			t.Fatal("sealed envelope holds the plaintext")
		}
	}
}

// T-12: the client refuses to seal without a pinned fingerprint, or with one
// that does not match the published key.
func TestSealRefusesUnpinnedKey(t *testing.T) {
	priv, key := newKey(t)
	_, other := newKey(t)
	otherPub, _ := other.PublicKeyBytes()
	good := Fingerprint(priv.PublicKey().Bytes())
	cases := []struct {
		name   string
		key    InstallKey
		pinned string
		want   error
	}{
		{"no pin", key, "", ErrNoPinnedFingerprint},
		{"blank pin", key, "   ", ErrNoPinnedFingerprint},
		{"pin of another key", key, Fingerprint(otherPub), ErrFingerprintMismatch},
		{"substituted key", other, good, ErrFingerprintMismatch},
		{"not a fingerprint", key, "sha256:abcd", ErrFingerprintMismatch},
		{"no prefix", key, strings.TrimPrefix(good, "sha256:"), ErrFingerprintMismatch},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Seal(c.key, c.pinned, testRef(), testSecret, nil)
			if !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
		})
	}
	// The admin may copy the fingerprint with colons, spaces or capitals.
	hexPart := strings.TrimPrefix(good, "sha256:")
	var grouped []string
	for i := 0; i < len(hexPart); i += 2 {
		grouped = append(grouped, strings.ToUpper(hexPart[i:i+2]))
	}
	if _, err := Seal(key, "SHA256: "+strings.Join(grouped, ":"), testRef(), testSecret, nil); err != nil {
		t.Fatalf("grouped fingerprint: %v", err)
	}
}

func TestSealRefusesBadInput(t *testing.T) {
	priv, key := newKey(t)
	pin := Fingerprint(priv.PublicKey().Bytes())
	wrongID := key
	wrongID.KeyID = "x25519-0000000000000000"
	if _, err := Seal(wrongID, pin, testRef(), testSecret, nil); err == nil {
		t.Error("key id not derived from the key was accepted")
	}
	if _, err := Seal(key, pin, testRef(), nil, nil); err == nil {
		t.Error("empty secret was sealed")
	}
	if _, err := Seal(key, pin, testRef(), bytes.Repeat([]byte("a"), authz.MaxSecretLen+1), nil); err == nil {
		t.Error("oversize secret was sealed")
	}
	bad := testRef()
	bad.Transport = authz.TransportSerial
	if _, err := Seal(key, pin, bad, testSecret, nil); err == nil {
		t.Error("invalid reference was sealed for")
	}
	lowOrder := InstallKey{PublicKey: base64.StdEncoding.EncodeToString(make([]byte, 32))}
	lowOrder.KeyID = KeyID(make([]byte, 32))
	if _, err := Seal(lowOrder, Fingerprint(make([]byte, 32)), testRef(), testSecret, nil); err == nil {
		t.Error("all-zero public key was accepted")
	}
}

// T-4 at the sealing layer: a sealed secret opens only for the reference it
// was sealed for, and only with the recipient's key.
func TestOpenBindsReference(t *testing.T) {
	priv, key := newKey(t)
	otherPriv, _ := newKey(t)
	ref := testRef()
	s, err := Seal(key, Fingerprint(priv.PublicKey().Bytes()), ref, testSecret, nil)
	if err != nil {
		t.Fatal(err)
	}
	mutate := map[string]func(*authz.CredentialRef){
		"id":           func(r *authz.CredentialRef) { r.ID = "cred_slice0002" },
		"version":      func(r *authz.CredentialRef) { r.Version = 2 },
		"asset":        func(r *authz.CredentialRef) { r.AssetID = "6f1c2d3e-4a5b-4c6d-8e7f-001122334466" },
		"node":         func(r *authz.CredentialRef) { r.NodeID = "site-a-node2" },
		"endpoint":     func(r *authz.CredentialRef) { r.EndpointID = "telnet1" },
		"transport":    func(r *authz.CredentialRef) { r.Transport = authz.TransportSSH },
		"access level": func(r *authz.CredentialRef) { r.AccessLevel = "2" },
	}
	for name, m := range mutate {
		r := ref
		m(&r)
		if _, err := Open(priv, r, s); !errors.Is(err, ErrOpen) {
			t.Errorf("%s: opened for another reference (%v)", name, err)
		}
	}
	if _, err := Open(otherPriv, ref, s); !errors.Is(err, ErrOpen) {
		t.Error("opened with another collector's key")
	}
	tampered := s
	ct, _ := base64.StdEncoding.DecodeString(s.Ciphertext)
	ct[0] ^= 1
	tampered.Ciphertext = base64.StdEncoding.EncodeToString(ct)
	if _, err := Open(priv, ref, tampered); !errors.Is(err, ErrOpen) {
		t.Error("tampered ciphertext opened")
	}
	swapped := s
	_, k2 := newKey(t)
	swapped.EphemeralPublicKey = k2.PublicKey
	if _, err := Open(priv, ref, swapped); !errors.Is(err, ErrOpen) {
		t.Error("ciphertext opened under another ephemeral key")
	}
	if _, err := Open(nil, ref, s); !errors.Is(err, ErrOpen) {
		t.Error("opened without a key")
	}
}

func TestNormalizeFingerprint(t *testing.T) {
	fp := Fingerprint([]byte("k"))
	for in, want := range map[string]string{
		fp:                                  fp,
		strings.ToUpper(fp):                 fp,
		" " + fp + " ":                      fp,
		"sha1:" + fp[7:]:                    "",
		"sha256:" + fp[7:70]:                "",
		"sha256:" + strings.Repeat("g", 64): "",
	} {
		if got := NormalizeFingerprint(in); got != want {
			t.Errorf("NormalizeFingerprint(%q) = %q, want %q", in, got, want)
		}
	}
}

func FuzzOpen(f *testing.F) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	pub := priv.PublicKey().Bytes()
	key := InstallKey{KeyID: KeyID(pub), PublicKey: base64.StdEncoding.EncodeToString(pub)}
	s, err := Seal(key, Fingerprint(pub), testRef(), testSecret, nil)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(s.EphemeralPublicKey, s.Nonce, s.Ciphertext)
	f.Fuzz(func(t *testing.T, eph, nonce, ct string) {
		in := s
		in.EphemeralPublicKey, in.Nonce, in.Ciphertext = eph, nonce, ct
		pt, err := Open(priv, testRef(), in)
		if err == nil && (eph != s.EphemeralPublicKey || nonce != s.Nonce || ct != s.Ciphertext) {
			t.Fatalf("a changed envelope opened to %d bytes", len(pt))
		}
	})
}
