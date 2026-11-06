package authz

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

func testUSM() *USM {
	return &USM{UserName: "otsec-ro", Auth: USMAuthHMACSHA512, Priv: USMPrivAES128,
		EngineID: "80007c4f03020000273101", SoleDeviceAttested: true}
}

// snmpInstall is the 0.1 golden's install body moved to an snmpv3 endpoint.
func snmpInstall(t *testing.T) *CredentialInstallBody {
	t.Helper()
	b := installBody(t)
	b.Ref.EndpointID, b.Ref.Transport, b.Ref.AccessLevel = "mgmt-snmp", TransportSNMPv3, ""
	b.Ref.DownstreamSecurity, b.Ref.PlaintextScope, b.Ref.USM = DownstreamEncryptedAuthenticated, "", testUSM()
	b.Sealed.Ciphertext = base64.StdEncoding.EncodeToString(make([]byte, USMSecretLen(testUSM())+16))
	return b
}

func TestSNMPv3Credential(t *testing.T) {
	if err := snmpInstall(t).Ref.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := snmpInstall(t).Sealed.Validate(); err != nil {
		t.Fatalf("an 80-byte key pair, sealed: %v", err)
	}
	for name, mut := range map[string]func(r *CredentialRef){
		"no usm":                  func(r *CredentialRef) { r.USM = nil },
		"an access level":         func(r *CredentialRef) { r.AccessLevel = "1" },
		"labelled weak":           func(r *CredentialRef) { r.DownstreamSecurity = DownstreamEncryptedWeak },
		"labelled plaintext":      func(r *CredentialRef) { r.DownstreamSecurity = DownstreamPlaintext },
		"a plaintext scope":       func(r *CredentialRef) { r.PlaintextScope = PlaintextLabOnly },
		"empty user":              func(r *CredentialRef) { r.USM.UserName = "" },
		"user over 32":            func(r *CredentialRef) { r.USM.UserName = strings.Repeat("u", 33) },
		"user with a space":       func(r *CredentialRef) { r.USM.UserName = "otsec ro" },
		"hmac-md5":                func(r *CredentialRef) { r.USM.Auth = "hmac-md5" },
		"hmac-sha-1":              func(r *CredentialRef) { r.USM.Auth = "hmac-sha-1" },
		"hmac-sha-384":            func(r *CredentialRef) { r.USM.Auth = "hmac-sha-384" },
		"des":                     func(r *CredentialRef) { r.USM.Priv = "des" },
		"aes-256":                 func(r *CredentialRef) { r.USM.Priv = "aes-256" },
		"no privacy":              func(r *CredentialRef) { r.USM.Priv = "" },
		"engine id of 4 octets":   func(r *CredentialRef) { r.USM.EngineID = "80007c4f" },
		"engine id of 33 octets":  func(r *CredentialRef) { r.USM.EngineID = strings.Repeat("ab", 33) },
		"engine id odd length":    func(r *CredentialRef) { r.USM.EngineID = "80007c4f030" },
		"engine id upper case":    func(r *CredentialRef) { r.USM.EngineID = "80007C4F03020000273101" },
		"engine id all zeros":     func(r *CredentialRef) { r.USM.EngineID = "0000000000" },
		"engine id all ff":        func(r *CredentialRef) { r.USM.EngineID = strings.Repeat("ff", 32) },
		"no attestation":          func(r *CredentialRef) { r.USM.SoleDeviceAttested = false },
		"snmpv2c is no transport": func(r *CredentialRef) { r.Transport = "snmpv2c" },
		"snmpv1 is no transport":  func(r *CredentialRef) { r.Transport = "snmpv1" },
	} {
		b := snmpInstall(t)
		mut(&b.Ref)
		if err := b.Ref.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	near := snmpInstall(t)
	near.Ref.USM.EngineID = "00000000ff" // neither all zeros nor all ff
	if err := near.Ref.Validate(); err != nil {
		t.Errorf("engine id 00000000ff: %v", err)
	}
	telnet := installBody(t)
	telnet.Ref.USM = testUSM()
	if err := telnet.Ref.Validate(); err == nil {
		t.Error("usm on a telnet credential accepted")
	}
	if TransportSNMPv3.Plaintext() {
		t.Error("snmpv3 reported as plaintext")
	}
}

// The AAD binds the localized keys to the user, protocols and engine ID, and
// leaves every other transport's AAD as it was.
func TestSealAADBindsUSM(t *testing.T) {
	telnet := installBody(t).Ref
	if bytes.Contains(SealAAD(telnet), []byte("usm_")) {
		t.Fatal("a telnet credential's AAD changed")
	}
	a := snmpInstall(t).Ref
	for name, mut := range map[string]func(u *USM){
		"engine id": func(u *USM) { u.EngineID = "80007c4f03020000273102" },
		"auth":      func(u *USM) { u.Auth = USMAuthHMACSHA256 },
		"user":      func(u *USM) { u.UserName = "other" },
	} {
		b := snmpInstall(t).Ref
		mut(b.USM)
		if bytes.Equal(SealAAD(a), SealAAD(b)) {
			t.Errorf("%s: the AAD does not bind it", name)
		}
	}
}

func TestSplitUSMSecret(t *testing.T) {
	key := func(n int) []byte { return bytes.Repeat([]byte{0x5a}, n) }
	for _, auth := range []USMAuth{USMAuthHMACSHA256, USMAuthHMACSHA512} {
		u := testUSM()
		u.Auth = auth
		n := USMSecretLen(u)
		if n != auth.KeyLen()+16 {
			t.Fatalf("%s: USMSecretLen %d", auth, n)
		}
		a, p, err := SplitUSMSecret(key(n), u)
		if err != nil || len(a) != auth.KeyLen() || len(p) != 16 {
			t.Fatalf("%s: %d, %d, %v", auth, len(a), len(p), err)
		}
		for name, s := range map[string][]byte{
			"short":         key(n - 1),
			"long":          key(n + 1),
			"zero auth key": append(make([]byte, auth.KeyLen()), key(16)...),
			"zero priv key": append(key(auth.KeyLen()), make([]byte, 16)...),
		} {
			if _, _, err := SplitUSMSecret(s, u); !errors.Is(err, ErrUSMSecretRejected) {
				t.Errorf("%s %s: got %v", auth, name, err)
			}
		}
	}
	if USMSecretLen(testUSM()) != MaxSealedLen {
		t.Fatal("MaxSealedLen is not the longest key pair")
	}
	sealed := snmpInstall(t).Sealed
	sealed.Ciphertext = base64.StdEncoding.EncodeToString(make([]byte, MaxSealedLen+17))
	if sealed.Validate() == nil {
		t.Fatal("a ciphertext over MaxSealedLen accepted")
	}
}

// An snmpv3 credential needs a request stamped 0.8 or later, in the clear
// and admin-signed.
func TestSNMPv3NeedsZeroPointEight(t *testing.T) {
	clear := func(contract string) *CollectorRequest {
		b := snmpInstall(t)
		b.Ref.CreatedBy = Principal{Type: PrincipalHuman, ID: "alice@site-a"}
		return &CollectorRequest{Contract: contract, Kind: KindCredentialInstall, RequestID: "req-20261105-0001",
			OnBehalfOf: b.Ref.CreatedBy, PolicyVersion: 3, CredentialInstall: b}
	}
	if err := clear(ContractID).Validate(); err != nil {
		t.Fatalf("0.8: %v", err)
	}
	if err := clear("otsec.authz/0.7").Validate(); err == nil {
		t.Fatal("an snmpv3 install stamped 0.7 accepted")
	}

	p := adminPayload(t, KindCredentialInstall)
	p.CredentialInstall = snmpInstall(t)
	p.CredentialInstall.Ref.CreatedBy = p.Principal
	req := signedRequest(t, testAdminPriv, p)
	if _, err := VerifyAdminRequest(roundTrip(t, req), testAdminKeys(), testAdminBind, testAdminNow); err != nil {
		t.Fatalf("admin-signed 0.8: %v", err)
	}
	req.Contract = "otsec.authz/0.7"
	if _, err := VerifyAdminRequest(roundTrip(t, req), testAdminKeys(), testAdminBind, testAdminNow); err == nil {
		t.Fatal("an admin-signed snmpv3 install stamped 0.7 accepted")
	}
}
