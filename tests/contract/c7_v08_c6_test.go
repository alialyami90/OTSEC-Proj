package contract

// C7 0.8 (otsec.authz/0.8, docs/phase4/C3-c11-advisory.md section 2.1,
// D4-49 Q1 to Q3, D4-53): C6's own cases for the snmpv3 credential.
// Expected outcomes come from the rule text, not from the code. Requests are
// built from C7's credential.install golden by editing its JSON; every
// value is invented, and no key is real. Ground truth: GT-HAND. Evidence
// class: desk.
//
// What is checked here that C3's per-package tests do not see: the
// credential as the collector decodes it off the wire (DecodeRequest, so
// no field for another security level or a password can ride in, and every
// refusal carries a C7 code); the engine ID read by one rule in C7 and in
// C1 0.3, since the collector compares the two (HR-16); and an snmpv3
// credential bound to nothing but its own use.

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/authz"
)

const c7EngineID = "80007c4f03020000273101"

// c7SNMPInstall is C7's credential.install golden moved to an snmpv3
// endpoint at 0.8, with edit applied to its JSON.
func c7SNMPInstall(t *testing.T, edit func(m map[string]any)) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "contracts", "authz", "testdata", "requests", "valid", "credential-install.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	m["contract"] = "otsec.authz/0.8"
	ci := m["credential_install"].(map[string]any)
	ref := ci["ref"].(map[string]any)
	ref["endpoint_id"], ref["transport"], ref["downstream_security"] = "mgmt-snmpv3", "snmpv3", "encrypted-authenticated"
	delete(ref, "access_level")
	delete(ref, "plaintext_scope")
	ref["usm"] = map[string]any{"user_name": "otsec-ro", "auth": "hmac-sha-512", "priv": "aes-128",
		"engine_id": c7EngineID, "sole_device_attested": true}
	// 64 + 16 bytes of localized keys, and the 16-byte tag.
	ci["sealed"].(map[string]any)["ciphertext"] = base64.StdEncoding.EncodeToString(make([]byte, 64+16+16))
	if edit != nil {
		edit(m)
	}
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func c7Ref(m map[string]any) map[string]any {
	return m["credential_install"].(map[string]any)["ref"].(map[string]any)
}

func c7USM(m map[string]any) map[string]any { return c7Ref(m)["usm"].(map[string]any) }

func TestC7V08SNMPv3InstallOnTheWire(t *testing.T) {
	req, err := authz.DecodeRequest(c7SNMPInstall(t, nil))
	if err != nil {
		t.Fatalf("the snmpv3 install: %v", err)
	}
	ref := req.CredentialInstall.Ref
	if ref.Transport != authz.TransportSNMPv3 || ref.USM == nil || ref.USM.EngineID != c7EngineID {
		t.Fatalf("decoded %+v", ref)
	}
	// 2.1: authPriv only, with no field for another level; the localized
	// keys, never a password; the strong algorithms only; the engine ID
	// pinned; one password per device, attested; collect-readonly; no v1 or
	// v2c (D4-49 Q3); and the transport only from 0.8.
	for name, edit := range map[string]func(m map[string]any){
		"at 0.7":                         func(m map[string]any) { m["contract"] = "otsec.authz/0.7" },
		"a security level field":         func(m map[string]any) { c7USM(m)["security_level"] = "authNoPriv" },
		"a level field saying authPriv":  func(m map[string]any) { c7USM(m)["level"] = "authPriv" },
		"an authentication password":     func(m map[string]any) { c7USM(m)["auth_password"] = "invented-password" },
		"a privacy password":             func(m map[string]any) { c7USM(m)["priv_password"] = "invented-password" },
		"a community":                    func(m map[string]any) { c7Ref(m)["community"] = "public" },
		"hmac-md5":                       func(m map[string]any) { c7USM(m)["auth"] = "hmac-md5" },
		"hmac-sha-1":                     func(m map[string]any) { c7USM(m)["auth"] = "hmac-sha-1" },
		"des":                            func(m map[string]any) { c7USM(m)["priv"] = "des" },
		"aes-256":                        func(m map[string]any) { c7USM(m)["priv"] = "aes-256" },
		"no privacy protocol":            func(m map[string]any) { delete(c7USM(m), "priv") },
		"no engine id":                   func(m map[string]any) { delete(c7USM(m), "engine_id") },
		"not attested":                   func(m map[string]any) { c7USM(m)["sole_device_attested"] = false },
		"no usm":                         func(m map[string]any) { delete(c7Ref(m), "usm") },
		"usm on a telnet credential":     func(m map[string]any) { c7Ref(m)["transport"] = "telnet" },
		"snmpv2c":                        func(m map[string]any) { c7Ref(m)["transport"] = "snmpv2c" },
		"snmpv1":                         func(m map[string]any) { c7Ref(m)["transport"] = "snmpv1" },
		"labelled encrypted-weak":        func(m map[string]any) { c7Ref(m)["downstream_security"] = "encrypted-weak" },
		"labelled plaintext":             func(m map[string]any) { c7Ref(m)["downstream_security"] = "plaintext-unauthenticated" },
		"a plaintext scope":              func(m map[string]any) { c7Ref(m)["plaintext_scope"] = "lab-only" },
		"an owner-approved scope":        func(m map[string]any) { c7Ref(m)["plaintext_scope"] = "owner-approved" },
		"an access level":                func(m map[string]any) { c7Ref(m)["access_level"] = "1" },
		"another purpose":                func(m map[string]any) { c7Ref(m)["purpose"] = "engineering" },
		"the legacy approval kind (2.2)": func(m map[string]any) { m["kind"] = "asset.legacy_snmp_approval" },
	} {
		_, err := authz.DecodeRequest(c7SNMPInstall(t, edit))
		var r *authz.Refusal
		if err == nil || !errors.As(err, &r) {
			t.Errorf("%s: got %v, want a refusal", name, err)
		}
	}
	// A key spelled twice, the weak value first, is refused, so a reader of
	// the first spelling cannot see MD5 where the collector took SHA-512.
	twice := strings.Replace(string(c7SNMPInstall(t, nil)), `"auth":"hmac-sha-512"`, `"auth":"hmac-md5","auth":"hmac-sha-512"`, 1)
	if !strings.Contains(twice, `"auth":"hmac-md5"`) {
		t.Fatal("the edit did not apply")
	}
	if _, err := authz.DecodeRequest([]byte(twice)); err == nil {
		t.Error("auth spelled twice: accepted")
	}
}

// The collector refuses a credential whose engine ID is not the asset's
// declared snmp_engine_id (HR-16), comparing C7's string with C1's. So the
// two contracts must take exactly the same strings: one that only C1 took
// could never be matched, and one that only C7 took would pin a key to an
// engine ID no asset can declare.
func TestC7V08EngineIDOneRuleInBoth(t *testing.T) {
	for _, c := range []struct {
		id   string
		want bool
	}{
		{c7EngineID, true},
		{"8000000001", true},                        // 5 octets
		{strings.Repeat("ab", 32), true},            // 32 octets
		{"80000000", false},                         // 4 octets
		{strings.Repeat("ab", 33), false},           // 33 octets
		{"80007c4f030", false},                      // odd length
		{strings.ToUpper(c7EngineID), false},        // upper case
		{"0x" + c7EngineID, false},                  // a prefix
		{"80:00:7c:4f:03:02:00:00:27:31:01", false}, // separators
		{"", false},
	} {
		u := authz.USM{UserName: "otsec-ro", Auth: authz.USMAuthHMACSHA512, Priv: authz.USMPrivAES128, EngineID: c.id, SoleDeviceAttested: true}
		inC7 := u.Validate() == nil
		b, err := c1SNMP(t, func(m map[string]any) {
			c1OperatorOnly(m, asset.AttrSNMPEngineID)
			c1Attr(m, asset.AttrSNMPEngineID)["value"] = c.id
			c1Obs(m, asset.AttrSNMPEngineID, 0)["value"] = c.id
		})
		if err != nil {
			t.Fatal(err)
		}
		_, derr := asset.Decode(b)
		inC1 := derr == nil
		if inC7 != c.want || inC1 != c.want {
			t.Errorf("engine ID %q: C7 takes it %v, C1 0.3 takes it %v, want %v (C1: %v)", c.id, inC7, inC1, c.want, derr)
		}
	}
	// The golden asset's snmpv3 endpoint and the credential carry the one
	// label C7 allows for snmpv3.
	b, err := c1SNMP(t, nil)
	if err != nil {
		t.Fatal(err)
	}
	a, err := asset.Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	if lvl, ok := a.WeakestDownstreamSecurity(); !ok || string(lvl) != string(authz.DownstreamEncryptedAuthenticated) {
		t.Errorf("the snmpv3 asset's weakest downstream security %q, want %q", lvl, authz.DownstreamEncryptedAuthenticated)
	}
}

// An snmpv3 credential binds its own node, asset, endpoint and transport,
// with no access level and no acknowledgement scope, and nothing else
// (C7-A2-4); anything else is credential_mismatch.
func TestC7V08SNMPv3BindsOnlyItsOwnUse(t *testing.T) {
	req, err := authz.DecodeRequest(c7SNMPInstall(t, nil))
	if err != nil {
		t.Fatal(err)
	}
	ref := req.CredentialInstall.Ref
	own := authz.Use{NodeID: ref.NodeID, AssetID: ref.AssetID, EndpointID: ref.EndpointID, Transport: authz.TransportSNMPv3}
	if err := ref.Binds(own); err != nil {
		t.Fatalf("its own use: %v", err)
	}
	if authz.TransportSNMPv3.Plaintext() {
		t.Error("snmpv3 reported as plaintext")
	}
	for name, edit := range map[string]func(u *authz.Use){
		"telnet":           func(u *authz.Use) { u.Transport = authz.TransportTelnet },
		"an access level":  func(u *authz.Use) { u.AccessLevel = "1" },
		"a lab-only ack":   func(u *authz.Use) { u.AckScope = authz.PlaintextLabOnly },
		"another endpoint": func(u *authz.Use) { u.EndpointID = "port1-telnet" },
		"another node":     func(u *authz.Use) { u.NodeID = "site-a-node-2" },
		"another asset":    func(u *authz.Use) { u.AssetID = "0a7d0000-0000-4000-8000-000000000001" },
		"an snmpv2c use":   func(u *authz.Use) { u.Transport = authz.Transport("snmpv2c") },
	} {
		u := own
		edit(&u)
		var r *authz.Refusal
		if err := ref.Binds(u); !errors.As(err, &r) || r.Code != authz.RefuseCredentialMismatch {
			t.Errorf("%s: got %v, want credential_mismatch", name, err)
		}
	}
}
