package collector

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/authz"
	"otsec.local/otsec/contracts/register"
)

// The SNMPv3 fixtures are C1 0.3's and C2 0.7's: the SEL-2731M asset with
// its pinned engine ID, and the SEL-27x1 register package. Both are test
// data; no device is behind them.
const snmpEngine = "80007c4f03020000273101"

func snmpAsset(t *testing.T) *asset.Asset {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "contracts", "asset", "testdata", "valid", "sel-2731m-snmpv3.json"))
	if err != nil {
		t.Fatal(err)
	}
	var a asset.Asset
	if err := json.Unmarshal(b, &a); err != nil {
		t.Fatal(err)
	}
	return &a
}

func snmpRegister(t *testing.T) *register.Package {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "contracts", "adapter", "testdata", "snmp", "register.json"))
	if err != nil {
		t.Fatal(err)
	}
	p, err := register.Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func snmpRef(t *testing.T, a *asset.Asset, version uint32) authz.CredentialRef {
	t.Helper()
	r := authz.CredentialRef{
		ID: "cred_sw1snmp01", AssetID: a.AssetID, NodeID: testNode, EndpointID: "mgmt-snmpv3",
		Transport: authz.TransportSNMPv3, Purpose: authz.PurposeCollectReadOnly,
		DownstreamSecurity: authz.DownstreamEncryptedAuthenticated,
		USM:                &authz.USM{UserName: "otsec-ro", Auth: authz.USMAuthHMACSHA256, Priv: authz.USMPrivAES128, EngineID: snmpEngine, SoleDeviceAttested: true},
		Version:            version, CreatedBy: testAdmin, CreatedAt: "2026-10-24T12:00:00Z",
	}
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	return r
}

// usmKeys is a 32-byte authentication key and a 16-byte AES key, test
// values only.
func usmKeys() []byte {
	return append(bytes.Repeat([]byte{0xa5}, 32), bytes.Repeat([]byte{0x5a}, 16)...)
}

func (f *credFixture) installSNMP(t *testing.T, ref authz.CredentialRef, a *asset.Asset, pkg *register.Package, secret []byte) (InstallResult, error) {
	t.Helper()
	return f.store.Install(authz.CredentialInstallBody{Ref: ref, Sealed: f.sealFor(t, ref, secret)}, InstallTarget{Asset: a, Register: pkg})
}

func TestInstallAndAcquireSNMPv3(t *testing.T) {
	f := newCredStore(t)
	a, pkg := snmpAsset(t), snmpRegister(t)
	ref := snmpRef(t, a, 1)
	if _, err := f.installSNMP(t, ref, a, pkg, usmKeys()); err != nil {
		t.Fatalf("install: %v", err)
	}
	// The stored ciphertext (80 bytes of keys at most) survives a reopen.
	s, err := OpenCredStore(f.path, CredStoreConfig{NodeID: testNode, Now: f.clock.now, Generations: f.gens})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	use := authz.Use{NodeID: testNode, AssetID: a.AssetID, EndpointID: "mgmt-snmpv3", Transport: authz.TransportSNMPv3}
	h, got, err := s.Acquire(ref.ID, use, pkg)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	defer h.Close()
	if got.USM == nil || got.USM.EngineID != snmpEngine {
		t.Fatalf("acquired ref %+v", got)
	}
	if !bytes.Equal(secretOf(t, h), usmKeys()) {
		t.Fatal("the keys read back differ")
	}
	// A package with no SNMP operation cannot be used with it.
	if _, _, err := s.Acquire(ref.ID, use, f.pkg); codeOf(err) != authz.RefuseCredentialMismatch {
		t.Fatalf("acquire under the SEL-751 package: %v", err)
	}
}

func TestInstallSNMPv3Refusals(t *testing.T) {
	a, pkg := snmpAsset(t), snmpRegister(t)
	for _, c := range []struct {
		name string
		f    func(*authz.CredentialRef, *asset.Asset, **register.Package, *[]byte)
		want authz.RefusalCode
	}{
		{"keys of the wrong length", func(_ *authz.CredentialRef, _ *asset.Asset, _ **register.Package, s *[]byte) { *s = (*s)[:47] }, authz.RefuseSecretRejected},
		{"a password in place of keys", func(_ *authz.CredentialRef, _ *asset.Asset, _ **register.Package, s *[]byte) {
			*s = []byte("otsec-password")
		}, authz.RefuseSecretRejected},
		{"another engine ID than the asset's", func(r *authz.CredentialRef, _ *asset.Asset, _ **register.Package, _ *[]byte) {
			u := *r.USM
			u.EngineID = "80007c4f03020000273102"
			r.USM = &u
		}, authz.RefuseCredentialMismatch},
		{"an asset with no declared engine ID", func(_ *authz.CredentialRef, a *asset.Asset, _ **register.Package, _ *[]byte) {
			var keep []asset.Attribute
			for _, at := range a.Attributes {
				if at.Name != asset.AttrSNMPEngineID {
					keep = append(keep, at)
				}
			}
			a.Attributes = keep
		}, authz.RefuseCredentialMismatch},
		{"a package with no SNMP operation", func(_ *authz.CredentialRef, _ *asset.Asset, p **register.Package, _ *[]byte) {
			q := **p
			q.SNMPOperations = nil
			*p = &q
		}, authz.RefuseCredentialMismatch},
		{"no package", func(_ *authz.CredentialRef, _ *asset.Asset, p **register.Package, _ *[]byte) { *p = nil }, authz.RefuseRegisterUnverified},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newCredStore(t)
			ref, aa, p, secret := snmpRef(t, a, 1), *a, pkg, usmKeys()
			aa.Attributes = append([]asset.Attribute(nil), a.Attributes...)
			c.f(&ref, &aa, &p, &secret)
			if _, err := f.installSNMP(t, ref, &aa, p, secret); codeOf(err) != c.want {
				t.Fatalf("got %v, want %s", err, c.want)
			}
		})
	}
}
