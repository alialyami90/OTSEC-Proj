package collector

// C6's case for #456. Evidence class: desk (a credential store in a temporary
// directory, test keys only, no device).

import (
	"bytes"
	"testing"

	"otsec.local/otsec/contracts/authz"
)

// An HMAC-SHA-512 credential's secret is 64 octets of auth key and 16 of AES
// key: 80 octets, over the 64-octet password bound. It must install, and the
// store must still open and give the keys back after a restart. If the
// stored-entry bound were the password's, the reopen would refuse the whole
// file, and every credential on the collector with it.
func TestC6SHA512CredentialSurvivesAReopen(t *testing.T) {
	f := newCredStore(t)
	a, pkg := snmpAsset(t), snmpRegister(t)
	ref := snmpRef(t, a, 1)
	u := *ref.USM
	u.Auth = authz.USMAuthHMACSHA512
	ref.USM = &u
	if err := ref.Validate(); err != nil {
		t.Fatal(err)
	}
	keys := append(bytes.Repeat([]byte{0xa5}, 64), bytes.Repeat([]byte{0x5a}, 16)...)
	if len(keys) <= authz.MaxSecretLen {
		t.Fatalf("the case needs a secret over the password bound (%d)", authz.MaxSecretLen)
	}
	if _, err := f.installSNMP(t, ref, a, pkg, keys); err != nil {
		t.Fatalf("install: %v", err)
	}
	s, err := OpenCredStore(f.path, CredStoreConfig{NodeID: testNode, Now: f.clock.now, Generations: f.gens})
	if err != nil {
		t.Fatalf("the store with an 80-octet secret does not reopen: %v", err)
	}
	use := authz.Use{NodeID: testNode, AssetID: a.AssetID, EndpointID: "mgmt-snmpv3", Transport: authz.TransportSNMPv3}
	h, _, err := s.Acquire(ref.ID, use, pkg)
	if err != nil {
		t.Fatalf("acquire after the reopen: %v", err)
	}
	defer h.Close()
	if !bytes.Equal(secretOf(t, h), keys) {
		t.Fatal("the keys read back differ")
	}
	// The wrong layout for SHA-512 (SHA-256's 48 octets) is refused.
	g := newCredStore(t)
	if _, err := g.installSNMP(t, ref, a, pkg, keys[16:]); codeOf(err) != authz.RefuseSecretRejected {
		t.Fatalf("48 octets for hmac-sha-512: %v", err)
	}
}
