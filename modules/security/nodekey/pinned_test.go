package nodekey

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"testing"
)

// TestOpenPinned (D4-106 item 3, test 2): OpenPinned returns the key only
// under its own public key. Another key under the name, or a pin that is
// not the key's PKIX DER, is refused with ErrKeyMismatch; a missing key is
// ErrNoKey, as Open says. LoadCertificate refuses a replaced key with
// ErrKeyMismatch too. Desk only, lab-files keys. Control: OpenPinned with
// the comparison skipped, which returns a signer for every wrong pin.
func TestOpenPinned(t *testing.T) {
	keys := LabFiles{Dir: t.TempDir()}
	name := KeyName("nodekey_pinned001", 1)
	s, err := keys.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(s.Public())
	if err != nil {
		t.Fatal(err)
	}
	got, err := OpenPinned(keys, name, spki)
	if err != nil || !got.Public().(*ecdsa.PublicKey).Equal(s.Public()) {
		t.Fatalf("the right pin: %v", err)
	}
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherSPKI, err := x509.MarshalPKIXPublicKey(other.Public())
	if err != nil {
		t.Fatal(err)
	}
	for pin, b := range map[string][]byte{
		"another key": otherSPKI,
		"no pin":      nil,
		"cut short":   spki[:len(spki)-1],
		"one more":    append(append([]byte{}, spki...), 0),
	} {
		got, err := OpenPinned(keys, name, b)
		if got != nil || !errors.Is(err, ErrKeyMismatch) || errors.Is(err, ErrNoKey) {
			t.Errorf("%s: %v, %v; want ErrKeyMismatch", pin, got, err)
		}
	}
	if got, err := OpenPinned(keys, KeyName("nodekey_pinned001", 2), spki); got != nil || !errors.Is(err, ErrNoKey) || errors.Is(err, ErrKeyMismatch) {
		t.Errorf("a missing key: %v, %v; want ErrNoKey", got, err)
	}

	r, rkeys := installed(t, newCA(t, "otsec test ca"))
	if err := rkeys.Delete(KeyName(clientRef, 1)); err != nil {
		t.Fatal(err)
	}
	if _, err := rkeys.Create(KeyName(clientRef, 1)); err != nil {
		t.Fatal(err)
	}
	if cert, _, err := r.LoadCertificate(clientRef, rkeys); cert != nil || !errors.Is(err, ErrKeyMismatch) {
		t.Errorf("LoadCertificate of a replaced key: %v; want ErrKeyMismatch", err)
	}
}
