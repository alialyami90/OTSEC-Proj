package nodekey

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"testing"
	"time"
)

// D4-106 item 3, test 1: OpenPinned frees the handle of every CNG key it
// refuses, so a reader that retries a replaced key at each step leaks
// nothing (D6's N1 on #685). Control: release with its free dropped, or
// OpenPinned with its release dropped: each compiles and frees nothing.

// countFrees makes freeKey count each handle it is given, until the test
// ends, and pass the handle on to the real free when pass is set.
func countFrees(t *testing.T, pass bool) *int {
	t.Helper()
	n := 0
	old := freeKey
	freeKey = func(h uintptr) {
		n++
		if pass {
			old(h)
		}
	}
	t.Cleanup(func() { freeKey = old })
	return &n
}

// fakeCNG opens a CNG signer whose handle no provider made: the counter
// never passes it on. Its other methods are a lab store's.
type fakeCNG struct {
	LabFiles
	next uintptr
	pub  *ecdsa.PublicKey
	open []*cngSigner
}

func (k *fakeCNG) Open(string) (crypto.Signer, error) {
	k.next++
	s := &cngSigner{key: k.next, pub: k.pub}
	k.open = append(k.open, s)
	return s, nil
}

// TestOpenPinnedFreesRefused runs on any Windows token: N wrong pins free
// N handles, each once, and the right pin frees none and keeps its handle.
func TestOpenPinnedFreesRefused(t *testing.T) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(k.Public())
	if err != nil {
		t.Fatal(err)
	}
	wrong := append(append([]byte{}, spki...), 0)
	keys := &fakeCNG{next: 0x1000, pub: &k.PublicKey}
	freed := countFrees(t, false)
	const n = 5
	for range n {
		if s, err := OpenPinned(keys, "fake", wrong); s != nil || !errors.Is(err, ErrKeyMismatch) {
			t.Fatalf("a wrong pin: %v, %v", s, err)
		}
	}
	if *freed != n {
		t.Fatalf("%d frees over %d wrong pins", *freed, n)
	}
	for i, s := range keys.open {
		if s.key != 0 {
			t.Errorf("refused signer %d still holds handle %#x", i, s.key)
		}
	}
	s, err := OpenPinned(keys, "fake", spki)
	if err != nil || s.(*cngSigner).key == 0 {
		t.Fatalf("the right pin: %v", err)
	}
	if *freed != n {
		t.Fatalf("the right pin freed a handle: %d frees", *freed)
	}
}

// TestOpenPinnedFreesCNGHandle is the same on real CNG keys, elevated (the
// Windows CI job): N wrong pins to OpenPinned, then N loads of a register
// key that was replaced, each free passed on to NCryptFreeObject.
func TestOpenPinnedFreesCNGHandle(t *testing.T) {
	needElevated(t)
	me, err := currentUser()
	if err != nil {
		t.Fatal(err)
	}
	keys := CNG{Users: []string{me}}
	name := cngKeyName("pin")
	s := created(t, keys, name)
	spki, err := x509.MarshalPKIXPublicKey(s.Public())
	if err != nil {
		t.Fatal(err)
	}
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrong, err := x509.MarshalPKIXPublicKey(other.Public())
	if err != nil {
		t.Fatal(err)
	}
	freed := countFrees(t, true)
	const n = 5
	for range n {
		if got, err := OpenPinned(keys, name, wrong); got != nil || !errors.Is(err, ErrKeyMismatch) {
			t.Fatalf("a wrong pin: %v, %v", got, err)
		}
	}
	if *freed != n {
		t.Fatalf("%d frees over %d wrong pins", *freed, n)
	}
	got, err := OpenPinned(keys, name, spki)
	if err != nil {
		t.Fatalf("the right pin: %v", err)
	}
	digest := sha256.Sum256([]byte("otsec nodekey pinned test"))
	sig, err := got.Sign(rand.Reader, digest[:], nil)
	if err != nil || !ecdsa.VerifyASN1(s.Public().(*ecdsa.PublicKey), digest[:], sig) {
		t.Fatalf("the pinned key does not sign: %v", err)
	}
	if *freed != n {
		t.Fatalf("the right pin freed a handle: %d frees", *freed)
	}

	// A register key replaced under its name: LoadCertificate refuses it
	// N times and frees each handle.
	ref := fmt.Sprintf("nodekey_pinreg%d", time.Now().UnixNano()%1e12)
	keyName := KeyName(ref, 1)
	t.Cleanup(func() {
		if err := keys.Delete(keyName); err != nil {
			t.Errorf("cleanup: %s is left: %v", keyName, err)
		}
	})
	r := NewRegister(testNode)
	csr, err := r.Request(keys, ref, pkix.Name{CommonName: testNode}, admin, now)
	if err != nil {
		t.Fatal(err)
	}
	ca := newCA(t, "otsec test ca")
	if err := r.Install(ref, [][]byte{ca.issue(t, csr, x509.ExtKeyUsageClientAuth, now.Add(90*24*time.Hour))}, admin, now); err != nil {
		t.Fatal(err)
	}
	if err := keys.Delete(keyName); err != nil {
		t.Fatal(err)
	}
	if _, err := keys.Create(keyName); err != nil {
		t.Fatal(err)
	}
	before := *freed
	for range n {
		if cert, _, err := r.LoadCertificate(ref, keys); cert != nil || !errors.Is(err, ErrKeyMismatch) {
			t.Fatalf("LoadCertificate of a replaced key: %v", err)
		}
	}
	if d := *freed - before; d != n {
		t.Fatalf("%d frees over %d loads of a replaced key", d, n)
	}
}
