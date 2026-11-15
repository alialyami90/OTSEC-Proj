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
	"slices"
	"testing"
	"time"
)

// D4-106 item 3, test 1: OpenPinned frees the handle of every CNG key it
// refuses, the very handle Open returned, so a reader that retries a
// replaced key at each step leaks nothing (D6's N1 on #685); and
// Register.Certificate frees the handle of a key it refuses on the period
// (D6's N3 on #697). Controls: release with its free dropped, OpenPinned
// with its release dropped, or release that zeroes the handle before it
// frees it (D6's N1 on #697): each compiles, and frees nothing or handle 0.

// countFrees makes freeKey record each handle it is given, until the test
// ends, and pass the handle on to the real free when pass is set.
func countFrees(t *testing.T, pass bool) *[]uintptr {
	t.Helper()
	var freed []uintptr
	old := freeKey
	freeKey = func(h uintptr) {
		freed = append(freed, h)
		if pass {
			old(h)
		}
	}
	t.Cleanup(func() { freeKey = old })
	return &freed
}

// fakeCNG opens a CNG signer whose handle no provider made: the counter
// never passes it on. Its other methods are a lab store's. opened holds
// each handle Open returned, in order.
type fakeCNG struct {
	LabFiles
	next   uintptr
	pub    *ecdsa.PublicKey
	open   []*cngSigner
	opened []uintptr
}

func (k *fakeCNG) Open(string) (crypto.Signer, error) {
	k.next++
	s := &cngSigner{key: k.next, pub: k.pub}
	k.open = append(k.open, s)
	k.opened = append(k.opened, s.key)
	return s, nil
}

// recordingCNG is a CNG store that records each handle Open returned.
type recordingCNG struct {
	CNG
	opened []uintptr
}

func (k *recordingCNG) Open(name string) (crypto.Signer, error) {
	s, err := k.CNG.Open(name)
	if err == nil {
		k.opened = append(k.opened, s.(*cngSigner).key)
	}
	return s, err
}

// sameHandles fails the test unless freed is exactly opened, in order,
// and no handle is 0.
func sameHandles(t *testing.T, what string, freed, opened []uintptr) {
	t.Helper()
	if !slices.Equal(freed, opened) || slices.Contains(freed, 0) {
		t.Fatalf("%s: freed %#x, opened %#x", what, freed, opened)
	}
}

// TestOpenPinnedFreesRefused runs on any Windows token: N wrong pins free
// the N handles Open returned, each once, and the right pin frees none and
// keeps its handle.
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
	sameHandles(t, "wrong pins", *freed, keys.opened)
	for i, s := range keys.open {
		if s.key != 0 {
			t.Errorf("refused signer %d still holds handle %#x", i, s.key)
		}
	}
	s, err := OpenPinned(keys, "fake", spki)
	if err != nil || s.(*cngSigner).key == 0 {
		t.Fatalf("the right pin: %v", err)
	}
	if len(*freed) != n {
		t.Fatalf("the right pin freed a handle: %#x", *freed)
	}
}

// TestCertificateFreesRefusedOnPeriod runs on any Windows token: a
// register key refused on its period has the handle LoadCertificate
// opened freed; one in its period frees nothing.
func TestCertificateFreesRefusedOnPeriod(t *testing.T) {
	r, lab := installed(t, newCA(t, "otsec test ca"))
	s, err := lab.Open(KeyName(clientRef, 1))
	if err != nil {
		t.Fatal(err)
	}
	keys := &fakeCNG{LabFiles: lab, next: 0x2000, pub: s.Public().(*ecdsa.PublicKey)}
	freed := countFrees(t, false)
	if cert, _, err := r.Certificate(clientRef, keys, now.Add(91*24*time.Hour)); cert != nil || !errors.Is(err, ErrCertificatePeriod) {
		t.Fatalf("an expired certificate: %v", err)
	}
	sameHandles(t, "expired", *freed, keys.opened)
	if cert, _, err := r.Certificate(clientRef, keys, now); err != nil || cert.PrivateKey.(*cngSigner).key == 0 {
		t.Fatalf("a certificate in its period: %v", err)
	}
	if len(*freed) != 1 {
		t.Fatalf("a certificate in its period freed a handle: %#x", *freed)
	}
}

// TestOpenPinnedFreesCNGHandle is the same on real CNG keys, elevated (the
// Windows CI job): N wrong pins to OpenPinned, then N loads of a register
// key that was replaced, each freeing the handle Open returned, passed on
// to NCryptFreeObject.
func TestOpenPinnedFreesCNGHandle(t *testing.T) {
	needElevated(t)
	me, err := currentUser()
	if err != nil {
		t.Fatal(err)
	}
	plain := CNG{Users: []string{me}}
	keys := &recordingCNG{CNG: plain}
	name := cngKeyName("pin")
	s := created(t, plain, name)
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
	sameHandles(t, "wrong pins", *freed, keys.opened)
	got, err := OpenPinned(keys, name, spki)
	if err != nil {
		t.Fatalf("the right pin: %v", err)
	}
	digest := sha256.Sum256([]byte("otsec nodekey pinned test"))
	sig, err := got.Sign(rand.Reader, digest[:], nil)
	if err != nil || !ecdsa.VerifyASN1(s.Public().(*ecdsa.PublicKey), digest[:], sig) {
		t.Fatalf("the pinned key does not sign: %v", err)
	}
	if len(*freed) != n {
		t.Fatalf("the right pin freed a handle: %#x", *freed)
	}

	// A register key replaced under its name: LoadCertificate refuses it
	// N times and frees each handle it opened.
	ref := fmt.Sprintf("nodekey_pinreg%d", time.Now().UnixNano()%1e12)
	keyName := KeyName(ref, 1)
	t.Cleanup(func() {
		if err := plain.Delete(keyName); err != nil {
			t.Errorf("cleanup: %s is left: %v", keyName, err)
		}
	})
	r := NewRegister(testNode)
	csr, err := r.Request(plain, ref, pkix.Name{CommonName: testNode}, admin, now)
	if err != nil {
		t.Fatal(err)
	}
	ca := newCA(t, "otsec test ca")
	if err := r.Install(ref, [][]byte{ca.issue(t, csr, x509.ExtKeyUsageClientAuth, now.Add(90*24*time.Hour))}, admin, now); err != nil {
		t.Fatal(err)
	}
	if err := plain.Delete(keyName); err != nil {
		t.Fatal(err)
	}
	if _, err := plain.Create(keyName); err != nil {
		t.Fatal(err)
	}
	*freed, keys.opened = nil, nil
	for range n {
		if cert, _, err := r.LoadCertificate(ref, keys); cert != nil || !errors.Is(err, ErrKeyMismatch) {
			t.Fatalf("LoadCertificate of a replaced key: %v", err)
		}
	}
	sameHandles(t, "a replaced register key", *freed, keys.opened)
}
