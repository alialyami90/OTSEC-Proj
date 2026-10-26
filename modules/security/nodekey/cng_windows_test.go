package nodekey

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

// The CNG tests make machine keys, which needs an elevated process (the
// Windows CI runner is one). Each key is deleted at the end.

func cngKeyName(t *testing.T) (string, string) {
	ref := fmt.Sprintf("nodekey_citest%d", time.Now().UnixNano()%1e12)
	return ref, KeyName(ref, 1)
}

func needElevated(t *testing.T, err error) {
	t.Helper()
	if err != nil && strings.Contains(err.Error(), "0x80090010") && os.Getenv("OTSEC_REQUIRE_ELEVATED") == "" { // NTE_PERM
		t.Skipf("not elevated: %v", err)
	}
}

// TestCNGKeyLifecycle: a CNG key signs where it lives, cannot be exported,
// and after Restrict is usable only by SYSTEM and the listed users.
func TestCNGKeyLifecycle(t *testing.T) {
	me, err := currentUser()
	if err != nil {
		t.Fatal(err)
	}
	keys := CNG{Users: []string{me}} // the test stands in for the node service
	_, name := cngKeyName(t)
	s, err := keys.Create(name)
	needElevated(t, err)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { keys.Delete(name) })
	if _, err := keys.Create(name); err == nil {
		t.Fatal("an existing key created again")
	}
	digest := sha256.Sum256([]byte("otsec nodekey test"))
	sig, err := s.Sign(rand.Reader, digest[:], nil)
	if err != nil {
		t.Fatal(err)
	}
	if !ecdsa.VerifyASN1(s.Public().(*ecdsa.PublicKey), digest[:], sig) {
		t.Fatal("signature does not verify")
	}
	if err := keys.exportPrivate(name); err != nil {
		t.Fatalf("export: %v", err)
	}
	if err := keys.Restrict(name); err != nil {
		t.Fatal(err)
	}
	dacl, err := keys.dacl(name)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(dacl, "D:P") || !strings.Contains(dacl, ";;;SY)") || !strings.Contains(dacl, me) || strings.Contains(dacl, ";;;WD)") {
		t.Fatalf("dacl %s", dacl)
	}
	o, err := keys.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	if !o.Public().(*ecdsa.PublicKey).Equal(s.Public()) {
		t.Fatal("opened another key")
	}
	if sig, err := o.Sign(rand.Reader, digest[:], nil); err != nil || !ecdsa.VerifyASN1(o.Public().(*ecdsa.PublicKey), digest[:], sig) {
		t.Fatalf("sign after restrict: %v", err)
	}
	if err := keys.Delete(name); err != nil {
		t.Fatal(err)
	}
	if _, err := keys.Open(name); !errors.Is(err, ErrNoKey) {
		t.Fatalf("after delete: %v", err)
	}
}

// TestCNGCreatorLosesUse: with no user listed, Restrict leaves the key to
// SYSTEM, so the administrator who made it can no longer sign with it.
func TestCNGCreatorLosesUse(t *testing.T) {
	keys := CNG{}
	ref, name := cngKeyName(t)
	r := NewRegister(testNode)
	csr, err := r.Request(keys, ref, pkix.Name{CommonName: testNode}, admin, now)
	needElevated(t, err)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { keys.Delete(name) })
	req, err := x509.ParseCertificateRequest(csr)
	if err != nil || req.CheckSignature() != nil {
		t.Fatalf("request: %v", err)
	}
	if r.Entries[0].Provider != ProviderCNGSoftware {
		t.Fatalf("provider %s", r.Entries[0].Provider)
	}
	digest := sha256.Sum256([]byte("otsec nodekey test"))
	if o, err := keys.Open(name); err == nil {
		if _, err := o.Sign(rand.Reader, digest[:], nil); err == nil {
			t.Fatal("the creator still signs with a restricted key")
		}
	}
	if err := keys.Delete(name); err != nil {
		t.Fatalf("an administrator cannot delete the key: %v", err)
	}
}
