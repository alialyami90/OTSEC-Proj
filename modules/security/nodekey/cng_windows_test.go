package nodekey

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// The CNG tests make machine keys, which the administrator's tool does
// elevated. They skip on a token that is not elevated, unless
// OTSEC_REQUIRE_ELEVATED is set (the Windows CI job), where that fails.
func needElevated(t *testing.T) {
	t.Helper()
	tok := windows.GetCurrentProcessToken()
	elevated := tok.IsElevated()
	level := "unknown"
	if g, err := tok.GetTokenGroups(); err == nil {
		for _, a := range g.AllGroups() {
			if s := a.Sid.String(); strings.HasPrefix(s, "S-1-16-") {
				level = s
			}
		}
	}
	t.Logf("token elevated=%v integrity=%s", elevated, level)
	if !elevated {
		if os.Getenv("OTSEC_REQUIRE_ELEVATED") != "" {
			t.Fatal("OTSEC_REQUIRE_ELEVATED is set but the token is not elevated")
		}
		t.Skip("not elevated")
	}
}

func cngKeyName() string {
	return KeyName(fmt.Sprintf("nodekey_citest%d", time.Now().UnixNano()%1e12), 1)
}

// created makes a key and deletes it at the end through its creating
// handle, which works whatever its DACL has become.
func created(t *testing.T, keys CNG, name string) crypto.Signer {
	t.Helper()
	s, err := keys.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := keys.Open(name); errors.Is(err, ErrNoKey) {
			return // the test deleted it
		}
		if err := deleteCreated(s); err != nil {
			t.Errorf("cleanup: %s is left: %v", name, err)
		}
	})
	return s
}

// TestCNGKeyLifecycle: a CNG key signs where it lives, cannot be exported,
// and after Restrict is usable by the listed users and has the DACL
// section 9 names.
func TestCNGKeyLifecycle(t *testing.T) {
	needElevated(t)
	me, err := currentUser()
	if err != nil {
		t.Fatal(err)
	}
	keys := CNG{Users: []string{me}} // the test stands in for the node service
	name := cngKeyName()
	s := created(t, keys, name)
	if _, err := keys.Create(name); err == nil {
		t.Fatal("an existing key created again")
	}
	digest := sha256.Sum256([]byte("otsec nodekey test"))
	sig, err := s.Sign(rand.Reader, digest[:], nil)
	if err != nil || !ecdsa.VerifyASN1(s.Public().(*ecdsa.PublicKey), digest[:], sig) {
		t.Fatalf("sign: %v", err)
	}
	if err := keys.exportPrivate(name); err != nil {
		t.Fatalf("export: %v", err)
	}
	if err := keys.Restrict(s); err != nil {
		t.Fatal(err)
	}
	if err := keys.Restrict(&ecdsa.PrivateKey{}); err == nil {
		t.Fatal("restricted a key CNG did not create")
	}
	dacl, err := keys.dacl(name)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("dacl after restrict: %s", dacl)
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
		t.Fatalf("delete: %v", err)
	}
	if _, err := keys.Open(name); !errors.Is(err, ErrNoKey) {
		t.Fatalf("after delete: %v", err)
	}
}

// TestCNGCreatorLosesUse: with no user listed, Restrict leaves the key to
// SYSTEM, so the administrator who made it can no longer sign with it.
func TestCNGCreatorLosesUse(t *testing.T) {
	needElevated(t)
	keys := CNG{}
	name := cngKeyName()
	s := created(t, keys, name)
	if err := keys.Restrict(s); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("otsec nodekey test"))
	o, err := keys.Open(name)
	t.Logf("creator opens the restricted key: %v", err)
	if err == nil {
		if _, err := o.Sign(rand.Reader, digest[:], nil); err == nil {
			t.Fatal("the creator still signs with a restricted key")
		} else {
			t.Logf("creator signs: %v", err)
		}
	}
	// An administrator removes a restricted key by name (retiring a node's
	// key). The cleanup deletes it through the creating handle if not.
	if err := keys.Delete(name); err != nil {
		t.Errorf("an administrator cannot delete the restricted key by name: %v", err)
	}
}
