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

func cngKeyName(tag string) string {
	return KeyName(fmt.Sprintf("nodekey_%s%d", tag, time.Now().UnixNano()%1e12), 1)
}

// created makes a key and tries to delete it at the end, reporting a key
// it could not delete.
func created(t *testing.T, keys CNG, name string) crypto.Signer {
	t.Helper()
	s, err := keys.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := keys.Delete(name); err != nil {
			t.Errorf("cleanup: %s is left: %v", name, err)
		}
	})
	return s
}

// TestCNGKeyLifecycle: a CNG key signs where it lives, cannot be exported,
// gets the final DACL once, and is then usable by the listed users and
// deletable by an administrator.
func TestCNGKeyLifecycle(t *testing.T) {
	needElevated(t)
	me, err := currentUser()
	if err != nil {
		t.Fatal(err)
	}
	keys := CNG{Users: []string{me}} // the test stands in for the node service
	name := cngKeyName("citest")
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
	if d, err := keys.dacl(name); err == nil {
		t.Logf("default dacl: %s", d)
	}
	if err := keys.Restrict(s); err != nil {
		t.Fatal(err)
	}
	if err := keys.Restrict(&ecdsa.PrivateKey{}); err == nil {
		t.Fatal("restricted a key CNG did not create")
	}
	if d, err := keys.dacl(name); err == nil {
		t.Logf("final dacl: %s", d)
	}
	// The DACL is compared as parsed ACEs: the KSP stores GR as its
	// specific rights and SDDL names some SIDs by alias (CI on #157).
	aces, protected, err := keys.keyACEs(name)
	if err != nil {
		t.Fatal(err)
	}
	const system, admins = "S-1-5-18", "S-1-5-32-544"
	const manage = windows.WRITE_DAC | windows.WRITE_OWNER | windows.DELETE | windows.GENERIC_WRITE | windows.GENERIC_ALL
	if !protected || len(aces) != 3 || aces[system] == 0 || aces[system] != aces[admins] || aces[me] == 0 || aces[me]&manage != 0 {
		t.Fatalf("protected %v, aces %#x", protected, aces)
	}
	if err := keys.exportPrivate(name); err != nil {
		t.Fatalf("export after restrict: %v", err)
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
		t.Fatalf("an administrator cannot delete the key: %v", err)
	}
	if _, err := keys.Open(name); !errors.Is(err, ErrNoKey) {
		t.Fatalf("after delete: %v", err)
	}
}

// TestCNGRightsProbe records what the Software KSP lets an elevated
// administrator do with a key, by name, under each Administrators ACE
// (SYSTEM always has full control). It is the evidence the production DACL
// (CNG.sddl) is chosen from, and it fails only if the production row stops
// allowing use, DACL read, a DACL change and delete.
func TestCNGRightsProbe(t *testing.T) {
	needElevated(t)
	keys := CNG{}
	digest := sha256.Sum256([]byte("otsec nodekey probe"))
	notTried := errors.New("-")
	res := func(err error) string {
		if err == nil {
			return "ok"
		}
		return err.Error()
	}
	for _, rights := range []string{"GA", "GR", "GRGW", "FA", "RCWDSD", "RCWDWOSD"} {
		name := cngKeyName("probe")
		s, err := keys.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		sddl := "D:P(A;;GA;;;SY)(A;;" + rights + ";;;BA)"
		setErr := setDACL(s.(*cngSigner).key, sddl)
		// Sign and the second DACL change need the key open by name; when
		// that fails they are not tried, and the log shows "-".
		signErr, resetErr := notTried, notTried
		var readErr error
		o, openErr := keys.Open(name)
		if openErr == nil {
			_, signErr = o.Sign(rand.Reader, digest[:], nil)
			if k, err := keys.openKey(name); err == nil {
				resetErr = setDACL(k, sddl)
				free(k)
			} else {
				resetErr = err
			}
		}
		_, readErr = keys.dacl(name)
		delErr := keys.Delete(name)
		t.Logf("BA %-9s set=%s open=%s sign=%s readDACL=%s setAgain=%s delete=%s",
			rights, res(setErr), res(openErr), res(signErr), res(readErr), res(resetErr), res(delErr))
		if rights == "GA" && (setErr != nil || openErr != nil || signErr != nil || readErr != nil || resetErr != nil || delErr != nil) {
			t.Errorf("the production Administrators ACE does not behave as designed")
		}
	}
}
