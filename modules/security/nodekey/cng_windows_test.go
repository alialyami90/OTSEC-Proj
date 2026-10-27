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
		created := s.(*cngSigner).key
		setErr := setDACL(created, sddl)
		// A second change through the creating handle, as well as one
		// through a handle opened by name: run 2 on #157 got NTE_PERM on
		// the creating handle under an ACE of read-control, write-DAC and
		// delete.
		creatingErr := setDACL(created, sddl)
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
		t.Logf("BA %-9s set=%s againCreating=%s open=%s sign=%s readDACL=%s againByName=%s delete=%s",
			rights, res(setErr), res(creatingErr), res(openErr), res(signErr), res(readErr), res(resetErr), res(delErr))
		if rights == "GA" && (setErr != nil || openErr != nil || signErr != nil || readErr != nil || resetErr != nil || delErr != nil) {
			t.Errorf("the production Administrators ACE does not behave as designed")
		}
	}
}

// atDepth runs f below d small frames, so f's calls start at a different
// stack offset for each d, a few words apart.
//
//go:noinline
func atDepth(d int, f func()) byte {
	var pad [16]byte
	pad[d%len(pad)] = byte(d)
	if d > 0 {
		return atDepth(d-1, f) + pad[(d*7)%len(pad)]
	}
	f()
	return pad[0]
}

// TestCNGStackMoves calls NCrypt from fresh goroutines at every stack
// depth up to 2048 small frames, so for some depths the stack grows inside
// call and moves. Steps of a few words are what find it: the same harness
// around clock_gettime on Linux, through a wrapper without
// go:uintptrescapes, failed at 12 of 2048 depths with 16-byte padding and
// at none with 256-byte padding (a step wider than the call's frames). An out-parameter or buffer left on the old stack is then
// written by NCrypt where Go no longer reads it: the public key reads as
// short ("not an ECDSA P-256 public key", #199's Windows job), a signature
// fails to verify, or a DACL read sees no descriptor. call's
// go:uintptrescapes moves every pointer it is passed to the heap.
//
// It is a smoke test, not the proof: on the hosted runner it passed
// without the fix, at both strides tried (#201's first two runs), so the
// window is narrower there than on Linux. TestCNGPointersEscape is the
// deterministic check.
func TestCNGStackMoves(t *testing.T) {
	needElevated(t)
	keys := CNG{}
	name := cngKeyName("stack")
	s := created(t, keys, name)
	key, err := keys.openKey(name)
	if err != nil {
		t.Fatal(err)
	}
	defer free(key)
	want := s.Public().(*ecdsa.PublicKey)
	errs := make(chan error, 3*2*2048) // room for every check to fail
	for round := range 2 {
		for d := range 2048 {
			done := make(chan struct{})
			go func() {
				defer close(done)
				atDepth(d, func() {
					digest := sha256.Sum256([]byte(fmt.Sprintf("otsec nodekey stack %d %d", round, d)))
					if pub, err := publicKey(key); err != nil || !pub.Equal(want) {
						errs <- fmt.Errorf("depth %d: public key: %v", d, err)
					}
					if sig, err := s.Sign(rand.Reader, digest[:], nil); err != nil || !ecdsa.VerifyASN1(want, digest[:], sig) {
						errs <- fmt.Errorf("depth %d: sign: %v", d, err)
					}
					if _, err := keys.securityDescriptor(name); err != nil {
						errs <- fmt.Errorf("depth %d: DACL read: %v", d, err)
					}
				})
			}()
			<-done
		}
	}
	close(errs)
	n := 0
	for err := range errs {
		if n++; n <= 10 {
			t.Error(err)
		}
	}
	if n > 10 {
		t.Errorf("and %d more", n-10)
	}
}
