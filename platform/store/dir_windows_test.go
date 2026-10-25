//go:build windows

package store

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

// The store directory's DACL is checked at every Lock (A3 condition 1).
func TestDirDACLChecked(t *testing.T) {
	env := func(dir string) *Env {
		e, err := NewEnv(Options{Dir: dir, Node: testNode, Database: evidenceDB})
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
	good := storeDir(t)
	unlock, err := env(good).Lock(bg)
	if err != nil {
		t.Fatalf("protected directory refused: %v", err)
	}
	unlock()

	inherits := filepath.Join(t.TempDir(), "plain")
	if err := os.Mkdir(inherits, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := env(inherits).Lock(bg); err == nil {
		t.Fatal("a directory that inherits its DACL was accepted")
	}

	users := filepath.Join(t.TempDir(), "users")
	if err := CreateDir(users, ""); err != nil {
		t.Fatal(err)
	}
	u, _ := windows.GetCurrentProcessToken().GetTokenUser()
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + u.User.Sid.String() + ")(A;OICI;FR;;;BU)")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, _ := sd.DACL()
	if err := windows.SetNamedSecurityInfo(users, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := env(users).Lock(bg); err == nil {
		t.Fatal("a directory Users can read was accepted")
	}
	if err := CreateDir(users, ""); err == nil {
		t.Fatal("CreateDir adopted an existing directory with a bad DACL")
	}

	// The account is parsed as a SID, so SDDL in it cannot add an entry
	// (A3 #84 note 1).
	if err := CreateDir(filepath.Join(t.TempDir(), "sddl"), "S-1-5-18)(A;OICI;FA;;;WD"); err == nil {
		t.Fatal("CreateDir took SDDL in the account")
	}
	if err := CreateDir(filepath.Join(t.TempDir(), "alias"), "WD"); err == nil {
		t.Fatal("CreateDir took the SDDL alias WD for Everyone")
	}

	// A junction to a good directory is refused (A3 #84 note 4).
	junction := filepath.Join(t.TempDir(), "junction")
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", junction, good).CombinedOutput(); err != nil {
		t.Fatalf("mklink: %v: %s", err, out)
	}
	if _, err := env(junction).Lock(bg); err == nil {
		t.Fatal("lock taken through a junction")
	}
}
