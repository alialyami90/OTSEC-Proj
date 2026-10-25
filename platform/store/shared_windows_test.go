//go:build windows

package store

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// peer stands for a reader service's SID, such as the collector's.
const peer = "S-1-5-80-1111111111-2222222222-3333333333-4444444444-555555555"

// checkSDFor is A3's rule for a file or directory other named services
// also read (OTSEC\config\admin): checked over security descriptors in
// SDDL, so no case needs an elevated process.
func TestCheckSDFor(t *testing.T) {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	self := u.User.Sid.String()
	readers, err := readerSIDs([]string{peer})
	if err != nil {
		t.Fatal(err)
	}
	base := "(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
	read := "(A;OICI;0x1200a9;;;" + peer + ")(A;OICI;0x1200a9;;;" + self + ")"
	for _, c := range []struct {
		name, sddl string
		dir, ok    bool
	}{
		{"directory: SY and BA full, the reader and self read", "O:BAD:P" + base + read, true, true},
		{"owner SYSTEM", "O:SYD:P" + base + read, true, true},
		{"file inheriting the directory's entries", "O:BAD:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;0x1200a9;;;" + peer + ")", false, true},
		{"read data only", "O:BAD:P" + base + "(A;;FR;;;" + peer + ")", true, true},
		{"a deny entry narrows", "O:BAD:P(D;;FA;;;WD)" + base + read, true, true},
		{"directory not protected", "O:BAD:" + base + read, true, false},
		{"reader with write (0x1201bf)", "O:BAD:P" + base + "(A;OICI;0x1201bf;;;" + peer + ")", true, false},
		{"reader with WRITE_DAC", "O:BAD:P" + base + "(A;OICI;0x1600a9;;;" + peer + ")", true, false},
		{"reader with GENERIC_READ, not mapped", "O:BAD:P" + base + "(A;OICI;GR;;;" + peer + ")", true, false},
		{"reader with write on children only", "O:BAD:P" + base + "(A;OICI;0x1200a9;;;" + peer + ")(A;OICIIO;FW;;;" + peer + ")", true, false},
		{"inherited write for the reader", "O:BAD:AI" + base + "(A;ID;0x1201bf;;;" + peer + ")", false, false},
		{"self with write", "O:BAD:P" + base + "(A;OICI;FA;;;" + self + ")", true, false},
		{"an unnamed SID, read only", "O:BAD:P" + base + "(A;OICI;0x1200a9;;;S-1-5-80-9-9-9-9-9)", true, false},
		{"Users, read only", "O:BAD:P" + base + "(A;OICI;FR;;;BU)", true, false},
		{"CREATOR OWNER", "O:BAD:P" + base + "(A;OICIIO;FA;;;CO)", true, false},
		{"OWNER RIGHTS", "O:BAD:P" + base + "(A;OICI;0x1200a9;;;OW)", true, false},
		{"owned by the reader", "O:" + peer + "D:P" + base + read, true, false},
		{"owned by this account", "O:" + self + "D:P" + base + read, true, false},
		{"an object entry", "O:BAD:P" + base + "(OA;;RP;bf967a86-0de6-11d0-a285-00aa003049e2;;SY)", true, false},
		{"a null DACL", "O:BAD:NO_ACCESS_CONTROL", true, false},
	} {
		sd, err := windows.SecurityDescriptorFromString(c.sddl)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		err = checkSDFor("directory", "test", sd, c.dir, readers)
		if (err == nil) != c.ok {
			t.Errorf("%s: %v, want ok %v", c.name, err, c.ok)
		}
	}
	for _, bad := range []string{"S-1-3-0", "S-1-3-4", "not a SID", "S-1-5-80-1;(A;;FA;;;WD)"} {
		if _, err := readerSIDs([]string{bad}); err == nil {
			t.Errorf("reader %q accepted", bad)
		}
	}
}

// On disk: a directory and file laid out as the installer lays out
// OTSEC\config\admin pass the For checks, and fail the plain ones, which
// admit no reader. Making Administrators the owner needs an elevated
// process; GitHub Actions has one.
func TestProtectedForOnDisk(t *testing.T) {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "admin")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "clear.json")
	if err := os.WriteFile(file, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	set := func(path, sddl string, si windows.SECURITY_INFORMATION) {
		t.Helper()
		sd, err := windows.SecurityDescriptorFromString(sddl)
		if err != nil {
			t.Fatal(err)
		}
		dacl, _, err := sd.DACL()
		if err != nil {
			t.Fatal(err)
		}
		if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|si, nil, nil, dacl, nil); err != nil {
			t.Fatal(err)
		}
	}
	set(dir, "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;"+peer+")(A;OICI;0x1200a9;;;"+u.User.Sid.String()+")", windows.PROTECTED_DACL_SECURITY_INFORMATION)
	set(file, "D:", windows.UNPROTECTED_DACL_SECURITY_INFORMATION)
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{dir, file} {
		if err := windows.SetNamedSecurityInfo(p, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, admins, nil, nil, nil); err != nil {
			if os.Getenv("GITHUB_ACTIONS") == "true" || os.Getenv("OTSEC_REQUIRE_ELEVATED") == "1" {
				t.Fatal(err)
			}
			t.Skip("needs an elevated process: ", err)
		}
	}
	if err := CheckProtectedDirFor(dir, []string{peer}); err != nil {
		t.Fatal(err)
	}
	if b, err := ReadProtectedFileFor(file, 64, []string{peer}); err != nil || string(b) != "{}" {
		t.Fatalf("%q: %v", b, err)
	}
	if err := CheckProtectedDir(dir); err == nil || !strings.Contains(err.Error(), peer) {
		t.Fatalf("plain check: %v", err)
	}
	if _, err := ReadProtectedFileFor(file, 64, nil); err == nil {
		t.Fatal("read with the reader not named")
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(dir, link); err == nil {
		if err := CheckProtectedDirFor(link, []string{peer}); err == nil {
			t.Fatal("a link accepted")
		}
	} else if !errors.Is(err, windows.ERROR_PRIVILEGE_NOT_HELD) {
		t.Fatal(err)
	}
}
