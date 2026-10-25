//go:build windows

package nodeconfigtest

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// LockTLS makes tls_dir and its files what D2-12 requires of an installed
// node: owner Administrators, and a protected DACL on tls_dir with full
// control for SYSTEM and Administrators and read for this account, which
// the files inherit. Making Administrators the owner needs an elevated
// process; a non-elevated test gets ErrNeedsElevation.
func (c *Config) LockTLS() error { return c.lock("") }

// ShareTLS is LockTLS for a directory another service also reads, as the
// installer lays out OTSEC\config\admin: the DACL also gives reader (a
// SID string) read and traverse, inherited by the files.
func (c *Config) ShareTLS(reader string) error { return c.lock("(A;OICI;0x1200a9;;;" + reader + ")") }

func (c *Config) lock(extra string) error {
	if err := c.setDACL(c.TLSDir, true, "FR", extra); err != nil {
		return err
	}
	// An empty, unprotected DACL leaves each file only what it inherits.
	// (ACLFromEntries cannot build one: it dereferences its nil old ACL.)
	emptySD, err := windows.SecurityDescriptorFromString("D:")
	if err != nil {
		return err
	}
	empty, _, err := emptySD.DACL()
	if err != nil {
		return err
	}
	paths := []string{c.TLSDir}
	ents, err := os.ReadDir(c.TLSDir)
	if err != nil {
		return err
	}
	for _, e := range ents {
		p := filepath.Join(c.TLSDir, e.Name())
		if err := windows.SetNamedSecurityInfo(p, windows.SE_FILE_OBJECT,
			windows.DACL_SECURITY_INFORMATION|windows.UNPROTECTED_DACL_SECURITY_INFORMATION, nil, nil, empty, nil); err != nil {
			return err
		}
		paths = append(paths, p)
	}
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return err
	}
	for _, p := range paths {
		if err := windows.SetNamedSecurityInfo(p, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, admins, nil, nil, nil); err != nil {
			return fmt.Errorf("%w: %v", ErrNeedsElevation, err)
		}
	}
	return nil
}

// UnlockTLS gives this account full control of tls_dir and its files
// again, so they can be changed or removed.
func (c *Config) UnlockTLS() error { return c.setDACL(c.TLSDir, true, "FA", "") }

// LoosenTLS gives this account write access to one file in tls_dir, or to
// tls_dir itself when name is empty, after LockTLS.
func (c *Config) LoosenTLS(name string) error {
	if name == "" {
		return c.setDACL(c.TLSDir, true, "FA", "")
	}
	return c.setDACL(filepath.Join(c.TLSDir, name), false, "FA", "")
}

// OwnTLS makes this account the owner of one file in tls_dir, or of
// tls_dir itself when name is empty, after LockTLS.
func (c *Config) OwnTLS(name string) error {
	p := c.TLSDir
	if name != "" {
		p = filepath.Join(p, name)
	}
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(p, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, u.User.Sid, nil, nil, nil)
}

// setDACL gives path a protected DACL: full control for SYSTEM and
// Administrators, selfAccess for this account, and the extra entries in
// SDDL; inheritable when dir.
func (c *Config) setDACL(path string, dir bool, selfAccess, extra string) error {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	inherit := ""
	if dir {
		inherit = "OICI"
	}
	sd, err := windows.SecurityDescriptorFromString(fmt.Sprintf("D:P(A;%[1]s;FA;;;SY)(A;%[1]s;FA;;;BA)(A;%[1]s;%[2]s;;;%[3]s)%[4]s",
		inherit, selfAccess, u.User.Sid, extra))
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}
