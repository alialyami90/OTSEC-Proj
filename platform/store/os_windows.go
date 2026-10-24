//go:build windows

package store

import (
	"fmt"
	"os"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// lockFile opens path with share mode 0, so no other handle to it can be
// opened while the node runs. It is one of the two layers of "nothing else
// opens the store"; the protected DACL on the directory is the other (A3
// C5 review, section 4).
func lockFile(path string) (func(), error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil,
		windows.OPEN_ALWAYS, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		if err == windows.ERROR_SHARING_VIOLATION {
			return nil, fmt.Errorf("store is locked by another process: %w", err)
		}
		return nil, fmt.Errorf("lock %s: %w", path, err)
	}
	var once sync.Once
	return func() { once.Do(func() { windows.CloseHandle(h) }) }, nil
}

// checkDir refuses a store directory whose DACL lets anyone but this
// process's own account, SYSTEM and Administrators in (A3 C5 review,
// condition 1, and A3's review of #77). It runs at every startup, not only
// at install, because an operator or a restore can change the DACL later.
// The DACL must be protected, so nothing is inherited from the parent; every
// allow entry must name one of the three; and the owner must be one of
// them, because an owner can rewrite the DACL (W-4). Under the SCM the
// process's account is the node's service SID, so the collector's SID,
// Users and Everyone are all refused.
func checkDir(dir string) error {
	st, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("store directory: %w", err)
	}
	if !st.IsDir() {
		return fmt.Errorf("store directory %s is not a directory", dir)
	}
	sd, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("store directory %s: read DACL: %w", dir, err)
	}
	allowed, err := allowedSIDs()
	if err != nil {
		return err
	}
	ok := func(sid *windows.SID) bool {
		for _, a := range allowed {
			if windows.EqualSid(sid, a) {
				return true
			}
		}
		return false
	}
	control, _, err := sd.Control()
	if err != nil {
		return err
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		return fmt.Errorf("store directory %s inherits its DACL; it must be protected (A3 condition 1)", dir)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}
	if !ok(owner) {
		return fmt.Errorf("store directory %s is owned by %s; the owner must be this account, SYSTEM or Administrators (W-4)", dir, owner)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	if dacl == nil {
		return fmt.Errorf("store directory %s has a null DACL, which grants everyone", dir)
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return fmt.Errorf("store directory %s: ACE %d: %w", dir, i, err)
		}
		switch ace.Header.AceType {
		case windows.ACCESS_DENIED_ACE_TYPE:
			continue // a deny entry only narrows access
		case windows.ACCESS_ALLOWED_ACE_TYPE:
			sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
			if !ok(sid) {
				return fmt.Errorf("store directory %s grants access to %s; only this account, SYSTEM and Administrators may have access", dir, sid)
			}
		default:
			return fmt.Errorf("store directory %s: ACE %d has type %d, which this check does not read", dir, i, ace.Header.AceType)
		}
	}
	return nil
}

// allowedSIDs are the process's own account, SYSTEM and Administrators.
func allowedSIDs() ([]*windows.SID, error) {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("read process account: %w", err)
	}
	self, err := u.User.Sid.Copy()
	if err != nil {
		return nil, err
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return nil, err
	}
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return nil, err
	}
	return []*windows.SID{self, system, admins}, nil
}

func freeBytes(dir string) (int64, error) {
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return 0, err
	}
	var avail, total, totalFree uint64
	if err := windows.GetDiskFreeSpaceEx(p, &avail, &total, &totalFree); err != nil {
		return 0, fmt.Errorf("free space of %s: %w", dir, err)
	}
	return int64(avail), nil
}

// syncDir is a no-op on Windows: NTFS metadata is journaled, and a
// directory handle cannot be flushed with FlushFileBuffers.
func syncDir(dir string) error { return nil }

// CreateDir creates dir as a store directory: a protected DACL granting
// full control to SYSTEM, Administrators and account (a SID string; empty
// means this process's account), and nothing else, owned by
// Administrators when the caller may set that and by the caller
// otherwise. The installer passes the node's service SID (W-4). If dir
// exists, CreateDir changes nothing and returns checkDir's verdict as the
// process running it sees it, so a pre-created directory is refused, never
// adopted.
func CreateDir(dir, account string) error {
	if _, err := os.Lstat(dir); err == nil {
		return checkDir(dir)
	}
	if account == "" {
		u, err := windows.GetCurrentProcessToken().GetTokenUser()
		if err != nil {
			return err
		}
		account = u.User.Sid.String()
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + account + ")")
	if err != nil {
		return fmt.Errorf("store directory DACL for %s: %w", account, err)
	}
	sa := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return err
	}
	if err := windows.CreateDirectory(p, sa); err != nil {
		return fmt.Errorf("create store directory %s: %w", dir, err)
	}
	return nil
}
