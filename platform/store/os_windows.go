//go:build windows

package store

import (
	"errors"
	"fmt"
	"os"
	"strings"
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
// Users and Everyone are all refused. A reparse point (a symbolic link, a
// junction or a mount point) is refused, so the checked DACL is the one on
// the directory the files are written to (A3 #84 note 4).
func checkDir(dir string) error {
	attrs, err := attributes(dir)
	if err != nil {
		return fmt.Errorf("store directory: %w", err)
	}
	if attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("store directory %s is a reparse point; it must be the directory itself", dir)
	}
	if attrs&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return fmt.Errorf("store directory %s is not a directory", dir)
	}
	return checkACL("store directory", dir, true)
}

// checkFile refuses a database file (the database, its -wal or its -shm)
// that is a reparse point or whose DACL or owner fails the directory's
// rule (A3 #84 note 3). Its DACL is the one it inherited from the store
// directory, so it is not required to be protected. A file that does not
// exist passes: SQLite creates it under the directory's DACL.
func checkFile(path string) error {
	attrs, err := attributes(path)
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("store file: %w", err)
	}
	if attrs&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 {
		return fmt.Errorf("store file %s is not a plain file", path)
	}
	return checkACL("store file", path, false)
}

// attributes reads path's attributes without following a reparse point.
func attributes(path string) (uint32, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	attrs, err := windows.GetFileAttributes(p)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", path, err)
	}
	return attrs, nil
}

// checkACL applies the rule to path's owner and DACL. protected also
// requires the DACL to be protected.
func checkACL(what, path string, protected bool) error {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("%s %s: read DACL: %w", what, path, err)
	}
	return checkSD(what, path, sd, protected, false)
}

// writeRights are the access rights that let a holder change a file or
// directory, its entries, its attributes or its security descriptor.
const writeRights = 0x2 | 0x4 | 0x10 | 0x40 | 0x100 | // FILE_WRITE_DATA/ADD_FILE, APPEND_DATA/ADD_SUBDIRECTORY, WRITE_EA, DELETE_CHILD, WRITE_ATTRIBUTES
	windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER | windows.GENERIC_WRITE | windows.GENERIC_ALL

// checkSD applies the store's rule to a security descriptor: the owner and
// every allow entry must be this account, SYSTEM or Administrators, and a
// protected DACL when protected is set. readOnly also requires an owner
// other than this account, which could rewrite the DACL, and no write right
// in this account's entries, inherit-only ones included (D2-12).
func checkSD(what, path string, sd *windows.SECURITY_DESCRIPTOR, protected, readOnly bool) error {
	allowed, err := allowedSIDs()
	if err != nil {
		return err
	}
	self := allowed[0]
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
	if protected && control&windows.SE_DACL_PROTECTED == 0 {
		return fmt.Errorf("%s %s inherits its DACL; it must be protected (A3 condition 1)", what, path)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}
	if owner == nil || !ok(owner) {
		return fmt.Errorf("%s %s is owned by %s; the owner must be this account, SYSTEM or Administrators (W-4)", what, path, owner)
	}
	if readOnly && windows.EqualSid(owner, self) {
		return fmt.Errorf("%s %s is owned by this account, which could rewrite its DACL; the owner must be SYSTEM or Administrators (D2-12)", what, path)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	if dacl == nil {
		return fmt.Errorf("%s %s has a null DACL, which grants everyone", what, path)
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return fmt.Errorf("%s %s: ACE %d: %w", what, path, i, err)
		}
		switch ace.Header.AceType {
		case windows.ACCESS_DENIED_ACE_TYPE:
			continue // a deny entry only narrows access
		case windows.ACCESS_ALLOWED_ACE_TYPE:
			sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
			if !ok(sid) {
				return fmt.Errorf("%s %s grants access to %s; only this account, SYSTEM and Administrators may have access", what, path, sid)
			}
			if readOnly && windows.EqualSid(sid, self) && ace.Mask&writeRights != 0 {
				return fmt.Errorf("%s %s lets this account write (access %#x); it may only read (D2-12)", what, path, ace.Mask)
			}
		default:
			return fmt.Errorf("%s %s: ACE %d has type %d, which this check does not read", what, path, i, ace.Header.AceType)
		}
	}
	return nil
}

func readProtected(path string, max int64) ([]byte, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	// FILE_FLAG_OPEN_REPARSE_POINT opens a link or junction itself, so the
	// attribute check below refuses it instead of following it.
	h, err := windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	f := os.NewFile(uintptr(h), path)
	defer f.Close()
	if t, err := windows.GetFileType(h); err != nil || t != windows.FILE_TYPE_DISK {
		return nil, fmt.Errorf("%s is not a file on disk (a device such as CON is refused)", path)
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 {
		return nil, fmt.Errorf("%s is not a regular file (a link or reparse point is refused)", path)
	}
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return nil, fmt.Errorf("%s: read DACL: %w", path, err)
	}
	if err := checkSD("file", path, sd, false, true); err != nil {
		return nil, err
	}
	if size := int64(info.FileSizeHigh)<<32 | int64(info.FileSizeLow); size > max {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, max)
	}
	return readAtMost(f, path, max)
}

func checkProtectedDir(dir string) error {
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return err
	}
	h, err := windows.CreateFile(p, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return fmt.Errorf("open directory %s: %w", dir, err)
	}
	defer windows.CloseHandle(h)
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return fmt.Errorf("%s: %w", dir, err)
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return fmt.Errorf("%s is not a plain directory (a junction or link is refused)", dir)
	}
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("%s: read DACL: %w", dir, err)
	}
	return checkSD("directory", dir, sd, true, true)
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
	// account goes into SDDL, so it is parsed as a SID first and written
	// back in canonical form: a string with SDDL syntax in it cannot add an
	// entry (A3 #84 note 1). StringToSid also takes SDDL aliases such as
	// WD (Everyone), so only the S-1- form is accepted (A3 #92 note 4).
	if !strings.HasPrefix(account, "S-1-") {
		return fmt.Errorf("store directory account %q is not a SID in S-1- form", account)
	}
	sid, err := windows.StringToSid(account)
	if err != nil {
		return fmt.Errorf("store directory account %q is not a SID: %w", account, err)
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + sid.String() + ")")
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
