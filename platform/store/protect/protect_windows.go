//go:build windows

package protect

import (
	"fmt"
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// CheckOwnACL applies the store directory rule to path's owner and DACL
// (platform/store's checkDir and checkFile): the owner and every allow
// entry name this account, SYSTEM or Administrators. protected also
// requires the DACL to be protected. what names the object in errors.
// It admits this account as owner and writer, so it is the store's rule
// and never for a file this account must not be able to change: use
// ReadFile or ReadFileFor for that (A6 on #116). Windows only: on Linux
// the store checks modes itself.
func CheckOwnACL(what, path string, protected bool) error {
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
	return readSDChecked(path, max, func(sd *windows.SECURITY_DESCRIPTOR) error {
		return checkSD("file", path, sd, false, true)
	})
}

func readProtectedFor(path string, max int64, readers []string) ([]byte, error) {
	sids, err := readerSIDs(readers)
	if err != nil {
		return nil, err
	}
	return readSDChecked(path, max, func(sd *windows.SECURITY_DESCRIPTOR) error {
		return checkSDFor("file", path, sd, false, sids)
	})
}

func readPublic(path string, max int64) ([]byte, error) { return readSDChecked(path, max, nil) }

// readSDChecked opens path and applies check to its security descriptor;
// a nil check is a public file, whose DACL is not read.
func readSDChecked(path string, max int64, check func(*windows.SECURITY_DESCRIPTOR) error) ([]byte, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	// A public file is shared for write and delete too, so that its
	// writer can rename a new one over it while the node reads (A3 #106).
	share := uint32(windows.FILE_SHARE_READ)
	if check == nil {
		share |= windows.FILE_SHARE_WRITE | windows.FILE_SHARE_DELETE
	}
	// FILE_FLAG_OPEN_REPARSE_POINT opens a link or junction itself, so the
	// attribute check below refuses it instead of following it.
	h, err := windows.CreateFile(p, windows.GENERIC_READ, share, nil,
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
	if check != nil {
		if info.NumberOfLinks > 1 {
			// Defence in depth (A6 on #108): a hard link would carry
			// another path's file, and its DACL, into the checked directory.
			return nil, fmt.Errorf("%s has %d hard links; only a file with one is read", path, info.NumberOfLinks)
		}
		sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			return nil, fmt.Errorf("%s: read DACL: %w", path, err)
		}
		if err := check(sd); err != nil {
			return nil, err
		}
	}
	if size := int64(info.FileSizeHigh)<<32 | int64(info.FileSizeLow); size > max {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, max)
	}
	return readAtMost(f, path, max)
}

func checkProtectedDir(dir string) error {
	return checkDirSD(dir, func(sd *windows.SECURITY_DESCRIPTOR) error {
		return checkSD("directory", dir, sd, true, true)
	})
}

func checkProtectedDirFor(dir string, readers []string) error {
	sids, err := readerSIDs(readers)
	if err != nil {
		return err
	}
	return checkDirSD(dir, func(sd *windows.SECURITY_DESCRIPTOR) error {
		return checkSDFor("directory", dir, sd, true, sids)
	})
}

func checkDirSD(dir string, check func(*windows.SECURITY_DESCRIPTOR) error) error {
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
	return check(sd)
}

// readRights is the most an entry for this account or a reader may grant
// in checkSDFor: FILE_GENERIC_READ | FILE_GENERIC_EXECUTE, which is read
// and traverse (A3).
const readRights = 0x1200a9

// readerSIDs parses the readers of ReadFileFor. CREATOR OWNER and
// OWNER RIGHTS are refused: they name whoever owns or creates the object,
// not a service. They are compared as SIDs, so no spelling gets past
// (A3 and A6 on #108).
func readerSIDs(readers []string) ([]*windows.SID, error) {
	var owners []*windows.SID
	for _, w := range []windows.WELL_KNOWN_SID_TYPE{windows.WinCreatorOwnerSid, windows.WinCreatorOwnerRightsSid} {
		sid, err := windows.CreateWellKnownSid(w)
		if err != nil {
			return nil, err
		}
		owners = append(owners, sid)
	}
	var sids []*windows.SID
	for _, r := range readers {
		sid, err := windows.StringToSid(r)
		if err != nil {
			return nil, fmt.Errorf("reader %q is not a SID: %w", r, err)
		}
		if !strings.EqualFold(sid.String(), r) {
			// StringToSid saturates a subauthority above 32 bits, so the
			// SID checked would not be the one named.
			return nil, fmt.Errorf("reader %q is not a SID as written (it reads as %s)", r, sid)
		}
		for _, o := range owners {
			if windows.EqualSid(sid, o) {
				return nil, fmt.Errorf("reader %s names an owner, not a service", r)
			}
		}
		sids = append(sids, sid)
	}
	return sids, nil
}

// checkSDFor is ReadFileFor's rule (A3): owner SYSTEM or
// Administrators; every allow entry SYSTEM or Administrators, or this
// account or a reader within readRights; nothing else. dir also requires a
// protected DACL. A deny entry only narrows access and is passed.
func checkSDFor(what, path string, sd *windows.SECURITY_DESCRIPTOR, dir bool, readers []*windows.SID) error {
	allowed, err := allowedSIDs()
	if err != nil {
		return err
	}
	self, system, admins := allowed[0], allowed[1], allowed[2]
	control, _, err := sd.Control()
	if err != nil {
		return err
	}
	if dir && control&windows.SE_DACL_PROTECTED == 0 {
		return fmt.Errorf("%s %s inherits its DACL; it must be protected", what, path)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}
	if owner == nil || !windows.EqualSid(owner, system) && !windows.EqualSid(owner, admins) {
		return fmt.Errorf("%s %s is owned by %s; the owner must be SYSTEM or Administrators", what, path, owner)
	}
	reader := func(sid *windows.SID) bool {
		if windows.EqualSid(sid, self) {
			return true
		}
		for _, r := range readers {
			if windows.EqualSid(sid, r) {
				return true
			}
		}
		return false
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
			continue
		case windows.ACCESS_ALLOWED_ACE_TYPE:
		default:
			return fmt.Errorf("%s %s: ACE %d has type %d; only plain allow and deny entries are accepted", what, path, i, ace.Header.AceType)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		switch {
		case windows.EqualSid(sid, system), windows.EqualSid(sid, admins):
		case reader(sid):
			if ace.Mask&^readRights != 0 {
				return fmt.Errorf("%s %s grants %s access %#x; a reader may only read and traverse (%#x)", what, path, sid, ace.Mask, readRights)
			}
		default:
			return fmt.Errorf("%s %s grants access to %s; only SYSTEM, Administrators, this account and the named readers may have access", what, path, sid)
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
