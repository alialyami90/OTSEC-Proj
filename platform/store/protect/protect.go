// Package protect reads files and checks directories that a service may
// read but must not be able to change: an administrator's file, a TLS key,
// another service's published file (D2-12, D2-15). It holds no database,
// so a privileged binary such as otsec-collector can link it without
// platform/store's SQLite (A3).
//
// Every read opens the file without following a link or reparse point and
// checks the opened handle, not the path. The rules are evidenced on
// Windows; on Linux, a development platform only, a mode check guards
// against mistakes and does not prove the boundary.
package protect

import (
	"fmt"
	"io"
)

// ReadFile reads a file the node may read but never change, such
// as a TLS trust anchor or its client key (D2-12). It opens the file
// without following a link or reparse point and checks the opened handle,
// not the path: it must be a regular file on disk (no device such as
// CON) with one hard link, of at most max bytes, that only this account, SYSTEM and
// Administrators can reach, and that this account cannot write. On Linux
// that is mode 0400 (no write bit, nothing for group and others); on
// Windows the store's owner and ACE rule, with an owner other than this
// account and no write right in this account's entries. Errors name the
// path only, never the content.
func ReadFile(path string, max int64) ([]byte, error) { return readProtected(path, max) }

// ReadPublicFile reads a file another service writes for this one, such as
// the collector's install-key.json: the handle checks of ReadFile
// (a regular file on disk, not a link, reparse point or device, at most max
// bytes) without its owner and mode rule, since the writer owns the file.
// Its integrity comes from the directory's DACL. On Windows the file is
// opened shared for write and delete, so the writer can rename a new file
// over it meanwhile.
func ReadPublicFile(path string, max int64) ([]byte, error) { return readPublic(path, max) }

// CheckDir refuses a directory that would let this account change
// the files in it (D2-12): the store directory rule (CheckOwnACL), with no
// write for this account. On Linux that is mode 0500; on Windows a
// protected DACL, an owner other than this account, and no write right in
// this account's entries. A link or reparse point is refused.
func CheckDir(dir string) error { return checkProtectedDir(dir) }

// ReadFileFor is ReadFile for a file that other named
// services may read too, such as an administrator's file in
// OTSEC\config\admin that both the node and the collector read (A3,
// A1). readers are the SIDs of those services, as strings; this account
// may be among them or not.
//
// On Windows the rule is stricter than ReadFile's (A3):
//   - the owner is SYSTEM or Administrators, never this account or a
//     reader;
//   - an entry for this account or a reader is an ACCESS_ALLOWED_ACE whose
//     mask is within read and traverse (0x1200a9); a generic bit, any
//     other right, or another entry type is refused, never mapped;
//   - every other allow entry names SYSTEM or Administrators; CREATOR
//     OWNER, OWNER RIGHTS and any other SID are refused;
//   - inherited entries are checked as explicit ones, inherit-only ones
//     included.
//
// On Linux, a development platform only, readers are not used: the file
// may be read by its owner and group, and written by nobody (0440). A
// mode check does not prove that this account could not have written the
// file: the directory's owner can make it writable, plant a file and
// restore the mode. On Linux it guards against mistakes only; the
// boundary is evidenced on Windows only (A3). The same holds for
// ReadFile and CheckDir.
func ReadFileFor(path string, max int64, readers []string) ([]byte, error) {
	return readProtectedFor(path, max, readers)
}

// CheckDirFor is CheckDir for a directory that the
// readers may also read, under ReadFileFor's rule; the DACL must
// also be protected, so nothing comes down from the parent. On Linux the
// mode must be within 0550.
func CheckDirFor(dir string, readers []string) error {
	return checkProtectedDirFor(dir, readers)
}

// readAtMost reads f to its end, refusing more than max bytes.
func readAtMost(f io.Reader, path string, max int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, max)
	}
	return b, nil
}
