package store

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"time"

	c5 "otsec.local/otsec/contracts/store"
)

// WAL bounds from E-A5-3, the values that kept the WAL bounded on a full
// disk: checkpoint every 64 pages and truncate the WAL back to 256 KiB.
const (
	WALAutocheckpointPages = 64
	JournalSizeLimitBytes  = 256 << 10
)

// WALBoundBytes is the most the WAL is expected to hold between
// checkpoints, at a 4 KiB page. The recovery reserve must be at least twice
// this (ADR-0004 item 1).
const WALBoundBytes = JournalSizeLimitBytes + WALAutocheckpointPages*4096

var databaseIDPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

// Options configure one database.
type Options struct {
	// Dir is the store directory. It holds every file of this database:
	// the database and its -wal and -shm, the lock file and both reserves.
	// It must exist. On Linux it must not be readable, writable or
	// searchable by group or others (A3 C5 review, section 4); on Windows
	// its protected DACL is set by the installer (W-4).
	Dir string
	// Node is the node ID every event of this database carries.
	Node c5.NodeID
	// Database is this database's entry in the node's Layout.
	Database c5.Database
	// Now is the clock; nil means time.Now.
	Now func() time.Time
	// Alarms receives every alarm the store raises outside startup. It is
	// called synchronously and must not call back into the store. Nil
	// discards them, which only tests should do.
	Alarms func(c5.Alarm)

	// hook is called at named points of every transaction. Only tests set
	// it, to kill the process at each commit point.
	hook func(point string)
	// freeBytes replaces the volume query. Only tests set it.
	freeBytes func() (int64, error)
}

func (o Options) validate() error {
	if o.Dir == "" {
		return invalid("store directory not set")
	}
	if !o.Node.Valid() {
		return invalid("node ID %q is not a lowercase DNS label", o.Node)
	}
	if !databaseIDPattern.MatchString(string(o.Database.ID)) {
		return invalid("database ID %q does not match %s", o.Database.ID, databaseIDPattern)
	}
	if len(o.Database.Streams) == 0 {
		return invalid("database %s has no streams", o.Database.ID)
	}
	// Layout.Validate requires exactly one audit stream per node. Only one
	// database holds it, so a database without one is checked next to a
	// placeholder audit database.
	l := c5.Layout{Databases: []c5.Database{o.Database}}
	if !holdsAudit(o.Database) {
		l.Databases = append(l.Databases, c5.Database{ID: "placeholder-audit", Writer: "placeholder",
			Streams: []c5.StreamSpec{{ID: "placeholder-audit", Class: c5.ClassAudit}},
			Classes: []c5.StreamClass{c5.ClassAudit}, Quotas: []c5.Quota{{Class: c5.ClassAudit, Bytes: 1, WarnFraction: 0.5}}})
	}
	return l.Validate()
}

func holdsAudit(d c5.Database) bool {
	for _, s := range d.Streams {
		if s.Class == c5.ClassAudit {
			return true
		}
	}
	return false
}

func (o Options) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now()
}

// Env is the contracts/store.StartupEnv of one database. None of its methods
// except Open touches the database, its WAL or its -shm.
type Env struct {
	opt Options
}

var _ c5.StartupEnv = (*Env)(nil)

// NewEnv checks opt and returns the database's startup environment.
func NewEnv(opt Options) (*Env, error) {
	if err := opt.validate(); err != nil {
		return nil, err
	}
	return &Env{opt: opt}, nil
}

// Path is the database file.
func (e *Env) Path() string { return filepath.Join(e.opt.Dir, string(e.opt.Database.ID)+".db") }

func (e *Env) lockPath() string { return filepath.Join(e.opt.Dir, string(e.opt.Database.ID)+".lock") }

func (e *Env) reservePath(r c5.Reserve) string {
	return filepath.Join(e.opt.Dir, string(e.opt.Database.ID)+".reserve-"+string(r))
}

// Lock takes an exclusive OS lock on the database's lock file and checks
// the directory's permissions. The lock is held until unlock is called.
func (e *Env) Lock(ctx context.Context) (func(), error) {
	if err := checkDir(e.opt.Dir); err != nil {
		return nil, err
	}
	return lockFile(e.lockPath())
}

// StoreExists reports whether the database file exists.
func (e *Env) StoreExists(ctx context.Context) (bool, error) { return exists(e.Path()) }

// ReserveExists reports whether the reserve exists, as a file of any size
// or anything else at its path.
func (e *Env) ReserveExists(ctx context.Context, r c5.Reserve) (bool, error) {
	return exists(e.reservePath(r))
}

// ReleaseReserve deletes the reserve. It returns nil only once nothing is
// at the reserve's path.
func (e *Env) ReleaseReserve(ctx context.Context, r c5.Reserve) error {
	p := e.reservePath(r)
	if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("release %s reserve: %w", r, err)
	}
	if ok, err := exists(p); err != nil || ok {
		return fmt.Errorf("release %s reserve: still present (%v)", r, err)
	}
	return nil
}

// FreeBytes is the space available to this process on the store's volume.
func (e *Env) FreeBytes(ctx context.Context) (int64, error) {
	if e.opt.freeBytes != nil {
		return e.opt.freeBytes()
	}
	return freeBytes(e.opt.Dir)
}

// Open opens the database, creating it if absent.
func (e *Env) Open(ctx context.Context) (c5.RecoveryStore, error) {
	return open(ctx, e.Path(), e.opt)
}

// AsDB returns the *DB behind a RecoveryStore that Open returned. The node
// uses it to get the Committer and the Log's start positions from
// RunStartup's Report.Store.
func AsDB(s c5.RecoveryStore) (*DB, bool) {
	db, ok := s.(*DB)
	return db, ok
}

// CreateReserve writes a reserve of exactly n bytes of zeros and flushes
// it. Zeros are written, not a sparse file, because a sparse file holds no
// space. On any error it removes what it wrote.
func (e *Env) CreateReserve(ctx context.Context, r c5.Reserve, n int64) (err error) {
	if n <= 0 {
		return fmt.Errorf("reserve size %d", n)
	}
	p := e.reservePath(r)
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create %s reserve: %w", r, err)
	}
	defer func() {
		if cerr := f.Close(); err == nil && cerr != nil {
			err = cerr
		}
		if err != nil {
			os.Remove(p)
		}
	}()
	buf := make([]byte, 64<<10)
	for left := n; left > 0; {
		if err := ctx.Err(); err != nil {
			return err
		}
		k := min(left, int64(len(buf)))
		if _, err := f.Write(buf[:k]); err != nil {
			return fmt.Errorf("write %s reserve: %w", r, err)
		}
		left -= k
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("flush %s reserve: %w", r, err)
	}
	return syncDir(e.opt.Dir)
}

func exists(p string) (bool, error) {
	_, err := os.Lstat(p)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, fs.ErrNotExist):
		return false, nil
	}
	return false, err
}

// ReadProtectedFile reads a file the node may read but never change, such
// as a TLS trust anchor or its client key (D2-12). It opens the file
// without following a link or reparse point and checks the opened handle,
// not the path: it must be a regular file on disk (no device such as
// CON) with one hard link, of at most max bytes, that only this account, SYSTEM and
// Administrators can reach, and that this account cannot write. On Linux
// that is mode 0400 (no write bit, nothing for group and others); on
// Windows the store's owner and ACE rule, with an owner other than this
// account and no write right in this account's entries. Errors name the
// path only, never the content.
func ReadProtectedFile(path string, max int64) ([]byte, error) { return readProtected(path, max) }

// ReadPublicFile reads a file another service writes for this one, such as
// the collector's install-key.json: the handle checks of ReadProtectedFile
// (a regular file on disk, not a link, reparse point or device, at most max
// bytes) without its owner and mode rule, since the writer owns the file.
// Its integrity comes from the directory's DACL. On Windows the file is
// opened shared for write and delete, so the writer can rename a new file
// over it meanwhile.
func ReadPublicFile(path string, max int64) ([]byte, error) { return readPublic(path, max) }

// CheckProtectedDir refuses a directory that would let this account change
// the files in it (D2-12): the store directory rule (checkDir), with no
// write for this account. On Linux that is mode 0500; on Windows a
// protected DACL, an owner other than this account, and no write right in
// this account's entries. A link or reparse point is refused.
func CheckProtectedDir(dir string) error { return checkProtectedDir(dir) }

// ReadProtectedFileFor is ReadProtectedFile for a file that other named
// services may read too, such as an administrator's file in
// OTSEC\config\admin that both the node and the collector read (A3,
// A1). readers are the SIDs of those services, as strings; this account
// may be among them or not.
//
// On Windows the rule is stricter than ReadProtectedFile's (A3):
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
// ReadProtectedFile and CheckProtectedDir.
func ReadProtectedFileFor(path string, max int64, readers []string) ([]byte, error) {
	return readProtectedFor(path, max, readers)
}

// CheckProtectedDirFor is CheckProtectedDir for a directory that the
// readers may also read, under ReadProtectedFileFor's rule; the DACL must
// also be protected, so nothing comes down from the parent. On Linux the
// mode must be within 0550.
func CheckProtectedDirFor(dir string, readers []string) error {
	return checkProtectedDirFor(dir, readers)
}
