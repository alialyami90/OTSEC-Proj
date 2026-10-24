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
