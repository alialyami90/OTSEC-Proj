package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sync"

	_ "modernc.org/sqlite" // registers the "sqlite" driver

	c5 "otsec.local/otsec/contracts/store"
)

// Format is the schema identifier kept in every database's meta table.
// A database with another format is refused, never migrated, in Phase 2.
// Format 2 (C5 0.5, D4-14) has rowid events and captures tables: the first
// format's WITHOUT ROWID tables spilled every row over about 1 KB to an
// overflow page of its own, so a commit wrote up to 3.3 times the WAL the
// reserve rule allows and the file grew up to 4.5 times the bytes the quota
// counts.
const Format = "otsec.platform-store/2"

// legacyFormat is the first format. It is refused with legacyRefusal.
const legacyFormat = "otsec.platform-store/1"

// legacyRefusal is why a database of the first format is not opened, and
// the way out. It is never changed, rewritten or deleted by the node.
func legacyRefusal(path string) error {
	return invalid("store %s was created by an earlier layout (format %s, events and captures WITHOUT ROWID); "+
		"the recovery reserve is not sized for it (C5 0.5, D4-14), so it is not opened, changed or deleted. "+
		"To start on this layout: stop the node, copy the store directory aside, let any events you need "+
		"forward upstream first (or keep the copy), remove the database files, and start the node (platform/node README, \"Store layout changes\")",
		path, legacyFormat)
}

// refuseLegacy returns legacyRefusal when the database at path is of the
// first format, and nil otherwise, including when the file cannot be read as
// a store: the open that follows reports that. It must write neither the
// database file nor its -wal. An ordinary open folds a hot -wal into the file
// and deletes it when the connection closes, and a refused database must be
// left as it was found (B1 on #282).
//
// A format row can be in the -wal, not yet in the main file (B6's #280), so
// the main file alone is not enough once the -wal holds frames. Then the
// check reads through the WAL with a read-only connection: it cannot
// checkpoint or delete the -wal, and the most it writes is the -shm, which is
// derived from the -wal and rebuilt when it is missing. With no -wal, or an
// empty one, nothing is in it, and the main file is read alone and immutable,
// so SQLite takes no lock and creates no -wal or -shm.
func refuseLegacy(ctx context.Context, path string) error {
	query := "mode=ro"
	if st, err := os.Stat(path + "-wal"); err != nil || st.Size() == 0 {
		query = "mode=ro&immutable=1"
	}
	sdb, err := sql.Open("sqlite", fileURI(path, query))
	if err != nil {
		return nil
	}
	defer sdb.Close()
	var format string
	if err := sdb.QueryRowContext(ctx, `SELECT value FROM meta WHERE key = 'format'`).Scan(&format); err != nil {
		return nil
	}
	if format == legacyFormat {
		return legacyRefusal(path)
	}
	return nil
}

// DB is one open database. It implements contracts/store.Committer and
// contracts/store.RecoveryStore.
type DB struct {
	opt  Options
	path string
	db   *sql.DB

	mu      sync.Mutex // one transaction at a time on conn
	conn    *sql.Conn
	sync    c5.Sync
	streams map[c5.StreamID]c5.StreamClass
	quotas  map[c5.StreamClass]c5.Quota
	full    map[c5.StreamClass]bool // quota-reached alarm raised and not cleared
	warned  map[c5.StreamClass]bool
	closed  bool
	// readOnly is set by OpenReadOnly: every transaction is refused.
	readOnly bool
}

var (
	_ c5.Committer     = (*DB)(nil)
	_ c5.RecoveryStore = (*DB)(nil)
)

const schema = `
CREATE TABLE meta (
	key   TEXT PRIMARY KEY,
	value TEXT NOT NULL
) WITHOUT ROWID;
CREATE TABLE streams (
	stream        TEXT PRIMARY KEY,
	class         TEXT NOT NULL,
	last_seq      INTEGER NOT NULL DEFAULT 0,
	last_at       INTEGER NOT NULL DEFAULT 0,
	source_cursor BLOB,
	head_seq      INTEGER,
	head_hash     TEXT,
	anchor_seq    INTEGER,
	anchor_hash   TEXT
) WITHOUT ROWID;
CREATE TABLE events (
	id            INTEGER PRIMARY KEY,
	stream        TEXT NOT NULL,
	seq           INTEGER NOT NULL,
	event         BLOB NOT NULL,
	capture       TEXT,
	source_cursor BLOB,
	committed_at  INTEGER NOT NULL
);
CREATE UNIQUE INDEX events_key ON events (stream, seq);
CREATE INDEX events_by_time ON events (stream, committed_at, seq);
CREATE INDEX events_by_capture ON events (capture) WHERE capture IS NOT NULL;
CREATE TABLE captures (
	id     INTEGER PRIMARY KEY,
	sha256 TEXT NOT NULL,
	class  TEXT NOT NULL,
	bytes  BLOB NOT NULL
);
CREATE UNIQUE INDEX captures_key ON captures (sha256);
CREATE TABLE cursors (
	consumer TEXT NOT NULL,
	stream   TEXT NOT NULL,
	through  INTEGER NOT NULL,
	PRIMARY KEY (consumer, stream)
) WITHOUT ROWID;
CREATE TABLE class_bytes (
	class TEXT PRIMARY KEY,
	bytes INTEGER NOT NULL
) WITHOUT ROWID;
`

// connPragmas are set on every open. They are per connection in SQLite, so
// setting them changes no persistent setting of an existing store.
// busy_timeout comes first: it needs no read of the file, and every other
// statement may start the connection's first read, which after a killed
// writer can meet another connection's WAL recovery (SQLITE_BUSY_RECOVERY,
// 261). With the handler set, the read waits for the recovery instead of
// failing the open (A1 and A6, store-full e2e on 9c50395).
var connPragmas = []string{
	"PRAGMA busy_timeout=5000",
	"PRAGMA synchronous=FULL",
	fmt.Sprintf("PRAGMA wal_autocheckpoint=%d", WALAutocheckpointPages),
	fmt.Sprintf("PRAGMA journal_size_limit=%d", JournalSizeLimitBytes),
	"PRAGMA temp_store=MEMORY",
	"PRAGMA foreign_keys=OFF",
}

func open(ctx context.Context, path string, opt Options) (*DB, error) {
	if err := checkFiles(path); err != nil {
		return nil, err
	}
	existed, err := exists(path)
	if err != nil {
		return nil, err
	}
	if !existed {
		if err := create(ctx, path, opt); err != nil {
			return nil, err
		}
	} else if err := refuseLegacy(ctx, path); err != nil {
		return nil, err
	}
	d, err := connect(ctx, path, opt)
	if err != nil {
		return nil, err
	}
	if err := d.load(ctx); err != nil {
		d.Close()
		return nil, err
	}
	return d, nil
}

// checkFiles applies checkFile to the database and its -wal and -shm, so a
// file whose own mode or DACL was widened after the directory was checked
// is refused before SQLite opens it.
func checkFiles(path string) error {
	for _, suffix := range []string{"", "-wal", "-shm"} {
		if err := checkFile(path + suffix); err != nil {
			return err
		}
	}
	return nil
}

// create builds a new database at path+".new" and renames it into place
// once its schema has committed, so a crash during creation never leaves a
// file at path that is not a complete store (A6 review of #77). Leftovers of
// an earlier interrupted creation were never a store and are removed.
func create(ctx context.Context, path string, opt Options) error {
	tmp := path + ".new"
	for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
		if err := os.Remove(tmp + suffix); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("remove interrupted creation %s: %w", tmp+suffix, err)
		}
	}
	// SQLite gives the -wal and -shm files the database file's mode, so
	// creating it 0600 keeps all three owner-only on Linux (A3 C5 review,
	// section 4). An empty file is a new database.
	f, err := os.OpenFile(tmp, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create %s: %w", tmp, err)
	}
	f.Close()
	d, err := connect(ctx, tmp, opt)
	if err != nil {
		return err
	}
	// Nothing reads the file before the rename, so its writes need no flush
	// of their own: synchronous=OFF here, and one flush of the whole file
	// before the rename below. This replaces about ten flushes per new
	// database (#230). synchronous is per connection; every later open sets
	// FULL again, and load checks it.
	// auto_vacuum must be set before the first table (E-A5-3 case 3), and
	// journal_mode=WAL is persistent. Both are set only here, on a new file.
	for _, q := range []string{"PRAGMA synchronous=OFF", "PRAGMA auto_vacuum=INCREMENTAL", "PRAGMA journal_mode=WAL"} {
		if _, err := d.conn.ExecContext(ctx, q); err != nil {
			d.Close()
			return fmt.Errorf("create %s: %s: %w", tmp, q, err)
		}
	}
	if err := d.create(ctx); err != nil {
		d.Close()
		return fmt.Errorf("create %s: %w", tmp, err)
	}
	if err := d.Close(); err != nil {
		return fmt.Errorf("create %s: close: %w", tmp, err)
	}
	d.point("create:closed")
	if err := flushCreated(tmp); err != nil {
		return fmt.Errorf("create %s: %w", tmp, err)
	}
	d.point("create:rename")
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	d.point("create:renamed")
	return syncDir(opt.Dir)
}

// flushCreated flushes a closed new database to disk. The close checkpointed
// its WAL into it and removed the -wal file; one that is still there holds
// committed pages the rename would leave behind, so it is refused.
func flushCreated(tmp string) error {
	if _, err := os.Lstat(tmp + "-wal"); err == nil {
		return errors.New("WAL left after close")
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	f, err := os.OpenFile(tmp, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// connect opens path on one connection with the per-connection settings.
func connect(ctx context.Context, path string, opt Options) (*DB, error) {
	sdb, err := sql.Open("sqlite", fileURI(path, ""))
	if err != nil {
		return nil, err
	}
	sdb.SetMaxOpenConns(1)
	sdb.SetMaxIdleConns(1)
	sdb.SetConnMaxLifetime(0)
	conn, err := sdb.Conn(ctx)
	if err != nil {
		sdb.Close()
		return nil, err
	}
	d := &DB{opt: opt, path: path, db: sdb, conn: conn,
		streams: map[c5.StreamID]c5.StreamClass{}, quotas: map[c5.StreamClass]c5.Quota{},
		full: map[c5.StreamClass]bool{}, warned: map[c5.StreamClass]bool{}}
	for _, q := range connPragmas {
		if _, err := conn.ExecContext(ctx, q); err != nil {
			d.Close()
			return nil, fmt.Errorf("open %s: %s: %w", path, q, err)
		}
	}
	return d, nil
}

func (d *DB) create(ctx context.Context) error {
	return d.tx(ctx, "create", func() error {
		if _, err := d.conn.ExecContext(ctx, schema); err != nil {
			return err
		}
		for k, v := range map[string]string{"format": Format, "node_id": string(d.opt.Node), "database": string(d.opt.Database.ID)} {
			if _, err := d.conn.ExecContext(ctx, `INSERT INTO meta (key, value) VALUES (?, ?)`, k, v); err != nil {
				return err
			}
		}
		return nil
	})
}

// load registers the database's streams and reads its persisted classes.
// A stream whose persisted class differs from the configured one is refused:
// a stream has one class for life (C5 Layout).
func (d *DB) load(ctx context.Context) error {
	for _, q := range d.opt.Database.Quotas {
		d.quotas[q.Class] = q
	}
	rows, err := d.conn.QueryContext(ctx, `SELECT stream, class FROM streams`)
	if err != nil {
		return fmt.Errorf("read streams: %w", err)
	}
	for rows.Next() {
		var s, c string
		if err := rows.Scan(&s, &c); err != nil {
			rows.Close()
			return err
		}
		d.streams[c5.StreamID(s)] = c5.StreamClass(c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	var add []c5.StreamSpec
	for _, s := range d.opt.Database.Streams {
		have, ok := d.streams[s.ID]
		switch {
		case !ok:
			add = append(add, s)
		case have != s.Class:
			return invalid("stream %s is stored as %s and configured as %s; a stream has one class for life", s.ID, have, s.Class)
		}
	}
	if len(add) > 0 {
		err := d.tx(ctx, "streams", func() error {
			for _, s := range add {
				if _, err := d.conn.ExecContext(ctx, `INSERT INTO streams (stream, class) VALUES (?, ?)`, string(s.ID), string(s.Class)); err != nil {
					return err
				}
				d.streams[s.ID] = s.Class
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	return d.ensureHolds(ctx)
}

// tx runs f in one BEGIN IMMEDIATE transaction on the connection. The
// caller holds d.mu, or is open. hook points: <name>:begin before BEGIN,
// <name>:commit just before COMMIT, <name>:done after it returned.
func (d *DB) tx(ctx context.Context, name string, f func() error) error {
	if d.readOnly {
		return errReadOnly
	}
	d.point(name + ":begin")
	if _, err := d.conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return fmt.Errorf("%s: begin: %w", name, err)
	}
	if err := f(); err != nil {
		if _, rerr := d.conn.ExecContext(context.Background(), "ROLLBACK"); rerr != nil {
			return errors.Join(err, fmt.Errorf("%s: rollback: %w", name, rerr))
		}
		return err
	}
	d.point(name + ":commit")
	if _, err := d.conn.ExecContext(context.Background(), "COMMIT"); err != nil {
		d.conn.ExecContext(context.Background(), "ROLLBACK")
		return fmt.Errorf("%s: commit: %w", name, err)
	}
	d.point(name + ":done")
	return nil
}

func (d *DB) point(name string) {
	if d.opt.hook != nil {
		d.opt.hook(name)
	}
}

func (d *DB) lock() error {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return errors.New("store: database is closed")
	}
	return nil
}

// CheckSettings fails unless the database is in WAL mode at
// synchronous=FULL with the WAL bounds, was created with
// auto_vacuum=INCREMENTAL, keeps temporary data in memory, and belongs to
// this node and database. It changes nothing.
func (d *DB) CheckSettings(ctx context.Context) error {
	if err := d.lock(); err != nil {
		return err
	}
	defer d.mu.Unlock()
	d.sync = c5.SyncUnknown
	want := []struct {
		pragma string
		value  string
	}{
		{"journal_mode", "wal"},
		{"synchronous", "2"}, // FULL
		{"auto_vacuum", "2"}, // INCREMENTAL
		{"wal_autocheckpoint", fmt.Sprint(WALAutocheckpointPages)},
		{"journal_size_limit", fmt.Sprint(JournalSizeLimitBytes)},
		{"temp_store", "2"}, // MEMORY
	}
	for _, w := range want {
		var got string
		if err := d.conn.QueryRowContext(ctx, "PRAGMA "+w.pragma).Scan(&got); err != nil {
			return fmt.Errorf("read %s: %w", w.pragma, err)
		}
		if got != w.value {
			return invalid("%s is %s, want %s; an existing store's settings are never changed", w.pragma, got, w.value)
		}
	}
	meta := map[string]string{}
	rows, err := d.conn.QueryContext(ctx, `SELECT key, value FROM meta`)
	if err != nil {
		return fmt.Errorf("read meta: %w", err)
	}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			rows.Close()
			return err
		}
		meta[k] = v
	}
	rows.Close()
	if meta["format"] == legacyFormat {
		return legacyRefusal(d.path)
	}
	for k, v := range map[string]string{"format": Format, "node_id": string(d.opt.Node), "database": string(d.opt.Database.ID)} {
		if meta[k] != v {
			return invalid("store %s is %q, want %q", k, meta[k], v)
		}
	}
	d.sync = c5.SyncFull
	return nil
}

// QuickCheck runs PRAGMA quick_check.
func (d *DB) QuickCheck(ctx context.Context) error {
	if err := d.lock(); err != nil {
		return err
	}
	defer d.mu.Unlock()
	rows, err := d.conn.QueryContext(ctx, "PRAGMA quick_check")
	if err != nil {
		return err
	}
	defer rows.Close()
	var msgs []string
	for rows.Next() {
		var m string
		if err := rows.Scan(&m); err != nil {
			return err
		}
		msgs = append(msgs, m)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if len(msgs) != 1 || msgs[0] != "ok" {
		return fmt.Errorf("quick_check: %v", msgs)
	}
	return nil
}

// Usage is (page_count - freelist_count) * page_size and the sum of the
// database's class quotas.
func (d *DB) Usage(ctx context.Context) (used, limit int64, err error) {
	if err := d.lock(); err != nil {
		return 0, 0, err
	}
	defer d.mu.Unlock()
	pages, free, size, err := d.pages(ctx)
	if err != nil {
		return 0, 0, err
	}
	for _, q := range d.quotas {
		limit += q.Bytes
	}
	return (pages - free) * size, limit, nil
}

func (d *DB) pages(ctx context.Context) (pages, free, size int64, err error) {
	for _, p := range []struct {
		q string
		v *int64
	}{{"PRAGMA page_count", &pages}, {"PRAGMA freelist_count", &free}, {"PRAGMA page_size", &size}} {
		if err = d.conn.QueryRowContext(ctx, p.q).Scan(p.v); err != nil {
			return 0, 0, 0, fmt.Errorf("%s: %w", p.q, err)
		}
	}
	return pages, free, size, nil
}

// CompactStep returns up to n free pages to the filesystem with
// incremental_vacuum, then checkpoints and truncates the WAL. more is false
// once no free page is left. A step that frees nothing while free pages
// remain is an error, so startup cannot loop on it.
func (d *DB) CompactStep(ctx context.Context, n int) (more bool, err error) {
	if err := d.lock(); err != nil {
		return false, err
	}
	defer d.mu.Unlock()
	if d.readOnly {
		return false, errReadOnly
	}
	_, before, _, err := d.pages(ctx)
	if err != nil {
		return false, err
	}
	if before == 0 {
		return false, nil
	}
	if _, err := d.conn.ExecContext(ctx, fmt.Sprintf("PRAGMA incremental_vacuum(%d)", n)); err != nil {
		return false, fmt.Errorf("incremental_vacuum: %w", err)
	}
	if _, err := d.conn.ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		return false, fmt.Errorf("checkpoint: %w", err)
	}
	_, after, _, err := d.pages(ctx)
	if err != nil {
		return false, err
	}
	if after >= before {
		return false, fmt.Errorf("incremental_vacuum freed no pages (%d free)", after)
	}
	return after > 0, nil
}

// Close checkpoints and closes the database. Later calls fail.
func (d *DB) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil
	}
	d.closed = true
	if !d.readOnly {
		d.conn.ExecContext(context.Background(), "PRAGMA wal_checkpoint(TRUNCATE)")
	}
	return errors.Join(d.conn.Close(), d.db.Close())
}

// Streams returns the class of every stream the database holds, including
// streams no longer configured, which stay readable.
func (d *DB) Streams() map[c5.StreamID]c5.StreamClass {
	d.mu.Lock()
	defer d.mu.Unlock()
	m := make(map[c5.StreamID]c5.StreamClass, len(d.streams))
	for s, c := range d.streams {
		m[s] = c
	}
	return m
}

func invalid(format string, args ...any) error {
	return &c5.Error{Code: c5.CodeInvalid, Detail: fmt.Sprintf(format, args...)}
}

func codeErr(code c5.Code, err error, format string, args ...any) error {
	return &c5.Error{Code: code, Detail: fmt.Sprintf(format, args...), Err: err}
}
