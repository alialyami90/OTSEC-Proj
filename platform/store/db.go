package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"sync"

	_ "modernc.org/sqlite" // registers the "sqlite" driver

	c5 "otsec.local/otsec/contracts/store"
)

// Format is the schema identifier kept in every database's meta table.
// A database with another format is refused, never migrated, in Phase 2.
const Format = "otsec.platform-store/1"

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
	stream        TEXT NOT NULL,
	seq           INTEGER NOT NULL,
	event         BLOB NOT NULL,
	capture       TEXT,
	source_cursor BLOB,
	committed_at  INTEGER NOT NULL,
	PRIMARY KEY (stream, seq)
) WITHOUT ROWID;
CREATE INDEX events_by_time ON events (stream, committed_at, seq);
CREATE INDEX events_by_capture ON events (capture) WHERE capture IS NOT NULL;
CREATE TABLE captures (
	sha256 TEXT PRIMARY KEY,
	class  TEXT NOT NULL,
	bytes  BLOB NOT NULL
) WITHOUT ROWID;
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
var connPragmas = []string{
	"PRAGMA synchronous=FULL",
	fmt.Sprintf("PRAGMA wal_autocheckpoint=%d", WALAutocheckpointPages),
	fmt.Sprintf("PRAGMA journal_size_limit=%d", JournalSizeLimitBytes),
	"PRAGMA temp_store=MEMORY",
	"PRAGMA busy_timeout=5000",
	"PRAGMA foreign_keys=OFF",
}

func open(ctx context.Context, path string, opt Options) (*DB, error) {
	existed, err := exists(path)
	if err != nil {
		return nil, err
	}
	if !existed {
		// SQLite gives the -wal and -shm files the database file's mode, so
		// creating it 0600 keeps all three owner-only on Linux (A3 C5
		// review, section 4). An empty file is a new database.
		f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return nil, fmt.Errorf("create %s: %w", path, err)
		}
		f.Close()
	}
	sdb, err := sql.Open("sqlite", path)
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
	fail := func(err error) (*DB, error) {
		conn.Close()
		sdb.Close()
		return nil, err
	}
	if !existed {
		// auto_vacuum must be set before the first table (E-A5-3 case 3),
		// and journal_mode=WAL is persistent. Both are set only here, on a
		// new file.
		for _, q := range []string{"PRAGMA auto_vacuum=INCREMENTAL", "PRAGMA journal_mode=WAL"} {
			if _, err := conn.ExecContext(ctx, q); err != nil {
				return fail(fmt.Errorf("create %s: %s: %w", path, q, err))
			}
		}
	}
	for _, q := range connPragmas {
		if _, err := conn.ExecContext(ctx, q); err != nil {
			return fail(fmt.Errorf("open %s: %s: %w", path, q, err))
		}
	}
	if !existed {
		if err := d.create(ctx); err != nil {
			return fail(err)
		}
	}
	if err := d.load(ctx); err != nil {
		return fail(err)
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
	if len(add) == 0 {
		return nil
	}
	return d.tx(ctx, "streams", func() error {
		for _, s := range add {
			if _, err := d.conn.ExecContext(ctx, `INSERT INTO streams (stream, class) VALUES (?, ?)`, string(s.ID), string(s.Class)); err != nil {
				return err
			}
			d.streams[s.ID] = s.Class
		}
		return nil
	})
}

// tx runs f in one BEGIN IMMEDIATE transaction on the connection. The
// caller holds d.mu, or is open. hook points: <name>:begin before BEGIN,
// <name>:commit just before COMMIT, <name>:done after it returned.
func (d *DB) tx(ctx context.Context, name string, f func() error) error {
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
	d.conn.ExecContext(context.Background(), "PRAGMA wal_checkpoint(TRUNCATE)")
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
