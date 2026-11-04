package storeholds

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/platform/store"
)

// C5 0.7 (#375, section 4; D4-39): the 0.7 side of the cross-version test.
// The 0.6 side, a 0.6 binary on a store a 0.7 binary had written, was pinned
// on main before the 0.7 store (#373, CI green on 68e3d57); no 0.6 code is
// left in the tree to run it. Here a 0.6 store is stood in for by SQL that
// removes what 0.7 adds, and a 0.6 commit by SQL that clears the two
// columns. Pinned:
//   - the migration at open adds doc_kind, doc_series and events_by_series,
//     keeps format otsec.platform-store/2, leaves the rows it found NULL,
//     and a second open changes nothing;
//   - a record with no series is refused by RemoveConfig, with nothing
//     removed;
//   - the newest-of-series check ignores a NULL row, even a newer one.
//
// Evidence class: simulated.
func TestC6StoreFromC5v06IsMigratedByThisCode(t *testing.T) {
	ctx := context.Background()
	d := database(c5.MinRecordBytes)
	dir := newDir(t)
	appendDocs := func(db *store.DB, from, n int) {
		t.Helper()
		l, err := c5.NewLogFor(db, node, d, c5.GroupOptions{MaxEvents: 10, MaxWait: time.Millisecond}, map[c5.StreamID]c5.Seq{cfg: c5.Seq(from - 1)})
		if err != nil {
			t.Fatal(err)
		}
		for i := from; i < from+n; i++ {
			if _, err := l.Append(ctx, c5.Record{Stream: cfg, Class: c5.ClassConfiguration, Event: fmt.Appendf(nil, `{"doc":%d}`, i)}); err != nil {
				t.Fatal(err)
			}
		}
	}
	db, done := session(t, dir, d)
	appendDocs(db, 1, 3)
	done()

	// A 0.6 store: the same rows, without what 0.7 adds.
	raw := rawDB(t, dir)
	for _, q := range []string{
		`DROP INDEX events_by_series`,
		`ALTER TABLE events DROP COLUMN doc_series`,
		`ALTER TABLE events DROP COLUMN doc_kind`,
	} {
		if _, err := raw.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	raw.Close()

	schema := func() string {
		t.Helper()
		raw := rawDB(t, dir)
		defer raw.Close()
		var format, check string
		if err := raw.QueryRow(`SELECT value FROM meta WHERE key = 'format'`).Scan(&format); err != nil || format != "otsec.platform-store/2" {
			t.Fatalf("format %q %v: 0.7 keeps format 2 (#375)", format, err)
		}
		if err := raw.QueryRow(`PRAGMA integrity_check`).Scan(&check); err != nil || check != "ok" {
			t.Fatalf("integrity_check: %q %v", check, err)
		}
		rows, err := raw.Query(`SELECT name, coalesce(sql, '') FROM sqlite_schema ORDER BY name`)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var out string
		for rows.Next() {
			var name, sql string
			if err := rows.Scan(&name, &sql); err != nil {
				t.Fatal(err)
			}
			out += name + ": " + sql + "\n"
		}
		return out
	}
	db, done = session(t, dir, d)
	done()
	migrated := schema()
	for _, want := range []string{"doc_kind TEXT", "doc_series TEXT",
		"events_by_series: CREATE INDEX events_by_series ON events (stream, doc_series, seq) WHERE doc_series IS NOT NULL"} {
		if !strings.Contains(migrated, want) {
			t.Errorf("after the migration the schema has no %q:\n%s", want, migrated)
		}
	}
	db, done = session(t, dir, d)
	done()
	if again := schema(); again != migrated {
		t.Errorf("a second open changed the schema:\n%s\nwas\n%s", again, migrated)
	}

	// The rows found are NULL; 0.7 commits name their series. Seq 6 is a
	// 0.6 commit after them, as a binary rolled back below 0.7 leaves it.
	db, done = session(t, dir, d)
	defer done()
	appendDocs(db, 4, 3)
	raw = rawDB(t, dir)
	defer raw.Close()
	if _, err := raw.Exec(`UPDATE events SET doc_kind = NULL, doc_series = NULL WHERE stream = ? AND seq = 6`, string(cfg)); err != nil {
		t.Fatal(err)
	}
	for seq, want := range map[int64]string{1: "", 2: "", 3: "", 4: "config.snapshot", 5: "config.snapshot", 6: ""} {
		var series sql.NullString
		if err := raw.QueryRow(`SELECT doc_series FROM events WHERE stream = ? AND seq = ?`, string(cfg), seq).Scan(&series); err != nil {
			t.Fatal(err)
		}
		if series.String != want || series.Valid != (want != "") {
			t.Errorf("seq %d: doc_series %+v, want %q", seq, series, want)
		}
	}

	stored := func() []c5.Seq {
		t.Helper()
		recs, err := db.Read(ctx, cfg, 0, 100)
		if err != nil {
			t.Fatal(err)
		}
		var out []c5.Seq
		for _, r := range recs {
			out = append(out, r.Key.Seq)
		}
		return out
	}
	all := []c5.Seq{1, 2, 3, 4, 5, 6}
	for _, seqs := range [][]c5.Seq{{1}, {6}, {4, 2}} {
		if _, err := db.RemoveConfig(ctx, cfg, c5.SeriesConfigSnapshot, seqs); !errors.Is(err, &c5.Error{Code: c5.CodeInvalid}) {
			t.Errorf("remove %v, naming a record with no series: %v", seqs, err)
		}
	}
	if _, err := db.RemoveConfig(ctx, cfg, c5.SeriesConfigSnapshot, []c5.Seq{5}); !errors.Is(err, &c5.Error{Code: c5.CodeInvalid}) {
		t.Errorf("remove 5, the newest of its series though seq 6 is later: %v", err)
	}
	if got := stored(); !slices.Equal(got, all) {
		t.Fatalf("after the refusals %v, want %v", got, all)
	}
	if r, err := db.RemoveConfig(ctx, cfg, c5.SeriesConfigSnapshot, []c5.Seq{4}); err != nil || r.Records != 1 {
		t.Fatalf("remove 4: %+v %v", r, err)
	}
	if got := stored(); !slices.Equal(got, []c5.Seq{1, 2, 3, 5, 6}) {
		t.Fatalf("after removing 4: %v", got)
	}
}

// session opens the store as open does, and returns a function that closes
// it and lets its directory go, so the same directory can be opened again.
func session(t *testing.T, dir string, d c5.Database) (*store.DB, func()) {
	t.Helper()
	env, err := store.NewEnv(store.Options{Dir: dir, Node: node, Database: d, Documents: docs})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	r := c5.RunStartup(ctx, env, c5.StartupPolicy{Streams: d.Streams, RecoveryReserveBytes: 2 * store.WALBoundBytes,
		LastResortReserveBytes: store.WALBoundBytes + c5.MinOpenHeadroom, OpenHeadroomBytes: store.WALBoundBytes + c5.MinOpenHeadroom,
		PruneStepEvents: 50, CompactStepPages: 32, PruneTarget: 0.8})
	if r.Mode != c5.ModeCollecting {
		t.Fatalf("startup %s: %v %v", r.Mode, r.Err, r.Steps)
	}
	db, ok := store.AsDB(r.Store)
	if !ok {
		t.Fatal("not the SQLite store")
	}
	return db, func() {
		db.Close()
		if r.Unlock != nil {
			r.Unlock()
		}
	}
}

// rawDB opens the store's only database file with a plain connection, as
// another binary would.
func rawDB(t *testing.T, dir string) *sql.DB {
	t.Helper()
	files, _ := filepath.Glob(filepath.Join(dir, "*.db"))
	if len(files) != 1 {
		t.Fatalf("database files %v", files)
	}
	raw, err := sql.Open("sqlite", "file:"+(&url.URL{Path: files[0]}).EscapedPath()+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
