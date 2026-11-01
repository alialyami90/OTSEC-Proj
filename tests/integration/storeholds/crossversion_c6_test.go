package storeholds

import (
	"context"
	"database/sql"
	"fmt"
	"maps"
	"net/url"
	"path/filepath"
	"slices"
	"testing"
	"time"

	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/platform/store"
)

// C5 0.7 (#375 at 243c4f8, section 4): a 0.6 binary on a store a 0.7 binary
// has written. This file runs against the C5 0.6 code on main, and must merge
// before the 0.7 store PR: after it, no 0.6 code is left in the tree to test.
//
// The 0.7 writer is stood in for by SQL, with the storage C5 named on #375:
// format otsec.platform-store/2 kept; events.doc_kind and events.doc_series,
// TEXT, nullable, no default; the partial index events_by_series ON events
// (stream, doc_series, seq) WHERE doc_series IS NOT NULL; and the two new
// hold codes, approved-difference and superseded-baseline. Pinned here:
//   - 0.6 opens the store (its format check passes);
//   - Held lists the new codes as written, and a prune past every record
//     leaves each held record stored;
//   - a 0.6 commit lands, with NULL in both new columns, and the rows 0.7
//     wrote keep theirs;
//   - a working-state checkpoint record in the stream is read like any
//     other record;
//   - the database passes integrity_check, and reopens.
//
// The node half of section 4 rests on code that is the same for any code
// 0.6 does not know: planHolds skips an unknown code (kept, never replaced or
// released, one store-holds-reconciled each; platform/node's holds tests), and
// locate compares digests only, so a checkpoint is passed over. Evidence
// class: simulated.
func TestC6StoreFromC5v07IsKeptByThisCode(t *testing.T) {
	ctx := context.Background()
	d := database(c5.MinRecordBytes)
	dir := newDir(t)

	type row struct{ kind, series string }
	docs07 := map[c5.Seq]row{
		1: {"evidence", "config.snapshot"},
		2: {"evidence", "config.difference"},
		3: {"evidence", "baseline.event"},
		4: {"evidence", "config.snapshot"},
		5: {"working-state", "eventcheckpoint.learner"},
		6: {"working-state", "eventcheckpoint.detector"},
	}
	newer := map[c5.Seq]c5.HoldCode{2: "approved-difference", 3: "superseded-baseline"}
	func() {
		db, done := session(t, dir, d)
		defer done()
		l, err := c5.NewLogFor(db, node, d, c5.GroupOptions{MaxEvents: 10, MaxWait: time.Millisecond}, map[c5.StreamID]c5.Seq{cfg: 0})
		if err != nil {
			t.Fatal(err)
		}
		for i := 1; i <= len(docs07); i++ {
			doc := fmt.Appendf(nil, `{"doc":%d}`, i)
			if r := docs07[c5.Seq(i)]; r.kind == "working-state" {
				doc = fmt.Appendf(nil, `{"schema":"otsec.eventcheckpoint/0.1","half":%q,"doc":%d}`, r.series, i)
			}
			rec := c5.Record{Stream: cfg, Class: c5.ClassConfiguration, Event: doc}
			if _, ok := newer[c5.Seq(i)]; ok {
				rec.Holds = []c5.Hold{{Reason: c5.HoldReason{Code: c5.HoldUnapprovedDifference, Ref: c5.Key{NodeID: node, Stream: "audit", Seq: c5.Seq(10 + i)}}}}
			}
			if _, err := l.Append(ctx, rec); err != nil {
				t.Fatal(err)
			}
		}
	}()

	// The 0.7 binary's open and writes, as C5 named them.
	raw := rawDB(t, dir)
	tx, err := raw.Begin()
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`ALTER TABLE events ADD COLUMN doc_kind TEXT`,
		`ALTER TABLE events ADD COLUMN doc_series TEXT`,
		`CREATE INDEX events_by_series ON events (stream, doc_series, seq) WHERE doc_series IS NOT NULL`,
	} {
		if _, err := tx.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	for seq, r := range docs07 {
		if _, err := tx.Exec(`UPDATE events SET doc_kind = ?, doc_series = ? WHERE stream = ? AND seq = ?`, r.kind, r.series, string(cfg), int64(seq)); err != nil {
			t.Fatal(err)
		}
	}
	for seq, code := range newer {
		if res, err := tx.Exec(`UPDATE holds SET code = ? WHERE stream = ? AND seq = ?`, string(code), string(cfg), int64(seq)); err != nil {
			t.Fatal(err)
		} else if n, _ := res.RowsAffected(); n != 1 {
			t.Fatalf("seq %d: %d hold rows", seq, n)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	var format string
	if err := raw.QueryRow(`SELECT value FROM meta WHERE key = 'format'`).Scan(&format); err != nil || format != "otsec.platform-store/2" {
		t.Fatalf("format %q %v: the 0.7 store keeps format 2 (#375)", format, err)
	}
	raw.Close()

	// This code opens it, lists the holds, commits, and prunes past every
	// record.
	db, done := session(t, dir, d)
	held, err := db.Held(ctx, cfg)
	if err != nil {
		t.Fatalf("Held over the 0.7 codes: %v", err)
	}
	got := map[c5.Seq]c5.HoldCode{}
	for _, h := range held {
		got[h.Seq] = h.Reason.Code
	}
	if !maps.Equal(got, newer) {
		t.Fatalf("held %v, want %v", got, newer)
	}
	l, err := c5.NewLogFor(db, node, d, c5.GroupOptions{MaxEvents: 10, MaxWait: time.Millisecond}, map[c5.StreamID]c5.Seq{cfg: c5.Seq(len(docs07))})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.Append(ctx, c5.Record{Stream: cfg, Class: c5.ClassConfiguration, Event: []byte(`{"doc":7}`)}); err != nil {
		t.Fatalf("a 0.6 commit into the 0.7 store: %v", err)
	}
	last := c5.Seq(len(docs07) + 1)
	recs, err := db.Read(ctx, cfg, 0, 100)
	if err != nil {
		t.Fatalf("reading the stream with its checkpoint records: %v", err)
	}
	if len(recs) != int(last) {
		t.Fatalf("read %d records, want %d", len(recs), last)
	}
	if err := db.SaveCursor(ctx, c5.Cursor{Consumer: "central", Stream: cfg, Through: last}); err != nil {
		t.Fatal(err)
	}
	b, err := c5.ComputeBoundary(ctx, db, db, []c5.Consumer{{ID: "central", Stream: cfg, Delivery: c5.Required}}, cfg, c5.ClassConfiguration, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if n, err := db.PruneStep(ctx, b, 100); err != nil || n != int(last)-len(newer) {
		t.Fatalf("PruneStep: %d %v, want the %d unheld records", n, err, int(last)-len(newer))
	}
	done()

	// What the 0.7 binary will find when it is back: the held rows with
	// their codes and columns, nothing else, and a sound file.
	raw = rawDB(t, dir)
	defer raw.Close()
	rows, err := raw.Query(`SELECT e.seq, e.doc_kind, e.doc_series, h.code FROM events e JOIN holds h ON h.stream = e.stream AND h.seq = e.seq WHERE e.stream = ? ORDER BY e.seq`, string(cfg))
	if err != nil {
		t.Fatal(err)
	}
	var left []c5.Seq
	for rows.Next() {
		var (
			seq                int64
			kind, series, code sql.NullString
		)
		if err := rows.Scan(&seq, &kind, &series, &code); err != nil {
			t.Fatal(err)
		}
		left = append(left, c5.Seq(seq))
		if w := docs07[c5.Seq(seq)]; kind.String != w.kind || series.String != w.series || c5.HoldCode(code.String) != newer[c5.Seq(seq)] {
			t.Errorf("seq %d after 0.6: %s %s %s, want %s %s %s", seq, kind.String, series.String, code.String, w.kind, w.series, newer[c5.Seq(seq)])
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(left, []c5.Seq{2, 3}) {
		t.Fatalf("held and stored after the prune %v, want 2 and 3", left)
	}
	var total int
	if err := raw.QueryRow(`SELECT count(*) FROM events WHERE stream = ?`, string(cfg)).Scan(&total); err != nil || total != len(newer) {
		t.Fatalf("%d records stored after the prune (%v), want only the held %d", total, err, len(newer))
	}
	var check string
	if err := raw.QueryRow(`PRAGMA integrity_check`).Scan(&check); err != nil || check != "ok" {
		t.Fatalf("integrity_check: %q %v", check, err)
	}
	// The 0.6 commit's columns, before the prune took it: checked on a second
	// store below, because the prune removes the unheld record 7.
	t.Run("a 0.6 commit leaves the new columns NULL", func(t *testing.T) {
		d := database(c5.MinRecordBytes)
		dir := newDir(t)
		func() {
			db, done := session(t, dir, d)
			defer done()
			l, err := c5.NewLogFor(db, node, d, c5.GroupOptions{MaxEvents: 10, MaxWait: time.Millisecond}, map[c5.StreamID]c5.Seq{cfg: 0})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := l.Append(ctx, c5.Record{Stream: cfg, Class: c5.ClassConfiguration, Event: []byte(`{"doc":1}`)}); err != nil {
				t.Fatal(err)
			}
		}()
		raw := rawDB(t, dir)
		for _, q := range []string{
			`ALTER TABLE events ADD COLUMN doc_kind TEXT`,
			`ALTER TABLE events ADD COLUMN doc_series TEXT`,
			`CREATE INDEX events_by_series ON events (stream, doc_series, seq) WHERE doc_series IS NOT NULL`,
			`UPDATE events SET doc_kind = 'evidence', doc_series = 'config.snapshot' WHERE seq = 1`,
		} {
			if _, err := raw.Exec(q); err != nil {
				t.Fatalf("%s: %v", q, err)
			}
		}
		raw.Close()
		db, done := session(t, dir, d)
		l, err := c5.NewLogFor(db, node, d, c5.GroupOptions{MaxEvents: 10, MaxWait: time.Millisecond}, map[c5.StreamID]c5.Seq{cfg: 1})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := l.Append(ctx, c5.Record{Stream: cfg, Class: c5.ClassConfiguration, Event: []byte(`{"doc":2}`)}); err != nil {
			t.Fatalf("a 0.6 commit into the 0.7 store: %v", err)
		}
		done()
		raw = rawDB(t, dir)
		defer raw.Close()
		want := map[int64][2]sql.NullString{
			1: {{String: "evidence", Valid: true}, {String: "config.snapshot", Valid: true}},
			2: {},
		}
		for seq, w := range want {
			var kind, series sql.NullString
			if err := raw.QueryRow(`SELECT doc_kind, doc_series FROM events WHERE stream = ? AND seq = ?`, string(cfg), seq).Scan(&kind, &series); err != nil {
				t.Fatal(err)
			}
			if kind != w[0] || series != w[1] {
				t.Errorf("seq %d: doc_kind %+v doc_series %+v, want %+v %+v", seq, kind, series, w[0], w[1])
			}
		}
	})
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
