package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	c5 "otsec.local/otsec/contracts/store"
)

// C5 0.7 in the SQLite store: each configuration record's series, the
// migration at open, and RemoveConfig (docs/phase4/C5-c5-0.7.md sections 2
// to 5, D4-39). Evidence class: simulated.

// seriesDoc is a test document of series s, naming cap when it has one.
func seriesDoc(n int, s string, cap *c5.Capture) []byte {
	if cap != nil {
		return fmt.Appendf(nil, `{"doc":%d,"series":%q,"cap":%q}`, n, s, cap.SHA256)
	}
	return fmt.Appendf(nil, `{"doc":%d,"series":%q}`, n, s)
}

// appendSeries commits one record per series in order to stream, with seq n
// the n-th, and returns their receipts' seqs.
func appendSeries(t *testing.T, db *DB, d c5.Database, stream c5.StreamID, series ...string) {
	t.Helper()
	l := configLog(t, db, d)
	for i, s := range series {
		if _, err := l.Append(bg, c5.Record{Stream: stream, Class: c5.ClassConfiguration, Event: seriesDoc(i, s, nil)}); err != nil {
			t.Fatalf("record %d (%s): %v", i+1, s, err)
		}
	}
}

// recount is the configuration class's bytes from the tables, as the quota
// counts them: events and source cursors, and each capture once.
func recount(t *testing.T, db *DB) int64 {
	t.Helper()
	var ev, caps int64
	if err := db.conn.QueryRowContext(bg, `SELECT coalesce(sum(length(e.event) + coalesce(length(e.source_cursor), 0)), 0)
		FROM events e JOIN streams s ON s.stream = e.stream WHERE s.class = ?`, string(c5.ClassConfiguration)).Scan(&ev); err != nil {
		t.Fatal(err)
	}
	if err := db.conn.QueryRowContext(bg, `SELECT coalesce(sum(length(bytes)), 0) FROM captures WHERE class = ?`,
		string(c5.ClassConfiguration)).Scan(&caps); err != nil {
		t.Fatal(err)
	}
	return ev + caps
}

func checkCounted(t *testing.T, db *DB, when string) {
	t.Helper()
	got, err := db.ClassBytes(bg, c5.ClassConfiguration)
	if err != nil {
		t.Fatal(err)
	}
	if want := recount(t, db); got != want {
		t.Errorf("%s: class bytes %d, recount %d", when, got, want)
	}
}

func seriesOf(t *testing.T, db *DB, stream c5.StreamID, seq c5.Seq) (kind, series sql.NullString) {
	t.Helper()
	if err := db.conn.QueryRowContext(bg, `SELECT doc_kind, doc_series FROM events WHERE stream = ? AND seq = ?`,
		string(stream), int64(seq)).Scan(&kind, &series); err != nil {
		t.Fatal(err)
	}
	return kind, series
}

// A commit keeps each record's DocumentInfo beside it, and a validator that
// returns a pair outside the closed table is refused with nothing stored.
func TestCommitKeepsDocumentSeries(t *testing.T) {
	db := openConfig(t, storeDir(t), configDB, nil)
	appendSeries(t, db, configDB, cfgA, c5.SeriesConfigSnapshot, c5.SeriesConfigDifference, c5.SeriesBaselineEvent,
		c5.SeriesCheckpointLearner, c5.SeriesCheckpointDetector)
	want := [][2]string{{"evidence", "config.snapshot"}, {"evidence", "config.difference"}, {"evidence", "baseline.event"},
		{"working-state", "eventcheckpoint.learner"}, {"working-state", "eventcheckpoint.detector"}}
	for i, w := range want {
		k, s := seriesOf(t, db, cfgA, c5.Seq(i+1))
		if k.String != w[0] || s.String != w[1] {
			t.Errorf("seq %d: %v %v, want %v", i+1, k, s, w)
		}
	}
	for _, bad := range []string{"baseline.configuration", ""} {
		l := configLog(t, db, configDB)
		_, err := l.Append(bg, c5.Record{Stream: cfgA, Class: c5.ClassConfiguration, Event: seriesDoc(9, bad, nil)})
		if !isCode(err, c5.CodeInvalid) {
			t.Errorf("series %q: %v", bad, err)
		}
	}
	// A validator that names a checkpoint as evidence.
	db.opt.Documents = func([]byte, *c5.Capture) (c5.DocumentInfo, error) {
		return c5.DocumentInfo{Kind: c5.DocumentEvidence, Series: c5.SeriesCheckpointLearner}, nil
	}
	if _, err := configLog(t, db, configDB).Append(bg, cfgRec(cfgA, 10)); !isCode(err, c5.CodeInvalid) {
		t.Errorf("an unpaired kind and series: %v", err)
	}
	if got := storedSeqs(t, db, cfgA); len(got) != len(want) {
		t.Errorf("stored %v after the refusals", got)
	}
	checkCounted(t, db, "after the refusals")
}

// The layout of TestRemoveConfigRefusals' stream cfgA, seq by seq: the
// newest config.snapshot is 13 (8 has no series), the newest learner 6 and
// the newest detector 10. 2 is held.
var refusalLayout = []string{
	c5.SeriesConfigSnapshot, c5.SeriesConfigSnapshot, c5.SeriesConfigDifference, c5.SeriesBaselineEvent,
	c5.SeriesCheckpointLearner, c5.SeriesCheckpointLearner, c5.SeriesCheckpointDetector, c5.SeriesConfigSnapshot,
	c5.SeriesConfigSnapshot, c5.SeriesCheckpointDetector, c5.SeriesConfigSnapshot, c5.SeriesConfigSnapshot, c5.SeriesConfigSnapshot,
}

func refusalStore(t *testing.T) *DB {
	t.Helper()
	db := openConfig(t, storeDir(t), configDB, nil)
	appendSeries(t, db, configDB, cfgA, refusalLayout...)
	appendSeries(t, db, configDB, cfgB, c5.SeriesConfigSnapshot, c5.SeriesConfigSnapshot)
	if err := db.Hold(bg, c5.Hold{Stream: cfgA, Seq: 2, Reason: baselineHold(7)}); err != nil {
		t.Fatal(err)
	}
	// Seq 8 as a binary before 0.7 commits it.
	if _, err := db.conn.ExecContext(bg, `UPDATE events SET doc_kind = NULL, doc_series = NULL WHERE stream = ? AND seq = 8`, string(cfgA)); err != nil {
		t.Fatal(err)
	}
	return db
}

func TestRemoveConfigRefusals(t *testing.T) {
	db := refusalStore(t)
	all := storedSeqs(t, db, cfgA)
	refused := []struct {
		name   string
		stream c5.StreamID
		series string
		seq    c5.Seq
	}{
		{"held", cfgA, c5.SeriesConfigSnapshot, 2},
		{"a config.difference", cfgA, c5.SeriesConfigSnapshot, 3},
		{"a baseline.event", cfgA, c5.SeriesConfigSnapshot, 4},
		{"a learner checkpoint as a snapshot", cfgA, c5.SeriesConfigSnapshot, 5},
		{"no series (pre-0.7)", cfgA, c5.SeriesConfigSnapshot, 8},
		{"the newest snapshot", cfgA, c5.SeriesConfigSnapshot, 13},
		{"the newest learner, with newer detectors", cfgA, c5.SeriesCheckpointLearner, 6},
		{"a detector as a learner", cfgA, c5.SeriesCheckpointLearner, 7},
		{"the newest detector", cfgA, c5.SeriesCheckpointDetector, 10},
		{"a snapshot as a detector", cfgA, c5.SeriesCheckpointDetector, 1},
		{"the newest of another stream", cfgB, c5.SeriesConfigSnapshot, 2},
		{"a series that is never removable", cfgA, c5.SeriesConfigDifference, 3},
		{"a stream not in this database", "config/asset-z", c5.SeriesConfigSnapshot, 1},
	}
	for _, c := range refused {
		if r, err := db.RemoveConfig(bg, c.stream, c.series, []c5.Seq{c.seq}); !isCode(err, c5.CodeInvalid) || r.Records != 0 {
			t.Errorf("%s: %+v %v", c.name, r, err)
		}
	}
	// Each refusal in a step of four whose other three are removable
	// removes nothing; so does a step naming the newest and older records.
	for _, bad := range []c5.Seq{2, 3, 4, 5, 8, 13} {
		if _, err := db.RemoveConfig(bg, cfgA, c5.SeriesConfigSnapshot, []c5.Seq{1, 9, bad, 11}); !isCode(err, c5.CodeInvalid) {
			t.Errorf("a step of four with %d: %v", bad, err)
		}
	}
	if got := storedSeqs(t, db, cfgA); !slices.Equal(got, all) {
		t.Fatalf("after the refusals %v, want %v", got, all)
	}
	checkCounted(t, db, "after the refusals")

	ev := open1(t, storeDir(t), evidenceDB, nil)
	if _, err := ev.RemoveConfig(bg, "relay1/ser", c5.SeriesConfigSnapshot, []c5.Seq{1}); !isCode(err, c5.CodeInvalid) {
		t.Errorf("an adapter-evidence stream: %v", err)
	}

	// What is removable is removed: four snapshots, the older learner and
	// the older detector, and the older record of the other stream.
	for _, step := range []struct {
		stream c5.StreamID
		series string
		seqs   []c5.Seq
	}{
		{cfgA, c5.SeriesConfigSnapshot, []c5.Seq{1, 9, 11, 12}},
		{cfgA, c5.SeriesCheckpointLearner, []c5.Seq{5}},
		{cfgA, c5.SeriesCheckpointDetector, []c5.Seq{7}},
		{cfgB, c5.SeriesConfigSnapshot, []c5.Seq{1}},
	} {
		if r, err := db.RemoveConfig(bg, step.stream, step.series, step.seqs); err != nil || r.Records != len(step.seqs) || len(r.Skipped) != 0 {
			t.Fatalf("%s %s %v: %+v %v", step.stream, step.series, step.seqs, r, err)
		}
	}
	if got := storedSeqs(t, db, cfgA); !slices.Equal(got, []c5.Seq{2, 3, 4, 6, 8, 10, 13}) {
		t.Errorf("cfgA after the removals %v", got)
	}
	if got := storedSeqs(t, db, cfgB); !slices.Equal(got, []c5.Seq{2}) {
		t.Errorf("cfgB after the removals %v", got)
	}
	checkCounted(t, db, "after the removals")
}

// A step that stops partway (a fault at its commit) removes nothing, and
// the counted bytes still match the tables. A second call removes what is
// left and lists what it skipped, including a seq past the stream's last.
func TestRemoveConfigFaultAndSkips(t *testing.T) {
	db := refusalStore(t)
	before, _ := db.ClassBytes(bg, c5.ClassConfiguration)
	db.opt.hook = func(p string) {
		if p == "remove:commit" {
			db.conn.ExecContext(context.Background(), "ROLLBACK") // the COMMIT that follows fails
		}
	}
	if _, err := db.RemoveConfig(bg, cfgA, c5.SeriesConfigSnapshot, []c5.Seq{1, 9}); err == nil {
		t.Fatal("a failed commit reported success")
	}
	db.opt.hook = nil
	if got, _ := db.ClassBytes(bg, c5.ClassConfiguration); got != before {
		t.Errorf("class bytes %d after the fault, want %d", got, before)
	}
	if got := storedSeqs(t, db, cfgA); !slices.Contains(got, 1) || !slices.Contains(got, 9) {
		t.Fatalf("the fault removed records: %v", got)
	}
	checkCounted(t, db, "after the fault")

	r, err := db.RemoveConfig(bg, cfgA, c5.SeriesConfigSnapshot, []c5.Seq{1, 9})
	if err != nil || r.Records != 2 || r.Bytes == 0 {
		t.Fatalf("first part: %+v %v", r, err)
	}
	r, err = db.RemoveConfig(bg, cfgA, c5.SeriesConfigSnapshot, []c5.Seq{1, 11, 9, 99})
	if err != nil || r.Records != 1 || !slices.Equal(r.Skipped, []c5.Seq{1, 9, 99}) {
		t.Fatalf("finishing call: %+v %v", r, err)
	}
	checkCounted(t, db, "after a removal finished by a second call")
}

// A capture is removed with the last retained record that refers to it.
// Here a held baseline and a later matching read share one transcript, so
// removing the read keeps the baseline's transcript (C2's note on #375).
func TestRemoveConfigKeepsSharedCapture(t *testing.T) {
	db := openConfig(t, storeDir(t), configDB, nil)
	l := configLog(t, db, configDB)
	shared, other := capture("transcript A"), capture("transcript B")
	for i, cp := range []*c5.Capture{&shared, &shared, &other, &other} {
		if _, err := l.Append(bg, c5.Record{Stream: cfgA, Class: c5.ClassConfiguration, Event: seriesDoc(i, c5.SeriesConfigSnapshot, cp), Capture: cp}); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Hold(bg, c5.Hold{Stream: cfgA, Seq: 1, Reason: baselineHold(7)}); err != nil {
		t.Fatal(err)
	}
	captures := func() int {
		var n int
		if err := db.conn.QueryRowContext(bg, `SELECT count(*) FROM captures`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	r, err := db.RemoveConfig(bg, cfgA, c5.SeriesConfigSnapshot, []c5.Seq{2})
	if err != nil || r.Records != 1 || r.Bytes != int64(len(seriesDoc(1, c5.SeriesConfigSnapshot, &shared))) || captures() != 2 {
		t.Fatalf("removing the read that shares the baseline's transcript: %+v %v, %d captures", r, err, captures())
	}
	r, err = db.RemoveConfig(bg, cfgA, c5.SeriesConfigSnapshot, []c5.Seq{3})
	if err != nil || r.Bytes != int64(len(seriesDoc(2, c5.SeriesConfigSnapshot, &other))) || captures() != 2 {
		t.Fatalf("removing a read whose transcript the newest shares: %+v %v, %d captures", r, err, captures())
	}
	checkCounted(t, db, "after the shared-capture removals")
}

// The remover runs with the class at its quota, which is when it matters
// most, and a commit then fits again.
func TestRemoveConfigAtQuota(t *testing.T) {
	d := withQuota(configDB, c5.ClassConfiguration, 256<<10)
	a := &alarms{}
	db := openConfig(t, storeDir(t), d, a)
	l := configLog(t, db, d)
	big := strings.Repeat("x", 60<<10)
	n := 0
	for ; ; n++ {
		_, err := l.Append(bg, c5.Record{Stream: cfgA, Class: c5.ClassConfiguration, Event: fmt.Appendf(nil, `{"doc":%d,"pad":%q}`, n, big)})
		if isCode(err, c5.CodeQuotaReached) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if n < 2 || !a.has(c5.AlarmQuotaReached) {
		t.Fatalf("%d records before the quota; alarms %v", n, a.got)
	}
	if r, err := db.RemoveConfig(bg, cfgA, c5.SeriesConfigSnapshot, []c5.Seq{1}); err != nil || r.Records != 1 {
		t.Fatalf("at the quota: %+v %v", r, err)
	}
	if _, err := configLog(t, db, d).Append(bg, cfgRec(cfgA, 99)); err != nil {
		t.Fatalf("a commit after the removal: %v", err)
	}
	checkCounted(t, db, "at the quota")
}

// noReserve is the store's Env with reserves that cannot be recreated, so
// startup ends drain-only.
type noReserve struct{ *Env }

func (noReserve) CreateReserve(context.Context, c5.Reserve, int64) error {
	return errors.New("no space for the reserve (test)")
}

func TestRemoveConfigWhileDrainOnly(t *testing.T) {
	dir := storeDir(t)
	db, first := testStore(t, Options{Dir: dir, Node: testNode, Database: configDB, Documents: testDocs}, policy(configDB), c5.ModeCollecting)
	appendSeries(t, db, configDB, cfgA, c5.SeriesConfigSnapshot, c5.SeriesConfigSnapshot)
	db.Close()
	unlock(first)
	env, err := NewEnv(Options{Dir: dir, Node: testNode, Database: configDB, Documents: testDocs})
	if err != nil {
		t.Fatal(err)
	}
	r := c5.RunStartup(bg, noReserve{env}, policy(configDB))
	defer unlock(r)
	if r.Mode != c5.ModeDrainOnly {
		t.Fatalf("mode %s: %v", r.Mode, r.Steps)
	}
	defer r.Store.Close()
	dr, _ := AsDB(r.Store)
	if got, err := dr.RemoveConfig(bg, cfgA, c5.SeriesConfigSnapshot, []c5.Seq{1}); err != nil || got.Records != 1 {
		t.Fatalf("drain-only: %+v %v", got, err)
	}
}

// The migration at open (section 2): a new configuration database has the
// columns and the index, a database of another layout does not; a 0.6
// database gets them in one transaction that a fault undoes whole, and a
// second open runs no migration.
func TestSeriesMigrationAtOpen(t *testing.T) {
	hasColumn := func(t *testing.T, conn interface {
		QueryRowContext(context.Context, string, ...any) *sql.Row
	}) bool {
		t.Helper()
		var n int
		if err := conn.QueryRowContext(bg, `SELECT count(*) FROM pragma_table_info('events') WHERE name IN ('doc_kind', 'doc_series')`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		var idx int
		if err := conn.QueryRowContext(bg, `SELECT count(*) FROM sqlite_schema WHERE name = 'events_by_series'`).Scan(&idx); err != nil {
			t.Fatal(err)
		}
		if (n == 2) != (idx == 1) || (n != 0 && n != 2) {
			t.Fatalf("%d of the columns and %d index: the migration is not whole", n, idx)
		}
		return n == 2
	}
	ev := open1(t, storeDir(t), evidenceDB, nil)
	if hasColumn(t, ev.conn) {
		t.Error("a database without the configuration class was migrated")
	}

	dir := storeDir(t)
	opt := Options{Dir: dir, Node: testNode, Database: configDB, Documents: testDocs}
	db, r := testStore(t, opt, policy(configDB), c5.ModeCollecting)
	if !hasColumn(t, db.conn) {
		t.Fatal("a new configuration database has no series columns")
	}
	appendSeries(t, db, configDB, cfgA, c5.SeriesConfigSnapshot)
	for _, q := range []string{`DROP INDEX events_by_series`, `ALTER TABLE events DROP COLUMN doc_series`, `ALTER TABLE events DROP COLUMN doc_kind`} {
		if _, err := db.conn.ExecContext(bg, q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	path := db.path
	db.Close()
	unlock(r)

	// A fault at the migration's commit leaves the 0.6 schema whole.
	var faulted *DB
	opt.hook = func(p string) {
		if p == "series:commit" && faulted != nil {
			faulted.conn.ExecContext(context.Background(), "ROLLBACK")
		}
	}
	faulted, err := connect(bg, path, opt)
	if err != nil {
		t.Fatal(err)
	}
	if err := faulted.load(bg); err == nil {
		t.Fatal("a failed migration commit reported success")
	}
	if hasColumn(t, faulted.conn) {
		t.Fatal("a failed migration left columns behind")
	}
	faulted.Close()

	var points []string
	opt.hook = func(p string) { points = append(points, p) }
	db, r = testStore(t, opt, policy(configDB), c5.ModeCollecting)
	if !hasColumn(t, db.conn) || !slices.Contains(points, "series:done") {
		t.Fatalf("the reopened 0.6 database was not migrated: %v", points)
	}
	if k, s := seriesOf(t, db, cfgA, 1); k.Valid || s.Valid {
		t.Errorf("the record found has %v %v, want NULL in both", k, s)
	}
	db.Close()
	unlock(r)
	points = nil
	db, _ = testStore(t, opt, policy(configDB), c5.ModeCollecting)
	if slices.ContainsFunc(points, func(p string) bool { return strings.HasPrefix(p, "series:") }) {
		t.Errorf("a second open ran the migration again: %v", points)
	}
	var format string
	if err := db.conn.QueryRowContext(bg, `SELECT value FROM meta WHERE key = 'format'`).Scan(&format); err != nil || format != Format {
		t.Errorf("format %q %v", format, err)
	}
}

// The WAL of the worst step (section 3): four records of about 1.5 MiB, each
// with its own capture, all removed, with the index and auto_vacuum as the
// store opens. The -wal is read after the commit and before any checkpoint,
// as in E-A5-3, and must fit the WAL bound the recovery reserve is twice.
func TestRemoveConfigStepWAL(t *testing.T) {
	const recordBytes = 1536 << 10
	d := configDB
	d.Quotas = []c5.Quota{{Class: c5.ClassConfiguration, Bytes: 64 << 20, WarnFraction: 0.9, MaxRecordBytes: recordBytes}}
	db := openConfig(t, storeDir(t), d, nil)
	if _, err := db.conn.ExecContext(bg, "PRAGMA wal_autocheckpoint=0"); err != nil {
		t.Fatal(err)
	}
	last := map[c5.StreamID]c5.Seq{cfgA: 0, cfgB: 0}
	l, err := c5.NewLogFor(db, testNode, d, c5.GroupOptions{MaxEvents: 2, MaxWait: time.Millisecond, MaxCommitBytes: 2 * recordBytes}, last)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i <= c5.RemoveConfigStep; i++ {
		cp := capture(fmt.Sprintf("%d%s", i, strings.Repeat("t", recordBytes-(64<<10))))
		doc := seriesDoc(i, c5.SeriesConfigSnapshot, &cp)
		doc = append(doc[:len(doc)-1], fmt.Appendf(nil, `,"pad":%q}`, strings.Repeat("d", 32<<10))...)
		if _, err := l.Append(bg, c5.Record{Stream: cfgA, Class: c5.ClassConfiguration, Event: doc, Capture: &cp}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.conn.ExecContext(bg, "PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		t.Fatal(err)
	}
	seqs := make([]c5.Seq, c5.RemoveConfigStep)
	for i := range seqs {
		seqs[i] = c5.Seq(i + 1)
	}
	r, err := db.RemoveConfig(bg, cfgA, c5.SeriesConfigSnapshot, seqs)
	if err != nil || r.Records != len(seqs) || r.Bytes < int64(len(seqs))*(recordBytes-(64<<10)) {
		t.Fatalf("remove: %+v %v", r, err)
	}
	fi, err := os.Stat(db.path + "-wal")
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() > WALBoundBytes {
		t.Fatalf("one step of %d records wrote %d bytes of WAL, more than the bound %d", len(seqs), fi.Size(), WALBoundBytes)
	}
	t.Logf("one step of %d records of about %d bytes (removed %d bytes): %d bytes of WAL (bound %d)", len(seqs), recordBytes, r.Bytes, fi.Size(), WALBoundBytes)
	checkCounted(t, db, "after the WAL step")
}
