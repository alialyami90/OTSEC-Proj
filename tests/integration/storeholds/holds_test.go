// Package storeholds checks C5 0.4's holds and commit-WAL rule on the real
// SQLite store (B6, P4-B6; a review of #273).
//
// Ground truth is not the store's: a model kept by this test (which seqs
// are stored, which are held, which captures each record refers to) and,
// for the WAL, the file's size read from disk with a second connection
// holding the WAL open. Evidence class: simulated.
package storeholds

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"math/rand"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/platform/store"
)

const (
	node             = "node-b6"
	cfg  c5.StreamID = "config/asset-a"
)

func database(maxRecord int64) c5.Database {
	return c5.Database{
		ID:      "configuration",
		Writer:  "ied",
		Streams: []c5.StreamSpec{{ID: cfg, Class: c5.ClassConfiguration}},
		Classes: []c5.StreamClass{c5.ClassConfiguration},
		Quotas:  []c5.Quota{{Class: c5.ClassConfiguration, Bytes: 64 << 20, WarnFraction: 0.8, MaxRecordBytes: maxRecord}},
	}
}

// docs accepts any JSON object: the document check is the node's, not
// what this package tests.
func docs(doc []byte, _ *c5.Capture) error {
	if len(doc) == 0 || doc[0] != '{' {
		return fmt.Errorf("not a document")
	}
	return nil
}

func open(t *testing.T, dir string, d c5.Database) *store.DB {
	t.Helper()
	env, err := store.NewEnv(store.Options{Dir: dir, Node: node, Database: d, Documents: docs})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	r := c5.RunStartup(ctx, env, c5.StartupPolicy{
		Streams:                d.Streams,
		RecoveryReserveBytes:   2 * store.WALBoundBytes,
		LastResortReserveBytes: store.WALBoundBytes + c5.MinOpenHeadroom,
		OpenHeadroomBytes:      store.WALBoundBytes + c5.MinOpenHeadroom,
		PruneStepEvents:        50,
		CompactStepPages:       32,
		PruneTarget:            0.8,
	})
	if r.Mode != c5.ModeCollecting {
		t.Fatalf("startup %s: %v %v", r.Mode, r.Err, r.Steps)
	}
	db, ok := store.AsDB(r.Store)
	if !ok {
		t.Fatal("not the SQLite store")
	}
	t.Cleanup(func() {
		db.Close()
		if r.Unlock != nil {
			r.Unlock()
		}
	})
	return db
}

func newDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "store")
	if err := store.CreateDir(dir, ""); err != nil {
		t.Fatal(err)
	}
	return dir
}

func capture(s string) c5.Capture {
	sum := sha256.Sum256([]byte(s))
	return c5.Capture{SHA256: hex.EncodeToString(sum[:]), Bytes: []byte(s)}
}

func reason(n int) c5.HoldReason {
	return c5.HoldReason{Code: c5.HoldBaseline, Ref: c5.Key{NodeID: node, Stream: "audit", Seq: c5.Seq(n)}}
}

// model is what the store must hold, kept without reading the store.
type model struct {
	stored  map[c5.Seq]bool
	held    map[c5.Seq]bool
	event   map[c5.Seq][]byte
	capOf   map[c5.Seq]string // sha256 hex, "" for none
	capSize map[string]int64
}

func (m *model) pruneStep(through c5.Seq, max int) int {
	var seqs []c5.Seq
	for s := range m.stored {
		if s <= through && !m.held[s] {
			seqs = append(seqs, s)
		}
	}
	slices.Sort(seqs)
	if len(seqs) > max {
		seqs = seqs[:max]
	}
	for _, s := range seqs {
		delete(m.stored, s)
	}
	return len(seqs)
}

// classBytes is the quota's count: each stored event, and each capture a
// stored record refers to, once.
func (m *model) classBytes() int64 {
	var n int64
	caps := map[string]bool{}
	for s := range m.stored {
		n += int64(len(m.event[s]))
		if c := m.capOf[s]; c != "" {
			caps[c] = true
		}
	}
	for c := range caps {
		n += m.capSize[c]
	}
	return n
}

// heldBytes is C5 0.4's HeldRecord.Bytes: the event, and its capture when
// no unheld stored record refers to it.
func (m *model) heldBytes(s c5.Seq) int64 {
	n := int64(len(m.event[s]))
	c := m.capOf[s]
	if c == "" {
		return n
	}
	for o := range m.stored {
		if m.capOf[o] == c && !m.held[o] {
			return n
		}
	}
	return n + m.capSize[c]
}

func check(t *testing.T, ctx context.Context, db *store.DB, m *model, at string) {
	t.Helper()
	got, err := db.Read(ctx, cfg, 0, 1000)
	if err != nil {
		t.Fatal(err)
	}
	var have, want []c5.Seq
	for _, r := range got {
		have = append(have, r.Key.Seq)
	}
	for s := range m.stored {
		want = append(want, s)
	}
	slices.Sort(want)
	if !slices.Equal(have, want) {
		t.Fatalf("%s: stored %v, model %v", at, have, want)
	}
	held, err := db.Held(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	var hs []c5.Seq
	for _, h := range held {
		hs = append(hs, h.Seq)
		if h.Reason != reason(int(h.Seq)) {
			t.Fatalf("%s: seq %d held for %+v", at, h.Seq, h.Reason)
		}
		if w := m.heldBytes(h.Seq); h.Bytes != w {
			t.Fatalf("%s: held seq %d keeps %d bytes, model %d", at, h.Seq, h.Bytes, w)
		}
	}
	var mh []c5.Seq
	for s := range m.held {
		mh = append(mh, s)
	}
	slices.Sort(mh)
	if !slices.Equal(hs, mh) {
		t.Fatalf("%s: held %v, model %v", at, hs, mh)
	}
	n, err := db.ClassBytes(ctx, c5.ClassConfiguration)
	if err != nil {
		t.Fatal(err)
	}
	if w := m.classBytes(); n != w {
		t.Fatalf("%s: class bytes %d, model %d", at, n, w)
	}
	refd := map[string]bool{}
	for s := range m.stored {
		if c := m.capOf[s]; c != "" {
			refd[c] = true
		}
	}
	for c := range m.capSize {
		_, err := db.ReadCapture(ctx, "sha256:"+c)
		if refd[c] != (err == nil) {
			t.Fatalf("%s: capture %s.. referred to %v, readable %v (%v)", at, c[:8], refd[c], err == nil, err)
		}
	}
}

// Pruning around holds, against the model, in steps of 1, 2, 7 and 1000:
// held records stay with their captures, unheld ones at or below the
// boundary go in seq order, a release lets its record go on a later step,
// the quota's count follows, and everything survives a reopen.
func TestPruneAroundHoldsAgainstAModel(t *testing.T) {
	for _, step := range []int{1, 2, 7, 1000} {
		for seed := int64(1); seed <= 4; seed++ {
			t.Run(fmt.Sprintf("step%d/seed%d", step, seed), func(t *testing.T) { pruneRun(t, step, seed) })
		}
	}
}

func pruneRun(t *testing.T, step int, seed int64) {
	ctx := context.Background()
	rng := rand.New(rand.NewSource(seed*1000 + int64(step)))
	d := database(c5.MinRecordBytes)
	dir := newDir(t)
	db := open(t, dir, d)
	l, err := c5.NewLogFor(db, node, d, c5.GroupOptions{MaxEvents: 10, MaxWait: time.Millisecond}, map[c5.StreamID]c5.Seq{cfg: 0})
	if err != nil {
		t.Fatal(err)
	}
	m := &model{stored: map[c5.Seq]bool{}, held: map[c5.Seq]bool{}, event: map[c5.Seq][]byte{},
		capOf: map[c5.Seq]string{}, capSize: map[string]int64{}}
	pool := make([]c5.Capture, 4)
	for i := range pool {
		pool[i] = capture(fmt.Sprintf("transcript %d of seed %d %s", i, seed, string(make([]byte, 100*(i+1)))))
		m.capSize[pool[i].SHA256] = int64(len(pool[i].Bytes))
	}
	const total = 40
	for i := 1; i <= total; i++ {
		s := c5.Seq(i)
		r := c5.Record{Stream: cfg, Class: c5.ClassConfiguration}
		if k := rng.Intn(len(pool) + 2); k < len(pool) {
			r.Capture = &pool[k]
			m.capOf[s] = pool[k].SHA256
		}
		r.Event = fmt.Appendf(nil, `{"doc":%d,"pad":%q}`, i, string(make([]byte, rng.Intn(50))))
		if rng.Intn(4) == 0 {
			r.Holds = []c5.Hold{{Reason: reason(i)}}
			m.held[s] = true
		}
		if _, err := l.Append(ctx, r); err != nil {
			t.Fatal(err)
		}
		m.stored[s], m.event[s] = true, r.Event
	}
	check(t, ctx, db, m, "after the appends")

	// The consumer has everything through 30; 31 to 40 stay whatever happens.
	const through = 30
	if err := db.SaveCursor(ctx, c5.Cursor{Consumer: "central", Stream: cfg, Through: through}); err != nil {
		t.Fatal(err)
	}
	b, err := c5.ComputeBoundary(ctx, db, db, []c5.Consumer{{ID: "central", Stream: cfg, Delivery: c5.Required}}, cfg, c5.ClassConfiguration, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if b.Through() != through {
		t.Fatalf("boundary %d, want %d", b.Through(), through)
	}
	for op := 0; op < 60; op++ {
		switch k := rng.Intn(10); {
		case k < 6:
			want := m.pruneStep(through, step)
			n, err := db.PruneStep(ctx, b, step)
			if err != nil || n != want {
				t.Fatalf("op %d: PruneStep(%d) = %d %v, model %d", op, step, n, err, want)
			}
		case k < 8:
			var hs []c5.Seq
			for s := range m.held {
				hs = append(hs, s)
			}
			if len(hs) == 0 {
				continue
			}
			slices.Sort(hs)
			s := hs[rng.Intn(len(hs))]
			if err := db.Release(ctx, cfg, s); err != nil {
				t.Fatal(err)
			}
			delete(m.held, s)
		default:
			s := c5.Seq(1 + rng.Intn(total))
			err := db.Hold(ctx, c5.Hold{Stream: cfg, Seq: s, Reason: reason(int(s))})
			switch {
			case m.stored[s] && err != nil:
				t.Fatalf("op %d: hold on stored seq %d: %v", op, s, err)
			case !m.stored[s] && !errors.Is(err, &c5.Error{Code: c5.CodeNotHoldable}):
				t.Fatalf("op %d: hold on pruned seq %d: %v, want not-holdable", op, s, err)
			case m.stored[s]:
				m.held[s] = true
			}
		}
		check(t, ctx, db, m, fmt.Sprintf("op %d", op))
	}
	// Release everything and prune to the end: only 31 to 40 are left.
	for s := range m.held {
		if err := db.Release(ctx, cfg, s); err != nil {
			t.Fatal(err)
		}
		delete(m.held, s)
	}
	for {
		want := m.pruneStep(through, step)
		n, err := db.PruneStep(ctx, b, step)
		if err != nil || n != want {
			t.Fatalf("drain: %d %v, model %d", n, err, want)
		}
		if n == 0 {
			break
		}
	}
	check(t, ctx, db, m, "drained")
	for s := range m.stored {
		if s <= through {
			t.Fatalf("seq %d at or below the boundary is still stored", s)
		}
	}
}

// Holds are durable: a reopened store has the same stored and held records
// and the same quota count, and still prunes around the holds.
func TestHoldsSurviveAReopen(t *testing.T) {
	ctx := context.Background()
	d := database(c5.MinRecordBytes)
	dir := newDir(t)
	m := &model{stored: map[c5.Seq]bool{}, held: map[c5.Seq]bool{}, event: map[c5.Seq][]byte{},
		capOf: map[c5.Seq]string{}, capSize: map[string]int64{}}
	cp := capture("one transcript")
	m.capSize[cp.SHA256] = int64(len(cp.Bytes))
	func() {
		env, err := store.NewEnv(store.Options{Dir: dir, Node: node, Database: d, Documents: docs})
		if err != nil {
			t.Fatal(err)
		}
		r := c5.RunStartup(ctx, env, c5.StartupPolicy{Streams: d.Streams, RecoveryReserveBytes: 2 * store.WALBoundBytes,
			LastResortReserveBytes: store.WALBoundBytes + c5.MinOpenHeadroom, OpenHeadroomBytes: store.WALBoundBytes + c5.MinOpenHeadroom,
			PruneStepEvents: 50, CompactStepPages: 32, PruneTarget: 0.8})
		if r.Mode != c5.ModeCollecting {
			t.Fatalf("startup %s: %v", r.Mode, r.Err)
		}
		db, _ := store.AsDB(r.Store)
		l, err := c5.NewLogFor(db, node, d, c5.GroupOptions{MaxEvents: 10, MaxWait: time.Millisecond}, map[c5.StreamID]c5.Seq{cfg: 0})
		if err != nil {
			t.Fatal(err)
		}
		for i := 1; i <= 6; i++ {
			r := c5.Record{Stream: cfg, Class: c5.ClassConfiguration, Event: fmt.Appendf(nil, `{"doc":%d}`, i)}
			if i%2 == 0 {
				r.Capture = &cp
				m.capOf[c5.Seq(i)] = cp.SHA256
			}
			if i == 2 || i == 3 {
				r.Holds = []c5.Hold{{Reason: reason(i)}}
				m.held[c5.Seq(i)] = true
			}
			if _, err := l.Append(ctx, r); err != nil {
				t.Fatal(err)
			}
			m.stored[c5.Seq(i)], m.event[c5.Seq(i)] = true, r.Event
		}
		check(t, ctx, db, m, "before the close")
		db.Close()
		if r.Unlock != nil {
			r.Unlock()
		}
	}()
	db := open(t, dir, d)
	check(t, ctx, db, m, "after the reopen")
	if err := db.SaveCursor(ctx, c5.Cursor{Consumer: "central", Stream: cfg, Through: 6}); err != nil {
		t.Fatal(err)
	}
	b, err := c5.ComputeBoundary(ctx, db, db, []c5.Consumer{{ID: "central", Stream: cfg, Delivery: c5.Required}}, cfg, c5.ClassConfiguration, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	want := m.pruneStep(6, 100)
	if n, err := db.PruneStep(ctx, b, 100); err != nil || n != want {
		t.Fatalf("prune after reopen: %d %v, model %d", n, err, want)
	}
	check(t, ctx, db, m, "pruned after the reopen")
}

// walPath is the database file; its -wal is measured next to it. A test
// pins the WAL with a read transaction from a second connection, so no
// checkpoint resets it under the measurement.
func walPath(t *testing.T, dir string) string {
	t.Helper()
	m, _ := filepath.Glob(filepath.Join(dir, "*.db"))
	if len(m) != 1 {
		t.Fatalf("database files %v", m)
	}
	return m[0]
}

// measureWAL runs commit while a second connection holds a read
// transaction on the database file, so no checkpoint can reset the WAL
// under the measurement, and returns how much the -wal file grew.
func measureWAL(t *testing.T, dir string, commit func()) int64 {
	t.Helper()
	ctx := context.Background()
	file := walPath(t, dir)
	before, err := os.Stat(file + "-wal")
	if err != nil {
		t.Fatal(err)
	}
	pin, err := sql.Open("sqlite", "file:"+(&url.URL{Path: file}).EscapedPath()+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer pin.Close()
	tx, err := pin.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM events`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	commit()
	after, err := os.Stat(file + "-wal")
	if err != nil {
		t.Fatal(err)
	}
	return after.Size() - before.Size()
}

// withinRule fails unless one commit of payload bytes in records rows grew
// the WAL by more than its payload (else the pin did not hold and nothing
// was measured) and by no more than CommitWALBytes(payload, records).
func withinRule(t *testing.T, payload, records, grew int64) {
	t.Helper()
	rule := c5.CommitWALBytes(payload, records)
	t.Logf("payload %d bytes in %d records: the WAL grew %d bytes (%.3f × payload; %d a record over 1.1 × payload + 64 KiB), rule %d",
		payload, records, grew, float64(grew)/float64(payload), (grew-payload-payload/10-64<<10)/records, rule)
	if grew <= payload {
		t.Fatalf("the WAL grew %d bytes for a %d-byte payload: the pin did not hold it, so this measured nothing", grew, payload)
	}
	if grew > rule {
		t.Fatalf("one commit of %d payload bytes in %d records wrote %d WAL bytes, over CommitWALBytes %d", payload, records, grew, rule)
	}
}

// compactAll runs compaction to its end, so the commit measured starts on a
// settled file.
func compactAll(t *testing.T, db *store.DB) {
	t.Helper()
	for more := true; more; {
		var err error
		if more, err = db.CompactStep(context.Background(), 1000); err != nil {
			t.Fatal(err)
		}
	}
}

// The WAL one commit writes stays under CommitWALBytes of its payload and
// its one record, on the real store with its own schema, indexes and
// settings: one configuration record per commit, from MinRecordBytes to
// 11 MiB, the largest cap any database uses (the evidence database's, D4-9).
func TestOneCommitsWALIsWithinTheRule(t *testing.T) {
	ctx := context.Background()
	for _, size := range []int64{c5.MinRecordBytes, 256 << 10, 768 << 10, 1 << 20, 1536 << 10, 4 << 20, 11 << 20} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			d := database(size)
			dir := newDir(t)
			db := open(t, dir, d)
			l, err := c5.NewLogFor(db, node, d, c5.GroupOptions{MaxEvents: 10, MaxWait: time.Millisecond}, map[c5.StreamID]c5.Seq{cfg: 0})
			if err != nil {
				t.Fatal(err)
			}
			// A first record, so the commit measured is not the stream's first.
			if _, err := l.Append(ctx, c5.Record{Stream: cfg, Class: c5.ClassConfiguration, Event: []byte(`{"doc":0}`)}); err != nil {
				t.Fatal(err)
			}
			compactAll(t, db)
			// Random bytes, as a transcript compresses nothing in SQLite anyway.
			rng := rand.New(rand.NewSource(size))
			raw := make([]byte, size/2)
			rng.Read(raw)
			cp := capture(hex.EncodeToString(raw)[:size/2])
			ev := fmt.Appendf(nil, `{"doc":1,"t":%q,"pad":%q}`, cp.SHA256, hex.EncodeToString(raw)[:size/2-200])
			r := c5.Record{Stream: cfg, Class: c5.ClassConfiguration, Event: ev, Capture: &cp}
			if r.Bytes() > size {
				t.Fatalf("record %d bytes over its cap %d", r.Bytes(), size)
			}
			// One Append with no other writer: the commit holds this one record.
			withinRule(t, r.Bytes(), 1, measureWAL(t, dir, func() {
				if _, err := l.Append(ctx, r); err != nil {
					t.Fatal(err)
				}
			}))
		})
	}
}

const ser c5.StreamID = "relay1/ser"

// serEvent is a pending C4 event of about size bytes for the SER stream.
func serEvent(n, size int) []byte {
	head := fmt.Sprintf(`{"schema":"otsec.event/0.1","id":{"node_id":%q,"stream":%q,"seq":0},`+
		`"origin":"platform","kind":"telemetry-health","source":{"origin_auth":"platform"},`+
		`"received":{"utc":"2026-10-24T12:00:00.000001Z","resolution_ns":1000,"clock":{"sync":"synchronized","source":"ntp"}},`+
		`"health":{"type":"store.test","details":{"n":"%d","pad":"`, node, ser, n)
	pad := max(size-len(head)-4, 1)
	return fmt.Appendf(nil, `%s%s"}}}`, head, hex.EncodeToString(make([]byte, pad))[:pad])
}

// One SER read commits as one AppendBatch: many events, one capture they
// share and the device cursor. Per-row index entries make this the commit
// shape with the most WAL per payload byte, so the rule is measured on it
// too, up to the evidence database's 11 MiB cap (B5's #278): the read
// shapes #278 measures, many small rows, and a read that fills the cap.
// The cursor is the largest #278 allows (2048 × 71 bytes) and is not
// counted in the payload, as the node does not count it either.
//
// Against C5 0.4's rule this failed on every shape: events was a WITHOUT
// ROWID table, so each event over about 1 KB spilled to an overflow page of
// its own (#280, D4-14). The shapes and the property are unchanged since;
// only the rule they are checked against is C5 0.5's.
func TestOneSERReadsWALIsWithinTheRule(t *testing.T) {
	ctx := context.Background()
	const capBytes = 11 << 20
	for _, c := range []struct {
		name                string
		rows, event, perRow int
	}{
		{"2048 small rows", 2048, 300, 70},
		{"2048 rows just over a leaf cell", 2048, 1100, 70},
		{"2048 shortest rows", 2048, 1900, 70},
		{"1024 long-element rows", 1024, 5800, 200},
		{"2048 rows of 500 bytes", 2048, 3700, 500},
		{"a read that fills the cap", 2048, 5300, 300},
	} {
		t.Run(c.name, func(t *testing.T) {
			d := c5.Database{
				ID:      "evidence",
				Writer:  "ied",
				Streams: []c5.StreamSpec{{ID: ser, Class: c5.ClassAdapterEvidence}},
				Classes: []c5.StreamClass{c5.ClassAdapterEvidence},
				Quotas:  []c5.Quota{{Class: c5.ClassAdapterEvidence, Bytes: 256 << 20, WarnFraction: 0.8, MaxRecordBytes: capBytes}},
			}
			dir := newDir(t)
			db := open(t, dir, d)
			l, err := c5.NewLogFor(db, node, d, c5.GroupOptions{MaxEvents: 10, MaxWait: time.Millisecond, MaxCommitBytes: capBytes, MaxCommitRecords: 2048}, map[c5.StreamID]c5.Seq{ser: 0})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := l.Append(ctx, c5.Record{Stream: ser, Class: c5.ClassAdapterEvidence, Event: serEvent(0, 400)}); err != nil {
				t.Fatal(err)
			}
			compactAll(t, db)
			rng := rand.New(rand.NewSource(int64(c.rows*c.event + c.perRow)))
			raw := make([]byte, c.rows*c.perRow/2)
			rng.Read(raw)
			cp := capture(hex.EncodeToString(raw))
			cursor := make([]byte, 2048*71)
			rng.Read(cursor)
			recs := make([]c5.Record, c.rows)
			payload := int64(len(cp.Bytes))
			for i := range recs {
				recs[i] = c5.Record{Stream: ser, Class: c5.ClassAdapterEvidence, Event: serEvent(i+1, c.event), Capture: &cp}
				payload += int64(len(recs[i].Event))
			}
			recs[len(recs)-1].SourceCursor = cursor
			if payload > capBytes {
				t.Fatalf("read of %d bytes over the cap %d", payload, capBytes)
			}
			withinRule(t, payload, int64(c.rows), measureWAL(t, dir, func() {
				if _, err := l.AppendBatch(ctx, recs); err != nil {
					t.Fatal(err)
				}
			}))
		})
	}
}

// evidenceDB is an evidence database whose commits may carry up to 2048
// records and 11 MiB, the evidence caps (D4-9, D4-14).
func evidenceDB(t *testing.T) (*store.DB, *c5.Log, string) {
	t.Helper()
	d := c5.Database{
		ID:      "evidence",
		Writer:  "ied",
		Streams: []c5.StreamSpec{{ID: ser, Class: c5.ClassAdapterEvidence}},
		Classes: []c5.StreamClass{c5.ClassAdapterEvidence},
		Quotas:  []c5.Quota{{Class: c5.ClassAdapterEvidence, Bytes: 1 << 30, WarnFraction: 0.9, MaxRecordBytes: evidenceCap}},
	}
	dir := newDir(t)
	db := open(t, dir, d)
	l, err := c5.NewLogFor(db, node, d, c5.GroupOptions{MaxEvents: 10, MaxWait: time.Millisecond, MaxCommitBytes: evidenceCap, MaxCommitRecords: 2048}, map[c5.StreamID]c5.Seq{ser: 0})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.Append(context.Background(), c5.Record{Stream: ser, Class: c5.ClassAdapterEvidence, Event: serEvent(0, 400)}); err != nil {
		t.Fatal(err)
	}
	compactAll(t, db)
	return db, l, dir
}

const evidenceCap = 11 << 20

// checkpoint runs a TRUNCATE checkpoint from a second connection and fails
// unless it completed.
func checkpoint(t *testing.T, file string) {
	t.Helper()
	c, err := sql.Open("sqlite", "file:"+(&url.URL{Path: file}).EscapedPath())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	var busy, logPages, done int
	if err := c.QueryRow(`PRAGMA wal_checkpoint(TRUNCATE)`).Scan(&busy, &logPages, &done); err != nil {
		t.Fatal(err)
	}
	if busy != 0 {
		t.Fatalf("checkpoint busy: %d of %d frames", done, logPages)
	}
}

// commitAndMeasure commits recs as one AppendBatch on a fresh evidence
// database and checks both of D4-14's properties: the WAL the commit wrote
// is within CommitWALBytes, and once checkpointed the file grew by no more
// than DiskBytesPerQuotaByte × what the quota counted.
func commitAndMeasure(t *testing.T, recs []c5.Record) {
	t.Helper()
	ctx := context.Background()
	db, l, dir := evidenceDB(t)
	file := walPath(t, dir)
	payload, seen := int64(0), map[string]bool{}
	for _, r := range recs {
		payload += int64(len(r.Event))
		if r.Capture != nil && !seen[r.Capture.SHA256] {
			seen[r.Capture.SHA256] = true
			payload += int64(len(r.Capture.Bytes))
		}
	}
	checkpoint(t, file)
	before, err := os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	counted, err := db.ClassBytes(ctx, c5.ClassAdapterEvidence)
	if err != nil {
		t.Fatal(err)
	}
	grew := measureWAL(t, dir, func() {
		if _, err := l.AppendBatch(ctx, recs); err != nil {
			t.Fatal(err)
		}
	})
	checkpoint(t, file)
	after, err := os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	now, err := db.ClassBytes(ctx, c5.ClassAdapterEvidence)
	if err != nil {
		t.Fatal(err)
	}
	fileGrew, quota := after.Size()-before.Size(), now-counted
	t.Logf("file grew %d for %d quota bytes (%.2f ×)", fileGrew, quota, float64(fileGrew)/float64(quota))
	if float64(fileGrew) > c5.DiskBytesPerQuotaByte*float64(quota) {
		t.Errorf("the file grew %d bytes for %d bytes the quota counts, over DiskBytesPerQuotaByte %.2f", fileGrew, quota, c5.DiskBytesPerQuotaByte)
	}
	withinRule(t, payload, int64(len(recs)), grew)
}

// sweepSizes is 100 B, then step bytes apart to 16 KiB and 8 × step apart
// to 64 KiB. At 256 B every overflow and page-sharing step is crossed.
func sweepSizes(step int) []int {
	sizes := []int{100}
	for s := step; s <= 16<<10; s += step {
		sizes = append(sizes, s)
	}
	for s := 16<<10 + 8*step; s <= 64<<10; s += 8 * step {
		sizes = append(sizes, s)
	}
	return sizes
}

// serRead is rows events of size bytes sharing one capture of about 70
// bytes a row, numbered from 1.
func serRead(rows, size int) []c5.Record {
	raw := make([]byte, rows*35)
	rand.New(rand.NewSource(int64(rows * size))).Read(raw)
	cp := capture(hex.EncodeToString(raw))
	recs := make([]c5.Record, rows)
	for i := range recs {
		recs[i] = c5.Record{Stream: ser, Class: c5.ClassAdapterEvidence, Event: serEvent(i+1, size), Capture: &cp}
	}
	return recs
}

// D4-14 item 6: event sizes from 100 B to 64 KiB at 1 record a commit, at
// 128, and at 2048 or as many as fit the 11 MiB evidence cap, each commit on
// a fresh database. Every commit must stay within CommitWALBytes, and the
// checkpointed file within DiskBytesPerQuotaByte of the quota bytes. The
// 2048-record sweep steps 512 B, to keep the Windows job's time: each of
// its commits writes up to 11 MiB, and TestPageEdgeSweep walks the edges.
func TestEventSizeSweep(t *testing.T) {
	for _, rows := range []int{1, 128, 2048} {
		step := 256
		if rows == 2048 {
			step = 512
		}
		for _, size := range sweepSizes(step) {
			n := max(1, min(rows, evidenceCap/(size+70)))
			t.Run(fmt.Sprintf("%d/%d", rows, size), func(t *testing.T) {
				commitAndMeasure(t, serRead(n, size))
			})
		}
	}
}

// The sweep's steps are 256 B apart, so they can miss the size where a row
// wastes most: an event just too big to share its leaf page. This walks
// 8 B steps across that edge, and across the edges where three and four
// events stop sharing a page, at 128 records a commit.
func TestPageEdgeSweep(t *testing.T) {
	for _, edge := range [][2]int{{1200, 1500}, {1850, 2150}, {3950, 4200}} {
		for size := edge[0]; size <= edge[1]; size += 8 {
			t.Run(fmt.Sprint(size), func(t *testing.T) {
				commitAndMeasure(t, serRead(128, size))
			})
		}
	}
}

// The rule is checked per record, so it must also hold when each record
// brings its own capture, as one datagram or one pushed file would (C5's
// Capture). captures is still a WITHOUT ROWID table: a capture over about
// 1 KB spills to overflow pages of its own.
func TestCaptureEachSweep(t *testing.T) {
	for _, rows := range []int{128, 1024} {
		for _, size := range []int{100, 512, 1024, 1100, 1536, 2048, 3072, 4096, 4200, 6144, 8192} {
			t.Run(fmt.Sprintf("%d/%d", rows, size), func(t *testing.T) {
				recs := make([]c5.Record, rows)
				for i := range recs {
					raw := make([]byte, size/2+1)
					rand.New(rand.NewSource(int64(i*size + rows))).Read(raw)
					cp := capture(hex.EncodeToString(raw)[:size])
					recs[i] = c5.Record{Stream: ser, Class: c5.ClassAdapterEvidence, Event: serEvent(i+1, 600), Capture: &cp}
				}
				commitAndMeasure(t, recs)
			})
		}
	}
}

// fileSums is the SHA-256 of each of a database's three files, "absent"
// for one that does not exist.
func fileSums(t *testing.T, file string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, suf := range []string{"", "-wal", "-shm"} {
		b, err := os.ReadFile(file + suf)
		switch {
		case errors.Is(err, os.ErrNotExist):
			out[suf] = "absent"
		case err != nil:
			t.Fatal(err)
		default:
			s := sha256.Sum256(b)
			out[suf] = fmt.Sprintf("%x (%d bytes)", s, len(b))
		}
	}
	return out
}

// A store of the first format is refused at start and by the offline
// reader, and the refusal writes nothing: the database, its -wal and its
// -shm are byte-identical afterwards, also when the node stopped with
// frames not yet checkpointed (D4-14 item 4, B1's ruling on #282). The
// store is made by this build, with the first format's identifier and an
// UPDATE left in the WAL, then copied while that writer is still open, as
// a crash leaves it.
func TestFirstFormatWithAHotWALIsLeftAlone(t *testing.T) {
	ctx := context.Background()
	d := database(c5.MinRecordBytes)
	dir := newDir(t)
	db := open(t, dir, d)
	l, err := c5.NewLogFor(db, node, d, c5.GroupOptions{MaxEvents: 10, MaxWait: time.Millisecond}, map[c5.StreamID]c5.Seq{cfg: 0})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.Append(ctx, c5.Record{Stream: cfg, Class: c5.ClassConfiguration, Event: []byte(`{"doc":1}`)}); err != nil {
		t.Fatal(err)
	}
	file := walPath(t, dir)
	db.Close()
	raw, err := sql.Open("sqlite", "file:"+(&url.URL{Path: file}).EscapedPath())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	raw.SetMaxOpenConns(1)
	for _, q := range []string{
		`PRAGMA wal_autocheckpoint=0`,
		`UPDATE meta SET value = 'otsec.platform-store/1' WHERE key = 'format'`,
		`UPDATE streams SET last_at = last_at + 1`,
	} {
		if _, err := raw.Exec(q); err != nil {
			t.Fatal(q, err)
		}
	}
	crash := newDir(t)
	copied := filepath.Join(crash, filepath.Base(file))
	for _, suf := range []string{"", "-wal", "-shm"} {
		b, err := os.ReadFile(file + suf)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(copied+suf, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	before := fileSums(t, copied)
	if before["-wal"] == "absent" || strings.HasSuffix(before["-wal"], "(0 bytes)") {
		t.Fatalf("the copy has no frames in its WAL, so this measures nothing: %v", before)
	}

	if _, err := store.OpenReadOnly(ctx, crash, node, d.ID); err == nil || !strings.Contains(err.Error(), "earlier layout") {
		t.Errorf("the offline reader on the first format: %v", err)
	}
	if after := fileSums(t, copied); !maps.Equal(before, after) {
		t.Errorf("the offline reader's refusal changed the files:\n before %v\n after  %v", before, after)
	}

	env, err := store.NewEnv(store.Options{Dir: crash, Node: node, Database: d, Documents: docs})
	if err != nil {
		t.Fatal(err)
	}
	r := c5.RunStartup(ctx, env, c5.StartupPolicy{
		Streams:                d.Streams,
		RecoveryReserveBytes:   2 * store.WALBoundBytes,
		LastResortReserveBytes: store.WALBoundBytes + c5.MinOpenHeadroom,
		OpenHeadroomBytes:      store.WALBoundBytes + c5.MinOpenHeadroom,
		PruneStepEvents:        50,
		CompactStepPages:       32,
		PruneTarget:            0.8,
	})
	if r.Unlock != nil {
		defer r.Unlock()
	}
	if r.Store != nil {
		r.Store.Close()
	}
	if r.Mode != c5.ModeFailed || r.Err == nil || !strings.Contains(r.Err.Error(), "earlier layout") {
		t.Errorf("start on the first format: mode %s, %v", r.Mode, r.Err)
	}
	if after := fileSums(t, copied); !maps.Equal(before, after) {
		t.Errorf("the refusal at start changed the files:\n before %v\n after  %v", before, after)
	}
}
