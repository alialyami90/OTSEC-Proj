package netretain

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"otsec.local/otsec/contracts/audit"
	"otsec.local/otsec/contracts/authz"
	"otsec.local/otsec/contracts/event"
	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/platform/store"
)

// Desk only: the store is a real platform/store database on the test's
// clocks; no sensor or device is involved.
const (
	testNode   = "site-a-node1"
	testSensor = "6f1c2a3b-4d5e-4f60-8a71-92b3c4d5e6f7"
	stream     = c5.StreamID(audit.AlertStreamPrefix + testSensor)
	day        = 24 * time.Hour
	retention  = 7 * day
)

var bg = context.Background()

// clocks are the test's wall and monotonic clocks, stepped by hand.
type clocks struct {
	wall time.Time
	mono time.Duration
}

func (c *clocks) Wall() time.Time     { return c.wall }
func (c *clocks) Mono() time.Duration { return c.mono }

// advance moves both clocks together, as time passing does.
func (c *clocks) advance(d time.Duration) { c.wall, c.mono = c.wall.Add(d), c.mono+d }

// env is one node's network database and audit stream.
type env struct {
	t     *testing.T
	clk   *clocks
	db    *store.DB
	log   *c5.Log
	recs  []*audit.Record
	fail  error // the next Record fails with it
	fails int
}

func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{t: t, clk: &clocks{wall: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC), mono: time.Minute}}
	dir := filepath.Join(t.TempDir(), "store")
	if err := store.CreateDir(dir, ""); err != nil {
		t.Fatal(err)
	}
	d := c5.Database{ID: "network", Writer: "detection",
		Streams: []c5.StreamSpec{{ID: stream, Class: c5.ClassNetworkAlert}},
		Classes: []c5.StreamClass{c5.ClassNetworkAlert},
		Quotas:  []c5.Quota{{Class: c5.ClassNetworkAlert, Bytes: 4 << 20, WarnFraction: 0.8, MaxRecordBytes: c5.MinRecordBytes}}}
	en, err := store.NewEnv(store.Options{Dir: dir, Node: testNode, Database: d, Now: func() time.Time { return e.clk.wall }})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(bg, time.Minute)
	defer cancel()
	r := c5.RunStartup(ctx, en, c5.StartupPolicy{Streams: d.Streams,
		RecoveryReserveBytes: 2 * store.WALBoundBytes, LastResortReserveBytes: store.WALBoundBytes + c5.MinOpenHeadroom,
		OpenHeadroomBytes: store.WALBoundBytes + c5.MinOpenHeadroom, PruneStepEvents: 50, CompactStepPages: 32, PruneTarget: 0.8})
	if r.Mode != c5.ModeCollecting {
		t.Fatalf("startup mode %s: %v", r.Mode, r.Err)
	}
	if r.Unlock != nil {
		t.Cleanup(r.Unlock)
	}
	db, ok := store.AsDB(r.Store)
	if !ok {
		t.Fatalf("store is %T", r.Store)
	}
	t.Cleanup(func() { db.Close() })
	if e.log, err = c5.NewLogFor(db, testNode, d, c5.GroupOptions{MaxEvents: 2, MaxWait: time.Millisecond, MaxCommitRecords: 128}, map[c5.StreamID]c5.Seq{}); err != nil {
		t.Fatal(err)
	}
	e.db = db
	return e
}

// alertEvent is a pending C4 event on the alert stream. It is a health
// event, not a C13 alert: the store reads only C4, and this consumer only
// commit times.
var alertEvent = []byte(`{"schema":"otsec.event/0.1","id":{"node_id":"` + testNode + `","stream":"` + string(stream) + `","seq":0},` +
	`"origin":"platform","kind":"telemetry-health","source":{"origin_auth":"platform"},` +
	`"received":{"utc":"2026-11-01T00:00:00.000001Z","resolution_ns":1000,"clock":{"sync":"synchronized","source":"ntp"}},` +
	`"health":{"type":"store.test","details":{}}}`)

// alert commits one alert now.
func (e *env) alert() {
	e.t.Helper()
	if _, err := e.log.Append(bg, c5.Record{Stream: stream, Class: c5.ClassNetworkAlert, Event: alertEvent}); err != nil {
		e.t.Fatal(err)
	}
}

// record is the Record seam: it wraps r as the node's C8 record, checks it
// with audit.Validate, and keeps it.
func (e *env) record(_ context.Context, r audit.Retention) error {
	if e.fails > 0 {
		e.fails--
		return e.fail
	}
	rec := &audit.Record{Contract: audit.ReaderID, NodeID: testNode, Seq: uint64(len(e.recs) + 2), PrevHash: strings.Repeat("6", 64),
		Time:   audit.Time{UTC: e.clk.wall.UTC().Format(time.RFC3339Nano), ResolutionNS: 1000, Clock: audit.Clock{Sync: event.SyncSynchronized, Source: "ntp"}},
		Actor:  audit.Actor{Type: authz.PrincipalNode, ID: testNode},
		Action: audit.ActionStoreRetentionMoved, Outcome: audit.OutcomeInfo, Target: &audit.Target{SensorID: testSensor}, Retention: &r}
	if err := rec.Validate(); err != nil {
		e.t.Fatalf("record %+v: %v", r, err)
	}
	e.recs = append(e.recs, rec)
	return nil
}

func (e *env) start() *Consumer {
	e.t.Helper()
	c, err := Start(bg, Config{SensorID: testSensor, Retention: retention},
		Options{Store: e.db, Wall: e.clk.Wall, Mono: e.clk.Mono, Record: e.record}, Latest(e.recs, testSensor))
	if err != nil {
		e.t.Fatal(err)
	}
	return c
}

func (e *env) tick(c *Consumer) {
	e.t.Helper()
	if err := c.Tick(bg); err != nil {
		e.t.Fatal(err)
	}
}

// last is the latest record's move.
func (e *env) last() *audit.Retention { return e.recs[len(e.recs)-1].Retention }

// cursor is the store's cursor of the consumer.
func (e *env) cursor() c5.Seq {
	e.t.Helper()
	cs, err := e.db.LoadCursors(bg, stream)
	if err != nil {
		e.t.Fatal(err)
	}
	for _, c := range cs {
		if c.Consumer == ConsumerID {
			return c.Through
		}
	}
	return 0
}

// verify checks the records as one chain (C8 0.12 section 2.2).
func (e *env) verify() {
	e.t.Helper()
	// From seq 2: seq 1 is the chain start, which the records here leave
	// out.
	if err := audit.VerifyConfigFrom(e.recs, 2); err != nil {
		e.t.Fatal(err)
	}
}

// prune prunes what the consumer has passed, as the node's prune step does.
func (e *env) prune() int {
	e.t.Helper()
	b, err := c5.ComputeBoundary(bg, e.db, e.db, []c5.Consumer{{ID: ConsumerID, Stream: stream, Delivery: c5.Required}},
		stream, c5.ClassNetworkAlert, e.clk.wall)
	if err != nil {
		e.t.Fatal(err)
	}
	n, err := e.db.PruneStep(bg, b, 1000)
	if err != nil {
		e.t.Fatal(err)
	}
	return n
}

// At creation the consumer records created and passes nothing, even with
// the wall clock stepped past the retention before its first tick (#534
// section 3, D5).
func TestCreated(t *testing.T) {
	e := newEnv(t)
	e.alert()
	first := e.clk.wall
	e.clk.advance(time.Hour)
	e.alert()
	e.clk.wall = e.clk.wall.Add(30 * day) // a forward step before the start
	c := e.start()
	r := e.last()
	if len(e.recs) != 1 || r.Bound != audit.BoundCreated || r.FromSeq != 0 || r.ToSeq != 0 || r.CutoffUTC != utc(first) {
		t.Fatalf("created %+v", r)
	}
	e.tick(c) // the monotonic bound has gained nothing since the start
	if len(e.recs) != 1 || e.cursor() != 0 || e.prune() != 0 {
		t.Fatalf("passed something after a step: %+v", e.last())
	}
	// An empty stream's created cutoff is the wall time less the retention.
	e2 := newEnv(t)
	e2.start()
	if r := e2.last(); r.CutoffUTC != utc(e2.clk.wall.Add(-retention)) || r.ToSeq != 0 {
		t.Fatalf("empty: %+v", r)
	}
	e.verify()
}

// Moves: at most once an hour, never back, only past alerts older than
// the retention, the record before the cursor, and only when a move
// advances; passed alerts are pruned (D5-c5-0.9 section 6).
func TestMoves(t *testing.T) {
	e := newEnv(t)
	c := e.start() // empty: cutoff = wall - 7d
	for range 5 {  // alerts 1..5, one an hour
		e.alert()
		e.clk.advance(time.Hour)
	}
	e.tick(c) // nothing older than the retention: no record
	if len(e.recs) != 1 {
		t.Fatalf("a move with nothing to pass: %+v", e.last())
	}
	e.clk.advance(retention - 5*time.Hour + time.Hour + time.Minute) // alerts 1 and 2 are past
	e.tick(c)
	r := e.last()
	if len(e.recs) != 2 || r.Bound != audit.BoundWall || r.FromSeq != 0 || r.ToSeq != 2 || e.cursor() != 2 {
		t.Fatalf("move %+v, cursor %d", r, e.cursor())
	}
	e.clk.advance(59 * time.Minute) // under an hour since the last tick
	e.tick(c)
	if len(e.recs) != 2 {
		t.Fatal("moved twice in an hour")
	}
	e.clk.advance(time.Minute)
	e.tick(c)
	if r := e.last(); len(e.recs) != 3 || r.FromSeq != 2 || r.ToSeq != 3 {
		t.Fatalf("second move %+v", r)
	}
	if n := e.prune(); n != 3 {
		t.Fatalf("pruned %d, want 3", n)
	}
	e.verify()
}

// A failed record leaves the cursor where it was, and the move is made at
// the next tick (#534 section 3).
func TestRecordFails(t *testing.T) {
	e := newEnv(t)
	c := e.start()
	e.alert()
	e.clk.advance(retention + time.Hour)
	e.fail, e.fails = errors.New("audit database full"), 1
	if err := c.Tick(bg); err == nil {
		t.Fatal("a move with no record")
	}
	if e.cursor() != 0 || len(e.recs) != 1 || e.prune() != 0 {
		t.Fatalf("cursor %d after a failed record", e.cursor())
	}
	e.clk.advance(time.Hour)
	e.tick(c)
	if e.cursor() != 1 || e.last().ToSeq != 1 {
		t.Fatalf("cursor %d", e.cursor())
	}
	// A failed created record leaves no consumer.
	e2 := newEnv(t)
	e2.fail, e2.fails = errors.New("audit database full"), 1
	if _, err := Start(bg, Config{SensorID: testSensor, Retention: retention},
		Options{Store: e2.db, Wall: e2.clk.Wall, Mono: e2.clk.Mono, Record: e2.record}, nil); err == nil {
		t.Fatal("started with no created record")
	}
	e.verify()
}

// A forward wall-clock step: the move takes the monotonic bound and passes
// no alert younger than the retention by monotonic time. After a restart
// the cutoff goes at most StartAllowance past the persisted one. A backward
// step stalls the cutoff and writes nothing (D6, D3; C8 0.12 section 3).
func TestClockSteps(t *testing.T) {
	e := newEnv(t)
	c := e.start()
	for range 48 { // an alert an hour for two days
		e.alert()
		e.clk.advance(time.Hour)
	}
	e.clk.advance(retention - 48*time.Hour + time.Hour) // the first alert is 7d+1h old
	e.tick(c)
	moved := e.last()
	if moved.Bound != audit.BoundWall {
		t.Fatalf("first move %+v", moved)
	}

	// Forward by twice the retention.
	e.clk.wall = e.clk.wall.Add(2 * retention)
	e.clk.advance(time.Hour)
	e.tick(c)
	r := e.last()
	prev, _ := time.Parse(time.RFC3339Nano, moved.CutoffUTC)
	cut, _ := time.Parse(time.RFC3339Nano, r.CutoffUTC)
	if r.Bound != audit.BoundMonotonic || !cut.Equal(prev.Add(time.Hour)) {
		t.Fatalf("after a forward step: %+v", r)
	}
	// By monotonic time the retention has passed only the alerts of the
	// first two hours and a third: seqs 1 to 3.
	if e.cursor() != 3 {
		t.Fatalf("cursor %d, want 3", e.cursor())
	}

	// A restart: the first move goes at most StartAllowance past the
	// persisted cutoff, though the wall clock is two retentions ahead.
	persisted := cut
	e.clk.mono = time.Minute // the monotonic clock restarts
	c = e.start()
	e.tick(c)
	r = e.last()
	cut, _ = time.Parse(time.RFC3339Nano, r.CutoffUTC)
	if r.Bound != audit.BoundStart || cut.After(persisted.Add(StartAllowance)) {
		t.Fatalf("after a restart: %+v, persisted %s", r, persisted)
	}

	// Backward by three retentions: ticks write nothing, and the chain
	// holds; once the wall time less the retention passes the old cutoff,
	// the next move chains to the record before the step.
	n := len(e.recs)
	e.clk.wall = e.clk.wall.Add(-3 * retention)
	for range 5 {
		e.clk.advance(time.Hour)
		e.tick(c)
	}
	if len(e.recs) != n {
		t.Fatalf("a stalled tick wrote %+v", e.last())
	}
	e.verify()
	e.clk.wall = cut.Add(retention + 2*time.Hour)
	e.clk.advance(time.Hour)
	e.tick(c)
	if r := e.last(); len(e.recs) != n+1 || r.PreviousCutoffUTC != utc(cut) || r.FromSeq != e.recs[n-1].Retention.ToSeq {
		t.Fatalf("after the stall: %+v", r)
	}
	e.verify()
}

// A crash between a move's record and its cursor: the next start saves
// the recorded cursor (#534 section 2.2).
func TestCursorAfterCrash(t *testing.T) {
	e := newEnv(t)
	c := e.start()
	e.alert()
	e.alert()
	e.clk.advance(retention + time.Hour)
	e.tick(c)
	if e.cursor() != 2 {
		t.Fatal("no move")
	}
	// A record whose cursor never saved: written as the next move, with
	// the store's cursor left where it was.
	e.alert()
	e.clk.advance(2 * time.Hour)
	e.record(bg, audit.Retention{Stream: string(stream), FromSeq: 2, ToSeq: 3, RetentionS: int64(retention / time.Second),
		WallUTC: utc(e.clk.wall), CutoffUTC: utc(e.clk.wall.Add(-retention)), PreviousCutoffUTC: e.last().CutoffUTC, Bound: audit.BoundWall})
	c = e.start()
	if e.cursor() != 3 || c.Status().Cursor != 3 || !c.Status().CursorSaved {
		t.Fatalf("cursor %d, status %+v", e.cursor(), c.Status())
	}
	e.verify()
}
