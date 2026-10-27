// Package storediscard checks C5 0.3's Discarder on the real store (A6,
// #151, D3-1). The store is opened through C5 startup, and events are
// committed through the real store. A6's own records are used; none of A5's
// test helpers. Ground truth is the rule text of D3-1 and the Discarder
// documentation:
//   - only the named seqs of the named quarantine stream go;
//   - a stream with a persisted cursor is refused, with nothing removed;
//   - a capture goes only when no retained record of any stream refers to
//     it, and its bytes are counted once;
//   - one step stays inside the WAL bound the recovery reserve is sized
//     for.
//
// Class: simulated.
package storediscard

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"

	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/platform/store"
)

const (
	qa  c5.StreamID = "quarantine/a6-asset-a"
	qb  c5.StreamID = "quarantine/a6-asset-b"
	ser c5.StreamID = "ser/a6-asset-a"
)

func database(quota int64) c5.Database {
	return c5.Database{
		ID: "evidence", Writer: "ied",
		Streams: []c5.StreamSpec{{ID: qa, Class: c5.ClassAdapterEvidence}, {ID: qb, Class: c5.ClassAdapterEvidence},
			{ID: ser, Class: c5.ClassAdapterEvidence}, {ID: "platform/health", Class: c5.ClassPlatform}},
		Classes: []c5.StreamClass{c5.ClassAdapterEvidence, c5.ClassPlatform},
		Quotas: []c5.Quota{{Class: c5.ClassAdapterEvidence, Bytes: quota, WarnFraction: 0.9},
			{Class: c5.ClassPlatform, Bytes: 8 << 20, WarnFraction: 0.9}},
	}
}

func open(t *testing.T, quota int64) (*store.DB, string) {
	t.Helper()
	d := filepath.Join(t.TempDir(), "store")
	if err := store.CreateDir(d, ""); err != nil {
		t.Fatal(err)
	}
	db := database(quota)
	e, err := store.NewEnv(store.Options{Dir: d, Node: "node-a6", Database: db})
	if err != nil {
		t.Fatal(err)
	}
	r := c5.RunStartup(context.Background(), e, c5.StartupPolicy{
		Streams:                db.Streams,
		RecoveryReserveBytes:   2 * store.WALBoundBytes,
		LastResortReserveBytes: store.WALBoundBytes + c5.MinOpenHeadroom,
		OpenHeadroomBytes:      store.WALBoundBytes + c5.MinOpenHeadroom,
		PruneStepEvents:        50, CompactStepPages: 32, PruneTarget: 0.8,
	})
	if r.Mode != c5.ModeCollecting {
		t.Fatalf("startup: %s %v", r.Mode, r.Alarms)
	}
	t.Cleanup(func() { r.Store.Close(); r.Unlock() })
	s, ok := store.AsDB(r.Store)
	if !ok {
		t.Fatal("not a platform store")
	}
	return s, filepath.Join(d, "evidence.db")
}

func event(stream c5.StreamID, n int) []byte {
	return fmt.Appendf(nil, `{"schema":"otsec.event/0.1","id":{"node_id":"node-a6","stream":%q,"seq":0},`+
		`"origin":"platform","kind":"telemetry-health","source":{"origin_auth":"platform"},`+
		`"received":{"utc":"2026-10-26T12:00:00.000001Z","resolution_ns":1000,"clock":{"sync":"synchronized","source":"ntp"}},`+
		`"health":{"type":"a6.discard","details":{"n":"%d"}}}`, stream, n)
}

func capture(b []byte) *c5.Capture {
	sum := sha256.Sum256(b)
	return &c5.Capture{SHA256: hex.EncodeToString(sum[:]), Bytes: b}
}

func commit(t *testing.T, db *store.DB, stream c5.StreamID, caps ...*c5.Capture) {
	t.Helper()
	var rs []c5.Record
	for i, c := range caps {
		rs = append(rs, c5.Record{Stream: stream, Class: c5.ClassAdapterEvidence, Event: event(stream, i), Capture: c})
	}
	if _, err := db.CommitBatch(context.Background(), stream, rs); err != nil {
		t.Fatal(err)
	}
}

func seqs(t *testing.T, db *store.DB, stream c5.StreamID) []c5.Seq {
	t.Helper()
	got, err := db.Read(context.Background(), stream, 0, 1000)
	if err != nil {
		t.Fatal(err)
	}
	var out []c5.Seq
	for _, s := range got {
		out = append(out, s.Key.Seq)
	}
	return out
}

func classBytes(t *testing.T, db *store.DB) int64 {
	t.Helper()
	n, err := db.ClassBytes(context.Background(), c5.ClassAdapterEvidence)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func has(db *store.DB, c *c5.Capture) bool {
	_, err := db.ReadCapture(context.Background(), "sha256:"+c.SHA256)
	return err == nil
}

// Seqs are per stream: the same numbers in another quarantine stream and in
// a SER stream stay, and a seq beyond the named stream's range removes
// nothing anywhere.
func TestDiscardOnlyTheNamedStream(t *testing.T) {
	ctx := context.Background()
	db, _ := open(t, 1<<30)
	for _, s := range []c5.StreamID{qa, qb, ser} {
		commit(t, db, s, nil, nil, nil, nil, nil)
	}
	if qbSeqs := seqs(t, db, qb); len(qbSeqs) != 5 {
		t.Fatalf("setup: %v", qbSeqs)
	}
	got, err := db.Discard(ctx, nil, qa, []c5.Seq{2, 4})
	if err != nil || got.Events != 2 {
		t.Fatalf("discard: %+v %v", got, err)
	}
	commit(t, db, qb, nil, nil, nil) // qb now runs to 8, qa to 5
	got, err = db.Discard(ctx, nil, qa, []c5.Seq{6, 7, 8})
	if err != nil || got.Events != 0 || got.Bytes != 0 {
		t.Fatalf("seqs only another stream has: %+v %v", got, err)
	}
	if s := fmt.Sprint(seqs(t, db, qa)); s != "[1 3 5]" {
		t.Errorf("qa keeps %s", s)
	}
	if s := fmt.Sprint(seqs(t, db, qb)); s != "[1 2 3 4 5 6 7 8]" {
		t.Errorf("qb keeps %s", s)
	}
	if s := fmt.Sprint(seqs(t, db, ser)); s != "[1 2 3 4 5]" {
		t.Errorf("ser keeps %s", s)
	}
}

// A persisted cursor on the quarantine stream refuses the call, with
// nothing removed; a cursor or consumer on another stream does not.
func TestDiscardRefusesACursoredQuarantine(t *testing.T) {
	ctx := context.Background()
	db, _ := open(t, 1<<30)
	commit(t, db, qa, nil, nil, nil)
	commit(t, db, qb, nil, nil, nil)
	commit(t, db, ser, nil, nil, nil)
	if err := db.SaveCursor(ctx, c5.Cursor{Consumer: "central", Stream: qa, Through: 1}); err != nil {
		t.Fatal(err)
	}
	if err := db.SaveCursor(ctx, c5.Cursor{Consumer: "central", Stream: ser, Through: 1}); err != nil {
		t.Fatal(err)
	}
	before := classBytes(t, db)
	got, err := db.Discard(ctx, nil, qa, []c5.Seq{2})
	var ce *c5.Error
	if !errorsAs(err, &ce) || ce.Code != c5.CodeInvalid || got.Events != 0 {
		t.Fatalf("cursored quarantine: %+v %v", got, err)
	}
	if s := fmt.Sprint(seqs(t, db, qa)); s != "[1 2 3]" || classBytes(t, db) != before {
		t.Fatalf("refusal removed something: %s", s)
	}
	others := []c5.Consumer{{ID: "central", Stream: ser, Delivery: c5.Required}}
	if got, err := db.Discard(ctx, others, qb, []c5.Seq{2}); err != nil || got.Events != 1 {
		t.Fatalf("a cursor and a consumer on other streams blocked qb: %+v %v", got, err)
	}
	reader := []c5.Consumer{{ID: "central", Stream: qb, Delivery: c5.BestEffort}}
	if got, err := db.Discard(ctx, reader, qb, []c5.Seq{3}); err == nil || got.Events != 0 {
		t.Errorf("a quarantine a consumer reads: %+v %v", got, err)
	}
	over := make([]c5.Seq, c5.DiscardStepEvents+1)
	for i := range over {
		over[i] = c5.Seq(100 + i)
	}
	if _, err := db.Discard(ctx, nil, qb, over); err == nil {
		t.Errorf("%d seqs in one call accepted", len(over))
	}
	if s := fmt.Sprint(seqs(t, db, qb)); s != "[1 3]" {
		t.Errorf("refusals changed qb: %s", s)
	}
	for _, bad := range []c5.StreamID{"quarantine/", "Quarantine/a6-asset-a", "quarantines/a6-asset-a", ser, "quarantine/a6-asset-a/x"} {
		if _, err := db.Discard(ctx, nil, bad, []c5.Seq{1}); err == nil {
			t.Errorf("stream %q accepted", bad)
		}
	}
}

// A capture goes only when no retained record of any stream refers to it:
// shared with a SER record, it stays; shared with a quarantine record not
// named, it stays; shared by two named records, it goes once and its bytes
// count once. The bytes reported are what the class lost.
func TestDiscardKeepsSharedCaptures(t *testing.T) {
	ctx := context.Background()
	db, _ := open(t, 1<<30)
	withSER := capture([]byte("a6 capture a SER record also keeps"))
	withKept := capture([]byte("a6 capture a quarantine record not named keeps"))
	twice := capture([]byte("a6 capture two named records share, and only they"))
	own := capture([]byte("a6 capture one named record alone keeps"))
	commit(t, db, qa, withSER, withKept, withKept, twice, twice, own)
	commit(t, db, ser, withSER)
	before := classBytes(t, db)
	got, err := db.Discard(ctx, nil, qa, []c5.Seq{1, 2, 4, 5, 6})
	if err != nil || got.Events != 5 {
		t.Fatalf("discard: %+v %v", got, err)
	}
	if lost := before - classBytes(t, db); lost != got.Bytes {
		t.Errorf("reported %d bytes freed, the class lost %d", got.Bytes, lost)
	}
	if !has(db, withSER) || !has(db, withKept) {
		t.Error("a capture a retained record refers to was removed")
	}
	if has(db, twice) || has(db, own) {
		t.Error("a capture nothing refers to any more was kept")
	}
	if s := fmt.Sprint(seqs(t, db, qa)); s != "[3]" {
		t.Errorf("qa keeps %s", s)
	}
	// The last reference goes: so does the capture, on the call that
	// removes it.
	if got, err := db.Discard(ctx, nil, qa, []c5.Seq{3}); err != nil || got.Events != 1 || has(db, withKept) {
		t.Errorf("last reference: %+v %v, capture kept %v", got, err, has(db, withKept))
	}
}

// The worst step for the WAL: DiscardStepEvents seqs spread across a long
// stream, each with its own capture. A5 measured 1 KiB captures; a SER
// capture can be far larger, so this uses 64 KiB, whose pages are overflow
// pages the delete frees. The WAL one step writes must stay inside
// store.WALBoundBytes.
func TestDiscardStepWALBoundLargeCaptures(t *testing.T) {
	if testing.Short() {
		t.Skip("writes about 64 MB")
	}
	ctx := context.Background()
	db, path := open(t, 1<<31)
	const n, size = 1000, 64 << 10
	for i := 0; i < n; i += 50 {
		var caps []*c5.Capture
		for j := i; j < i+50; j++ {
			b := make([]byte, size)
			copy(b, fmt.Sprintf("a6 capture %d", j))
			caps = append(caps, capture(b))
		}
		commit(t, db, qa, caps...)
	}
	// Start the step from an empty WAL. The checkpoint runs on A6's own
	// connection, which the store's idle connection does not block.
	if err := checkpoint(path); err != nil {
		t.Fatal(err)
	}
	named := make([]c5.Seq, c5.DiscardStepEvents)
	for i := range named {
		named[i] = c5.Seq(1 + i*n/len(named))
	}
	got, err := db.Discard(ctx, nil, qa, named)
	if err != nil || got.Events != len(named) {
		t.Fatalf("discard: %+v %v", got, err)
	}
	fi, err := os.Stat(path + "-wal")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("one step of %d events with %d KiB captures: %d bytes of WAL (bound %d)", len(named), size>>10, fi.Size(), store.WALBoundBytes)
	if fi.Size() > store.WALBoundBytes {
		t.Fatalf("one discard step wrote %d bytes of WAL, over the bound %d", fi.Size(), store.WALBoundBytes)
	}
	if slices.Contains(seqs(t, db, qa), named[3]) {
		t.Fatal("a named seq is still stored")
	}
}
