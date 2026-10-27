package store

import (
	"context"
	"fmt"
	"os"
	"testing"

	c5 "otsec.local/otsec/contracts/store"
)

const qStream c5.StreamID = "quarantine/relay1"

// quarantineDB is evidenceDB with a quarantine stream beside the SER one.
var quarantineDB = func() c5.Database {
	d := evidenceDB
	d.Streams = append([]c5.StreamSpec{{ID: qStream, Class: c5.ClassAdapterEvidence}}, evidenceDB.Streams...)
	return d
}()

// seqsOf returns the seqs stream retains.
func seqsOf(t *testing.T, db *DB, stream c5.StreamID) []c5.Seq {
	t.Helper()
	got, err := db.Read(context.Background(), stream, 0, MaxRead)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]c5.Seq, len(got))
	for i, s := range got {
		out[i] = s.Key.Seq
	}
	return out
}

// Discard removes only the named seqs; a capture another stream's retained
// record still refers to stays, one nothing refers to goes; the bytes it
// reports are what the class lost; and naming a seq already gone is not an
// error, so a clear stopped partway is finished by calling it again.
func TestDiscardNamedSeqs(t *testing.T) {
	ctx := context.Background()
	db := open1(t, storeDir(t), quarantineDB, nil)
	l := testLog(t, db)
	shared := capture("a capture the SER stream also keeps")
	own := capture("a capture only the quarantine keeps")
	var rs []c5.Record
	for i := 0; i < 5; i++ {
		r := rec(qStream, c5.ClassAdapterEvidence, i)
		switch i {
		case 1:
			r.Capture = &shared
		case 2:
			r.Capture = &own
		}
		rs = append(rs, r)
	}
	ser := rec("relay1/ser", c5.ClassAdapterEvidence, 99)
	ser.Capture = &shared
	for _, b := range [][]c5.Record{rs, {ser}} {
		if _, err := l.AppendBatch(ctx, b); err != nil {
			t.Fatal(err)
		}
	}
	before, _ := db.ClassBytes(ctx, c5.ClassAdapterEvidence)
	got, err := db.Discard(ctx, nil, qStream, []c5.Seq{2, 3, 1})
	if err != nil || got.Events != 3 {
		t.Fatalf("discard: %+v %v", got, err)
	}
	after, _ := db.ClassBytes(ctx, c5.ClassAdapterEvidence)
	if before-after != got.Bytes {
		t.Fatalf("reported %d bytes freed, class lost %d", got.Bytes, before-after)
	}
	if s := fmt.Sprint(seqsOf(t, db, qStream)); s != "[4 5]" {
		t.Fatalf("quarantine keeps %s, want [4 5]", s)
	}
	if s := seqsOf(t, db, "relay1/ser"); len(s) != 1 {
		t.Fatalf("SER stream keeps %v", s)
	}
	if c, err := db.ReadCapture(ctx, "sha256:"+shared.SHA256); err != nil || string(c.Bytes) != string(shared.Bytes) {
		t.Fatalf("shared capture: %q %v", c.Bytes, err)
	}
	if _, err := db.ReadCapture(ctx, "sha256:"+own.SHA256); err == nil {
		t.Fatal("a capture nothing refers to any more was kept")
	}
	again, err := db.Discard(ctx, nil, qStream, []c5.Seq{1, 2, 3, 4})
	if err != nil || again.Events != 1 {
		t.Fatalf("finishing call: %+v %v", again, err)
	}
	if s := fmt.Sprint(seqsOf(t, db, qStream)); s != "[5]" {
		t.Fatalf("quarantine keeps %s, want [5]", s)
	}
}

// Every refusal leaves the stream as it was.
func TestDiscardRefusals(t *testing.T) {
	ctx := context.Background()
	db := open1(t, storeDir(t), quarantineDB, nil)
	l := testLog(t, db)
	for _, b := range [][]c5.Record{recs(qStream, c5.ClassAdapterEvidence, 0, 60), recs("relay1/ser", c5.ClassAdapterEvidence, 0, 3)} {
		if _, err := l.AppendBatch(ctx, b); err != nil {
			t.Fatal(err)
		}
	}
	many := make([]c5.Seq, c5.DiscardStepEvents+1)
	for i := range many {
		many[i] = c5.Seq(i + 1)
	}
	reader := c5.Consumer{ID: "central", Stream: qStream, Delivery: c5.Required}
	for name, call := range map[string]func() error{
		"not a quarantine stream": func() error { _, err := db.Discard(ctx, nil, "relay1/ser", []c5.Seq{1}); return err },
		"read by a consumer":      func() error { _, err := db.Discard(ctx, []c5.Consumer{reader}, qStream, []c5.Seq{1}); return err },
		"no seqs":                 func() error { _, err := db.Discard(ctx, nil, qStream, nil); return err },
		"over a step":             func() error { _, err := db.Discard(ctx, nil, qStream, many); return err },
		"seq 0":                   func() error { _, err := db.Discard(ctx, nil, qStream, []c5.Seq{0}); return err },
		"repeated seq":            func() error { _, err := db.Discard(ctx, nil, qStream, []c5.Seq{1, 1}); return err },
		"unknown stream":          func() error { _, err := db.Discard(ctx, nil, "quarantine/other", []c5.Seq{1}); return err },
	} {
		if err := call(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := db.SaveCursor(ctx, c5.Cursor{Consumer: "central", Stream: qStream, Through: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Discard(ctx, nil, qStream, []c5.Seq{2}); !isCode(err, c5.CodeInvalid) {
		t.Errorf("stream with a persisted cursor: %v", err)
	}
	if n := len(seqsOf(t, db, qStream)); n != 60 {
		t.Fatalf("refusals removed events: %d left", n)
	}
	ro, err := OpenReadOnly(ctx, db.opt.Dir, testNode, quarantineDB.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()
	if _, err := ro.Discard(ctx, nil, qStream, []c5.Seq{3}); err == nil {
		t.Fatal("a read-only handle discarded")
	}
}

// D3-1 condition 3: one step of the shape that costs the most WAL, seqs
// spread across a long stream so each touches its own pages, each event with
// its own small capture, writes less than the WAL bound, so it fits the
// reserved headroom on a full disk as a prune step does (E-A5-3). Evidence
// class: simulated.
func TestDiscardStepWALBound(t *testing.T) {
	ctx := context.Background()
	db := open1(t, storeDir(t), withQuota(quarantineDB, c5.ClassAdapterEvidence, 1<<30), nil)
	l := testLog(t, db)
	// The fixture is built in 16 commits of about 550 KiB (under C5 0.4's
	// MaxCommitBytes) with checkpoints off: on the hosted Windows runner
	// each flush is slow, and 80 commits with a checkpoint every 64 pages
	// took 274 to 438 s (#230). The step measured below starts from a
	// truncated WAL either way.
	if _, err := db.conn.ExecContext(ctx, "PRAGMA wal_autocheckpoint=0"); err != nil {
		t.Fatal(err)
	}
	const n = 8000
	for i := 0; i < n; i += 500 {
		var rs []c5.Record
		for j := i; j < i+500; j++ {
			r := rec(qStream, c5.ClassAdapterEvidence, j)
			c := capture(fmt.Sprintf("%01024d", j))
			r.Capture = &c
			rs = append(rs, r)
		}
		if _, err := l.AppendBatch(ctx, rs); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.conn.ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		t.Fatal(err)
	}
	seqs := make([]c5.Seq, c5.DiscardStepEvents)
	for i := range seqs {
		seqs[i] = c5.Seq(1 + i*n/len(seqs))
	}
	got, err := db.Discard(ctx, nil, qStream, seqs)
	if err != nil || got.Events != len(seqs) {
		t.Fatalf("discard: %+v %v", got, err)
	}
	fi, err := os.Stat(db.path + "-wal")
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() > WALBoundBytes {
		t.Fatalf("one discard step wrote %d bytes of WAL, more than the bound %d", fi.Size(), WALBoundBytes)
	}
	t.Logf("one step of %d events: %d bytes of WAL (bound %d)", len(seqs), fi.Size(), WALBoundBytes)
}
