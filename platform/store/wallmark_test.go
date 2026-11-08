package store

import (
	"context"
	"strconv"
	"testing"
	"time"

	c5 "otsec.local/otsec/contracts/store"
)

// A commit time is floored at the database's persisted wall mark, which
// every commit and every cursor save raises: with the clock stepped back, a
// commit on a stream idle since before the step, or on one never written,
// takes the latest wall time the database has used, not the stepped-back
// one (D3's F1 on #559, D4-71). Desk only.
func TestWallMarkFloorsCommitTime(t *testing.T) {
	ctx := context.Background()
	t0 := time.Date(2026, 11, 8, 0, 0, 0, 0, time.UTC)
	now := t0
	db, _ := testStore(t, Options{Dir: storeDir(t), Node: testNode, Database: evidenceDB, Now: func() time.Time { return now }},
		policy(evidenceDB), c5.ModeCollecting)
	commit := func(stream c5.StreamID, class c5.StreamClass) time.Time {
		t.Helper()
		c, err := db.CommitBatch(ctx, stream, []c5.Record{{Stream: stream, Class: class, Event: pending(stream, 1)}})
		if err != nil {
			t.Fatal(err)
		}
		return c.At
	}
	mark := func() time.Time {
		t.Helper()
		var v string
		if err := db.conn.QueryRowContext(ctx, `SELECT value FROM meta WHERE key = 'wall_mark'`).Scan(&v); err != nil {
			t.Fatal(err)
		}
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		return time.Unix(0, n).UTC()
	}

	if at := commit("relay1/ser", c5.ClassAdapterEvidence); !at.Equal(t0) || !mark().Equal(t0) {
		t.Fatalf("first commit at %s, mark %s", at, mark())
	}
	now = t0.Add(-10 * 24 * time.Hour) // stepped back
	if at := commit("syslog/relay1", c5.ClassSyslogStream); !at.Equal(t0) {
		t.Fatalf("a commit on a stream never written, with the clock back, at %s; want the mark %s", at, t0)
	}
	// A cursor save raises the mark too.
	now = t0.Add(time.Hour)
	if err := db.SaveCursor(ctx, c5.Cursor{Consumer: "c", Stream: "relay1/ser", Through: 1}); err != nil {
		t.Fatal(err)
	}
	if !mark().Equal(now) {
		t.Fatalf("mark %s after a cursor save at %s", mark(), now)
	}
	now = t0.Add(-time.Hour)
	if at := commit("platform/health", c5.ClassPlatform); !at.Equal(t0.Add(time.Hour)) {
		t.Fatalf("a commit after a cursor save, with the clock back, at %s", at)
	}
	// With the clock past the mark again, commit times follow it.
	now = t0.Add(2 * time.Hour)
	if at := commit("relay1/ser", c5.ClassAdapterEvidence); !at.Equal(now) || !mark().Equal(now) {
		t.Fatalf("commit at %s, mark %s; want %s", at, mark(), now)
	}
}
