package storeholds

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"path/filepath"
	"slices"
	"testing"
	"time"

	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/platform/store"
)

// A store written by a later C5 holds a code this code's closed set does
// not know (D4-18: C5 0.6 adds acknowledged-difference). Opened, listed
// and pruned by this code, the record stays stored and held, with its code
// as written: an older binary never unholds what a newer one held
// (B6, D4-18). The newer writer is stood in for by setting the code with
// SQL after a hold this code takes. Evidence class: simulated.
func TestB6NewerHoldCodeIsKeptByThisCode(t *testing.T) {
	ctx := context.Background()
	d := database(c5.MinRecordBytes)
	dir := newDir(t)
	newer := map[c5.Seq]c5.HoldCode{2: "acknowledged-difference", 3: "a-code-from-c5-9.9"}
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
		defer func() {
			db.Close()
			if r.Unlock != nil {
				r.Unlock()
			}
		}()
		l, err := c5.NewLogFor(db, node, d, c5.GroupOptions{MaxEvents: 10, MaxWait: time.Millisecond}, map[c5.StreamID]c5.Seq{cfg: 0})
		if err != nil {
			t.Fatal(err)
		}
		for i := 1; i <= 5; i++ {
			rec := c5.Record{Stream: cfg, Class: c5.ClassConfiguration, Event: fmt.Appendf(nil, `{"doc":%d}`, i)}
			if _, ok := newer[c5.Seq(i)]; ok {
				rec.Holds = []c5.Hold{{Reason: c5.HoldReason{Code: c5.HoldUnapprovedDifference, Ref: c5.Key{NodeID: node, Stream: "audit", Seq: c5.Seq(10 + i)}}}}
			}
			if _, err := l.Append(ctx, rec); err != nil {
				t.Fatal(err)
			}
		}
	}()

	// The newer binary's write: the same rows, with codes this one lacks.
	files, _ := filepath.Glob(filepath.Join(dir, "*.db"))
	if len(files) != 1 {
		t.Fatalf("database files %v", files)
	}
	raw, err := sql.Open("sqlite", "file:"+(&url.URL{Path: files[0]}).EscapedPath()+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	for seq, code := range newer {
		if res, err := raw.Exec(`UPDATE holds SET code = ? WHERE stream = ? AND seq = ?`, string(code), string(cfg), int64(seq)); err != nil {
			t.Fatal(err)
		} else if n, _ := res.RowsAffected(); n != 1 {
			t.Fatalf("seq %d: %d hold rows", seq, n)
		}
	}
	raw.Close()
	if err := (c5.HoldReason{Code: newer[2], Ref: c5.Key{NodeID: node, Stream: "audit", Seq: 1}}).Validate(); err == nil {
		t.Log("this code's C5 knows acknowledged-difference: the case is then only the later code")
	}

	// This code opens it, lists it, and prunes past every record.
	db := open(t, dir, d)
	held, err := db.Held(ctx, cfg)
	if err != nil {
		t.Fatalf("Held over a newer code: %v", err)
	}
	got := map[c5.Seq]c5.HoldCode{}
	for _, h := range held {
		got[h.Seq] = h.Reason.Code
		if want := c5.Seq(10 + int(h.Seq)); h.Reason.Ref.Seq != want {
			t.Errorf("seq %d: ref %+v, want audit seq %d", h.Seq, h.Reason.Ref, want)
		}
	}
	if len(got) != len(newer) || got[2] != newer[2] || got[3] != newer[3] {
		t.Fatalf("held %v, want %v", got, newer)
	}
	if err := db.SaveCursor(ctx, c5.Cursor{Consumer: "central", Stream: cfg, Through: 5}); err != nil {
		t.Fatal(err)
	}
	b, err := c5.ComputeBoundary(ctx, db, db, []c5.Consumer{{ID: "central", Stream: cfg, Delivery: c5.Required}}, cfg, c5.ClassConfiguration, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if n, err := db.PruneStep(ctx, b, 100); err != nil || n != 3 {
		t.Fatalf("PruneStep: %d %v, want the 3 unheld records", n, err)
	}
	recs, err := db.Read(ctx, cfg, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	var left []c5.Seq
	for _, r := range recs {
		left = append(left, r.Key.Seq)
	}
	if !slices.Equal(left, []c5.Seq{2, 3}) {
		t.Fatalf("stored after the prune %v, want the held 2 and 3", left)
	}
	if held, err := db.Held(ctx, cfg); err != nil || len(held) != 2 {
		t.Fatalf("held after the prune %v %v", held, err)
	}
}
