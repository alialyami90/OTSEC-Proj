package contract

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"otsec.local/otsec/contracts/store"
)

// C5 otsec.store/0.5 (B6, D4-14): the record cap on a commit, the rule's
// per-record term, the reserve that follows from it, the disk constant and
// the cap on holds, against the contract's own Log with B6's committer
// (c5_v04_b6_test.go). Expected behaviour comes from D4-14 and the
// contracts/store doc comments, not from B5's v05_test.go. What the store
// writes is measured on the real store in tests/integration/storeholds.

// MaxCommitRecords is 0 (meaning MaxEvents) or in [MaxEvents, MaxBatch].
func TestC5v05CommitRecordsOption(t *testing.T) {
	base := store.GroupOptions{MaxEvents: 10, MaxWait: time.Millisecond}
	for _, c := range []struct {
		records int
		ok      bool
		eff     int
	}{
		{0, true, 10}, {10, true, 10}, {2048, true, 2048}, {store.MaxBatch, true, store.MaxBatch},
		{9, false, 0}, {1, false, 0}, {store.MaxBatch + 1, false, 0}, {-1, false, 0},
	} {
		o := base
		o.MaxCommitRecords = c.records
		err := o.Validate()
		if c.ok != (err == nil) {
			t.Errorf("MaxCommitRecords %d: %v, want ok %v", c.records, err, c.ok)
			continue
		}
		if c.ok && o.CommitRecords() != c.eff {
			t.Errorf("MaxCommitRecords %d: effective %d, want %d", c.records, o.CommitRecords(), c.eff)
		}
		if !c.ok && !c5vIs(err, store.CodeInvalid) {
			t.Errorf("MaxCommitRecords %d: %v, want invalid", c.records, err)
		}
	}
}

// An AppendBatch of more records than the cap is refused whole with
// record-too-large, before anything is queued, and the Log keeps running;
// a batch at the cap commits as one commit. With no cap set, the cap is
// MaxEvents.
func TestC5v05BatchOverRecordCapRefusedWhole(t *testing.T) {
	ctx := context.Background()
	d := c5vDB("evidence", c5vEvid, store.ClassAdapterEvidence, 64<<20, 0)
	batch := func(n int) []store.Record {
		cp := c5vCapture([]byte("one read"))
		out := make([]store.Record, n)
		for i := range out {
			out[i] = store.Record{Stream: c5vEvid, Class: store.ClassAdapterEvidence, Event: []byte(fmt.Sprintf(`{"row":%d}`, i)), Capture: cp}
		}
		return out
	}
	for _, c := range []struct {
		name  string
		cap   int
		limit int
	}{{"cap 20", 20, 20}, {"no cap", 0, 10}} {
		t.Run(c.name, func(t *testing.T) {
			l, com := c5vLog(t, d, store.GroupOptions{MaxEvents: 10, MaxWait: time.Millisecond, MaxCommitRecords: c.cap})
			if _, err := l.AppendBatch(ctx, batch(c.limit+1)); !c5vIs(err, store.CodeRecordTooLarge) {
				t.Fatalf("a batch of %d over a cap of %d: %v", c.limit+1, c.limit, err)
			}
			if n := len(com.all()); n != 0 {
				t.Fatalf("the refused batch reached the committer in %d commits", n)
			}
			rs, err := l.AppendBatch(ctx, batch(c.limit))
			if err != nil || len(rs) != c.limit {
				t.Fatalf("a batch at the cap: %d receipts, %v", len(rs), err)
			}
			if all := com.all(); len(all) != 1 || len(all[0]) != c.limit {
				t.Fatalf("a batch at the cap committed as %d commits", len(all))
			}
			if err := l.Stopped(); err != nil {
				t.Fatalf("the refusal stopped the Log: %v", err)
			}
		})
	}
}

// Records appended one at a time never commit more than the record cap
// together, however many arrive at once: groups close at MaxEvents, which
// the cap is at least.
func TestC5v05GroupsStayUnderRecordCap(t *testing.T) {
	d := c5vDB("evidence", c5vEvid, store.ClassAdapterEvidence, 64<<20, 0)
	l, com := c5vLog(t, d, store.GroupOptions{MaxEvents: 7, MaxWait: 20 * time.Millisecond, MaxCommitRecords: 7})
	var wg sync.WaitGroup
	for i := range 1000 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := l.Append(context.Background(), store.Record{Stream: c5vEvid, Class: store.ClassAdapterEvidence, Event: []byte(fmt.Sprintf(`{"n":%d}`, i))}); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	total := 0
	for _, c := range com.all() {
		if len(c) > 7 {
			t.Errorf("a commit of %d records over the cap of 7", len(c))
		}
		total += len(c)
	}
	if total != 1000 {
		t.Errorf("%d records committed, want 1000", total)
	}
}

// The rule is W(C, R) = 1.1 × C + 64 KiB + RowWALBytes × R, with
// RowWALBytes 3 KiB (D4-14 item 2): exact at a few points, and growing in
// both arguments.
func TestC5v05CommitWALBytes(t *testing.T) {
	if store.RowWALBytes != 3<<10 {
		t.Errorf("RowWALBytes %d, D4-14 sets 3 KiB", store.RowWALBytes)
	}
	for _, c := range []struct{ c, r, want int64 }{
		{0, 0, 64 << 10},
		{0, 1, 64<<10 + 3<<10},
		{1 << 20, 1, 1<<20 + 104857 + 64<<10 + 3<<10},
		{11 << 20, 2048, 11<<20 + 1153433 + 64<<10 + 2048*3<<10},
		{1536 << 10, 1, 1536<<10 + 157286 + 64<<10 + 3<<10},
	} {
		if got := store.CommitWALBytes(c.c, c.r); got != c.want {
			t.Errorf("CommitWALBytes(%d, %d) = %d, want %d", c.c, c.r, got, c.want)
		}
	}
	for _, p := range []int64{0, store.MinRecordBytes, 1 << 20, 11 << 20} {
		for _, r := range []int64{1, 128, 2048} {
			w := store.CommitWALBytes(p, r)
			if store.CommitWALBytes(p+1, r) < w || store.CommitWALBytes(p, r+1) != w+store.RowWALBytes {
				t.Errorf("CommitWALBytes is not increasing at (%d, %d)", p, r)
			}
		}
	}
}

// The rule against B6's measurements on the built layout (#280 on #282 at
// 2323806, rowid events, 4 KiB pages; simulated, Linux): the worst
// commits of each kind. Evidence class here: desk.
func TestC5v05CommitWALCoversMeasured(t *testing.T) {
	for _, m := range []struct {
		what               string
		payload, rows, wal int64
	}{
		{"one 3.5 KB record", 3654, 1, 45352},
		{"one 64 KiB record", 65606, 1, 103032},
		{"128 events of 2 KB", 271104, 128, 585072},
		{"128 events at the page edge, 1954 B", 259072, 128, 585072},
		{"2048 events of 2 KB", 4337664, 2048, 8936312},
		{"180 events of 62 KB, at the 11 MiB cap", 11440440, 180, 11952152},
		{"a SER read that fills the cap", 11468800, 2048, 12512440},
		{"2048 SER rows just over a leaf cell", 2396160, 2048, 3592640},
	} {
		if w := store.CommitWALBytes(m.payload, m.rows); w < m.wal {
			t.Errorf("%s: rule %d below the measured %d", m.what, w, m.wal)
		}
	}
}

// RecoveryReserveFor(w, C, R) = 2w + W(C, R), and the D4-14 reserves for
// the node's databases follow from it with a 512 KiB WAL bound.
func TestC5v05RecoveryReserve(t *testing.T) {
	const w = 512 << 10
	for _, c := range []struct {
		db      string
		c, r    int64
		reserve int64
	}{
		{"evidence", 11 << 20, 2048, 20093337},
		{"syslog", 1 << 20, 1024, 5413273},
		{"audit", 1 << 20, 128, 2660761},
		{"configuration", 1536 << 10, 1, 2847334},
	} {
		got := store.RecoveryReserveFor(w, c.c, c.r)
		if got != 2*w+store.CommitWALBytes(c.c, c.r) {
			t.Errorf("%s: RecoveryReserveFor %d is not 2 × WAL bound + W(C, R)", c.db, got)
		}
		if got != c.reserve {
			t.Errorf("%s: reserve %d, want %d", c.db, got, c.reserve)
		}
	}
}

// LargestCommitRecords is one for a database that holds only the
// configuration class, and the record cap otherwise.
func TestC5v05LargestCommitRecords(t *testing.T) {
	opt := store.GroupOptions{MaxEvents: 10, MaxWait: time.Millisecond, MaxCommitRecords: 2048}
	cfg := c5vDB("config", c5vConfig, store.ClassConfiguration, 8<<20, 512<<10)
	if n := store.LargestCommitRecords(cfg, opt); n != 1 {
		t.Errorf("configuration only: %d, want 1", n)
	}
	ev := c5vDB("evidence", c5vEvid, store.ClassAdapterEvidence, 64<<20, 0)
	if n := store.LargestCommitRecords(ev, opt); n != 2048 {
		t.Errorf("evidence with a cap of 2048: %d", n)
	}
	if n := store.LargestCommitRecords(ev, store.GroupOptions{MaxEvents: 10, MaxWait: time.Millisecond}); n != 10 {
		t.Errorf("evidence with no cap: %d, want MaxEvents", n)
	}
	mixed := ev
	mixed.Classes = []store.StreamClass{store.ClassAdapterEvidence, store.ClassConfiguration}
	if n := store.LargestCommitRecords(mixed, opt); n != 2048 {
		t.Errorf("a database with configuration and another class: %d, want the cap", n)
	}
}

// The start-up policy sets the WAL bound, the largest commit and its
// record count all or none, and refuses a reserve one byte below the rule
// at any record count, including one sized without the per-record term.
func TestC5v05StartupReserve(t *testing.T) {
	base := store.StartupPolicy{
		Streams:                []store.StreamSpec{{ID: c5vEvid, Class: store.ClassAdapterEvidence}},
		Consumers:              []store.Consumer{{ID: "forward", Stream: c5vEvid, Delivery: store.Required}},
		LastResortReserveBytes: 128 << 10, OpenHeadroomBytes: 128 << 10,
		PruneStepEvents: 50, CompactStepPages: 32, PruneTarget: 0.8,
	}
	const w = 512 << 10
	for _, r := range []int64{1, 128, 2048} {
		need := store.RecoveryReserveFor(w, 11<<20, r)
		p := base
		p.WALBoundBytes, p.LargestCommitBytes, p.LargestCommitRecords = w, 11<<20, r
		p.RecoveryReserveBytes = need
		if err := p.Validate(); err != nil {
			t.Errorf("%d records at exactly the rule: %v", r, err)
		}
		p.RecoveryReserveBytes = need - 1
		if err := p.Validate(); !c5vIs(err, store.CodeInvalid) {
			t.Errorf("%d records one byte below the rule: %v", r, err)
		}
		p.RecoveryReserveBytes = 2*w + (11<<20)*11/10 + 64<<10 // the 0.4 rule
		if r > 0 {
			if err := p.Validate(); !c5vIs(err, store.CodeInvalid) {
				t.Errorf("%d records at the 0.4 rule, without the per-record term: %v", r, err)
			}
		}
	}
	for _, set := range [][3]int64{{w, 1 << 20, 0}, {w, 0, 1}, {0, 1 << 20, 1}} {
		p := base
		p.RecoveryReserveBytes = 1 << 30
		p.WALBoundBytes, p.LargestCommitBytes, p.LargestCommitRecords = set[0], set[1], set[2]
		if err := p.Validate(); !c5vIs(err, store.CodeInvalid) {
			t.Errorf("WAL bound, bytes, records %v set partly: %v", set, err)
		}
	}
}

// DiskBytesPerQuotaByte is 2.5 (D4-14 item 3), above the worst B6 measured
// on the built layout: 2.24 for one 3.5 KB record, 2.10 at the page edge.
func TestC5v05DiskConstant(t *testing.T) {
	if store.DiskBytesPerQuotaByte != 2.5 {
		t.Errorf("DiskBytesPerQuotaByte %v, D4-14 sets 2.5", store.DiskBytesPerQuotaByte)
	}
	for _, measured := range []float64{2.24, 2.10, 2.04, 2.01} {
		if store.DiskBytesPerQuotaByte < measured {
			t.Errorf("the constant is below a measured %v", measured)
		}
	}
}

// A record takes at most MaxHoldsPerRecord holds; one more is refused
// before anything is queued.
func TestC5v05HoldsPerRecord(t *testing.T) {
	if store.MaxHoldsPerRecord != 16 {
		t.Errorf("MaxHoldsPerRecord %d", store.MaxHoldsPerRecord)
	}
	d := c5vDB("config", c5vConfig, store.ClassConfiguration, 8<<20, 512<<10)
	for _, n := range []int{16, 17} {
		l, com := c5vLog(t, d, store.GroupOptions{MaxEvents: 10, MaxWait: time.Millisecond})
		holds := make([]store.Hold, n)
		for i := range holds {
			holds[i] = store.Hold{Reason: c5vRef()}
		}
		_, err := l.Append(context.Background(), store.Record{Stream: c5vConfig, Class: store.ClassConfiguration, Event: []byte(`{"doc":1}`), Holds: holds})
		switch {
		case n <= store.MaxHoldsPerRecord && err != nil:
			t.Errorf("%d holds: %v", n, err)
		case n > store.MaxHoldsPerRecord && !c5vIs(err, store.CodeInvalid):
			t.Errorf("%d holds: %v, want invalid", n, err)
		case n > store.MaxHoldsPerRecord && len(com.all()) != 0:
			t.Errorf("%d holds reached the committer", n)
		}
	}
}
