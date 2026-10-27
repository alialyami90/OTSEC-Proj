package store

import (
	"bytes"
	"context"
	"sync"
	"testing"
	"time"
)

// countingCommitter records the payload bytes and size of every commit.
type countingCommitter struct {
	*fake
	mu      sync.Mutex
	commits []int64
	counts  []int
}

func (c *countingCommitter) CommitBatch(ctx context.Context, s StreamID, recs []Record) (Commit, error) {
	var n int64
	seen := map[string]bool{}
	for _, r := range recs {
		n += int64(len(r.Event))
		if r.Capture != nil && !seen[r.Capture.SHA256] {
			seen[r.Capture.SHA256] = true
			n += int64(len(r.Capture.Bytes))
		}
	}
	c.mu.Lock()
	c.commits, c.counts = append(c.commits, n), append(c.counts, len(recs))
	c.mu.Unlock()
	return c.fake.CommitBatch(ctx, s, recs)
}

var auditRef = Key{NodeID: "site-a-node1", Stream: "audit", Seq: 7}

func configDB(capBytes int64) Database {
	return Database{ID: "config", Writer: "ied", Streams: []StreamSpec{{"config/relay1", ClassConfiguration}, {"ev", ClassAdapterEvidence}},
		Classes: []StreamClass{ClassConfiguration},
		Quotas:  []Quota{{Class: ClassConfiguration, Bytes: 64 << 20, WarnFraction: 0.8, MaxRecordBytes: capBytes}}}
}

func configRec(n int, holds ...Hold) Record {
	return Record{Stream: "config/relay1", Class: ClassConfiguration, Event: []byte(`{"kind":"config.snapshot"}`), Capture: capture(string(bytes.Repeat([]byte{'x'}, n))), Holds: holds}
}

// A configuration stream needs its record cap, so only NewLogFor opens a
// Log over it.
func TestConfigurationNeedsItsCap(t *testing.T) {
	f := newFake()
	if _, err := NewLog(f, f.node, map[StreamID]StreamClass{"config/relay1": ClassConfiguration}, DefaultGroup, nil); !isCode(err, CodeInvalid) {
		t.Fatalf("NewLog over a configuration stream: %v", err)
	}
	d := configDB(512 << 10)
	d.Quotas[0].MaxRecordBytes = 0
	if _, err := NewLogFor(f, f.node, d, DefaultGroup, nil); !isCode(err, CodeInvalid) {
		t.Fatalf("NewLogFor without a cap: %v", err)
	}
}

// A record over its class's cap, or over the commit cap in a class with no
// cap of its own, is refused before it is queued and nothing is stored.
func TestRecordTooLarge(t *testing.T) {
	f := newFake()
	l, err := NewLogFor(f, f.node, configDB(MinRecordBytes), DefaultGroup, nil)
	if err != nil {
		t.Fatal(err)
	}
	over := configRec(MinRecordBytes)
	if _, err := l.Append(context.Background(), over); !isCode(err, CodeRecordTooLarge) {
		t.Fatalf("over the class cap: %v", err)
	}
	if _, err := l.AppendBatch(context.Background(), []Record{over}); !isCode(err, CodeRecordTooLarge) {
		t.Fatalf("over the class cap in a batch: %v", err)
	}
	big := Record{Stream: "ev", Class: ClassAdapterEvidence, Event: bytes.Repeat([]byte{'e'}, DefaultMaxCommitBytes+1)}
	if _, err := l.Append(context.Background(), big); !isCode(err, CodeRecordTooLarge) {
		t.Fatalf("over the commit cap with no class cap: %v", err)
	}
	if len(f.events) != 0 || len(f.captures) != 0 {
		t.Fatalf("a refused record was stored: %v", f.events)
	}
	if _, err := l.Append(context.Background(), configRec(MinRecordBytes-100)); err != nil {
		t.Fatalf("under the cap: %v", err)
	}
}

// A configuration record commits alone, even when many are appended at
// once, so the largest commit is one capped record (B6 on #246).
func TestConfigurationCommitsAlone(t *testing.T) {
	c := &countingCommitter{fake: newFake()}
	l, err := NewLogFor(c, c.node, configDB(512<<10), GroupOptions{MaxEvents: 100, MaxWait: time.Second}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := l.Append(context.Background(), configRec(1000)); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	for i, n := range c.counts {
		if n != 1 {
			t.Fatalf("commit %d held %d configuration records", i, n)
		}
	}
	if len(c.counts) != 20 {
		t.Fatalf("%d commits for 20 records", len(c.counts))
	}
	if _, err := l.AppendBatch(context.Background(), []Record{configRec(10), configRec(20)}); !isCode(err, CodeInvalid) {
		t.Fatalf("a configuration batch of two: %v", err)
	}
}

// Groups close before a record would take them past MaxCommitBytes, and
// seqs still follow append order (D4-9).
func TestCommitCapBoundsGroups(t *testing.T) {
	c := &countingCommitter{fake: newFake()}
	opt := GroupOptions{MaxEvents: 1000, MaxWait: 20 * time.Millisecond, MaxCommitBytes: MinRecordBytes}
	l, err := NewLog(c, c.node, testStreams, opt, nil)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 64 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := l.Append(context.Background(), Record{Stream: "s", Class: ClassAdapterEvidence, Event: bytes.Repeat([]byte{'e'}, 7000)}); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	var total int
	for i, n := range c.commits {
		if n > MinRecordBytes {
			t.Errorf("commit %d carried %d bytes, over the cap %d", i, n, MinRecordBytes)
		}
		total += c.counts[i]
	}
	if total != 64 || len(c.commits) < 64*7000/MinRecordBytes {
		t.Fatalf("%d records in %d commits", total, len(c.commits))
	}
	for i, s := range c.events["s"] {
		if s.Key.Seq != Seq(i+1) {
			t.Fatalf("seq %d at %d", s.Key.Seq, i)
		}
	}
	// A batch of more than one record over the cap is refused whole; one
	// shared capture counts once.
	shared := capture(string(bytes.Repeat([]byte{'c'}, MinRecordBytes-1000)))
	batch := []Record{{Stream: "s", Class: ClassAdapterEvidence, Event: []byte("a"), Capture: shared}, {Stream: "s", Class: ClassAdapterEvidence, Event: []byte("b"), Capture: shared}}
	if _, err := l.AppendBatch(context.Background(), batch); err != nil {
		t.Fatalf("a batch whose shared capture fits: %v", err)
	}
	batch = append(batch, Record{Stream: "s", Class: ClassAdapterEvidence, Event: bytes.Repeat([]byte{'e'}, 2000)})
	if _, err := l.AppendBatch(context.Background(), batch); !isCode(err, CodeRecordTooLarge) {
		t.Fatalf("a batch over the cap: %v", err)
	}
}

// A record over the commit cap that its class's cap allows commits alone.
func TestRecordOverCommitCapCommitsAlone(t *testing.T) {
	c := &countingCommitter{fake: newFake()}
	d := Database{ID: "ev", Writer: "ied", Streams: []StreamSpec{{"s", ClassAdapterEvidence}}, Classes: []StreamClass{ClassAdapterEvidence},
		Quotas: []Quota{{Class: ClassAdapterEvidence, Bytes: 64 << 20, WarnFraction: 0.8, MaxRecordBytes: 4 << 20}}}
	l, err := NewLogFor(c, c.node, d, GroupOptions{MaxEvents: 10, MaxWait: time.Millisecond}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.Append(context.Background(), Record{Stream: "s", Class: ClassAdapterEvidence, Event: bytes.Repeat([]byte{'e'}, 2<<20)}); err != nil {
		t.Fatal(err)
	}
	if len(c.counts) != 1 || c.counts[0] != 1 {
		t.Fatalf("commits %v", c.counts)
	}
	if got := LargestCommit(d, GroupOptions{}); got != 4<<20 {
		t.Fatalf("LargestCommit %d", got)
	}
}

// Only configuration records take holds, and a hold names a C8 record by
// a code from the closed set.
func TestHoldsOnRecords(t *testing.T) {
	f := newFake()
	l, err := NewLogFor(f, f.node, configDB(512<<10), DefaultGroup, nil)
	if err != nil {
		t.Fatal(err)
	}
	good := Hold{Reason: HoldReason{Code: HoldUnapprovedDifference, Ref: auditRef}}
	if _, err := l.Append(context.Background(), configRec(100, good)); err != nil {
		t.Fatal(err)
	}
	ev := Record{Stream: "ev", Class: ClassAdapterEvidence, Event: []byte("e"), Holds: []Hold{good}}
	if _, err := l.Append(context.Background(), ev); !isCode(err, CodeNotHoldable) {
		t.Fatalf("a hold on an evidence record: %v", err)
	}
	for name, h := range map[string]Hold{
		"free text":  {Reason: HoldReason{Code: "because", Ref: auditRef}},
		"no record":  {Reason: HoldReason{Code: HoldBaseline}},
		"seq 0":      {Reason: HoldReason{Code: HoldBaseline, Ref: Key{NodeID: "site-a-node1", Stream: "audit"}}},
		"bad stream": {Stream: "Bad Stream", Reason: HoldReason{Code: HoldBaseline, Ref: auditRef}},
	} {
		if _, err := l.Append(context.Background(), configRec(100, h)); !isCode(err, CodeInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// The reserve rule is payload plus a constant, and it covers every WAL
// measured on #246 at its payload, from the smallest cap up (B6).
func TestRecoveryReserveFor(t *testing.T) {
	const walBound = 512 << 10
	for _, m := range []struct{ payload, wal int64 }{
		{128 << 10, 164832}, {256 << 10, 296672}, {512 << 10, 560352}, {768 << 10, 824032}, // B5, modernc
		{128 << 10, 152472}, {256 << 10, 284312}, {512 << 10, 547992}, {768 << 10, 811672}, // B6, sqlite3
	} {
		if w := CommitWALBytes(m.payload); w < m.wal {
			t.Errorf("payload %d: W %d below the measured %d", m.payload, w, m.wal)
		}
	}
	// The fixed cost, about 34 KB, dominates at the smallest cap: a ratio
	// rule of 1.25 would allow 81,920 bytes there.
	if w := CommitWALBytes(MinRecordBytes); w < MinRecordBytes+34<<10 {
		t.Errorf("W at the smallest cap %d", w)
	}
	if got, want := RecoveryReserveFor(walBound, 512<<10), int64(2*walBound+512<<10+512<<10/10+64<<10); got != want {
		t.Errorf("reserve %d, want %d", got, want)
	}
	if got := RecoveryReserveFor(walBound, DefaultMaxCommitBytes); got > 23<<20/10 {
		t.Errorf("event database reserve %d, over about 2.2 MiB", got)
	}
}
