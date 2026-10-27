package store

import (
	"bytes"
	"context"
	"testing"
	"time"
)

// C5 0.5 (D4-14): the WAL a commit may write counts its rows, and the file
// is bounded against what the quota counts. Evidence class: simulated.

func evRec(n int) Record {
	return Record{Stream: "s", Class: ClassAdapterEvidence, Event: bytes.Repeat([]byte{'e'}, n)}
}

// An AppendBatch of more records than MaxCommitRecords is refused whole,
// like one over MaxCommitBytes; a batch at the cap is accepted.
func TestBatchOverCommitRecordsIsRefused(t *testing.T) {
	f := newFake()
	opt := GroupOptions{MaxEvents: 4, MaxWait: time.Millisecond, MaxCommitRecords: 8}
	l, err := NewLog(f, f.node, testStreams, opt, nil)
	if err != nil {
		t.Fatal(err)
	}
	batch := func(n int) []Record {
		out := make([]Record, n)
		for i := range out {
			out[i] = evRec(100)
		}
		return out
	}
	if _, err := l.AppendBatch(context.Background(), batch(9)); !isCode(err, CodeRecordTooLarge) {
		t.Fatalf("9 records over a cap of 8: %v", err)
	}
	if len(f.events) != 0 {
		t.Fatalf("a refused batch was stored: %d events", len(f.events))
	}
	if _, err := l.AppendBatch(context.Background(), batch(8)); err != nil {
		t.Fatalf("8 records at the cap: %v", err)
	}
	// The Log keeps running after a refusal.
	if _, err := l.Append(context.Background(), evRec(100)); err != nil {
		t.Fatalf("after a refusal: %v", err)
	}
}

// MaxCommitRecords defaults to MaxEvents and is at least MaxEvents.
func TestCommitRecordsDefaultsAndBounds(t *testing.T) {
	if got := (GroupOptions{MaxEvents: 100, MaxWait: time.Millisecond}).CommitRecords(); got != 100 {
		t.Errorf("default %d, want MaxEvents", got)
	}
	for name, o := range map[string]GroupOptions{
		"below MaxEvents": {MaxEvents: 100, MaxWait: time.Millisecond, MaxCommitRecords: 99},
		"over MaxBatch":   {MaxEvents: 100, MaxWait: time.Millisecond, MaxCommitRecords: MaxBatch + 1},
	} {
		if err := o.Validate(); !isCode(err, CodeInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	ok := GroupOptions{MaxEvents: 100, MaxWait: time.Millisecond, MaxCommitRecords: 2048}
	if err := ok.Validate(); err != nil {
		t.Errorf("2048 records: %v", err)
	}
}

// A database that holds only configuration commits one record; any other
// takes the Log's record cap.
func TestLargestCommitRecords(t *testing.T) {
	opt := GroupOptions{MaxEvents: 100, MaxWait: time.Millisecond, MaxCommitRecords: 2048}
	if n := LargestCommitRecords(configDB(512<<10), opt); n != 1 {
		t.Errorf("configuration database: %d, want 1", n)
	}
	ev := Database{ID: "ev", Writer: "ied", Classes: []StreamClass{ClassAdapterEvidence, ClassPlatform}}
	if n := LargestCommitRecords(ev, opt); n != 2048 {
		t.Errorf("evidence database: %d, want 2048", n)
	}
	if n := LargestCommitRecords(ev, GroupOptions{MaxEvents: 100, MaxWait: time.Millisecond}); n != 100 {
		t.Errorf("default: %d, want MaxEvents", n)
	}
}

// The rule is payload, a fixed term and a term a row. B6's worst case on the
// event-size sweep (#280, 128 events of 2 KB: 262,522 bytes over the 0.4 rule
// at 271,104 payload) is inside it with margin, and the figures D4-14 gives
// come out.
func TestCommitWALBytesCountsRows(t *testing.T) {
	if got, want := CommitWALBytes(1<<20, 1), int64(1<<20+(1<<20)/10+64<<10+3<<10); got != want {
		t.Errorf("1 MiB, 1 row: %d, want %d", got, want)
	}
	const worstExcessPerRow = 262522 / 128 // 2,051 B beyond the 0.4 rule, at 2 KB events
	if RowWALBytes < worstExcessPerRow*14/10 {
		t.Errorf("RowWALBytes %d is under 40%% over the worst measured %d a row", RowWALBytes, worstExcessPerRow)
	}
	const worstPayload, worstWAL, rows = 271104, 271104 + 262522 + 271104/10 + 64<<10, 128
	if w := CommitWALBytes(worstPayload, rows); w <= worstWAL {
		t.Errorf("the sweep's worst case wrote %d bytes of WAL; the rule gives %d", worstWAL, w)
	}
	// A row-less rule is the 0.4 rule: the term is per row.
	if CommitWALBytes(1<<20, 2048)-CommitWALBytes(1<<20, 1) != 2047*RowWALBytes {
		t.Errorf("the row term is not linear")
	}
	const wal = 512 << 10
	evidence := RecoveryReserveFor(wal, 11<<20, 2048)
	if evidence != 2*wal+11<<20+(11<<20)/10+64<<10+2048*3<<10 {
		t.Errorf("evidence reserve %d", evidence)
	}
	if got := float64(evidence) / (1 << 20); got < 19.1 || got > 19.2 {
		t.Errorf("evidence reserve %.2f MiB, D4-14 gives 19.16", got)
	}
}

// The disk factor is a published bound above the measured worst case.
func TestDiskBytesPerQuotaByte(t *testing.T) {
	const measuredWorst = 2.02 // B6's sweep, rowid events table, 4 KiB pages
	if DiskBytesPerQuotaByte < measuredWorst*1.2 {
		t.Errorf("DiskBytesPerQuotaByte %v leaves under 20%% margin over %v", DiskBytesPerQuotaByte, measuredWorst)
	}
}
