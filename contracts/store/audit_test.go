package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"
)

// testChain stands in for C8 until it merges: a sealed record is
// "<seq>|<prev hash hex>|<pending>". TODO(C8): use audit.Seal and
// audit.VerifyChain.
type testChain struct{}

func (testChain) ValidatePending(p []byte) error {
	if len(p) == 0 || bytes.ContainsRune(p, '|') {
		return fmt.Errorf("pending record %q", p)
	}
	return nil
}

func (testChain) Seal(p []byte, seq Seq, prev string) ([]byte, error) {
	return fmt.Appendf(nil, "%d|%s|%s", seq, prev, p), nil
}

func (testChain) Hash(stored []byte) string {
	sum := sha256.Sum256(stored)
	return hex.EncodeToString(sum[:])
}

func (testChain) Genesis() string { return strings.Repeat("0", 64) }

// verifyChain checks that retained records follow from anchor link by link.
func verifyChain(retained []Stored, anchor ChainLink) error {
	at := anchor
	for _, r := range retained {
		want := fmt.Sprintf("%d|%s|", at.Seq+1, at.Hash)
		if r.Key.Seq != at.Seq+1 || !bytes.HasPrefix(r.Event, []byte(want)) {
			return fmt.Errorf("seq %d: %q does not follow %d", r.Key.Seq, r.Event, at.Seq)
		}
		at = ChainLink{Seq: r.Key.Seq, Hash: testChain{}.Hash(r.Event)}
	}
	return nil
}

func auditRecords(n int) []Record {
	recs := make([]Record, n)
	for i := range recs {
		recs[i] = Record{Stream: "audit", Class: ClassAudit, Event: fmt.Appendf(nil, "op-%d", i)}
	}
	return recs
}

func auditFake() *fake {
	f := newFake()
	f.chain = testChain{}
	return f
}

func readAll(t *testing.T, f *fake, stream StreamID) []Stored {
	t.Helper()
	got, err := f.Read(context.Background(), stream, 0, 1000)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

// C5-A3-1: records are sealed in the commit, chain across batches, and are
// read back byte for byte as sealed.
func TestAuditSealedInCommit(t *testing.T) {
	f := auditFake()
	l, err := NewLog(f, f.node, GroupOptions{MaxEvents: 2, MaxWait: time.Millisecond}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := l.AppendBatch(ctx, auditRecords(3)); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Append(ctx, auditRecords(1)[0]); err != nil {
		t.Fatal(err)
	}
	got := readAll(t, f, "audit")
	if len(got) != 4 {
		t.Fatalf("%d records", len(got))
	}
	if err := verifyChain(got, ChainLink{Hash: testChain{}.Genesis()}); err != nil {
		t.Fatal(err)
	}
	if f.heads["audit"] != (ChainLink{Seq: 4, Hash: testChain{}.Hash(got[3].Event)}) {
		t.Fatalf("head %+v", f.heads["audit"])
	}
}

// A batch with one bad pending record is refused whole, nothing is written,
// and the Log keeps running.
func TestAuditBadPendingRefusesBatch(t *testing.T) {
	f := auditFake()
	l, _ := NewLog(f, f.node, DefaultGroup, nil)
	recs := auditRecords(3)
	recs[1].Event = []byte("a|b")
	if _, err := l.AppendBatch(context.Background(), recs); !isCode(err, CodeInvalid) {
		t.Fatalf("err %v", err)
	}
	if len(f.events["audit"]) != 0 || l.Stopped() != nil {
		t.Fatalf("%d written, stopped %v", len(f.events["audit"]), l.Stopped())
	}
	if _, err := l.AppendBatch(context.Background(), auditRecords(2)); err != nil {
		t.Fatal(err)
	}
	if err := verifyChain(readAll(t, f, "audit"), ChainLink{Hash: testChain{}.Genesis()}); err != nil {
		t.Fatal(err)
	}
}

// C5-A3-2(a): an interrupted audit prune leaves an anchor the retained chain
// verifies from, and so does the resumed prune.
func TestAuditPruneKeepsAnchor(t *testing.T) {
	f := auditFake()
	l, _ := NewLog(f, f.node, DefaultGroup, nil)
	ctx := context.Background()
	if _, err := l.AppendBatch(ctx, auditRecords(10)); err != nil {
		t.Fatal(err)
	}
	central := Consumer{ID: "central", Stream: "audit", Delivery: Required}
	if err := f.SaveCursor(ctx, Cursor{"central", "audit", 7}); err != nil {
		t.Fatal(err)
	}
	for step := 0; ; step++ {
		b, err := ComputeBoundary(ctx, f, f, []Consumer{central}, "audit", ClassAudit, f.now)
		if err != nil {
			t.Fatal(err)
		}
		n, err := f.PruneStep(ctx, b, 3) // each step is one "run" that may be killed after it
		if err != nil {
			t.Fatal(err)
		}
		anchor, err := f.ChainAnchor(ctx, "audit")
		if err != nil {
			t.Fatal(err)
		}
		if err := verifyChain(readAll(t, f, "audit"), anchor); err != nil {
			t.Fatalf("after step %d: %v", step, err)
		}
		if n == 0 {
			if anchor.Seq != 7 {
				t.Fatalf("anchor %d, want 7", anchor.Seq)
			}
			return
		}
	}
}

// C5-A3-2(b): best-effort windows never make audit prunable.
func TestAuditBoundaryIgnoresBestEffort(t *testing.T) {
	f := auditFake()
	f.seed("audit", 10, f.now.Add(-48*time.Hour))
	ctx := context.Background()
	siem := Consumer{ID: "siem", Stream: "audit", Delivery: BestEffort, ReplayWindow: time.Hour}
	if _, err := ComputeBoundary(ctx, f, f, []Consumer{siem}, "audit", ClassAudit, f.now); !isCode(err, CodeNoConsumers) {
		t.Fatalf("audit with only a best-effort consumer: %v", err)
	}
	// The same consumers on a non-audit stream would allow all ten.
	if b, _ := ComputeBoundary(ctx, f, f, []Consumer{siem}, "audit", ClassPlatform, f.now); b.Through() != 10 {
		t.Fatalf("control: %d", b.Through())
	}
	central := Consumer{ID: "central", Stream: "audit", Delivery: Required}
	f.SaveCursor(ctx, Cursor{"central", "audit", 3})
	b, err := ComputeBoundary(ctx, f, f, []Consumer{central, siem}, "audit", ClassAudit, f.now)
	if err != nil || b.Through() != 3 {
		t.Fatalf("boundary %v %v, want the required cursor 3", b, err)
	}
}

// C5-A3-3: no receipt, no act, whatever the reason.
func TestAuditBeforeAct(t *testing.T) {
	ctx := context.Background()
	rec := auditRecords(1)[0]
	cases := map[string]func() (*Log, context.Context){
		"log stopped": func() (*Log, context.Context) {
			f := auditFake()
			l, _ := NewLog(f, f.node, DefaultGroup, nil)
			f.fail["CommitBatch"] = errInjected
			l.AppendBatch(ctx, auditRecords(1))
			delete(f.fail, "CommitBatch")
			return l, ctx
		},
		"quota reached": func() (*Log, context.Context) {
			f := auditFake()
			f.quotaFull["audit"] = true
			l, _ := NewLog(f, f.node, DefaultGroup, nil)
			return l, ctx
		},
		"audit store not open": func() (*Log, context.Context) { return nil, ctx },
		"cancelled": func() (*Log, context.Context) {
			f := auditFake()
			l, _ := NewLog(f, f.node, GroupOptions{MaxEvents: 100, MaxWait: time.Second}, nil)
			c, cancel := context.WithCancel(ctx)
			cancel()
			return l, c
		},
	}
	for name, setup := range cases {
		l, c := setup()
		ran := false
		err := AuditBeforeAct(c, l, rec, func(Receipt) error { ran = true; return nil })
		if ran || !isCode(err, CodeAuditUnavailable) {
			t.Errorf("%s: ran %v err %v", name, ran, err)
		}
	}

	f := auditFake()
	l, _ := NewLog(f, f.node, GroupOptions{MaxEvents: 2, MaxWait: time.Millisecond}, nil)
	var got Receipt
	if err := AuditBeforeAct(ctx, l, rec, func(r Receipt) error { got = r; return nil }); err != nil || got == nil || got.Key().Seq != 1 {
		t.Fatalf("err %v receipt %v", err, got)
	}
	if err := AuditBeforeAct(ctx, l, Record{Stream: "s", Class: ClassPlatform, Event: []byte("e")}, func(Receipt) error { return nil }); !isCode(err, CodeInvalid) {
		t.Fatalf("non-audit record: %v", err)
	}
}

// A quota refusal on one stream leaves the Log running for the others.
func TestQuotaRefusalDoesNotStopTheLog(t *testing.T) {
	f := newFake()
	f.quotaFull["full"] = true
	l, _ := NewLog(f, f.node, DefaultGroup, nil)
	ctx := context.Background()
	if _, err := l.AppendBatch(ctx, []Record{{Stream: "full", Class: ClassSyslogStream, Event: []byte("e")}}); !isCode(err, CodeQuotaReached) {
		t.Fatalf("err %v", err)
	}
	if _, err := l.AppendBatch(ctx, []Record{{Stream: "ok", Class: ClassAdapterEvidence, Event: []byte("e")}}); err != nil || l.Stopped() != nil {
		t.Fatalf("err %v stopped %v", err, l.Stopped())
	}
}
