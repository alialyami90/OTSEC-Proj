package store

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"otsec.local/otsec/contracts/audit"
)

// pendingAudit builds a pending C8 record for the fake's node.
func pendingAudit(action, extra string) []byte {
	return fmt.Appendf(nil, `{"contract":"otsec.audit/0.1","node_id":"site-a-node1",`+
		`"time":{"utc":"2026-10-24T12:00:00.000001Z","resolution_ns":1000,"clock":{"sync":"synchronized","source":"ntp"}},`+
		`"actor":{"type":"system","id":"node"},"action":%q,"outcome":"info"%s}`, action, extra)
}

// verifyChain checks the retained records with C8's own verifier, from anchor.
func verifyChain(retained []Stored, anchor ChainLink) error {
	stored := make([][]byte, len(retained))
	for i, r := range retained {
		stored[i] = r.Event
	}
	return audit.VerifyChain(anchor.NodeID, stored, &anchor, nil)
}

// auditRecords returns n pending store.mode_change records.
func auditRecords(n int) []Record {
	recs := make([]Record, n)
	for i := range recs {
		recs[i] = Record{Stream: "audit", Class: ClassAudit,
			Event: pendingAudit("store.mode_change", fmt.Sprintf(`,"reason_code":"collecting","detail":"op-%d"`, i))}
	}
	return recs
}

// auditFake returns a fake whose audit chain already holds its
// audit.chain.start record at seq 1, sealed as a Committer would.
func auditFake() *fake {
	f := newFake()
	f.sealAudit = true
	if _, err := f.CommitBatch(context.Background(), "audit", []Record{{Stream: "audit", Class: ClassAudit, Event: pendingAudit("audit.chain.start", "")}}); err != nil {
		panic(err)
	}
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
	l, err := NewLog(f, f.node, testStreams, GroupOptions{MaxEvents: 2, MaxWait: time.Millisecond}, nil)
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
	if len(got) != 5 {
		t.Fatalf("%d records", len(got))
	}
	if err := verifyChain(got, GenesisLink(f.node)); err != nil {
		t.Fatal(err)
	}
	if f.heads["audit"] != (ChainLink{NodeID: string(f.node), Seq: 5, Hash: audit.Hash(got[4].Event)}) {
		t.Fatalf("head %+v", f.heads["audit"])
	}
}

// A batch with one bad pending record is refused whole, nothing is written,
// and the Log keeps running.
func TestAuditBadPendingRefusesBatch(t *testing.T) {
	f := auditFake()
	l, _ := NewLog(f, f.node, testStreams, DefaultGroup, nil)
	recs := auditRecords(3)
	recs[1].Event = pendingAudit("store.mode_change", `,"reason_code":"collecting","password":"x"`)
	if _, err := l.AppendBatch(context.Background(), recs); !isCode(err, CodeInvalid) {
		t.Fatalf("err %v", err)
	}
	if len(f.events["audit"]) != 1 || l.Stopped() != nil {
		t.Fatalf("%d written, stopped %v", len(f.events["audit"]), l.Stopped())
	}
	if _, err := l.AppendBatch(context.Background(), auditRecords(2)); err != nil {
		t.Fatal(err)
	}
	if err := verifyChain(readAll(t, f, "audit"), GenesisLink(f.node)); err != nil {
		t.Fatal(err)
	}
}

// C5-A3-2(a): an interrupted audit prune leaves an anchor the retained chain
// verifies from, and so does the resumed prune.
func TestAuditPruneKeepsAnchor(t *testing.T) {
	f := auditFake()
	l, _ := NewLog(f, f.node, testStreams, DefaultGroup, nil)
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
	f := newFake()
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
			l, _ := NewLog(f, f.node, testStreams, DefaultGroup, nil)
			f.fail["CommitBatch"] = errInjected
			l.AppendBatch(ctx, auditRecords(1))
			delete(f.fail, "CommitBatch")
			return l, ctx
		},
		"quota reached": func() (*Log, context.Context) {
			f := auditFake()
			f.quotaFull["audit"] = true
			l, _ := NewLog(f, f.node, testStreams, DefaultGroup, nil)
			return l, ctx
		},
		"audit store not open": func() (*Log, context.Context) { return nil, ctx },
		"cancelled": func() (*Log, context.Context) {
			f := auditFake()
			l, _ := NewLog(f, f.node, testStreams, GroupOptions{MaxEvents: 100, MaxWait: time.Second}, nil)
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
	l, _ := NewLog(f, f.node, testStreams, GroupOptions{MaxEvents: 2, MaxWait: time.Millisecond}, nil)
	var got Receipt
	if err := AuditBeforeAct(ctx, l, rec, func(r Receipt) error { got = r; return nil }); err != nil || got == nil || got.Key().Seq != 2 {
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
	l, _ := NewLog(f, f.node, testStreams, DefaultGroup, nil)
	ctx := context.Background()
	if _, err := l.AppendBatch(ctx, []Record{{Stream: "full", Class: ClassSyslogStream, Event: []byte("e")}}); !isCode(err, CodeQuotaReached) {
		t.Fatalf("err %v", err)
	}
	if _, err := l.AppendBatch(ctx, []Record{{Stream: "ok", Class: ClassAdapterEvidence, Event: []byte("e")}}); err != nil || l.Stopped() != nil {
		t.Fatalf("err %v stopped %v", err, l.Stopped())
	}
}

// SealAudit refuses a record for another node and a second chain start,
// before anything is sealed.
func TestSealAuditRefusesWrongNodeAndRestart(t *testing.T) {
	head := GenesisLink("site-a-node1")
	start := Record{Stream: "audit", Class: ClassAudit, Event: pendingAudit("audit.chain.start", "")}
	_, head, err := SealAudit(head, []Record{start})
	if err != nil {
		t.Fatal(err)
	}
	other := Record{Stream: "audit", Class: ClassAudit, Event: []byte(strings.Replace(string(auditRecords(1)[0].Event), "site-a-node1", "site-b-node1", 1))}
	if _, h, err := SealAudit(head, []Record{other}); !isCode(err, CodeInvalid) || h != head {
		t.Fatalf("other node: %v", err)
	}
	if _, h, err := SealAudit(head, []Record{start}); !isCode(err, CodeInvalid) || h != head {
		t.Fatalf("second chain start: %v", err)
	}
}
