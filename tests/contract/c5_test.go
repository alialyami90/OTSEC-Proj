package contract

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"otsec.local/otsec/contracts/store"
)

// C5 otsec.store/0.1: A1 D1-11 (audit before act) with A6's own Committer.
// Expected behaviour comes from the AuditBeforeAct and Committer doc text:
// with the audit store full, no privileged act runs (so no ACC is sent),
// the Log keeps running, and other streams, such as received Syslog, still
// commit. Ground truth: GT-HAND from contract prose; independent of A5's
// fake_test.go.

const (
	c5Audit  store.StreamID = "node/audit"
	c5Syslog store.StreamID = "syslog/received"
)

// c5Committer commits every stream in order, except that the streams in
// refuse fail with refuseErr, having written nothing.
type c5Committer struct {
	mu        sync.Mutex
	next      map[store.StreamID]store.Seq
	refuse    map[store.StreamID]bool
	refuseErr error
	commits   map[store.StreamID]int
}

func (c *c5Committer) CommitBatch(_ context.Context, s store.StreamID, recs []store.Record) (store.Commit, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.refuse[s] {
		return store.Commit{}, c.refuseErr
	}
	if c.next[s] == 0 {
		c.next[s] = 1
	}
	first := c.next[s]
	c.next[s] += store.Seq(len(recs))
	c.commits[s] += len(recs)
	return store.Commit{Node: "site-a6-node-1", Stream: s, FirstSeq: first, Count: len(recs), Sync: store.SyncFull, At: time.Now()}, nil
}

func c5Log(t *testing.T, refuseErr error) (*store.Log, *c5Committer) {
	t.Helper()
	c := &c5Committer{next: map[store.StreamID]store.Seq{}, refuse: map[store.StreamID]bool{c5Audit: true},
		refuseErr: refuseErr, commits: map[store.StreamID]int{}}
	l, err := store.NewLog(c, "site-a6-node-1", map[store.StreamID]store.StreamClass{
		c5Audit: store.ClassAudit, c5Syslog: store.ClassSyslogStream,
	}, store.GroupOptions{MaxEvents: 2, MaxWait: 5 * time.Millisecond}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return l, c
}

func c5AuditRecord() store.Record {
	return store.Record{Stream: c5Audit, Class: store.ClassAudit, Event: c8Pending("collector.request", "")}
}

func TestC5NoACCWithAuditStoreFull(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	l, c := c5Log(t, &store.Error{Code: store.CodeQuotaReached, Detail: "A6: audit class at quota"})
	acc := 0
	err := store.AuditBeforeAct(ctx, l, c5AuditRecord(), func(store.Receipt) error { acc++; return nil })
	if acc != 0 {
		t.Fatal("the act (ACC) ran with the audit store full")
	}
	if !errors.Is(err, &store.Error{Code: store.CodeAuditUnavailable}) {
		t.Errorf("got %v, want audit-unavailable", err)
	}
	if err := l.Stopped(); err != nil {
		t.Errorf("a quota refusal stopped the Log: %v", err)
	}
	// Reception goes on: a received Syslog record still commits.
	r, err := l.Append(ctx, store.Record{Stream: c5Syslog, Class: store.ClassSyslogStream, Event: []byte(`{"a6":"received"}`)})
	if err != nil || r == nil || r.Key().Stream != c5Syslog {
		t.Errorf("Syslog append with the audit store full: %v", err)
	}
	if c.commits[c5Syslog] != 1 || c.commits[c5Audit] != 0 {
		t.Errorf("commits %v", c.commits)
	}
}

func TestC5NoACCAfterCommitFailure(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	l, _ := c5Log(t, errors.New("A6: disk error, durability unknown"))
	acc := 0
	act := func(store.Receipt) error { acc++; return nil }
	if err := store.AuditBeforeAct(ctx, l, c5AuditRecord(), act); !errors.Is(err, &store.Error{Code: store.CodeAuditUnavailable}) {
		t.Errorf("got %v, want audit-unavailable", err)
	}
	if l.Stopped() == nil {
		t.Error("a commit of unknown durability did not stop the Log")
	}
	// Once stopped, nothing more runs until a restart.
	if err := store.AuditBeforeAct(ctx, l, c5AuditRecord(), act); err == nil {
		t.Error("act allowed on a stopped Log")
	}
	if acc != 0 {
		t.Fatalf("the act ran %d times", acc)
	}
	if err := store.AuditBeforeAct(ctx, nil, c5AuditRecord(), act); !errors.Is(err, &store.Error{Code: store.CodeAuditUnavailable}) || acc != 0 {
		t.Errorf("no audit store open: %v", err)
	}
}

func TestC5ActRunsOnlyWithReceipt(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	l, c := c5Log(t, nil)
	c.refuse[c5Audit] = false
	var got store.Receipt
	if err := store.AuditBeforeAct(ctx, l, c5AuditRecord(), func(r store.Receipt) error { got = r; return nil }); err != nil {
		t.Fatal(err)
	}
	if got == nil || got.Key().Stream != c5Audit || got.Key().Seq != 1 {
		t.Errorf("receipt %v", got)
	}
}
