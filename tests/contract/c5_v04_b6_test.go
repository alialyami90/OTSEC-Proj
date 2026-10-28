package contract

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"otsec.local/otsec/contracts/store"
)

// C5 otsec.store/0.4 (B6, P4-B6): the configuration class, holds, the
// syslog-unknown class and the commit cap (D4-9), against the contract's
// own Log with B6's committer. Expected behaviour comes from the 0.4 text
// (docs/phase4/B5-c5-0.4-proposal.md) and the contracts/store doc comments,
// not from B5's v04_test.go. Cases that need the SQLite store (PruneStep
// around holds, a held capture, the class quota's drops, the measured WAL)
// are in B6's review of the store PR, not here.

const (
	c5vNode   store.NodeID   = "site-b6-node-1"
	c5vConfig store.StreamID = "config/asset-1"
	c5vEvid   store.StreamID = "adapter/asset-1"
	c5vSyslog store.StreamID = "syslog/l1"
	c5vUnk    store.StreamID = "syslog-unknown/l1"
	c5vAudit  store.StreamID = "node/audit"
)

// c5vCommitter assigns consecutive seqs and records each commit's records.
// refuse, when set, is returned for the next commit instead, having
// written nothing.
type c5vCommitter struct {
	mu      sync.Mutex
	next    map[store.StreamID]store.Seq
	commits [][]store.Record
	refuse  error
}

func newC5vCommitter() *c5vCommitter {
	return &c5vCommitter{next: map[store.StreamID]store.Seq{}}
}

func (c *c5vCommitter) CommitBatch(_ context.Context, s store.StreamID, recs []store.Record) (store.Commit, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.refuse != nil {
		err := c.refuse
		c.refuse = nil
		return store.Commit{}, err
	}
	if c.next[s] == 0 {
		c.next[s] = 1
	}
	first := c.next[s]
	c.next[s] += store.Seq(len(recs))
	c.commits = append(c.commits, append([]store.Record(nil), recs...))
	return store.Commit{Node: c5vNode, Stream: s, FirstSeq: first, Count: len(recs), Sync: store.SyncFull, At: time.Now()}, nil
}

func (c *c5vCommitter) all() [][]store.Record {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([][]store.Record(nil), c.commits...)
}

// c5vDB is a database of one class and one stream.
func c5vDB(id store.DatabaseID, s store.StreamID, class store.StreamClass, quota, cap int64) store.Database {
	return store.Database{ID: id, Writer: "node", Streams: []store.StreamSpec{{ID: s, Class: class}},
		Classes: []store.StreamClass{class}, Quotas: []store.Quota{{Class: class, Bytes: quota, WarnFraction: 0.8, MaxRecordBytes: cap}}}
}

func c5vLog(t *testing.T, d store.Database, opt store.GroupOptions) (*store.Log, *c5vCommitter) {
	t.Helper()
	c := newC5vCommitter()
	l, err := store.NewLogFor(c, c5vNode, d, opt, nil)
	if err != nil {
		t.Fatal(err)
	}
	return l, c
}

func c5vCapture(b []byte) *store.Capture {
	s := sha256.Sum256(b)
	return &store.Capture{SHA256: hex.EncodeToString(s[:]), Bytes: b}
}

func c5vIs(err error, code store.Code) bool { return errors.Is(err, &store.Error{Code: code}) }

func c5vRef() store.HoldReason {
	return store.HoldReason{Code: store.HoldBaseline, Ref: store.Key{NodeID: c5vNode, Stream: c5vAudit, Seq: 7}}
}

func TestC5v04Identifier(t *testing.T) {
	if store.Identifier != "otsec.store/0.6" {
		t.Errorf("identifier %q", store.Identifier)
	}
}

// The configuration quota needs a record cap in [MinRecordBytes, Bytes];
// any class may set one in that range; 0 is "no cap of its own" elsewhere.
func TestC5v04QuotaRecordCap(t *testing.T) {
	const mib = 1 << 20
	for _, c := range []struct {
		q  store.Quota
		ok bool
	}{
		{store.Quota{Class: store.ClassConfiguration, Bytes: 8 * mib, WarnFraction: 0.8}, false},
		{store.Quota{Class: store.ClassConfiguration, Bytes: 8 * mib, WarnFraction: 0.8, MaxRecordBytes: store.MinRecordBytes - 1}, false},
		{store.Quota{Class: store.ClassConfiguration, Bytes: 8 * mib, WarnFraction: 0.8, MaxRecordBytes: store.MinRecordBytes}, true},
		{store.Quota{Class: store.ClassConfiguration, Bytes: 8 * mib, WarnFraction: 0.8, MaxRecordBytes: 8 * mib}, true},
		{store.Quota{Class: store.ClassConfiguration, Bytes: 8 * mib, WarnFraction: 0.8, MaxRecordBytes: 8*mib + 1}, false},
		{store.Quota{Class: store.ClassSyslogUnknown, Bytes: 8 * mib, WarnFraction: 0.8}, true},
		{store.Quota{Class: store.ClassAdapterEvidence, Bytes: 64 * mib, WarnFraction: 0.8, MaxRecordBytes: 10 * mib}, true},
		{store.Quota{Class: store.ClassAdapterEvidence, Bytes: 64 * mib, WarnFraction: 0.8, MaxRecordBytes: 1024}, false},
	} {
		if err := c.q.Validate(); (err == nil) != c.ok {
			t.Errorf("%+v: %v, want ok=%v", c.q, err, c.ok)
		}
	}
	if store.MinRecordBytes != 64<<10 {
		t.Errorf("MinRecordBytes %d, the text says 64 KiB", store.MinRecordBytes)
	}
}

// The two new classes exist, with the at-quota actions the text gives:
// configuration stops reads, syslog-unknown drops and counts.
func TestC5v04Classes(t *testing.T) {
	have := map[store.StreamClass]bool{}
	for _, c := range store.Classes {
		have[c] = true
	}
	if !have[store.ClassConfiguration] || !have[store.ClassSyslogUnknown] {
		t.Fatalf("classes %v", store.Classes)
	}
	if a, err := store.ActionFor(store.ClassConfiguration); err != nil || a != store.StopCollecting {
		t.Errorf("configuration at quota: %v %v, want StopCollecting", a, err)
	}
	if a, err := store.ActionFor(store.ClassSyslogUnknown); err != nil || a != store.DropAndCount {
		t.Errorf("syslog-unknown at quota: %v %v, want DropAndCount", a, err)
	}
}

// Configuration is alone in its database.
func TestC5v04LayoutKeepsConfigurationAlone(t *testing.T) {
	cfg := c5vDB("config", c5vConfig, store.ClassConfiguration, 8<<20, 512<<10)
	audit := c5vDB("audit", c5vAudit, store.ClassAudit, 8<<20, 0)
	ok := store.Layout{Databases: []store.Database{audit, cfg, c5vDB("unknown", c5vUnk, store.ClassSyslogUnknown, 8<<20, 0)}}
	if err := ok.Validate(); err != nil {
		t.Fatalf("configuration alone: %v", err)
	}
	mixed := cfg
	mixed.Streams = append(append([]store.StreamSpec(nil), cfg.Streams...), store.StreamSpec{ID: c5vEvid, Class: store.ClassAdapterEvidence})
	mixed.Classes = append(append([]store.StreamClass(nil), cfg.Classes...), store.ClassAdapterEvidence)
	mixed.Quotas = append(append([]store.Quota(nil), cfg.Quotas...), store.Quota{Class: store.ClassAdapterEvidence, Bytes: 8 << 20, WarnFraction: 0.8})
	err := (store.Layout{Databases: []store.Database{audit, mixed}}).Validate()
	if !c5vIs(err, store.CodeInvalid) || !strings.Contains(err.Error(), "mixes configuration") {
		t.Errorf("configuration mixed with adapter-evidence: %v", err)
	}
}

// NewLog cannot know a configuration stream's cap, so it refuses one;
// NewLogFor takes it from the database's quota.
func TestC5v04ConfigurationNeedsNewLogFor(t *testing.T) {
	_, err := store.NewLog(newC5vCommitter(), c5vNode, map[store.StreamID]store.StreamClass{c5vConfig: store.ClassConfiguration},
		store.GroupOptions{MaxEvents: 4, MaxWait: time.Millisecond}, nil)
	if !c5vIs(err, store.CodeInvalid) {
		t.Errorf("NewLog with a configuration stream: %v", err)
	}
	bad := c5vDB("config", c5vConfig, store.ClassConfiguration, 8<<20, 0)
	if _, err := store.NewLogFor(newC5vCommitter(), c5vNode, bad, store.GroupOptions{MaxEvents: 4, MaxWait: time.Millisecond}, nil); err == nil {
		t.Error("NewLogFor took a configuration quota with no record cap")
	}
}

// A record over its class's cap is refused before it is queued: the
// committer never sees it, nothing is stored, and the Log keeps running.
// A record at the cap, event plus capture, commits.
func TestC5v04RecordCapRefusesBeforeQueue(t *testing.T) {
	const capB = store.MinRecordBytes
	l, c := c5vLog(t, c5vDB("config", c5vConfig, store.ClassConfiguration, 8<<20, capB), store.GroupOptions{MaxEvents: 8, MaxWait: time.Millisecond})
	ctx := context.Background()
	doc := []byte(strings.Repeat("d", 1000))
	over := store.Record{Stream: c5vConfig, Class: store.ClassConfiguration, Event: doc, Capture: c5vCapture(make([]byte, capB-len(doc)+1))}
	if _, err := l.Append(ctx, over); !c5vIs(err, store.CodeRecordTooLarge) {
		t.Fatalf("a record one byte over the cap: %v", err)
	}
	if _, err := l.AppendBatch(ctx, []store.Record{over}); !c5vIs(err, store.CodeRecordTooLarge) {
		t.Fatalf("a batch of one record one byte over the cap: %v", err)
	}
	if n := len(c.all()); n != 0 {
		t.Fatalf("%d commits reached the store for refused records", n)
	}
	at := over
	at.Capture = c5vCapture(make([]byte, capB-len(doc)))
	r, err := l.Append(ctx, at)
	if err != nil || r.Key().Seq != 1 {
		t.Fatalf("a record at the cap: %v %v", r, err)
	}
	if l.Stopped() != nil {
		t.Errorf("Log stopped: %v", l.Stopped())
	}
}

// In a class with no cap of its own, MaxCommitBytes is the record bound.
func TestC5v04UncappedClassUsesCommitCap(t *testing.T) {
	opt := store.GroupOptions{MaxEvents: 8, MaxWait: time.Millisecond, MaxCommitBytes: store.MinRecordBytes}
	l, c := c5vLog(t, c5vDB("syslog", c5vSyslog, store.ClassSyslogStream, 8<<20, 0), opt)
	ctx := context.Background()
	if _, err := l.Append(ctx, store.Record{Stream: c5vSyslog, Class: store.ClassSyslogStream, Event: make([]byte, store.MinRecordBytes+1)}); !c5vIs(err, store.CodeRecordTooLarge) {
		t.Fatalf("a record over the commit cap in an uncapped class: %v", err)
	}
	if _, err := l.Append(ctx, store.Record{Stream: c5vSyslog, Class: store.ClassSyslogStream, Event: make([]byte, store.MinRecordBytes)}); err != nil {
		t.Fatalf("a record at the commit cap: %v", err)
	}
	if n := len(c.all()); n != 1 {
		t.Errorf("%d commits, want 1", n)
	}
}

// D4-9 condition 2: a record over MaxCommitBytes that its class's cap
// allows commits alone, never refused for the commit cap.
func TestC5v04BigRecordCommitsAlone(t *testing.T) {
	opt := store.GroupOptions{MaxEvents: 100, MaxWait: 50 * time.Millisecond, MaxCommitBytes: store.MinRecordBytes}
	l, c := c5vLog(t, c5vDB("evidence", c5vEvid, store.ClassAdapterEvidence, 64<<20, 4*store.MinRecordBytes), opt)
	ctx := context.Background()
	var wg sync.WaitGroup
	sizes := []int{100, 3 * store.MinRecordBytes, 100}
	for _, n := range sizes {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			if _, err := l.Append(ctx, store.Record{Stream: c5vEvid, Class: store.ClassAdapterEvidence, Event: make([]byte, n)}); err != nil {
				t.Errorf("append of %d bytes: %v", n, err)
			}
		}(n)
		time.Sleep(5 * time.Millisecond)
	}
	wg.Wait()
	for _, g := range c.all() {
		var sum int64
		for _, r := range g {
			sum += r.Bytes()
		}
		if sum > opt.CommitBytes() && len(g) != 1 {
			t.Errorf("a commit of %d records and %d bytes, over the cap with company", len(g), sum)
		}
	}
}

// Appends group, but a group commits before a record would take it past
// MaxCommitBytes; seqs stay consecutive and in append order.
func TestC5v04GroupsStayUnderCommitCap(t *testing.T) {
	opt := store.GroupOptions{MaxEvents: 1000, MaxWait: 200 * time.Millisecond, MaxCommitBytes: store.MinRecordBytes}
	l, c := c5vLog(t, c5vDB("syslog", c5vSyslog, store.ClassSyslogStream, 64<<20, 0), opt)
	ctx := context.Background()
	const n, size = 40, 10 << 10
	keys := make([]store.Seq, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		ev := make([]byte, size)
		ev[0] = byte(i)
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			r, err := l.Append(ctx, store.Record{Stream: c5vSyslog, Class: store.ClassSyslogStream, Event: ev})
			if err != nil {
				t.Errorf("append %d: %v", i, err)
				return
			}
			keys[i] = r.Key().Seq
		}(i)
		time.Sleep(time.Millisecond)
	}
	wg.Wait()
	groups := c.all()
	var seq store.Seq
	for _, g := range groups {
		var sum int64
		for _, r := range g {
			sum += r.Bytes()
			seq++
			if keys[r.Event[0]] != seq {
				t.Errorf("record %d has seq %d, committed at position %d", r.Event[0], keys[r.Event[0]], seq)
			}
		}
		if sum > opt.CommitBytes() {
			t.Errorf("a group of %d records and %d bytes, over the %d cap", len(g), sum, opt.CommitBytes())
		}
	}
	if seq != n || len(groups) < n*size/int(opt.CommitBytes()) {
		t.Errorf("%d records in %d groups", seq, len(groups))
	}
}

// AppendBatch stays atomic: more than one record over MaxCommitBytes is
// refused whole, nothing queued; a capture shared by the batch counts once.
func TestC5v04BatchOverCommitCapRefusedWhole(t *testing.T) {
	opt := store.GroupOptions{MaxEvents: 8, MaxWait: time.Millisecond, MaxCommitBytes: store.MinRecordBytes}
	l, c := c5vLog(t, c5vDB("evidence", c5vEvid, store.ClassAdapterEvidence, 64<<20, 0), opt)
	ctx := context.Background()
	half := store.MinRecordBytes/2 + 1
	two := []store.Record{
		{Stream: c5vEvid, Class: store.ClassAdapterEvidence, Event: make([]byte, half)},
		{Stream: c5vEvid, Class: store.ClassAdapterEvidence, Event: make([]byte, half)},
	}
	if _, err := l.AppendBatch(ctx, two); !c5vIs(err, store.CodeRecordTooLarge) {
		t.Fatalf("a two-record batch over the cap: %v", err)
	}
	if n := len(c.all()); n != 0 {
		t.Fatalf("%d commits for a refused batch", n)
	}
	// Three records of 1 KiB sharing a 60 KiB capture: 63 KiB counted once,
	// 183 KiB if the capture were counted per record.
	cp := c5vCapture(make([]byte, 60<<10))
	shared := make([]store.Record, 3)
	for i := range shared {
		shared[i] = store.Record{Stream: c5vEvid, Class: store.ClassAdapterEvidence, Event: make([]byte, 1<<10), Capture: cp}
	}
	rs, err := l.AppendBatch(ctx, shared)
	if err != nil || len(rs) != 3 || rs[0].Key().Seq != 1 || rs[2].Key().Seq != 3 {
		t.Fatalf("a batch sharing one capture: %v %v", rs, err)
	}
	if g := c.all(); len(g) != 1 || len(g[0]) != 3 {
		t.Errorf("the shared-capture batch committed as %d groups", len(g))
	}
}

// One configuration record per commit: concurrent appends never share a
// commit, and a batch of two is refused with nothing queued.
func TestC5v04OneConfigurationRecordPerCommit(t *testing.T) {
	l, c := c5vLog(t, c5vDB("config", c5vConfig, store.ClassConfiguration, 8<<20, 512<<10),
		store.GroupOptions{MaxEvents: 100, MaxWait: 100 * time.Millisecond})
	ctx := context.Background()
	rec := store.Record{Stream: c5vConfig, Class: store.ClassConfiguration, Event: []byte(`{"kind":"config.snapshot"}`)}
	if _, err := l.AppendBatch(ctx, []store.Record{rec, rec}); err == nil {
		t.Fatal("a configuration batch of two records was accepted")
	}
	if n := len(c.all()); n != 0 {
		t.Fatalf("%d commits for a refused configuration batch", n)
	}
	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := l.Append(ctx, rec); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	for _, g := range c.all() {
		if len(g) != 1 {
			t.Errorf("a configuration commit of %d records", len(g))
		}
	}
	if n := len(c.all()); n != 6 {
		t.Errorf("%d commits for 6 records", n)
	}
}

// Only configuration records may take holds; a hold elsewhere is refused
// with CodeNotHoldable before it reaches the store.
func TestC5v04HoldsOnlyOnConfiguration(t *testing.T) {
	l, c := c5vLog(t, c5vDB("evidence", c5vEvid, store.ClassAdapterEvidence, 64<<20, 0), store.GroupOptions{MaxEvents: 8, MaxWait: time.Millisecond})
	ctx := context.Background()
	held := store.Record{Stream: c5vEvid, Class: store.ClassAdapterEvidence, Event: []byte("e"), Holds: []store.Hold{{Reason: c5vRef()}}}
	if _, err := l.Append(ctx, held); !c5vIs(err, store.CodeNotHoldable) {
		t.Fatalf("a hold on an adapter-evidence record: %v", err)
	}
	if n := len(c.all()); n != 0 {
		t.Fatalf("%d commits for a refused hold", n)
	}
	cl, cc := c5vLog(t, c5vDB("config", c5vConfig, store.ClassConfiguration, 8<<20, 512<<10), store.GroupOptions{MaxEvents: 8, MaxWait: time.Millisecond})
	ok := store.Record{Stream: c5vConfig, Class: store.ClassConfiguration, Event: []byte("{}"), Holds: []store.Hold{{Reason: c5vRef()}}}
	if _, err := cl.Append(ctx, ok); err != nil {
		t.Fatalf("a hold on a configuration record: %v", err)
	}
	if g := cc.all(); len(g) != 1 || len(g[0][0].Holds) != 1 {
		t.Errorf("the hold did not reach the store with its record: %+v", g)
	}
}

// A hold reason names a C8 record and a closed code; never free text.
func TestC5v04HoldReason(t *testing.T) {
	good := c5vRef()
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, r := range map[string]store.HoldReason{
		"unknown code": {Code: "because", Ref: good.Ref},
		"no node":      {Code: store.HoldBaseline, Ref: store.Key{Stream: c5vAudit, Seq: 1}},
		"no stream":    {Code: store.HoldUnapprovedDifference, Ref: store.Key{NodeID: c5vNode, Seq: 1}},
		"seq 0":        {Code: store.HoldBaseline, Ref: store.Key{NodeID: c5vNode, Stream: c5vAudit}},
	} {
		if err := r.Validate(); !c5vIs(err, store.CodeInvalid) {
			t.Errorf("%s: %v", name, err)
		}
		rec := store.Record{Stream: c5vConfig, Class: store.ClassConfiguration, Event: []byte("{}"), Holds: []store.Hold{{Reason: r}}}
		if err := rec.Validate(); err == nil {
			t.Errorf("%s: a record with this hold validates", name)
		}
	}
	rec := store.Record{Stream: c5vConfig, Class: store.ClassConfiguration, Event: []byte("{}"), Holds: []store.Hold{{Stream: "Not A Stream", Seq: 1, Reason: good}}}
	if err := rec.Validate(); err == nil {
		t.Error("a hold naming an invalid stream validates")
	}
}

// The store's 0.4 refusals wrote nothing: the Log fails that batch and
// keeps running, as it does for quota-reached (Committer's doc).
func TestC5v04StoreRefusalsKeepTheLogRunning(t *testing.T) {
	for _, code := range []store.Code{store.CodeRecordTooLarge, store.CodeNotHoldable} {
		l, c := c5vLog(t, c5vDB("config", c5vConfig, store.ClassConfiguration, 8<<20, 512<<10), store.GroupOptions{MaxEvents: 8, MaxWait: time.Millisecond})
		ctx := context.Background()
		rec := store.Record{Stream: c5vConfig, Class: store.ClassConfiguration, Event: []byte("{}")}
		c.refuse = &store.Error{Code: code}
		if _, err := l.Append(ctx, rec); !c5vIs(err, code) {
			t.Errorf("%s: the append got %v", code, err)
		}
		if err := l.Stopped(); err != nil {
			t.Errorf("%s from the store stopped the Log: %v", code, err)
			continue
		}
		if r, err := l.Append(ctx, rec); err != nil || r.Key().Seq != 1 {
			t.Errorf("%s: the next append: %v %v", code, r, err)
		}
	}
}

// LargestCommit is the commit cap or the largest class cap, whichever is
// more; the reserve covers it.
func TestC5v04LargestCommit(t *testing.T) {
	cfg := c5vDB("config", c5vConfig, store.ClassConfiguration, 8<<20, 512<<10)
	if n := store.LargestCommit(cfg, store.GroupOptions{MaxCommitBytes: 512 << 10}); n != 512<<10 {
		t.Errorf("configuration at 512 KiB: %d", n)
	}
	ev := c5vDB("evidence", c5vEvid, store.ClassAdapterEvidence, 64<<20, 10<<20)
	if n := store.LargestCommit(ev, store.GroupOptions{}); n != 10<<20 {
		t.Errorf("a 10 MiB record cap over the default commit cap: %d", n)
	}
	sys := c5vDB("syslog", c5vSyslog, store.ClassSyslogStream, 64<<20, 0)
	if n := store.LargestCommit(sys, store.GroupOptions{}); n != 1<<20 || store.DefaultMaxCommitBytes != 1<<20 {
		t.Errorf("an event database with no class cap: %d, want the 1 MiB default", n)
	}
}

// The WAL rule against independent measurements: B6's own, SQLite through
// Python with another schema, 4 KiB pages, WAL, one record per commit after
// a TRUNCATE checkpoint (on #246, 6450668075), and the fixed-cost shape it
// gives at MinRecordBytes. Evidence class: desk.
func TestC5v04CommitWALCoversMeasured(t *testing.T) {
	for payload, measured := range map[int64]int64{
		128 << 10: 152472,
		256 << 10: 284312,
		512 << 10: 547992,
		768 << 10: 811672,
		// fixed about 34 KB plus 1.0 × payload, the shape of the rows above
		store.MinRecordBytes: 34<<10 + store.MinRecordBytes,
	} {
		if w := store.CommitWALBytes(payload, 1); w < measured {
			t.Errorf("payload %d: rule %d below measured %d", payload, w, measured)
		}
	}
	if w := store.CommitWALBytes(1<<20, 1); w != 1<<20+(1<<20)/10+64<<10+store.RowWALBytes {
		t.Errorf("CommitWALBytes(1 MiB) = %d, the text says 1.1 × C + 64 KiB", w)
	}
	if r := store.RecoveryReserveFor(512<<10, 1<<20, 1); r != 2*(512<<10)+store.CommitWALBytes(1<<20, 1) {
		t.Errorf("RecoveryReserveFor = %d, the text says 2 × WAL bound + W(C)", r)
	}
}

// The start-up policy refuses a reserve below the 0.4 rule, at the
// smallest cap too, and a half-set rule.
func TestC5v04StartupReserve(t *testing.T) {
	base := store.StartupPolicy{
		Streams:                []store.StreamSpec{{ID: c5vConfig, Class: store.ClassConfiguration}},
		Consumers:              []store.Consumer{{ID: "forward", Stream: c5vConfig, Delivery: store.Required}},
		LastResortReserveBytes: 128 << 10, OpenHeadroomBytes: 128 << 10,
		PruneStepEvents: 50, CompactStepPages: 32, PruneTarget: 0.8,
	}
	const wal = 512 << 10
	for _, largest := range []int64{store.MinRecordBytes, 512 << 10, 1 << 20, 10 << 20} {
		need := store.RecoveryReserveFor(wal, largest, 1)
		p := base
		p.WALBoundBytes, p.LargestCommitBytes, p.LargestCommitRecords = wal, largest, 1
		p.RecoveryReserveBytes = need
		if err := p.Validate(); err != nil {
			t.Errorf("largest %d at exactly the rule's %d: %v", largest, need, err)
		}
		p.RecoveryReserveBytes = need - 1
		if err := p.Validate(); !c5vIs(err, store.CodeInvalid) {
			t.Errorf("largest %d one byte below the rule: %v", largest, err)
		}
		p.RecoveryReserveBytes = 2 * wal // the 0.3 floor, short by W(C)
		if err := p.Validate(); !c5vIs(err, store.CodeInvalid) {
			t.Errorf("largest %d at the 0.3 floor: %v", largest, err)
		}
	}
	p := base
	p.RecoveryReserveBytes, p.WALBoundBytes = 1<<30, wal
	if err := p.Validate(); !c5vIs(err, store.CodeInvalid) {
		t.Errorf("a WAL bound with no largest commit: %v", err)
	}
	p.WALBoundBytes, p.LargestCommitBytes, p.LargestCommitRecords = 0, 1<<20, 1
	if err := p.Validate(); !c5vIs(err, store.CodeInvalid) {
		t.Errorf("a largest commit with no WAL bound: %v", err)
	}
}

// The 0.4 alarm codes exist with the names the text gives.
func TestC5v04Alarms(t *testing.T) {
	if store.AlarmSyslogUnknownFull != "syslog-unknown-full" || store.AlarmHoldsReconciled != "store-holds-reconciled" {
		t.Errorf("alarm codes %q %q", store.AlarmSyslogUnknownFull, store.AlarmHoldsReconciled)
	}
	if store.CodeRecordTooLarge != "record-too-large" || store.CodeNotHoldable != "not-holdable" {
		t.Errorf("error codes %q %q", store.CodeRecordTooLarge, store.CodeNotHoldable)
	}
}
