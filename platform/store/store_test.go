package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"otsec.local/otsec/contracts/audit"
	"otsec.local/otsec/contracts/event"
	c5 "otsec.local/otsec/contracts/store"
)

var bg = context.Background()

// Receipts carry consecutive seqs, the stored event carries its seq and
// passes C4 Decode, and every byte outside "id" is the producer's.
func TestCommitAssignsSeq(t *testing.T) {
	db := open1(t, storeDir(t), evidenceDB, nil)
	l := testLog(t, db)
	rs, err := l.AppendBatch(bg, recs("relay1/ser", c5.ClassAdapterEvidence, 0, 3))
	if err != nil {
		t.Fatal(err)
	}
	r, err := l.Append(bg, rec("relay1/ser", c5.ClassAdapterEvidence, 3))
	if err != nil {
		t.Fatal(err)
	}
	rs = append(rs, r)
	got, err := db.Read(bg, "relay1/ser", 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 {
		t.Fatalf("%d events", len(got))
	}
	for i, s := range got {
		want := c5.Key{NodeID: testNode, Stream: "relay1/ser", Seq: c5.Seq(i + 1)}
		if s.Key != want || rs[i].Key() != want {
			t.Fatalf("event %d: stored %v receipt %v", i, s.Key, rs[i].Key())
		}
		e, err := event.Decode(s.Event)
		if err != nil || e.ID != want {
			t.Fatalf("event %d does not decode with its ID: %v", i, err)
		}
		orig := pending("relay1/ser", i)
		if !bytes.Equal(withoutID(t, s.Event), withoutID(t, orig)) {
			t.Fatalf("event %d changed outside id:\n%s\n%s", i, s.Event, orig)
		}
		if !s.CommittedAt.Equal(rs[i].CommittedAt()) {
			t.Fatalf("event %d committed at %v, receipt says %v", i, s.CommittedAt, rs[i].CommittedAt())
		}
	}
}

func withoutID(t *testing.T, b []byte) []byte {
	t.Helper()
	out, err := replaceMember(b, "id", []byte("null"))
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// Seqs continue across a restart, and a stream's class is kept for life.
func TestReopenContinuesSeq(t *testing.T) {
	dir := storeDir(t)
	opt := Options{Dir: dir, Node: testNode, Database: evidenceDB}
	db, r := testStore(t, opt, policy(evidenceDB), c5.ModeCollecting)
	if _, err := testLog(t, db).AppendBatch(bg, recs("syslog/relay1", c5.ClassSyslogStream, 0, 5)); err != nil {
		t.Fatal(err)
	}
	db.Close()
	r.Unlock()

	db, r = testStore(t, opt, policy(evidenceDB), c5.ModeCollecting)
	rs, err := testLog(t, db).AppendBatch(bg, recs("syslog/relay1", c5.ClassSyslogStream, 5, 1))
	if err != nil || rs[0].Key().Seq != 6 {
		t.Fatalf("after restart: %v %v", rs, err)
	}
	db.Close()
	r.Unlock()

	changed := evidenceDB
	changed.Streams = []c5.StreamSpec{{ID: "relay1/ser", Class: c5.ClassAdapterEvidence}, {ID: "syslog/relay1", Class: c5.ClassPlatform}, {ID: "platform/health", Class: c5.ClassPlatform}}
	env, _ := NewEnv(Options{Dir: dir, Node: testNode, Database: changed})
	rep := c5.RunStartup(bg, env, policy(changed))
	if rep.Mode != c5.ModeFailed || rep.Steps[len(rep.Steps)-1].Step != c5.StepOpen {
		t.Fatalf("class change: %s %v", rep.Mode, rep.Steps)
	}
	unlock(rep)
}

// A refusal writes nothing and leaves the Log running; the next batch gets
// the next seq.
func TestRefusalsWriteNothing(t *testing.T) {
	db := open1(t, storeDir(t), evidenceDB, nil)
	l := testLog(t, db)
	other := pending("relay1/ser", 0)
	other = bytes.Replace(other, []byte(`"site-a-node1"`), []byte(`"site-b-node1"`), 1)
	cases := map[string][]byte{
		"not json":       []byte("e"),
		"not c4":         []byte(`{"schema":"otsec.event/0.1"}`),
		"seq set":        bytes.Replace(pending("relay1/ser", 0), []byte(`"seq":0`), []byte(`"seq":7`), 1),
		"other stream":   pending("platform/health", 0),
		"other node":     other,
		"later minor":    bytes.Replace(pending("relay1/ser", 0), []byte(`otsec.event/0.1`), []byte(`otsec.event/0.9`), 1),
		"duplicate id":   bytes.Replace(pending("relay1/ser", 0), []byte(`"origin":`), []byte(`"id":{"node_id":"site-a-node1","stream":"relay1/ser","seq":0},"origin":`), 1),
		"trailing bytes": append(pending("relay1/ser", 0), []byte(" {}")...),
	}
	for name, ev := range cases {
		_, err := l.Append(bg, c5.Record{Stream: "relay1/ser", Class: c5.ClassAdapterEvidence, Event: ev})
		if !isCode(err, c5.CodeInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if l.Stopped() != nil {
		t.Fatal(l.Stopped())
	}
	r, err := l.Append(bg, rec("relay1/ser", c5.ClassAdapterEvidence, 0))
	if err != nil || r.Key().Seq != 1 {
		t.Fatalf("after refusals: %v %v", r, err)
	}
	if n, _ := db.LastCommitted(bg, "relay1/ser"); n != 1 {
		t.Fatalf("last %d", n)
	}
}

// A class at quota is refused with quota-reached and an alarm; other
// classes still commit (ADR-0004 item 9).
func TestQuotaPerClass(t *testing.T) {
	var a alarms
	d := withQuota(evidenceDB, c5.ClassSyslogStream, 2000)
	db := open1(t, storeDir(t), d, &a)
	l := testLog(t, db)
	var err error
	n := 0
	for ; err == nil && n < 100; n++ {
		_, err = l.Append(bg, rec("syslog/relay1", c5.ClassSyslogStream, n))
	}
	if !isCode(err, c5.CodeQuotaReached) || n < 2 {
		t.Fatalf("after %d: %v", n, err)
	}
	if !a.has(c5.AlarmQuotaWarning) || !a.has(c5.AlarmQuotaReached) {
		t.Fatalf("alarms %v", a.got)
	}
	used, _ := db.ClassBytes(bg, c5.ClassSyslogStream)
	if used > 2000 {
		t.Fatalf("class holds %d bytes over its 2000 quota", used)
	}
	if _, err := l.Append(bg, rec("relay1/ser", c5.ClassAdapterEvidence, 0)); err != nil || l.Stopped() != nil {
		t.Fatalf("evidence after syslog quota: %v %v", err, l.Stopped())
	}
}

// Audit records are sealed in the commit, chain across batches and
// restarts, and verify with C8's own verifier; pruning keeps an anchor the
// retained chain verifies from (C5-A3-1, C5-A3-2).
func TestAuditChain(t *testing.T) {
	dir := storeDir(t)
	opt := Options{Dir: dir, Node: testNode, Database: auditDB}
	db, r := testStore(t, opt, policy(auditDB), c5.ModeCollecting)
	l := testLog(t, db)
	if _, err := l.Append(bg, auditRec("audit.chain.start", "")); err != nil {
		t.Fatal(err)
	}
	batch := []c5.Record{modeChange(1), modeChange(2), modeChange(3)}
	if _, err := l.AppendBatch(bg, batch); err != nil {
		t.Fatal(err)
	}
	db.Close()
	r.Unlock()

	central := c5.Consumer{ID: "central", Stream: "audit", Delivery: c5.Required}
	db, _ = testStore(t, opt, policy(auditDB, central), c5.ModeCollecting)
	l = testLog(t, db)
	for i := 4; i < 10; i++ {
		if _, err := l.Append(bg, modeChange(i)); err != nil {
			t.Fatal(err)
		}
	}
	verify := func() {
		t.Helper()
		got, err := db.Read(bg, "audit", 0, 100)
		if err != nil {
			t.Fatal(err)
		}
		anchor, err := db.ChainAnchor(bg, "audit")
		if err != nil {
			t.Fatal(err)
		}
		stored := make([][]byte, len(got))
		for i, s := range got {
			stored[i] = s.Event
		}
		if err := audit.VerifyChain(anchor.NodeID, stored, &anchor, nil); err != nil {
			t.Fatalf("chain from %+v: %v", anchor, err)
		}
	}
	verify()
	if err := db.SaveCursor(bg, c5.Cursor{Consumer: "central", Stream: "audit", Through: 7}); err != nil {
		t.Fatal(err)
	}
	for {
		b, err := c5.ComputeBoundary(bg, db, db, []c5.Consumer{central}, "audit", c5.ClassAudit, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		n, err := db.PruneStep(bg, b, 3)
		if err != nil {
			t.Fatal(err)
		}
		verify()
		if n == 0 {
			break
		}
	}
	if a, _ := db.ChainAnchor(bg, "audit"); a.Seq != 7 {
		t.Fatalf("anchor %+v", a)
	}
	if first, _ := db.FirstRetained(bg, "audit"); first != 8 {
		t.Fatalf("first retained %d", first)
	}

	// A bad record refuses its whole batch and the chain stays intact.
	bad := modeChange(10)
	bad.Event = pendingAudit("store.mode_change", `,"reason_code":"collecting","password":"x"`)
	if _, err := l.AppendBatch(bg, []c5.Record{modeChange(11), bad}); !isCode(err, c5.CodeInvalid) || l.Stopped() != nil {
		t.Fatalf("bad audit batch: %v %v", err, l.Stopped())
	}
	if _, err := l.Append(bg, modeChange(12)); err != nil {
		t.Fatal(err)
	}
	verify()
	if _, err := db.ChainAnchor(bg, "nope"); !isCode(err, c5.CodeInvalid) {
		t.Fatalf("anchor of unknown stream: %v", err)
	}
}

func TestChainAnchorRefusesOtherStreams(t *testing.T) {
	db := open1(t, storeDir(t), evidenceDB, nil)
	if _, err := db.ChainAnchor(bg, "relay1/ser"); !isCode(err, c5.CodeInvalid) {
		t.Fatalf("anchor of an evidence stream: %v", err)
	}
}

// Cursors are durable, never move back, never pass the stream, and
// LoadCursors reads the database.
func TestCursors(t *testing.T) {
	dir := storeDir(t)
	opt := Options{Dir: dir, Node: testNode, Database: evidenceDB}
	db, r := testStore(t, opt, policy(evidenceDB), c5.ModeCollecting)
	if _, err := testLog(t, db).AppendBatch(bg, recs("relay1/ser", c5.ClassAdapterEvidence, 0, 5)); err != nil {
		t.Fatal(err)
	}
	c := c5.Cursor{Consumer: "siem", Stream: "relay1/ser", Through: 3}
	if err := db.SaveCursor(bg, c); err != nil {
		t.Fatal(err)
	}
	if err := db.SaveCursor(bg, c5.Cursor{Consumer: "siem", Stream: "relay1/ser", Through: 2}); !isCode(err, c5.CodeCursorRegress) {
		t.Fatalf("regress: %v", err)
	}
	if err := db.SaveCursor(bg, c5.Cursor{Consumer: "siem", Stream: "relay1/ser", Through: 6}); !isCode(err, c5.CodeCursorAhead) {
		t.Fatalf("ahead: %v", err)
	}
	if err := db.SaveCursor(bg, c); err != nil {
		t.Fatalf("same position: %v", err)
	}
	db.Close()
	r.Unlock()
	db, _ = testStore(t, opt, policy(evidenceDB), c5.ModeCollecting)
	got, err := db.LoadCursors(bg, "relay1/ser")
	if err != nil || len(got) != 1 || got[0] != c {
		t.Fatalf("after restart: %v %v", got, err)
	}
	if got, _ := db.LoadCursors(bg, "syslog/relay1"); len(got) != 0 {
		t.Fatalf("other stream: %v", got)
	}
}

// The boundary comes from persisted cursors and replay windows; Read past
// the prune point returns the first retained events; captures go with
// their last record (EP-6).
func TestPruneAndCaptures(t *testing.T) {
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	clock := now.Add(-3 * time.Hour)
	opt := Options{Dir: storeDir(t), Node: testNode, Database: evidenceDB, Now: func() time.Time { return clock }}
	db, _ := testStore(t, opt, policy(evidenceDB), c5.ModeCollecting)
	l := testLog(t, db)
	capA := capture("report A")
	capB := capture("report B")
	batch := recs("relay1/ser", c5.ClassAdapterEvidence, 0, 4)
	for i := range batch {
		batch[i].Capture = &capA
	}
	batch[3].Capture = &capB
	batch[3].SourceCursor = []byte("row 4")
	if _, err := l.AppendBatch(bg, batch); err != nil {
		t.Fatal(err)
	}
	clock = now.Add(-30 * time.Minute)
	more := recs("relay1/ser", c5.ClassAdapterEvidence, 4, 2)
	more[0].Capture = &capB
	if _, err := l.AppendBatch(bg, more); err != nil {
		t.Fatal(err)
	}
	if cur, _ := db.SourceCursor(bg, "relay1/ser"); string(cur) != "row 4" {
		t.Fatalf("source cursor %q", cur)
	}

	central := c5.Consumer{ID: "central", Stream: "relay1/ser", Delivery: c5.Required}
	siem := c5.Consumer{ID: "siem", Stream: "relay1/ser", Delivery: c5.BestEffort, ReplayWindow: time.Hour}
	// The best-effort cursor is ahead, but its window holds events 5 and 6.
	if err := db.SaveCursor(bg, c5.Cursor{Consumer: "siem", Stream: "relay1/ser", Through: 6}); err != nil {
		t.Fatal(err)
	}
	b, err := c5.ComputeBoundary(bg, db, db, []c5.Consumer{central, siem}, "relay1/ser", c5.ClassAdapterEvidence, now)
	if err != nil || b.Through() != 0 {
		t.Fatalf("no required cursor: %v %v", b, err)
	}
	if err := db.SaveCursor(bg, c5.Cursor{Consumer: "central", Stream: "relay1/ser", Through: 6}); err != nil {
		t.Fatal(err)
	}
	b, err = c5.ComputeBoundary(bg, db, db, []c5.Consumer{central, siem}, "relay1/ser", c5.ClassAdapterEvidence, now)
	if err != nil || b.Through() != 4 {
		t.Fatalf("window: %v %v", b, err)
	}
	if n, err := db.PruneStep(bg, b, 3); err != nil || n != 3 {
		t.Fatalf("step 1: %d %v", n, err)
	}
	if _, err := db.ReadCapture(bg, c5.EvidenceRef(capA.SHA256)); !isCode(err, c5.CodeInvalid) {
		t.Fatalf("capture A outlived events 1 to 3, its only records: %v", err)
	}
	if n, err := db.PruneStep(bg, b, 3); err != nil || n != 1 {
		t.Fatalf("step 2: %d %v", n, err)
	}
	if got, err := db.ReadCapture(bg, c5.EvidenceRef(capB.SHA256)); err != nil || !bytes.Equal(got.Bytes, capB.Bytes) {
		t.Fatalf("capture B, still referred to by event 5: %v", err)
	}
	if n, _ := db.PruneStep(bg, b, 3); n != 0 {
		t.Fatalf("pruned past the boundary: %d", n)
	}
	got, err := db.Read(bg, "relay1/ser", 1, 10)
	if err != nil || len(got) != 2 || got[0].Key.Seq != 5 || got[0].EvidenceRef != c5.EvidenceRef(capB.SHA256) {
		t.Fatalf("read past the prune point: %v %v", got, err)
	}
	if first, _ := db.FirstRetained(bg, "relay1/ser"); first != 5 {
		t.Fatalf("first retained %d", first)
	}
	if last, _ := db.LastCommitted(bg, "relay1/ser"); last != 6 {
		t.Fatalf("last committed %d", last)
	}
	bytesLeft, _ := db.ClassBytes(bg, c5.ClassAdapterEvidence)
	var want int64
	for _, s := range got {
		want += int64(len(s.Event) + len(s.SourceCursor))
	}
	want += int64(len(capB.Bytes))
	if bytesLeft != want {
		t.Fatalf("class bytes %d, want %d", bytesLeft, want)
	}
}

func capture(s string) c5.Capture {
	sum := sha256.Sum256([]byte(s))
	return c5.Capture{SHA256: hex.EncodeToString(sum[:]), Bytes: []byte(s)}
}

// V-S9 conformance: PageBytes falls as pruning deletes, before any compaction,
// and CompactStep reports done once the free pages are returned.
func TestUsageAndCompaction(t *testing.T) {
	db := open1(t, storeDir(t), evidenceDB, nil)
	l := testLog(t, db)
	big := make([]c5.Record, 0, 200)
	for i := 0; i < 200; i++ {
		r := rec("relay1/ser", c5.ClassAdapterEvidence, i)
		c := capture(string(bytes.Repeat([]byte{byte(i)}, 4000)))
		r.Capture = &c
		big = append(big, r)
	}
	if _, err := l.AppendBatch(bg, big); err != nil {
		t.Fatal(err)
	}
	before, err := db.PageBytes(bg)
	if err != nil {
		t.Fatal(err)
	}
	usedBefore, _, err := db.Usage(bg)
	if err != nil {
		t.Fatal(err)
	}
	central := c5.Consumer{ID: "central", Stream: "relay1/ser", Delivery: c5.Required}
	db.SaveCursor(bg, c5.Cursor{Consumer: "central", Stream: "relay1/ser", Through: 200})
	b, _ := c5.ComputeBoundary(bg, db, db, []c5.Consumer{central}, "relay1/ser", c5.ClassAdapterEvidence, time.Now())
	if n, err := db.PruneStep(bg, b, 150); err != nil || n != 150 {
		t.Fatalf("prune: %d %v", n, err)
	}
	after, _ := db.PageBytes(bg)
	// Usage is the quota's count: it fell with the prune, before any
	// compaction, and is the class bytes.
	if usedAfter, _, _ := db.Usage(bg); usedAfter >= usedBefore/2 {
		t.Fatalf("Usage %d after pruning 150 of 200, was %d", usedAfter, usedBefore)
	} else if held, _ := db.ClassBytes(bg, c5.ClassAdapterEvidence); usedAfter != held {
		t.Fatalf("Usage %d, class bytes %d", usedAfter, held)
	}
	if after >= before/2 {
		t.Fatalf("usage %d after pruning 150 of 200, was %d: free pages counted as used", after, before)
	}
	file := func() int64 {
		var pages int64
		db.conn.QueryRowContext(bg, "PRAGMA page_count").Scan(&pages)
		return pages
	}
	pagesBefore := file()
	steps := 0
	for more := true; more; steps++ {
		if more, err = db.CompactStep(bg, 32); err != nil {
			t.Fatal(err)
		}
		if steps > 1000 {
			t.Fatal("compaction does not finish")
		}
	}
	var free int64
	db.conn.QueryRowContext(bg, "PRAGMA freelist_count").Scan(&free)
	if free != 0 || file() >= pagesBefore {
		t.Fatalf("after %d steps: %d free pages, %d pages (was %d)", steps, free, file(), pagesBefore)
	}
	if more, err := db.CompactStep(bg, 32); err != nil || more {
		t.Fatalf("compacted store: %v %v", more, err)
	}
	if u, _ := db.PageBytes(bg); u > after {
		t.Fatalf("usage rose in compaction: %d > %d", u, after)
	}
}

// A store created without auto_vacuum=INCREMENTAL, or another node's
// store, is refused at the settings step and left unchanged.
func TestCheckSettingsRefuses(t *testing.T) {
	t.Run("no incremental vacuum", func(t *testing.T) {
		dir := storeDir(t)
		path := filepath.Join(dir, "evidence.db")
		raw, err := sql.Open("sqlite", path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := raw.Exec("PRAGMA journal_mode=WAL; CREATE TABLE x (y)"); err != nil {
			t.Fatal(err)
		}
		raw.Close()
		env, _ := NewEnv(Options{Dir: dir, Node: testNode, Database: evidenceDB})
		r := c5.RunStartup(bg, env, policy(evidenceDB))
		defer unlock(r)
		if r.Mode != c5.ModeFailed {
			t.Fatalf("mode %s", r.Mode)
		}
		raw, _ = sql.Open("sqlite", path)
		defer raw.Close()
		var av int
		raw.QueryRow("PRAGMA auto_vacuum").Scan(&av)
		if av != 0 {
			t.Fatalf("auto_vacuum changed to %d", av)
		}
	})
	t.Run("other node", func(t *testing.T) {
		dir := storeDir(t)
		db, first := testStore(t, Options{Dir: dir, Node: testNode, Database: evidenceDB}, policy(evidenceDB), c5.ModeCollecting)
		db.Close()
		first.Unlock()
		env, _ := NewEnv(Options{Dir: dir, Node: "site-b-node1", Database: evidenceDB})
		r := c5.RunStartup(bg, env, policy(evidenceDB))
		defer unlock(r)
		if r.Mode != c5.ModeFailed || r.Alarms[len(r.Alarms)-1].Code != c5.AlarmSettingsInvalid {
			t.Fatalf("mode %s %v", r.Mode, r.Alarms)
		}
	})
}

func TestCommitBeforeSettingsChecked(t *testing.T) {
	dir := storeDir(t)
	env, _ := NewEnv(Options{Dir: dir, Node: testNode, Database: evidenceDB})
	st, err := env.Open(bg)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	db, _ := AsDB(st)
	if _, err := db.CommitBatch(bg, "relay1/ser", recs("relay1/ser", c5.ClassAdapterEvidence, 0, 1)); err == nil || isCode(err, c5.CodeInvalid) {
		t.Fatalf("commit before CheckSettings: %v", err)
	}
}

// On Linux the database and its WAL and shared-memory files are owner-only.
func TestFileModes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the store directory's DACL is checked by the installer (W-4)")
	}
	dir := storeDir(t)
	db := open1(t, dir, evidenceDB, nil)
	if _, err := testLog(t, db).Append(bg, rec("relay1/ser", c5.ClassAdapterEvidence, 0)); err != nil {
		t.Fatal(err)
	}
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		info, _ := e.Info()
		if info.Mode().Perm()&0o077 != 0 {
			t.Errorf("%s has mode %v", e.Name(), info.Mode())
		}
	}
	db.Close()

	// A database file widened after the directory was checked is refused
	// before SQLite opens it, and so is one that is a link (A3 #84 note 3).
	opt := Options{Dir: dir, Node: testNode, Database: evidenceDB}
	path := filepath.Join(dir, string(evidenceDB.ID)+".db")
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := open(bg, path, opt); err == nil {
		t.Fatal("opened a database file others can read")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(t.TempDir(), "elsewhere")
	if err := os.WriteFile(other, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	os.Remove(path + "-wal")
	if err := os.Symlink(other, path+"-wal"); err != nil {
		t.Fatal(err)
	}
	if _, err := open(bg, path, opt); err == nil {
		t.Fatal("opened a database whose WAL is a link")
	}
	os.Remove(path + "-wal")
	d, err := open(bg, path, opt)
	if err != nil {
		t.Fatalf("plain files refused: %v", err)
	}
	d.Close()

	// A link to a good directory is refused, so the checked mode is the
	// mode of the directory written to (A3 #84 note 4).
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	linked, _ := NewEnv(Options{Dir: link, Node: testNode, Database: auditDB})
	if _, err := linked.Lock(bg); err == nil {
		t.Fatal("lock taken through a symbolic link")
	}

	if err := os.Chmod(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	env, _ := NewEnv(Options{Dir: dir, Node: testNode, Database: auditDB})
	if _, err := env.Lock(bg); err == nil {
		t.Fatal("lock taken on a directory others can read")
	}
}

func TestSaveSourceCursor(t *testing.T) {
	dir := storeDir(t)
	opt := Options{Dir: dir, Node: testNode, Database: evidenceDB}
	db, r := testStore(t, opt, policy(evidenceDB), c5.ModeCollecting)
	r1 := rec("relay1/ser", c5.ClassAdapterEvidence, 0)
	r1.SourceCursor = []byte("state 1")
	if _, err := testLog(t, db).Append(bg, r1); err != nil {
		t.Fatal(err)
	}
	if err := db.SaveSourceCursor(bg, "relay1/ser", []byte("state 2")); err != nil {
		t.Fatal(err)
	}
	db.Close()
	r.Unlock()
	db, _ = testStore(t, opt, policy(evidenceDB), c5.ModeCollecting)
	if got, _ := db.SourceCursor(bg, "relay1/ser"); string(got) != "state 2" {
		t.Fatalf("after restart: %q", got)
	}
	if n, _ := db.LastCommitted(bg, "relay1/ser"); n != 1 {
		t.Fatalf("a source cursor changed the seq: %d", n)
	}
	if err := db.SaveSourceCursor(bg, "nope", []byte("x")); !isCode(err, c5.CodeInvalid) {
		t.Fatalf("unknown stream: %v", err)
	}
}

// CommitBatch checks capture digests itself, so a capture with the wrong
// bytes cannot be stored and then hide the correct one (A6 review of #77).
func TestCommitBatchRefusesBadCapture(t *testing.T) {
	db := open1(t, storeDir(t), evidenceDB, nil)
	good := capture("report")
	bad := c5.Capture{SHA256: good.SHA256, Bytes: []byte("not the report")}
	r := rec("relay1/ser", c5.ClassAdapterEvidence, 0)
	r.Capture = &bad
	if _, err := db.CommitBatch(bg, "relay1/ser", []c5.Record{r}); !isCode(err, c5.CodeInvalid) {
		t.Fatalf("bad capture: %v", err)
	}
	r.Capture = &good
	if _, err := db.CommitBatch(bg, "relay1/ser", []c5.Record{r}); err != nil {
		t.Fatal(err)
	}
	if got, err := db.ReadCapture(bg, c5.EvidenceRef(good.SHA256)); err != nil || string(got.Bytes) != "report" {
		t.Fatalf("stored capture: %q %v", got.Bytes, err)
	}
}
