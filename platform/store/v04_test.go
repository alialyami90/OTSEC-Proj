package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	c5 "otsec.local/otsec/contracts/store"
)

// C5 0.4 in the SQLite store: the configuration class, holds, the record
// cap and the syslog-unknown class. Evidence class: simulated.

const cfgA, cfgB c5.StreamID = "config/asset-a", "config/asset-b"

var configDB = c5.Database{
	ID:      "configuration",
	Writer:  "ied",
	Streams: []c5.StreamSpec{{ID: cfgA, Class: c5.ClassConfiguration}, {ID: cfgB, Class: c5.ClassConfiguration}},
	Classes: []c5.StreamClass{c5.ClassConfiguration},
	Quotas:  []c5.Quota{{Class: c5.ClassConfiguration, Bytes: 8 << 20, WarnFraction: 0.8, MaxRecordBytes: c5.MinRecordBytes}},
}

// testDocs accepts a document that starts with {"doc": and, when the
// record has a capture, names the capture's digest: the shape of the node's
// C9 check that a snapshot names its own transcript.
func testDocs(doc []byte, capture *c5.Capture) error {
	if !bytes.HasPrefix(doc, []byte(`{"doc":`)) {
		return errors.New("not a test document")
	}
	if capture != nil && !bytes.Contains(doc, []byte(capture.SHA256)) {
		return errors.New("document does not name its capture")
	}
	return nil
}

func doc(n int) []byte { return fmt.Appendf(nil, `{"doc":%d}`, n) }

func cfgRec(stream c5.StreamID, n int, holds ...c5.Hold) c5.Record {
	return c5.Record{Stream: stream, Class: c5.ClassConfiguration, Event: doc(n), Holds: holds}
}

func openConfig(t *testing.T, dir string, d c5.Database, a *alarms) *DB {
	t.Helper()
	opt := Options{Dir: dir, Node: testNode, Database: d, Documents: testDocs}
	if a != nil {
		opt.Alarms = a.sink
	}
	db, _ := testStore(t, opt, policy(d), c5.ModeCollecting)
	return db
}

func configLog(t *testing.T, db *DB, d c5.Database) *c5.Log {
	t.Helper()
	last := map[c5.StreamID]c5.Seq{}
	for s := range db.Streams() {
		n, err := db.LastCommitted(context.Background(), s)
		if err != nil {
			t.Fatal(err)
		}
		last[s] = n
	}
	l, err := c5.NewLogFor(db, testNode, d, c5.GroupOptions{MaxEvents: 10, MaxWait: 5 * time.Millisecond, MaxCommitRecords: 1000}, last)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func baselineHold(seq c5.Seq) c5.HoldReason {
	return c5.HoldReason{Code: c5.HoldBaseline, Ref: c5.Key{NodeID: testNode, Stream: "audit", Seq: seq}}
}

func heldSeqs(t *testing.T, db *DB, s c5.StreamID) []c5.Seq {
	t.Helper()
	h, err := db.Held(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	var out []c5.Seq
	for _, x := range h {
		out = append(out, x.Seq)
	}
	return out
}

func storedSeqs(t *testing.T, db *DB, s c5.StreamID) []c5.Seq {
	t.Helper()
	got, err := db.Read(context.Background(), s, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	var out []c5.Seq
	for _, x := range got {
		out = append(out, x.Key.Seq)
	}
	return out
}

func hasTable(t *testing.T, db *DB, name string) bool {
	t.Helper()
	var n int
	if err := db.conn.QueryRowContext(context.Background(), `SELECT count(*) FROM sqlite_schema WHERE type = 'table' AND name = ?`, name).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n > 0
}

// TestHoldsTableOnlyForConfiguration: a 0.3 layout opens unchanged, with no
// holds table; a configuration database gets one, and needs a validator.
func TestHoldsTableOnlyForConfiguration(t *testing.T) {
	ev := open1(t, storeDir(t), evidenceDB, nil)
	if hasTable(t, ev, "holds") {
		t.Error("a database with no configuration class has a holds table")
	}
	if _, err := ev.Held(context.Background(), "relay1/ser"); !isCode(err, c5.CodeNotHoldable) {
		t.Errorf("Held on an evidence stream: %v", err)
	}
	cfg := openConfig(t, storeDir(t), configDB, nil)
	if !hasTable(t, cfg, "holds") {
		t.Error("a configuration database has no holds table")
	}
	if _, err := NewEnv(Options{Dir: storeDir(t), Node: testNode, Database: configDB}); !isCode(err, c5.CodeInvalid) {
		t.Errorf("a configuration database with no document validator: %v", err)
	}
}

// TestConfigurationKeepsBytes: a configuration record is stored exactly as
// given, with no seq written in, and only after the validator accepts it,
// with its capture. A refusal stores nothing and the Log keeps running.
func TestConfigurationKeepsBytes(t *testing.T) {
	ctx := context.Background()
	db := openConfig(t, storeDir(t), configDB, nil)
	l := configLog(t, db, configDB)
	cp := capture("transcript of a read")
	r := c5.Record{Stream: cfgA, Class: c5.ClassConfiguration, Capture: &cp,
		Event: fmt.Appendf(nil, `{"doc":1,"transcript":%q}`, cp.SHA256)}
	if _, err := l.Append(ctx, r); err != nil {
		t.Fatal(err)
	}
	got, err := db.Read(ctx, cfgA, 0, 10)
	if err != nil || len(got) != 1 {
		t.Fatalf("read: %v %v", got, err)
	}
	if !bytes.Equal(got[0].Event, r.Event) || got[0].EvidenceRef != c5.EvidenceRef(cp.SHA256) {
		t.Errorf("stored %s ref %s, want the document as given with its capture", got[0].Event, got[0].EvidenceRef)
	}

	other := capture("another transcript")
	bad := r
	bad.Capture = &other
	if _, err := l.Append(ctx, bad); !isCode(err, c5.CodeInvalid) {
		t.Errorf("a document that does not name its capture: %v", err)
	}
	if _, err := l.Append(ctx, c5.Record{Stream: cfgA, Class: c5.ClassConfiguration, Event: []byte(`{"x":1}`)}); !isCode(err, c5.CodeInvalid) {
		t.Errorf("a document the validator refuses: %v", err)
	}
	if l.Stopped() != nil {
		t.Fatalf("a refusal stopped the log: %v", l.Stopped())
	}
	if _, err := l.Append(ctx, cfgRec(cfgA, 2)); err != nil {
		t.Fatalf("after refusals: %v", err)
	}
	if s := storedSeqs(t, db, cfgA); len(s) != 2 || s[1] != 2 {
		t.Errorf("stored %v, want seqs 1 and 2", s)
	}
}

// TestStoreRefusesOverRecordCap: the store checks the class's
// MaxRecordBytes itself, not only the Log, and a refusal writes nothing.
func TestStoreRefusesOverRecordCap(t *testing.T) {
	ctx := context.Background()
	db := openConfig(t, storeDir(t), configDB, nil)
	big := c5.Record{Stream: cfgA, Class: c5.ClassConfiguration,
		Event: append([]byte(`{"doc":"`), append(bytes.Repeat([]byte("x"), c5.MinRecordBytes), '"', '}')...)}
	if _, err := db.CommitBatch(ctx, cfgA, []c5.Record{big}); !isCode(err, c5.CodeRecordTooLarge) {
		t.Fatalf("over the cap: %v", err)
	}
	if s := storedSeqs(t, db, cfgA); len(s) != 0 {
		t.Errorf("stored %v after a refusal", s)
	}
}

// TestHoldsCommitWithRecord: a record's holds commit in its transaction,
// on itself and on an earlier record; a hold on a record that is not
// stored refuses the whole batch.
func TestHoldsCommitWithRecord(t *testing.T) {
	ctx := context.Background()
	db := openConfig(t, storeDir(t), configDB, nil)
	l := configLog(t, db, configDB)
	if _, err := l.Append(ctx, cfgRec(cfgA, 1)); err != nil {
		t.Fatal(err)
	}
	diff := c5.HoldReason{Code: c5.HoldUnapprovedDifference, Ref: c5.Key{NodeID: testNode, Stream: "audit", Seq: 9}}
	// A difference holds itself and the earlier snapshot it names.
	if _, err := l.Append(ctx, cfgRec(cfgA, 2, c5.Hold{Reason: diff}, c5.Hold{Seq: 1, Reason: diff})); err != nil {
		t.Fatal(err)
	}
	if got := heldSeqs(t, db, cfgA); fmt.Sprint(got) != "[1 2]" {
		t.Errorf("held %v, want [1 2]", got)
	}
	h, _ := db.Held(ctx, cfgA)
	if h[0].Reason != diff || h[0].Bytes != int64(len(doc(1))) {
		t.Errorf("held %+v", h[0])
	}
	// A hold on seq 7, never stored, refuses the batch: nothing is stored.
	if _, err := l.Append(ctx, cfgRec(cfgA, 3, c5.Hold{Seq: 7, Reason: diff})); !isCode(err, c5.CodeNotHoldable) {
		t.Errorf("hold on an unstored record: %v", err)
	}
	if s := storedSeqs(t, db, cfgA); len(s) != 2 {
		t.Errorf("stored %v after a refused hold", s)
	}
	if l.Stopped() != nil {
		t.Fatalf("a refused hold stopped the log: %v", l.Stopped())
	}
	// Holds outside the configuration class are refused before any write.
	ev := open1(t, storeDir(t), evidenceDB, nil)
	r := rec("relay1/ser", c5.ClassAdapterEvidence, 1)
	r.Holds = []c5.Hold{{Reason: diff}}
	if _, err := ev.CommitBatch(ctx, "relay1/ser", []c5.Record{r}); !isCode(err, c5.CodeNotHoldable) {
		t.Errorf("hold on an evidence record: %v", err)
	}
}

// TestHolderAPI: Hold, Release and Held, with their refusals, and holds
// survive a reopen.
func TestHolderAPI(t *testing.T) {
	ctx := context.Background()
	dir := storeDir(t)
	opt := Options{Dir: dir, Node: testNode, Database: configDB, Documents: testDocs}
	db, r := testStore(t, opt, policy(configDB), c5.ModeCollecting)
	l := configLog(t, db, configDB)
	for i := 1; i <= 3; i++ {
		if _, err := l.Append(ctx, cfgRec(cfgB, i)); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Hold(ctx, c5.Hold{Stream: cfgB, Seq: 2, Reason: baselineHold(4)}); err != nil {
		t.Fatal(err)
	}
	// Holding again replaces the reason.
	if err := db.Hold(ctx, c5.Hold{Stream: cfgB, Seq: 2, Reason: baselineHold(5)}); err != nil {
		t.Fatal(err)
	}
	for name, h := range map[string]c5.Hold{
		"unstored seq":   {Stream: cfgB, Seq: 9, Reason: baselineHold(4)},
		"unknown stream": {Stream: "config/none", Seq: 1, Reason: baselineHold(4)},
	} {
		if err := db.Hold(ctx, h); !isCode(err, c5.CodeNotHoldable) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := db.Hold(ctx, c5.Hold{Stream: cfgB, Seq: 1, Reason: c5.HoldReason{Code: "because"}}); !isCode(err, c5.CodeInvalid) {
		t.Errorf("free-text reason: %v", err)
	}
	if err := db.Release(ctx, cfgB, 3); err != nil {
		t.Errorf("releasing an unheld record: %v", err)
	}
	db.Close()
	unlock(r)

	db = openConfig(t, dir, configDB, nil)
	h, err := db.Held(ctx, cfgB)
	if err != nil || len(h) != 1 || h[0].Seq != 2 || h[0].Reason != baselineHold(5) {
		t.Fatalf("after reopen: %+v %v", h, err)
	}
	if err := db.Release(ctx, cfgB, 2); err != nil {
		t.Fatal(err)
	}
	if got := heldSeqs(t, db, cfgB); len(got) != 0 {
		t.Errorf("held %v after release", got)
	}
}

// TestPruneAroundHolds: the boundary passes held seqs; they stay and still
// count in the class, later unheld seqs are pruned in order, and a held
// record keeps its capture while a capture shared with an unheld record
// survives that record's prune.
func TestPruneAroundHolds(t *testing.T) {
	ctx := context.Background()
	db := openConfig(t, storeDir(t), configDB, nil)
	l := configLog(t, db, configDB)
	cp := capture("shared transcript")
	for i := 1; i <= 6; i++ {
		r := cfgRec(cfgA, i)
		if i == 2 || i == 3 {
			r.Capture = &cp
			r.Event = fmt.Appendf(nil, `{"doc":%d,"t":%q}`, i, cp.SHA256)
		}
		if i == 3 {
			r.Holds = []c5.Hold{{Reason: baselineHold(1)}}
		}
		if i == 5 {
			r.Holds = []c5.Hold{{Reason: baselineHold(2)}}
		}
		if _, err := l.Append(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	before, _ := db.ClassBytes(ctx, c5.ClassConfiguration)
	central := c5.Consumer{ID: "central", Stream: cfgA, Delivery: c5.Required}
	if err := db.SaveCursor(ctx, c5.Cursor{Consumer: "central", Stream: cfgA, Through: 6}); err != nil {
		t.Fatal(err)
	}
	b, err := c5.ComputeBoundary(ctx, db, db, []c5.Consumer{central}, cfgA, c5.ClassConfiguration, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	// Two at a time: 1 and 2, then 4 and 6.
	if n, err := db.PruneStep(ctx, b, 2); err != nil || n != 2 {
		t.Fatalf("first step: %d %v", n, err)
	}
	if got := storedSeqs(t, db, cfgA); fmt.Sprint(got) != "[3 4 5 6]" {
		t.Errorf("after one step %v", got)
	}
	if _, err := db.ReadCapture(ctx, "sha256:"+cp.SHA256); err != nil {
		t.Errorf("held record's capture went with an unheld one: %v", err)
	}
	if n, err := db.PruneStep(ctx, b, 2); err != nil || n != 2 {
		t.Fatalf("second step: %d %v", n, err)
	}
	if n, err := db.PruneStep(ctx, b, 2); err != nil || n != 0 {
		t.Fatalf("only held records left: %d %v", n, err)
	}
	if got := storedSeqs(t, db, cfgA); fmt.Sprint(got) != "[3 5]" {
		t.Errorf("left %v, want the held [3 5]", got)
	}
	after, _ := db.ClassBytes(ctx, c5.ClassConfiguration)
	want := int64(len(fmt.Appendf(nil, `{"doc":%d,"t":%q}`, 3, cp.SHA256))+len(cp.Bytes)) + int64(len(doc(5)))
	if after != want || after >= before {
		t.Errorf("class bytes %d (was %d), want %d: held records and the held capture still count", after, before, want)
	}
	h, _ := db.Held(ctx, cfgA)
	if h[0].Bytes != want-int64(len(doc(5))) {
		t.Errorf("held bytes of seq 3 %d: its capture is now only its own", h[0].Bytes)
	}
	// Released, it prunes on the next step.
	if err := db.Release(ctx, cfgA, 3); err != nil {
		t.Fatal(err)
	}
	if n, err := db.PruneStep(ctx, b, 10); err != nil || n != 1 {
		t.Fatalf("after release: %d %v", n, err)
	}
	if _, err := db.ReadCapture(ctx, "sha256:"+cp.SHA256); err == nil {
		t.Error("capture kept after its last record was pruned")
	}
	if _, err := db.Discard(ctx, nil, cfgA, []c5.Seq{5}); err == nil {
		t.Error("a configuration record was discarded")
	}
}

// TestFullAlarmNamesStreams: a full syslog-unknown class raises its own
// alarm, and full configuration and syslog-unknown alarms name the streams
// holding the most bytes.
func TestFullAlarmNamesStreams(t *testing.T) {
	ctx := context.Background()
	unknown := c5.Database{ID: "syslog", Writer: "telemetry",
		Streams: []c5.StreamSpec{{ID: "syslog/unknown-a", Class: c5.ClassSyslogUnknown}, {ID: "syslog/unknown-b", Class: c5.ClassSyslogUnknown}},
		Classes: []c5.StreamClass{c5.ClassSyslogUnknown},
		Quotas:  []c5.Quota{{Class: c5.ClassSyslogUnknown, Bytes: 4096, WarnFraction: 0.5}}}
	a := &alarms{}
	db := open1(t, storeDir(t), unknown, a)
	l := testLog(t, db)
	var err error
	for i := 0; err == nil && i < 1000; i++ {
		_, err = l.Append(ctx, rec("syslog/unknown-a", c5.ClassSyslogUnknown, i))
	}
	if !isCode(err, c5.CodeQuotaReached) {
		t.Fatalf("filling: %v", err)
	}
	var full *c5.Alarm
	for i := range a.got {
		if a.got[i].Code == c5.AlarmSyslogUnknownFull {
			full = &a.got[i]
		}
	}
	if full == nil || a.has(c5.AlarmQuotaReached) || !strings.Contains(full.Detail, "syslog/unknown-a") {
		t.Fatalf("alarms %+v", a.got)
	}

	ca := &alarms{}
	small := configDB
	small.Quotas = []c5.Quota{{Class: c5.ClassConfiguration, Bytes: c5.MinRecordBytes, WarnFraction: 0.5, MaxRecordBytes: c5.MinRecordBytes}}
	cdb := openConfig(t, storeDir(t), small, ca)
	cl := configLog(t, cdb, small)
	pad := bytes.Repeat([]byte("p"), 20000)
	err = nil
	for i := 0; err == nil && i < 10; i++ {
		s := cfgA
		if i%3 == 2 {
			s = cfgB
		}
		_, err = cl.Append(ctx, c5.Record{Stream: s, Class: c5.ClassConfiguration, Event: fmt.Appendf(nil, `{"doc":%d,"p":%q}`, i, pad)})
	}
	if !isCode(err, c5.CodeQuotaReached) {
		t.Fatalf("filling configuration: %v", err)
	}
	for _, x := range ca.got {
		if x.Code == c5.AlarmQuotaReached {
			if !strings.Contains(x.Detail, "most bytes: "+string(cfgA)) || !strings.Contains(x.Detail, string(cfgB)) {
				t.Errorf("detail %q does not name the streams, largest first", x.Detail)
			}
			return
		}
	}
	t.Fatalf("no full alarm: %+v", ca.got)
}
