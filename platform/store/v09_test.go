package store

import (
	"bytes"
	"strconv"
	"strings"
	"testing"
	"time"

	c5 "otsec.local/otsec/contracts/store"
)

// C5 0.9 in the SQLite store: the two network classes, network-full, and a
// shared capture charged once to each class that cites it
// (docs/phase4/D5-c5-0.9.md sections 1, 2 and 6). Evidence class: simulated.

const (
	netObs   c5.StreamID = "netobs/sensor1"
	netAlert c5.StreamID = "netalert/sensor1"
)

func networkDB(obsBytes, alertBytes int64) c5.Database {
	return c5.Database{
		ID:      "network",
		Writer:  "node",
		Streams: []c5.StreamSpec{{ID: netObs, Class: c5.ClassNetworkObservation}, {ID: netAlert, Class: c5.ClassNetworkAlert}},
		Classes: []c5.StreamClass{c5.ClassNetworkObservation, c5.ClassNetworkAlert},
		Quotas: []c5.Quota{
			{Class: c5.ClassNetworkObservation, Bytes: obsBytes, WarnFraction: 0.8, MaxRecordBytes: c5.MinRecordBytes},
			{Class: c5.ClassNetworkAlert, Bytes: alertBytes, WarnFraction: 0.8, MaxRecordBytes: c5.MinRecordBytes},
		},
	}
}

func withCapture(r c5.Record, c c5.Capture) c5.Record {
	r.Capture = &c
	return r
}

func commit1(t *testing.T, db *DB, r c5.Record) {
	t.Helper()
	if _, err := db.CommitBatch(bg, r.Stream, []c5.Record{r}); err != nil {
		t.Fatalf("commit to %s: %v", r.Stream, err)
	}
}

func classBytes(t *testing.T, db *DB, c c5.StreamClass) int64 {
	t.Helper()
	n, err := db.ClassBytes(bg, c)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// payloadBytes is the event and cursor bytes stream holds.
func payloadBytes(t *testing.T, db *DB, stream c5.StreamID) int64 {
	t.Helper()
	var n int64
	if err := db.conn.QueryRowContext(bg, `SELECT coalesce(sum(length(event) + coalesce(length(source_cursor), 0)), 0)
		FROM events WHERE stream = ?`, string(stream)).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func pruneAll(t *testing.T, db *DB, stream c5.StreamID, class c5.StreamClass) {
	t.Helper()
	last, err := db.LastCommitted(bg, stream)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SaveCursor(bg, c5.Cursor{Consumer: "c-" + c5.ConsumerID(strings.ReplaceAll(string(stream), "/", "-")), Stream: stream, Through: last}); err != nil {
		t.Fatal(err)
	}
	c := c5.Consumer{ID: "c-" + c5.ConsumerID(strings.ReplaceAll(string(stream), "/", "-")), Stream: stream, Delivery: c5.Required}
	b, err := c5.ComputeBoundary(bg, db, db, []c5.Consumer{c}, stream, class, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.PruneStep(bg, b, 100); err != nil {
		t.Fatal(err)
	}
}

func captureStored(t *testing.T, db *DB, sha string) bool {
	t.Helper()
	var n int
	if err := db.conn.QueryRowContext(bg, `SELECT count(*) FROM captures WHERE sha256 = ?`, sha).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n == 1
}

// A network record over its class's cap is refused before it is queued, and
// one at the cap commits.
func TestNetworkRecordCapV09(t *testing.T) {
	db := open1(t, storeDir(t), networkDB(8<<20, 8<<20), nil)
	r := rec(netObs, c5.ClassNetworkObservation, 1)
	room := int(c5.MinRecordBytes) - len(r.Event)
	at := withCapture(r, capture(string(bytes.Repeat([]byte{'a'}, room))))
	over := withCapture(r, capture(string(bytes.Repeat([]byte{'b'}, room+1))))
	if _, err := db.CommitBatch(bg, netObs, []c5.Record{over}); !isCode(err, c5.CodeRecordTooLarge) {
		t.Fatalf("one byte over the cap: %v, want CodeRecordTooLarge", err)
	}
	commit1(t, db, at)
}

// At the quota a network commit is refused, network-full is raised once with
// the class and the top streams, and a prune re-arms it.
func TestNetworkFullV09(t *testing.T) {
	a := &alarms{}
	db := open1(t, storeDir(t), networkDB(8<<20, c5.MinRecordBytes), a)
	n := 0
	var refused error
	for refused == nil && n < 10000 {
		n++
		_, refused = db.CommitBatch(bg, netAlert, []c5.Record{rec(netAlert, c5.ClassNetworkAlert, n)})
	}
	if !isCode(refused, c5.CodeQuotaReached) {
		t.Fatalf("after %d alerts: %v, want CodeQuotaReached", n, refused)
	}
	db.CommitBatch(bg, netAlert, []c5.Record{rec(netAlert, c5.ClassNetworkAlert, n+1)})
	var full []c5.Alarm
	for _, x := range a.got {
		if x.Code == c5.AlarmNetworkFull {
			full = append(full, x)
		}
	}
	if len(full) != 1 || full[0].Class != c5.ClassNetworkAlert || !strings.Contains(full[0].Detail, "most bytes: "+string(netAlert)) {
		t.Fatalf("network-full alarms %+v, want one naming the class and the top stream", full)
	}
	if a.has(c5.AlarmQuotaReached) {
		t.Error("store-quota-reached raised for a network class")
	}
	pruneAll(t, db, netAlert, c5.ClassNetworkAlert)
	for refused = nil; refused == nil; {
		n++
		_, refused = db.CommitBatch(bg, netAlert, []c5.Record{rec(netAlert, c5.ClassNetworkAlert, n)})
	}
	full = full[:0]
	for _, x := range a.got {
		if x.Code == c5.AlarmNetworkFull {
			full = append(full, x)
		}
	}
	if len(full) != 2 {
		t.Fatalf("%d network-full alarms after a prune and a second fill, want 2", len(full))
	}
}

// A first-sight observation stores a capture and an alert cites it: both
// classes are charged its bytes. Pruning the observation ends only the
// observation class's charge. Pruning the alert deletes the capture and ends
// the last charge (section 2).
func TestCaptureChargedPerClassV09(t *testing.T) {
	db := open1(t, storeDir(t), networkDB(8<<20, 8<<20), nil)
	frames := capture(string(bytes.Repeat([]byte{'f'}, 16536)))
	size := int64(len(frames.Bytes))

	commit1(t, db, withCapture(rec(netObs, c5.ClassNetworkObservation, 1), frames))
	if got, want := classBytes(t, db, c5.ClassNetworkObservation), payloadBytes(t, db, netObs)+size; got != want {
		t.Fatalf("observation class %d, want %d", got, want)
	}
	// Two alerts in one batch and one more later: the alert class is
	// charged once.
	if _, err := db.CommitBatch(bg, netAlert, []c5.Record{
		withCapture(rec(netAlert, c5.ClassNetworkAlert, 1), frames), withCapture(rec(netAlert, c5.ClassNetworkAlert, 2), frames),
	}); err != nil {
		t.Fatal(err)
	}
	commit1(t, db, withCapture(rec(netAlert, c5.ClassNetworkAlert, 3), frames))
	alertBefore := classBytes(t, db, c5.ClassNetworkAlert)
	if want := payloadBytes(t, db, netAlert) + size; alertBefore != want {
		t.Fatalf("alert class %d, want %d (the capture once)", alertBefore, want)
	}

	pruneAll(t, db, netObs, c5.ClassNetworkObservation)
	if got := classBytes(t, db, c5.ClassNetworkObservation); got != 0 {
		t.Errorf("observation class %d after its prune, want 0", got)
	}
	if got := classBytes(t, db, c5.ClassNetworkAlert); got != alertBefore {
		t.Errorf("alert class %d after the observation prune, want %d", got, alertBefore)
	}
	if !captureStored(t, db, frames.SHA256) {
		t.Fatal("capture deleted while alerts cite it")
	}

	pruneAll(t, db, netAlert, c5.ClassNetworkAlert)
	if got := classBytes(t, db, c5.ClassNetworkAlert); got != 0 {
		t.Errorf("alert class %d after its prune, want 0", got)
	}
	if captureStored(t, db, frames.SHA256) {
		t.Error("capture kept after its last citing record")
	}
}

// The alert's capture alone holds the alert class: an observation flood
// that fills its own class leaves the alert class's bytes as they were.
func TestSharedCaptureDoesNotHoldOtherQuotaV09(t *testing.T) {
	db := open1(t, storeDir(t), networkDB(c5.MinRecordBytes, 8<<20), nil)
	frames := capture(string(bytes.Repeat([]byte{'g'}, 16536)))
	commit1(t, db, withCapture(rec(netAlert, c5.ClassNetworkAlert, 1), frames))
	// The alert stored the capture first; the observation that cites it is
	// still charged for it.
	commit1(t, db, withCapture(rec(netObs, c5.ClassNetworkObservation, 1), frames))
	if got, want := classBytes(t, db, c5.ClassNetworkObservation), payloadBytes(t, db, netObs)+int64(len(frames.Bytes)); got != want {
		t.Fatalf("observation class %d, want %d", got, want)
	}
	pruneAll(t, db, netAlert, c5.ClassNetworkAlert)
	if got := classBytes(t, db, c5.ClassNetworkAlert); got != 0 {
		t.Errorf("alert class %d after its prune, want 0", got)
	}
	if got, want := classBytes(t, db, c5.ClassNetworkObservation), payloadBytes(t, db, netObs)+int64(len(frames.Bytes)); got != want {
		t.Errorf("observation class %d after the alert prune, want %d", got, want)
	}
}

// Discard keeps the same rule: discarding one class's last citing record
// ends that class's charge only.
func TestDiscardChargesPerClassV09(t *testing.T) {
	d := evidenceDB
	d.Streams = append([]c5.StreamSpec{{ID: "quarantine/relay1", Class: c5.ClassAdapterEvidence}}, d.Streams...)
	db := open1(t, storeDir(t), d, nil)
	tr := capture("a collection run's transcript")
	commit1(t, db, withCapture(rec("quarantine/relay1", c5.ClassAdapterEvidence, 1), tr))
	commit1(t, db, withCapture(rec("platform/health", c5.ClassPlatform, 1), tr))
	healthBefore := classBytes(t, db, c5.ClassPlatform)
	if want := payloadBytes(t, db, "platform/health") + int64(len(tr.Bytes)); healthBefore != want {
		t.Fatalf("platform class %d, want %d", healthBefore, want)
	}
	payload := payloadBytes(t, db, "quarantine/relay1")
	out, err := db.Discard(bg, nil, "quarantine/relay1", []c5.Seq{1})
	if err != nil || out.Events != 1 {
		t.Fatalf("discard: %+v %v", out, err)
	}
	if want := payload + int64(len(tr.Bytes)); out.Bytes != want {
		t.Errorf("discarded %d bytes, want %d: the event and the ended capture charge", out.Bytes, want)
	}
	if got := classBytes(t, db, c5.ClassAdapterEvidence); got != 0 {
		t.Errorf("evidence class %d after the discard, want 0", got)
	}
	if got := classBytes(t, db, c5.ClassPlatform); got != healthBefore {
		t.Errorf("platform class %d after the discard, want %d", got, healthBefore)
	}
	if !captureStored(t, db, tr.SHA256) {
		t.Error("capture deleted while a health record cites it")
	}
}

// A capture a 0.8 binary stored is charged as 0.8 charged it, to its first
// class only, until its row is deleted (section 5).
func TestCaptureChargeFromV09(t *testing.T) {
	dir := storeDir(t)
	reopen := func() (*DB, func()) {
		db, r := testStore(t, Options{Dir: dir, Node: testNode, Database: evidenceDB}, policy(evidenceDB), c5.ModeCollecting)
		return db, func() { db.Close(); r.Unlock() }
	}
	db, done := reopen()
	if db.chargeFrom != 1 {
		t.Fatalf("a new database charges from capture %d, want 1", db.chargeFrom)
	}
	tr := capture("stored by 0.8")
	commit1(t, db, withCapture(rec("relay1/ser", c5.ClassAdapterEvidence, 1), tr))
	// As if a 0.8 binary had stored it: no key yet, so this binary's first
	// open puts the 0.9 rule after it.
	if _, err := db.conn.ExecContext(bg, `DELETE FROM meta WHERE key = ?`, chargeFromKey); err != nil {
		t.Fatal(err)
	}
	done()
	db, done = reopen()
	var id int64
	db.conn.QueryRowContext(bg, `SELECT id FROM captures WHERE sha256 = ?`, tr.SHA256).Scan(&id)
	if db.chargeFrom != id+1 {
		t.Fatalf("charges from capture %d, want %d", db.chargeFrom, id+1)
	}
	var v string
	db.conn.QueryRowContext(bg, `SELECT value FROM meta WHERE key = ?`, chargeFromKey).Scan(&v)
	if v != strconv.FormatInt(id+1, 10) {
		t.Fatalf("meta %s = %q", chargeFromKey, v)
	}

	serBefore := classBytes(t, db, c5.ClassAdapterEvidence)
	commit1(t, db, withCapture(rec("platform/health", c5.ClassPlatform, 1), tr))
	if got, want := classBytes(t, db, c5.ClassPlatform), payloadBytes(t, db, "platform/health"); got != want {
		t.Fatalf("platform class %d, want %d: a 0.8 capture charged to a second class", got, want)
	}
	if serBefore != payloadBytes(t, db, "relay1/ser")+int64(len(tr.Bytes)) {
		t.Fatalf("evidence class %d before the prunes", serBefore)
	}
	pruneAll(t, db, "relay1/ser", c5.ClassAdapterEvidence)
	if got := classBytes(t, db, c5.ClassAdapterEvidence); got != int64(len(tr.Bytes)) {
		t.Errorf("evidence class %d after its prune, want the capture's %d still charged to it", got, len(tr.Bytes))
	}
	pruneAll(t, db, "platform/health", c5.ClassPlatform)
	if got := classBytes(t, db, c5.ClassAdapterEvidence); got != 0 {
		t.Errorf("evidence class %d once the capture is deleted, want 0", got)
	}
	if got := classBytes(t, db, c5.ClassPlatform); got != 0 {
		t.Errorf("platform class %d, want 0", got)
	}
	done()
	db, done = reopen()
	defer done()
	if db.chargeFrom != id+1 {
		t.Errorf("reopened: charges from %d, want %d", db.chargeFrom, id+1)
	}
}
