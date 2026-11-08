package store

import (
	"bytes"
	"strings"
	"testing"
	"time"

	c5 "otsec.local/otsec/contracts/store"
)

// C5 0.9 in the SQLite store: the two network classes, network-full, and a
// shared capture charged once to each class that cites it
// (docs/phase4/D5-c5-0.9.md sections 1, 2 and 6). Evidence class: simulated.

const (
	netObs   c5.StreamID = "network-observation/sensor1"
	netAlert c5.StreamID = "network-alert/sensor1"
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
	pruneN(t, db, stream, class, 0)
}

// pruneN prunes stream's first n records, or all of them when n is 0.
func pruneN(t *testing.T, db *DB, stream c5.StreamID, class c5.StreamClass, n int) {
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
	if n > 0 {
		if _, err := db.PruneStep(bg, b, n); err != nil {
			t.Fatal(err)
		}
		return
	}
	for {
		n, err := db.PruneStep(bg, b, 100)
		if err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			return
		}
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

// D6's F1 on #601 and D1's ruling: network-full is raised once per fill.
// A prune elsewhere in the database leaves a full class full, though it
// is below its quota by less than one record, so refused commits after
// each of several observation prunes raise no second alarm. A prune that
// frees at least MinRecordBytes of the class re-arms it, and the next fill
// raises the second.
func TestNetworkFullOncePerFill(t *testing.T) {
	a := &alarms{}
	db := open1(t, storeDir(t), networkDB(8<<20, c5.MinRecordBytes), a)
	fills := func() (n int) {
		for _, x := range a.got {
			if x.Code == c5.AlarmNetworkFull {
				n++
			}
		}
		return n
	}
	n := 0
	fill := func() {
		t.Helper()
		var refused error
		for refused == nil && n < 100000 {
			n++
			_, refused = db.CommitBatch(bg, netAlert, []c5.Record{rec(netAlert, c5.ClassNetworkAlert, n)})
		}
		if !isCode(refused, c5.CodeQuotaReached) {
			t.Fatalf("after %d alerts: %v, want CodeQuotaReached", n, refused)
		}
	}
	fill()
	for i := 1; i <= 5; i++ {
		commit1(t, db, rec(netObs, c5.ClassNetworkObservation, i))
		pruneAll(t, db, netObs, c5.ClassNetworkObservation)
		n++
		if _, err := db.CommitBatch(bg, netAlert, []c5.Record{rec(netAlert, c5.ClassNetworkAlert, n)}); !isCode(err, c5.CodeQuotaReached) {
			t.Fatalf("after observation prune %d: %v, want CodeQuotaReached", i, err)
		}
	}
	if f := fills(); f != 1 {
		t.Fatalf("%d network-full alarms for one fill with prunes elsewhere, want 1", f)
	}
	pruneAll(t, db, netAlert, c5.ClassNetworkAlert)
	fill()
	if f := fills(); f != 2 {
		t.Fatalf("%d network-full alarms after the class was pruned and filled again, want 2", f)
	}
}

// D1 on F1: a quota below MinRecordBytes, allowed for a class with no
// record cap, re-arms its full alarm only once the class is empty, since
// any record could fill it. A prune of one record leaves it full, and the
// refill raises no second alarm; a prune of every record re-arms it.
func TestSmallQuotaFullOncePerFill(t *testing.T) {
	const stream c5.StreamID = "platform/health"
	a := &alarms{}
	db := open1(t, storeDir(t), withQuota(evidenceDB, c5.ClassPlatform, 4<<10), a)
	fills := func() (n int) {
		for _, x := range a.got {
			if x.Code == c5.FullAlarm(c5.ClassPlatform) && x.Class == c5.ClassPlatform {
				n++
			}
		}
		return n
	}
	n := 0
	fill := func() {
		t.Helper()
		var refused error
		for refused == nil && n < 10000 {
			n++
			_, refused = db.CommitBatch(bg, stream, []c5.Record{rec(stream, c5.ClassPlatform, n)})
		}
		if !isCode(refused, c5.CodeQuotaReached) {
			t.Fatalf("after %d records: %v, want CodeQuotaReached", n, refused)
		}
	}
	fill()
	pruneN(t, db, stream, c5.ClassPlatform, 1)
	fill()
	if f := fills(); f != 1 {
		t.Fatalf("%d full alarms after a one-record prune and a refill, want 1", f)
	}
	pruneAll(t, db, stream, c5.ClassPlatform)
	fill()
	if f := fills(); f != 2 {
		t.Fatalf("%d full alarms after the class was emptied and filled again, want 2", f)
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

// Outside the network classes a capture keeps 0.8's accounting exactly
// (D6's R1 on #544): one charge, to the class that stored it first, ended
// when the row is deleted. Pruning in either order leaves no class negative
// and no charge behind.
func TestNonNetworkCaptureChargedOnceV09(t *testing.T) {
	for _, order := range [][]c5.StreamID{{"relay1/ser", "platform/health"}, {"platform/health", "relay1/ser"}} {
		t.Run(string(order[0])+" first", func(t *testing.T) {
			db := open1(t, storeDir(t), evidenceDB, nil)
			tr := capture("a collection run's transcript")
			size := int64(len(tr.Bytes))
			commit1(t, db, withCapture(rec("relay1/ser", c5.ClassAdapterEvidence, 1), tr))
			commit1(t, db, withCapture(rec("platform/health", c5.ClassPlatform, 1), tr))
			ser, health := payloadBytes(t, db, "relay1/ser"), payloadBytes(t, db, "platform/health")
			if got := classBytes(t, db, c5.ClassAdapterEvidence); got != ser+size {
				t.Fatalf("evidence class %d, want %d (its payload and the capture)", got, ser+size)
			}
			if got := classBytes(t, db, c5.ClassPlatform); got != health {
				t.Fatalf("platform class %d, want its payload %d: a second class charged for the capture", got, health)
			}
			class := map[c5.StreamID]c5.StreamClass{"relay1/ser": c5.ClassAdapterEvidence, "platform/health": c5.ClassPlatform}
			pruneAll(t, db, order[0], class[order[0]])
			wantSer, wantHealth := ser+size, health // the capture is still cited
			if order[0] == "relay1/ser" {
				wantSer = size
			} else {
				wantHealth = 0
			}
			if got := classBytes(t, db, c5.ClassAdapterEvidence); got != wantSer {
				t.Errorf("evidence class %d after the first prune, want %d", got, wantSer)
			}
			if got := classBytes(t, db, c5.ClassPlatform); got != wantHealth {
				t.Errorf("platform class %d after the first prune, want %d", got, wantHealth)
			}
			if !captureStored(t, db, tr.SHA256) {
				t.Fatal("capture deleted while a record cites it")
			}
			pruneAll(t, db, order[1], class[order[1]])
			for _, c := range []c5.StreamClass{c5.ClassAdapterEvidence, c5.ClassPlatform} {
				if got := classBytes(t, db, c); got != 0 {
					t.Errorf("%s class %d after both prunes, want 0", c, got)
				}
			}
			if captureStored(t, db, tr.SHA256) {
				t.Error("capture kept after its last citing record")
			}
		})
	}
}

// Discard keeps 0.8's accounting too: discarding the quarantined record
// that stored a capture another class still cites frees only its event,
// and the capture stays charged to its first class until its row goes.
func TestDiscardKeepsFirstChargeV09(t *testing.T) {
	d := evidenceDB
	d.Streams = append([]c5.StreamSpec{{ID: "quarantine/relay1", Class: c5.ClassAdapterEvidence}}, d.Streams...)
	db := open1(t, storeDir(t), d, nil)
	tr := capture("a collection run's transcript")
	size := int64(len(tr.Bytes))
	commit1(t, db, withCapture(rec("quarantine/relay1", c5.ClassAdapterEvidence, 1), tr))
	commit1(t, db, withCapture(rec("platform/health", c5.ClassPlatform, 1), tr))
	health := payloadBytes(t, db, "platform/health")
	payload := payloadBytes(t, db, "quarantine/relay1")
	out, err := db.Discard(bg, nil, "quarantine/relay1", []c5.Seq{1})
	if err != nil || out.Events != 1 {
		t.Fatalf("discard: %+v %v", out, err)
	}
	if out.Bytes != payload {
		t.Errorf("discarded %d bytes, want the event's %d: the capture is still cited", out.Bytes, payload)
	}
	if got := classBytes(t, db, c5.ClassAdapterEvidence); got != size {
		t.Errorf("evidence class %d after the discard, want the capture's %d", got, size)
	}
	if got := classBytes(t, db, c5.ClassPlatform); got != health {
		t.Errorf("platform class %d after the discard, want %d", got, health)
	}
	pruneAll(t, db, "platform/health", c5.ClassPlatform)
	for _, c := range []c5.StreamClass{c5.ClassAdapterEvidence, c5.ClassPlatform} {
		if got := classBytes(t, db, c); got != 0 {
			t.Errorf("%s class %d once the capture is deleted, want 0", c, got)
		}
	}
}

// S1 (D6 on #544): a capture written as a 0.8 binary writes it, with any
// id, is charged once, to its first class, whatever cites it later.
func TestLegacyInsertChargedOnceV09(t *testing.T) {
	db := open1(t, storeDir(t), evidenceDB, nil)
	tr := capture("stored by a 0.8 binary")
	size := int64(len(tr.Bytes))
	// 0.8's insert: the row with its first class, and that class charged.
	if _, err := db.conn.ExecContext(bg, `INSERT INTO captures (id, sha256, class, bytes) VALUES (?, ?, ?, ?)`,
		int64(1)<<40, tr.SHA256, string(c5.ClassAdapterEvidence), tr.Bytes); err != nil {
		t.Fatal(err)
	}
	if _, err := db.conn.ExecContext(bg, `INSERT INTO class_bytes (class, bytes) VALUES (?, ?)
		ON CONFLICT (class) DO UPDATE SET bytes = bytes + excluded.bytes`, string(c5.ClassAdapterEvidence), size); err != nil {
		t.Fatal(err)
	}
	commit1(t, db, withCapture(rec("relay1/ser", c5.ClassAdapterEvidence, 1), tr))
	commit1(t, db, withCapture(rec("platform/health", c5.ClassPlatform, 1), tr))
	if got, want := classBytes(t, db, c5.ClassAdapterEvidence), payloadBytes(t, db, "relay1/ser")+size; got != want {
		t.Fatalf("evidence class %d, want %d", got, want)
	}
	if got, want := classBytes(t, db, c5.ClassPlatform), payloadBytes(t, db, "platform/health"); got != want {
		t.Fatalf("platform class %d, want %d: charged for a 0.8 capture", got, want)
	}
	pruneAll(t, db, "platform/health", c5.ClassPlatform)
	pruneAll(t, db, "relay1/ser", c5.ClassAdapterEvidence)
	for _, c := range []c5.StreamClass{c5.ClassAdapterEvidence, c5.ClassPlatform} {
		if got := classBytes(t, db, c); got != 0 {
			t.Errorf("%s class %d after both prunes, want 0", c, got)
		}
	}
}

// S2 (D6 on #544): a class count that would go below zero fails its
// transaction, so a drift shows instead of letting the class past its
// quota.
func TestClassBytesNeverNegativeV09(t *testing.T) {
	db := open1(t, storeDir(t), evidenceDB, nil)
	commit1(t, db, rec("platform/health", c5.ClassPlatform, 1))
	before := classBytes(t, db, c5.ClassPlatform)
	err := db.tx(bg, "drift", func() error {
		return db.addClassBytes(bg, c5.ClassPlatform, -(before + 1))
	})
	if err == nil {
		t.Fatal("a count below zero was stored")
	}
	if got := classBytes(t, db, c5.ClassPlatform); got != before {
		t.Errorf("platform class %d after the failed update, want %d", got, before)
	}
	if err := db.tx(bg, "exact", func() error { return db.addClassBytes(bg, c5.ClassPlatform, -before) }); err != nil {
		t.Errorf("down to exactly zero: %v", err)
	}
}
