package node

import (
	"database/sql"
	"encoding/json"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"otsec.local/otsec/contracts/event"
	"otsec.local/otsec/contracts/netobs"
	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/platform/store"
)

// CH-35's bridge (P4-4-CC deliverable 1), kept by the C13 0.2 code for a
// later minor (C13 0.3 section 1.2; deliverable 2): the node's reading of
// what a node of a later minor stored before it was rolled back to this
// build, and of the 0.1 checkpoint it finds at the upgrade. Under the
// brief's "Later-minor legs move with the minor", the later minor is now
// 0.3. Desk only: the 0.1 and 0.3 documents and records are this build's
// own, edited by hand to C13 0.2 section 11's and C13 0.3 section 1.2's
// text; no sensor, 0.1 node or 0.3 node wrote them, and no device was
// contacted.

// appendStoredAs commits rec with the node stopped, past this build's
// configuration document check, as a build of a later minor would have,
// with info as the document's kind and series; then it removes the records
// of info's series at remove, as that build's own checkpoint did. It
// returns rec's seq.
func appendStoredAs(t *testing.T, c *Config, rec c5.Record, info c5.DocumentInfo, remove []c5.Seq) c5.Seq {
	t.Helper()
	layout, err := c.Layout()
	if err != nil {
		t.Fatal(err)
	}
	var spec c5.Database
	for _, d := range layout.Databases {
		for _, s := range d.Streams {
			if s.ID == rec.Stream {
				spec = d
			}
		}
	}
	env, err := store.NewEnv(store.Options{Dir: c.Store.Dir, Node: c.NodeID, Database: spec, Now: time.Now, WallMark: spec.ID == NetworkDB,
		Documents: func([]byte, *c5.Capture) (c5.DocumentInfo, error) { return info, nil }})
	if err != nil {
		t.Fatal(err)
	}
	unlock, err := env.Lock(bg)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	rs, err := env.Open(bg)
	if err != nil {
		t.Fatal(err)
	}
	db, _ := store.AsDB(rs)
	defer db.Close()
	if err := db.CheckSettings(bg); err != nil {
		t.Fatal(err)
	}
	last, err := db.LastCommitted(bg, rec.Stream)
	if err != nil {
		t.Fatal(err)
	}
	log, err := c5.NewLogFor(db, c.NodeID, spec, groupFor(spec, c5.DefaultGroup), map[c5.StreamID]c5.Seq{rec.Stream: last})
	if err != nil {
		t.Fatal(err)
	}
	rcs, err := log.AppendBatch(bg, []c5.Record{rec})
	if err != nil {
		t.Fatal(err)
	}
	if len(remove) > 0 {
		if _, err := db.RemoveConfig(bg, rec.Stream, info.Series, remove); err != nil {
			t.Fatal(err)
		}
	}
	return rcs[0].Key().Seq
}

// later02 rewrites a JSON object: schema to sch, and each of set's members
// added or replaced, with a key "a.b" naming member b of object a.
func laterMinor(t *testing.T, doc []byte, sch string, set map[string]string) []byte {
	t.Helper()
	var top map[string]json.RawMessage
	if err := json.Unmarshal(doc, &top); err != nil {
		t.Fatal(err)
	}
	top["schema"] = json.RawMessage(`"` + sch + `"`)
	for k, v := range set {
		outer, inner, nested := strings.Cut(k, ".")
		if !nested {
			top[k] = json.RawMessage(v)
			continue
		}
		var m map[string]json.RawMessage
		if err := json.Unmarshal(top[outer], &m); err != nil || m == nil {
			t.Fatalf("%s is not an object: %v", outer, err)
		}
		m[inner] = json.RawMessage(v)
		b, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		top[outer] = b
	}
	b, err := json.Marshal(top)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// configSchemas are the schemas of the documents on the intake's
// configuration stream, in order.
func configSchemas(t *testing.T, r *Runtime) []string {
	t.Helper()
	stream := r.intakeStream()
	got, err := r.Store(stream).Read(bg, stream, 0, 1000)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, st := range got {
		var head struct{ Schema string }
		if err := json.Unmarshal(st.Event, &head); err != nil {
			t.Fatal(err)
		}
		out = append(out, head.Schema)
	}
	return out
}

// ownCheckpoint runs a node over one spoofed flow, which raises its two
// alerts, and returns the stored detector checkpoints' seqs and the
// newest's document, written by this build.
func ownCheckpoint(t *testing.T, c *Config, dir string) ([]c5.Seq, []byte) {
	t.Helper()
	r, _, _ := start(t, c, dir)
	defer r.Close()
	if err := r.ServeSensor(bg, sensorChannel(t, spoofFlow(1, frameData(1), ""))); err != nil {
		t.Fatal(err)
	}
	tick(t, r)
	if n := len(committedAlerts(t, r)); n != 2 {
		t.Fatalf("%d alerts, want 2", n)
	}
	seqs, doc, err := r.detectorCheckpoints(bg)
	if err != nil || len(seqs) != 1 {
		t.Fatalf("checkpoints %v: %v", seqs, err)
	}
	return seqs, doc
}

// storedAlerts counts the records on the alert stream, read or not.
func storedAlerts(t *testing.T, r *Runtime) int {
	t.Helper()
	stream := NetAlertStream(sensorID)
	got, err := r.Store(stream).Read(bg, stream, 0, 1000)
	if err != nil {
		t.Fatal(err)
	}
	return len(got)
}

// The read of an older detector checkpoint at the upgrade: a 0.1 one (C13
// 0.2 CH-35's table, "Read"; P4-4-CC deliverable 2, D5's node leg) and a
// 0.2 one (N-13's leg (3); C13 0.3 sections 1.2 and 12). A node at this
// code, given the checkpoint an older node left, the only detector
// checkpoint in the store, restores from it with no alarm and raises no
// alert again, and its next checkpoint is otsec.netcheckpoint/0.3, after
// which the older document is gone. ConfigDocuments still refuses to write
// the older document: this build writes 0.3 only. The control is an exact
// match on the 0.3 identifier in detectorDocument, which passes the older
// document over: a first start that raises the two alerts again.
func TestDetectorReads01Checkpoint(t *testing.T) {
	readsOlderCheckpoint(t, netobs.CheckpointIdentifier01)
}

func TestDetectorReads02Checkpoint(t *testing.T) {
	readsOlderCheckpoint(t, netobs.CheckpointIdentifier02)
}

func readsOlderCheckpoint(t *testing.T, schema string) {
	c, dir := holdConfig(t)
	seqs, doc := ownCheckpoint(t, c, dir)
	older := laterMinor(t, doc, schema, nil)
	if _, err := netobs.DecodeDetectorCheckpoint(older); err != nil {
		t.Fatalf("the %s document is not read strictly: %v", schema, err)
	}
	if _, err := ConfigDocuments(older, nil); err == nil {
		t.Fatalf("ConfigDocuments accepts a %s detector checkpoint for writing", schema)
	}
	vOld := appendStoredAs(t, c, c5.Record{Stream: NetBaselineStream(sensorID), Class: c5.ClassConfiguration, Event: older},
		c5.DocumentInfo{Kind: c5.DocumentWorkingState, Series: c5.SeriesNetCheckpointDetector}, seqs)

	r, st, _ := start(t, c, dir)
	defer r.Close()
	tick(t, r)
	if d := detectorStatus(t, st); !d.Restored || d.Through != 1 || countAlarms(st, AlarmDetectorNotRestored) != 0 {
		t.Fatalf("%s restore: status %+v, %d not-restored alarms", schema, d, countAlarms(st, AlarmDetectorNotRestored))
	}
	if n := storedAlerts(t, r); n != 2 {
		t.Fatalf("%d alerts, want the 2 held back", n)
	}
	if err := r.ServeSensor(bg, sensorChannel(t, spoofFlow(2, frameData(2), ""))); err != nil {
		t.Fatal(err)
	}
	tick(t, r)
	now := detectorCkpts(t, r)
	if got := configSchemas(t, r); len(now) != 1 || now[0] <= vOld || len(got) != 1 || got[0] != "otsec.netcheckpoint/0.3" {
		t.Fatalf("checkpoints %v (the %s one %d), schemas %v", now, schema, vOld, got)
	}
}

// R-4 (C13 0.2 section 15; CH-35's bridge items 1 and 2) and N-13's leg
// (1) (C13 0.3 sections 1.2 and 12), moved to 0.4 with the minor (the
// brief's "Later-minor legs move with the minor"): this build restores its
// own checkpoint with no alarm. Given the 0.4 one a rolled-forward node
// left, the only detector checkpoint in the store, and an
// own-session-mismatch alert that node stored, it raises
// network-detector-not-restored, starts from the oldest retained
// observation and raises its alerts again, as CH-35 states, removes the
// 0.4 document once its own first checkpoint commits, and keeps the 0.4
// alert. The next start restores from its own. The control is main's exact
// match on CheckpointIdentifier, which passes the 0.4 document over: a
// first start with no alarm, and the document never removed.
func TestDetectorLaterCheckpoint(t *testing.T) {
	c, dir := holdConfig(t)
	seqs, doc := ownCheckpoint(t, c, dir)

	// Its own checkpoint restores, with no alarm.
	r, st, _ := start(t, c, dir)
	tick(t, r)
	if d := detectorStatus(t, st); !d.Restored || d.Through != 1 || countAlarms(st, AlarmDetectorNotRestored) != 0 {
		t.Fatalf("own restore: status %+v, %d alarms", d, countAlarms(st, AlarmDetectorNotRestored))
	}
	alerts := NetAlertStream(sensorID)
	got, err := r.Store(alerts).Read(bg, alerts, 0, 1)
	if err != nil || len(got) != 1 {
		t.Fatalf("%d alerts: %v", len(got), err)
	}
	r.Close()

	// A 0.4 node's checkpoint, in this build's form, and an
	// own-session-mismatch alert it stored; the older checkpoint is gone,
	// as that node's first checkpoint removed it.
	doc04 := laterMinor(t, doc, "otsec.netcheckpoint/0.4", nil)
	if _, err := netobs.DecodeDetectorCheckpoint(doc04); err == nil {
		t.Fatal("this build reads the 0.4 checkpoint, so the test shows nothing")
	}
	v04 := appendStoredAs(t, c, c5.Record{Stream: NetBaselineStream(sensorID), Class: c5.ClassConfiguration, Event: doc04},
		c5.DocumentInfo{Kind: c5.DocumentWorkingState, Series: c5.SeriesNetCheckpointDetector}, seqs)
	e, err := event.Decode(got[0].Event)
	if err != nil {
		t.Fatal(err)
	}
	e.ID.Seq = 0
	e.Health.Details["schema"], e.Health.Details["rule"] = "otsec.netobs/0.4", "own-session-mismatch"
	if _, err := netobs.AlertFromEvent(e); err == nil {
		t.Fatal("this build reads the 0.4 alert, so the test shows nothing")
	}
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	appendStoredAs(t, c, c5.Record{Stream: alerts, Class: c5.ClassNetworkAlert, Event: b}, c5.DocumentInfo{}, nil)

	r, st, _ = start(t, c, dir)
	tick(t, r)
	d, now := detectorStatus(t, st), detectorCkpts(t, r)
	if countAlarms(st, AlarmDetectorNotRestored) != 1 || d.Restored || d.Through != 1 {
		t.Fatalf("0.4 checkpoint: status %+v, %d not-restored alarms", d, countAlarms(st, AlarmDetectorNotRestored))
	}
	if n := storedAlerts(t, r); n != 5 {
		t.Fatalf("%d alerts after the restart from the oldest retained, want the 2, the 0.4 one, and the 2 raised again", n)
	}
	if len(now) != 1 || now[0] <= v04 || slices.Contains(configSchemas(t, r), "otsec.netcheckpoint/0.4") {
		t.Fatalf("checkpoints %v (the 0.4 one %d), schemas %v", now, v04, configSchemas(t, r))
	}
	r.Close()

	r, st, _ = start(t, c, dir)
	defer r.Close()
	if d := detectorStatus(t, st); !d.Restored || d.Through != 1 || countAlarms(st, AlarmDetectorNotRestored) != 0 {
		t.Fatalf("after its own checkpoint: status %+v", d)
	}
	if n := eventsContaining(t, c, `"rule":"own-session-mismatch"`); n != 1 {
		t.Fatalf("%d stored own-session-mismatch alerts, want the 1 kept", n)
	}
}

// R-4's record legs (CH-35's bridge items 3 and 4, read by the node). The
// three asset_id values are 0.2's own now and do not move (the brief's
// "Later-minor legs move with the minor"): a stored 0.2 alert keyed
// clock-skew, with its assets, is read by the restore and not skipped. The
// unknown degraded value moves with the minor, to 0.4 now that this build
// is 0.3, whose own records refuse it strictly: a stored 0.4 alert whose
// coverage.degraded holds a value this build does not know is read and not
// skipped, and a stored 0.4 observation with that value is taken by the
// detector and not refused. The controls are D4's on contracts/netobs:
// each value refused at every minor makes the restore skip the alert, or
// the detector refuse the observation; and the value left at 0.3, this
// build's own minor, which the restore skips and the detector refuses.
func TestDetectorBridgeLaterRecords(t *testing.T) {
	c, dir := holdConfig(t)
	r, _, _ := start(t, c, dir)
	if err := r.ServeSensor(bg, sensorChannel(t, spoofFlow(1, frameData(1), ""))); err != nil {
		t.Fatal(err)
	}
	tick(t, r)
	alerts, obs := NetAlertStream(sensorID), NetObservationStream(sensorID)
	got, err := r.Store(alerts).Read(bg, alerts, 0, 2)
	if err != nil || len(got) != 2 {
		t.Fatalf("%d alerts: %v", len(got), err)
	}
	var outside []byte // the own-session-outside-record alert, the rule an aggregate key is for
	for _, st := range got {
		if strings.Contains(string(st.Event), `"rule":"`+string(netobs.RuleOwnSessionOutsideRecord)+`"`) {
			outside = st.Event
		}
	}
	if outside == nil {
		t.Fatal("no own-session-outside-record alert")
	}
	var recs []c5.Record
	for _, set := range []map[string]string{
		{"schema": netobs.Identifier02, "asset_id": netobs.AggregateClockSkew, "assets": relayID, "assets_total": "1"},
		{"schema": "otsec.netobs/0.4", "coverage.degraded": "drops-driver prp-late"}} {
		e, err := event.Decode(outside)
		if err != nil {
			t.Fatal(err)
		}
		e.ID.Seq = 0
		for k, v := range set {
			e.Health.Details[k] = v
		}
		b, err := json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		recs = append(recs, c5.Record{Stream: alerts, Class: c5.ClassNetworkAlert, Event: b})
	}
	o, err := r.Store(obs).Read(bg, obs, 0, 1)
	if err != nil || len(o) != 1 {
		t.Fatalf("%d observations: %v", len(o), err)
	}
	e, err := event.Decode(o[0].Event)
	if err != nil {
		t.Fatal(err)
	}
	e.ID.Seq = 0
	e.Netobs = laterMinor(t, e.Netobs, "otsec.netobs/0.4", map[string]string{"seq": `"2"`,
		"made_utc": `"2026-11-07T10:00:00.250000Z"`, "coverage.degraded": `["prp-late"]`})
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	recs = append(recs, c5.Record{Stream: obs, Class: c5.ClassNetworkObservation, Event: b})
	r.Close()
	// Stored with the node stopped, so its clean stop's checkpoint passes
	// none of them.
	for _, rec := range recs {
		appendStoredAs(t, c, rec, c5.DocumentInfo{}, nil)
	}

	r, st, _ := start(t, c, dir)
	defer r.Close()
	tick(t, r)
	d := detectorStatus(t, st)
	if !d.Restored || d.AlertsUnreadable != 0 || countAlarms(st, AlarmAlertUnreadable) != 0 || d.Through != 2 || d.Refused != 0 {
		t.Fatalf("status %+v, %d unreadable alarms", d, countAlarms(st, AlarmAlertUnreadable))
	}
}

// corruptEvent rewrites the stored event at stream and seq with the node
// stopped, replacing old by new in its text, as a disk fault or a record
// of another build would leave it.
func corruptEvent(t *testing.T, c *Config, stream c5.StreamID, seq c5.Seq, old, new string) {
	t.Helper()
	var n int64
	paths, _ := filepath.Glob(filepath.Join(c.Store.Dir, "*.db"))
	for _, p := range paths {
		db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(p)+"?_pragma=busy_timeout(5000)")
		if err != nil {
			t.Fatal(err)
		}
		if res, err := db.Exec(`UPDATE events SET event = CAST(replace(CAST(event AS TEXT), ?, ?) AS BLOB) WHERE stream = ? AND seq = ?`,
			old, new, string(stream), int64(seq)); err == nil {
			k, _ := res.RowsAffected()
			n += k
		}
		db.Close()
	}
	if n != 1 {
		t.Fatalf("%d events of %s:%d rewritten", n, stream, seq)
	}
}

// eventsContaining counts the stored events, in every database, whose
// text holds s.
func eventsContaining(t *testing.T, c *Config, s string) (n int64) {
	t.Helper()
	paths, _ := filepath.Glob(filepath.Join(c.Store.Dir, "*.db"))
	for _, p := range paths {
		db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(p)+"?_pragma=busy_timeout(5000)")
		if err != nil {
			t.Fatal(err)
		}
		var k int64
		if err := db.QueryRow(`SELECT count(*) FROM events WHERE CAST(event AS TEXT) LIKE ?`, "%"+s+"%").Scan(&k); err != nil {
			t.Fatal(err)
		}
		n += k
		db.Close()
	}
	return n
}

// N-13's leg (2) (C13 0.3 section 12; D4-102 item 5 (d)): a restore from a
// checkpoint it reads, with one alert after last_alert_seq that
// AlertFromEvent refuses and one that event.Decode refuses, skips both,
// counts 2 under detector_alerts_unreadable, raises
// network-alert-unreadable once, in status and the OS log, with no health
// event, holds neither back (no mismatch), and keeps both in the store. At
// the next restore, which skips none, the alarm is not raised and the
// count is 0. The control is main's alertsAfter, which fails the whole
// restore at the first.
func TestDetectorAlertUnreadableSkipped(t *testing.T) {
	c, dir := holdConfig(t)
	r, _, _ := start(t, c, dir)
	if err := r.ServeSensor(bg, sensorChannel(t, spoofFlow(1, frameData(1), ""))); err != nil {
		t.Fatal(err)
	}
	tick(t, r)
	alerts := NetAlertStream(sensorID)
	got, err := r.Store(alerts).Read(bg, alerts, 0, 1)
	if err != nil || len(got) != 1 {
		t.Fatalf("%d alerts: %v", len(got), err)
	}
	e, err := event.Decode(got[0].Event)
	if err != nil {
		t.Fatal(err)
	}
	e.ID.Seq = 0
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	r.Close()
	var bad []c5.Seq
	for range 2 {
		bad = append(bad, appendStoredAs(t, c, c5.Record{Stream: alerts, Class: c5.ClassNetworkAlert, Event: b}, c5.DocumentInfo{}, nil))
	}
	corruptEvent(t, c, alerts, bad[0], `"type":"`+netobs.HealthAlert+`"`, `"type":"netobs.alerx"`)
	corruptEvent(t, c, alerts, bad[1], `"schema":"`+event.Identifier+`"`, `"schema":"otsec.event/9.0"`)

	r, st, logged := start(t, c, dir)
	tick(t, r)
	d := detectorStatus(t, st)
	if !d.Restored || d.AlertsUnreadable != 2 || d.Mismatches != 0 || countAlarms(st, AlarmAlertUnreadable) != 1 ||
		countAlarms(st, AlarmDetectorNotRestored) != 0 {
		t.Fatalf("status %+v, %d unreadable alarms, %d not-restored", d, countAlarms(st, AlarmAlertUnreadable), countAlarms(st, AlarmDetectorNotRestored))
	}
	raw, err := r.Store(alerts).Read(bg, alerts, 0, 1000)
	if err != nil || len(raw) != 4 {
		t.Fatalf("%d alerts stored, want the 2 unreadable kept: %v", len(raw), err)
	}
	if e, err := event.Decode(raw[2].Event); err != nil {
		t.Fatalf("the first should fail AlertFromEvent only: %v", err)
	} else if _, err := netobs.AlertFromEvent(e); err == nil {
		t.Fatal("AlertFromEvent reads the first")
	}
	if _, err := event.Decode(raw[3].Event); err == nil {
		t.Fatal("event.Decode reads the second")
	}
	var inLog bool
	for _, l := range *logged {
		inLog = inLog || strings.Contains(l, AlarmAlertUnreadable+" the restore skipped 2 ")
	}
	if !inLog {
		t.Fatalf("not in the OS log: %q", *logged)
	}
	if n := eventsContaining(t, c, AlarmAlertUnreadable); n != 0 {
		t.Fatalf("%d stored events name %s; it writes no health event", n, AlarmAlertUnreadable)
	}

	// A checkpoint past the two, then a restore that skips none.
	if err := r.ServeSensor(bg, sensorChannel(t, spoofFlow(2, frameData(2), ""))); err != nil {
		t.Fatal(err)
	}
	tick(t, r)
	r.Close()
	r, st, _ = start(t, c, dir)
	defer r.Close()
	tick(t, r)
	if d := detectorStatus(t, st); !d.Restored || d.AlertsUnreadable != 0 || countAlarms(st, AlarmAlertUnreadable) != 0 {
		t.Fatalf("the next restore: status %+v, %d alarms", d, countAlarms(st, AlarmAlertUnreadable))
	}
}
