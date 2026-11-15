package node

import (
	"database/sql"
	"encoding/json"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"otsec.local/otsec/contracts/event"
	"otsec.local/otsec/contracts/netobs"
	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/platform/store"
)

// CH-35's bridge on the C13 0.1 code (P4-4-CC deliverable 1): the node's
// reading of what a node of a later minor stored before it was rolled back
// to this build. Desk only: the later-minor documents and records are this
// build's own, edited by hand to C13 0.2's text (C13 0.2 section 11); no
// sensor or 0.2 node wrote them, and no device was contacted.

// appendStoredAs commits rec with the node stopped, past this build's
// configuration document check, as a build of a later minor would have,
// with info as the document's kind and series; then it removes the records
// of info's series at remove, as that build's own checkpoint did. It
// returns rec's seq.
func appendStoredAs(t *testing.T, c *Config, rec c5.Record, info c5.DocumentInfo, remove []c5.Seq) c5.Seq {
	t.Helper()
	return appendStoredAll(t, c, []c5.Record{rec}, info, remove)[0]
}

// appendStoredAll is appendStoredAs for recs, all of one stream, committed
// in batches of 100, and returns their seqs.
func appendStoredAll(t *testing.T, c *Config, recs []c5.Record, info c5.DocumentInfo, remove []c5.Seq) []c5.Seq {
	t.Helper()
	rec := recs[0]
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
	var seqs []c5.Seq
	for b := range slices.Chunk(recs, 100) {
		rcs, err := log.AppendBatch(bg, b)
		if err != nil {
			t.Fatal(err)
		}
		for _, rc := range rcs {
			seqs = append(seqs, rc.Key().Seq)
		}
	}
	if len(remove) > 0 {
		if _, err := db.RemoveConfig(bg, rec.Stream, info.Series, remove); err != nil {
			t.Fatal(err)
		}
	}
	return seqs
}

// later02 rewrites a JSON object: schema to sch, and each of set's members
// added or replaced, with a key "a.b" naming member b of object a.
func later02(t *testing.T, doc []byte, sch string, set map[string]string) []byte {
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

// R-4 (C13 0.2 section 15; CH-35's bridge items 1 and 2): the bridge build
// restores its own 0.1 detector checkpoint with no alarm. Given the 0.2 one
// a rolled-forward node left, the only detector checkpoint in the store, it
// raises network-detector-not-restored, starts from the oldest retained
// observation and raises its alerts again, as CH-35 states, and removes the
// 0.2 document once its own first checkpoint commits. The next start
// restores from that one. The control is main's exact match on
// CheckpointIdentifier, which passes the 0.2 document over: a first start
// with no alarm, and the document never removed.
func TestDetectorBridgeLaterCheckpoint(t *testing.T) {
	c, dir := holdConfig(t)
	r, _, _ := start(t, c, dir)
	if err := r.ServeSensor(bg, sensorChannel(t, spoofFlow(1, frameData(1), ""))); err != nil {
		t.Fatal(err)
	}
	tick(t, r)
	if n := len(committedAlerts(t, r)); n != 2 {
		t.Fatalf("%d alerts, want 2", n)
	}
	r.Close()

	// Its own 0.1 checkpoint restores, with no alarm.
	r, st, _ := start(t, c, dir)
	tick(t, r)
	if d := detectorStatus(t, st); !d.Restored || d.Through != 1 || countAlarms(st, AlarmDetectorNotRestored) != 0 {
		t.Fatalf("0.1 restore: status %+v, %d alarms", d, countAlarms(st, AlarmDetectorNotRestored))
	}
	seqs, doc, err := r.detectorCheckpoints(bg)
	if err != nil || len(seqs) != 1 {
		t.Fatalf("checkpoints %v: %v", seqs, err)
	}
	r.Close()

	// A 0.2 node's checkpoint: the coverage carries 0.2's config_digest,
	// and the 0.1 one is gone, as that node's first checkpoint removed it.
	doc02 := later02(t, doc, "otsec.netcheckpoint/0.2", map[string]string{
		"coverage.config_digest": `"sha256:` + strings.Repeat("ab", 32) + `"`})
	if _, err := netobs.DecodeDetectorCheckpoint(doc02); err == nil {
		t.Fatal("this build reads the 0.2 checkpoint, so the test shows nothing")
	}
	v02 := appendStoredAs(t, c, c5.Record{Stream: r.intakeStream(), Class: c5.ClassConfiguration, Event: doc02},
		c5.DocumentInfo{Kind: c5.DocumentWorkingState, Series: c5.SeriesNetCheckpointDetector}, seqs)

	r, st, _ = start(t, c, dir)
	tick(t, r)
	d, now := detectorStatus(t, st), detectorCkpts(t, r)
	if countAlarms(st, AlarmDetectorNotRestored) != 1 || d.Restored || d.Through != 1 {
		t.Fatalf("0.2 checkpoint: status %+v, %d not-restored alarms", d, countAlarms(st, AlarmDetectorNotRestored))
	}
	if n := len(committedAlerts(t, r)); n != 4 {
		t.Fatalf("%d alerts after the restart from the oldest retained, want the 2 raised again", n)
	}
	if len(now) != 1 || now[0] <= v02 || slices.Contains(configSchemas(t, r), "otsec.netcheckpoint/0.2") {
		t.Fatalf("checkpoints %v (the 0.2 one %d), schemas %v", now, v02, configSchemas(t, r))
	}
	r.Close()

	r, st, _ = start(t, c, dir)
	defer r.Close()
	if d := detectorStatus(t, st); !d.Restored || d.Through != 1 || countAlarms(st, AlarmDetectorNotRestored) != 0 {
		t.Fatalf("after the bridge's own checkpoint: status %+v", d)
	}
}

// R-4's record legs (CH-35's bridge items 3 and 4, read by the node): a
// stored 0.2 alert keyed clock-skew, and one whose coverage.degraded holds
// a value this build does not know, are read by the restore and not
// skipped; a stored 0.2 observation with that value is taken by the
// detector and not refused. The controls are D4's on contracts/netobs:
// each value refused at every minor makes the restore skip the alert, or
// the detector refuse the observation.
func TestDetectorBridgeLaterRecords(t *testing.T) {
	c, dir := holdConfig(t)
	r, _, _ := start(t, c, dir)
	if err := r.ServeSensor(bg, sensorChannel(t, spoofFlow(1, frameData(1), ""))); err != nil {
		t.Fatal(err)
	}
	tick(t, r)
	alerts, obs := NetAlertStream(sensorID), NetObservationStream(sensorID)
	got, err := r.Store(alerts).Read(bg, alerts, 0, 1)
	if err != nil || len(got) != 1 {
		t.Fatalf("%d alerts: %v", len(got), err)
	}
	var recs []c5.Record
	for _, set := range []map[string]string{{"asset_id": "clock-skew"}, {"coverage.degraded": "drops-driver prp-late"}} {
		e, err := event.Decode(got[0].Event)
		if err != nil {
			t.Fatal(err)
		}
		e.ID.Seq, e.Health.Details["schema"] = 0, "otsec.netobs/0.2"
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
	e.Netobs = later02(t, e.Netobs, "otsec.netobs/0.2", map[string]string{"seq": `"2"`,
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
	corruptEvents(t, c, stream, seq, seq, old, new)
}

// corruptEvents is corruptEvent for each seq from seq to last.
func corruptEvents(t *testing.T, c *Config, stream c5.StreamID, seq, last c5.Seq, old, new string) {
	t.Helper()
	var n int64
	paths, _ := filepath.Glob(filepath.Join(c.Store.Dir, "*.db"))
	for _, p := range paths {
		db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(p)+"?_pragma=busy_timeout(5000)")
		if err != nil {
			t.Fatal(err)
		}
		if res, err := db.Exec(`UPDATE events SET event = CAST(replace(CAST(event AS TEXT), ?, ?) AS BLOB) WHERE stream = ? AND seq BETWEEN ? AND ?`,
			old, new, string(stream), int64(seq), int64(last)); err == nil {
			k, _ := res.RowsAffected()
			n += k
		}
		db.Close()
	}
	if n != int64(last-seq+1) {
		t.Fatalf("%d events of %s:%d to %d rewritten", n, stream, seq, last)
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
	h := healthHead(t, r)
	r.Close()
	// The control for the health events: a restore that skips none, and
	// the health events its stop and start commit (D6's N3 on #682).
	r, _, _ = start(t, c, dir)
	tick(t, r)
	clean := healthTypesAfter(t, r, h)
	h = healthHead(t, r)
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
	if got := healthTypesAfter(t, r, h); !slices.Equal(got, clean) {
		t.Fatalf("the stop and the start with the skip committed health events %q, the ones without it %q", got, clean)
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

// healthHead is the last seq on the health stream.
func healthHead(t *testing.T, r *Runtime) c5.Seq {
	t.Helper()
	h, err := r.Store(HealthStream).LastCommitted(bg, HealthStream)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// healthTypesAfter are the types of the health events committed after
// seq, of any type, sorted.
func healthTypesAfter(t *testing.T, r *Runtime, seq c5.Seq) []string {
	t.Helper()
	got, err := r.Store(HealthStream).Read(bg, HealthStream, seq, 10000)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, st := range got {
		e, err := event.Decode(st.Event)
		if err != nil || e.Health == nil {
			t.Fatalf("health record %d: %v", st.Key.Seq, err)
		}
		out = append(out, e.Health.Type)
	}
	slices.Sort(out)
	return out
}

// N-13's leg (2) at its bounds (D6's N1 and N2 on #682): exactly one
// unreadable alert after last_alert_seq is counted and alarmed, and 257,
// more than a read page (detectorReadPage), are all read past and each
// counted once, with the restore ending. The controls are the mutants
// skipped > 1, which hides the one, and after set only for an alert that
// reads, which reads the first page again and never ends the start.
func TestDetectorAlertUnreadableBounds(t *testing.T) {
	for _, n := range []int{1, detectorReadPage + 1} {
		t.Run(strconv.Itoa(n), func(t *testing.T) {
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
			recs := make([]c5.Record, n)
			for i := range recs {
				recs[i] = c5.Record{Stream: alerts, Class: c5.ClassNetworkAlert, Event: b}
			}
			seqs := appendStoredAll(t, c, recs, c5.DocumentInfo{}, nil)
			corruptEvents(t, c, alerts, seqs[0], seqs[n-1], `"type":"`+netobs.HealthAlert+`"`, `"type":"netobs.alerx"`)

			r, st, _ := start(t, c, dir)
			defer r.Close()
			tick(t, r)
			if d := detectorStatus(t, st); !d.Restored || d.AlertsUnreadable != int64(n) || countAlarms(st, AlarmAlertUnreadable) != 1 {
				t.Fatalf("status %+v, %d unreadable alarms", d, countAlarms(st, AlarmAlertUnreadable))
			}
		})
	}
}
