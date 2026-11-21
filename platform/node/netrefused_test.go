package node

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"otsec.local/otsec/contracts/event"
	"otsec.local/otsec/contracts/netobs"
	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/modules/detection/netdetect"
)

// C4 0.6 step 2, S2-a (brief P4-4-C4-06-S2; D1 on #772): the refusal
// classifier's malformed and detector-refused reasons, R1's
// network-observation-refused, observations_refused_by, the
// network-detector-not-restored fix, and L2's guard that detectorConfig
// sets no baseline (docs/phase4/D5-refusal-alarms-options.md sections 2,
// 3.2 and 4, tests T2, T3, T4 and T7). Desk only: the stored records are
// this build's own, edited by hand; no sensor wrote them and no device was
// contacted.

// otherSensor is a sensor that is not the node's.
const otherSensor = "11111111-2222-4333-8444-555555555555"

// refusalMarker is placed in a refused record, and must reach neither the
// status file nor the OS log.
const refusalMarker = "zzrefusalmarker"

// storeAfterCheckpoint runs the node over one valid flow of its own sensor,
// so the detector checkpoints past it, and calls build, with the node still
// running, for the events to store after it. It stops the node, stores
// them on the observation stream past this build's checks, calls edit with
// their seqs when it is not nil, starts the node again and ticks once, so
// the detector restores and reads them. The caller closes the node.
func storeAfterCheckpoint(t *testing.T, build func(r *Runtime, base []byte) [][]byte,
	edit func(c *Config, seqs []c5.Seq)) (*Runtime, *Status, *[]string, *Config, string) {
	t.Helper()
	c, dir := holdConfig(t)
	r, _, _ := start(t, c, dir)
	if err := r.ServeSensor(bg, sensorChannel(t, ownFlow(1))); err != nil {
		t.Fatal(err)
	}
	tick(t, r)
	obs := NetObservationStream(sensorID)
	got, err := r.Store(obs).Read(bg, obs, 0, 1)
	if err != nil || len(got) != 1 {
		t.Fatalf("%d observations: %v", len(got), err)
	}
	e, err := event.Decode(got[0].Event)
	if err != nil {
		t.Fatal(err)
	}
	e.ID.Seq = 0
	base, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	evs := build(r, base)
	r.Close()
	seqs := storeObservations(t, c, evs)
	if edit != nil {
		edit(c, seqs)
	}
	r, st, logged := start(t, c, dir)
	tick(t, r)
	return r, st, logged, c, dir
}

// storeObservations stores evs on the observation stream, with the node
// stopped, past this build's checks, and returns their seqs.
func storeObservations(t *testing.T, c *Config, evs [][]byte) []c5.Seq {
	t.Helper()
	var recs []c5.Record
	for _, b := range evs {
		recs = append(recs, c5.Record{Stream: NetObservationStream(sensorID), Class: c5.ClassNetworkObservation, Event: b})
	}
	return appendStoredAll(t, c, recs, c5.DocumentInfo{}, nil)
}

// editNetobs is base's event with its stored observation's members in set
// replaced, as laterMinor does, at the observation's own schema.
func editNetobs(t *testing.T, base []byte, set map[string]string) []byte {
	t.Helper()
	var e event.Event
	if err := json.Unmarshal(base, &e); err != nil {
		t.Fatal(err)
	}
	var head struct{ Schema string }
	if err := json.Unmarshal(e.Netobs, &head); err != nil {
		t.Fatal(err)
	}
	e.Netobs = laterMinor(t, e.Netobs, head.Schema, set)
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// storedObservation is the record at seq on the observation stream.
func storedObservation(t *testing.T, r *Runtime, seq c5.Seq) c5.Stored {
	t.Helper()
	obs := NetObservationStream(sensorID)
	got, err := r.Store(obs).Read(bg, obs, seq-1, 1)
	if err != nil || len(got) != 1 || got[0].Key.Seq != seq {
		t.Fatalf("%d records at %d: %v", len(got), seq, err)
	}
	return got[0]
}

// refusedAlarms are the details of the network-observation-refused alarms.
func refusedAlarms(st *Status) (out []string) {
	for _, a := range st.Snapshot("n").Alarms {
		if a.Code == AlarmObservationRefused {
			out = append(out, a.Detail)
		}
	}
	return out
}

// noMarker fails when the marker is in the status file or the OS log.
func noMarker(t *testing.T, st *Status, logged *[]string) {
	t.Helper()
	b, err := json.Marshal(st.Snapshot("n"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), refusalMarker) {
		t.Fatalf("the marker is in the status file: %s", b)
	}
	for _, l := range *logged {
		if strings.Contains(l, refusalMarker) {
			t.Fatalf("the marker is in the OS log: %s", l)
		}
	}
}

// T2, first leg: a stored record whose observation does not decode is
// refused under malformed, and the alarm names the error's code and field
// and the seq, never the record's text. Positive control, first: the
// marker is in observationOf's error string, so a mutant that put the
// error's text in the alarm would show it. Control: the valid record
// stored beside it is judged and not counted. Mutant: the error string put
// in the alarm's detail, which shows the marker.
func TestObservationRefusedMalformed(t *testing.T) {
	r, st, logged, _, _ := storeAfterCheckpoint(t, func(_ *Runtime, base []byte) [][]byte {
		return [][]byte{base, editNetobs(t, base, map[string]string{"first_utc": `"` + refusalMarker + `"`})}
	}, nil)
	defer r.Close()
	if _, err := observationOf(storedObservation(t, r, 3)); err == nil || !strings.Contains(err.Error(), refusalMarker) {
		t.Fatalf("positive control: observationOf's error %v does not hold the marker", err)
	}
	d := detectorStatus(t, st)
	got := refusedAlarms(st)
	if d.Through != 3 || d.Refused != 1 || d.RefusedBy[RefusedMalformed] != 1 || d.RefusedBy[RefusedByDetector] != 0 || len(got) != 1 ||
		!strings.Contains(got[0], "at netobs.first_utc)") || !strings.Contains(got[0], "First at seq 3.") {
		t.Fatalf("status %+v, alarms %q", d, got)
	}
	noMarker(t, st, logged)
}

// T2, second leg (D3's F4 on #766): a record whose error names a key of
// health.details, which C4's validator takes from the record, shows the
// map's name as the field, never the key. The store refuses such an event
// at commit, so a valid one is stored and its text then edited, as a disk
// fault would leave it. Positive control, first: the marker, the key, is
// in observationOf's error string. Mutant: the field not cut, or the error
// string in the detail, either of which shows it.
func TestObservationRefusedMapKey(t *testing.T) {
	const cause, marked = `"cause":"malformed"`, `"cause":"malformed","` + refusalMarker + `":"1"`
	r, st, logged, _, _ := storeAfterCheckpoint(t, func(r *Runtime, _ []byte) [][]byte {
		rec, err := r.healthEventRecord(NetObservationStream(sensorID), event.Health{Type: event.HealthBaselineRefused, Details: map[string]string{
			"hash": "sha256:" + strings.Repeat("ab", 32), "schema": event.BaselineSchemaUnreadable, "cause": "malformed"}})
		if err != nil {
			t.Fatal(err)
		}
		return [][]byte{rec.Event}
	}, func(c *Config, seqs []c5.Seq) {
		corruptEvent(t, c, NetObservationStream(sensorID), seqs[0], cause, marked)
	})
	defer r.Close()
	if _, err := observationOf(storedObservation(t, r, 2)); err == nil || !strings.Contains(err.Error(), refusalMarker) {
		t.Fatalf("positive control: observationOf's error %v does not hold the marker", err)
	}
	d := detectorStatus(t, st)
	got := refusedAlarms(st)
	if d.Through != 2 || d.RefusedBy[RefusedMalformed] != 1 || len(got) != 1 || !strings.Contains(got[0], " at health.details)") {
		t.Fatalf("status %+v, alarms %q", d, got)
	}
	noMarker(t, st, logged)
}

// T2, third and fourth legs (D3's B1 on #777): a record that observationOf
// refuses but that it still decodes, of the node's own sensor and with a
// readable first_utc, so Observe alone would judge it: a node.dst_asset
// that conflicts with the event's source.asset, and a port out of range.
// Each is refused, counted under malformed and never judged, so it raises
// no network alert. Control, first: observationOf returns the decoded
// observation beside its error. Mutant: observeTo's o = nil made a no-op,
// which judges the record and counts nothing.
func TestObservationRefusedNotJudged(t *testing.T) {
	for name, set := range map[string]map[string]string{
		"asset": {"node.dst_asset": `"99999999-8888-4777-8666-555555555555"`},
		"port":  {"ip.sport": `70000`},
	} {
		t.Run(name, func(t *testing.T) {
			var alerts int
			r, st, _, _, _ := storeAfterCheckpoint(t, func(r *Runtime, base []byte) [][]byte {
				alerts = storedAlerts(t, r)
				return [][]byte{editNetobs(t, base, set)}
			}, nil)
			defer r.Close()
			o, err := observationOf(storedObservation(t, r, 2))
			if err == nil || o == nil || o.SensorID != sensorID {
				t.Fatalf("control: observationOf gave %+v, %v", o, err)
			}
			d := detectorStatus(t, st)
			if d.Through != 2 || d.Refused != 1 || d.RefusedBy[RefusedMalformed] != 1 || len(refusedAlarms(st)) != 1 || storedAlerts(t, r) != alerts {
				t.Fatalf("status %+v, alarms %q, %d alerts stored, %d before", d, refusedAlarms(st), storedAlerts(t, r), alerts)
			}
		})
	}
}

// T3: a stored observation of another sensor is refused under
// detector-refused, and the alarm says so from the record, not from
// Observe's error. Control: the node's own sensor's record stored beside
// it is judged and not counted. The alarm is on the network database and
// the observation stream (D6's N3 on #777).
func TestObservationRefusedOtherSensor(t *testing.T) {
	r, st, logged, _, _ := storeAfterCheckpoint(t, func(_ *Runtime, base []byte) [][]byte {
		return [][]byte{editNetobs(t, base, map[string]string{"sensor_id": `"` + otherSensor + `"`}), base}
	}, nil)
	defer r.Close()
	d := detectorStatus(t, st)
	got := refusedAlarms(st)
	if d.Through != 3 || d.Refused != 1 || d.RefusedBy[RefusedByDetector] != 1 || d.RefusedBy[RefusedMalformed] != 0 || len(got) != 1 ||
		!strings.Contains(got[0], "(another sensor's)") || !strings.Contains(got[0], "First at seq 2.") {
		t.Fatalf("status %+v, alarms %q", d, got)
	}
	for _, a := range st.Snapshot("n").Alarms {
		if a.Code == AlarmObservationRefused && (a.Database != NetworkDB || a.Stream != string(NetObservationStream(sensorID))) {
			t.Fatalf("the alarm is on database %q, stream %q", a.Database, a.Stream)
		}
	}
	line := "otsec store " + string(NetworkDB) + ": " + AlarmObservationRefused + " "
	if !slices.ContainsFunc(*logged, func(l string) bool { return strings.HasPrefix(l, line) }) {
		t.Fatalf("no OS log line %q in %q", line, *logged)
	}
}

// T4 (R1): five refusals of one reason raise one alarm, and a second
// reason one more, each naming its first seq; every refusal is counted by
// reason. A restart raises it again at the first new refusal, since the
// alarm is once per process run, and the counts go on from the counts
// event (S2-bc). Mutant: a raise per record, which raises six.
func TestObservationRefusedOncePerReason(t *testing.T) {
	var bad []byte
	r, st, _, c, dir := storeAfterCheckpoint(t, func(_ *Runtime, base []byte) [][]byte {
		bad = editNetobs(t, base, map[string]string{"first_utc": `"` + refusalMarker + `"`})
		other := editNetobs(t, base, map[string]string{"sensor_id": `"` + otherSensor + `"`})
		return [][]byte{bad, bad, other, bad, bad, bad}
	}, nil)
	d := detectorStatus(t, st)
	got := refusedAlarms(st)
	if d.Through != 7 || d.Refused != 6 || d.RefusedBy[RefusedMalformed] != 5 || d.RefusedBy[RefusedByDetector] != 1 || len(got) != 2 ||
		!strings.Contains(got[0], "First at seq 2.") || !strings.Contains(got[1], "First at seq 4.") {
		t.Fatalf("status %+v, alarms %q", d, got)
	}
	r.Close()
	storeObservations(t, c, [][]byte{bad})
	r, st, _ = start(t, c, dir)
	defer r.Close()
	tick(t, r)
	if d, got := detectorStatus(t, st), refusedAlarms(st); d.RefusedBy[RefusedMalformed] != 6 || len(got) != 1 || !strings.Contains(got[0], "First at seq 8.") {
		t.Fatalf("after a restart: status %+v, alarms %q", d, got)
	}
}

// T7, first leg (section 4): a checkpoint that does not restore, followed
// by fresh starts that fail for three ticks at their last step that can
// fail (D6's N1 on #777), raises no not-restored and one not-started, whose
// text holds the restore's own error (N2); the start that then succeeds
// raises exactly one not-restored, which holds it too. Mutant: the raise
// put anywhere before that step, which raises it at every try.
func TestDetectorNotRestoredOnceStarted(t *testing.T) {
	c, dir := holdConfig(t)
	r, _, _ := start(t, c, dir)
	if err := r.ServeSensor(bg, sensorChannel(t, ownFlow(1))); err != nil {
		t.Fatal(err)
	}
	tick(t, r)
	foreignCheckpoint(t, r)
	r.Close()
	var tries, left atomic.Int64
	left.Store(1 << 40)
	t.Cleanup(func() { rebuildIndex = (*Runtime).rebuildFrameIndex })
	rebuildIndex = func(r *Runtime, ctx context.Context, nd *netDetector) error {
		tries.Add(1)
		if left.Load() > 0 {
			return errors.New("test: the fresh start fails")
		}
		return r.rebuildFrameIndex(ctx, nd)
	}
	r, st, _ := start(t, c, dir)
	defer r.Close()
	for range 3 {
		tick(t, r)
	}
	var down bool
	heldManager(r, func() { down = r.detector == nil })
	// restoreErr is RestoreDetector's own text for foreignCheckpoint's node.
	const restoreErr = "site-b-node1"
	started := adminAlarm(st, AlarmDetectorNotStarted)
	if tries.Load() < 4 || !down || countAlarms(st, AlarmDetectorNotRestored) != 0 || countAlarms(st, AlarmDetectorNotStarted) != 1 ||
		!strings.Contains(started, "the stored checkpoint did not restore either: ") || !strings.Contains(started, restoreErr) {
		t.Fatalf("%d tries, detector down %v, %d not-restored, %d not-started %q", tries.Load(), down,
			countAlarms(st, AlarmDetectorNotRestored), countAlarms(st, AlarmDetectorNotStarted), started)
	}
	left.Store(0)
	tick(t, r)
	tick(t, r)
	d := detectorStatus(t, st)
	restored := adminAlarm(st, AlarmDetectorNotRestored)
	if d.Restored || d.Through != 1 || !strings.Contains(restored, restoreErr) || countAlarms(st, AlarmDetectorNotStarted) != 1 {
		t.Fatalf("after the start succeeds: status %+v, %d not-restored %q, %d not-started", d,
			countAlarms(st, AlarmDetectorNotRestored), restored, countAlarms(st, AlarmDetectorNotStarted))
	}
}

// L2 (section 3.2): network-baseline-refused lands with the change that
// puts the approved baseline into detectorConfig (T8 and T9 are owed by
// it), so until then detectorConfig sets none and NewDetector takes the
// no-baseline branch, which cannot refuse a baseline. Control: the running
// detector's own configuration, built by startDetector, has none either.
// Mutant: a baseline set in detectorConfig, which fails both.
func TestDetectorConfigNoBaseline(t *testing.T) {
	c, dir := holdConfig(t)
	r, _, _ := start(t, c, dir)
	defer r.Close()
	tick(t, r)
	var cfg, running netdetect.DetectorConfig
	heldManager(r, func() {
		cfg = r.detectorConfig()
		if r.detector != nil {
			running = r.detector.cfg
		}
	})
	if cfg.SensorID != sensorID || cfg.Baseline != nil || running.SensorID != sensorID || running.Baseline != nil {
		t.Fatalf("detectorConfig sensor %q, baseline %d bytes; running sensor %q, baseline %d bytes", cfg.SensorID, len(cfg.Baseline),
			running.SensorID, len(running.Baseline))
	}
}

// refusalAt reads the first typed error of a join or of a single wrap
// (D6's N4 on #777), cuts a health.details key to the map's name, and
// gives "-" for an untyped error.
func TestRefusalAt(t *testing.T) {
	for _, tc := range []struct {
		err         error
		code, field string
	}{
		{errors.Join(errors.New("x"), &netobs.Error{Code: netobs.CodeForm, Field: "first_utc"}, &event.Error{Code: event.CodeEnum, Field: "kind"}), "form", "first_utc"},
		{&event.Error{Code: event.CodeEnum, Field: "health.details." + refusalMarker}, "enum", "health.details"},
		{fmt.Errorf("x: %w", &netobs.Error{Code: netobs.CodeForm, Field: "ip.sport"}), "form", "ip.sport"},
		{errors.New(refusalMarker), "-", "-"},
	} {
		if code, field := refusalAt(tc.err); code != tc.code || field != tc.field {
			t.Errorf("%v: %s at %s, want %s at %s", tc.err, code, field, tc.code, tc.field)
		}
	}
}
