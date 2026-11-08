package node

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"slices"
	"testing"

	"otsec.local/otsec/contracts/authz"
	"otsec.local/otsec/contracts/event"
	"otsec.local/otsec/contracts/netobs"
	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/platform/sensorlink"
)

// The detector consumer (P4-4-B5, PR B2, D1 in D4-74). Desk only: the
// observations are constructed C13 records, no sensor produced them, and
// no device was contacted.

// spoofFlow is a flow start from the node's address 192.0.2.10 to the
// relay's run endpoint, on the node's VLAN 10, sent from a MAC that is not
// the node's, and tied to no run: the detector raises node-address-spoofed
// and own-session-outside-record on it. With data it is a first sight whose
// one frame is data; without, a later flow citing frame.
func spoofFlow(seq int, data []byte, frame string) *netobs.Observation {
	o := sensorFlow(seq, sensorID)
	p := 2323
	o.IP.Src, o.IP.Dst, o.IP.Dport = "192.0.2.10", "127.0.0.1", &p
	o.Protocol, o.Coverage.Decodes = "unknown", []string{}
	if data != nil {
		sum := sha256.Sum256(data)
		frame = hex.EncodeToString(sum[:])
		o.FirstSight = true
		o.Frames = []netobs.Frame{{N: int64(seq), TS: o.FirstUTC, Data: base64.StdEncoding.EncodeToString(data)}}
	}
	o.Citation.Frames = []netobs.CitedFrame{{N: int64(seq), CapturedLen: 74, WireLen: 74, SHA256: frame}}
	return o
}

// frameData is a 74-byte frame that differs by n.
func frameData(n byte) []byte {
	b := make([]byte, 74)
	for i := range b {
		b[i] = byte(i) ^ n
	}
	return b
}

// storedAlert is a committed alert with its capture's frames.
type storedAlert struct {
	seq    c5.Seq
	alert  *netobs.Alert
	frames []sensorlink.CaptureFrame
}

// committedAlerts are the alerts on the alert stream, with their captures.
func committedAlerts(t *testing.T, r *Runtime) (out []storedAlert) {
	t.Helper()
	stream := NetAlertStream(sensorID)
	db := r.Store(stream)
	got, err := db.Read(bg, stream, 0, 1000)
	if err != nil {
		t.Fatal(err)
	}
	for _, st := range got {
		e, err := event.Decode(st.Event)
		if err != nil {
			t.Fatal(err)
		}
		a, err := netobs.AlertFromEvent(e)
		if err != nil {
			t.Fatal(err)
		}
		sa := storedAlert{seq: st.Key.Seq, alert: a}
		if st.EvidenceRef != "" {
			c, err := db.ReadCapture(bg, st.EvidenceRef)
			if err != nil {
				t.Fatal(err)
			}
			if sa.frames, err = sensorlink.ParseCapture(c.Bytes); err != nil {
				t.Fatal(err)
			}
		}
		out = append(out, sa)
	}
	return out
}

// laterFlow is spoofFlow at 10:20, past the windows the 10:00 flows open,
// so it closes them.
func laterFlow(seq int, frame string) *netobs.Observation {
	o := spoofFlow(seq, nil, frame)
	o.FirstUTC, o.LastUTC = "2026-11-07T10:20:00.000001Z", "2026-11-07T10:20:00.120001Z"
	return o
}

// hashOf is data's SHA-256 in hex.
func hashOf(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// detectorStatus is the detector's part of status.
func detectorStatus(t *testing.T, st *Status) DetectorStatus {
	t.Helper()
	s := st.Snapshot("x").Sensor
	if s == nil || s.Detector == nil {
		t.Fatalf("no detector in status: %+v", s)
	}
	return *s.Detector
}

// detectorCheckpoints are the stored netcheckpoint.detector seqs.
func detectorCkpts(t *testing.T, r *Runtime) []c5.Seq {
	t.Helper()
	seqs, _, err := r.detectorCheckpoints(bg)
	if err != nil {
		t.Fatal(err)
	}
	return seqs
}

// detectorCursor is the detector consumer's stored cursor.
func detectorCursor(t *testing.T, r *Runtime) c5.Seq {
	t.Helper()
	stream := NetObservationStream(sensorID)
	cs, err := r.Store(stream).LoadCursors(bg, stream)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cs {
		if c.Consumer == DetectorConsumer {
			return c.Through
		}
	}
	return 0
}

// An alert commits on the alert stream with a capture of the cited frames
// the node holds, in citation order (C13 section 7.1). A first sight's
// alert holds its frame. A window that closes cites a frame no stored
// first sight holds, and a later hit's citing the first sight's frame:
// its capture holds that frame twice and frames_missing is 1. An alert
// whose only frame is missing has a header-only capture. Status counts the
// alerts with frames_missing above 0 (D1 in D4-74).
func TestDetectorAlertCapture(t *testing.T) {
	c, dir := holdConfig(t)
	r, st, _ := start(t, c, dir)
	defer r.Close()
	f1, gone := frameData(1), hashOf(frameData(2))
	if err := r.ServeSensor(bg, sensorChannel(t, spoofFlow(1, f1, ""), spoofFlow(2, nil, gone), spoofFlow(3, nil, hashOf(f1)), laterFlow(4, gone))); err != nil {
		t.Fatal(err)
	}
	r.Tick(bg)
	got := committedAlerts(t, r)
	type want struct {
		rule    netobs.Rule
		missing int64
		frames  int
	}
	wants := []want{{netobs.RuleOwnSessionOutsideRecord, 0, 1}, {netobs.RuleNodeAddressSpoofed, 0, 1},
		{netobs.RuleNodeAddressSpoofed, 1, 2}, {netobs.RuleOwnSessionOutsideRecord, 1, 2},
		{netobs.RuleOwnSessionOutsideRecord, 1, 0}, {netobs.RuleNodeAddressSpoofed, 1, 0}}
	if len(got) != len(wants) {
		t.Fatalf("%d alerts, want %d", len(got), len(wants))
	}
	for i, w := range wants {
		a := got[i]
		if a.alert.Rule != w.rule || a.alert.FramesMissing != w.missing || len(a.frames) != w.frames {
			t.Errorf("alert %d: %s, %d missing, %d frames; want %+v", i, a.alert.Rule, a.alert.FramesMissing, len(a.frames), w)
		}
		for _, f := range a.frames {
			if string(f.Data) != string(f1) || f.WireLen != len(f1) {
				t.Errorf("alert %d: a frame that is not the first sight's", i)
			}
		}
	}
	if d := detectorStatus(t, st); d.Alerts != 6 || d.AlertsFramesMissing != 4 || d.AlertsNotStored != 0 || d.Through != 4 {
		t.Fatalf("status %+v", d)
	}
}

// A cited frame whose capture the index names, but whose bytes there don't
// hash to the cite, counts as missing, as one whose capture is gone does
// (D1 in D4-74). Desk: the index entry is set by hand.
func TestDetectorFrameHashMismatch(t *testing.T) {
	c, dir := holdConfig(t)
	r, _, _ := start(t, c, dir)
	defer r.Close()
	f1, f2 := frameData(1), frameData(2)
	if err := r.ServeSensor(bg, sensorChannel(t, spoofFlow(1, f1, ""))); err != nil {
		t.Fatal(err)
	}
	r.Tick(bg)
	nd := r.detector
	ref := nd.index.at[hashOf(f1)]
	if ref == "" {
		t.Fatal("the first sight's frame is not indexed")
	}
	nd.index.add(hashOf(f2), ref) // f2 named in f1's capture, which lacks it
	a := &netobs.Alert{Cites: []netobs.Cite{{Frames: []netobs.CiteFrame{{SHA256: hashOf(f2)}, {SHA256: hashOf(f1)}}}}}
	capture, missing, err := r.alertCapture(bg, nd, a)
	if err != nil {
		t.Fatal(err)
	}
	frames, err := sensorlink.ParseCapture(capture.Bytes)
	if err != nil || missing != 1 || len(frames) != 1 || string(frames[0].Data) != string(f1) {
		t.Fatalf("capture: %d frames, %d missing, %v", len(frames), missing, err)
	}
}

// The detector checkpoints at a tick where it moved, then moves its cursor
// to the checkpoint's Through, then removes the older checkpoints: one
// stays. A checkpoint over item 3's ceiling is not stored, the cursor
// stays, the alarm is raised once, and status counts each failure (D1 in
// D4-74).
func TestDetectorCheckpointCursor(t *testing.T) {
	c, dir := ceilingConfig(t)
	r, st, _ := start(t, c, dir)
	defer r.Close()
	if n := len(detectorCkpts(t, r)); n != 1 {
		t.Fatalf("%d checkpoints after start, want the first start's", n)
	}
	for i := 1; i <= 2; i++ {
		if err := r.ServeSensor(bg, sensorChannel(t, spoofFlow(i, frameData(byte(i)), ""))); err != nil {
			t.Fatal(err)
		}
		r.Tick(bg)
		if seqs := detectorCkpts(t, r); len(seqs) != 1 || detectorCursor(t, r) != c5.Seq(i) {
			t.Fatalf("after observation %d: checkpoints %v, cursor %d", i, seqs, detectorCursor(t, r))
		}
	}
	r.Tick(bg)
	if d := detectorStatus(t, st); d.CheckpointsWritten != 3 || d.Checkpointed != 2 {
		t.Fatalf("a tick that didn't move wrote a checkpoint: %+v", d)
	}
	fillCeiling(t, r, c)
	before := detectorCkpts(t, r)
	for i := 3; i <= 4; i++ {
		if err := r.ServeSensor(bg, sensorChannel(t, spoofFlow(i, frameData(byte(i)), ""))); err != nil {
			t.Fatal(err)
		}
		r.Tick(bg)
	}
	d := detectorStatus(t, st)
	if seqs := detectorCkpts(t, r); !slices.Equal(seqs, before) || detectorCursor(t, r) != 2 || d.Through != 4 || d.Checkpointed != 2 ||
		d.CheckpointFailures != 2 || countAlarms(st, AlarmDetectorCheckpoint) != 1 {
		t.Fatalf("checkpoints %v (were %v), cursor %d, status %+v, %d alarms", seqs, before, detectorCursor(t, r), d, countAlarms(st, AlarmDetectorCheckpoint))
	}
}

// A crash after an alert commits and before the checkpoint that covers it
// gives one alert: the restart restores from the last checkpoint, here the
// first start's, reads the observation again, and holds back the alert it
// raises again (D1 in D4-74). The crash is the checkpoint refused at item
// 3's ceiling.
func TestDetectorReplayNoDuplicate(t *testing.T) {
	c, dir := ceilingConfig(t)
	r, _, _ := start(t, c, dir)
	fillCeiling(t, r, c)
	if err := r.ServeSensor(bg, sensorChannel(t, spoofFlow(1, frameData(1), ""))); err != nil {
		t.Fatal(err)
	}
	r.Tick(bg)
	if n := len(committedAlerts(t, r)); n != 2 || detectorCursor(t, r) != 0 {
		t.Fatalf("%d alerts before the crash, cursor %d", n, detectorCursor(t, r))
	}
	r.Close()

	r, st, _ := start(t, c, dir)
	defer r.Close()
	r.Tick(bg)
	d := detectorStatus(t, st)
	if n := len(committedAlerts(t, r)); n != 2 || !d.Restored || d.Through != 1 || d.Mismatches != 0 || d.Alerts != 0 {
		t.Fatalf("%d alerts after the restart, status %+v", n, d)
	}
}

// A first start over a pruned observation stream skips a session that
// started before the first observation it reads, for before-retained (D1
// in D4-74). The skip is the last thing the detector takes before its
// checkpoint, and a restart that hands the session over again finds it
// taken: no ordering fault, and no own-session-unseen once its window
// passes. Desk: the stream's pruning is set by hand.
func TestDetectorTrailingSkip(t *testing.T) {
	c, dir := holdConfig(t)
	r, st, _ := start(t, c, dir)
	r.detector.pruned = true
	if err := r.ServeSensor(bg, sensorChannel(t, ownFlow(1))); err != nil {
		t.Fatal(err)
	}
	r.Tick(bg)
	// The run started an hour before the observation at 09:15, and its
	// flows are taken to be pruned. Its collection.run comes at a tick
	// that reads no observation.
	s := newScheduler(t, r, &fakeCollector{})
	if !s.health(bg, HealthCollectionRun, c.Schedule[0], "r-1", okInvocation, map[string]string{"endpoint": "127.0.0.1:2323", "l4": "tcp",
		"started_at": "2026-10-24T08:15:00Z", "ended_at": "2026-10-24T08:15:01Z", "connected": "true", "open_flow": "false", "after_seq": "1"}) {
		t.Fatal("collection.run not stored")
	}
	r.Tick(bg)
	if d := detectorStatus(t, st); d.NotJudged["before-retained"] != 1 || d.OrderingFaults != 0 || d.Checkpointed != 1 || d.CheckpointsWritten != 3 || d.CheckpointFailures != 0 {
		t.Fatalf("status %+v", d)
	}
	r.Close()

	r, st, _ = start(t, c, dir)
	defer r.Close()
	later := ownFlow(2)
	later.FirstUTC, later.LastUTC = "2026-10-24T11:15:00.100000Z", "2026-10-24T11:15:00.200000Z"
	if err := r.ServeSensor(bg, sensorChannel(t, later)); err != nil {
		t.Fatal(err)
	}
	r.Tick(bg)
	d := detectorStatus(t, st)
	for _, a := range committedAlerts(t, r) {
		if a.alert.Rule == netobs.RuleOwnSessionUnseen {
			t.Errorf("the skipped session alerted after the restart: %+v", a.alert)
		}
	}
	if !d.Restored || d.OrderingFaults != 0 || d.NotJudged["before-retained"] != 0 || d.Through != 2 {
		t.Fatalf("after the restart: %+v", d)
	}
}

// The handover barrier: while a run's release has committed and its
// collection.run hasn't, the detector reads no observation past the run's
// after_seq, so the session, handed over once it commits, is never an
// ordering fault (D4's finding 4 on #576). Desk: the run in flight is set
// by hand, as resultHold sets it.
func TestDetectorHandoverBarrier(t *testing.T) {
	c, dir := holdConfig(t)
	r, st, _ := start(t, c, dir)
	defer r.Close()
	if err := r.ServeSensor(bg, sensorChannel(t, ownFlow(1))); err != nil {
		t.Fatal(err)
	}
	r.intake.enter("r-1", 1, true) // released, its after_seq 1
	later := ownFlow(2)
	later.FirstUTC, later.LastUTC = "2026-10-24T09:15:05.100000Z", "2026-10-24T09:15:05.200000Z"
	if err := r.ServeSensor(bg, sensorChannel(t, later)); err != nil {
		t.Fatal(err)
	}
	r.Tick(bg)
	if d := detectorStatus(t, st); d.Through != 1 {
		t.Fatalf("the detector passed the barrier: through %d", d.Through)
	}
	s := newScheduler(t, r, &fakeCollector{})
	if !s.health(bg, HealthCollectionRun, c.Schedule[0], "r-1", okInvocation, map[string]string{"endpoint": "127.0.0.1:2323", "l4": "tcp",
		"started_at": "2026-10-24T09:15:00Z", "ended_at": "2026-10-24T09:15:01Z", "connected": "true", "open_flow": "false", "after_seq": "1"}) {
		t.Fatal("collection.run not stored")
	}
	r.intake.leave("r-1")
	r.Tick(bg)
	if d := detectorStatus(t, st); d.Through != 2 || d.OrderingFaults != 0 || countAlarms(st, AlarmDetectorOrdering) != 0 {
		t.Fatalf("status %+v", d)
	}
}

// The barrier holds from before a run's release: a tick between the
// release's commit and the run's entry at its after_seq stops at the head
// before the release, so a flow committed after the release isn't read
// before the session is handed over (D4's finding 4 on #576). The run is
// the SEL-751 fixture's, as in TestIntakeRunSession.
func TestDetectorBarrierDuringRelease(t *testing.T) {
	c, dir := holdConfig(t)
	r, st, _ := start(t, c, dir)
	defer r.Close()
	r.afterRelease = func() {
		after := ownFlow(2)
		after.FirstUTC, after.LastUTC = "2026-10-24T09:15:05.100000Z", "2026-10-24T09:15:05.200000Z"
		*after.IP.Dport = 2324 // not the run's conversation
		if err := r.ServeSensor(bg, sensorChannel(t, after)); err != nil {
			t.Error(err)
		}
		r.Tick(bg)
	}
	result, transcript := figureOrderFrom(t, ok09Result)
	var seq uint64
	client := wireCollectorResult(t, result, transcript, func(*authz.CollectorRequest) {
		if err := r.ServeSensor(bg, sensorChannel(t, ownFlow(1))); err != nil {
			t.Error(err)
		}
	}, &seq)
	if rep := newScheduler(t, r, client).RunOnce(bg, 0); rep.Outcome != "ok" {
		t.Fatalf("run: %+v", rep)
	}
	r.afterRelease = nil
	r.Tick(bg)
	if d := detectorStatus(t, st); d.Through != 2 || d.OrderingFaults != 0 || countAlarms(st, AlarmDetectorOrdering) != 0 {
		t.Fatalf("status %+v", d)
	}
}
