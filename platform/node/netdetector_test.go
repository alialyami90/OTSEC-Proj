package node

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"testing"
	"time"

	"otsec.local/otsec/contracts/authz"
	"otsec.local/otsec/contracts/event"
	"otsec.local/otsec/contracts/netobs"
	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/platform/node/nodeconfigtest"
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
	tick(t, r)
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
	tick(t, r)
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
		tick(t, r)
		if seqs := detectorCkpts(t, r); len(seqs) != 1 || detectorCursor(t, r) != c5.Seq(i) {
			t.Fatalf("after observation %d: checkpoints %v, cursor %d", i, seqs, detectorCursor(t, r))
		}
	}
	tick(t, r)
	if d := detectorStatus(t, st); d.CheckpointsWritten != 3 || d.Checkpointed != 2 {
		t.Fatalf("a tick that didn't move wrote a checkpoint: %+v", d)
	}
	fillCeiling(t, r, c)
	before := detectorCkpts(t, r)
	for i := 3; i <= 4; i++ {
		if err := r.ServeSensor(bg, sensorChannel(t, spoofFlow(i, frameData(byte(i)), ""))); err != nil {
			t.Fatal(err)
		}
		tick(t, r)
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
	tick(t, r)
	if n := len(committedAlerts(t, r)); n != 2 || detectorCursor(t, r) != 0 {
		t.Fatalf("%d alerts before the crash, cursor %d", n, detectorCursor(t, r))
	}
	r.Close()

	r, st, _ := start(t, c, dir)
	defer r.Close()
	tick(t, r)
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
	heldManager(r, func() { r.detector.pruned = true })
	if err := r.ServeSensor(bg, sensorChannel(t, ownFlow(1))); err != nil {
		t.Fatal(err)
	}
	tick(t, r)
	// The run started an hour before the observation at 09:15, and its
	// flows are taken to be pruned. Its collection.run comes at a tick
	// that reads no observation.
	s := newScheduler(t, r, &fakeCollector{})
	if !s.health(bg, HealthCollectionRun, c.Schedule[0], "r-1", okInvocation, map[string]string{"endpoint": "127.0.0.1:2323", "l4": "tcp",
		"started_at": "2026-10-24T08:15:00Z", "ended_at": "2026-10-24T08:15:01Z", "connected": "true", "open_flow": "false", "after_seq": "1"}) {
		t.Fatal("collection.run not stored")
	}
	tick(t, r)
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
	tick(t, r)
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
	tick(t, r)
	if d := detectorStatus(t, st); d.Through != 1 {
		t.Fatalf("the detector passed the barrier: through %d", d.Through)
	}
	s := newScheduler(t, r, &fakeCollector{})
	if !s.health(bg, HealthCollectionRun, c.Schedule[0], "r-1", okInvocation, map[string]string{"endpoint": "127.0.0.1:2323", "l4": "tcp",
		"started_at": "2026-10-24T09:15:00Z", "ended_at": "2026-10-24T09:15:01Z", "connected": "true", "open_flow": "false", "after_seq": "1"}) {
		t.Fatal("collection.run not stored")
	}
	r.intake.leave("r-1")
	tick(t, r)
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
		tick(t, r)
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
	tick(t, r)
	if d := detectorStatus(t, st); d.Through != 2 || d.OrderingFaults != 0 || countAlarms(st, AlarmDetectorOrdering) != 0 {
		t.Fatalf("status %+v", d)
	}
}

// An alert that isn't committed stays unsent: the detector reads nothing
// more, neither its checkpoint nor its cursor passes the alert, the alarm
// is raised once, and each tick tries again. Once the commit succeeds the
// alerts are stored in the order raised and the detector goes on (D1's F1
// on #590). Desk: the commit is refused by a test hook.
func TestDetectorAlertRetried(t *testing.T) {
	c, dir := holdConfig(t)
	r, st, _ := start(t, c, dir)
	defer r.Close()
	r.alertAppend = func([]c5.Record) error { return errors.New("refused") }
	if err := r.ServeSensor(bg, sensorChannel(t, spoofFlow(1, frameData(1), ""), laterFlow(2, hashOf(frameData(1))))); err != nil {
		t.Fatal(err)
	}
	tick(t, r)
	tick(t, r)
	d := detectorStatus(t, st)
	if n := len(committedAlerts(t, r)); n != 0 || d.Through != 1 || d.AlertsPending != 2 || d.AlertCommitFailures != 2 ||
		d.CheckpointsWritten != 1 || detectorCursor(t, r) != 0 || countAlarms(st, AlarmAlertNotStored) != 1 {
		t.Fatalf("%d alerts, cursor %d, status %+v, %d alarms", n, detectorCursor(t, r), d, countAlarms(st, AlarmAlertNotStored))
	}
	r.alertAppend = nil
	tick(t, r)
	got := committedAlerts(t, r)
	d = detectorStatus(t, st)
	if len(got) != 4 || got[0].alert.Rule != netobs.RuleOwnSessionOutsideRecord || got[1].alert.Rule != netobs.RuleNodeAddressSpoofed ||
		d.Through != 2 || d.AlertsPending != 0 || d.Alerts != 4 || detectorCursor(t, r) != 2 {
		t.Fatalf("%d alerts, cursor %d, status %+v", len(got), detectorCursor(t, r), d)
	}
}

// An alert still unsent at a stop is raised again by the restart's replay
// and stored once: the stop wrote no checkpoint past it (D1's F1 on #590).
func TestDetectorAlertUnsentAtStop(t *testing.T) {
	c, dir := holdConfig(t)
	r, _, _ := start(t, c, dir)
	r.alertAppend = func([]c5.Record) error { return errors.New("refused") }
	if err := r.ServeSensor(bg, sensorChannel(t, spoofFlow(1, frameData(1), ""))); err != nil {
		t.Fatal(err)
	}
	tick(t, r)
	r.Close()

	r, st, _ := start(t, c, dir)
	defer r.Close()
	tick(t, r)
	d := detectorStatus(t, st)
	if n := len(committedAlerts(t, r)); n != 2 || !d.Restored || d.Through != 1 || d.Mismatches != 0 || detectorCursor(t, r) != 1 {
		t.Fatalf("%d alerts after the restart, cursor %d, status %+v", n, detectorCursor(t, r), d)
	}
}

// D4's probe on #590: after a pruned start, the first record read is the
// fin end of a flow from 07:00 to 09:30, committed at 09:30. A session at
// 08:15 may have had its flows pruned, so it is skipped, for
// before-retained, and raises no own-session-unseen once its window
// passes. The guard's bound is the record's commit time, not its
// first_utc, which is the flow's start (D1 on #590). Desk: the stream's
// pruning is set by hand, and the times are relative to the commit.
func TestDetectorGuardCommitTime(t *testing.T) {
	c, dir := holdConfig(t)
	r, st, _ := start(t, c, dir)
	defer r.Close()
	heldManager(r, func() { r.detector.pruned = true })
	now := time.Now().UTC()
	at := func(d time.Duration) string { return now.Add(d).Format("2006-01-02T15:04:05.000000Z") }
	end := ownFlow(1)
	end.FirstUTC, end.LastUTC, end.Coverage.SinceUTC = at(-150*time.Minute), at(0), at(-4*time.Hour)
	no := false
	end.Flow.Phase, end.Flow.End, end.Flow.SynOnly = "end", "fin", &no
	if err := r.ServeSensor(bg, sensorChannel(t, end)); err != nil {
		t.Fatal(err)
	}
	s := newScheduler(t, r, &fakeCollector{})
	if !s.health(bg, HealthCollectionRun, c.Schedule[0], "r-1", okInvocation, map[string]string{"endpoint": "127.0.0.1:2323", "l4": "tcp",
		"started_at": at(-75 * time.Minute), "ended_at": at(-74 * time.Minute), "connected": "true", "open_flow": "false", "after_seq": "1"}) {
		t.Fatal("collection.run not stored")
	}
	later := ownFlow(2)
	later.FirstUTC, later.LastUTC, later.Coverage.SinceUTC = at(-10*time.Minute), at(-10*time.Minute+time.Second), at(-4*time.Hour)
	if err := r.ServeSensor(bg, sensorChannel(t, later)); err != nil {
		t.Fatal(err)
	}
	tick(t, r)
	for _, a := range committedAlerts(t, r) {
		if a.alert.Rule == netobs.RuleOwnSessionUnseen {
			t.Errorf("the session at 08:15 alerted: %+v", a.alert)
		}
	}
	if d := detectorStatus(t, st); d.NotJudged["before-retained"] != 1 || d.Through != 2 {
		t.Fatalf("status %+v", d)
	}
}

// An alert the store refuses for its class's quota or record cap is
// dropped and counted, and the detector goes on: its checkpoint and cursor
// move, as C5 0.9 section 8 drops a full class's records (D1 on #590).
func TestDetectorAlertDroppedAtQuota(t *testing.T) {
	for _, code := range []c5.Code{c5.CodeQuotaReached, c5.CodeRecordTooLarge} {
		t.Run(string(code), func(t *testing.T) {
			c, dir := holdConfig(t)
			r, st, _ := start(t, c, dir)
			defer r.Close()
			r.alertAppend = func([]c5.Record) error { return &c5.Error{Code: code} }
			if err := r.ServeSensor(bg, sensorChannel(t, spoofFlow(1, frameData(1), ""))); err != nil {
				t.Fatal(err)
			}
			tick(t, r)
			d := detectorStatus(t, st)
			if d.AlertsNotStored != 2 || d.AlertsPending != 0 || d.AlertCommitFailures != 0 || d.Through != 1 || d.Checkpointed != 1 ||
				detectorCursor(t, r) != 1 || countAlarms(st, AlarmAlertNotStored) != 1 {
				t.Fatalf("cursor %d, status %+v, %d alarms", detectorCursor(t, r), d, countAlarms(st, AlarmAlertNotStored))
			}
			reason := map[c5.Code]string{c5.CodeQuotaReached: sensorlink.DropClassFull, c5.CodeRecordTooLarge: sensorlink.DropRecordCap}[code]
			if s := st.Snapshot("x").Sensor; !maps.Equal(s.AlertsDropped, map[string]uint64{reason: 2}) || !maps.Equal(s.AlertsDroppedBy, spoofDrops(1)) {
				t.Fatalf("dropped %v, by (rule, asset) %v", s.AlertsDropped, s.AlertsDroppedBy)
			}
		})
	}
}

// spoofDrops are the drop counts by (rule, asset) of n spoofFlow alert
// pairs: the relay's endpoint is the destination.
func spoofDrops(n uint64) map[string]uint64 {
	return map[string]uint64{string(netobs.RuleOwnSessionOutsideRecord) + "." + relayID: n, string(netobs.RuleNodeAddressSpoofed) + "." + relayID: n}
}

// alertDropEvent is the last intake.drop-counted event of the alert
// stream's, or nil.
func alertDropEvent(t *testing.T, r *Runtime) map[string]string {
	t.Helper()
	got, err := r.Store(HealthStream).Read(bg, HealthStream, 0, 10000)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]string
	for _, st := range got {
		e, err := event.Decode(st.Event)
		if err != nil {
			t.Fatal(err)
		}
		if h := e.Health; h != nil && h.Type == event.HealthDropCounted && h.Details["stream"] == string(NetAlertStream(sensorID)) {
			out = h.Details
		}
	}
	return out
}

// AP-36 (3), desk: the alerts the store refuses at the class's quota are
// counted by (rule, asset) in status, beside network-full, and in an
// intake.drop-counted event of the alert class, and a clean stop and
// start keeps them. Desk: the store's refusal is a test hook; D6's row
// fills a real store.
func TestDetectorAlertDropsKept(t *testing.T) {
	c, dir := holdConfig(t)
	r, st, _ := start(t, c, dir)
	r.alertAppend = func([]c5.Record) error { return &c5.Error{Code: c5.CodeQuotaReached} }
	if err := r.ServeSensor(bg, sensorChannel(t, spoofFlow(1, frameData(1), ""))); err != nil {
		t.Fatal(err)
	}
	tick(t, r)
	det := alertDropEvent(t, r)
	want := map[string]string{"stream": string(NetAlertStream(sensorID)), "class": string(c5.ClassNetworkAlert), "count": "2", "reason." + sensorlink.DropClassFull: "2"}
	for k := range spoofDrops(1) {
		want[k] = "1"
	}
	since := st.Snapshot("x").Sensor.AlertDropsSince
	want["since"] = since.Format(time.RFC3339Nano)
	if !maps.Equal(det, want) {
		t.Fatalf("event %v, want %v", det, want)
	}
	r.Close()
	r, st, _ = start(t, c, dir)
	defer r.Close()
	s := st.Snapshot("x").Sensor
	if !maps.Equal(s.AlertsDropped, map[string]uint64{sensorlink.DropClassFull: 2}) || !maps.Equal(s.AlertsDroppedBy, spoofDrops(1)) || !s.AlertDropsSince.Equal(since) {
		t.Fatalf("after the restart: dropped %v, by (rule, asset) %v, since %v (was %v)", s.AlertsDropped, s.AlertsDroppedBy, s.AlertDropsSince, since)
	}
}

// D6's E15 on #590 and D1 on B3: network-alert-not-stored is raised once
// for a stretch of failures, and again for the next stretch after an
// alert commits, whether the alerts were dropped at the quota or held.
// Desk: the store's refusal is a test hook.
func TestDetectorAlertAlarmRearmed(t *testing.T) {
	for _, refuse := range []error{&c5.Error{Code: c5.CodeQuotaReached}, errors.New("refused")} {
		t.Run(refuse.Error(), func(t *testing.T) {
			c, dir := holdConfig(t)
			r, st, _ := start(t, c, dir)
			defer r.Close()
			r.alertAppend = func([]c5.Record) error { return refuse }
			if err := r.ServeSensor(bg, sensorChannel(t, spoofFlow(1, frameData(1), ""))); err != nil {
				t.Fatal(err)
			}
			tick(t, r)
			tick(t, r)
			if n := countAlarms(st, AlarmAlertNotStored); n != 1 {
				t.Fatalf("%d alarms in the first stretch", n)
			}
			r.alertAppend = nil
			if err := r.ServeSensor(bg, sensorChannel(t, laterFlow(2, hashOf(frameData(1))))); err != nil {
				t.Fatal(err)
			}
			tick(t, r)
			if n := countAlarms(st, AlarmAlertNotStored); n != 1 || detectorStatus(t, st).Alerts == 0 {
				t.Fatalf("%d alarms, status %+v", n, detectorStatus(t, st))
			}
			r.alertAppend = func([]c5.Record) error { return refuse }
			third := laterFlow(3, hashOf(frameData(1)))
			third.FirstUTC, third.LastUTC = "2026-11-07T10:40:00.000001Z", "2026-11-07T10:40:00.120001Z"
			if err := r.ServeSensor(bg, sensorChannel(t, third)); err != nil {
				t.Fatal(err)
			}
			tick(t, r)
			if n := countAlarms(st, AlarmAlertNotStored); n != 2 {
				t.Fatalf("%d alarms after the second stretch, status %+v", n, detectorStatus(t, st))
			}
		})
	}
}

// B4 on the node (D1 on #590, C13 §14 item 19): a connected session
// handed over before any observation, as when a collection runs before the
// sensor has sent anything, is checkpointed with no clock, restored, and
// judged once an observation moves the clock past its window: one
// own-session-unseen, with no checkpoint failure.
func TestDetectorSessionBeforeClock(t *testing.T) {
	c, dir := holdConfig(t)
	r, st, _ := start(t, c, dir)
	from := time.Date(2026, 11, 7, 9, 0, 0, 0, time.UTC)
	guardRun(t, newScheduler(t, r, &fakeCollector{}), c, testInvocation(1), from, 0)
	tick(t, r)
	if d := detectorStatus(t, st); d.CheckpointFailures != 0 || d.CheckpointsWritten != 2 || countAlarms(st, AlarmDetectorCheckpoint) != 0 {
		t.Fatalf("status %+v", d)
	}
	r.Close()
	r, st, _ = start(t, c, dir)
	defer r.Close()
	if err := r.ServeSensor(bg, sensorChannel(t, laterFlow(1, hashOf(frameData(1))))); err != nil {
		t.Fatal(err)
	}
	tick(t, r)
	if d := detectorStatus(t, st); unseenAlerts(t, r) != 1 || !d.Restored || d.CheckpointFailures != 0 {
		t.Fatalf("%d unseen, status %+v", unseenAlerts(t, r), d)
	}
}

// The alarm re-arms at a commit with alerts still unsent: in one flush,
// an alert that commits ends the stretch, and the next one dropped raises
// the alarm again (D1 on B3). Desk: the store's answers are a test hook.
func TestDetectorAlertAlarmRearmedInFlush(t *testing.T) {
	c, dir := holdConfig(t)
	r, st, _ := start(t, c, dir)
	defer r.Close()
	r.alertAppend = func([]c5.Record) error { return &c5.Error{Code: c5.CodeQuotaReached} }
	if err := r.ServeSensor(bg, sensorChannel(t, spoofFlow(1, frameData(1), ""))); err != nil {
		t.Fatal(err)
	}
	tick(t, r)
	answers := []error{errors.New("batch refused"), nil, &c5.Error{Code: c5.CodeQuotaReached}}
	r.alertAppend = func([]c5.Record) error {
		err := answers[0]
		answers = answers[1:]
		return err
	}
	if err := r.ServeSensor(bg, sensorChannel(t, laterFlow(2, hashOf(frameData(1))))); err != nil {
		t.Fatal(err)
	}
	tick(t, r)
	if d := detectorStatus(t, st); len(answers) != 0 || d.Alerts != 1 || d.AlertsNotStored != 3 || countAlarms(st, AlarmAlertNotStored) != 2 {
		t.Fatalf("%d answers left, status %+v, %d alarms", len(answers), d, countAlarms(st, AlarmAlertNotStored))
	}
}

// D1 on B3: the alert class's intake.drop-counted event names the pairs of
// an enrolled asset before the unresolved buckets, so decoys to unresolved
// addresses in every rule never push an enrolled asset's one drop into
// other; past SensorDropDetailAssets the rest are summed there.
func TestAlertDropDetailsEnrolledFirst(t *testing.T) {
	d := dropCounts{map[string]uint64{sensorlink.DropClassFull: 0}, map[string]uint64{}}
	rules := []netobs.Rule{netobs.RuleNodeAddressSpoofed, netobs.RuleOwnSessionOutsideRecord, netobs.RuleOwnSessionUnseen, netobs.RuleUnresolvedAddress,
		"r5", "r6", "r7", "r8", "r9"}
	for _, rule := range rules {
		d.asset[string(rule)+"."+netobs.AssetUnresolved] = 1000
	}
	real := string(netobs.RuleOwnSessionOutsideRecord) + "." + relayID
	d.asset[real] = 1
	for _, n := range d.asset {
		d.reason[sensorlink.DropClassFull] += n
	}
	det := alertDropDetails(NetAlertStream(sensorID), time.Now(), d)
	if det[real] != "1" || det[sensorDropOther] != "2000" || det["count"] != "9001" {
		t.Fatalf("details %v", det)
	}
}

// testInvocation is the i-th invocation ID of a test run.
func testInvocation(i int) string { return fmt.Sprintf("00000000-0000-4000-8000-%012d", i) }

// runRecord stores a connected collection.run of the relay's endpoint for
// invocation inv, with details changed by over.
func runRecord(t *testing.T, s *Scheduler, c *Config, inv string, over map[string]string) {
	t.Helper()
	d := map[string]string{"endpoint": "127.0.0.1:2323", "l4": "tcp", "started_at": "2026-10-24T09:15:00Z", "ended_at": "2026-10-24T09:15:01Z",
		"connected": "true", "open_flow": "false", "after_seq": "0"}
	maps.Copy(d, over)
	if !s.health(bg, HealthCollectionRun, c.Schedule[0], "r-"+inv, inv, d) {
		t.Fatal("collection.run not stored")
	}
}

// A session past MaxPendingSessions is not judged: status counts it as
// pending-full and the alarm is raised as the count rises (D1's F2 on
// #590). A collection.run that doesn't parse counts as session missing
// (D3 on #590).
func TestDetectorPendingFullAlarm(t *testing.T) {
	c, dir := holdConfig(t)
	r, st, _ := start(t, c, dir)
	defer r.Close()
	s := newScheduler(t, r, &fakeCollector{})
	for i := range netobs.MaxPendingSessions + 1 {
		runRecord(t, s, c, testInvocation(i+1), nil)
	}
	runRecord(t, s, c, testInvocation(1000), map[string]string{"after_seq": "x"})
	tick(t, r)
	tick(t, r)
	d := detectorStatus(t, st)
	if d.NotJudged["pending-full"] != 1 || d.NotJudged["tied-evicted"] != 0 || d.NotJudged["session-missing"] != 1 || countAlarms(st, AlarmSessionNotJudged) != 1 {
		t.Fatalf("status %+v, %d alarms", d, countAlarms(st, AlarmSessionNotJudged))
	}
}

// A tied flow whose session never comes, dropped past MaxTiedSessions, is
// a session not judged: status counts it as tied-evicted and the alarm is
// raised as the count rises (D1's F2 on #590). Desk: the ties are written
// to the observation stream by hand, as intake writes them.
func TestDetectorTiedEvictedAlarm(t *testing.T) {
	c, dir := holdConfig(t)
	r, st, _ := start(t, c, dir)
	defer r.Close()
	if err := r.ServeSensor(bg, sensorChannel(t, ownFlow(1))); err != nil {
		t.Fatal(err)
	}
	stream := NetObservationStream(sensorID)
	got, err := r.Store(stream).Read(bg, stream, 0, 1)
	if err != nil || len(got) != 1 {
		t.Fatalf("%d observations, %v", len(got), err)
	}
	e, err := event.Decode(got[0].Event)
	if err != nil {
		t.Fatal(err)
	}
	var o netobs.Observation
	if err := json.Unmarshal(e.Netobs, &o); err != nil {
		t.Fatal(err)
	}
	for i := range netobs.MaxTiedSessions + 1 {
		e.ID.Seq = 0
		o.Node.PlatformSession = &netobs.PlatformSession{InvocationID: testInvocation(i + 1), Tie: sensorlink.TieConnection}
		if e.Netobs, err = json.Marshal(&o); err != nil {
			t.Fatal(err)
		}
		b, err := json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := r.Log(stream).Append(bg, c5.Record{Stream: stream, Class: c5.ClassNetworkObservation, Event: b}); err != nil {
			t.Fatal(err)
		}
	}
	tick(t, r)
	tick(t, r)
	d := detectorStatus(t, st)
	if d.NotJudged["tied-evicted"] != 1 || d.NotJudged["pending-full"] != 0 || countAlarms(st, AlarmSessionNotJudged) != 1 {
		t.Fatalf("status %+v, %d alarms", d, countAlarms(st, AlarmSessionNotJudged))
	}
}

// pruneObservations prunes the observation stream at the detector's
// cursor, at most max records, as the runtime's prune pass does.
func pruneObservations(t *testing.T, r *Runtime, c *Config, max int) {
	t.Helper()
	stream := NetObservationStream(sensorID)
	db := r.Store(stream)
	cs, err := c.Consumers()
	if err != nil {
		t.Fatal(err)
	}
	b, err := c5.ComputeBoundary(bg, db, db, cs, stream, c5.ClassNetworkObservation, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if k, err := db.PruneStep(bg, b, max); err != nil || k == 0 {
		t.Fatalf("pruned %d: %v", k, err)
	}
}

// firstRetained is the observation stream's first retained seq.
func firstRetained(t *testing.T, r *Runtime) c5.Seq {
	t.Helper()
	stream := NetObservationStream(sensorID)
	first, err := r.Store(stream).FirstRetained(bg, stream)
	if err != nil {
		t.Fatal(err)
	}
	return first
}

// foreignCheckpoint stores, as the newest detector checkpoint, the newest
// one renamed to another node's, which doesn't restore here, and returns
// its seq.
func foreignCheckpoint(t *testing.T, r *Runtime) c5.Seq {
	t.Helper()
	_, doc, err := r.detectorCheckpoints(bg)
	if err != nil || doc == nil {
		t.Fatalf("no checkpoint: %v", err)
	}
	k, err := netobs.DecodeDetectorCheckpoint(doc)
	if err != nil {
		t.Fatal(err)
	}
	k.NodeID = "site-b-node1"
	b, err := json.Marshal(k)
	if err != nil {
		t.Fatal(err)
	}
	rc, err := r.Log(r.intakeStream()).Append(bg, c5.Record{Stream: r.intakeStream(), Class: c5.ClassConfiguration, Event: b})
	if err != nil {
		t.Fatal(err)
	}
	return rc.Key().Seq
}

// prunedStart is a node whose detector starts again over an observation
// stream pruned of every record: one observation was read, checkpointed
// and pruned at the cursor, and the checkpoint then failed to restore. It
// returns the pruned observation's event.
func prunedStart(t *testing.T) (*Runtime, *Status, *Config, event.Event) {
	t.Helper()
	c, dir := holdConfig(t)
	r, _, _ := start(t, c, dir)
	if err := r.ServeSensor(bg, sensorChannel(t, ownFlow(1))); err != nil {
		t.Fatal(err)
	}
	tick(t, r)
	stream := NetObservationStream(sensorID)
	got, err := r.Store(stream).Read(bg, stream, 0, 1)
	if err != nil || len(got) != 1 {
		t.Fatalf("%d observations, %v", len(got), err)
	}
	e, err := event.Decode(got[0].Event)
	if err != nil {
		t.Fatal(err)
	}
	pruneObservations(t, r, c, 1000)
	foreignCheckpoint(t, r)
	r.Close()
	r, st, _ := start(t, c, dir)
	tick(t, r)
	if nd := r.detector; !nd.pruned || nd.restored || !nd.firstObs.IsZero() || firstRetained(t, r) != 0 {
		t.Fatalf("pruned %v, restored %v, first read at %v", nd.pruned, nd.restored, nd.firstObs)
	}
	return r, st, c, *e
}

// D6's R1 on #590: the guard's pruned is computed from a stream the
// store's prune step really pruned, with records still retained after the
// detector's Through and with none; a restore at the stream's head finds
// it not pruned. Desk: the restore fails on a checkpoint renamed to
// another node's.
func TestDetectorPrunedFromStream(t *testing.T) {
	for _, tc := range []struct {
		name  string
		step  int
		first c5.Seq
	}{{"some retained", 1, 2}, {"none retained", 1000, 0}} {
		t.Run(tc.name, func(t *testing.T) {
			c, dir := holdConfig(t)
			r, _, _ := start(t, c, dir)
			if err := r.ServeSensor(bg, sensorChannel(t, ownFlow(1), ownFlow(2))); err != nil {
				t.Fatal(err)
			}
			tick(t, r)
			pruneObservations(t, r, c, tc.step)
			if f := firstRetained(t, r); f != tc.first || detectorCursor(t, r) != 2 {
				t.Fatalf("first retained %d, cursor %d", f, detectorCursor(t, r))
			}
			r.Close()
			r, _, _ = start(t, c, dir)
			if nd := r.detector; !nd.restored || nd.pruned {
				t.Fatalf("a restore at the head: restored %v, pruned %v", nd.restored, nd.pruned)
			}
			foreignCheckpoint(t, r)
			r.Close()
			r, st, _ := start(t, c, dir)
			defer r.Close()
			if nd := r.detector; nd.restored || !nd.pruned || countAlarms(st, AlarmDetectorNotRestored) != 1 {
				t.Fatalf("a first start: restored %v, pruned %v, %d alarms", nd.restored, nd.pruned, countAlarms(st, AlarmDetectorNotRestored))
			}
		})
	}
}

// guardRun stores a connected collection.run of the relay's endpoint for
// inv, started at from and ended a second later, after after.
func guardRun(t *testing.T, s *Scheduler, c *Config, inv string, from time.Time, after int) {
	t.Helper()
	f := func(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }
	runRecord(t, s, c, inv, map[string]string{"started_at": f(from), "ended_at": f(from.Add(time.Second)), "after_seq": strconv.Itoa(after)})
}

// unseenAlerts are the committed own-session-unseen alerts, each checked
// to have no capture (C13 section 7.1).
func unseenAlerts(t *testing.T, r *Runtime) (n int) {
	t.Helper()
	for _, a := range committedAlerts(t, r) {
		if a.alert.Rule == netobs.RuleOwnSessionUnseen {
			if a.alert.Capture != "" || a.frames != nil {
				t.Errorf("own-session-unseen with a capture: %+v", a.alert)
			}
			n++
		}
	}
	return n
}

// D6's R2 to R4 on #590, from the CommittedAt bound: after a pruned start
// the first record read, stored or refused, sets the bound at its commit
// time T. A session that starts at T + 2g, so start − g equals T + g, is
// judged, and alerts own-session-unseen once its window passes with no
// flow; one that starts a nanosecond earlier is skipped, for
// before-retained. D6's R8: own-session-unseen has no capture. Desk: the
// refused record is the pruned observation stored again by hand with
// another sensor's ID, which the detector refuses.
func TestDetectorGuardEdge(t *testing.T) {
	for _, first := range []string{"stored", "refused", "undecodable", "a day ahead"} {
		t.Run(first, func(t *testing.T) {
			r, st, c, e := prunedStart(t)
			defer r.Close()
			stream := NetObservationStream(sensorID)
			switch first {
			case "refused", "undecodable":
				var o netobs.Observation
				if err := json.Unmarshal(e.Netobs, &o); err != nil {
					t.Fatal(err)
				}
				o.SensorID = "00000000-0000-4000-8000-0000000000ff"
				b, err := json.Marshal(&o)
				if err != nil {
					t.Fatal(err)
				}
				if first == "undecodable" { // D6's E11 on #590: observationOf fails
					b = []byte(`{"schema":"not an observation"}`)
				}
				e.ID.Seq, e.Netobs = 0, b
				if b, err = json.Marshal(e); err != nil {
					t.Fatal(err)
				}
				if _, err := r.Log(stream).Append(bg, c5.Record{Stream: stream, Class: c5.ClassNetworkObservation, Event: b}); err != nil {
					t.Fatal(err)
				}
			case "a day ahead": // D3 on #590: the sensor's clock a day ahead of the commit
				ahead := ownFlow(2)
				day := time.Now().UTC().Add(24 * time.Hour).Format("2006-01-02T15:04:05.000000Z")
				ahead.FirstUTC, ahead.LastUTC = day, day
				if err := r.ServeSensor(bg, sensorChannel(t, ahead)); err != nil {
					t.Fatal(err)
				}
			default:
				if err := r.ServeSensor(bg, sensorChannel(t, ownFlow(2))); err != nil {
					t.Fatal(err)
				}
			}
			got, err := r.Store(stream).Read(bg, stream, 1, 1)
			if err != nil || len(got) != 1 || got[0].Key.Seq != 2 {
				t.Fatalf("%d records, %v", len(got), err)
			}
			if _, err := observationOf(got[0]); (err != nil) != (first == "undecodable") {
				t.Fatalf("observationOf: %v", err)
			}
			at, g := got[0].CommittedAt, time.Duration(netobs.DefaultTieGraceS)*time.Second
			s := newScheduler(t, r, &fakeCollector{})
			guardRun(t, s, c, testInvocation(1), at.Add(2*g-time.Nanosecond), 2)
			guardRun(t, s, c, testInvocation(2), at.Add(2*g), 2)
			later := ownFlow(3)
			us := func(d time.Duration) string { return at.Add(d).UTC().Format("2006-01-02T15:04:05.000000Z") }
			later.FirstUTC, later.LastUTC, later.Coverage.SinceUTC = us(time.Hour), us(time.Hour+time.Second), us(-4*time.Hour)
			if err := r.ServeSensor(bg, sensorChannel(t, later)); err != nil {
				t.Fatal(err)
			}
			tick(t, r)
			d := detectorStatus(t, st)
			refused := int64(0)
			if first == "refused" || first == "undecodable" {
				refused = 1
			}
			if !r.detector.firstObs.Equal(at) || d.NotJudged["before-retained"] != 1 || unseenAlerts(t, r) != 1 || d.Refused != refused || d.Through != 3 {
				t.Fatalf("bound %v, want %v; %d unseen; status %+v", r.detector.firstObs, at, unseenAlerts(t, r), d)
			}
		})
	}
}

// D6's R4 on #590: after a pruned start, a session handed over before
// any record is read has no bound, so it is skipped.
func TestDetectorGuardNothingRead(t *testing.T) {
	r, st, c, _ := prunedStart(t)
	defer r.Close()
	guardRun(t, newScheduler(t, r, &fakeCollector{}), c, testInvocation(1), time.Now().Add(time.Hour), 1)
	tick(t, r)
	if d := detectorStatus(t, st); d.NotJudged["before-retained"] != 1 || d.Through != 0 || d.OrderingFaults != 0 {
		t.Fatalf("status %+v", d)
	}
}

// D6's R8 on #590, without the guard: a connected session with no flow
// alerts own-session-unseen once its window passes, with no capture.
func TestDetectorUnseenNoCapture(t *testing.T) {
	c, dir := holdConfig(t)
	r, _, _ := start(t, c, dir)
	defer r.Close()
	from := time.Date(2026, 11, 7, 10, 0, 0, 0, time.UTC)
	guardRun(t, newScheduler(t, r, &fakeCollector{}), c, testInvocation(1), from, 0)
	if err := r.ServeSensor(bg, sensorChannel(t, laterFlow(1, hashOf(frameData(1))))); err != nil {
		t.Fatal(err)
	}
	tick(t, r)
	if n := unseenAlerts(t, r); n != 1 {
		t.Fatalf("%d own-session-unseen alerts", n)
	}
}

// D6's R5 on #590: the frame index is rebuilt at a restart from the
// retained first sights, so an alert after the restart that cites a
// first sight's frame holds it.
func TestDetectorFrameIndexRebuilt(t *testing.T) {
	c, dir := holdConfig(t)
	r, _, _ := start(t, c, dir)
	f1 := frameData(1)
	if err := r.ServeSensor(bg, sensorChannel(t, spoofFlow(1, f1, ""))); err != nil {
		t.Fatal(err)
	}
	tick(t, r)
	r.Close()
	r, _, _ = start(t, c, dir)
	defer r.Close()
	if !r.detector.restored || r.detector.index.at[hashOf(f1)] == "" {
		t.Fatalf("restored %v, index %v", r.detector.restored, r.detector.index.at)
	}
	if err := r.ServeSensor(bg, sensorChannel(t, laterFlow(2, hashOf(f1)))); err != nil {
		t.Fatal(err)
	}
	tick(t, r)
	got := committedAlerts(t, r)
	if len(got) != 4 {
		t.Fatalf("%d alerts", len(got))
	}
	for _, a := range got[2:] {
		if a.alert.FramesMissing != 0 || len(a.frames) != 1 || string(a.frames[0].Data) != string(f1) {
			t.Errorf("%s: %d missing, %d frames", a.alert.Rule, a.alert.FramesMissing, len(a.frames))
		}
	}
}

// D6's R6 on #590: a checkpoint that doesn't restore raises the alarm, the
// detector starts again from the oldest retained observation, its first
// checkpoint is stored, and every older one, the one that didn't restore
// too, is removed: the next restart restores from the new one. Desk: the
// checkpoint is renamed to another node's.
func TestDetectorRestoreFailure(t *testing.T) {
	c, dir := holdConfig(t)
	r, _, _ := start(t, c, dir)
	if err := r.ServeSensor(bg, sensorChannel(t, ownFlow(1))); err != nil {
		t.Fatal(err)
	}
	tick(t, r)
	foreign := foreignCheckpoint(t, r)
	r.Close()
	r, st, _ := start(t, c, dir)
	tick(t, r)
	d, seqs := detectorStatus(t, st), detectorCkpts(t, r)
	if countAlarms(st, AlarmDetectorNotRestored) != 1 || d.Restored || r.detector.pruned || d.Through != 1 || len(seqs) != 1 || seqs[0] <= foreign {
		t.Fatalf("status %+v, checkpoints %v (foreign %d), %d alarms", d, seqs, foreign, countAlarms(st, AlarmDetectorNotRestored))
	}
	r.Close()
	r, st, _ = start(t, c, dir)
	defer r.Close()
	if d := detectorStatus(t, st); !d.Restored || d.Through != 1 || countAlarms(st, AlarmDetectorNotRestored) != 0 {
		t.Fatalf("status %+v", d)
	}
}

// D6's R7 on #590: a crash after a second checkpoint that holds committed
// alerts, and after more alerts commit, gives each alert once: the restore
// holds back the alerts after the checkpoint's last_alert_seq, and those
// at or below it are not raised again. The crash is the next checkpoint
// refused at item 3's ceiling.
func TestDetectorCrashAfterAlertCheckpoint(t *testing.T) {
	c, dir := ceilingConfig(t)
	r, _, _ := start(t, c, dir)
	f1 := frameData(1)
	if err := r.ServeSensor(bg, sensorChannel(t, spoofFlow(1, f1, ""))); err != nil {
		t.Fatal(err)
	}
	tick(t, r)
	_, doc, err := r.detectorCheckpoints(bg)
	if err != nil {
		t.Fatal(err)
	}
	k, err := netobs.DecodeDetectorCheckpoint(doc)
	if err != nil || k.LastAlertSeq != 2 || len(detectorCkpts(t, r)) != 1 {
		t.Fatalf("checkpoint %+v, %v", k, err)
	}
	fillCeiling(t, r, c)
	if err := r.ServeSensor(bg, sensorChannel(t, laterFlow(2, hashOf(f1)))); err != nil {
		t.Fatal(err)
	}
	tick(t, r)
	if n := len(committedAlerts(t, r)); n != 4 || detectorCursor(t, r) != 1 {
		t.Fatalf("%d alerts before the crash, cursor %d", n, detectorCursor(t, r))
	}
	r.Close()
	r, st, _ := start(t, c, dir)
	defer r.Close()
	tick(t, r)
	d := detectorStatus(t, st)
	if n := len(committedAlerts(t, r)); n != 4 || !d.Restored || d.Through != 2 || d.Mismatches != 0 || d.Alerts != 0 {
		t.Fatalf("%d alerts after the restart, status %+v", n, d)
	}
}

// D6's R9 on #590: a session handed over after observations it precedes
// raises the ordering alarm; a restore whose replay departs from the
// alerts committed raises the mismatch alarm. Desk: the ordering fault is
// a collection.run with an after_seq below Through, and the departure an
// alert committed again by hand after the checkpoint.
func TestDetectorOrderingMismatchAlarms(t *testing.T) {
	c, dir := holdConfig(t)
	r, st, _ := start(t, c, dir)
	if err := r.ServeSensor(bg, sensorChannel(t, spoofFlow(1, frameData(1), ""), ownFlow(2))); err != nil {
		t.Fatal(err)
	}
	tick(t, r)
	runRecord(t, newScheduler(t, r, &fakeCollector{}), c, testInvocation(1), map[string]string{"after_seq": "1"})
	tick(t, r)
	if d := detectorStatus(t, st); d.OrderingFaults != 1 || countAlarms(st, AlarmDetectorOrdering) != 1 || d.NotJudged["session-missing"] != 0 {
		t.Fatalf("status %+v, %d alarms", d, countAlarms(st, AlarmDetectorOrdering))
	}
	stream := NetAlertStream(sensorID)
	got, err := r.Store(stream).Read(bg, stream, 0, 1)
	if err != nil || len(got) != 1 {
		t.Fatalf("%d alerts, %v", len(got), err)
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
	if _, err := r.Log(stream).Append(bg, c5.Record{Stream: stream, Class: c5.ClassNetworkAlert, Event: b}); err != nil {
		t.Fatal(err)
	}
	r.Close()
	r, st, _ = start(t, c, dir)
	defer r.Close()
	tick(t, r)
	if d := detectorStatus(t, st); !d.Restored || d.Mismatches != 1 || countAlarms(st, AlarmDetectorMismatch) != 1 {
		t.Fatalf("status %+v, %d alarms", d, countAlarms(st, AlarmDetectorMismatch))
	}
}

// D6's R9 on #590: enrolled run endpoint addresses past
// MaxDetectorEndpoints raise the alarm at start, with their count.
func TestDetectorEndpointsNotTracked(t *testing.T) {
	c, dir := schedConfig(t, func(nc *nodeconfigtest.Config) {
		sensorQuotas(nc)
		nc.NetworkSensor = sensorSection()
		// 256 entries every 300 s over 72 outage hours need 1.8 GB of the
		// platform class beneath the sensor (PlatformFloor).
		nc.Store.Quotas["platform"] = 2 << 30
		for i := range netobs.MaxDetectorEndpoints {
			nc.AddSEL751(fmt.Sprintf("%08x-0000-4000-9000-000000000000", i+1), fmt.Sprintf("127.1.%d.%d", i/250, i%250+1), 2323, 300)
		}
	})
	r, st, _ := start(t, c, dir)
	defer r.Close()
	if d := detectorStatus(t, st); d.EndpointsNotTracked != 1 || countAlarms(st, AlarmEndpointsNotTracked) != 1 {
		t.Fatalf("status %+v, %d alarms", d, countAlarms(st, AlarmEndpointsNotTracked))
	}
}

// D6's R10 on #590: the frame index holds FrameIndexEntries frames, the
// oldest out first, and a frame indexed again keeps its place.
func TestDetectorFrameIndexBound(t *testing.T) {
	var x frameIndex
	for i := range FrameIndexEntries + 1 {
		x.add(fmt.Sprint(i), "r")
		if i == 1 {
			x.add("0", "r") // already in: no move
		}
	}
	if len(x.at) != FrameIndexEntries || len(x.order) != FrameIndexEntries || x.at["0"] != "" || x.at["1"] == "" || x.at[fmt.Sprint(FrameIndexEntries)] == "" {
		t.Fatalf("%d entries, %d in order", len(x.at), len(x.order))
	}
}

// D6's N1 on #590: a collection.run the driver stops before, at an alert
// not committed, is read again and handed over at the next tick, and one
// that doesn't parse, before it, is counted once. A read of the health
// stream that fails moves nothing. Desk: the commit is
// refused by a test hook, and the read by a fake reader.
func TestDetectorHealthPosition(t *testing.T) {
	for _, bad := range []bool{true, false} { // D6's E6 on #590: the good session first
		t.Run(fmt.Sprintf("bad first %v", bad), func(t *testing.T) { healthPosition(t, bad) })
	}
}

func healthPosition(t *testing.T, bad bool) {
	c, dir := holdConfig(t)
	r, st, _ := start(t, c, dir)
	defer r.Close()
	r.alertAppend = func([]c5.Record) error { return errors.New("refused") }
	if err := r.ServeSensor(bg, sensorChannel(t, spoofFlow(1, frameData(1), ""))); err != nil {
		t.Fatal(err)
	}
	before := r.detector.health
	s := newScheduler(t, r, &fakeCollector{})
	missing := int64(0)
	if bad {
		runRecord(t, s, c, testInvocation(2), map[string]string{"after_seq": "x"})
		missing = 1
	}
	runRecord(t, s, c, testInvocation(1), map[string]string{"after_seq": "1", "connected": "false"})
	tick(t, r)
	run, err := r.Store(HealthStream).LastCommitted(bg, HealthStream)
	if err != nil {
		t.Fatal(err)
	}
	if h := r.detector.health; h >= run || (!bad && h != before) {
		t.Fatalf("health position %d (was %d) past the session at %d, not handed over", h, before, run)
	}
	r.alertAppend = nil
	tick(t, r)
	doc, err := r.detector.d.Checkpoint(0)
	if err != nil {
		t.Fatal(err)
	}
	k, err := netobs.DecodeDetectorCheckpoint(doc)
	if d := detectorStatus(t, st); err != nil || k.SessionThrough != uint64(run) || d.Alerts != 2 || d.NotJudged["session-missing"] != missing {
		t.Fatalf("session through %d, status %+v, %v", k.SessionThrough, d, err)
	}
	pages, health := 0, r.detector.health
	runs, _, err := r.newSessions(bg, readerFunc(func(after c5.Seq) ([]c5.Stored, error) {
		if pages++; pages > 1 {
			return nil, errors.New("refused")
		}
		return make([]c5.Stored, detectorReadPage), nil
	}), r.detector)
	if err == nil || runs != nil || r.detector.health != health {
		t.Fatalf("%d runs, health %d, %v", len(runs), r.detector.health, err)
	}
}

// D1's note 2 on #590: a restored detector's health read starts at its
// SessionThrough, so a collection.run before the last session taken, one
// that doesn't parse included, is not read or counted again after a
// restart.
func TestDetectorHealthReadRestored(t *testing.T) {
	c, dir := holdConfig(t)
	r, st, _ := start(t, c, dir)
	if err := r.ServeSensor(bg, sensorChannel(t, spoofFlow(1, frameData(1), ""))); err != nil {
		t.Fatal(err)
	}
	s := newScheduler(t, r, &fakeCollector{})
	runRecord(t, s, c, testInvocation(2), map[string]string{"after_seq": "x"})
	runRecord(t, s, c, testInvocation(1), map[string]string{"after_seq": "1", "connected": "false"})
	tick(t, r)
	run, err := r.Store(HealthStream).LastCommitted(bg, HealthStream)
	if err != nil {
		t.Fatal(err)
	}
	if d := detectorStatus(t, st); d.NotJudged["session-missing"] != 1 || r.detector.d.SessionThrough() != uint64(run) {
		t.Fatalf("session through %d (run %d), status %+v", r.detector.d.SessionThrough(), run, d)
	}
	r.Close()
	r, st, _ = start(t, c, dir)
	defer r.Close()
	tick(t, r)
	if d := detectorStatus(t, st); !d.Restored || d.NotJudged["session-missing"] != 0 {
		t.Fatalf("after the restart: status %+v", d)
	}
	// D6's R1 on #600: a run after the restart is read and judged.
	guardRun(t, newScheduler(t, r, &fakeCollector{}), c, testInvocation(3), time.Date(2026, 11, 7, 10, 5, 0, 0, time.UTC), 1)
	if err := r.ServeSensor(bg, sensorChannel(t, laterFlow(2, hashOf(frameData(1))))); err != nil {
		t.Fatal(err)
	}
	tick(t, r)
	if n := unseenAlerts(t, r); n != 1 {
		t.Fatalf("%d own-session-unseen after the restart, status %+v", n, detectorStatus(t, st))
	}
}

// D6's R2 on #600: a crash after a collection.run commits and before the
// checkpoint that takes it. The run, the first past the restored
// SessionThrough, is read and taken after the restart. Desk: the
// checkpoint fails at item 3's ceiling, filled by hand, as a crash before
// it would leave it.
func TestDetectorHealthReadAfterCrash(t *testing.T) {
	c, dir := ceilingConfig(t)
	r, st, _ := start(t, c, dir)
	if err := r.ServeSensor(bg, sensorChannel(t, spoofFlow(1, frameData(1), ""))); err != nil {
		t.Fatal(err)
	}
	s := newScheduler(t, r, &fakeCollector{})
	last := func() c5.Seq {
		seq, err := r.Store(HealthStream).LastCommitted(bg, HealthStream)
		if err != nil {
			t.Fatal(err)
		}
		return seq
	}
	runRecord(t, s, c, testInvocation(1), map[string]string{"after_seq": "1", "connected": "false"})
	tick(t, r)
	run1 := last()
	fillCeiling(t, r, c)
	runRecord(t, s, c, testInvocation(2), map[string]string{"after_seq": "1", "connected": "false"})
	run2 := last()
	tick(t, r)
	if d := detectorStatus(t, st); run2 != run1+1 || r.detector.d.SessionThrough() != uint64(run2) || d.CheckpointFailures == 0 {
		t.Fatalf("runs at %d and %d, session through %d, status %+v", run1, run2, r.detector.d.SessionThrough(), d)
	}
	r.Close()
	r, st, _ = start(t, c, dir)
	defer r.Close()
	tick(t, r)
	if d := detectorStatus(t, st); !d.Restored || r.detector.d.SessionThrough() != uint64(run2) {
		t.Fatalf("after the restart: session through %d, want %d, status %+v", r.detector.d.SessionThrough(), run2, d)
	}
}

// readerFunc is a health stream reader.
type readerFunc func(c5.Seq) ([]c5.Stored, error)

func (f readerFunc) Read(_ context.Context, _ c5.StreamID, after c5.Seq, _ int) ([]c5.Stored, error) {
	return f(after)
}

// D6's N2 on #590: a stored checkpoint whose cursor save or older
// checkpoints' removal failed is completed at the next tick, though
// nothing moved. Desk: the failure is the checkpoint stored by hand with
// neither, the state a failed SaveCursor or RemoveConfig leaves.
func TestDetectorCursorRetried(t *testing.T) {
	c, dir := holdConfig(t)
	r, st, _ := start(t, c, dir)
	defer r.Close()
	for i := 1; i <= 2; i++ {
		if err := r.ServeSensor(bg, sensorChannel(t, ownFlow(i))); err != nil {
			t.Fatal(err)
		}
		if i == 1 {
			tick(t, r)
		}
	}
	var seq c5.Seq
	var err error
	heldManager(r, func() {
		nd := r.detector
		r.observeTo(bg, nd, 2, newDrive())
		if seq, err = r.storeDetectorCheckpoint(bg, nd); err == nil {
			nd.written, nd.ckpts = nd.d.Through(), append(nd.ckpts, seq)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	if n := len(detectorCkpts(t, r)); n != 2 || detectorCursor(t, r) != 1 {
		t.Fatalf("%d checkpoints, cursor %d", n, detectorCursor(t, r))
	}
	written := detectorStatus(t, st).CheckpointsWritten
	tick(t, r)
	if seqs := detectorCkpts(t, r); len(seqs) != 1 || seqs[0] != seq || detectorCursor(t, r) != 2 || detectorStatus(t, st).CheckpointsWritten != written {
		t.Fatalf("checkpoints %v, cursor %d", seqs, detectorCursor(t, r))
	}
}

// D6's N3 on #590: a session the detector refuses, here one that ends
// before it starts, is not judged, and counts as session missing.
func TestDetectorSessionRefused(t *testing.T) {
	c, dir := holdConfig(t)
	r, st, _ := start(t, c, dir)
	defer r.Close()
	runRecord(t, newScheduler(t, r, &fakeCollector{}), c, testInvocation(1), map[string]string{"ended_at": "2026-10-24T09:14:00Z"})
	tick(t, r)
	if d := detectorStatus(t, st); d.NotJudged["session-missing"] != 1 || d.OrderingFaults != 0 {
		t.Fatalf("status %+v", d)
	}
}
