package node

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
	"testing"
	"time"

	"otsec.local/otsec/contracts/event"
	"otsec.local/otsec/contracts/netobs"
	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/contracts/syslog"
	"otsec.local/otsec/platform/sensorlink"
)

// Constructed C13 records, desk only: no sensor produced them and no device
// was contacted. Addresses are TEST-NET-2 (198.51.100.0/24), which no
// asset holds, so every observation is unresolved.
const sensorRun = "0b9e4c6d-1a2f-4e3b-8c7d-5f6a7b8c9d0e"

func sensorFlow(seq int, sensor string) *netobs.Observation {
	p := func(v int) *int { return &v }
	return &netobs.Observation{
		Schema: netobs.Identifier, Type: netobs.TypeObservation, SensorID: sensor, RunID: sensorRun, Seq: strconv.Itoa(seq),
		Kind: netobs.KindFlow, FirstUTC: "2026-11-07T10:00:00.000001Z", LastUTC: "2026-11-07T10:00:00.120001Z", ResolutionNS: 1000,
		L2:        netobs.L2{SrcMAC: "02:00:00:00:00:01", DstMAC: "02:00:00:00:00:02", VLAN: p(10), EtherType: "0x0800"},
		IP:        &netobs.IP{Src: "198.51.100.1", Dst: "198.51.100.2", L4: "tcp", Sport: p(51234), Dport: p(20000)},
		Direction: netobs.DirectionClientServer, Protocol: "dnp3",
		Citation: netobs.Citation{CaptureID: "ring:" + sensorRun + ":3", FramesTotal: 1, Frames: []netobs.CitedFrame{
			{N: 17, CapturedLen: 74, WireLen: 74, SHA256: "5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef"}}},
		Coverage: netobs.Coverage{
			SensorVersion: "0.1.0", Engine: netobs.Engine{Name: "test-engine", Version: "1"},
			Interfaces: []netobs.Interface{{Name: "eth1", Attachment: "span", LAN: "single"}},
			PRP:        netobs.PRP{LANsSeen: []string{}}, HSR: netobs.HSRNotDecoded,
			VLANsSeen: []int{10}, UntaggedSeen: true, Decodes: []string{"dnp3"}, Degraded: []string{},
			Settings: netobs.Settings{SAReplyTimeoutMS: netobs.DefaultSAReplyTimeoutMS, MaxPendingDNP3: netobs.DefaultMaxPendingDNP3, FlowIdleS: netobs.DefaultFlowIdleS},
			SinceUTC: "2026-11-07T08:00:00.000000Z",
		},
		Flow: &netobs.Flow{Phase: "start", Packets: 3, Bytes: 222},
	}
}

// sensorChannel frames records as the sensor writes them.
func sensorChannel(t *testing.T, recs ...any) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	for _, r := range recs {
		b, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		if err := netobs.WriteFrame(&buf, b); err != nil {
			t.Fatal(err)
		}
	}
	return &buf
}

// dropEvents are the intake.drop-counted events on platform/health.
func dropEvents(t *testing.T, r *Runtime) (out []map[string]string) {
	t.Helper()
	got, err := r.Store(HealthStream).Read(bg, HealthStream, 0, 1000)
	if err != nil {
		t.Fatal(err)
	}
	for _, st := range got {
		var e struct {
			Health *event.Health `json:"health"`
		}
		if json.Unmarshal(st.Event, &e) == nil && e.Health != nil && e.Health.Type == event.HealthDropCounted {
			out = append(out, e.Health.Details)
		}
	}
	return out
}

// The sensor's intake in the runtime (P4-4-B5 deliverable 2). Unresolved
// observations over the budget, which starts empty, are dropped and
// counted by reason and in the unresolved bucket, and a record from
// another sensor is refused, counted and alarmed once. The counts are
// written as an intake.drop-counted event at once, then at most once a
// minute and only when they changed, and at a clean stop; a restart shows
// the same counts, and the same since (D5-c5-0.9.md section 4). Desk only.
func TestSensorDropCounts(t *testing.T) {
	g := newRetentionRig(t)
	r, st := g.start()
	serve := func(recs ...any) {
		t.Helper()
		if err := r.ServeSensor(bg, sensorChannel(t, recs...)); err != nil {
			t.Fatal(err)
		}
	}
	seq := 0
	flows := func(n int) (out []any) {
		for range n {
			seq++
			out = append(out, sensorFlow(seq, sensorID))
		}
		return out
	}
	serve(flows(2)...)
	seq++
	serve(sensorFlow(seq, "11111111-2222-4333-8444-555555555555")) // another sensor's
	r.Tick(bg)
	s := st.Snapshot("x").Sensor
	if s == nil || s.Dropped[sensorlink.DropUnresolvedBudget] != 2 || s.DroppedByAsset[netobs.AssetUnresolved] != 2 ||
		s.Refused[sensorlink.RefusedSensorID] != 1 || s.Connected {
		t.Fatalf("status %+v", s)
	}
	since := s.DropsSince
	if n := alarms(st, AlarmSensorRecordRefused); n != 1 {
		t.Fatalf("%d refused alarms", n)
	}
	ev := dropEvents(t, r)
	if len(ev) != 1 || ev[0]["count"] != "2" || ev[0]["reason."+sensorlink.DropUnresolvedBudget] != "2" ||
		ev[0]["asset."+netobs.AssetUnresolved] != "2" || ev[0]["stream"] != string(NetObservationStream(sensorID)) {
		t.Fatalf("events %v", ev)
	}

	// More drops: not written again within the minute, then written.
	serve(flows(3)...)
	g.advance(30 * time.Second)
	r.Tick(bg)
	if ev := dropEvents(t, r); len(ev) != 1 {
		t.Fatalf("written again within the minute: %v", ev)
	}
	g.advance(30 * time.Second)
	r.Tick(bg)
	if ev := dropEvents(t, r); len(ev) != 2 || ev[1]["count"] != "5" {
		t.Fatalf("after the minute: %v", ev)
	}
	r.Tick(bg) // unchanged: nothing written
	seq++
	serve(sensorFlow(seq, "11111111-2222-4333-8444-555555555555"))
	r.Tick(bg)
	if n := alarms(st, AlarmSensorRecordRefused); n != 1 || len(dropEvents(t, r)) != 2 {
		t.Fatalf("%d refused alarms, %d events", n, len(dropEvents(t, r)))
	}

	// A clean stop writes what changed since, and a start reads it back.
	// The minute has refilled the budget by a record or so, so four more
	// flows drop at least two.
	serve(flows(4)...)
	want := r.sensor.link.Stats().Dropped[sensorlink.DropUnresolvedBudget] // all since this start, with nothing restored
	if want < 7 {
		t.Fatalf("only %d dropped in all", want)
	}
	r.Close()
	r, st = g.start()
	defer r.Close()
	if ev := dropEvents(t, r); len(ev) != 3 || ev[2]["count"] != strconv.FormatUint(want, 10) {
		t.Fatalf("at the stop, want %d: %v", want, ev)
	}
	s = st.Snapshot("x").Sensor
	if s.Dropped[sensorlink.DropUnresolvedBudget] != want || s.DroppedByAsset[netobs.AssetUnresolved] != want || !s.DropsSince.Equal(since) || s.Committed != 0 {
		t.Fatalf("after the restart: %+v, want %d, since %s", s, want, since)
	}
}

// The worst intake.drop-counted event: many enrolled assets and the
// unresolved bucket all dropping, under every reason. The event names
// SensorDropDetailAssets assets, the most dropped first, and sums the rest
// in asset.other, so the asset details sum to count; a restored
// asset.other is summed again, never listed twice. With every value at its
// widest the event renders in under three quarters of a default target's
// octets (D4-72, D4's low row on #568). Desk only.
func TestSensorDropEventFits(t *testing.T) {
	const enrolled = 4 * SensorDropDetailAssets
	d := dropCounts{map[string]uint64{}, map[string]uint64{}}
	for _, r := range []string{sensorlink.DropUnresolvedBudget, sensorlink.DropClassFull, sensorlink.DropRecordCap, sensorlink.DropStore} {
		d.reason[r] = 1000
	}
	d.asset[netobs.AssetUnresolved] = 5
	for i := range enrolled {
		d.asset[fmt.Sprintf("00000000-0000-4000-8000-%012d", i)] = uint64(i + 1)
	}
	d.asset[sensorDropOther] = 7 // as a restart restores it
	sum := func(det map[string]string) (n uint64, assets int) {
		for k, v := range det {
			if strings.HasPrefix(k, "asset.") {
				x, err := strconv.ParseUint(v, 10, 64)
				if err != nil {
					t.Fatal(err)
				}
				n += x
				assets++
			}
		}
		return n, assets
	}
	var all uint64
	for _, v := range d.asset {
		all += v
	}
	stream := NetObservationStream(sensorID)
	det := dropDetails(stream, time.Date(2026, 11, 1, 0, 0, 0, 123456789, time.UTC), d)
	if n, k := sum(det); n != all || k != SensorDropDetailAssets+1 {
		t.Fatalf("asset details sum to %d in %d details, want %d in %d: %v", n, k, all, SensorDropDetailAssets+1, det)
	}
	for i := enrolled - SensorDropDetailAssets; i < enrolled; i++ { // the most dropped are named
		if id := fmt.Sprintf("00000000-0000-4000-8000-%012d", i); det["asset."+id] == "" {
			t.Fatalf("%s not named: %v", id, det)
		}
	}
	if det["asset."+sensorDropOther] == "" || det["asset."+netobs.AssetUnresolved] != "" {
		t.Fatalf("asset.other or the unresolved bucket: %v", det)
	}

	// Every value at its widest, and the longest node ID.
	for k := range det {
		if k != "stream" && k != "class" && k != "since" {
			det[k] = strconv.FormatUint(math.MaxUint64, 10)
		}
	}
	e := &event.Event{Schema: event.Identifier, ID: event.EventID{NodeID: event.NodeID(strings.Repeat("n", 63)), Stream: event.Stream(HealthStream), Seq: math.MaxUint64 >> 1},
		Origin: event.OriginPlatform, Kind: event.KindHealth, Source: event.Source{OriginAuth: event.AuthPlatform},
		Received: event.Received{UTC: "2026-11-01T00:00:00.000000001Z", ResolutionNS: 1, Clock: event.Clock{Sync: event.SyncSynchronized, Source: "ntp"}},
		Health:   &event.Health{Type: event.HealthDropCounted, Details: det}}
	tg, err := syslog.ParseTarget([]byte(`{"schema": "otsec.syslog/0.1", "name": "central", "host": "collector.example", "port": 6514,
		"transport": "tls", "format": "rfc5424", "framing": "octet-counting", "class": "best-effort", "replay_seconds": 3600, "max_message_octets": 2048,
		"tls": {"server_name": "collector.example", "trust_anchor_ref": "ca"}}`))
	if err != nil {
		t.Fatal(err)
	}
	msg, out, err := syslog.Render(e, tg)
	if err != nil || out.SummaryDropped || len(msg) > syslog.DefaultMaxOctets*3/4 {
		t.Fatalf("%d octets (limit %d), %+v, %v: %s", len(msg), syslog.DefaultMaxOctets*3/4, out, err, msg)
	}
	t.Logf("worst case: %d octets", len(msg))
}

// A drop-count write that fails raises store-commit-failed on the health
// stream's database, once for each try, and is tried again a minute later,
// not at every tick (D4-72, D4's low row on #568). Desk only.
func TestSensorDropWriteFails(t *testing.T) {
	g := newRetentionRig(t)
	r, st := g.start()
	defer r.Close()
	d := r.dbFor(HealthStream)
	r.state.Lock()
	mode := d.report.Mode
	d.report.Mode = c5.ModeDrainOnly
	r.state.Unlock()
	if err := r.ServeSensor(bg, sensorChannel(t, sensorFlow(1, sensorID))); err != nil {
		t.Fatal(err)
	}
	failed := func() (n int) {
		for _, a := range st.Snapshot("x").Alarms {
			if a.Code == string(c5.AlarmCommitFailed) && a.Stream == string(HealthStream) && a.Database == d.spec.ID {
				n++
			}
		}
		return n
	}
	r.tickSensor(bg, false)
	r.tickSensor(bg, false)
	g.advance(30 * time.Second)
	r.tickSensor(bg, false)
	if n := failed(); n != 1 || len(dropEvents(t, r)) != 0 {
		t.Fatalf("%d store-commit-failed alarms, %d events", n, len(dropEvents(t, r)))
	}
	g.advance(30 * time.Second)
	r.tickSensor(bg, false)
	if n := failed(); n != 2 {
		t.Fatalf("%d store-commit-failed alarms after the minute", n)
	}
	r.state.Lock()
	d.report.Mode = mode
	r.state.Unlock()
	g.advance(time.Minute)
	r.tickSensor(bg, false)
	if ev := dropEvents(t, r); failed() != 2 || len(ev) != 1 || ev[0]["count"] != "1" {
		t.Fatalf("after the store recovered: %d alarms, %v", failed(), ev)
	}
}

// Two refusal reasons raise two sensor-record-refused alarms, one each
// (D6's M6 on #568). Desk only.
func TestSensorRefusedAlarmPerReason(t *testing.T) {
	g := newRetentionRig(t)
	r, st := g.start()
	defer r.Close()
	if err := r.ServeSensor(bg, sensorChannel(t, sensorFlow(1, sensorID), sensorFlow(1, sensorID),
		sensorFlow(2, "11111111-2222-4333-8444-555555555555"))); err != nil {
		t.Fatal(err)
	}
	r.tickSensor(bg, false)
	s := st.Snapshot("x").Sensor
	if n := alarms(st, AlarmSensorRecordRefused); n != 2 || s.Refused[sensorlink.RefusedSeq] != 1 || s.Refused[sensorlink.RefusedSensorID] != 1 {
		t.Fatalf("%d refused alarms, refused %v", n, s.Refused)
	}
}

// Status shows the link connected while ServeSensor reads, and not after
// (D6's M7 on #568). Desk only.
func TestSensorConnected(t *testing.T) {
	g := newRetentionRig(t)
	r, st := g.start()
	defer r.Close()
	pr, pw := io.Pipe()
	done := make(chan error, 1)
	go func() { done <- r.ServeSensor(bg, pr) }()
	b := sensorChannel(t, sensorFlow(1, sensorID)).Bytes()
	if _, err := pw.Write(b); err != nil { // returns once Serve has read it
		t.Fatal(err)
	}
	r.tickSensor(bg, false)
	if s := st.Snapshot("x").Sensor; !s.Connected {
		t.Fatalf("not connected while serving: %+v", s)
	}
	pw.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	r.tickSensor(bg, false)
	if s := st.Snapshot("x").Sensor; s.Connected {
		t.Fatalf("connected after the stream ended: %+v", s)
	}
}

// The first write happens at once even at monotonic time 0, which the
// minute gate alone would hold back (D6's M2 on #568). Desk only.
func TestSensorFirstWriteAtMonoZero(t *testing.T) {
	g := newRetentionRig(t)
	r, _ := g.start()
	defer r.Close()
	g.mu.Lock()
	g.mono = 0
	g.mu.Unlock()
	if err := r.ServeSensor(bg, sensorChannel(t, sensorFlow(1, sensorID))); err != nil {
		t.Fatal(err)
	}
	r.tickSensor(bg, false)
	if ev := dropEvents(t, r); len(ev) != 1 || ev[0]["count"] != "1" {
		t.Fatalf("events %v", ev)
	}
}

// A start finds the last drop counts behind more than one page of other
// health records, and past sensorDropScanRecords starts from zero, with
// since the start (D6's M10 and M11 on #568). Desk only.
func TestSensorDropRestoreScan(t *testing.T) {
	g := newRetentionRig(t)
	r, _ := g.start()
	if err := r.ServeSensor(bg, sensorChannel(t, sensorFlow(1, sensorID))); err != nil {
		t.Fatal(err)
	}
	r.tickSensor(bg, false)
	fill := func(r *Runtime, n int) {
		t.Helper()
		for n > 0 {
			k := min(n, 100)
			recs := make([]c5.Record, k)
			for i := range recs {
				rec, err := r.healthRecord(HealthStream, "store.test", map[string]string{"i": strconv.Itoa(i)})
				if err != nil {
					t.Fatal(err)
				}
				recs[i] = rec
			}
			if _, err := r.Log(HealthStream).AppendBatch(bg, recs); err != nil {
				t.Fatal(err)
			}
			n -= k
		}
	}
	fill(r, 600) // more than one 500-record page
	r.Close()
	g.advance(time.Hour)
	r, st := g.start()
	s := st.Snapshot("x").Sensor
	if s.Dropped[sensorlink.DropUnresolvedBudget] != 1 || !s.DropsSince.Equal(time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("behind 600 records: %+v", s)
	}
	fill(r, sensorDropScanRecords)
	r.Close()
	g.advance(time.Hour)
	r, st = g.start()
	defer r.Close()
	if s := st.Snapshot("x").Sensor; s.Dropped[sensorlink.DropUnresolvedBudget] != 0 || !s.DropsSince.Equal(g.now()) {
		t.Fatalf("behind %d records: %+v", sensorDropScanRecords+600, s)
	}
}

// sensorHeartbeat is a heartbeat of sensorRun.
func sensorHeartbeat(seq int) *netobs.Heartbeat {
	return &netobs.Heartbeat{Schema: netobs.Identifier, Type: netobs.TypeHeartbeat, SensorID: sensorID, RunID: sensorRun,
		Seq: strconv.Itoa(seq), AtUTC: "2026-11-07T10:00:10.000000Z", Coverage: sensorFlow(1, sensorID).Coverage,
		Counters: netobs.Counters{Packets: uint64(seq), Bytes: uint64(seq) * 90}, InterfaceCheck: "ok"}
}

// unreachable is the sensor-unreachable alarms raised and status's flag.
func unreachable(r *Runtime, st *Status) (int, bool) {
	r.tickSensor(bg, false)
	return alarms(st, AlarmSensorUnreachable), st.Snapshot("x").Sensor.Unreachable
}

// sensor-unreachable on the node's monotonic clock (D4-73): it is raised
// at SensorUnreachableAfter (60 s) exactly, so not at 59 s from the start
// and raised by 61 s, with no heartbeat ever; once only; and cleared by a
// heartbeat. Desk only.
func TestSensorUnreachable(t *testing.T) {
	g := newRetentionRig(t)
	r, st := g.start()
	defer r.Close()
	step := func(d time.Duration, wantN int, wantFlag bool) {
		t.Helper()
		g.advance(d)
		if n, f := unreachable(r, st); n != wantN || f != wantFlag {
			t.Fatalf("at mono %s: %d alarms, unreachable %v; want %d, %v", g.monoNow(), n, f, wantN, wantFlag)
		}
	}
	step(59*time.Second, 0, false)
	step(2*time.Second, 1, true)
	step(120*time.Second, 1, true) // once
	if err := r.ServeSensor(bg, sensorChannel(t, sensorHeartbeat(1))); err != nil {
		t.Fatal(err)
	}
	step(0, 1, false) // cleared by the heartbeat
	step(59*time.Second, 1, false)
	step(2*time.Second, 2, true) // a new quiet stretch
}

// A connect never resets the timer (D3's S1, D1 in D4-73): reconnecting
// every 30 s for 120 s with no heartbeat raises once, at 61 s after the
// last heartbeat, and the flag stays until a heartbeat. Desk only.
func TestSensorUnreachableReconnects(t *testing.T) {
	g := newRetentionRig(t)
	r, st := g.start()
	defer r.Close()
	if err := r.ServeSensor(bg, sensorChannel(t, sensorHeartbeat(1))); err != nil {
		t.Fatal(err)
	}
	reconnect := func() {
		t.Helper()
		if err := r.ServeSensor(bg, sensorChannel(t)); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range []struct {
		advance   time.Duration
		reconnect bool
		n         int
	}{{30 * time.Second, true, 0}, {29 * time.Second, false, 0}, {time.Second, true, 1}, {time.Second, false, 1},
		{29 * time.Second, true, 1}, {30 * time.Second, true, 1}} {
		g.advance(c.advance)
		if c.reconnect {
			reconnect()
		}
		if n, f := unreachable(r, st); n != c.n || f != (c.n > 0) {
			t.Fatalf("at %s after the heartbeat: %d alarms, unreachable %v; want %d", g.monoNow()-time.Minute, n, f, c.n)
		}
	}
}

// (d): the wall clock moves nothing. A forward wall jump of an hour with
// 10 s of monotonic time raises nothing; a backward wall step with 61 s of
// monotonic time still raises. Desk only.
func TestSensorUnreachableWallSteps(t *testing.T) {
	g := newRetentionRig(t)
	r, st := g.start()
	defer r.Close()
	g.mu.Lock()
	g.wall, g.mono = g.wall.Add(time.Hour), g.mono+10*time.Second
	g.mu.Unlock()
	if n, f := unreachable(r, st); n != 0 || f {
		t.Fatalf("a wall jump raised it: %d, %v", n, f)
	}
	g.mu.Lock()
	g.wall, g.mono = g.wall.Add(-3*time.Hour), g.mono+51*time.Second
	g.mu.Unlock()
	if n, f := unreachable(r, st); n != 1 || !f {
		t.Fatalf("a backward wall step held it back: %d, %v", n, f)
	}
}

// The quiet stretch runs from the last accepted heartbeat, not from the
// connect before it. Desk only.
func TestSensorUnreachableFromHeartbeat(t *testing.T) {
	g := newRetentionRig(t)
	r, st := g.start()
	defer r.Close()
	pr, pw := io.Pipe()
	done := make(chan error, 1)
	go func() { done <- r.ServeSensor(bg, pr) }()
	// Write returns once Serve has read the bytes, which may be before it
	// has accepted the heartbeat, so the test waits for each one before it
	// moves the clock (D1 on #590, go on windows-latest at 0f8fdaf8).
	accepted := func(n uint64) {
		t.Helper()
		for deadline := time.Now().Add(10 * time.Second); r.sensor.link.Stats().Heartbeats < n; {
			if time.Now().After(deadline) {
				t.Fatalf("heartbeat %d not accepted", n)
			}
			time.Sleep(time.Millisecond)
		}
	}
	if _, err := pw.Write(sensorChannel(t, sensorHeartbeat(1)).Bytes()); err != nil {
		t.Fatal(err)
	}
	accepted(1)
	g.advance(40 * time.Second)
	if _, err := pw.Write(sensorChannel(t, sensorHeartbeat(2)).Bytes()); err != nil {
		t.Fatal(err)
	}
	accepted(2)
	g.advance(59 * time.Second)
	if n, f := unreachable(r, st); n != 0 || f {
		t.Fatalf("raised 59 s after a heartbeat: %d, %v", n, f)
	}
	g.advance(2 * time.Second)
	if n, f := unreachable(r, st); n != 1 || !f {
		t.Fatalf("not raised 61 s after a heartbeat: %d, %v", n, f)
	}
	pw.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// The cadence through the exported Tick at the real TickInterval (D1 on
// #581): a heartbeat just after a tick raises nothing at the next tick,
// TickInterval later, and the tick after that raises it, within 60 s +
// TickInterval of the heartbeat. Desk only.
func TestSensorUnreachableTickCadence(t *testing.T) {
	g := newRetentionRig(t)
	r, st := g.start()
	defer r.Close()
	r.Tick(bg)
	g.advance(time.Second)
	if err := r.ServeSensor(bg, sensorChannel(t, sensorHeartbeat(1))); err != nil {
		t.Fatal(err)
	}
	hb := g.monoNow()
	g.advance(TickInterval - time.Second)
	r.Tick(bg)
	if n := alarms(st, AlarmSensorUnreachable); n != 0 {
		t.Fatalf("raised at the first tick after the heartbeat: %d", n)
	}
	g.advance(TickInterval)
	r.Tick(bg)
	if n, f := alarms(st, AlarmSensorUnreachable), st.Snapshot("x").Sensor.Unreachable; n != 1 || !f {
		t.Fatalf("not raised at the second tick: %d, %v", n, f)
	}
	if d := g.monoNow() - hb; d < SensorUnreachableAfter || d > SensorUnreachableAfter+TickInterval {
		t.Fatalf("raised %s after the heartbeat, outside [60 s, 60 s + TickInterval]", d)
	}
}
