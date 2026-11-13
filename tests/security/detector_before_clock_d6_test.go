package security

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"otsec.local/otsec/contracts/event"
	"otsec.local/otsec/contracts/netobs"
	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/platform/node"
	"otsec.local/otsec/platform/node/nodeconfigtest"
	"otsec.local/otsec/platform/store"
)

// D6's independent row for B4 (C13 §14 item 19, D1 on #590 and #593),
// through the node's exported API, beside D5's unit row in platform/node.
// A collection runs before the sensor has sent anything, so the detector
// takes a connected session with no capture clock. The node must store
// that checkpoint without network-detector-checkpoint-failed, a restart
// must restore it with the session pending, and the session must then be
// judged once observations move the clock past its end plus tie_grace_s:
// with no flow of its own, own-session-unseen. Evidence class: simulated
// (in process, no network, no sensor, no device).

const bcInvocation = "3c2b1a09-8f7e-4d6c-9b5a-4a3b2c1d0e0f"

// bcStart starts a node with a network sensor on the store at dir, which
// it creates on the first start.
func bcStart(t *testing.T, dir string, create bool) (*node.Runtime, *node.Status) {
	t.Helper()
	if create {
		if err := store.CreateDir(dir, ""); err != nil {
			t.Fatal(err)
		}
	}
	nc := nodeconfigtest.New("site-a-node1", dir).AddSEL751(unrAsset, "", 2323, 300)
	nc.Store.Quotas["configuration"] = 16 << 20
	nc.Store.Quotas["network-observation"] = 64 << 20
	nc.Store.Quotas["network-alert"] = 16 << 20
	nc.NetworkSensor = map[string]any{"sensor_id": unrSensor, "evidence_class": "simulated", "outage_hours": 72, "alert_retention_days": 30,
		"node_addresses": []string{"192.0.2.5"}, "node_macs": []string{"02:00:00:00:00:05"}, "node_vlans": []any{10}}
	if err := nc.WriteInstallKey("ik_d6_before_clock"); err != nil {
		t.Fatal(err)
	}
	c, err := node.ParseConfig(nc.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	st := node.NewStatus("", nil, nil)
	r, err := node.Start(context.Background(), c, node.RuntimeOptions{Status: st})
	if err != nil {
		t.Fatal(err)
	}
	waitFirstStep(t, r)
	return r, st
}

// bcSession commits a connected collection.run to the health stream, as
// the scheduler's ending record holds it, with after_seq 0: no
// observation had committed when its result was released.
func bcSession(t *testing.T, r *node.Runtime) c5.Seq {
	t.Helper()
	e := event.Event{Schema: event.Identifier, ID: event.EventID{NodeID: "site-a-node1", Stream: event.Stream(node.HealthStream)},
		Origin: event.OriginPlatform, Kind: event.KindHealth, Source: event.Source{OriginAuth: event.AuthPlatform},
		Received: event.Received{UTC: time.Now().UTC().Format("2006-01-02T15:04:05.000000Z"), ResolutionNS: 1000, Clock: event.Clock{Sync: event.SyncUnknown}},
		Health: &event.Health{Type: node.HealthCollectionRun, Details: map[string]string{
			"asset_id": unrAsset, "request_id": "r-d6-before-clock", "invocation_id": bcInvocation, "status": "ok",
			"endpoint": "127.0.0.1:2323", "l4": "tcp", "started_at": "2026-11-08T10:00:00Z", "ended_at": "2026-11-08T10:00:01Z",
			"connected": "true", "open_flow": "false", "after_seq": "0"}}}
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	rc, err := r.Log(node.HealthStream).Append(context.Background(), c5.Record{Stream: node.HealthStream, Class: c5.ClassPlatform, Event: b})
	if err != nil {
		t.Fatal(err)
	}
	return rc.Key().Seq
}

// bcFlow is a flow between two hosts other than the node, to the relay's
// address on VLAN 10, at first: it shows the address on the wire and
// moves the capture clock, and ties to no session.
func bcFlow(seq int, first string) *netobs.Observation {
	p := func(v int) *int { return &v }
	return &netobs.Observation{
		Schema: netobs.Identifier, Type: netobs.TypeObservation, SensorID: unrSensor, RunID: unrRun, Seq: strconv.Itoa(seq),
		Kind: netobs.KindFlow, FirstUTC: first, LastUTC: first, ResolutionNS: 1000,
		L2:        netobs.L2{SrcMAC: "02:00:00:00:00:01", DstMAC: "02:00:00:00:00:02", VLAN: p(10), EtherType: "0x0800"},
		IP:        &netobs.IP{Src: "198.51.100.1", Dst: "127.0.0.1", L4: "tcp", Sport: p(51234), Dport: p(20000)},
		Direction: netobs.DirectionClientServer, Protocol: "dnp3",
		Citation: netobs.Citation{CaptureID: "ring:" + unrRun + ":3", FramesTotal: 1, Frames: []netobs.CitedFrame{
			{N: int64(seq), CapturedLen: 74, WireLen: 74, SHA256: "5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef"}}},
		Coverage: netobs.Coverage{
			SensorVersion: "0.1.0", Engine: netobs.Engine{Name: "test-engine", Version: "1"},
			Interfaces: []netobs.Interface{{Name: "eth1", Attachment: "span", LAN: "single"}},
			PRP:        netobs.PRP{LANsSeen: []string{}}, HSR: netobs.HSRNotDecoded,
			VLANsSeen: []int{10}, UntaggedSeen: true, Decodes: []string{"dnp3"}, Degraded: []string{},
			Settings: netobs.Settings{SAReplyTimeoutMS: netobs.DefaultSAReplyTimeoutMS, MaxPendingDNP3: netobs.DefaultMaxPendingDNP3, FlowIdleS: netobs.DefaultFlowIdleS},
			SinceUTC: "2026-11-08T08:00:00.000000Z",
		},
		Flow: &netobs.Flow{Phase: "start", Packets: 3, Bytes: 222},
	}
}

// serveRecs is one sensor connection carrying recs. ServeSensor returns
// once it has taken them all, so they are committed before it returns.
func serveRecs(t *testing.T, r *node.Runtime, recs ...any) {
	t.Helper()
	var buf bytes.Buffer
	for _, rec := range recs {
		b, err := json.Marshal(rec)
		if err != nil {
			t.Fatal(err)
		}
		if err := netobs.WriteFrame(&buf, b); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.ServeSensor(context.Background(), &buf); err != nil {
		t.Fatal(err)
	}
}

// bcCheckpoint is the newest netcheckpoint.detector on the sensor's
// baseline stream, and how many are stored.
func bcCheckpoint(t *testing.T, r *node.Runtime) (*netobs.DetectorCheckpoint, int) {
	t.Helper()
	stream := node.NetBaselineStream(unrSensor)
	got, err := r.Store(stream).Read(context.Background(), stream, 0, 1000)
	if err != nil {
		t.Fatal(err)
	}
	var (
		k *netobs.DetectorCheckpoint
		n int
	)
	for _, st := range got {
		var head struct{ Schema, Half string }
		if json.Unmarshal(st.Event, &head) != nil || head.Schema != netobs.CheckpointIdentifier || head.Half != netobs.HalfDetector {
			continue
		}
		if k, err = netobs.DecodeDetectorCheckpoint(st.Event); err != nil {
			t.Fatal(err)
		}
		n++
	}
	if k == nil {
		t.Fatal("no detector checkpoint stored")
	}
	return k, n
}

// bcAlarms counts the alarms with code in status.
func bcAlarms(st *node.Status, code string) (n int) {
	for _, a := range st.Snapshot("site-a-node1").Alarms {
		if a.Code == code {
			n++
		}
	}
	return n
}

// bcUnseen counts the committed own-session-unseen alerts for the session.
func bcUnseen(t *testing.T, r *node.Runtime) (n int) {
	t.Helper()
	stream := node.NetAlertStream(unrSensor)
	got, err := r.Store(stream).Read(context.Background(), stream, 0, 1000)
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
		if a.Rule == netobs.RuleOwnSessionUnseen {
			if a.AssetID != unrAsset || st.EvidenceRef != "" {
				t.Errorf("own-session-unseen for %s with evidence %q", a.AssetID, st.EvidenceRef)
			}
			n++
		}
	}
	return n
}

// bcDetector is the detector's part of status.
func bcDetector(t *testing.T, st *node.Status, at string) node.DetectorStatus {
	t.Helper()
	s := st.Snapshot("site-a-node1").Sensor
	if s == nil || s.Detector == nil {
		t.Fatalf("%s: no detector in status", at)
	}
	return *s.Detector
}

func TestD6DetectorSessionBeforeClock(t *testing.T) {
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "store")
	r, st := bcStart(t, dir, true)
	r.Tick(ctx) // the detector starts and stores its first-start checkpoint
	run := bcSession(t, r)
	r.Tick(ctx)
	k, n := bcCheckpoint(t, r)
	d := bcDetector(t, st, "before any observation")
	if f := bcAlarms(st, node.AlarmDetectorCheckpoint); f != 0 || d.CheckpointFailures != 0 || d.CheckpointsWritten != 2 {
		t.Fatalf("before any observation: %d checkpoint-failed alarms, status %+v", f, d)
	}
	if k.ClockUTC != "" || k.Through != 0 || k.SessionThrough != uint64(run) || len(k.Sessions) != 1 || k.Sessions[0].InvocationID != bcInvocation || len(k.Taken) != 0 || n != 1 {
		t.Fatalf("checkpoint: clock %q, through %d, session_through %d (want %d), sessions %+v, taken %d, %d stored",
			k.ClockUTC, k.Through, k.SessionThrough, run, k.Sessions, len(k.Taken), n)
	}
	if u := bcUnseen(t, r); u != 0 {
		t.Fatalf("judged with no clock: %d own-session-unseen", u)
	}
	r.Close()

	r, st = bcStart(t, dir, false)
	defer r.Close()
	r.Tick(ctx)
	if d := bcDetector(t, st, "after the restart"); !d.Restored || bcAlarms(st, node.AlarmDetectorNotRestored) != 0 || d.OrderingFaults != 0 {
		t.Fatalf("after the restart: status %+v, %d not-restored alarms", d, bcAlarms(st, node.AlarmDetectorNotRestored))
	}
	// 10:00:20 is before the session's end plus tie_grace_s (10:00:31):
	// the session stays pending. 10:01:00 is past it: judged, unseen.
	serveRecs(t, r, bcFlow(1, "2026-11-08T10:00:20.000000Z"))
	r.Tick(ctx)
	if u := bcUnseen(t, r); u != 0 {
		t.Fatalf("judged before its end plus tie_grace_s: %d own-session-unseen", u)
	}
	serveRecs(t, r, bcFlow(2, "2026-11-08T10:01:00.000000Z"))
	r.Tick(ctx)
	d = bcDetector(t, st, "after the clock passed")
	if u := bcUnseen(t, r); u != 1 || d.Through != 2 || bcAlarms(st, node.AlarmDetectorCheckpoint) != 0 || d.CheckpointFailures != 0 {
		t.Fatalf("after the clock passed: %d own-session-unseen, status %+v", u, d)
	}
	if k, _ := bcCheckpoint(t, r); len(k.Sessions) != 0 || k.ClockUTC == "" {
		t.Fatalf("checkpoint after the verdict: clock %q, sessions %+v", k.ClockUTC, k.Sessions)
	}
}
