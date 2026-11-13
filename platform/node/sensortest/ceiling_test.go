package sensortest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"otsec.local/otsec/contracts/netobs"
	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/platform/node"
	"otsec.local/otsec/platform/node/nodeconfigtest"
)

// sensorRun is the constructed sensor run. Its flows are between TEST-NET-2
// addresses, which no asset holds, so every one is unresolved and, with
// the unresolved budget nearly spent, dropped and counted.
const sensorRun = "0b9e4c6d-1a2f-4e3b-8c7d-5f6a7b8c9d0e"

func unresolvedFlow(seq int) *netobs.Observation {
	p := func(v int) *int { return &v }
	return &netobs.Observation{
		Schema: netobs.Identifier, Type: netobs.TypeObservation, SensorID: sensorID, RunID: sensorRun, Seq: strconv.Itoa(seq),
		Kind: netobs.KindFlow, FirstUTC: "2026-11-13T10:00:00.000001Z", LastUTC: "2026-11-13T10:00:00.120001Z", ResolutionNS: 1000,
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
			SinceUTC: "2026-11-13T08:00:00.000000Z",
		},
		Flow: &netobs.Flow{Phase: "start", Packets: 3, Bytes: 222},
	}
}

// channel frames records as the sensor writes them.
func channel(t *testing.T, recs ...any) *bytes.Buffer {
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

// sized is a platform health record of about n bytes, as collection's
// collection.* records are reckoned at (node.SensorHealthRecordBytes).
func sized(n int) c5.Record {
	ev := fmt.Sprintf(`{"schema":"otsec.event/0.1","id":{"node_id":"site-a-node1","stream":%q,"seq":0},`+
		`"origin":"platform","kind":"telemetry-health","source":{"origin_auth":"platform"},`+
		`"received":{"utc":"2026-11-13T10:00:00.000001Z","resolution_ns":1000,"clock":{"sync":"synchronized","source":"ntp"}},`+
		`"health":{"type":"sensortest.collection","details":{"pad":"%s"}}}`, string(node.HealthStream), strings.Repeat("x", max(n-420, 1)))
	return c5.Record{Stream: node.HealthStream, Class: c5.ClassPlatform, Event: []byte(ev)}
}

// F1's ceiling in bytes (section 1.9 item 5), in process on the test clock
// over main's sensor events (intake.drop-counted): the platform class is
// filled to just under its quota less collection's need C, then the
// sensor's drops are counted and written once a minute for a quarter of an
// hour. The sensor's events stop beneath the ceiling and are counted in
// health_held, so collection's C is still there: C's worth of collection
// records, at 4,096 bytes each, all commit. Control 1 (the ceiling
// removed: ceilingFits always true) lets the sensor's events into C, and
// collection's records are refused at the quota.
func TestSensorEventsUnderPlatformCeiling(t *testing.T) {
	const h = 1
	// One SEL-751 read every 300 s over one outage hour.
	col, sen := int64(12*2*node.SensorHealthRecordBytes*h), int64(node.SensorHealthEventsHour*node.SensorHealthRecordBytes*h)
	quota := col + sen + 256<<10
	g := newRig(t, func(nc *nodeconfigtest.Config) {
		nc.NetworkSensor["outage_hours"] = h
		nc.Store.Quotas["platform"] = quota
		nc.Store.Quotas["network-observation"] = 1 << 20
	})
	if c, s := g.c.PlatformFloor(); c != col || s != sen {
		t.Fatalf("PlatformFloor %d, %d; want %d, %d", c, s, col, sen)
	}
	r, st := g.start(node.SensorSeams{})
	defer r.Close()
	db := r.Store(node.HealthStream)
	used := func() int64 {
		n, err := db.ClassBytes(bg, c5.ClassPlatform)
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	for used()+3600 < quota-col-2500 {
		if _, err := r.Log(node.HealthStream).Append(bg, sized(3500)); err != nil {
			t.Fatal(err)
		}
	}
	seq := 0
	for range 15 {
		var recs []any
		for range 10 {
			seq++
			recs = append(recs, unresolvedFlow(seq))
		}
		if err := r.ServeSensor(bg, channel(t, recs...)); err != nil {
			t.Fatal(err)
		}
		g.advance(time.Minute)
		r.Tick(bg)
		if err := r.WaitSensorStep(bg); err != nil {
			t.Fatal(err)
		}
	}
	if u := used(); u >= quota-col {
		t.Fatalf("the platform class holds %d bytes, at or past the ceiling %d", u, quota-col)
	}
	for i := range int(col / node.SensorHealthRecordBytes) {
		if _, err := r.Log(node.HealthStream).Append(bg, sized(node.SensorHealthRecordBytes-96)); err != nil {
			t.Fatalf("collection's record %d of its need was refused: %v (class %d of %d bytes)", i, err, used(), quota)
		}
	}
	s := st.Snapshot("x").Sensor
	if s == nil || s.HealthHeld == 0 || s.Dropped["unresolved-budget"] == 0 {
		t.Fatalf("no sensor event held at the ceiling: %+v", s)
	}
}
