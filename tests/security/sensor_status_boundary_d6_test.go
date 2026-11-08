package security

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"otsec.local/otsec/contracts/netobs"
	"otsec.local/otsec/platform/node"
	"otsec.local/otsec/platform/node/nodeconfigtest"
	"otsec.local/otsec/platform/store"
)

// D3's status-boundary probe on #568, as a row through the node's exported
// API (D1, D4-72): text the sensor chooses never reaches the node's status.
// A mark is put in every string field a sensor record carries that intake
// might name or count by: a valid observation's engine and interface
// names, a refused observation's protocol, a foreign sensor's run ID, a
// heartbeat's fields, a record of an unknown type and a frame that is not
// JSON. After the node takes them and ticks, the status snapshot must not
// hold the mark. Evidence class: simulated (in process, no network).
func TestD6SensorTextNeverReachesStatus(t *testing.T) {
	const (
		mark   = "ZZDEVTEXTZZ"
		sensor = "6f1c2a3b-4d5e-4f60-8a71-92b3c4d5e6f7"
		run    = "0b9e4c6d-1a2f-4e3b-8c7d-5f6a7b8c9d0e"
		asset  = "6f1c2e8a-4b3d-4c5e-9f70-0a1b2c3d4e5f"
	)
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "store")
	if err := store.CreateDir(dir, ""); err != nil {
		t.Fatal(err)
	}
	nc := nodeconfigtest.New("site-a-node1", dir).AddSEL751(asset, "", 2323, 300)
	nc.Store.Quotas["configuration"] = 16 << 20
	nc.Store.Quotas["network-observation"] = 64 << 20
	nc.Store.Quotas["network-alert"] = 16 << 20
	nc.NetworkSensor = map[string]any{"sensor_id": sensor, "evidence_class": "simulated", "outage_hours": 72, "alert_retention_days": 30}
	if err := nc.WriteInstallKey("ik_d6_boundary"); err != nil {
		t.Fatal(err)
	}
	c, err := node.ParseConfig(nc.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	st := node.NewStatus("", nil, time.Now)
	r, err := node.Start(ctx, c, node.RuntimeOptions{Status: st})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	flow := func(seq int, sensor string) *netobs.Observation {
		p := func(v int) *int { return &v }
		return &netobs.Observation{
			Schema: netobs.Identifier, Type: netobs.TypeObservation, SensorID: sensor, RunID: run, Seq: strconv.Itoa(seq),
			Kind: netobs.KindFlow, FirstUTC: "2026-11-07T10:00:00.000001Z", LastUTC: "2026-11-07T10:00:00.120001Z", ResolutionNS: 1000,
			L2:        netobs.L2{SrcMAC: "02:00:00:00:00:01", DstMAC: "02:00:00:00:00:02", VLAN: p(10), EtherType: "0x0800"},
			IP:        &netobs.IP{Src: "198.51.100.1", Dst: "198.51.100.2", L4: "tcp", Sport: p(51234), Dport: p(20000)},
			Direction: netobs.DirectionClientServer, Protocol: "dnp3",
			Citation: netobs.Citation{CaptureID: "ring:" + run + ":3", FramesTotal: 1, Frames: []netobs.CitedFrame{
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
	bad := flow(1, sensor)
	bad.Coverage.Engine.Name = mark
	bad.Coverage.Interfaces[0].Name = mark
	bad.Protocol = mark // refused
	good := flow(2, sensor)
	good.Coverage.Engine.Name = mark + "ok"
	good.Coverage.Interfaces[0].Name = mark
	other := flow(3, "11111111-2222-4333-8444-555555555555")
	other.RunID = mark
	hb := map[string]any{"schema": netobs.Identifier, "type": "heartbeat", "sensor_id": sensor, "run_id": run, "seq": "4",
		"at_utc": mark, "interface_check": mark}
	unknown := map[string]any{"type": mark, mark: mark}

	var buf bytes.Buffer
	for _, rec := range []any{bad, good, other, hb, unknown} {
		b, err := json.Marshal(rec)
		if err != nil {
			t.Fatal(err)
		}
		if err := netobs.WriteFrame(&buf, b); err != nil {
			t.Fatal(err)
		}
	}
	if err := netobs.WriteFrame(&buf, []byte(mark+"{not json")); err != nil {
		t.Fatal(err)
	}
	if err := r.ServeSensor(ctx, &buf); err != nil {
		t.Logf("serve: %v", err) // the channel may close on the bad frame; what was taken still counts
	}
	r.Tick(ctx)

	snap := st.Snapshot("site-a-node1")
	b, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	// The row is only meaningful if intake took the records: the four
	// refused ones are counted by reason and the valid one by its drop.
	if snap.Sensor == nil || len(snap.Sensor.Refused) < 4 || len(snap.Sensor.Dropped) == 0 {
		t.Fatalf("intake didn't count the records, so the row tests nothing: %s", b)
	}
	if bytes.Contains(b, []byte(mark)) {
		t.Fatalf("sensor-chosen text in status: %s", b)
	}
}
