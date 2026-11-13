package security

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"otsec.local/otsec/contracts/netobs"
	"otsec.local/otsec/platform/node"
	"otsec.local/otsec/platform/node/nodeconfigtest"
	"otsec.local/otsec/platform/store"
)

// sensor-unreachable through the node's exported API (D1 in D4-73, D6's
// independent rows beside D5's unit tests on #581). The node is started
// with test wall and monotonic clocks, the sensor speaks through
// ServeSensor, and the node is driven by Tick at chosen monotonic times,
// as the service drives it. The alarm is raised at the first Tick at or
// after 60 s with no heartbeat accepted, timed from the
// later of the last accepted heartbeat and the node's start; a connect
// never resets it; it is raised once per quiet stretch; an accepted
// heartbeat clears it. The Tick cadence itself is D5's test on #581.
// Evidence class: simulated (in process, no network,
// no sensor).

const (
	unrSensor = "6f1c2a3b-4d5e-4f60-8a71-92b3c4d5e6f7"
	unrRun    = "0b9e4c6d-1a2f-4e3b-8c7d-5f6a7b8c9d0e"
	unrAsset  = "6f1c2e8a-4b3d-4c5e-9f70-0a1b2c3d4e5f"
)

// unrNode is a node with a network sensor on the test's clocks.
type unrNode struct {
	t    *testing.T
	mu   sync.Mutex
	wall time.Time
	mono time.Duration
	r    *node.Runtime
	st   *node.Status
	hb   int
}

func newUnrNode(t *testing.T) *unrNode {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "store")
	if err := store.CreateDir(dir, ""); err != nil {
		t.Fatal(err)
	}
	nc := nodeconfigtest.New("site-a-node1", dir).AddSEL751(unrAsset, "", 2323, 300)
	nc.Store.Quotas["configuration"] = 16 << 20
	nc.Store.Quotas["network-observation"] = 64 << 20
	nc.Store.Quotas["network-alert"] = 16 << 20
	nc.NetworkSensor = map[string]any{"sensor_id": unrSensor, "evidence_class": "simulated", "outage_hours": 72, "alert_retention_days": 30,
		"node_addresses": []string{"192.0.2.5"}, "node_macs": []string{"02:00:00:00:00:05"}, "node_vlans": []any{10}}
	if err := nc.WriteInstallKey("ik_d6_unreachable"); err != nil {
		t.Fatal(err)
	}
	c, err := node.ParseConfig(nc.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	n := &unrNode{t: t, wall: time.Date(2026, 11, 8, 10, 0, 0, 0, time.UTC), mono: time.Minute}
	n.st = node.NewStatus("", nil, n.now)
	n.r, err = node.Start(context.Background(), c, node.RuntimeOptions{Status: n.st, Now: n.now, Mono: n.monoNow})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { n.r.Close() })
	waitFirstStep(t, n.r)
	return n
}

// waitFirstStep waits for the sensor manager's first step, which opens the
// sensor's database and starts its intake after Start returns (D1's
// ruling on #663). The tests then read the sensor as before.
func waitFirstStep(t *testing.T, r *node.Runtime) {
	t.Helper()
	select {
	case <-r.SensorFirstStep():
	case <-time.After(30 * time.Second):
		t.Fatal("the sensor manager's first step did not end within 30 s")
	}
}

func (n *unrNode) now() time.Time { n.mu.Lock(); defer n.mu.Unlock(); return n.wall }

func (n *unrNode) monoNow() time.Duration { n.mu.Lock(); defer n.mu.Unlock(); return n.mono }

// advance moves the monotonic clock by mono and the wall clock by wall.
func (n *unrNode) advance(mono, wall time.Duration) {
	n.mu.Lock()
	n.mono, n.wall = n.mono+mono, n.wall.Add(wall)
	n.mu.Unlock()
}

// serve is one sensor connection carrying recs, which ends after them.
func (n *unrNode) serve(recs ...any) {
	n.t.Helper()
	var buf bytes.Buffer
	for _, r := range recs {
		b, err := json.Marshal(r)
		if err != nil {
			n.t.Fatal(err)
		}
		if err := netobs.WriteFrame(&buf, b); err != nil {
			n.t.Fatal(err)
		}
	}
	if err := n.r.ServeSensor(context.Background(), &buf); err != nil {
		n.t.Fatal(err)
	}
}

// heartbeat is the sensor's next heartbeat, its counters rising.
func (n *unrNode) heartbeat() *netobs.Heartbeat {
	n.hb++
	return &netobs.Heartbeat{Schema: netobs.Identifier, Type: netobs.TypeHeartbeat, SensorID: unrSensor, RunID: unrRun,
		Seq: strconv.Itoa(n.hb), AtUTC: "2026-11-08T10:00:10.000000Z", InterfaceCheck: "ok",
		Counters: netobs.Counters{Packets: uint64(n.hb), Bytes: uint64(n.hb) * 90},
		Coverage: netobs.Coverage{
			SensorVersion: "0.1.0", Engine: netobs.Engine{Name: "test-engine", Version: "1"},
			Interfaces: []netobs.Interface{{Name: "eth1", Attachment: "span", LAN: "single"}},
			PRP:        netobs.PRP{LANsSeen: []string{}}, HSR: netobs.HSRNotDecoded,
			VLANsSeen: []int{10}, UntaggedSeen: true, Decodes: []string{"dnp3"}, Degraded: []string{},
			Settings: netobs.Settings{SAReplyTimeoutMS: netobs.DefaultSAReplyTimeoutMS, MaxPendingDNP3: netobs.DefaultMaxPendingDNP3, FlowIdleS: netobs.DefaultFlowIdleS},
			SinceUTC: "2026-11-08T08:00:00.000000Z",
		}}
}

// tick runs one Tick and checks the alarms raised so far and the flag.
func (n *unrNode) tick(at string, alarms int, flag bool) {
	n.t.Helper()
	n.r.Tick(context.Background())
	s := n.st.Snapshot("site-a-node1")
	got := 0
	for _, a := range s.Alarms {
		if a.Code == node.AlarmSensorUnreachable {
			got++
		}
	}
	if s.Sensor == nil {
		n.t.Fatalf("%s: status has no sensor section", at)
	}
	if got != alarms || s.Sensor.Unreachable != flag {
		n.t.Fatalf("%s: %d sensor-unreachable alarms, unreachable %v; want %d, %v", at, got, s.Sensor.Unreachable, alarms, flag)
	}
}

// With no heartbeat ever: not at 59 s from the start, raised at the first
// Tick at 60 s, once only, however many Ticks follow.
func TestD6SensorUnreachableFromStart(t *testing.T) {
	n := newUnrNode(t)
	n.advance(59*time.Second, 59*time.Second)
	n.tick("59 s", 0, false)
	n.advance(time.Second, time.Second)
	n.tick("60 s", 1, true)
	for i := range 3 {
		n.advance(60*time.Second, 60*time.Second)
		n.tick("60 s later x"+strconv.Itoa(i+1), 1, true)
	}
}

// After a heartbeat: 59 s raises nothing and 61 s raises it, timed from
// the heartbeat, not from the first Tick after it; a heartbeat clears it, and the next quiet stretch raises it again, once.
func TestD6SensorUnreachableFromHeartbeat(t *testing.T) {
	n := newUnrNode(t)
	n.advance(30*time.Second, 30*time.Second)
	n.serve(n.heartbeat())
	n.advance(40*time.Second, 40*time.Second) // the first Tick after it comes late
	n.tick("40 s after it", 0, false)
	n.advance(19*time.Second, 19*time.Second)
	n.tick("59 s after it", 0, false)
	n.advance(2*time.Second, 2*time.Second)
	n.tick("61 s after it", 1, true)
	n.serve(n.heartbeat())
	n.tick("a second heartbeat", 1, false)
	n.advance(59*time.Second, 59*time.Second)
	n.tick("59 s after the second", 1, false)
	n.advance(2*time.Second, 2*time.Second)
	n.tick("61 s after the second", 2, true)
	n.advance(120*time.Second, 120*time.Second)
	n.tick("181 s after the second", 2, true)
}

// A connect never resets it (D3's S1): after a heartbeat, the sensor
// reconnects about every 30 s for 120 s and no heartbeat is accepted; the
// alarm is raised once, at 61 s after the heartbeat, and stays.
func TestD6SensorUnreachableReconnectLoop(t *testing.T) {
	n := newUnrNode(t)
	n.serve(n.heartbeat())
	n.tick("heartbeat", 0, false)
	elapsed := 0
	for _, c := range []struct {
		at        int // seconds after the heartbeat
		reconnect bool
		alarms    int
	}{{30, true, 0}, {59, false, 0}, {61, true, 1}, {90, true, 1}, {120, true, 1}} {
		d := time.Duration(c.at-elapsed) * time.Second
		n.advance(d, d)
		elapsed = c.at
		if c.reconnect {
			n.serve() // a connection with nothing on it
		}
		n.tick(strconv.Itoa(c.at)+" s after the heartbeat", c.alarms, c.alarms > 0)
	}
}

// The node's monotonic clock times it: a forward wall jump of an hour with
// 10 s of monotonic time raises nothing, and a backward wall step of three
// hours with 61 s of monotonic time still raises it.
func TestD6SensorUnreachableWallSteps(t *testing.T) {
	n := newUnrNode(t)
	n.advance(10*time.Second, time.Hour)
	n.tick("wall +1 h, mono 10 s", 0, false)
	n.advance(51*time.Second, -3*time.Hour)
	n.tick("wall −3 h, mono 61 s", 1, true)
}
