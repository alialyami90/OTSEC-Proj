package security

import (
	"context"
	"encoding/json"
	"maps"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"otsec.local/otsec/contracts/event"
	"otsec.local/otsec/contracts/netobs"
	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/platform/node"
	"otsec.local/otsec/platform/node/nodeconfigtest"
	"otsec.local/otsec/platform/sensorlink"
	"otsec.local/otsec/platform/store"
)

// D6's rows for C5 0.9 section 8's alert drops (AP-36 (3), B3 in #597),
// through the node's exported API, against a network-alert class that the
// detector's own alerts really fill: no hook on the store, no injected
// error. The detector raises node-address-spoofed and
// own-session-outside-record on flows from the node's address, as in
// alert_capture_d6_test.go; each (rule, asset) gives one alert per
// coalescing window, so the counts below are exact. The node's monotonic
// clock is a test clock, so the drop event is written when the test
// advances it a minute, or at a clean stop. Evidence class: simulated (in
// process, no network, no sensor, no device).

const (
	adSpoofed = string(netobs.RuleNodeAddressSpoofed)
	adOutside = string(netobs.RuleOwnSessionOutsideRecord)
	adNodeMAC = "02:00:00:00:00:05" // the node's own MAC: no spoof alert
	adUnknown = "198.51.100.77"     // resolves to no asset
)

// adDecoys are enrolled relays at 127.0.0.2 to 127.0.0.6, beside the
// real one, unrAsset, at 127.0.0.1. Each ID's first 8 characters differ,
// as the schedule's IDs need.
var adDecoys = []string{
	"a1d6e0c1-0000-4000-8000-000000000001",
	"a2d6e0c2-0000-4000-8000-000000000002",
	"a3d6e0c3-0000-4000-8000-000000000003",
	"a4d6e0c4-0000-4000-8000-000000000004",
	"a5d6e0c5-0000-4000-8000-000000000005",
}

// adNode is a started node and its monotonic test clock.
type adNode struct {
	r    *node.Runtime
	st   *node.Status
	mono *atomic.Int64
}

// adStart starts a node with a network sensor and the relays, with the
// network-alert class's quota at alertQuota, on the store at dir, which
// it creates on the first start. The monotonic clock starts at 0, as a
// new process's does.
func adStart(t *testing.T, dir string, create bool, alertQuota int64) *adNode {
	t.Helper()
	if create {
		if err := store.CreateDir(dir, ""); err != nil {
			t.Fatal(err)
		}
	}
	nc := nodeconfigtest.New("site-a-node1", dir).AddSEL751(unrAsset, "", 2323, 300)
	for i, id := range adDecoys {
		nc.AddSEL751(id, "127.0.0."+strconv.Itoa(i+2), 2323, 300)
	}
	nc.Store.Quotas["configuration"] = 16 << 20
	nc.Store.Quotas["network-observation"] = 64 << 20
	nc.Store.Quotas["network-alert"] = alertQuota
	nc.NetworkSensor = map[string]any{"sensor_id": unrSensor, "evidence_class": "simulated", "outage_hours": 72, "alert_retention_days": 30,
		"node_addresses": []string{"192.0.2.5"}, "node_macs": []string{adNodeMAC}, "node_vlans": []any{10}}
	if err := nc.WriteInstallKey("ik_d6_alert_drops"); err != nil {
		t.Fatal(err)
	}
	c, err := node.ParseConfig(nc.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	n := &adNode{st: node.NewStatus("", nil, nil), mono: new(atomic.Int64)}
	n.r, err = node.Start(context.Background(), c, node.RuntimeOptions{Status: n.st,
		Mono: func() time.Duration { return time.Duration(n.mono.Load()) }})
	if err != nil {
		t.Fatal(err)
	}
	n.r.Tick(context.Background())
	return n
}

// advance moves the monotonic clock by d and ticks.
func (n *adNode) advance(d time.Duration) {
	n.mono.Add(int64(d))
	n.r.Tick(context.Background())
}

// adHit is one flow start from the node's address to dst:2323 at the
// given time: from a MAC not the node's it raises node-address-spoofed
// and, to an enrolled relay, own-session-outside-record; from the node's
// MAC, only own-session-outside-record, and to an enrolled relay only.
type adHit struct {
	dst, mac string
}

// adWindow sends one flow per hit at at, in one sensor connection, and
// ticks. seq numbers the flows across the test.
func (n *adNode) window(t *testing.T, seq *int, at time.Time, hits ...adHit) {
	t.Helper()
	var recs []any
	for _, h := range hits {
		*seq++
		o := acFlow(*seq, at.Format("2006-01-02T15:04:05.000000Z"), []string{acHash(acFrame(byte(*seq)))})
		o.IP.Dst, o.L2.SrcMAC = h.dst, h.mac
		recs = append(recs, o)
	}
	serveRecs(t, n.r, recs...)
	n.r.Tick(context.Background())
}

// adSpoof and adOwn are the hits on relay i (0 is the real relay).
func adSpoof(i int) adHit { return adHit{"127.0.0." + strconv.Itoa(i+1), "02:00:00:00:00:01"} }
func adOwn(i int) adHit   { return adHit{"127.0.0." + strconv.Itoa(i+1), adNodeMAC} }

// adKey is a (rule, asset) drop key.
func adKey(rule, asset string) string { return rule + "." + asset }

// sensor is the node's sensor status.
func (n *adNode) sensor(t *testing.T, at string) node.SensorStatus {
	t.Helper()
	s := n.st.Snapshot("site-a-node1").Sensor
	if s == nil || s.Detector == nil {
		t.Fatalf("%s: no sensor or detector in status", at)
	}
	return *s
}

// fullAlarms counts the network-full alarms for the alert class.
func (n *adNode) fullAlarms() (k int) {
	for _, a := range n.st.Snapshot("site-a-node1").Alarms {
		if a.Code == string(c5.AlarmNetworkFull) && a.Class == string(c5.ClassNetworkAlert) {
			k++
		}
	}
	return k
}

// alertDropEvents are the alert class's intake.drop-counted details on
// platform/health, oldest first.
func (n *adNode) alertDropEvents(t *testing.T) []map[string]string {
	t.Helper()
	got, err := n.r.Store(node.HealthStream).Read(context.Background(), node.HealthStream, 0, 10000)
	if err != nil {
		t.Fatal(err)
	}
	var out []map[string]string
	for _, st := range got {
		e, err := event.Decode(st.Event)
		if err != nil {
			t.Fatal(err)
		}
		if e.Health != nil && e.Health.Type == event.HealthDropCounted && e.Health.Details["class"] == string(c5.ClassNetworkAlert) {
			out = append(out, e.Health.Details)
		}
	}
	return out
}

// lastAlertDrops is the newest alert-class drop event's details.
func (n *adNode) lastAlertDrops(t *testing.T, at string) map[string]string {
	t.Helper()
	ev := n.alertDropEvents(t)
	if len(ev) == 0 {
		t.Fatalf("%s: no intake.drop-counted event for the alert class", at)
	}
	return ev[len(ev)-1]
}

// fill sends one window a minute after another, each with hits, until the
// store refuses an alert, and returns the time of the next window. The
// class's quota is small, so this takes a few dozen windows.
func (n *adNode) fill(t *testing.T, seq *int, at time.Time, hits ...adHit) time.Time {
	t.Helper()
	for w := 0; ; w++ {
		if w == 200 {
			t.Fatal("the alert class did not fill in 200 windows")
		}
		n.window(t, seq, at, hits...)
		at = at.Add(time.Duration(netobs.DefaultCoalesceWindowS+1) * time.Second)
		if s := n.sensor(t, "filling"); len(s.AlertsDropped) > 0 {
			return at
		}
	}
}

// dropsOf is drops by key as status shows them, less base.
func dropsOf(s node.SensorStatus, base map[string]uint64) map[string]uint64 {
	out := map[string]uint64{}
	for k, v := range s.AlertsDroppedBy {
		if d := v - base[k]; d > 0 {
			out[k] = d
		}
	}
	return out
}

// §8's count test (D5-c5-0.9.md section 8): with the alert class full and
// no forward target, network-full is raised, K alerts of one rule and J
// of another are refused, status shows K and J by (rule, asset) beside
// it, the intake.drop-counted event carries them, and after a clean stop
// and start status shows the same counts.
func TestD6AlertClassFullCounts(t *testing.T) {
	const K, J = 5, 3
	dir := filepath.Join(t.TempDir(), "store")
	n := adStart(t, dir, true, 64<<10)
	seq := 0
	at := n.fill(t, &seq, time.Date(2026, 11, 8, 10, 0, 0, 1000, time.UTC), adOwn(0))
	s := n.sensor(t, "full")
	base, committed := maps.Clone(s.AlertsDroppedBy), s.Detector.Alerts
	if n.fullAlarms() != 1 {
		t.Fatalf("full: %d network-full alarms for the alert class", n.fullAlarms())
	}
	// J windows of a spoofed flow to the real relay (both rules), then
	// K-J of a flow from the node's own MAC (outside-record only). One
	// flow per window, so one alert per rule per window and no summary.
	for w := 0; w < K; w++ {
		hit := adSpoof(0)
		if w >= J {
			hit = adOwn(0)
		}
		n.window(t, &seq, at, hit)
		at = at.Add(time.Duration(netobs.DefaultCoalesceWindowS+1) * time.Second)
	}
	s = n.sensor(t, "after the drops")
	want := map[string]uint64{adKey(adOutside, unrAsset): K, adKey(adSpoofed, unrAsset): J}
	if got := dropsOf(s, base); !maps.Equal(got, want) || s.Detector.Alerts != committed {
		t.Fatalf("drops since full %v, want %v; alerts committed %d, was %d", got, want, s.Detector.Alerts, committed)
	}
	// Once per fill: the detector's prunes of the observation stream
	// leave the alert class without room for a minimum-size record, so
	// they don't re-arm it (D6's F1 on #601, fixed in #602).
	if n.fullAlarms() != 1 {
		t.Fatalf("%d network-full alarms after the drops, want the one", n.fullAlarms())
	}
	var total uint64
	for _, v := range s.AlertsDroppedBy {
		total += v
	}
	if len(s.AlertsDropped) != 1 || s.AlertsDropped[sensorlink.DropClassFull] != total {
		t.Fatalf("drops by reason %v, by key %v", s.AlertsDropped, s.AlertsDroppedBy)
	}
	// The event is written at most once a minute: a minute on, it carries
	// the counts status shows.
	n.advance(node.SensorDropReportEvery)
	ev := n.lastAlertDrops(t, "a minute on")
	wantEv := map[string]string{"stream": string(node.NetAlertStream(unrSensor)), "class": string(c5.ClassNetworkAlert),
		"since": ev["since"], "count": strconv.FormatUint(total, 10), "reason." + sensorlink.DropClassFull: strconv.FormatUint(total, 10)}
	for k, v := range s.AlertsDroppedBy {
		wantEv[k] = strconv.FormatUint(v, 10)
	}
	if !maps.Equal(ev, wantEv) {
		t.Fatalf("event %v, want %v", ev, wantEv)
	}
	before, fullBefore := n.sensor(t, "before the stop"), n.fullAlarms()
	n.r.Close()

	n = adStart(t, dir, false, 64<<10)
	defer n.r.Close()
	after := n.sensor(t, "after the restart")
	if !maps.Equal(after.AlertsDroppedBy, before.AlertsDroppedBy) || !maps.Equal(after.AlertsDropped, before.AlertsDropped) ||
		!after.AlertDropsSince.Equal(before.AlertDropsSince) {
		t.Fatalf("after the restart: by key %v, by reason %v, since %v; before: %v, %v, %v",
			after.AlertsDroppedBy, after.AlertsDropped, after.AlertDropsSince, before.AlertsDroppedBy, before.AlertsDropped, before.AlertDropsSince)
	}
	t.Logf("full after %d alerts; since: %s %d, %s %d; totals %v; %d network-full alarms before the stop",
		committed, adOutside, K, adSpoofed, J, after.AlertsDroppedBy, fullBefore)
}

// D3's hiding case (D5-c5-0.9.md section 8, AP-36's test on #533), with
// decoys on enrolled assets beside the unresolved bucket (D3 and D1 on
// B3). Alerts of rule R, node-address-spoofed, to an unresolved address,
// two records a window (the first and the summary), fill the class; then
// decoys to three enrolled relays and the unresolved address drop in
// three more windows, the unresolved bucket with the most drops; then one
// alert of R to the real relay A is refused. With 8 enrolled pairs, status
// and the event show exactly 1 against (R, A), and the unresolved bucket
// is summed in other. With 10, the real pairs, with the fewest drops, go
// to other, as a spoofed source can always make them (D5-sensor-node.md):
// status still shows every pair, and the total survives a restart.
func TestD6AlertDropsHidingEnrolledDecoys(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "store")
	n := adStart(t, dir, true, 64<<10)
	// The unresolved budget starts empty and fills over outage_hours on
	// the monotonic clock; a full budget lets the unresolved flows commit.
	n.advance(72 * time.Hour)
	seq := 0
	unknown := adHit{adUnknown, "02:00:00:00:00:01"}
	at := n.fill(t, &seq, time.Date(2026, 11, 8, 10, 0, 0, 1000, time.UTC), unknown, unknown)
	committed := n.sensor(t, "full").Detector.Alerts
	for w := 0; w < 3; w++ {
		n.window(t, &seq, at, adSpoof(1), adSpoof(2), adSpoof(3), unknown, unknown)
		at = at.Add(time.Duration(netobs.DefaultCoalesceWindowS+1) * time.Second)
	}
	r, o := adKey(adSpoofed, unrAsset), adKey(adOutside, unrAsset)
	unres := adKey(adSpoofed, netobs.AssetUnresolved)
	n.window(t, &seq, at, adSpoof(0)) // and closes the third window
	at = at.Add(time.Duration(netobs.DefaultCoalesceWindowS+1) * time.Second)
	s := n.sensor(t, "after the real alert")
	u := s.AlertsDroppedBy[unres]
	if s.AlertsDroppedBy[r] != 1 || s.AlertsDroppedBy[o] != 1 || u < 6 || len(s.AlertsDroppedBy) != 9 || s.Detector.Alerts != committed {
		t.Fatalf("drops %v (%d keys), alerts committed %d, was %d", s.AlertsDroppedBy, len(s.AlertsDroppedBy), s.Detector.Alerts, committed)
	}
	for _, i := range []int{1, 2, 3} {
		for _, k := range []string{adKey(adSpoofed, adDecoys[i-1]), adKey(adOutside, adDecoys[i-1])} {
			if s.AlertsDroppedBy[k] != 3 {
				t.Fatalf("decoy %s: %d drops, want 3", k, s.AlertsDroppedBy[k])
			}
		}
	}
	n.advance(node.SensorDropReportEvery)
	ev := n.lastAlertDrops(t, "8 enrolled pairs")
	if ev[r] != "1" || ev[o] != "1" || ev[unres] != "" || ev["other"] != strconv.FormatUint(u, 10) || len(ev) != 4+1+8+1 {
		t.Fatalf("with 8 enrolled pairs: event %v", ev)
	}

	// Two more enrolled pairs: spoofed flows to relay 4, two windows.
	for w := 0; w < 2; w++ {
		n.window(t, &seq, at, adSpoof(4))
		at = at.Add(time.Duration(netobs.DefaultCoalesceWindowS+1) * time.Second)
	}
	s = n.sensor(t, "with 10 enrolled pairs")
	var total uint64
	for _, v := range s.AlertsDroppedBy {
		total += v
	}
	if s.AlertsDroppedBy[r] != 1 || s.AlertsDroppedBy[o] != 1 || len(s.AlertsDroppedBy) != 11 || s.Detector.Alerts != committed {
		t.Fatalf("status with 10 enrolled pairs: %v, alerts committed %d", s.AlertsDroppedBy, s.Detector.Alerts)
	}
	n.r.Close() // a clean stop writes the event
	n = adStart(t, dir, false, 64<<10)
	defer n.r.Close()
	ev = n.lastAlertDrops(t, "10 enrolled pairs")
	if ev[r] != "" || ev[o] != "" || ev[unres] != "" || ev["other"] != strconv.FormatUint(u+2, 10) || ev["count"] != strconv.FormatUint(total, 10) {
		t.Fatalf("with 10 enrolled pairs: event %v, total %d", ev, total)
	}
	after := n.sensor(t, "after the restart")
	var restored uint64
	for k, v := range after.AlertsDroppedBy {
		restored += v
		if ev[k] != strconv.FormatUint(v, 10) {
			t.Errorf("after the restart: %s %d, event %q", k, v, ev[k])
		}
	}
	if restored != total || len(after.AlertsDroppedBy) != 9 || after.AlertsDropped[sensorlink.DropClassFull] != total {
		t.Fatalf("after the restart: %v (sum %d, want %d), by reason %v", after.AlertsDroppedBy, restored, total, after.AlertsDropped)
	}
	b, _ := json.Marshal(after.AlertsDroppedBy)
	t.Logf("unresolved %d; before the restart %d pairs, total %d; after it %s", u, len(s.AlertsDroppedBy), total, b)
}
