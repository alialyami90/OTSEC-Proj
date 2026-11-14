package contract

// C13 otsec.netobs/0.2, the records (P4-4-CC deliverable 2, D4-103): D6's
// contract tests of docs/phase4/D4-c13-0.2-proposal.md §15's rows T-1 (the
// records), T-4's contract leg, P-1, K-1, T-9, R-2, R-5, U-1 and U-2, the
// heartbeat's new fields (CH-26, CH-27, CH-31, CH-43), and §11's 0.1
// readers: the channel reader main's intake uses stays as strict as it was
// (D4-103 ruling 2), and the 0.2 DecodeDetectorCheckpoint reads a 0.1
// document strictly, with coverage that lacks the two new fields (the
// brief's deliverable 2, "The read of a 0.1 detector checkpoint").
//
// The observation is the netobs body of D6's fixture
// testdata/cc-d0/event-0.4-network-observation.json (#683), its node object
// taken off for the channel; the heartbeat, the alerts and the checkpoint
// are written here from the text. Ground truth: GT-HAND, from the approved
// text. Evidence class: desk.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/event"
	"otsec.local/otsec/contracts/netobs"
)

const (
	v2AssetA = "3f2a1b0c-9d8e-4f7a-a6b5-c4d3e2f1a0b9"
	v2AssetB = "7c1e5a20-4d3b-4f6a-8b2c-9e0d1f2a3b4c"
)

// v2Asset is the nth of a run of distinct asset IDs.
func v2Asset(n int) string { return fmt.Sprintf("1a2b3c4d-0000-4000-8000-%012d", n) }

// v2Stored is the fixture's stored 0.2 observation, as a map.
func v2Stored(t *testing.T) v2Msg {
	t.Helper()
	b, err := os.ReadFile("testdata/cc-d0/event-0.4-network-observation.json")
	if err != nil {
		t.Fatal(err)
	}
	var e struct {
		Netobs v2Msg `json:"netobs"`
	}
	if err := json.Unmarshal(b, &e); err != nil {
		t.Fatal(err)
	}
	return e.Netobs
}

// v2Observation is the same observation as the sensor sends it on the 0.2
// channel: no node object.
func v2Observation(t *testing.T) v2Msg {
	m := v2Stored(t)
	delete(m, "node")
	return m
}

func v2Coverage() map[string]any {
	return map[string]any{
		"sensor_version": "d6-test-0.2", "engine": map[string]any{"name": "zeek", "version": "9.0.1"},
		"interfaces": []any{map[string]any{"name": "mon0", "attachment": "tap", "lan": "single"}},
		"prp":        map[string]any{"lans_seen": []any{}, "duplicates_discarded": false},
		"hsr":        "not-decoded", "vlans_seen": []any{}, "vlans_overflow": false, "untagged_seen": true,
		"decodes": []any{"dnp3", "modbus"}, "degraded": []any{}, "config_digest": v2Digest,
		"settings":  map[string]any{"sa_reply_timeout_ms": 5000, "max_pending_dnp3": 4096, "flow_idle_s": 60, "prp_window_ms": 400},
		"since_utc": "2026-11-15T09:00:00Z",
	}
}

var v2AgentCloses = []string{"handshake", "node-hello", "node-hello-timeout", "binding", "ack", "type", "idle",
	"frame-too-large", "superseded", "run-complete", "shutdown"}

// v2NewCounters are the heartbeat counters C13 0.2 adds: CH-26's three,
// CH-29's four and CH-34's one.
var v2NewCounters = []string{"drops_holder", "frames_overlong", "frames_outgoing", "prp_mismatched",
	"prp_table_full", "prp_tag_differs", "prp_wrong_lan", "engine_lines_refused"}

// v2Heartbeat is a 0.2 heartbeat (0.1 §6 with CH-26, CH-27, CH-29, CH-31,
// CH-34 and CH-43).
func v2Heartbeat() v2Msg {
	closes := map[string]any{}
	for _, k := range v2AgentCloses {
		closes[k] = 0
	}
	counters := map[string]any{"packets": 1200, "bytes": 96000, "drops_driver": 0, "drops_decoder": 0, "drops_channel": 3,
		"decoder_errors": 0, "sessions_unparsed": 0, "table_evictions": 0, "dnp3_pending_overflows": 0,
		"dnp3_seq_reused": 0, "prp_discards": 0, "redactions": 0, "logins_not_placed": 0}
	for _, k := range v2NewCounters {
		counters[k] = 0
	}
	return v2Msg{"schema": "otsec.netobs/0.2", "type": "heartbeat", "sensor_id": v2Sensor, "run_id": v2Run,
		"seq": "12", "at_utc": "2026-11-15T10:00:10Z", "coverage": v2Coverage(), "counters": counters,
		"interface_check": "ok",
		"interfaces":      []any{map[string]any{"name": "mon0", "carrier": "up", "packets": 1200}},
		"agent":           map[string]any{"closes": closes, "taken_ahead": 0, "sync_late": 0, "entries_unreadable": 0},
	}
}

func v2Decode(t *testing.T, m v2Msg) (*netobs.FromSensor, error) {
	t.Helper()
	return netobs.DecodeFromSensor(v2JSON(t, m))
}

func v2HB(t *testing.T, m v2Msg) *netobs.Heartbeat {
	t.Helper()
	f, err := v2Decode(t, m)
	if err != nil || f.Heartbeat == nil {
		t.Fatalf("a valid 0.2 heartbeat: %v", err)
	}
	return f.Heartbeat
}

func v2Has(err error, code netobs.Code) bool { return slices.Contains(netobs.Codes(err), code) }

// The base records pass, and each new field is required on the 0.2 channel
// (C13 0.2 §11, CH-35: "required in a 0.2 channel record").
func TestC13v02RecordsRequired(t *testing.T) {
	if _, err := v2Decode(t, v2Observation(t)); err != nil {
		t.Fatalf("the 0.2 observation: %v", err)
	}
	if _, err := v2Decode(t, v2Heartbeat()); err != nil {
		t.Fatalf("the 0.2 heartbeat: %v", err)
	}
	for _, p := range []string{"made_utc", "coverage.config_digest", "coverage.settings.prp_window_ms"} {
		m := v2Observation(t)
		v2Del(m, p)
		if _, err := v2Decode(t, m); !v2Has(err, netobs.CodeMissing) {
			t.Errorf("a 0.2 observation without %s: %v, want missing", p, err)
		}
	}
	paths := []string{"coverage.config_digest", "coverage.settings.prp_window_ms", "interfaces", "agent"}
	for _, k := range v2NewCounters {
		paths = append(paths, "counters."+k)
	}
	for _, p := range paths {
		m := v2Heartbeat()
		v2Del(m, p)
		if _, err := v2Decode(t, m); !v2Has(err, netobs.CodeMissing) {
			t.Errorf("a 0.2 heartbeat without %s: %v, want missing", p, err)
		}
	}
	// A sensor's record never carries node, at 0.2 as at 0.1.
	if _, err := v2Decode(t, v2Stored(t)); !v2Has(err, netobs.CodeConflict) {
		t.Errorf("a channel observation with node: %v, want conflict", err)
	}
}

// T-1 (CH-21) for the records, and T-4's contract leg: made_utc in RFC 3339
// UTC with Z, other forms refused as form; no order is checked between it
// and the capture times, so a record from a sensor 10 minutes ahead is not
// refused (the lateness that uses E is the node's, owed).
func TestC13v02T1RecordTimes(t *testing.T) {
	for _, v := range []string{"2026-11-14T09:58:02+00:00", "2026-11-14T09:58:02z", "2026-11-14T09:58:02.1234567890Z", "2026-11-14 09:58:02Z", "1763114282"} {
		m := v2Observation(t)
		m["made_utc"] = v
		if _, err := v2Decode(t, m); !v2Has(err, netobs.CodeForm) {
			t.Errorf("made_utc %q: %v, want form", v, err)
		}
	}
	for name, v := range map[string]string{
		"nine fractional digits":      "2026-11-14T09:58:02.123456789Z",
		"10 minutes after last_utc":   "2026-11-14T10:08:02.123456Z",
		"before first_utc":            "2026-11-14T09:58:01Z",
		"in 2100, a sensor far ahead": "2100-01-01T00:00:00Z",
	} {
		m := v2Observation(t)
		m["made_utc"] = v
		if _, err := v2Decode(t, m); err != nil {
			t.Errorf("made_utc %s: %v", name, err)
		}
	}
	for _, v := range []string{"2026-11-15T10:00:10+01:00", "2026-11-15T10:00:10"} {
		m := v2Heartbeat()
		m["at_utc"] = v
		if _, err := v2Decode(t, m); !v2Has(err, netobs.CodeForm) {
			t.Errorf("heartbeat at_utc %q: %v, want form", v, err)
		}
	}
}

// P-1 (CH-28): prp_window_ms outside 10 to 2,000 is range; absent is
// missing.
func TestC13v02P1PRPWindow(t *testing.T) {
	for _, rec := range []func() v2Msg{func() v2Msg { return v2Observation(t) }, v2Heartbeat} {
		for v, want := range map[int]netobs.Code{9: netobs.CodeRange, 2001: netobs.CodeRange, 0: netobs.CodeRange, -1: netobs.CodeRange, 10: "", 400: "", 2000: ""} {
			m := rec()
			v2Set(m, "coverage.settings.prp_window_ms", v)
			_, err := v2Decode(t, m)
			if (want == "" && err != nil) || (want != "" && !v2Has(err, want)) {
				t.Errorf("%s prp_window_ms %d: %v, want %q", m["type"], v, err, want)
			}
		}
	}
}

// CH-32: config_digest is sha256: and 64 lowercase hex digits.
func TestC13v02ConfigDigestForm(t *testing.T) {
	for _, v := range []string{"sha256:" + strings.Repeat("A", 64), "sha256:" + strings.Repeat("a", 63), "sha256:" + strings.Repeat("a", 65), "SHA256:" + strings.Repeat("a", 64), strings.Repeat("a", 64), "sha512:" + strings.Repeat("a", 64)} {
		for _, m := range []v2Msg{v2Observation(t), v2Heartbeat()} {
			v2Set(m, "coverage.config_digest", v)
			if _, err := v2Decode(t, m); !v2Has(err, netobs.CodeForm) {
				t.Errorf("%s config_digest %q: %v, want form", m["type"], v, err)
			}
		}
	}
}

// K-1 (CH-31): the heartbeat's interfaces.
func TestC13v02K1Interfaces(t *testing.T) {
	two := func() v2Msg {
		m := v2Heartbeat()
		v2Set(m, "coverage.interfaces", []any{
			map[string]any{"name": "mon0", "attachment": "tap", "lan": "single"},
			map[string]any{"name": "mon1", "attachment": "tap", "lan": "single"}})
		m["interfaces"] = []any{
			map[string]any{"name": "mon0", "carrier": "up", "packets": 1000},
			map[string]any{"name": "mon1", "carrier": "down", "packets": 200}}
		return m
	}
	if _, err := v2Decode(t, two()); err != nil {
		t.Fatalf("two interfaces summing to packets: %v", err)
	}
	if _, err := v2Decode(t, func() v2Msg {
		m := two()
		m["interfaces"] = []any{m["interfaces"].([]any)[1], m["interfaces"].([]any)[0]}
		return m
	}()); err != nil {
		t.Errorf("the two in another order: %v", err)
	}
	for name, c := range map[string]struct {
		f    func(v2Msg)
		code netobs.Code
	}{
		"a name not in the coverage statement": {func(m v2Msg) { m["interfaces"].([]any)[1].(map[string]any)["name"] = "mon2" }, netobs.CodeConflict},
		"one interface left out":               {func(m v2Msg) { m["interfaces"] = m["interfaces"].([]any)[:1]; v2Set(m, "counters.packets", 1000) }, netobs.CodeConflict},
		"one interface twice": {func(m v2Msg) {
			m["interfaces"] = []any{m["interfaces"].([]any)[0], maps.Clone(m["interfaces"].([]any)[0].(map[string]any))}
			v2Set(m, "counters.packets", 2000)
		}, netobs.CodeConflict},
		"no interfaces":             {func(m v2Msg) { m["interfaces"] = []any{} }, netobs.CodeConflict},
		"a sum below packets":       {func(m v2Msg) { v2Set(m, "counters.packets", 1201) }, netobs.CodeConflict},
		"a sum above packets":       {func(m v2Msg) { v2Set(m, "counters.packets", 1199) }, netobs.CodeConflict},
		"a carrier outside its set": {func(m v2Msg) { m["interfaces"].([]any)[0].(map[string]any)["carrier"] = "dormant" }, netobs.CodeForm},
		"a sum that wraps 2^64": {func(m v2Msg) {
			m["interfaces"].([]any)[0].(map[string]any)["packets"] = uint64(1<<64 - 1)
			v2Set(m, "counters.packets", 199)
		}, netobs.CodeConflict},
	} {
		m := two()
		c.f(m)
		if _, err := v2Decode(t, m); !v2Has(err, c.code) {
			t.Errorf("%s: %v, want %s", name, err, c.code)
		}
	}
	for _, carrier := range []string{"up", "down", "unknown"} {
		m := v2Heartbeat()
		m["interfaces"].([]any)[0].(map[string]any)["carrier"] = carrier
		if _, err := v2Decode(t, m); err != nil {
			t.Errorf("carrier %s: %v", carrier, err)
		}
	}
	// A falling interfaces[].packets within a run is refused as order.
	prev := v2HB(t, two())
	next := two()
	next["seq"] = "13"
	next["interfaces"].([]any)[1].(map[string]any)["packets"] = 199
	next["interfaces"].([]any)[0].(map[string]any)["packets"] = 1001
	if err := v2HB(t, next).Follows(prev); !v2Has(err, netobs.CodeOrder) {
		t.Errorf("mon1's packets falling from 200 to 199: %v, want order", err)
	}
	same := two()
	same["seq"] = "13"
	if err := v2HB(t, same).Follows(prev); err != nil {
		t.Errorf("unchanged counts: %v", err)
	}
}

// CH-26, CH-29, CH-34: the eight new counters are run totals that never
// decrease; and CH-43: the agent's counts, every key present, none
// falling. Follows refuses a fall as order (S-2's heartbeat leg covers
// drops_channel, a 0.1 counter, with the same rule).
func TestC13v02HeartbeatCounts(t *testing.T) {
	prev := v2Heartbeat()
	for _, k := range v2NewCounters {
		v2Set(prev, "counters."+k, 5)
	}
	for _, k := range v2AgentCloses {
		v2Set(prev, "agent.closes."+k, 5)
	}
	for _, k := range []string{"taken_ahead", "sync_late", "entries_unreadable"} {
		v2Set(prev, "agent."+k, 5)
	}
	p := v2HB(t, prev)
	paths := []string{"counters.drops_channel"}
	for _, k := range v2NewCounters {
		paths = append(paths, "counters."+k)
	}
	for _, k := range v2AgentCloses {
		paths = append(paths, "agent.closes."+k)
	}
	paths = append(paths, "agent.taken_ahead", "agent.sync_late", "agent.entries_unreadable")
	for _, path := range paths {
		next := v2Heartbeat()
		next["seq"] = "13"
		for _, k := range v2NewCounters {
			v2Set(next, "counters."+k, 5)
		}
		for _, k := range v2AgentCloses {
			v2Set(next, "agent.closes."+k, 5)
		}
		for _, k := range []string{"taken_ahead", "sync_late", "entries_unreadable"} {
			v2Set(next, "agent."+k, 5)
		}
		old := 5
		if path == "counters.drops_channel" {
			old = 3
		}
		v2Set(next, path, old-1)
		if err := v2HB(t, next).Follows(p); !v2Has(err, netobs.CodeOrder) {
			t.Errorf("%s falling: %v, want order", path, err)
		}
		v2Set(next, path, old)
		if err := v2HB(t, next).Follows(p); err != nil {
			t.Errorf("%s unchanged: %v", path, err)
		}
	}
	// A new run starts afresh.
	other := v2Heartbeat()
	other["run_id"] = v2RunB
	if err := v2HB(t, other).Follows(p); err != nil {
		t.Errorf("a new run's first heartbeat: %v", err)
	}
	// Each of the agent's keys is required, and no other key is taken.
	for _, k := range append(slices.Clone(v2AgentCloses), "taken_ahead", "sync_late", "entries_unreadable") {
		m := v2Heartbeat()
		if slices.Contains(v2AgentCloses, k) {
			v2Del(m, "agent.closes."+k)
		} else {
			v2Del(m, "agent."+k)
		}
		if _, err := v2Decode(t, m); err == nil || !(v2Has(err, netobs.CodeMissing) || v2Has(err, netobs.CodeDecode)) {
			t.Errorf("agent without %s: %v, want missing or decode", k, err)
		}
	}
	for name, path := range map[string]string{"closed-before-hello": "agent.closes.closed-before-hello", "an unknown count": "agent.restarts"} {
		m := v2Heartbeat()
		v2Set(m, path, 0)
		if _, err := v2Decode(t, m); !v2Has(err, netobs.CodeDecode) {
			t.Errorf("agent with %s: %v, want decode", name, err)
		}
	}
	// The counters' bound: 2^64 - 1 is a count, a negative one is not.
	m := v2Heartbeat()
	v2Set(m, "counters.frames_outgoing", uint64(1<<64-1))
	if _, err := v2Decode(t, m); err != nil {
		t.Errorf("frames_outgoing at 2^64 - 1: %v", err)
	}
	v2Set(m, "counters.frames_outgoing", -1)
	if _, err := v2Decode(t, m); err == nil {
		t.Error("frames_outgoing -1 accepted")
	}
}

// CH-27: egress_check is ok or absent, and is left out when it cannot be
// read; another value is refused.
func TestC13v02EgressCheck(t *testing.T) {
	for v, ok := range map[string]bool{"ok": true, "absent": true, "unknown": false, "bound": false, "OK": false} {
		m := v2Heartbeat()
		m["egress_check"] = v
		if _, err := v2Decode(t, m); (err == nil) != ok {
			t.Errorf("egress_check %q: %v, want accepted %v", v, err, ok)
		}
	}
	if _, err := v2Decode(t, v2Heartbeat()); err != nil {
		t.Errorf("egress_check left out: %v", err)
	}
}

// R-2 (CH-35): the stored reader takes a 0.1 observation without the new
// fields, strictly; a stored 0.2 observation may lack them; a later minor
// is read forward.
func TestC13v02R2StoredReader(t *testing.T) {
	added := []string{"made_utc", "coverage.config_digest", "coverage.settings.prp_window_ms", "node.late", "node.backlog", "node.lost"}
	at01 := func(keep string) v2Msg {
		m := v2Stored(t)
		m["schema"] = "otsec.netobs/0.1"
		for _, p := range added {
			if p != keep {
				v2Del(m, p)
			}
		}
		return m
	}
	o, err := netobs.DecodeStored(v2JSON(t, at01("")))
	if err != nil || o.Schema != "otsec.netobs/0.1" || o.MadeUTC != "" || o.Coverage.ConfigDigest != "" || o.Node.Late || o.Node.Lost != nil {
		t.Fatalf("a stored 0.1 observation: %+v, %v", o, err)
	}
	for _, p := range added {
		if _, err := netobs.DecodeStored(v2JSON(t, at01(p))); err == nil {
			t.Errorf("a stored 0.1 observation with %s: accepted", p)
		}
	}
	skewed := at01("")
	v2Set(skewed, "node.skewed", true)
	if _, err := netobs.DecodeStored(v2JSON(t, skewed)); err == nil {
		t.Error("a stored 0.1 observation with node.skewed: accepted")
	}
	// At 0.2 each new field is optional in a stored record.
	m := v2Stored(t)
	for _, p := range added {
		v2Del(m, p)
	}
	if _, err := netobs.DecodeStored(v2JSON(t, m)); err != nil {
		t.Errorf("a stored 0.2 observation without the new fields: %v", err)
	}
	// node.lost holds at most 8 spans, each in form.
	m = v2Stored(t)
	var l []any
	for i := range 9 {
		l = append(l, v2Span(fmt.Sprintf("2026-11-14T09:%02d:00Z", 2*i), fmt.Sprintf("2026-11-14T09:%02d:30Z", 2*i)))
	}
	v2Set(m, "node.lost", l)
	if _, err := netobs.DecodeStored(v2JSON(t, m)); !v2Has(err, netobs.CodeRange) {
		t.Errorf("node.lost with 9 spans: %v, want range", err)
	}
	v2Set(m, "node.lost", l[:8])
	if _, err := netobs.DecodeStored(v2JSON(t, m)); err != nil {
		t.Errorf("node.lost with 8 spans: %v", err)
	}
	// A later minor is read forward: a field it adds is ignored.
	m = v2Stored(t)
	m["schema"], m["added_in_0_3"] = "otsec.netobs/0.3", "x"
	if _, err := netobs.DecodeStored(v2JSON(t, m)); err != nil {
		t.Errorf("a stored 0.3 observation with a new field: %v", err)
	}
	// At its own minor the reader is strict.
	m = v2Stored(t)
	m["added_in_0_3"] = "x"
	if _, err := netobs.DecodeStored(v2JSON(t, m)); !v2Has(err, netobs.CodeDecode) {
		t.Errorf("a stored 0.2 observation with an unknown field: %v, want decode", err)
	}
}

// D4-103 ruling 2: the 0.1 channel reader that main's intake uses
// (DecodeChannel) stays as it was. A 0.1 record carrying any key 0.2 adds
// is refused, as main refused it (an unknown field refuses the record, 0.1
// §1), whatever the key's value; and so does the 0.1 stored reader. The
// zero values matter because the Go types now hold these fields with
// omitempty, so a key present with its zero value must not read as absent.
func TestC13v02Readers01StayStrict(t *testing.T) {
	obs01 := func() v2Msg {
		m := v2Observation(t)
		m["schema"] = "otsec.netobs/0.1"
		v2Del(m, "made_utc")
		v2Del(m, "coverage.config_digest")
		v2Del(m, "coverage.settings.prp_window_ms")
		return m
	}
	hb01 := func() v2Msg {
		m := v2Heartbeat()
		m["schema"] = "otsec.netobs/0.1"
		v2Del(m, "coverage.config_digest")
		v2Del(m, "coverage.settings.prp_window_ms")
		v2Del(m, "interfaces")
		v2Del(m, "agent")
		for _, k := range v2NewCounters {
			v2Del(m, "counters."+k)
		}
		return m
	}
	if _, err := netobs.DecodeChannel(v2JSON(t, obs01())); err != nil {
		t.Fatalf("a 0.1 channel observation: %v", err)
	}
	if _, err := netobs.DecodeChannel(v2JSON(t, hb01())); err != nil {
		t.Fatalf("a 0.1 channel heartbeat: %v", err)
	}
	type tc struct {
		path string
		v    any
	}
	for _, c := range []tc{
		{"made_utc", "2026-11-14T09:58:02.4Z"}, {"made_utc", ""},
		{"coverage.config_digest", v2Digest}, {"coverage.config_digest", ""},
		{"coverage.settings.prp_window_ms", 400}, {"coverage.settings.prp_window_ms", 0},
	} {
		m := obs01()
		v2Set(m, c.path, c.v)
		if _, err := netobs.DecodeChannel(v2JSON(t, m)); err == nil {
			t.Errorf("a 0.1 channel observation with %s %v: accepted", c.path, c.v)
		}
	}
	for _, c := range []tc{
		{"interfaces", nil}, {"interfaces", []any{}}, {"agent", nil}, {"egress_check", ""}, {"egress_check", "ok"},
		{"counters.drops_holder", nil}, {"counters.drops_holder", 0}, {"counters.engine_lines_refused", nil},
		{"coverage.config_digest", ""}, {"coverage.settings.prp_window_ms", 0},
	} {
		m := hb01()
		v2Set(m, c.path, c.v)
		if _, err := netobs.DecodeChannel(v2JSON(t, m)); err == nil {
			t.Errorf("a 0.1 channel heartbeat with %s %v: accepted", c.path, c.v)
		}
	}
	// The stored reader, on a 0.1 record.
	stored01 := func() v2Msg {
		m := v2Stored(t)
		m["schema"] = "otsec.netobs/0.1"
		for _, p := range []string{"made_utc", "coverage.config_digest", "coverage.settings.prp_window_ms", "node.late", "node.backlog", "node.lost"} {
			v2Del(m, p)
		}
		return m
	}
	for _, c := range []tc{
		{"made_utc", ""}, {"coverage.config_digest", ""}, {"coverage.settings.prp_window_ms", 0},
		{"node.late", false}, {"node.backlog", false}, {"node.skewed", false}, {"node.lost", nil},
	} {
		m := stored01()
		v2Set(m, c.path, c.v)
		if _, err := netobs.DecodeStored(v2JSON(t, m)); err == nil {
			t.Errorf("a stored 0.1 observation with %s %v: accepted", c.path, c.v)
		}
	}
}

// R-5 (CH-35's sizes, §12): the new bounds by value; the node's messages
// (in c13_v02_link_d6_test.go); the stored body against 0.1's 24 KiB, which
// a 0.1 DecodeStored checks first; and what the new fields add to a stored
// observation at their largest, against CH-35's figures. The cursor leg in
// Record.Bytes is owed (the C13 0.2 intake brief), and the worst body's
// absolute size is D4's TestWorstStored02Fits, not rebuilt here.
func TestC13v02R5Bounds(t *testing.T) {
	for _, c := range []struct {
		name      string
		got, want int64
	}{
		{"MaxNodeMessage", int64(netobs.MaxNodeMessage), 1 << 10},
		{"MaxLostSpans", int64(netobs.MaxLostSpans), 8},
		{"MinBufferBytes", int64(netobs.MinBufferBytes), 16 << 20},
		{"MaxBufferBytes", int64(netobs.MaxBufferBytes), 64 << 30},
		{"SiteBufferFloor", int64(netobs.SiteBufferFloor), 256 << 20},
		{"TickMinSpacing (ms)", netobs.TickMinSpacing.Milliseconds(), 5000},
		{"DefaultPRPWindowMS", int64(netobs.DefaultPRPWindowMS), 400},
		{"MinPRPWindowMS", int64(netobs.MinPRPWindowMS), 10},
		{"MaxPRPWindowMS", int64(netobs.MaxPRPWindowMS), 2000},
		{"MaxAggregateAssets", int64(netobs.MaxAggregateAssets), 8},
		{"MaxInterfaces", int64(netobs.MaxInterfaces), 8},
		{"MaxChannelFrame", int64(netobs.MaxChannelFrame), 64 << 10},
		{"MaxCoverageBytes", int64(netobs.MaxCoverageBytes), 2 << 10},
		{"event.MaxNetobsBytes", int64(event.MaxNetobsBytes), 24 << 10},
		{"MaxAlertBytes", int64(netobs.MaxAlertBytes), 24 << 10},
	} {
		if c.got != c.want {
			t.Errorf("%s %d, C13 0.2 states %d", c.name, c.got, c.want)
		}
	}
	// 24 KiB is the stored body's bound: at it, read; one byte over,
	// refused before decoding.
	b := v2JSON(t, v2Stored(t))
	pad := func(n int) []byte {
		return append(append(bytes.Clone(b[:len(b)-1]), bytes.Repeat([]byte(" "), n-len(b))...), '}')
	}
	if _, err := netobs.DecodeStored(pad(24 << 10)); err != nil {
		t.Errorf("a stored body of 24 KiB: %v", err)
	}
	if _, err := netobs.DecodeStored(pad(24<<10 + 1)); !v2Has(err, netobs.CodeRange) {
		t.Errorf("a stored body of 24 KiB + 1: %v, want range", err)
	}
	// The new fields at their largest: made_utc and the three marks, eight
	// spans, the digest and the window.
	base := v2Stored(t)
	for _, p := range []string{"made_utc", "coverage.config_digest", "coverage.settings.prp_window_ms", "node.late", "node.backlog", "node.lost"} {
		v2Del(base, p)
	}
	full := v2Stored(t)
	full["made_utc"] = "2026-11-14T09:58:02.123456789Z"
	v2Set(full, "node.late", true)
	v2Set(full, "node.backlog", true)
	v2Set(full, "node.skewed", true)
	var l []any
	for i := range 8 {
		l = append(l, v2Span(fmt.Sprintf("2026-11-14T09:%02d:00.123456789Z", 2*i), fmt.Sprintf("2026-11-14T09:%02d:30.123456789Z", 2*i)))
	}
	v2Set(full, "node.lost", l)
	v2Set(full, "coverage.settings.prp_window_ms", 2000)
	if _, err := netobs.DecodeStored(v2JSON(t, full)); err != nil {
		t.Fatalf("the new fields at their largest: %v", err)
	}
	added := len(v2JSON(t, full)) - len(v2JSON(t, base))
	t.Logf("the 0.2 fields add %d bytes to a stored observation at their largest (CH-35: about 60 + 8 x 70 + 110)", added)
	if added > 1<<10 {
		t.Errorf("the 0.2 fields add %d bytes, above 1 KiB", added)
	}
}

// T-9 (CH-47): the three aggregate keys, each only for the two own-session
// rules, with assets present exactly with a key and assets_total at least
// their number.
func TestC13v02T9Aggregate(t *testing.T) {
	cov := map[string]string{}
	for k, v := range func() map[string]string {
		b, err := os.ReadFile("testdata/cc-d0/event-0.4-netobs-alert.json")
		if err != nil {
			t.Fatal(err)
		}
		var e struct {
			Health struct {
				Details map[string]string `json:"details"`
			} `json:"health"`
		}
		if err := json.Unmarshal(b, &e); err != nil {
			t.Fatal(err)
		}
		return e.Health.Details
	}() {
		if strings.HasPrefix(k, "coverage.") {
			cov[k] = v
		}
	}
	unseen := func(key string) map[string]string {
		d := map[string]string{"schema": "otsec.netobs/0.2", "rule": "own-session-unseen", "asset_id": key,
			"key_text": "the node's sessions while no tie was made", "baseline_value": "every session of the node is seen",
			"observation": "sessions of the node not seen on the wire", "clock": "capture",
			"at_utc": "2026-11-15T10:00:00Z", "window_start_utc": "2026-11-15T09:58:00Z", "hits": "50",
			"sources": "0", "related_total": "0", "param.tie_grace_s": "30",
			"assets": v2AssetA + " " + v2AssetB, "assets_total": "50"}
		maps.Copy(d, cov)
		return d
	}
	outside := func(key string) map[string]string {
		d := unseen(key)
		d["rule"], d["sources"], d["related_total"], d["hits"] = "own-session-outside-record", "1", "1", "1"
		d["cite.1"] = "ring:0d1e2f30-4a5b-4c6d-8e7f-a0b1c2d3e4f5:7 1=767354afe9a0c562d52ada82288f55ab76b29b863a5a282119797f909621e3f6"
		d["capture"] = "4a4085de4a744472679284a1113a53c7a1cfca55736d9e3953b034f8a05b574a"
		return d
	}
	related := []event.EventID{{NodeID: "d6-node", Stream: "network-observation/5a3c2e10-7b4d-4c8e-9f1a-2b3c4d5e6f70", Seq: 41}}
	read := func(d map[string]string) (*netobs.Alert, error) {
		h := event.Health{Type: netobs.HealthAlert, Details: d}
		if d["rule"] != "own-session-unseen" {
			h.Related = related
		}
		return netobs.AlertFromHealth(h)
	}
	for _, key := range []string{"clock-skew", "sensor-records-late", "hold-timeout"} {
		for name, d := range map[string]map[string]string{"own-session-unseen": unseen(key), "own-session-outside-record": outside(key)} {
			a, err := read(d)
			if err != nil {
				t.Errorf("%s under %s: %v", key, name, err)
				continue
			}
			if a.AssetID != key || !slices.Equal(a.Assets, []string{v2AssetA, v2AssetB}) || a.AssetsTotal != 50 {
				t.Errorf("%s under %s read as %q %v %d", key, name, a.AssetID, a.Assets, a.AssetsTotal)
			}
		}
	}
	nine := make([]string, 9)
	for i := range nine {
		nine[i] = v2Asset(i + 1)
	}
	// CH-47 names conflict for the first five; the rest are refused by the
	// form of assets ("the asset IDs it covers ... at most 8") or of
	// asset_id.
	for _, c := range []struct {
		name     string
		f        func(map[string]string)
		conflict bool
	}{
		{"a key under another rule", func(d map[string]string) {
			o := outside("x")
			d["rule"], d["sources"], d["related_total"], d["hits"] = "sa-failed", "1", "1", "1"
			d["cite.1"], d["capture"] = o["cite.1"], o["capture"]
			delete(d, "param.tie_grace_s")
		}, true},
		{"a key without assets", func(d map[string]string) { delete(d, "assets"); delete(d, "assets_total") }, true},
		{"a key with assets and no assets_total", func(d map[string]string) { delete(d, "assets_total") }, true},
		{"a key with assets_total and no assets", func(d map[string]string) { delete(d, "assets") }, true},
		{"assets under an asset ID", func(d map[string]string) { d["asset_id"] = v2AssetA }, true},
		{"assets under asset-unresolved", func(d map[string]string) { d["asset_id"] = "asset-unresolved" }, true},
		{"assets_total below the assets listed", func(d map[string]string) { d["assets_total"] = "1" }, true},
		{"nine assets", func(d map[string]string) { d["assets"], d["assets_total"] = strings.Join(nine, " "), "9" }, false},
		{"an asset repeated", func(d map[string]string) { d["assets"] = v2AssetA + " " + v2AssetA }, false},
		{"asset-unresolved in assets", func(d map[string]string) { d["assets"] = v2AssetA + " asset-unresolved" }, false},
		{"an empty assets", func(d map[string]string) { d["assets"] = "" }, false},
		{"another key", func(d map[string]string) { d["asset_id"] = "sensor-clock-skew" }, false},
		{"a key at 0.1", func(d map[string]string) {
			d["schema"] = "otsec.netobs/0.1"
			delete(d, "coverage.config_digest")
			delete(d, "coverage.settings.prp_window_ms")
		}, false},
	} {
		d := unseen("hold-timeout")
		c.f(d)
		_, err := read(d)
		if err == nil || (c.conflict && !v2Has(err, netobs.CodeConflict)) {
			t.Errorf("%s: %v, want it refused%s", c.name, err, map[bool]string{true: " as conflict (CH-47)"}[c.conflict])
		}
	}
	// The limits that pass: eight assets, a total equal to them.
	d := unseen("clock-skew")
	d["assets"], d["assets_total"] = strings.Join(nine[:8], " "), "8"
	if _, err := read(d); err != nil {
		t.Errorf("eight assets, total 8: %v", err)
	}
	// A later minor reads the keys forward.
	d = unseen("sensor-records-late")
	d["schema"] = "otsec.netobs/0.3"
	if _, err := read(d); err != nil {
		t.Errorf("a 0.3 alert under an aggregate key: %v", err)
	}
	// A hold-timeout alert built by the detector names its assets, through
	// the health body and back.
	a, err := read(unseen("hold-timeout"))
	if err != nil {
		t.Fatal(err)
	}
	h, err := a.Health()
	if err != nil {
		t.Fatalf("Health: %v", err)
	}
	if h.Details["assets"] != v2AssetA+" "+v2AssetB || h.Details["assets_total"] != "50" {
		t.Errorf("the health body carries assets %q, assets_total %q", h.Details["assets"], h.Details["assets_total"])
	}
}

// U-1 (CH-48) and U-2 (CH-49), the record's form: a flow the engine names
// nothing for gives its flow records with protocol unknown and one
// undecoded record with basis none; a layer-2 frame gives basis ethertype;
// basis port stays in the closed set for a later minor. A service record
// puts the server at ip.dst even on the flow whose first sender is the
// server, and a UDP flow's src is its first sender.
func TestC13v02U1U2Forms(t *testing.T) {
	flow := func() v2Msg {
		m := v2Observation(t)
		m["protocol"] = "unknown"
		m["ip"] = map[string]any{"src": "192.0.2.14", "dst": "192.0.2.30", "l4": "tcp", "sport": 41022, "dport": 5020}
		return m
	}
	undecoded := func(basis string) v2Msg {
		m := flow()
		delete(m, "flow")
		m["kind"], m["undecoded"] = "undecoded", map[string]any{"basis": basis, "packets": 3}
		return m
	}
	l2 := func() v2Msg {
		m := undecoded("ethertype")
		delete(m, "ip")
		m["direction"] = "none"
		v2Set(m, "l2.ethertype", "0x88b5")
		return m
	}
	udpFlow := func() v2Msg {
		m := v2Observation(t)
		m["ip"] = map[string]any{"src": "192.0.2.20", "dst": "192.0.2.14", "l4": "udp", "sport": 20000, "dport": 20000}
		m["direction"] = "none"
		return m
	}
	service := func() v2Msg {
		m := v2Observation(t)
		delete(m, "flow")
		m["kind"], m["service"] = "service", map[string]any{"basis": "content"}
		m["ip"] = map[string]any{"src": "192.0.2.14", "dst": "192.0.2.20", "l4": "udp", "sport": 20000, "dport": 20000}
		m["direction"] = "none"
		return m
	}
	for name, m := range map[string]v2Msg{
		"a TCP flow with protocol unknown":        flow(),
		"undecoded, basis none":                   undecoded("none"),
		"undecoded, basis port (a later minor's)": undecoded("port"),
		"undecoded layer-2, basis ethertype":      l2(),
		"a UDP flow from the outstation":          udpFlow(),
		"a service at ip.dst":                     service(),
	} {
		if _, err := v2Decode(t, m); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := v2Decode(t, undecoded("guess")); !v2Has(err, netobs.CodeForm) {
		t.Errorf("undecoded with basis guess: %v, want form", err)
	}
}

// The read of a 0.1 detector checkpoint (CH-35's table, "Read"; the brief's
// deliverable 2): the 0.2 DecodeDetectorCheckpoint reads a 0.1 document
// strictly, with coverage that lacks the two new fields. A 0.1 document
// whose coverage carries either is refused, as is any key 0.1 does not
// define, whatever its value. This code writes 0.2.
func TestC13v02Checkpoint01(t *testing.T) {
	if netobs.CheckpointIdentifier != "otsec.netcheckpoint/0.2" || netobs.CheckpointIdentifier01 != "otsec.netcheckpoint/0.1" {
		t.Fatalf("CheckpointIdentifier %q, CheckpointIdentifier01 %q", netobs.CheckpointIdentifier, netobs.CheckpointIdentifier01)
	}
	cov01 := func() map[string]any {
		c := v2Coverage()
		delete(c, "config_digest")
		delete(c["settings"].(map[string]any), "prp_window_ms")
		return c
	}
	doc := func(schema string) v2Msg {
		return v2Msg{"schema": schema, "half": "detector", "sensor_id": v2Sensor, "node_id": "d6-node",
			"stream": "network-observation/" + v2Sensor, "baseline": "", "baseline_version": 0, "through": 41,
			"last_alert_seq": 3, "clock_utc": "2026-11-14T09:58:02.123456Z",
			"windows": []any{map[string]any{"rule": "own-session-unseen", "asset_id": v2AssetA,
				"key_text": "a session of the node to 192.0.2.20", "baseline_value": "every session of the node is seen",
				"observation": "a session of the node not seen on the wire", "at_utc": "2026-11-14T09:58:00Z",
				"window_start_utc": "2026-11-14T09:58:00Z", "hits": 1, "sources": []any{}, "related": []any{},
				"cites": []any{}, "coverage": cov01()}},
			"coverage": cov01(), "session_through": 0, "sessions": []any{}, "tied": []any{}, "taken": []any{},
			"endpoints": []any{}, "degraded": []any{}, "degraded_open": false}
	}
	k, err := netobs.DecodeDetectorCheckpoint(v2JSON(t, doc("otsec.netcheckpoint/0.1")))
	if err != nil {
		t.Fatalf("a 0.1 detector checkpoint: %v", err)
	}
	if k.Schema != "otsec.netcheckpoint/0.1" || k.Coverage == nil || k.Coverage.ConfigDigest != "" || k.Coverage.Settings.PRPWindowMS != 0 || len(k.Windows) != 1 {
		t.Errorf("read as %q, coverage %+v, %d windows", k.Schema, k.Coverage, len(k.Windows))
	}
	type tc struct {
		name string
		f    func(v2Msg)
	}
	for _, c := range []tc{
		{"coverage.config_digest", func(m v2Msg) { v2Set(m, "coverage.config_digest", v2Digest) }},
		{"coverage.settings.prp_window_ms", func(m v2Msg) { v2Set(m, "coverage.settings.prp_window_ms", 400) }},
		{"a window's config_digest", func(m v2Msg) {
			m["windows"].([]any)[0].(map[string]any)["coverage"].(map[string]any)["config_digest"] = v2Digest
		}},
		{"a window's prp_window_ms", func(m v2Msg) {
			m["windows"].([]any)[0].(map[string]any)["coverage"].(map[string]any)["settings"].(map[string]any)["prp_window_ms"] = 400
		}},
		{"an aggregate key in a window", func(m v2Msg) { m["windows"].([]any)[0].(map[string]any)["asset_id"] = "clock-skew" }},
		{"a key 0.1 does not define", func(m v2Msg) { m["assets"] = []any{} }},
		{"coverage.config_digest empty", func(m v2Msg) { v2Set(m, "coverage.config_digest", "") }},
		{"coverage.settings.prp_window_ms 0", func(m v2Msg) { v2Set(m, "coverage.settings.prp_window_ms", 0) }},
		{"a window's config_digest empty", func(m v2Msg) {
			m["windows"].([]any)[0].(map[string]any)["coverage"].(map[string]any)["config_digest"] = ""
		}},
	} {
		m := doc("otsec.netcheckpoint/0.1")
		c.f(m)
		if _, err := netobs.DecodeDetectorCheckpoint(v2JSON(t, m)); err == nil {
			t.Errorf("a 0.1 checkpoint with %s: accepted", c.name)
		}
	}
	// The same document at 0.2: its coverage may hold the two fields or
	// lack them (a coverage statement from a stored 0.1 observation).
	m := doc("otsec.netcheckpoint/0.2")
	if _, err := netobs.DecodeDetectorCheckpoint(v2JSON(t, m)); err != nil {
		t.Errorf("a 0.2 checkpoint whose coverage lacks the two fields: %v", err)
	}
	v2Set(m, "coverage.config_digest", v2Digest)
	v2Set(m, "coverage.settings.prp_window_ms", 400)
	if _, err := netobs.DecodeDetectorCheckpoint(v2JSON(t, m)); err != nil {
		t.Errorf("a 0.2 checkpoint whose coverage has them: %v", err)
	}
	for _, schema := range []string{"otsec.netcheckpoint/0.3", "otsec.netcheckpoint/1.0", "otsec.netobs/0.2"} {
		if _, err := netobs.DecodeDetectorCheckpoint(v2JSON(t, doc(schema))); !v2Has(err, netobs.CodeSchema) {
			t.Errorf("a checkpoint stamped %s: %v, want schema", schema, err)
		}
	}
}
