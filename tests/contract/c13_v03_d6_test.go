package contract

// C13 otsec.netobs/0.3 (P4-4-CC deliverable 3, D4-103): D6's contract tests
// of docs/phase4/D4-c13-0.3-proposal.md §12's rows N-1, N-2's legs (1) and
// (2), N-4, N-5, N-7, N-9's decoder half, and N-12's second and third
// cases. N-12's first case is in cc_d3_n12_d6_test.go. N-8's leg (2) and
// N-13 are D5's node legs. The rest are owed by the briefs that brief
// P4-4-CC's "Owed" table names: N-2's leg (3), N-3, N-6, N-8's legs (1)
// and (3), N-9's node half, N-10, N-11 and N-14 to N-19.
//
// Every record is written here from the text (§1 to §6, §12) on the 0.2
// records of c13_v02_records_d6_test.go, not from contracts/netobs's tests
// or helpers. A record after the hello is read as the node reads it on a
// 0.3 connection, DecodeFromSensorIn with the hello's schema (CH-36).
// Ground truth: GT-HAND, from the approved text. Evidence class: desk.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"math"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/event"
	"otsec.local/otsec/contracts/netobs"
)

const (
	v3Schema = "otsec.netobs/0.3"
	v2Schema = "otsec.netobs/0.2"
)

// v3Counts are the counts 0.3 adds to a flow end, CH-52's four first
// (CH-52 to CH-55). v3Keys adds incomplete (CH-53).
var (
	v3Counts = []string{"orig_payload", "resp_payload", "orig_pkts", "resp_pkts",
		"to_device_overlap_octets", "rexmit_inconsistent", "password_lines"}
	v3Keys = append(slices.Clone(v3Counts), "incomplete")
)

// v3End is a TCP end as a 0.3 sensor sends it: the end of a Telnet flow
// from the node to a relay, its overlap count complete, with one password
// line, as in testdata/cc-d3's counted fixture.
func v3End(t *testing.T) v2Msg {
	m := v2Observation(t)
	m["schema"] = v3Schema
	m["ip"] = map[string]any{"src": "192.0.2.14", "dst": "192.0.2.20", "l4": "tcp", "sport": 49812, "dport": 23}
	m["protocol"] = "telnet"
	m["last_utc"] = "2026-11-14T09:58:09.87431Z"
	m["flow"] = map[string]any{"phase": "end", "packets": 38, "bytes": 3728, "end": "fin", "syn_only": false,
		"orig_payload": 214, "resp_payload": 1462, "orig_pkts": 19, "resp_pkts": 19,
		"to_device_overlap_octets": 0, "rexmit_inconsistent": 0, "password_lines": 1}
	return m
}

// v3UDPEnd is a UDP end, which carries CH-52's four counts only.
func v3UDPEnd(t *testing.T) v2Msg {
	m := v3End(t)
	m["ip"] = map[string]any{"src": "192.0.2.14", "dst": "192.0.2.21", "l4": "udp", "sport": 50161, "dport": 161}
	m["direction"], m["protocol"] = "none", "snmp"
	m["flow"] = map[string]any{"phase": "end", "packets": 4, "bytes": 612, "end": "idle",
		"orig_payload": 230, "resp_payload": 214, "orig_pkts": 2, "resp_pkts": 2}
	return m
}

// v3Start is the TCP flow's start, which carries none of them.
func v3Start(t *testing.T) v2Msg {
	m := v3End(t)
	m["last_utc"] = m["first_utc"]
	m["flow"] = map[string]any{"phase": "start", "packets": 1, "bytes": 74}
	return m
}

// v3Without drops every key 0.3 adds to an end.
func v3Without(m v2Msg) v2Msg {
	for _, k := range v3Keys {
		v2Del(m, "flow."+k)
	}
	return m
}

// v3Stored is m as the node stores it, at schema: the node object of the
// cc-d0 fixture back on, and at 0.1 without 0.2's fields.
func v3Stored(t *testing.T, m v2Msg, schema string) v2Msg {
	m["schema"] = schema
	m["node"] = v2Stored(t)["node"]
	if schema == "otsec.netobs/0.1" {
		for _, p := range []string{"made_utc", "coverage.config_digest", "coverage.settings.prp_window_ms", "node.late", "node.backlog", "node.lost"} {
			v2Del(m, p)
		}
	}
	return m
}

// v3On reads m as a record after the hello on a connection of minor conn.
func v3On(t *testing.T, m v2Msg, conn string) (*netobs.FromSensor, error) {
	t.Helper()
	return netobs.DecodeFromSensorIn(v2JSON(t, m), conn)
}

func v3Decode(t *testing.T, m v2Msg) (*netobs.FromSensor, error) {
	t.Helper()
	return v3On(t, m, v3Schema)
}

func v3Stored03(t *testing.T, m v2Msg) (*netobs.Observation, error) {
	t.Helper()
	return netobs.DecodeStored(v2JSON(t, v3Stored(t, m, v3Schema)))
}

// N-4 (CH-52, CH-54, CH-55): placement. On the 0.3 channel the four counts
// are required on a TCP and a UDP end, and rexmit_inconsistent on a TCP
// end; none is on a start; rexmit_inconsistent and password_lines are on a
// TCP end only; password_lines is never required and never beside
// incomplete. A flow is never on a layer-2 record. In a stored record of
// 0.1, 0.2 and 0.3 each may be absent. Below 0.3 each is refused, as the
// 0.2 channel refused it (§1.1): on a 0.2 connection, and in a 0.3 record
// on a 0.2 connection, which is not that connection's minor (CH-36).
func TestC13v03N4Placement(t *testing.T) {
	for name, m := range map[string]v2Msg{"a TCP end": v3End(t), "a UDP end": v3UDPEnd(t), "a start": v3Start(t)} {
		if _, err := v3Decode(t, m); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	for _, k := range v3Counts[:4] {
		for name, end := range map[string]func(*testing.T) v2Msg{"TCP": v3End, "UDP": v3UDPEnd} {
			m := end(t)
			v2Del(m, "flow."+k)
			if _, err := v3Decode(t, m); !v2Has(err, netobs.CodeMissing) {
				t.Errorf("a 0.3 %s end without %s: %v, want missing", name, k, err)
			}
		}
	}
	m := v3End(t)
	v2Del(m, "flow.rexmit_inconsistent")
	if _, err := v3Decode(t, m); !v2Has(err, netobs.CodeMissing) {
		t.Errorf("a 0.3 TCP end without rexmit_inconsistent: %v, want missing", err)
	}
	m = v3End(t)
	v2Del(m, "flow.password_lines")
	if _, err := v3Decode(t, m); err != nil {
		t.Errorf("a 0.3 TCP end without password_lines, which is never required: %v", err)
	}
	for _, k := range v3Counts {
		m := v3Start(t)
		v2Set(m, "flow."+k, 0)
		if _, err := v3Decode(t, m); !v2Has(err, netobs.CodeConflict) {
			t.Errorf("a start with %s: %v, want conflict", k, err)
		}
	}
	for _, k := range []string{"rexmit_inconsistent", "password_lines"} {
		m := v3UDPEnd(t)
		v2Set(m, "flow."+k, 0)
		if _, err := v3Decode(t, m); !v2Has(err, netobs.CodeConflict) {
			t.Errorf("a UDP end with %s: %v, want conflict", k, err)
		}
	}
	m = v3End(t)
	v2Set(m, "flow.incomplete", true)
	if _, err := v3Decode(t, m); !v2Has(err, netobs.CodeConflict) {
		t.Errorf("password_lines beside incomplete: true: %v, want conflict", err)
	}
	m = v3End(t)
	delete(m, "ip")
	m["direction"] = "none"
	if _, err := v3Decode(t, m); !v2Has(err, netobs.CodeConflict) {
		t.Errorf("a layer-2 record with a flow end and its counts: %v, want conflict", err)
	}
	// Stored: each may be absent at 0.1, 0.2 and 0.3, and at 0.3 each alone
	// may be absent, the channel's required ones included.
	for _, schema := range []string{"otsec.netobs/0.1", v2Schema, v3Schema} {
		for name, end := range map[string]func(*testing.T) v2Msg{"TCP": v3End, "UDP": v3UDPEnd} {
			if _, err := netobs.DecodeStored(v2JSON(t, v3Stored(t, v3Without(end(t)), schema))); err != nil {
				t.Errorf("a stored %s %s end without the 0.3 fields: %v", schema, name, err)
			}
		}
	}
	for _, k := range v3Counts {
		m := v3End(t)
		v2Del(m, "flow."+k)
		if _, err := v3Stored03(t, m); err != nil {
			t.Errorf("a stored 0.3 TCP end without %s: %v", k, err)
		}
	}
	// Below 0.3 on the channel: a 0.2 connection's end with any of them is
	// refused, whatever its value; and a 0.3 record on a 0.2 connection, or
	// a 0.2 record on a 0.3 one, is one record refused as schema.
	if _, err := v3On(t, v3Without(v3End(t)), v2Schema); !v2Has(err, netobs.CodeSchema) {
		t.Errorf("a 0.3 record on a 0.2 connection: %v, want schema", err)
	}
	m02 := func() v2Msg {
		m := v3Without(v3End(t))
		m["schema"] = v2Schema
		return m
	}
	if _, err := v3On(t, m02(), v2Schema); err != nil {
		t.Fatalf("a 0.2 end on a 0.2 connection: %v", err)
	}
	if _, err := v3Decode(t, m02()); !v2Has(err, netobs.CodeSchema) {
		t.Errorf("a 0.2 record on a 0.3 connection: %v, want schema", err)
	}
	for _, k := range v3Keys {
		m := m02()
		v2Set(m, "flow."+k, map[bool]any{true: true, false: 0}[k == "incomplete"])
		if _, err := v3On(t, m, v2Schema); !v2Has(err, netobs.CodeDecode) {
			t.Errorf("a 0.2 channel end with %s: %v, want decode", k, err)
		}
	}
}

// N-5 (CH-52 to CH-55): each count is a decimal from 0 to 2^63 - 1: -1 is
// refused as range, 0 and 2^63 - 1 are accepted, and 2^63 is refused (no
// int64 holds it, so it fails as decode or range), on the channel and in a
// stored record. On a syn-only TCP end both payload counts are 0.
func TestC13v03N5Ranges(t *testing.T) {
	for _, k := range v3Counts {
		for _, c := range []struct {
			v    any
			want []netobs.Code
		}{
			{-1, []netobs.Code{netobs.CodeRange}},
			{0, nil},
			{int64(math.MaxInt64), nil},
			{uint64(1 << 63), []netobs.Code{netobs.CodeDecode, netobs.CodeRange}},
		} {
			m := v3End(t)
			v2Set(m, "flow."+k, c.v)
			_, err1 := v3Decode(t, m)
			_, err2 := v3Stored03(t, m)
			for where, err := range map[string]error{"channel": err1, "stored": err2} {
				if c.want == nil && err != nil {
					t.Errorf("%s %s %v: %v", where, k, c.v, err)
				}
				if c.want != nil && !slices.ContainsFunc(c.want, func(code netobs.Code) bool { return v2Has(err, code) }) {
					t.Errorf("%s %s %v: %v, want %v", where, k, c.v, err, c.want)
				}
			}
		}
	}
	// A syn-only end: the client's SYNs and no handshake, so no overlap
	// record joined and the agent marks it incomplete (CH-53).
	synOnly := func() v2Msg {
		m := v3End(t)
		m["flow"] = map[string]any{"phase": "end", "packets": 2, "bytes": 148, "end": "idle", "syn_only": true,
			"orig_payload": 0, "resp_payload": 0, "orig_pkts": 2, "resp_pkts": 0,
			"incomplete": true, "rexmit_inconsistent": 0}
		return m
	}
	if _, err := v3Decode(t, synOnly()); err != nil {
		t.Fatalf("a syn-only end with no payload: %v", err)
	}
	for _, k := range []string{"orig_payload", "resp_payload"} {
		m := synOnly()
		v2Set(m, "flow."+k, 1)
		if _, err := v3Decode(t, m); !v2Has(err, netobs.CodeConflict) {
			t.Errorf("a syn-only end with %s 1: %v, want conflict", k, err)
		}
		if _, err := v3Stored03(t, m); !v2Has(err, netobs.CodeConflict) {
			t.Errorf("a stored syn-only end with %s 1: %v, want conflict", k, err)
		}
	}
}

// N-7 (CH-53): to_device_overlap_octets and incomplete are on a TCP end
// only; incomplete is present only as true, with or without a count. On
// the 0.3 channel a TCP end carries the count, incomplete or both, never
// neither; a stored end may carry neither (D1's ruling 3 on #689, D4-105
// item 2.3).
func TestC13v03N7Overlap(t *testing.T) {
	marked := func(count bool) v2Msg {
		m := v3End(t)
		v2Del(m, "flow.password_lines")
		v2Set(m, "flow.incomplete", true)
		if !count {
			v2Del(m, "flow.to_device_overlap_octets")
		}
		return m
	}
	for _, count := range []bool{true, false} {
		if _, err := v3Decode(t, marked(count)); err != nil {
			t.Errorf("incomplete: true, a count %v: %v", count, err)
		}
	}
	for _, count := range []bool{true, false} {
		m := marked(count)
		v2Set(m, "flow.incomplete", false)
		if _, err := v3Decode(t, m); !v2Has(err, netobs.CodeForm) {
			t.Errorf("incomplete: false, a count %v: %v, want form", count, err)
		}
		if _, err := v3Stored03(t, m); !v2Has(err, netobs.CodeForm) {
			t.Errorf("a stored end with incomplete: false, a count %v: %v, want form", count, err)
		}
		v2Set(m, "flow.incomplete", nil)
		if _, err := v3Decode(t, m); err == nil {
			t.Errorf("incomplete: null, a count %v: accepted", count)
		}
	}
	for k, v := range map[string]any{"to_device_overlap_octets": 0, "incomplete": true} {
		for name, m := range map[string]v2Msg{"a UDP end": v3UDPEnd(t), "a start": v3Start(t)} {
			v2Set(m, "flow."+k, v)
			if _, err := v3Decode(t, m); !v2Has(err, netobs.CodeConflict) {
				t.Errorf("%s with %s: %v, want conflict", name, k, err)
			}
			if _, err := v3Stored03(t, m); !v2Has(err, netobs.CodeConflict) {
				t.Errorf("stored, %s with %s: %v, want conflict", name, k, err)
			}
		}
	}
	m := v3End(t)
	v2Del(m, "flow.password_lines")
	v2Del(m, "flow.to_device_overlap_octets")
	if _, err := v3Decode(t, m); !v2Has(err, netobs.CodeMissing) {
		t.Errorf("a 0.3 channel TCP end with neither the count nor incomplete: %v, want missing", err)
	}
	if _, err := v3Stored03(t, m); err != nil {
		t.Errorf("a stored 0.3 TCP end with neither: %v", err)
	}
}

// v3Overlap are the three counts CH-53 adds to the heartbeat.
var v3Overlap = []string{"frame_stage.overlap_table_full", "agent.overlap_join_refused", "agent.overlap_unjoined"}

// v3Heartbeat is a 0.3 heartbeat: v2Heartbeat with frame_stage and the
// agent's two counts (CH-53).
func v3Heartbeat() v2Msg {
	m := v2Heartbeat()
	m["schema"] = v3Schema
	m["frame_stage"] = map[string]any{"overlap_table_full": 0}
	v2Set(m, "agent.overlap_join_refused", 0)
	v2Set(m, "agent.overlap_unjoined", 0)
	return m
}

// N-9 (CH-53), the decoder's half: frame_stage.overlap_table_full and the
// agent's overlap_join_refused and overlap_unjoined are <uint64>, required
// in a 0.3 heartbeat with every key present, refused in a 0.2 heartbeat,
// run totals refused when they fall (Follows), and not counters: no key of
// counters, no name of sensor.counters, and diff.<name> refused by C4 0.4's
// closed set. The node's half, a node that maps none of them, is owed (the
// C13 0.2 intake brief).
func TestC13v03N9Heartbeat(t *testing.T) {
	if _, err := v3Decode(t, v3Heartbeat()); err != nil {
		t.Fatalf("a 0.3 heartbeat: %v", err)
	}
	for _, p := range append([]string{"frame_stage"}, v3Overlap...) {
		m := v3Heartbeat()
		v2Del(m, p)
		if _, err := v3Decode(t, m); !v2Has(err, netobs.CodeMissing) {
			t.Errorf("a 0.3 heartbeat without %s: %v, want missing", p, err)
		}
	}
	for _, p := range v3Overlap {
		for v, ok := range map[any]bool{nil: false, -1: false, 0: true, uint64(math.MaxUint64): true} {
			m := v3Heartbeat()
			v2Set(m, p, v)
			if _, err := v3Decode(t, m); (err == nil) != ok {
				t.Errorf("%s %v: %v, want accepted %v", p, v, err, ok)
			}
		}
		// Refused in a 0.2 heartbeat, whatever its value.
		m := v2Heartbeat()
		if strings.HasPrefix(p, "frame_stage.") {
			m["frame_stage"] = map[string]any{}
		}
		v2Set(m, p, 0)
		if _, err := v3On(t, m, v2Schema); !v2Has(err, netobs.CodeDecode) {
			t.Errorf("a 0.2 heartbeat with %s: %v, want decode", p, err)
		}
	}
	// Run totals: each falling by one is refused as order.
	five := func(seq string) *netobs.Heartbeat {
		m := v3Heartbeat()
		m["seq"] = seq
		for _, p := range v3Overlap {
			v2Set(m, p, 5)
		}
		f, err := v3Decode(t, m)
		if err != nil || f.Heartbeat == nil {
			t.Fatalf("a 0.3 heartbeat at 5: %v", err)
		}
		return f.Heartbeat
	}
	prev := five("12")
	for _, p := range v3Overlap {
		for v, ok := range map[int]bool{4: false, 5: true, 6: true} {
			m := v3Heartbeat()
			m["seq"] = "13"
			for _, q := range v3Overlap {
				v2Set(m, q, 5)
			}
			v2Set(m, p, v)
			f, err := v3Decode(t, m)
			if err != nil {
				t.Fatalf("%s %d: %v", p, v, err)
			}
			err = f.Heartbeat.Follows(prev)
			if (err == nil) != ok || (!ok && !v2Has(err, netobs.CodeOrder)) {
				t.Errorf("%s from 5 to %d: %v, want accepted %v (order)", p, v, err, ok)
			}
		}
	}
	if err := five("13").Follows(prev); err != nil {
		t.Errorf("unchanged: %v", err)
	}
	// Not counters.
	var counterTags []string
	ty := reflect.TypeOf(netobs.Counters{})
	for i := range ty.NumField() {
		name, _, _ := strings.Cut(ty.Field(i).Tag.Get("json"), ",")
		counterTags = append(counterTags, name)
	}
	b, err := os.ReadFile("testdata/cc-d0/event-0.4-sensor-counters.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := event.Decode(b); err != nil {
		t.Fatalf("the cc-d0 sensor.counters event: %v", err)
	}
	for _, p := range v3Overlap {
		_, name, _ := strings.Cut(p, ".")
		if slices.Contains(counterTags, name) || slices.Contains(event.SensorCounters, name) || slices.Contains(event.SensorCounters04, name) {
			t.Errorf("%s is a counter: %v, %v, %v", name, counterTags, event.SensorCounters, event.SensorCounters04)
		}
		m := v3Heartbeat()
		v2Set(m, "counters."+name, 0)
		if _, err := v3Decode(t, m); !v2Has(err, netobs.CodeDecode) {
			t.Errorf("a heartbeat with counters.%s: %v, want decode", name, err)
		}
		var e map[string]any
		if err := json.Unmarshal(b, &e); err != nil {
			t.Fatal(err)
		}
		e["health"].(map[string]any)["details"].(map[string]any)["diff."+name] = "1"
		if _, err := event.Decode(v2JSON(t, e)); err == nil {
			t.Errorf("a sensor.counters event with diff.%s: accepted", name)
		}
	}
}

// v3AlertHealth is an own-session-mismatch alert at 0.3, as its health
// body: the cc-d0 alert fixture's (a baseline-free rule raised with no
// baseline) with the rule, its key, its baseline value and a head.
func v3AlertHealth(t *testing.T) event.Health {
	t.Helper()
	b, err := os.ReadFile("testdata/cc-d0/event-0.4-netobs-alert.json")
	if err != nil {
		t.Fatal(err)
	}
	var e struct {
		Health event.Health `json:"health"`
	}
	if err := json.Unmarshal(b, &e); err != nil {
		t.Fatal(err)
	}
	d := e.Health.Details
	d["schema"], d["rule"] = v3Schema, "own-session-mismatch"
	d["key_text"] = "an own session of the node, 192.0.2.14 -> 192.0.2.20 tcp/23"
	d["baseline_value"] = "the run's profile"
	d["observation"] = "comparison M3: 412 octets to the relay above the run's profile"
	return e.Health
}

// N-1 (CH-51): own-session-mismatch is a rule, runs before any baseline is
// acknowledged, and shows no params: an alert with it and no baseline
// validates, through its health body and back; one that shows tie_grace_s
// is refused. Below 0.3 it is not a rule: a 0.2 or 0.1 alert with it is
// refused as form (§2, "What an earlier reader does"), where the same
// alert with a 0.2 rule passes.
func TestC13v03N1Rule(t *testing.T) {
	r := netobs.Rule("own-session-mismatch")
	if netobs.RuleOwnSessionMismatch != r || !slices.Contains(netobs.Rules, r) || !slices.Contains(netobs.BaselineFree, r) || len(netobs.RuleParams(r)) != 0 {
		t.Errorf("%q: in Rules %v, in BaselineFree %v, params %v", netobs.RuleOwnSessionMismatch,
			slices.Contains(netobs.Rules, r), slices.Contains(netobs.BaselineFree, r), netobs.RuleParams(r))
	}
	h := v3AlertHealth(t)
	a, err := netobs.AlertFromHealth(h)
	if err != nil {
		t.Fatalf("an own-session-mismatch alert with no baseline: %v", err)
	}
	if a.Rule != r || a.Baseline != "" || a.BaselineVersion != 0 || len(a.Params) != 0 {
		t.Errorf("read as rule %q, baseline %q %d, params %v", a.Rule, a.Baseline, a.BaselineVersion, a.Params)
	}
	back, err := a.Health()
	if err != nil || !maps.Equal(back.Details, h.Details) {
		t.Errorf("through the health body and back: %v\n got %v\nwant %v", err, back.Details, h.Details)
	}
	d := maps.Clone(h.Details)
	d["param.tie_grace_s"] = "30"
	if _, err := netobs.AlertFromHealth(event.Health{Type: h.Type, Related: h.Related, Details: d}); err == nil {
		t.Error("an own-session-mismatch alert showing tie_grace_s: accepted")
	}
	p := *a
	p.Params = []netobs.Param{{Name: "tie_grace_s", Value: "30"}}
	if err := p.Validate(); !v2Has(err, netobs.CodeConflict) {
		t.Errorf("Validate with tie_grace_s: %v, want conflict", err)
	}
	for _, schema := range []string{v2Schema, "otsec.netobs/0.1"} {
		b := *a
		b.Schema = schema
		if schema == "otsec.netobs/0.1" {
			b.Coverage.ConfigDigest, b.Coverage.Settings.PRPWindowMS = "", 0
		}
		if err := b.Validate(); !v2Has(err, netobs.CodeForm) {
			t.Errorf("a %s alert with own-session-mismatch: %v, want form", schema, err)
		}
		b.Rule, b.Observation = netobs.RuleNodeAddressSpoofed, "a flow from the node's address that no session of the node made"
		if err := b.Validate(); err != nil {
			t.Errorf("the same %s alert with node-address-spoofed: %v", schema, err)
		}
	}
}

// v3Items are CH-51's parts and their items, in the grammar's order.
var (
	v3C = []string{"M1", "M2", "M3", "M4", "M5", "M6a", "M6b"}
	v3U = []string{"M2:incomplete", "M3:incomplete", "M5:incomplete", "M6a:incomplete", "M6b:incomplete", "M6b:no-profile"}
	v3R = []string{"prp-table-full", "prp-mismatched"}
)

// N-2 (CH-51), legs (1) and (2): the head grammar, matched over the whole
// observation by Alert.Validate. Leg (3), the detector's union, is owed
// (P4-4-HR24's stage 3).
func TestC13v03N2Head(t *testing.T) {
	a, err := netobs.AlertFromHealth(v3AlertHealth(t))
	if err != nil {
		t.Fatal(err)
	}
	check := func(obs string) error {
		b := *a
		b.Observation = obs
		return b.Validate()
	}
	// (1) Accepted.
	var heads []string
	for _, c := range v3C {
		heads = append(heads, "comparison "+c)
	}
	for _, u := range v3U {
		heads = append(heads, "unjudged "+u)
	}
	for _, r := range v3R {
		heads = append(heads, "reason "+r)
	}
	all := []string{"comparison " + strings.Join(v3C, " "), "unjudged " + strings.Join(v3U, " "), "reason " + strings.Join(v3R, " "), "no-profile"}
	heads = append(heads, all...)
	one := []string{"comparison M3", "unjudged M6b:incomplete", "reason prp-mismatched", "no-profile"}
	for i := range one {
		for j := i + 1; j < len(one); j++ {
			heads = append(heads, one[i]+" "+one[j])
		}
	}
	heads = append(heads, strings.Join(one, " "))
	longest := strings.Join(all, " ")
	heads = append(heads, longest)
	if len(longest) != 177 {
		t.Errorf("the grammar's longest head is %d octets; CH-51 states 177", len(longest))
	}
	for _, h := range heads {
		for _, obs := range []string{h, h + ": 412 octets to the relay above the run's profile", h + ": a: b"} {
			if err := check(obs); err != nil {
				t.Errorf("%q: %v", obs, err)
			}
		}
	}
	// (1) Refused, each as form.
	for _, obs := range []string{
		": 412 octets", "412 octets to the relay", "comparison M7", "comparison M6b M3", "comparison M3 M3",
		"comparison M3x", "comparison M1:incomplete", "unjudged M5:no-profile", "unjudged M1:incomplete",
		"unjudged M4:incomplete", "unjudged M6b:no-profile M6b:incomplete", "comparison M6b:no-profile",
		"comparison prp-table-full", "reason prp-mismatched prp-table-full", "reason incomplete", "reason no-profile",
		"unjudged M5:incomplete comparison M3", "reason prp-table-full unjudged M5:incomplete",
		"no-profile reason prp-mismatched", "no-profile comparison M3", "comparison M1 comparison M3",
		"no-profile no-profile", "comparisonM3", "comparison  M3", "comparison M3unjudged M5:incomplete",
		" comparison M3", "comparison M3 ", "comparison", "unjudged", "reason", "comparison unjudged M5:incomplete",
		"comparison M3 unjudged", "comparison M3:x", "comparison M3 :x", "comparison M3,M5", "comparison M3; text",
		"comparison M3 text", "comparison M3\t: text", "Comparison M3", "comparison m3", "comparison M6b reason no-profile",
	} {
		if err := check(obs); !v2Has(err, netobs.CodeForm) {
			t.Errorf("%q: %v, want form", obs, err)
		}
	}
	// A stored alert is read with the same grammar.
	h := v3AlertHealth(t)
	h.Details["observation"] = "comparison M3 M3: 412 octets"
	if _, err := netobs.AlertFromHealth(h); err == nil {
		t.Error("a stored alert whose head repeats M3: accepted")
	}
	// (2) D6's pair: both valid, and distinct.
	pair := []string{"comparison M5 unjudged M6b:no-profile", "unjudged M5:incomplete"}
	for _, obs := range pair {
		if err := check(obs); err != nil {
			t.Errorf("%q: %v", obs, err)
		}
	}
	if pair[0] == pair[1] {
		t.Error("D6's pair is one string")
	}
}

// N-12's second case (§1.1): a 0.2 stored end read by the 0.3 decoder,
// strictly: valid, with the eight fields absent (nil, never 0 or false);
// and a 0.2 or 0.1 stored end that carries any of them, or a key no minor
// defines, is refused, as the 0.2 reader refused it, whatever its value.
func TestC13v03N12Stored02End(t *testing.T) {
	o, err := netobs.DecodeStored(v2JSON(t, v3Stored(t, v3Without(v3End(t)), v2Schema)))
	if err != nil {
		t.Fatalf("a stored 0.2 end: %v", err)
	}
	f := o.Flow
	if f == nil || f.OrigPayload != nil || f.RespPayload != nil || f.OrigPkts != nil || f.RespPkts != nil ||
		f.ToDeviceOverlapOctets != nil || f.Incomplete != nil || f.RexmitInconsistent != nil || f.PasswordLines != nil {
		t.Errorf("a stored 0.2 end read with a 0.3 field: %+v", f)
	}
	got := map[string]any{}
	if err := json.Unmarshal(v2JSON(t, o.Flow), &got); err != nil {
		t.Fatal(err)
	}
	for _, k := range v3Keys {
		if _, ok := got[k]; ok {
			t.Errorf("the 0.2 end re-encodes with %s", k)
		}
	}
	for _, schema := range []string{v2Schema, "otsec.netobs/0.1"} {
		m := v3Stored(t, v3Without(v3End(t)), schema)
		m["d6_unknown"] = "x"
		if _, err := netobs.DecodeStored(v2JSON(t, m)); !v2Has(err, netobs.CodeDecode) {
			t.Errorf("a stored %s end with a key no minor defines: %v, want decode", schema, err)
		}
		for _, k := range v3Keys {
			m := v3Stored(t, v3Without(v3End(t)), schema)
			v2Set(m, "flow."+k, map[bool]any{true: true, false: 0}[k == "incomplete"])
			if _, err := netobs.DecodeStored(v2JSON(t, m)); !v2Has(err, netobs.CodeDecode) {
				t.Errorf("a stored %s end with %s: %v, want decode", schema, k, err)
			}
		}
	}
}

// N-12's third case (§1.3): the worst stored body with every new field,
// under MaxNetobsBytes. The eight fields are only on a flow end, so this
// is the worst flow end, every other kind being as 0.2 left it. Each field
// is at its longest form: 19 or 20 digits, nine fractional digits, IPv6
// addresses of 39 characters, eight cited frames of sixteen redactions,
// eight lost spans, and the longest value of each closed set (the evidence
// class included, for its length only). The coverage statement is counted
// at MaxCoverageBytes, its bound. §1.3's counts are checked on the same
// end: the seven counts the node accepts add 260 octets, and all eight
// keys 278. The control: the same end padded one octet past
// MaxNetobsBytes is refused as range.
func TestC13v03N12WorstEnd(t *testing.T) {
	const max63 = int64(math.MaxInt64)
	const sha = "9cbad339406feea40d9113c7dd0c675a70f2b327c0713f886e964bed3ad7f6bd"
	const t9 = "2026-11-14T09:58:02.123456789Z"
	uuid := func(n int) string { return fmt.Sprintf("1a2b3c4d-0000-4000-8000-%012d", n) }
	m := v3Stored(t, v3End(t), v3Schema)
	m["seq"] = "18446744073709551615"
	m["first_sight"] = true
	m["first_utc"], m["last_utc"], m["made_utc"] = t9, t9, t9
	m["resolution_ns"] = 1000000000
	m["l2"] = map[string]any{"src_mac": "02:00:5e:10:00:0e", "dst_mac": "02:00:5e:10:00:14", "vlan": 4094, "ethertype": "0x86dd"}
	m["ip"] = map[string]any{"src": "2001:db8:ffff:ffff:ffff:ffff:ffff:fffe", "dst": "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff",
		"l4": "tcp", "sport": 65535, "dport": 65534}
	m["protocol"] = strings.Repeat("p", 64)
	var frames []any
	for i := range 8 {
		var red []any
		for j := range 16 {
			red = append(red, map[string]any{"offset": 1000 + 64*j, "length": 60, "reason": "credential"})
		}
		frames = append(frames, map[string]any{"n": max63 - 7 + int64(i), "captured_len": 2048, "wire_len": 262144,
			"sha256": sha, "lan": "a", "redactions": red})
	}
	m["citation"] = map[string]any{"capture_id": "file:" + sha, "frames": frames, "frames_total": max63}
	m["flow"] = map[string]any{"phase": "end", "packets": max63, "bytes": max63, "end": "sensor-stop", "syn_only": false}
	var lost []any
	for i := range 8 {
		lost = append(lost, v2Span(fmt.Sprintf("2026-11-14T09:%02d:00.123456789Z", 2*i), fmt.Sprintf("2026-11-14T09:%02d:30.123456789Z", 2*i)))
	}
	m["node"] = map[string]any{"src_asset": uuid(1), "dst_asset": uuid(2), "resolved_by": "ip",
		"platform_session": map[string]any{"invocation_id": uuid(3), "tie": "connection"},
		"evidence_class":   "device-observed", "stored_capture": sha, "late": true, "backlog": true, "skewed": true, "lost": lost}
	without := len(v2JSON(t, m))
	for _, k := range v3Counts {
		v2Set(m, "flow."+k, max63)
	}
	worst := v2JSON(t, m)
	if _, err := netobs.DecodeStored(worst); err != nil {
		t.Fatalf("the worst 0.3 flow end: %v", err)
	}
	if added := len(worst) - without; added != 260 {
		t.Errorf("the seven counts at 2^63 - 1 add %d octets; C13 0.3 §1.3 states 260", added)
	}
	all := maps.Clone(m["flow"].(map[string]any))
	all["incomplete"] = true
	if added := len(v2JSON(t, all)) - len(v2JSON(t, m["flow"])) + 260; added != 278 {
		t.Errorf("all eight keys add %d octets; C13 0.3 §1.3 states 278", added)
	}
	cov := len(v2JSON(t, m["coverage"]))
	bound := len(worst) - cov + netobs.MaxCoverageBytes
	t.Logf("the worst 0.3 flow end: %d bytes, %d with its coverage at MaxCoverageBytes (%d); MaxNetobsBytes %d", len(worst), bound, netobs.MaxCoverageBytes, event.MaxNetobsBytes)
	if bound > event.MaxNetobsBytes {
		t.Errorf("the worst 0.3 flow end is %d bytes with its coverage at its bound, above MaxNetobsBytes %d", bound, event.MaxNetobsBytes)
	}
	over := append(append(bytes.Clone(worst[:len(worst)-1]), bytes.Repeat([]byte(" "), event.MaxNetobsBytes+1-len(worst))...), '}')
	if _, err := netobs.DecodeStored(over); !v2Has(err, netobs.CodeRange) {
		t.Errorf("the worst end padded to MaxNetobsBytes + 1: %v, want range", err)
	}
}
