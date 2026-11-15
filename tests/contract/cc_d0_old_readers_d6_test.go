package contract

// P4-4-CC deliverable 0 (D4-103; docs/agent-handoffs.md, "P4-4-CC"): D6's
// fixtures on the old readers. Each file under testdata/cc-d0 is written
// from the approved text, before any code writes its minor, and is read here
// by main's readers: C13 0.1 (netobs.DecodeStored, netobs.AlertFromHealth)
// and C4 0.3 (event.Decode).
//
//   - R-3 (docs/phase4/D4-c13-0.2-proposal.md §11, CH-35's table, and §15):
//     a stored 0.2 observation and a 0.2 alert without the new asset_id
//     values are accepted, the new fields ignored.
//   - E4-4 (docs/phase4/D4-c4-0.4-proposal.md §2, §3 and §5): a 0.4
//     sensor.counters with diff.packets and only 0.4's new counters beside
//     it is accepted; the same without diff.packets is refused ("no
//     diff.<counter>").
//   - E4-7's backward leg (the same document, §3 and §5): a stored 0.4 SER,
//     Syslog, node health and network-observation event is read by Decode.
//   - C8-1's old-reader leg (docs/phase4/D3-sensor-link.md §11.2), with the
//     narrowing of D4-104 item 2 (a) lifted by D1's ruling 6894226253 on
//     #683 (D4-107): the ten audit-0.13-* files are full 0.13 records in the
//     ruled forms (S1, St1, T1, K1, F1), one view of a node's chain from seq
//     20. They hold each new action, a denied enrolment, a revocation with
//     streams {} and one with both keys at 0, and C8-6's allowed and info
//     collector.request of each new kind (D6's 6894220276, §0). A 0.12
//     reader refuses every one: each sensor.* record as an unknown action,
//     and each collector.request on the kind it names. That leg ran on main
//     at 8e96c821 (this file and the fixtures on main's code; desk, Go
//     1.27.3 windows/amd64), and it runs again on any build whose ReaderID
//     is 0.12. From P4-4-CC deliverable 5 the reader is 0.13, and the test
//     asserts what it does: each record is read, and the same bytes stamped
//     0.12 are refused (C8-1). The forward check of the whole view is
//     cc_d5_forward_d6_test.go's.
//
// The brief's "The backward fixtures also hold forward": deliverable 2's
// branch reads the event-0.4-* files with the new code, so they keep their
// names.
//
// The old-reader proof ran on main before 0.2, at #683's merge commit
// 36fabc3a, as a one-time proof. Since deliverable 2 these functions are
// the C13 0.2 and C4 0.4 readers. By D1's ruling D on #687 (comment
// 6884862565), TestCCD0R3Alert and TestCCD0E44SensorCounters assert what
// that code does with the same fixtures, which are unchanged. The other
// three tests hold as written under both codes; their messages name the
// old readers.
// Ground truth: independent (the approved text). The SER row is D6's
// transcription of SEL-751 Figure 10.16; every other value is constructed.
// None is device output. Evidence class: desk.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/audit"
	"otsec.local/otsec/contracts/event"
	"otsec.local/otsec/contracts/netobs"
)

const ccD0Dir = "testdata/cc-d0"

func ccD0File(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(ccD0Dir, name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func ccD0Map(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func ccD0JSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// ccD0Path returns the object that holds the last part of a dotted path,
// and that part, or nil when an object on the way is missing.
func ccD0Path(m map[string]any, path string) (map[string]any, string) {
	parts := strings.Split(path, ".")
	for _, p := range parts[:len(parts)-1] {
		next, ok := m[p].(map[string]any)
		if !ok {
			return nil, ""
		}
		m = next
	}
	return m, parts[len(parts)-1]
}

// ccD0Observation0x are the fields 0.2 adds to a stored observation (CH-35's
// table), as paths into the netobs body; each fixture adds the node marks it
// carries.
var ccD0Observation0x = []string{"made_utc", "coverage.config_digest", "coverage.settings.prp_window_ms"}

func TestCCD0R3StoredObservation(t *testing.T) {
	for _, c := range []struct {
		file  string
		marks []string
	}{
		{"event-0.4-network-observation.json", []string{"node.late", "node.backlog", "node.lost"}},
		{"event-0.4-network-observation-skewed.json", []string{"node.skewed"}},
	} {
		t.Run(c.file, func(t *testing.T) {
			b := ccD0File(t, c.file)
			var wrap struct {
				Netobs json.RawMessage `json:"netobs"`
			}
			if err := json.Unmarshal(b, &wrap); err != nil {
				t.Fatal(err)
			}
			o, err := netobs.DecodeStored(wrap.Netobs)
			if err != nil {
				t.Fatalf("the 0.1 DecodeStored refuses a stored 0.2 observation: %v", err)
			}
			if o.Schema != "otsec.netobs/0.2" {
				t.Errorf("schema %q", o.Schema)
			}
			// The node's own read of the same record: the 0.3 event reader,
			// then the observation's destination against the event's asset.
			e, err := event.Decode(b)
			if err != nil {
				t.Fatalf("event.Decode: %v", err)
			}
			if _, err := netobs.ObservationFromEvent(e); err != nil {
				t.Fatalf("ObservationFromEvent: %v", err)
			}

			// The fixture carries each field R-3 names, and the 0.1 type knows
			// none of them: stamped 0.1, so read strictly, the body without
			// them is valid, and with any one of them it is refused.
			fields := append(slices.Clone(ccD0Observation0x), c.marks...)
			whole := ccD0Map(t, wrap.Netobs)
			for _, p := range fields {
				if parent, k := ccD0Path(whole, p); parent == nil || parent[k] == nil {
					t.Errorf("the fixture lacks %s", p)
				}
			}
			at01 := func(keep string) []byte {
				m := ccD0Map(t, wrap.Netobs)
				m["schema"] = "otsec.netobs/0.1"
				for _, p := range fields {
					if parent, k := ccD0Path(m, p); p != keep && parent != nil {
						delete(parent, k)
					}
				}
				return ccD0JSON(t, m)
			}
			if _, err := netobs.DecodeStored(at01("")); err != nil {
				t.Errorf("stamped 0.1 without the 0.2 fields: %v", err)
			}
			for _, p := range fields {
				if _, err := netobs.DecodeStored(at01(p)); !slices.Contains(netobs.Codes(err), netobs.CodeDecode) {
					t.Errorf("stamped 0.1 with %s: %v, want a strict decode refusal", p, err)
				}
			}
		})
	}
}

func TestCCD0R3Alert(t *testing.T) {
	e, err := event.Decode(ccD0File(t, "event-0.4-netobs-alert.json"))
	if err != nil {
		t.Fatalf("the 0.4 event reader refuses the 0.4 alert event: %v", err)
	}
	a, err := netobs.AlertFromEvent(e)
	if err != nil {
		t.Fatalf("the 0.2 alert reader refuses a 0.2 alert: %v", err)
	}
	if a.Schema != "otsec.netobs/0.2" || !netobs.ValidUUID(a.AssetID) {
		t.Errorf("schema %q, asset_id %q: want a 0.2 alert under an asset ID", a.Schema, a.AssetID)
	}

	// Without the new asset_id values, so without their details (CH-47), and
	// with the two coverage details 0.2 flattens into every alert.
	d := e.Health.Details
	for _, k := range []string{"assets", "assets_total"} {
		if _, ok := d[k]; ok {
			t.Errorf("the fixture carries %s", k)
		}
	}
	added := []string{"coverage.config_digest", "coverage.settings.prp_window_ms"}
	for _, k := range added {
		if _, ok := d[k]; !ok {
			t.Errorf("the fixture lacks %s", k)
		}
	}
	// Stamped 0.1, the alert without them is valid, and with either one it
	// is refused, naming the key: the 0.2 reader reads an earlier minor
	// strictly (CH-35). CH-35 states no code, so none is asserted (the 0.1
	// reader on main gave conflict, this code gives decode).
	at01 := func(keep string) event.Health {
		h := event.Health{Type: e.Health.Type, Related: e.Health.Related, Details: maps.Clone(d)}
		h.Details["schema"] = "otsec.netobs/0.1"
		for _, k := range added {
			if k != keep {
				delete(h.Details, k)
			}
		}
		return h
	}
	if _, err := netobs.AlertFromHealth(at01("")); err != nil {
		t.Errorf("stamped 0.1 without the 0.2 details: %v", err)
	}
	for _, k := range added {
		_, err := netobs.AlertFromHealth(at01(k))
		if err == nil || !strings.Contains(fmt.Sprint(err), k) {
			t.Errorf("stamped 0.1 with %s: %v, want it refused, naming the key", k, err)
		}
	}
}

// ccD0Counters04 are the eight counters C4 0.4 adds (C4-0.4-1).
var ccD0Counters04 = []string{"drops_holder", "frames_overlong", "frames_outgoing", "prp_mismatched",
	"prp_table_full", "prp_tag_differs", "prp_wrong_lan", "engine_lines_refused"}

func TestCCD0E44SensorCounters(t *testing.T) {
	ok := ccD0File(t, "event-0.4-sensor-counters.json")
	e, err := event.Decode(ok)
	if err != nil {
		t.Fatalf("the 0.4 code refuses a 0.4 sensor.counters with diff.packets: %v", err)
	}
	// diff.packets and, beside it, only 0.4's counters, none of them a 0.3
	// counter; and the capture_loss that C4-0.4-2 asks for the two that rose.
	var diffs []string
	for k := range e.Health.Details {
		if n, isDiff := strings.CutPrefix(k, "diff."); isDiff {
			diffs = append(diffs, n)
		}
	}
	want := append([]string{"packets"}, ccD0Counters04...)
	slices.Sort(diffs)
	slices.Sort(want)
	if !slices.Equal(diffs, want) {
		t.Errorf("diff names %v, want %v", diffs, want)
	}
	for _, n := range ccD0Counters04 {
		if slices.Contains(event.SensorCounters, n) {
			t.Errorf("%s is a 0.3 counter", n)
		}
	}
	if got := e.Health.Details["capture_loss"]; got != "drops_holder frames_overlong" {
		t.Errorf("capture_loss %q", got)
	}

	// Without diff.packets, refused by the 0.4 code for that alone
	// (C4-0.4-3). At 0.4 the eight new counters count as counters, so 0.3's
	// "no diff.<counter>" no longer applies (D4's N1 on #683, 6884433844).
	no := ccD0File(t, "event-0.4-sensor-counters-no-packets.json")
	_, err = event.Decode(no)
	if !slices.Equal(event.Codes(err), []event.Code{event.CodeMissing}) || !strings.Contains(fmt.Sprint(err), "health.details.diff.packets: missing") {
		t.Errorf("without diff.packets: %v, want only %q", err, "health.details.diff.packets: missing")
	}
	a, b := ccD0Map(t, ok), ccD0Map(t, no)
	delete(a["health"].(map[string]any)["details"].(map[string]any), "diff.packets")
	if !reflect.DeepEqual(a, b) {
		t.Error("the two fixtures differ in more than diff.packets")
	}

	// Stamped 0.3, each 0.4 detail is refused, as 0.3 refuses it (C4-0.4-1):
	// the 0.4 code accepts them at 0.4 only.
	m := ccD0Map(t, ok)
	m["schema"] = "otsec.event/0.3"
	_, err = event.Decode(ccD0JSON(t, m))
	for _, n := range ccD0Counters04 {
		if !strings.Contains(fmt.Sprint(err), "health.details.diff."+n+": enum") {
			t.Errorf("stamped 0.3, diff.%s is not refused: %v", n, err)
		}
	}
	if !strings.Contains(fmt.Sprint(err), "health.details.capture_loss: enum") {
		t.Errorf("stamped 0.3, capture_loss is not refused: %v", err)
	}
}

func TestCCD0E47StoredEvents(t *testing.T) {
	for _, c := range []struct {
		file   string
		kind   event.Kind
		origin event.Origin
	}{
		{"event-0.4-ser.json", event.KindSER, event.OriginDevice},
		{"event-0.4-syslog.json", event.KindSyslog, event.OriginDevice},
		{"event-0.4-health-node.json", event.KindHealth, event.OriginPlatform},
		{"event-0.4-network-observation.json", event.KindNetworkObservation, event.OriginPlatform},
	} {
		t.Run(c.file, func(t *testing.T) {
			b := ccD0File(t, c.file)
			e, err := event.Decode(b)
			if err != nil {
				t.Fatalf("the 0.3 Decode refuses a stored 0.4 %s event: %v", c.kind, err)
			}
			if e.Schema != "otsec.event/0.4" || e.Kind != c.kind || e.Origin != c.origin || e.ID.Seq == 0 {
				t.Errorf("schema %q, kind %q, origin %q, seq %d", e.Schema, e.Kind, e.Origin, e.ID.Seq)
			}
			// 0.4 changes no rule of these types (C4 0.4 §2): stamped 0.3, so
			// read strictly, the same event is valid.
			m := ccD0Map(t, b)
			m["schema"] = "otsec.event/0.3"
			if _, err := event.Decode(ccD0JSON(t, m)); err != nil {
				t.Errorf("stamped 0.3: %v", err)
			}
		})
	}
}

// ccD0LinkRefusedReasons are C8-4's six reasons for sensor.link_refused, and
// ccD0EnrolDeniedReasons C8-2's seven for a denied sensor.enrolled, each in
// the underscore form reason_code carries (F1, D1's ruling 6894226253 on
// #683).
var (
	ccD0LinkRefusedReasons = []string{"peer_key", "expired", "binding", "run_regressed", "run_forked", "sensor_id"}
	ccD0EnrolDeniedReasons = []string{"node_key", "generation", "revoked_key", "forked_key", "reason", "not_after", "asset_address"}
)

// ccD0Audit013 are the 0.13 records, in chain order from seq 20. kind is the
// admin kind a collector.request names in claimed (info) or verified
// (allowed).
var ccD0Audit013 = []struct{ file, action, outcome, kind string }{
	{"audit-0.13-collector-request-sensor-enrol-info.json", "collector.request", "info", "node.sensor_enrol"},
	{"audit-0.13-collector-request-sensor-enrol.json", "collector.request", "allowed", "node.sensor_enrol"},
	{"audit-0.13-sensor-enrolled.json", "sensor.enrolled", "succeeded", ""},
	{"audit-0.13-sensor-link-refused.json", "sensor.link_refused", "denied", ""},
	{"audit-0.13-collector-request-sensor-revoke-info.json", "collector.request", "info", "node.sensor_revoke"},
	{"audit-0.13-collector-request-sensor-revoke.json", "collector.request", "allowed", "node.sensor_revoke"},
	{"audit-0.13-sensor-revoked.json", "sensor.revoked", "succeeded", ""},
	{"audit-0.13-sensor-revoked-no-link.json", "sensor.revoked", "succeeded", ""},
	{"audit-0.13-sensor-revoked-streams-zero.json", "sensor.revoked", "succeeded", ""},
	{"audit-0.13-sensor-enrolled-denied.json", "sensor.enrolled", "denied", ""},
}

func TestCCD0C81OldReaderRefuses(t *testing.T) {
	for _, c := range ccD0Audit013 {
		t.Run(c.file, func(t *testing.T) {
			// A record is one line; its terminator is not part of it.
			b := bytes.TrimRight(ccD0File(t, c.file), "\r\n")
			m := ccD0Map(t, b)
			if m["contract"] != "otsec.audit/0.13" || m["action"] != c.action || m["outcome"] != c.outcome {
				t.Fatalf("contract %v, action %v, outcome %v", m["contract"], m["action"], m["outcome"])
			}
			// What the ruled forms fix, read without either reader. A sensor
			// record is the node's, names the sensor and nothing else (C8-1),
			// and carries one sensor object (S1); a denied one carries one of
			// its action's codes (F1). C8-6's allowed record names the sensor
			// too, and its info record names no target.
			target, _ := m["target"].(map[string]any)
			id, _ := target["sensor_id"].(string)
			_, sensor := m["sensor"].(map[string]any)
			named := len(target) == 1 && netobs.ValidUUID(id)
			if c.kind == "" {
				if actor, _ := m["actor"].(map[string]any); actor["type"] != "node" || !named || !sensor {
					t.Errorf("actor %v, target %v, sensor %v: want the node, exactly {sensor_id}, and a sensor object", m["actor"], m["target"], m["sensor"])
				}
			} else if want := c.outcome == "allowed"; named != want || sensor != want || (!want && m["target"] != nil) {
				t.Errorf("target %v, sensor %v: want both, only on the allowed record", m["target"], m["sensor"])
			}
			reason, _ := m["reason_code"].(string)
			switch c.action {
			case "sensor.link_refused":
				if !slices.Contains(ccD0LinkRefusedReasons, reason) {
					t.Errorf("reason_code %q is not one of C8-4's six", reason)
				}
			case "sensor.enrolled":
				if (c.outcome == "denied") != slices.Contains(ccD0EnrolDeniedReasons, reason) {
					t.Errorf("%s with reason_code %q", c.outcome, reason)
				}
			}

			_, err := audit.ParseRecord(b)
			if audit.ReaderID == "otsec.audit/0.12" {
				// The 0.12 reader: main before deliverable 5.
				want := fmt.Sprintf("unknown action %q", c.action)
				if c.kind != "" {
					want = fmt.Sprintf("%q is not a kind an administrator signs", c.kind)
				}
				if !errors.Is(err, audit.ErrRecordRejected) || !strings.Contains(fmt.Sprint(err), want) {
					t.Errorf("the 0.12 reader: %v, want it refused: %s", err, want)
				}
				return
			}
			// The 0.13 reader reads it, and refuses the same bytes stamped
			// 0.12, which cannot carry the action or the kind (C8-1).
			if err != nil {
				t.Fatalf("the %s reader: %v", audit.ReaderID, err)
			}
			at12 := bytes.Replace(b, []byte(`"contract":"otsec.audit/0.13"`), []byte(`"contract":"otsec.audit/0.12"`), 1)
			name := c.action
			if c.kind != "" {
				name = c.kind
			}
			_, err = audit.ParseRecord(at12)
			if !errors.Is(err, audit.ErrRecordRejected) || !strings.Contains(fmt.Sprint(err), name+" is new in 0.13") {
				t.Errorf("stamped 0.12: %v, want it refused, naming %s as new in 0.13", err, name)
			}
		})
	}
}
