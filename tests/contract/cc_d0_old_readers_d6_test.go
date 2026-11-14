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
//   - C8-1's old-reader leg (docs/phase4/D3-sensor-link.md §11.2), narrowed
//     by D1's ruling 1 (a) on #683: a 0.13 record of each new action, valid
//     at 0.12 in every field but the action and its sensor target, is
//     refused by the 0.12 audit.ParseRecord as an unknown action. §11.2
//     leaves the records' other fields open (ruling 1 (b)), so none is here.
//     The three audit-0.13-* files are therefore not valid 0.13 records and
//     serve only this narrowed leg: deliverable 5's forward check uses the
//     forms D3 settles (ruling 1 (c)).
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
	// is refused by name: the 0.2 reader reads an earlier minor strictly
	// (CH-35), so a key 0.1 does not have is an unknown key (decode), as in
	// TestCCD0R3StoredObservation. The 0.1 reader on main refused it as an
	// unknown detail (conflict).
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
		if !slices.Contains(netobs.Codes(err), netobs.CodeDecode) || !strings.Contains(fmt.Sprint(err), k) {
			t.Errorf("stamped 0.1 with %s: %v, want it refused by name", k, err)
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

// ccD0LinkRefusedReasons are C8-4's six reasons for sensor.link_refused.
var ccD0LinkRefusedReasons = []string{"peer-key", "expired", "binding", "run-regressed", "run-forked", "sensor-id"}

func TestCCD0C81OldReaderRefuses(t *testing.T) {
	for _, c := range []struct{ file, action, outcome string }{
		{"audit-0.13-sensor-enrolled.json", "sensor.enrolled", "succeeded"},
		{"audit-0.13-sensor-revoked.json", "sensor.revoked", "succeeded"},
		{"audit-0.13-sensor-link-refused.json", "sensor.link_refused", "denied"},
	} {
		t.Run(c.action, func(t *testing.T) {
			// A record is one line; its terminator is not part of it.
			b := bytes.TrimRight(ccD0File(t, c.file), "\r\n")
			m := ccD0Map(t, b)
			if m["contract"] != "otsec.audit/0.13" || m["action"] != c.action {
				t.Fatalf("contract %v, action %v", m["contract"], m["action"])
			}
			// What §11.2 does fix, which the 0.12 reader never reaches: the
			// target is the sensor and no asset (C8-1), sensor.enrolled and
			// sensor.revoked succeed (C8-2, C8-3), and sensor.link_refused is
			// denied with one of C8-4's six reasons.
			target, _ := m["target"].(map[string]any)
			if id, _ := target["sensor_id"].(string); len(target) != 1 || !netobs.ValidUUID(id) {
				t.Errorf("target %v, want exactly {sensor_id: <lowercase UUID>}", m["target"])
			}
			if m["outcome"] != c.outcome {
				t.Errorf("outcome %v, want %s", m["outcome"], c.outcome)
			}
			if reason, _ := m["reason_code"].(string); c.outcome == "denied" && !slices.Contains(ccD0LinkRefusedReasons, reason) {
				t.Errorf("reason_code %q is not one of C8-4's six", reason)
			}
			// No field outside the 0.12 record's.
			dec := json.NewDecoder(bytes.NewReader(b))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&audit.Record{}); err != nil {
				t.Errorf("a field outside the 0.12 record: %v", err)
			}
			_, err := audit.ParseRecord(b)
			if !errors.Is(err, audit.ErrRecordRejected) || !strings.Contains(fmt.Sprint(err), fmt.Sprintf("unknown action %q", c.action)) {
				t.Errorf("the 0.12 reader: %v, want it refused as an unknown action", err)
			}
		})
	}
}
