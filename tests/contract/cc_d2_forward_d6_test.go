package contract

// P4-4-CC deliverable 2 (D4-103), the brief's "The backward fixtures also
// hold forward": D6's fixtures of deliverable 0 (#683, testdata/cc-d0),
// written from the approved text and read by main's old readers there, are
// read here by the new code at its own minor. R-3's stored 0.2 observation
// and 0.2 alert validate under the 0.2 readers, E4-4's 0.4 sensor.counters
// and E4-7's four stored events under the 0.5 reader, as 0.4 events, an
// earlier minor (C4 0.5), and E4-4's fixture without diff.packets is still
// refused, by C4-0.4-3. Each fixture is also read strictly, as a reader's
// own minor and earlier are: what the old reader passed over as a later
// minor's field is refused here. With E4-7's forward contract leg: the
// identifier this code stamps is 0.5 (C4 0.5 §2).
//
// The fixtures are #683's files, unchanged (their meaning is #683's).
// Ground truth: independent (the approved text). Evidence class: desk.

import (
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/event"
	"otsec.local/otsec/contracts/netobs"
	"otsec.local/otsec/contracts/version"
)

func ccD2File(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/cc-d0/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// ccD2With adds a top-level key to a JSON object, or under obj when it is
// not "".
func ccD2With(t *testing.T, b []byte, obj, key string) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	target := m
	if obj != "" {
		target = m[obj].(map[string]any)
	}
	target[key] = "x"
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// R-3, forward: the stored 0.2 observations validate under the 0.2 stored
// reader, carrying what the fixture states, and are read strictly.
func TestCCD2ForwardR3Observation(t *testing.T) {
	for _, c := range []struct {
		file                  string
		late, backlog, skewed bool
		lost                  int
	}{
		{"event-0.4-network-observation.json", true, true, false, 1},
		{"event-0.4-network-observation-skewed.json", false, false, true, 0},
	} {
		t.Run(c.file, func(t *testing.T) {
			b := ccD2File(t, c.file)
			e, err := event.Decode(b)
			if err != nil {
				t.Fatalf("event.Decode: %v", err)
			}
			o, err := netobs.ObservationFromEvent(e)
			if err != nil {
				t.Fatalf("ObservationFromEvent: %v", err)
			}
			if o.Schema != "otsec.netobs/0.2" || o.MadeUTC == "" || o.Coverage.ConfigDigest == "" || o.Coverage.Settings.PRPWindowMS != 400 {
				t.Errorf("schema %q, made_utc %q, config_digest %q, prp_window_ms %d", o.Schema, o.MadeUTC, o.Coverage.ConfigDigest, o.Coverage.Settings.PRPWindowMS)
			}
			if n := o.Node; n.Late != c.late || n.Backlog != c.backlog || n.Skewed != c.skewed || len(n.Lost) != c.lost {
				t.Errorf("node marks late %v backlog %v skewed %v lost %d", n.Late, n.Backlog, n.Skewed, len(n.Lost))
			}
			// 0.2 is this reader's own minor, so it is read strictly.
			if _, err := netobs.DecodeStored(ccD2With(t, e.Netobs, "", "added_in_0_3")); !slices.Contains(netobs.Codes(err), netobs.CodeDecode) {
				t.Errorf("the 0.2 body with an unknown field: %v, want decode", err)
			}
		})
	}
}

// R-3, forward: the 0.2 alert validates under the 0.2 alert reader, with
// its two flattened coverage details read, and is read strictly.
func TestCCD2ForwardR3Alert(t *testing.T) {
	e, err := event.Decode(ccD2File(t, "event-0.4-netobs-alert.json"))
	if err != nil {
		t.Fatalf("event.Decode: %v", err)
	}
	a, err := netobs.AlertFromEvent(e)
	if err != nil {
		t.Fatalf("AlertFromEvent: %v", err)
	}
	if a.Schema != "otsec.netobs/0.2" || !netobs.ValidUUID(a.AssetID) || a.Assets != nil || a.AssetsTotal != 0 {
		t.Errorf("schema %q, asset_id %q, assets %v %d", a.Schema, a.AssetID, a.Assets, a.AssetsTotal)
	}
	if a.Coverage.ConfigDigest != e.Health.Details["coverage.config_digest"] || a.Coverage.Settings.PRPWindowMS != 400 {
		t.Errorf("coverage read as config_digest %q, prp_window_ms %d", a.Coverage.ConfigDigest, a.Coverage.Settings.PRPWindowMS)
	}
	// Through the health body and back, unchanged.
	h, err := a.Health()
	if err != nil {
		t.Fatalf("Health: %v", err)
	}
	if !maps.Equal(h.Details, e.Health.Details) {
		t.Errorf("the alert's details changed through Health:\n got %v\nwant %v", h.Details, e.Health.Details)
	}
	// At its own minor an unknown detail is refused.
	d := maps.Clone(e.Health.Details)
	d["added_in_0_3"] = "x"
	if _, err := netobs.AlertFromHealth(event.Health{Type: e.Health.Type, Related: e.Health.Related, Details: d}); err == nil {
		t.Error("the 0.2 alert with an unknown detail: accepted")
	}
}

// E4-4, forward: the 0.4 sensor.counters validates under the 0.4 code; the
// same without diff.packets is refused by C4-0.4-3, as
// health.details.diff.packets: missing (and not as 0.3's "no
// diff.<counter>", since the event carries the 0.4 counters).
func TestCCD2ForwardE44(t *testing.T) {
	e, err := event.Decode(ccD2File(t, "event-0.4-sensor-counters.json"))
	if err != nil {
		t.Fatalf("the 0.4 sensor.counters: %v", err)
	}
	if e.Schema != "otsec.event/0.4" || e.Health.Details["capture_loss"] != "drops_holder frames_overlong" {
		t.Errorf("schema %q, capture_loss %q", e.Schema, e.Health.Details["capture_loss"])
	}
	_, err = event.Decode(ccD2File(t, "event-0.4-sensor-counters-no-packets.json"))
	if !slices.Equal(event.Codes(err), []event.Code{event.CodeMissing}) || !strings.Contains(fmt.Sprint(err), "health.details.diff.packets: missing") {
		t.Errorf("without diff.packets: %v, want only health.details.diff.packets: missing", err)
	}
	if strings.Contains(fmt.Sprint(err), "no diff.<counter>") {
		t.Errorf("without diff.packets: %v, refused as having no counter", err)
	}
}

// E4-7, forward contract leg: the identifier this code stamps on every
// event is 0.6 (C4 0.6 §1), and a stored 0.4 event of each type validates
// under the 0.6 reader, strictly at its own earlier minor (the 0.3 reader
// passed a later minor's field over). The later minor is one above
// event.Identifier, computed (C4 0.6 §6).
func TestCCD2ForwardE47(t *testing.T) {
	if event.Identifier != "otsec.event/0.6" {
		t.Errorf("event.Identifier %q, C4 0.6 §1: every event this code stamps says 0.6", event.Identifier)
	}
	laterV, err := version.Parse(event.Identifier)
	if err != nil {
		t.Fatal(err)
	}
	laterV.Minor++
	later := laterV.String()
	for _, c := range []struct {
		file string
		kind event.Kind
	}{
		{"event-0.4-ser.json", event.KindSER},
		{"event-0.4-syslog.json", event.KindSyslog},
		{"event-0.4-health-node.json", event.KindHealth},
		{"event-0.4-network-observation.json", event.KindNetworkObservation},
		{"event-0.4-netobs-alert.json", event.KindHealth},
		{"event-0.4-sensor-counters.json", event.KindHealth},
	} {
		t.Run(c.file, func(t *testing.T) {
			b := ccD2File(t, c.file)
			e, err := event.Decode(b)
			if err != nil {
				t.Fatalf("event.Decode: %v", err)
			}
			if e.Schema != "otsec.event/0.4" || e.Kind != c.kind {
				t.Errorf("schema %q, kind %q", e.Schema, e.Kind)
			}
			if _, err := event.Decode(ccD2With(t, b, "", "added_in_0_5")); !slices.Contains(event.Codes(err), event.CodeDecode) {
				t.Errorf("with an unknown field at 0.4: %v, want decode", err)
			}
			// A later minor is read forward.
			var m map[string]any
			if err := json.Unmarshal(ccD2With(t, b, "", "added_in_0_5"), &m); err != nil {
				t.Fatal(err)
			}
			m["schema"] = later
			fwd, err := json.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := event.Decode(fwd); err != nil {
				t.Errorf("stamped %s with a field it adds: %v", later, err)
			}
		})
	}
}
