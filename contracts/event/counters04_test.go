package event

import (
	"slices"
	"testing"
)

// counters04 is the 0.3 sensor.counters golden restamped 0.4, which still
// carries diff.packets.
func counters04(t *testing.T) *Event {
	e := load(t, "testdata/valid/health-sensor-counters.json")
	e.Schema = "otsec.event/0.4"
	return e
}

// C4-0.4-1: the eight new counters are accepted as differences at 0.4, each
// up to 2^64 - 1, and refused at 0.3 (E4-1, E4-8 in this package's terms).
func TestSensorCounters04Names(t *testing.T) {
	if len(SensorCounters04) != 8 {
		t.Fatalf("SensorCounters04 has %d names, want 8", len(SensorCounters04))
	}
	for _, n := range SensorCounters04 {
		e := counters04(t)
		e.Health.Details["diff."+n] = "18446744073709551615"
		if n == "drops_holder" || n == "frames_overlong" {
			e.Health.Details[DetailCaptureLoss] = n
		}
		if err := e.Validate(); err != nil {
			t.Errorf("%s at 0.4: %v", n, err)
		}
		e.Schema = "otsec.event/0.3"
		delete(e.Health.Details, DetailCaptureLoss)
		if !slices.Contains(Codes(e.Validate()), CodeEnum) {
			t.Errorf("%s at 0.3: accepted, want enum", n)
		}
		for _, bad := range []string{"18446744073709551616", "07", "-1"} {
			e := counters04(t)
			e.Health.Details["diff."+n] = bad
			if !slices.Contains(Codes(e.Validate()), CodeEnum) {
				t.Errorf("%s = %q at 0.4: accepted, want enum", n, bad)
			}
		}
		// A total, by either form, is refused (E4-5).
		for _, k := range []string{n, "total." + n} {
			e := counters04(t)
			e.Health.Details[k] = "1"
			if !slices.Contains(Codes(e.Validate()), CodeForbidden) {
				t.Errorf("total %s at 0.4: accepted, want forbidden", k)
			}
		}
	}
}

// C4-0.4-3: diff.packets is required at 0.4 and not at 0.3 (E4-3).
func TestSensorCounters04Packets(t *testing.T) {
	e := counters04(t)
	delete(e.Health.Details, "diff.packets")
	if got := Codes(e.Validate()); !slices.Contains(got, CodeMissing) {
		t.Errorf("0.4 without diff.packets: %v, want missing", got)
	}
	e.Schema = "otsec.event/0.3"
	if err := e.Validate(); err != nil {
		t.Errorf("0.3 without diff.packets: %v", err)
	}
	e = counters04(t)
	e.Health.Details["diff.packets"] = "0"
	if err := e.Validate(); err != nil {
		t.Errorf("0.4 with diff.packets 0: %v", err)
	}
}

// C4-0.4-2: capture_loss is present exactly when one of the three rose,
// and names those that rose, in order (E4-2).
func TestSensorCounters04CaptureLoss(t *testing.T) {
	cases := []struct {
		name  string
		diffs map[string]string
		loss  *string
		want  Code // "" for accepted
	}{
		{"none rose, absent", map[string]string{"drops_holder": "0"}, nil, ""},
		{"holder rose", map[string]string{"drops_holder": "3"}, ptr("drops_holder"), ""},
		{"driver rose", map[string]string{"drops_driver": "1"}, ptr("drops_driver"), ""},
		{"all three", map[string]string{"drops_driver": "1", "drops_holder": "2", "frames_overlong": "3"}, ptr("drops_driver drops_holder frames_overlong"), ""},
		{"two, one zero", map[string]string{"drops_driver": "0", "drops_holder": "2", "frames_overlong": "3"}, ptr("drops_holder frames_overlong"), ""},
		{"absent when one rose", map[string]string{"frames_overlong": "1"}, nil, CodeMissing},
		{"present when none rose", map[string]string{"drops_holder": "0"}, ptr("drops_holder"), CodeEnum},
		{"present, nothing listed", nil, ptr(""), CodeEnum},
		{"out of order", map[string]string{"drops_driver": "1", "drops_holder": "2"}, ptr("drops_holder drops_driver"), CodeEnum},
		{"names one that did not rise", map[string]string{"drops_holder": "2"}, ptr("drops_driver drops_holder"), CodeEnum},
		{"names drops_decoder", map[string]string{"drops_holder": "2"}, ptr("drops_holder drops_decoder"), CodeEnum},
		{"a doubled space", map[string]string{"drops_driver": "1", "drops_holder": "2"}, ptr("drops_driver  drops_holder"), CodeEnum},
	}
	for _, tc := range cases {
		e := counters04(t)
		for k, v := range tc.diffs {
			e.Health.Details["diff."+k] = v
		}
		if tc.loss != nil {
			e.Health.Details[DetailCaptureLoss] = *tc.loss
		}
		got := Codes(e.Validate())
		switch {
		case tc.want == "" && len(got) != 0:
			t.Errorf("%s: refused %v", tc.name, got)
		case tc.want != "" && !slices.Contains(got, tc.want):
			t.Errorf("%s: %v, want %s", tc.name, got, tc.want)
		}
	}
	// At 0.3 capture_loss is not a detail.
	e := load(t, "testdata/valid/health-sensor-counters.json")
	e.Health.Details[DetailCaptureLoss] = "drops_driver"
	e.Health.Details["diff.drops_driver"] = "1"
	if !slices.Contains(Codes(e.Validate()), CodeEnum) {
		t.Error("capture_loss at 0.3: accepted, want enum")
	}
}

// Every event this code builds is stamped 0.4, and this reader reads 0.4
// strictly and a later minor forward (E4-7's contract leg).
func TestIdentifier04(t *testing.T) {
	if Identifier != "otsec.event/0.4" || self.Minor != 4 {
		t.Fatalf("Identifier %s, self minor %d", Identifier, self.Minor)
	}
	e := counters04(t)
	e.Health.Details["note"] = "x"
	if !slices.Contains(Codes(e.Validate()), CodeEnum) {
		t.Error("an unknown detail at 0.4: accepted")
	}
	e.Schema = "otsec.event/0.5"
	if err := e.Validate(); err != nil {
		t.Errorf("an unknown detail at 0.5: %v", err)
	}
}

func ptr(s string) *string { return &s }
