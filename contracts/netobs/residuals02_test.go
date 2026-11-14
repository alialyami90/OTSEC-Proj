package netobs

import (
	"bytes"
	"testing"
)

// N1 (b) on #687: a key present with null decodes as absent, so prior on
// a sensor-hello and taken on a node-hello are refused as null, not read
// as absent. Controls: each absent, and each present with its object,
// decodes.
func TestChannelNullObjects(t *testing.T) {
	h := encodeWith(t, fxSensorHello(), func(m map[string]any) { m["prior"] = nil })
	if m, err := DecodeFromSensor(h); !hasCode(err, CodeForm) || m.Type != TypeSensorHello {
		t.Errorf("sensor-hello, prior null: type %q, %v; want sensor-hello, form", m.Type, err)
	}
	withPrior := fxSensorHello()
	withPrior.Prior = fxPrior()
	for name, v := range map[string]any{"absent": fxSensorHello(), "present": withPrior} {
		if _, err := DecodeFromSensor(mustJSON(t, v)); err != nil {
			t.Errorf("sensor-hello, prior %s: %v", name, err)
		}
	}
	n := encodeWith(t, fxNodeHello(), func(m map[string]any) { m["taken"] = nil })
	if m, err := DecodeFromNode(n); !hasCode(err, CodeForm) || m.Close != CloseNodeHello {
		t.Errorf("node-hello, taken null: close %q, %v; want node-hello, form", m.Close, err)
	}
	noTaken := fxNodeHello()
	noTaken.Taken = nil
	for name, v := range map[string]any{"absent": noTaken, "present": fxNodeHello()} {
		if _, err := DecodeFromNode(mustJSON(t, v)); err != nil {
			t.Errorf("node-hello, taken %s: %v", name, err)
		}
	}
}

// N1 (c) on #687, CH-31: an interface entry without packets is refused as
// missing, not read as 0. Control: the same heartbeat with packets 0.
func TestHeartbeatInterfacePacketsRequired(t *testing.T) {
	h := fxHeartbeat02()
	h.Counters.Packets, h.Interfaces[0].Packets = 0, 0
	if _, err := DecodeFromSensor(mustJSON(t, h)); err != nil {
		t.Fatalf("control, packets 0: %v", err)
	}
	b := encodeWith(t, h, func(m map[string]any) { delete(m["interfaces"].([]any)[0].(map[string]any), "packets") })
	if _, err := DecodeFromSensor(b); !hasCode(err, CodeMissing) {
		t.Errorf("packets absent: %v, want missing", err)
	}
}

// N1 (d) on #687: a 0.2 detector checkpoint's window coverage with
// config_digest "" or settings.prp_window_ms 0 is refused, as the same
// keys in the top-level coverage are (form, range). Control: the document
// with the window's values decodes.
func TestDetectorWindowCoverage02Values(t *testing.T) {
	k := fxDetectorCheckpoint()
	cv := fxCoverage02()
	k.Coverage, k.Windows[0].Coverage = &cv, cv
	b, err := k.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeDetectorCheckpoint(b); err != nil {
		t.Fatalf("control: %v", err)
	}
	for _, tc := range []struct {
		name string
		path []any
		v    any
		code Code
	}{
		{"window config_digest empty", []any{"windows", 0, "coverage", "config_digest"}, "", CodeForm},
		{"window prp_window_ms 0", []any{"windows", 0, "coverage", "settings", "prp_window_ms"}, 0, CodeRange},
		{"top-level config_digest empty", []any{"coverage", "config_digest"}, "", CodeForm},
		{"top-level prp_window_ms 0", []any{"coverage", "settings", "prp_window_ms"}, 0, CodeRange},
	} {
		doc := encodeWith(t, k, func(m map[string]any) { setPath(m, tc.v, tc.path...) })
		if _, err := DecodeDetectorCheckpoint(doc); !hasCode(err, tc.code) {
			t.Errorf("%s: %v, want %s", tc.name, err, tc.code)
		}
	}
}

// N2 on #687: a window whose coverage carries a field new in 0.2 gives a
// 0.2 alert, which builds its health body; one with a 0.1 coverage gives
// a 0.1 alert. Control: the 0.2 window's alert stamped 0.1, as before the
// fix, is refused.
func TestWindowAlertSchema(t *testing.T) {
	for _, tc := range []struct {
		name string
		cv   Coverage
		want string
	}{
		{"0.1 coverage", fxCoverage(), Identifier},
		{"0.2 coverage", fxCoverage02(), Identifier02},
	} {
		k := fxDetectorCheckpoint()
		k.Windows[0].Coverage = tc.cv
		a := k.Windows[0].Alert(k, fxAlert().Params)
		a.Capture = fxAlert().Capture
		if a.Schema != tc.want {
			t.Errorf("%s: %s, want %s", tc.name, a.Schema, tc.want)
		}
		if _, err := a.Health(); err != nil {
			t.Errorf("%s: %v", tc.name, err)
		}
		if tc.want == Identifier02 {
			a.Schema = Identifier
			if _, err := a.Health(); err == nil {
				t.Errorf("%s stamped 0.1: built, so the control shows nothing", tc.name)
			}
		}
	}
}

// N4 on #687, CH-31: an interface named twice is refused, even when every
// name is the coverage statement's and the packets sum to
// counters.packets. Control: the mutant that drops the seen check in
// checkInterfaces accepts it.
func TestHeartbeatInterfaceNamedTwice(t *testing.T) {
	h := fxHeartbeat02()
	half := h.Counters.Packets / 2
	h.Interfaces = []InterfaceCount{
		{Name: "eth1", Carrier: "up", Packets: half},
		{Name: "eth1", Carrier: "up", Packets: h.Counters.Packets - half},
	}
	if len(h.Coverage.Interfaces) != 1 || h.Coverage.Interfaces[0].Name != "eth1" {
		t.Fatalf("coverage interfaces %+v, want eth1 alone", h.Coverage.Interfaces)
	}
	b := mustJSON(t, h)
	if !bytes.Contains(b, []byte(`"interfaces":[{"name":"eth1"`)) {
		t.Fatalf("encoded: %s", b)
	}
	if _, err := DecodeFromSensor(b); !hasCode(err, CodeConflict) {
		t.Errorf("eth1 twice: %v, want conflict", err)
	}
}
