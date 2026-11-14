package netobs

import (
	"bytes"
	"testing"
)

// dupKey writes key a second time, with value v, just after the object's
// opening brace, so the document holds key twice at the top level.
func dupKey(t *testing.T, b []byte, key, v string) []byte {
	t.Helper()
	if len(b) == 0 || b[0] != '{' {
		t.Fatalf("not an object: %s", b)
	}
	return append([]byte(`{"`+key+`":"`+v+`",`), b[1:]...)
}

// CH-5 at the agent: a field not listed, in any case, closes as type; any
// other strict-decode failure of a known type, a duplicate key included,
// closes as that type. A frame whose type cannot be read closes as type.
func TestDecodeFromNodeCloseReason(t *testing.T) {
	cases := []struct {
		name  string
		b     []byte
		close string
	}{
		{"node-hello, a duplicate sensor_id", dupKey(t, mustJSON(t, fxNodeHello()), "sensor_id", fxSensor), CloseNodeHello},
		{"node-hello, a duplicate in taken", bytes.Replace(mustJSON(t, fxNodeHello()), []byte(`"seq":"100"`), []byte(`"seq":"100","seq":"99"`), 1), CloseNodeHello},
		{"ack, a duplicate seq", dupKey(t, mustJSON(t, fxAck()), "seq", "10"), CloseAck},
		{"node-hello, Generation for generation", encodeWith(t, fxNodeHello(), func(m map[string]any) {
			m["Generation"] = m["generation"]
			delete(m, "generation")
		}), CloseType},
		{"node-hello, Generation beside generation", encodeWith(t, fxNodeHello(), func(m map[string]any) { m["Generation"] = "3" }), CloseType},
		{"node-hello, a case variant in taken", encodeWith(t, fxNodeHello(), func(m map[string]any) {
			tk := m["taken"].(map[string]any)
			tk["SEQ"] = tk["seq"]
			delete(tk, "seq")
		}), CloseType},
		{"ack, Type beside type", encodeWith(t, fxAck(), func(m map[string]any) { m["Type"] = TypeAck }), CloseType},
		{"a duplicate type", dupKey(t, mustJSON(t, fxAck()), "type", TypeAck), CloseType},
		{"type not a string", encodeWith(t, fxAck(), func(m map[string]any) { m["type"] = 1 }), CloseType},
		{"no type", encodeWith(t, fxAck(), func(m map[string]any) { delete(m, "type") }), CloseType},
		{"data after the object", append(mustJSON(t, fxAck()), []byte(" {}")...), CloseType},
		{"node-hello, taken a string", encodeWith(t, fxNodeHello(), func(m map[string]any) { m["taken"] = "x" }), CloseNodeHello},
	}
	for _, tc := range cases {
		m, err := DecodeFromNode(tc.b)
		if err == nil || m.Close != tc.close {
			t.Errorf("%s: close %q (%v), want %s", tc.name, m.Close, err, tc.close)
		}
	}
}

// CH-8, CH-10, CH-13 row 1: a tick or sensor-hello that fails its strict
// decode, a duplicate key included, reports its type, so the node closes
// as tick or hello. A record that cannot be read as typed reports none.
func TestDecodeFromSensorDuplicateKey(t *testing.T) {
	for _, tc := range []struct {
		name, typ string
		b         []byte
	}{
		{"sensor-hello", TypeSensorHello, dupKey(t, mustJSON(t, fxSensorHello()), "run_counter", "5")},
		{"tick", TypeTick, dupKey(t, mustJSON(t, fxTick()), "sent_seq", "15")},
		{"tick, a duplicate schema", TypeTick, dupKey(t, mustJSON(t, fxTick()), "schema", Identifier02)},
		{"tick, Type beside type", TypeTick, encodeWith(t, fxTick(), func(m map[string]any) { m["Type"] = TypeTick })},
		{"heartbeat", TypeHeartbeat, dupKey(t, mustJSON(t, fxHeartbeat02()), "run_id", fxRun)},
		{"a duplicate type", "", dupKey(t, mustJSON(t, fxTick()), "type", TypeTick)},
		{"not an object", "", []byte(`["tick"]`)},
	} {
		m, err := DecodeFromSensor(tc.b)
		if err == nil || m.Type != tc.typ {
			t.Errorf("%s: type %q (%v), want %q", tc.name, m.Type, err, tc.typ)
		}
		if err != nil && tc.typ != "" && !hasCode(err, CodeDecode) {
			t.Errorf("%s: %v, want decode", tc.name, err)
		}
	}
}
