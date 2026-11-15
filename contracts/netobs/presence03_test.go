package netobs

import "testing"

// Finding C on #687, for the fields 0.3 adds: a key present with null is
// refused below 0.3 as new, and at 0.3 as null; it is never read as absent.
func TestNull03KeysRefused(t *testing.T) {
	for _, c := range []struct {
		name string
		rec  any
		conn string
		path []any
		code Code
	}{
		{"0.2 end, orig_payload null", clear03(fxEnd03("tcp"), Identifier02), Identifier02, []any{"flow", "orig_payload"}, CodeDecode},
		{"0.2 end, incomplete null", clear03(fxEnd03("tcp"), Identifier02), Identifier02, []any{"flow", "incomplete"}, CodeDecode},
		{"0.2 heartbeat, frame_stage null", fxHeartbeat02(), Identifier02, []any{"frame_stage"}, CodeDecode},
		{"0.2 heartbeat, an agent 0.3 count null", fxHeartbeat02(), Identifier02, []any{"agent", "overlap_unjoined"}, CodeDecode},
		{"0.3 end, orig_payload null", fxEnd03("tcp"), Identifier03, []any{"flow", "orig_payload"}, CodeForm},
		{"0.3 end, rexmit_inconsistent null", fxEnd03("tcp"), Identifier03, []any{"flow", "rexmit_inconsistent"}, CodeForm},
		{"0.3 end, incomplete null", fxEnd03("tcp"), Identifier03, []any{"flow", "incomplete"}, CodeForm},
		{"0.3 heartbeat, frame_stage null", fxHeartbeat03(), Identifier03, []any{"frame_stage"}, CodeForm},
		{"0.3 heartbeat, an agent 0.3 count null", fxHeartbeat03(), Identifier03, []any{"agent", "overlap_unjoined"}, CodeForm},
	} {
		b := encodeWith(t, c.rec, func(m map[string]any) { setPath(m, nil, c.path...) })
		if _, err := DecodeFromSensorIn(b, c.conn); !hasCode(err, c.code) {
			t.Errorf("%s: %v, want %s", c.name, err, c.code)
		}
	}
	// A stored 0.2 end with a 0.3 count null is refused too.
	b := encodeWith(t, asStored(clear03(fxEnd03("tcp"), Identifier02)), func(m map[string]any) { setPath(m, nil, "flow", "resp_pkts") })
	if _, err := DecodeStored(b); !hasCode(err, CodeDecode) {
		t.Errorf("a stored 0.2 end with resp_pkts null: %v, want decode", err)
	}
}
