package netobs

import (
	"testing"
)

// FuzzDecodeFromSensorIn: the 0.3 node's decoder never panics on hostile
// bytes under any connection minor, sets at most one kind, sets one exactly
// when it accepts, accepts on a connection only a frame of its minor, and
// an accepted frame encodes to bytes it accepts again (CH-5, CH-36).
func FuzzDecodeFromSensorIn(f *testing.F) {
	h3 := fxSensorHello()
	h3.Schema = Identifier03
	k3 := fxTick()
	k3.Schema = Identifier03
	inc := fxEnd03("tcp")
	inc.Flow.PasswordLines, inc.Flow.Incomplete = nil, ptr(true)
	for i, v := range []any{h3, k3, fxHeartbeat03(), fxEnd03("tcp"), fxEnd03("udp"), inc, fxSensorHello(), fxHeartbeat02()} {
		f.Add(mustJSON(f, v), uint8(i))
	}
	f.Add([]byte(`{"schema":"otsec.netobs/0.3","type":"observation","flow":{"incomplete":false}}`), uint8(2))
	conns := []string{"", Identifier02, Identifier03}
	f.Fuzz(func(t *testing.T, b []byte, c uint8) {
		conn := conns[int(c)%len(conns)]
		m, err := DecodeFromSensorIn(b, conn)
		set := 0
		var v any
		var schema string
		if m.Hello != nil {
			set, v, schema = set+1, m.Hello, m.Hello.Schema
		}
		if m.Tick != nil {
			set, v, schema = set+1, m.Tick, m.Tick.Schema
		}
		if m.Heartbeat != nil {
			set, v, schema = set+1, m.Heartbeat, m.Heartbeat.Schema
		}
		if m.Observation != nil {
			set, v, schema = set+1, m.Observation, m.Observation.Schema
		}
		if set > 1 || (err == nil && set != 1) {
			t.Fatalf("%d kinds set, err %v", set, err)
		}
		if err != nil {
			return
		}
		if conn != "" && schema != conn {
			t.Fatalf("a %s frame accepted on a %s connection", schema, conn)
		}
		if _, err := DecodeFromSensorIn(mustJSON(t, v), conn); err != nil {
			t.Fatalf("re-encoded frame refused: %v", err)
		}
	})
}
