package netobs

import (
	"slices"
	"testing"
)

// FuzzDecodeFromSensor: the 0.2 node's decoder never panics on hostile
// bytes, sets at most one kind, sets one exactly when it accepts, and an
// accepted frame encodes to bytes it accepts again (C13 0.2 CH-5).
func FuzzDecodeFromSensor(f *testing.F) {
	h := fxSensorHello()
	h.Prior = fxPrior()
	for _, v := range []any{fxSensorHello(), h, fxTick(), fxHeartbeat02(), fxObservation02()} {
		f.Add(mustJSON(f, v))
	}
	f.Add([]byte(`{"schema":"otsec.netobs/0.2","type":"alert"}`))
	f.Add([]byte(`{"schema":"otsec.netobs/0.1","type":"sensor-hello"}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		m, err := DecodeFromSensor(b)
		set := 0
		var v any
		if m.Hello != nil {
			set, v = set+1, m.Hello
		}
		if m.Tick != nil {
			set, v = set+1, m.Tick
		}
		if m.Heartbeat != nil {
			set, v = set+1, m.Heartbeat
		}
		if m.Observation != nil {
			set, v = set+1, m.Observation
		}
		if set > 1 || (err == nil && set != 1) {
			t.Fatalf("%d kinds set, err %v", set, err)
		}
		if err != nil {
			return
		}
		if _, err := DecodeFromSensor(mustJSON(t, v)); err != nil {
			t.Fatalf("re-encoded frame refused: %v", err)
		}
	})
}

// FuzzDecodeFromNode: the agent's decoder never panics, every refusal names
// a close reason of the agent's set, and an accepted frame names none.
func FuzzDecodeFromNode(f *testing.F) {
	nh := fxNodeHello()
	nh.Taken = nil
	for _, v := range []any{fxNodeHello(), nh, fxAck()} {
		f.Add(mustJSON(f, v))
	}
	f.Add([]byte(`{"schema":"otsec.netobs/0.2","type":"tick"}`))
	f.Add([]byte(`{"schema":"otsec.netobs/0.2","type":"ack","seq":"01"}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		m, err := DecodeFromNode(b)
		switch {
		case err != nil && !slices.Contains(AgentCloseReasons, m.Close):
			t.Fatalf("refused with close %q: %v", m.Close, err)
		case err == nil && (m.Close != "" || (m.Hello == nil) == (m.Ack == nil)):
			t.Fatalf("accepted: %+v", m)
		}
	})
}
