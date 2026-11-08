package netobs

import (
	"bytes"
	"testing"
)

// FuzzDecodeChannel: the channel decoder never panics on hostile bytes, a
// record it accepts is exactly one of the two types, and an accepted record
// encodes to bytes it accepts again (C13 §1: the sensor's output is hostile
// input). The seeds are the valid fixtures and their framing.
func FuzzDecodeChannel(f *testing.F) {
	for _, v := range []any{fxFunction(), fxFlow(), fxHeartbeat(), worstObservations(f)[0]} {
		f.Add(mustJSON(f, v))
	}
	f.Add([]byte(`{"schema":"otsec.netobs/0.1","type":"alert"}`))
	f.Add([]byte(`{"schema":"otsec.netobs/0.1","type":"observation","type":"heartbeat"}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := DecodeChannel(b)
		if err != nil {
			return
		}
		var v any
		switch {
		case r.Observation != nil && r.Heartbeat == nil:
			v = r.Observation
		case r.Heartbeat != nil && r.Observation == nil:
			v = r.Heartbeat
		default:
			t.Fatalf("accepted record is not exactly one type: %+v", r)
		}
		again := mustJSON(t, v)
		if _, err := DecodeChannel(again); err != nil {
			t.Fatalf("re-encoded record refused: %v", err)
		}
		var buf bytes.Buffer
		if err := WriteFrame(&buf, again); err != nil {
			t.Fatal(err)
		}
		if got, err := ReadFrame(&buf); err != nil || !bytes.Equal(got, again) {
			t.Fatalf("framing: %v", err)
		}
	})
}
