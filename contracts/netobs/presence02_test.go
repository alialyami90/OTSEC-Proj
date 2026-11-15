package netobs

import "testing"

// setPath sets the value at a dotted path of a decoded document, making the
// last key if it is absent. "windows.0" indexes a list.
func setPath(m map[string]any, v any, path ...any) {
	var cur any = m
	for i, p := range path {
		last := i == len(path)-1
		switch k := p.(type) {
		case string:
			if last {
				cur.(map[string]any)[k] = v
				return
			}
			cur = cur.(map[string]any)[k]
		case int:
			cur = cur.([]any)[k]
		}
	}
}

// D4-103 ruling 2: the 0.1 readers refuse a key new in 0.2 whatever its
// value, the zero value of its Go field included ("", 0, false, null).
func TestReaders01RefuseZeroValued02Keys(t *testing.T) {
	type tc struct {
		v    any
		path []any
	}
	obs := []tc{
		{"", []any{"made_utc"}},
		{"", []any{"coverage", "config_digest"}},
		{0, []any{"coverage", "settings", "prp_window_ms"}},
	}
	for _, c := range obs {
		b := encodeWith(t, fxFunction(), func(m map[string]any) { setPath(m, c.v, c.path...) })
		if _, err := DecodeChannel(b); !hasCode(err, CodeDecode) {
			t.Errorf("0.1 channel observation with %v %#v: %v, want decode", c.path, c.v, err)
		}
	}
	hb := append([]tc{
		{nil, []any{"interfaces"}},
		{nil, []any{"agent"}},
		{"", []any{"egress_check"}},
		{nil, []any{"counters", "drops_holder"}},
		{nil, []any{"counters", "engine_lines_refused"}},
	}, obs[1:]...)
	for _, c := range hb {
		b := encodeWith(t, fxHeartbeat(), func(m map[string]any) { setPath(m, c.v, c.path...) })
		if _, err := DecodeChannel(b); !hasCode(err, CodeDecode) {
			t.Errorf("0.1 channel heartbeat with %v %#v: %v, want decode", c.path, c.v, err)
		}
	}
	stored := append([]tc{
		{false, []any{"node", "late"}},
		{false, []any{"node", "backlog"}},
		{false, []any{"node", "skewed"}},
		{nil, []any{"node", "lost"}},
	}, obs...)
	for _, c := range stored {
		b := encodeWith(t, fxStored(), func(m map[string]any) { setPath(m, c.v, c.path...) })
		if _, err := DecodeStored(b); !hasCode(err, CodeDecode) {
			t.Errorf("stored 0.1 observation with %v %#v: %v, want decode", c.path, c.v, err)
		}
	}
	k := fxDetectorCheckpoint()
	k.Schema = CheckpointIdentifier01
	for _, c := range []tc{
		{"", []any{"coverage", "config_digest"}},
		{0, []any{"coverage", "settings", "prp_window_ms"}},
		{"", []any{"windows", 0, "coverage", "config_digest"}},
		{0, []any{"windows", 0, "coverage", "settings", "prp_window_ms"}},
	} {
		b := encodeWith(t, k, func(m map[string]any) { setPath(m, c.v, c.path...) })
		if _, err := DecodeDetectorCheckpoint(b); !hasCode(err, CodeDecode) {
			t.Errorf("0.1 checkpoint with %v %#v: %v, want decode", c.path, c.v, err)
		}
	}
	// The same documents without the keys still read.
	for _, b := range [][]byte{mustJSON(t, fxFunction()), mustJSON(t, fxHeartbeat())} {
		if _, err := DecodeChannel(b); err != nil {
			t.Errorf("a 0.1 channel record: %v", err)
		}
	}
	if _, err := DecodeStored(mustJSON(t, fxStored())); err != nil {
		t.Errorf("a stored 0.1 observation: %v", err)
	}
	if _, err := DecodeDetectorCheckpoint(mustJSON(t, k)); err != nil {
		t.Errorf("a 0.1 checkpoint: %v", err)
	}
}

// On the 0.2 channel a key present with its zero value is judged by that
// value, not read as absent: prp_window_ms 0 is range (CH-28), and an
// empty or null required field is refused, never accepted.
func TestChannel02ZeroValuedKeys(t *testing.T) {
	for _, c := range []struct {
		rec  any
		v    any
		path []any
		code Code
	}{
		{fxObservation02(), 0, []any{"coverage", "settings", "prp_window_ms"}, CodeRange},
		{fxHeartbeat02(), 0, []any{"coverage", "settings", "prp_window_ms"}, CodeRange},
		{fxObservation02(), "", []any{"made_utc"}, CodeMissing}, // an empty time is missing, as everywhere in C13
		{fxObservation02(), "", []any{"coverage", "config_digest"}, CodeForm},
		{fxHeartbeat02(), "", []any{"egress_check"}, CodeForm},
		{fxHeartbeat02(), nil, []any{"interfaces"}, CodeRange},
		{fxHeartbeat02(), nil, []any{"agent"}, CodeForm},
		{fxHeartbeat02(), nil, []any{"counters", "drops_holder"}, CodeForm},
	} {
		b := encodeWith(t, c.rec, func(m map[string]any) { setPath(m, c.v, c.path...) })
		if _, err := DecodeFromSensor(b); !hasCode(err, c.code) {
			t.Errorf("%T with %v %#v: %v, want %s", c.rec, c.path, c.v, err, c.code)
		}
	}
}
