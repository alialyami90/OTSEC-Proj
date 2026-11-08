package netobs

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

func fxLearnerCheckpoint(t *testing.T) *LearnerCheckpoint {
	t.Helper()
	draft, err := fxBaseline().Encode()
	if err != nil {
		t.Fatal(err)
	}
	return &LearnerCheckpoint{Schema: CheckpointIdentifier, Half: HalfLearner, SensorID: fxSensor, Through: 1 << 40, Frozen: true, Draft: draft}
}

// A learner checkpoint round-trips byte for byte, its draft kept exact.
func TestLearnerCheckpointRoundTrip(t *testing.T) {
	b, err := fxLearnerCheckpoint(t).Encode()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(b, []byte(`{"schema":"`+CheckpointIdentifier+`"`)) {
		t.Fatalf("schema is not the first field: %.60s", b)
	}
	k, err := DecodeLearnerCheckpoint(b)
	if err != nil {
		t.Fatal(err)
	}
	again, _ := k.Encode()
	if !bytes.Equal(again, b) || k.Through != 1<<40 || !k.Frozen {
		t.Fatalf("round trip: %s", again)
	}
}

func TestLearnerCheckpointRules(t *testing.T) {
	writers := fxBaseline()
	writers.AuthorizedWriters = []Writer{{Client: fxMaster, Server: fxAsset, Class: ClassWrite}}
	withWriters, _ := writers.Encode()
	cases := []struct {
		name string
		code Code
		mut  func(k *LearnerCheckpoint)
	}{
		{"schema", CodeSchema, func(k *LearnerCheckpoint) { k.Schema = "otsec.netcheckpoint/0.2" }},
		{"half", CodeForm, func(k *LearnerCheckpoint) { k.Half = HalfDetector }},
		{"sensor", CodeForm, func(k *LearnerCheckpoint) { k.SensorID = "sensor-1" }},
		{"other sensor's draft", CodeConflict, func(k *LearnerCheckpoint) { k.SensorID = fxAsset }},
		{"draft not canonical", CodeForm, func(k *LearnerCheckpoint) {
			k.Draft = bytes.Replace(k.Draft, []byte(`"pairs":[`), []byte(`"pairs": [`), 1)
		}},
		{"draft not a baseline", CodeForm, func(k *LearnerCheckpoint) { k.Draft = []byte(`{"schema":"x"}`) }},
		{"draft with writers", CodeForm, func(k *LearnerCheckpoint) { k.Draft = withWriters }},
		{"held once frozen", CodeConflict, func(k *LearnerCheckpoint) { k.Held = []HeldStart{fxHeld(1)} }},
		{"held unsorted", CodeOrder, func(k *LearnerCheckpoint) { k.Frozen, k.Held = false, []HeldStart{fxHeld(2), fxHeld(1)} }},
		{"held twice", CodeOrder, func(k *LearnerCheckpoint) { k.Frozen, k.Held = false, []HeldStart{fxHeld(1), fxHeld(1)} }},
		{"held over the bound", CodeRange, func(k *LearnerCheckpoint) {
			k.Frozen = false
			for i := range MaxHeldStarts + 1 {
				k.Held = append(k.Held, fxHeld(i))
			}
		}},
		{"held UDP", CodeForm, func(k *LearnerCheckpoint) {
			h := fxHeld(1)
			h.Pair.L4 = "udp"
			k.Frozen, k.Held = false, []HeldStart{h}
		}},
		{"held address", CodeForm, func(k *LearnerCheckpoint) {
			h := fxHeld(1)
			h.Src = "::ffff:192.0.2.10"
			k.Frozen, k.Held = false, []HeldStart{h}
		}},
		{"held sport", CodeRange, func(k *LearnerCheckpoint) {
			h := fxHeld(1)
			h.Sport = 65536
			k.Frozen, k.Held = false, []HeldStart{h}
		}},
	}
	for _, tc := range cases {
		k := fxLearnerCheckpoint(t)
		tc.mut(k)
		if got := Codes(k.Validate()); !slices.Contains(got, tc.code) {
			t.Errorf("%s: got %v, want %s", tc.name, got, tc.code)
		}
		if _, err := k.Encode(); err == nil {
			t.Errorf("%s: encoded", tc.name)
		}
	}
	b, _ := fxLearnerCheckpoint(t).Encode()
	if _, err := DecodeLearnerCheckpoint(bytes.Replace(b, []byte(`"frozen"`), []byte(`"extra":1,"frozen"`), 1)); !slices.Contains(Codes(err), CodeDecode) {
		t.Errorf("unknown field: %v", err)
	}
	big := []byte(`{"pad":"` + strings.Repeat("a", MaxLearnerCheckpointBytes) + `"}`)
	if _, err := DecodeLearnerCheckpoint(big); !slices.Contains(Codes(err), CodeRange) {
		t.Errorf("over MaxLearnerCheckpointBytes: %v", err)
	}
}

// A draft at MaxBaselineBytes fits its checkpoint: the envelope stays
// within the 1 KiB MaxLearnerCheckpointBytes allows beside it.
func TestLearnerCheckpointFits(t *testing.T) {
	k := fxLearnerCheckpoint(t)
	k.Through = ^uint64(0)
	k.Draft = []byte(`{}`)
	b, err := json.Marshal(k)
	if err != nil {
		t.Fatal(err)
	}
	if envelope := len(b) - len(k.Draft); envelope > MaxLearnerCheckpointBytes-MaxBaselineBytes {
		t.Fatalf("envelope %d bytes", envelope)
	}
}

func fxHeld(sport int) HeldStart {
	return HeldStart{Src: "192.0.2.10", Sport: sport, Dst: "192.0.2.20",
		Pair: Pair{Client: fxMaster, Server: fxAsset, L4: "tcp", Port: 20000, Protocol: "dnp3"}}
}

// An unfrozen checkpoint with held starts round-trips; the worst held start
// fits MaxHeldStartBytes with its comma, so MaxHeldStarts of them fit
// MaxLearnerCheckpointBytes beside the largest draft.
func TestWorstHeldStartFits(t *testing.T) {
	k := fxLearnerCheckpoint(t)
	k.Frozen, k.Held = false, []HeldStart{fxHeld(1), fxHeld(2)}
	b, err := k.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if back, err := DecodeLearnerCheckpoint(b); err != nil || len(back.Held) != 2 {
		t.Fatalf("round trip: %v", err)
	}
	v6 := "ffff:ffff:ffff:ffff:ffff:ffff:ffff:fff1"
	worst := HeldStart{Src: v6, Sport: 65535, Dst: v6, Pair: Pair{Client: "addr:" + v6, Server: "addr:" + v6, L4: "tcp", Port: 65535, Protocol: strings.Repeat("p", 64)}}
	w, _ := json.Marshal(worst)
	if len(w)+1 > MaxHeldStartBytes {
		t.Fatalf("worst held start %d bytes with its comma, above %d", len(w)+1, MaxHeldStartBytes)
	}
}
