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
