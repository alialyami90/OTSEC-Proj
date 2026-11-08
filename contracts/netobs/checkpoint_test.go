package netobs

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/config"
	"otsec.local/otsec/contracts/event"
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
	// The learner's bounds, by value (D1 in D4-71).
	if MaxHeldStarts != 512 || MaxHeldStartBytes != 384 || MaxLearnerCheckpointBytes != 721920 {
		t.Fatalf("bounds %d, %d, %d", MaxHeldStarts, MaxHeldStartBytes, MaxLearnerCheckpointBytes)
	}
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

func fxDetectorCheckpoint() *DetectorCheckpoint {
	a := fxAlert()
	return &DetectorCheckpoint{Schema: CheckpointIdentifier, Half: HalfDetector, SensorID: fxSensor,
		NodeID: a.Related[0].NodeID, Stream: a.Related[0].Stream, Baseline: a.Baseline, BaselineVersion: a.BaselineVersion, Through: 40, LastAlertSeq: 6, ClockUTC: a.AtUTC,
		Windows: []DetectorWindow{{Rule: a.Rule, AssetID: a.AssetID, KeyText: a.KeyText, BaselineValue: a.BaselineValue,
			Observation: a.Observation, AtUTC: a.AtUTC, WindowStartUTC: a.WindowStartUTC, Hits: a.Hits,
			Sources: []string{"192.0.2.10", "198.51.100.7"}, Related: []uint64{7, 9, 12}, Cites: a.Cites, Coverage: a.Coverage}}}
}

// A detector checkpoint round-trips byte for byte, and each window gives
// the summary alert it holds.
func TestDetectorCheckpointRoundTrip(t *testing.T) {
	k := fxDetectorCheckpoint()
	b, err := k.Encode()
	if err != nil {
		t.Fatal(err)
	}
	back, err := DecodeDetectorCheckpoint(b)
	if err != nil {
		t.Fatal(err)
	}
	again, _ := back.Encode()
	if !bytes.Equal(again, b) {
		t.Fatalf("round trip:\n%s\n%s", b, again)
	}
	a := back.Windows[0].Alert(back, nil)
	a.Capture = fxAlert().Capture
	if err := a.Validate(); err != nil || !reflect.DeepEqual(&a, fxAlert()) {
		t.Fatalf("window alert: %v\n got %+v\nwant %+v", err, a, fxAlert())
	}
	empty := &DetectorCheckpoint{Schema: CheckpointIdentifier, Half: HalfDetector, SensorID: fxSensor, NodeID: "site-a-node1", Stream: "network-observation/" + fxSensor}
	if b, err := empty.Encode(); err != nil || !bytes.Contains(b, []byte(`"windows":[]`)) {
		t.Fatalf("no baseline, no windows: %s, %v", b, err)
	}
}

func TestDetectorCheckpointRules(t *testing.T) {
	cases := []struct {
		name string
		code Code
		mut  func(k *DetectorCheckpoint)
	}{
		{"schema", CodeSchema, func(k *DetectorCheckpoint) { k.Schema = Identifier }},
		{"half", CodeForm, func(k *DetectorCheckpoint) { k.Half = HalfLearner }},
		{"sensor", CodeForm, func(k *DetectorCheckpoint) { k.SensorID = "sensor-1" }},
		{"node", CodeForm, func(k *DetectorCheckpoint) { k.NodeID = "Node_1" }},
		{"stream", CodeForm, func(k *DetectorCheckpoint) { k.Stream = "" }},
		{"windows past the bound", CodeRange, func(k *DetectorCheckpoint) {
			for len(k.Windows) <= MaxDetectorWindows {
				w := k.Windows[0]
				w.AssetID = fmt.Sprintf("%s9%03d", fxAsset[:len(fxAsset)-4], len(k.Windows))
				k.Windows = append(k.Windows, w)
			}
		}},
		{"related seq 0", CodeOrder, func(k *DetectorCheckpoint) { k.Windows[0].Related[0] = 0 }},
		{"related after through", CodeOrder, func(k *DetectorCheckpoint) { k.Windows[0].Related[2] = k.Through + 1 }},
		{"related out of order", CodeOrder, func(k *DetectorCheckpoint) { k.Windows[0].Related = []uint64{9, 7, 12} }},
		{"baseline form", CodeForm, func(k *DetectorCheckpoint) { k.Baseline = "abc" }},
		{"version with no baseline", CodeConflict, func(k *DetectorCheckpoint) { k.Baseline, k.Windows = "", nil }},
		{"baseline version 0", CodeRange, func(k *DetectorCheckpoint) { k.BaselineVersion = 0 }},
		{"windows with no clock", CodeConflict, func(k *DetectorCheckpoint) { k.ClockUTC = "" }},
		{"clock form", CodeForm, func(k *DetectorCheckpoint) { k.ClockUTC = "2026-11-07 10:04:00" }},
		{"window of a baseline rule with no baseline", CodeForm, func(k *DetectorCheckpoint) { k.Baseline, k.BaselineVersion = "", 0 }},
		{"window twice", CodeOrder, func(k *DetectorCheckpoint) { k.Windows = append(k.Windows, k.Windows[0]) }},
		{"related short", CodeConflict, func(k *DetectorCheckpoint) { k.Windows[0].Related = k.Windows[0].Related[:2] }},
		{"sources unsorted", CodeOrder, func(k *DetectorCheckpoint) { k.Windows[0].Sources = []string{"198.51.100.7", "192.0.2.10"} }},
		{"source form", CodeForm, func(k *DetectorCheckpoint) { k.Windows[0].Sources = []string{"::ffff:192.0.2.10"} }},
		{"no source", CodeForm, func(k *DetectorCheckpoint) { k.Windows[0].Sources = nil }},
		{"no cite", CodeForm, func(k *DetectorCheckpoint) { k.Windows[0].Cites = nil }},
	}
	for _, tc := range cases {
		k := fxDetectorCheckpoint()
		tc.mut(k)
		if got := Codes(k.Validate()); !slices.Contains(got, tc.code) {
			t.Errorf("%s: got %v, want %s", tc.name, got, tc.code)
		}
		if _, err := k.Encode(); err == nil {
			t.Errorf("%s: encoded", tc.name)
		}
	}
	b, _ := fxDetectorCheckpoint().Encode()
	if _, err := DecodeDetectorCheckpoint(bytes.Replace(b, []byte(`"through"`), []byte(`"extra":1,"through"`), 1)); !slices.Contains(Codes(err), CodeDecode) {
		t.Errorf("unknown field: %v", err)
	}
}

// The detector's bounds, by value (D1 in D4-72): the window cap, one
// window's worst encoding, and the checkpoint under the configuration
// record cap less its headroom.
func TestDetectorBounds(t *testing.T) {
	if MaxDetectorWindows != 96 || MaxDetectorWindowBytes != 12288 || MaxDetectorCheckpointBytes != 1180672 {
		t.Fatalf("bounds %d, %d, %d", MaxDetectorWindows, MaxDetectorWindowBytes, MaxDetectorCheckpointBytes)
	}
	if MaxDetectorCheckpointBytes > config.RecordCap-config.RecordHeadroom {
		t.Fatalf("%d, above the configuration record cap less headroom %d", MaxDetectorCheckpointBytes, config.RecordCap-config.RecordHeadroom)
	}
}

// worstWindow is the longest window C13 allows, but for its coverage, which
// the caller allows for at MaxCoverageBytes: every text ExplainMax bytes
// that each encode to 6, 32 sources of 39 characters, 32 related seqs of 20
// digits, and 4 flows of 2 frames with the longest capture ID and frame
// numbers.
func worstWindow(asset string) DetectorWindow {
	text := strings.Repeat("<", ExplainMax)
	w := DetectorWindow{Rule: RuleOwnSessionOutsideRecord, AssetID: asset, KeyText: text, BaselineValue: text, Observation: text,
		AtUTC: "2026-11-07T10:04:00.123456789Z", WindowStartUTC: "2026-11-07T10:00:00.123456789Z", Hits: 1<<63 - 1,
		Coverage: fxCoverage()}
	for i := range MaxRelated {
		w.Sources = append(w.Sources, fmt.Sprintf("ffff:ffff:ffff:ffff:ffff:ffff:ffff:f%03x", i))
		w.Related = append(w.Related, 1<<64-1-uint64(MaxRelated)+uint64(i))
	}
	for i := range MaxAlertFlows {
		w.Cites = append(w.Cites, Cite{CaptureID: "file:" + hash([]byte{byte(i)}),
			Frames: []CiteFrame{{N: 1<<63 - 2, SHA256: hash([]byte{1, byte(i)})}, {N: 1<<63 - 1, SHA256: hash([]byte{2, byte(i)})}}})
	}
	return w
}

// A worst window fits MaxDetectorWindowBytes with its comma, and a
// checkpoint of MaxDetectorWindows worst windows encodes within
// MaxDetectorCheckpointBytes, coverage at its bound allowed for.
func TestWorstDetectorCheckpointFits(t *testing.T) {
	cv, _ := json.Marshal(fxCoverage())
	slack := MaxCoverageBytes - len(cv)
	k := fxDetectorCheckpoint()
	k.Through, k.NodeID, k.Stream = 1<<64-1, event.NodeID(strings.Repeat("n", 63)), event.Stream(strings.Repeat("s", 128))
	k.Windows = []DetectorWindow{worstWindow(fxAsset)}
	b, err := k.Encode()
	if err != nil {
		t.Fatal(err)
	}
	w, _ := json.Marshal(k.Windows[0])
	if len(w)+1+slack > MaxDetectorWindowBytes {
		t.Fatalf("worst window %d bytes with its comma and coverage slack %d, above %d", len(w)+1, slack, MaxDetectorWindowBytes)
	}
	t.Logf("worst window %d bytes, slack %d", len(w)+1, slack)
	if env := len(b) - len(w); env >= 1<<10 {
		t.Fatalf("envelope %d bytes, not under 1 KiB", env)
	}
	k.Windows = nil
	for i := range MaxDetectorWindows {
		k.Windows = append(k.Windows, worstWindow(fmt.Sprintf("%s%04d", fxAsset[:len(fxAsset)-4], i)))
	}
	b, err = k.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if n := len(b) + MaxDetectorWindows*slack; n > MaxDetectorCheckpointBytes {
		t.Fatalf("worst checkpoint %d bytes with coverage slack, above %d", n, MaxDetectorCheckpointBytes)
	}
	if _, err := DecodeDetectorCheckpoint(b); err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeDetectorCheckpoint(append(b, make([]byte, MaxDetectorCheckpointBytes)...)); !slices.Contains(Codes(err), CodeRange) {
		t.Errorf("an oversized checkpoint: %v", err)
	}
}
