package netobs

import (
	"bytes"
	"cmp"
	"encoding/json"
	"fmt"

	"otsec.local/otsec/contracts/event"
	"otsec.local/otsec/contracts/internal/strictjson"
)

// CheckpointIdentifier is the schema of both network checkpoints, the
// learner's and the detector's, its first field (C13 §8).
const CheckpointIdentifier = "otsec.netcheckpoint/0.1"

// The checkpoint halves. Each is its own C5 series (C13 §8): the learner's
// in netcheckpoint.learner, the detector's in netcheckpoint.detector.
const (
	HalfLearner  = "learner"
	HalfDetector = "detector"
)

// MaxHeldStarts bounds the TCP starts a learner holds until its flow shows
// it was not only a dial (baseline note §2.2, D1 in D4-71). A start that
// can't be held counts in period.overflow.
const MaxHeldStarts = 512

// MaxHeldStartBytes bounds one held start as encoded, with its comma
// (TestWorstHeldStartFits).
const MaxHeldStartBytes = 384

// MaxDetectorWindows bounds the open coalescing windows a detector holds
// (C13 §7.3, D1 in D4-72). When it is full, a new key still alerts at once,
// and the window that started earliest closes early with its summary.
const MaxDetectorWindows = 96

// MaxDetectorWindowBytes bounds one open window as encoded, with its comma
// (TestWorstDetectorWindowFits).
const MaxDetectorWindowBytes = 12 << 10

// MaxDetectorCheckpointBytes bounds a detector checkpoint: its windows and
// an envelope of under 1 KiB, 1,180,672 bytes. It is under the
// configuration record cap less its headroom (1,507,328), so a checkpoint
// that fits is never refused there.
const MaxDetectorCheckpointBytes = MaxDetectorWindows*MaxDetectorWindowBytes + 1<<10

// MaxLearnerCheckpointBytes bounds a learner checkpoint: its draft, at
// most MaxBaselineBytes, its held starts, and an envelope of under 1 KiB.
const MaxLearnerCheckpointBytes = MaxBaselineBytes + MaxHeldStarts*MaxHeldStartBytes + 1<<10

// HeldStart is a TCP client-server flow start whose pair the learner has
// not learned yet: its flow (the client's address and port, and the
// server's address with the pair's port) and the pair it would learn.
type HeldStart struct {
	Src   string `json:"src"`
	Sport int    `json:"sport"`
	Dst   string `json:"dst"`
	Pair  Pair   `json:"pair"`
}

// CompareHeldStart orders held starts by flow: src, sport, dst, then the
// server port.
func CompareHeldStart(a, b HeldStart) int {
	return cmp.Or(cmp.Compare(a.Src, b.Src), cmp.Compare(a.Sport, b.Sport), cmp.Compare(a.Dst, b.Dst), cmp.Compare(a.Pair.Port, b.Pair.Port))
}

// LearnerCheckpoint is the learner's checkpoint (C13 §8, baseline note
// §2.2). The learner's whole state is its draft, so restoring is decoding
// the draft and folding on after Through.
type LearnerCheckpoint struct {
	Schema   string `json:"schema"`
	Half     string `json:"half"`
	SensorID string `json:"sensor_id"`
	// Through is the last observation-stream seq the learner folded or
	// passed over. It folds nothing at or below it, so a re-read after a
	// restore folds each observation once.
	Through uint64 `json:"through"`
	// Frozen says learning has ended: the draft is final and the learner
	// folds nothing more.
	Frozen bool `json:"frozen"`
	// Draft is the draft baseline in C13 §8's canonical encoding, with no
	// authorized writers. Until it is frozen, its end_utc is its start_utc.
	Draft json.RawMessage `json:"draft"`
	// Held are the starts held unproven, sorted by flow, one per flow, at
	// most MaxHeldStarts, and none once frozen: a start unproven at the
	// period's end is not learned.
	Held []HeldStart `json:"held"`
}

// Validate checks the checkpoint: its schema and half, its sensor, and a
// draft that is a canonical baseline of the same sensor with no writers.
func (k *LearnerCheckpoint) Validate() error {
	c := &checker{}
	if k.Schema != CheckpointIdentifier {
		c.fail(CodeSchema, "schema", "%q is not %s", k.Schema, CheckpointIdentifier)
	}
	if k.Half != HalfLearner {
		c.fail(CodeForm, "half", "%q is not %s", k.Half, HalfLearner)
	}
	c.uuid("sensor_id", k.SensorID)
	b, err := DecodeBaseline(k.Draft)
	switch {
	case err != nil:
		c.fail(CodeForm, "draft", "not a network baseline: %v", err)
	case !IsCanonical(k.Draft):
		c.fail(CodeForm, "draft", "not in canonical encoding")
	case b.SensorID != k.SensorID:
		c.fail(CodeConflict, "draft.sensor_id", "%s, not the checkpoint's %s", b.SensorID, k.SensorID)
	case len(b.AuthorizedWriters) != 0:
		c.fail(CodeForm, "draft.authorized_writers", "a draft has none; a person adds them")
	}
	switch {
	case len(k.Held) > MaxHeldStarts:
		c.fail(CodeRange, "held", "%d starts, above %d", len(k.Held), MaxHeldStarts)
	case k.Frozen && len(k.Held) != 0:
		c.fail(CodeConflict, "held", "a frozen draft holds no starts")
	}
	for i := range k.Held {
		h := &k.Held[i]
		f := fmt.Sprintf("held[%d]", i)
		c.addr(f+".src", h.Src)
		c.addr(f+".dst", h.Dst)
		if h.Sport < 0 || h.Sport > 65535 {
			c.fail(CodeRange, f+".sport", "%d not in [0, 65535]", h.Sport)
		}
		h.Pair.check(c, f+".pair")
		if h.Pair.L4 != "tcp" {
			c.fail(CodeForm, f+".pair.l4", "%q: only a TCP start is held", h.Pair.L4)
		}
		if i > 0 && CompareHeldStart(k.Held[i-1], *h) >= 0 {
			c.fail(CodeOrder, "held", "sorted by flow, one per flow")
		}
	}
	return c.err()
}

// Encode validates k and encodes it.
func (k *LearnerCheckpoint) Encode() ([]byte, error) {
	if err := k.Validate(); err != nil {
		return nil, err
	}
	e := *k
	if e.Held == nil {
		e.Held = []HeldStart{}
	}
	out, err := json.Marshal(&e)
	if err != nil {
		return nil, err
	}
	if len(out) > MaxLearnerCheckpointBytes {
		return nil, &Error{Code: CodeRange, Field: "checkpoint", Detail: fmt.Sprintf("%d bytes, above %d", len(out), MaxLearnerCheckpointBytes)}
	}
	return out, nil
}

// DecodeLearnerCheckpoint decodes a learner checkpoint strictly and
// validates it. The draft is kept as its exact bytes.
func DecodeLearnerCheckpoint(b []byte) (*LearnerCheckpoint, error) {
	if len(b) > MaxLearnerCheckpointBytes {
		return nil, &Error{Code: CodeRange, Field: "checkpoint", Detail: fmt.Sprintf("%d bytes, above %d", len(b), MaxLearnerCheckpointBytes)}
	}
	var k LearnerCheckpoint
	if err := strictjson.Decode(b, &k); err != nil {
		return nil, &Error{Code: CodeDecode, Field: "checkpoint", Detail: err.Error()}
	}
	k.Draft = bytes.Clone(k.Draft)
	return &k, k.Validate()
}

// DetectorCheckpoint is the detector's checkpoint (C13 §8, baseline note
// §3): the baseline it judges against, the last observation it took, the
// capture clock, the open coalescing windows, and the last alert seq it
// knew of. A restore replays the observations after Through from this
// state, and the alerts committed after LastAlertSeq tell it which of the
// alerts it raises again were committed already.
type DetectorCheckpoint struct {
	Schema   string `json:"schema"`
	Half     string `json:"half"`
	SensorID string `json:"sensor_id"`
	// NodeID and Stream are the observation stream the detector reads. A
	// window's related observations are seqs on it.
	NodeID event.NodeID `json:"node_id"`
	Stream event.Stream `json:"stream"`
	// Baseline and BaselineVersion name the acknowledged baseline the
	// detector judges against: its hash and version, or "" and 0 before any
	// acknowledgement.
	Baseline        string `json:"baseline"`
	BaselineVersion int64  `json:"baseline_version"`
	// Through is the last observation-stream seq the detector took.
	Through uint64 `json:"through"`
	// LastAlertSeq is the last seq on the sensor's alert stream that the
	// detector knew to be committed.
	LastAlertSeq uint64 `json:"last_alert_seq"`
	// ClockUTC is the capture clock: the latest first_utc taken, or "" when
	// none has been.
	ClockUTC string `json:"clock_utc"`
	// Windows are the open coalescing windows, sorted by rule and then
	// asset, one per key, at most MaxDetectorWindows (C13 §7.3).
	Windows []DetectorWindow `json:"windows"`
}

// DetectorWindow is one open coalescing window: what its summary alert
// would carry so far, and the distinct source addresses it has counted.
// Its first alert was raised when it opened.
type DetectorWindow struct {
	Rule           Rule   `json:"rule"`
	AssetID        string `json:"asset_id"`
	KeyText        string `json:"key_text"`
	BaselineValue  string `json:"baseline_value"`
	Observation    string `json:"observation"`
	AtUTC          string `json:"at_utc"`
	WindowStartUTC string `json:"window_start_utc"`
	Hits           int64  `json:"hits"`
	// Sources are the distinct source addresses counted, sorted, at most
	// MaxRelated; past that the count stops (baseline note §8).
	Sources []string `json:"sources"`
	// Related are the seqs, on the checkpoint's observation stream, of the
	// first min(hits, MaxRelated) hits, in order.
	Related  []uint64 `json:"related"`
	Cites    []Cite   `json:"cites"`
	Coverage Coverage `json:"coverage"`
}

// Alert is the summary alert w would give now, without its capture, under
// the baseline k names and with the rule's params.
func (w *DetectorWindow) Alert(k *DetectorCheckpoint, params []Param) Alert {
	related := make([]event.EventID, len(w.Related))
	for i, seq := range w.Related {
		related[i] = event.EventID{NodeID: k.NodeID, Stream: k.Stream, Seq: seq}
	}
	return Alert{Schema: Identifier, Rule: w.Rule, AssetID: w.AssetID, Baseline: k.Baseline, BaselineVersion: k.BaselineVersion,
		KeyText: w.KeyText, Params: params, BaselineValue: w.BaselineValue, Observation: w.Observation, Clock: ClockCapture,
		AtUTC: w.AtUTC, WindowStartUTC: w.WindowStartUTC, Hits: w.Hits, Sources: int64(len(w.Sources)),
		Related: related, RelatedTotal: w.Hits, Cites: w.Cites, Coverage: w.Coverage}
}

// Validate checks the checkpoint: its schema, half and sensor, the baseline
// named or not, the clock, and every window as the alert it would give.
func (k *DetectorCheckpoint) Validate() error {
	c := &checker{}
	if k.Schema != CheckpointIdentifier {
		c.fail(CodeSchema, "schema", "%q is not %s", k.Schema, CheckpointIdentifier)
	}
	if k.Half != HalfDetector {
		c.fail(CodeForm, "half", "%q is not %s", k.Half, HalfDetector)
	}
	c.uuid("sensor_id", k.SensorID)
	if !k.NodeID.Valid() {
		c.fail(CodeForm, "node_id", "%q is not a node ID", k.NodeID)
	}
	if !k.Stream.Valid() {
		c.fail(CodeForm, "stream", "%q is not a stream", k.Stream)
	}
	if len(k.Windows) > MaxDetectorWindows {
		c.fail(CodeRange, "windows", "%d open, above %d", len(k.Windows), MaxDetectorWindows)
	}
	switch {
	case k.Baseline == "" && k.BaselineVersion != 0:
		c.fail(CodeConflict, "baseline_version", "a version with no baseline")
	case k.Baseline != "" && !baselineHashForm.MatchString(k.Baseline):
		c.fail(CodeForm, "baseline", "%q is not sha256:<hex>", k.Baseline)
	case k.Baseline != "" && k.BaselineVersion < 1:
		c.fail(CodeRange, "baseline_version", "%d is below 1", k.BaselineVersion)
	}
	if k.ClockUTC == "" && len(k.Windows) != 0 {
		c.fail(CodeConflict, "clock_utc", "windows open with no clock")
	}
	if k.ClockUTC != "" {
		c.utc("clock_utc", k.ClockUTC)
	}
	for i := range k.Windows {
		w := &k.Windows[i]
		f := fmt.Sprintf("windows[%d]", i)
		if i > 0 {
			p := &k.Windows[i-1]
			if p.Rule > w.Rule || (p.Rule == w.Rule && p.AssetID >= w.AssetID) {
				c.fail(CodeOrder, f, "windows sorted by rule and asset, one per key")
			}
		}
		var params []Param
		for _, name := range ruleParams[w.Rule] {
			params = append(params, Param{Name: name, Value: "1"}) // the values are the detector's
		}
		a := w.Alert(k, params)
		a.Capture = fmt.Sprintf("%064x", 0)
		if err := a.Validate(); err != nil {
			c.fail(CodeForm, f, "%v", err)
		}
		if w.Rule == RuleOwnSessionUnseen {
			continue
		}
		if n := min(w.Hits, MaxRelated); int64(len(w.Related)) != n {
			c.fail(CodeConflict, f+".related", "%d seqs for %d hits", len(w.Related), w.Hits)
		}
		for j, seq := range w.Related {
			if seq == 0 || seq > k.Through || (j > 0 && w.Related[j-1] >= seq) {
				c.fail(CodeOrder, f+".related", "seqs rising, from 1 to through %d", k.Through)
				break
			}
		}
		for j, s := range w.Sources {
			c.addr(fmt.Sprintf("%s.sources[%d]", f, j), s)
			if j > 0 && w.Sources[j-1] >= s {
				c.fail(CodeOrder, f+".sources", "sorted, without duplicates")
			}
		}
		if len(w.Sources) > MaxRelated {
			c.fail(CodeRange, f+".sources", "%d, above %d", len(w.Sources), MaxRelated)
		}
	}
	return c.err()
}

// Encode validates k and encodes it.
func (k *DetectorCheckpoint) Encode() ([]byte, error) {
	if err := k.Validate(); err != nil {
		return nil, err
	}
	e := *k
	if e.Windows == nil {
		e.Windows = []DetectorWindow{}
	}
	out, err := json.Marshal(&e)
	if err != nil {
		return nil, err
	}
	if len(out) > MaxDetectorCheckpointBytes {
		return nil, &Error{Code: CodeRange, Field: "checkpoint", Detail: fmt.Sprintf("%d bytes, above %d", len(out), MaxDetectorCheckpointBytes)}
	}
	return out, nil
}

// DecodeDetectorCheckpoint decodes a detector checkpoint strictly and
// validates it.
func DecodeDetectorCheckpoint(b []byte) (*DetectorCheckpoint, error) {
	if len(b) > MaxDetectorCheckpointBytes {
		return nil, &Error{Code: CodeRange, Field: "checkpoint", Detail: fmt.Sprintf("%d bytes, above %d", len(b), MaxDetectorCheckpointBytes)}
	}
	var k DetectorCheckpoint
	if err := strictjson.Decode(b, &k); err != nil {
		return nil, &Error{Code: CodeDecode, Field: "checkpoint", Detail: err.Error()}
	}
	return &k, k.Validate()
}
