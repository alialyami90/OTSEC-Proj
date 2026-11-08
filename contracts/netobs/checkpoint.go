package netobs

import (
	"bytes"
	"encoding/json"
	"fmt"

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

// MaxLearnerCheckpointBytes bounds a learner checkpoint: its draft, at
// most MaxBaselineBytes, and an envelope of under 1 KiB.
const MaxLearnerCheckpointBytes = MaxBaselineBytes + 1<<10

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
	return c.err()
}

// Encode validates k and encodes it.
func (k *LearnerCheckpoint) Encode() ([]byte, error) {
	if err := k.Validate(); err != nil {
		return nil, err
	}
	out, err := json.Marshal(k)
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
