package netobs

import (
	"bytes"
	"cmp"
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

// MaxHeldStarts bounds the TCP starts a learner holds until its flow shows
// it was not only a dial (baseline note §2.2, D1 in D4-71). A start that
// can't be held counts in period.overflow.
const MaxHeldStarts = 512

// MaxHeldStartBytes bounds one held start as encoded, with its comma
// (TestWorstHeldStartFits).
const MaxHeldStartBytes = 384

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
