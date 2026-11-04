package node

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"time"

	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/event"
	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/modules/detection/eventbaseline"
	"otsec.local/otsec/modules/telemetry/normalize"
)

// EventCheckpointSchema is the node's event-baseline checkpoint document
// (feeder slice 1c, D4-32): the state of one half, the learner's or the
// detector's, of one asset, stored in config/<asset> with the half's
// snapshot as the record's capture. It is working state, not evidence, and
// no C8 record names it.
const EventCheckpointSchema = "otsec.eventcheckpoint/0.1"

// The two halves of an asset's event baseline. Each is checkpointed in a
// record of its own, so each record is self-contained (D4-30).
const (
	CheckpointLearner  = "learner"
	CheckpointDetector = "detector"
)

// MaxCheckpointStreams bounds the streams a checkpoint names: an asset's
// SER and health streams and the listener streams that can carry its Syslog.
// It is the detector's own bound on the streams its held events name, and
// the node configuration is held to it at load (checkEventBaselines).
const MaxCheckpointStreams = eventbaseline.MaxStreams

// MaxCheckpointDocBytes bounds a checkpoint document: MaxAlignRows
// alignment keys at 74 bytes each (a 71-byte key, its quotes and a comma),
// plus 16 KiB for everything else, plus the 16 KiB envelope allowance. It is
// the figure D4-38 counts against the configuration record, so a snapshot of
// MaxSnapshotBytes and its document always fit one record.
const MaxCheckpointDocBytes = event.MaxAlignRows*74 + 16<<10 + 16<<10

// eventCheckpoint is the document. Times are RFC 3339 UTC with a Z.
type eventCheckpoint struct {
	Schema  string `json:"schema"`
	Half    string `json:"half"`
	AssetID string `json:"asset_id"`
	// The baseline the half belongs to: for the learner, the version it
	// will record and the hash of the baseline it replaces (empty for
	// version 1); for the detector, the baseline it watches against.
	Version  int64  `json:"version,omitempty"`
	Previous string `json:"previous,omitempty"`
	Baseline string `json:"baseline,omitempty"`
	// Watermark is the feeder's watermark for the asset: everything at or
	// before it was passed to the half, or counted late.
	Watermark string             `json:"watermark_utc"`
	Streams   []checkpointStream `json:"streams"`
	// PrevKeys is the previous SER read's alignment state, for NotCounted.
	PrevKeys []string `json:"prev_keys"`
	// Gap is the collection gap open at the checkpoint, if one is.
	Gap        *checkpointGap `json:"gap,omitempty"`
	LastGapEnd string         `json:"last_gap_end_utc,omitempty"`
	Late       int64          `json:"late"`
	// Snapshot names the record's capture: the half's Snapshot bytes.
	Snapshot checkpointSnapshot `json:"snapshot"`
}

// checkpointStream is one stream's position. Every record at or before
// RestartAfter was passed or was not the asset's; the feeder resumes after
// it. ReadThrough is the last seq read, so a record re-read after a restart
// at or before it, and at or before the watermark, was already taken.
type checkpointStream struct {
	Stream       string `json:"stream"`
	RestartAfter uint64 `json:"restart_after"`
	ReadThrough  uint64 `json:"read_through"`
}

type checkpointGap struct {
	From   string `json:"from_utc"`
	Reason string `json:"reason"`
}

type checkpointSnapshot struct {
	SHA256 string `json:"sha256"` // lowercase hex, as c5.Capture
	Length int64  `json:"length"`
}

var (
	baselineHashForm = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	captureHashForm  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	gapReasonForm    = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,63}$`) // C10's token
)

// encodeCheckpoint checks c and writes the bytes the store keeps.
func encodeCheckpoint(c eventCheckpoint) ([]byte, error) {
	if err := c.check(); err != nil {
		return nil, err
	}
	b, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	if len(b) > MaxCheckpointDocBytes {
		return nil, fmt.Errorf("event checkpoint: %d bytes, above %d", len(b), MaxCheckpointDocBytes)
	}
	return b, nil
}

// decodeCheckpoint reads a document encodeCheckpoint wrote, and only that:
// one strict JSON object, checked, in the bytes the encoder writes.
func decodeCheckpoint(b []byte) (eventCheckpoint, error) {
	var c eventCheckpoint
	if len(b) > MaxCheckpointDocBytes {
		return c, fmt.Errorf("event checkpoint: %d bytes, above %d", len(b), MaxCheckpointDocBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return c, fmt.Errorf("event checkpoint: %w", err)
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return c, errors.New("event checkpoint: trailing data")
	}
	again, err := encodeCheckpoint(c)
	if err != nil {
		return c, err
	}
	if !bytes.Equal(again, b) {
		return c, errors.New("event checkpoint: not the bytes the node's encoder writes")
	}
	return c, nil
}

func (c eventCheckpoint) check() error {
	bad := func(format string, a ...any) error { return fmt.Errorf("event checkpoint: "+format, a...) }
	switch {
	case c.Schema != EventCheckpointSchema:
		return bad("schema %q", c.Schema)
	case !asset.ValidAssetID(c.AssetID):
		return bad("asset_id %q", c.AssetID)
	}
	switch c.Half {
	case CheckpointLearner:
		switch {
		case c.Version < 1 || c.Baseline != "":
			return bad("a learner has a version from 1 and no baseline")
		case (c.Version == 1) != (c.Previous == ""):
			return bad("a learner's previous is set from version 2 on, and only then")
		case c.Previous != "" && !baselineHashForm.MatchString(c.Previous):
			return bad("previous %q is not sha256:<hex>", c.Previous)
		}
	case CheckpointDetector:
		if c.Version != 0 || c.Previous != "" || !baselineHashForm.MatchString(c.Baseline) {
			return bad("a detector names its baseline as sha256:<hex>, and no version or previous")
		}
	default:
		return bad("half %q", c.Half)
	}
	if err := utcTime("watermark_utc", c.Watermark); err != nil {
		return err
	}
	if len(c.Streams) == 0 || len(c.Streams) > MaxCheckpointStreams {
		return bad("%d streams, 1 to %d", len(c.Streams), MaxCheckpointStreams)
	}
	seen := map[string]bool{}
	for _, s := range c.Streams {
		switch {
		case !c5.StreamID(s.Stream).Valid():
			return bad("stream %q is not a stream token", s.Stream)
		case seen[s.Stream]:
			return bad("stream %s named twice", s.Stream)
		case s.RestartAfter > s.ReadThrough:
			return bad("stream %s restarts after %d, past what it read (%d)", s.Stream, s.RestartAfter, s.ReadThrough)
		}
		seen[s.Stream] = true
	}
	if len(c.PrevKeys) > 0 {
		if _, err := normalize.EncodeState(c.PrevKeys); err != nil {
			return bad("prev_keys: %v", err)
		}
	}
	if c.Gap != nil {
		if err := utcTime("gap.from_utc", c.Gap.From); err != nil {
			return err
		}
		if !gapReasonForm.MatchString(c.Gap.Reason) {
			return bad("gap reason %q is not a token", c.Gap.Reason)
		}
	}
	if c.LastGapEnd != "" {
		if err := utcTime("last_gap_end_utc", c.LastGapEnd); err != nil {
			return err
		}
	}
	switch {
	case c.Late < 0:
		return bad("late %d", c.Late)
	case !captureHashForm.MatchString(c.Snapshot.SHA256):
		return bad("snapshot sha256 %q", c.Snapshot.SHA256)
	case c.Snapshot.Length < 1 || c.Snapshot.Length > eventbaseline.MaxSnapshotBytes:
		return bad("snapshot of %d bytes, 1 to %d", c.Snapshot.Length, eventbaseline.MaxSnapshotBytes)
	}
	return nil
}

// utcTime checks an RFC 3339 time in UTC with a Z.
func utcTime(field, s string) error {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil || t.Location() != time.UTC || s[len(s)-1] != 'Z' {
		return fmt.Errorf("event checkpoint: %s %q is not an RFC 3339 UTC time", field, s)
	}
	return nil
}

// checkCheckpointRecord is ConfigDocuments' case for a checkpoint: the
// document decodes as above, and its capture is the snapshot it names.
// Restore checks the snapshot's own format and checksum; here it is opaque.
// The record is working state in its half's series (C5 0.7).
func checkCheckpointRecord(document []byte, capture *c5.Capture) (c5.DocumentInfo, error) {
	c, err := decodeCheckpoint(document)
	if err != nil {
		return c5.DocumentInfo{}, err
	}
	if capture == nil {
		return c5.DocumentInfo{}, errors.New("configuration document: a checkpoint has no capture; its snapshot is the capture")
	}
	if err := capture.Validate(); err != nil {
		return c5.DocumentInfo{}, err
	}
	if capture.SHA256 != c.Snapshot.SHA256 || int64(len(capture.Bytes)) != c.Snapshot.Length {
		return c5.DocumentInfo{}, fmt.Errorf("configuration document: the capture (sha256 %s, %d bytes) is not the snapshot the checkpoint names (sha256 %s, %d bytes)",
			capture.SHA256, len(capture.Bytes), c.Snapshot.SHA256, c.Snapshot.Length)
	}
	series := c5.SeriesCheckpointLearner
	if c.Half == CheckpointDetector {
		series = c5.SeriesCheckpointDetector
	}
	return c5.DocumentInfo{Kind: c5.DocumentWorkingState, Series: series}, nil
}
