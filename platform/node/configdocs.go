package node

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"otsec.local/otsec/contracts/baseline"
	"otsec.local/otsec/contracts/config"
	"otsec.local/otsec/contracts/finding"
	c5 "otsec.local/otsec/contracts/store"
)

// ConfigDocuments is the C5 DocumentValidator of the configuration class
// (C5 0.4): the store runs it on every record of the class before it is
// stored, as it runs C8's seal on audit records, so C5 imports neither C9 nor
// C10. It accepts four documents and nothing else:
//
//   - a C9 snapshot (otsec.config, kind config.snapshot) that decodes and
//     validates, with a capture that is the transcript it names: the same
//     SHA-256 and the same length, so a snapshot never commits beside bytes
//     it was not read from (B2 on #246). The deeper check against the
//     transcript's segments, Snapshot.CheckAgainst, needs the C2 result's
//     segments, which the capture does not carry: the node runs it before
//     it builds the record, as it runs C2's CheckLines on a result;
//   - a C9 difference (config.difference) that decodes and validates, with
//     no capture. It names its two snapshots by digest;
//   - a C10 baseline (otsec.baseline) that decodes and validates, with no
//     capture, in the compact bytes baseline.Encode produces, so that the
//     stored bytes hash to the baseline's Hash (B4 on #299);
//   - the node's event-baseline checkpoint (otsec.eventcheckpoint, feeder
//     slice 1c), in the bytes its encoder writes, with a capture that is the
//     snapshot it names. It is working state, not evidence (D4-32);
//   - since C5 0.8, a C11 advisory set envelope, signature included, in the
//     series advisory.set (checkAdvisorySetRecord);
//   - since C5 0.8, the node's identity record (otsec.identity, evidence,
//     series identity), with a capture that holds the bytes its session
//     observations' spans point to, and its latest-read record
//     (otsec.identityread, working state, series identity.read), with no
//     capture (identity.go);
//   - since C5 0.8, a C12 finding (otsec.finding, evidence, series
//     finding), with no capture, that passes C12's Validate in the bytes
//     the node's encoder writes (findings.go).
//
// It returns each document's C5 0.7 DocumentInfo. The first three are
// evidence, in the series config.snapshot or config.difference (C9's own
// kind names) or baseline.event. A checkpoint is working state, in the
// series of its half, eventcheckpoint.learner or eventcheckpoint.detector,
// taken from the decoded document (C3 on #376).
//
// The validator cannot see the record's stream. The writer, which builds the
// record for config/<asset>, must give it the asset's own document; the
// document names the asset it is about.
func ConfigDocuments(document []byte, capture *c5.Capture) (c5.DocumentInfo, error) {
	var head struct {
		Schema   string `json:"schema"`
		Kind     string `json:"kind"`
		Contract string `json:"contract"`
	}
	if err := json.Unmarshal(document, &head); err != nil {
		return c5.DocumentInfo{}, fmt.Errorf("configuration document: %w", err)
	}
	switch {
	case strings.HasPrefix(head.Schema, "otsec.config/") && head.Kind == config.KindSnapshot:
		s, err := config.DecodeSnapshot(document)
		if err != nil {
			return c5.DocumentInfo{}, err
		}
		if capture == nil {
			return c5.DocumentInfo{}, errors.New("configuration document: a snapshot has no capture; its transcript is the capture")
		}
		if err := capture.Validate(); err != nil {
			return c5.DocumentInfo{}, err
		}
		if capture.SHA256 != s.Transcript.SHA256 || int64(len(capture.Bytes)) != s.Transcript.Length {
			return c5.DocumentInfo{}, fmt.Errorf("configuration document: the capture (sha256 %s, %d bytes) is not the transcript the snapshot names (sha256 %s, %d bytes)",
				capture.SHA256, len(capture.Bytes), s.Transcript.SHA256, s.Transcript.Length)
		}
		return c5.DocumentInfo{Kind: c5.DocumentEvidence, Series: config.KindSnapshot}, nil
	case strings.HasPrefix(head.Schema, "otsec.config/") && head.Kind == config.KindDifference:
		if capture != nil {
			return c5.DocumentInfo{}, errors.New("configuration document: a difference has no capture")
		}
		if _, err := config.DecodeDifference(document); err != nil {
			return c5.DocumentInfo{}, err
		}
		return c5.DocumentInfo{Kind: c5.DocumentEvidence, Series: config.KindDifference}, nil
	case strings.HasPrefix(head.Schema, "otsec.baseline/"):
		if capture != nil {
			return c5.DocumentInfo{}, errors.New("configuration document: a baseline has no capture")
		}
		b, err := baseline.Decode(document)
		if err != nil {
			return c5.DocumentInfo{}, err
		}
		// Decode accepts any strictly valid JSON, whitespace and key order
		// included, but a baseline's Hash is taken over the bytes Encode
		// produces, and the store keeps the bytes it is given. Anything
		// else would store a document whose SHA-256 is not the Hash the
		// acknowledgement names (B4 on #299).
		canonical, err := baseline.Encode(b, 0)
		if err != nil {
			return c5.DocumentInfo{}, err
		}
		if !bytes.Equal(document, canonical) {
			return c5.DocumentInfo{}, errors.New("configuration document: a baseline must be stored as baseline.Encode's bytes")
		}
		return c5.DocumentInfo{Kind: c5.DocumentEvidence, Series: c5.SeriesBaselineEvent}, nil
	case head.Schema == EventCheckpointSchema:
		return checkCheckpointRecord(document, capture)
	case head.Schema == "" && strings.HasPrefix(head.Contract, "otsec.advisory/"):
		return checkAdvisorySetRecord(document, capture)
	case head.Schema == IdentitySchema:
		return checkIdentityRecord(document, capture)
	case head.Schema == IdentityReadSchema:
		return checkIdentityReadRecord(document, capture)
	case finding.Known(head.Schema):
		return checkFindingRecord(document, capture)
	}
	return c5.DocumentInfo{}, fmt.Errorf("configuration document: schema %q kind %q is not a C9 snapshot or difference, a C10 baseline, an event checkpoint, a C11 set, an identity record or a C12 finding", head.Schema, head.Kind)
}
