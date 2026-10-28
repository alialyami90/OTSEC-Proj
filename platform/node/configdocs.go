package node

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"otsec.local/otsec/contracts/baseline"
	"otsec.local/otsec/contracts/config"
	c5 "otsec.local/otsec/contracts/store"
)

// ConfigDocuments is the C5 DocumentValidator of the configuration class
// (C5 0.4): the store runs it on every record of the class before it is
// stored, as it runs C8's seal on audit records, so C5 imports neither C9 nor
// C10. It accepts three documents and nothing else:
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
//     stored bytes hash to the baseline's Hash (B4 on #299).
//
// The validator cannot see the record's stream. The writer, which builds the
// record for config/<asset>, must give it the asset's own document; the
// document names the asset it is about.
func ConfigDocuments(document []byte, capture *c5.Capture) error {
	var head struct {
		Schema string `json:"schema"`
		Kind   string `json:"kind"`
	}
	if err := json.Unmarshal(document, &head); err != nil {
		return fmt.Errorf("configuration document: %w", err)
	}
	switch {
	case strings.HasPrefix(head.Schema, "otsec.config/") && head.Kind == config.KindSnapshot:
		s, err := config.DecodeSnapshot(document)
		if err != nil {
			return err
		}
		if capture == nil {
			return errors.New("configuration document: a snapshot has no capture; its transcript is the capture")
		}
		if err := capture.Validate(); err != nil {
			return err
		}
		if capture.SHA256 != s.Transcript.SHA256 || int64(len(capture.Bytes)) != s.Transcript.Length {
			return fmt.Errorf("configuration document: the capture (sha256 %s, %d bytes) is not the transcript the snapshot names (sha256 %s, %d bytes)",
				capture.SHA256, len(capture.Bytes), s.Transcript.SHA256, s.Transcript.Length)
		}
		return nil
	case strings.HasPrefix(head.Schema, "otsec.config/") && head.Kind == config.KindDifference:
		if capture != nil {
			return errors.New("configuration document: a difference has no capture")
		}
		_, err := config.DecodeDifference(document)
		return err
	case strings.HasPrefix(head.Schema, "otsec.baseline/"):
		if capture != nil {
			return errors.New("configuration document: a baseline has no capture")
		}
		b, err := baseline.Decode(document)
		if err != nil {
			return err
		}
		// Decode accepts any strictly valid JSON, whitespace and key order
		// included, but a baseline's Hash is taken over the bytes Encode
		// produces, and the store keeps the bytes it is given. Anything
		// else would store a document whose SHA-256 is not the Hash the
		// acknowledgement names (B4 on #299).
		canonical, err := baseline.Encode(b, 0)
		if err != nil {
			return err
		}
		if !bytes.Equal(document, canonical) {
			return errors.New("configuration document: a baseline must be stored as baseline.Encode's bytes")
		}
		return nil
	}
	return fmt.Errorf("configuration document: schema %q kind %q is not a C9 snapshot or difference or a C10 baseline", head.Schema, head.Kind)
}
