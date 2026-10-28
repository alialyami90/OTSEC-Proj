package node

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/config"
	c5 "otsec.local/otsec/contracts/store"
)

// bigConfigSnapshot is read 1 with its first section holding n settings of
// value v, naming a transcript of config.MaxTranscriptBytes: the largest
// record a configuration run can produce (D4-25).
func bigConfigSnapshot(t *testing.T, n int, v string) (config.Snapshot, c5.Capture) {
	t.Helper()
	s, err := config.DecodeSnapshot(contractFile(t, "config/testdata/valid/snapshot-read-1.json"))
	if err != nil {
		t.Fatal(err)
	}
	transcript := make([]byte, config.MaxTranscriptBytes)
	for i := range transcript {
		transcript[i] = byte('a' + i%26)
	}
	sum := sha256.Sum256(transcript)
	sha := hex.EncodeToString(sum[:])
	s.Transcript = config.Evidence{Ref: "sha256:" + sha, SHA256: sha, Length: int64(len(transcript))}
	const digits = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	s.Sections[0].Settings = nil
	for k := 0; k < n; k++ {
		name := string([]byte{digits[k/1296%36], digits[k/36%36], digits[k%36]})
		s.Sections[0].Settings = append(s.Sections[0].Settings, config.Setting{Name: name, Value: v})
	}
	return s, c5.Capture{SHA256: sha, Bytes: transcript}
}

// The largest snapshot C9 accepts, with the longest transcript, is stored by
// the real configuration database as the node lays a snapshot out: the
// snapshot's compact bytes as the event, the transcript as the capture, and
// no source cursor. Its size as C5 counts it (Record.Bytes) leaves at least
// config.RecordHeadroom under ConfigRecordBytes (B1 on #345). One byte more
// of snapshot is refused by C9, so by ConfigDocuments, and nothing is stored.
func TestLargestConfigRecordIsStored(t *testing.T) {
	lo, hi := 1, 400
	for lo < hi {
		mid := (lo + hi + 1) / 2
		if s, _ := bigConfigSnapshot(t, 3000, strings.Repeat("V", mid)); s.Validate() == nil {
			lo = mid
		} else {
			hi = mid - 1
		}
	}
	s, capture := bigConfigSnapshot(t, 3000, strings.Repeat("V", lo))
	doc, err := s.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if len(doc) < config.MaxSnapshotBytes-3500 {
		t.Fatalf("the search stopped at %d bytes, far from the %d bound", len(doc), config.MaxSnapshotBytes)
	}
	rec := c5.Record{Stream: ConfigStream(relayID), Class: c5.ClassConfiguration, Event: doc, Capture: &capture}
	if got, max := rec.Bytes(), ConfigRecordBytes-config.RecordHeadroom; got > max {
		t.Fatalf("the largest record is %d bytes, over the cap %d less the headroom (%d)", got, ConfigRecordBytes, max)
	}

	c, dir := configNode(t, nil)
	r, _, _ := start(t, c, dir)
	defer r.Close()
	_, log, _ := r.view(r.find(ConfigDB))
	if _, err := log.Append(bg, rec); err != nil {
		t.Fatalf("the largest record is not stored: %v", err)
	}

	// Two more bytes of one value (the encoded snapshot grows by two) cannot
	// be a snapshot C9 accepts, once the bound is passed.
	over, ocap := bigConfigSnapshot(t, 3000, strings.Repeat("V", lo+400))
	odoc, err := over.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if err := over.Validate(); !errors.Is(err, config.ErrTooLarge) {
		t.Fatalf("an over-bound snapshot validates: %v", err)
	}
	if _, err := log.Append(bg, c5.Record{Stream: ConfigStream(relayID), Class: c5.ClassConfiguration, Event: odoc, Capture: &ocap}); err == nil {
		t.Fatal("an over-bound snapshot was stored")
	}
}
