//go:build windows

package collector

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"testing"
)

// A reader that holds state.json open without FILE_SHARE_DELETE, as an
// antivirus scanner, backup agent or indexer can, makes the rename over it
// fail. The collector then fails closed: the state breaks, no number is
// handed out, and the file keeps the old doc for the next start (A1 on
// #179). os.Open shares read and write only, so it is such a reader.
func TestHeldStateFileBreaksState(t *testing.T) {
	path, s, c := newState(t)
	if got, err := s.NextSeq(); err != nil || got != 1 {
		t.Fatalf("NextSeq: %d, %v", got, err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	h, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.BeginAuth(testAsset); !errors.Is(err, ErrStateUnavailable) {
		h.Close()
		t.Fatalf("BeginAuth with state.json held open: %v, want ErrStateUnavailable", err)
	}
	h.Close()

	// Broken for the rest of the process, even with the file released.
	if _, err := s.NextSeq(); !errors.Is(err, ErrStateUnavailable) {
		t.Fatalf("NextSeq after the failed rename: %v", err)
	}
	if err := s.CheckFloor(testAsset); !errors.Is(err, ErrStateUnavailable) {
		t.Fatalf("CheckFloor after the failed rename: %v", err)
	}
	if s.LastSeq() != 1 {
		t.Fatalf("seq advanced by a failed write: %d", s.LastSeq())
	}

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatalf("state.json changed by a failed rename:\n%s\n%s", before, after)
	}

	// The rename was the step that failed: the new doc was written and
	// flushed to the .tmp beside state.json, with the floor BeginAuth set.
	tmp, err := os.ReadFile(path + ".tmp")
	if err != nil {
		t.Fatalf("no .tmp left by the failed rename: %v", err)
	}
	if bytes.Equal(tmp, before) {
		t.Fatal(".tmp holds the old doc: the write before the rename did not run")
	}
	var doc stateDoc
	if err := json.Unmarshal(tmp, &doc); err != nil {
		t.Fatalf(".tmp: %v", err)
	}
	if doc.Assets[testAsset].UnconfirmedAuthUTC == "" {
		t.Fatalf(".tmp has no floor for the asset: %s", tmp)
	}

	// The next start reads the old doc, with the stale .tmp still beside
	// it: no floor was recorded, and numbering resumes after 1.
	s2, err := OpenState(path, c.now)
	if err != nil {
		t.Fatal(err)
	}
	if err := s2.CheckFloor(testAsset); err != nil {
		t.Fatalf("CheckFloor after the restart: %v", err)
	}
	if got, err := s2.NextSeq(); err != nil || got != 2 {
		t.Fatalf("NextSeq after the restart: %d, %v, want 2", got, err)
	}
	if _, err := os.Stat(path + ".tmp"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale .tmp after the next write: %v", err)
	}
}
