package store

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	c5 "otsec.local/otsec/contracts/store"
)

// A reader opened beside the running store sees committed events, writes
// nothing (every write path is refused and the files' bytes are unchanged
// by the reader alone), and refuses another node's or a missing database.
func TestOpenReadOnly(t *testing.T) {
	dir := storeDir(t)
	db, _ := testStore(t, Options{Dir: dir, Node: testNode, Database: evidenceDB}, policy(evidenceDB), c5.ModeCollecting)
	l := testLog(t, db)
	if _, err := l.AppendBatch(bg, recs("relay1/ser", c5.ClassAdapterEvidence, 0, 3)); err != nil {
		t.Fatal(err)
	}

	r, err := OpenReadOnly(bg, dir, testNode, evidenceDB.ID)
	if err != nil {
		t.Fatal(err)
	}
	got, err := r.Read(bg, "relay1/ser", 0, 100)
	if err != nil || len(got) != 3 {
		t.Fatalf("read %d events: %v", len(got), err)
	}
	if _, err := l.Append(bg, rec("relay1/ser", c5.ClassAdapterEvidence, 3)); err != nil {
		t.Fatal(err)
	}
	if got, _ := r.Read(bg, "relay1/ser", 0, 100); len(got) != 4 {
		t.Fatalf("reader does not see a later commit: %d events", len(got))
	}

	files := func() map[string][]byte {
		m := map[string][]byte{}
		ents, _ := os.ReadDir(dir)
		for _, e := range ents {
			b, _ := os.ReadFile(filepath.Join(dir, e.Name()))
			m[e.Name()] = b
		}
		return m
	}
	before := files()
	if _, err := r.CommitBatch(bg, "relay1/ser", recs("relay1/ser", c5.ClassAdapterEvidence, 9, 1)); err == nil {
		t.Error("reader committed a batch")
	}
	if err := r.SaveCursor(bg, c5.Cursor{Consumer: "central", Stream: "relay1/ser", Through: 1}); err == nil {
		t.Error("reader saved a cursor")
	}
	if err := r.SaveSourceCursor(bg, "relay1/ser", []byte("x")); err == nil {
		t.Error("reader saved a source cursor")
	}
	if _, err := r.CompactStep(bg, 1); err == nil {
		t.Error("reader compacted")
	}
	if _, err := r.conn.ExecContext(bg, `DELETE FROM events`); err == nil {
		t.Error("query_only connection deleted events")
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	after := files()
	for name, b := range before {
		if name == "evidence.db-shm" {
			continue // the WAL index is shared memory, read and written by every reader
		}
		if !bytes.Equal(after[name], b) {
			t.Errorf("%s changed while only the reader ran", name)
		}
	}

	if _, err := OpenReadOnly(bg, dir, "site-b-node1", evidenceDB.ID); err == nil {
		t.Error("another node's database opened")
	}
	if _, err := OpenReadOnly(bg, dir, testNode, "audit"); err == nil {
		t.Error("a missing database opened")
	}
	if _, err := os.Stat(filepath.Join(dir, "audit.db")); !os.IsNotExist(err) {
		t.Errorf("opening a missing database created it: %v", err)
	}
}
