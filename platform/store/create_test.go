package store

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	c5 "otsec.local/otsec/contracts/store"
)

// A new database is built without flushes and flushed once before its
// rename (#230). Just before the rename, its whole content must be in the
// main file: no -wal, no non-empty -shm, and the main file alone opens as
// the complete store. The kill test covers each step of the creation.
func TestCreateHoldsEverythingInTheMainFile(t *testing.T) {
	dir := storeDir(t)
	tmp := filepath.Join(dir, string(evidenceDB.ID)+".db.new")
	var checked bool
	opt := Options{Dir: dir, Node: testNode, Database: evidenceDB, hook: func(p string) {
		if p != "create:rename" {
			return
		}
		checked = true
		if _, err := os.Lstat(tmp + "-wal"); !os.IsNotExist(err) {
			t.Errorf("-wal before the rename: %v", err)
		}
		if fi, err := os.Lstat(tmp + "-shm"); err == nil && fi.Size() > 0 {
			t.Errorf("-shm of %d bytes before the rename", fi.Size())
		}
		b, err := os.ReadFile(tmp)
		if err != nil {
			t.Fatal(err)
		}
		alone := filepath.Join(t.TempDir(), "alone.db")
		if err := os.WriteFile(alone, b, 0o600); err != nil {
			t.Fatal(err)
		}
		sdb, err := sql.Open("sqlite", fileURI(alone, "immutable=1"))
		if err != nil {
			t.Fatal(err)
		}
		defer sdb.Close()
		var format, node string
		if err := sdb.QueryRow(`SELECT value FROM meta WHERE key = 'format'`).Scan(&format); err != nil {
			t.Fatalf("the main file alone: %v", err)
		}
		sdb.QueryRow(`SELECT value FROM meta WHERE key = 'node_id'`).Scan(&node)
		if format != Format || node != string(testNode) {
			t.Errorf("the main file alone holds format %q node %q", format, node)
		}
	}}
	db, _ := testStore(t, opt, policy(evidenceDB), c5.ModeCollecting)
	if !checked {
		t.Fatal("create:rename was not reached")
	}
	var sync int
	if err := db.conn.QueryRowContext(bg, "PRAGMA synchronous").Scan(&sync); err != nil || sync != 2 {
		t.Fatalf("synchronous after creation: %d %v, want 2 (FULL)", sync, err)
	}
}
