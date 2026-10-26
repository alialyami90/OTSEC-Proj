// Package storeopen checks C5 0.2's busy-open retry on the real store (A6,
// P3-A6; docs/phase2/A5-p3-failed-open-retry.md tests 1 and 2).
//
// The holder is A6's own connection through the SQLite driver, not A5's
// test helpers. Ground truth: the C5 0.2 rule text. An open that another
// connection holds busy is retried by Resume and succeeds once the holder
// lets go, under the lock the first startup took; an open that fails for
// any other reason is never retried. Class: simulated (a second connection
// in the same process stands in for a second process holding the file).
package storeopen

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"

	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/platform/store"
)

var db = c5.Database{
	ID:      "evidence",
	Writer:  "ied",
	Streams: []c5.StreamSpec{{ID: "relay1/ser", Class: c5.ClassAdapterEvidence}, {ID: "platform/health", Class: c5.ClassPlatform}},
	Classes: []c5.StreamClass{c5.ClassAdapterEvidence, c5.ClassPlatform},
	Quotas: []c5.Quota{
		{Class: c5.ClassAdapterEvidence, Bytes: 8 << 20, WarnFraction: 0.8},
		{Class: c5.ClassPlatform, Bytes: 8 << 20, WarnFraction: 0.8},
	},
}

func policy() c5.StartupPolicy {
	return c5.StartupPolicy{
		Streams:                db.Streams,
		RecoveryReserveBytes:   2 * store.WALBoundBytes,
		LastResortReserveBytes: store.WALBoundBytes + c5.MinOpenHeadroom,
		OpenHeadroomBytes:      store.WALBoundBytes + c5.MinOpenHeadroom,
		PruneStepEvents:        50,
		CompactStepPages:       32,
		PruneTarget:            0.8,
	}
}

func env(t *testing.T, dir string) *store.Env {
	t.Helper()
	e, err := store.NewEnv(store.Options{Dir: dir, Node: "node-a6", Database: db})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func dir(t *testing.T) string {
	t.Helper()
	d := filepath.Join(t.TempDir(), "store")
	if err := store.CreateDir(d, ""); err != nil {
		t.Fatal(err)
	}
	return d
}

// hold opens the database file exclusively: in WAL mode an exclusive
// connection keeps the file once it has read and written, so every other
// open is busy until it closes.
func hold(t *testing.T, path string) *sql.DB {
	t.Helper()
	h, err := sql.Open("sqlite", "file:"+(&url.URL{Path: path}).EscapedPath())
	if err != nil {
		t.Fatal(err)
	}
	h.SetMaxOpenConns(1)
	for _, q := range []string{"PRAGMA locking_mode=EXCLUSIVE", "BEGIN IMMEDIATE", "SELECT count(*) FROM sqlite_master", "COMMIT"} {
		if _, err := h.Exec(q); err != nil {
			h.Close()
			t.Fatalf("%s: %v", q, err)
		}
	}
	return h
}

func create(t *testing.T, d string) {
	t.Helper()
	r := c5.RunStartup(context.Background(), env(t, d), policy())
	if r.Mode != c5.ModeCollecting {
		t.Fatalf("first startup: %s %v", r.Mode, r.Alarms)
	}
	r.Store.Close()
	r.Unlock()
}

func TestBusyOpenIsRetriedUntilTheHolderLetsGo(t *testing.T) {
	if testing.Short() {
		t.Skip("waits out busy_timeout")
	}
	ctx := context.Background()
	d := dir(t)
	create(t, d)
	h := hold(t, filepath.Join(d, "evidence.db"))
	e := env(t, d)
	r := c5.RunStartup(ctx, e, policy())
	if r.Mode != c5.ModeFailed || !r.OpenBusy() || r.Unlock == nil {
		h.Close()
		t.Fatalf("startup beside a holder: mode %s busy %v alarms %v", r.Mode, r.OpenBusy(), r.Alarms)
	}
	r = c5.Resume(ctx, e, policy(), r)
	if r.Mode != c5.ModeFailed || !r.OpenBusy() {
		h.Close()
		t.Fatalf("retry while still held: mode %s busy %v", r.Mode, r.OpenBusy())
	}
	h.Close()
	r = c5.Resume(ctx, e, policy(), r)
	if r.Mode != c5.ModeCollecting || r.Store == nil || r.Unlock == nil {
		t.Fatalf("retry after the holder let go: mode %s alarms %v", r.Mode, r.Alarms)
	}
	// The retry ran under the first startup's lock: a second node on the
	// same directory is still refused until it is released.
	if r2 := c5.RunStartup(ctx, env(t, d), policy()); r2.Mode != c5.ModeFailed || r2.OpenBusy() {
		t.Fatalf("second startup while the first holds the lock: %s busy %v", r2.Mode, r2.OpenBusy())
	}
	r.Store.Close()
	r.Unlock()
}

// A file that is not a database, and one that is another node's, fail at
// or after the open for reasons that are not busy; Resume leaves them.
func TestOtherOpenFailuresAreNotRetried(t *testing.T) {
	ctx := context.Background()
	junk := dir(t)
	if err := os.WriteFile(filepath.Join(junk, "evidence.db"), []byte(strings.Repeat("not a database ", 512)), 0o600); err != nil {
		t.Fatal(err)
	}
	other := dir(t)
	create(t, other)
	for name, c := range map[string]struct {
		dir  string
		node c5.NodeID
	}{"not a database": {junk, "node-a6"}, "another node's database": {other, "node-b6"}} {
		e, err := store.NewEnv(store.Options{Dir: c.dir, Node: c.node, Database: db})
		if err != nil {
			t.Fatal(err)
		}
		r := c5.RunStartup(ctx, e, policy())
		if r.Mode != c5.ModeFailed || r.OpenBusy() {
			t.Errorf("%s: mode %s busy %v", name, r.Mode, r.OpenBusy())
		}
		for _, s := range r.Steps {
			if errors.Is(s.Err, &c5.Error{Code: c5.CodeOpenBusy}) {
				t.Errorf("%s: step %s typed busy: %v", name, s.Step, s.Err)
			}
		}
		if next := c5.Resume(ctx, e, policy(), r); next.Mode != c5.ModeFailed || next.Store != nil {
			t.Errorf("%s: Resume gave %s", name, next.Mode)
		}
		if r.Unlock != nil {
			r.Unlock()
		}
	}
}
