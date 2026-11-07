package store

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	c5 "otsec.local/otsec/contracts/store"
)

// A reserve holds its full size on disk: the space allocated to the file,
// not only its length, is at least the bytes asked for (P4-H4, ADR-0004
// item 8).
func TestReserveHoldsItsSpace(t *testing.T) {
	e, err := NewEnv(Options{Dir: storeDir(t), Node: testNode, Database: evidenceDB})
	if err != nil {
		t.Fatal(err)
	}
	const n = 4<<20 + 12345
	for _, r := range []c5.Reserve{c5.ReserveRecovery, c5.ReserveLastResort} {
		if err := e.CreateReserve(bg, r, n); err != nil {
			t.Fatal(err)
		}
		fi, err := os.Stat(e.reservePath(r))
		if err != nil {
			t.Fatal(err)
		}
		got := allocatedBytes(t, e.reservePath(r))
		if got < n || fi.Size() != n {
			t.Fatalf("%s reserve: %d bytes long, %d allocated, want %d of both", r, fi.Size(), got, n)
		}
		t.Logf("%s reserve: %d bytes long, %d allocated", r, fi.Size(), got)
	}
}

// allocatedBytes tells a sparse file from a full one, so the test above
// fails for a reserve that only has its length.
func TestAllocatedBytesSeesASparseFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sparse")
	const n = 4 << 20
	makeSparse(t, p, n)
	if got := allocatedBytes(t, p); got >= n {
		t.Fatalf("a sparse file of %d bytes reads as %d allocated", n, got)
	}
}

// A file system with no single allocation call, such as Linux's fallocate
// returning EOPNOTSUPP, gets the reserve written as zeros, with its full
// space; any other allocation error fails CreateReserve and leaves no
// reserve (P4-H4).
func TestReserveAllocationFallback(t *testing.T) {
	const n = 1<<20 + 12345
	for _, c := range []struct {
		name string
		err  error
	}{{"unsupported", unsupported}, {"other", errors.New("injected allocation fault")}} {
		t.Run(c.name, func(t *testing.T) {
			defer func(a func(*os.File, int64) error) { reserveAllocate = a }(reserveAllocate)
			reserveAllocate = func(*os.File, int64) error { return c.err }
			e, err := NewEnv(Options{Dir: storeDir(t), Node: testNode, Database: evidenceDB})
			if err != nil {
				t.Fatal(err)
			}
			err = e.CreateReserve(bg, c5.ReserveRecovery, n)
			p := e.reservePath(c5.ReserveRecovery)
			if c.name == "other" {
				if ok, xerr := e.ReserveExists(bg, c5.ReserveRecovery); !errors.Is(err, c.err) || ok || xerr != nil {
					t.Fatalf("CreateReserve: %v; reserve left: %v %v", err, ok, xerr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			fi, err := os.Stat(p)
			if err != nil {
				t.Fatal(err)
			}
			if got := allocatedBytes(t, p); got < n || fi.Size() != n {
				t.Fatalf("written reserve: %d bytes long, %d allocated, want %d of both", fi.Size(), got, n)
			}
		})
	}
}

// A fault in either of the reserve's flushes, the file's or its folder's,
// fails CreateReserve and leaves no reserve; at startup the database ends
// drain-only with reserve-recreate-failed, so it accepts no new events
// (P4-H4, ADR-0004 item 8). On Windows the folder flush does nothing, and
// its fault tests the handling only.
func TestReserveFlushFaults(t *testing.T) {
	injected := errors.New("injected flush fault")
	for _, step := range []string{"file", "folder"} {
		t.Run(step, func(t *testing.T) {
			restore := failReserveFlush(step, injected)
			defer restore()
			dir := storeDir(t)
			e, err := NewEnv(Options{Dir: dir, Node: testNode, Database: evidenceDB})
			if err != nil {
				t.Fatal(err)
			}
			if err := e.CreateReserve(bg, c5.ReserveRecovery, 1<<20); !errors.Is(err, injected) {
				t.Fatalf("CreateReserve: %v", err)
			}
			if ok, err := e.ReserveExists(bg, c5.ReserveRecovery); err != nil || ok {
				t.Fatalf("a reserve whose flush failed is left in place: %v %v", ok, err)
			}
			db, r := testStore(t, Options{Dir: dir, Node: testNode, Database: evidenceDB}, policy(evidenceDB), c5.ModeDrainOnly)
			a := alarms{got: r.Alarms}
			if !a.has(c5.AlarmReserveRecreateFailed) || r.Mode.AcceptsEvents() || db == nil {
				t.Fatalf("startup: mode %s, alarms %v", r.Mode, r.Alarms)
			}
		})
	}
}

// failReserveFlush makes the reserve's file or folder flush return err
// until restore is called.
func failReserveFlush(step string, err error) (restore func()) {
	file, dir := reserveFileSync, reserveDirSync
	switch step {
	case "file":
		reserveFileSync = func(*os.File) error { return err }
	case "folder":
		reserveDirSync = func(string) error { return err }
	}
	return func() { reserveFileSync, reserveDirSync = file, dir }
}
