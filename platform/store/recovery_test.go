package store

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"

	c5 "otsec.local/otsec/contracts/store"
)

// A database left by a killed writer needs WAL recovery, which the first
// connection to read it runs while the others get SQLITE_BUSY_RECOVERY.
// The node's open and a read-only CLI's open (otsec health, polled while
// the node restarts) must both wait for it rather than fail: an open that
// fails leaves the database failed until the node restarts again (A1 and
// A6, store-full e2e on 9c50395). Evidence class: simulated.
func TestOpenBesideReaderAfterKill(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a child process")
	}
	killed := storeDir(t)
	cmd := exec.Command(os.Args[0], "-test.run=^TestCrashChild$")
	cmd.Env = append(os.Environ(), "OTSEC_CRASH_DIR="+killed, "OTSEC_CRASH_POINT=commit:done", "OTSEC_CRASH_NTH=40")
	out, err := cmd.Output()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != crashExit {
		t.Fatalf("child did not stop: %v\n%s", err, out)
	}
	path := filepath.Join(killed, string(evidenceDB.ID)+".db")
	if fi, err := os.Stat(path + "-wal"); err != nil || fi.Size() == 0 {
		t.Fatalf("no WAL left by the killed writer: %v", err)
	}
	const rounds, readers = 40, 4
	for round := 0; round < rounds; round++ {
		dir := storeDir(t)
		for _, suffix := range []string{"", "-wal", "-shm"} {
			copyFile(t, path+suffix, filepath.Join(dir, string(evidenceDB.ID)+".db"+suffix))
		}
		ctx := context.Background()
		start := make(chan struct{})
		var wg sync.WaitGroup
		errs := make(chan error, readers+1)
		for i := 0; i < readers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				r, err := OpenReadOnly(ctx, dir, testNode, evidenceDB.ID)
				if err != nil {
					errs <- fmt.Errorf("reader: %w", err)
					return
				}
				r.Close()
			}()
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			d, err := open(ctx, filepath.Join(dir, string(evidenceDB.ID)+".db"), Options{Dir: dir, Node: testNode, Database: evidenceDB})
			if err != nil {
				errs <- fmt.Errorf("node: %w", err)
				return
			}
			d.Close()
		}()
		close(start)
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Errorf("round %d: %v", round, err)
		}
		if t.Failed() {
			return
		}
	}
}

func copyFile(t *testing.T, from, to string) {
	t.Helper()
	src, err := os.Open(from)
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	dst, err := os.OpenFile(to, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer dst.Close()
	if _, err := io.Copy(dst, src); err != nil {
		t.Fatal(err)
	}
}

// C5 0.2: an open that another connection holds busy past busy_timeout is
// CodeOpenBusy, which Resume retries, and it opens once that connection
// lets go. A file that is not a database is not, so it is never retried.
func TestOpenBusyIsTyped(t *testing.T) {
	if testing.Short() {
		t.Skip("waits out busy_timeout")
	}
	dir := storeDir(t)
	open1(t, dir, evidenceDB, nil).Close()
	path := filepath.Join(dir, string(evidenceDB.ID)+".db")
	// In WAL mode an exclusive-locking connection holds the file for as
	// long as it is open once it has read, so every other open is busy.
	holder, err := sql.Open("sqlite", fileURI(path, ""))
	if err != nil {
		t.Fatal(err)
	}
	holder.SetMaxOpenConns(1)
	ctx := context.Background()
	for _, q := range []string{"PRAGMA locking_mode=EXCLUSIVE", "BEGIN IMMEDIATE", "SELECT count(*) FROM meta", "COMMIT"} {
		if _, err := holder.ExecContext(ctx, q); err != nil {
			holder.Close()
			t.Fatalf("%s: %v", q, err)
		}
	}
	env, err := NewEnv(Options{Dir: dir, Node: testNode, Database: evidenceDB})
	if err != nil {
		holder.Close()
		t.Fatal(err)
	}
	_, err = env.Open(ctx)
	holder.Close()
	if !errors.Is(err, &c5.Error{Code: c5.CodeOpenBusy}) {
		t.Fatalf("open beside an exclusive holder: %v, want %s", err, c5.CodeOpenBusy)
	}
	st, err := env.Open(ctx)
	if err != nil {
		t.Fatalf("open once the holder let go: %v", err)
	}
	st.Close()

	bad := storeDir(t)
	if err := os.WriteFile(filepath.Join(bad, string(evidenceDB.ID)+".db"), bytes.Repeat([]byte("not a database "), 512), 0o600); err != nil {
		t.Fatal(err)
	}
	benv, err := NewEnv(Options{Dir: bad, Node: testNode, Database: evidenceDB})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := benv.Open(ctx); err == nil || errors.Is(err, &c5.Error{Code: c5.CodeOpenBusy}) {
		t.Fatalf("open of a file that is not a database: %v", err)
	}
}

func TestBusyReadsTheCodeNotTheText(t *testing.T) {
	if busy(errors.New("database is locked (5) (SQLITE_BUSY)")) {
		t.Fatal("busy matched an error's text")
	}
	if busy(nil) {
		t.Fatal("busy(nil)")
	}
}
