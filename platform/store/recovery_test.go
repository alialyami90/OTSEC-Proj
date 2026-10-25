package store

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
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
