//go:build windows

package collector

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// openShared opens path for reading with the given share mode, as another
// process (a scanner, an indexer, the node) would.
func openShared(t *testing.T, path string, share uint32) windows.Handle {
	t.Helper()
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ, share, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func writeOld(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "f.json")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func checkBytes(t *testing.T, path, want string) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, []byte(want)) {
		t.Fatalf("%s holds %q, %v; want %q", filepath.Base(path), got, err, want)
	}
}

// A reader that shares delete does not stop the replace: POSIX semantics
// unlink the old file while the reader holds it, and nothing falls back.
func TestReplaceWhileReaderSharesDelete(t *testing.T) {
	path := writeOld(t)
	h := openShared(t, path, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE)
	defer windows.CloseHandle(h)
	before := renameFallbacks.Load()
	if err := ReplaceFile(path, []byte("new"), 0o600); err != nil {
		t.Fatalf("replace under a share-delete reader: %v", err)
	}
	checkBytes(t, path, "new")
	if n := renameFallbacks.Load() - before; n != 0 {
		t.Fatalf("%d fallbacks to MoveFileEx, want 0", n)
	}
}

// A reader that does not share delete holds the replace off. It is retried
// for the budget, then fails with the sharing or access error, without the
// MoveFileEx fallback; the old bytes stay and the temporary file is left.
func TestReplaceHeldWithoutShareDeleteFails(t *testing.T) {
	path := writeOld(t)
	h := openShared(t, path, windows.FILE_SHARE_READ)
	defer windows.CloseHandle(h)
	before := renameFallbacks.Load()
	start := time.Now()
	err := ReplaceFile(path, []byte("new"), 0o600)
	took := time.Since(start)
	if !heldOpen(err) {
		t.Fatalf("replace under a held reader: %v, want a sharing or access error", err)
	}
	if took < renameBudget {
		t.Fatalf("gave up after %s, inside the %s budget", took, renameBudget)
	}
	if n := renameFallbacks.Load() - before; n != 0 {
		t.Fatalf("%d fallbacks to MoveFileEx, want 0", n)
	}
	checkBytes(t, path, "old")
	checkBytes(t, path+".tmp", "new")
}

// A reader that lets go within the budget only delays the replace.
func TestReplaceHeldThenReleased(t *testing.T) {
	path := writeOld(t)
	h := openShared(t, path, windows.FILE_SHARE_READ)
	done := make(chan struct{})
	go func() {
		defer close(done)
		time.Sleep(renameBudget / 4)
		windows.CloseHandle(h)
	}()
	err := ReplaceFile(path, []byte("new"), 0o600)
	<-done
	if err != nil {
		t.Fatalf("replace after the reader let go: %v", err)
	}
	checkBytes(t, path, "new")
}

// A volume that refuses FileRenameInfoEx as unsupported takes MoveFileEx,
// and the fallback is counted.
func TestReplaceFallsBackWhenUnsupported(t *testing.T) {
	saved := setRenameInfo
	setRenameInfo = func(windows.Handle, uint32, *byte, uint32) error { return windows.ERROR_NOT_SUPPORTED }
	defer func() { setRenameInfo = saved }()
	path := writeOld(t)
	before := renameFallbacks.Load()
	if err := ReplaceFile(path, []byte("new"), 0o600); err != nil {
		t.Fatalf("replace with the fallback: %v", err)
	}
	checkBytes(t, path, "new")
	if n := renameFallbacks.Load() - before; n != 1 {
		t.Fatalf("%d fallbacks to MoveFileEx, want 1", n)
	}
}

// Any other error from the rename call is returned as it is: a
// share-delete reader does not need a fallback, and a refusal for another
// reason must not be routed around.
func TestReplaceOtherErrorNoFallback(t *testing.T) {
	saved := setRenameInfo
	setRenameInfo = func(windows.Handle, uint32, *byte, uint32) error { return windows.ERROR_DISK_FULL }
	defer func() { setRenameInfo = saved }()
	path := writeOld(t)
	before := renameFallbacks.Load()
	if err := ReplaceFile(path, []byte("new"), 0o600); !errors.Is(err, windows.ERROR_DISK_FULL) {
		t.Fatalf("replace: %v, want ERROR_DISK_FULL", err)
	}
	if n := renameFallbacks.Load() - before; n != 0 {
		t.Fatalf("%d fallbacks to MoveFileEx, want 0", n)
	}
	checkBytes(t, path, "old")
}
