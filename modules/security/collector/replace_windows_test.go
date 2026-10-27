//go:build windows

package collector

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
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

// episodes captures the default logger for the test and returns the retry
// episodes logged for path so far, one map per line.
func episodes(t *testing.T, path string) func() []map[string]any {
	t.Helper()
	var buf bytes.Buffer
	saved := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(saved) })
	return func() []map[string]any {
		var got []map[string]any
		for _, line := range bytes.Split(bytes.TrimSpace(buf.Bytes()), []byte("\n")) {
			var m map[string]any
			if len(line) == 0 || json.Unmarshal(line, &m) != nil {
				continue
			}
			if m["msg"] == retryEpisodeMsg && m["path"] == path {
				got = append(got, m)
			}
		}
		return got
	}
}

// checkEpisode asserts exactly one retry episode, with the outcome given.
func checkEpisode(t *testing.T, got []map[string]any, succeeded bool) {
	t.Helper()
	if len(got) != 1 {
		t.Fatalf("%d retry episodes logged, want 1: %v", len(got), got)
	}
	e := got[0]
	if e["succeeded"] != succeeded || e["held_by"] == "" || e["attempts"].(float64) < 2 {
		t.Fatalf("retry episode %v, want succeeded %v, held_by set, attempts at least 2", e, succeeded)
	}
	if _, ok := e["error"]; ok == succeeded {
		t.Fatalf("retry episode %v: error present %v, want %v", e, ok, !succeeded)
	}
}

// A reader that shares delete does not stop the replace: POSIX semantics
// unlink the old file while the reader holds it, and nothing falls back.
func TestReplaceWhileReaderSharesDelete(t *testing.T) {
	path := writeOld(t)
	h := openShared(t, path, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE)
	defer windows.CloseHandle(h)
	logged := episodes(t, path)
	before := renameFallbacks.Load()
	if err := ReplaceFile(path, []byte("new"), 0o600); err != nil {
		t.Fatalf("replace under a share-delete reader: %v", err)
	}
	checkBytes(t, path, "new")
	if got := logged(); len(got) != 0 {
		t.Fatalf("retry episodes logged with nothing holding the replace off: %v", got)
	}
	if n := renameFallbacks.Load() - before; n != 0 {
		t.Fatalf("%d fallbacks to MoveFileEx, want 0", n)
	}
}

// A reader that does not share delete holds the replace off. It is retried
// for the budget, then fails with the sharing or access error, without the
// MoveFileEx fallback; the old bytes stay and the temporary file is left.
// The episode logs one line, as failed.
func TestReplaceHeldWithoutShareDeleteFails(t *testing.T) {
	path := writeOld(t)
	h := openShared(t, path, windows.FILE_SHARE_READ)
	defer windows.CloseHandle(h)
	logged := episodes(t, path)
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
	checkEpisode(t, logged(), false)
}

// A reader that lets go within the budget only delays the replace. The
// reader closes when the first retry starts, not after a wall-clock sleep,
// so the test holds however the runner schedules it (B6 on #257). The
// episode logs exactly one line, as succeeded.
func TestReplaceHeldThenReleased(t *testing.T) {
	path := writeOld(t)
	h := openShared(t, path, windows.FILE_SHARE_READ)
	logged := episodes(t, path)
	retries := 0
	renameRetryHook = func() {
		if retries++; retries == 1 {
			windows.CloseHandle(h)
		}
	}
	defer func() { renameRetryHook = nil }()
	if err := ReplaceFile(path, []byte("new"), 0o600); err != nil {
		t.Fatalf("replace after the reader let go: %v", err)
	}
	if retries == 0 {
		windows.CloseHandle(h)
		t.Fatal("the held reader did not hold the replace off: no retry")
	}
	checkBytes(t, path, "new")
	checkEpisode(t, logged(), true)
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
