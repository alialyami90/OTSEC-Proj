package security

import (
	"sync"
	"syscall"
	"testing"
)

// makeUnreadable holds dir open with no sharing, so that every other open
// of it fails, and returns the function that closes the handle. It changes
// no ACL, so it needs no elevation and leaves nothing behind. The failure
// is a sharing violation, not the "Access is denied" of a directory another
// account owns; the walker treats the two alike, as a directory it cannot
// read.
func makeUnreadable(t *testing.T, dir string) (reopen func()) {
	t.Helper()
	p, err := syscall.UTF16PtrFromString(dir)
	if err != nil {
		t.Fatal(err)
	}
	h, err := syscall.CreateFile(p, syscall.GENERIC_READ, 0, nil, syscall.OPEN_EXISTING, syscall.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		t.Fatalf("open %s with no sharing: %v", dir, err)
	}
	var once sync.Once
	reopen = func() { once.Do(func() { syscall.CloseHandle(h) }) }
	t.Cleanup(reopen)
	return reopen
}
