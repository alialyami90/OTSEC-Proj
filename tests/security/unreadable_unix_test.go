//go:build !windows

package security

import (
	"os"
	"testing"
)

// makeUnreadable takes every permission off dir, and returns the function
// that gives them back. It does not stop root.
func makeUnreadable(t *testing.T, dir string) (reopen func()) {
	t.Helper()
	if err := os.Chmod(dir, 0); err != nil {
		t.Fatal(err)
	}
	reopen = func() { os.Chmod(dir, 0o700) }
	t.Cleanup(reopen)
	return reopen
}
