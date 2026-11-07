//go:build !windows

package store

import (
	"os"
	"syscall"
	"testing"
)

// allocatedBytes is the space the file system has allocated to path: its
// blocks, in 512-byte units, never its length, which a sparse file passes.
func allocatedBytes(t *testing.T, path string) int64 {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Sys().(*syscall.Stat_t).Blocks * 512
}

// makeSparse makes path n bytes long with no blocks written: a truncate,
// which on Linux file systems leaves a hole.
func makeSparse(t *testing.T, path string, n int64) {
	t.Helper()
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(path, n); err != nil {
		t.Fatal(err)
	}
}

// unsupported is the error Linux's fallocate returns on a file system
// without it.
var unsupported error = syscall.EOPNOTSUPP
