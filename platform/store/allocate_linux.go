package store

import (
	"os"

	"golang.org/x/sys/unix"
)

// allocateFile makes f n bytes long with its blocks allocated, by fallocate(2)
// in mode 0, which allocates and does not make a sparse file. A file system
// without fallocate returns an error that is errors.ErrUnsupported.
func allocateFile(f *os.File, n int64) error {
	return unix.Fallocate(int(f.Fd()), 0, 0, n)
}
