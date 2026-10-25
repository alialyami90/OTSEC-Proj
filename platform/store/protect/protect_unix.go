//go:build !windows

package protect

import (
	"fmt"
	"os"
	"syscall"
)

func readProtected(path string, max int64) ([]byte, error) {
	return readModeChecked(path, max, func(perm os.FileMode) error {
		if perm&0o277 != 0 {
			return fmt.Errorf("%s has mode %04o; it must be readable by its owner only and not writable (0400)", path, perm)
		}
		return nil
	})
}

// readProtectedFor is the Linux rule for a file other services also read:
// readers are Windows SIDs and are not used here; group read stands in for
// them. Linux is a development platform only (A3).
func readProtectedFor(path string, max int64, readers []string) ([]byte, error) {
	return readModeChecked(path, max, func(perm os.FileMode) error {
		if perm&^0o440 != 0 {
			return fmt.Errorf("%s has mode %04o; only its owner and group may read it, and nobody may write it (0440)", path, perm)
		}
		return nil
	})
}

func readPublic(path string, max int64) ([]byte, error) { return readModeChecked(path, max, nil) }

// readModeChecked opens path and applies mode to its permission bits; a
// nil mode is a public file, whose mode is not checked.
func readModeChecked(path string, max int64, mode func(os.FileMode) error) ([]byte, error) {
	// O_NOFOLLOW refuses a link; O_NONBLOCK keeps a FIFO from blocking the
	// open, and the handle check below refuses it.
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w (a link is refused)", path, err)
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if mode != nil {
		if err := mode(st.Mode().Perm()); err != nil {
			return nil, err
		}
		if sys, ok := st.Sys().(*syscall.Stat_t); ok && sys.Nlink > 1 {
			// As on Windows (A6 on #108): a hard link would carry a file
			// from another path into the checked directory.
			return nil, fmt.Errorf("%s has %d hard links; only a file with one is read", path, sys.Nlink)
		}
	}
	if st.Size() > max {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, max)
	}
	return readAtMost(f, path, max)
}

func checkProtectedDir(dir string) error {
	return checkDirMode(dir, func(perm os.FileMode) error {
		if perm&0o277 != 0 {
			return fmt.Errorf("directory %s has mode %04o; it must be usable by its owner only and not writable (0500)", dir, perm)
		}
		return nil
	})
}

// checkProtectedDirFor is checkProtectedDir with group read and traverse
// standing in for the readers, as readProtectedFor.
func checkProtectedDirFor(dir string, readers []string) error {
	return checkDirMode(dir, func(perm os.FileMode) error {
		if perm&^0o550 != 0 {
			return fmt.Errorf("directory %s has mode %04o; only its owner and group may use it, and nobody may write it (0550)", dir, perm)
		}
		return nil
	})
}

func checkDirMode(dir string, mode func(os.FileMode) error) error {
	fd, err := syscall.Open(dir, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open directory %s: %w (a link is refused)", dir, err)
	}
	f := os.NewFile(uintptr(fd), dir)
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if !st.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	return mode(st.Mode().Perm())
}
