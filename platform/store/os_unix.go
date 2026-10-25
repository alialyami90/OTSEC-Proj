//go:build !windows

package store

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sync"
	"syscall"
)

// lockFile takes an exclusive flock on path. flock is advisory, so it stops
// only cooperating processes; the directory mode is the real barrier on
// Linux (A3 C5 review, section 4).
func lockFile(path string) (func(), error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open lock file: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, fmt.Errorf("store is locked by another process: %w", err)
		}
		return nil, fmt.Errorf("lock %s: %w", path, err)
	}
	var once sync.Once
	return func() { once.Do(func() { f.Close() }) }, nil
}

// checkDir refuses a store directory that group or others can use, and a
// symbolic link, so the checked mode is the one on the directory the files
// are written to (A3 #84 note 4).
func checkDir(dir string) error {
	st, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("store directory: %w", err)
	}
	if st.Mode()&fs.ModeSymlink != 0 {
		return fmt.Errorf("store directory %s is a symbolic link; it must be the directory itself", dir)
	}
	if !st.IsDir() {
		return fmt.Errorf("store directory %s is not a directory", dir)
	}
	if perm := st.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("store directory %s has mode %04o; group and others must have no access (0700)", dir, perm)
	}
	return nil
}

// checkFile refuses a database file (the database, its -wal or its -shm)
// that is not a plain file or that group or others can use (A3 #84 note
// 3). A file that does not exist passes: SQLite creates it with the
// database file's mode.
func checkFile(path string) error {
	st, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("store file: %w", err)
	}
	if !st.Mode().IsRegular() {
		return fmt.Errorf("store file %s is not a plain file", path)
	}
	if perm := st.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("store file %s has mode %04o; group and others must have no access (0600)", path, perm)
	}
	return nil
}

func freeBytes(dir string) (int64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return 0, fmt.Errorf("free space of %s: %w", dir, err)
	}
	return int64(st.Bavail) * int64(st.Bsize), nil
}

// syncDir flushes the directory, so a created or removed file survives a
// crash.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// CreateDir creates dir as a store directory, mode 0700. account is for
// Windows; on Linux the installer runs the node as the directory's owner.
// If dir exists, CreateDir changes nothing and returns checkDir's verdict.
func CreateDir(dir, account string) error {
	if _, err := os.Lstat(dir); err == nil {
		return checkDir(dir)
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		return fmt.Errorf("create store directory %s: %w", dir, err)
	}
	// Mkdir applies the umask, which can only remove bits from 0700.
	return checkDir(dir)
}

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
	if err := mode(st.Mode().Perm()); err != nil {
		return nil, err
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); ok && sys.Nlink > 1 {
		// As on Windows (A6 on #108): a hard link would carry a file from
		// another path into the checked directory.
		return nil, fmt.Errorf("%s has %d hard links; only a file with one is read", path, sys.Nlink)
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
