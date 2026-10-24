//go:build !windows

package store

import (
	"errors"
	"fmt"
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

// checkDir refuses a store directory that group or others can use.
func checkDir(dir string) error {
	st, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("store directory: %w", err)
	}
	if !st.IsDir() {
		return fmt.Errorf("store directory %s is not a directory", dir)
	}
	if perm := st.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("store directory %s has mode %04o; group and others must have no access (0700)", dir, perm)
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
