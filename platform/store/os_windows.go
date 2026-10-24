//go:build windows

package store

import (
	"fmt"
	"os"
	"sync"

	"golang.org/x/sys/windows"
)

// lockFile opens path with share mode 0, so no other handle to it can be
// opened while the node runs. It is one of the two layers of "nothing else
// opens the store"; the protected DACL on the directory is the other (A3
// C5 review, section 4).
func lockFile(path string) (func(), error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil,
		windows.OPEN_ALWAYS, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		if err == windows.ERROR_SHARING_VIOLATION {
			return nil, fmt.Errorf("store is locked by another process: %w", err)
		}
		return nil, fmt.Errorf("lock %s: %w", path, err)
	}
	var once sync.Once
	return func() { once.Do(func() { windows.CloseHandle(h) }) }, nil
}

// checkDir checks that dir is a directory. Its DACL is the installer's
// (platform/winsvc, W-4) and is checked there.
func checkDir(dir string) error {
	st, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("store directory: %w", err)
	}
	if !st.IsDir() {
		return fmt.Errorf("store directory %s is not a directory", dir)
	}
	return nil
}

func freeBytes(dir string) (int64, error) {
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return 0, err
	}
	var avail, total, totalFree uint64
	if err := windows.GetDiskFreeSpaceEx(p, &avail, &total, &totalFree); err != nil {
		return 0, fmt.Errorf("free space of %s: %w", dir, err)
	}
	return int64(avail), nil
}

// syncDir is a no-op on Windows: NTFS metadata is journaled, and a
// directory handle cannot be flushed with FlushFileBuffers.
func syncDir(dir string) error { return nil }
