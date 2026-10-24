//go:build windows

package collector

import "golang.org/x/sys/windows"

// syncDir is a no-op on Windows: a directory handle cannot be flushed, and
// renameDurable writes the rename through instead.
func syncDir(string) error { return nil }

// renameDurable replaces to with from and returns only once the rename is
// on disk (MOVEFILE_WRITE_THROUGH), so a crash after it returns keeps the
// new file.
func renameDurable(from, to string) error {
	f, err := windows.UTF16PtrFromString(from)
	if err != nil {
		return err
	}
	t, err := windows.UTF16PtrFromString(to)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(f, t, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}
