//go:build !windows

package collector

import "os"

// syncDir flushes a directory, so a file created or renamed in it survives
// a crash.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// renameDurable renames over an existing file; the caller flushes the
// directory.
func renameDurable(from, to string) error { return os.Rename(from, to) }
