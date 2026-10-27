package collector

import (
	"os"
	"path/filepath"
)

// ReplaceFile writes b to path+".tmp", flushes it, renames it over path
// and flushes the rename, so that after a crash path holds either the old
// or the new bytes, never a mix. The temporary file is created with perm.
// On Windows the rename keeps POSIX semantics where the volume supports
// them and retries briefly while another process holds path open
// (renameDurable); a rename that still fails returns the error, wrapped,
// and leaves the temporary file for the caller.
//
// The collector's state and credential store use it, and so does the
// published install key (cmd/otsec-collector).
func ReplaceFile(path string, b []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	replaceStep(stepWritten)
	if err := renameDurable(tmp, path); err != nil {
		return err
	}
	replaceStep(stepRenamed)
	if err := syncDir(filepath.Dir(path)); err != nil {
		return err
	}
	replaceStep(stepFlushed)
	return nil
}

// replaceFile is ReplaceFile for the collector's own files, which only its
// account reads.
func replaceFile(path string, b []byte) error { return ReplaceFile(path, b, 0o600) }

// The points in ReplaceFile a crash test stops the process at.
const (
	stepWritten = "written" // the temporary file is flushed; path is untouched
	stepRenamed = "renamed" // the rename returned
	stepFlushed = "flushed" // the directory is flushed too
)

// replaceHook, when set by a test, runs at each step of ReplaceFile.
var replaceHook func(step string)

func replaceStep(step string) {
	if replaceHook != nil {
		replaceHook(step)
	}
}
