//go:build windows

package collector

import (
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The FILE_RENAME_INFO flags (WinBase.h). golang.org/x/sys has the
// FileRenameInfoEx class but neither the structure nor its flags.
const (
	fileRenameReplaceIfExists = 0x1
	fileRenamePOSIXSemantics  = 0x2
)

// fileRenameInfo is FILE_RENAME_INFO. FileName is a flexible array: the
// structure is allocated with room for the whole name.
type fileRenameInfo struct {
	Flags          uint32
	RootDirectory  windows.Handle
	FileNameLength uint32 // bytes, without the terminating NUL
	FileName       [1]uint16
}

// renameBudget bounds how long a rename retries while another process
// holds the target or the temporary file open without FILE_SHARE_DELETE (an
// antivirus scanner, an indexer, a backup agent, or the node reading the
// published install key). After it the rename fails, and the caller fails
// closed: the state or store breaks, or the collector does not start.
const (
	renameBudget = 500 * time.Millisecond
	renameWait   = 25 * time.Millisecond
)

var (
	// setRenameInfo is the rename call; a test replaces it to stand in for
	// a volume that refuses POSIX semantics.
	setRenameInfo = windows.SetFileInformationByHandle
	// renameFallbacks counts rename attempts that took MoveFileEx (a held
	// target retried counts each attempt), and fallbackLogged makes the
	// first one log.
	renameFallbacks atomic.Int64
	fallbackLogged  atomic.Bool
	// renameRetryHook, when set by a test, runs before each retry of a
	// rename another process holds off.
	renameRetryHook func()
)

// renameDurable replaces to with from and returns once the rename is on
// disk. It renames with FileRenameInfoEx and POSIX semantics, so the
// replace succeeds even while a reader holds to open with
// FILE_SHARE_DELETE, and flushes the renamed file. Where the volume refuses
// that call as unsupported (FAT and exFAT, some network shares and filter
// drivers), it falls back to MoveFileEx with MOVEFILE_WRITE_THROUGH, and
// logs that once per process; it never falls back by Windows version, and
// never on a sharing or access error. Those are retried for up to
// renameBudget and then returned. A rename that needed a retry logs one
// line when it ends, whether it then succeeded or not, so a reader that
// holds the file off on every write shows before the budget runs out.
func renameDurable(from, to string) error {
	start := time.Now()
	deadline := start.Add(renameBudget)
	var held error
	for tries := 1; ; tries++ {
		err := renameOnce(from, to)
		var flushed errFlushAfterRename
		if err == nil || !heldOpen(err) || errors.As(err, &flushed) || !time.Now().Before(deadline) {
			if held != nil {
				logRetryEpisode(to, held, err, tries, time.Since(start))
			}
			if err != nil {
				return fmt.Errorf("rename %s over %s: %w", filepath.Base(from), to, err)
			}
			return nil
		}
		held = err
		if renameRetryHook != nil {
			renameRetryHook()
		}
		time.Sleep(renameWait)
	}
}

// retryEpisodeMsg is the one line a held-off rename logs.
const retryEpisodeMsg = "collector: a rename was held off by another process"

// logRetryEpisode logs a rename that another process held off: the error
// that held it, how it ended, the attempts, and the time taken.
func logRetryEpisode(path string, held, final error, tries int, took time.Duration) {
	args := []any{"path", path, "held_by", held.Error(), "attempts", tries,
		"elapsed_ms", took.Milliseconds(), "succeeded", final == nil}
	if final != nil {
		args = append(args, "error", final.Error())
	}
	slog.Warn(retryEpisodeMsg, args...)
}

func renameOnce(from, to string) error {
	err := renamePOSIX(from, to)
	var unsupported errRenameUnsupported
	if !errors.As(err, &unsupported) {
		return err
	}
	renameFallbacks.Add(1)
	if fallbackLogged.CompareAndSwap(false, true) {
		slog.Warn("collector: this volume refuses POSIX-semantics rename; replacing files with MoveFileEx, which fails while any reader holds the file",
			"path", to, "error", unsupported.err)
	}
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

// errRenameUnsupported is a FileRenameInfoEx call the volume refused as
// unsupported: the only error that takes the MoveFileEx fallback.
type errRenameUnsupported struct{ err error }

func (e errRenameUnsupported) Error() string { return "POSIX rename unsupported: " + e.err.Error() }
func (e errRenameUnsupported) Unwrap() error { return e.err }

// errFlushAfterRename is a flush that failed after the rename took effect:
// to already holds the new bytes and from is gone, so it is returned as it
// is, never retried (a retry would report from as missing).
type errFlushAfterRename struct{ err error }

func (e errFlushAfterRename) Error() string { return "renamed, but not flushed: " + e.err.Error() }
func (e errFlushAfterRename) Unwrap() error { return e.err }

func renamePOSIX(from, to string) error {
	abs, err := filepath.Abs(to)
	if err != nil {
		return err
	}
	name, err := windows.UTF16FromString(abs) // with the terminating NUL
	if err != nil {
		return err
	}
	src, err := windows.UTF16PtrFromString(from)
	if err != nil {
		return err
	}
	// DELETE to rename it, GENERIC_WRITE to flush it.
	h, err := windows.CreateFile(src, windows.DELETE|windows.GENERIC_WRITE|windows.SYNCHRONIZE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)

	var info fileRenameInfo
	size := int(unsafe.Offsetof(info.FileName)) + 2*len(name)
	buf := make([]uint64, (size+7)/8) // 8-byte aligned for the handle field
	ri := (*fileRenameInfo)(unsafe.Pointer(&buf[0]))
	ri.Flags = fileRenameReplaceIfExists | fileRenamePOSIXSemantics
	ri.FileNameLength = uint32(2 * (len(name) - 1))
	copy(unsafe.Slice(&ri.FileName[0], len(name)), name)
	if err := setRenameInfo(h, windows.FileRenameInfoEx, (*byte)(unsafe.Pointer(&buf[0])), uint32(size)); err != nil {
		if unsupportedCall(err) {
			return errRenameUnsupported{err}
		}
		return err
	}
	// The handle now names to: flush its data and metadata.
	if err := windows.FlushFileBuffers(h); err != nil {
		return errFlushAfterRename{err}
	}
	return nil
}

// unsupportedCall reports the errors a volume or filter gives for a call
// it does not implement.
func unsupportedCall(err error) bool {
	return errors.Is(err, windows.ERROR_INVALID_PARAMETER) || errors.Is(err, windows.ERROR_NOT_SUPPORTED) ||
		errors.Is(err, windows.ERROR_INVALID_FUNCTION)
}

// heldOpen reports the errors another process's open handle causes.
func heldOpen(err error) bool {
	return errors.Is(err, windows.ERROR_SHARING_VIOLATION) || errors.Is(err, windows.ERROR_ACCESS_DENIED)
}

// syncDir flushes the directory where NTFS allows it (a handle opened with
// FILE_FLAG_BACKUP_SEMANTICS). It is best effort: the rename was already
// flushed through the renamed file's handle, and a volume or account that
// cannot open or flush a directory handle is not an error.
func syncDir(dir string) error {
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return err
	}
	h, err := windows.CreateFile(p, windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		if unsupportedCall(err) || errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			return nil
		}
		return err
	}
	defer windows.CloseHandle(h)
	if err := windows.FlushFileBuffers(h); err != nil && !unsupportedCall(err) && !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		return err
	}
	return nil
}
