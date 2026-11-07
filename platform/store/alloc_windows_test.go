package store

import (
	"errors"
	"os"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// fileStandardInfo is FILE_STANDARD_INFO.
type fileStandardInfo struct {
	AllocationSize int64
	EndOfFile      int64
	NumberOfLinks  uint32
	DeletePending  bool
	Directory      bool
}

// allocatedBytes is the space the file system has allocated to path, from
// FILE_STANDARD_INFO's AllocationSize, never its length, which a sparse
// file passes.
func allocatedBytes(t *testing.T, path string) int64 {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var info fileStandardInfo
	if err := windows.GetFileInformationByHandleEx(windows.Handle(f.Fd()), windows.FileStandardInfo, (*byte)(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		t.Fatal(err)
	}
	return info.AllocationSize
}

// makeSparse makes path an NTFS sparse file n bytes long: FSCTL_SET_SPARSE,
// then a truncate, which leaves the range unallocated.
func makeSparse(t *testing.T, path string, n int64) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var ret uint32
	if err := windows.DeviceIoControl(windows.Handle(f.Fd()), windows.FSCTL_SET_SPARSE, nil, 0, nil, 0, &ret, nil); err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(n); err != nil {
		t.Fatal(err)
	}
}

// unsupported is the error allocateFile returns where the OS has no single
// allocation call.
var unsupported = errors.ErrUnsupported
