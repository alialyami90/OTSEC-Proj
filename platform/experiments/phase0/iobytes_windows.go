//go:build windows

package main

import (
	"syscall"
	"unsafe"
)

var getProcessIoCounters = syscall.NewLazyDLL("kernel32.dll").NewProc("GetProcessIoCounters")

type ioCounters struct {
	ReadOperationCount, WriteOperationCount, OtherOperationCount uint64
	ReadTransferCount, WriteTransferCount, OtherTransferCount    uint64
}

// bytesWritten returns the bytes this process has written
// (GetProcessIoCounters WriteTransferCount), or -1 on failure.
func bytesWritten() int64 {
	h, err := syscall.GetCurrentProcess()
	if err != nil {
		return -1
	}
	var c ioCounters
	r, _, _ := getProcessIoCounters.Call(uintptr(h), uintptr(unsafe.Pointer(&c)))
	if r == 0 {
		return -1
	}
	return int64(c.WriteTransferCount)
}
