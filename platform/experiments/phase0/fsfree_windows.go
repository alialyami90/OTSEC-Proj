//go:build windows

package main

import (
	"syscall"
	"unsafe"
)

var getDiskFreeSpaceEx = syscall.NewLazyDLL("kernel32.dll").NewProc("GetDiskFreeSpaceExW")

func fsFree(dir string) int64 {
	p, err := syscall.UTF16PtrFromString(dir)
	if err != nil {
		return -1
	}
	var availToCaller, total, totalFree uint64
	r, _, _ := getDiskFreeSpaceEx.Call(uintptr(unsafe.Pointer(p)),
		uintptr(unsafe.Pointer(&availToCaller)), uintptr(unsafe.Pointer(&total)), uintptr(unsafe.Pointer(&totalFree)))
	if r == 0 {
		return -1
	}
	return int64(availToCaller)
}
