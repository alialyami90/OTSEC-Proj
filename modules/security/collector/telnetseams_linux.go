//go:build linux

package collector

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// readTCPInfo is getsockopt(TCP_INFO), which reads and sets nothing. It is
// called raw, not through unix.GetsockoptTCPInfo, because that drops the
// length the kernel wrote: a kernel before 4.19 writes a shorter struct with
// no tcpi_bytes_retrans, and reading its zero would be a count, not
// unsupported. tcpi_notsent_bytes (4.6) comes before it in the struct.
// syscall.Syscall6 keeps the pointers alive through the call
// (tests/security TestUintptrConversionsInCallArgs).
func readTCPInfo(fd uintptr) (sockCounts, error) {
	var ti unix.TCPInfo
	n := uint32(unix.SizeofTCPInfo)
	if _, _, e := syscall.Syscall6(unix.SYS_GETSOCKOPT, fd, unix.IPPROTO_TCP, unix.TCP_INFO,
		uintptr(unsafe.Pointer(&ti)), uintptr(unsafe.Pointer(&n)), 0); e != 0 {
		return sockCounts{}, e
	}
	return sockCounts{
		supported: uintptr(n) >= unsafe.Offsetof(ti.Bytes_retrans)+unsafe.Sizeof(ti.Bytes_retrans),
		unacked:   uint64(ti.Unacked),
		unsent:    uint64(ti.Notsent_bytes),
		retrans:   ti.Bytes_retrans,
	}, nil
}
