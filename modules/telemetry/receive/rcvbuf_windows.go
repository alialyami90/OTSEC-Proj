//go:build windows

package receive

import (
	"net"
	"syscall"
	"unsafe"
)

// readBuffer reads back SO_RCVBUF, the receive buffer the OS granted.
func readBuffer(c *net.UDPConn) (int, error) {
	rc, err := c.SyscallConn()
	if err != nil {
		return 0, err
	}
	var n int32
	l := int32(unsafe.Sizeof(n))
	var serr error
	if err := rc.Control(func(fd uintptr) {
		serr = syscall.Getsockopt(syscall.Handle(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, (*byte)(unsafe.Pointer(&n)), &l)
	}); err != nil {
		return 0, err
	}
	return int(n), serr
}
