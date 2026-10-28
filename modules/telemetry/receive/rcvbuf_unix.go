//go:build unix

package receive

import (
	"net"
	"syscall"
)

// readBuffer reads back SO_RCVBUF, the receive buffer the OS granted.
func readBuffer(c *net.UDPConn) (int, error) {
	rc, err := c.SyscallConn()
	if err != nil {
		return 0, err
	}
	var n int
	var serr error
	if err := rc.Control(func(fd uintptr) {
		n, serr = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF)
	}); err != nil {
		return 0, err
	}
	return n, serr
}
