//go:build !unix && !windows

package receive

import (
	"errors"
	"net"
)

// readBuffer reports that this OS's granted receive buffer is not read.
func readBuffer(*net.UDPConn) (int, error) {
	return 0, errors.New("the granted receive buffer is not read on this OS")
}
