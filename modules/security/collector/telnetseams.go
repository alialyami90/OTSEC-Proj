package collector

import (
	"fmt"
	"net"

	"otsec.local/otsec/contracts/adapter"
)

// The collector's two seams for C2 0.10's session.telnet (D4-102 item 5 (a);
// docs/phase4/D2-c2-0.10-proposal.md §1.3, §1.4 and §3.3). SEL751Runner.Run
// sets sel751.Config.HalfClose and Rexmit to these functions, and to nothing
// a RunPlan or a request carries. The adapter gives each the connection the
// plan's Dial returned, which endpointDialer limits to the run's endpoint.
// Neither sends a payload octet, and neither sets a socket option: there is
// no abortive close and no SO_LINGER 0 (§3.3, D3's and D6's B1).

// halfClose shuts the write side of a TCP connection: a FIN, and no data
// octet. The read side stays open, so the relay's late octets are read and
// acknowledged rather than answered with an RST. Any other connection type
// is left as it is, with an error, and the adapter then closes as before
// 0.10.
func halfClose(c net.Conn) error {
	tc, ok := c.(*net.TCPConn)
	if !ok {
		return fmt.Errorf("collector: half-close: %T is not a TCP connection", c)
	}
	return tc.CloseWrite()
}

// rexmit reads, and only reads, the payload octets the connection's socket
// retransmitted to the device, or the rexmit_unknown token for why it could
// not (adapter.RexmitUnknowns). A connection that is not a TCP socket has no
// count to ask for: unsupported.
func rexmit(c net.Conn) (int64, string) {
	tc, ok := c.(*net.TCPConn)
	if !ok {
		return 0, adapter.RexmitUnsupported
	}
	rc, err := tc.SyscallConn()
	if err != nil {
		return 0, adapter.RexmitCallFailed
	}
	var s sockCounts
	var serr error
	if err := rc.Control(func(fd uintptr) { s, serr = readTCPInfo(fd) }); err != nil || serr != nil {
		return 0, adapter.RexmitCallFailed
	}
	return s.judge()
}

// sockCounts is one read of the socket's TCP statistics (readTCPInfo).
type sockCounts struct {
	// supported is false when the platform's answer lacks a field below.
	supported bool
	// unacked is sent and unacknowledged: Linux tcpi_unacked (segments, an
	// unacknowledged FIN included), Windows BytesInFlight (octets).
	unacked uint64
	// unsent is written and not yet sent: Linux tcpi_notsent_bytes. Windows
	// has no such field, so it is 0 there (§1.4).
	unsent uint64
	// retrans is Linux tcpi_bytes_retrans, Windows BytesRetrans.
	retrans uint64
}

// judge applies §3.3's read rule: the count is valid only when nothing
// written to the socket is unacknowledged, sent or unsent.
func (s sockCounts) judge() (int64, string) {
	switch {
	case !s.supported:
		return 0, adapter.RexmitUnsupported
	case s.unacked != 0 || s.unsent != 0:
		return 0, adapter.RexmitInFlight
	}
	return int64(s.retrans), ""
}
