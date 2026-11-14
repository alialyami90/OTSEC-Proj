//go:build linux

package collector

import (
	"bytes"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"otsec.local/otsec/contracts/adapter"
)

// lingerOn reads SO_LINGER's l_onoff.
func lingerOn(fd uintptr) (bool, error) {
	l, err := unix.GetsockoptLinger(int(fd), unix.SOL_SOCKET, unix.SO_LINGER)
	if err != nil {
		return false, err
	}
	return l.Onoff != 0, nil
}

// A far end that stops reading closes its window, so octets written stay
// unsent in the send buffer: tcpi_notsent_bytes is not 0, and the count is
// not valid (§3.3, Linux).
func TestRexmitUnsentIsInFlight(t *testing.T) {
	near, _ := tcpPair(t)
	_ = near.SetWriteBuffer(1 << 16)
	_ = near.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
	chunk := bytes.Repeat([]byte("x"), 1<<16)
	for range 1024 { // at most 64 MiB, far above any loopback buffer
		if _, err := near.Write(chunk); err != nil {
			break
		}
	}
	if o, u := rexmit(near); u != adapter.RexmitInFlight {
		t.Fatalf("rexmit %d %q with unsent octets, want in-flight", o, u)
	}
}
