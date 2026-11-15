//go:build linux || windows

package collector

import "testing"

// Neither seam makes the later close abortive (§3.3): after both run, the
// socket's SO_LINGER is still off, so the adapter's Close is graceful.
func TestSeamsSetNoLinger(t *testing.T) {
	near, _ := tcpPair(t)
	if err := halfClose(near); err != nil {
		t.Fatal(err)
	}
	rexmit(near)
	rc, err := near.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var on bool
	var lerr error
	if err := rc.Control(func(fd uintptr) { on, lerr = lingerOn(fd) }); err != nil || lerr != nil {
		t.Fatal(err, lerr)
	}
	if on {
		t.Fatal("SO_LINGER is on after the seams: the close would be abortive")
	}
}
