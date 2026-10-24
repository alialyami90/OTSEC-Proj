//go:build linux

package collectorwire

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

// Listen opens the collector's Unix socket. Accept returns only connections
// whose peer uid is ep.Peer; any other connection is closed before a byte is
// read, and Accept reports it as an error wrapping ErrPeerRefused so the
// server can log it and carry on.
//
// The socket's directory must not be writable by group or others, so no
// other user can replace the socket. A socket file left by a collector that
// stopped is removed; one that still answers is refused, so two collectors
// never serve the same path.
func Listen(ep Endpoint) (net.Listener, error) {
	uid, err := parseUID(ep.Peer)
	if err != nil {
		return nil, err
	}
	dir, err := os.Stat(filepath.Dir(ep.Address))
	if err != nil {
		return nil, fmt.Errorf("collectorwire: socket directory: %w", err)
	}
	if dir.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("collectorwire: socket directory %s is writable by group or others (%v)", filepath.Dir(ep.Address), dir.Mode().Perm())
	}
	if fi, err := os.Lstat(ep.Address); err == nil {
		if fi.Mode().Type() != fs.ModeSocket {
			return nil, fmt.Errorf("collectorwire: %s exists and is not a socket", ep.Address)
		}
		if c, err := net.DialTimeout("unix", ep.Address, 200*time.Millisecond); err == nil {
			c.Close()
			return nil, fmt.Errorf("collectorwire: %s is already served", ep.Address)
		}
		if err := os.Remove(ep.Address); err != nil {
			return nil, fmt.Errorf("collectorwire: remove stale socket: %w", err)
		}
	}
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: ep.Address, Net: "unix"})
	if err != nil {
		return nil, err
	}
	// The peer check is the gate; the mode keeps others from even
	// connecting when the node runs in the collector's group.
	if err := os.Chmod(ep.Address, 0o660); err != nil {
		ln.Close()
		return nil, err
	}
	return &unixListener{UnixListener: ln, peer: uid}, nil
}

type unixListener struct {
	*net.UnixListener
	peer uint32
}

func (l *unixListener) Accept() (net.Conn, error) {
	c, err := l.UnixListener.AcceptUnix()
	if err != nil {
		return nil, err
	}
	got, err := peerUID(c)
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("%w: %v", ErrPeerRefused, err)
	}
	if got != l.peer {
		c.Close()
		return nil, fmt.Errorf("%w: client uid %d, want %d", ErrPeerRefused, got, l.peer)
	}
	return c, nil
}

// Dial connects to the collector's socket and returns the connection only if
// the server's uid is ep.Peer. Nothing is sent before the check.
func Dial(ctx context.Context, ep Endpoint) (net.Conn, error) {
	uid, err := parseUID(ep.Peer)
	if err != nil {
		return nil, err
	}
	var d net.Dialer
	c, err := d.DialContext(ctx, "unix", ep.Address)
	if err != nil {
		return nil, err
	}
	uc := c.(*net.UnixConn)
	got, err := peerUID(uc)
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("%w: %v", ErrPeerRefused, err)
	}
	if got != uid {
		c.Close()
		return nil, fmt.Errorf("%w: server uid %d, want %d", ErrPeerRefused, got, uid)
	}
	return c, nil
}

// CurrentIdentity returns this process's identity in the form Endpoint.Peer
// takes. Tests use it to run both ends as one user.
func CurrentIdentity() (string, error) {
	return strconv.Itoa(os.Getuid()), nil
}

func parseUID(s string) (uint32, error) {
	if s == "" {
		return 0, errors.New("collectorwire: endpoint has no peer identity")
	}
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("collectorwire: peer %q is not a uid", s)
	}
	return uint32(n), nil
}

// peerUID reads the uid the kernel recorded for the other end when the
// connection was made (SO_PEERCRED). The peer cannot choose it.
func peerUID(c *net.UnixConn) (uint32, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return 0, err
	}
	var cred *syscall.Ucred
	var serr error
	if err := raw.Control(func(fd uintptr) {
		cred, serr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return 0, err
	}
	if serr != nil {
		return 0, serr
	}
	return cred.Uid, nil
}
