//go:build linux

package collectorwire

import (
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func testAddress(t *testing.T) string {
	dir, err := os.MkdirTemp("", "cw")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return filepath.Join(dir, "c.sock")
}

func otherIdentity(t *testing.T) string {
	return strconv.Itoa(os.Getuid() + 1)
}

func TestListenRefusesSharedDirectory(t *testing.T) {
	addr := testAddress(t)
	if err := os.Chmod(filepath.Dir(addr), 0o777); err != nil {
		t.Fatal(err)
	}
	if ln, err := Listen(Endpoint{Address: addr, Peer: strconv.Itoa(os.Getuid())}); err == nil {
		ln.Close()
		t.Fatal("listened in a world-writable directory")
	}
}

func TestListenReplacesStaleSocket(t *testing.T) {
	addr := testAddress(t)
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: addr, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	l.SetUnlinkOnClose(false)
	l.Close() // leaves the socket file, as a crashed collector would
	ln, err := Listen(Endpoint{Address: addr, Peer: strconv.Itoa(os.Getuid())})
	if err != nil {
		t.Fatalf("stale socket not replaced: %v", err)
	}
	ln.Close()
}

func TestListenRefusesNonSocket(t *testing.T) {
	addr := testAddress(t)
	if err := os.WriteFile(addr, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if ln, err := Listen(Endpoint{Address: addr, Peer: strconv.Itoa(os.Getuid())}); err == nil {
		ln.Close()
		t.Fatal("replaced a regular file")
	}
}
