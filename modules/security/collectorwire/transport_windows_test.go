//go:build windows

package collectorwire

import (
	"crypto/rand"
	"encoding/hex"
	"testing"
)

func testAddress(t *testing.T) string {
	b := make([]byte, 8)
	rand.Read(b)
	return `\\.\pipe\otsec-test-` + hex.EncodeToString(b)
}

// otherIdentity is LocalService, which the test process does not run as.
func otherIdentity(t *testing.T) string {
	if self(t) == "S-1-5-19" {
		t.Skip("test runs as LocalService")
	}
	return "S-1-5-19"
}

func TestListenRefusesRemotePipeName(t *testing.T) {
	if ln, err := Listen(Endpoint{Address: `\\server\pipe\x`, Peer: self(t)}); err == nil {
		ln.Close()
		t.Fatal("listened on a remote pipe name")
	}
}
