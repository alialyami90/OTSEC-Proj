//go:build windows

package collectorwire

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"testing"
	"time"

	"golang.org/x/sys/windows"
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

// A client that opens the waiting instance and closes it before Accept is
// called makes ConnectNamedPipe fail with ERROR_NO_DATA. Accept must treat
// that as no connection and serve the next client; it once returned the
// error, which stopped the collector's Serve loop (A6's flake in
// TestTransportRefusesOtherServer under load).
func TestAcceptAfterClientWentAway(t *testing.T) {
	ln, ep := listenSelf(t, self(t))
	name, err := windows.UTF16PtrFromString(ep.Address)
	if err != nil {
		t.Fatal(err)
	}
	h, err := windows.CreateFile(name, clientAccess, 0, nil, windows.OPEN_EXISTING,
		windows.SECURITY_SQOS_PRESENT|windows.SECURITY_IDENTIFICATION, 0)
	if err != nil {
		t.Fatalf("open the waiting instance: %v", err)
	}
	windows.CloseHandle(h)

	type accepted struct {
		b   []byte
		err error
	}
	done := make(chan accepted, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			done <- accepted{err: err}
			return
		}
		defer c.Close()
		c.SetReadDeadline(time.Now().Add(5 * time.Second))
		b := make([]byte, 2)
		_, err = io.ReadFull(c, b)
		done <- accepted{b, err}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := Dial(ctx, ep)
	if err != nil {
		t.Fatalf("Dial after a client went away: %v", err)
	}
	defer c.Close()
	if _, err := c.Write([]byte("ok")); err != nil {
		t.Fatal(err)
	}
	if a := <-done; a.err != nil || string(a.b) != "ok" {
		t.Fatalf("Accept after a client went away: %q %v", a.b, a.err)
	}
}
