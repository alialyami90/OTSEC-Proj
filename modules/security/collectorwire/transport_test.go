//go:build linux || windows

package collectorwire

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// These tests run the real transport, with both ends as the test's own
// user: on Linux a Unix socket with SO_PEERCRED, on Windows a named pipe
// with the token checks. "Another identity" is one the test process does
// not hold.

func listenSelf(t *testing.T, peer string) (net.Listener, Endpoint) {
	t.Helper()
	ep := Endpoint{Address: testAddress(t), Peer: peer}
	ln, err := Listen(ep)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	return ln, ep
}

func self(t *testing.T) string {
	t.Helper()
	id, err := CurrentIdentity()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestTransportRoundTrip(t *testing.T) {
	ln, ep := listenSelf(t, self(t))
	done := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		defer c.Close()
		b, err := ReadFrame(c, 64)
		if err == nil {
			err = WriteFrame(c, append([]byte("echo:"), b...), 64)
		}
		io.Copy(io.Discard, c)
		done <- err
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := Dial(ctx, Endpoint{Address: ep.Address, Peer: self(t)})
	if err != nil {
		t.Fatal(err)
	}
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if err := WriteFrame(c, []byte("ping"), 64); err != nil {
		t.Fatal(err)
	}
	got, err := ReadFrame(c, 64)
	if err != nil || string(got) != "echo:ping" {
		t.Fatalf("got %q, %v", got, err)
	}
	c.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// The collector refuses a client that is not the configured peer before
// reading a byte, and keeps serving.
func TestTransportRefusesOtherClient(t *testing.T) {
	ln, ep := listenSelf(t, otherIdentity(t))
	accepted := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if c != nil {
			c.Close()
		}
		accepted <- err
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := Dial(ctx, Endpoint{Address: ep.Address, Peer: self(t)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := <-accepted; !errors.Is(err, ErrPeerRefused) {
		t.Fatalf("Accept: %v, want ErrPeerRefused", err)
	}
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("refused client could read")
	}
}

// The node refuses a server that is not the configured collector, and
// sends nothing.
func TestTransportRefusesOtherServer(t *testing.T) {
	ln, ep := listenSelf(t, self(t))
	got := make(chan int, 1)
	go func() {
		c, err := ln.Accept()
		if errors.Is(err, net.ErrClosed) {
			// The client refused and left before Accept took the
			// connection, and the listener was then closed: nothing was
			// received.
			got <- 0
			return
		}
		if err != nil {
			t.Errorf("Accept: %v", err)
			got <- -1
			return
		}
		defer c.Close()
		c.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, _ := io.Copy(io.Discard, c)
		got <- int(n)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := Dial(ctx, Endpoint{Address: ep.Address, Peer: otherIdentity(t)})
	if !errors.Is(err, ErrPeerRefused) {
		if c != nil {
			c.Close()
		}
		t.Fatalf("Dial: %v, want ErrPeerRefused", err)
	}
	// Under load the client can finish before the server reaches Accept,
	// which then waits for the next client; closing the listener ends it.
	ln.Close()
	if n := <-got; n != 0 {
		t.Fatalf("server received %d bytes from a client that refused it", n)
	}
}

func TestTransportNeedsPeer(t *testing.T) {
	if _, err := Listen(Endpoint{Address: testAddress(t)}); err == nil {
		t.Fatal("Listen accepted an endpoint with no peer")
	}
	if _, err := Dial(context.Background(), Endpoint{Address: testAddress(t)}); err == nil {
		t.Fatal("Dial accepted an endpoint with no peer")
	}
	if _, err := Listen(Endpoint{Address: testAddress(t), Peer: "not an identity"}); err == nil {
		t.Fatal("Listen accepted a malformed peer")
	}
}

// Two collectors never serve one address.
func TestTransportSecondListenerRefused(t *testing.T) {
	_, ep := listenSelf(t, self(t))
	if ln, err := Listen(ep); err == nil {
		ln.Close()
		t.Fatal("a second listener took the address")
	}
}

func TestTransportCloseUnblocksAccept(t *testing.T) {
	ln, _ := listenSelf(t, self(t))
	done := make(chan error, 1)
	go func() {
		_, err := ln.Accept()
		done <- err
	}()
	time.Sleep(50 * time.Millisecond)
	ln.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Accept returned a connection after Close")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Accept still blocked after Close")
	}
}
