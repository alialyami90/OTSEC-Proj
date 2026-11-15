package collector

import (
	"errors"
	"io"
	"log/slog"
	"net"
	"testing"
)

// TestServeAfterCloseClosesListener: when Close runs before Serve, Serve
// returns ErrServerClosed and closes the listener it was given, so the next
// start can bind the same endpoint (P4-COL-1, D4-104 item 3). The listener is
// TCP on loopback, the address the kernel picked.
func TestServeAfterCloseClosesListener(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	addr := ln.Addr().String()

	s := &Server{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := s.Serve(ln); !errors.Is(err, ErrServerClosed) {
		t.Fatalf("Serve after Close = %v, want ErrServerClosed", err)
	}

	again, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("listener %s still bound after Serve returned ErrServerClosed: %v", addr, err)
	}
	again.Close()
}
