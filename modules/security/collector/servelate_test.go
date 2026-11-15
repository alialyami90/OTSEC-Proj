package collector

import (
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"otsec.local/otsec/modules/security/collectorwire"
)

// closeSignalConn reports when the server closes its end, and whether the
// server's lock was held at that moment.
type closeSignalConn struct {
	net.Conn
	mu         *sync.Mutex
	lockedAtCl atomic.Bool
	once       sync.Once
	closed     chan struct{}
}

func (c *closeSignalConn) Close() error {
	c.once.Do(func() {
		if c.mu.TryLock() {
			c.mu.Unlock()
		} else {
			c.lockedAtCl.Store(true)
		}
		close(c.closed)
	})
	return c.Conn.Close()
}

// lateListener hands over one connection only once Close has begun: Accept
// blocks until release is closed. With handInClose, its own Close releases
// the connection and then waits, for at most 10 s, for the server to close
// it. That wait is the test's, not the server's: Server.Close calls this
// Close synchronously, so the wait is what orders the connection's close
// before Server.Close returns. Without handInClose, the test releases the
// connection after Server.Close has returned.
type lateListener struct {
	conn        *closeSignalConn
	handInClose bool
	release     chan struct{}
	relOnce     sync.Once
	closing     chan struct{}
	closeOnce   sync.Once
	handed      bool
}

func (l *lateListener) Accept() (net.Conn, error) {
	if l.handed {
		<-l.closing
		return nil, net.ErrClosed
	}
	<-l.release
	l.handed = true
	return l.conn, nil
}

func (l *lateListener) Close() error {
	l.closeOnce.Do(func() { close(l.closing) })
	if l.handInClose {
		l.relOnce.Do(func() { close(l.release) })
		select {
		case <-l.conn.closed:
		case <-time.After(10 * time.Second):
		}
	}
	return nil
}

func (l *lateListener) Addr() net.Addr { return &net.UnixAddr{Name: "late", Net: "unix"} }

// TestConnAcceptedDuringCloseNotDecided: a connection that Accept returns
// only after Close has begun carries a well-formed request, and no request
// on it is decided: neither Handle nor Refuse is called, and Serve closes it
// unserved and returns ErrServerClosed (P4-COL-2, D4-107 item 5.1). The
// server's lock is free when it closes the connection and after Serve
// returns.
//
// In "during", the connection is accepted while Close runs. Server.Close
// does not wait for it; lateListener.Close's own bounded wait is what makes
// the connection close before Server.Close returns. In "after", it is
// accepted once Close has returned, the order D6's N1 names.
func TestConnAcceptedDuringCloseNotDecided(t *testing.T) {
	for _, tc := range []struct {
		name        string
		handInClose bool
	}{{"during", true}, {"after", false}} {
		t.Run(tc.name, func(t *testing.T) {
			client, server := net.Pipe()
			t.Cleanup(func() { client.Close(); server.Close() })
			client.SetDeadline(time.Now().Add(10 * time.Second))
			go func() { // the node's side: send a request, read a reply if one comes, close
				if _, err := client.Write(frame(runRequest)); err == nil {
					collectorwire.ReadFrame(client, collectorwire.MaxReplyBytes)
				}
				client.Close()
			}()

			h := &fakeHandler{}
			s := &Server{Handler: h, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
			ln := &lateListener{
				conn:        &closeSignalConn{Conn: server, mu: &s.mu, closed: make(chan struct{})},
				handInClose: tc.handInClose,
				release:     make(chan struct{}),
				closing:     make(chan struct{}),
			}
			served := make(chan error, 1)
			go func() { served <- s.Serve(ln) }()
			waitServing(t, s)

			closed := make(chan struct{})
			go func() { s.Close(); close(closed) }()
			select {
			case <-closed:
			case <-time.After(15 * time.Second):
				t.Fatal("Close did not return")
			}
			if tc.handInClose {
				select {
				case <-ln.conn.closed:
				default:
					t.Fatal("the server did not close the connection accepted during Close within lateListener.Close's 10 s wait")
				}
			} else {
				ln.relOnce.Do(func() { close(ln.release) })
				select {
				case <-ln.conn.closed:
				case <-time.After(10 * time.Second):
					t.Fatal("the connection accepted after Close was not closed")
				}
			}
			select {
			case err := <-served:
				if !errors.Is(err, ErrServerClosed) {
					t.Fatalf("Serve = %v, want ErrServerClosed", err)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("Serve did not return")
			}
			if handled, refused := h.counts(); handled != 0 || refused != 0 {
				t.Fatalf("a request on a connection accepted after Close began was decided: handled %d, refused %d", handled, refused)
			}
			if ln.conn.lockedAtCl.Load() {
				t.Fatal("s.mu was held when the server closed the connection")
			}
			if !s.mu.TryLock() {
				t.Fatal("s.mu is still held after Serve returned")
			}
			s.mu.Unlock()
		})
	}
}

// waitServing waits until Serve has recorded its listener, so Close finds it.
func waitServing(t *testing.T, s *Server) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		s.mu.Lock()
		ok := s.ln != nil
		s.mu.Unlock()
		if ok {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("Serve did not start")
		}
		time.Sleep(time.Millisecond)
	}
}
