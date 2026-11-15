package collector

import (
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	"otsec.local/otsec/modules/security/collectorwire"
)

// closeSignalConn reports when the server closes its end.
type closeSignalConn struct {
	net.Conn
	once   sync.Once
	closed chan struct{}
}

func (c *closeSignalConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

// lateListener hands over one connection only once Close has begun: Accept
// blocks until release is closed. With handInClose, its own Close releases
// the connection and waits, bounded, for the server to close it, so the
// connection is accepted while Server.Close runs. Without it, the test
// releases the connection after Server.Close has returned.
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
// on it is decided: neither Handle nor Refuse is called (P4-COL-2, D4-107
// item 5.1). In "during", the connection is accepted while Close runs, and
// Close returns only after the server has closed it. In "after", it is
// accepted once Close has returned, the order D6's N1 names; the server
// closes it unserved and Serve returns ErrServerClosed.
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

			ln := &lateListener{
				conn:        &closeSignalConn{Conn: server, closed: make(chan struct{})},
				handInClose: tc.handInClose,
				release:     make(chan struct{}),
				closing:     make(chan struct{}),
			}
			h := &fakeHandler{}
			s := &Server{Handler: h, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
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
					t.Fatal("Close returned before the connection accepted during it was closed")
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
