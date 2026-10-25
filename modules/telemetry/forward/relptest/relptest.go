// Package relptest is the receiving half of a RELP collector for unit tests
// of the forwarder (P2-A4). It is not a product component and never runs on
// a node.
//
// It answers open with the offers commands=syslog, records each syslog
// message before it acknowledges it (the receiver side of
// ack_after "durable-write"), and answers close. A script decides what
// happens to each syslog frame, so tests can close the connection mid-batch,
// refuse, stay silent, send serverclose or answer twice. A frame that breaks
// the client grammar ends the connection with serverclose and is recorded as
// an error: the receiver is stricter than the forwarder, never looser.
//
// The end-to-end oracle is A6's receiver in tests/integration/slice and
// rsyslog in the integration job; this one shares no code with either.
package relptest

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

// Action is what the receiver does with one syslog frame.
type Action int

const (
	Ack         Action = iota // record, then 200 OK
	Refuse                    // 500, not recorded
	Close                     // close the connection without recording or answering
	Silent                    // read on, never answer
	ServerClose               // serverclose instead of an answer, not recorded
	AckTwice                  // record, then 200 OK twice: a grammar violation for the client
)

// Message is one syslog frame the receiver acknowledged.
type Message struct {
	Conn int    // connection number, from 1
	TXNR uint64 // the client's transaction number
	Data []byte // the message as received
}

// Command is one client frame.
type Command struct {
	TXNR    uint64
	Command string // open, syslog or close
	Data    []byte
}

// MaxData bounds the DATA of a client frame: C6's largest message
// (syslog.MaxMaxOctets). Kept here as a number so the receiver does not
// import the code under test.
const MaxData = 65535

// ErrIncomplete reports a buffer that holds the start of a valid frame.
var ErrIncomplete = errors.New("relptest: incomplete frame")

// ParseCommand reads one client frame from the start of buf:
//
//	TXNR SP COMMAND SP DATALEN [SP DATA] LF
//
// TXNR is 1 to 9 digits, at least 1, with no leading zero. COMMAND is open,
// syslog or close. DATALEN is 1 to 5 digits with no leading zero, at most
// MaxData, and DATA of exactly DATALEN octets is present exactly when
// DATALEN > 0. It returns the frame and the octets it used, ErrIncomplete,
// or another error.
func ParseCommand(buf []byte) (Command, int, error) {
	var c Command
	i := 0
	num := func(max int) (uint64, error) {
		start := i
		for i < len(buf) && buf[i] >= '0' && buf[i] <= '9' {
			i++
			if i-start > max {
				return 0, fmt.Errorf("relptest: number longer than %d digits", max)
			}
		}
		if i == len(buf) {
			return 0, ErrIncomplete
		}
		if i == start {
			return 0, fmt.Errorf("relptest: digits expected at %d", start)
		}
		if i-start > 1 && buf[start] == '0' {
			return 0, fmt.Errorf("relptest: leading zero at %d", start)
		}
		return strconv.ParseUint(string(buf[start:i]), 10, 64)
	}
	expect := func(b byte) error {
		if i == len(buf) {
			return ErrIncomplete
		}
		if buf[i] != b {
			return fmt.Errorf("relptest: %q expected at %d, found %q", b, i, buf[i])
		}
		i++
		return nil
	}
	txnr, err := num(9)
	if err != nil {
		return c, 0, err
	}
	if txnr == 0 {
		return c, 0, errors.New("relptest: TXNR 0")
	}
	if err := expect(' '); err != nil {
		return c, 0, err
	}
	start := i
	for i < len(buf) && buf[i] >= 'a' && buf[i] <= 'z' && i-start < 6 {
		i++
	}
	if i == len(buf) {
		return c, 0, ErrIncomplete
	}
	cmd := string(buf[start:i])
	if cmd != "open" && cmd != "syslog" && cmd != "close" {
		return c, 0, fmt.Errorf("relptest: command %q", cmd)
	}
	if err := expect(' '); err != nil {
		return c, 0, err
	}
	n, err := num(5)
	if err != nil {
		return c, 0, err
	}
	if n > MaxData {
		return c, 0, fmt.Errorf("relptest: DATALEN %d over %d", n, MaxData)
	}
	var data []byte
	if n > 0 {
		if err := expect(' '); err != nil {
			return c, 0, err
		}
		if len(buf)-i < int(n) {
			return c, 0, ErrIncomplete
		}
		data = buf[i : i+int(n)]
		i += int(n)
	}
	if err := expect('\n'); err != nil {
		return c, 0, err
	}
	return Command{TXNR: txnr, Command: cmd, Data: data}, i, nil
}

// Server is a RELP receiver on a loopback port.
type Server struct {
	ln net.Listener
	// script decides what happens to the nth syslog frame, n counted from
	// 1 over the server's lifetime. Nil acknowledges everything.
	script func(n int, m Message) Action

	mu     sync.Mutex
	frames int
	conns  int
	acked  []Message
	errs   []error
	open   map[net.Conn]bool
	wg     sync.WaitGroup
	closed bool
}

// Start listens on 127.0.0.1 with a free port, over TLS when cfg is not nil.
func Start(cfg *tls.Config, script func(n int, m Message) Action) (*Server, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	if cfg != nil {
		ln = tls.NewListener(ln, cfg)
	}
	s := &Server{ln: ln, script: script, open: map[net.Conn]bool{}}
	s.wg.Add(1)
	go s.accept()
	return s, nil
}

// Addr is the listening address.
func (s *Server) Addr() *net.TCPAddr { return s.ln.Addr().(*net.TCPAddr) }

// Acked returns the acknowledged messages, in the order acknowledged.
func (s *Server) Acked() []Message {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Message(nil), s.acked...)
}

// Errors returns the grammar and connection errors the receiver saw.
func (s *Server) Errors() []error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]error(nil), s.errs...)
}

// Conns is the number of connections accepted.
func (s *Server) Conns() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.conns
}

// Close stops the server and every connection.
func (s *Server) Close() error {
	s.mu.Lock()
	s.closed = true
	for c := range s.open {
		c.Close()
	}
	s.mu.Unlock()
	err := s.ln.Close()
	s.wg.Wait()
	return err
}

func (s *Server) accept() {
	defer s.wg.Done()
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			c.Close()
			return
		}
		s.conns++
		id := s.conns
		s.open[c] = true
		s.mu.Unlock()
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			if err := s.serve(id, c); err != nil {
				s.mu.Lock()
				s.errs = append(s.errs, fmt.Errorf("conn %d: %w", id, err))
				s.mu.Unlock()
			}
			c.Close()
			s.mu.Lock()
			delete(s.open, c)
			s.mu.Unlock()
		}()
	}
}

func rsp(txnr uint64, body string) []byte {
	return []byte(fmt.Sprintf("%d rsp %d %s\n", txnr, len(body), body))
}

// serve runs one connection. It returns nil at a clean end (close, a
// scripted close, or the client closing between frames).
func (s *Server) serve(id int, c net.Conn) error {
	var buf []byte
	chunk := make([]byte, 16*1024)
	var last uint64
	opened := false
	violate := func(err error) error {
		c.Write([]byte("0 serverclose 0\n"))
		return err
	}
	for {
		cmd, n, err := ParseCommand(buf)
		if errors.Is(err, ErrIncomplete) || (err == nil && n == 0) {
			if len(buf) > MaxData+32 {
				return violate(errors.New("relptest: frame too long"))
			}
			c.SetReadDeadline(time.Now().Add(time.Minute))
			k, rerr := c.Read(chunk)
			buf = append(buf, chunk[:k]...)
			if k == 0 && rerr != nil {
				if errors.Is(rerr, io.EOF) && len(buf) == 0 {
					return nil
				}
				if errors.Is(rerr, net.ErrClosed) {
					return nil
				}
				return rerr
			}
			continue
		}
		if err != nil {
			return violate(err)
		}
		buf = buf[n:]
		if cmd.TXNR <= last {
			return violate(fmt.Errorf("relptest: TXNR %d after %d", cmd.TXNR, last))
		}
		last = cmd.TXNR
		switch cmd.Command {
		case "open":
			if opened || cmd.TXNR != 1 {
				return violate(fmt.Errorf("relptest: open as transaction %d", cmd.TXNR))
			}
			if !offersSyslog(cmd.Data) {
				return violate(errors.New("relptest: open does not offer commands=syslog"))
			}
			opened = true
			if _, err := c.Write(rsp(cmd.TXNR, "200 OK\nrelp_version=0\nrelp_software=relptest\ncommands=syslog")); err != nil {
				return err
			}
		case "close":
			c.Write([]byte(strconv.FormatUint(cmd.TXNR, 10) + " rsp 0\n"))
			return nil
		case "syslog":
			if !opened {
				return violate(errors.New("relptest: syslog before open"))
			}
			if bytes.ContainsAny(cmd.Data, "\n\r\x00") {
				return violate(errors.New("relptest: message contains LF, CR or NUL"))
			}
			m := Message{Conn: id, TXNR: cmd.TXNR, Data: append([]byte(nil), cmd.Data...)}
			s.mu.Lock()
			s.frames++
			nth := s.frames
			s.mu.Unlock()
			act := Ack
			if s.script != nil {
				act = s.script(nth, m)
			}
			switch act {
			case Ack, AckTwice:
				s.mu.Lock()
				s.acked = append(s.acked, m)
				s.mu.Unlock()
				out := rsp(cmd.TXNR, "200 OK")
				if act == AckTwice {
					out = append(out, out...)
				}
				if _, err := c.Write(out); err != nil {
					return err
				}
			case Refuse:
				if _, err := c.Write(rsp(cmd.TXNR, "500 refused by test")); err != nil {
					return err
				}
			case Close:
				return nil
			case Silent:
			case ServerClose:
				c.Write([]byte("0 serverclose 0\n"))
				return nil
			}
		}
	}
}

func offersSyslog(data []byte) bool {
	for _, line := range bytes.Split(data, []byte("\n")) {
		if v, ok := bytes.CutPrefix(line, []byte("commands=")); ok {
			for _, c := range bytes.Split(v, []byte(",")) {
				if string(c) == "syslog" {
					return true
				}
			}
		}
	}
	return false
}
