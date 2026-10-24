// Package telnet is the minimal RFC 854 client the SEL-751 adapter talks
// through (ADR-0005, D2-1). It refuses every option, bounds what it reads,
// and puts nothing on the socket that its caller's egress check has not
// passed.
//
// What it does:
//
//   - Reads: Read returns the NVT data stream with every Telnet command
//     removed. IAC IAC is one 0xFF data byte. Everything else is kept
//     verbatim, CR NUL included, because the data is evidence (C2 EP-1).
//     Data beyond Config.MaxReceived fails with ErrTooLarge.
//   - Options: every WILL is answered DONT and every DO is answered WONT, once
//     per option and verb (RFC 854: a request to enter a mode already
//     refused is not answered again). WONT and DONT need no answer, because
//     no option is ever on. Subnegotiation is discarded up to
//     MaxSubnegotiation bytes. More than Config.MaxCommands commands in one
//     session fails with ErrNegotiation, so a peer cannot hold the
//     session in negotiation.
//   - Writes: Send writes one caller line in one Write. The line is checked
//     first by Config.Egress on the exact bytes, then by the transport's own
//     rule: printable ASCII, CR and LF only (ADR-0005, A2 D5). Because 0xFF
//     can never pass, data needs no IAC escaping, and the bytes the egress
//     check saw are the bytes on the socket.
//   - The refusals are the only other bytes it writes: three bytes each,
//     IAC WONT x or IAC DONT x, written from inside Read.
//
// What it leaves out: options, subnegotiation, urgent data (the Synch
// signal's data mark is discarded like any other command), and concurrency.
// A Conn is used by one goroutine.
//
// The refusals are not in the C2 transcript, which holds the NVT data
// stream. Stats counts them.
package telnet

import (
	"errors"
	"fmt"
	"net"
	"time"
)

// Telnet command bytes (RFC 854).
const (
	cmdSE   = 0xF0
	cmdSB   = 0xFA
	cmdWILL = 0xFB
	cmdWONT = 0xFC
	cmdDO   = 0xFD
	cmdDONT = 0xFE
	cmdIAC  = 0xFF
)

// MaxSubnegotiation bounds the bytes discarded inside one IAC SB ... IAC SE.
const MaxSubnegotiation = 256

var (
	// ErrTooLarge: the peer sent more data than Config.MaxReceived.
	ErrTooLarge = errors.New("telnet: received data over the limit")
	// ErrNegotiation: more commands than Config.MaxCommands, or an
	// oversized subnegotiation.
	ErrNegotiation = errors.New("telnet: negotiation over the limit")
	// ErrEgress: Send refused the line; nothing was written.
	ErrEgress = errors.New("telnet: line refused at egress")
)

// Config bounds one session.
type Config struct {
	// MaxReceived is the most data bytes Read returns in the session.
	MaxReceived int64
	// MaxCommands is the most Telnet commands accepted in the session.
	MaxCommands int
	// Egress is the caller's check on every line Send writes. It sees the
	// exact bytes the socket will get. It is required.
	Egress func(line []byte) error
}

// Stats counts what the transport did outside the data stream.
type Stats struct {
	Commands int // Telnet commands received
	Refusals int // IAC WONT and IAC DONT written
}

// Conn is a Telnet session over a connected net.Conn.
type Conn struct {
	nc  net.Conn
	cfg Config

	state    parseState
	verb     byte
	sbLen    int
	received int64
	stats    Stats
	refused  map[[2]byte]bool // verb and option already answered
	err      error            // sticky: the session is over
	pending  []byte           // data decoded but not yet returned
	readBuf  []byte
}

type parseState int

const (
	stData   parseState = iota
	stIAC               // after IAC
	stOption            // after IAC WILL/WONT/DO/DONT
	stSB                // inside a subnegotiation
	stSBIAC             // IAC inside a subnegotiation
)

// New starts a session on nc. It does not take ownership of deadlines;
// set them with SetDeadline.
func New(nc net.Conn, cfg Config) (*Conn, error) {
	switch {
	case nc == nil:
		return nil, errors.New("telnet: no connection")
	case cfg.MaxReceived <= 0 || cfg.MaxCommands < 0:
		return nil, errors.New("telnet: limits must be positive")
	case cfg.Egress == nil:
		return nil, errors.New("telnet: an egress check is required")
	}
	return &Conn{nc: nc, cfg: cfg, refused: map[[2]byte]bool{}, readBuf: make([]byte, 4096)}, nil
}

// Read returns NVT data. It reads from the socket until it has at least one
// data byte, answering negotiation as it goes, or until an error.
func (c *Conn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for len(c.pending) == 0 {
		if c.err != nil {
			return 0, c.err
		}
		n, err := c.nc.Read(c.readBuf)
		if n > 0 {
			if perr := c.decode(c.readBuf[:n]); perr != nil {
				c.err = perr
			}
		}
		if err != nil && c.err == nil {
			c.err = err
		}
	}
	n := copy(p, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}

// decode runs the command parser over b, appending data to c.pending.
func (c *Conn) decode(b []byte) error {
	for _, x := range b {
		switch c.state {
		case stData:
			if x == cmdIAC {
				c.state = stIAC
				continue
			}
			if err := c.data(x); err != nil {
				return err
			}
		case stIAC:
			c.state = stData
			if x == cmdIAC {
				if err := c.data(x); err != nil {
					return err
				}
				continue
			}
			if err := c.command(); err != nil {
				return err
			}
			switch x {
			case cmdWILL, cmdWONT, cmdDO, cmdDONT:
				c.verb, c.state = x, stOption
			case cmdSB:
				c.sbLen, c.state = 0, stSB
			}
			// Any other command (NOP, DM, GA, ...) is discarded.
		case stOption:
			c.state = stData
			if err := c.answer(c.verb, x); err != nil {
				return err
			}
		case stSB:
			if x == cmdIAC {
				c.state = stSBIAC
				continue
			}
			if c.sbLen++; c.sbLen > MaxSubnegotiation {
				return ErrNegotiation
			}
		case stSBIAC:
			switch x {
			case cmdSE:
				c.state = stData
			case cmdIAC:
				c.state = stSB
				if c.sbLen++; c.sbLen > MaxSubnegotiation {
					return ErrNegotiation
				}
			default:
				// RFC 854 allows no other command inside SB; end it here.
				c.state = stData
			}
		}
	}
	return nil
}

func (c *Conn) data(x byte) error {
	if c.received >= c.cfg.MaxReceived {
		return ErrTooLarge
	}
	c.received++
	c.pending = append(c.pending, x)
	return nil
}

func (c *Conn) command() error {
	if c.stats.Commands++; c.stats.Commands > c.cfg.MaxCommands {
		return ErrNegotiation
	}
	return nil
}

// answer refuses an option the peer offers or asks for, once.
func (c *Conn) answer(verb, opt byte) error {
	var reply byte
	switch verb {
	case cmdWILL:
		reply = cmdDONT
	case cmdDO:
		reply = cmdWONT
	default:
		return nil // WONT and DONT: no option is on, nothing to answer
	}
	key := [2]byte{verb, opt}
	if c.refused[key] {
		return nil
	}
	c.refused[key] = true
	if _, err := c.nc.Write([]byte{cmdIAC, reply, opt}); err != nil {
		return fmt.Errorf("telnet: refusing option %d: %w", opt, err)
	}
	c.stats.Refusals++
	return nil
}

// Send writes line, exactly, in one Write: after the caller's egress check
// and the transport's own byte rule. On a refusal nothing is written.
func (c *Conn) Send(line []byte) error {
	if c.err != nil {
		return c.err
	}
	if len(line) == 0 {
		return fmt.Errorf("%w: empty line", ErrEgress)
	}
	if err := c.cfg.Egress(line); err != nil {
		return fmt.Errorf("%w: %v", ErrEgress, err)
	}
	for i, x := range line {
		if (x < 0x20 || x > 0x7e) && x != '\r' && x != '\n' {
			return fmt.Errorf("%w: byte 0x%02x at %d is not printable ASCII, CR or LF", ErrEgress, x, i)
		}
	}
	n, err := c.nc.Write(line)
	if err == nil && n != len(line) {
		err = fmt.Errorf("telnet: short write, %d of %d bytes", n, len(line))
	}
	return err
}

// SetDeadline sets the read and write deadline of the socket.
func (c *Conn) SetDeadline(t time.Time) error { return c.nc.SetDeadline(t) }

// Stats returns the session's command counts.
func (c *Conn) Stats() Stats { return c.stats }

// Received returns the data bytes returned or pending so far.
func (c *Conn) Received() int64 { return c.received }

// Close closes the socket.
func (c *Conn) Close() error { return c.nc.Close() }
