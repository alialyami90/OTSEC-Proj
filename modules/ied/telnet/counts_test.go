package telnet

import (
	"errors"
	"io"
	"testing"
)

// Wire - Received is every octet received that is not data: a command's
// IAC, verb and option, a subnegotiation whole, and the IAC of an escaped
// 0xFF (C2 0.10 §1.2). The input is counted by hand beside each part.
func TestCountsCommandOctets(t *testing.T) {
	in := []byte{
		cmdIAC, cmdWILL, 1, // 3, refused
		cmdIAC, cmdDO, 24, // 3, refused
		cmdIAC, cmdWILL, 1, // 3, already refused
		cmdIAC, 0xF1, // NOP: 2
		cmdIAC, cmdSB, 24, 1, cmdIAC, cmdIAC, 2, cmdIAC, cmdSE, // 9
		'a', cmdIAC, cmdIAC, 'b', // data a, 0xFF, b: 1 command octet
		'=',
	}
	c, _ := session(t, Config{}, in[:7], in[7:])
	got, err := readAll(c)
	if !errors.Is(err, io.EOF) {
		t.Fatalf("error %v, want EOF", err)
	}
	n := c.Counts()
	if n.Received != int64(len(got)) || string(got) != "a\xffb=" {
		t.Errorf("data %q, received %d", got, n.Received)
	}
	if n.Wire != int64(len(in)) {
		t.Errorf("wire %d, want %d", n.Wire, len(in))
	}
	if cmd, want := n.Wire-n.Received, int64(3+3+3+2+9+1); cmd != want {
		t.Errorf("command octets %d, want %d", cmd, want)
	}
	if n.Refusals != 2 || n.Stats != c.Stats() {
		t.Errorf("counts %+v, stats %+v", n, c.Stats())
	}
	if cmd := n.Wire - n.Received; cmd < 3*int64(n.Refusals) {
		t.Errorf("command octets %d below 3 x refusals %d", cmd, n.Refusals)
	}
}

// failWrite is a peer whose socket refuses every write, as a socket whose
// write side is shut after the half-close does (C2 0.10 §1.1).
type failWrite struct{ fakeConn }

func (f *failWrite) Write([]byte) (int, error) { return 0, errors.New("test: write side shut") }

// AtEOF is true only at the peer's end of stream with the decoder in no
// error. The control is the plain EOF; each other case ends otherwise.
func TestAtEOF(t *testing.T) {
	c, _ := session(t, Config{}, []byte("=>"))
	if c.AtEOF() {
		t.Fatal("at EOF before any read")
	}
	if _, err := readAll(c); !errors.Is(err, io.EOF) || !c.AtEOF() {
		t.Errorf("plain EOF: error %v, AtEOF %v", err, c.AtEOF())
	}

	c, _ = session(t, Config{MaxCommands: 1}, []byte{cmdIAC, 0xF1, cmdIAC, 0xF1})
	if _, err := readAll(c); !errors.Is(err, ErrNegotiation) || c.AtEOF() {
		t.Errorf("negotiation over the limit: error %v, AtEOF %v", err, c.AtEOF())
	}

	c, _ = session(t, Config{MaxReceived: 1}, []byte("ab"))
	if _, err := readAll(c); !errors.Is(err, ErrTooLarge) || c.AtEOF() {
		t.Errorf("data over the limit: error %v, AtEOF %v", err, c.AtEOF())
	}

	// A DO whose refusal cannot be written: not counted, and the session
	// ends on the write error, not at EOF, though the peer then closes.
	f := &failWrite{fakeConn{chunks: [][]byte{{cmdIAC, cmdDO, 1}}}}
	c, err := New(f, Config{MaxReceived: 1 << 20, MaxCommands: 64, Egress: allow})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := readAll(c); err == nil || errors.Is(err, io.EOF) || c.AtEOF() {
		t.Errorf("refusal unwritten: error %v, AtEOF %v", err, c.AtEOF())
	}
	if n := c.Counts(); n.Refusals != 0 || n.Wire != 3 || n.Received != 0 {
		t.Errorf("refusal unwritten: counts %+v", n)
	}
}
