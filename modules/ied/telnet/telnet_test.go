package telnet

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// fakeConn serves reads from chunks, one chunk per Read, and records writes.
type fakeConn struct {
	chunks [][]byte
	wrote  bytes.Buffer
	writes int
}

func (f *fakeConn) Read(p []byte) (int, error) {
	if len(f.chunks) == 0 {
		return 0, io.EOF
	}
	n := copy(p, f.chunks[0])
	if f.chunks[0] = f.chunks[0][n:]; len(f.chunks[0]) == 0 {
		f.chunks = f.chunks[1:]
	}
	return n, nil
}
func (f *fakeConn) Write(p []byte) (int, error)      { f.writes++; return f.wrote.Write(p) }
func (f *fakeConn) Close() error                     { return nil }
func (f *fakeConn) LocalAddr() net.Addr              { return nil }
func (f *fakeConn) RemoteAddr() net.Addr             { return nil }
func (f *fakeConn) SetDeadline(time.Time) error      { return nil }
func (f *fakeConn) SetReadDeadline(time.Time) error  { return nil }
func (f *fakeConn) SetWriteDeadline(time.Time) error { return nil }

func allow([]byte) error { return nil }

func session(t *testing.T, cfg Config, chunks ...[]byte) (*Conn, *fakeConn) {
	t.Helper()
	f := &fakeConn{chunks: chunks}
	if cfg.MaxReceived == 0 {
		cfg.MaxReceived = 1 << 20
	}
	if cfg.MaxCommands == 0 {
		cfg.MaxCommands = 64
	}
	if cfg.Egress == nil {
		cfg.Egress = allow
	}
	c, err := New(f, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return c, f
}

// readAll reads until an error and returns the data and that error.
func readAll(c *Conn) ([]byte, error) {
	var out []byte
	buf := make([]byte, 7) // small, so reads split the stream
	for {
		n, err := c.Read(buf)
		out = append(out, buf[:n]...)
		if err != nil {
			return out, err
		}
	}
}

func TestReadStripsCommandsAndKeepsData(t *testing.T) {
	in := []byte("SEL-751\r\n\x02\r\x00=\xff\xff\xff\xf1x\xff\xf9\x03=")
	c, f := session(t, Config{}, in)
	got, err := readAll(c)
	if !errors.Is(err, io.EOF) {
		t.Fatalf("error %v, want EOF", err)
	}
	if want := []byte("SEL-751\r\n\x02\r\x00=\xffx\x03="); !bytes.Equal(got, want) {
		t.Errorf("data %q, want %q", got, want)
	}
	if f.wrote.Len() != 0 {
		t.Errorf("wrote %x for NOP and GA", f.wrote.Bytes())
	}
	if s := c.Stats(); s.Commands != 2 || s.Refusals != 0 {
		t.Errorf("stats %+v", s)
	}
}

func TestRefusesEveryOptionOnce(t *testing.T) {
	in := []byte{
		cmdIAC, cmdWILL, 1, // ECHO offered
		cmdIAC, cmdDO, 24, // TERMINAL-TYPE asked for
		cmdIAC, cmdWILL, 1, // offered again: already refused
		cmdIAC, cmdWONT, 3, // nothing to answer
		cmdIAC, cmdDONT, 3,
		'=',
	}
	c, f := session(t, Config{}, in)
	got, _ := readAll(c)
	if string(got) != "=" {
		t.Errorf("data %q", got)
	}
	want := []byte{cmdIAC, cmdDONT, 1, cmdIAC, cmdWONT, 24}
	if !bytes.Equal(f.wrote.Bytes(), want) {
		t.Errorf("wrote %x, want %x", f.wrote.Bytes(), want)
	}
	if s := c.Stats(); s.Commands != 5 || s.Refusals != 2 {
		t.Errorf("stats %+v", s)
	}
}

func TestCommandSplitAcrossReads(t *testing.T) {
	c, f := session(t, Config{}, []byte("a\xff"), []byte{cmdDO}, []byte{31, 'b', cmdIAC}, []byte{cmdIAC, 'c'})
	got, _ := readAll(c)
	if string(got) != "ab\xffc" {
		t.Errorf("data %q", got)
	}
	if !bytes.Equal(f.wrote.Bytes(), []byte{cmdIAC, cmdWONT, 31}) {
		t.Errorf("wrote %x", f.wrote.Bytes())
	}
}

func TestSubnegotiationDiscarded(t *testing.T) {
	in := append([]byte{cmdIAC, cmdSB, 24, 1, cmdIAC, cmdIAC, 2, cmdIAC, cmdSE}, "=>"...)
	c, f := session(t, Config{}, in)
	got, _ := readAll(c)
	if string(got) != "=>" || f.wrote.Len() != 0 {
		t.Errorf("data %q, wrote %x", got, f.wrote.Bytes())
	}
}

// An option verb inside a subnegotiation ends it; its option byte never
// becomes data, and the option is refused like any other (A6 #75 review).
func TestCommandInsideSubnegotiation(t *testing.T) {
	in := append([]byte{cmdIAC, cmdSB, 24, 1, cmdIAC, cmdWILL, 1}, "=>"...)
	c, f := session(t, Config{}, in)
	got, _ := readAll(c)
	if string(got) != "=>" {
		t.Errorf("data %q", got)
	}
	if !bytes.Equal(f.wrote.Bytes(), []byte{cmdIAC, cmdDONT, 1}) {
		t.Errorf("wrote %x", f.wrote.Bytes())
	}
}

func TestSubnegotiationBounded(t *testing.T) {
	in := append([]byte{cmdIAC, cmdSB, 24}, bytes.Repeat([]byte{'x'}, MaxSubnegotiation+1)...)
	c, _ := session(t, Config{}, in)
	if _, err := readAll(c); !errors.Is(err, ErrNegotiation) {
		t.Errorf("error %v, want ErrNegotiation", err)
	}
}

func TestCommandsBounded(t *testing.T) {
	in := bytes.Repeat([]byte{cmdIAC, 0xF1}, 4) // four NOPs
	c, _ := session(t, Config{MaxCommands: 3}, in)
	if _, err := readAll(c); !errors.Is(err, ErrNegotiation) {
		t.Errorf("error %v, want ErrNegotiation", err)
	}
}

func TestReceivedBounded(t *testing.T) {
	c, _ := session(t, Config{MaxReceived: 5}, []byte("abc"), []byte("\xff\xffdef"))
	got, err := readAll(c)
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("error %v, want ErrTooLarge", err)
	}
	if string(got) != "abc\xffd" || c.Received() != 5 {
		t.Errorf("data %q, received %d", got, c.Received())
	}
	if _, err := c.Read(make([]byte, 1)); !errors.Is(err, ErrTooLarge) {
		t.Errorf("the error does not stick: %v", err)
	}
}

func TestSendChecksTheExactBytes(t *testing.T) {
	var seen []string
	egress := func(b []byte) error {
		seen = append(seen, string(b))
		if string(b) == "SER D" {
			return errors.New("denied")
		}
		b[0] = 'X' // a check that changes its argument changes nothing written
		return nil
	}
	c, f := session(t, Config{Egress: egress})
	for _, line := range []string{"SER\r\n", "ID\r", "QUI\n"} {
		if err := c.Send([]byte(line)); err != nil {
			t.Fatalf("%q: %v", line, err)
		}
	}
	for name, line := range map[string]string{
		"egress refusal":     "SER D\r\n",
		"control byte":       "SER\x07\r\n",
		"IAC":                "SER\xff\xf4\r\n",
		"high bit":           "SER\xe9\r\n",
		"empty":              "",
		"line end only":      "\r\n",
		"no line end":        "SER",
		"two lines":          "SER\r\nSER D\r\n",
		"CR inside":          "SER\rD\r\n",
		"LF inside":          "SER\nD\n",
		"two line ends":      "SER\r\n\r\n",
		"LF CR":              "SER\n\r",
		"NUL after CR":       "SER\r\x00",
		"two lines, no last": "QUI\r\nSER D",
	} {
		if err := c.Send([]byte(line)); !errors.Is(err, ErrEgress) {
			t.Errorf("%s: error %v, want ErrEgress", name, err)
		}
	}
	if f.wrote.String() != "SER\r\nID\rQUI\n" || f.writes != 3 {
		t.Errorf("wrote %q in %d writes; only the permitted lines may reach the socket", f.wrote.String(), f.writes)
	}
	if len(seen) != 4 || seen[0] != "SER" || seen[1] != "ID" || seen[2] != "QUI" || seen[3] != "SER D" {
		t.Errorf("egress saw %q", seen)
	}
}

func TestSendSecretOnce(t *testing.T) {
	var seen int
	c, f := session(t, Config{Egress: func([]byte) error { seen++; return nil }})
	for name, s := range map[string]string{"empty": "", "CR": "pa\rss", "LF": "pa\nss", "IAC": "pa\xffss", "NUL": "pa\x00ss"} {
		if err := c.SendSecret([]byte(s)); !errors.Is(err, ErrEgress) {
			t.Errorf("%s: error %v", name, err)
		}
	}
	if err := c.SendSecret([]byte("Otter#2026")); err != nil {
		t.Fatal(err)
	}
	if err := c.SendSecret([]byte("Otter#2026")); !errors.Is(err, ErrEgress) {
		t.Errorf("second credential: %v", err)
	}
	if f.wrote.String() != "Otter#2026\r\n" || f.writes != 1 || seen != 0 {
		t.Errorf("wrote %q in %d writes, egress called %d times", f.wrote.String(), f.writes, seen)
	}
}

func TestSendAfterFailure(t *testing.T) {
	c, f := session(t, Config{MaxReceived: 1}, []byte("ab"))
	readAll(c)
	if err := c.Send([]byte("QUI\r\n")); !errors.Is(err, ErrTooLarge) {
		t.Errorf("error %v, want the session's error", err)
	}
	if f.wrote.Len() != 0 {
		t.Errorf("wrote %q after the session failed", f.wrote.String())
	}
}

func TestNewRefusesBadConfig(t *testing.T) {
	f := &fakeConn{}
	for name, cfg := range map[string]Config{
		"no egress":       {MaxReceived: 1, MaxCommands: 1},
		"no limit":        {MaxCommands: 1, Egress: allow},
		"negative limit":  {MaxReceived: -1, MaxCommands: 1, Egress: allow},
		"negative counts": {MaxReceived: 1, MaxCommands: -1, Egress: allow},
	} {
		if _, err := New(f, cfg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := New(nil, Config{MaxReceived: 1, Egress: allow}); err == nil {
		t.Error("nil connection accepted")
	}
}
