package sel751

import (
	"bytes"
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"otsec.local/otsec/contracts/adapter"
	"otsec.local/otsec/modules/ied/telnet"
)

// No unregistered line reaches the socket (P2-A2 acceptance). The oracle is
// written out here from the register content, not derived from the code
// under test: for a SER read, the only lines that may be written are these,
// each only in its phase.
var mayWrite = map[adapter.Phase][]string{
	adapter.PhaseProbe:   {"QUI", "ID"},
	adapter.PhaseAuth:    {"ACC"},
	adapter.PhaseOperate: {"SHO P 1", "SER"},
	adapter.PhaseClose:   {"QUI"},
}

// wire records what is written and never has anything to read.
type wire struct{ bytes.Buffer }

func (w *wire) Read([]byte) (int, error)         { return 0, net.ErrClosed }
func (w *wire) Close() error                     { return nil }
func (w *wire) LocalAddr() net.Addr              { return nil }
func (w *wire) RemoteAddr() net.Addr             { return nil }
func (w *wire) SetDeadline(time.Time) error      { return nil }
func (w *wire) SetReadDeadline(time.Time) error  { return nil }
func (w *wire) SetWriteDeadline(time.Time) error { return nil }

var (
	egressOnce   sync.Once
	egressInputs inputs // read-only once loaded
)

// egressSession is a checked session for the SER read on a recording wire.
func egressSession(t testing.TB) (*session, *wire) {
	t.Helper()
	egressOnce.Do(func() { egressInputs = load(t) })
	f := egressInputs
	s := &session{inv: f.inv, cfg: Config{Asset: f.asset, Profile: f.profile, Register: f.reg,
		Secret: &secret{b: []byte(testSecret)}, Floor: &floor{},
		Dial: func(context.Context, string, string) (net.Conn, error) { return nil, nil }}, level: -1}
	if code := s.check(); code != "" {
		t.Fatalf("check: %s", code)
	}
	w := &wire{}
	c, err := telnet.New(w, telnet.Config{MaxReceived: 1024, MaxCommands: 4, Egress: s.egress})
	if err != nil {
		t.Fatal(err)
	}
	s.conn = c
	return s, w
}

func allowed(ph adapter.Phase, line string) bool {
	for _, l := range mayWrite[ph] {
		if l == line {
			return true
		}
	}
	return false
}

var phases = []adapter.Phase{adapter.PhaseProbe, adapter.PhaseAuth, adapter.PhaseOperate, adapter.PhaseClose}

// Lines the register denies or does not list, near misses of approved ones,
// and approved lines in the wrong phase: none may be written, even when the
// dialogue itself asks for it.
func TestEgressRefusesUnregistered(t *testing.T) {
	lines := []string{
		"SER C", "SER R", "SER D", "SER 10", "SER 1 10", "ser", "SER ", " SER", "SE", "SERX",
		"2AC", "ACC 2", "OPE", "OPE 1", "CLO", "PUL OUT101", "SET", "SET P 1", "PAS", "CON",
		"TAR R", "HIS C", "SUM R", "MET R", "LDP C", "COM C", "L_D", "R_S", "CAL",
		"SHO G", "SHO P 2", "SHO", "STA", "EVE", "QUIT", "QUI ", "ID ", "ACC", "QUI", "ID", "SHO P 1", "SER",
		"SAL", "MOS P 1", "Y", "N", "LabPass1", "[REDACTED]",
	}
	for _, ph := range phases {
		for _, l := range lines {
			s, w := egressSession(t)
			s.phase, s.want = ph, l // the dialogue asks for exactly this line
			err := s.conn.Send([]byte(l + "\r\n"))
			wrote := w.Len() > 0
			if want := allowed(ph, l); wrote != want {
				t.Errorf("%s %q: written %v (err %v), want %v", ph, l, wrote, err, want)
			}
		}
	}
}

// A line the dialogue did not mean to send is refused even when the
// register would permit it: the egress check also holds the step's own line.
func TestEgressHoldsTheStepsLine(t *testing.T) {
	s, w := egressSession(t)
	s.phase, s.want = adapter.PhaseOperate, "SHO P 1"
	if err := s.conn.Send([]byte("SER\r\n")); err == nil || w.Len() > 0 {
		t.Fatalf("a permitted line other than the step's was written: %v, %q", err, w.String())
	}
	s.want = ""
	if err := s.conn.Send([]byte("SER\r\n")); err == nil || w.Len() > 0 {
		t.Fatalf("a line with no step asking for it was written: %v", err)
	}
}

// FuzzEgress: whatever line and phase the dialogue asks for, only the
// oracle's lines are written, exactly as given, in one line.
func FuzzEgress(f *testing.F) {
	for _, ph := range phases {
		for _, l := range mayWrite[ph] {
			f.Add(string(ph), l)
		}
	}
	f.Add("operate", "SER C")
	f.Add("auth", "2AC")
	f.Fuzz(func(t *testing.T, ph, line string) {
		s, w := egressSession(t)
		s.phase, s.want = adapter.Phase(ph), line
		_ = s.conn.Send([]byte(line + "\r\n"))
		if w.Len() == 0 {
			return
		}
		if !allowed(adapter.Phase(ph), line) || w.String() != line+"\r\n" {
			t.Fatalf("phase %q: wrote %q", ph, w.String())
		}
	})
}
