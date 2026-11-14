// Package c2telnet holds D6's integration tests 7, 8 and 10 of C2 0.10's
// session.telnet (docs/phase4/D2-c2-0.10-proposal.md §1.3, §1.4, §3 and §8;
// brief P4-4-CC deliverable 4; D4-102 item 5 (a)). They check the SEL-751
// adapter's close step and counts, and the collector's two seams, from
// outside both, against D6's own scripted relay on a real TCP socket: a far
// end that answers each line it receives and records the far side. Expected
// values come from the proposal's text, not from D2's or D3's tests.
//
// Test 7 runs on loopback in both go jobs. Tests 8 and 10 need nft and a
// capture, so they run only in a6-c2-netns, as root in a network namespace
// of their own (netns_d6_linux_test.go).
//
// Evidence class: simulated. Every relay reply is invented; S22 prints none
// of the close phase's. No device is contacted.
package c2telnet

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"otsec.local/otsec/contracts/adapter"
	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/register"
	"otsec.local/otsec/modules/ied/sel751"
	"otsec.local/otsec/modules/security/collector"
)

// pw is a test value only, 18 octets, so that each echo of it adds 8 octets
// to the wire beyond the 10-octet marker that replaces it (C-A2-3).
const pw = "D6-c2-0.10-test-pw"

// The runs' limits. step is every run's step_timeout_ms; quiet is the
// adapter's prompt quiet interval (sel751 promptQuiet), which the far end
// cannot change.
const (
	step     = 2000 * time.Millisecond
	quiet    = 200 * time.Millisecond
	maxResp  = 8192
	allow    = 4096 // sel751 closeAllowance: what QUI's reply may add to max_response_bytes
	finWait  = step + 2*time.Second
	serveFor = 30 * time.Second
)

const header = "\r\nSEL-751          Date: 11/15/2026  Time: 09:15:00\r\nFEEDER 1         Time Source: Internal\r\n\r\n"

func frame(echo, body, prompt string) string { return echo + "\r\n\x02" + body + "\x03" + prompt }

const idReply = "ID\r\n\x02\"FID=SEL-751-R501-V0-Z104101-D20260910\",\"0000\"\r\n\"BFID=BOOTLDR-R500-V0-Z000000-D20090925\",\"0000\"\r\n\"CID=E754\",\"0000\"\r\n\"DEVID=FEEDER 1\",\"0000\"\r\n\"DEVCODE=91\",\"0000\"\r\n\"PARTNO=751501A1A5A0X8C080\",\"0000\"\r\n\x03="

const serBody = header + "Serial No = SIM0000000000001\r\nFID = SEL-751-R501-V0-Z104101-D20260910     CID = E754\r\n\r\n#    DATE       TIME           ELEMENT           STATE\r\n2    11/15/2026 09:10:00.004   IN101             Asserted\r\n1    11/15/2026 09:10:01.004   IN101             Deasserted\r\n\r\n"

// ending is what the far end does once the close phase's script is done.
type ending int

const (
	closeFIN ending = iota // close: a FIN
	closeRST               // SO_LINGER 0, then close: an RST
	hold                   // neither close nor send until the test's run returns
)

// script is how the far end answers the close phase's QUI (the second QUI;
// the first is the language probe) and what it does after the client's FIN.
type script struct {
	greet        func(w *writer) // at connect, before any line; nil sends "\r\n="
	quiAfter     time.Duration   // QUI's reply waits this long
	quiSilent    bool            // QUI gets no reply
	closeAtReply bool            // close right after QUI's reply, before any FIN from the client
	late         func(w *writer) // sent once the client's FIN came, or finWait passed
	end          ending
	probeReset   bool              // after the client's FIN, write an octet, and see whether an RST answers it
	onLine       func(line string) // called with each line before it is answered
}

// record is the far side of one session.
type record struct {
	client       string    // the client's address, as the far end saw it
	rx           []byte    // every octet received
	lines        []string  // the lines received, the password as "<pw>"
	refusals     int       // IAC DONT x and IAC WONT x received
	otherCmds    int       // any other IAC sequence received
	wire, data   int64     // octets sent, and how many of them were data octets
	echoes       int       // echoes of the secret sent
	writeErr     error     // the first failed write
	quiAt        time.Time // when the close phase's QUI arrived
	replyAt      time.Time // when its reply went out
	finAt        time.Time // when the client's FIN arrived; zero if it never did
	rxAfterReply int       // octets received after QUI's reply went out
	lateSent     time.Time // when the late octets went out
	resetSeen    bool      // probeReset: a write after the client's FIN failed
	readEnd      error     // how the far end's reading ended
}

// farEnd is D6's scripted SEL-751: one connection, answered by the line it
// receives. The framing (echo, STX, ETX, prompt) is S22's as A6 transcribed
// it for the recording simulator (#166).
type farEnd struct {
	addr     string
	sc       script
	release  chan struct{}
	served   chan struct{}
	stopOnce sync.Once

	mu sync.Mutex
	r  record
}

func newFarEnd(t *testing.T, sc script) *farEnd {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &farEnd{addr: ln.Addr().String(), sc: sc, release: make(chan struct{}), served: make(chan struct{})}
	go func() {
		defer close(f.served)
		c, err := ln.Accept()
		ln.Close()
		if err != nil {
			return
		}
		f.serve(c)
	}()
	t.Cleanup(func() { ln.Close(); f.stop() })
	return f
}

// stop releases a far end that holds the connection.
func (f *farEnd) stop() { f.stopOnce.Do(func() { close(f.release) }) }

// wait returns the record once the far end is done with the connection.
func (f *farEnd) wait(t *testing.T, d time.Duration) record {
	t.Helper()
	f.stop()
	select {
	case <-f.served:
	case <-time.After(d):
		t.Errorf("the far end was still serving after %v", d)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	r := f.r
	r.rx = append([]byte(nil), f.r.rx...)
	r.lines = append([]string(nil), f.r.lines...)
	return r
}

func (f *farEnd) set(fn func(r *record)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(&f.r)
}

// writer sends the far end's octets and counts them: data octets (0xFF
// escaped as IAC IAC, one data octet for two on the wire) apart from command
// octets.
type writer struct {
	c net.Conn
	f *farEnd
}

func (w *writer) data(s string) {
	w.send(bytes.ReplaceAll([]byte(s), []byte{0xff}, []byte{0xff, 0xff}), int64(len(s)))
}

func (w *writer) cmd(b ...byte) { w.send(b, 0) }

func (w *writer) send(b []byte, data int64) {
	_ = w.c.SetWriteDeadline(time.Now().Add(5 * time.Second))
	n, err := w.c.Write(b)
	w.f.set(func(r *record) {
		r.wire += int64(n)
		if err == nil {
			r.data += data
		} else if r.writeErr == nil {
			r.writeErr = err
		}
	})
}

// read records every octet the client sends, counts its refusals (the only
// IAC sequences a client of this adapter sends, three octets each), and
// passes each line on. It stops at the first error; EOF is the client's FIN.
func (f *farEnd) read(c net.Conn, lines chan<- string, fin chan<- struct{}) {
	defer close(lines)
	var line, cmd []byte
	buf := make([]byte, 4096)
	for {
		_ = c.SetReadDeadline(time.Now().Add(serveFor))
		n, err := c.Read(buf)
		now := time.Now()
		var got []string
		f.set(func(r *record) {
			r.rx = append(r.rx, buf[:n]...)
			if !r.replyAt.IsZero() {
				r.rxAfterReply += n
			}
			for _, b := range buf[:n] {
				switch {
				case len(cmd) > 0 || b == 0xff:
					if cmd = append(cmd, b); len(cmd) == 3 {
						if cmd[1] == 0xfe || cmd[1] == 0xfc {
							r.refusals++
						} else {
							r.otherCmds++
						}
						cmd = cmd[:0]
					}
				case b == '\n':
					l := strings.TrimSuffix(string(line), "\r")
					if l == pw {
						l = "<pw>"
					}
					r.lines = append(r.lines, l)
					got = append(got, l)
					line = line[:0]
				default:
					line = append(line, b)
				}
			}
			if err != nil {
				r.readEnd = err
				if errors.Is(err, io.EOF) {
					r.finAt = now
				}
			}
		})
		for _, l := range got {
			lines <- l
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				close(fin)
			}
			return
		}
	}
}

func (f *farEnd) serve(c net.Conn) {
	defer c.Close()
	f.set(func(r *record) { r.client = c.RemoteAddr().String() })
	w := &writer{c: c, f: f}
	lines := make(chan string, 256)
	fin := make(chan struct{})
	go f.read(c, lines, fin)
	if f.sc.greet != nil {
		f.sc.greet(w)
	} else {
		w.data("\r\n=")
	}
	quis, pwNext := 0, false
	for l := range lines {
		if f.sc.onLine != nil {
			f.sc.onLine(l)
		}
		switch {
		case pwNext:
			pwNext = false
			if l == "<pw>" {
				w.data(pw) // the echo of the secret
				f.set(func(r *record) { r.echoes++ })
			}
			w.data("\r\n\x02" + header + "Level 1\r\n\x03=>")
		case l == "":
			w.data("\r\n=")
		case l == "QUI":
			if quis++; quis == 1 {
				w.data(frame("QUI", header, "="))
				continue
			}
			f.closePhase(c, w, fin)
			return
		case l == "ID":
			w.data(idReply)
		case l == "ACC":
			w.data("ACC\r\nPassword: ? ")
			pwNext = true
		case l == "SHO P 1":
			w.data(frame("SHO P 1", "Port 1\r\n\r\nMAXACC  := 1\r\nFASTOP  := N\r\nLANG    := ENGLISH\r\nEHTTP   := N\r\nFTPACC  := 1\r\nHTTPACC := 1\r\nTIDLE   := 15\r\n\r\n", "=>"))
		case l == "SHO G":
			w.data(frame("SHO G", "\r\nGlobal Settings\r\n\r\nPHROT    := ABC     FNOM    := 60      DATE_F := MDY\r\nIRIGC    := NONE    UTC_OFF := 0.00\r\n\r\n", "=>"))
		case l == "SER":
			w.data(frame("SER", serBody, "=>"))
		default:
			w.data(l + "\r\nInvalid Command\r\n=>")
		}
	}
}

// closePhase answers the close phase's QUI by the script.
func (f *farEnd) closePhase(c net.Conn, w *writer, fin <-chan struct{}) {
	f.set(func(r *record) { r.quiAt = time.Now() })
	awaitFIN := func() {
		select {
		case <-fin:
		case <-time.After(finWait):
		}
	}
	if f.sc.quiSilent {
		awaitFIN()
		if f.sc.probeReset {
			f.probeReset(c)
		}
		return
	}
	time.Sleep(f.sc.quiAfter)
	w.data(frame("QUI", header, "="))
	f.set(func(r *record) { r.replyAt = time.Now() })
	if f.sc.closeAtReply {
		return
	}
	awaitFIN()
	if f.sc.late != nil {
		f.sc.late(w)
		f.set(func(r *record) { r.lateSent = time.Now() })
	}
	switch f.sc.end {
	case closeRST:
		_ = c.(*net.TCPConn).SetLinger(0)
	case hold:
		select {
		case <-f.release:
		case <-time.After(serveFor):
		}
	}
}

// probeReset writes one octet after the client's FIN, waits, and writes
// another. A client that still reads acknowledges both; a closed socket
// answers the first with an RST, and the second write then fails.
func (f *farEnd) probeReset(c net.Conn) {
	_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, err1 := c.Write([]byte("x"))
	time.Sleep(300 * time.Millisecond)
	_, err2 := c.Write([]byte("y"))
	f.set(func(r *record) { r.resetSeen = err1 != nil || err2 != nil })
}

// inputs are a run's contract inputs, from the repository's fixtures.
type inputs struct {
	inv     adapter.Invocation
	asset   asset.Asset
	profile asset.CapabilityProfile
	reg     *register.Package
}

func readFile(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "..", p))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// load reads the fixtures for a Level 0 ID run, or with ser for a Level 1
// SER read, with every run's step and response limits set here.
func load(t *testing.T, ser bool) inputs {
	t.Helper()
	var in inputs
	var err error
	inv := "contracts/adapter/testdata/invocations/valid/sel-id-level0.json"
	if ser {
		inv = "contracts/adapter/testdata/invocations/valid/sel-ser-read.json"
	}
	if in.inv, err = adapter.DecodeInvocation(readFile(t, inv)); err != nil {
		t.Fatal(err)
	}
	in.inv.Limits.StepTimeoutMS = int64(step / time.Millisecond)
	in.inv.Limits.MaxResponseBytes = maxResp
	if in.asset, err = asset.Decode(readFile(t, "contracts/asset/testdata/valid/sel-751-simulated.json")); err != nil {
		t.Fatal(err)
	}
	if in.profile, err = asset.DecodeProfile(readFile(t, "contracts/asset/testdata/valid/profile-sel-751-ascii.json")); err != nil {
		t.Fatal(err)
	}
	if in.reg, err = register.Decode(readFile(t, "contracts/register/testdata/sel-751.json")); err != nil {
		t.Fatal(err)
	}
	return in
}

type secret struct{ uses int }

func (s *secret) Use(f func([]byte) error) error {
	if s.uses++; s.uses > 1 {
		return errors.New("used twice")
	}
	return f([]byte(pw))
}

func (s *secret) EchoSpans(rx []byte) [][2]int {
	var out [][2]int
	for i := 0; ; {
		j := bytes.Index(rx[i:], []byte(pw))
		if j < 0 {
			return out
		}
		out = append(out, [2]int{i + j, i + j + len(pw)})
		i += j + len(pw)
	}
}

type floor struct{}

func (floor) BeforeACC(context.Context) error { return nil }
func (floor) Confirmed(context.Context)       {}

// halfCloser is the test's HalfClose seam for runs that call sel751.Run
// directly. It does what §3.3 says the collector's does, CloseWrite on a
// *net.TCPConn and nothing else, and counts its calls.
type halfCloser struct {
	mu    sync.Mutex
	calls int
}

func (h *halfCloser) halfClose(c net.Conn) error {
	h.mu.Lock()
	h.calls++
	h.mu.Unlock()
	tc, ok := c.(*net.TCPConn)
	if !ok {
		return errors.New("not a TCP connection")
	}
	return tc.CloseWrite()
}

func (h *halfCloser) count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.calls
}

// runAdapter runs sel751.Run against f, with h as the HalfClose seam and no
// Rexmit seam, and returns the result and when Run returned.
func runAdapter(t *testing.T, f *farEnd, ser bool, h *halfCloser) (adapter.Result, time.Time) {
	t.Helper()
	in := load(t, ser)
	cfg := sel751.Config{
		Asset: in.asset, Profile: in.profile, Register: in.reg, Endpoint: in.inv.EndpointID,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, f.addr)
		},
		HalfClose: h.halfClose,
	}
	if ser {
		cfg.Secret, cfg.Floor = &secret{}, floor{}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	r := sel751.Run(ctx, in.inv, cfg)
	end := time.Now()
	checkResult(t, r, in)
	return r, end
}

// runRunner runs the plan through the collector's SEL751Runner, which sets
// both of C2 0.10's seams itself (§3.3), for a Level 0 ID run against f. The
// floor gate has no state: a Level 0 run reads only whether a login was
// confirmed. linger0 sets SO_LINGER 0 on the session's socket at dial time,
// for test 10's control.
func runRunner(t *testing.T, ctx context.Context, f *farEnd, linger0 bool) adapter.Result {
	t.Helper()
	in := load(t, false)
	var ep asset.Endpoint
	for _, e := range in.asset.Endpoints {
		if e.ID == in.inv.EndpointID {
			ep = e
		}
	}
	plan := collector.RunPlan{
		Invocation: in.inv, Asset: in.asset, Profile: in.profile, Endpoint: ep, Register: in.reg,
		Floor: collector.NewFloorGate(nil, in.asset.AssetID),
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			c, err := d.DialContext(ctx, network, f.addr)
			if err == nil && linger0 {
				err = c.(*net.TCPConn).SetLinger(0)
			}
			return c, err
		},
	}
	var rn collector.SEL751Runner
	rep := rn.Run(ctx, plan)
	r, err := adapter.DecodeResult(rep.Outcome.Result)
	if err != nil {
		t.Fatalf("the runner's result does not decode: %v", err)
	}
	checkResult(t, r, in)
	return r
}

func checkResult(t *testing.T, r adapter.Result, in inputs) {
	t.Helper()
	if err := r.Validate(); err != nil {
		t.Errorf("Validate: %v", err)
	}
	if err := r.CheckLines(in.reg, in.inv); err != nil {
		t.Errorf("CheckLines: %v", err)
	}
	if r.Session.Telnet == nil {
		t.Fatalf("a connected Telnet result without session.telnet: %+v", r.Session)
	}
}

func readToEOF(r adapter.Result) bool {
	return r.Session.Telnet != nil && r.Session.Telnet.ReadToEOF != nil && *r.Session.Telnet.ReadToEOF
}

func code(r adapter.Result) string {
	if r.Error == nil {
		return "ok"
	}
	return string(r.Error.Code)
}

// sentLines are the lines the transcript says were sent, the credential
// slot as "<pw>".
func sentLines(r adapter.Result) []string {
	var out []string
	for _, sg := range r.Transcript.Segments {
		if sg.Dir != adapter.Sent {
			continue
		}
		l := strings.TrimSuffix(string(r.Transcript.Data[sg.Offset:sg.Offset+sg.Length]), "\r\n")
		if l == adapter.RedactionMarker {
			l = "<pw>"
		}
		out = append(out, l)
	}
	return out
}

// received is the transcript's received octets, with each echo already
// replaced by the 10-octet marker.
func received(r adapter.Result) int64 {
	var n int64
	for _, sg := range r.Transcript.Segments {
		if sg.Dir == adapter.Received {
			n += sg.Length
		}
	}
	return n
}

// passive is §8 test 7's passive proof, from the far side. Every octet the
// relay received is a line the transcript sent (the credential as itself)
// or a refusal the far end counted, so the client sent nothing else (§1.1).
// When the client half-closed, its FIN came after QUI's reply and no octet
// came after that reply: the half-close sends a FIN and no data octet or
// command (§1.3 condition 2), and a refusal asked for after it is not
// written (condition 6).
func passive(t *testing.T, r adapter.Result, rec record, halfClosed bool) {
	t.Helper()
	want := sentLines(r)
	if strings.Join(rec.lines, "|") != strings.Join(want, "|") {
		t.Errorf("the far end received the lines %q, the transcript sent %q", rec.lines, want)
	}
	wire := 0
	for _, l := range want {
		if l == "<pw>" {
			l = pw
		}
		wire += len(l) + 2
	}
	if got := len(rec.rx); got != wire+3*rec.refusals || rec.otherCmds != 0 {
		t.Errorf("the far end received %d octets, want %d: the transcript's lines and %d refusals (and %d other commands)",
			got, wire+3*rec.refusals, rec.refusals, rec.otherCmds)
	}
	if !halfClosed {
		return
	}
	switch {
	case rec.finAt.IsZero():
		t.Errorf("no FIN from the client after QUI's reply (the far end's read ended with %v)", rec.readEnd)
	case rec.finAt.Before(rec.replyAt):
		t.Errorf("the client's FIN came before QUI's reply")
	}
	if rec.rxAfterReply != 0 {
		t.Errorf("the far end received %d octets from the client after QUI's reply", rec.rxAfterReply)
	}
}
