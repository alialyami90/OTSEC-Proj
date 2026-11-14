package sel751

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"otsec.local/otsec/contracts/adapter"
)

// C2 0.10's session.telnet and the half-close (D4-102; D2-c2-0.10 §1.3,
// §3.2), driven over net.Pipe with a scripted far end. The half-close is the
// collector's seam, so here it is a stub that shuts sock's write side: every
// later Write fails locally, as EPIPE or WSAESHUTDOWN would, and nothing
// reaches the far end. Simulated evidence only.

// sock is the near end: a pipe with a TCP local address, a write side the
// HalfClose stub shuts, and a log of what Run did to it, in order.
type sock struct {
	net.Conn
	shut   bool
	half   chan struct{}
	events []string
}

func newSock(c net.Conn) *sock { return &sock{Conn: c, half: make(chan struct{})} }

func (s *sock) LocalAddr() net.Addr { return localAddr }

func (s *sock) event(e string) {
	if n := len(s.events); n == 0 || s.events[n-1] != e {
		s.events = append(s.events, e)
	}
}

func (s *sock) Read(b []byte) (int, error) {
	n, err := s.Conn.Read(b)
	if n > 0 || (err != nil && !isTimeout(err)) {
		s.event("read")
	}
	return n, err
}

func (s *sock) Write(b []byte) (int, error) {
	if s.shut {
		s.event("write refused")
		return 0, errors.New("test: the write side is shut")
	}
	s.event("write")
	return s.Conn.Write(b)
}

func (s *sock) Close() error { s.event("close"); return s.Conn.Close() }

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// halfClose is the HalfClose stub. It counts its calls.
func halfClose(calls *int) func(net.Conn) error {
	return func(nc net.Conn) error {
		*calls++
		s := nc.(*sock)
		s.event("halfclose")
		s.shut = true
		close(s.half)
		return nil
	}
}

// rexmit is the Rexmit stub: it answers octets or unknown, and checks it is
// given the connection Dial returned.
func rexmit(t *testing.T, octets int64, unknown string, calls *int) func(net.Conn) (int64, string) {
	return func(nc net.Conn) (int64, string) {
		*calls++
		s, ok := nc.(*sock)
		if !ok {
			t.Errorf("Rexmit given %T, not the dialled connection", nc)
		} else {
			s.event("rexmit")
		}
		return octets, unknown
	}
}

// farTail is what the far end does after the script's last reply. half is
// closed when Run half-closes.
type farTail func(c net.Conn, half <-chan struct{}) error

// playThen plays steps on c like farEnd, waits lastDelay before the last reply,
// reports when it read the last line in quiAt, then runs tail.
func playThen(c net.Conn, steps []step, lastDelay time.Duration, half <-chan struct{}, quiAt *time.Time, tail farTail) <-chan error {
	done := make(chan error, 1)
	go func() {
		defer c.Close()
		for i, st := range steps {
			if len(st.expect) > 0 {
				got := make([]byte, len(st.expect))
				_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
				if _, err := io.ReadFull(c, got); err != nil || !bytes.Equal(got, st.expect) {
					done <- fmt.Errorf("turn %d: received %q (%v), want %q", i, got, err, st.expect)
					return
				}
			}
			if i == len(steps)-1 {
				*quiAt = time.Now()
				time.Sleep(lastDelay)
			}
			if len(st.reply) > 0 {
				_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
				if _, err := c.Write(st.reply); err != nil {
					done <- fmt.Errorf("turn %d: %v", i, err)
					return
				}
			}
		}
		done <- tail(c, half)
	}()
	return done
}

// afterHalf waits for the half-close, then sends b, then: closes when hold
// is false, or reads until Run closes when it is true. Either way nothing
// may arrive from Run after the half-close (the passive proof).
func afterHalf(b []byte, hold bool) farTail {
	return func(c net.Conn, half <-chan struct{}) error {
		select {
		case <-half:
		case <-time.After(5 * time.Second):
			return errors.New("no half-close")
		}
		if len(b) > 0 {
			_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if _, err := c.Write(b); err != nil {
				return err
			}
		}
		if !hold {
			return nil
		}
		return readNothing(c)
	}
}

// readNothing reads until Run closes, and fails on any octet.
func readNothing(c net.Conn) error {
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	extra, _ := io.ReadAll(c)
	if len(extra) > 0 {
		return fmt.Errorf("received %q after the script", extra)
	}
	return nil
}

type closeCase struct {
	steps     []step
	step      time.Duration // step_timeout_ms
	lastDelay time.Duration
	tail      farTail
	halfClose bool
	rexmit    func(net.Conn) (int64, string)
	ctx       context.Context // Run's context; Background when nil
}

type closeRun struct {
	res        adapter.Result
	sock       *sock
	quiAt, end time.Time
	halfCalls  int
}

func runClose(t *testing.T, c closeCase) closeRun {
	t.Helper()
	f := load(t)
	if c.step > 0 {
		f.inv.Limits.StepTimeoutMS = int64(c.step / time.Millisecond)
	}
	near, far := net.Pipe()
	var out closeRun
	out.sock = newSock(near)
	cfg := Config{Asset: f.asset, Profile: f.profile, Register: f.reg, Endpoint: f.inv.EndpointID,
		Secret: &secret{b: []byte(testSecret)}, Floor: &floor{}, Now: clock(),
		hooks:  &hooks{quiet: 20 * time.Millisecond, wakeWait: 50 * time.Millisecond},
		Dial:   func(context.Context, string, string) (net.Conn, error) { return out.sock, nil },
		Rexmit: c.rexmit}
	if c.halfClose {
		cfg.HalfClose = halfClose(&out.halfCalls)
	}
	done := playThen(far, c.steps, c.lastDelay, out.sock.half, &out.quiAt, c.tail)
	ctx := c.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	out.res = Run(ctx, f.inv, cfg)
	out.end = time.Now()
	if err := <-done; err != nil {
		t.Errorf("far end: %v", err)
	}
	check(t, f, out.res)
	return out
}

func telnetOf(t *testing.T, r adapter.Result) adapter.TelnetFacts {
	t.Helper()
	if r.Session.Telnet == nil {
		t.Fatal("no session.telnet")
	}
	return *r.Session.Telnet
}

func okSteps(t *testing.T) []step { return script(golden(t, "ok")) }

// The relay closes after the half-close, having sent more first: those
// octets join QUI's reply, and read_to_eof is true. The control is the same
// relay with no HalfClose: Run closes as before 0.10, the relay never sees
// a FIN before the close, and read_to_eof is false.
func TestHalfCloseReadsToEOF(t *testing.T) {
	late := []byte("\r\nlate octets\r\n")
	var rx int
	r := runClose(t, closeCase{steps: okSteps(t), tail: afterHalf(late, false), halfClose: true,
		rexmit: rexmit(t, 7, "", &rx)})
	tf := telnetOf(t, r.res)
	if !*tf.ReadToEOF {
		t.Error("read_to_eof false after the relay closed")
	}
	if r.halfCalls != 1 || rx != 1 || tf.RexmitOctets == nil || *tf.RexmitOctets != 7 || tf.RexmitUnknown != "" {
		t.Errorf("half-close %d, Rexmit %d, facts %+v", r.halfCalls, rx, tf)
	}
	segs := r.res.Transcript.Segments
	last := segs[len(segs)-1]
	if last.Phase != adapter.PhaseClose || last.Dir != adapter.Received ||
		!bytes.HasSuffix(r.res.Transcript.Data[last.Offset:last.Offset+last.Length], late) {
		t.Errorf("the late octets are not the end of QUI's reply segment: %+v", last)
	}
	if got, want := strings.Join(r.sock.events, ","), "write,read,halfclose,read,rexmit,close"; !strings.HasSuffix(got, want) {
		t.Errorf("events %s, want them to end %s", got, want)
	}

	r = runClose(t, closeCase{steps: okSteps(t), tail: func(c net.Conn, _ <-chan struct{}) error { return readNothing(c) }})
	tf = telnetOf(t, r.res)
	if *tf.ReadToEOF || r.halfCalls != 0 || tf.RexmitOctets != nil || tf.RexmitUnknown != adapter.RexmitUnsupported {
		t.Errorf("control, no HalfClose and no Rexmit: %+v", tf)
	}
}

// A relay that neither closes nor sends after the half-close: the close
// phase ends at QUI's send plus one step, the end QUI's own reply had, and
// not one step after the reply (D3's and D6's B2 on #671). The relay
// answers QUI at half a step. A fresh step after the reply would end at 1.5
// steps; the run as before 0.10 would end at half a step plus the quiet
// interval.
func TestHalfCloseEndsWithQUIStep(t *testing.T) {
	const step = 600 * time.Millisecond
	r := runClose(t, closeCase{steps: okSteps(t), step: step, lastDelay: step / 2,
		tail: afterHalf(nil, true), halfClose: true})
	tf := telnetOf(t, r.res)
	if *tf.ReadToEOF || r.halfCalls != 1 || r.res.Error != nil {
		t.Errorf("facts %+v, half-close %d, error %+v", tf, r.halfCalls, r.res.Error)
	}
	if took := r.end.Sub(r.quiAt); took < step-50*time.Millisecond || took > step+200*time.Millisecond {
		t.Errorf("the close phase took %v after QUI, want about one step, %v", took, step)
	}
}

// A DO after the half-close: its refusal cannot be written, so nothing
// reaches the relay, the refusal is not counted, the session ends on that
// error, and read_to_eof is false though the relay then closes.
func TestHalfCloseRefusalUnwritten(t *testing.T) {
	do := []byte{0xFF, 0xFD, 0x01}
	r := runClose(t, closeCase{steps: okSteps(t), halfClose: true, tail: func(c net.Conn, half <-chan struct{}) error {
		if err := afterHalf(do, false)(c, half); err != nil {
			return err
		}
		return readNothing(c)
	}})
	tf := telnetOf(t, r.res)
	if *tf.ReadToEOF || *tf.Refusals != 0 || *tf.CommandOctetsReceived != 3 {
		t.Errorf("facts %+v, want no EOF, no refusal and the DO's 3 octets", tf)
	}
	if !strings.Contains(strings.Join(r.sock.events, ","), "halfclose,read,write refused") {
		t.Errorf("events %v", r.sock.events)
	}
}

// No half-close unless QUI's reply ended in a prompt: here the relay never
// answers QUI. The run is as before 0.10: QUI's step times out and the
// socket closes. The control is TestHalfCloseReadsToEOF's first run.
func TestNoHalfCloseWithoutQUIPrompt(t *testing.T) {
	steps := okSteps(t)
	steps[len(steps)-1].reply = nil
	r := runClose(t, closeCase{steps: steps, step: 300 * time.Millisecond, halfClose: true,
		tail: func(c net.Conn, _ <-chan struct{}) error { return readNothing(c) }})
	tf := telnetOf(t, r.res)
	if r.halfCalls != 0 || *tf.ReadToEOF || !r.res.Session.QuitSent {
		t.Errorf("half-close %d, facts %+v, quit_sent %v", r.halfCalls, tf, r.res.Session.QuitSent)
	}
}

// The counts: a relay that offers two options, sends a NOP and a
// subnegotiation before its first prompt. Two refusals, 3 + 3 + 2 + 6
// command octets. The refusals reach the relay before QUI.
func TestTelnetCounts(t *testing.T) {
	steps := okSteps(t)
	neg := []byte{0xFF, 0xFB, 1, 0xFF, 0xFD, 24, 0xFF, 0xF1, 0xFF, 0xFA, 24, 1, 0xFF, 0xF0}
	steps[1].reply = append(append([]byte(nil), neg...), steps[1].reply...)
	steps[2].expect = append([]byte{0xFF, 0xFE, 1, 0xFF, 0xFC, 24}, steps[2].expect...)
	var rx int
	r := runClose(t, closeCase{steps: steps, rexmit: rexmit(t, 0, adapter.RexmitInFlight, &rx),
		tail: func(c net.Conn, _ <-chan struct{}) error { return readNothing(c) }})
	tf := telnetOf(t, r.res)
	if *tf.Refusals != 2 || *tf.CommandOctetsReceived != 14 {
		t.Errorf("refusals %d, command octets %d, want 2 and 14", *tf.Refusals, *tf.CommandOctetsReceived)
	}
	if rx != 1 || tf.RexmitOctets != nil || tf.RexmitUnknown != adapter.RexmitInFlight {
		t.Errorf("Rexmit %d, facts %+v, want the token copied and no count", rx, tf)
	}
}

// Rexmit is called once on a path that ends without QUI, after the last
// read and before the close (C2 0.10 §3.2).
func TestRexmitWithoutQUI(t *testing.T) {
	var rx int
	r := runClose(t, closeCase{steps: script(golden(t, "failed.auth_rejected")), halfClose: true,
		rexmit: rexmit(t, 0, "", &rx), tail: func(c net.Conn, _ <-chan struct{}) error { return readNothing(c) }})
	tf := telnetOf(t, r.res)
	if r.res.Error == nil || r.res.Error.Code != adapter.FailedAuthRejected || r.res.Session.QuitSent {
		t.Fatalf("not the auth_rejected run: %+v", r.res.Error)
	}
	if rx != 1 || r.halfCalls != 0 || *tf.ReadToEOF || tf.RexmitOctets == nil || *tf.RexmitOctets != 0 {
		t.Errorf("Rexmit %d, half-close %d, facts %+v", rx, r.halfCalls, tf)
	}
	if got := strings.Join(r.sock.events, ","); !strings.HasSuffix(got, "read,rexmit,close") {
		t.Errorf("events %s", got)
	}
}

// QUI's reply ends in a prompt of a level no earlier prompt showed, here
// "=>>". When octets follow it after the FIN, that prompt is no longer the
// reply's suffix, and it counts in neither the adapter's access_level nor
// Validate (C2 0.10 §1.3 condition 4; D6's B1 on #684). runClose checks
// that each result passes Validate. The control is the reply with nothing
// after the FIN: the prompt is the suffix and counts, access_level "2".
func TestQUIPromptCountsOnlyAsSuffix(t *testing.T) {
	for _, c := range []struct {
		name  string
		late  []byte
		hold  bool
		level string
		eof   bool
	}{
		{"nothing after the FIN, the relay closes (control)", nil, false, "2", true},
		{"octets after the FIN, the relay closes", []byte("\r\nX"), false, "1", true},
		{"octets after the FIN, the relay holds", []byte("\r\nX"), true, "1", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			steps := okSteps(t)
			steps[len(steps)-1].reply = []byte("\r\n=>>")
			r := runClose(t, closeCase{steps: steps, step: 300 * time.Millisecond,
				tail: afterHalf(c.late, c.hold), halfClose: true})
			tf := telnetOf(t, r.res)
			if r.halfCalls != 1 || *tf.ReadToEOF != c.eof || r.res.Error != nil {
				t.Errorf("half-close %d, facts %+v, error %+v", r.halfCalls, tf, r.res.Error)
			}
			if got := r.res.Session.AccessLevel; got != c.level {
				t.Errorf("access_level %q, want %q", got, c.level)
			}
		})
	}
}

// A relay that closes right after QUI's prompt ends the transport within
// QUI's await: no half-close is made on a dead session (D6's N1 on #684).
// The control is TestHalfCloseReadsToEOF's first run, with one half-close.
func TestNoHalfCloseWhenDead(t *testing.T) {
	r := runClose(t, closeCase{steps: okSteps(t), halfClose: true,
		tail: func(net.Conn, <-chan struct{}) error { return nil }})
	tf := telnetOf(t, r.res)
	if r.halfCalls != 0 {
		t.Errorf("%d half-closes on a session whose transport had ended", r.halfCalls)
	}
	if !*tf.ReadToEOF || !r.res.Session.QuitSent {
		t.Errorf("facts %+v, quit_sent %v", tf, r.res.Session.QuitSent)
	}
}

// readToEnd ends at EOF and at any other error, not at QUI's step end (D6's
// N2 on #684): the relay closes after the FIN, or sends a DO whose refusal
// cannot be written and then holds. Each run returns well before QUI's step
// ends.
func TestReadToEndEndsAtEOFOrError(t *testing.T) {
	const step = 3 * time.Second
	for _, c := range []struct {
		name string
		tail farTail
		eof  bool
	}{
		{"EOF", afterHalf([]byte("\r\nlate\r\n"), false), true},
		{"error", afterHalf([]byte{0xFF, 0xFD, 0x01}, true), false},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := runClose(t, closeCase{steps: okSteps(t), step: step, tail: c.tail, halfClose: true})
			tf := telnetOf(t, r.res)
			if r.halfCalls != 1 || *tf.ReadToEOF != c.eof {
				t.Errorf("half-close %d, facts %+v", r.halfCalls, tf)
			}
			if took := r.end.Sub(r.quiAt); took > step/3 {
				t.Errorf("the close phase took %v after QUI, want it to end at the %s, well before the step %v", took, c.name, step)
			}
		})
	}
}

// readToEnd ends at the context, which carries the pipeline's hard timeout
// (Pipeline.execute): cancelled during the close phase, with the relay
// holding, Run returns at once, not at QUI's step end (D6's N2 on #684).
func TestReadToEndEndsAtContext(t *testing.T) {
	const step = 3 * time.Second
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var cancelAt time.Time
	r := runClose(t, closeCase{steps: okSteps(t), step: step, halfClose: true, ctx: ctx,
		tail: func(c net.Conn, half <-chan struct{}) error {
			select {
			case <-half:
			case <-time.After(5 * time.Second):
				return errors.New("no half-close")
			}
			time.Sleep(100 * time.Millisecond) // readToEnd is waiting by now
			cancelAt = time.Now()
			cancel()
			return readNothing(c)
		}})
	tf := telnetOf(t, r.res)
	if r.halfCalls != 1 || *tf.ReadToEOF {
		t.Errorf("half-close %d, facts %+v", r.halfCalls, tf)
	}
	if took := r.end.Sub(cancelAt); took > 500*time.Millisecond {
		t.Errorf("Run returned %v after the context ended, want at once (QUI's step is %v)", took, step)
	}
}
