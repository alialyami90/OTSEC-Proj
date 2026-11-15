package c2telnet

// C2 0.10's test 7 (docs/phase4/D2-c2-0.10-proposal.md §8): the adapter's
// counts and close step from outside the adapter, against D6's far end on
// a loopback TCP socket. Each run but the runner's calls sel751.Run with a
// HalfClose seam that does what §3.3 says the collector's does; the runner's
// leg uses the collector's own seams.

import (
	"context"
	"strings"
	"testing"
	"time"

	"otsec.local/otsec/contracts/adapter"
)

// The close step's margins, pinned before the run (§8 test 7, D3's and D6's
// B2). The close phase must end by QUI's send plus one step_timeout_ms; it
// is measured from the far end's receipt of QUI to Run's return. stepEarly
// allows for the far end receiving QUI after the adapter's step began, and
// stepLate for the Rexmit call and the result after the read ends. The
// fresh-stepEnd mutant ends at about step/2 + quiet + step, 3.2 s here.
const (
	stepEarly = 200 * time.Millisecond
	stepLate  = 600 * time.Millisecond
)

// TestC2v10T7Counts: refusals and command_octets_received equal what the
// far end received and sent, and on a run that reads to EOF, with an echo
// of the secret, the transcript's received octets + command_octets_received
// + Σ (p − 10) equal every octet the far end sent (§1.1, §1.2, D4's N3).
func TestC2v10T7Counts(t *testing.T) {
	f := newFarEnd(t, script{
		greet: func(w *writer) {
			w.cmd(0xff, 0xfb, 0x01)                   // IAC WILL ECHO: refused
			w.cmd(0xff, 0xfd, 0x18)                   // IAC DO TTYPE: refused
			w.cmd(0xff, 0xfa, 0x18, 0x01, 0xff, 0xf0) // IAC SB TTYPE SEND IAC SE
			w.cmd(0xff, 0xf1)                         // IAC NOP
			w.cmd(0xff, 0xfb, 0x01)                   // IAC WILL ECHO again: not answered twice (RFC 854)
			w.data("\r\n=")
		},
		late: func(w *writer) {
			w.data("\r\nlate \xff octets")                       // an escaped 0xFF: one data octet, two on the wire
			w.cmd(0xff, 0xf1)                                    // IAC NOP
			w.cmd(0xff, 0xfa, 0x18, 0x00, 'x', 0xff, 0xf0)       // a subnegotiation, which needs no answer
			w.data("\r\nmore late octets, then the relay's FIN") // data after the commands
		},
	})
	h := &halfCloser{}
	r, _ := runAdapter(t, f, true, h)
	rec := f.wait(t, 10*time.Second)
	passive(t, r, rec, true)
	if code(r) != "ok" || h.count() != 1 || rec.writeErr != nil {
		t.Fatalf("code %s, %d half-closes, far end write error %v: want an ok run with one half-close", code(r), h.count(), rec.writeErr)
	}
	if !readToEOF(r) {
		t.Fatalf("read_to_eof false, but the far end closed after its late octets: the equalities hold only on a run that reads to EOF")
	}
	tf := r.Session.Telnet
	if rec.refusals != 2 || *tf.Refusals != int64(rec.refusals) {
		t.Errorf("refusals %d; the far end received %d, and offered 2 options", *tf.Refusals, rec.refusals)
	}
	if want := rec.wire - rec.data; *tf.CommandOctetsReceived != want {
		t.Errorf("command_octets_received %d; the far end sent %d octets, %d of them data: want %d",
			*tf.CommandOctetsReceived, rec.wire, rec.data, want)
	}
	echoes := 0
	for _, rd := range r.Transcript.Redactions {
		if rd.Reason == adapter.RedactEcho {
			echoes++
		}
	}
	if rec.echoes != 1 || echoes != rec.echoes {
		t.Errorf("%d echoes redacted; the far end echoed the secret %d times", echoes, rec.echoes)
	}
	sum := received(r) + *tf.CommandOctetsReceived + int64(rec.echoes)*int64(len(pw)-len(adapter.RedactionMarker))
	if sum != rec.wire {
		t.Errorf("received %d + command_octets_received %d + %d x (%d - %d) = %d; the far end sent %d",
			received(r), *tf.CommandOctetsReceived, rec.echoes, len(pw), len(adapter.RedactionMarker), sum, rec.wire)
	}
	t.Logf("far end: %d octets sent, %d data, %d refusals received; result: refusals %d, command_octets_received %d, transcript received %d",
		rec.wire, rec.data, rec.refusals, *tf.Refusals, *tf.CommandOctetsReceived, received(r))
}

// TestC2v10T7EOF: read_to_eof by how the relay ends the close phase (§1.3
// conditions 1, 3 and 6). Each relay that should give false still closes
// with a FIN after it, except the RST case, so a client that ignored the
// cause would read EOF and report true.
func TestC2v10T7EOF(t *testing.T) {
	cases := []struct {
		name       string
		sc         script
		want       bool
		halfClosed bool // the far end must see a FIN after QUI's reply and no octet
		check      func(t *testing.T, r adapter.Result, rec record)
	}{
		{
			name: "closes after the half-close",
			sc:   script{late: func(w *writer) { w.data("\r\nlate octets") }},
			want: true, halfClosed: true,
			check: func(t *testing.T, r adapter.Result, rec record) {
				// The late octets are read, not answered with an RST, and they
				// end QUI's reply (§1.3 condition 4). With no "=>" in them,
				// access_level stays "0": the twin of the level-prompt test.
				last := r.Transcript.Segments[len(r.Transcript.Segments)-1]
				seg := string(r.Transcript.Data[last.Offset : last.Offset+last.Length])
				if last.Dir != adapter.Received || !strings.HasPrefix(seg, "QUI\r\n") || !strings.HasSuffix(seg, "late octets") {
					t.Errorf("the last segment is %s %q: want QUI's reply ending in the late octets", last.Dir, seg)
				}
				if r.Session.AccessLevel != "0" {
					t.Errorf("access_level %q, want \"0\"", r.Session.AccessLevel)
				}
			},
		},
		{
			name: "closes before the half-close",
			sc:   script{closeAtReply: true},
			want: true,
		},
		{
			name: "RST after the half-close",
			sc:   script{end: closeRST},
			want: false, halfClosed: true,
		},
		{
			name: "DO after the half-close",
			// IAC DO NAWS, an option not offered before, so the transport
			// tries to refuse it. The write side is shut, so nothing goes on
			// the wire, the refusal is not counted, and the error is sticky
			// (§1.1, §1.3 condition 6).
			sc:   script{late: func(w *writer) { w.cmd(0xff, 0xfd, 0x1f) }},
			want: false, halfClosed: true,
			check: func(t *testing.T, r adapter.Result, rec record) {
				if *r.Session.Telnet.Refusals != int64(rec.refusals) || rec.refusals != 0 {
					t.Errorf("refusals %d; the far end received %d, and the only offer came after the FIN",
						*r.Session.Telnet.Refusals, rec.refusals)
				}
			},
		},
		{
			name: "more than MaxCommands after the half-close",
			sc: script{late: func(w *writer) {
				for range 65 { // sel751 maxCommands is 64 per session
					w.cmd(0xff, 0xf1) // IAC NOP
				}
			}},
			want: false, halfClosed: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFarEnd(t, c.sc)
			r, _ := runAdapter(t, f, false, &halfCloser{})
			rec := f.wait(t, 10*time.Second)
			passive(t, r, rec, c.halfClosed)
			if code(r) != "ok" {
				t.Errorf("code %s: the close phase changes no code", code(r))
			}
			if got := readToEOF(r); got != c.want {
				t.Errorf("read_to_eof %v, want %v", got, c.want)
			}
			if c.check != nil {
				c.check(t, r, rec)
			}
		})
	}
}

// TestC2v10T7OverCloseAllowance: relay octets after the half-close that go
// past max_response_bytes + closeAllowance end the read at the budget, the
// first of §1.3 condition 3's ends, and not at QUI's step end; read_to_eof
// is false. The relay then holds the connection, so only the budget can end
// the read early (D2's note on readToEnd's s.total < s.budget, #684).
func TestC2v10T7OverCloseAllowance(t *testing.T) {
	f := newFarEnd(t, script{
		late: func(w *writer) { w.data(strings.Repeat("a", maxResp+allow)) },
		end:  hold,
	})
	r, ranAt := runAdapter(t, f, false, &halfCloser{})
	rec := f.wait(t, 10*time.Second)
	passive(t, r, rec, true)
	if readToEOF(r) {
		t.Errorf("read_to_eof true after relay octets over the close allowance")
	}
	if n := received(r); n > maxResp+allow {
		t.Errorf("the transcript holds %d received octets, over %d + %d", n, maxResp, allow)
	}
	if d := ranAt.Sub(rec.quiAt); d >= step/2 {
		t.Errorf("Run returned %v after QUI; at the budget it must end at once, not at QUI's step end (%v)", d, step)
	}
}

// TestC2v10T7CloseStepEnd: the relay answers QUI at half a step and then
// neither closes nor sends. read_to_eof is false, and the close phase ends
// by QUI's send plus one step_timeout_ms, within the margins pinned above
// (§1.3 condition 3; D3's and D6's B2). Its control is the fresh-stepEnd
// mutant, which ends at about 1.5 steps plus the quiet interval.
func TestC2v10T7CloseStepEnd(t *testing.T) {
	f := newFarEnd(t, script{quiAfter: step / 2, end: hold})
	h := &halfCloser{}
	r, ranAt := runAdapter(t, f, false, h)
	rec := f.wait(t, 10*time.Second)
	passive(t, r, rec, true)
	if readToEOF(r) || h.count() != 1 {
		t.Errorf("read_to_eof %v with %d half-closes: want false after one half-close", readToEOF(r), h.count())
	}
	d := ranAt.Sub(rec.quiAt)
	if d < step-stepEarly || d > step+stepLate {
		t.Errorf("the close phase took %v after QUI; want QUI's send + one step (%v), within -%v and +%v", d, step, stepEarly, stepLate)
	}
	t.Logf("the close phase took %v after QUI (step %v)", d, step)
}

// TestC2v10T7NoHalfCloseWithoutReply: QUI gets no reply, so there is no
// half-close (§1.3 condition 1), and the relay's octet after the client's
// FIN draws an RST, as on main: the socket is closed whole.
func TestC2v10T7NoHalfCloseWithoutReply(t *testing.T) {
	f := newFarEnd(t, script{quiSilent: true, probeReset: true})
	h := &halfCloser{}
	r, _ := runAdapter(t, f, false, h)
	rec := f.wait(t, 10*time.Second)
	passive(t, r, rec, false)
	if h.count() != 0 {
		t.Errorf("%d half-closes after a QUI with no reply", h.count())
	}
	if readToEOF(r) {
		t.Errorf("read_to_eof true after a QUI with no reply")
	}
	switch {
	case rec.finAt.IsZero():
		t.Errorf("no FIN from the client (the far end's read ended with %v)", rec.readEnd)
	case rec.finAt.Sub(rec.quiAt) < step-stepEarly:
		t.Errorf("the client's FIN came %v after QUI, before QUI's step (%v) ended", rec.finAt.Sub(rec.quiAt), step)
	}
	if !rec.resetSeen {
		t.Errorf("the far end's octet after the client's FIN drew no RST: the client still reads")
	}
}

// TestC2v10T7LevelPromptAfterFIN: the relay's octets after the FIN end in
// "=>". They are part of QUI's reply, so access_level shows Level 1, and the
// result's code is unchanged (§1.3 condition 4). The twin with no "=>" is
// the first case of TestC2v10T7EOF, at "0".
func TestC2v10T7LevelPromptAfterFIN(t *testing.T) {
	f := newFarEnd(t, script{late: func(w *writer) { w.data("\r\n=>") }})
	r, _ := runAdapter(t, f, false, &halfCloser{})
	rec := f.wait(t, 10*time.Second)
	passive(t, r, rec, true)
	if !readToEOF(r) {
		t.Errorf("read_to_eof false, but the relay closed")
	}
	if r.Session.AccessLevel != "1" {
		t.Errorf("access_level %q, want \"1\" from the prompt after the FIN", r.Session.AccessLevel)
	}
	if code(r) != "ok" {
		t.Errorf("code %s, want ok: the adapter acts on nothing after QUI", code(r))
	}
}

// TestC2v10T7Runner: one leg through the collector's SEL751Runner.Run,
// which sets the HalfClose and Rexmit seams itself (§3.3). A runner whose
// HalfClose were nil would degrade silently to read_to_eof false, which the
// node takes as "not judged" and which raises no alert; against a relay
// that closes after the FIN it must be true.
func TestC2v10T7Runner(t *testing.T) {
	f := newFarEnd(t, script{late: func(w *writer) { w.data("\r\nlate octets") }})
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	r := runRunner(t, ctx, f, false)
	rec := f.wait(t, 10*time.Second)
	passive(t, r, rec, true)
	if !readToEOF(r) {
		t.Errorf("read_to_eof false through the runner, against a relay that closes after the FIN")
	}
	tf := r.Session.Telnet
	t.Logf("code %s, read_to_eof %v, rexmit_octets %v, rexmit_unknown %q", code(r), readToEOF(r), deref(tf.RexmitOctets), tf.RexmitUnknown)
}

func deref(p *int64) any {
	if p == nil {
		return nil
	}
	return *p
}
