package sensorlink

import (
	"strings"
	"testing"

	"otsec.local/otsec/contracts/netobs"
)

// noAckAfter fails if the node sent any ack after the decision: the acks
// channel closes when the connection does.
func (p *peer) noAckAfter() {
	p.t.Helper()
	for a := range p.acks {
		p.t.Errorf("ack %s sent after the decision", a.Seq)
	}
}

// D6's B1 (ii) on #732: an observation whose marked cursor cannot be
// encoded (above MaxLinkCursorBytes) is the node's fault, not the record's
// refusal. It is not stored, counted or acked, T stays, and the connection
// closes position-not-saved with its alarm. The stored cursor stands in
// for the node's fault: one unmarked prior span, its marking 14 bytes,
// padded so the marked cursor is one byte over the bound. Controls: the
// cursor padded so the marked one is at the bound (6 of 6 stored and
// acked); main's code (6 of 6 refused stored, T at 6, acked through 6).
func TestCursorEncodeFailureNotFinal(t *testing.T) {
	for _, over := range []bool{true, false} {
		t.Run(map[bool]string{true: "over", false: "control"}[over], func(t *testing.T) {
			r := newRig(t, nil)
			r.accepted(hello02()).end()
			c := cursorNow(t, r.cs)
			c.Prior.Spans = []HeldSpan{{FromUTC: "2026-11-07T09:00:00Z", ToUTC: "2026-11-07T09:01:00Z", CutUTC: "2026-11-07T09:01:00Z"}}
			mark := len(`,"marked":true`)
			target := MaxLinkCursorBytes - mark
			if over {
				target++
			}
			c.Prior.StartedBy += strings.Repeat("x", target-len(mustJSON(t, c)))
			b := mustJSON(t, c)
			if len(b) != target {
				t.Fatalf("padded to %d, want %d", len(b), target)
			}
			if err := r.cs.SaveSourceCursor(bg, b); err != nil {
				t.Fatal(err)
			}
			p := r.accepted(resume(1, 20))
			for i := 1; i <= 6; i++ {
				// The over leg closes at the first: the rest are written
				// until the pipe is closed, never read.
				if err := netobs.WriteFrame(p.c, mustJSON(t, obs02(i))); err != nil {
					break
				}
			}
			if !over {
				p.ack(6)
				if n := len(storedObs(t, r.s)); n != 6 {
					t.Fatalf("%d stored", n)
				}
				return
			}
			if got := p.closed(); got != netobs.ClosePositionNotSaved || r.al.count(AlarmPositionNotSaved) != 1 {
				t.Fatalf("close %q, raises %v", got, r.al.list)
			}
			p.noAckAfter()
			if n := len(storedObs(t, r.s)); n != 0 {
				t.Fatalf("%d stored", n)
			}
			if s := r.l.Stats(); s.Refused[RefusedStored] != 0 {
				t.Fatalf("refused stored: %v", s.Refused)
			}
			if c := cursorNow(t, r.cs); c.Taken != 0 || c.Refused != 0 || c.Dropped != 0 {
				t.Fatalf("cursor moved: T %d, refused %d, dropped %d", c.Taken, c.Refused, c.Dropped)
			}
		})
	}
}
