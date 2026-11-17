package sensorlink

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"otsec.local/otsec/contracts/netobs"
)

// closedWithin waits at most d for the node's close reason, and fails when
// the connection is still open.
func (p *peer) closedWithin(d time.Duration) string {
	p.t.Helper()
	select {
	case r := <-p.done:
		return r
	case <-time.After(d):
		p.t.Fatalf("the connection is still open %v after the decision", d)
		return ""
	}
}

// noAckAfter fails if the node sent any ack after the decision: the acks
// channel closes when the connection does.
func (p *peer) noAckAfter() {
	p.t.Helper()
	for a := range p.acks {
		p.t.Errorf("ack %s sent after the decision", a.Seq)
	}
}

// D3's B2 on #732, CH-37 steps 1 and 2: a decision (CloseConn) made while
// a frame is acted on is followed by no ack, and the connection closes at
// once with the sensor silent, not at the next frame or Idle. Controls:
// the hook not armed (the tick is acked and the connection stays open);
// main's code (ack 5 after the decision, the close only at the next frame).
func TestDecisionMidFrameNoAck(t *testing.T) {
	for _, armed := range []bool{true, false} {
		t.Run(map[bool]string{true: "decision", false: "control"}[armed], func(t *testing.T) {
			var l *Link
			var arm atomic.Bool
			r := newRig(t, func(o *Options) {
				inner := o.Owed
				o.Owed = func(ctx context.Context, w Owed) error {
					if arm.Load() {
						l.CloseConn(netobs.CloseEnrolment)
					}
					return inner(ctx, w)
				}
			})
			l = r.l
			p := r.accepted(hello02())
			arm.Store(armed)
			tk := tick02(20, 5, 5)
			tk.Lost = []netobs.Span{lspan("09:00:00", "09:10:00")} // widened: Owed is called inside the frame
			r.tickAfter(p, tk)
			if !armed {
				p.ack(5)
				p.stillOpen()
				return
			}
			if got := p.closedWithin(r.l.timeouts().Idle / 2); got != netobs.CloseEnrolment {
				t.Fatalf("close %q, want enrolment", got)
			}
			p.noAckAfter()
		})
	}
}

// D3's B2 on #732: the node's context cancelled while a frame is acted on
// closes as shutdown at once, with no ack after it and no later frame
// acted on. Controls: the context not cancelled (the tick is acked); main's
// code (the next frame acted on, the close as store).
func TestCancelMidFrameShutdown(t *testing.T) {
	for _, armed := range []bool{true, false} {
		t.Run(map[bool]string{true: "cancel", false: "control"}[armed], func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var arm atomic.Bool
			r := newRig(t, func(o *Options) {
				inner := o.Owed
				o.Owed = func(c context.Context, w Owed) error {
					if arm.Load() {
						cancel()
					}
					return inner(c, w)
				}
			})
			p := r.dialCtx(ctx, enrolment())
			p.send(hello02())
			p.ack(0)
			arm.Store(armed)
			tk := tick02(20, 5, 5)
			tk.Lost = []netobs.Span{lspan("09:00:00", "09:10:00")}
			r.tickAfter(p, tk)
			if !armed {
				p.ack(5)
				p.stillOpen()
				return
			}
			if got := p.closedWithin(r.l.timeouts().Idle / 2); got != netobs.CloseShutdown {
				t.Fatalf("close %q, want shutdown", got)
			}
			p.noAckAfter()
			if n := closes(r.l, netobs.CloseStore); n != 0 {
				t.Fatalf("closed as store %d times", n)
			}
		})
	}
}

// D3's N3 on #732: the first decision wins. CloseConn(enrolment) and then
// the node's context cancelled closes, and is counted, as enrolment.
// Controls: the cancel alone (shutdown); a6264dd8's assignment, the later
// request kept (shutdown, the enrolment close not counted).
func TestFirstDecisionWins(t *testing.T) {
	for _, revoke := range []bool{true, false} {
		t.Run(map[bool]string{true: "enrolment then cancel", false: "control"}[revoke], func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var l *Link
			var arm atomic.Bool
			r := newRig(t, func(o *Options) {
				inner := o.Owed
				o.Owed = func(c context.Context, w Owed) error {
					if arm.Load() {
						if revoke {
							l.CloseConn(netobs.CloseEnrolment)
						}
						cancel()
					}
					return inner(c, w)
				}
			})
			l = r.l
			p := r.dialCtx(ctx, enrolment())
			p.send(hello02())
			p.ack(0)
			arm.Store(true)
			tk := tick02(20, 5, 5)
			tk.Lost = []netobs.Span{lspan("09:00:00", "09:10:00")}
			r.tickAfter(p, tk)
			want := map[bool]string{true: netobs.CloseEnrolment, false: netobs.CloseShutdown}[revoke]
			if got := p.closedWithin(r.l.timeouts().Idle / 2); got != want {
				t.Fatalf("close %q, want %q", got, want)
			}
			p.noAckAfter()
			if n, m := closes(r.l, want), closes(r.l, netobs.CloseShutdown)+closes(r.l, netobs.CloseEnrolment); n != 1 || m != 1 {
				t.Fatalf("closes %v", r.l.ConnStats().Closes)
			}
		})
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
