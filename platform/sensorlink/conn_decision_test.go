package sensorlink

import (
	"context"
	"errors"
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

// ackRaceConn lands a decision (CloseConn(enrolment)) at the instant the
// ack's write deadline is set: when that deadline is set outside the
// guard's lock, the decision is made first and the deadline then set over
// it; when it is set under the lock, the decision waits for the lock and
// the write waits for the decision.
type ackRaceConn struct {
	Conn
	l     *Link
	armed atomic.Bool
	done  chan struct{}
}

func (c *ackRaceConn) SetWriteDeadline(t time.Time) error {
	if !t.After(time.Now()) || !c.armed.CompareAndSwap(true, false) {
		return c.Conn.SetWriteDeadline(t)
	}
	if c.l.guard.mu.TryLock() {
		c.l.guard.mu.Unlock()
		c.l.CloseConn(netobs.CloseEnrolment)
		close(c.done)
	} else {
		go func() { c.l.CloseConn(netobs.CloseEnrolment); close(c.done) }()
	}
	return c.Conn.SetWriteDeadline(t)
}

func (c *ackRaceConn) Write(b []byte) (int, error) {
	select {
	case <-c.done:
	default:
		if !c.armed.Load() {
			<-c.done
		}
	}
	return c.Conn.Write(b)
}

// D3's N2 on #732: a decision made as the ack's write deadline is set is
// not overwritten by it. No ack follows the decision, and the connection
// closes as enrolment at once, not after Idle. Controls: the hook not
// armed (the hello is acked and the connection stays open); a6264dd8's
// order, the deadline set outside the lock (ack 0 sent after the
// decision).
func TestDecisionAtAckDeadline(t *testing.T) {
	for _, armed := range []bool{true, false} {
		t.Run(map[bool]string{true: "decision", false: "control"}[armed], func(t *testing.T) {
			r := newRig(t, nil)
			c := &ackRaceConn{l: r.l, done: make(chan struct{})}
			c.armed.Store(armed)
			if !armed {
				close(c.done)
			}
			p := r.dialWrap(bg, enrolment(), func(b Conn) Conn { c.Conn = b; return c })
			p.send(hello02())
			if !armed {
				p.ack(0)
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
// encoded is the node's fault, not the record's refusal. It is not stored,
// counted or acked, T stays, and the connection closes position-not-saved
// with its alarm. Section 1.4's form is bounded by construction, so the
// fault is the test seam cursorEncodeFault, failing once a prior span is
// marked (the stored cursor holds one unmarked). Controls: the seam off
// (6 of 6 stored and acked); main's code (6 of 6 refused stored, T at 6,
// acked through 6).
func TestCursorEncodeFailureNotFinal(t *testing.T) {
	for _, over := range []bool{true, false} {
		t.Run(map[bool]string{true: "over", false: "control"}[over], func(t *testing.T) {
			r := newRig(t, nil)
			r.accepted(hello02()).end()
			c := cursorNow(t, r.cs)
			c.Prior.Spans = []HeldSpan{{FromUTC: "2026-11-07T09:00:00Z", ToUTC: "2026-11-07T09:01:00Z", CutUTC: "2026-11-07T09:01:00Z"}}
			saveTestCursor(t, r, c)
			if over {
				cursorEncodeFault = func(c *Cursor) error {
					if c.Prior != nil && len(c.Prior.Spans) == 1 && c.Prior.Spans[0].Marked {
						return errors.New("test: the marked cursor cannot be encoded")
					}
					return nil
				}
				t.Cleanup(func() { cursorEncodeFault = nil })
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
