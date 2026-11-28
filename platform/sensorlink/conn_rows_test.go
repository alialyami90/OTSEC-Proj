package sensorlink

import (
	"bytes"
	"context"
	"errors"
	"math"
	"net/netip"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"otsec.local/otsec/contracts/netobs"
	c5 "otsec.local/otsec/contracts/store"
)

// accepted dials and has hello h accepted, its first ack read.
func (r *rig) accepted(h *netobs.SensorHello) *peer {
	r.t.Helper()
	p := r.dial(enrolment())
	p.send(h)
	p.ack(num(h.FirstSeq) - 1)
	return p
}

// resume is a resume of testRun (run 5) from first_seq.
func resume(first, newest int) *netobs.SensorHello {
	h := hello02()
	h.Prior, h.FirstSeq, h.NewestSeq = nil, itoa(first), itoa(newest)
	return h
}

func itoa(n int) string { return strconv.Itoa(n) }

// seeded has run 5 accepted with records 1 to n stored, then ends the
// connection from the sensor's side.
func seeded(t *testing.T, n int) *rig {
	r := newRig(t, nil)
	p := r.accepted(hello02())
	for i := 1; i <= n; i++ {
		p.send(obs02(i))
		p.ack(uint64(i))
	}
	p.end()
	return r
}

// M-8: every node close reason is reachable through the intake. Control:
// a reason removed from the intake (its leg closes otherwise).
func TestIntakeM8EachCloseReason(t *testing.T) {
	reached := map[string]bool{}
	check := func(t *testing.T, got, want string) {
		t.Helper()
		if got != want {
			t.Fatalf("close %q, want %q", got, want)
		}
		reached[want] = true
	}
	t.Run("hello", func(t *testing.T) {
		r := newRig(t, nil)
		p := r.dial(enrolment())
		p.send(heartbeat02(1, 10))
		check(t, p.closed(), netobs.CloseHello)
	})
	t.Run("hello-timeout", func(t *testing.T) {
		r := newRig(t, func(o *Options) { o.Timeouts.Hello = 50 * time.Millisecond })
		check(t, r.dial(enrolment()).closed(), netobs.CloseHelloTimeout)
	})
	t.Run("binding", func(t *testing.T) {
		r := newRig(t, nil)
		p := r.dial(enrolment())
		h := hello02()
		h.Generation = "3"
		p.send(h)
		check(t, p.closed(), netobs.CloseBinding)
	})
	t.Run("run-regressed", func(t *testing.T) {
		r := seeded(t, 2)
		p := r.dial(enrolment())
		p.send(resume(1, 1)) // newest_seq below T, row 5a
		check(t, p.closed(), netobs.CloseRunRegressed)
	})
	t.Run("run-forked", func(t *testing.T) {
		r := seeded(t, 1)
		p := r.dial(enrolment())
		h := resume(2, 2)
		h.RunID = testRun2
		p.send(h)
		check(t, p.closed(), netobs.CloseRunForked)
		if !r.l.ConnStats().ForkHeld {
			t.Fatal("run-forked did not hold the sensor")
		}
	})
	t.Run("run", func(t *testing.T) {
		r := newRig(t, nil)
		p := r.accepted(hello02())
		o := obs02(1)
		o.RunID = testRun2
		p.send(o)
		check(t, p.closed(), netobs.CloseRun)
	})
	t.Run("tick", func(t *testing.T) {
		r := newRig(t, nil)
		p := r.accepted(hello02())
		p.send(tick02(5, 0, 0)) // newest_seq below the hello's 20
		check(t, p.closed(), netobs.CloseTick)
	})
	t.Run("idle", func(t *testing.T) {
		r := newRig(t, func(o *Options) { o.Timeouts.Idle = 50 * time.Millisecond })
		r.accepted(hello02())
		// The idle wait runs from the last frame read.
		check(t, r.l.waitClose(t), netobs.CloseIdle)
	})
	t.Run("frame-too-large", func(t *testing.T) {
		r := newRig(t, nil)
		p := r.accepted(hello02())
		go func() { _, _ = p.c.Write([]byte{0, 1, 0, 1}) }()
		check(t, p.closed(), netobs.CloseFrameTooLarge)
	})
	t.Run("store", func(t *testing.T) {
		var fail failingStore
		r := newRig(t, func(o *Options) { fail.Appender = o.Store; o.Store = &fail })
		p := r.accepted(hello02())
		fail.n = 1
		p.send(obs02(1))
		check(t, p.closed(), netobs.CloseStore)
	})
	t.Run("position-not-saved", func(t *testing.T) {
		r := newRig(t, nil)
		r.cs.failNext(1)
		p := r.dial(enrolment())
		p.send(hello02())
		check(t, p.closed(), netobs.ClosePositionNotSaved)
		if r.al.count(AlarmPositionNotSaved) != 1 {
			t.Fatal("sensor-position-not-saved not raised")
		}
	})
	t.Run("second-connection", func(t *testing.T) {
		r := newRig(t, nil)
		first := r.accepted(hello02())
		check(t, r.dial(enrolment()).closed(), netobs.CloseSecondConnection)
		first.stillOpen()
	})
	for _, reason := range []string{netobs.CloseEnrolment, netobs.CloseShutdown, netobs.CloseStateUnread} {
		t.Run(reason, func(t *testing.T) {
			r := newRig(t, nil)
			p := r.accepted(hello02())
			r.l.CloseConn(reason)
			check(t, p.closed(), reason)
		})
	}
	for _, reason := range netobs.NodeCloseReasons {
		if !reached[reason] {
			t.Errorf("close reason %s not reached", reason)
		}
	}
}

// waitClose waits for the link's live connection to close, and returns
// the last reason counted.
func (l *Link) waitClose(t *testing.T) string {
	t.Helper()
	deadline := time.Now().Add(waitBound(t))
	for time.Now().Before(deadline) {
		l.guard.mu.Lock()
		live := l.guard.live
		l.guard.mu.Unlock()
		if live == nil {
			for r, n := range l.ConnStats().Closes {
				if n > 0 && r != ClosedBeforeHello {
					return r
				}
			}
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("the connection did not close")
	return ""
}

// failingStore fails its next n appends with an error that is not final.
type failingStore struct {
	Appender
	n int
}

func (f *failingStore) Append(ctx context.Context, rec c5.Record) (c5.Receipt, error) {
	if f.n > 0 {
		f.n--
		return nil, errors.New("test: the database is closed")
	}
	return f.Appender.Append(ctx, rec)
}

// H-1: CH-13's rows in order, each acted on as its verdict states, without
// the sensor.link_refused legs (P4-4-DE): a close saves nothing; an
// accepted hello saves its position before it is acted on; rows 8 and 9
// raise and do not close. Control: an intake that takes the verdict and
// does not act on it (keeps the connection open, or saves before it
// closes).
func TestIntakeH1Rows(t *testing.T) {
	closesWith := func(t *testing.T, r *rig, h *netobs.SensorHello, en Enrolment, want string) {
		t.Helper()
		before := cursorNow(t, r.cs)
		p := r.dial(en)
		p.send(h)
		if got := p.closed(); got != want {
			t.Fatalf("close %q, want %q", got, want)
		}
		if after := cursorNow(t, r.cs); string(mustJSON(t, before)) != string(mustJSON(t, after)) {
			t.Fatalf("the closed hello changed the cursor: %+v -> %+v", before, after)
		}
		if closes(r.l, want) != 1 {
			t.Fatalf("%s not counted", want)
		}
	}
	t.Run("1 hello", func(t *testing.T) {
		h := hello02()
		h.BufferBytes = "1024"
		closesWith(t, newRig(t, nil), h, enrolment(), netobs.CloseHello)
	})
	t.Run("2 binding sensor_id", func(t *testing.T) {
		h := hello02()
		h.SensorID = otherSensor
		closesWith(t, newRig(t, nil), h, enrolment(), netobs.CloseBinding)
	})
	t.Run("2 binding generation", func(t *testing.T) {
		h := hello02()
		h.Generation = "1"
		closesWith(t, newRig(t, nil), h, enrolment(), netobs.CloseBinding)
	})
	t.Run("3 run-regressed", func(t *testing.T) {
		r := seeded(t, 1)
		h := hello02()
		h.RunCounter, h.RunID = "4", testRun2
		closesWith(t, r, h, enrolment(), netobs.CloseRunRegressed)
	})
	t.Run("4 run-forked", func(t *testing.T) {
		r := seeded(t, 1)
		h := resume(2, 3)
		h.RunID = testRun2
		closesWith(t, r, h, enrolment(), netobs.CloseRunForked)
	})
	t.Run("5 resume with a falling drops_channel", func(t *testing.T) {
		r := newRig(t, nil)
		h := hello02()
		h.DropsChannel = "3"
		r.accepted(h).end()
		h = resume(1, 20)
		h.DropsChannel = "2"
		closesWith(t, r, h, enrolment(), netobs.CloseRunRegressed)
	})
	t.Run("5a newest below T", func(t *testing.T) {
		closesWith(t, seeded(t, 3), resume(3, 2), enrolment(), netobs.CloseRunRegressed)
	})
	t.Run("5 prior on a resume", func(t *testing.T) {
		h := resume(2, 3)
		h.Prior = prior()
		closesWith(t, seeded(t, 1), h, enrolment(), netobs.CloseHello)
	})
	t.Run("6 new run without prior", func(t *testing.T) {
		h := hello02()
		h.Prior = nil
		closesWith(t, newRig(t, nil), h, enrolment(), netobs.CloseHello)
	})
	t.Run("6 position-not-saved", func(t *testing.T) {
		r := newRig(t, nil)
		r.cs.failNext(1)
		closesWith(t, r, hello02(), enrolment(), netobs.ClosePositionNotSaved)
	})
	t.Run("7 pinned_by", func(t *testing.T) {
		r := seeded(t, 1)
		h := resume(2, 2)
		h.PinnedBy = "console"
		closesWith(t, r, h, enrolment(), netobs.CloseBinding)
	})
	t.Run("5 and 6 accepted", func(t *testing.T) {
		r := seeded(t, 2)
		c := cursorNow(t, r.cs)
		if c == nil || c.RunCounter != 5 || c.Taken != 2 {
			t.Fatalf("row 6's save: %+v", c)
		}
		p := r.accepted(resume(3, 4)) // row 5
		p.send(obs02(3))
		p.ack(3)
		p.end()
		h := hello02()
		h.RunCounter, h.RunID, h.Prior.RunsSkipped = "6", testRun2, "0"
		r.accepted(h).end() // row 6
		if c := cursorNow(t, r.cs); c.RunCounter != 6 || c.RunID != testRun2 || c.Taken != 0 {
			t.Fatalf("row 6's save: %+v", c)
		}
	})
	// D6's N1 on #732: a resume under a renewed generation is accepted and
	// saved under it (row 5b); with the position begun at that generation,
	// the generation 2 cursor reads as none, so the resume is a new run
	// without prior and closes hello. Control: row 5b's save removed (the
	// cursor stays at generation 2).
	t.Run("5b generation renewed", func(t *testing.T) {
		r := seeded(t, 2)
		en := enrolment()
		en.Generation = 3
		h := resume(3, 4)
		h.Generation = "3"
		p := r.dial(en)
		p.send(h)
		p.ack(2)
		p.end()
		if c := cursorNow(t, r.cs); c.Generation != 3 || c.Taken != 2 {
			t.Fatalf("row 5b's save: %+v", c)
		}
		en.Began = 3
		closesWith(t, seeded(t, 2), h, en, netobs.CloseHello)
	})
	t.Run("8 digest and 9 buffer raise", func(t *testing.T) {
		r := newRig(t, nil)
		h := hello02()
		h.ConfigDigest, h.BufferBytes = otherDigest, itoa(32<<20)
		p := r.accepted(h)
		p.stillOpen()
		if r.al.count(AlarmCoverageMismatch) != 1 || r.al.count(AlarmBufferSmall) != 1 {
			t.Fatalf("raises: %v", r.al.list)
		}
	})
}

// H-2: a runs_skipped that disagrees raises sensor-gap-undeclared (runs),
// and the hello is accepted. Control: a close on the disagreement.
func TestIntakeH2RunsSkipped(t *testing.T) {
	r := newRig(t, nil)
	h := hello02()
	h.Prior.RunsSkipped = "1" // run 5 with no saved run: 4 skipped
	p := r.accepted(h)
	p.stillOpen()
	if r.al.count(AlarmGapUndeclared) != 1 || !strings.Contains(r.al.list[0], "reason runs") {
		t.Fatalf("raises: %v", r.al.list)
	}
}

// H-4, without its sensor.link_refused and dial legs: a hello whose
// newest_seq is below what the node took (an agent that applied a taken
// above its newest) closes as run-regressed, and the position is kept.
func TestIntakeH4TakenAhead(t *testing.T) {
	r := seeded(t, 5)
	p := r.dial(enrolment())
	p.send(resume(5, 4))
	if got := p.closed(); got != netobs.CloseRunRegressed {
		t.Fatalf("close %q", got)
	}
	if c := cursorNow(t, r.cs); c.Taken != 5 {
		t.Fatalf("T %d, want 5", c.Taken)
	}
}

// S-1: CH-14's rows. A record under another sensor_id is refused, the
// connection open, L moved and no gap; a seq at or below L is refused; a
// seq above L and at or below P is a duplicate; a jump counts a gap; a
// record of another run closes. Control: sensor-id refused before its seq
// is taken (a false gap).
func TestIntakeS1Place(t *testing.T) {
	r := seeded(t, 3)
	p := r.dial(enrolment())
	p.send(resume(2, 9)) // L = 1, P = 3
	p.ackAtLeast(1)
	p.send(obs02(2), obs02(3)) // duplicates
	other := obs02(4)
	other.SensorID = otherSensor
	p.send(other, obs02(4)) // sensor-id moves L to 4; then 4 is at or below L
	p.send(obs02(5))
	p.ack(5)
	p.send(obs02(7)) // seq 6 is a gap
	p.ack(7)
	st := r.l.Stats()
	if st.Dropped[RefusedDuplicate] != 2 || st.Refused[RefusedSensorID] != 1 || st.Refused[RefusedSeq] != 1 {
		t.Fatalf("counts: refused %v dropped %v", st.Refused, st.Dropped)
	}
	if c := cursorNow(t, r.cs); c.G != 1 {
		t.Fatalf("G %d, want 1: the sensor-id record left a false gap, or the jump none", c.G)
	}
	o := obs02(8)
	o.RunID = testRun2
	p.send(o)
	if got := p.closed(); got != netobs.CloseRun {
		t.Fatalf("close %q, want run", got)
	}
	if n := len(storedObs(t, r.s)); n != 5 {
		t.Fatalf("%d stored, want 5", n)
	}
}

// tickAfter sends a tick once the test's monotonic clock has moved past
// TickMinSpacing.
func (r *rig) tickAfter(p *peer, t *netobs.Tick) {
	p.taken()
	r.clk.add(netobs.TickMinSpacing + time.Second)
	p.send(t)
}

// S-2 and K-1: a gap covered by drops_channel raises nothing; above it,
// sensor-gap-undeclared with the excess at the next tick; a falling
// drops_channel in a tick closes; in a heartbeat it is refused as order
// and counted counter-decrease, as is a falling interfaces[].packets
// (K-1). Control: an intake that does not call Follows with the run's
// last heartbeat.
func TestIntakeS2GapDeclared(t *testing.T) {
	r := newRig(t, nil)
	p := r.accepted(hello02())
	p.send(obs02(1), obs02(3)) // G 1
	p.ack(3)
	r.tickAfter(p, r.agreeTick(tick02(20, 3, 2))) // D 2, above G: nothing
	p.send(obs02(6))                              // G 3
	p.ack(6)
	if r.al.count(AlarmGapUndeclared) != 0 {
		t.Fatalf("raised while D covers G: %v", r.al.list)
	}
	r.tickAfter(p, r.agreeTick(tick02(20, 6, 2))) // G 3 above D 2: the excess, 1
	hb7 := twoIfs(heartbeat02(7, 10), 6, 4)
	hb7.Counters.DropsChannel = 2
	p.send(hb7) // a frame after the tick, so the tick is read
	settle(t, r.l, func(s Stats) bool { return s.Heartbeats == 1 })
	if r.al.count(AlarmGapUndeclared) != 1 || !strings.Contains(r.al.list[0], "reason seq") || !strings.Contains(r.al.list[0], "3 records never read beyond the 2") {
		t.Fatalf("raises: %v", r.al.list)
	}
	hb := twoIfs(heartbeat02(8, 9), 5, 4) // packets falls
	hb.Counters.DropsChannel = 2
	p.send(hb)
	hb = twoIfs(heartbeat02(9, 20), 5, 15) // interfaces[].packets falls alone (K-1)
	hb.Counters.DropsChannel = 2
	p.send(hb)
	hb = twoIfs(heartbeat02(10, 20), 6, 14) // drops_channel falls from 2
	hb.Counters.DropsChannel = 1
	p.send(hb)
	settle(t, r.l, func(s Stats) bool { return s.Refused[RefusedCounterDecrease] == 3 })
	r.tickAfter(p, tick02(20, 10, 1)) // drops_channel falls from 2
	if got := p.closed(); got != netobs.CloseTick {
		t.Fatalf("close %q, want tick", got)
	}
	// The cursor counts the three refusals, and T is past them (D6's N3 on
	// #732).
	if c := cursorNow(t, r.cs); c.Refused != 3 || c.Taken != 10 {
		t.Fatalf("cursor after the refused heartbeats: refused %d, T %d", c.Refused, c.Taken)
	}
}

// K-1 within a run across a reconnect (D6's N3 on #732): a falling
// interfaces[].packets after a resume of the same run is refused
// counter-decrease, counted in the cursor with T past it. Control: the
// run's heartbeat baseline cleared at a resume. Across a node restart the
// baseline is part 2's (W in the cursor, CH-18).
func TestIntakeK1AcrossReconnect(t *testing.T) {
	r := newRig(t, nil)
	p := r.accepted(hello02())
	p.send(heartbeat02(1, 10))
	settle(t, r.l, func(s Stats) bool { return s.Heartbeats == 1 })
	p.end()
	p = r.accepted(resume(2, 20))
	p.send(heartbeat02(2, 9))
	settle(t, r.l, func(s Stats) bool { return s.Refused[RefusedCounterDecrease] == 1 })
	p.send(heartbeat02(3, 12))
	settle(t, r.l, func(s Stats) bool { return s.Heartbeats == 2 })
	p.end()
	if c := cursorNow(t, r.cs); c.Refused != 1 || c.Taken != 3 {
		t.Fatalf("cursor: refused %d, T %d", c.Refused, c.Taken)
	}
	if n := r.l.Stats().Heartbeats; n != 2 {
		t.Fatalf("%d heartbeats taken, want 2", n)
	}
}

// twoIfs gives h two interfaces with packets a and b, which sum to its
// packets, under a coverage statement that names both.
func twoIfs(h *netobs.Heartbeat, a, b uint64) *netobs.Heartbeat {
	h.Coverage.Interfaces = append(h.Coverage.Interfaces, netobs.Interface{Name: "eth2", Attachment: "span", LAN: "single"})
	h.Interfaces = []netobs.InterfaceCount{{Name: "eth1", Carrier: "up", Packets: a}, {Name: "eth2", Carrier: "up", Packets: b}}
	return h
}

// S-5's node leg, the check before row 6's save: an old run with G above
// D, the node stopped at row 6's save (a save that fails stands for the
// kill): after the restart, the next hello's judging raises
// sensor-gap-undeclared for the old run. Control: the check run after row
// 6's save, which then checks the new run.
func TestIntakeS5CheckBeforeSave(t *testing.T) {
	r := newRig(t, nil)
	p := r.accepted(hello02())
	p.send(obs02(1), obs02(3)) // G 1, D 0, never checked
	p.ack(3)
	r.l.CloseConn(netobs.CloseShutdown)
	p.closed()
	next := hello02()
	next.RunCounter, next.RunID, next.Prior.RunsSkipped = "6", testRun2, "0"
	r.restart()
	r.cs.failNext(1)
	p = r.dial(enrolment())
	p.send(next)
	if got := p.closed(); got != netobs.ClosePositionNotSaved {
		t.Fatalf("close %q", got)
	}
	r.restart()
	r.accepted(next)
	if r.al.count(AlarmGapUndeclared) != 1 || !strings.Contains(r.al.list[0], testRun) {
		t.Fatalf("raises after the restart: %v", r.al.list)
	}
	// S-5's tick leg: a record refused before its seq is read becomes a
	// gap at the tick's sent_seq, and T reaches it.
	r2 := newRig(t, nil)
	p = r2.accepted(hello02())
	p.send(obs02(1), []byte(`{"type":"observation","schema":"otsec.netobs/0.2","seq":`))
	r2.tickAfter(p, tick02(20, 2, 1))
	r2.tickAfter(p, tick02(20, 2, 1)) // the cursor is saved at most once a second
	p.ack(2)
}

// S-9: an impossible span closes; a new span with no rise closes; a valid
// span opens a lost gap and raises sensor-records-lost; a span ending
// after sensor_utc is cut once and counted, the connection open; one in
// 2100 is cut at the node's receipt plus the bound; the same span in three
// more ticks changes nothing. Controls: spans taken unchecked; a close on
// the cut; the cut moved by later ticks.
func TestIntakeS9Spans(t *testing.T) {
	t.Run("impossible", func(t *testing.T) {
		r := newRig(t, nil)
		p := r.accepted(hello02())
		tk := tick02(20, 0, 1)
		tk.Lost = []netobs.Span{lspan("09:10:00", "09:05:00")}
		r.tickAfter(p, tk)
		if got := p.closed(); got != netobs.CloseTick {
			t.Fatalf("close %q", got)
		}
	})
	t.Run("no rise", func(t *testing.T) {
		r := newRig(t, nil)
		p := r.accepted(hello02())
		tk := tick02(20, 0, 0)
		tk.Lost = []netobs.Span{lspan("09:00:00", "09:05:00")}
		r.tickAfter(p, tk)
		if got := p.closed(); got != netobs.CloseTick {
			t.Fatalf("close %q", got)
		}
		h := hello02()
		h.Lost = []netobs.Span{lspan("09:00:00", "09:05:00")}
		r2 := newRig(t, nil)
		p = r2.dial(enrolment())
		p.send(h)
		if got := p.closed(); got != netobs.CloseHello {
			t.Fatalf("hello close %q", got)
		}
	})
	t.Run("cut and kept", func(t *testing.T) {
		r := newRig(t, nil)
		p := r.accepted(hello02())
		tk := tick02(20, 0, 1)
		// Ends after sensor_utc (10:00:10): cut at the receipt, 10:00:00
		// plus 2 s, the earliest of the three.
		tk.Lost = []netobs.Span{lspan("09:59:00", "10:05:00"), {FromUTC: "2100-01-01T00:00:00Z", ToUTC: "2100-01-01T01:00:00Z"}}
		tk.SensorUTC = "2100-01-01T02:00:00Z"
		r.tickAfter(p, tk)
		p.send(obs02(1))
		p.ack(1)
		cs := r.l.ConnStats()
		if cs.SpansCut != 2 || cs.LostGaps != 2 || r.al.count(AlarmRecordsLost) != 1 {
			t.Fatalf("cut %d, gaps %d, raises %v", cs.SpansCut, cs.LostGaps, r.al.list)
		}
		c := cursorNow(t, r.cs)
		if len(c.Spans) != 2 || c.Spans[0].CutUTC != "2026-11-07T10:00:02Z" || c.Spans[1].CutUTC != "2026-11-07T10:00:02Z" {
			t.Fatalf("spans %+v", c.Spans)
		}
		got := storedObs(t, r.s)[0].Node.Lost
		// The 2100 window is cut to nothing (its cut end before its start):
		// no entry.
		if len(got) != 1 || got[0].ToUTC != "2026-11-07T10:00:02Z" {
			t.Fatalf("node.lost %+v", got)
		}
		for i := range 3 {
			r.addWall(time.Minute)
			tk.DropsChannel = "1"
			r.tickAfter(p, tk)
			p.send(obs02(2 + i))
			p.ack(uint64(2 + i))
		}
		p.stillOpen()
		if cs := r.l.ConnStats(); cs.SpansCut != 2 || cs.LostGaps != 2 {
			t.Fatalf("the same span counted again: %+v", cs)
		}
		if c := cursorNow(t, r.cs); c.Spans[0].CutUTC != "2026-11-07T10:00:02Z" {
			t.Fatalf("the window moved: %+v", c.Spans)
		}
	})
}

// T-1: made_utc without Z refuses the record as form, the connection open;
// sensor_utc without Z closes the hello as hello and a tick as tick.
// Control: an intake that stores such a record.
func TestIntakeT1UTCForm(t *testing.T) {
	r := newRig(t, nil)
	p := r.accepted(hello02())
	o := obs02(1)
	o.MadeUTC = "2026-11-07T10:00:00.200000+00:00"
	p.send(o)
	settle(t, r.l, func(s Stats) bool { return s.Refused[string(netobs.CodeForm)] == 1 })
	p.send(obs02(2))
	p.ack(2)
	if n := len(storedObs(t, r.s)); n != 1 {
		t.Fatalf("%d stored, want 1", n)
	}
	tk := tick02(20, 2, 0)
	tk.SensorUTC = "2026-11-07T10:00:10+00:00"
	r.tickAfter(p, tk)
	if got := p.closed(); got != netobs.CloseTick {
		t.Fatalf("tick close %q", got)
	}
	h := hello02()
	h.SensorUTC = "2026-11-07T10:00:00+00:00"
	p = newRig(t, nil).dial(enrolment())
	p.send(h)
	if got := p.closed(); got != netobs.CloseHello {
		t.Fatalf("hello close %q", got)
	}
}

// T-5, without its sensor.link_refused leg: a tick 2 s after the last is
// tick_early and moves nothing (no gap check); a tick under another
// sensor_id closes as tick and counts sensor-id. Control: no rate rule.
func TestIntakeT5TickEarly(t *testing.T) {
	r := newRig(t, nil)
	p := r.accepted(hello02())
	r.tickAfter(p, tick02(20, 0, 0))
	p.taken()
	r.clk.add(2 * time.Second)
	p.send(tick02(20, 10, 0)) // early: its 10 unread seqs are no gap yet
	p.send(heartbeat02(1, 10))
	settle(t, r.l, func(s Stats) bool { return s.Heartbeats == 1 })
	if r.l.ConnStats().TickEarly != 1 || r.al.count(AlarmGapUndeclared) != 0 {
		t.Fatalf("early %d, raises %v", r.l.ConnStats().TickEarly, r.al.list)
	}
	tk := tick02(20, 1, 0)
	tk.SensorID = otherSensor
	r.tickAfter(p, tk)
	if got := p.closed(); got != netobs.CloseTick || refused(r.l, RefusedSensorID) != 1 {
		t.Fatalf("close %q, sensor-id %d", got, refused(r.l, RefusedSensorID))
	}
}

// G-4: pinned_by outside its set closes as hello; changed within a
// generation closes as binding, across a node restart too. Control: a
// node that does not keep pinned_by across its restart.
func TestIntakeG4PinnedBy(t *testing.T) {
	r := newRig(t, nil)
	h := hello02()
	h.PinnedBy = "usb"
	p := r.dial(enrolment())
	p.send(h)
	if got := p.closed(); got != netobs.CloseHello {
		t.Fatalf("close %q", got)
	}
	r.accepted(hello02()).end()
	r.restart()
	h = resume(1, 20)
	h.PinnedBy = "console"
	p = r.dial(enrolment())
	p.send(h)
	if got := p.closed(); got != netobs.CloseBinding {
		t.Fatalf("after the restart: close %q", got)
	}
}

// D3's condition 1 (D4-106 item 1.6): a first hello with a changed
// pinned_by that closes at row 5 or 6 keeps nothing, and the next
// well-formed hello is accepted. Control: the value kept at row 7.
func TestPinnedByCloseKeepsNothing(t *testing.T) {
	r := newRig(t, nil)
	h := hello02()
	h.PinnedBy, h.Prior = "console", nil // closes at row 6
	p := r.dial(enrolment())
	p.send(h)
	if got := p.closed(); got != netobs.CloseHello {
		t.Fatalf("close %q", got)
	}
	if v, _ := r.pins.PinnedBy(2); v != "" {
		t.Fatalf("kept %q from a closed hello", v)
	}
	r.accepted(hello02()).end() // signature
	if v, _ := r.pins.PinnedBy(2); v != "signature" {
		t.Fatalf("kept %q", v)
	}
	// D6's N2 on #732: a first hello whose row 6 save fails keeps nothing,
	// and the next hello, with another value, is accepted and kept.
	// Control: KeepPinnedBy before row 6's save.
	r = newRig(t, nil)
	h = hello02()
	h.PinnedBy = "console"
	r.cs.failNext(1)
	p = r.dial(enrolment())
	p.send(h)
	if got := p.closed(); got != netobs.ClosePositionNotSaved {
		t.Fatalf("close %q", got)
	}
	if v, _ := r.pins.PinnedBy(2); v != "" {
		t.Fatalf("kept %q from a hello whose save failed", v)
	}
	r.accepted(hello02()).end()
	if v, _ := r.pins.PinnedBy(2); v != "signature" {
		t.Fatalf("kept %q", v)
	}
}

// D3's N1 on #732: a failed KeepPinnedBy closes position-not-saved,
// raises sensor-position-not-saved and keeps nothing; once it works, the
// next hello, with either value, is accepted and kept. Control:
// KeepPinnedBy's error ignored (the hello is accepted with nothing kept).
func TestKeepPinnedByFails(t *testing.T) {
	for _, next := range []string{"signature", "console"} {
		t.Run(next, func(t *testing.T) {
			r := newRig(t, nil)
			r.pins.fail = true
			p := r.dial(enrolment())
			p.send(hello02())
			if got := p.closed(); got != netobs.ClosePositionNotSaved || r.al.count(AlarmPositionNotSaved) != 1 {
				t.Fatalf("close %q, raises %v", got, r.al.list)
			}
			if v, _ := r.pins.PinnedBy(2); v != "" {
				t.Fatalf("kept %q", v)
			}
			r.pins.fail = false
			h := resume(1, 20) // row 6's save was made before the pin failed
			h.PinnedBy = next
			r.accepted(h).end()
			if v, _ := r.pins.PinnedBy(2); v != next {
				t.Fatalf("kept %q, want %q", v, next)
			}
		})
	}
}

// R-1: a 0.1 peer is closed at its first frame (hello); a 0.1 record on a
// 0.2 connection is refused as schema, the connection open.
func TestIntakeR1Peer01(t *testing.T) {
	r := newRig(t, nil)
	p := r.dial(enrolment())
	p.send(heartbeat(1, 10))
	if got := p.closed(); got != netobs.CloseHello {
		t.Fatalf("close %q", got)
	}
	p = r.accepted(hello02())
	p.send(flow(1, "192.0.2.10", "192.0.2.20"))
	settle(t, r.l, func(s Stats) bool { return s.Refused[RefusedOtherMinor] == 1 })
	p.send(obs02(1))
	p.ack(1)
	if n := len(storedObs(t, r.s)); n != 1 {
		t.Fatalf("%d stored", n)
	}
}

// R-6's node leg (D4-108 item 4): on an accepted 0.3 connection a
// 0.2-stamped observation is refused as schema, not stored, the
// connection open, and a 0.3 one is stored. Control: a node that decodes
// every frame with DecodeFromSensor.
func TestIntakeDecodesAtHelloMinor(t *testing.T) {
	r := newRig(t, nil)
	h := hello02()
	h.Schema = netobs.Identifier03
	p := r.accepted(h)
	p.send(obs02(1))
	settle(t, r.l, func(s Stats) bool { return s.Refused[RefusedOtherMinor] == 1 })
	p.send(obs03(1))
	p.ack(1)
	got := storedObs(t, r.s)
	if len(got) != 1 || got[0].Schema != netobs.Identifier03 {
		t.Fatalf("stored %d", len(got))
	}
}

// D4-104 item 1.3: the stored record's schema is the minor the node
// checked strictly on the channel, on a 0.2 and a 0.3 connection. The
// decode at the hello's minor (R-6) already refuses any other, so the
// control is that test's: a node that decodes with DecodeFromSensor would
// store a 0.2 record on a 0.3 connection.
func TestStoredSchemaIsChannelMinor(t *testing.T) {
	for _, minor := range []string{netobs.Identifier02, netobs.Identifier03} {
		r := newRig(t, nil)
		h := hello02()
		h.Schema = minor
		p := r.accepted(h)
		o := obs02(1)
		o.Schema = minor
		p.send(o)
		p.ack(1)
		if got := storedObs(t, r.s); got[0].Schema != minor {
			t.Fatalf("%s connection stored %s", minor, got[0].Schema)
		}
	}
}

// Its tied leg (D4-106 item 1.6, D3's N1 on #682): a record held, tied
// and stored carries the channel's minor and no field the channel refused.
// Control: a hold that stores the sensor's raw frame (it carries frames).
func TestStoredSchemaIsChannelMinorTied(t *testing.T) {
	saved := 0
	r := newRig(t, func(o *Options) {
		o.Hold = HoldConfig{NodeAddrs: []netip.Addr{netip.MustParseAddr(nodeAddr)}, TieGrace: 30 * time.Second,
			Now: func() time.Time { return t0 }, Save: func(context.Context, RunRecord) error { saved++; return nil }}
	})
	if err := r.l.Dispatch(bg, HoldRun{RequestID: "req-1", AssetID: relay, Endpoint: endpoint, L4: "tcp"}); err != nil {
		t.Fatal(err)
	}
	h := live02()
	h.Schema = netobs.Identifier03
	p := r.accepted(h)
	o := obs03(1)
	o.IP.Src, o.IP.Sport, o.IP.Dport = nodeAddr, ptr(40001), ptr(22)
	o.FirstUTC, o.LastUTC = t0.Add(time.Second).Format("2006-01-02T15:04:05.000000Z"), t0.Add(time.Second).Format("2006-01-02T15:04:05.000000Z")
	p.send(o)
	p.taken()
	r.addWall(netobs.TickMinSpacing + time.Second) // as tickAfter moves the monotonic clock: no move for the skew gate
	r.tickAfter(p, r.agreeTick(tick02(20, 1, 0)))  // read once the held record is taken
	p.taken()
	r.pass(30 * time.Second) // the Result comes after the session's end
	if _, err := r.l.Result(bg, "req-1", session09("0e4d8a2c-6b1f-4c3e-9a5d-7f2b1c0d9e8f", 40001, 0)); err != nil {
		t.Fatal(err)
	}
	got := storedObs(t, r.s)
	if len(got) != 1 || got[0].Schema != netobs.Identifier03 || got[0].Node.PlatformSession == nil || len(got[0].Frames) != 0 {
		t.Fatalf("stored %+v", got)
	}
	if saved == 0 {
		t.Fatal("the record was not held")
	}
}

// U-1's node leg: an undecoded observation is stored as any observation.
func TestIntakeU1Undecoded(t *testing.T) {
	r := newRig(t, nil)
	p := r.accepted(hello02())
	o := obs02(1)
	o.Kind, o.Flow, o.Protocol = netobs.KindUndecoded, nil, "unknown"
	o.Undecoded = &netobs.Undecoded{Basis: "none", Packets: 3}
	p.send(o)
	p.ack(1)
	got := storedObs(t, r.s)
	if len(got) != 1 || got[0].Kind != netobs.KindUndecoded {
		t.Fatalf("stored %+v, refused %v", got, r.l.Stats().Refused)
	}
}

// G-3's node leg: a record whose config_digest differs from the run's is
// refused as conflict, after a node restart too. Control: the run's digest
// not kept in the cursor.
func TestDigestConflictAfterRestart(t *testing.T) {
	r := newRig(t, nil)
	p := r.accepted(hello02())
	o := obs02(1)
	o.Coverage.ConfigDigest = otherDigest
	p.send(o)
	settle(t, r.l, func(s Stats) bool { return s.Refused[string(netobs.CodeConflict)] == 1 })
	p.end()
	r.restart()
	h := resume(2, 20)
	h.ConfigDigest = otherDigest // the run's digest is the cursor's, not the hello's
	p = r.accepted(h)
	o = obs02(2)
	o.Coverage.ConfigDigest = otherDigest
	p.send(o)
	settle(t, r.l, func(s Stats) bool { return s.Refused[string(netobs.CodeConflict)] == 1 })
	if n := len(storedObs(t, r.s)); n != 0 {
		t.Fatalf("%d stored", n)
	}
}

// H-7's leg on an ordinary resume (§3 moves its renew legs): a resume
// whose save fails closes as position-not-saved and raises
// sensor-position-not-saved. Control: a node that saves nothing on a
// resume.
func TestResumeSaveFailsPositionNotSaved(t *testing.T) {
	r := seeded(t, 2)
	r.cs.failNext(1)
	p := r.dial(enrolment())
	p.send(resume(3, 5))
	if got := p.closed(); got != netobs.ClosePositionNotSaved || r.al.count(AlarmPositionNotSaved) != 1 {
		t.Fatalf("close %q, raises %v", got, r.al.list)
	}
}

// A-4: a refused record, then the node stopped before the totals are
// saved: the record is resent and refused again, counted once; a store
// error that is not final closes as store, T stays, and the record is
// resent and stored once. Control: T moved before the totals are saved.
func TestRefusedRecordCountedOnceAcrossRestart(t *testing.T) {
	r := newRig(t, nil)
	p := r.accepted(hello02())
	bad := obs02(1)
	bad.MadeUTC = "2026-11-07T10:00:00.2+00:00"
	p.send(bad)
	settle(t, r.l, func(s Stats) bool { return s.Refused[string(netobs.CodeForm)] == 1 })
	r.cs.failNext(1) // the stop's save fails: the kill before the totals
	r.l.CloseConn(netobs.CloseShutdown)
	p.closed()
	if c := cursorNow(t, r.cs); c.Taken != 0 || c.Refused != 0 {
		t.Fatalf("T moved past an unsaved refusal: %+v", c)
	}
	r.restart()
	p = r.accepted(resume(1, 20))
	p.send(bad)
	settle(t, r.l, func(s Stats) bool { return s.Refused[string(netobs.CodeForm)] == 1 })
	r.l.CloseConn(netobs.CloseShutdown)
	p.closed()
	if c := cursorNow(t, r.cs); c.Taken != 1 || c.Refused != 1 {
		t.Fatalf("cursor %+v, want T 1 and the refusal once", c)
	}

	var fail failingStore
	r = newRig(t, func(o *Options) { fail.Appender = o.Store; o.Store = &fail })
	p = r.accepted(hello02())
	fail.n = 1
	p.send(obs02(1))
	if got := p.closed(); got != netobs.CloseStore {
		t.Fatalf("close %q", got)
	}
	if c := cursorNow(t, r.cs); c.Taken != 0 {
		t.Fatalf("T %d after a store error that is not final", c.Taken)
	}
	p = r.accepted(resume(1, 20))
	p.send(obs02(1))
	p.ack(1)
	if n := len(storedObs(t, r.s)); n != 1 || r.l.Stats().Dropped[DropStore] != 0 {
		t.Fatalf("%d stored, dropped %v", n, r.l.Stats().Dropped)
	}
}

// S-4, the node test: a new run's prior is saved in the cursor with its
// owed mark before the hello is accepted, and stays owed until its
// sensor.run-loss has been written: the node stopped between the hello and
// the event (the event's write fails) writes it after its restart, with
// the run's generation, counter and run_id, once or twice, never not at
// all. Control: prior kept in memory only.
func TestPriorDurableUntilEvent(t *testing.T) {
	r := newRig(t, nil)
	r.owedE = errors.New("test: the health stream is down")
	h := hello02()
	h.DropsChannel, h.Prior.RecordsLost = "0", "3"
	h.Prior.Lost = []netobs.Span{lspan("09:00:00", "09:01:00")}
	r.accepted(h).end()
	if c := cursorNow(t, r.cs); c.Prior == nil || !c.Prior.Owed || c.Prior.RecordsLost != 3 {
		t.Fatalf("prior not durable: %+v", c.Prior)
	}
	r.owedE = nil
	r.restart()
	if err := r.l.WriteOwed(bg); err != nil {
		t.Fatal(err)
	}
	if len(r.owed) != 1 || r.owed[0].Prior == nil || r.owed[0].Generation != 2 || r.owed[0].RunCounter != 5 || r.owed[0].RunID != testRun {
		t.Fatalf("owed %+v", r.owed)
	}
	if c := cursorNow(t, r.cs); c.Prior.Owed || slices.ContainsFunc(c.Prior.Spans, func(s HeldSpan) bool { return s.Owed }) {
		t.Fatalf("the mark stayed after the event: %+v", c.Prior)
	}
	if err := r.l.WriteOwed(bg); err != nil || len(r.owed) != 1 {
		t.Fatalf("written again: %v %+v", err, r.owed)
	}
}

// R-5's cursor leg: a stored cursor of MaxLinkCursorBytes is within the
// bound and one byte over is refused, on encode and on read; at the bound
// the store saves it. Section 1.4's form is at most 2,032 bytes, so no
// cursor the intake builds reaches it. Control: the cap off by one.
func TestCursorAtMaxLinkCursorBytes(t *testing.T) {
	at := bytes.Repeat([]byte("x"), MaxLinkCursorBytes)
	if err := checkCursorBytes(at); err != nil {
		t.Fatalf("%d bytes refused: %v", len(at), err)
	}
	if err := checkCursorBytes(append(at, 'x')); err == nil {
		t.Fatalf("%d bytes accepted", len(at)+1)
	}
	over := append([]byte("sp2"), bytes.Repeat([]byte(" -"), MaxLinkCursorBytes)...)
	if _, err := decodeCursor(over); err == nil {
		t.Fatal("a cursor over the bound was read")
	}
	r := newRig(t, nil)
	if err := r.cs.SaveSourceCursor(bg, at); err != nil {
		t.Fatalf("a cursor at the bound was not saved: %v", err)
	}
}

// TestCursorLargestForm (D1's ruling 8 on #788): the largest cursor the
// encoder can write, every field at its largest (every decimal 20 digits,
// every time 2262's, 8 interfaces, a held gap with every mark, 8 spans
// and 8 prior spans, unclean and enrolment, and G and D at W's heartbeat),
// reads back as written and is within the 2,026 bytes D1's ruling names,
// section 1.4's count of 2,068 (each time counted at 20 digits; Unix
// nanoseconds to 2262 take 19) and MaxLinkCursorBytes. The negative is
// TestCursorAtMaxLinkCursorBytes.
func TestCursorLargestForm(t *testing.T) {
	const top = uint64(18446744073709551615)
	end := time.Unix(0, math.MaxInt64).UTC()
	e := canonUTC(end)
	var spans []HeldSpan
	for range netobs.MaxLostSpans {
		spans = append(spans, HeldSpan{FromUTC: e, ToUTC: e, CutUTC: e, Owed: true, Marked: true})
	}
	var ifs []IfaceMark
	for range netobs.MaxInterfaces {
		ifs = append(ifs, IfaceMark{Packets: top, RiseUTC: end})
	}
	tp := top
	all := uint16(1<<len(gapCauses) - 1)
	c := &Cursor{Generation: top, RunCounter: top, RunID: testRun, Taken: top, G: top, D: top, Refused: top, Dropped: top,
		WriteNo: top, Digest: testDigest, Ds: top, NewestSeq: top, FramesOutgoing: &tp, DropsHolder: &tp, FramesOverlong: &tp,
		DropsDriver: &tp, Egress: EgressCarried, W: end, WSeq: top, WAtUTC: end, WG: top, WD: top, Causes: all, R: end, Ifaces: ifs,
		Held: &HeldGap{From: end, To: end, Cause: CauseSensorFailed, Causes: all, Gaps: top, Stepped: true, Bound: true, Covered: true},
		M:    end, Spans: spans,
		Prior: &HeldPrior{RunsSkipped: top, RecordsLost: top, PreviousEnd: "unclean", StartedBy: "enrolment", Owed: true, Spans: spans}}
	b, err := encodeCursor(c)
	if err != nil {
		t.Fatal(err)
	}
	got, err := decodeCursor(b)
	if err != nil || !reflect.DeepEqual(got, c) {
		t.Fatalf("read back %+v (%v), wrote %+v", got, err, c)
	}
	f := strings.Split(string(b), " ")
	if len(f[118]) != 20 || len(f[119]) != 20 {
		t.Fatalf("G and D at W %q %q, want 20 digits each", f[118], f[119])
	}
	t.Logf("the largest cursor: %d bytes (D1's ruling 2,026, section 1.4's count 2,068, MaxLinkCursorBytes %d)", len(b), MaxLinkCursorBytes)
	if len(b) > 2026 || len(b) > 2068 || len(b) > MaxLinkCursorBytes {
		t.Fatalf("%d bytes", len(b))
	}
}

// The cursor's text form (section 1.4, CH-18): every field it fills reads
// back as written, write_no, the baselines (2b), M (2c), and W, R and the
// interfaces kept with W (2e-1), W's causes and the gap held for the floor
// (2e-2) and G and D at W's heartbeat (2e-3) included, with drops_driver
// absent (unknown); W's causes or a held gap's out of the set, a held gap
// partly filled, W without its seq, at_utc, G or D, G and D without W, an interface count out of range or an interface slot past
// it, M not a decimal, a span slot past the count, a mark out of range,
// or a time that Unix nanoseconds cannot hold, is refused. Control: a
// decoder that reads the gap's fields loosely.
func TestCursorTextForm(t *testing.T) {
	c := &Cursor{Generation: 2, RunCounter: 5, RunID: testRun, Taken: 9, G: 3, D: 1, Refused: 4, Dropped: 6, Ds: 1,
		NewestSeq: 20, Digest: testDigest, WriteNo: 7, FramesOutgoing: ptr(uint64(0)), DropsHolder: ptr(uint64(3)),
		FramesOverlong: ptr(uint64(1)), Egress: EgressCarried, M: time.Date(2026, 11, 7, 9, 30, 0, 123456789, time.UTC),
		W: time.Date(2026, 11, 7, 9, 29, 0, 5, time.UTC), WSeq: 8, WAtUTC: time.Date(2026, 11, 7, 9, 28, 59, 0, time.UTC), WG: 2, WD: 1,
		R: time.Date(2026, 11, 7, 9, 28, 0, 0, time.UTC), Ifaces: []IfaceMark{{Packets: 700, RiseUTC: time.Date(2026, 11, 7, 9, 28, 59, 0, time.UTC)},
			{Packets: 0, RiseUTC: time.Date(2026, 11, 7, 9, 0, 0, 0, time.UTC)}},
		Causes: 1<<1 | 1<<6, Held: &HeldGap{From: time.Date(2026, 11, 7, 9, 10, 0, 0, time.UTC), To: time.Date(2026, 11, 7, 9, 5, 0, 0, time.UTC),
			Cause: CauseSilent, Causes: 1<<6 | 1<<2, Gaps: 2, Stepped: true},
		Spans: []HeldSpan{{FromUTC: "2026-11-07T09:00:00Z", ToUTC: "2026-11-07T09:00:05.5Z", CutUTC: "2026-11-07T09:00:05.5Z", Owed: true, Marked: true}},
		Prior: &HeldPrior{RunsSkipped: 4, RecordsLost: 2, PreviousEnd: "unclean", StartedBy: "enrolment", Owed: true,
			Spans: []HeldSpan{{FromUTC: "2026-11-07T08:00:00Z", ToUTC: "2026-11-07T08:01:00Z", CutUTC: "2026-11-07T08:00:30Z", Marked: true}}}}
	b, err := encodeCursor(c)
	if err != nil {
		t.Fatal(err)
	}
	got, err := decodeCursor(b)
	if err != nil {
		t.Fatalf("%v: %s", err, b)
	}
	if !reflect.DeepEqual(got, c) {
		t.Fatalf("read back %+v, wrote %+v", got, c)
	}
	if n := len(strings.Split(string(b), " ")); n != 120 {
		t.Fatalf("%d fields", n)
	}
	// The held gap's cause at its open is one character, as section 1.4
	// gives it (D6's N5 on #781).
	if f := strings.Split(string(b), " "); f[42] != "6" {
		t.Fatalf("field 42 %q, want silent's code 6", f[42])
	}
	none := *c
	none.Prior, none.Spans, none.Digest = nil, []HeldSpan{}, ""
	none.W, none.WSeq, none.WAtUTC, none.R, none.Ifaces, none.WG, none.WD = time.Time{}, 0, time.Time{}, time.Time{}, nil, 0, 0
	none.Causes, none.Held = 0, nil
	b2, _ := encodeCursor(&none)
	if back, err := decodeCursor(b2); err != nil || back.Prior != nil || back.Digest != "" || back.Held != nil || back.Causes != 0 {
		t.Fatalf("no prior: %+v %v", back, err)
	}
	f := strings.Split(string(b), " ")
	for _, k := range []struct {
		name string
		i    int
		v    string
	}{
		{"write_no absent", 9, "-"}, {"a baseline not a decimal", 13, "x"}, {"an egress mark out of range", 17, "2"},
		{"W's causes empty", 21, "0"}, {"W's causes out of the set", 21, "512"}, {"W without its seq", 19, "-"}, {"W without its at_utc", 20, "-"},
		{"R not a decimal", 22, "x"}, {"an interface count of 0", 23, "0"}, {"an interface count of 9", 23, "9"},
		{"an interface slot past the count", 28, "0"}, {"an interface's rise absent", 25, "-"},
		{"the held gap's from absent", 40, "-"}, {"the held gap's to not a decimal", 41, "x"},
		{"the held gap's cause out of the set", 42, "unknown"}, {"the held gap's causes empty", 43, "0"},
		{"the held gap's causes out of the set", 43, "512"}, {"the held gap carries none", 44, "0"},
		{"the held gap's mark out of range", 45, "8"}, {"M not a decimal", 46, "x"}, {"a slot past the count", 52, "0"},
		{"a mark out of range", 51, "4"}, {"a leading zero", 4, "09"}, {"a sign", 4, "+9"}, {"previous_end", 82, "x"},
		{"started_by", 83, "someone"}, {"the tag", 0, "sp1"}, {"run_id", 3, "not-a-uuid"},
		{"W without G at its heartbeat", 118, "-"}, {"W without D at its heartbeat", 119, "-"},
		{"G at W not a decimal", 118, "x"}, {"D at W with a leading zero", 119, "01"},
	} {
		g := slices.Clone(f)
		g[k.i] = k.v
		if _, err := decodeCursor([]byte(strings.Join(g, " "))); err == nil {
			t.Errorf("%s: read", k.name)
		}
	}
	if _, err := decodeCursor(append(slices.Clone(b), " -"...)); err == nil {
		t.Error("121 fields read")
	}
	// Every field of an absent held gap, of an absent prior (D6's N1 on
	// #742), and of G and D at W with no W.
	nf := strings.Split(string(b2), " ")
	for i := 40; i < 46; i++ {
		g := slices.Clone(nf)
		g[i] = "1"
		if _, err := decodeCursor([]byte(strings.Join(g, " "))); err == nil {
			t.Errorf("field %d of an absent held gap filled: read", i)
		}
	}
	for i := 80; i < cursorFields; i++ {
		g := slices.Clone(nf)
		g[i] = "0"
		if _, err := decodeCursor([]byte(strings.Join(g, " "))); err == nil {
			t.Errorf("field %d of an absent prior, or of G and D with no W, filled: read", i)
		}
	}
	// The digest in its one form, and a span in CH-40's order (D3's N1,
	// D6's N2 on #742). The span is 09:00:00 to 09:00:05.5.
	to := f[49]
	after := strconv.FormatUint(num(to)+1, 10)
	for _, k := range []struct {
		name string
		i    int
		v    string
	}{
		{"an empty digest", 10, ""}, {"a digest of another form", 10, "x\x00\x01<script>"},
		{"a digest in upper case", 10, strings.ToUpper(testDigest)}, {"a span's from after its to", 48, after},
		{"a span's cut end after its to", 50, after},
	} {
		g := slices.Clone(f)
		g[k.i] = k.v
		if _, err := decodeCursor([]byte(strings.Join(g, " "))); err == nil {
			t.Errorf("%s: read", k.name)
		}
	}
	// What the decoder refuses is never encoded.
	for name, mut := range map[string]func(*Cursor){
		"a time past 2262": func(c *Cursor) {
			c.Spans = []HeldSpan{{FromUTC: "2300-01-01T00:00:00Z", ToUTC: "2300-01-01T00:00:01Z", CutUTC: "2300-01-01T00:00:01Z"}}
		},
		"a time before 1970": func(c *Cursor) {
			c.Spans = []HeldSpan{{FromUTC: "1969-12-31T23:59:59Z", ToUTC: "1970-01-01T00:00:01Z", CutUTC: "1970-01-01T00:00:01Z"}}
		},
		"a run_id that is not a UUID": func(c *Cursor) { c.RunID = strings.Repeat("a", 3000) },
		"a digest of another form":    func(c *Cursor) { c.Digest = "sha256:x" },
		"a span's cut end after its to": func(c *Cursor) {
			c.Spans = []HeldSpan{{FromUTC: "2026-11-07T09:00:00Z", ToUTC: "2026-11-07T09:00:01Z", CutUTC: "2026-11-07T09:00:02Z"}}
		},
	} {
		bad := *c
		mut(&bad)
		if _, err := encodeCursor(&bad); err == nil {
			t.Errorf("%s: encoded", name)
		}
	}
}
