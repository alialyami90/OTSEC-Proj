package sensorlink

import (
	"context"
	"errors"
	"net/netip"
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
	deadline := time.Now().Add(20 * time.Second)
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
	r.tickAfter(p, tick02(20, 3, 1)) // D 1 covers it
	p.send(obs02(6))                 // G 3
	p.ack(6)
	if r.al.count(AlarmGapUndeclared) != 0 {
		t.Fatalf("raised while D covers G: %v", r.al.list)
	}
	r.tickAfter(p, tick02(20, 6, 1))
	hb7 := twoIfs(heartbeat02(7, 10), 6, 4)
	hb7.Counters.DropsChannel = 1
	p.send(hb7) // a frame after the tick, so the tick is read
	settle(t, r.l, func(s Stats) bool { return s.Heartbeats == 1 })
	if r.al.count(AlarmGapUndeclared) != 1 || !strings.Contains(r.al.list[0], "reason seq") {
		t.Fatalf("raises: %v", r.al.list)
	}
	hb := twoIfs(heartbeat02(8, 9), 5, 4) // packets falls
	hb.Counters.DropsChannel = 1
	p.send(hb)
	hb = twoIfs(heartbeat02(9, 20), 5, 15) // interfaces[].packets falls alone (K-1)
	hb.Counters.DropsChannel = 1
	p.send(hb)
	hb = twoIfs(heartbeat02(10, 20), 6, 14) // drops_channel falls from 1
	p.send(hb)
	settle(t, r.l, func(s Stats) bool { return s.Refused[RefusedCounterDecrease] == 3 })
	r.tickAfter(p, tick02(20, 10, 0)) // drops_channel falls from 1
	if got := p.closed(); got != netobs.CloseTick {
		t.Fatalf("close %q, want tick", got)
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
	h := hello02()
	h.Schema = netobs.Identifier03
	p := r.accepted(h)
	o := obs03(1)
	o.IP.Src, o.IP.Sport, o.IP.Dport = nodeAddr, ptr(40001), ptr(22)
	o.FirstUTC, o.LastUTC = t0.Add(time.Second).Format("2006-01-02T15:04:05.000000Z"), t0.Add(time.Second).Format("2006-01-02T15:04:05.000000Z")
	p.send(o)
	r.tickAfter(p, tick02(20, 1, 0)) // read once the held record is taken
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

// R-5's cursor leg: a cursor of MaxLinkCursorBytes is encoded and saved
// in the observation stream's source cursor; one byte over is refused.
// Control: the cap off by one.
func TestCursorAtMaxLinkCursorBytes(t *testing.T) {
	c := &Cursor{RunID: testRun, Digest: testDigest, Spans: []HeldSpan{{FromUTC: "x", ToUTC: "x", CutUTC: "x"}}}
	c.Spans[0].FromUTC += strings.Repeat("x", MaxLinkCursorBytes-len(mustJSON(t, c)))
	at, err := encodeCursor(c)
	if err != nil || len(at) != MaxLinkCursorBytes {
		t.Fatalf("%d bytes: %v", len(at), err)
	}
	c.Spans[0].FromUTC += "x"
	if b, err := encodeCursor(c); err == nil {
		t.Fatalf("a cursor of %d bytes was encoded", len(b))
	}
	r := newRig(t, nil)
	if err := r.cs.SaveSourceCursor(bg, at); err != nil {
		t.Fatalf("a cursor at the bound was not saved: %v", err)
	}
}
