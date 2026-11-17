package sensorlink

import (
	"errors"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/netobs"
)

// Option (a) for the cursor's bound (D1's ruling on #732, with D3's
// 6948579191 and D6's 6948584141): what a replaced cursor owes is written
// before row 6's save, and the cursor holds one run. The control for each
// test below is the reviewed code's carry (8e5528ea), which saves the new
// run with the old run's owed events carried and unwritten.

// run5Owing has run 5 accepted while the health stream is down, so its
// prior and its one lost span stay owed in the saved cursor.
func run5Owing(t *testing.T, r *rig) {
	t.Helper()
	r.owedE = errors.New("test: the health stream is down")
	h := hello02()
	h.DropsChannel, h.Lost = "1", []netobs.Span{lspan("09:30:00", "09:31:00")}
	h.Prior.RecordsLost, h.Prior.Lost = "3", []netobs.Span{lspan("09:00:00", "09:01:00")}
	r.accepted(h).end()
	if c := cursorNow(t, r.cs); !c.Prior.Owed || !c.Spans[0].Owed {
		t.Fatalf("run 5 owes nothing: %+v", c)
	}
}

// run6 is a new run after run 5.
func run6() *netobs.SensorHello {
	h := hello02()
	h.RunCounter, h.RunID, h.Prior.RunsSkipped = "6", testRun2, "0"
	return h
}

// raised reports whether a raise of name contains text.
func (r *rig) raised(name, text string) bool {
	r.al.mu.Lock()
	defer r.al.mu.Unlock()
	for _, a := range r.al.list {
		if strings.HasPrefix(a, name+":") && strings.Contains(a, text) {
			return true
		}
	}
	return false
}

func (r *rig) owedNow() []Owed {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Owed(nil), r.owed...)
}

// isRun5 reports whether o is run 5's owed events under run 5's identity.
func isRun5(o Owed) bool {
	return o.Generation == 2 && o.RunCounter == 5 && o.RunID == testRun && o.Prior != nil && len(o.Spans) == 1 &&
		o.Spans[0].FromUTC == "2026-11-07T09:30:00Z"
}

// D6's condition 2 and D3's condition 4 (D3 3 in D1's ruling): run 5's
// owed write fails at its hello, which raises and stays open. Run 6's
// hello then closes position-not-saved with the count of unwritten
// events, the saved cursor byte for byte run 5's, nothing written and no
// pin kept. Once the stream is back, the next hello writes run 5's events
// under run 5's identity, saves, is accepted, and then writes run 6's.
func TestRow6OwedWriteFails(t *testing.T) {
	r := newRig(t, nil)
	r.owedE = errors.New("test: the health stream is down")
	h := hello02()
	h.DropsChannel, h.Lost = "1", []netobs.Span{lspan("09:30:00", "09:31:00")}
	h.Prior.RecordsLost, h.Prior.Lost = "3", []netobs.Span{lspan("09:00:00", "09:01:00")}
	p := r.accepted(h)
	p.stillOpen()
	if n := r.al.count(AlarmPositionNotSaved); n != 1 || !r.raised(AlarmPositionNotSaved, "2 owed events of run "+testRun) {
		t.Fatalf("mid-run failure not raised: %v", r.al.list)
	}
	p.end()
	before := mustJSON(t, cursorNow(t, r.cs))

	en := enrolment()
	en.Generation, en.Began = 3, 1
	h6 := run6()
	h6.Generation = "3"
	p = r.dial(en)
	p.send(h6)
	if got := p.closed(); got != netobs.ClosePositionNotSaved {
		t.Fatalf("close %q", got)
	}
	if n := r.al.count(AlarmPositionNotSaved); n != 2 || !r.raised(AlarmPositionNotSaved, "2 owed events of run "+testRun+" were not written") {
		t.Fatalf("raises %v", r.al.list)
	}
	if after := mustJSON(t, cursorNow(t, r.cs)); string(after) != string(before) {
		t.Fatalf("the cursor changed:\n%s\n%s", before, after)
	}
	if v, _ := r.pins.PinnedBy(3); v != "" || len(r.owedNow()) != 0 {
		t.Fatalf("run 6 kept pin %q, owed %+v", v, r.owedNow())
	}

	r.mu.Lock()
	r.owedE = nil
	r.mu.Unlock()
	r.accepted6(en, h6)
	w := r.owedNow()
	if len(w) != 2 || !isRun5(w[0]) || w[1].RunCounter != 6 || w[1].Generation != 3 || w[1].RunID != testRun2 {
		t.Fatalf("owed %+v", w)
	}
	if c := cursorNow(t, r.cs); c.RunCounter != 6 || c.Prior.Owed {
		t.Fatalf("cursor %+v", c)
	}
}

// accepted6 dials under en and has h accepted (its ack of first_seq - 1).
func (r *rig) accepted6(en Enrolment, h *netobs.SensorHello) *peer {
	r.t.Helper()
	p := r.dial(en)
	p.send(h)
	p.ack(num(h.FirstSeq) - 1)
	p.end()
	return p
}

// D3's condition 1: owed events with no Options.Owed close
// position-not-saved at run 6's hello, the cursor unchanged: never a
// silent drop.
func TestRow6OwedNoWriter(t *testing.T) {
	r := newRig(t, func(o *Options) { o.Owed = nil })
	h := hello02()
	h.Prior.RecordsLost, h.Prior.Lost = "3", []netobs.Span{lspan("09:00:00", "09:01:00")}
	r.accepted(h).end()
	before := mustJSON(t, cursorNow(t, r.cs))
	p := r.dial(enrolment())
	p.send(run6())
	if got := p.closed(); got != netobs.ClosePositionNotSaved || r.al.count(AlarmPositionNotSaved) != 1 ||
		!r.raised(AlarmPositionNotSaved, "no writer") {
		t.Fatalf("close %q, raises %v", got, r.al.list)
	}
	if after := mustJSON(t, cursorNow(t, r.cs)); string(after) != string(before) {
		t.Fatalf("the cursor changed")
	}
}

// D6's condition 3 and D3's condition 2: the write succeeds and row 6's
// save fails, the kill's stand-in. The old cursor stays with its marks,
// and the next hello writes the same events again, with the same
// identity, and is accepted: twice, never not at all. Control: the marks
// cleared before the save (the second hello writes run 5 nothing).
func TestRow6SaveFailsWritesAgain(t *testing.T) {
	r := newRig(t, nil)
	run5Owing(t, r)
	r.mu.Lock()
	r.owedE = nil
	r.mu.Unlock()
	r.cs.failNext(1)
	p := r.dial(enrolment())
	p.send(run6())
	if got := p.closed(); got != netobs.ClosePositionNotSaved {
		t.Fatalf("close %q", got)
	}
	if w := r.owedNow(); len(w) != 1 || !isRun5(w[0]) {
		t.Fatalf("owed %+v", w)
	}
	if c := cursorNow(t, r.cs); c.RunCounter != 5 || !c.Prior.Owed {
		t.Fatalf("cursor %+v", c)
	}
	r.accepted(run6()).end()
	w := r.owedNow()
	if len(w) != 3 || !isRun5(w[1]) || w[2].RunID != testRun2 {
		t.Fatalf("owed %+v", w)
	}
	if string(mustJSON(t, w[0])) != string(mustJSON(t, w[1])) {
		t.Fatalf("the repeat's identity differs:\n%s\n%s", mustJSON(t, w[0]), mustJSON(t, w[1]))
	}
}

// D6's condition 4 (H-8's leg): a cursor that reads as none (its
// generation below Began) with owed marks set has them written under its
// own identity before the new run's save. Control: the old marks dropped.
func TestRow6PositionReadsAsNone(t *testing.T) {
	r := newRig(t, nil)
	run5Owing(t, r)
	r.mu.Lock()
	r.owedE = nil
	r.mu.Unlock()
	en := enrolment()
	en.Generation, en.Began = 3, 3
	h := hello02() // run 5 again: the position reads as none, so a new run
	h.Generation = "3"
	r.accepted6(en, h)
	w := r.owedNow()
	if len(w) != 2 || !isRun5(w[0]) || w[1].Generation != 3 {
		t.Fatalf("owed %+v", w)
	}
}

// D6's condition 5: a hello that closes at rows 1 to 7 writes nothing of
// what the cursor owes. Control: the write before JudgeHello's verdict.
func TestOwedOnlyAfterAccept(t *testing.T) {
	r := newRig(t, nil)
	run5Owing(t, r)
	r.mu.Lock()
	r.owedE = nil
	r.mu.Unlock()
	bad := run6()
	bad.BufferBytes = "1024" // row 1
	binding := run6()
	binding.Generation = "1" // row 2
	regressed := run6()
	regressed.RunCounter = "4" // row 3
	forked := run6()
	forked.RunCounter = "5" // row 4
	noPrior := run6()
	noPrior.Prior = nil // row 6 without prior
	pin := run6()
	pin.PinnedBy = "console" // row 7
	for i, h := range []*netobs.SensorHello{bad, binding, regressed, forked, noPrior, pin} {
		p := r.dial(enrolment())
		p.send(h)
		if got := p.closed(); got == "" {
			t.Fatalf("hello %d not closed", i)
		}
		if w := r.owedNow(); len(w) != 0 {
			t.Fatalf("hello %d wrote %+v", i, w)
		}
	}
}

// D3's condition 4 (D1's "D3 3"): an owed write that fails mid-run, at a
// tick, raises and the connection stays open, the marks kept. Control: the
// error dropped, as the reviewed code did (nothing raised).
func TestOwedFailsInRunRaises(t *testing.T) {
	r := newRig(t, nil)
	p := r.accepted(hello02())
	r.mu.Lock()
	r.owedE = errors.New("test: the health stream is down")
	r.mu.Unlock()
	r.tickAfter(p, spanTick(1, lspan("09:00:00", "09:10:00")))
	p.send(obs02(1))
	p.ack(1)
	p.stillOpen()
	if r.al.count(AlarmPositionNotSaved) != 1 || !r.raised(AlarmPositionNotSaved, "1 owed events") {
		t.Fatalf("raises %v", r.al.list)
	}
	if c := cursorNow(t, r.cs); !c.Spans[0].Owed {
		t.Fatalf("mark cleared: %+v", c.Spans)
	}
}
