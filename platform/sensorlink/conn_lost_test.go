package sensorlink

import (
	"testing"
	"time"

	"otsec.local/otsec/contracts/netobs"
)

// spanTick is a tick of run 5 declaring lost with drops_channel drops.
func spanTick(drops int, lost ...netobs.Span) *netobs.Tick {
	t := tick02(20, 0, drops)
	t.Lost = lost
	return t
}

// S-7's node leg, CH-40's mark (D4's A3): node.lost goes on the next
// stored observation of the run, at most 8 entries, the rest on the one
// after; a new run's prior.lost on its first observation; a window cut to
// nothing writes no entry. Control: no mark.
func TestLostSpanMarksNextObservation(t *testing.T) {
	r := newRig(t, nil)
	h := hello02()
	h.Prior.RecordsLost = "8"
	for i := range 8 {
		m := string(rune('0' + i))
		h.Prior.Lost = append(h.Prior.Lost, lspan("0"+m+":00:00", "0"+m+":01:00"))
	}
	p := r.accepted(h)
	p.send(obs02(1))
	p.ack(1)
	// A span in the run's own list, and one cut to nothing (in 2100).
	tk := spanTick(1, lspan("09:00:00", "09:05:00"), netobs.Span{FromUTC: "2100-01-01T00:00:00Z", ToUTC: "2100-01-01T01:00:00Z"})
	r.tickAfter(p, tk)
	p.send(obs02(2))
	p.ack(2)
	p.send(obs02(3))
	p.ack(3)
	got := storedObs(t, r.s)
	if l := got[0].Node.Lost; len(l) != 8 || l[0] != lspan("00:00:00", "00:01:00") {
		t.Fatalf("first observation: node.lost %+v, want prior.lost's 8", l)
	}
	if l := got[1].Node.Lost; len(l) != 1 || l[0] != lspan("09:00:00", "09:05:00") {
		t.Fatalf("second observation: node.lost %+v", l)
	}
	if l := got[2].Node.Lost; l != nil {
		t.Fatalf("third observation: node.lost %+v, want none", l)
	}
}

// S-10 (a): a span widened with drops_channel rising from 5 to 9 is
// accepted; after a node restart, the resume that states the wider span
// with drops_channel 9 is accepted, opens no second gap, and its window
// ends at the cut end fixed when it was first accepted. The spans are in
// the cursor, never in sensorrun.json, so the run file's legs have nothing
// to roll back. Control: spans kept in memory only (the resume closes
// hello).
func TestLostSpansSurviveRestart(t *testing.T) {
	r := newRig(t, nil)
	p := r.accepted(hello02())
	r.tickAfter(p, spanTick(5, lspan("09:00:00", "09:05:00")))
	r.tickAfter(p, spanTick(9, lspan("09:00:00", "09:07:00")))
	r.tickAfter(p, spanTick(9, lspan("09:00:00", "09:07:00")))
	p.send(obs02(1))
	p.ack(1)
	before := cursorNow(t, r.cs)
	if len(before.Spans) != 1 || before.Spans[0].CutUTC != "2026-11-07T09:07:00Z" || before.Ds != 9 {
		t.Fatalf("held %+v, Ds %d", before.Spans, before.Ds)
	}
	p.end()
	r.restart()
	r.addWall(time.Hour)
	h := resume(2, 20)
	h.DropsChannel, h.Lost = "9", []netobs.Span{lspan("09:00:00", "09:07:00")}
	r.accepted(h).end()
	if cs := r.l.ConnStats(); cs.LostGaps != 0 || r.al.count(AlarmRecordsLost) != 0 {
		t.Fatalf("a second gap: %+v %v", cs, r.al.list)
	}
	if c := cursorNow(t, r.cs); c.Spans[0].CutUTC != before.Spans[0].CutUTC {
		t.Fatalf("cut end %s, want %s", c.Spans[0].CutUTC, before.Spans[0].CutUTC)
	}
}

// S-10 (b) and (e): after a restart, a span wider than the one held with
// no rise above Ds closes the hello; a heartbeat made after an eviction
// and read before the tick that declares its span raises D, and the tick
// is still accepted because the rise is judged against Ds. Controls: (b)
// the stated spans taken as held after a loss; (e) the rise judged against
// D.
func TestLostSpanRiseJudgedAgainstDs(t *testing.T) {
	r := newRig(t, nil)
	p := r.accepted(hello02())
	hb := heartbeat02(1, 10)
	hb.Counters.DropsChannel = 3
	p.send(hb)
	r.tickAfter(p, spanTick(3, lspan("09:00:00", "09:05:00"))) // D is 3, Ds 0: accepted
	r.tickAfter(p, spanTick(3, lspan("09:00:00", "09:05:00")))
	p.ack(1)
	p.stillOpen()
	if c := cursorNow(t, r.cs); c.Ds != 3 || len(c.Spans) != 1 {
		t.Fatalf("cursor %+v", c)
	}
	p.end()
	r.restart()
	h := resume(2, 20)
	h.DropsChannel, h.Lost = "3", []netobs.Span{lspan("09:00:00", "09:06:00")}
	p = r.dial(enrolment())
	p.send(h)
	if got := p.closed(); got != netobs.CloseHello {
		t.Fatalf("close %q, want hello", got)
	}
}

// S-10 (c): a span stated to end in 2100, cut when first accepted, and the
// node restarted an hour later: the cut end is the same. Control: a cut
// end fixed again at the restart.
func TestLostSpanCutOnce(t *testing.T) {
	r := newRig(t, nil)
	p := r.accepted(hello02())
	far := netobs.Span{FromUTC: "2026-11-07T09:59:00Z", ToUTC: "2100-01-01T00:00:00Z"}
	r.tickAfter(p, spanTick(1, far))
	r.tickAfter(p, spanTick(1, far))
	p.end()
	cut := cursorNow(t, r.cs).Spans[0].CutUTC
	if cut != "2026-11-07T10:00:02Z" {
		t.Fatalf("cut %s", cut)
	}
	r.restart()
	r.addWall(time.Hour)
	h := resume(1, 20)
	h.DropsChannel, h.Lost, h.SensorUTC = "1", []netobs.Span{far}, "2100-01-02T00:00:00Z"
	r.accepted(h).end()
	if c := cursorNow(t, r.cs); c.Spans[0].CutUTC != cut || r.l.ConnStats().SpansCut != 0 {
		t.Fatalf("cut %s after the restart, want %s; counted %d", c.Spans[0].CutUTC, cut, r.l.ConnStats().SpansCut)
	}
}

// S-10 (f), one cut end: a cut span widened after its stated end keeps its
// window and raises the gap and the alarm; an uncut span widened reaches
// the new part's cut end. Its fractional leg states every time with six
// fractional digits, which C13 allows: "not cut" compares times, not
// strings (D4's B1 on #732). Controls: the window taken to the new part's
// cut end in both cases; the string compare, which fails the fractional
// leg.
func TestLostSpanOneCutEnd(t *testing.T) {
	for _, frac := range []string{"", ".000000"} {
		t.Run("frac="+frac, func(t *testing.T) {
			sp := func(from, to string) netobs.Span { return lspan(from+frac, to+frac) }
			r := newRig(t, nil)
			p := r.accepted(hello02())
			cutSpan, uncut := sp("09:59:00", "10:05:00"), sp("09:00:00", "09:05:00")
			r.tickAfter(p, spanTick(1, uncut, cutSpan))
			p.send(obs02(1))
			p.ack(1) // the tick is taken
			r.addWall(5 * time.Minute)
			r.tickAfter(p, spanTick(2, sp("09:00:00", "09:10:00"), sp("09:59:00", "10:07:00")))
			p.send(obs02(2))
			p.ack(2)
			p.stillOpen()
			c := cursorNow(t, r.cs)
			if len(c.Spans) != 2 || c.Spans[0].CutUTC != "2026-11-07T09:10:00Z" || c.Spans[1].CutUTC != "2026-11-07T10:00:02Z" {
				t.Fatalf("windows %+v", c.Spans)
			}
			if cs := r.l.ConnStats(); cs.LostGaps != 4 || r.al.count(AlarmRecordsLost) != 2 {
				t.Fatalf("gaps %d, raises %v", cs.LostGaps, r.al.list)
			}
		})
	}
}

// M-10's legs other than §3's (no dial: P4-4-DE): two sensors' open
// connections both close as state-unread when the node's state cannot be
// read, and a cursor that cannot be parsed closes a connection at its
// start as state-unread. The fold and its sensor-state-unread alarm are
// P4-4-DE's (the fold is not built). Control: a node that keeps its open
// connections.
func TestStateUnreadClosesConnections(t *testing.T) {
	a, b := newRig(t, nil), newRig(t, nil)
	pa, pb := a.accepted(hello02()), b.accepted(hello02())
	for _, r := range []*rig{a, b} {
		r.l.CloseConn(netobs.CloseStateUnread)
	}
	if ra, rb := pa.closed(), pb.closed(); ra != netobs.CloseStateUnread || rb != netobs.CloseStateUnread {
		t.Fatalf("closes %q and %q", ra, rb)
	}
	if err := a.cs.SaveSourceCursor(bg, []byte("{not a cursor")); err != nil {
		t.Fatal(err)
	}
	p := a.dial(enrolment())
	p.send(resume(1, 20))
	if got := p.closed(); got != netobs.CloseStateUnread {
		t.Fatalf("close %q at an unreadable cursor", got)
	}
}
