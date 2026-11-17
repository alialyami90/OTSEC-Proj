package sensorlink

import (
	"errors"
	"strings"
	"testing"
)

// Option (a) for the cursor's bound (D1's ruling on #732, with D3's
// 6948579191 and D6's 6948584141): what a replaced cursor owes is written
// before row 6's save, and the cursor holds one run. The control for each
// test below is the reviewed code's carry (8e5528ea), which saves the new
// run with the old run's owed events carried and unwritten.

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
