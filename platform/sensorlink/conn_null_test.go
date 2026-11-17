package sensorlink

import (
	"encoding/json"
	"testing"
	"time"

	"otsec.local/otsec/contracts/netobs"
)

// withNull is v's JSON with the value at path (object keys) set to null,
// or left as it is when null is false.
func withNull(t *testing.T, v any, null bool, path ...string) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(mustJSON(t, v), &m); err != nil {
		t.Fatal(err)
	}
	if null {
		at := m
		for _, k := range path[:len(path)-1] {
			at = at[k].(map[string]any)
		}
		at[path[len(path)-1]] = nil
	}
	return mustJSON(t, m)
}

// P4-4-NULL over ServeConn (#735; D5's note 3 in its review there): a
// null in an observation (coverage.degraded, which read as not degraded)
// is refused form, takes its seq, and the connection stays open; a null
// in a tick (lost) closes tick. Controls: the same frames without the
// null are taken (the observation stored, the tick acked).
func TestNullOverServeConn(t *testing.T) {
	for _, null := range []bool{true, false} {
		t.Run(map[bool]string{true: "null", false: "control"}[null], func(t *testing.T) {
			r := newRig(t, nil)
			p := r.accepted(hello02())
			p.send(withNull(t, obs02(1), null, "coverage", "degraded"), obs02(2))
			p.ack(2)
			want := map[bool]int{true: 1, false: 2}[null]
			if n := len(storedObs(t, r.s)); n != want {
				t.Fatalf("%d stored, want %d", n, want)
			}
			if got := refused(r.l, string(netobs.CodeForm)); (got == 1) != null {
				t.Fatalf("refused form %d", got)
			}
			p.stillOpen()
			p.taken()
			r.clk.add(netobs.TickMinSpacing + time.Second)
			p.send(withNull(t, tick02(20, 2, 0), null, "lost"))
			if !null {
				p.send(obs02(3))
				p.ack(3)
				return
			}
			if got := p.closed(); got != netobs.CloseTick {
				t.Fatalf("close %q, want tick", got)
			}
			if c := cursorNow(t, r.cs); c.Refused != 1 || c.Taken != 2 {
				t.Fatalf("cursor: refused %d, T %d", c.Refused, c.Taken)
			}
		})
	}
}
