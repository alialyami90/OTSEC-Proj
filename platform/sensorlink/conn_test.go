package sensorlink

import (
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/netobs"
)

// The intake legs of C13 0.2 §15's rows (P4-4-INT's split §2.3): the node
// applies each contracts/netobs verdict as the row states. Each control is
// an intake that takes the verdict and does not act on it (D6's N3 on
// #719); the control named in each test is the mutation that makes it fail.

// A new run accepted, two records stored, the position saved with them,
// and acks that name the saved T.
func TestIntakeNewRunStoresAndAcks(t *testing.T) {
	r := newRig(t, nil)
	p := r.dial(enrolment())
	p.send(hello02())
	p.ack(0)
	p.send(obs02(1), obs02(2))
	p.ack(1)
	p.ack(2)
	if got := storedObs(t, r.s); len(got) != 2 {
		t.Fatalf("%d stored, want 2", len(got))
	}
	c := cursorNow(t, r.cs)
	if c.RunID != testRun || c.RunCounter != 5 || c.Generation != 2 || c.Taken != 2 || c.Digest != testDigest {
		t.Fatalf("cursor %+v", c)
	}
	if got := p.end(); got != "" {
		t.Fatalf("close %q at the sensor's end", got)
	}
}

// M-1: the sensor's closed set. A type outside it, an alert among them, is
// refused as type, the connection open, nothing stored. Control: a type
// added to the set (the intake stores or closes on it).
func TestIntakeM1ClosedSet(t *testing.T) {
	r := newRig(t, nil)
	p := r.dial(enrolment())
	p.send(hello02())
	p.ack(0)
	alert := encodeMut(t, obs02(1), func(m map[string]any) { m["type"] = "alert" })
	other := encodeMut(t, obs02(1), func(m map[string]any) { m["type"] = "ack" })
	p.send(alert, other)
	settle(t, r.l, func(s Stats) bool { return s.Refused[string(netobs.CodeType)] == 2 })
	p.send(obs02(1))
	p.ack(1)
	p.stillOpen()
	if got := storedObs(t, r.s); len(got) != 1 {
		t.Fatalf("%d stored, want 1", len(got))
	}
}

// M-2: a sensor frame above 64 KiB closes the node's connection as
// frame-too-large. Control: the cap raised.
func TestIntakeM2FrameTooLarge(t *testing.T) {
	r := newRig(t, nil)
	p := r.dial(enrolment())
	p.send(hello02())
	p.ack(0)
	go func() { _, _ = p.c.Write(binary.BigEndian.AppendUint32(nil, netobs.MaxChannelFrame+1)) }()
	if got := p.closed(); got != netobs.CloseFrameTooLarge {
		t.Fatalf("close %q, want %s", got, netobs.CloseFrameTooLarge)
	}
	if closes(r.l, netobs.CloseFrameTooLarge) != 1 {
		t.Fatal("frame-too-large not counted")
	}
}

// M-3: a heartbeat first closes as hello; a hello that fails its strict
// decode closes as hello; a second hello closes as hello.
func TestIntakeM3HelloFirst(t *testing.T) {
	cases := []struct {
		name  string
		first []any
	}{
		{"heartbeat first", []any{heartbeat02(1, 10)}},
		{"observation first", []any{obs02(1)}},
		{"tick first", []any{tick02(1, 0, 0)}},
		{"unknown key", []any{encodeMut(t, hello02(), func(m map[string]any) { m["extra"] = 1 })}},
		{"duplicate key", []any{[]byte(strings.Replace(string(mustJSON(t, hello02())), `"type"`, `"type":"sensor-hello","type"`, 1))}},
		{"leading zero", []any{encodeMut(t, hello02(), func(m map[string]any) { m["first_seq"] = "01" })}},
		{"above 2^64-1", []any{encodeMut(t, hello02(), func(m map[string]any) { m["newest_seq"] = "18446744073709551616" })}},
		{"missing key", []any{encodeMut(t, hello02(), func(m map[string]any) { delete(m, "current") })}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newRig(t, nil)
			p := r.dial(enrolment())
			p.send(c.first...)
			if got := p.closed(); got != netobs.CloseHello {
				t.Fatalf("close %q, want hello", got)
			}
			if cursorNow(t, r.cs) != nil {
				t.Fatal("a refused hello saved a position")
			}
		})
	}
	t.Run("second hello", func(t *testing.T) {
		r := newRig(t, nil)
		p := r.dial(enrolment())
		p.send(hello02())
		p.ack(0)
		p.send(hello02())
		if got := p.closed(); got != netobs.CloseHello {
			t.Fatalf("close %q, want hello", got)
		}
	})
}

func encodeMut(t *testing.T, v any, mut func(map[string]any)) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(mustJSON(t, v), &m); err != nil {
		t.Fatal(err)
	}
	mut(m)
	return mustJSON(t, m)
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
