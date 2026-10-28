package eventbaseline_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"otsec.local/otsec/contracts/baseline"
	"otsec.local/otsec/contracts/event"
	"otsec.local/otsec/modules/detection/eventbaseline"
)

// The D4-30 caps that are not in the format alone. Everything here is
// `simulated`.

// TestHeldIDBudget: once the detector's pending records list heldIDBudget
// IDs, a further held break is counted for the next alarm's note and not
// listed; an alarm that lists a record's IDs frees them for later breaks.
// Budget 4, one alarm per hold.
func TestHeldIDBudget(t *testing.T) {
	defer eventbaseline.SetHeldIDBudget(4)()
	d, cfg := plainDetector(t, 2100, func(p *baseline.Params) { p.MaxAlarmsPerHold = 1 })
	feed := func(e *event.Event) eventbaseline.Output {
		t.Helper()
		o, err := d.Observe(eventbaseline.Obs{Event: e})
		if err != nil {
			t.Fatal(err)
		}
		if c, l := d.HeldIDs(); c != l {
			t.Fatalf("the detector counts %d listed IDs, its records list %d", c, l)
		}
		return o
	}
	check := func(what string, listed, beyond int64) {
		t.Helper()
		c, _ := d.HeldIDs()
		if d.ListedHeld() != listed || d.BeyondNow() != beyond || int64(c) != listed {
			t.Errorf("%s: %d held and listed (%d IDs), %d unlisted; want %d and %d", what, d.ListedHeld(), c, d.BeyondNow(), listed, beyond)
		}
		snap := mustSnap(t, d.Snapshot)
		if r, err := eventbaseline.RestoreDetector(cfg, snap); err != nil || !bytes.Equal(mustSnap(t, r.Snapshot), snap) {
			t.Errorf("%s: restore: %v", what, err)
		}
	}

	if o := feed(ser("X", "Asserted", at(2101), "")); len(o.Alarms) != 1 {
		t.Fatalf("the new type raised %d alarms", len(o.Alarms))
	}
	// A rate break of A, held by the used-up hold: its record lists it.
	for i := 0; i < 3; i++ {
		feed(ser("A", "Asserted", at(2200+i), ""))
	}
	check("after the held rate break", 1, 0)
	// Ten new types, each held: three fit the budget, seven do not.
	for i := 0; i < 10; i++ {
		feed(ser(fmt.Sprintf("Q%d", i), "Asserted", at(2300+i), ""))
	}
	check("after ten held new types", 4, 7)

	// The next hold, a day on: A's rate alarm lists its held break and states the
	// seven, and its record's ID is free again.
	var o eventbaseline.Output
	for i := 0; i < 3; i++ {
		o = feed(ser("A", "Asserted", at(86400+100+i), "")) // the next day's hour 0, so the time rule stays quiet
	}
	if len(o.Alarms) != 1 || o.Alarms[0].Rule != baseline.RuleRate {
		t.Fatalf("the next hold's rate break raised %v", o.Alarms)
	}
	m := beyondNote.FindStringSubmatch(o.Alarms[0].Observation)
	if m == nil || m[1] != "7" || o.Alarms[0].EventsTotal != 4 {
		t.Errorf("the alarm says %q with %d events: want 7 not listed and 4 events (the held break and the bucket's three)", o.Alarms[0].Observation, o.Alarms[0].EventsTotal)
	}
	check("after the rate alarm", 3, 0)
	feed(ser("Q10", "Asserted", at(86400+200), ""))
	check("after one more held new type", 4, 0)
}

// TestSnapshotStreamsBound: a detector whose held IDs name more than
// MaxStreams (node, stream) pairs is refused a snapshot, and one at
// MaxStreams is not.
func TestSnapshotStreamsBound(t *testing.T) {
	for _, tc := range []struct {
		streams int
		ok      bool
	}{{eventbaseline.MaxStreams, true}, {eventbaseline.MaxStreams + 1, false}} {
		d, cfg := plainDetector(t, 2100, func(p *baseline.Params) { p.MaxAlarmsPerHold = 1 })
		// X's alarm uses the hold, so each Q is held and its ID listed.
		if _, err := d.Observe(eventbaseline.Obs{Event: ser("X", "Asserted", at(2101), "")}); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < tc.streams; i++ {
			e := ser(fmt.Sprintf("Q%d", i), "Asserted", at(2102+i), "")
			e.ID.Stream = event.Stream(fmt.Sprintf("events/unit-%d", i))
			if _, err := d.Observe(eventbaseline.Obs{Event: e}); err != nil {
				t.Fatal(err)
			}
		}
		b, err := d.Snapshot(0)
		if tc.ok != (err == nil) || (!tc.ok && (!errors.Is(err, eventbaseline.ErrSnapshotTooLarge) || b != nil)) {
			t.Errorf("%d streams: %d bytes, %v", tc.streams, len(b), err)
		}
		if !tc.ok {
			continue
		}
		// Restore reads the table to MaxStreams too: one more entry, which
		// no ID names, is refused.
		off := 6      // magic, version, kind
		for range 2 { // hash, asset
			n, w := binary.Uvarint(b[off:])
			off += w + int(n)
		}
		for range 2 { // activation, types
			_, w := binary.Uvarint(b[off:])
			off += w
		}
		if b[off] != byte(eventbaseline.MaxStreams) {
			t.Fatalf("the event ID table is not where the test expects")
		}
		extra := append([]byte{byte(eventbaseline.MaxStreams + 1)}, "\x05node2\x05other"...)
		bad := append(append(append([]byte{}, b[:off]...), extra...), b[off+1:]...)
		if r, err := eventbaseline.RestoreDetector(cfg, reseal(bad)); !errors.Is(err, eventbaseline.ErrSnapshot) || r != nil {
			t.Errorf("a table of %d streams: %v, %v", eventbaseline.MaxStreams+1, r, err)
		}
	}
}

// TestGapRefusesWhatTheRecordCannotHold: a reason that is not a C10 token, a
// gap that ends before it starts and a time past the year 9999 are refused
// with ErrGap and not taken; the period is as if they were never given.
func TestGapRefusesWhatTheRecordCannotHold(t *testing.T) {
	far := time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name     string
		from, to time.Time
		reason   string
	}{
		{"empty reason", at(100), at(400), ""},
		{"upper case", at(100), at(400), "Failed.timeout"},
		{"65 bytes", at(100), at(400), "f" + strings.Repeat("a", 64)},
		{"a space", at(100), at(400), "failed timeout"},
		{"backwards", at(400), at(100), "failed.timeout"},
		{"year 10000", at(100), far, "failed.timeout"},
	} {
		l := learner(t, nil)
		ref := learner(t, nil)
		if err := l.Gap(tc.from, tc.to, tc.reason); !errors.Is(err, eventbaseline.ErrGap) {
			t.Errorf("%s: %v", tc.name, err)
		}
		for _, x := range []*eventbaseline.Learner{l, ref} {
			observe(t, x, ser("A", "Asserted", at(0), ""), ser("A", "Asserted", at(900), ""))
		}
		a, b := mustSnap(t, l.Snapshot), mustSnap(t, ref.Snapshot)
		if !bytes.Equal(a, b) {
			t.Errorf("%s: the refused gap changed the learner", tc.name)
		}
	}
	l := learner(t, nil)
	if err := l.Gap(at(100), at(400), "failed.timeout"); err != nil {
		t.Errorf("a well-formed gap: %v", err)
	}
	// MaxGaps + 1 gaps: the last is merged into the one before, so the time
	// between them counts as not collected.
	m := learner(t, nil)
	observe(t, m, ser("A", "Asserted", at(0), ""))
	for i := 0; i <= eventbaseline.MaxGaps; i++ {
		if err := m.Gap(at(10*i+1), at(10*i+5), "failed.timeout"); err != nil {
			t.Fatal(err)
		}
	}
	end := 10*eventbaseline.MaxGaps + 100
	observe(t, m, ser("A", "Asserted", at(end), ""))
	p := m.Progress(at(end))
	want := int64(end) - int64(4*(eventbaseline.MaxGaps-1)) - int64(10*eventbaseline.MaxGaps+5-(10*(eventbaseline.MaxGaps-1)+1))
	if p.CollectedS != want {
		t.Errorf("collected %d s, want %d (%d gaps of 4 s and one merged of 14 s)", p.CollectedS, want, eventbaseline.MaxGaps-1)
	}
}
