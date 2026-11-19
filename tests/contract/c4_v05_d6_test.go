package contract

// C4 otsec.event/0.5 (docs/phase4/D4-c4-0.5-proposal.md, approved at
// a7e91394 on #753), D6's independent rows E5-1, E5-2 and E5-4, and E5-8's
// contract leg (§5; D6's N5 on #753; brief P4-D6-C405). E5-3 is in
// c4_v05_old_readers_d6_test.go. E5-5 to E5-7 and E5-9 are D5's. The
// events are D6's own, built with c4v4Counters (c4_v04_d6_test.go) from
// C4-0.5-1 to C4-0.5-3, not from D4's code or testdata.
// Ground truth: GT-HAND, from the approved text. Evidence class: desk.

import (
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/event"
)

const (
	c4v5Max  = "18446744073709551615" // 2^64 - 1
	c4v5Over = "18446744073709551616" // 2^64
)

// E5-1 (C4-0.5-1): runs_folded is a decimal from 1 to 2^64 - 1 with no
// leading zero, in an event of minor 0.5 or later. Every other form is
// refused (enum), naming the detail. An event without it is one run, as in
// 0.4, and is accepted.
func TestC4v05E51RunsFolded(t *testing.T) {
	for _, schema := range []string{"otsec.event/0.5", "otsec.event/0.6"} {
		if _, err := event.Decode(c4v4Counters(t, schema, map[string]string{"diff.packets": "10"})); err != nil {
			t.Errorf("%s without runs_folded (one run): %v", schema, err)
		}
		for _, v := range []string{"1", "2", "9", "10", "18446744073709551614", c4v5Max} {
			if _, err := event.Decode(c4v4Counters(t, schema, map[string]string{"diff.packets": "10", "runs_folded": v})); err != nil {
				t.Errorf("%s runs_folded %q: %v", schema, v, err)
			}
		}
		for _, v := range []string{"0", "00", "01", "007", "-1", "+1", "1.0", "", " 1", "1 ", "1e3", "0x1", "١",
			c4v5Over, "99999999999999999999", "100000000000000000000"} {
			_, err := event.Decode(c4v4Counters(t, schema, map[string]string{"diff.packets": "10", "runs_folded": v}))
			if !c4v4Refused(err, "health.details.runs_folded", event.CodeEnum) {
				t.Errorf("%s runs_folded %q: %v, want enum", schema, v, err)
			}
		}
	}
}

// E5-2 (C4-0.5-1): runs_folded is new in 0.5. On an event stamped 0.4 or
// 0.3 it is refused as a detail that minor does not define (enum). It is
// not a counter: diff.runs_folded and total.runs_folded are refused at 0.5
// as details the minor does not define, and runs_folded alone is not the
// diff.<counter> an event needs.
func TestC4v05E52Minors(t *testing.T) {
	// The folded event of E5-4 is valid at 0.4 but for runs_folded, so that
	// detail is the one refusal.
	folded := map[string]string{"diff.packets": "10", "diff.drops_holder": "3", "capture_loss": "drops_holder", "runs_folded": "1"}
	_, err := event.Decode(c4v4Counters(t, "otsec.event/0.4", folded))
	want := "health.details.runs_folded: enum: not a detail of sensor.counters in otsec.event/0.4"
	if !slices.Equal(event.Codes(err), []event.Code{event.CodeEnum}) || !strings.Contains(fmt.Sprint(err), want) {
		t.Errorf("runs_folded at 0.4: %v, want only %q", err, want)
	}
	_, err = event.Decode(c4v4Counters(t, "otsec.event/0.3", map[string]string{"diff.packets": "10", "runs_folded": "1"}))
	if !c4v4Refused(err, "health.details.runs_folded", event.CodeEnum) {
		t.Errorf("runs_folded at 0.3: %v, want enum", err)
	}

	for _, k := range []string{"diff.runs_folded", "total.runs_folded"} {
		for _, beside := range []bool{false, true} {
			d := map[string]string{"diff.packets": "10", k: "1"}
			if beside {
				d["runs_folded"] = "1"
			}
			_, err := event.Decode(c4v4Counters(t, "otsec.event/0.5", d))
			if !slices.Equal(event.Codes(err), []event.Code{event.CodeEnum}) || !c4v4Refused(err, "health.details."+k, event.CodeEnum) {
				t.Errorf("%s at 0.5 (runs_folded beside it: %v): %v, want only %s refused, enum", k, beside, err, k)
			}
		}
	}

	_, err = event.Decode(c4v4Counters(t, "otsec.event/0.5", map[string]string{"runs_folded": "2"}))
	if !c4v4Refused(err, "health.details", event.CodeMissing) || !c4v4Refused(err, "health.details.diff.packets", event.CodeMissing) {
		t.Errorf("runs_folded and no diff.<counter>: %v, want no counter (missing) and diff.packets missing", err)
	}
}

// E5-4 (C4-0.5-2): in a folded event, C4-0.4-2 applies to the summed
// values unchanged: capture_loss is present exactly when diff.drops_driver,
// diff.drops_holder or diff.frames_overlong is above 0, naming those that
// are, in that order. C4-0.4-3 is unchanged too: diff.packets is required.
func TestC4v05E54FoldedCaptureLoss(t *testing.T) {
	for _, folded := range []string{"1", "2", c4v5Max} {
		for _, c := range []struct {
			name string
			d    map[string]string
			code event.Code // "" when accepted
		}{
			{"drops_holder rose, named", map[string]string{"diff.drops_holder": "3", "capture_loss": "drops_holder"}, ""},
			{"all three rose, in order", map[string]string{"diff.drops_driver": "1", "diff.drops_holder": "4", "diff.frames_overlong": "2",
				"capture_loss": "drops_driver drops_holder frames_overlong"}, ""},
			{"at the maximum, named", map[string]string{"diff.frames_overlong": c4v5Max, "capture_loss": "frames_overlong"}, ""},
			{"none of the three rose", map[string]string{"diff.drops_driver": "0", "diff.drops_holder": "0", "diff.frames_overlong": "0"}, ""},
			{"none of the three carried", map[string]string{"diff.drops_decoder": "9"}, ""},
			{"drops_holder rose, absent", map[string]string{"diff.drops_holder": "3"}, event.CodeMissing},
			{"at the maximum, absent", map[string]string{"diff.frames_overlong": c4v5Max}, event.CodeMissing},
			{"names a counter at 0", map[string]string{"diff.drops_holder": "0", "capture_loss": "drops_holder"}, event.CodeEnum},
			{"names one not carried", map[string]string{"capture_loss": "drops_holder"}, event.CodeEnum},
			{"one that rose left out", map[string]string{"diff.drops_holder": "1", "diff.frames_overlong": "1", "capture_loss": "drops_holder"}, event.CodeEnum},
			{"out of order", map[string]string{"diff.drops_holder": "1", "diff.frames_overlong": "1", "capture_loss": "frames_overlong drops_holder"}, event.CodeEnum},
		} {
			d := map[string]string{"diff.packets": "10", "runs_folded": folded}
			maps.Copy(d, c.d)
			_, err := event.Decode(c4v4Counters(t, "otsec.event/0.5", d))
			switch {
			case c.code == "" && err != nil:
				t.Errorf("runs_folded %s, %s: %v", folded, c.name, err)
			case c.code != "" && !c4v4Refused(err, "health.details.capture_loss", c.code):
				t.Errorf("runs_folded %s, %s: %v, want capture_loss refused as %s", folded, c.name, err, c.code)
			}
		}
		d := map[string]string{"runs_folded": folded, "diff.drops_holder": "3", "capture_loss": "drops_holder"}
		_, err := event.Decode(c4v4Counters(t, "otsec.event/0.5", d))
		if !c4v4Refused(err, "health.details.diff.packets", event.CodeMissing) {
			t.Errorf("runs_folded %s without diff.packets: %v, want missing", folded, err)
		}
	}
}

// E5-8's contract leg (C4-0.5-3; ruling 6996137498 item 4). E5-8 is a node
// test (D5): the writer never wraps a sum and holds the maximum. What a
// reader sees is checked here: each event that E5-8's cases expect the
// node to write is a valid 0.5 event; a value one above the maximum is
// refused; and the event a wrapping writer would write is accepted. That
// last case is the limit of §6 (the validator checks form, not truth), so
// the control "plain uint64 addition" can be killed only by D5's node
// test, not here.
//
// Runs r1 to r4 follow E5-8. In (a), r1 and r2 rise 2^63 and 2^63 - 1 on
// drops_holder, a sum of exactly 2^64 - 1. In (b), each rises 2^63, a sum
// of 2^64, held at 2^64 - 1. In (b1), r3's only rise is on drops_holder.
// In (b2), r4 rises 1 on frames_overlong and 7 on packets. r1 and r2 each
// rise 10 on packets.
func TestC4v05E58NoWrapContract(t *testing.T) {
	const (
		r2 = "1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d"
		r3 = "2b3c4d5e-6f7a-4b8c-9d0e-1f2a3b4c5d6e"
		r4 = "3c4d5e6f-7a8b-4c9d-a0e1-2f3a4b5c6d7e"
	)
	for _, c := range []struct {
		name string
		d    map[string]string
	}{
		// (a) and (b) write the same event; only the status line differs.
		{"(a) an exact sum of 2^64 - 1, and (b) a sum of 2^64 held", map[string]string{"run_id": r2, "runs_folded": "1",
			"diff.packets": "20", "diff.drops_holder": c4v5Max, "capture_loss": "drops_holder"}},
		{"(b1) a third run's only rise on the held counter", map[string]string{"run_id": r3, "runs_folded": "2",
			"diff.packets": "20", "diff.drops_holder": c4v5Max, "capture_loss": "drops_holder"}},
		{"(b2) a fourth run's rises summed", map[string]string{"run_id": r4, "runs_folded": "3",
			"diff.packets": "27", "diff.drops_holder": c4v5Max, "diff.frames_overlong": "1", "capture_loss": "drops_holder frames_overlong"}},
		{"runs_folded held at the maximum too", map[string]string{"run_id": r4, "runs_folded": c4v5Max,
			"diff.packets": c4v5Max, "diff.drops_holder": c4v5Max, "capture_loss": "drops_holder"}},
	} {
		if _, err := event.Decode(c4v4Counters(t, "otsec.event/0.5", c.d)); err != nil {
			t.Errorf("%s: %v", c.name, err)
		}
	}

	// A writer that sums past 64 bits without holding the maximum writes a
	// value the validator refuses, naming the detail.
	for _, k := range []string{"diff.drops_holder", "runs_folded"} {
		d := map[string]string{"run_id": r2, "runs_folded": "1", "diff.packets": "20", "diff.drops_holder": c4v5Max, "capture_loss": "drops_holder"}
		d[k] = c4v5Over
		_, err := event.Decode(c4v4Counters(t, "otsec.event/0.5", d))
		if err == nil || !strings.Contains(fmt.Sprint(err), "health.details."+k+":") {
			t.Errorf("%s at 2^64: %v, want it refused, naming the detail", k, err)
		}
	}

	// The limit: plain uint64 addition gives 0 for (b), with no
	// capture_loss, and the validator accepts that event (§5, E5-8's
	// control; §6).
	var rise uint64 = 1 << 63
	wrapped := strconv.FormatUint(rise+rise, 10)
	if wrapped != "0" {
		t.Fatalf("2^63 + 2^63 in uint64 is %s", wrapped)
	}
	d := map[string]string{"run_id": r2, "runs_folded": "1", "diff.packets": "20", "diff.drops_holder": wrapped}
	if _, err := event.Decode(c4v4Counters(t, "otsec.event/0.5", d)); err != nil {
		t.Errorf("the wrapped (b): %v; §5 says the validator accepts it, so E5-8's node test is the only check", err)
	}
}
