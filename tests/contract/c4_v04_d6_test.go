package contract

// C4 otsec.event/0.4 (D4-92; docs/phase4/D4-c4-0.4-proposal.md), D6's
// contract tests for P4-4-CC deliverable 2: E4-1, E4-2, E4-3, E4-5 and E4-8
// of the proposal's §5. E4-7's forward contract leg and E4-4's forward
// check are in cc_d2_forward_d6_test.go; E4-6 and E4-7's store and node
// legs are D5's. The events are D6's own, written from §2's rules.
// Ground truth: GT-HAND, from the approved text. Evidence class: desk.

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/event"
)

// The eight counters C4-0.4-1 adds, in §2's table order.
var c4v4New = []string{"drops_holder", "frames_overlong", "frames_outgoing", "prp_mismatched",
	"prp_table_full", "prp_tag_differs", "prp_wrong_lan", "engine_lines_refused"}

// c4v4Counters builds a sensor.counters event of the given minor with the
// given details beside reported_by, sensor_id and run_id.
func c4v4Counters(t *testing.T, schema string, details map[string]string) []byte {
	t.Helper()
	d := map[string]string{"reported_by": "sensor", "sensor_id": "5a3c2e10-7b4d-4c8e-9f1a-2b3c4d5e6f70",
		"run_id": "0d1e2f30-4a5b-4c6d-8e7f-a0b1c2d3e4f5"}
	for k, v := range details {
		d[k] = v
	}
	e := map[string]any{"schema": schema, "id": map[string]any{"node_id": "d6-node", "stream": "platform/health", "seq": 12},
		"origin": "platform", "kind": "telemetry-health", "source": map[string]any{"origin_auth": "platform"},
		"received": map[string]any{"utc": "2026-11-15T10:10:00.000125Z", "resolution_ns": 1000,
			"clock": map[string]any{"sync": "synchronized", "source": "chrony"}},
		"health": map[string]any{"type": "sensor.counters", "details": d}}
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// c4v4Refused reports whether err holds code on the detail named.
func c4v4Refused(err error, field string, code event.Code) bool {
	return slices.Contains(event.Codes(err), code) && strings.Contains(fmt.Sprint(err), field+": "+string(code))
}

// E4-1 (C4-0.4-1): each new name accepted as diff.<name> at 0.4, and the
// same event stamped 0.3 refused for it (enum).
func TestC4v04E41NewCounters(t *testing.T) {
	for _, n := range c4v4New {
		d := map[string]string{"diff.packets": "10", "diff." + n: "5"}
		at4 := map[string]string{"diff.packets": "10", "diff." + n: "5"}
		if n == "drops_holder" || n == "frames_overlong" {
			at4["capture_loss"] = n
		}
		if _, err := event.Decode(c4v4Counters(t, "otsec.event/0.4", at4)); err != nil {
			t.Errorf("diff.%s at 0.4: %v", n, err)
		}
		_, err := event.Decode(c4v4Counters(t, "otsec.event/0.3", d))
		if !c4v4Refused(err, "health.details.diff."+n, event.CodeEnum) {
			t.Errorf("diff.%s at 0.3: %v, want enum", n, err)
		}
	}
	// All eight together, with the 0.3 counters, at 0.4.
	d := map[string]string{"capture_loss": "drops_driver drops_holder frames_overlong"}
	for _, n := range append(slices.Clone(event.SensorCounters), c4v4New...) {
		d["diff."+n] = "1"
	}
	if _, err := event.Decode(c4v4Counters(t, "otsec.event/0.4", d)); err != nil {
		t.Errorf("all 21 counters at 0.4: %v", err)
	}
	// A name 0.4 does not add is still refused at 0.4.
	_, err := event.Decode(c4v4Counters(t, "otsec.event/0.4", map[string]string{"diff.packets": "1", "diff.agent.closes.ack": "1"}))
	if !c4v4Refused(err, "health.details.diff.agent.closes.ack", event.CodeEnum) {
		t.Errorf("an agent count at 0.4: %v, want enum (C4 0.4 §2: not added)", err)
	}
}

// E4-2 (C4-0.4-2): capture_loss present exactly when diff.drops_driver,
// diff.drops_holder or diff.frames_overlong is above 0, naming those that
// are, in that order.
func TestC4v04E42CaptureLoss(t *testing.T) {
	type tc struct {
		name string
		d    map[string]string
		code event.Code // "" when accepted
	}
	for _, c := range []tc{
		{"drops_holder rose, named", map[string]string{"diff.drops_holder": "3", "capture_loss": "drops_holder"}, ""},
		{"drops_driver rose, named", map[string]string{"diff.drops_driver": "2", "capture_loss": "drops_driver"}, ""},
		{"frames_overlong rose, named", map[string]string{"diff.frames_overlong": "1", "capture_loss": "frames_overlong"}, ""},
		{"all three rose, in order", map[string]string{"diff.drops_driver": "1", "diff.drops_holder": "1", "diff.frames_overlong": "1",
			"capture_loss": "drops_driver drops_holder frames_overlong"}, ""},
		{"two rose, one at 0", map[string]string{"diff.drops_driver": "1", "diff.drops_holder": "0", "diff.frames_overlong": "4",
			"capture_loss": "drops_driver frames_overlong"}, ""},
		{"none of the three rose", map[string]string{"diff.drops_driver": "0", "diff.drops_holder": "0", "diff.frames_overlong": "0"}, ""},
		{"none of the three carried", map[string]string{"diff.drops_decoder": "9", "diff.drops_channel": "9"}, ""},
		{"absent when drops_holder rose", map[string]string{"diff.drops_holder": "3"}, event.CodeMissing},
		{"absent when drops_driver rose", map[string]string{"diff.drops_driver": "1"}, event.CodeMissing},
		{"present when none rose", map[string]string{"diff.drops_holder": "0", "capture_loss": "drops_holder"}, event.CodeEnum},
		{"present when none is carried", map[string]string{"capture_loss": "drops_holder"}, event.CodeEnum},
		{"out of order", map[string]string{"diff.drops_holder": "1", "diff.frames_overlong": "1", "capture_loss": "frames_overlong drops_holder"}, event.CodeEnum},
		{"one that rose left out", map[string]string{"diff.drops_holder": "1", "diff.frames_overlong": "1", "capture_loss": "drops_holder"}, event.CodeEnum},
		{"names one that did not rise", map[string]string{"diff.drops_holder": "1", "diff.frames_overlong": "0", "capture_loss": "drops_holder frames_overlong"}, event.CodeEnum},
		{"names drops_decoder", map[string]string{"diff.drops_decoder": "1", "diff.drops_holder": "1", "capture_loss": "drops_decoder drops_holder"}, event.CodeEnum},
		{"names drops_channel", map[string]string{"diff.drops_channel": "1", "capture_loss": "drops_channel"}, event.CodeEnum},
		{"two spaces", map[string]string{"diff.drops_driver": "1", "diff.drops_holder": "1", "capture_loss": "drops_driver  drops_holder"}, event.CodeEnum},
		{"a trailing space", map[string]string{"diff.drops_holder": "1", "capture_loss": "drops_holder "}, event.CodeEnum},
		{"a comma", map[string]string{"diff.drops_driver": "1", "diff.drops_holder": "1", "capture_loss": "drops_driver,drops_holder"}, event.CodeEnum},
		{"a name repeated", map[string]string{"diff.drops_holder": "1", "capture_loss": "drops_holder drops_holder"}, event.CodeEnum},
	} {
		d := map[string]string{"diff.packets": "10"}
		for k, v := range c.d {
			d[k] = v
		}
		_, err := event.Decode(c4v4Counters(t, "otsec.event/0.4", d))
		switch {
		case c.code == "" && err != nil:
			t.Errorf("%s: %v", c.name, err)
		case c.code != "" && !c4v4Refused(err, "health.details.capture_loss", c.code):
			t.Errorf("%s: %v, want capture_loss refused as %s", c.name, err, c.code)
		}
	}
	// At 0.3 the detail does not exist.
	_, err := event.Decode(c4v4Counters(t, "otsec.event/0.3", map[string]string{"diff.drops_driver": "1", "capture_loss": "drops_driver"}))
	if !c4v4Refused(err, "health.details.capture_loss", event.CodeEnum) {
		t.Errorf("capture_loss at 0.3: %v, want enum", err)
	}
	if _, err := event.Decode(c4v4Counters(t, "otsec.event/0.3", map[string]string{"diff.drops_driver": "1"})); err != nil {
		t.Errorf("drops_driver rose at 0.3, no capture_loss: %v", err)
	}
}

// E4-3 (C4-0.4-3): a 0.4 event without diff.packets is refused (missing);
// at 0.3 it is not required.
func TestC4v04E43Packets(t *testing.T) {
	for _, n := range []string{"bytes", "frames_outgoing", "engine_lines_refused"} {
		_, err := event.Decode(c4v4Counters(t, "otsec.event/0.4", map[string]string{"diff." + n: "1"}))
		if !c4v4Refused(err, "health.details.diff.packets", event.CodeMissing) {
			t.Errorf("0.4 with diff.%s and no diff.packets: %v, want diff.packets missing", n, err)
		}
	}
	if _, err := event.Decode(c4v4Counters(t, "otsec.event/0.4", map[string]string{"diff.packets": "0"})); err != nil {
		t.Errorf("0.4 with diff.packets 0 alone: %v", err)
	}
	if _, err := event.Decode(c4v4Counters(t, "otsec.event/0.3", map[string]string{"diff.bytes": "1"})); err != nil {
		t.Errorf("0.3 with diff.bytes and no diff.packets: %v", err)
	}
}

// E4-5 (C4-0.4-1): a total of a new counter is refused, without diff. or
// with total.; at 0.4 by the rule on totals (forbidden), as 0.3 refuses
// its own.
func TestC4v04E45Totals(t *testing.T) {
	for _, n := range c4v4New {
		for _, k := range []string{n, "total." + n} {
			_, err := event.Decode(c4v4Counters(t, "otsec.event/0.4", map[string]string{"diff.packets": "1", k: "5"}))
			if !c4v4Refused(err, "health.details."+k, event.CodeForbidden) {
				t.Errorf("%s at 0.4: %v, want forbidden", k, err)
			}
		}
	}
}

// E4-8: diff.<name> of each new counter at 2^64 - 1 accepted; at 2^64, with
// a leading zero, or negative, refused, naming the field. C4 0.4 §2 and C4
// 0.3 §5 say "refused" and state no code, so none is asserted.
func TestC4v04E48Bounds(t *testing.T) {
	for _, n := range c4v4New {
		d := map[string]string{"diff.packets": "1", "diff." + n: "18446744073709551615"}
		if n == "drops_holder" || n == "frames_overlong" {
			d["capture_loss"] = n
		}
		if _, err := event.Decode(c4v4Counters(t, "otsec.event/0.4", d)); err != nil {
			t.Errorf("diff.%s at 2^64 - 1: %v", n, err)
		}
		for _, v := range []string{"18446744073709551616", "99999999999999999999", "05", "00", "-1", "+1", "1.0", "1e3", "", " 1"} {
			d := map[string]string{"diff.packets": "1", "diff." + n: v}
			_, err := event.Decode(c4v4Counters(t, "otsec.event/0.4", d))
			if err == nil || !strings.Contains(fmt.Sprint(err), "health.details.diff."+n+":") {
				t.Errorf("diff.%s %q: %v, want it refused, naming the field", n, v, err)
			}
		}
	}
}
