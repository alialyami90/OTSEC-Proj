package contract

// C4 otsec.event/0.5 (docs/phase4/D4-c4-0.5-proposal.md, approved at
// a7e91394 on #753), row E5-3: every earlier reader accepts every 0.5
// event, so 0.5 has no reader floor (§3). testdata/c4-v05 holds D6's
// folded 0.5 sensor.counters, written from C4-0.5-1 and C4-0.5-2 before
// any code writes minor 5. It carries runs_folded, diff.packets, a 0.4
// capture counter that rose (diff.drops_holder) and its capture_loss, so a
// 0.4 reader's C4-0.4-2 runs on a folded event with a loss.
//
// The legs (§5, E5-3, "How it runs"):
//
//   - The C4 0.4 code on main: this test, committed before the 0.5 code
//     lands, as 0.4's E4-4 was.
//   - The C4 0.3 code at c9d4d6c8: a one-time desk run on that SHA's
//     tree, with this file and the fixture copied in, recorded below.
//   - The C4 0.5 code: this test again, once that code has merged.
//
// One-time leg on the 0.3 code (desk, Go 1.27.3 windows/amd64,
// 2026-11-19), on the tree of `git archive c9d4d6c8`, whose Identifier is
// otsec.event/0.3:
//
//	go test ./tests/contract/ -run TestC4v05E53 -count=1 -v
//	=== RUN   TestC4v05E53OldReaders
//	--- PASS: TestC4v05E53OldReaders (0.00s)
//	PASS
//	ok  	otsec.local/otsec/tests/contract	0.287s
//
// The 0.3 reader also accepts the folded event without capture_loss, and
// with a capture_loss that names a counter at 0, because it checks neither
// (C4-0.4-2 is 0.4's); it does the same with 0.4 events. The test asserts
// what each reader does.
//
// Control: a reader that refuses the details of a later minor, which would
// mean 0.5 needs a reader floor. With `later := false` in
// checkSensorCounters the test fails on the 0.4 code at 067d2a62
// ("health.details.runs_folded: enum: not a detail of sensor.counters in
// otsec.event/0.5") and on the 0.3 code at c9d4d6c8 (runs_folded,
// diff.drops_holder and capture_loss refused, enum).
//
// Ground truth: GT-HAND, from the approved text. Every value is
// constructed; none is device output. Evidence class: desk, and CI-Linux
// and CI-Windows for the leg on main.

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/event"
)

const c4v5FoldedFile = "testdata/c4-v05/event-0.5-sensor-counters-folded.json"

func TestC4v05E53OldReaders(t *testing.T) {
	b, err := os.ReadFile(c4v5FoldedFile)
	if err != nil {
		t.Fatal(err)
	}
	e, err := event.Decode(b)
	if err != nil {
		t.Fatalf("the %s reader refuses the folded 0.5 sensor.counters: %v", event.Identifier, err)
	}
	if err := e.Validate(); err != nil {
		t.Fatalf("the %s reader's Validate refuses the folded 0.5 sensor.counters: %v", event.Identifier, err)
	}

	// The fixture is what E5-3 names, and the reader keeps runs_folded.
	if e.Schema != "otsec.event/0.5" || e.Kind != event.KindHealth || e.Health == nil || e.Health.Type != "sensor.counters" || e.ID.Seq == 0 {
		t.Fatalf("schema %q, kind %q, health %v, seq %d: want a stored 0.5 sensor.counters", e.Schema, e.Kind, e.Health, e.ID.Seq)
	}
	d := e.Health.Details
	for k, want := range map[string]string{"runs_folded": "2", "diff.packets": "4800", "diff.drops_holder": "3", "capture_loss": "drops_holder"} {
		if d[k] != want {
			t.Errorf("%s %q, want %q", k, d[k], want)
		}
	}
	if slices.Contains(event.SensorCounters, "drops_holder") {
		t.Error("drops_holder is a 0.3 counter; E5-3 needs a 0.4 capture counter")
	}

	// C4-0.4-2 and C4-0.4-3 on the folded event: the 0.4 reader, and any
	// later one, applies them to a 0.5 event (C4-0.5-2: "unchanged, applied
	// to the summed values"). The 0.3 reader checks neither C4-0.4-2 rule;
	// without diff.packets it has no counter of its own and refuses the
	// event too ("no diff.<counter>").
	old := event.Identifier == "otsec.event/0.3"
	for _, c := range []struct {
		name  string
		edit  func(map[string]any)
		field string
		code  event.Code
		at03  bool // the 0.3 reader accepts it
	}{
		{"without capture_loss", func(d map[string]any) { delete(d, "capture_loss") },
			"health.details.capture_loss", event.CodeMissing, true},
		{"capture_loss naming a counter at 0", func(d map[string]any) {
			d["diff.frames_overlong"] = "0"
			d["capture_loss"] = "drops_holder frames_overlong"
		}, "health.details.capture_loss", event.CodeEnum, true},
		{"without diff.packets", func(d map[string]any) { delete(d, "diff.packets") },
			"health.details.diff.packets", event.CodeMissing, false},
	} {
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatal(err)
		}
		c.edit(m["health"].(map[string]any)["details"].(map[string]any))
		v, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		_, err = event.Decode(v)
		switch {
		case old && c.at03:
			if err != nil {
				t.Errorf("%s: the 0.3 reader refuses it: %v", c.name, err)
			}
		case old:
			if !slices.Contains(event.Codes(err), c.code) {
				t.Errorf("%s: the 0.3 reader gives %v, want %s", c.name, err, c.code)
			}
		case !slices.Contains(event.Codes(err), c.code) || !strings.Contains(fmt.Sprint(err), c.field+": "+string(c.code)):
			t.Errorf("%s: the %s reader gives %v, want %s refused as %s", c.name, event.Identifier, err, c.field, c.code)
		}
	}
}
