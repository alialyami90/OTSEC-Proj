package contract

// P4-4-CC deliverable 3 (D4-103), N-12's first case
// (docs/phase4/D4-c13-0.3-proposal.md §1.1, §12): a 0.3 stored flow end,
// written from the 0.3 text, read by the 0.2 decoder with the new fields
// ignored; and the brief's "The backward fixtures also hold forward": the
// same fixtures validate under the 0.3 code, every field read.
//
// The fixtures are testdata/cc-d3/event-0.4-netobs-0.3-end-*.json: a C4
// 0.4 network-observation event whose netobs is a stored 0.3 TCP end of a
// Telnet flow to a relay, one with a complete overlap count and
// password_lines (CH-52 to CH-55), and one with incomplete and a partial
// count (CH-53). Between them they carry all eight fields 0.3 adds to an
// end.
//
// This file uses only what both codes export (event.Decode,
// netobs.ObservationFromEvent, netobs.DecodeStored and
// netobs.CheckpointIdentifier), so it runs unchanged on main's 0.2 code
// and on the 0.3 code. CheckpointIdentifier, the identifier each code
// writes (C13 0.3 §1.2), says which reader runs. The 0.2 leg ran on main at
// 410a04d5 (after #687 merged as 26545062), as a one-time proof, with its
// control there: the 0.2 DecodeStored made strict for a later minor
// refuses both fixtures. On #689's branch the 0.3 leg runs.
//
// Ground truth: GT-HAND, from the approved text. Every value is
// constructed; the frame hash is the SHA-256 of a label, not of a frame.
// None is device output. Evidence class: desk.

import (
	"encoding/json"
	"os"
	"reflect"
	"slices"
	"testing"

	"otsec.local/otsec/contracts/event"
	"otsec.local/otsec/contracts/netobs"
)

// ccD3Keys03 are the keys C13 0.3 adds to a flow end (CH-52 to CH-55).
var ccD3Keys03 = []string{"orig_payload", "resp_payload", "orig_pkts", "resp_pkts",
	"to_device_overlap_octets", "incomplete", "rexmit_inconsistent", "password_lines"}

var ccD3Files = []string{"event-0.4-netobs-0.3-end-counted.json", "event-0.4-netobs-0.3-end-incomplete.json"}

func ccD3Event(t *testing.T, name string) *event.Event {
	t.Helper()
	b, err := os.ReadFile("testdata/cc-d3/" + name)
	if err != nil {
		t.Fatal(err)
	}
	e, err := event.Decode(b)
	if err != nil {
		t.Fatalf("event.Decode: %v", err)
	}
	return e
}

func ccD3Map(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// TestCCD3N12StoredEnd03: under the 0.2 reader, 0.3 is a later minor, so
// the stored end is read forward: valid, every 0.1 and 0.2 field read as
// written, the eight 0.3 fields ignored, and an unknown key ignored too.
// Under the 0.3 reader it is the reader's own minor: valid, every field
// read as written, the eight included, and an unknown key refused.
func TestCCD3N12StoredEnd03(t *testing.T) {
	var forward bool
	switch netobs.CheckpointIdentifier {
	case "otsec.netcheckpoint/0.2":
		forward = true
	case "otsec.netcheckpoint/0.3":
	default:
		t.Fatalf("this code writes %s: N-12's first case is for the 0.2 and 0.3 readers; move it with the minor", netobs.CheckpointIdentifier)
	}
	seen := map[string]bool{}
	for _, name := range ccD3Files {
		t.Run(name, func(t *testing.T) {
			e := ccD3Event(t, name)
			for _, k := range ccD3Keys03 {
				_, ok := ccD3Map(t, e.Netobs)["flow"].(map[string]any)[k]
				seen[k] = seen[k] || ok
			}
			o, err := netobs.ObservationFromEvent(e)
			if err != nil {
				t.Fatalf("a stored 0.3 end, read by the reader that writes %s: %v", netobs.CheckpointIdentifier, err)
			}
			if o.Schema != "otsec.netobs/0.3" || o.Kind != netobs.KindFlow || o.Flow == nil || o.Flow.Phase != "end" {
				t.Fatalf("read as schema %q, kind %q, flow %+v", o.Schema, o.Kind, o.Flow)
			}
			want := ccD3Map(t, e.Netobs)
			got := ccD3Map(t, v2JSON(t, o))
			wf, gf := want["flow"].(map[string]any), got["flow"].(map[string]any)
			for _, k := range ccD3Keys03 {
				w, written := wf[k]
				g, read := gf[k]
				switch {
				case forward && read:
					t.Errorf("the 0.2 reader kept flow.%s = %v: a later minor's field is ignored", k, g)
				case !forward && (written != read || !reflect.DeepEqual(w, g)):
					t.Errorf("the 0.3 reader read flow.%s as %v (present %v); the fixture has %v (present %v)", k, g, read, w, written)
				}
				delete(wf, k)
				delete(gf, k)
			}
			if !reflect.DeepEqual(want, got) {
				t.Errorf("the other fields changed in the read:\n got %v\nwant %v", got, want)
			}
			// A key no minor defines: ignored in a later minor, refused at
			// the reader's own.
			m := ccD3Map(t, e.Netobs)
			m["d6_unknown"] = "x"
			_, err = netobs.DecodeStored(v2JSON(t, m))
			switch {
			case forward && err != nil:
				t.Errorf("the 0.2 reader refused a 0.3 end with an unknown key: %v", err)
			case !forward && !slices.Contains(netobs.Codes(err), netobs.CodeDecode):
				t.Errorf("the 0.3 reader took a 0.3 end with an unknown key: %v, want decode", err)
			}
		})
	}
	// The two fixtures between them carry every field 0.3 adds to an end.
	for _, k := range ccD3Keys03 {
		if !seen[k] {
			t.Errorf("no fixture carries flow.%s", k)
		}
	}
}
