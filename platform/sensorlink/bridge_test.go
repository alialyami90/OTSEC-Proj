package sensorlink

import (
	"encoding/json"
	"reflect"
	"testing"

	"otsec.local/otsec/contracts/event"
	"otsec.local/otsec/contracts/netobs"
)

// CH-35's bridge item 5 (P4-4-CC deliverable 1), kept by the C13 0.2 code
// for a later minor (C13 0.3 section 1.2), moved to 0.3 with the minor
// (the brief's "Later-minor legs move with the minor"), and N-13's leg (4)
// (C13 0.3 section 12): a held flow end of 0.3, tied, keeps every field
// this build's type does not know, the counts of CH-52 to CH-54 among
// them, a 0 as a 0. Desk only: the 0.3 body is the rig's 0.1 end with
// C13 0.2's made_utc and the node's marks, and C13 0.3's counts, added by
// hand on the flow object, as C13 0.3 sections 3 to 5 name them (an SSH
// flow, so no password_lines, which is Telnet's, CH-55); no sensor
// or node of 0.3 wrote it. The control is a tie that re-encodes the body
// with this build's type, which drops the counts.
func TestHoldTieKeepsLaterMinor(t *testing.T) {
	g := newHoldRig(t)
	g.dispatch("req-1")
	g.send(g.obs("start", 40001, 0), g.obs("end", 40001, 0))
	if n := len(g.saved); n == 0 || len(g.saved[n-1].Flows) != 1 || len(g.saved[n-1].Flows[0].Records) != 2 {
		t.Fatalf("saved %+v", g.saved)
	}

	// The held end, as a 0.3 node's intake hold would have saved it
	// before the node was rolled back to this build.
	held := &g.saved[len(g.saved)-1].Flows[0].Records[1]
	var top, node, flow map[string]json.RawMessage
	if err := json.Unmarshal(held.Observation, &top); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(top["node"], &node); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(top["flow"], &flow); err != nil {
		t.Fatal(err)
	}
	top["schema"] = json.RawMessage(`"otsec.netobs/0.3"`)
	top["made_utc"] = json.RawMessage(`"2026-11-07T10:00:00.250000Z"`)
	node["late"] = json.RawMessage(`true`)
	node["lost"] = json.RawMessage(`[{"from_utc":"2026-11-07T09:59:00.000000Z","to_utc":"2026-11-07T09:59:30.000000Z"}]`)
	for k, v := range map[string]string{"orig_payload": "41", "resp_payload": "7", "orig_pkts": "2", "resp_pkts": "1",
		"to_device_overlap_octets": "0", "rexmit_inconsistent": "0"} {
		flow[k] = json.RawMessage(v)
	}
	var err error
	if top["node"], err = json.Marshal(node); err != nil {
		t.Fatal(err)
	}
	if top["flow"], err = json.Marshal(flow); err != nil {
		t.Fatal(err)
	}
	if held.Observation, err = json.Marshal(top); err != nil {
		t.Fatal(err)
	}
	body := held.Observation

	// A start restores the hold, and the session's result ties the flow.
	g.l = g.link(g.restore())
	if err := g.l.RecoverHold(bg); err != nil {
		t.Fatal(err)
	}
	if _, err := g.l.Result(bg, "req-1", session09(inv1, 40001, 0)); err != nil {
		t.Fatal(err)
	}
	want(t, g.committed(), tied{1, inv1, TieConnection}, tied{2, inv1, TieConnection})

	// The stored end is the held one with node.platform_session added,
	// and nothing else changed.
	got := stored(t, g.s)
	var e event.Event
	if err := json.Unmarshal(got[1].Event, &e); err != nil {
		t.Fatal(err)
	}
	var have, wantBody map[string]any
	if err := json.Unmarshal(e.Netobs, &have); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(body, &wantBody); err != nil {
		t.Fatal(err)
	}
	wantBody["node"].(map[string]any)["platform_session"] = map[string]any{"invocation_id": inv1, "tie": TieConnection}
	if !reflect.DeepEqual(have, wantBody) {
		t.Fatalf("the tied body changed:\n got %s\nwant %s", e.Netobs, body)
	}
	if f := have["flow"].(map[string]any); f["orig_payload"] != 41.0 || f["to_device_overlap_octets"] != 0.0 || have["schema"] != "otsec.netobs/0.3" {
		t.Fatalf("a count or the schema lost: %s", e.Netobs)
	}
}

// N-8's leg (2) (C13 0.3 sections 1.1 and 12; D5's B4): absent, 0 and true
// stay distinct through Link.record's tie path for the fields of CH-52 to
// CH-55. Three held 0.3 TCP ends, leg (1)'s three records, are tied by a
// session's result: one with all seven counts at 0, password_lines (CH-55)
// among them; one with none of them and incomplete true; and one with a
// partial overlap count beside incomplete true, the other five counts at 0
// and password_lines absent (CH-53, CH-55). Each stored end keeps those fields
// exactly as held, and the stored record read by the node's reader
// (ObservationFromEvent, the detector's) encodes back to the same fields,
// so the Go type keeps an absent count absent, a 0 count 0, and incomplete
// absent or true. incomplete false never reaches the tie: C13 0.3 has it
// present only as true. Desk only: the 0.3 bodies are the rig's end with
// the counts added by hand, as TestHoldTieKeepsLaterMinor's are; no sensor
// wrote them. The control is the same field as a non-pointer uint64 in
// contracts/netobs's Flow (orig_payload): absent then reads, and encodes,
// as 0. Since CH-35's bridge item 5, Link.record patches the raw body and
// does not re-encode it, so the control fails at the reader's half; the
// tie's own re-encode control is TestHoldTieKeepsLaterMinor's. The third
// case's control is the overlap count refused beside incomplete, as
// password_lines is, in contracts/netobs's Flow.check03: it fails that case
// alone.
func TestHoldTieKeepsAbsentZeroApart(t *testing.T) {
	counts := []string{"orig_payload", "resp_payload", "orig_pkts", "resp_pkts", "to_device_overlap_octets", "rexmit_inconsistent", "password_lines"}
	zero, absent := map[string]string{}, map[string]string{"incomplete": "true"}
	partial := map[string]string{"incomplete": "true"}
	for _, k := range counts {
		zero[k] = "0"
		if k != "password_lines" {
			partial[k] = "0"
		}
	}
	partial["to_device_overlap_octets"] = "7"
	for _, c := range []struct {
		name string
		set  map[string]string
	}{{"zero", zero}, {"absent", absent}, {"count-and-incomplete", partial}} {
		t.Run(c.name, func(t *testing.T) {
			g := newHoldRig(t)
			g.dispatch("req-1")
			g.send(g.obs("start", 40001, 0), g.obs("end", 40001, 0))
			if n := len(g.saved); n == 0 || len(g.saved[n-1].Flows) != 1 || len(g.saved[n-1].Flows[0].Records) != 2 {
				t.Fatalf("saved %+v", g.saved)
			}
			held := &g.saved[len(g.saved)-1].Flows[0].Records[1]
			var top, node, flow map[string]json.RawMessage
			if err := json.Unmarshal(held.Observation, &top); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(top["node"], &node); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(top["flow"], &flow); err != nil {
				t.Fatal(err)
			}
			top["schema"] = json.RawMessage(`"otsec.netobs/0.3"`)
			top["made_utc"] = json.RawMessage(`"2026-11-07T10:00:00.250000Z"`)
			node["late"] = json.RawMessage(`false`)
			node["lost"] = json.RawMessage(`[]`)
			for k, v := range c.set {
				flow[k] = json.RawMessage(v)
			}
			var err error
			if top["node"], err = json.Marshal(node); err != nil {
				t.Fatal(err)
			}
			if top["flow"], err = json.Marshal(flow); err != nil {
				t.Fatal(err)
			}
			if held.Observation, err = json.Marshal(top); err != nil {
				t.Fatal(err)
			}

			g.l = g.link(g.restore())
			if err := g.l.RecoverHold(bg); err != nil {
				t.Fatal(err)
			}
			if _, err := g.l.Result(bg, "req-1", session09(inv1, 40001, 0)); err != nil {
				t.Fatal(err)
			}
			want(t, g.committed(), tied{1, inv1, TieConnection}, tied{2, inv1, TieConnection})

			var e event.Event
			if err := json.Unmarshal(stored(t, g.s)[1].Event, &e); err != nil {
				t.Fatal(err)
			}
			var stTop, stFlow map[string]json.RawMessage
			if err := json.Unmarshal(e.Netobs, &stTop); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(stTop["flow"], &stFlow); err != nil {
				t.Fatal(err)
			}
			o, err := netobs.ObservationFromEvent(&e)
			if err != nil {
				t.Fatalf("the stored end is not read: %v", err)
			}
			rb, err := json.Marshal(o.Flow)
			if err != nil {
				t.Fatal(err)
			}
			var readFlow map[string]json.RawMessage
			if err := json.Unmarshal(rb, &readFlow); err != nil {
				t.Fatal(err)
			}
			for _, k := range append(counts, "incomplete") {
				w, inHeld := flow[k]
				for _, x := range []struct {
					where string
					m     map[string]json.RawMessage
				}{{"stored", stFlow}, {"read", readFlow}} {
					if g, ok := x.m[k]; ok != inHeld || string(g) != string(w) {
						t.Errorf("%s flow.%s: %q (present %v), want %q (present %v)", x.where, k, g, ok, w, inHeld)
					}
				}
			}
		})
	}
}
