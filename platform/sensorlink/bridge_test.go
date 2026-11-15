package sensorlink

import (
	"encoding/json"
	"reflect"
	"testing"

	"otsec.local/otsec/contracts/event"
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
