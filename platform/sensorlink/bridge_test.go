package sensorlink

import (
	"encoding/json"
	"reflect"
	"testing"

	"otsec.local/otsec/contracts/event"
)

// CH-35's bridge item 5 (P4-4-CC deliverable 1): a held observation of a
// later minor, tied, keeps every field this build's type does not know.
// Desk only: the 0.2 body is the rig's 0.1 record with C13 0.2's made_utc
// and the node's four marks added by hand, as C13 0.2 section 11's table
// names them; no sensor or node of 0.2 wrote it.
func TestHoldTieKeepsLaterMinor(t *testing.T) {
	g := newHoldRig(t)
	g.dispatch("req-1")
	g.send(g.obs("start", 40001, 0))
	if n := len(g.saved); n == 0 || len(g.saved[n-1].Flows) != 1 || len(g.saved[n-1].Flows[0].Records) != 1 {
		t.Fatalf("saved %+v", g.saved)
	}

	// The held body, as a 0.2 node's intake hold would have saved it
	// before the node was rolled back to this build.
	held := &g.saved[len(g.saved)-1].Flows[0].Records[0]
	var top, node map[string]json.RawMessage
	if err := json.Unmarshal(held.Observation, &top); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(top["node"], &node); err != nil {
		t.Fatal(err)
	}
	top["schema"] = json.RawMessage(`"otsec.netobs/0.2"`)
	top["made_utc"] = json.RawMessage(`"2026-11-07T10:00:00.250000Z"`)
	node["late"] = json.RawMessage(`true`)
	node["backlog"] = json.RawMessage(`true`)
	node["skewed"] = json.RawMessage(`true`)
	node["lost"] = json.RawMessage(`[{"from_utc":"2026-11-07T09:59:00.000000Z","to_utc":"2026-11-07T09:59:30.000000Z"}]`)
	var err error
	if top["node"], err = json.Marshal(node); err != nil {
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
	want(t, g.committed(), tied{1, inv1, TieConnection})

	// The stored body is the held one with node.platform_session added,
	// and nothing else changed.
	got := stored(t, g.s)
	var e event.Event
	if err := json.Unmarshal(got[0].Event, &e); err != nil {
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
	if have["made_utc"] == nil || have["schema"] != "otsec.netobs/0.2" {
		t.Fatalf("made_utc or schema lost: %s", e.Netobs)
	}
}
