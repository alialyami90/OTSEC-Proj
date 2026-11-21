package contract

// C4 otsec.event/0.6, C4-0.6-3 (docs/phase4/D4-c4-0.6-proposal.md §3.1,
// approved at 5e7f0487 on #768, D4-121): D6's independent row E6-6, in
// tests/contract, against step 3 (#780, brief P4-4-C4-06-S3). A
// network-observation event one C4 minor above event.Identifier, with a
// body at C13's self, is refused by netobs.ObservationFromEvent as one
// *netobs.Error with CodeSchema, Field "schema" and ErrLaterMinor, and the
// observation returned is nil. It is still schema, not decode, with an
// unknown key at the top level and in source.asset; and with a second
// defect, an envelope asset that conflicts with the body's dst_asset, the
// refusal is returned alone, not inside a join.
//
// Each event is D6's fixture testdata/c4-v06/event-0.6-network-observation.json
// with its C4 stamp set to event.Identifier (the control) or to one minor
// above it, computed, and its body's stamp set to netobs.SelfIdentifier();
// no later minor is a literal (self-check 11). Each is read as §3.1 says
// the node reads it: event.Decode, which reads a later minor forward, then
// ObservationFromEvent. At event.Identifier each edit is shown to be a
// defect: an unknown key is refused by the strict read (decode), and the
// asset as conflict.
//
// Controls: §6's five for E6-6, each applied alone to contracts/netobs at
// 478b426d and shown failing this test: the refusal removed from
// ObservationFromEvent; > made >= (refuses the control at
// event.Identifier); compared against C13's self (refuses the control
// while C13's minor is below C4's; the guard below fails if they meet); a
// non-nil observation returned with the refusal; and the later-minor error
// joined with the asset conflict. The commit message has the results.
//
// Ground truth: GT-HAND, from the approved text. Every value is
// constructed; none is device output. Evidence class: desk, and CI-Linux
// and CI-Windows for this test on the PR.

import (
	"encoding/json"
	"errors"
	"slices"
	"testing"

	"otsec.local/otsec/contracts/event"
	"otsec.local/otsec/contracts/netobs"
	"otsec.local/otsec/contracts/version"
)

// c4v6s3Event is the fixture stamped schema, its body at C13's self, with
// edit applied.
func c4v6s3Event(t *testing.T, schema string, edit func(map[string]any)) []byte {
	t.Helper()
	m := c4v6Tree(t, c4v6Read(t, "event-0.6-network-observation.json")).(map[string]any)
	m["schema"] = schema
	m["netobs"].(map[string]any)["schema"] = netobs.SelfIdentifier()
	if edit != nil {
		edit(m)
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func c4v6s3Asset(m map[string]any) map[string]any {
	return m["source"].(map[string]any)["asset"].(map[string]any)
}

func TestC4v06E66LaterC4Observation(t *testing.T) {
	c4, err := version.Parse(event.Identifier)
	if err != nil {
		t.Fatal(err)
	}
	c13, err := version.Parse(netobs.SelfIdentifier())
	if err != nil {
		t.Fatal(err)
	}
	if c4.Minor == c13.Minor {
		t.Errorf("event.Identifier's minor equals C13's self (%d): the control no longer kills a check against C13's self", c4.Minor)
	}
	later := c4v6Minor(t, 1)

	top := func(m map[string]any) { m["d6_added_later"] = "x" }
	asset := func(m map[string]any) { c4v6s3Asset(m)["d6_added_later"] = "x" }
	both := func(m map[string]any) { top(m); asset(m) }
	conflict := func(m map[string]any) {
		if c4v6s3Asset(m)["id"] != v2AssetA || m["netobs"].(map[string]any)["node"].(map[string]any)["dst_asset"] != v2AssetA {
			t.Fatal("the fixture's envelope asset is not its dst_asset")
		}
		c4v6s3Asset(m)["id"] = v2AssetB
	}

	// The control, at event.Identifier: accepted.
	e, err := event.Decode(c4v6s3Event(t, event.Identifier, nil))
	if err != nil {
		t.Fatalf("at %s: event.Decode: %v", event.Identifier, err)
	}
	if o, err := netobs.ObservationFromEvent(e); o == nil || err != nil {
		t.Fatalf("at %s: %v, %v, want accepted", event.Identifier, o, err)
	}

	// At event.Identifier each edit is a defect.
	for name, ed := range map[string]func(map[string]any){"top": top, "source.asset": asset, "both": both} {
		if _, err := event.Decode(c4v6s3Event(t, event.Identifier, ed)); !slices.Equal(c4v6Pairs(err), []string{"event decode"}) {
			t.Errorf("an unknown key (%s) at %s: %v, want decode", name, event.Identifier, err)
		}
	}
	e, err = event.Decode(c4v6s3Event(t, event.Identifier, conflict))
	if err != nil {
		t.Fatalf("the asset conflict at %s: event.Decode: %v", event.Identifier, err)
	}
	if _, err := netobs.ObservationFromEvent(e); !slices.Equal(netobs.Codes(err), []netobs.Code{netobs.CodeConflict}) || errors.Is(err, netobs.ErrLaterMinor) {
		t.Errorf("the asset conflict at %s: %v, want conflict", event.Identifier, err)
	}

	// One C4 minor above: read forward, then refused alone.
	for _, c := range []struct {
		name string
		edit func(map[string]any)
	}{
		{"no unknown key", nil},
		{"an unknown top-level key", top},
		{"an unknown key in source.asset", asset},
		{"both unknown keys", both},
		{"an envelope asset conflicting with dst_asset", conflict},
	} {
		e, err := event.Decode(c4v6s3Event(t, later, c.edit))
		if err != nil {
			t.Errorf("%s at %s: event.Decode: %v, want the forward read", c.name, later, err)
			continue
		}
		o, err := netobs.ObservationFromEvent(e)
		x, one := err.(*netobs.Error)
		switch {
		case o != nil:
			t.Errorf("%s at %s: an observation returned with %v", c.name, later, err)
		case !one:
			t.Errorf("%s at %s: %v (%T), want one *netobs.Error, not a join", c.name, later, err, err)
		case x.Code != netobs.CodeSchema || x.Field != "schema" || !errors.Is(err, netobs.ErrLaterMinor):
			t.Errorf("%s at %s: %v, want schema at schema with ErrLaterMinor", c.name, later, err)
		}
	}
}
