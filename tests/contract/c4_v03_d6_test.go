package contract

// C4 otsec.event/0.3 (D4-68; docs/phase4/D4-c4-0.3.md), D6's contract
// tests. The events are D6's own, written from the note's rules, not from
// contracts/event/testdata. Ground truth: independent of D4's tests and
// goldens. Evidence class: desk.

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/event"
)

const c4v3Asset = `"asset": {"id": "7c1e5a20-4d3b-4f6a-8b2c-9e0d1f2a3b4c", "binding": {"method": "sender-address", "confidence": "inferred"}},`

// c4v3Event builds a network-observation event. Each argument replaces one
// part, so a case changes exactly what it names.
type c4v3Parts struct {
	schema, origin, kind, asset, auth, extra, netobs, flags string
}

func c4v3Base() c4v3Parts {
	return c4v3Parts{
		schema: "otsec.event/0.3", origin: "platform", kind: "network-observation",
		asset: c4v3Asset, auth: "platform",
		netobs: `{"schema": "otsec.netobs/0.1", "type": "observation", "kind": "flow"}`,
	}
}

func (p c4v3Parts) json() []byte {
	var b strings.Builder
	b.WriteString(`{"schema": "` + p.schema + `", "id": {"node_id": "d6-node", "stream": "netobs/d6", "seq": 4},`)
	b.WriteString(`"origin": "` + p.origin + `", "kind": "` + p.kind + `",`)
	b.WriteString(`"source": {` + p.asset + `"origin_auth": "` + p.auth + `"},`)
	b.WriteString(`"received": {"utc": "2026-11-07T20:00:01.000001Z", "resolution_ns": 1000, "clock": {"sync": "synchronized", "source": "chrony"}}`)
	if p.extra != "" {
		b.WriteString(`, ` + p.extra)
	}
	if p.netobs != "" {
		b.WriteString(`, "netobs": ` + p.netobs)
	}
	if p.flags != "" {
		b.WriteString(`, "flags": ` + p.flags)
	}
	b.WriteString(`}`)
	return []byte(b.String())
}

func TestC4v03Constants(t *testing.T) {
	if event.Identifier != "otsec.event/0.3" {
		t.Errorf("Identifier %q", event.Identifier)
	}
	if event.KindNetworkObservation != "network-observation" {
		t.Errorf("kind %q", event.KindNetworkObservation)
	}
	if event.MaxNetobsBytes != 24<<10 {
		t.Errorf("MaxNetobsBytes %d, want 24 KiB as D4 stated it", event.MaxNetobsBytes)
	}
}

func TestC4v03Controls(t *testing.T) {
	ok := c4v3Base()
	e, err := event.Decode(ok.json())
	if err != nil {
		t.Fatalf("resolved observation: %v", err)
	}
	if e.Kind != event.KindNetworkObservation || !json.Valid(e.Netobs) {
		t.Errorf("decoded kind %q netobs %q", e.Kind, e.Netobs)
	}
	unresolved := c4v3Base()
	unresolved.asset, unresolved.flags = "", `["asset-unresolved"]`
	if _, err := event.Decode(unresolved.json()); err != nil {
		t.Errorf("unresolved observation with its flag: %v", err)
	}
	// netobs is opaque to C4: a body C13 would refuse still passes here,
	// because the node checks it at intake (note, "What C4 does not check").
	opaque := c4v3Base()
	opaque.netobs = `{"anything": [1, 2, 3]}`
	if _, err := event.Decode(opaque.json()); err != nil {
		t.Errorf("opaque body: %v", err)
	}
}

// Each case changes one thing and must be refused with the code named.
func TestC4v03Refusals(t *testing.T) {
	type tc struct {
		name string
		mod  func(*c4v3Parts)
		code event.Code
	}
	cases := []tc{
		{"netobs on telemetry-health", func(p *c4v3Parts) {
			p.kind = "telemetry-health"
			p.extra = `"health": {"type": "netobs.alert"}`
		}, event.CodeForbidden},
		{"network-observation without netobs", func(p *c4v3Parts) { p.netobs = "" }, event.CodeMissing},
		{"netobs at 0.2", func(p *c4v3Parts) { p.schema = "otsec.event/0.2" }, event.CodeForbidden},
		{"netobs at 0.1", func(p *c4v3Parts) { p.schema = "otsec.event/0.1" }, event.CodeForbidden},
		{"netobs a string", func(p *c4v3Parts) { p.netobs = `"{}"` }, event.CodeEnum},
		{"netobs an array", func(p *c4v3Parts) { p.netobs = `[{}]` }, event.CodeEnum},
		{"netobs a number", func(p *c4v3Parts) { p.netobs = `7` }, event.CodeEnum},
		{"origin device", func(p *c4v3Parts) { p.origin = "device" }, event.CodeEnum},
		{"no asset and no flag", func(p *c4v3Parts) { p.asset = "" }, event.CodeMissing},
	}
	for _, c := range cases {
		p := c4v3Base()
		c.mod(&p)
		_, err := event.Decode(p.json())
		if !slices.Contains(event.Codes(err), c.code) {
			t.Errorf("%s: %v, want code %s", c.name, err, c.code)
		}
	}
	// The existing platform-event rules hold on the new kind: each of these
	// is refused by the rule on the field it names, not by a decode error.
	for name, mod := range map[string]func(*c4v3Parts){
		"origin_auth not platform": func(p *c4v3Parts) { p.auth = "tls-mutual" },
		"with native": func(p *c4v3Parts) {
			p.extra = `"native": {"bytes": "YQ==", "record_sha256": "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb", "record_length": 1, "evidence": {"sha256": "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb", "length": 1, "ref": "sha256:ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"}}`
		},
		"with evidence_class": func(p *c4v3Parts) { p.asset += `"evidence_class": "simulated",` },
		"netobs null":         func(p *c4v3Parts) { p.netobs = `null` },
	} {
		p := c4v3Base()
		mod(&p)
		_, err := event.Decode(p.json())
		if err == nil || slices.Contains(event.Codes(err), event.CodeDecode) {
			t.Errorf("%s: %v, want a refusal by rule", name, err)
		}
	}
}

// The bound is exact on the bytes as they stand in the event: at
// MaxNetobsBytes it passes, one byte more is refused.
func TestC4v03Bound(t *testing.T) {
	body := func(n int) string {
		const head, tail = `{"pad":"`, `"}`
		return head + strings.Repeat("a", n-len(head)-len(tail)) + tail
	}
	at := c4v3Base()
	at.netobs = body(event.MaxNetobsBytes)
	if _, err := event.Decode(at.json()); err != nil {
		t.Errorf("netobs at MaxNetobsBytes: %v", err)
	}
	over := c4v3Base()
	over.netobs = body(event.MaxNetobsBytes + 1)
	if _, err := event.Decode(over.json()); !slices.Contains(event.Codes(err), event.CodeForbidden) {
		t.Errorf("netobs one byte over: %v", err)
	}
}

// ValidatePending applies the same rules before the store assigns seq.
func TestC4v03Pending(t *testing.T) {
	p := c4v3Base()
	p.netobs = ""
	var e event.Event
	if err := json.Unmarshal(p.json(), &e); err != nil {
		t.Fatal(err)
	}
	e.ID.Seq = 0
	if !slices.Contains(event.Codes(e.ValidatePending()), event.CodeMissing) {
		t.Errorf("pending observation without netobs: %v", e.ValidatePending())
	}
}
