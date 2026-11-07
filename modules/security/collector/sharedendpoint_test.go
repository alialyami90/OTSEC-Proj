package collector

import (
	"strings"
	"testing"

	"otsec.local/otsec/contracts/asset"
)

// Two enrolled assets on one transport layer, host and port would make the
// node's tie of a flow to a session ambiguous, so the collector refuses to
// load them (C2 0.9 §4, D4-68). The host is compared unmapped and without a
// zone. Different ports, TCP beside UDP, or endpoints that get no session
// (CheckPath fails) load.
func TestNewPipelineRefusesSharedEndpoint(t *testing.T) {
	f := newPipeline(t)
	base := PipelineConfig{NodeID: testNode, PolicyVersion: 1, State: f.state, Creds: f.store, Registers: f.registers, Runner: f.runner}
	relay := func(id, host string, port int) Enrolled {
		a := simAsset(t)
		a.AssetID = id
		a.Endpoints[0].Host, a.Endpoints[0].Port = host, port
		return Enrolled{Asset: a, Profile: simProfile(t)}
	}
	portServer := func(id string) Enrolled {
		e := relay(id, "10.0.0.9", 4001)
		e.Asset.Endpoints[0].Path = asset.PortServer
		return e
	}
	const one, two = "2b7d4e10-8c3f-4a5b-9e21-7c4f0d6a8b13", "9a1c3e5f-7b2d-4c6e-8f10-2a4b6c8d0e1f"
	switch2 := func(host string, port int) Enrolled {
		a := *snmpAsset(t)
		a.AssetID = two
		a.Endpoints[0].Host, a.Endpoints[0].Port = host, port
		a.Profile = &asset.ProfileRef{ID: "sel-27x1-rstp", Version: "0.1"} // as snmp_test.go enrolls it
		return Enrolled{Asset: a, Profile: snmpProfile(t)}
	}
	for name, c := range map[string]struct {
		assets  []Enrolled
		refused bool
	}{
		"one host and port":       {[]Enrolled{relay(one, "10.0.0.5", 23), relay(two, "10.0.0.5", 23)}, true},
		"mapped and plain":        {[]Enrolled{relay(one, "10.0.0.5", 23), relay(two, "::ffff:10.0.0.5", 23)}, true},
		"differ only by zone":     {[]Enrolled{relay(one, "fe80::5%eth0", 23), relay(two, "fe80::5%eth1", 23)}, true},
		"different ports":         {[]Enrolled{relay(one, "10.0.0.5", 23), relay(two, "10.0.0.5", 2323)}, false},
		"TCP and UDP on one port": {[]Enrolled{relay(one, "10.0.0.5", 161), switch2("10.0.0.5", 161)}, false},
		// Two relays behind one port server's TCP port: multi-drop. Neither
		// gets a session, so neither is compared (D5, D1 on #547).
		"two port-server assets on one port": {[]Enrolled{portServer(one), portServer(two)}, false},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := base
			cfg.Assets = c.assets
			for _, e := range c.assets {
				if err := e.Asset.Validate(); err != nil {
					t.Fatalf("the test asset is not valid C1: %v", err)
				}
			}
			_, err := NewPipeline(cfg)
			switch {
			case c.refused && (err == nil || !strings.Contains(err.Error(), "share the outbound endpoint")):
				t.Errorf("loaded, or refused for another reason: %v", err)
			case !c.refused && err != nil:
				t.Errorf("refused: %v", err)
			}
		})
	}
	// One asset with two endpoints on its own host is not refused.
	a := simAsset(t)
	ep := a.Endpoints[0]
	ep.ID = "second"
	a.Endpoints = append(a.Endpoints, ep)
	if err := a.Validate(); err != nil {
		t.Fatalf("the test asset is not valid C1: %v", err)
	}
	cfg := base
	cfg.Assets = []Enrolled{{Asset: a, Profile: simProfile(t)}}
	if _, err := NewPipeline(cfg); err != nil {
		t.Errorf("one asset refused against itself: %v", err)
	}
}

// A transport the check does not name is refused, so a new outbound one
// cannot bypass it (D3 on #547).
func TestNewPipelineRefusesUnknownTransport(t *testing.T) {
	f := newPipeline(t)
	cfg := PipelineConfig{NodeID: testNode, PolicyVersion: 1, State: f.state, Creds: f.store, Registers: f.registers, Runner: f.runner}
	// A later C1 minor may carry a transport this reader does not know, and
	// C1 accepts such a record; this check must still refuse it.
	a := *snmpAsset(t)
	a.Profile = &asset.ProfileRef{ID: "sel-27x1-rstp", Version: "0.1"}
	a.Schema = "otsec.asset/0.4"
	a.Endpoints[0].Transport = "modbus-tcp"
	if err := a.Validate(); err != nil {
		t.Fatalf("C1 refuses the later-minor asset itself: %v", err)
	}
	cfg.Assets = []Enrolled{{Asset: a, Profile: snmpProfile(t)}}
	if _, err := NewPipeline(cfg); err == nil || !strings.Contains(err.Error(), "is not one the shared-endpoint check knows") {
		t.Fatalf("an endpoint with an unknown transport: %v", err)
	}
}
