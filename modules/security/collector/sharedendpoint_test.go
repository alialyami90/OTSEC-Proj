package collector

import (
	"strings"
	"testing"

	"otsec.local/otsec/contracts/asset"
)

// Two enrolled assets on one transport layer, host and port would make the
// node's tie of a flow to a session ambiguous, so the collector refuses to
// load them (C2 0.9 §4, D4-68). The host is compared unmapped and without a
// zone. Different ports, or TCP beside UDP, load.
func TestNewPipelineRefusesSharedEndpoint(t *testing.T) {
	f := newPipeline(t)
	base := PipelineConfig{NodeID: testNode, PolicyVersion: 1, State: f.state, Creds: f.store, Registers: f.registers, Runner: f.runner}
	relay := func(id, host string, port int) Enrolled {
		a := simAsset(t)
		a.AssetID = id
		a.Endpoints[0].Host, a.Endpoints[0].Port = host, port
		return Enrolled{Asset: a, Profile: simProfile(t)}
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
