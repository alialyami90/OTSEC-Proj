package collector

import (
	"errors"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/authz"
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

// A transport from a later C1 minor does not stop the collector loading:
// CheckPath refuses its endpoint, so it is not compared, and a run on it is
// refused at session time (D2-16; D3, D1 on #547).
func TestUnknownTransportLoadsAndIsRefusedAtSessionTime(t *testing.T) {
	f := newPipeline(t)
	cfg := PipelineConfig{NodeID: testNode, PolicyVersion: policyVersion, State: f.state, Creds: f.store, Registers: f.registers, Runner: f.runner}
	// C1 accepts a later-minor record with a transport this reader does
	// not know.
	a := *snmpAsset(t)
	a.Profile = &asset.ProfileRef{ID: "sel-27x1-rstp", Version: "0.1"}
	a.Schema = "otsec.asset/0.4"
	a.Endpoints[0].Transport = "modbus-tcp"
	if err := a.Validate(); err != nil {
		t.Fatalf("C1 refuses the later-minor asset itself: %v", err)
	}
	if err := a.Endpoints[0].CheckPath(); !errors.Is(err, asset.ErrPathRefused) {
		t.Fatalf("CheckPath on the unknown transport: %v", err)
	}
	cfg.Assets = []Enrolled{{Asset: a, Profile: snmpProfile(t)}}
	p, err := NewPipeline(cfg)
	if err != nil {
		t.Fatalf("the collector does not load: %v", err)
	}
	f.pipe = p
	req := pipeRun("sel.id", "")
	req.Run.AssetID = a.AssetID
	if reply, _ := f.run(t, req); refusalOf(reply) != authz.RefuseAssetNotEnrolled {
		t.Fatalf("a run on the endpoint: %+v", reply)
	}
	if f.runner.count() != 0 {
		t.Fatal("the runner was called")
	}
}

// Every transport C1 knows whose endpoint can pass CheckPath has a case in
// sharedL4, so its default arm is unreachable; a transport added to C1
// without one fails here, not in a load (D3, D1 on #547).
func TestSharedL4CoversEveryTransport(t *testing.T) {
	want := map[asset.Transport]string{asset.Telnet: "tcp", asset.SSH: "tcp", asset.SNMPv3: "udp", asset.Serial: ""}
	for _, tr := range asset.Transports {
		if (asset.Endpoint{ID: "e", Transport: tr, Path: asset.Direct}).CheckPath() != nil {
			continue // never compared
		}
		l4, err := sharedL4(tr)
		if err != nil {
			t.Errorf("%s: %v", tr, err)
			continue
		}
		if w, ok := want[tr]; !ok || l4 != w {
			t.Errorf("%s maps to %q; this test names it %q (known %v)", tr, l4, w, ok)
		}
	}
	if _, err := sharedL4("modbus-tcp"); err == nil {
		t.Error("an unknown transport maps to a layer")
	}
}
