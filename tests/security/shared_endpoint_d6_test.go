package security

// C2 0.9 §4 (docs/phase4/D2-c2-0.9.md, D4-68), D6's test 5: the collector
// refuses to load two enrolled assets on one direct outbound endpoint, by
// transport layer, host and port, with the host compared unmapped and
// without a zone. D1's ruling on #547 bounds it to direct endpoints, the
// ones CheckPath lets the node dial: two port-server assets on one
// host:port load. Expected outcomes come from the rule text. The assets are
// the collector's SEL-751 test fixture and C1's SEL-2731M example, edited;
// nothing is contacted. Evidence class: desk.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/modules/security/collector"
)

const (
	sharedA = "2b7d4e10-8c3f-4a5b-9e21-7c4f0d6a8b13"
	sharedB = "5e3a9c71-2d4b-4f86-a0c1-8b7e6d5f4a32"
)

func sharedRelay(t *testing.T, id, host string, port int, path asset.Path) collector.Enrolled {
	t.Helper()
	a, err := asset.Decode(readLockFixture(t, "sel-751-simulated.json"))
	if err != nil {
		t.Fatal(err)
	}
	p, err := asset.DecodeProfile(readLockFixture(t, "profile-sel-751-ascii.json"))
	if err != nil {
		t.Fatal(err)
	}
	a.AssetID = id
	a.Endpoints[0].Host, a.Endpoints[0].Port, a.Endpoints[0].Path = host, port, path
	return collector.Enrolled{Asset: a, Profile: p}
}

func sharedSwitch(t *testing.T, id, host string, port int) collector.Enrolled {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "contracts", "asset", "testdata", "valid", "sel-2731m-snmpv3.json"))
	if err != nil {
		t.Fatal(err)
	}
	var a asset.Asset
	if err := json.Unmarshal(b, &a); err != nil {
		t.Fatal(err)
	}
	p, err := asset.DecodeProfile(readLockFixture(t, "profile-sel-27x1-rstp.json"))
	if err != nil {
		t.Fatal(err)
	}
	a.AssetID = id
	a.Profile = &asset.ProfileRef{ID: p.ProfileID, Version: p.Version}
	a.Endpoints[0].Host, a.Endpoints[0].Port = host, port
	return collector.Enrolled{Asset: a, Profile: p}
}

func TestC2v09CollectorRefusesASharedDirectEndpoint(t *testing.T) {
	d, ps := asset.Direct, asset.PortServer
	for name, c := range map[string]struct {
		assets  func(t *testing.T) []collector.Enrolled
		refused bool
	}{
		"two direct on one host and port": {func(t *testing.T) []collector.Enrolled {
			return []collector.Enrolled{sharedRelay(t, sharedA, "192.0.2.21", 23, d), sharedRelay(t, sharedB, "192.0.2.21", 23, d)}
		}, true},
		"10.0.0.5 beside ::ffff:10.0.0.5": {func(t *testing.T) []collector.Enrolled {
			return []collector.Enrolled{sharedRelay(t, sharedA, "10.0.0.5", 23, d), sharedRelay(t, sharedB, "::ffff:10.0.0.5", 23, d)}
		}, true},
		"differ only by zone": {func(t *testing.T) []collector.Enrolled {
			return []collector.Enrolled{sharedRelay(t, sharedA, "fe80::5%eth0", 23, d), sharedRelay(t, sharedB, "fe80::5%eth1", 23, d)}
		}, true},
		"one zoned, one not": {func(t *testing.T) []collector.Enrolled {
			return []collector.Enrolled{sharedRelay(t, sharedA, "fe80::5%eth0", 23, d), sharedRelay(t, sharedB, "fe80::5", 23, d)}
		}, true},
		"IPv6 written two ways": {func(t *testing.T) []collector.Enrolled {
			return []collector.Enrolled{sharedRelay(t, sharedA, "2001:db8::5", 23, d), sharedRelay(t, sharedB, "2001:db8:0:0::5", 23, d)}
		}, true},
		"one host, different ports": {func(t *testing.T) []collector.Enrolled {
			return []collector.Enrolled{sharedRelay(t, sharedA, "10.0.0.5", 23, d), sharedRelay(t, sharedB, "10.0.0.5", 2323, d)}
		}, false},
		"one host and port, TCP and UDP": {func(t *testing.T) []collector.Enrolled {
			return []collector.Enrolled{sharedRelay(t, sharedA, "10.0.0.5", 161, d), sharedSwitch(t, sharedB, "10.0.0.5", 161)}
		}, false},
		// D1 on #547: only direct endpoints, which CheckPath passes.
		"two port-server on one host and port": {func(t *testing.T) []collector.Enrolled {
			return []collector.Enrolled{sharedRelay(t, sharedA, "10.0.0.7", 3001, ps), sharedRelay(t, sharedB, "10.0.0.7", 3001, ps)}
		}, false},
		"one port-server beside one direct": {func(t *testing.T) []collector.Enrolled {
			return []collector.Enrolled{sharedRelay(t, sharedA, "10.0.0.7", 3001, ps), sharedRelay(t, sharedB, "10.0.0.7", 3001, d)}
		}, false},
	} {
		t.Run(name, func(t *testing.T) {
			assets := c.assets(t)
			for _, e := range assets {
				if err := e.Asset.Validate(); err != nil {
					t.Fatalf("the test asset is not valid C1: %v", err)
				}
			}
			_, err := newRig(t, "192.0.2.21", 23, nil, func(cfg *collector.PipelineConfig) { cfg.Assets = assets })
			switch {
			case c.refused && err == nil:
				t.Error("loaded")
			case c.refused && !(strings.Contains(err.Error(), sharedA) && strings.Contains(err.Error(), sharedB)):
				t.Errorf("refused without naming both assets: %v", err)
			case !c.refused && err != nil:
				t.Errorf("refused: %v", err)
			}
		})
	}
}

// The control: each asset of the refused pairs loads alone, so a refusal
// above is the pair's and not the asset's.
func TestC2v09SharedEndpointControl(t *testing.T) {
	for _, h := range []string{"192.0.2.21", "10.0.0.5", "::ffff:10.0.0.5", "fe80::5%eth0", "2001:db8:0:0::5"} {
		e := sharedRelay(t, sharedA, h, 23, asset.Direct)
		if _, err := newRig(t, "192.0.2.21", 23, nil, func(cfg *collector.PipelineConfig) { cfg.Assets = []collector.Enrolled{e} }); err != nil {
			t.Errorf("%s alone: %v", h, err)
		}
	}
}
