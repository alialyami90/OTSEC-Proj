package contract

// C13 §14 item 9 against C1's inbound-sender check (D3 on #549, D6).
// asset.CheckSenders keys an inbound sender on (node, transport, host) and
// keeps the zone, so two assets whose Syslog senders differ only in
// transport or zone enroll. C13 resolves every host after
// Unmap().WithZone(""), over the inbound endpoints and the direct ones, so
// the same pair is one address there and resolves to neither asset,
// ip-ambiguous: the closed side. These cases pin that both halves stay as
// written. The node's resolver is not in the tree yet (P4-4-B5); when it
// lands, its outcome for each case below must be ip-ambiguous, and the
// resolver check replaces c13Key. Ground truth: GT-HAND, from the rule text.

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"otsec.local/otsec/contracts/asset"
)

// c13Asset is the C1 Syslog golden with its asset ID and endpoints replaced.
func c13Asset(t *testing.T, id string, eps ...map[string]any) asset.Asset {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "contracts", "asset", "testdata", "valid", "sel-rtac-syslog.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	tmpl := m["endpoints"].([]any)[0].(map[string]any)
	var out []any
	for _, e := range eps {
		ep := map[string]any{}
		for k, v := range tmpl {
			ep[k] = v
		}
		for k, v := range e {
			ep[k] = v
		}
		out = append(out, ep)
	}
	m["asset_id"] = id
	m["endpoints"] = out
	if b, err = json.Marshal(m); err != nil {
		t.Fatal(err)
	}
	a, err := asset.Decode(b)
	if err != nil {
		t.Fatalf("C1 refuses %s: %v", id, err)
	}
	return a
}

// c13Key is C13 §14 item 9's comparison key for an endpoint host.
func c13Key(t *testing.T, host string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(host)
	if err != nil {
		t.Fatalf("host %q: %v", host, err)
	}
	return a.Unmap().WithZone("")
}

const (
	c13A = "11111111-2222-4333-8444-555555555555"
	c13B = "66666666-7777-4888-9999-aaaaaaaaaaaa"
)

func sender(transport, host string) map[string]any {
	return map[string]any{"id": "in-" + transport, "transport": transport, "host": host, "port": 514}
}

// Each pair enrolls (CheckSenders passes) and shares one C13 address, so
// C13 resolves neither asset there.
func TestC13SendersThatEnrollButAreAmbiguous(t *testing.T) {
	for _, c := range []struct {
		name         string
		hostA, hostB string
		a, b         map[string]any
	}{
		{"transport only", "192.0.2.40", "192.0.2.40", sender("syslog-udp", "192.0.2.40"), sender("syslog-tcp", "192.0.2.40")},
		{"zone only", "fe80::40%eth0", "fe80::40%eth1", sender("syslog-udp", "fe80::40%eth0"), sender("syslog-udp", "fe80::40%eth1")},
		{"zoned beside unzoned", "fe80::40%eth0", "fe80::40", sender("syslog-udp", "fe80::40%eth0"), sender("syslog-udp", "fe80::40")},
		{"transport and mapped form", "192.0.2.40", "::ffff:192.0.2.40", sender("syslog-udp", "192.0.2.40"), sender("syslog-tcp", "::ffff:192.0.2.40")},
		{"sender beside a direct endpoint", "192.0.2.40", "192.0.2.40", sender("syslog-udp", "192.0.2.40"),
			map[string]any{"id": "ssh", "transport": "ssh", "host": "192.0.2.40", "port": 22, "path": "direct"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			assets := []asset.Asset{c13Asset(t, c13A, c.a), c13Asset(t, c13B, c.b)}
			if err := asset.CheckSenders(assets); err != nil {
				t.Fatalf("CheckSenders refuses the pair, so the C13 case cannot arise: %v", err)
			}
			if c13Key(t, c.hostA) != c13Key(t, c.hostB) {
				t.Fatalf("%s and %s are two C13 addresses", c.hostA, c.hostB)
			}
		})
	}
}

// Control: the same transport and host, or the same host in its mapped
// form, is refused at enrollment, so it never reaches resolution.
func TestC13SendersControl(t *testing.T) {
	for _, c := range []struct{ name, hostA, hostB string }{
		{"same host", "192.0.2.40", "192.0.2.40"},
		{"mapped form", "192.0.2.40", "::ffff:192.0.2.40"},
		{"same zone", "fe80::40%eth0", "fe80::40%eth0"},
	} {
		t.Run(c.name, func(t *testing.T) {
			assets := []asset.Asset{
				c13Asset(t, c13A, sender("syslog-udp", c.hostA)),
				c13Asset(t, c13B, sender("syslog-udp", c.hostB)),
			}
			if err := asset.CheckSenders(assets); err == nil {
				t.Fatal("CheckSenders passes two assets on one sender")
			}
		})
	}
	// One asset with two senders on one host is its own, not ambiguous.
	if err := asset.CheckSenders([]asset.Asset{c13Asset(t, c13A,
		sender("syslog-udp", "192.0.2.40"), sender("syslog-tcp", "192.0.2.40"))}); err != nil {
		t.Fatalf("one asset, two senders: %v", err)
	}
}
