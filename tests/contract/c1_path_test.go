package contract

// C1 0.2 endpoint path (#149, D2-16, P3-A2): A6's own cases. Expected
// outcomes come from the rule text: only a direct path gets a session;
// no path, a port server, a path this reader does not know and a Syslog
// endpoint are refused, every refusal wrapping ErrPathRefused; a 0.1
// record may not carry a path; a later minor's unknown path reads as a
// port server. Records are built from the C1 golden by editing its JSON.
// Ground truth: GT-HAND.

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"otsec.local/otsec/contracts/asset"
)

// c1Record is the C1 golden with its schema and first endpoint's path
// and transport set as given; "-" leaves a field out.
func c1Record(t *testing.T, schema, transport, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "contracts", "asset", "testdata", "valid", "sel-751-simulated.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	m["schema"] = schema
	ep := m["endpoints"].([]any)[0].(map[string]any)
	delete(ep, "path")
	if path != "-" {
		ep["path"] = path
	}
	if transport != "" {
		ep["transport"] = transport
		if transport == "syslog-udp" || transport == "syslog-tcp" || transport == "syslog-tls" {
			ep["port"] = 514
		}
	}
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestC1PathCheck(t *testing.T) {
	for _, c := range []struct {
		transport asset.Transport
		path      asset.Path
		ok        bool
	}{
		{"telnet", asset.Direct, true},
		{"ssh", asset.Direct, true},
		{"telnet", "", false},
		{"telnet", asset.PortServer, false},
		{"telnet", "jump-host", false},
		{"telnet", "Direct", false},
		{"telnet", "direct ", false},
		{"syslog-udp", asset.Direct, false},
		{"syslog-tcp", asset.Direct, false},
		{"syslog-tls", asset.Direct, false},
		{"syslog-udp", "", false},
		{"modbus-tcp", asset.Direct, false}, // a transport this reader does not know (A6 on #149)
		{"syslog-relp", asset.Direct, false},
	} {
		err := asset.Endpoint{ID: "ep", Transport: c.transport, Path: c.path}.CheckPath()
		if c.ok != (err == nil) || (err != nil && !errors.Is(err, asset.ErrPathRefused)) {
			t.Errorf("%s path %q: %v", c.transport, c.path, err)
		}
	}
}

func TestC1PathReading(t *testing.T) {
	for _, c := range []struct {
		name, schema, transport, path string
		valid                         bool
		check                         bool // CheckPath allows the first endpoint
	}{
		{"0.2 direct", "otsec.asset/0.2", "", "direct", true, true},
		{"0.2 no path", "otsec.asset/0.2", "", "-", true, false},
		{"0.2 port-server", "otsec.asset/0.2", "", "port-server", true, false},
		{"0.2 empty path", "otsec.asset/0.2", "", "", true, false},
		{"0.2 unknown path", "otsec.asset/0.2", "", "jump-host", false, false},
		{"0.2 upper-case path", "otsec.asset/0.2", "", "DIRECT", false, false},
		{"0.2 path on syslog", "otsec.asset/0.2", "syslog-udp", "direct", false, false},
		{"0.1 no path", "otsec.asset/0.1", "", "-", true, false},
		{"0.1 with path", "otsec.asset/0.1", "", "direct", false, false},
		{"0.3 unknown path", "otsec.asset/0.3", "", "jump-host", true, false},
		{"0.3 direct", "otsec.asset/0.3", "", "direct", true, true},
		{"0.3 path on syslog", "otsec.asset/0.3", "syslog-tls", "direct", false, false},
		{"0.3 upper-case path", "otsec.asset/0.3", "", "DIRECT", false, false},
		{"0.3 unknown transport, direct", "otsec.asset/0.3", "syslog-relp", "direct", true, false},
	} {
		a, err := asset.Decode(c1Record(t, c.schema, c.transport, c.path))
		if c.valid != (err == nil) {
			t.Errorf("%s: decode %v", c.name, err)
			continue
		}
		if err != nil {
			continue
		}
		if got := a.Endpoints[0].CheckPath() == nil; got != c.check {
			t.Errorf("%s: CheckPath allows %v, want %v (path %q)", c.name, got, c.check, a.Endpoints[0].Path)
		}
		if c.path == "jump-host" && a.Endpoints[0].Path != asset.PortServer {
			t.Errorf("%s: a later minor's unknown path reads as %q, want port-server", c.name, a.Endpoints[0].Path)
		}
		if again := a.Effective(); again.Endpoints[0].Path != a.Endpoints[0].Path {
			t.Errorf("%s: Effective is not stable: %q then %q", c.name, a.Endpoints[0].Path, again.Endpoints[0].Path)
		}
	}
}
