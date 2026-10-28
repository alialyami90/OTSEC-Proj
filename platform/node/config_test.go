package node

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/platform/node/nodeconfigtest"
)

const relayID = "2b7d4e10-8c3f-4a5b-9e21-7c4f0d6a8b13"

func sample(t *testing.T) *nodeconfigtest.Config {
	t.Helper()
	return nodeconfigtest.New("site-a-node1", t.TempDir()).
		AddSEL751(relayID, "127.0.0.1", 2323, 300).
		AddRELPTarget("central", "127.0.0.1", 2514, "test-ca", "test-client", "test/durable-ack", true).
		AddListener("lab-udp", "syslog-udp", "127.0.0.1:5514")
}

func TestLoadSample(t *testing.T) {
	path := filepath.Join(t.TempDir(), "node.json")
	if err := sample(t).Write(path); err != nil {
		t.Fatal(err)
	}
	c, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.AssetRecords()) != 1 || len(c.ForwardTargets()) != 1 {
		t.Fatalf("%d assets %d targets", len(c.AssetRecords()), len(c.ForwardTargets()))
	}
	l, err := c.Layout()
	if err != nil {
		t.Fatal(err)
	}
	want := map[c5.StreamID]c5.StreamClass{
		SERStream(relayID):        c5.ClassAdapterEvidence,
		QuarantineStream(relayID): c5.ClassAdapterEvidence,
		HealthStream:              c5.ClassPlatform,
		ListenerStream("lab-udp"): c5.ClassSyslogDatagram,
		UnknownStream("lab-udp"):  c5.ClassSyslogUnknown,
		AuditStream:               c5.ClassAudit,
	}
	got := l.StreamClasses()
	if len(got) != len(want) {
		t.Fatalf("streams %v", got)
	}
	for s, class := range want {
		if got[s] != class {
			t.Fatalf("stream %s is %s, want %s", s, got[s], class)
		}
	}
	cs, err := c.Consumers()
	if err != nil {
		t.Fatal(err)
	}
	// One required consumer per stream, audit included (the target audits),
	// (the unknown stream too), and none for the quarantine stream, which
	// nothing forwards.
	if len(cs) != 5 {
		t.Fatalf("consumers %v", cs)
	}
	for _, x := range cs {
		if x.ID != "central" || x.Delivery != c5.Required || x.Stream == QuarantineStream(relayID) {
			t.Fatalf("consumer %+v", x)
		}
	}
}

// D2-4: a device-observed endpoint or listener refuses the whole file.
func TestDeviceObservedRefused(t *testing.T) {
	endpoint := sample(t).SetEndpointTarget(relayID, "device-observed")
	listener := sample(t)
	listener.Listeners[0].Target = "device-observed"
	for name, c := range map[string]*nodeconfigtest.Config{"endpoint": endpoint, "listener": listener} {
		_, err := ParseConfig(c.Bytes())
		if !errors.Is(err, ErrDeviceObserved) {
			t.Errorf("%s: %v", name, err)
		}
	}
	other := sample(t)
	other.Listeners[0].Target = "documented"
	if _, err := ParseConfig(other.Bytes()); err == nil || errors.Is(err, ErrDeviceObserved) {
		t.Errorf("listener target documented: %v", err)
	}
	missing := sample(t)
	missing.Listeners[0].Target = ""
	if _, err := ParseConfig(missing.Bytes()); err == nil {
		t.Error("listener without a target loaded")
	}
}

// D2-10: a collection endpoint or a listener off loopback refuses the whole
// file, whatever its target label says. Forwarding targets are exempt.
func TestNotLoopbackRefused(t *testing.T) {
	host := func(h string) *nodeconfigtest.Config {
		c := sample(t)
		c.Assets[0]["endpoints"].([]any)[0].(map[string]any)["host"] = h
		return c
	}
	for _, h := range []string{"10.0.0.5", "192.0.2.10", "::ffff:127.0.0.1", "::1%lo", "0.0.0.0"} {
		if _, err := ParseConfig(host(h).Bytes()); !errors.Is(err, ErrNotLoopback) {
			t.Errorf("endpoint host %s: %v", h, err)
		}
	}
	// C1 refuses a host name before the loopback check sees it.
	for _, h := range []string{"localhost", "relay1.example"} {
		if _, err := ParseConfig(host(h).Bytes()); err == nil {
			t.Errorf("endpoint host %s loaded", h)
		}
	}
	for _, h := range []string{"127.0.0.1", "127.8.9.10", "::1"} {
		if _, err := ParseConfig(host(h).Bytes()); err != nil {
			t.Errorf("endpoint host %s refused: %v", h, err)
		}
	}
	for addr, ok := range map[string]bool{"10.0.0.5:5514": false, "0.0.0.0:5514": false, "[::ffff:127.0.0.1]:5514": false, "127.0.0.1:5514": true, "[::1]:5514": true} {
		c := sample(t)
		c.Listeners[0].Address = addr
		_, err := ParseConfig(c.Bytes())
		if ok && err != nil || !ok && !errors.Is(err, ErrNotLoopback) {
			t.Errorf("listener %s: %v", addr, err)
		}
	}
	upstream := sample(t)
	upstream.Targets[0]["host"] = "192.0.2.20"
	upstream.Targets[0]["tls"].(map[string]any)["server_name"] = "collector.example"
	if _, err := ParseConfig(upstream.Bytes()); err != nil {
		t.Errorf("forwarding target off loopback refused: %v", err)
	}
}

func TestStrictDecoding(t *testing.T) {
	good := sample(t).Bytes()
	cases := map[string][]byte{
		"unknown field":  bytes.Replace(good, []byte(`"node_id"`), []byte(`"nodes":1,"node_id"`), 1),
		"case variant":   bytes.Replace(good, []byte(`"node_id"`), []byte(`"NODE_ID"`), 1),
		"duplicate key":  bytes.Replace(good, []byte(`"node_id"`), []byte(`"node_id":"site-b-node1","node_id"`), 1),
		"trailing data":  append(append([]byte{}, good...), []byte(`{}`)...),
		"other schema":   bytes.Replace(good, []byte(`otsec.nodeconfig/0.1`), []byte(`otsec.nodeconfig/0.2`), 1),
		"asset dup key":  bytes.Replace(good, []byte(`"asset_id"`), []byte(`"asset_id":"x","asset_id"`), 1),
		"nested variant": bytes.Replace(good, []byte(`"transport": "telnet"`), []byte(`"Transport": "telnet"`), 1),
	}
	for name, b := range cases {
		if _, err := ParseConfig(b); err == nil {
			t.Errorf("%s: loaded", name)
		}
	}
	if _, err := ParseConfig(good); err != nil {
		t.Fatal(err)
	}
}

func TestChecks(t *testing.T) {
	cases := map[string]func(c *nodeconfigtest.Config){
		"bad node":         func(c *nodeconfigtest.Config) { c.NodeID = "Site-A" },
		"relative store":   func(c *nodeconfigtest.Config) { c.Store.Dir = "store" },
		"missing quota":    func(c *nodeconfigtest.Config) { delete(c.Store.Quotas, "audit") },
		"unknown quota":    func(c *nodeconfigtest.Config) { c.Store.Quotas["cache"] = 1 },
		"zero quota":       func(c *nodeconfigtest.Config) { c.Store.Quotas["platform"] = 0 },
		"warn fraction":    func(c *nodeconfigtest.Config) { c.Store.WarnFraction = 1 },
		"pipe":             func(c *nodeconfigtest.Config) { c.CollectorPipe = "collector" },
		"listener address": func(c *nodeconfigtest.Config) { c.Listeners[0].Address = "localhost" },
		"listener tcp to device": func(c *nodeconfigtest.Config) {
			c.Listeners[0].Transport = "telnet"
		},
		"duplicate listener": func(c *nodeconfigtest.Config) { c.Listeners = append(c.Listeners, c.Listeners[0]) },
		"unknown asset":      func(c *nodeconfigtest.Config) { c.Schedule[0].AssetID = "00000000-0000-4000-8000-000000000000" },
		"unknown endpoint":   func(c *nodeconfigtest.Config) { c.Schedule[0].Endpoint = "port2" },
		"bad operation":      func(c *nodeconfigtest.Config) { c.Schedule[0].Operation = "SER" },
		"long operation": func(c *nodeconfigtest.Config) {
			c.Schedule[0].Operation = "sel." + strings.Repeat("a", MaxOperationBytes)
		},
		"fast schedule":      func(c *nodeconfigtest.Config) { c.Schedule[0].EverySeconds = 5 },
		"other node's asset": func(c *nodeconfigtest.Config) { c.Assets[0]["node_id"] = "site-b-node1" },
		"duplicate target":   func(c *nodeconfigtest.Config) { c.Targets = append(c.Targets, c.Targets[0]) },
		"invalid target":     func(c *nodeconfigtest.Config) { delete(c.Targets[0], "durable_ack") },
		"invalid asset":      func(c *nodeconfigtest.Config) { delete(c.Assets[0], "identity_binding") },
		"no schedule id":     func(c *nodeconfigtest.Config) { c.Schedule[0].ID = "" },
		"duplicate schedule": func(c *nodeconfigtest.Config) { c.Schedule = append(c.Schedule, c.Schedule[0]) },
		"bad credential ref": func(c *nodeconfigtest.Config) { c.Schedule[0].CredentialRef = "password123" },
		"bad param":          func(c *nodeconfigtest.Config) { c.Schedule[0].Params = map[string]string{"n": "1\r\nQUI"} },
		"no policy version":  func(c *nodeconfigtest.Config) { c.PolicyVersion = 0 },
		"no register":        func(c *nodeconfigtest.Config) { c.RegisterVersion = 0 },
	}
	if runtime.GOOS != "windows" {
		cases["no collector peer"] = func(c *nodeconfigtest.Config) { c.CollectorPeer = "" }
	}
	for name, mutate := range cases {
		c := sample(t)
		mutate(c)
		_, err := ParseConfig(c.Bytes())
		if err == nil {
			t.Errorf("%s: loaded", name)
		}
		t.Logf("%s: %v", name, err)
	}
}

func TestLoadConfigBounds(t *testing.T) {
	path := filepath.Join(t.TempDir(), "big.json")
	if err := os.WriteFile(path, bytes.Repeat([]byte(" "), MaxConfigBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil || !strings.Contains(err.Error(), "larger") {
		t.Fatalf("oversize: %v", err)
	}
}

func FuzzParseConfig(f *testing.F) {
	f.Add(nodeconfigtest.New("site-a-node1", "/var/lib/otsec").AddSEL751(relayID, "127.0.0.1", 23, 300).Bytes())
	f.Add([]byte(`{"schema":"otsec.nodeconfig/0.1"}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		c, err := ParseConfig(b)
		if err != nil {
			return
		}
		for _, a := range c.AssetRecords() {
			for _, ep := range a.Endpoints {
				if ep.Target != "simulated" {
					t.Fatalf("loaded endpoint target %q", ep.Target)
				}
			}
		}
		for _, l := range c.Listeners {
			if l.Target != "simulated" {
				t.Fatalf("loaded listener target %q", l.Target)
			}
		}
		if _, err := c.Layout(); err != nil {
			t.Fatalf("loaded config has no layout: %v", err)
		}
	})
}
