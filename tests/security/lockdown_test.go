package security

import (
	"errors"
	"path/filepath"
	"testing"

	"otsec.local/otsec/platform/node"
	"otsec.local/otsec/platform/node/nodeconfigtest"
	"otsec.local/otsec/platform/store"
)

// D2-10, lock 1 of 2: the node loader refuses any collection endpoint or
// Syslog listener that is not a loopback IP literal (127.0.0.0/8 or ::1).
// Lock 2, in the collector, gets its own test when A3's check lands.
//
// Ground truth is the rule text of D2-10 (docs/phase2/A1-decisions.md), not
// A5's implementation.
// Evidence class: simulated. Nothing here opens a connection.

const relayID = "6f1c2e8a-4b3d-4c5e-9f70-0a1b2c3d4e5f"

// IP literals C1 accepts as a host that are not loopback, or are loopback
// in a form D2-10 refuses (IPv4-mapped, zoned): the loader must refuse each
// with ErrNotLoopback.
var ipNotLoopback = []string{
	"10.0.0.5", "192.168.1.10", "172.16.0.1", "8.8.8.8",
	"0.0.0.0", "::", "fe80::1", "fd00::1", "2001:db8::1",
	"::ffff:127.0.0.1", "::ffff:7f00:1", "0:0:0:0:0:ffff:127.0.0.1",
	"::1%lo", "::1%1",
}

// Hosts that are not an IP literal at all: names (localhost included),
// shortened and numeric IPv4 forms, brackets, ports and spaces. Refused
// for any reason (today C1 refuses them first); none may load.
var notAnIP = []string{
	"localhost", "LOCALHOST", "localhost.", "ip6-localhost", "relay1", "127.0.0.1.nip.io",
	"127.1", "127.0.1", "2130706433", "0x7f000001", "0177.0.0.1", "017700000001", "127.000.000.001",
	"[::1]", "127.0.0.1 ", " 127.0.0.1", "127.0.0.1:23", "",
}

var loopbackHosts = []string{"127.0.0.1", "127.0.0.2", "127.255.255.254", "::1", "0:0:0:0:0:0:0:1"}

func storeDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "store")
	if err := store.CreateDir(dir, ""); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestD210NodeRefusesNonLoopbackEndpoint(t *testing.T) {
	dir := storeDir(t)
	withHost := func(host string) []byte {
		c := nodeconfigtest.New("site-a-node1", dir).AddSEL751(relayID, "127.0.0.1", 2323, 300)
		c.Assets[0]["endpoints"].([]any)[0].(map[string]any)["host"] = host
		return c.Bytes()
	}
	for _, host := range ipNotLoopback {
		if _, err := node.ParseConfig(withHost(host)); !errors.Is(err, node.ErrNotLoopback) {
			t.Errorf("endpoint host %q: %v, want ErrNotLoopback", host, err)
		}
	}
	for _, host := range notAnIP {
		if _, err := node.ParseConfig(withHost(host)); err == nil {
			t.Errorf("endpoint host %q accepted", host)
		}
	}
	for _, host := range loopbackHosts {
		c := nodeconfigtest.New("site-a-node1", dir).AddSEL751(relayID, host, 2323, 300)
		if _, err := node.ParseConfig(c.Bytes()); err != nil {
			t.Errorf("endpoint host %q refused: %v", host, err)
		}
	}
}

// Every endpoint other than inbound Syslog is checked, scheduled or not
// (A5 review of #93): a second, unscheduled telnet endpoint on a
// non-loopback host is refused just as the scheduled one is.
func TestD210NodeRefusesUnscheduledEndpoint(t *testing.T) {
	dir := storeDir(t)
	withSecond := func(transport, host string, port int) []byte {
		c := nodeconfigtest.New("site-a-node1", dir).AddSEL751(relayID, "127.0.0.1", 2323, 300)
		eps := c.Assets[0]["endpoints"].([]any)
		second := map[string]any{}
		for k, v := range eps[0].(map[string]any) {
			second[k] = v
		}
		second["id"], second["transport"], second["host"], second["port"] = "port2", transport, host, port
		c.Assets[0]["endpoints"] = append(eps, second)
		return c.Bytes()
	}
	for _, host := range []string{"10.0.0.5", "192.168.1.10", "::ffff:127.0.0.1"} {
		if _, err := node.ParseConfig(withSecond("telnet", host, 23)); !errors.Is(err, node.ErrNotLoopback) {
			t.Errorf("unscheduled telnet endpoint on %q: %v, want ErrNotLoopback", host, err)
		}
	}
	if _, err := node.ParseConfig(withSecond("telnet", "127.0.0.1", 23)); err != nil {
		t.Errorf("unscheduled loopback telnet endpoint refused: %v", err)
	}
	// An inbound Syslog endpoint names a sender the node only receives
	// from and never connects to, so D2-10 does not apply to it (A1, D2-10
	// "collection endpoints"; A5). Pinned so that a change to that reading
	// is a deliberate one.
	for _, tr := range []string{"syslog-udp", "syslog-tcp", "syslog-tls"} {
		if _, err := node.ParseConfig(withSecond(tr, "10.0.0.5", 514)); err != nil {
			t.Errorf("inbound %s sender on 10.0.0.5 refused: %v", tr, err)
		}
	}
}

func TestD210NodeRefusesNonLoopbackListener(t *testing.T) {
	dir := storeDir(t)
	// Valid ip:port that is not loopback: refused under D2-10.
	for _, addr := range []string{
		"0.0.0.0:6514", "[::]:6514", "10.0.0.5:6514", "192.168.1.10:514", "[fe80::1%1]:514",
		"[::ffff:127.0.0.1]:6514", "[::1%1]:6514",
	} {
		for _, tr := range []string{"syslog-udp", "syslog-tcp", "syslog-tls"} {
			c := nodeconfigtest.New("site-a-node1", dir).AddListener("syslog-in", tr, addr)
			if _, err := node.ParseConfig(c.Bytes()); !errors.Is(err, node.ErrNotLoopback) {
				t.Errorf("%s listener %q: %v, want ErrNotLoopback", tr, addr, err)
			}
		}
	}
	// Not an ip:port at all: refused, whatever the reason.
	for _, addr := range []string{"localhost:6514", "127.1:6514", ":6514", "6514", ""} {
		c := nodeconfigtest.New("site-a-node1", dir).AddListener("syslog-in", "syslog-tls", addr)
		if _, err := node.ParseConfig(c.Bytes()); err == nil {
			t.Errorf("listener %q accepted", addr)
		}
	}
	for _, addr := range []string{"127.0.0.1:6514", "[::1]:6514"} {
		for _, tr := range []string{"syslog-udp", "syslog-tcp", "syslog-tls"} {
			c := nodeconfigtest.New("site-a-node1", dir).AddListener("syslog-in", tr, addr)
			if _, err := node.ParseConfig(c.Bytes()); err != nil {
				t.Errorf("%s listener %q refused: %v", tr, addr, err)
			}
		}
	}
}

// D2-4 alongside: a device-observed endpoint is refused even on loopback,
// so lifting D2-10 alone never reaches a device.
func TestD24NodeRefusesDeviceObservedOnLoopback(t *testing.T) {
	c := nodeconfigtest.New("site-a-node1", storeDir(t)).AddSEL751(relayID, "127.0.0.1", 2323, 300)
	c.Assets[0]["endpoints"].([]any)[0].(map[string]any)["target"] = "device-observed"
	if _, err := node.ParseConfig(c.Bytes()); !errors.Is(err, node.ErrDeviceObserved) {
		t.Fatalf("device-observed loopback endpoint: %v, want ErrDeviceObserved", err)
	}
}
