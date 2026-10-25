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

func TestD210NodeRefusesNonLoopbackListener(t *testing.T) {
	dir := storeDir(t)
	// Valid ip:port that is not loopback: refused under D2-10.
	for _, addr := range []string{
		"0.0.0.0:6514", "[::]:6514", "10.0.0.5:6514", "192.168.1.10:514", "[fe80::1%1]:514",
		"[::ffff:127.0.0.1]:6514", "[::1%1]:6514",
	} {
		c := nodeconfigtest.New("site-a-node1", dir).AddListener("syslog-in", "syslog-tls", addr)
		if _, err := node.ParseConfig(c.Bytes()); !errors.Is(err, node.ErrNotLoopback) {
			t.Errorf("listener %q: %v, want ErrNotLoopback", addr, err)
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
		c := nodeconfigtest.New("site-a-node1", dir).AddListener("syslog-in", "syslog-tls", addr)
		if _, err := node.ParseConfig(c.Bytes()); err != nil {
			t.Errorf("listener %q refused: %v", addr, err)
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
