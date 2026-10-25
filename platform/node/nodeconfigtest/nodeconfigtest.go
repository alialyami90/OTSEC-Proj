// Package nodeconfigtest writes otsec.nodeconfig/0.1 files for tests (A1
// D2-6: tests write the node configuration only through A5's helper). Every
// value it writes is a test value. Every endpoint and listener is
// simulated unless a test sets otherwise on purpose, to check a refusal.
package nodeconfigtest

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
)

// Config is a node configuration under construction. Its fields are the
// file's sections; tests may change any of them before Bytes or Write.
type Config struct {
	Schema          string           `json:"schema"`
	NodeID          string           `json:"node_id"`
	Store           Store            `json:"store"`
	Listeners       []Listener       `json:"listeners"`
	Assets          []map[string]any `json:"assets"`
	Targets         []map[string]any `json:"targets"`
	Schedule        []Collection     `json:"schedule"`
	CollectorPipe   string           `json:"collector_pipe"`
	CollectorPeer   string           `json:"collector_peer,omitempty"`
	PolicyVersion   uint64           `json:"policy_version"`
	RegisterVersion uint64           `json:"register_version"`
	TLSDir          string           `json:"tls_dir,omitempty"`
}

type Store struct {
	Dir          string           `json:"dir"`
	Quotas       map[string]int64 `json:"quotas"`
	WarnFraction float64          `json:"warn_fraction"`
}

type Listener struct {
	ID        string `json:"id"`
	Transport string `json:"transport"`
	Address   string `json:"address"`
	Target    string `json:"target"`
}

type Collection struct {
	ID            string            `json:"id"`
	AssetID       string            `json:"asset_id"`
	Endpoint      string            `json:"endpoint"`
	Operation     string            `json:"operation"`
	Params        map[string]string `json:"params,omitempty"`
	CredentialRef string            `json:"credential_ref,omitempty"`
	EverySeconds  int               `json:"every_seconds"`
}

// TestCredentialRef is the credential reference AddSEL751 schedules with: a
// handle from the C7 test data, never bound to a real secret.
const TestCredentialRef = "cred_7f3k2m9q4x"

// New returns a configuration for node with its store in storeDir, 64 MiB
// per class, its TLS files in "tls" beside storeDir (WritePKI writes them),
// and no assets, listeners or targets. The collector peer is
// this process's uid on Linux (empty, the service SID, on Windows), and the
// policy and register versions are those of the C7 and C3 test data (3 and
// 2).
func New(node, storeDir string) *Config {
	pipe := filepath.Join(storeDir, "collector.sock")
	peer := strconv.Itoa(os.Getuid())
	if runtime.GOOS == "windows" {
		pipe, peer = `\\.\pipe\otsec-collector-test`, ""
	}
	q := int64(64 << 20)
	return &Config{
		Schema: "otsec.nodeconfig/0.1",
		NodeID: node,
		Store: Store{Dir: storeDir, WarnFraction: 0.8, Quotas: map[string]int64{
			"adapter-evidence": q, "syslog-stream": q, "syslog-datagram": q, "platform": q, "audit": q,
		}},
		Listeners:       []Listener{},
		Assets:          []map[string]any{},
		Targets:         []map[string]any{},
		Schedule:        []Collection{},
		CollectorPipe:   pipe,
		CollectorPeer:   peer,
		PolicyVersion:   3,
		RegisterVersion: 2,
		TLSDir:          filepath.Join(filepath.Dir(storeDir), "tls"),
	}
}

// AddSEL751 adds a simulated SEL-751 reached over Telnet at host:port (A6's
// recording simulator); an empty host is 127.0.0.1, and the loader refuses
// any host that is not a loopback IP literal (D2-10) and schedules sel.ser.read_all on it every
// everySeconds. The record is a C1 asset with operator-declared attributes
// only: nothing in it claims a device observation.
func (c *Config) AddSEL751(assetID, host string, port, everySeconds int) *Config {
	if host == "" {
		host = "127.0.0.1"
	}
	declared := func(name, value string) map[string]any {
		return map[string]any{
			"name": name, "value": value, "confidence": "single-source",
			"observations": []any{map[string]any{
				"value": value, "evidence_class": "operator-declared",
				"source": map[string]any{"method": "operator-entry", "ref": "operator:test-fixture", "observed_at": "2026-10-24T09:00:00Z"},
			}},
		}
	}
	c.Assets = append(c.Assets, map[string]any{
		"schema":   "otsec.asset/0.1",
		"asset_id": assetID,
		"node_id":  c.NodeID,
		"attributes": []any{
			declared("device_class", "protective-relay"),
			declared("vendor", "sel"),
			declared("product_family", "sel-751"),
			declared("firmware_id", "SEL-751-R501-V0-Z104101-D20260910"),
			declared("serial_number", "SIM0000000000001"),
		},
		"endpoints": []any{map[string]any{
			"id": "port1-telnet", "transport": "telnet", "host": host, "port": port, "target": "simulated",
			"downstream_security": map[string]any{
				"level": "plaintext-unauthenticated",
				"acknowledgement": map[string]any{
					"by": "admin:lab-admin", "at": "2026-10-24T09:00:00Z",
					"reason": "Simulated slice only, test credentials (ADR-0005)", "scope": "lab-only",
				},
			},
		}},
		"identity_binding": map[string]any{
			"method": "device-reported", "strength": "spoofable",
			"attributes": []string{"firmware_id", "serial_number"}, "pre_credential": []string{"firmware_id"},
		},
		"profile": map[string]any{"id": "sel-751-ascii", "version": "0.1"},
	})
	c.Schedule = append(c.Schedule, Collection{ID: "sch-ser-" + assetID[:8], AssetID: assetID, Endpoint: "port1-telnet",
		Operation: "sel.ser.read_all", CredentialRef: TestCredentialRef, EverySeconds: everySeconds})
	return c
}

// AddRELPTarget adds a required relp-tls C6 0.2 target. durableAckRef is
// the evidence reference of the target's durable-acknowledgement check
// (V-S6); tests that have not run one must not use a required target. The
// collector's permitted peer is the node ID, its test certificate name,
// checked by name and acknowledged after a durable write (D2-9).
func (c *Config) AddRELPTarget(name, host string, port int, trustAnchor, clientCredential, durableAckRef string, audit bool) *Config {
	t := map[string]any{
		"schema": "otsec.syslog/0.2", "name": name, "host": host, "port": port,
		"transport": "relp-tls", "format": "rfc5424", "framing": "relp", "class": "required",
		"max_message_octets": 2048, "facility": 16, "relp_window": 128,
		"tls": map[string]any{"server_name": host, "trust_anchor_ref": trustAnchor, "client_credential_ref": clientCredential},
		"durable_ack": map[string]any{"verified_utc": "2026-10-24T09:00:00Z", "evidence_ref": durableAckRef,
			"peer_check": "name", "permitted_peer": c.NodeID, "ack_after": "durable-write"},
	}
	if audit {
		// A sealed C8 record must fit whole (C6, audit.MaxRecordBytes).
		t["audit"] = true
		t["max_message_octets"] = 17408
	}
	c.Targets = append(c.Targets, t)
	return c
}

// AddListener adds a simulated Syslog listener.
func (c *Config) AddListener(id, transport, address string) *Config {
	c.Listeners = append(c.Listeners, Listener{ID: id, Transport: transport, Address: address, Target: "simulated"})
	return c
}

// SetEndpointTarget sets the target of every endpoint of the asset, for
// tests of the D2-4 refusal.
func (c *Config) SetEndpointTarget(assetID, target string) *Config {
	for _, a := range c.Assets {
		if a["asset_id"] != assetID {
			continue
		}
		for _, ep := range a["endpoints"].([]any) {
			ep.(map[string]any)["target"] = target
		}
	}
	return c
}

// Bytes is the file's content.
func (c *Config) Bytes() []byte {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		panic(fmt.Sprintf("nodeconfigtest: %v", err))
	}
	return append(b, '\n')
}

// Write writes the file to path, readable by its owner only.
func (c *Config) Write(path string) error { return os.WriteFile(path, c.Bytes(), 0o600) }
