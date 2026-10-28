// Package nodeconfigtest writes otsec.nodeconfig/0.1 files for tests (A1
// D2-6: tests write the node configuration only through A5's helper). Every
// value it writes is a test value. Every endpoint and listener is
// simulated unless a test sets otherwise on purpose, to check a refusal.
package nodeconfigtest

import (
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"

	"otsec.local/otsec/modules/security/seal"
)

// Config is a node configuration under construction. Its fields are the
// file's sections; tests may change any of them before Bytes or Write.
type Config struct {
	Schema            string           `json:"schema"`
	NodeID            string           `json:"node_id"`
	Store             Store            `json:"store"`
	Listeners         []Listener       `json:"listeners"`
	SyslogOutageHours int              `json:"syslog_outage_hours,omitempty"`
	Assets            []map[string]any `json:"assets"`
	Targets           []map[string]any `json:"targets"`
	Schedule          []Collection     `json:"schedule"`
	CollectorPipe     string           `json:"collector_pipe"`
	CollectorPeer     string           `json:"collector_peer,omitempty"`
	PolicyVersion     uint64           `json:"policy_version"`
	RegisterVersion   uint64           `json:"register_version"`
	// LabTLSFiles is the lab flag tls_dir needs (D2-12); New sets it.
	LabTLSFiles bool   `json:"lab_tls_files,omitempty"`
	TLSDir      string `json:"tls_dir,omitempty"`
	// KeyRegister is the node key register (WriteKeyRegister).
	KeyRegister string `json:"key_register,omitempty"`
	AdminDir    string `json:"admin_dir,omitempty"`
	// CollectorPublicDir holds install-key.json (WriteInstallKey).
	CollectorPublicDir string `json:"collector_public_dir,omitempty"`
}

type Store struct {
	Dir          string           `json:"dir"`
	Quotas       map[string]int64 `json:"quotas"`
	WarnFraction float64          `json:"warn_fraction"`
}

type Listener struct {
	ID        string       `json:"id"`
	Transport string       `json:"transport"`
	Address   string       `json:"address"`
	Target    string       `json:"target"`
	Plaintext bool         `json:"plaintext,omitempty"`
	TLS       *ListenerTLS `json:"tls,omitempty"`
	// ReadBuffer is a syslog-udp listener's read_buffer_bytes.
	ReadBuffer int `json:"read_buffer_bytes,omitempty"`
}

type ListenerTLS struct {
	CredentialRef     string `json:"credential_ref"`
	SenderCARef       string `json:"sender_ca_ref,omitempty"`
	RequireSenderCert bool   `json:"require_sender_cert,omitempty"`
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
		Listeners:          []Listener{},
		Assets:             []map[string]any{},
		Targets:            []map[string]any{},
		Schedule:           []Collection{},
		CollectorPipe:      pipe,
		CollectorPeer:      peer,
		PolicyVersion:      3,
		RegisterVersion:    4,
		LabTLSFiles:        true,
		TLSDir:             filepath.Join(filepath.Dir(storeDir), "tls"),
		CollectorPublicDir: filepath.Join(filepath.Dir(storeDir), "collector-public"),
	}
}

// InstallKey is the test install key named name: an X25519 key whose
// private half is the SHA-256 of name, with its derived key ID and
// fingerprint (seal.KeyID, seal.Fingerprint), so one name always gives the
// same key and different names give different keys.
func InstallKey(name string) (keyID, publicKey, fingerprint string) {
	sum := sha256.Sum256([]byte(name))
	priv, err := ecdh.X25519().NewPrivateKey(sum[:])
	if err != nil {
		panic(err) // any 32 bytes are an X25519 private key
	}
	pub := priv.PublicKey().Bytes()
	return seal.KeyID(pub), base64.StdEncoding.EncodeToString(pub), seal.Fingerprint(pub)
}

// InstallKeyID is the key ID of InstallKey(name).
func InstallKeyID(name string) string {
	id, _, _ := InstallKey(name)
	return id
}

// WriteInstallKey writes install-key.json in CollectorPublicDir as the
// collector does (A3 #106), for the test install key named name.
func (c *Config) WriteInstallKey(name string) error {
	if err := os.MkdirAll(c.CollectorPublicDir, 0o700); err != nil {
		return err
	}
	id, pub, fp := InstallKey(name)
	// Indented and ending in a newline, as cmd/otsec-collector's
	// publishInstallKey writes it (A3 #106), so the node's strict read is
	// tested against the real writer's shape.
	b, err := json.MarshalIndent(map[string]string{"schema": "otsec.collector.install_key/0.1", "key_id": id,
		"public_key": pub, "fingerprint": fp}, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	tmp := filepath.Join(c.CollectorPublicDir, ".install-key.tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(c.CollectorPublicDir, "install-key.json"))
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
		"schema":   "otsec.asset/0.2",
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
			"id": "port1-telnet", "transport": "telnet", "host": host, "port": port, "target": "simulated", "path": "direct",
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

// AddListener adds a simulated Syslog listener that loads: a syslog-tls
// listener names the credential "test-listener" in tls_dir, and a
// plaintext one sets the lab-only flag.
func (c *Config) AddListener(id, transport, address string) *Config {
	l := Listener{ID: id, Transport: transport, Address: address, Target: "simulated"}
	if transport == "syslog-tls" {
		l.TLS = &ListenerTLS{CredentialRef: "test-listener"}
	} else {
		l.Plaintext = true
	}
	c.Listeners = append(c.Listeners, l)
	return c
}

// AddSyslogSender gives the asset an inbound Syslog endpoint: host is the
// sender's address as a listener sees it, and port 0 matches any listener
// port.
func (c *Config) AddSyslogSender(assetID, epID, transport, host string, port int) *Config {
	for _, a := range c.Assets {
		if a["asset_id"] != assetID {
			continue
		}
		// Without a pinned key, TLS does not authenticate the device, so a
		// TLS sender is encrypted-weak (C1).
		level := "plaintext-unauthenticated"
		if transport == "syslog-tls" {
			level = "encrypted-weak"
		}
		ds := map[string]any{"level": level, "acknowledgement": map[string]any{
			"by": "admin:lab-admin", "at": "2026-10-24T09:00:00Z",
			"reason": "Simulated sender only (ADR-0005)", "scope": "lab-only",
		}}
		ep := map[string]any{"id": epID, "transport": transport, "host": host, "target": "simulated", "downstream_security": ds}
		if port != 0 {
			ep["port"] = port
		}
		a["endpoints"] = append(a["endpoints"].([]any), ep)
	}
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
