package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/authz"
	"otsec.local/otsec/contracts/node"
	"otsec.local/otsec/modules/security/collector"
	"otsec.local/otsec/modules/security/collectorwire"
)

// ConfigFormat identifies the collector's configuration file. Any other
// value is refused.
const ConfigFormat = "otsec.collector-config/0.1"

// maxConfigBytes bounds the configuration file before it is parsed.
const maxConfigBytes = 8 << 20

// layout is where the collector keeps its files under the data directory
// (%ProgramData%\OTSEC on Windows). The installer creates the directories
// with their DACLs (A5, platform/winsvc; A3 design W-4).
type layout struct {
	config      string // collector\collector.json: owner BA, collector reads, node nothing
	state       string // collector\state\state.json
	provision   string // collector\state\provision: the installer's first-start marker
	credentials string // collector\credentials\credentials.json
	publicKey   string // collector\public\install-key.json: public, the node reads it
	// admin is config\admin, the administrators' folder the node and the
	// collector both read and neither writes: owner BA, a protected DACL,
	// read and traverse for each service (A5, #108). It holds
	// clear-suspension.json (C7 0.2 asset.clear_suspension).
	admin string
}

func newLayout(data string) layout {
	c := filepath.Join(data, "collector")
	return layout{
		config:      filepath.Join(c, "collector.json"),
		state:       filepath.Join(c, "state", "state.json"),
		provision:   filepath.Join(c, "state", "provision"),
		credentials: filepath.Join(c, "credentials", "credentials.json"),
		publicKey:   filepath.Join(c, "public", "install-key.json"),
		admin:       filepath.Join(data, "config", "admin"),
	}
}

// fileConfig is collector.json. An administrator writes it; the node
// cannot read or change it. Assets and profiles are C1 records, decoded by
// C1; registers are signed C3 envelopes, verified by the collector.
type fileConfig struct {
	Format        string            `json:"format"`
	NodeID        string            `json:"node_id"`
	PolicyVersion uint64            `json:"policy_version"`
	IPC           ipcConfig         `json:"ipc"`
	Assets        []json.RawMessage `json:"assets"`
	Profiles      []json.RawMessage `json:"profiles"`
	TrustAnchors  []anchorConfig    `json:"trust_anchors"`
	Registers     []json.RawMessage `json:"registers"`
	// InstallLimit is installs per hour; 0 means the pipeline's default.
	InstallLimit int `json:"install_limit,omitempty"`
}

type ipcConfig struct {
	// Address is the pipe or socket; empty means the platform default
	// (\\.\pipe\otsec-collector on Windows).
	Address string `json:"address,omitempty"`
	// NodePeer is the node's identity: a SID on Windows, a uid on Linux.
	// Empty on Windows means NT SERVICE\otsec-node's service SID.
	NodePeer string `json:"node_peer,omitempty"`
}

type anchorConfig struct {
	KeyID     string `json:"key_id"`
	PublicKey string `json:"public_key"` // standard base64, 32 bytes
	Status    string `json:"status"`     // active or revoked
}

// config is the checked configuration.
type config struct {
	NodeID        string
	PolicyVersion uint64
	Endpoint      collectorwire.Endpoint
	Assets        []collector.Enrolled
	Anchors       []authz.TrustAnchor
	Registers     [][]byte
	InstallLimit  int
}

func loadConfig(path string) (config, error) {
	f, err := os.Open(path)
	if err != nil {
		return config{}, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return config{}, err
	}
	if !st.Mode().IsRegular() || st.Size() > maxConfigBytes {
		return config{}, fmt.Errorf("%s is not a regular file of at most %d bytes", path, maxConfigBytes)
	}
	b := make([]byte, st.Size())
	if _, err := f.ReadAt(b, 0); err != nil && st.Size() > 0 {
		return config{}, err
	}
	return parseConfig(b)
}

// parseConfig decodes and checks collector.json. Every asset must be valid
// C1, on this node, with exactly one matching profile; NewPipeline checks
// the same again.
func parseConfig(b []byte) (config, error) {
	var fc fileConfig
	if err := collectorwire.DecodeStrict(b, &fc); err != nil {
		return config{}, fmt.Errorf("collector config: %w", err)
	}
	if fc.Format != ConfigFormat {
		return config{}, fmt.Errorf("collector config: format %q, want %q", fc.Format, ConfigFormat)
	}
	if !node.ID(fc.NodeID).Valid() {
		return config{}, fmt.Errorf("collector config: node_id %q is not valid", fc.NodeID)
	}
	if fc.PolicyVersion == 0 {
		return config{}, errors.New("collector config: policy_version must be at least 1")
	}
	if fc.InstallLimit < 0 {
		return config{}, errors.New("collector config: install_limit is negative")
	}
	c := config{NodeID: fc.NodeID, PolicyVersion: fc.PolicyVersion, InstallLimit: fc.InstallLimit}
	ep, err := defaultEndpoint(fc.IPC)
	if err != nil {
		return config{}, err
	}
	c.Endpoint = ep

	profiles := map[string]asset.CapabilityProfile{}
	for i, raw := range fc.Profiles {
		p, err := asset.DecodeProfile(raw)
		if err != nil {
			return config{}, fmt.Errorf("collector config: profiles[%d]: %w", i, err)
		}
		if _, dup := profiles[p.ProfileID]; dup {
			return config{}, fmt.Errorf("collector config: profile %s appears twice", p.ProfileID)
		}
		profiles[p.ProfileID] = p
	}
	for i, raw := range fc.Assets {
		a, err := asset.Decode(raw)
		if err != nil {
			return config{}, fmt.Errorf("collector config: assets[%d]: %w", i, err)
		}
		if a.Profile == nil {
			return config{}, fmt.Errorf("collector config: asset %s names no profile", a.AssetID)
		}
		p, ok := profiles[a.Profile.ID]
		if !ok || p.Version != a.Profile.Version {
			return config{}, fmt.Errorf("collector config: asset %s names profile %s %s, which is not in the file", a.AssetID, a.Profile.ID, a.Profile.Version)
		}
		c.Assets = append(c.Assets, collector.Enrolled{Asset: a, Profile: p})
	}
	for i, a := range fc.TrustAnchors {
		pub, err := base64.StdEncoding.Strict().DecodeString(a.PublicKey)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			return config{}, fmt.Errorf("collector config: trust_anchors[%d]: public_key is not 32 bytes of strict base64", i)
		}
		st := authz.KeyStatus(a.Status)
		if st != authz.KeyActive && st != authz.KeyRevoked {
			return config{}, fmt.Errorf("collector config: trust_anchors[%d]: status %q", i, a.Status)
		}
		c.Anchors = append(c.Anchors, authz.TrustAnchor{KeyID: a.KeyID, PublicKey: ed25519.PublicKey(pub), Status: st})
	}
	for _, r := range fc.Registers {
		c.Registers = append(c.Registers, []byte(r))
	}
	return c, nil
}

var errMissingIPC = errors.New("collector config: ipc.address and ipc.node_peer are required on this platform")
