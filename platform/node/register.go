package node

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"

	"otsec.local/otsec/contracts/authz"
	"otsec.local/otsec/contracts/register"
)

// RegisterCopy is the node's own copy of the signed command register (D4-40
// item 7, #383). It comes from the node's configuration only, never from the
// collector, and nothing derived from it goes to the collector. The node
// verifies the envelope against its own trust anchors, refuses any payload
// but the pinned one and any revision but the configured one, and uses the
// package only to render a run's lines when it builds a C9 snapshot.
type RegisterCopy struct {
	// Envelope is the absolute path of the signed register envelope, as
	// the collector is given it.
	Envelope string `json:"envelope"`
	// PayloadSHA256 pins the envelope's payload: lowercase hex of its
	// SHA-256. Other bytes are refused, whatever their signature.
	PayloadSHA256 string `json:"payload_sha256"`
	// TrustAnchors are the register signing keys the node accepts.
	TrustAnchors []RegisterAnchor `json:"trust_anchors"`
}

// RegisterAnchor is one register signing key, as the collector's
// trust_anchors entry.
type RegisterAnchor struct {
	KeyID     string `json:"key_id"`
	PublicKey string `json:"public_key"` // standard base64, 32 bytes
	Status    string `json:"status"`     // active or revoked
}

// AlarmRegisterRefused is raised at start when the register copy cannot be
// loaded: the file is unreadable, its payload is not the pinned one, its
// signature does not verify against the node's anchors, or its revision is
// not register_version. Every configuration read is then held, so no
// snapshot is built from a register the node was not commissioned with; the
// asset's other collections run. Level 0.
const AlarmRegisterRefused = "config-register-refused"

// checkRegister holds the configuration to a register copy whenever a
// configuration read is scheduled, and checks its fields' forms.
func (c *Config) checkRegister(fail func(format string, args ...any)) {
	reads := false
	for _, s := range c.Schedule {
		if !s.ReadsConfiguration() {
			continue
		}
		reads = true
		if _, ok := c.configRule(s.AssetID); !ok {
			fail("schedule %s reads the configuration of asset %s, whose profile has no configuration rule (ConfigRules)", s.ID, s.AssetID)
		}
	}
	r := c.Register
	switch {
	case r == nil && reads:
		fail("register is required: a scheduled configuration read builds its snapshot from the node's own copy of the register (D4-40)")
		return
	case r == nil:
		return
	}
	if !filepath.IsAbs(r.Envelope) {
		fail("register.envelope %q is not an absolute path", r.Envelope)
	}
	if !sha256Hex.MatchString(r.PayloadSHA256) {
		fail("register.payload_sha256 is not 64 lowercase hex digits")
	}
	if len(r.TrustAnchors) == 0 {
		fail("register.trust_anchors is empty")
	}
	if _, err := r.anchors(); err != nil {
		fail("register.%v", err)
	}
}

// checkRegisterVersions checks register_versions: each key is the profile
// of a scheduled asset, so a misspelt one cannot fall back to
// register_version unseen, and each value is at least 1. The node holds
// one register copy, so every asset whose configuration it reads must
// name the same revision.
func (c *Config) checkRegisterVersions(fail func(format string, args ...any)) {
	scheduled := map[string]bool{}
	for _, s := range c.Schedule {
		if a, ok := c.Asset(s.AssetID); ok && a.Profile != nil {
			scheduled[a.Profile.ID] = true
		}
	}
	for _, p := range slices.Sorted(maps.Keys(c.RegisterVersions)) {
		switch {
		case !scheduled[p]:
			fail("register_versions names profile %q, which no scheduled asset uses", p)
		case c.RegisterVersions[p] == 0:
			fail("register_versions[%q] must be at least 1", p)
		}
	}
	var first *Collection
	for i, s := range c.Schedule {
		if !s.ReadsConfiguration() {
			continue
		}
		if first == nil {
			first = &c.Schedule[i]
		} else if a, b := c.registerVersion(first.AssetID), c.registerVersion(s.AssetID); a != b {
			fail("schedule %s reads the configuration under register revision %d and %s under %d; the node holds one register copy", first.ID, a, s.ID, b)
		}
	}
}

// registerVersion is the register revision a run on the asset names: its
// profile's in register_versions, else register_version.
func (c *Config) registerVersion(assetID string) uint64 {
	if a, ok := c.Asset(assetID); ok && a.Profile != nil {
		if v, ok := c.RegisterVersions[a.Profile.ID]; ok {
			return v
		}
	}
	return c.RegisterVersion
}

// copyRevision is the revision the register copy must have: that of the
// assets whose configuration the node reads, else register_version, and
// the field that names it.
func (c *Config) copyRevision() (uint64, string) {
	for _, s := range c.Schedule {
		if !s.ReadsConfiguration() {
			continue
		}
		if a, ok := c.Asset(s.AssetID); ok && a.Profile != nil {
			if v, ok := c.RegisterVersions[a.Profile.ID]; ok {
				return v, fmt.Sprintf("register_versions[%q]", a.Profile.ID)
			}
		}
		break
	}
	return c.RegisterVersion, "register_version"
}

func (r *RegisterCopy) anchors() ([]authz.TrustAnchor, error) {
	var out []authz.TrustAnchor
	for i, a := range r.TrustAnchors {
		pub, err := base64.StdEncoding.Strict().DecodeString(a.PublicKey)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("trust_anchors[%d]: public_key is not 32 bytes of strict base64", i)
		}
		st := authz.KeyStatus(a.Status)
		if st != authz.KeyActive && st != authz.KeyRevoked {
			return nil, fmt.Errorf("trust_anchors[%d]: status %q", i, a.Status)
		}
		out = append(out, authz.TrustAnchor{KeyID: a.KeyID, PublicKey: ed25519.PublicKey(pub), Status: st})
	}
	return out, nil
}

// loadRegister reads, pins and verifies the register copy and returns its
// matcher. The pin is checked before the signature, so bytes other than the
// commissioned ones are refused without being parsed. No floor is kept: the
// node accepts exactly one revision: that of the assets whose
// configuration it reads (copyRevision).
func (c *Config) loadRegister() (*register.Matcher, error) {
	r := c.Register
	f, err := os.Open(r.Envelope)
	if err != nil {
		return nil, fmt.Errorf("register envelope: %w", err)
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 2*authz.MaxRegisterPayload+1))
	if err != nil {
		return nil, fmt.Errorf("register envelope: %w", err)
	}
	env, err := authz.DecodeRegisterEnvelope(b)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(env.Payload)
	if got := hex.EncodeToString(sum[:]); got != r.PayloadSHA256 {
		return nil, fmt.Errorf("register payload sha256 %s is not the pinned %s", got, r.PayloadSHA256)
	}
	anchors, err := r.anchors()
	if err != nil {
		return nil, err
	}
	pkg, _, err := authz.VerifyRegisterPackage(env, anchors, nil)
	if err != nil {
		return nil, err
	}
	if want, field := c.copyRevision(); pkg.Revision != want {
		return nil, fmt.Errorf("register revision %d is not %s %d", pkg.Revision, field, want)
	}
	return register.NewMatcher(pkg)
}
