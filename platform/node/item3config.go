package node

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"

	"otsec.local/otsec/contracts/advisory"
)

// The item 3 switches (docs/phase4/C5-asset-node.md section 1, D4-50). Each
// is a top-level section of the node configuration, and an absent section
// means the feature is off, as event_baselines does: no section, no work.

// AssetModule is the asset section. It turns on the asset module's side of
// the node: identity records, the SNMP schedule entries and the identity
// status lines. It has no fields yet.
type AssetModule struct{}

// Applicability is the applicability section. It turns on R9: the advisory
// set, the matcher and findings. It needs the asset section, because
// findings are computed from identity records and only the asset module
// writes them (D4-50).
type Applicability struct {
	// Anchors are the advisory signing keys this node accepts (C11 1.6).
	// They are their own trust root, never an admin, release or node key,
	// and come only with the node's configuration at enrollment or with a
	// signed release, never from central policy.
	Anchors []AdvisoryAnchor `json:"anchors"`
}

// AdvisoryAnchor is one advisory signing key, in the form of the register's
// trust_anchors entries.
type AdvisoryAnchor struct {
	KeyID     string `json:"key_id"`
	PublicKey string `json:"public_key"` // standard base64, 32 bytes
	Status    string `json:"status"`     // active or revoked
}

// AdvisorySetFile is the one name the administrator gives the signed set file
// in admin_dir (section 3 of the note). The admin-request scan reads only
// admin-request-* names, so it never reads this file.
const AdvisorySetFile = "advisory-set.json"

// AssetOn reports whether the asset module is on.
func (c *Config) AssetOn() bool { return c.AssetModule != nil }

// ApplicabilityOn reports whether R9 is on. A loaded configuration has it
// on only with the asset module on.
func (c *Config) ApplicabilityOn() bool { return c.Applicability != nil }

// checkItem3 refuses applicability without asset (D4-50), and checks the
// advisory anchors and the place the set file arrives.
func (c *Config) checkItem3(fail func(format string, args ...any)) {
	a := c.Applicability
	if a == nil {
		return
	}
	if c.AssetModule == nil {
		fail("applicability is set without asset: findings are computed from identity records, which only the asset module writes (D4-50)")
	}
	if c.AdminDir == "" {
		fail("applicability needs admin_dir: the signed advisory set arrives there as %s", AdvisorySetFile)
	}
	if len(a.Anchors) == 0 {
		fail("applicability.anchors is empty: no advisory set could ever be accepted")
	}
	if _, err := a.advisoryAnchors(); err != nil {
		fail("applicability.%v", err)
	}
}

// advisoryAnchors decodes the anchors and checks them as C11 does. A test
// key is accepted only in a test build (advisoryTestBuild).
func (a *Applicability) advisoryAnchors() ([]advisory.Anchor, error) {
	var out []advisory.Anchor
	for i, x := range a.Anchors {
		pub, err := base64.StdEncoding.Strict().DecodeString(x.PublicKey)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("anchors[%d]: public_key is not 32 bytes of strict base64", i)
		}
		out = append(out, advisory.Anchor{KeyID: x.KeyID, PublicKey: ed25519.PublicKey(pub), Status: advisory.KeyStatus(x.Status)})
	}
	if err := advisory.ValidateAnchors(out, advisoryTestBuild); err != nil {
		return nil, fmt.Errorf("anchors: %w", err)
	}
	return out, nil
}
