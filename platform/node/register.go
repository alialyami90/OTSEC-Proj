package node

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"otsec.local/otsec/contracts/authz"
	"otsec.local/otsec/contracts/register"
)

// RegisterCopy is the node's own copy of the signed command register (D4-40
// item 7, #383). It comes from the node's configuration only, never from the
// collector, and nothing derived from it goes to the collector. The node
// verifies the envelope against its own trust anchors, refuses any payload
// but the pinned one and any revision but register_version, and uses the
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
		reads = reads || s.ReadsConfiguration()
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
// node accepts exactly one revision, register_version.
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
	if pkg.Revision != c.RegisterVersion {
		return nil, fmt.Errorf("register revision %d is not register_version %d", pkg.Revision, c.RegisterVersion)
	}
	return register.NewMatcher(pkg)
}
