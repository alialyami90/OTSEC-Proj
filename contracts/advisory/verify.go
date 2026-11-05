package advisory

import (
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"regexp"
	"slices"

	"otsec.local/otsec/contracts/authz"
	"otsec.local/otsec/contracts/internal/strictjson"
	"otsec.local/otsec/contracts/version"
)

// SigningDomain is prefixed to the payload before signing and verifying. It
// names the contract and the artifact, so a signature over a register
// package, an admin request or a release never verifies as a set, and the
// reverse (1.1). It is a fixed tag: every 0.x minor keeps it.
const SigningDomain = "otsec.advisory/0 set\n"

// SigningInput returns the exact bytes an advisory key signs for a payload.
func SigningInput(payload []byte) []byte {
	in := make([]byte, 0, len(SigningDomain)+len(payload))
	in = append(in, SigningDomain...)
	return append(in, payload...)
}

// Envelope carries a set and its detached signature (1.1).
type Envelope struct {
	Contract  string `json:"contract"`
	Algorithm string `json:"algorithm"` // "ed25519"
	KeyID     string `json:"key_id"`
	Payload   []byte `json:"payload"`   // the set's exact JSON bytes
	Signature []byte `json:"signature"` // over SigningInput(Payload)
}

// KeyStatus is an advisory anchor's status.
type KeyStatus string

const (
	KeyActive  KeyStatus = "active"
	KeyRevoked KeyStatus = "revoked"
)

// Anchor is one advisory public key. Advisory anchors are their own trust
// root, never an admin, release or node key, and arrive only at enrollment or
// by a signed release of the node software, never by central policy (1.6).
type Anchor struct {
	KeyID     string
	PublicKey ed25519.PublicKey
	Status    KeyStatus
}

// KeyID is the key ID of an advisory public key, by the admin key rule
// (authz.AdminKeyID): "ed25519-" and the first 16 hex digits of its SHA-256.
func KeyID(pub ed25519.PublicKey) string { return authz.AdminKeyID(pub) }

var keyIDRe = regexp.MustCompile(`^ed25519-[0-9a-f]{16}$`)

// ValidateAnchors checks the anchors a node pins: each key has the Ed25519
// size and the key ID its key gives, a status in the closed list, and no key
// ID appears twice. Unless allowTestKeys, which only a test build passes, an
// anchor whose key ID is in TestKeyIDs is refused, because every test key's
// private half is public (1.6).
func ValidateAnchors(anchors []Anchor, allowTestKeys bool) error {
	seen := make(map[string]bool, len(anchors))
	for i, a := range anchors {
		if len(a.PublicKey) != ed25519.PublicKeySize {
			return fmt.Errorf("advisory: anchor %d: key is not %d bytes", i, ed25519.PublicKeySize)
		}
		if a.KeyID != KeyID(a.PublicKey) {
			return fmt.Errorf("advisory: anchor %d: key ID %q is not its key's ID", i, a.KeyID)
		}
		if a.Status != KeyActive && a.Status != KeyRevoked {
			return fmt.Errorf("advisory: anchor %s: status %q", a.KeyID, a.Status)
		}
		if seen[a.KeyID] {
			return fmt.Errorf("advisory: anchor %s appears twice", a.KeyID)
		}
		seen[a.KeyID] = true
		if !allowTestKeys && slices.Contains(TestKeyIDs, a.KeyID) {
			return fmt.Errorf("advisory: anchor %s is a test key, whose private half is public", a.KeyID)
		}
	}
	return nil
}

// Code is why a set is refused (1.5). Closed list, in the order the steps
// run.
type Code string

const (
	Malformed          Code = "malformed"
	UnknownKey         Code = "unknown_key"
	RevokedKey         Code = "revoked_key"
	BadSignature       Code = "bad_signature"
	Invalid            Code = "invalid"
	WrongSet           Code = "wrong_set"
	SameVersionDiffers Code = "same_version_differs"
	OlderVersion       Code = "older_version"
	TestSet            Code = "test_set"
)

// Codes lists every Code.
var Codes = []Code{Malformed, UnknownKey, RevokedKey, BadSignature, Invalid, WrongSet, SameVersionDiffers, OlderVersion, TestSet}

// DetailNoSignature is a malformed refusal's detail when the file has no
// signature, so V-M8's unsigned case is told apart without reading the file
// again (C6).
const DetailNoSignature = "no signature"

// Refusal is one refused file. FileSHA256 is always set. KeyID is set once
// the key ID is known to be in its form, and SetID and Version once the
// payload has passed step 4, so a record built from them never carries
// unchecked bytes from the file (C8 0.11's advisory.set_refused).
type Refusal struct {
	Code       Code
	Detail     string
	FileSHA256 [32]byte
	KeyID      string
	SetID      string
	Version    uint64
}

func (r *Refusal) Error() string {
	if r.Detail == "" {
		return "advisory: set refused: " + string(r.Code)
	}
	return "advisory: set refused: " + string(r.Code) + ": " + r.Detail
}

// Verified is a file that passed steps 1 to 4.
type Verified struct {
	Set           *Set
	KeyID         string
	PayloadSHA256 [32]byte
	FileSHA256    [32]byte
}

// Verify runs steps 1 to 4 of 1.5 on a candidate file, in order, and stops at
// the first failure. The payload is parsed only after the signature
// verifies. A node also runs it on the stored set in use at every start and
// on every anchor change, so a set whose key has since been revoked or
// unpinned stops being used (D4-53).
//
// anchors should have passed ValidateAnchors; Verify still never calls
// ed25519 with a key of the wrong size.
func Verify(file []byte, anchors []Anchor) (*Verified, *Refusal) {
	fileSum := sha256.Sum256(file)
	refuse := func(c Code, keyID, detail string) (*Verified, *Refusal) {
		return nil, &Refusal{Code: c, Detail: detail, FileSHA256: fileSum, KeyID: keyID}
	}

	// 1. Size and envelope.
	if len(file) > MaxEnvelopeBytes {
		return refuse(Malformed, "", fmt.Sprintf("file is over %d bytes", MaxEnvelopeBytes))
	}
	var env Envelope
	if err := strictjson.Decode(file, &env); err != nil {
		return refuse(Malformed, "", "envelope does not decode strictly")
	}
	id, err := version.Parse(env.Contract)
	if err != nil || id.Name != "advisory" || id.Major != 0 {
		return refuse(Malformed, "", "envelope does not name otsec.advisory/0.x")
	}
	if env.Algorithm != "ed25519" {
		return refuse(Malformed, "", "algorithm is not ed25519")
	}
	if !keyIDRe.MatchString(env.KeyID) {
		return refuse(Malformed, "", "key_id is not in its form")
	}
	if len(env.Payload) == 0 {
		return refuse(Malformed, env.KeyID, "no payload")
	}
	if len(env.Signature) == 0 {
		return refuse(Malformed, env.KeyID, DetailNoSignature)
	}
	if len(env.Signature) != ed25519.SignatureSize {
		return refuse(Malformed, env.KeyID, "signature is not 64 bytes")
	}

	// 2. Key.
	var anchor *Anchor
	for i := range anchors {
		if anchors[i].KeyID == env.KeyID {
			anchor = &anchors[i]
			break
		}
	}
	if anchor == nil || len(anchor.PublicKey) != ed25519.PublicKeySize {
		return refuse(UnknownKey, env.KeyID, "")
	}
	if anchor.Status == KeyRevoked {
		return refuse(RevokedKey, env.KeyID, "")
	}
	if anchor.Status != KeyActive {
		return refuse(UnknownKey, env.KeyID, "")
	}

	// 3. Signature.
	if !ed25519.Verify(anchor.PublicKey, SigningInput(env.Payload), env.Signature) {
		return refuse(BadSignature, env.KeyID, "")
	}

	// 4. Payload.
	set, err := Decode(env.Payload)
	if err != nil {
		return refuse(Invalid, env.KeyID, detailOf(err))
	}
	if set.Contract != env.Contract {
		return refuse(Invalid, env.KeyID, "payload contract differs from the envelope's")
	}
	return &Verified{Set: set, KeyID: env.KeyID, PayloadSHA256: sha256.Sum256(env.Payload), FileSHA256: fileSum}, nil
}

func detailOf(err error) string {
	s := err.Error()
	p := ErrInvalid.Error() + ": "
	if len(s) > len(p) && s[:len(p)] == p {
		return s[len(p):]
	}
	return s
}

// Floor is the set in use: its set ID, version and payload SHA-256. The zero
// value means the node holds no set. The node derives it at start from the
// store and the audit chain, and stores it nowhere else (C5).
type Floor struct {
	SetID         string
	Version       uint64
	PayloadSHA256 [32]byte
}

// Held reports whether the floor names a set.
func (f Floor) Held() bool { return f.SetID != "" }

// Outcome is what Admit decided for a set that is not refused.
type Outcome int

const (
	// Install: the set replaces the one in use. The node stores it, then
	// writes advisory.set_installed, and moves the floor to Next.
	Install Outcome = iota + 1
	// InUse: the same version and bytes as the set in use. Nothing is
	// recorded and the file is ignored.
	InUse
)

// Admit runs steps 5 to 7 of 1.5 on a verified set against the node's floor.
// acceptTestSets is true only in a build with the otsec_testclock tag; no
// configuration sets it.
func Admit(v *Verified, floor Floor, acceptTestSets bool) (Outcome, Floor, *Refusal) {
	s := v.Set
	refuse := func(c Code) (Outcome, Floor, *Refusal) {
		return 0, Floor{}, &Refusal{Code: c, FileSHA256: v.FileSHA256, KeyID: v.KeyID, SetID: s.SetID, Version: s.Version}
	}
	// 5. Set.
	if floor.Held() && s.SetID != floor.SetID {
		return refuse(WrongSet)
	}
	// 6. Order.
	if floor.Held() {
		switch {
		case s.Version < floor.Version:
			return refuse(OlderVersion)
		case s.Version == floor.Version && v.PayloadSHA256 != floor.PayloadSHA256:
			return refuse(SameVersionDiffers)
		case s.Version == floor.Version:
			return InUse, floor, nil
		}
	}
	// 7. Purpose.
	if s.Purpose == PurposeTest && !acceptTestSets {
		return refuse(TestSet)
	}
	return Install, Floor{SetID: s.SetID, Version: s.Version, PayloadSHA256: v.PayloadSHA256}, nil
}
