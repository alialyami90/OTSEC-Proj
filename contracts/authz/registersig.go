package authz

import (
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"

	"otsec.local/otsec/contracts/internal/strictjson"
	"otsec.local/otsec/contracts/register"
)

// RegisterSigningContext is prepended to a register payload before signing,
// so a release key's signature over any other artifact can never verify as a
// register package (C3-A3-1).
const RegisterSigningContext = register.SigningDomain

// MaxRegisterPayload bounds a register payload before anything parses it.
const MaxRegisterPayload = 1 << 20

// RegisterSigningInput returns the exact bytes a release key signs for a
// register payload.
func RegisterSigningInput(payload []byte) []byte {
	in := make([]byte, 0, len(RegisterSigningContext)+len(payload))
	in = append(in, RegisterSigningContext...)
	return append(in, payload...)
}

// KeyStatus is a release key's status in the node's trust anchors.
type KeyStatus string

const (
	KeyActive  KeyStatus = "active"
	KeyRevoked KeyStatus = "revoked"
)

// TrustAnchor is one release public key. Trust anchors are installed on the
// node at enrollment or by a signed release of the node software, never by
// central policy (AP-7, C-A5-2).
type TrustAnchor struct {
	KeyID     string
	PublicKey ed25519.PublicKey
	Status    KeyStatus
}

// FamilyFloor is what the collector persists per device family: the highest
// revision it has accepted and the SHA-256 of that exact payload.
type FamilyFloor struct {
	Revision      uint64
	PayloadSHA256 [32]byte
}

// ErrRegisterRejected wraps every reason a register package is rejected. On
// this error the collector does no device I/O for that family and raises an
// alarm (SC-18).
var ErrRegisterRejected = errors.New("authz: register package rejected")

func reject(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrRegisterRejected, fmt.Sprintf(format, a...))
}

// DecodeRegisterEnvelope decodes an envelope strictly: unknown fields,
// duplicate keys and trailing data are rejected.
func DecodeRegisterEnvelope(data []byte) (*register.Envelope, error) {
	if len(data) > 2*MaxRegisterPayload {
		return nil, reject("envelope too large")
	}
	var env register.Envelope
	if err := strictjson.Decode(data, &env); err != nil {
		return nil, reject("envelope: %v", err)
	}
	return &env, nil
}

// VerifyRegisterPackage applies the C7 rules to a register envelope, in this
// order, and parses the payload only after the signature verifies:
//
//  1. The envelope is present, carries the C3 contract identifier, and names
//     algorithm "ed25519". No other algorithm is accepted.
//  2. KeyID names exactly one trust anchor, whose status is active and whose
//     key has the Ed25519 size.
//  3. The payload is non-empty and at most MaxRegisterPayload bytes.
//  4. The signature is 64 bytes and verifies over RegisterSigningInput(payload).
//  5. The payload has no duplicate keys and passes register.Decode, which is
//     strict and runs Package.Validate.
//  6. Anti-rollback, per family (C3-A3-4): a revision below the persisted
//     floor is refused, and an equal revision is accepted only if its payload
//     is byte-identical to the one accepted before.
//
// floors maps a family ID to its persisted floor; a family with no entry has
// never had a package. On success the caller persists the returned floor
// durably before it activates the package, and does not activate if that
// write fails.
func VerifyRegisterPackage(env *register.Envelope, anchors []TrustAnchor, floors map[string]FamilyFloor) (*register.Package, FamilyFloor, error) {
	if env == nil {
		return nil, FamilyFloor{}, reject("unsigned package: no envelope")
	}
	if env.Contract != register.ContractID {
		return nil, FamilyFloor{}, reject("envelope contract %q", env.Contract)
	}
	if env.Algorithm != "ed25519" {
		return nil, FamilyFloor{}, reject("algorithm %q is not ed25519", env.Algorithm)
	}
	var anchor *TrustAnchor
	for i := range anchors {
		if anchors[i].KeyID == env.KeyID {
			if anchor != nil {
				return nil, FamilyFloor{}, reject("key id %q appears twice in the trust anchors", env.KeyID)
			}
			anchor = &anchors[i]
		}
	}
	if anchor == nil {
		return nil, FamilyFloor{}, reject("unknown key id %q", env.KeyID)
	}
	if anchor.Status != KeyActive {
		return nil, FamilyFloor{}, reject("key %q is %s", env.KeyID, anchor.Status)
	}
	if len(anchor.PublicKey) != ed25519.PublicKeySize {
		return nil, FamilyFloor{}, reject("key %q has the wrong size", env.KeyID)
	}
	if len(env.Payload) == 0 || len(env.Payload) > MaxRegisterPayload {
		return nil, FamilyFloor{}, reject("payload size %d", len(env.Payload))
	}
	if len(env.Signature) != ed25519.SignatureSize {
		return nil, FamilyFloor{}, reject("unsigned package: signature is %d bytes", len(env.Signature))
	}
	if !ed25519.Verify(anchor.PublicKey, RegisterSigningInput(env.Payload), env.Signature) {
		return nil, FamilyFloor{}, reject("bad signature")
	}
	pkg, err := register.Decode(env.Payload)
	if err != nil {
		return nil, FamilyFloor{}, reject("payload: %v", err)
	}
	sum := sha256.Sum256(env.Payload)
	if prev, ok := floors[pkg.Family]; ok {
		if pkg.Revision < prev.Revision {
			return nil, FamilyFloor{}, reject("family %s revision %d is below the floor %d (rollback)", pkg.Family, pkg.Revision, prev.Revision)
		}
		if pkg.Revision == prev.Revision && sum != prev.PayloadSHA256 {
			return nil, FamilyFloor{}, reject("family %s revision %d was already accepted with different bytes", pkg.Family, pkg.Revision)
		}
	}
	return pkg, FamilyFloor{Revision: pkg.Revision, PayloadSHA256: sum}, nil
}
