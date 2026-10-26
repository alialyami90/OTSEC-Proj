package authz

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	"otsec.local/otsec/contracts/internal/strictjson"
)

// Admin-signed requests (0.4, D2-11). From 0.4 the collector accepts a
// credential request, and an asset clear the node relays, only when an
// administrator signed it with a key pinned in the collector's own
// configuration. The node can relay such a request but can neither
// originate nor change one, which closes the install path as an equality
// oracle for a compromised node (D2-11). See the package documentation,
// "Admin-signed requests".
const (
	// AdminRequestFormat is the signed payload's format.
	AdminRequestFormat = "otsec.authz.admin-request/0.4"
	// adminSigningContract is the contract the signing prefix names. It is
	// fixed by the payload format, not taken from ContractID, so a later
	// minor that keeps this format keeps verifying its signatures.
	adminSigningContract = "otsec.authz/0.4"
	// adminSignedSince is the minor that added AdminSigned.
	adminSignedSince = 4
	// MaxAdminPayload bounds the signed payload before anything parses it.
	MaxAdminPayload = 4 << 10
	// MaxAdminLifetime is the longest a signed request is valid: from
	// issued_at, and from the collector's clock.
	MaxAdminLifetime = 15 * time.Minute
	// MaxAdminClockSkew is how far issued_at may lie ahead of the
	// collector's clock.
	MaxAdminClockSkew = 2 * time.Minute
	// AdminNonceLen is the nonce's length in bytes before encoding.
	AdminNonceLen = 16
)

var (
	adminKeyIDPattern = regexp.MustCompile(`^ed25519-[0-9a-f]{16}$`)
	adminNoncePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{22}$`)
)

// adminKinds are the request kinds an administrator signs.
var adminKinds = map[RequestKind]bool{
	KindCredentialInstall: true, KindCredentialRevoke: true, KindCredentialClearSusp: true, KindAssetClearSusp: true,
}

// AdminSigned is the envelope of an admin-signed request (0.4). The
// signature is Ed25519 over AdminSigningInput(kind, payload), so the
// signed bytes travel as they are and no canonical JSON is needed.
type AdminSigned struct {
	KeyID     string `json:"key_id"`
	Algorithm string `json:"algorithm"` // "ed25519"
	Payload   []byte `json:"payload"`   // the AdminRequest's exact JSON bytes
	Signature []byte `json:"signature"`
}

// AdminRequest is the signed payload. It is decoded strictly, and only
// after the signature verifies. Exactly one body is set, the one that
// matches Kind; it is the body a 0.3 request carried in the clear, and it
// exists only here, so there is no outer copy to disagree with.
type AdminRequest struct {
	Format    string      `json:"format"`
	Kind      RequestKind `json:"kind"`
	Principal Principal   `json:"principal"`
	// AdminKeyID repeats the envelope's key ID inside the signed bytes, so
	// the signed record alone names the key (rotation and revocation).
	AdminKeyID string `json:"admin_key_id"`
	// NodeID and InstallKeyID bind the request to one collector: another
	// node's, or this one's after its install key changes, refuses it.
	NodeID       string `json:"node_id"`
	InstallKeyID string `json:"install_key_id"`
	// Nonce is AdminNonceLen random bytes, base64url without padding. The
	// collector spends it durably before any decision.
	Nonce     string `json:"nonce"`
	IssuedAt  string `json:"issued_at"`  // RFC 3339, UTC
	ExpiresAt string `json:"expires_at"` // RFC 3339, UTC

	CredentialInstall   *CredentialInstallBody   `json:"credential_install,omitempty"`
	CredentialRevoke    *CredentialRevokeBody    `json:"credential_revoke,omitempty"`
	CredentialClearSusp *CredentialClearSuspBody `json:"credential_clear_suspension,omitempty"`
	AssetClearSusp      *AssetClearSuspBody      `json:"asset_clear_suspension,omitempty"`
}

// Expires is the request's parsed expiry; it is valid on a request
// VerifyAdminRequest returned.
func (p *AdminRequest) Expires() time.Time {
	t, _ := time.Parse(time.RFC3339, p.ExpiresAt)
	return t
}

// AdminKey is one administrator's public key, pinned in the collector's
// configuration out of band. A key speaks for exactly one person.
type AdminKey struct {
	KeyID     string
	PublicKey ed25519.PublicKey
	// Principal is the human principal ID the key speaks for.
	Principal string
	Status    KeyStatus
}

// AdminKeyID is the key ID of an Ed25519 public key: "ed25519-" and the
// first 16 hex digits of SHA-256 over the key. The collector checks a
// pinned key's ID against it.
func AdminKeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return "ed25519-" + hex.EncodeToString(sum[:8])
}

// AdminBinding is what the collector binds a signed request to.
type AdminBinding struct {
	NodeID       string
	InstallKeyID string
}

// AdminCheck names the check a signed request failed. The reply carries it
// only in a fixed detail; the collector's audit record carries it, so an
// operator can tell a replay from a bad signature afterwards (A1).
type AdminCheck string

const (
	AdminCheckEnvelope  AdminCheck = "envelope"  // unsigned, another algorithm, or a size out of bounds
	AdminCheckKey       AdminCheck = "key"       // unknown, revoked, malformed, or not derived from its key
	AdminCheckSignature AdminCheck = "signature" // does not verify over this kind's prefix
	AdminCheckPayload   AdminCheck = "payload"   // not strict JSON, another format, or a body that fails its rules
	AdminCheckBinding   AdminCheck = "binding"   // kind, principal, key ID, node or install key differ
	AdminCheckWindow    AdminCheck = "window"    // not yet valid, expired, or longer than MaxAdminLifetime
	AdminCheckReplay    AdminCheck = "replay"    // the nonce was spent already (the collector's check)
	AdminCheckCapacity  AdminCheck = "capacity"  // the collector holds too many unexpired nonces
)

// AdminChecks lists every check, in the order they run.
var AdminChecks = []AdminCheck{AdminCheckEnvelope, AdminCheckKey, AdminCheckSignature, AdminCheckPayload,
	AdminCheckBinding, AdminCheckWindow, AdminCheckReplay, AdminCheckCapacity}

// AdminRejected is why VerifyAdminRequest refused. Reason is for tests and
// the collector's own diagnostics; it never holds the payload, but it may
// name a key ID, so it does not go into a reply.
type AdminRejected struct {
	Check  AdminCheck
	Reason string
}

func (e *AdminRejected) Error() string {
	return "authz: admin request not verified: " + string(e.Check) + ": " + e.Reason
}

// Refusal is the reply to a request that failed check: always
// admin_unverified, with a detail that names the check and nothing else.
// Every failure gets the same code, so no reply can tell a wrong guess from
// a right one (D2-11).
func (e *AdminRejected) Refusal() *Refusal { return AdminRefusal(e.Check) }

// AdminRefusal is the refusal for a failed check.
func AdminRefusal(check AdminCheck) *Refusal {
	return &Refusal{Code: RefuseAdminUnverified, Detail: "admin signature not verified: " + string(check)}
}

func adminReject(check AdminCheck, format string, a ...any) *AdminRejected {
	return &AdminRejected{Check: check, Reason: fmt.Sprintf(format, a...)}
}

// AdminSigningInput returns the exact bytes an administrator signs for a
// request of kind. The prefix names the contract and the operation, so a
// signature for one kind never verifies for another, and never as a
// register package.
func AdminSigningInput(kind RequestKind, payload []byte) []byte {
	prefix := adminSigningContract + " admin-request " + string(kind) + "\n"
	in := make([]byte, 0, len(prefix)+len(payload))
	in = append(in, prefix...)
	return append(in, payload...)
}

// SignAdminRequest signs p for the request kind p.Kind with priv, whose
// key ID p.AdminKeyID must name. It is the administrator's side; tests and
// the admin client use it so both sides share one definition.
func SignAdminRequest(priv ed25519.PrivateKey, p AdminRequest) (*AdminSigned, error) {
	keyID := AdminKeyID(priv.Public().(ed25519.PublicKey))
	if p.AdminKeyID != keyID {
		return nil, fmt.Errorf("authz: admin_key_id %q is not the signing key's %q", p.AdminKeyID, keyID)
	}
	payload, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	if len(payload) > MaxAdminPayload {
		return nil, fmt.Errorf("authz: admin payload is %d bytes, over %d", len(payload), MaxAdminPayload)
	}
	return &AdminSigned{KeyID: keyID, Algorithm: "ed25519", Payload: payload,
		Signature: ed25519.Sign(priv, AdminSigningInput(p.Kind, payload))}, nil
}

// VerifyAdminRequest applies the 0.4 rules to a request of an admin kind,
// in this order, and decodes the payload only after the signature
// verifies:
//
//  1. envelope: AdminSigned is present, names "ed25519", and its payload
//     (at most MaxAdminPayload bytes) and signature have their sizes;
//  2. key: KeyID names exactly one pinned key, which is active, has the
//     Ed25519 size, and whose ID is derived from it (AdminKeyID);
//  3. signature: it verifies over AdminSigningInput(req.Kind, payload);
//  4. payload: strict JSON, AdminRequestFormat, a nonce and two UTC times
//     of the right shape, and exactly one body, matching req.Kind and
//     passing the rules the clear body had;
//  5. binding: the payload's kind, the principal (a person, equal to
//     on_behalf_of and to the key's principal), admin_key_id, node_id and
//     install_key_id match;
//  6. window: issued_at is at most MaxAdminClockSkew ahead of now,
//     expires_at is after issued_at and after now, and at most
//     MaxAdminLifetime after either.
//
// Every failure is an *AdminRejected. Spending the nonce durably is the
// collector's step, after this and before any other decision.
func VerifyAdminRequest(req *CollectorRequest, keys []AdminKey, bind AdminBinding, now time.Time) (*AdminRequest, error) {
	env := req.AdminSigned
	switch {
	case env == nil:
		return nil, adminReject(AdminCheckEnvelope, "unsigned")
	case env.Algorithm != "ed25519":
		return nil, adminReject(AdminCheckEnvelope, "algorithm %q is not ed25519", env.Algorithm)
	case len(env.Payload) == 0 || len(env.Payload) > MaxAdminPayload:
		return nil, adminReject(AdminCheckEnvelope, "payload size %d", len(env.Payload))
	case len(env.Signature) != ed25519.SignatureSize:
		return nil, adminReject(AdminCheckEnvelope, "signature is %d bytes", len(env.Signature))
	}
	var key *AdminKey
	for i := range keys {
		if keys[i].KeyID == env.KeyID {
			if key != nil {
				return nil, adminReject(AdminCheckKey, "key id %q is pinned twice", env.KeyID)
			}
			key = &keys[i]
		}
	}
	switch {
	case key == nil:
		return nil, adminReject(AdminCheckKey, "unknown key id %q", env.KeyID)
	case key.Status != KeyActive:
		return nil, adminReject(AdminCheckKey, "key %q is %s", env.KeyID, key.Status)
	case len(key.PublicKey) != ed25519.PublicKeySize:
		return nil, adminReject(AdminCheckKey, "key %q has the wrong size", env.KeyID)
	case AdminKeyID(key.PublicKey) != key.KeyID:
		return nil, adminReject(AdminCheckKey, "key id %q is not derived from its key", env.KeyID)
	}
	if !ed25519.Verify(key.PublicKey, AdminSigningInput(req.Kind, env.Payload), env.Signature) {
		return nil, adminReject(AdminCheckSignature, "bad signature")
	}
	var p AdminRequest
	if err := strictjson.Decode(env.Payload, &p); err != nil {
		return nil, adminReject(AdminCheckPayload, "%v", err)
	}
	if err := p.validate(); err != nil {
		return nil, adminReject(AdminCheckPayload, "%v", err)
	}
	switch {
	case p.Kind != req.Kind:
		return nil, adminReject(AdminCheckBinding, "signed kind %q, request kind %q", p.Kind, req.Kind)
	case p.Principal != req.OnBehalfOf:
		return nil, adminReject(AdminCheckBinding, "signed principal is not on_behalf_of")
	case p.Principal.Type != PrincipalHuman || p.Principal.ID != key.Principal:
		return nil, adminReject(AdminCheckBinding, "key %q does not speak for the signed principal", key.KeyID)
	case p.AdminKeyID != env.KeyID:
		return nil, adminReject(AdminCheckBinding, "signed admin_key_id is not the envelope's")
	case p.NodeID != bind.NodeID:
		return nil, adminReject(AdminCheckBinding, "signed for node %s", p.NodeID)
	case p.InstallKeyID != bind.InstallKeyID:
		return nil, adminReject(AdminCheckBinding, "signed for install key %s", p.InstallKeyID)
	}
	issued, _ := time.Parse(time.RFC3339, p.IssuedAt) // checked by validate
	expires := p.Expires()
	switch {
	case issued.After(now.Add(MaxAdminClockSkew)):
		return nil, adminReject(AdminCheckWindow, "issued in the future")
	case !expires.After(issued):
		return nil, adminReject(AdminCheckWindow, "expires before it is issued")
	case !expires.After(now):
		return nil, adminReject(AdminCheckWindow, "expired")
	case expires.Sub(issued) > MaxAdminLifetime:
		return nil, adminReject(AdminCheckWindow, "valid for longer than %s", MaxAdminLifetime)
	case expires.Sub(now) > MaxAdminLifetime:
		return nil, adminReject(AdminCheckWindow, "expires more than %s ahead of the collector's clock", MaxAdminLifetime)
	}
	return &p, nil
}

// validate checks the payload's own syntax: the format, the nonce, the
// times, the identifiers, and exactly one body that matches Kind and
// passes the rules it has in the clear.
func (p *AdminRequest) validate() error {
	if p.Format != AdminRequestFormat {
		return fmt.Errorf("format %q", p.Format)
	}
	if !adminKinds[p.Kind] {
		return fmt.Errorf("kind %q is not signed by an administrator", p.Kind)
	}
	if err := p.Principal.Validate(); err != nil {
		return err
	}
	if !adminKeyIDPattern.MatchString(p.AdminKeyID) {
		return errors.New("admin_key_id")
	}
	if !nodeIDPattern.MatchString(p.NodeID) {
		return errors.New("node_id")
	}
	if !keyIDPattern.MatchString(p.InstallKeyID) {
		return errors.New("install_key_id")
	}
	if n, err := base64.RawURLEncoding.DecodeString(p.Nonce); err != nil || len(n) != AdminNonceLen || !adminNoncePattern.MatchString(p.Nonce) {
		return errors.New("nonce is not 16 bytes of base64url without padding")
	}
	for _, ts := range []string{p.IssuedAt, p.ExpiresAt} {
		t, err := time.Parse(time.RFC3339, ts)
		if err != nil || t.Location() != time.UTC || t.Format(time.RFC3339Nano) != ts {
			return fmt.Errorf("time %q is not RFC 3339 UTC", ts)
		}
	}
	set := 0
	for _, present := range []bool{p.CredentialInstall != nil, p.CredentialRevoke != nil, p.CredentialClearSusp != nil, p.AssetClearSusp != nil} {
		if present {
			set++
		}
	}
	if set != 1 {
		return fmt.Errorf("exactly one body must be set, got %d", set)
	}
	return validateBody(p.Kind, p.Principal, requestBodies{
		CredentialInstall: p.CredentialInstall, CredentialRevoke: p.CredentialRevoke,
		CredentialClearSusp: p.CredentialClearSusp, AssetClearSusp: p.AssetClearSusp})
}
