package authz

import (
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"time"
)

// Provisional identifier patterns for concepts owned by other contracts.
var (
	// TODO(C1): import the asset ID type and pattern from contracts/asset.
	assetIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	// TODO(C4): import the node ID type and pattern from contracts/event.
	nodeIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	// TODO(C3): use an exported ID pattern from contracts/register; this copies
	// its entry ID rule.
	operationIDPattern = regexp.MustCompile(`^[a-z0-9]+(\.[a-z0-9_]+)+$`)

	credentialRefIDPattern = regexp.MustCompile(`^cred_[a-z0-9]{8,40}$`)
	accessLevelPattern     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,15}$`)
	keyIDPattern           = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
)

// Transport is the downstream transport a credential is used on.
type Transport string

const (
	TransportTelnet Transport = "telnet"
	TransportSerial Transport = "serial"
	TransportSSH    Transport = "ssh"
)

// Plaintext reports whether the transport carries the credential in clear.
func (t Transport) Plaintext() bool { return t == TransportTelnet || t == TransportSerial }

// Purpose says what a credential may be used for. 0.1 allows one value.
type Purpose string

// PurposeCollectReadOnly is the only purpose in 0.1: read-only collection by
// the collector. Engineering credentials do not exist until Phase 4.
const PurposeCollectReadOnly Purpose = "collect-readonly"

// DownstreamSecurity labels the device-side connection (A3 findings 4.5).
// TODO(C1): import from contracts/asset, which owns the asset label.
type DownstreamSecurity string

const (
	DownstreamEncryptedAuthenticated DownstreamSecurity = "encrypted-authenticated"
	DownstreamEncryptedWeak          DownstreamSecurity = "encrypted-weak"
	DownstreamPlaintext              DownstreamSecurity = "plaintext-unauthenticated"
)

// PlaintextScope records where a plaintext credential may be used. 0.1 has
// one value: the owner accepted Telnet for the simulated and lab slice only
// (ADR-0005). Production plaintext use needs a new value, which needs an owner
// decision and a contract change.
type PlaintextScope string

// PlaintextLabOnly allows a plaintext credential only on simulator and lab
// assets.
const PlaintextLabOnly PlaintextScope = "lab-only"

// CredentialRef is the opaque handle to one device credential. It names the
// one asset and the one node it is for, and it never contains the secret. Only
// the collector on NodeID can resolve it, and only inside the transport, at
// connect time, through the prompt-gated credential slot (A3 findings 8.3).
type CredentialRef struct {
	ID                 string             `json:"id"`
	AssetID            string             `json:"asset_id"`
	NodeID             string             `json:"node_id"`
	Transport          Transport          `json:"transport"`
	Purpose            Purpose            `json:"purpose"`
	AccessLevel        string             `json:"access_level"` // device-native level name, e.g. "ACC"; must not exceed the family ceiling in the register
	DownstreamSecurity DownstreamSecurity `json:"downstream_security"`
	PlaintextScope     PlaintextScope     `json:"plaintext_scope,omitempty"` // required when the transport is plaintext
	Version            uint32             `json:"version"`                   // 1 on install, +1 on every replacement
	CreatedBy          Principal          `json:"created_by"`
	CreatedAt          string             `json:"created_at"` // RFC 3339 UTC with Z
}

// Validate checks the reference on its own. The collector additionally checks
// AccessLevel against the register's ceiling for the asset's family, and that
// AssetID is enrolled on this node.
func (c CredentialRef) Validate() error {
	if !credentialRefIDPattern.MatchString(c.ID) {
		return fmt.Errorf("authz: credential ref id %q is not valid", c.ID)
	}
	if !assetIDPattern.MatchString(c.AssetID) {
		return fmt.Errorf("authz: asset id %q is not valid", c.AssetID)
	}
	if !nodeIDPattern.MatchString(c.NodeID) {
		return fmt.Errorf("authz: node id %q is not valid", c.NodeID)
	}
	switch c.Transport {
	case TransportTelnet, TransportSerial, TransportSSH:
	default:
		return fmt.Errorf("authz: unknown transport %q", c.Transport)
	}
	if c.Purpose != PurposeCollectReadOnly {
		return fmt.Errorf("authz: purpose %q is not allowed in %s", c.Purpose, ContractID)
	}
	if !accessLevelPattern.MatchString(c.AccessLevel) {
		return fmt.Errorf("authz: access level %q is not valid", c.AccessLevel)
	}
	switch c.DownstreamSecurity {
	case DownstreamEncryptedAuthenticated, DownstreamEncryptedWeak, DownstreamPlaintext:
	default:
		return fmt.Errorf("authz: unknown downstream security %q", c.DownstreamSecurity)
	}
	if c.Transport.Plaintext() {
		if c.DownstreamSecurity != DownstreamPlaintext {
			return fmt.Errorf("authz: transport %s must be labelled %s", c.Transport, DownstreamPlaintext)
		}
		if c.PlaintextScope != PlaintextLabOnly {
			return fmt.Errorf("authz: plaintext transport %s needs plaintext_scope %q", c.Transport, PlaintextLabOnly)
		}
	} else if c.PlaintextScope != "" {
		return errors.New("authz: plaintext_scope is only for plaintext transports")
	}
	if c.Version == 0 {
		return errors.New("authz: credential version starts at 1")
	}
	if err := c.CreatedBy.Validate(); err != nil {
		return err
	}
	if c.CreatedBy.Type != PrincipalHuman {
		return errors.New("authz: credentials are installed by a person")
	}
	if err := validUTC(c.CreatedAt); err != nil {
		return err
	}
	return nil
}

// CredentialState is the collector's state for one credential version.
type CredentialState string

const (
	CredentialActive    CredentialState = "active"
	CredentialSuspended CredentialState = "suspended" // never used until an admin clears it (D2)
	CredentialRevoked   CredentialState = "revoked"   // terminal; the secret is destroyed
)

// SuspendReason says why a credential is suspended. The names are C1's asset
// suspension reasons, limited to the ones where the password was sent or may
// have been: language-not-english and firmware-not-allowlisted are found in
// the probe phase, before ACC, so they suspend the asset (C1) but not the
// credential. The per-asset failed-auth floor is a refusal (rate_limited),
// not a suspension.
type SuspendReason string

const (
	SuspendAuthFailed           SuspendReason = "auth-failed"             // wrong password: one attempt, disconnect, no QUI (C-19)
	SuspendPasswordPromptAbsent SuspendReason = "password-prompt-absent"  // ACC reached a prompt without asking for a password (D26, AP-23)
	SuspendUnexpectedLevel      SuspendReason = "unexpected-access-level" // first prompt already elevated (D18)
	SuspendIdentityMismatch     SuspendReason = "identity-mismatch"       // serial number differed after login: the password went to another device (C1-A3-5)
	SuspendOperator             SuspendReason = "operator"                // an admin suspended it
)

// ClearableInPlace reports whether an admin may clear a suspension with this
// reason on the same credential version. An identity-mismatch suspension
// means the secret was sent to a device that is not the bound one, so it is
// treated as exposed: the collector refuses to clear it unless the asset was
// re-commissioned after the suspension. Otherwise the admin replaces the
// credential, which is a new version (C1-A3-5).
func (r SuspendReason) ClearableInPlace() bool { return r != SuspendIdentityMismatch }

// RevokeReason says why a credential was revoked.
type RevokeReason string

const (
	RevokeRotated        RevokeReason = "rotated"
	RevokeCompromised    RevokeReason = "compromised"
	RevokeDecommissioned RevokeReason = "asset-decommissioned"
	RevokeOperator       RevokeReason = "operator"
)

// SealedSecret is a device secret encrypted to the collector's install key on
// one node. The main process relays it and cannot open it. The algorithm is
// fixed in 0.1: an X25519 key agreement with an ephemeral sender key, HKDF-SHA256,
// and AES-256-GCM, with SealAAD(ref) as additional data, so a sealed secret
// cannot be replayed onto another reference, version, asset or node.
type SealedSecret struct {
	Alg                string `json:"alg"`
	RecipientKeyID     string `json:"recipient_key_id"`
	EphemeralPublicKey string `json:"ephemeral_public_key"` // base64, 32 bytes
	Nonce              string `json:"nonce"`                // base64, 12 bytes
	Ciphertext         string `json:"ciphertext"`           // base64, secret plus 16-byte tag
}

// SealAlg is the only sealing algorithm in 0.1.
const SealAlg = "x25519-hkdf-sha256-aes256gcm"

// MaxSecretLen bounds a sealed secret's plaintext length for every family.
// A family's register entry may set a lower bound (12 on the SEL-751, Table 7.54).
const MaxSecretLen = 64

// Validate checks the envelope's shape. It cannot check the plaintext.
func (s SealedSecret) Validate() error {
	if s.Alg != SealAlg {
		return fmt.Errorf("authz: sealing algorithm %q is not %q", s.Alg, SealAlg)
	}
	if !keyIDPattern.MatchString(s.RecipientKeyID) {
		return fmt.Errorf("authz: recipient key id %q is not valid", s.RecipientKeyID)
	}
	for _, f := range []struct {
		name     string
		value    string
		min, max int
	}{
		{"ephemeral_public_key", s.EphemeralPublicKey, 32, 32},
		{"nonce", s.Nonce, 12, 12},
		{"ciphertext", s.Ciphertext, 1 + 16, MaxSecretLen + 16},
	} {
		b, err := base64.StdEncoding.Strict().DecodeString(f.value)
		if err != nil {
			return fmt.Errorf("authz: %s is not strict base64", f.name)
		}
		if len(b) < f.min || len(b) > f.max {
			return fmt.Errorf("authz: %s has %d bytes, want %d to %d", f.name, len(b), f.min, f.max)
		}
	}
	return nil
}

// SealAAD returns the additional authenticated data that binds a sealed
// secret to exactly one credential reference version.
func SealAAD(ref CredentialRef) []byte {
	return []byte("otsec.authz/0.1 sealed-secret\n" +
		"ref=" + ref.ID + "\n" +
		"version=" + strconv.FormatUint(uint64(ref.Version), 10) + "\n" +
		"asset=" + ref.AssetID + "\n" +
		"node=" + ref.NodeID + "\n" +
		"transport=" + string(ref.Transport) + "\n" +
		"access_level=" + ref.AccessLevel + "\n")
}

// SecretPolicy is the write-time rule for a decrypted secret, applied inside
// the collector before anything is stored. The family's register entry
// supplies MaxLen and Allowed; the rest applies to every family.
type SecretPolicy struct {
	MinLen  int
	MaxLen  int            // at most MaxSecretLen
	Allowed *regexp.Regexp // whole-secret pattern, e.g. the SEL-751 Table 7.54 set; nil means printable ASCII
}

// ErrSecretRejected is returned for a secret that fails write-time validation.
// The error never includes the secret.
var ErrSecretRejected = errors.New("authz: secret rejected at write time")

// ValidateSecret applies the write-time rules (A3 findings 4.2): printable
// ASCII only, no CR or LF, within the length bounds and the family's allowed
// set, and not equal to anything the register would accept or deny as a line,
// so the credential slot can never carry a command. isRegisterLine reports
// whether a line matches any register entry, allowed or denied.
func ValidateSecret(secret []byte, p SecretPolicy, isRegisterLine func(line string) bool) error {
	max := p.MaxLen
	if max <= 0 || max > MaxSecretLen {
		max = MaxSecretLen
	}
	min := p.MinLen
	if min < 1 {
		min = 1
	}
	if len(secret) < min || len(secret) > max {
		return fmt.Errorf("%w: length out of bounds", ErrSecretRejected)
	}
	for _, b := range secret {
		if b < 0x20 || b > 0x7e {
			return fmt.Errorf("%w: byte outside printable ASCII", ErrSecretRejected)
		}
	}
	if p.Allowed != nil && !p.Allowed.Match(secret) {
		return fmt.Errorf("%w: character outside the family's allowed set", ErrSecretRejected)
	}
	if isRegisterLine == nil {
		return fmt.Errorf("%w: no register check supplied", ErrSecretRejected)
	}
	if isRegisterLine(string(secret)) {
		return fmt.Errorf("%w: secret matches a register line", ErrSecretRejected)
	}
	return nil
}

func validUTC(s string) error {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil || t.Location() != time.UTC || s[len(s)-1] != 'Z' {
		return fmt.Errorf("authz: time %q is not RFC 3339 UTC with Z", s)
	}
	return nil
}

// CredentialStatus is what the collector reports about one credential, for the
// asset view and audit. It carries no secret and nothing derived from one.
type CredentialStatus struct {
	RefID   string          `json:"ref_id"`
	Version uint32          `json:"version"`
	State   CredentialState `json:"state"`
	Reason  string          `json:"reason,omitempty"` // a SuspendReason or RevokeReason; empty when active
	Since   string          `json:"since"`            // RFC 3339 UTC with Z
}

// Validate checks the status, including that a reason accompanies every
// state other than active.
func (s CredentialStatus) Validate() error {
	if !credentialRefIDPattern.MatchString(s.RefID) || s.Version == 0 {
		return errors.New("authz: credential status needs a valid ref_id and version")
	}
	switch s.State {
	case CredentialActive:
		if s.Reason != "" {
			return errors.New("authz: an active credential has no reason")
		}
	case CredentialSuspended:
		switch SuspendReason(s.Reason) {
		case SuspendAuthFailed, SuspendPasswordPromptAbsent, SuspendUnexpectedLevel, SuspendIdentityMismatch, SuspendOperator:
		default:
			return fmt.Errorf("authz: unknown suspend reason %q", s.Reason)
		}
	case CredentialRevoked:
		switch RevokeReason(s.Reason) {
		case RevokeRotated, RevokeCompromised, RevokeDecommissioned, RevokeOperator:
		default:
			return fmt.Errorf("authz: unknown revoke reason %q", s.Reason)
		}
	default:
		return fmt.Errorf("authz: unknown credential state %q", s.State)
	}
	return validUTC(s.Since)
}
