package authz

import (
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"regexp/syntax"
	"strconv"
	"strings"
	"time"

	"otsec.local/otsec/contracts/node"
	"otsec.local/otsec/contracts/register"
)

// Provisional identifier patterns for concepts owned by other contracts.
var (
	// TODO(C1): use asset.ValidAssetID once contracts/asset merges; this is
	// C1's rule, a lowercase UUID (C8-A4-2), the same copy C4 holds.
	assetIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	nodeIDPattern  = regexp.MustCompile(node.IDPattern) // D1-1, C7-A5-1
	// TODO(C3): use an exported ID pattern from contracts/register; this copies
	// its entry ID rule.
	operationIDPattern = regexp.MustCompile(`^[a-z0-9]+(\.[a-z0-9_]+)+$`)

	credentialRefIDPattern = regexp.MustCompile(`^cred_[a-z0-9]{8,40}$`)
	// TODO(C1): use C1's endpoint ID rule once contracts/asset merges; this
	// copies its token pattern for Endpoint.ID.
	endpointIDPattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	accessLevelPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,15}$`)
	keyIDPattern       = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
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
	EndpointID         string             `json:"endpoint_id"` // the C1 endpoint of AssetID this credential is sent over (C7-A2-6)
	Transport          Transport          `json:"transport"`
	Purpose            Purpose            `json:"purpose"`
	AccessLevel        string             `json:"access_level"` // the register's access level token the credential reaches, e.g. "1" for SEL Level 1 (C7-A2-4); never "0"
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
	if !endpointIDPattern.MatchString(c.EndpointID) {
		return fmt.Errorf("authz: endpoint id %q is not valid", c.EndpointID)
	}
	switch c.Transport {
	case TransportTelnet, TransportSSH:
	case TransportSerial:
		// A serial port keeps its session state and nothing closes it, so
		// serial credentials wait for a lab capture of the port's behaviour
		// (C7-A2, note on serial transport).
		return fmt.Errorf("authz: transport %s is not allowed in %s", c.Transport, ContractID)
	default:
		return fmt.Errorf("authz: unknown transport %q", c.Transport)
	}
	if c.Purpose != PurposeCollectReadOnly {
		return fmt.Errorf("authz: purpose %q is not allowed in %s", c.Purpose, ContractID)
	}
	if !accessLevelPattern.MatchString(c.AccessLevel) || c.AccessLevel == register.ProbeAccessLevel {
		return fmt.Errorf("authz: access level %q is not valid; a level 0 operation needs no credential", c.AccessLevel)
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
// credential. A first prompt that is already elevated (D18) is not one of
// them either: no password was sent and the state clears on its own, so C2
// refuses the session (refused.session_elevated) without suspending the
// credential (C7-A2-2). The per-asset failed-auth floor is a refusal
// (rate_limited), not a suspension.
type SuspendReason string

const (
	SuspendAuthFailed           SuspendReason = "auth-failed"             // wrong password: one attempt, disconnect, no QUI (C-19)
	SuspendPasswordPromptAbsent SuspendReason = "password-prompt-absent"  // ACC reached a prompt without asking for a password (D26, AP-23)
	SuspendUnexpectedLevel      SuspendReason = "unexpected-access-level" // ACC and the password reached a prompt other than the credential's level (C7-A2-2)
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

// FailureFloor is the shortest time between two failed authentications to
// one asset (C7-A2-1). After a wrong password a SEL relay asks for the
// password again, up to three times, and pulses SALARM on the third failure
// (S22 p. 7.33). A Telnet session closed without QUI stays at its prompt
// until the port's TIDLE expires (S22 p. 7.16), so a new session inside TIDLE
// could land on that pending prompt and its first line would be the second
// attempt. The floor is therefore longer than TIDLE: tidle plus one minute
// when SHO P 1 last read it, and 31 minutes (the largest TIDLE, 30, plus one)
// when it is unknown or out of range.
func FailureFloor(tidle time.Duration) time.Duration {
	if tidle <= 0 || tidle > 30*time.Minute {
		return 31 * time.Minute
	}
	return tidle + time.Minute
}

// InsideFailureFloor reports whether a request for an asset whose last
// failed authentication was at lastFailure must be refused with
// rate_limited. The collector reads lastFailure from its durable state,
// which it flushes before it replies to the run that failed (C7-A5-3), so
// the floor survives a restart. A failure time after now counts as inside
// the floor: a clock stepped backwards must not reopen it. Zero means no
// failure is recorded.
func InsideFailureFloor(lastFailure, now time.Time, floor time.Duration) bool {
	if lastFailure.IsZero() {
		return false
	}
	return lastFailure.After(now) || now.Sub(lastFailure) < floor
}

// Use is what the collector is about to do with a credential: the node it
// runs on, the asset and C1 endpoint it connects to, the endpoint's
// transport and acknowledgement scope, and the access level the register
// operation needs.
type Use struct {
	NodeID      string
	AssetID     string
	EndpointID  string
	Transport   Transport
	AckScope    PlaintextScope // the C1 endpoint acknowledgement's scope; empty when it has none
	AccessLevel string         // the register operation's access level token
}

// Binds checks bound use (C7-A2-4): the credential may be sent only for the
// node, asset, endpoint, transport and access level it was installed for,
// and a plaintext credential only where the endpoint's acknowledgement has
// the same scope (C1-A3-3). Anything else is credential_mismatch.
func (c *CredentialRef) Binds(u Use) error {
	switch {
	case u.NodeID != c.NodeID:
		return refuse(RefuseCredentialMismatch, "credential is for node %s", c.NodeID)
	case u.AssetID != c.AssetID || u.EndpointID != c.EndpointID:
		return refuse(RefuseCredentialMismatch, "credential is for another asset or endpoint")
	case u.Transport != c.Transport:
		return refuse(RefuseCredentialMismatch, "credential is for transport %s", c.Transport)
	case u.AccessLevel != c.AccessLevel:
		return refuse(RefuseCredentialMismatch, "operation needs level %q, credential reaches %q", u.AccessLevel, c.AccessLevel)
	case u.AckScope != c.PlaintextScope:
		return refuse(RefuseCredentialMismatch, "endpoint acknowledgement scope %q differs from the credential's %q", u.AckScope, c.PlaintextScope)
	}
	return nil
}

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
		"endpoint=" + ref.EndpointID + "\n" +
		"transport=" + string(ref.Transport) + "\n" +
		"access_level=" + ref.AccessLevel + "\n")
}

// SecretPolicy is the write-time rule for a decrypted secret, applied inside
// the collector before anything is stored. The family's register entry
// supplies MaxLen, Allowed and MnemonicLen; the rest applies to every family.
type SecretPolicy struct {
	MinLen  int
	MaxLen  int            // at most MaxSecretLen
	Allowed *regexp.Regexp // whole-secret pattern, e.g. the SEL-751 Table 7.54 set; nil means printable ASCII
	// MnemonicLen is how many leading characters of a command word the
	// device reads: 3 for SEL, which accepts QUIT as QUI and CLOSE as CLO.
	// 0 means the device reads whole words.
	MnemonicLen int
}

// ErrSecretRejected is returned for a secret that fails write-time validation.
// The error never includes the secret.
var ErrSecretRejected = errors.New("authz: secret rejected at write time")

// ValidateSecret applies the write-time rules (A3 findings 4.2): printable
// ASCII only, no CR or LF, within the length bounds and the family's allowed
// set, and nothing the device could read as a command (C7-A6-3). pkg is the
// family's verified register package. The secret is rejected when, in any
// case, the register matches it as a line (allowed or denied), or when its
// upper-case form, without leading spaces, starts with the mnemonic of any
// operation, session line or deny rule: the first MnemonicLen characters of
// the command word, or the whole word when MnemonicLen is 0. The
// prompt-gated slot is the main barrier; this check keeps a secret that the
// slot sends at the wrong moment from reading as a command.
func ValidateSecret(secret []byte, p SecretPolicy, pkg *register.Package) error {
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
	if pkg == nil {
		return fmt.Errorf("%w: no verified register package", ErrSecretRejected)
	}
	m, err := register.NewMatcher(pkg)
	if err != nil {
		return fmt.Errorf("%w: register: %v", ErrSecretRejected, err)
	}
	upper := strings.ToUpper(string(secret))
	for _, line := range []string{string(secret), upper} {
		if v, _ := m.Match(line); v != register.VerdictUnlisted {
			return fmt.Errorf("%w: secret matches a register line", ErrSecretRejected)
		}
	}
	lead := strings.TrimLeft(upper, " ")
	word := lead
	if i := strings.IndexByte(word, ' '); i >= 0 {
		word = word[:i]
	}
	for _, mn := range mnemonics(pkg) {
		if p.MnemonicLen > 0 {
			if len(mn) > p.MnemonicLen {
				mn = mn[:p.MnemonicLen]
			}
			if strings.HasPrefix(lead, mn) {
				return fmt.Errorf("%w: secret starts with a command mnemonic", ErrSecretRejected)
			}
		} else if word == mn {
			return fmt.Errorf("%w: secret is a command word", ErrSecretRejected)
		}
	}
	return nil
}

// mnemonics lists the upper-case command words of a register package: the
// first word of every operation and session line, and the leading literal of
// every deny rule. A deny rule with no leading literal (such as the rule for
// bytes outside ASCII) adds none; Match still applies it.
func mnemonics(pkg *register.Package) []string {
	var out []string
	first := func(line string) {
		if f := strings.Fields(line); len(f) > 0 {
			out = append(out, strings.ToUpper(f[0]))
		}
	}
	for _, o := range pkg.Operations {
		first(o.Line)
	}
	for _, s := range pkg.SessionControl {
		first(s.Line)
	}
	for _, d := range pkg.Denied {
		re, err := syntax.Parse(d.Pattern, syntax.Perl)
		if err != nil {
			continue // NewMatcher has already compiled every pattern
		}
		out = append(out, literalPrefixes(re)...)
	}
	return out
}

// literalPrefixes returns the literal each alternative of re starts with,
// after leading optional whitespace, or nil when one alternative does not
// start with a literal.
func literalPrefixes(re *syntax.Regexp) []string {
	switch re.Op {
	case syntax.OpLiteral:
		return []string{strings.ToUpper(string(re.Rune))}
	case syntax.OpCapture:
		return literalPrefixes(re.Sub[0])
	case syntax.OpAlternate:
		var out []string
		for _, sub := range re.Sub {
			p := literalPrefixes(sub)
			if p == nil {
				return nil
			}
			out = append(out, p...)
		}
		return out
	case syntax.OpConcat:
		for _, sub := range re.Sub {
			if sub.Op == syntax.OpStar && sub.Sub[0].Op == syntax.OpCharClass && whitespaceOnly(sub.Sub[0]) {
				continue
			}
			return literalPrefixes(sub)
		}
	}
	return nil
}

func whitespaceOnly(cc *syntax.Regexp) bool {
	for i := 0; i+1 < len(cc.Rune); i += 2 {
		for r := cc.Rune[i]; r <= cc.Rune[i+1]; r++ {
			if !strings.ContainsRune(" \t\n\v\f\r", r) {
				return false
			}
		}
	}
	return true
}

// CheckAccessLevel checks a credential's access level against the family's
// verified register package (C7-A6-1). The level must be one that an
// auth-phase session line reaches from level 0 (for SEL-751, "ACC" with
// access_level "0 -> 1"), and that a read-only operation in the operate
// phase needs. For SEL-751 0.1 only "1" passes, so a Level 2 credential
// cannot be installed. The collector applies it at install and at every run.
// It cannot tell what the password opens: a Level 2 password installed as
// level 1 is caught only if the relay rejects it at ACC (H-12).
func CheckAccessLevel(pkg *register.Package, level string) error {
	if pkg == nil {
		return refuse(RefuseRegisterUnverified, "no verified register package")
	}
	reached := false
	for _, s := range pkg.SessionControl {
		from, to, ok := strings.Cut(s.AccessLevel, "->")
		if !ok || strings.TrimSpace(from) != register.ProbeAccessLevel || strings.TrimSpace(to) != level {
			continue
		}
		for _, ph := range s.Phases {
			if ph == register.PhaseAuth {
				reached = true
			}
		}
	}
	if !reached {
		return refuse(RefuseCredentialMismatch, "no auth-phase session line reaches access level %q", level)
	}
	for i := range pkg.Operations {
		o := &pkg.Operations[i]
		if o.AccessLevel == level && o.Classification == register.ReadOnly && o.InPhase(register.PhaseOperate) {
			return nil
		}
	}
	return refuse(RefuseCredentialMismatch, "no read-only operation needs access level %q", level)
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
