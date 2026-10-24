package asset

import (
	"fmt"
	"regexp"

	"otsec.local/otsec/contracts/version"
)

// ProfileKind distinguishes a capability profile from an asset record; both
// carry the schema identifier otsec.asset/0.1.
const ProfileKind = "capability-profile"

// CapabilityProfile says what the platform can do with one product family,
// by which mechanism, and how well each claim is supported (CLAUDE.md
// section 3, P7). An asset names its profile with ProfileRef. Profiles ship
// in the signed register package with the operations they reference
// (C-A2-2), so a profile cannot widen what the collector may send.
type CapabilityProfile struct {
	Schema        string   `json:"schema"`
	Kind          string   `json:"kind"`
	ProfileID     string   `json:"profile_id"`
	Version       string   `json:"version"`
	Vendor        string   `json:"vendor"`
	ProductFamily string   `json:"product_family"`
	DeviceClass   string   `json:"device_class"`
	Firmware      Firmware `json:"firmware"`
	// PreCredential lists the attributes the family reports before
	// authentication, which an asset's binding may compare before a
	// credential is sent. Its evidence is the identification capability's
	// citation. Empty for a family that reports nothing unauthenticated.
	PreCredential []string     `json:"pre_credential,omitempty"`
	Capabilities  []Capability `json:"capabilities"`
	// MaxReadRows bounds one read of the family's native record buffer
	// (D1-12): a read with more rows is a failed parse, and nothing from it
	// is aligned or stored. At most MaxReadRowsCeiling. Required when event
	// retrieval uses an adapter operation; zero otherwise.
	MaxReadRows int `json:"max_read_rows,omitempty"`
	// SessionLimits are required when the profile sends adapter operations,
	// and absent otherwise (D1-18).
	SessionLimits *SessionLimits `json:"session_limits,omitempty"`
	// SecretPolicy is required when the family takes a password
	// (session_limits.password_attempts 1), and absent otherwise (D1-19).
	SecretPolicy *SecretPolicy `json:"secret_policy,omitempty"`
}

// SecretPolicy is the family's write-time rule for a password (D1-19). C7's
// ValidateSecret applies it inside the collector, together with the checks
// that hold for every family; the collector never builds a policy itself,
// and a missing or zero policy is invalid, never "accept anything".
type SecretPolicy struct {
	MinLen int `json:"min_len"`
	// MaxLen is at most MaxSecretLen.
	MaxLen int `json:"max_len"`
	// Allowed is an RE2 expression for the allowed characters, matched
	// against the whole secret (C7 anchors it).
	Allowed string `json:"allowed"`
	// MnemonicLen is how many leading characters of a command word the
	// device reads (3 for SEL, which reads QUIT as QUI). Exactly one of
	// MnemonicLen and WholeWord is set; zero is not a mode.
	MnemonicLen int    `json:"mnemonic_len,omitempty"`
	WholeWord   bool   `json:"whole_word,omitempty"`
	Citation    string `json:"citation"`
}

// MaxSecretLen is C7's authz.MaxSecretLen, copied so that C7 can import this
// package; a test checks the two agree.
const MaxSecretLen = 64

// MaxReadRowsCeiling is C4's event.MaxAlignRows, the most rows Align accepts
// (D1-12). It is a copy, so that C1 and C4 need not import each other (D1-1);
// a test checks the two agree.
const MaxReadRowsCeiling = 2048

// SessionLimits are a family's timing and counts for adapter sessions
// (D1-18). C7 and the collector read them from here, and C2's ceilings bound
// them when an invocation is built (TODO(C2)). Each value is a device fact or
// a platform choice made from one; Citation says which.
type SessionLimits struct {
	// MaxConcurrentSessions is how many sessions the platform may hold to one
	// asset at once. It is below what the device allows, so that an engineer
	// can still connect.
	MaxConcurrentSessions int `json:"max_concurrent_sessions"`
	// MinIntervalMS is the minimum time between two collections from one
	// asset.
	MinIntervalMS int64 `json:"min_interval_ms"`
	// PasswordAttempts per session: 0 for a family that takes no password,
	// otherwise 1 (C7: one attempt per session, never a retry).
	PasswordAttempts int `json:"password_attempts"`
	// IdleTimeoutMS is the longest the device may keep a session's state
	// after the connection closes: an access level, or a pending password
	// prompt (for the SEL-751, the largest TIDLE). The platform assumes this
	// value, not the setting's default.
	IdleTimeoutMS int64 `json:"idle_timeout_ms"`
	// FailedAuthFloorMS is how long runs to an asset are refused after a
	// session that sent a password and did not confirm the expected level.
	// When the family takes a password it is longer than IdleTimeoutMS, so a
	// new session never lands at a prompt the failed one left open, where its
	// first line would be another password attempt (C7-A2 change 1).
	FailedAuthFloorMS int64 `json:"failed_auth_floor_ms"`
	// Citation is the evidence for the values.
	Citation string `json:"citation"`
}

// Firmware says which firmware the profile may be used with.
type Firmware struct {
	// Allowlist names a firmware allowlist in the register package
	// (TODO(C3)), or is "none" for a family that is never contacted by an
	// adapter (for example a Syslog-only source).
	Allowlist string `json:"allowlist"`
}

// Capability is one row of the family's capability matrix.
type Capability struct {
	Capability CapabilityName `json:"capability"`
	Mechanism  Mechanism      `json:"mechanism"`
	// Operations are register operation IDs (TODO(C3)) for mechanism
	// adapter-operation, and empty otherwise.
	Operations []string         `json:"operations,omitempty"`
	Status     CapabilityStatus `json:"status"`
	// Citation is the evidence for Status: a document and page, a fixture
	// path, or a hardware log. Required unless Status is unknown.
	Citation string `json:"citation,omitempty"`
	Notes    string `json:"notes,omitempty"`
}

// CapabilityName is what a capability row is about (R1, R3, R4).
type CapabilityName string

const (
	CapIdentification         CapabilityName = "identification"
	CapEventRetrieval         CapabilityName = "event-retrieval"
	CapEventPush              CapabilityName = "event-push"
	CapConfigurationRetrieval CapabilityName = "configuration-retrieval"
	CapHealth                 CapabilityName = "health"
	CapTimeQuality            CapabilityName = "time-quality"
)

// Mechanism is how the platform exercises the capability.
type Mechanism string

const (
	MechAdapterOperation Mechanism = "adapter-operation" // a C2 invocation of register operations
	MechSyslogReceive    Mechanism = "syslog-receive"    // the device pushes; the platform only listens
	MechPassive          Mechanism = "passive"           // network observation (later phase)
	MechOperatorEntry    Mechanism = "operator-entry"    // typed in from records
	MechNone             Mechanism = "none"              // no mechanism (status unsupported or unknown)
)

// CapabilityStatus is the project's evidence classification for a claim.
type CapabilityStatus string

const (
	StatusHardwareVerified      CapabilityStatus = "hardware-verified"
	StatusDocumentedUntested    CapabilityStatus = "documented-untested"
	StatusSimulated             CapabilityStatus = "simulated"
	StatusInferredOwnerAccepted CapabilityStatus = "inferred-owner-accepted"
	StatusUnsupported           CapabilityStatus = "unsupported"
	StatusUnknown               CapabilityStatus = "unknown"
)

var (
	CapabilityNames    = []CapabilityName{CapIdentification, CapEventRetrieval, CapEventPush, CapConfigurationRetrieval, CapHealth, CapTimeQuality}
	Mechanisms         = []Mechanism{MechAdapterOperation, MechSyslogReceive, MechPassive, MechOperatorEntry, MechNone}
	CapabilityStatuses = []CapabilityStatus{StatusHardwareVerified, StatusDocumentedUntested, StatusSimulated,
		StatusInferredOwnerAccepted, StatusUnsupported, StatusUnknown}
)

// operationIDPattern is the agreed shape of a register operation ID, for
// example "sel.ser.read_all". TODO(C3): import from contracts/register.
var operationIDPattern = regexp.MustCompile(`^[a-z0-9]+(\.[a-z0-9_]+)+$`)

// ValidOperationID reports whether s has the shape of an operation ID.
// TODO(C3): replace with contracts/register.
func ValidOperationID(s string) bool { return operationIDPattern.MatchString(s) }

// DecodeProfile parses and validates a capability profile.
func DecodeProfile(b []byte) (CapabilityProfile, error) {
	var p CapabilityProfile
	if err := decodeStrict(b, &p, func() string { return p.Schema }); err != nil {
		return CapabilityProfile{}, fmt.Errorf("asset: profile: %w", err)
	}
	return p, p.Validate()
}

// Validate checks the profile.
func (p CapabilityProfile) Validate() error {
	v := &validator{}
	id, err := parseSchema(p.Schema)
	if err != nil {
		return err
	}
	v.later = id.Minor > self.Minor
	if p.Kind != ProfileKind {
		v.fail("kind must be %q", ProfileKind)
	}
	if !tokenPattern.MatchString(p.ProfileID) || p.Version == "" {
		v.fail("profile_id and version are required")
	}
	v.value("vendor", AttrVendor, p.Vendor)
	v.value("product_family", AttrProductFamily, p.ProductFamily)
	v.enum("device_class", p.DeviceClass, DeviceClasses)
	if p.Firmware.Allowlist != "none" && !tokenPattern.MatchString(p.Firmware.Allowlist) {
		v.fail("firmware.allowlist must name an allowlist or be \"none\"")
	}
	for i, name := range p.PreCredential {
		if !ValidAttributeName(name) || contains(OperatorOnlyAttributes, name) {
			v.fail("pre_credential[%d]: %q is not an attribute a device reports", i, name)
		}
	}
	usesAdapter := false
	seen := map[CapabilityName]bool{}
	for i, c := range p.Capabilities {
		q := fmt.Sprintf("capabilities[%d]", i)
		v.enum(q+".capability", string(c.Capability), CapabilityNames)
		v.enum(q+".mechanism", string(c.Mechanism), Mechanisms)
		v.enum(q+".status", string(c.Status), CapabilityStatuses)
		if seen[c.Capability] {
			v.fail("%s: capability %q listed twice", q, c.Capability)
		}
		seen[c.Capability] = true
		if c.Mechanism == MechAdapterOperation {
			usesAdapter = true
			if len(c.Operations) == 0 {
				v.fail("%s: adapter-operation needs at least one operation ID", q)
			}
		} else if len(c.Operations) != 0 {
			v.fail("%s: operations are allowed only with mechanism adapter-operation", q)
		}
		for _, op := range c.Operations {
			if !ValidOperationID(op) {
				v.fail("%s: %q is not an operation ID", q, op)
			}
		}
		if c.Mechanism == MechNone && c.Status != StatusUnsupported && c.Status != StatusUnknown {
			v.fail("%s: mechanism none goes only with status unsupported or unknown", q)
		}
		if c.Status != StatusUnknown && c.Citation == "" {
			v.fail("%s: status %q needs a citation", q, c.Status)
		}
	}
	if usesAdapter && p.Firmware.Allowlist == "none" {
		v.fail("a profile that sends adapter operations needs a firmware allowlist (AP-27)")
	}
	readsByAdapter := false
	for _, c := range p.Capabilities {
		readsByAdapter = readsByAdapter || (c.Capability == CapEventRetrieval && c.Mechanism == MechAdapterOperation)
	}
	switch {
	case p.MaxReadRows < 0 || p.MaxReadRows > MaxReadRowsCeiling:
		v.fail("max_read_rows %d is outside 0..%d", p.MaxReadRows, MaxReadRowsCeiling)
	case readsByAdapter && p.MaxReadRows == 0:
		v.fail("event retrieval by adapter operation needs max_read_rows (D1-12)")
	case !readsByAdapter && p.MaxReadRows != 0:
		v.fail("max_read_rows is only for event retrieval by adapter operation")
	}
	takesPassword := p.SessionLimits != nil && p.SessionLimits.PasswordAttempts == 1
	switch sp := p.SecretPolicy; {
	case takesPassword && sp == nil:
		v.fail("a family that takes a password needs secret_policy (D1-19)")
	case !takesPassword && sp != nil:
		v.fail("secret_policy is only for a family that takes a password")
	case sp != nil:
		sp.validate(v)
	}
	switch l := p.SessionLimits; {
	case usesAdapter && l == nil:
		v.fail("a profile that sends adapter operations needs session_limits (D1-18)")
	case !usesAdapter && l != nil:
		v.fail("session_limits are only for a profile that sends adapter operations")
	case l != nil:
		l.validate(v)
	}
	return v.err()
}

func (sp *SecretPolicy) validate(v *validator) {
	if sp.MinLen < 1 || sp.MaxLen < sp.MinLen || sp.MaxLen > MaxSecretLen {
		v.fail("secret_policy: lengths must satisfy 1 <= min_len <= max_len <= %d", MaxSecretLen)
	}
	if sp.Allowed == "" {
		v.fail("secret_policy.allowed is required")
	} else if _, err := regexp.Compile(sp.Allowed); err != nil {
		v.fail("secret_policy.allowed: %v", err)
	}
	if (sp.MnemonicLen > 0) == sp.WholeWord || sp.MnemonicLen < 0 {
		v.fail("secret_policy: set exactly one of mnemonic_len and whole_word")
	}
	if sp.Citation == "" {
		v.fail("secret_policy needs a citation")
	}
}

func (l *SessionLimits) validate(v *validator) {
	if l.MaxConcurrentSessions < 1 {
		v.fail("session_limits.max_concurrent_sessions must be at least 1")
	}
	if l.MinIntervalMS < 1 {
		v.fail("session_limits.min_interval_ms must be positive")
	}
	if l.PasswordAttempts != 0 && l.PasswordAttempts != 1 {
		v.fail("session_limits.password_attempts must be 0 or 1 (C7)")
	}
	if l.IdleTimeoutMS < 0 || l.FailedAuthFloorMS < 0 {
		v.fail("session_limits: times cannot be negative")
	}
	if l.PasswordAttempts == 1 && l.FailedAuthFloorMS <= l.IdleTimeoutMS {
		v.fail("session_limits.failed_auth_floor_ms %d must be longer than idle_timeout_ms %d", l.FailedAuthFloorMS, l.IdleTimeoutMS)
	}
	if l.Citation == "" {
		v.fail("session_limits needs a citation")
	}
}

// CheckProfile checks the asset against its capability profile: the profile
// is the one the asset names, and every pre-credential attribute of the
// binding is one the family reports before authentication.
func (a Asset) CheckProfile(p CapabilityProfile) error {
	if a.Profile == nil || a.Profile.ID != p.ProfileID || a.Profile.Version != p.Version {
		return fmt.Errorf("asset: profile %s %s is not the one the asset names", p.ProfileID, p.Version)
	}
	for _, name := range a.IdentityBinding.PreCredential {
		if !contains(p.PreCredential, name) {
			return fmt.Errorf("asset: pre_credential attribute %q is not reported before authentication by profile %s", name, p.ProfileID)
		}
	}
	return nil
}

func parseSchema(s string) (version.ID, error) {
	id, err := version.Parse(s)
	if err != nil || !self.Accepts(id) {
		return version.ID{}, fmt.Errorf("asset: schema %q is not readable as %s", s, Contract)
	}
	return id, nil
}
