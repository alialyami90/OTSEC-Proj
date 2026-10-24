package asset

import (
	"fmt"
	"regexp"

	"otsec.local/otsec/contracts/internal/strictjson"
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
	if err := strictjson.Forward(b, &p); err != nil {
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
	return v.err()
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
