package asset

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"otsec.local/otsec/contracts/internal/strictjson"
	"otsec.local/otsec/contracts/version"
)

// Contract is this package's identifier. Readers accept every 0.x minor
// (contracts/version) and ignore fields they do not know, but reject case
// variants and duplicate keys (strictjson.Forward, D1-10).
const Contract = "otsec.asset/0.1"

var self = version.ID{Name: "asset", Major: 0, Minor: 1}

// Asset is one device the platform knows about.
type Asset struct {
	Schema  string `json:"schema"`
	AssetID string `json:"asset_id"`
	// NodeID is the node that runs adapter sessions to this asset: one node
	// per asset, because some devices allow very few sessions (D9). Other
	// nodes may still receive the asset's Syslog; their events reference the
	// same asset ID. Failover of the collecting node under N-1 redundancy is
	// open (A5, A1). The format is C4's NodeID, kept as a copy here because
	// C4 imports this package (C1-A4-1); A6's tests check the two agree.
	NodeID          string          `json:"node_id"`
	Attributes      []Attribute     `json:"attributes"`
	Endpoints       []Endpoint      `json:"endpoints,omitempty"`
	IdentityBinding IdentityBinding `json:"identity_binding"`
	Profile         *ProfileRef     `json:"profile,omitempty"`
	Suspension      *Suspension     `json:"suspension,omitempty"`
	PlatformNode    *PlatformNode   `json:"platform_node,omitempty"`
}

// Attribute is one fact about the asset. Value is the resolved value; the
// observations say where it came from. See Confidence for how the two relate.
type Attribute struct {
	Name         string        `json:"name"`
	Value        string        `json:"value"`
	Confidence   Confidence    `json:"confidence"`
	Observations []Observation `json:"observations"`
}

// Observation is one source's report of an attribute value. An attribute
// keeps at most one observation per (evidence class, source method): the
// latest.
type Observation struct {
	Value         string        `json:"value"`
	EvidenceClass EvidenceClass `json:"evidence_class"`
	Source        Source        `json:"source"`
}

// Source says how and when a value was obtained.
type Source struct {
	Method SourceMethod `json:"method"`
	// Ref points at the evidence: the C2 invocation ID for adapter-session,
	// the operator principal for operator-entry (TODO(C7)), a document
	// citation for document, the attribute names used for derived.
	Ref string `json:"ref"`
	// Span is the byte span in the invocation's transcript that holds the
	// value, for adapter-session observations (A4 EP-2).
	Span *Span `json:"span,omitempty"`
	// ObservedAt is a platform time, RFC 3339 UTC with Z. TODO(C4): timestamp model.
	ObservedAt string `json:"observed_at"`
}

// Span is a byte range in a transcript or other raw evidence object.
type Span struct {
	Offset int64 `json:"offset"`
	Length int64 `json:"length"`
}

// Endpoint is one way to reach or hear from the asset.
//
// For telnet and ssh, Host and Port are where the node connects. For the
// Syslog transports the device is the sender (C1-A4-2): Host is the source
// address the node expects its messages from, as the node's listener sees it
// (after any NAT); Port is optional and, when set, is the node's listening
// port, never the device's ephemeral source port. Within one node a
// (transport, host) pair belongs to at most one asset (CheckSenders). A
// message relayed by another Syslog host arrives from the relay's address,
// so an address-only binding names the direct sender only.
type Endpoint struct {
	ID                 string             `json:"id"`
	Transport          Transport          `json:"transport"`
	Host               string             `json:"host,omitempty"`
	Port               int                `json:"port,omitempty"`
	SerialDevice       string             `json:"serial_device,omitempty"`
	DownstreamSecurity DownstreamSecurity `json:"downstream_security"`
}

// DownstreamSecurity is A3 §4.5's label for the link from the node to the
// device, plus the acknowledgement any level below encrypted-authenticated
// requires.
type DownstreamSecurity struct {
	Level           SecurityLevel    `json:"level"`
	Acknowledgement *Acknowledgement `json:"acknowledgement,omitempty"`
}

// Acknowledgement records an administrator's per-device acceptance of an
// insecure downstream link (A3 §4.5, ADR-0005).
type Acknowledgement struct {
	By     string `json:"by"` // TODO(C7): human principal ID.
	At     string `json:"at"` // RFC 3339 UTC. TODO(C4).
	Reason string `json:"reason"`
	// Scope is where the acceptance holds. The collector refuses to run when
	// the credential's C7 plaintext_scope differs from it (C1-A3-3).
	Scope AckScope `json:"scope"`
}

// AckScope is where an insecure downstream link is accepted. 0.1 has one
// value: the owner accepted Telnet for the simulated and lab slice only
// (ADR-0005). A production scope needs an owner decision and a later minor.
type AckScope string

const LabOnly AckScope = "lab-only"

// IdentityBinding says which attributes tie this asset record to the device
// that answers, and how strong that tie is. See the package documentation.
type IdentityBinding struct {
	Method BindingMethod `json:"method"`
	// Strength must equal the value Method implies (StrengthOf). It is
	// carried explicitly so that every consumer, including a UI that knows
	// nothing of methods, can show "spoofable".
	Strength BindingStrength `json:"strength"`
	// Attributes are compared on every session. Each must exist on the asset
	// with an operator-declared observation, which is the expected value.
	Attributes []string `json:"attributes"`
	// PreCredential is the subset of Attributes compared before any
	// credential leaves the node: what the device reports without
	// authentication (for the SEL-751, the ID response, S22 Figure 7.38). A
	// device-reported binding needs at least one, so that ACC is never sent
	// ungated (AP-27, V-S19). The other attributes are compared after
	// authentication, where they detect a substitution but cannot protect
	// the credential. Which attributes a family can report before
	// authentication is profile content (CapabilityProfile.PreCredential).
	PreCredential []string `json:"pre_credential,omitempty"`
}

// ProfileRef names the capability profile the collector uses for this asset.
type ProfileRef struct {
	ID      string `json:"id"`
	Version string `json:"version"`
}

// Suspension stops collection from the asset until an operator clears it.
type Suspension struct {
	Reason SuspensionReason `json:"reason"`
	Since  string           `json:"since"` // RFC 3339 UTC. TODO(C4).
	// Ref is the C2 invocation ID that caused it, or the operator principal
	// for reason "operator".
	Ref string `json:"ref"`
}

// PlatformNode marks the asset as a site platform node itself. Only an asset
// of class "server" may carry it.
type PlatformNode struct {
	Posture []PostureLabel `json:"posture"`
}

// PostureLabel is one of A5's node posture labels (C-24, V-S20, ADR-0007).
// TODO(A5): docs/phase1/A5-node-posture.md defines when each applies.
type PostureLabel struct {
	Label PostureCode `json:"label"`
	Since string      `json:"since"` // RFC 3339 UTC. TODO(C4).
	// Condition is the standing condition the label carries, for example the
	// owner's acceptance of an unsupported OS. Required for os-out-of-support.
	Condition string `json:"condition,omitempty"`
	// MigrationDate is the planned end of the condition, YYYY-MM-DD.
	MigrationDate string `json:"migration_date,omitempty"`
}

// --- closed enumerations ---------------------------------------------------
//
// Every enum below is closed: a 0.1 reader rejects a value it does not know
// in a 0.1 message. A message stamped with a later 0.x minor may carry values
// added since; a 0.1 reader accepts the message and reads such a value as the
// enum's fallback, never as anything more trusted. Decode applies the
// fallbacks (Asset.Effective), so a 0.1 consumer never sees a later value.

// Confidence is derived from the observations by fixed rules, so it can be
// checked rather than asserted:
//
//   - single-source: every observation equal to Value, all from one evidence
//     class. Usually one observation; two device claims (an adapter session
//     and Syslog) are one class and stay single-source.
//   - corroborated: two or more observations, all equal to Value, from at
//     least two different evidence classes. Two device claims (ID and the SER
//     header) are one class and do not corroborate each other.
//   - conflicting: two or more observations that do not all agree. Value is
//     the operator-declared observation's value if there is one, so a device
//     claim never overwrites the records.
type Confidence string

const (
	SingleSource Confidence = "single-source"
	Corroborated Confidence = "corroborated"
	Conflicting  Confidence = "conflicting"
)

// EvidenceClass is the kind of evidence behind one observation. It follows
// the project's classes (CLAUDE.md section 3) as they apply to a value rather
// than to a capability.
type EvidenceClass string

const (
	// DeviceObserved: read from or sent by the device itself. A device's claim
	// about itself, not a verification of it (C-07).
	DeviceObserved EvidenceClass = "device-observed"
	// Simulated: produced by a simulator or test fixture. Never shown as a
	// device observation.
	Simulated EvidenceClass = "simulated"
	// OperatorDeclared: entered by an operator from records, for example the
	// FID at commissioning (ADR-0005).
	OperatorDeclared EvidenceClass = "operator-declared"
	// Documented: taken from OEM documentation, for example a model's default.
	Documented EvidenceClass = "documented"
	// Inferred: derived from other attributes by a stated rule.
	Inferred EvidenceClass = "inferred"
)

// SourceMethod is how the observation was obtained.
type SourceMethod string

const (
	AdapterSession SourceMethod = "adapter-session"   // a C2 invocation
	SyslogReceived SourceMethod = "syslog-received"   // a message the device sent
	PassiveNetwork SourceMethod = "passive-network"   // traffic observation (later phase)
	OperatorEntry  SourceMethod = "operator-entry"    // typed in by an operator
	DocumentSource SourceMethod = "document"          // OEM documentation
	Derived        SourceMethod = "derived"           // computed from other attributes
	SimulatorRun   SourceMethod = "simulator-session" // a session with a simulator
)

// Transport is how an endpoint is reached or heard.
type Transport string

const (
	Telnet    Transport = "telnet"
	SSH       Transport = "ssh"
	Serial    Transport = "serial"
	SyslogUDP Transport = "syslog-udp"
	SyslogTCP Transport = "syslog-tcp"
	SyslogTLS Transport = "syslog-tls"
)

// SecurityLevel is A3 §4.5's downstream_security value. Its fallback is the
// least secure level.
type SecurityLevel string

const (
	EncryptedAuthenticated   SecurityLevel = "encrypted-authenticated"
	EncryptedWeak            SecurityLevel = "encrypted-weak"
	PlaintextUnauthenticated SecurityLevel = "plaintext-unauthenticated"
)

// BindingMethod is how the asset record is tied to the device that answers.
type BindingMethod string

const (
	// DeviceReported compares identifiers the device prints (SEL FID, serial
	// number) with operator-declared values. Spoofable.
	DeviceReported BindingMethod = "device-reported"
	// AddressOnly relies on the network address alone, for example a Syslog
	// sender. Spoofable.
	AddressOnly BindingMethod = "address-only"
	// PinnedKey compares a host key or certificate pinned at commissioning
	// (A3 §4.5, V-S14). Not used by any slice-1 device.
	PinnedKey BindingMethod = "pinned-key"
)

// BindingStrength says whether a match authenticates the device.
type BindingStrength string

const (
	Spoofable     BindingStrength = "spoofable"
	Cryptographic BindingStrength = "cryptographic"
)

// SuspensionReason is why collection from the asset is stopped.
type SuspensionReason string

const (
	SuspendIdentityMismatch     SuspensionReason = "identity-mismatch"
	SuspendAuthFailed           SuspensionReason = "auth-failed"
	SuspendPasswordPromptAbsent SuspensionReason = "password-prompt-absent"
	SuspendLanguageNotEnglish   SuspensionReason = "language-not-english"
	SuspendFirmwareNotAllowed   SuspensionReason = "firmware-not-allowlisted"
	SuspendUnexpectedLevel      SuspensionReason = "unexpected-access-level"
	SuspendOperator             SuspensionReason = "operator"
)

// PostureCode is one of A5's node posture labels.
type PostureCode string

const (
	StorageDurabilityUnverified PostureCode = "storage-durability-unverified"
	OSOutOfSupport              PostureCode = "os-out-of-support"
	OSSupportUnknown            PostureCode = "os-support-unknown"
)

// DeviceClass values are the classes of ADR-0006 and R1.6.
const (
	ClassProtectiveRelay         = "protective-relay"
	ClassIEDOther                = "ied-other"
	ClassRTU                     = "rtu"
	ClassAutomationController    = "automation-controller"
	ClassCommunicationsProcessor = "communications-processor"
	ClassEthernetSwitch          = "ethernet-switch"
	ClassRouter                  = "router"
	ClassSecurityGateway         = "security-gateway"
	ClassFirewall                = "firewall"
	ClassTimeServer              = "time-server"
	ClassServer                  = "server"
	ClassEngineeringWorkstation  = "engineering-workstation"
	ClassHMI                     = "hmi"
	ClassHistorian               = "historian"
	ClassMeter                   = "meter"
	ClassPortServer              = "port-server"
	ClassUnknown                 = "unknown"
)

var (
	Confidences       = []Confidence{SingleSource, Corroborated, Conflicting}
	EvidenceClasses   = []EvidenceClass{DeviceObserved, Simulated, OperatorDeclared, Documented, Inferred}
	SourceMethods     = []SourceMethod{AdapterSession, SyslogReceived, PassiveNetwork, OperatorEntry, DocumentSource, Derived, SimulatorRun}
	Transports        = []Transport{Telnet, SSH, Serial, SyslogUDP, SyslogTCP, SyslogTLS}
	SecurityLevels    = []SecurityLevel{EncryptedAuthenticated, EncryptedWeak, PlaintextUnauthenticated}
	BindingMethods    = []BindingMethod{DeviceReported, AddressOnly, PinnedKey}
	BindingStrengths  = []BindingStrength{Spoofable, Cryptographic}
	AckScopes         = []AckScope{LabOnly}
	SuspensionReasons = []SuspensionReason{SuspendIdentityMismatch, SuspendAuthFailed, SuspendPasswordPromptAbsent,
		SuspendLanguageNotEnglish, SuspendFirmwareNotAllowed, SuspendUnexpectedLevel, SuspendOperator}
	PostureCodes  = []PostureCode{StorageDurabilityUnverified, OSOutOfSupport, OSSupportUnknown}
	DeviceClasses = []string{ClassProtectiveRelay, ClassIEDOther, ClassRTU, ClassAutomationController,
		ClassCommunicationsProcessor, ClassEthernetSwitch, ClassRouter, ClassSecurityGateway, ClassFirewall,
		ClassTimeServer, ClassServer, ClassEngineeringWorkstation, ClassHMI, ClassHistorian, ClassMeter,
		ClassPortServer, ClassUnknown}
)

// Fallbacks for values added in a later minor. Each is the least trusted
// reading of its enum.
const (
	FallbackSecurityLevel = PlaintextUnauthenticated
	FallbackStrength      = Spoofable
	FallbackDeviceClass   = ClassUnknown
	// FallbackEvidenceClass is how a 0.1 reader reads an evidence class it
	// does not know, and a device-observed value from a source method it
	// does not know: never as a device observation.
	FallbackEvidenceClass = Inferred
)

// StrengthOf is the strength a binding method implies.
func StrengthOf(m BindingMethod) BindingStrength {
	if m == PinnedKey {
		return Cryptographic
	}
	return Spoofable
}

// Insecure reports whether the level must be labelled insecure wherever the
// endpoint appears (R2.3).
func (l SecurityLevel) Insecure() bool { return l != EncryptedAuthenticated }

// --- attribute names -------------------------------------------------------

// Attribute names without a vendor prefix must be one of these. A name of the
// form "<vendor>.<name>" (for example "sel.cid") is a vendor-specific
// attribute and may be added by any profile without a contract change.
const (
	AttrDeviceClass     = "device_class"
	AttrVendor          = "vendor"
	AttrProductFamily   = "product_family"
	AttrModel           = "model"
	AttrPartNumber      = "part_number"
	AttrSerialNumber    = "serial_number"
	AttrFirmwareID      = "firmware_id"
	AttrFirmwareVersion = "firmware_version"
	AttrDeviceName      = "device_name"
	AttrHostname        = "hostname"
	AttrIPAddress       = "ip_address"
	AttrMACAddress      = "mac_address"
	AttrLocation        = "location"
	AttrOSName          = "os_name"
	AttrOSVersion       = "os_version"
	AttrHardwareModel   = "hardware_model"
	AttrDriveModel      = "drive_model"
)

var AttributeNames = []string{AttrDeviceClass, AttrVendor, AttrProductFamily, AttrModel, AttrPartNumber,
	AttrSerialNumber, AttrFirmwareID, AttrFirmwareVersion, AttrDeviceName, AttrHostname, AttrIPAddress,
	AttrMACAddress, AttrLocation, AttrOSName, AttrOSVersion, AttrHardwareModel, AttrDriveModel}

// Vendor and product family values are lowercase tokens ("sel", "sel-751",
// "sel-3355-2"), so that a C3 register package's family names the same
// thing. A display name belongs in the UI, not in the record.

// RequiredAttributes are present on every asset, with value "unknown" where
// nothing better is known (ADR-0006 item 5).
var RequiredAttributes = []string{AttrDeviceClass, AttrVendor}

// OperatorOnlyAttributes are never reported by a device about itself. A
// device-reported binding cannot compare them: the device does not print
// them, so the comparison would check nothing (A6 C1 review change 1).
var OperatorOnlyAttributes = []string{AttrDeviceClass, AttrVendor, AttrProductFamily, AttrDeviceName,
	AttrIPAddress, AttrLocation}

// --- formats -----------------------------------------------------------------

var (
	uuidPattern       = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	nodeIDPattern     = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`) // same as C4 NodeID; see Asset.NodeID
	attrNamePattern   = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	vendorAttrPattern = regexp.MustCompile(`^[a-z][a-z0-9]{1,15}\.[a-z][a-z0-9_]{0,63}$`)
	tokenPattern      = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	datePattern       = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`)
	// familyPattern is the shape of vendor and product family values. C3
	// names a register package's family with the same token ("sel-751").
	familyPattern = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
)

// MaxValueBytes bounds an attribute value. Values are UTF-8 text with no
// control characters; device bytes that do not fit stay in the transcript.
const MaxValueBytes = 256

// ValidAssetID reports whether s is an asset ID: a lowercase RFC 9562 UUID,
// assigned at registration.
func ValidAssetID(s string) bool { return uuidPattern.MatchString(s) }

// ValidAttributeName reports whether s is a known name or a vendor-prefixed one.
func ValidAttributeName(s string) bool {
	if vendorAttrPattern.MatchString(s) {
		return true
	}
	return attrNamePattern.MatchString(s) && contains(AttributeNames, s)
}

// ValidTime reports whether s is a platform time: RFC 3339, UTC, Z suffix.
// TODO(C4): replace with C4's timestamp model.
func ValidTime(s string) bool {
	if !strings.HasSuffix(s, "Z") {
		return false
	}
	_, err := time.Parse(time.RFC3339Nano, s)
	return err == nil
}

// --- decoding and validation ---------------------------------------------------

// Decode parses and validates an asset record, and returns it as a 0.1
// reader must read it (Effective). Decoding is strict except for forward
// compatibility (D1-10): a key that differs from a field name only in case,
// a duplicate key, or data after the record is rejected, so a reviewer and
// the node always read the same binding (A6 C1 review change 3). An unknown
// field from a later minor is ignored.
func Decode(b []byte) (Asset, error) {
	var a Asset
	if err := strictjson.Forward(b, &a); err != nil {
		return Asset{}, fmt.Errorf("asset: %w", err)
	}
	if err := a.Validate(); err != nil {
		return Asset{}, err
	}
	return a.Effective(), nil
}

// Effective is the record as a 0.1 reader reads it. Values a later minor
// added are read down to the least trusted 0.1 value, wherever they carry
// trust (A6 C1 review change 2):
//
//   - binding strength is always StrengthOf(method): spoofable unless the
//     method is pinned-key;
//   - an evidence class 0.1 does not know reads as FallbackEvidenceClass;
//   - a device-observed value from a source method 0.1 does not know reads
//     as FallbackEvidenceClass, so it is never shown as a device observation;
//     a simulator-session value always reads as simulated;
//   - a confidence 0.1 does not know is recomputed from the observations;
//   - a downstream security level 0.1 does not know reads as
//     FallbackSecurityLevel.
//
// For a valid 0.1 record, Effective returns the record unchanged. Device
// class is not rewritten; read it with DeviceClass.
func (a Asset) Effective() Asset {
	out := a
	out.Attributes = make([]Attribute, len(a.Attributes))
	for i, at := range a.Attributes {
		at.Observations = append([]Observation(nil), at.Observations...)
		for j := range at.Observations {
			at.Observations[j].EvidenceClass = effectiveClass(at.Observations[j])
		}
		if !contains(Confidences, at.Confidence) {
			at.Confidence = DeriveConfidence(at.Value, at.Observations)
		}
		out.Attributes[i] = at
	}
	out.Endpoints = append([]Endpoint(nil), a.Endpoints...)
	for i := range out.Endpoints {
		if !contains(SecurityLevels, out.Endpoints[i].DownstreamSecurity.Level) {
			out.Endpoints[i].DownstreamSecurity.Level = FallbackSecurityLevel
		}
	}
	out.IdentityBinding.Strength = StrengthOf(a.IdentityBinding.Method)
	return out
}

func effectiveClass(ob Observation) EvidenceClass {
	switch {
	case ob.Source.Method == SimulatorRun:
		return Simulated
	case !contains(EvidenceClasses, ob.EvidenceClass):
		return FallbackEvidenceClass
	case ob.EvidenceClass == DeviceObserved && !contains(SourceMethods, ob.Source.Method):
		return FallbackEvidenceClass
	}
	return ob.EvidenceClass
}

// DeriveConfidence computes the confidence the rules give a value and its
// observations.
func DeriveConfidence(value string, obs []Observation) Confidence {
	classes := map[EvidenceClass]bool{}
	for _, ob := range obs {
		if ob.Value != value {
			return Conflicting
		}
		classes[ob.EvidenceClass] = true
	}
	if len(classes) >= 2 {
		return Corroborated
	}
	return SingleSource
}

// DeviceClass is the asset's device class as a 0.1 reader reads it: a class
// from a later minor reads as FallbackDeviceClass.
func (a Asset) DeviceClass() string {
	at, _ := a.Attribute(AttrDeviceClass)
	if !contains(DeviceClasses, at.Value) {
		return FallbackDeviceClass
	}
	return at.Value
}

// Validate checks every rule of the contract that can be checked from the
// record alone.
func (a Asset) Validate() error {
	v := &validator{}
	id, err := parseSchema(a.Schema)
	if err != nil {
		return err
	}
	v.later = id.Minor > self.Minor

	if !ValidAssetID(a.AssetID) {
		v.fail("asset_id %q is not a lowercase UUID", a.AssetID)
	}
	if !nodeIDPattern.MatchString(a.NodeID) {
		v.fail("node_id %q is not a node ID", a.NodeID)
	}

	attrs := map[string]Attribute{}
	for i, at := range a.Attributes {
		v.attribute(i, at)
		if _, dup := attrs[at.Name]; dup {
			v.fail("attributes[%d]: duplicate name %q", i, at.Name)
		}
		attrs[at.Name] = at
	}
	for _, name := range RequiredAttributes {
		if _, ok := attrs[name]; !ok {
			v.fail("required attribute %q is missing", name)
		}
	}

	eps := map[string]bool{}
	for i, ep := range a.Endpoints {
		v.endpoint(i, ep)
		if eps[ep.ID] {
			v.fail("endpoints[%d]: duplicate id %q", i, ep.ID)
		}
		eps[ep.ID] = true
	}

	v.binding(a, attrs)

	if a.Profile != nil {
		if !tokenPattern.MatchString(a.Profile.ID) || a.Profile.Version == "" {
			v.fail("profile: id and version are required")
		}
	}
	if s := a.Suspension; s != nil {
		v.enum("suspension.reason", string(s.Reason), SuspensionReasons)
		if !ValidTime(s.Since) {
			v.fail("suspension.since %q is not an RFC 3339 UTC time", s.Since)
		}
		if s.Ref == "" {
			v.fail("suspension.ref is required")
		}
	}
	if pn := a.PlatformNode; pn != nil {
		if attrs[AttrDeviceClass].Value != ClassServer {
			v.fail("platform_node is allowed only on an asset of class %q", ClassServer)
		}
		seen := map[PostureCode]bool{}
		for i, p := range pn.Posture {
			v.enum(fmt.Sprintf("platform_node.posture[%d].label", i), string(p.Label), PostureCodes)
			if seen[p.Label] {
				v.fail("platform_node.posture[%d]: duplicate label %q", i, p.Label)
			}
			seen[p.Label] = true
			if !ValidTime(p.Since) {
				v.fail("platform_node.posture[%d].since is not an RFC 3339 UTC time", i)
			}
			if p.Label == OSOutOfSupport && strings.TrimSpace(p.Condition) == "" {
				v.fail("platform_node.posture[%d]: os-out-of-support needs the standing condition", i)
			}
			if p.MigrationDate != "" {
				if _, err := time.Parse("2006-01-02", p.MigrationDate); err != nil || !datePattern.MatchString(p.MigrationDate) {
					v.fail("platform_node.posture[%d].migration_date %q is not YYYY-MM-DD", i, p.MigrationDate)
				}
			}
		}
	}
	return v.err()
}

func (v *validator) attribute(i int, at Attribute) {
	p := fmt.Sprintf("attributes[%d]", i)
	if !ValidAttributeName(at.Name) {
		v.fail("%s: name %q is neither a known attribute nor <vendor>.<name>", p, at.Name)
	}
	v.value(p+".value", at.Name, at.Value)
	if len(at.Observations) == 0 {
		v.fail("%s (%s): an attribute needs at least one observation with an evidence class", p, at.Name)
		return
	}
	type key struct {
		c EvidenceClass
		m SourceMethod
	}
	seen := map[key]bool{}
	classes := map[EvidenceClass]bool{}
	allEqual := true
	declared := ""
	for j, ob := range at.Observations {
		q := fmt.Sprintf("%s.observations[%d]", p, j)
		if ob.EvidenceClass == "" {
			v.fail("%s: evidence_class is required", q)
		} else {
			v.enum(q+".evidence_class", string(ob.EvidenceClass), EvidenceClasses)
		}
		v.enum(q+".source.method", string(ob.Source.Method), SourceMethods)
		v.value(q+".value", at.Name, ob.Value)
		if ob.Source.Ref == "" {
			v.fail("%s.source.ref is required", q)
		}
		if !ValidTime(ob.Source.ObservedAt) {
			v.fail("%s.source.observed_at %q is not an RFC 3339 UTC time", q, ob.Source.ObservedAt)
		}
		if sp := ob.Source.Span; sp != nil && (sp.Offset < 0 || sp.Length <= 0) {
			v.fail("%s.source.span must have offset >= 0 and length > 0", q)
		}
		if (ob.Source.Method == AdapterSession || ob.Source.Method == SimulatorRun) && ob.Source.Span == nil {
			v.fail("%s: an observation from a session needs the transcript span (EP-2)", q)
		}
		if (ob.EvidenceClass == Simulated) != (ob.Source.Method == SimulatorRun) {
			v.fail("%s: evidence class simulated and method simulator-session go together, never one without the other", q)
		}
		k := key{ob.EvidenceClass, ob.Source.Method}
		if seen[k] {
			v.fail("%s: more than one observation for %s/%s; keep only the latest", q, k.c, k.m)
		}
		seen[k] = true
		classes[ob.EvidenceClass] = true
		if ob.Value != at.Observations[0].Value {
			allEqual = false
		}
		if ob.EvidenceClass == OperatorDeclared {
			declared = ob.Value
		}
	}
	switch at.Confidence {
	case SingleSource:
		if !allEqual || at.Observations[0].Value != at.Value || len(classes) != 1 {
			v.fail("%s: single-source needs observations equal to value, all from one evidence class", p)
		}
	case Corroborated:
		if len(at.Observations) < 2 || !allEqual || at.Observations[0].Value != at.Value || len(classes) < 2 {
			v.fail("%s: corroborated needs two or more equal observations from at least two evidence classes", p)
		}
	case Conflicting:
		if len(at.Observations) < 2 || allEqual {
			v.fail("%s: conflicting needs observations that disagree", p)
		}
		if declared != "" && at.Value != declared {
			v.fail("%s: a conflicting attribute keeps the operator-declared value", p)
		}
	default:
		v.enum(p+".confidence", string(at.Confidence), Confidences)
	}
}

func (v *validator) value(path, name, val string) {
	if val == "" || len(val) > MaxValueBytes || !utf8.ValidString(val) {
		v.fail("%s: value must be 1 to %d bytes of UTF-8", path, MaxValueBytes)
		return
	}
	for _, r := range val {
		if r < 0x20 || r == 0x7f {
			v.fail("%s: value contains a control character", path)
			return
		}
	}
	switch name {
	case AttrDeviceClass:
		v.enum(path, val, DeviceClasses)
	case AttrVendor, AttrProductFamily:
		if !familyPattern.MatchString(val) {
			v.fail("%s: %q is not a lowercase token such as \"sel\" or \"sel-751\"", path, val)
		}
	case AttrIPAddress:
		if _, err := netip.ParseAddr(val); err != nil {
			v.fail("%s: %q is not an IP address", path, val)
		}
	case AttrMACAddress:
		if _, err := net.ParseMAC(val); err != nil {
			v.fail("%s: %q is not a MAC address", path, val)
		}
	}
}

func (v *validator) endpoint(i int, ep Endpoint) {
	p := fmt.Sprintf("endpoints[%d]", i)
	if !tokenPattern.MatchString(ep.ID) {
		v.fail("%s.id %q is not a token", p, ep.ID)
	}
	v.enum(p+".transport", string(ep.Transport), Transports)
	if ep.Transport == Serial {
		if ep.SerialDevice == "" || ep.Host != "" {
			v.fail("%s: a serial endpoint names serial_device and no host", p)
		}
	} else if contains(Transports, ep.Transport) {
		if _, err := netip.ParseAddr(ep.Host); err != nil {
			v.fail("%s.host %q is not an IP address", p, ep.Host)
		}
		optional := ep.Transport.Inbound() && ep.Port == 0
		if !optional && (ep.Port < 1 || ep.Port > 65535) {
			v.fail("%s.port %d is out of range", p, ep.Port)
		}
	}
	ds := ep.DownstreamSecurity
	v.enum(p+".downstream_security.level", string(ds.Level), SecurityLevels)
	if AlwaysPlaintext(ep.Transport) && ds.Level != PlaintextUnauthenticated {
		v.fail("%s: %s is plaintext-unauthenticated, whatever the record says", p, ep.Transport)
	}
	if ds.Level != "" && ds.Level != EncryptedAuthenticated {
		ack := ds.Acknowledgement
		if ack == nil || ack.By == "" || strings.TrimSpace(ack.Reason) == "" || !ValidTime(ack.At) {
			v.fail("%s: %s needs an acknowledgement with by, at, reason and scope (A3 §4.5)", p, ds.Level)
		} else {
			v.enum(p+".downstream_security.acknowledgement.scope", string(ack.Scope), AckScopes)
		}
	}
}

// Inbound reports whether the device sends to the node on this transport,
// rather than the node connecting to the device.
func (t Transport) Inbound() bool { return t == SyslogUDP || t == SyslogTCP || t == SyslogTLS }

// CheckSenders checks a node's asset registry: an inbound (transport, host)
// pair may belong to at most one asset per node, so a received message is
// attributed to one asset or to none, never to the wrong one (C1-A4-2).
// Validate cannot check this, because it sees one asset at a time.
func CheckSenders(assets []Asset) error {
	type key struct {
		node string
		t    Transport
		host string
	}
	owner := map[key]string{}
	var errs []error
	for _, a := range assets {
		for _, ep := range a.Endpoints {
			if !ep.Transport.Inbound() {
				continue
			}
			addr, err := netip.ParseAddr(ep.Host)
			host := ep.Host
			if err == nil {
				host = addr.Unmap().String()
			}
			k := key{a.NodeID, ep.Transport, host}
			if prev, ok := owner[k]; ok && prev != a.AssetID {
				errs = append(errs, fmt.Errorf("node %s: %s sender %s belongs to both %s and %s", k.node, k.t, k.host, prev, a.AssetID))
				continue
			}
			owner[k] = a.AssetID
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("asset: %w", errors.Join(errs...))
	}
	return nil
}

// AlwaysPlaintext reports whether a transport is plaintext-unauthenticated
// whatever a record says: Telnet, serial (anything on the line or on a
// networked serial server sees the password) and Syslog without TLS
// (A3 §4.5, C1-A3-1).
func AlwaysPlaintext(t Transport) bool {
	return t == Telnet || t == Serial || t == SyslogUDP || t == SyslogTCP
}

func (v *validator) binding(a Asset, attrs map[string]Attribute) {
	b := a.IdentityBinding
	v.enum("identity_binding.method", string(b.Method), BindingMethods)
	v.enum("identity_binding.strength", string(b.Strength), BindingStrengths)
	if contains(BindingMethods, b.Method) && b.Strength != StrengthOf(b.Method) {
		v.fail("identity_binding.strength must be %q for method %q", StrengthOf(b.Method), b.Method)
	}
	for _, ep := range a.Endpoints {
		if b.Method == PinnedKey && ep.DownstreamSecurity.Level == PlaintextUnauthenticated {
			v.fail("identity_binding: a plaintext endpoint (%s) cannot carry a pinned key", ep.ID)
		}
		// Encryption without a key pinned at commissioning does not
		// authenticate the device (AP-12, V-S14, C1-A3-2): such a link is
		// encrypted-weak, with its acknowledgement.
		if ep.DownstreamSecurity.Level == EncryptedAuthenticated && b.Method != PinnedKey {
			v.fail("endpoints: %s is labelled encrypted-authenticated but the binding is %q; only pinned-key authenticates the device", ep.ID, b.Method)
		}
	}
	if b.Method == DeviceReported && len(b.Attributes) == 0 {
		v.fail("identity_binding: device-reported needs at least one attribute")
	}
	if b.Method == DeviceReported && len(b.PreCredential) == 0 {
		v.fail("identity_binding: device-reported needs a pre_credential attribute, compared before any credential is sent (AP-27)")
	}
	if b.Method == AddressOnly && len(b.PreCredential) != 0 {
		v.fail("identity_binding: address-only compares nothing the device reports, so pre_credential is empty")
	}
	pre := map[string]bool{}
	for _, name := range b.PreCredential {
		if pre[name] {
			v.fail("identity_binding: pre_credential lists %q twice", name)
		}
		pre[name] = true
		if !contains(b.Attributes, name) {
			v.fail("identity_binding: pre_credential attribute %q is not in attributes", name)
		}
	}
	if b.Method == DeviceReported {
		for _, name := range b.Attributes {
			if contains(OperatorOnlyAttributes, name) {
				v.fail("identity_binding: device-reported cannot compare %q, which the device does not report", name)
			}
		}
	}
	for _, name := range b.Attributes {
		at, ok := attrs[name]
		if !ok {
			v.fail("identity_binding: attribute %q is not on the asset", name)
			continue
		}
		declared := false
		for _, ob := range at.Observations {
			if ob.EvidenceClass == OperatorDeclared {
				declared = true
			}
		}
		if !declared {
			v.fail("identity_binding: attribute %q has no operator-declared value to compare against", name)
		}
	}
}

// Attribute returns the named attribute.
func (a Asset) Attribute(name string) (Attribute, bool) {
	for _, at := range a.Attributes {
		if at.Name == name {
			return at, true
		}
	}
	return Attribute{}, false
}

// Declared returns the operator-declared value of an attribute, the value the
// identity binding compares against.
func (a Asset) Declared(name string) (string, bool) {
	at, ok := a.Attribute(name)
	if !ok {
		return "", false
	}
	for _, ob := range at.Observations {
		if ob.EvidenceClass == OperatorDeclared {
			return ob.Value, true
		}
	}
	return "", false
}

// WeakestDownstreamSecurity is the asset-level label: the least secure level
// of any endpoint. An asset with no endpoints has no downstream link.
func (a Asset) WeakestDownstreamSecurity() (SecurityLevel, bool) {
	rank := map[SecurityLevel]int{EncryptedAuthenticated: 0, EncryptedWeak: 1, PlaintextUnauthenticated: 2}
	var worst SecurityLevel
	for _, ep := range a.Endpoints {
		l := ep.DownstreamSecurity.Level
		if _, ok := rank[l]; !ok {
			l = FallbackSecurityLevel
		}
		if worst == "" || rank[l] > rank[worst] {
			worst = l
		}
	}
	return worst, worst != ""
}

// --- helpers -------------------------------------------------------------------

type validator struct {
	later bool // message is from a later minor: unknown enum values read as fallback
	errs  []error
}

func (v *validator) fail(format string, args ...any) {
	v.errs = append(v.errs, fmt.Errorf(format, args...))
}

func (v *validator) err() error {
	if len(v.errs) == 0 {
		return nil
	}
	return fmt.Errorf("asset: %w", errors.Join(v.errs...))
}

func (v *validator) enum(path, val string, allowed any) {
	if val == "" {
		v.fail("%s is required", path)
		return
	}
	if enumContains(allowed, val) {
		return
	}
	if v.later && tokenPattern.MatchString(val) {
		return
	}
	v.fail("%s %q is not one of the 0.1 values", path, val)
}

func enumContains(allowed any, val string) bool {
	switch xs := allowed.(type) {
	case []string:
		return contains(xs, val)
	case []Confidence:
		return contains(xs, Confidence(val))
	case []EvidenceClass:
		return contains(xs, EvidenceClass(val))
	case []SourceMethod:
		return contains(xs, SourceMethod(val))
	case []Transport:
		return contains(xs, Transport(val))
	case []SecurityLevel:
		return contains(xs, SecurityLevel(val))
	case []BindingMethod:
		return contains(xs, BindingMethod(val))
	case []BindingStrength:
		return contains(xs, BindingStrength(val))
	case []SuspensionReason:
		return contains(xs, SuspensionReason(val))
	case []PostureCode:
		return contains(xs, PostureCode(val))
	case []AckScope:
		return contains(xs, AckScope(val))
	case []CapabilityName:
		return contains(xs, CapabilityName(val))
	case []Mechanism:
		return contains(xs, Mechanism(val))
	case []CapabilityStatus:
		return contains(xs, CapabilityStatus(val))
	}
	panic("asset: enumContains: unhandled type")
}

func contains[T comparable](xs []T, x T) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}
