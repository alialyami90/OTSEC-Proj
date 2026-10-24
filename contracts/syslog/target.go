package syslog

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"otsec.local/otsec/contracts/audit"
	"otsec.local/otsec/contracts/authz"
	"otsec.local/otsec/contracts/internal/strictjson"
	"otsec.local/otsec/contracts/version"
)

// Identifier is the contract identifier carried in every target.
const Identifier = "otsec.syslog/0.1"

// Target is one upstream collector.
type Target struct {
	Schema    string    `json:"schema"`
	Name      string    `json:"name"`
	Host      string    `json:"host"`
	Port      int       `json:"port"`
	Transport Transport `json:"transport"`
	Format    Format    `json:"format"`
	Framing   Framing   `json:"framing"`
	Class     Class     `json:"class"`
	// MaxMessageOctets bounds the rendered message (without framing).
	MaxMessageOctets int `json:"max_message_octets"`
	// Facility is the Syslog facility, 0 to 23.
	Facility int        `json:"facility"`
	TLS      *TLSConfig `json:"tls,omitempty"`
	// RELPWindow bounds frames in flight in mode A.
	RELPWindow int `json:"relp_window,omitempty"`
	// ReplaySeconds is the mode B replay window (ADR-0004 items 5 and 6): on
	// every reconnect the forwarder re-sends the events committed in the last
	// ReplaySeconds seconds. The C5 consumer for this target has the same
	// window, so those events are never pruned before the replay.
	ReplaySeconds int `json:"replay_seconds,omitempty"`
	// Audit is set when the target also carries the node's C8 audit stream.
	// Only a required relp-tls target in RFC 5424 with room for a whole
	// sealed record may (A1 D1-15): an audit consumer is always required,
	// and audit is pruned only after a RELP acknowledgement.
	Audit bool `json:"audit,omitempty"`
	// DurableAck records the commissioning check that a required target's
	// collector acknowledges only after the message is durably written
	// (C6-A6-1). Required when class is required.
	DurableAck *DurableAck `json:"durable_ack,omitempty"`
	// Acknowledgement is an admin's acceptance of an insecure target (tcp,
	// udp, plain relp), required on those and refused on the others (A1
	// D1-22). It covers the target as configured, device_content included.
	// Setting or changing it is a C8 audit record.
	Acknowledgement *Acknowledgement `json:"acknowledgement,omitempty"`
	// DeviceContent says whether messages carry what is derived from the
	// device record: its bytes (dtext), the normalized subject, subject
	// type, value, category and mapping, and the MSG summary. Absent means
	// on for relp-tls and tls, off for insecure transports, so which
	// element operated never crosses an unencrypted link unless an admin
	// chose it (D1-22 and its amendment). With it off, the event's kind,
	// asset, times, severity and record hash are still sent; the message
	// carries content_omitted="config", and the omission is reported once,
	// in the target's state and audit record.
	DeviceContent *bool `json:"device_content,omitempty"`
}

// Acknowledgement has the shape of C1's insecure-endpoint acknowledgement.
// TODO(C1): use asset.Acknowledgement once contracts/asset merges.
type Acknowledgement struct {
	By     string   `json:"by"` // a C7 human principal ID
	At     string   `json:"at"` // RFC 3339 UTC with Z
	Reason string   `json:"reason"`
	Scope  AckScope `json:"scope"`
}

// AckScope is where an insecure target is accepted. 0.1 has one value, as
// in C1 (ADR-0005); a production scope needs an owner decision and a later
// minor.
type AckScope string

const LabOnly AckScope = "lab-only"

// SendsDeviceContent reports whether messages to t carry device content.
func (t *Target) SendsDeviceContent() bool {
	if t.DeviceContent != nil {
		return *t.DeviceContent
	}
	return !t.Insecure()
}

// DurableAck is the result of the commissioning check of a required
// target: a numbered burst is sent, the collector is killed after it
// acknowledges and restarted, and every acknowledged message is found
// stored. The reference configuration is the one E-A4-03 trial 2 passed
// (rsyslog imrelp with Direct queues and confirmMessages on). A collector
// with in-memory queues lost 1,471 of 1,500 acknowledged messages in trial
// 1, so without this check a required target could let C5 prune records
// that exist nowhere else (V-S9). The check runs against the real
// collector, because the result depends on its configuration (A6 V-S6).
type DurableAck struct {
	// VerifiedUTC is when the check passed, RFC 3339 UTC with Z.
	VerifiedUTC string `json:"verified_utc"`
	// EvidenceRef names the stored record of the check.
	EvidenceRef string `json:"evidence_ref"`
}

// Transport is closed.
type Transport string

const (
	TransportRELPTLS Transport = "relp-tls" // RELP over TLS: mode A; the only transport allowed as required
	TransportRELP    Transport = "relp"     // plain RELP: mode A acks, but forgeable on the path; best-effort, insecure
	TransportTLS     Transport = "tls"      // RFC 5425: mode B, best-effort
	TransportTCP     Transport = "tcp"      // RFC 6587: mode B, best-effort, insecure
	TransportUDP     Transport = "udp"      // RFC 5426: mode B, best-effort, insecure; loss invisible to both ends
)

// Format is closed.
type Format string

const (
	FormatRFC5424 Format = "rfc5424"
	FormatRFC3164 Format = "rfc3164" // RFC 3164-compatible rendering; fields travel as SD text inside MSG
)

// Framing is closed.
type Framing string

const (
	FramingOctetCounting  Framing = "octet-counting"  // RFC 6587 3.4.1; required for tls
	FramingNonTransparent Framing = "non-transparent" // RFC 6587 3.4.2, LF trailer; tcp only
	FramingDatagram       Framing = "datagram"        // udp: one message per datagram
	FramingRELP           Framing = "relp"            // relp, relp-tls: RELP frames carry the length
)

// Class is closed. Pruning waits only for required targets (ADR-0004 item 6).
type Class string

const (
	ClassRequired   Class = "required"
	ClassBestEffort Class = "best-effort"
)

// Mode is derived from the transport.
type Mode string

const (
	ModeA Mode = "A" // acknowledged: the cursor advances on RELP 200 OK
	ModeB Mode = "B" // unacknowledged: replay window on reconnect
)

// TLSConfig names the server to verify and the node's client key.
//
// Every TLS target verifies the collector (TB5, SC-16): TLS 1.2 or later
// (MinTLSVersion), the certificate chain against TrustAnchorRef, and the
// host name against ServerName. A failure closes the connection; nothing
// falls back to plaintext and no verification step is ever skipped.
// TrustAnchorRef names a CA set used only for this platform's collectors;
// when a broader set is unavoidable, SPKIPins pins the collector's key and
// anything else is refused, so no other certificate for ServerName can act
// as the collector and acknowledge events into pruning (AP-9).
type TLSConfig struct {
	// ServerName is verified against the collector's certificate.
	ServerName string `json:"server_name"`
	// TrustAnchorRef names the CA set that verifies the collector.
	// TODO(A3 node key ref): not a C7 CredentialRef, which is a device
	// credential held by the collector service (C6-A3-4).
	TrustAnchorRef string `json:"trust_anchor_ref"`
	// SPKIPins are base64 SHA-256 hashes of the collector's
	// SubjectPublicKeyInfo. When set, the collector's key must match one.
	SPKIPins []string `json:"spki_sha256,omitempty"`
	// ClientCredentialRef names the node's TLS client key, so the collector
	// can refuse a stream that is not from an enrolled node. Required on
	// required and audit targets (C6-A3-2); recommended on every tls target.
	// TODO(A3 node key ref): a non-exportable key in the node service's
	// store, not a C7 CredentialRef.
	ClientCredentialRef string `json:"client_credential_ref,omitempty"`
}

// MinTLSVersion is the lowest TLS version a target may negotiate.
const MinTLSVersion = "1.2"

// Size limits. RFC 5425 receivers must accept 2048 octets; RFC 5426 sets
// 480 (IPv4) and 1180 (IPv6) as the floors when the path is unknown; RFC
// 3164 caps messages at 1024.
const (
	DefaultMaxOctets = 2048
	MinMaxOctets     = 480
	MaxMaxOctets     = 65535
	MaxOctets3164    = 1024
	MaxUDPOctets     = 65507
	DefaultFacility  = 16 // local0
	MaxReplaySeconds = 7 * 24 * 3600

	// MinAuditOctets is the smallest max_message_octets of an audit target:
	// a whole sealed record plus room for the header and the SD element
	// that carries node, seq and hash.
	MinAuditOctets = audit.MaxRecordBytes + 1024
)

// Mode returns the delivery mode of the target's transport.
func (t *Target) Mode() Mode {
	if t.Transport == TransportRELPTLS || t.Transport == TransportRELP {
		return ModeA
	}
	return ModeB
}

// Insecure reports whether the transport has no confidentiality or
// integrity. Every place a target is shown must label it.
func (t *Target) Insecure() bool {
	return t.Transport == TransportTCP || t.Transport == TransportUDP || t.Transport == TransportRELP
}

// Code is a validation failure. Closed list.
type Code string

const (
	CodeSchema        Code = "schema"          // identifier missing, malformed, or another contract or major
	CodeUnknownField  Code = "unknown-field"   // targets are strict: unknown, duplicate or case-variant key
	CodeEnum          Code = "enum"            // value outside a closed enum
	CodeRequiredClass Code = "required-class"  // required on a transport other than relp-tls
	CodeFraming       Code = "framing"         // framing not allowed for the transport
	CodeSize          Code = "size"            // size limit outside the allowed range
	CodeTLS           Code = "tls"             // TLS settings missing or present where they do not apply
	CodeDelivery      Code = "delivery"        // RELP window or replay window missing or out of range
	CodeField         Code = "field"           // name, host, port or facility invalid
	CodeTooLarge      Code = "too-large"       // fixed fields alone exceed the size limit (Render)
	CodeFrameUnsafe   Code = "frame-unsafe"    // LF or NUL in a message for non-transparent framing (Frame)
	CodeRELPViolation Code = "relp-violation"  // inbound bytes outside the TB5 grammar (ParseRELPResponse)
	CodeEventInvalid  Code = "event-invalid"   // the C4 event failed its own validation (Render)
	CodeAudit         Code = "audit"           // audit on a target that is not required relp-tls RFC 5424 with room for a record (D1-15)
	CodeAck           Code = "acknowledgement" // an insecure target without a complete acknowledgement, or a secure one with one (D1-22)
)

// Error is one validation failure.
type Error struct {
	Code   Code
	Field  string
	Detail string
}

func (e *Error) Error() string { return fmt.Sprintf("syslog: %s: %s: %s", e.Field, e.Code, e.Detail) }

// Codes returns the codes of every *Error in err, which may be a join.
func Codes(err error) []Code {
	if ve, ok := err.(*Error); ok {
		return []Code{ve.Code}
	}
	var out []Code
	if j, ok := err.(interface{ Unwrap() []error }); ok {
		for _, x := range j.Unwrap() {
			out = append(out, Codes(x)...)
		}
	}
	return out
}

var (
	self        = version.ID{Name: "syslog", Major: 0, Minor: 1}
	namePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	refPattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$`)
	pinPattern  = regexp.MustCompile(`^[A-Za-z0-9+/]{43}=$`)
	hostPattern = regexp.MustCompile(`^[A-Za-z0-9.:\[\]-]{1,253}$`)
)

// ParseTarget decodes a target strictly with contracts/internal/strictjson
// (unknown fields, duplicate keys, case variants and trailing data are
// rejected, A1 D1-10) and validates it.
func ParseTarget(b []byte) (*Target, error) {
	var t Target
	if err := strictjson.Decode(b, &t); err != nil {
		return nil, &Error{Code: CodeUnknownField, Field: "target", Detail: err.Error()}
	}
	return &t, t.Validate()
}

// Validate checks every rule of the contract that applies to one target.
func (t *Target) Validate() error {
	var errs []error
	fail := func(code Code, field, format string, a ...any) {
		errs = append(errs, &Error{Code: code, Field: field, Detail: fmt.Sprintf(format, a...)})
	}
	if got, err := version.Parse(t.Schema); err != nil || !self.Accepts(got) {
		fail(CodeSchema, "schema", "%q is not an otsec.syslog/0.x identifier", t.Schema)
	}
	if !namePattern.MatchString(t.Name) {
		fail(CodeField, "name", "%q", t.Name)
	}
	if !hostPattern.MatchString(t.Host) {
		fail(CodeField, "host", "%q", t.Host)
	}
	if t.Port < 1 || t.Port > 65535 {
		fail(CodeField, "port", "%d", t.Port)
	}
	if t.Facility < 0 || t.Facility > 23 {
		fail(CodeField, "facility", "%d is not 0 to 23", t.Facility)
	}
	known := true
	switch t.Transport {
	case TransportRELPTLS, TransportRELP, TransportTLS, TransportTCP, TransportUDP:
	default:
		known = false
		fail(CodeEnum, "transport", "%q", t.Transport)
	}
	if t.Format != FormatRFC5424 && t.Format != FormatRFC3164 {
		fail(CodeEnum, "format", "%q", t.Format)
	}
	switch t.Class {
	case ClassRequired:
		if t.Transport != TransportRELPTLS {
			fail(CodeRequiredClass, "class", "only relp-tls may be required; %q cannot confirm delivery against a forged or lost acknowledgement", t.Transport)
		}
	case ClassBestEffort:
	default:
		fail(CodeEnum, "class", "%q", t.Class)
	}
	if known {
		allowed := map[Transport][]Framing{
			TransportRELPTLS: {FramingRELP},
			TransportRELP:    {FramingRELP},
			TransportTLS:     {FramingOctetCounting},
			TransportTCP:     {FramingOctetCounting, FramingNonTransparent},
			TransportUDP:     {FramingDatagram},
		}[t.Transport]
		ok := false
		for _, f := range allowed {
			ok = ok || f == t.Framing
		}
		if !ok {
			fail(CodeFraming, "framing", "%q is not allowed on %q (allowed: %v)", t.Framing, t.Transport, allowed)
		}
	}
	max := MaxMaxOctets
	switch {
	case t.Format == FormatRFC3164:
		max = MaxOctets3164
	case t.Transport == TransportUDP:
		max = MaxUDPOctets
	}
	if t.MaxMessageOctets < MinMaxOctets || t.MaxMessageOctets > max {
		fail(CodeSize, "max_message_octets", "%d is outside %d to %d", t.MaxMessageOctets, MinMaxOctets, max)
	}
	if t.Audit {
		switch {
		case t.Transport != TransportRELPTLS:
			fail(CodeAudit, "audit", "audit goes only to relp-tls targets; %q gives no acknowledgement that a record or checkpoint arrived (D1-15)", t.Transport)
		case t.Class != ClassRequired:
			fail(CodeAudit, "audit", "an audit target is always required (D1-15)")
		case t.Format != FormatRFC5424:
			fail(CodeAudit, "audit", "audit records travel in the RFC 5424 MSG part")
		case t.MaxMessageOctets < MinAuditOctets:
			fail(CodeAudit, "audit", "max_message_octets %d cannot hold a whole sealed record; at least %d", t.MaxMessageOctets, MinAuditOctets)
		}
	}
	usesTLS := t.Transport == TransportRELPTLS || t.Transport == TransportTLS
	switch {
	case usesTLS && (t.TLS == nil || t.TLS.ServerName == "" || t.TLS.TrustAnchorRef == ""):
		fail(CodeTLS, "tls", "%q needs server_name and trust_anchor_ref", t.Transport)
	case !usesTLS && t.TLS != nil && known:
		fail(CodeTLS, "tls", "%q does not use TLS", t.Transport)
	}
	if usesTLS && t.TLS != nil {
		for i, p := range t.TLS.SPKIPins {
			if !pinPattern.MatchString(p) {
				fail(CodeTLS, fmt.Sprintf("tls.spki_sha256[%d]", i), "%q is not a base64 SHA-256", p)
			}
		}
		if (t.Class == ClassRequired || t.Audit) && t.TLS.ClientCredentialRef == "" {
			fail(CodeTLS, "tls.client_credential_ref", "required and audit targets authenticate the node with mutual TLS, so no one else can write to the collector (C6-A3-2)")
		}
	}
	if known {
		a := t.Acknowledgement
		switch {
		case !t.Insecure() && a != nil:
			fail(CodeAck, "acknowledgement", "%q is not insecure; nothing to acknowledge", t.Transport)
		case t.Insecure() && (a == nil || (authz.Principal{Type: authz.PrincipalHuman, ID: a.By}).Validate() != nil || !utcZ(a.At) || strings.TrimSpace(a.Reason) == ""):
			fail(CodeAck, "acknowledgement", "%q sends in clear text and needs an acknowledgement with by, at, reason and scope (D1-22)", t.Transport)
		case t.Insecure() && a.Scope != LabOnly:
			fail(CodeAck, "acknowledgement.scope", "%q: 0.1 accepts an insecure target for lab-only", a.Scope)
		}
	}
	if t.Class == ClassRequired {
		d := t.DurableAck
		switch {
		case d == nil:
			fail(CodeDelivery, "durable_ack", "a required target needs a passed durable-acknowledgement check, or C5 may prune what the collector lost (C6-A6-1)")
		case !utcZ(d.VerifiedUTC) || !refPattern.MatchString(d.EvidenceRef):
			fail(CodeDelivery, "durable_ack", "verified_utc must be RFC 3339 UTC with Z and evidence_ref a reference")
		}
	} else if t.DurableAck != nil {
		fail(CodeDelivery, "durable_ack", "only a required target records a durable-acknowledgement check")
	}
	if known {
		if t.Mode() == ModeA {
			if t.RELPWindow < 1 || t.RELPWindow > 1024 {
				fail(CodeDelivery, "relp_window", "mode A needs a window of 1 to 1024 frames")
			}
			if t.ReplaySeconds != 0 {
				fail(CodeDelivery, "replay_seconds", "mode A advances on acknowledgements, not a replay window")
			}
		} else {
			if t.ReplaySeconds < 1 || t.ReplaySeconds > MaxReplaySeconds {
				fail(CodeDelivery, "replay_seconds", "mode B needs a replay window of 1 to %d seconds", MaxReplaySeconds)
			}
			if t.RELPWindow != 0 {
				fail(CodeDelivery, "relp_window", "only RELP targets have a RELP window")
			}
		}
	}
	return errors.Join(errs...)
}

func utcZ(s string) bool {
	t, err := time.Parse(time.RFC3339Nano, s)
	return err == nil && t.Location() == time.UTC && strings.HasSuffix(s, "Z")
}
