package netobs

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"time"

	"otsec.local/otsec/contracts/version"
)

// Identifier is this contract's identifier, stamped on every record.
const Identifier = "otsec.netobs/0.1"

var self = version.ID{Name: "netobs", Major: 0, Minor: 1}

// Bounds (C13 §10).
const (
	// MaxChannelFrame bounds one framed record on the channel. A length
	// above it closes the channel (ErrFrameTooLarge).
	MaxChannelFrame = 64 << 10
	// MaxCitedFrames bounds the frames a citation lists.
	MaxCitedFrames = 8
	// MaxFrameBytes is the most bytes of one frame the sensor stores.
	MaxFrameBytes = 2048
	// MaxWireLen bounds a frame's wire_len, so the stored capture's
	// 32-bit orig_len can't wrap (C13 §3.2, §10; D3 on #553).
	MaxWireLen = 256 << 10
	// MaxTextBytes is the most original bytes a Text keeps, and
	// MaxTextEscaped the longest escaped value.
	MaxTextBytes   = 256
	MaxTextEscaped = 4 * MaxTextBytes
	// MaxCoverageBytes bounds a coverage statement encoded compact.
	MaxCoverageBytes = 2 << 10
	// MaxObjects bounds the DNP3 object headers of a function observation.
	MaxObjects = 16
	// MaxRedactions bounds the redactions in one cited frame. A frame with
	// more slots is covered as one slot-not-placed over that side's payload
	// (raised with D1 with this code).
	MaxRedactions = 16
	// MaxVLANs bounds coverage.vlans_seen, and MaxInterfaces
	// coverage.interfaces.
	MaxVLANs      = 64
	MaxInterfaces = 8
	// An alert cites at most MaxAlertFlows flows, each with at most
	// MaxAlertFramesPerFlow frames, and lists at most MaxRelated
	// observation event IDs.
	MaxAlertFlows         = 4
	MaxAlertFramesPerFlow = 2
	MaxRelated            = 32
	// MaxCaptureBytes is the largest capture an observation or an alert
	// stores: a classic pcap of MaxCitedFrames frames of MaxFrameBytes
	// (24-byte file header, 16-byte record headers).
	MaxCaptureBytes = 24 + MaxCitedFrames*(16+MaxFrameBytes)
	// ExplainMax bounds an alert's key_text, baseline_value and
	// observation, as C10's ExplainMax does.
	ExplainMax = 256
)

// Sensor settings carried in coverage.settings, and the detector's
// coalescing window (C13 §7.3, §10).
const (
	DefaultSAReplyTimeoutMS = 5000
	MinSAReplyTimeoutMS     = 1000
	MaxSAReplyTimeoutMS     = 30000

	DefaultMaxPendingDNP3 = 4096
	MinMaxPendingDNP3     = 256
	MaxMaxPendingDNP3     = 65536

	DefaultFlowIdleS = 60
	MinFlowIdleS     = 10
	MaxFlowIdleS     = 600

	DefaultCoalesceWindowS = 300
	MinCoalesceWindowS     = 60
	MaxCoalesceWindowS     = 3600
)

// Code is a validation failure. Closed.
type Code string

const (
	CodeSchema   Code = "schema"   // identifier missing, malformed, another contract, or a minor this reader does not know
	CodeDecode   Code = "decode"   // not one JSON object, an unknown or duplicate key, or a key in the wrong case
	CodeMissing  Code = "missing"  // a required field is absent
	CodeForm     Code = "form"     // a field's value is not in its form or its closed set
	CodeRange    Code = "range"    // a number or a size outside its bound
	CodeOrder    Code = "order"    // entries out of order, or repeated
	CodeConflict Code = "conflict" // fields that must agree do not
	CodeHash     Code = "hash"     // frame bytes do not match their cited hash, or a redaction was not applied
	CodeType     Code = "type"     // a channel record whose type the channel does not carry
)

// Error is one validation failure.
type Error struct {
	Code   Code
	Field  string
	Detail string
}

func (e *Error) Error() string {
	return fmt.Sprintf("netobs: %s: %s: %s", e.Field, e.Code, e.Detail)
}

// Codes returns the codes of every *Error in err, which may be a join.
func Codes(err error) []Code {
	var out []Code
	if ve, ok := err.(*Error); ok {
		return append(out, ve.Code)
	}
	if j, ok := err.(interface{ Unwrap() []error }); ok {
		for _, x := range j.Unwrap() {
			out = append(out, Codes(x)...)
		}
	}
	return out
}

type checker struct{ errs []error }

func (c *checker) fail(code Code, field, format string, a ...any) {
	c.errs = append(c.errs, &Error{Code: code, Field: field, Detail: fmt.Sprintf(format, a...)})
}

func (c *checker) err() error { return errors.Join(c.errs...) }

var (
	tokenForm   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:+-]{0,63}$`)
	uuidForm    = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	utcForm     = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$`)
	sha256Form  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	decimalForm = regexp.MustCompile(`^[1-9][0-9]{0,19}$`)
	tableForm   = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}/[1-9][0-9]{0,5}$`)
)

// ValidToken reports whether s is a C13 token: a sensor-supplied name that
// is never device text (C13 §2).
func ValidToken(s string) bool { return tokenForm.MatchString(s) }

// ValidUUID reports whether s is a lowercase UUID, the form of sensor_id,
// run_id and every asset ID C13 names: version 1 to 8 and variant 8, 9, a or
// b, the same form as C1's asset IDs and C2's invocation IDs (D5 on #549).
func ValidUUID(s string) bool { return uuidForm.MatchString(s) }

func (c *checker) token(field, s string) {
	if !ValidToken(s) {
		c.fail(CodeForm, field, "%q is not a token", s)
	}
}

// table checks a class table's name and version, such as "fc-classes/1".
func (c *checker) table(field, s string) {
	if !tableForm.MatchString(s) {
		c.fail(CodeForm, field, "%q is not <table>/<version>", s)
	}
}

func (c *checker) uuid(field, s string) {
	if !ValidUUID(s) {
		c.fail(CodeForm, field, "%q is not a lowercase UUID", s)
	}
}

func (c *checker) sha256(field, s string) {
	if !sha256Form.MatchString(s) {
		c.fail(CodeForm, field, "%q is not a lowercase hex SHA-256", s)
	}
}

// utc parses an RFC 3339 UTC time with a Z suffix and at most nine
// fractional digits, or fails c.
func (c *checker) utc(field, s string) (time.Time, bool) {
	if s == "" {
		c.fail(CodeMissing, field, "required")
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if !utcForm.MatchString(s) || err != nil {
		c.fail(CodeForm, field, "%q is not RFC 3339 UTC with Z", s)
		return time.Time{}, false
	}
	return t, true
}

// seq parses a record's seq: a decimal from 1, with no leading zero, that
// fits a uint64.
func (c *checker) seq(field, s string) uint64 {
	n, err := strconv.ParseUint(s, 10, 64)
	if !decimalForm.MatchString(s) || err != nil {
		c.fail(CodeForm, field, "%q is not a decimal from 1", s)
		return 0
	}
	return n
}

// addr parses an IP address in the canonical form netip.Addr.String gives,
// unmapped and with no zone, as the sensor reads it from the IP header.
func (c *checker) addr(field, s string) (netip.Addr, bool) {
	a, err := netip.ParseAddr(s)
	if err != nil || a.String() != s || a.Is4In6() || a.Zone() != "" {
		c.fail(CodeForm, field, "%q is not a canonical IP address", s)
		return netip.Addr{}, false
	}
	return a, true
}

// strictSchema checks a channel record's schema. C13 is strict: a minor
// this reader does not know refuses the record (C13 §1).
func (c *checker) strictSchema(s string) {
	if s != Identifier {
		c.fail(CodeSchema, "schema", "%q is not %s", s, Identifier)
	}
}

// storedSchema checks a stored record's schema: any 0.x minor, because a
// stored record written by a later node is read forward (contracts/README.md).
func (c *checker) storedSchema(s string) {
	got, err := version.Parse(s)
	if err != nil || !self.Accepts(got) {
		c.fail(CodeSchema, "schema", "%q is not %s or another 0.x minor of it", s, Identifier)
	}
}

func contains[T comparable](list []T, v T) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
