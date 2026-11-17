package netobs

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"time"

	"otsec.local/otsec/contracts/version"
)

// Identifier is C13 0.1's identifier: the identifier of the records on the
// 0.1 channel, the one main's intake reads (DecodeChannel), and of the
// alerts the detector stamps today. It stays 0.1 until the C13 0.2 intake
// brief moves the channel to 0.2 under CH-36 (D4-103 ruling 2), so that no
// intermediate main breaks that intake or its tests.
const Identifier = "otsec.netobs/0.1"

// Identifier02 is C13 0.2's identifier, carried by every message and record
// of a 0.2 connection (DecodeFromSensorIn, DecodeFromNode; C13 0.2 §1), and
// by the node's two messages at 0.3 too (NodeHello.Validate). The stored
// readers read 0.1, 0.2 and 0.3 strictly, and a later 0.x minor forward.
const Identifier02 = "otsec.netobs/0.2"

// Identifier03 is C13 0.3's identifier (docs/phase4/D4-c13-0.3-proposal.md,
// approved in D4-102), the minor a 0.3 sensor offers on the channel. A 0.3
// node also knows 0.2 on the channel, so that it can drain a 0.2 sensor's
// buffered runs (C13 0.3 §1.1, CH-36).
const Identifier03 = "otsec.netobs/0.3"

// channelIdentifiers are the channel minors this code knows (CH-36).
var channelIdentifiers = []string{Identifier02, Identifier03}

var self = version.ID{Name: "netobs", Major: 0, Minor: 3}

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

	// coverage.settings.prp_window_ms, new in 0.2 (CH-28).
	DefaultPRPWindowMS = 400
	MinPRPWindowMS     = 10
	MaxPRPWindowMS     = 2000
)

// C13 0.2's bounds that the channel's pure checks use (C13 0.2 §12).
const (
	// MaxNodeMessage bounds a frame from the node: the agent closes on a
	// longer one (frame-too-large, CH-2).
	MaxNodeMessage = 1 << 10
	// MaxLostSpans bounds each lost list (CH-40).
	MaxLostSpans = 8
	// sensor-hello's buffer_bytes is from MinBufferBytes to MaxBufferBytes
	// on the wire; below SiteBufferFloor the node raises sensor-buffer-small
	// and does not close (CH-7, CH-13 row 9, CH-20).
	MinBufferBytes  = 16 << 20
	MaxBufferBytes  = 64 << 30
	SiteBufferFloor = 256 << 20
	// TickMinSpacing: an accepted tick less than this after the previous
	// one on the connection, other than the first after the hello, is
	// tick_early and does nothing more (CH-8).
	TickMinSpacing = 5 * time.Second
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

// checker collects a validation's failures. minor is the record's minor,
// set by strictSchema and storedSchema, so that a field new in 0.2 is
// refused in a 0.1 record, and one new in 0.3 in a 0.1 or 0.2 record.
// later is set by storedSchema when the record is of a later 0.x minor
// than this reader's, so the bridge rules of CH-35 (C13 0.2 §11) read it
// forward. need is the channel minor whose required fields a channel
// record must carry, 0 for a stored record (C13 0.2 §11, C13 0.3 §1.1:
// optional in the Go type and in a stored record, required on the channel
// of their minor and later). keys holds a decoded document's key paths
// (keyPaths), nil when a Go value is validated. nulls holds the paths of
// those keys whose value is null (docPaths), set only for a record read
// from a sensor on the 0.2 or 0.3 channel.
type checker struct {
	errs  []error
	minor int
	later bool
	need  int
	keys  map[string]bool
	nulls map[string]bool
}

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

// strictSchema checks a channel record's schema against want, the
// connection's minor. C13 is strict: another minor refuses the record (C13
// §1; C13 0.2 CH-36).
func (c *checker) strictSchema(s, want string) {
	c.minor = 1
	if v, err := version.Parse(want); err == nil && v.Minor >= 2 {
		c.minor, c.need = v.Minor, v.Minor
	}
	if s != want {
		c.fail(CodeSchema, "schema", "%q is not %s", s, want)
	}
}

// channelSchema checks a sensor message's schema: one of the channel
// minors this code knows, read strictly at that minor (CH-36).
func (c *checker) channelSchema(s string) {
	if contains(channelIdentifiers, s) {
		c.strictSchema(s, s)
		return
	}
	c.strictSchema(Identifier03, Identifier03)
	c.fail(CodeSchema, "schema", "%q is not a channel minor this code knows, %v", s, channelIdentifiers)
}

// storedSchema checks a stored record's schema: any 0.x minor, because a
// stored record written by a later node is read forward (contracts/README.md).
func (c *checker) storedSchema(s string) {
	got, err := version.Parse(s)
	if err != nil || !self.Accepts(got) {
		c.fail(CodeSchema, "schema", "%q is not %s or another 0.x minor of it", s, Identifier02)
		return
	}
	c.minor = got.Minor
	c.later = got.Minor > self.Minor
}

// new02 checks a field that C13 0.2 adds (C13 0.2 §11). In a record of a
// minor below 0.2 it must be absent, so a 0.1 record stays as strict as
// the 0.1 reader was (D4-103 ruling 2). In a 0.2 channel record it must be
// present.
func (c *checker) new02(field string, set bool) bool {
	return c.newAt(2, field, set)
}

// new03 checks a field that C13 0.3 adds (C13 0.3 §1.1), as new02 does for
// 0.2: refused below 0.3, required on the 0.3 channel.
func (c *checker) new03(field string, set bool) bool {
	return c.newAt(3, field, set)
}

// newAt checks a field new in the given minor. The field is present when
// set holds (its Go value is not the zero value) or when its key is in the
// decoded document, whatever its value ("", 0, false, null). newAt reports
// whether the field's value is to be checked: present, and not already
// refused as new.
func (c *checker) newAt(minor int, field string, set bool) bool {
	present := set || c.keys[field]
	switch {
	case present && c.minor < minor:
		c.fail(CodeDecode, field, "new in otsec.netobs/0.%d; not in a 0.%d record", minor, c.minor)
		return false
	case !present && c.need >= minor:
		c.fail(CodeMissing, field, "required in an otsec.netobs/0.%d channel record", c.need)
	}
	return present
}

// null refuses a key whose value was null: its pointer field is nil while
// its key is in the document. Such a key is never read as absent.
func (c *checker) null(field string, isNil bool) {
	if isNil && c.keys[field] {
		c.fail(CodeForm, field, "null is not a value")
	}
}

// keyPaths lists every key of a JSON document by its path in the checker's
// field form ("coverage.settings.prp_window_ms", "windows[0].coverage").
// It is called only on a document strictjson has read, so no key repeats.
func keyPaths(b []byte) map[string]bool {
	keys, _ := docPaths(b)
	return keys
}

// docPaths is keyPaths, and also the paths of the keys whose value is
// null. A null decodes into a plain count as 0, so only this set tells the
// two apart.
func docPaths(b []byte) (keys, nulls map[string]bool) {
	var doc any
	if json.Unmarshal(b, &doc) != nil {
		return nil, nil
	}
	out, nulls := map[string]bool{}, map[string]bool{}
	var walk func(path string, v any)
	walk = func(path string, v any) {
		switch x := v.(type) {
		case map[string]any:
			for k, e := range x {
				p := k
				if path != "" {
					p = path + "." + k
				}
				out[p] = true
				if e == nil {
					nulls[p] = true
				}
				walk(p, e)
			}
		case []any:
			for i, e := range x {
				walk(fmt.Sprintf("%s[%d]", path, i), e)
			}
		}
	}
	walk("", doc)
	return out, nulls
}

// decimal parses a C13 0.2 number written "decimal from 1" (from1) or
// "decimal from 0": no leading zero, at most 2^64 - 1 (CH-5).
func (c *checker) decimal(field, s string, from1 bool) uint64 {
	n, err := strconv.ParseUint(s, 10, 64)
	switch {
	case err != nil || strconv.FormatUint(n, 10) != s:
		c.fail(CodeForm, field, "%q is not a decimal", s)
	case from1 && n == 0:
		c.fail(CodeForm, field, "%q is not a decimal from 1", s)
	}
	return n
}

func contains[T comparable](list []T, v T) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
