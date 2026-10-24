package event

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"otsec.local/otsec/contracts/version"
)

// Code is a validation failure. Closed list.
type Code string

const (
	CodeSchema             Code = "schema"              // schema identifier missing, malformed or another contract/major
	CodeID                 Code = "id"                  // node ID, stream or seq invalid
	CodeEnum               Code = "enum"                // value outside a closed enum, or malformed open-set token
	CodeMissing            Code = "missing"             // required field absent
	CodeForbidden          Code = "forbidden"           // field present where the contract forbids it
	CodeTimeFormat         Code = "time-format"         // a time string not in its required form
	CodePrecision          Code = "precision"           // a time claims more fractional digits than its resolution
	CodeOffset             Code = "offset"              // offset and UTC inconsistent, or UTC without a known offset
	CodeEvidence           Code = "evidence"            // native bytes, hashes, lengths or span inconsistent
	CodeUnjustifiedMeaning Code = "unjustified-meaning" // a category without the mapping that assigned it
)

// Error is one validation failure.
type Error struct {
	Code   Code
	Field  string
	Detail string
}

func (e *Error) Error() string { return fmt.Sprintf("event: %s: %s: %s", e.Field, e.Code, e.Detail) }

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

var (
	hexSHA256      = regexp.MustCompile(`^[0-9a-f]{64}$`)
	alignKeyFormat = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	wallClockForm  = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.(\d{1,9}))?$`)
	utcForm        = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.(\d{1,9}))?Z$`)
	offsetForm     = regexp.MustCompile(`^([+-])(0\d|1[0-4]):([0-5]\d)$`)
	hexForm        = regexp.MustCompile(`^(?:[0-9a-f]{2})+$`)
)

var self = version.ID{Name: "event", Major: 0, Minor: 1}

// Validate checks every rule of the contract that can be checked on one
// event. It returns nil or a join of *Error values.
func (e *Event) Validate() error {
	c := &checker{}
	if got, err := version.Parse(e.Schema); err != nil || !self.Accepts(got) {
		c.fail(CodeSchema, "schema", "%q is not an otsec.event/0.x identifier", e.Schema)
	}
	if !e.ID.NodeID.Valid() {
		c.fail(CodeID, "id.node_id", "%q is not a lowercase DNS label", e.ID.NodeID)
	}
	if !e.ID.Stream.Valid() {
		c.fail(CodeID, "id.stream", "%q is not a stream token", e.ID.Stream)
	}
	if e.ID.Seq == 0 {
		c.fail(CodeID, "id.seq", "seq starts at 1")
	}
	if !tokenPattern.MatchString(string(e.Kind)) {
		c.fail(CodeEnum, "kind", "%q is not a kind token", e.Kind)
	}
	for i, f := range e.Flags {
		checkFlag(c, fmt.Sprintf("flags[%d]", i), f)
	}
	checkReceived(c, &e.Received)
	switch e.Origin {
	case OriginDevice:
		checkDeviceEvent(c, e)
	case OriginPlatform:
		checkPlatformEvent(c, e)
	default:
		c.fail(CodeEnum, "origin", "%q is not device or platform", e.Origin)
	}
	return errors.Join(c.errs...)
}

func checkFlag(c *checker, field, f string) {
	name, _, _ := strings.Cut(f, ":")
	if !tokenPattern.MatchString(name) || strings.ContainsAny(f, "\x00\n\r") {
		c.fail(CodeEnum, field, "%q is not a flag token", f)
	}
}

func checkReceived(c *checker, r *Received) {
	if r.ResolutionNS <= 0 {
		c.fail(CodeMissing, "received.resolution_ns", "must be positive")
	}
	checkUTC(c, "received.utc", r.UTC, r.ResolutionNS, true)
	if !oneOf(r.Clock.Sync, SyncSynchronized, SyncUnsynchronized, SyncUnknown) {
		c.fail(CodeEnum, "received.clock.sync", "%q", r.Clock.Sync)
	}
}

func checkDeviceEvent(c *checker, e *Event) {
	s := &e.Source
	if !oneOf(s.OriginAuth, AuthNone, AuthTLSServerOnly, AuthTLSMutual, AuthSession) {
		c.fail(CodeEnum, "source.origin_auth", "%q is not valid for a device event", s.OriginAuth)
	}
	if s.Asset == nil && s.Sender == nil {
		c.fail(CodeMissing, "source", "a device event names its asset, its sender, or both")
	}
	if s.Asset == nil && !contains(e.Flags, "asset-unresolved") {
		c.fail(CodeMissing, "flags", "an event without an asset carries asset-unresolved")
	}
	if s.Asset != nil {
		checkAsset(c, s.Asset)
	}
	if s.Sender != nil && strings.TrimSpace(s.Sender.Address) == "" {
		c.fail(CodeMissing, "source.sender.address", "empty")
	}
	if e.Health != nil {
		c.fail(CodeForbidden, "health", "only platform events carry health")
	}
	if e.Collection == nil {
		c.fail(CodeMissing, "collection", "required on device events")
	} else {
		checkCollection(c, e.Collection)
	}
	if e.Native == nil {
		c.fail(CodeMissing, "native", "device events keep their native evidence (EP-1)")
	} else {
		checkNative(c, e.Native)
	}
	if e.DeviceTime != nil {
		checkDeviceTime(c, e.DeviceTime)
	}
	if e.Normalized != nil {
		checkNormalized(c, e.Normalized)
		if e.Collection != nil && e.Collection.ParseStatus == ParseFailed {
			c.fail(CodeForbidden, "normalized", "a failed parse has no normalized form")
		}
	}
}

func checkPlatformEvent(c *checker, e *Event) {
	if e.Source.OriginAuth != AuthPlatform {
		c.fail(CodeEnum, "source.origin_auth", "platform events use %q", AuthPlatform)
	}
	if e.Source.Asset != nil {
		checkAsset(c, e.Source.Asset)
	}
	if e.Native != nil || e.DeviceTime != nil || e.Collection != nil {
		c.fail(CodeForbidden, "native/device_time/collection", "platform events carry no device record")
	}
	if e.Kind == KindHealth {
		if e.Health == nil {
			c.fail(CodeMissing, "health", "required on telemetry-health events")
		} else {
			if !tokenPattern.MatchString(e.Health.Type) {
				c.fail(CodeEnum, "health.type", "%q is not a health type token", e.Health.Type)
			}
			for i, r := range e.Health.Related {
				if !r.NodeID.Valid() || !r.Stream.Valid() || r.Seq == 0 {
					c.fail(CodeID, fmt.Sprintf("health.related[%d]", i), "%v is not a valid event ID", r)
				}
			}
		}
	}
	if e.Normalized != nil {
		checkNormalized(c, e.Normalized)
	}
}

func checkAsset(c *checker, a *AssetRef) {
	if !assetIDPattern.MatchString(a.ID) {
		c.fail(CodeID, "source.asset.id", "%q is not an asset ID", a.ID)
	}
	if !oneOf(a.Binding.Method, BindAdapterTarget, BindSenderAddress, BindContentField, BindOperator) {
		c.fail(CodeEnum, "source.asset.binding.method", "%q", a.Binding.Method)
	}
	if !oneOf(a.Binding.Confidence, ConfidenceConfigured, ConfidenceAsserted, ConfidenceInferred) {
		c.fail(CodeEnum, "source.asset.binding.confidence", "%q", a.Binding.Confidence)
	}
	if a.Binding.Method == BindContentField && a.Binding.Confidence == ConfidenceConfigured {
		c.fail(CodeEnum, "source.asset.binding.confidence", "a subject named by the content is asserted or inferred, never configured (AP-22)")
	}
}

func checkCollection(c *checker, col *Collection) {
	if !oneOf(col.Method, MethodAdapterPoll, MethodSyslogReceive, MethodHostPush) {
		c.fail(CodeEnum, "collection.method", "%q", col.Method)
	}
	if !oneOf(col.ParseStatus, ParseOK, ParsePartial, ParseFailed) {
		c.fail(CodeEnum, "collection.parse_status", "%q", col.ParseStatus)
	}
	if col.Alignment != "" && !oneOf(col.Alignment, AlignFirstRead, AlignOK, AlignGapBefore, AlignPossibleDuplicate) {
		c.fail(CodeEnum, "collection.alignment", "%q", col.Alignment)
	}
	if col.Parser != nil && (col.Parser.Name == "" || col.Parser.Version == "") {
		c.fail(CodeMissing, "collection.parser", "name and version are both required")
	}
}

func checkNative(c *checker, n *Native) {
	if !hexSHA256.MatchString(n.RecordSHA256) {
		c.fail(CodeEvidence, "native.record_sha256", "not lowercase hex SHA-256")
	}
	if n.RecordLength < 0 {
		c.fail(CodeEvidence, "native.record_length", "negative")
	}
	if n.Bytes != nil {
		sum := sha256.Sum256(n.Bytes)
		if hex.EncodeToString(sum[:]) != n.RecordSHA256 {
			c.fail(CodeEvidence, "native.bytes", "SHA-256 does not match record_sha256")
		}
		if int64(len(n.Bytes)) != n.RecordLength {
			c.fail(CodeEvidence, "native.bytes", "length %d does not match record_length %d", len(n.Bytes), n.RecordLength)
		}
	}
	if !hexSHA256.MatchString(n.Evidence.SHA256) {
		c.fail(CodeEvidence, "native.evidence.sha256", "not lowercase hex SHA-256")
	}
	if n.Evidence.Length < 0 {
		c.fail(CodeEvidence, "native.evidence.length", "negative")
	}
	if n.Span != nil {
		if n.Span.Offset < 0 || n.Span.Length != n.RecordLength || n.Span.Offset+n.Span.Length > n.Evidence.Length {
			c.fail(CodeEvidence, "native.span", "span must lie inside the evidence and match record_length")
		}
	}
	if n.AlignmentKey != "" && !alignKeyFormat.MatchString(n.AlignmentKey) {
		c.fail(CodeEvidence, "native.alignment_key", "not sha256:<hex>")
	}
	for i, f := range n.Fields {
		if f.Name == "" {
			c.fail(CodeMissing, fmt.Sprintf("native.fields[%d].name", i), "empty")
		}
	}
}

func checkDeviceTime(c *checker, t *DeviceTime) {
	if t.Native == "" {
		c.fail(CodeMissing, "device_time.native", "the native time is kept verbatim")
	}
	switch t.NativeEncoding {
	case EncodingText:
	case EncodingHex:
		if !hexForm.MatchString(t.Native) {
			c.fail(CodeTimeFormat, "device_time.native", "not lowercase hex")
		}
	default:
		c.fail(CodeEnum, "device_time.native_encoding", "%q", t.NativeEncoding)
	}
	if !tokenPattern.MatchString(t.Format) {
		c.fail(CodeEnum, "device_time.format", "%q is not a format token", t.Format)
	}
	if t.ResolutionNS <= 0 {
		c.fail(CodeMissing, "device_time.resolution_ns", "must be positive")
	}
	if t.AccuracyNS != nil && *t.AccuracyNS <= 0 {
		c.fail(CodeMissing, "device_time.accuracy_ns", "must be positive when stated; omit when unknown")
	}
	wall, wallOK := parseLocal(c, "device_time.wall_clock", t.WallClock, t.ResolutionNS)
	if !oneOf(t.OffsetBasis, BasisNone, BasisOnWire, BasisFormatUTC, BasisDeviceSetting, BasisOperator) {
		c.fail(CodeEnum, "device_time.offset_basis", "%q", t.OffsetBasis)
	}
	if t.Offset == "unknown" {
		if t.UTC != "" {
			c.fail(CodeOffset, "device_time.utc", "no UTC time when the offset is unknown")
		}
		if t.OffsetBasis != BasisNone {
			c.fail(CodeOffset, "device_time.offset_basis", "must be none when the offset is unknown")
		}
	} else if m := offsetForm.FindStringSubmatch(t.Offset); m == nil {
		c.fail(CodeTimeFormat, "device_time.offset", "%q is not +HH:MM, -HH:MM or unknown", t.Offset)
	} else {
		if t.OffsetBasis == BasisNone {
			c.fail(CodeOffset, "device_time.offset_basis", "a known offset states its basis")
		}
		if t.UTC == "" {
			c.fail(CodeOffset, "device_time.utc", "required when the offset is known")
		} else if utc, ok := checkUTC(c, "device_time.utc", t.UTC, t.ResolutionNS, false); ok && wallOK {
			off := time.Duration(atoi(m[2]))*time.Hour + time.Duration(atoi(m[3]))*time.Minute
			if m[1] == "-" {
				off = -off
			}
			if !wall.Add(-off).Equal(utc) {
				c.fail(CodeOffset, "device_time.utc", "%s is not wall_clock %s minus offset %s", t.UTC, t.WallClock, t.Offset)
			}
		}
	}
	if q := t.Quality; q != nil {
		if !oneOf(q.Sync, SyncSynchronized, SyncUnsynchronized, SyncUnknown) {
			c.fail(CodeEnum, "device_time.quality.sync", "%q", q.Sync)
		}
		if !oneOf(q.Scope, ScopeRecord, ScopeReport, ScopeDevice, ScopeStream) {
			c.fail(CodeEnum, "device_time.quality.scope", "%q", q.Scope)
		}
		if q.AccuracyRelativeNS != nil && *q.AccuracyRelativeNS <= 0 {
			c.fail(CodeMissing, "device_time.quality.accuracy_relative_ns", "must be positive when stated")
		}
	}
	for i, f := range t.Flags {
		checkFlag(c, fmt.Sprintf("device_time.flags[%d]", i), f)
	}
}

func checkNormalized(c *checker, n *Normalized) {
	if n.Category == "" {
		c.fail(CodeMissing, "normalized.category", "use %q when no mapping applies", Unmapped)
	}
	if n.Category != Unmapped && n.Category != "" {
		if n.Mapping == nil || n.Mapping.Table == "" || n.Mapping.Version == "" {
			c.fail(CodeUnjustifiedMeaning, "normalized.category", "%q needs the mapping table and version that assigned it", n.Category)
		}
	}
}

// parseLocal parses a zone-less wall-clock time and checks its precision.
func parseLocal(c *checker, field, s string, resNS int64) (time.Time, bool) {
	m := wallClockForm.FindStringSubmatch(s)
	if m == nil {
		c.fail(CodeTimeFormat, field, "%q is not YYYY-MM-DDTHH:MM:SS[.fraction]", s)
		return time.Time{}, false
	}
	t, err := time.Parse("2006-01-02T15:04:05.999999999", s)
	if err != nil {
		c.fail(CodeTimeFormat, field, "%q: %v", s, err)
		return time.Time{}, false
	}
	checkDigits(c, field, m[1], resNS)
	return t, true
}

// checkUTC parses an RFC 3339 UTC time with a Z suffix and checks its precision.
func checkUTC(c *checker, field, s string, resNS int64, required bool) (time.Time, bool) {
	if s == "" {
		if required {
			c.fail(CodeMissing, field, "required")
		}
		return time.Time{}, false
	}
	m := utcForm.FindStringSubmatch(s)
	if m == nil {
		c.fail(CodeTimeFormat, field, "%q is not RFC 3339 UTC with a Z suffix", s)
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		c.fail(CodeTimeFormat, field, "%q: %v", s, err)
		return time.Time{}, false
	}
	checkDigits(c, field, m[1], resNS)
	return t, true
}

// checkDigits rejects a fraction whose last digit is finer than the
// resolution: d digits express steps of 10^(9-d) ns.
func checkDigits(c *checker, field, frac string, resNS int64) {
	if frac == "" || resNS <= 0 {
		return
	}
	step := int64(1)
	for i := len(frac); i < 9; i++ {
		step *= 10
	}
	if step < resNS {
		c.fail(CodePrecision, field, "%d fractional digits claim %d ns steps, finer than the %d ns resolution", len(frac), step, resNS)
	}
}

func atoi(s string) int {
	n := 0
	for _, r := range s {
		n = n*10 + int(r-'0')
	}
	return n
}

func oneOf[T comparable](v T, set ...T) bool {
	for _, s := range set {
		if v == s {
			return true
		}
	}
	return false
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}
