package event

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Identifier is the contract identifier carried in every event's schema field.
const Identifier = "otsec.event/0.1"

// NodeID names a platform node. It is a lowercase DNS label (1 to 63
// characters, letters, digits and inner hyphens), so it is valid as a Syslog
// HOSTNAME and as a file name on Windows and Linux.
type NodeID string

var nodeIDPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

// Valid reports whether n is a well-formed node ID.
func (n NodeID) Valid() bool { return nodeIDPattern.MatchString(string(n)) }

// Stream names one native sequence space on a node, for example one
// device's SER buffer or one Syslog sender. 1 to 128 characters: lowercase
// letters, digits, '.', '_', '/', '-', starting with a letter or digit. It
// never contains ':', which separates the parts of EventID.String.
type Stream string

var streamPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._/-]{0,127}$`)

// Valid reports whether s is a well-formed stream token.
func (s Stream) Valid() bool { return streamPattern.MatchString(string(s)) }

// EventID is the transport identity of an event (ADR-0004 item 3). Seq is
// assigned at durable commit, starts at 1 and increases by exactly 1 per
// (NodeID, Stream). It is never reused, including after a restart.
type EventID struct {
	NodeID NodeID `json:"node_id"`
	Stream Stream `json:"stream"`
	Seq    uint64 `json:"seq"`
}

// String returns the canonical form "<node_id>:<stream>:<seq>".
func (id EventID) String() string {
	return fmt.Sprintf("%s:%s:%d", id.NodeID, id.Stream, id.Seq)
}

// ParseEventID parses the canonical form produced by String.
func ParseEventID(s string) (EventID, error) {
	parts := strings.Split(s, ":")
	if len(parts) != 3 {
		return EventID{}, fmt.Errorf("event: %q is not <node_id>:<stream>:<seq>", s)
	}
	seq, err := strconv.ParseUint(parts[2], 10, 64)
	if err != nil || parts[2] != strconv.FormatUint(seq, 10) {
		return EventID{}, fmt.Errorf("event: %q has an invalid seq", s)
	}
	id := EventID{NodeID: NodeID(parts[0]), Stream: Stream(parts[1]), Seq: seq}
	if !id.NodeID.Valid() || !id.Stream.Valid() || seq == 0 {
		return EventID{}, fmt.Errorf("event: %q is not a valid event ID", s)
	}
	return id, nil
}

// Event is one record committed by a node.
type Event struct {
	Schema     string      `json:"schema"` // Identifier, or another 0.x minor
	ID         EventID     `json:"id"`
	Origin     Origin      `json:"origin"`
	Kind       Kind        `json:"kind"`
	Source     Source      `json:"source"`
	Collection *Collection `json:"collection,omitempty"`
	Received   Received    `json:"received"`
	DeviceTime *DeviceTime `json:"device_time,omitempty"`
	Native     *Native     `json:"native,omitempty"`
	Normalized *Normalized `json:"normalized,omitempty"`
	Health     *Health     `json:"health,omitempty"`
	Flags      []string    `json:"flags,omitempty"` // open set, see KnownFlags
}

// Origin says who produced the content. It is set by the collector from how
// the record arrived, never from the record's content. Closed.
type Origin string

const (
	OriginDevice   Origin = "device"
	OriginPlatform Origin = "platform"
)

// Kind is an open set. A reader that meets an unknown kind keeps the event
// and treats it as opaque.
type Kind string

const (
	KindSER          Kind = "ser"              // SEL ASCII SER row or another ring-buffer sequence-of-events record
	KindSOELog       Kind = "soe-log"          // an SOE log entry, for example from an RTAC
	KindDeviceLog    Kind = "device-log"       // a device's own event log entry read by an adapter (for example a clock's log)
	KindSyslog       Kind = "syslog"           // a Syslog message received from a device
	KindHostEvent    Kind = "host-event"       // a host event pushed by a host (Windows Event Forwarding or a forwarder)
	KindDeviceStatus Kind = "device-status"    // a status report read from a device (for example a clock STATUS report)
	KindHealth       Kind = "telemetry-health" // a platform event; Health is set
)

var tokenPattern = regexp.MustCompile(`^[a-z][a-z0-9.-]{0,63}$`)

// Source identifies the subject of the event and who delivered it.
type Source struct {
	// Asset is the subject. Nil when the subject could not be resolved; the
	// event then carries the flag "asset-unresolved".
	Asset *AssetRef `json:"asset,omitempty"`
	// Sender is who delivered the bytes (network peer or forwarder). Never
	// copied into Asset when the sender relays for others (A3 AP-22).
	Sender     *Sender    `json:"sender,omitempty"`
	OriginAuth OriginAuth `json:"origin_auth"`
}

// AssetRef refers to a C1 asset.
//
// TODO(C1): replace ID with the C1 asset ID type once C1 is merged. The
// binding fields stay in C4: they describe how this event was attributed,
// not the asset.
type AssetRef struct {
	ID      string  `json:"id"`
	Binding Binding `json:"binding"`
}

var assetIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$`)

// Binding records how the event was attributed to the asset.
type Binding struct {
	Method     BindingMethod     `json:"method"`
	Confidence BindingConfidence `json:"confidence"`
}

// BindingMethod is closed.
type BindingMethod string

const (
	BindAdapterTarget BindingMethod = "adapter-target" // the adapter was invoked against this asset
	BindSenderAddress BindingMethod = "sender-address" // the sender's address maps to this asset
	BindContentField  BindingMethod = "content-field"  // a field in the record names the subject (RTAC tag, OpenFlow datapath ID)
	BindOperator      BindingMethod = "operator"       // an operator assigned it
)

// BindingConfidence is closed.
type BindingConfidence string

const (
	ConfidenceConfigured BindingConfidence = "configured" // from configuration the platform controls
	ConfidenceAsserted   BindingConfidence = "asserted"   // stated by the sender or the content, not verified
	ConfidenceInferred   BindingConfidence = "inferred"   // derived heuristically
)

// Sender is who delivered the bytes.
type Sender struct {
	Address string `json:"address"`            // IP address, host name or local endpoint as observed
	AssetID string `json:"asset_id,omitempty"` // TODO(C1): C1 asset ID of the sender when known
}

// OriginAuth records how the sender was authenticated (A3 AP-22). Closed.
// Only tls-mutual authenticates the sender to the platform; events with any
// other value may raise alerts but must not drive automated actions.
type OriginAuth string

const (
	AuthNone          OriginAuth = "none"            // UDP or TCP Syslog: anyone on the path can send or alter
	AuthTLSServerOnly OriginAuth = "tls-server-only" // TLS where only the platform proved its identity
	AuthTLSMutual     OriginAuth = "tls-mutual"      // TLS with a client certificate the platform verified
	AuthSession       OriginAuth = "session"         // read by a platform-initiated adapter session to a configured target
	AuthPlatform      OriginAuth = "platform"        // produced by the platform itself
)

// Collection describes how the record was obtained.
type Collection struct {
	Method         CollectionMethod `json:"method"`
	InvocationID   string           `json:"invocation_id,omitempty"` // C2 invocation
	OperationID    string           `json:"operation_id,omitempty"`  // TODO(C3): C3 operation ID type
	Parser         *Parser          `json:"parser,omitempty"`
	NativePosition string           `json:"native_position,omitempty"` // the device's own row number or position, verbatim
	Alignment      Alignment        `json:"alignment,omitempty"`
	ParseStatus    ParseStatus      `json:"parse_status"`
}

// CollectionMethod is closed.
type CollectionMethod string

const (
	MethodAdapterPoll   CollectionMethod = "adapter-poll"
	MethodSyslogReceive CollectionMethod = "syslog-receive"
	MethodHostPush      CollectionMethod = "host-push"
)

// Parser names the parser and its version, which changes when its output
// for the same bytes changes.
type Parser struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Alignment is the snapshot-alignment outcome for this record. Closed.
type Alignment string

const (
	AlignFirstRead         Alignment = "first-read"         // first read of the stream; nothing to compare with
	AlignOK                Alignment = "ok"                 // new after an unambiguous overlap
	AlignGapBefore         Alignment = "gap-before"         // records may be missing before this one (no overlap)
	AlignPossibleDuplicate Alignment = "possible-duplicate" // ambiguous overlap: may already have been stored
)

// ParseStatus is closed. A failed parse still yields an event: the native
// bytes are kept and Normalized is absent.
type ParseStatus string

const (
	ParseOK      ParseStatus = "ok"
	ParsePartial ParseStatus = "partial"
	ParseFailed  ParseStatus = "failed"
)

// Received is when and how the node received or committed the record.
type Received struct {
	UTC          string `json:"utc"` // RFC 3339, UTC, Z suffix
	ResolutionNS int64  `json:"resolution_ns"`
	Clock        Clock  `json:"clock"`
}

// Clock is the node clock's state at receive time.
type Clock struct {
	Sync   SyncState `json:"sync"`
	Source string    `json:"source,omitempty"` // ntp, ptp, w32time, ... (open)
}

// SyncState is closed.
type SyncState string

const (
	SyncSynchronized   SyncState = "synchronized"
	SyncUnsynchronized SyncState = "unsynchronized"
	SyncUnknown        SyncState = "unknown"
)

// DeviceTime is the device's own timestamp for the record.
type DeviceTime struct {
	// Native is the device's time exactly as it appeared: text, or lowercase
	// hex for binary encodings.
	Native         string         `json:"native"`
	NativeEncoding NativeEncoding `json:"native_encoding"`
	// Format names the decoding rule (open), for example sel-ascii-ser-row,
	// rfc3164, rfc5424, cp56time2a, iec61850-utctime, windows-systemtime.
	Format string `json:"format"`
	// WallClock is the decoded time on the device's clock face, without a
	// zone: YYYY-MM-DDTHH:MM:SS with up to 9 fractional digits.
	WallClock string `json:"wall_clock"`
	// Offset is the device clock's offset from UTC, "+HH:MM", "-HH:MM", or
	// "unknown". Never guessed.
	Offset      string      `json:"offset"`
	OffsetBasis OffsetBasis `json:"offset_basis"`
	// UTC is WallClock minus Offset, RFC 3339 with Z. Present exactly when
	// Offset is known.
	UTC string `json:"utc,omitempty"`
	// ResolutionNS is the smallest step the native time can express.
	ResolutionNS int64 `json:"resolution_ns"`
	// AccuracyNS is the stated accuracy against true time, when the format or
	// the time source states one. Nil means unknown, not zero.
	AccuracyNS *int64       `json:"accuracy_ns,omitempty"`
	Quality    *TimeQuality `json:"quality,omitempty"`
	Flags      []string     `json:"flags,omitempty"` // open set, see KnownTimeFlags
}

// NativeEncoding is closed.
type NativeEncoding string

const (
	EncodingText NativeEncoding = "text"
	EncodingHex  NativeEncoding = "hex"
)

// OffsetBasis says where a known offset came from. Closed.
type OffsetBasis string

const (
	BasisNone          OffsetBasis = "none"           // offset unknown
	BasisOnWire        OffsetBasis = "on-wire"        // the record itself carries the offset (RFC 5424, ISO 8601)
	BasisFormatUTC     OffsetBasis = "format-utc"     // the format is defined as UTC (IEC 61850 UtcTime, Windows SystemTime)
	BasisDeviceSetting OffsetBasis = "device-setting" // read from the device's settings (UTC_OFF and DST) by the adapter
	BasisOperator      OffsetBasis = "operator"       // recorded by an operator for this device
)

// TimeQuality is what the source says about its clock, with the scope it
// applies to.
type TimeQuality struct {
	TimeSource         string    `json:"time_source,omitempty"` // verbatim, for example "Internal" (open)
	Sync               SyncState `json:"sync"`
	LeapSecondsKnown   *bool     `json:"leap_seconds_known,omitempty"`
	ClockFailure       *bool     `json:"clock_failure,omitempty"`
	AccuracyRelativeNS *int64    `json:"accuracy_relative_ns,omitempty"` // accuracy relative to the device's own time source, not to true time
	Scope              Scope     `json:"scope"`
}

// Scope is what a quality statement applies to. Closed.
type Scope string

const (
	ScopeRecord Scope = "record" // stated on this record
	ScopeReport Scope = "report" // stated once for the report the record came from
	ScopeDevice Scope = "device" // device-level status read separately
	ScopeStream Scope = "stream" // inferred for the whole stream
)

// Native is the record's evidence.
type Native struct {
	// Bytes are the record's own native bytes, verbatim. Optional on the
	// wire when the evidence store holds them; RecordSHA256 is always set.
	Bytes        []byte `json:"bytes,omitempty"`
	RecordSHA256 string `json:"record_sha256"` // lowercase hex of SHA-256(Bytes)
	RecordLength int64  `json:"record_length"`
	// Evidence is the capture the record came from (a whole SER report, a
	// datagram, a pushed event file).
	Evidence Evidence `json:"evidence"`
	// Span locates the record inside the evidence.
	Span *Span `json:"span,omitempty"`
	// AlignmentKey is set for ring-buffer records: "sha256:<hex>" of the
	// record bytes without the device's row numbering (R-A4-1). The adapter
	// computes it; it is not a uniqueness key.
	AlignmentKey string `json:"alignment_key,omitempty"`
	// Fields are the parsed native fields, names and values as the device
	// printed them, in order. Never a substitute for Bytes.
	Fields []Field `json:"fields,omitempty"`
}

// Evidence identifies a stored capture.
type Evidence struct {
	SHA256 string `json:"sha256"`
	Length int64  `json:"length"`
	Ref    string `json:"ref,omitempty"` // evidence store reference (C5)
}

// Span is a byte range inside the evidence.
type Span struct {
	Offset int64 `json:"offset"`
	Length int64 `json:"length"`
}

// Field is one native field.
type Field struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Normalized is the platform's reading of the record.
type Normalized struct {
	Subject     string `json:"subject"`      // for SER, the element name as printed
	SubjectType string `json:"subject_type"` // for example "relay-word-bit", "message" (open)
	Value       string `json:"value"`        // for SER, the state as printed
	// Category is "unmapped" unless Mapping names the table that assigned it.
	Category string   `json:"category"`
	Mapping  *Mapping `json:"mapping,omitempty"`
}

// Unmapped is the category of every record no mapping table has classified.
const Unmapped = "unmapped"

// Mapping names a versioned mapping table.
type Mapping struct {
	Table   string `json:"table"`
	Version string `json:"version"`
}

// Health is set on platform events (Kind telemetry-health).
type Health struct {
	Type    string            `json:"type"` // open set, see the Health* constants
	Related []EventID         `json:"related,omitempty"`
	Details map[string]string `json:"details,omitempty"`
}

// Platform event types. Open: later minors may add types.
const (
	HealthSERGap              = "ser.gap"                 // alignment found no overlap: records may be missing
	HealthAlignmentAmbiguous  = "ser.alignment-ambiguous" // overlap ambiguous: possible duplicates flagged
	HealthNativeLossIndicated = "native.loss-indicated"   // the device says it lost records (overflow, autoremoval)
	HealthTimeUnsynchronized  = "time.unsynchronized"     // a source's clock is reported unsynchronized
	HealthParseFailed         = "parse.failed"            // a record kept as bytes only
	HealthSourceSilent        = "source.silent"           // a sender that normally talks has gone quiet
	HealthDropCounted         = "intake.drop-counted"     // datagrams dropped and counted (storage full, rate limit)
	HealthForwardUnconfirmed  = "forward.unconfirmed"     // events sent to a best-effort target without confirmation
	HealthForwardUnreachable  = "forward.unreachable"     // a required target unreachable beyond its period
	HealthForwardTextOmitted  = "forward.text-omitted"    // device text replaced by a reference to fit the size limit
)

// KnownFlags are the event flags defined in 0.1. The set is open.
var KnownFlags = []string{"asset-unresolved", "gap-before", "possible-duplicate"}

// KnownTimeFlags are the device-time flags defined in 0.1. The set is open;
// flags with a ':' carry a value, for example "date-format-assumed:MDY".
var KnownTimeFlags = []string{
	"two-digit-year", "year-absent", "year-assumed", "dst-ambiguous",
	"date-format-assumed", "invalid-time", "substituted-time",
}
