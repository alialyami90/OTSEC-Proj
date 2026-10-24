package syslog

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"otsec.local/otsec/contracts/event"
)

// SDID is the SD-ID of the one structured-data element every message
// carries. 32473 is the RFC 5612 documentation Private Enterprise Number; it
// must be replaced by an IANA-assigned number before production (ADR-0004
// amendment).
const SDID = "otsec@32473"

// AppName is the RFC 5424 APP-NAME and the RFC 3164 TAG.
const AppName = "otsec"

// Health types C6 adds to C4's open set. forward.text-omitted is C4's own.
const HealthTooLarge = "forward.too-large"

// Outcome reports what Render had to leave out to fit the size limit.
type Outcome struct {
	TextOmitted    bool // device text replaced by dtext_omitted="1"
	SummaryDropped bool // MSG summary left out
}

// Param is one SD-PARAM, with its value unescaped.
type Param struct {
	Name  string
	Value string
}

// The SD-PARAMs, in the order Render writes them. A parameter is written
// only when the event has the field. A name ending in _b64 replaces the plain
// name when the value is not printable UTF-8 (see printable); the value is
// then standard base64 of the bytes. Repeated names keep the event's order.
//
//	v        C6 identifier, otsec.syslog/0.1
//	ev       C4 identifier of the event, for example otsec.event/0.1
//	eid      C4 event ID, canonical text; receivers remove duplicates by it
//	origin   device or platform
//	kind     C4 kind
//	asset    C1 asset ID of the subject
//	abind    binding method/confidence, for example adapter-target/configured
//	sender   sender address as observed by the node
//	auth     C4 origin_auth
//	rcv      received.utc at full precision (HEADER TIMESTAMP is truncated)
//	rres     received.resolution_ns
//	rsync    received clock sync state
//	coll     collection method
//	inv      C2 invocation ID
//	op       C3 operation ID
//	parser   parser name/version
//	pos      the device's own row number or position
//	align    snapshot alignment outcome
//	parse    parse status
//	dt       device time, native text (or its hex for binary encodings)
//	dfmt     device time format
//	dwall    wall clock, no zone
//	doff     offset from UTC, or unknown
//	dbasis   where a known offset came from
//	dutc     device time in UTC, only when the offset is known
//	dres     device time resolution, ns
//	dacc     device time accuracy against true time, ns
//	tsrc     time source as printed by the device
//	tsync    device time sync state
//	tacc     accuracy relative to the device's own time source, ns
//	tscope   scope of the time quality
//	dflag    a device-time flag (repeated)
//	subj     normalized subject
//	stype    subject type
//	val      normalized value
//	cat      category, unmapped unless a mapping table assigned it
//	map      mapping table@version
//	htype    health type
//	hrel     a related event ID (repeated)
//	hd       a health detail, key=value, sorted by key (repeated)
//	rsha256  SHA-256 of the record's native bytes
//	rlen     length of the record's native bytes
//	esha256  SHA-256 of the evidence capture
//	flag     an event flag (repeated)
//	dtext    the record's native bytes, when printable UTF-8
//	dtext_b64      the record's native bytes otherwise
//	dtext_omitted  "1" when the bytes were left out to fit the size limit
func params(e *event.Event, withText bool) []Param {
	var ps []Param
	add := func(name, value string) {
		if printable(value) {
			ps = append(ps, Param{name, value})
		} else {
			ps = append(ps, Param{name + "_b64", base64.StdEncoding.EncodeToString([]byte(value))})
		}
	}
	opt := func(name, value string) {
		if value != "" {
			add(name, value)
		}
	}
	num := func(name string, v int64) { add(name, strconv.FormatInt(v, 10)) }
	add("v", Identifier)
	add("ev", e.Schema)
	add("eid", e.ID.String())
	add("origin", string(e.Origin))
	add("kind", string(e.Kind))
	if a := e.Source.Asset; a != nil {
		add("asset", a.ID)
		add("abind", string(a.Binding.Method)+"/"+string(a.Binding.Confidence))
	}
	if s := e.Source.Sender; s != nil {
		add("sender", s.Address)
	}
	add("auth", string(e.Source.OriginAuth))
	add("rcv", e.Received.UTC)
	num("rres", e.Received.ResolutionNS)
	add("rsync", string(e.Received.Clock.Sync))
	if c := e.Collection; c != nil {
		add("coll", string(c.Method))
		opt("inv", c.InvocationID)
		opt("op", c.OperationID)
		if c.Parser != nil {
			add("parser", c.Parser.Name+"/"+c.Parser.Version)
		}
		opt("pos", c.NativePosition)
		opt("align", string(c.Alignment))
		add("parse", string(c.ParseStatus))
	}
	if t := e.DeviceTime; t != nil {
		add("dt", t.Native)
		add("dfmt", t.Format)
		opt("dwall", t.WallClock)
		add("doff", t.Offset)
		add("dbasis", string(t.OffsetBasis))
		opt("dutc", t.UTC)
		num("dres", t.ResolutionNS)
		if t.AccuracyNS != nil {
			num("dacc", *t.AccuracyNS)
		}
		if q := t.Quality; q != nil {
			opt("tsrc", q.TimeSource)
			add("tsync", string(q.Sync))
			if q.AccuracyRelativeNS != nil {
				num("tacc", *q.AccuracyRelativeNS)
			}
			add("tscope", string(q.Scope))
		}
		for _, f := range t.Flags {
			add("dflag", f)
		}
	}
	if n := e.Normalized; n != nil {
		add("subj", n.Subject)
		add("stype", n.SubjectType)
		add("val", n.Value)
		add("cat", n.Category)
		if n.Mapping != nil {
			add("map", n.Mapping.Table+"@"+n.Mapping.Version)
		}
	}
	if h := e.Health; h != nil {
		add("htype", h.Type)
		for _, r := range h.Related {
			add("hrel", r.String())
		}
		keys := make([]string, 0, len(h.Details))
		for k := range h.Details {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			add("hd", k+"="+h.Details[k])
		}
	}
	if n := e.Native; n != nil {
		add("rsha256", n.RecordSHA256)
		num("rlen", n.RecordLength)
		add("esha256", n.Evidence.SHA256)
	}
	for _, f := range e.Flags {
		add("flag", f)
	}
	if n := e.Native; n != nil && n.Bytes != nil {
		switch {
		case !withText:
			ps = append(ps, Param{"dtext_omitted", "1"})
		case printable(string(n.Bytes)):
			ps = append(ps, Param{"dtext", string(n.Bytes)})
		default:
			ps = append(ps, Param{"dtext_b64", base64.StdEncoding.EncodeToString(n.Bytes)})
		}
	}
	return ps
}

// printable reports whether s can travel as an escaped PARAM-VALUE without
// changing meaning anywhere on the path: valid UTF-8 with no C0 or C1
// control character, no DEL, no line or paragraph separator and no BOM. A
// value that fails travels as base64, so LF, NUL and invalid UTF-8 never
// reach the wire (E-A4-02).
func printable(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r < 0x20 || (r >= 0x7f && r <= 0x9f) || r == 0x2028 || r == 0x2029 || r == 0xfeff {
			return false
		}
	}
	return true
}

// escape escapes a PARAM-VALUE as RFC 5424 section 6.3.3 requires.
func escape(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, `]`, `\]`).Replace(s)
}

func sd(ps []Param) string {
	var b strings.Builder
	b.WriteString("[" + SDID)
	for _, p := range ps {
		b.WriteString(" " + p.Name + `="` + escape(p.Value) + `"`)
	}
	b.WriteString("]")
	return b.String()
}

// summaryToken is the character set a normalized value must match to appear
// in MSG. It excludes everything that could start a new message, header, SD
// element or escape: LF, NUL, '<', '[', ']', '"', '\', '='.
var summaryToken = regexp.MustCompile(`^[A-Za-z0-9 ._:/+()',-]{1,64}$`)

// summary is MSG: a short line for people, never needed to read the event.
func summary(e *event.Event) string {
	s := string(e.Kind)
	if h := e.Health; h != nil && summaryToken.MatchString(h.Type) {
		return s + " " + h.Type
	}
	if n := e.Normalized; n != nil && summaryToken.MatchString(n.Subject) && summaryToken.MatchString(n.Value) {
		s += " " + n.Subject + " " + n.Value
	}
	return s
}

var msgIDs = map[event.Kind]string{
	event.KindSER: "SER", event.KindSOELog: "SOE", event.KindDeviceLog: "DEVLOG", event.KindSyslog: "SYSLOG",
	event.KindHostEvent: "HOST", event.KindDeviceStatus: "STATUS", event.KindHealth: "HEALTH",
}

// MsgID returns the RFC 5424 MSGID for a kind; kinds C6 does not know map
// to EVENT, and the kind parameter still says which.
func MsgID(k event.Kind) string {
	if id, ok := msgIDs[k]; ok {
		return id
	}
	return "EVENT"
}

// Severity is the Syslog severity: 4 (warning) for platform health events,
// 5 (notice) for everything else. It carries no device meaning: C4 assigns
// none (category unmapped), and a severity guessed from device text would
// claim one.
func Severity(e *event.Event) int {
	if e.Health != nil {
		return 4
	}
	return 5
}

// headerTime renders received.utc for the RFC 5424 TIMESTAMP, which allows
// at most 6 fractional digits (TIME-SECFRAC). Extra digits are cut, never
// rounded or padded, so the header never claims more than the event does;
// rcv carries the full value.
func headerTime(utc string) string {
	dot := strings.IndexByte(utc, '.')
	if dot < 0 || len(utc)-1-(dot+1) <= 6 {
		return utc
	}
	return utc[:dot+7] + "Z"
}

func assemble(e *event.Event, t *Target, ps []Param, msg string) ([]byte, error) {
	pri := "<" + strconv.Itoa(t.Facility*8+Severity(e)) + ">"
	var b strings.Builder
	switch t.Format {
	case FormatRFC3164:
		rt, err := time.Parse(time.RFC3339Nano, e.Received.UTC)
		if err != nil {
			return nil, &Error{Code: CodeEventInvalid, Field: "received.utc", Detail: err.Error()}
		}
		b.WriteString(pri + rt.UTC().Format(time.Stamp) + " " + string(e.ID.NodeID) + " " + AppName + ": " + MsgID(e.Kind) + " " + sd(ps))
	default:
		b.WriteString(pri + "1 " + headerTime(e.Received.UTC) + " " + string(e.ID.NodeID) + " " + AppName + " - " + MsgID(e.Kind) + " " + sd(ps))
	}
	if msg != "" {
		b.WriteString(" " + msg)
	}
	return []byte(b.String()), nil
}

// Render produces the one canonical message for e on target t. It validates
// both first. The result never exceeds t.MaxMessageOctets and never contains
// LF, CR or NUL; see the package documentation for the size steps.
func Render(e *event.Event, t *Target) ([]byte, Outcome, error) {
	var out Outcome
	if err := t.Validate(); err != nil {
		return nil, out, err
	}
	if err := e.Validate(); err != nil {
		return nil, out, &Error{Code: CodeEventInvalid, Field: "event", Detail: err.Error()}
	}
	withText, msg := true, summary(e)
	for {
		b, err := assemble(e, t, params(e, withText), msg)
		if err != nil {
			return nil, out, err
		}
		if len(b) <= t.MaxMessageOctets {
			return b, out, nil
		}
		switch {
		case withText && e.Native != nil && e.Native.Bytes != nil:
			withText, out.TextOmitted = false, true
		case msg != "":
			msg, out.SummaryDropped = "", true
		default:
			return nil, out, &Error{Code: CodeTooLarge, Field: "message", Detail: fmt.Sprintf("%d octets without device text or summary, limit %d", len(b), t.MaxMessageOctets)}
		}
	}
}
