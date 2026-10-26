package normalize

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/event"
)

// SyslogParser is C4 collection.parser on every received Syslog event. Its
// version changes whenever the events built from the same bytes change.
var SyslogParser = event.Parser{Name: "otsec-syslog", Version: "0.1"}

// Dialect is the Syslog layout a sender uses. It comes from configuration
// (the asset the sender address maps to), never from the message, so a
// sender cannot choose how its own bytes are read.
type Dialect string

const (
	// DialectRFC reads RFC 5424 or RFC 3164, told apart by the bytes after
	// PRI. It is used for every sender without a dialect of its own,
	// unknown senders included.
	DialectRFC Dialect = "rfc"
	// DialectRTAC is the SEL RTAC Logger: RFC 3164 with a year in the
	// header, and the event time, level, category, tag and description in
	// MSG (S23 Table 8.16 and the example on p. 636, documented-untested).
	// The header time is the RTAC's send time; the event time is the tag's
	// time stamp, so device_time is the event time.
	DialectRTAC Dialect = "sel-rtac"
)

// Dialects lists every Dialect.
var Dialects = []Dialect{DialectRFC, DialectRTAC}

// Subject types of received Syslog events (C4 normalized.subject_type).
const (
	SubjectSyslogApp  = "syslog-app"  // RFC 5424 APP-NAME or the RFC 3164 TAG
	SubjectSyslogHost = "syslog-host" // the HOSTNAME, when the message names no application
	SubjectRTACTag    = "rtac-tag"    // the RTAC tag name, as printed
)

// Device-time formats of received Syslog events (C4 device_time.format).
const (
	FormatRFC5424 = "rfc5424"         // RFC 5424 TIMESTAMP
	FormatRFC3164 = "rfc3164"         // Mmm dd hh:mm:ss, no year
	FormatYear    = "rfc3164-year"    // Mmm dd yyyy hh:mm:ss (the RTAC header)
	FormatRFC3339 = "rfc3339"         // an RFC 3339 time where RFC 3164 puts its TIMESTAMP
	FormatRTAC    = "sel-rtac-logger" // the RTAC event time, yyyy-mm-dd hh:mm:ss.fff
)

// Receive flags: the listener's account of how a message arrived, carried
// on the event (C4 flags are an open set).
const (
	// FlagTruncated: the message is cut short. The frame was longer than
	// the listener's limit, or the connection ended or timed out inside it.
	// The bytes kept are the ones received; the rest were never stored.
	FlagTruncated = "frame-truncated"
	// FlagFraming: the bytes did not follow the stream framing, so the
	// listener cut them at the next LF (or at its limit) and kept them.
	FlagFraming = "frame-invalid"
)

// rtacMaxValue bounds normalized.value for the RTAC description: the RTAC
// limits a whole packet to 1024 bytes (S23 p. 636).
const rtacMaxValue = 1024

// SyslogInput is one received Syslog message and what the listener knows
// about it.
type SyslogInput struct {
	Node event.NodeID
	// Stream is the listener's stream.
	Stream event.Stream
	// Message is the message as received: one UDP datagram, or one stream
	// frame without its framing (the octet count and its space, or the
	// trailing LF). Nothing is trimmed or decoded.
	Message []byte
	// Sender is the source IP address as the listener saw it.
	Sender string
	// Auth is how the sender was authenticated: none (UDP, TCP),
	// tls-server-only or tls-mutual.
	Auth event.OriginAuth
	// AssetID is the C1 asset the sender address maps to, or "" when no
	// asset has an inbound endpoint for it.
	AssetID string
	// EvidenceClass is device-observed only when both the asset's endpoint
	// and the listener are; for an unknown sender it is the listener's
	// (C4 Source.EvidenceClass, D1-24 amendment).
	EvidenceClass asset.EvidenceClass
	Dialect       Dialect
	Received      event.Received
	// Flags are receive flags (FlagTruncated, FlagFraming).
	Flags []string
}

// Syslog builds the pending C4 event (seq 0) of one received message. It
// returns an error only for an input the listener should never build; for
// any bytes at all it returns an event that passes C4 ValidatePending.
//
// The record is the whole message: native.bytes are the message, and
// native.evidence is the message itself (the same SHA-256 and length, a
// span over all of it, no C5 capture), because a datagram or frame is its
// own capture and storing it twice would double the Syslog database. A
// message that does not parse keeps its bytes with parse_status failed
// (EP-1).
func Syslog(in SyslogInput) (event.Event, error) {
	if err := in.check(); err != nil {
		return event.Event{}, err
	}
	sum := sha256.Sum256(in.Message)
	sha := hex.EncodeToString(sum[:])
	n := int64(len(in.Message))
	src := event.Source{Sender: &event.Sender{Address: in.Sender}, OriginAuth: in.Auth, EvidenceClass: in.EvidenceClass}
	var flags []string
	if in.AssetID != "" {
		// The direct sender is the subject: a relayed message arrives from
		// the relay's address, so an address binding names the relay.
		src.Asset = &event.AssetRef{ID: in.AssetID, Binding: event.Binding{Method: event.BindSenderAddress, Confidence: event.ConfidenceConfigured}}
		src.Sender.AssetID = in.AssetID
	} else {
		flags = append(flags, "asset-unresolved")
	}
	flags = append(flags, in.Flags...)
	rcv, _ := time.Parse(time.RFC3339Nano, in.Received.UTC)
	p := parseSyslog(in.Message, in.Dialect, rcv)
	if len(in.Flags) > 0 && p.status == event.ParseOK {
		// A cut or misframed message cannot be known to be whole.
		p.status = event.ParsePartial
	}
	e := event.Event{
		Schema: event.Identifier,
		ID:     event.EventID{NodeID: in.Node, Stream: in.Stream},
		Origin: event.OriginDevice,
		Kind:   event.KindSyslog,
		Source: src,
		Collection: &event.Collection{
			Method:      event.MethodSyslogReceive,
			Parser:      &SyslogParser,
			ParseStatus: p.status,
		},
		Received:   in.Received,
		DeviceTime: p.time,
		Native: &event.Native{
			Bytes:        in.Message,
			RecordSHA256: sha,
			RecordLength: n,
			Evidence:     event.Evidence{SHA256: sha, Length: n},
			Span:         &event.Span{Offset: 0, Length: n},
			Fields:       p.fields,
		},
		Flags: flags,
	}
	if p.subject != "" {
		e.Normalized = &event.Normalized{Subject: p.subject, SubjectType: p.subjectType, Value: p.value, Category: event.Unmapped}
	}
	if err := e.ValidatePending(); err != nil {
		// A parser fault must not cost the message: keep its bytes alone.
		e.DeviceTime, e.Normalized, e.Native.Fields = nil, nil, nil
		e.Collection.ParseStatus = event.ParseFailed
		if err := e.ValidatePending(); err != nil {
			return event.Event{}, fmt.Errorf("normalize: built an invalid Syslog event: %w", err)
		}
	}
	return e, nil
}

func (in SyslogInput) check() error {
	switch {
	case !in.Node.Valid():
		return fmt.Errorf("%w: node %q", ErrInput, in.Node)
	case !in.Stream.Valid():
		return fmt.Errorf("%w: stream %q", ErrInput, in.Stream)
	case len(in.Message) == 0:
		return fmt.Errorf("%w: empty message", ErrInput)
	case strings.TrimSpace(in.Sender) == "" || !utf8.ValidString(in.Sender):
		return fmt.Errorf("%w: sender %q", ErrInput, in.Sender)
	case !slices.Contains(event.AllowedOriginAuth[event.MethodSyslogReceive], in.Auth):
		return fmt.Errorf("%w: origin_auth %q", ErrInput, in.Auth)
	case in.EvidenceClass != asset.DeviceObserved && in.EvidenceClass != asset.Simulated:
		return fmt.Errorf("%w: evidence class %q", ErrInput, in.EvidenceClass)
	case !slices.Contains(Dialects, in.Dialect):
		return fmt.Errorf("%w: dialect %q", ErrInput, in.Dialect)
	}
	return nil
}

// parsed is what the parser read from one message.
type parsed struct {
	status      event.ParseStatus
	fields      []event.Field
	time        *event.DeviceTime
	subject     string
	subjectType string
	value       string
}

func (p *parsed) add(name, value string) {
	p.fields = append(p.fields, event.Field{Name: name, Value: value})
}

// parseSyslog reads a message. Field values are the bytes as printed; a
// value that is not valid UTF-8 is left out (JSON would replace its bytes),
// and the message is then partial. Fields may overlap: msg is the whole MSG
// part, and tag and pid are read from its start.
func parseSyslog(b []byte, d Dialect, rcv time.Time) parsed {
	p := parsed{status: event.ParseFailed}
	pri, rest, ok := readPRI(b)
	if !ok {
		return p
	}
	p.add("pri", pri)
	p.status = event.ParseOK
	if v, after, ok := readVersion(rest); ok {
		p.add("version", v)
		if v != "1" {
			// Only version 1 is defined; a later header may differ.
			p.status = event.ParsePartial
			return p
		}
		parse5424(&p, after)
		return p
	}
	parse3164(&p, rest, d, rcv)
	return p
}

// readPRI reads "<" PRIVAL ">", PRIVAL 0 to 191 with no leading zero.
func readPRI(b []byte) (string, []byte, bool) {
	if len(b) < 3 || b[0] != '<' {
		return "", nil, false
	}
	end := bytes.IndexByte(b[1:min(len(b), 5)], '>')
	if end < 1 {
		return "", nil, false
	}
	s := string(b[1 : 1+end])
	v, ok := digits(s, 0, len(s))
	if !ok || v > 191 || (len(s) > 1 && s[0] == '0') {
		return "", nil, false
	}
	return s, b[2+end:], true
}

// readVersion reads the RFC 5424 VERSION and the space after it: a nonzero
// digit and up to two more. An RFC 3164 message has a month name or an
// RFC 3339 year there instead, never one to three digits and a space.
func readVersion(b []byte) (string, []byte, bool) {
	i := 0
	for i < len(b) && i < 3 && b[i] >= '0' && b[i] <= '9' {
		i++
	}
	if i == 0 || b[0] == '0' || i >= len(b) || b[i] != ' ' {
		return "", nil, false
	}
	return string(b[:i]), b[i+1:], true
}

// token reads one RFC 5424 header field: 1 to max printable US-ASCII bytes
// up to a space. ok is false when the field is missing, too long, or holds
// another byte.
func token(b []byte, max int) (string, []byte, bool) {
	i := 0
	for i < len(b) && b[i] != ' ' {
		if b[i] < 33 || b[i] > 126 {
			return "", nil, false
		}
		i++
	}
	if i == 0 || i > max {
		return "", nil, false
	}
	return string(b[:i]), b[i:], true
}

// parse5424 reads the rest of an RFC 5424 message after VERSION SP.
func parse5424(p *parsed, b []byte) {
	names := []string{"timestamp", "hostname", "app_name", "procid", "msgid"}
	limits := []int{64, 255, 48, 128, 32}
	vals := map[string]string{}
	for i, name := range names {
		if i > 0 {
			if len(b) == 0 || b[0] != ' ' {
				p.status = event.ParsePartial
				return
			}
			b = b[1:]
		}
		v, after, ok := token(b, limits[i])
		if !ok {
			p.status = event.ParsePartial
			return
		}
		p.add(name, v)
		vals[name] = v
		b = after
		if name == "timestamp" && v != "-" {
			dt := rfc3339Time(v, FormatRFC5424)
			p.time = &dt
			if slices.Contains(dt.Flags, "invalid-time") {
				p.status = event.ParsePartial
			}
		}
	}
	switch {
	case vals["app_name"] != "-":
		p.subject, p.subjectType = vals["app_name"], SubjectSyslogApp
	case vals["hostname"] != "-":
		p.subject, p.subjectType = vals["hostname"], SubjectSyslogHost
	}
	if len(b) == 0 || b[0] != ' ' {
		p.status = event.ParsePartial
		return
	}
	b = b[1:]
	sd, after, ok := structuredData(b)
	if !ok {
		p.status = event.ParsePartial
		return
	}
	p.add("structured_data", sd)
	if len(after) == 0 {
		return
	}
	if after[0] != ' ' {
		p.status = event.ParsePartial
		return
	}
	msg(p, after[1:])
}

// structuredData reads STRUCTURED-DATA: "-" or one or more SD-ELEMENTs,
// returned verbatim.
func structuredData(b []byte) (string, []byte, bool) {
	if len(b) > 0 && b[0] == '-' {
		return "-", b[1:], true
	}
	i := 0
	for i < len(b) && b[i] == '[' {
		j, ok := sdElement(b, i)
		if !ok {
			return "", nil, false
		}
		i = j
	}
	if i == 0 || !utf8.Valid(b[:i]) {
		return "", nil, false
	}
	return string(b[:i]), b[i:], true
}

// sdElement reads one "[" SD-ID *(SP SD-PARAM) "]" starting at b[i] and
// returns the index after it.
func sdElement(b []byte, i int) (int, bool) {
	i++ // '['
	j, ok := sdName(b, i)
	if !ok {
		return 0, false
	}
	i = j
	for {
		if i >= len(b) {
			return 0, false
		}
		switch b[i] {
		case ']':
			return i + 1, true
		case ' ':
		default:
			return 0, false
		}
		j, ok := sdName(b, i+1)
		if !ok || j+1 >= len(b) || b[j] != '=' || b[j+1] != '"' {
			return 0, false
		}
		i = j + 2
		for {
			if i >= len(b) {
				return 0, false
			}
			if b[i] == '\\' && i+1 < len(b) {
				i += 2
				continue
			}
			if b[i] == '"' {
				i++
				break
			}
			i++
		}
	}
}

// sdName reads an SD-NAME: 1 to 32 printable US-ASCII bytes other than
// '=', space, ']' and '"'.
func sdName(b []byte, i int) (int, bool) {
	j := i
	for j < len(b) && j-i <= 32 {
		c := b[j]
		if c < 33 || c > 126 || c == '=' || c == ']' || c == '"' {
			break
		}
		j++
	}
	return j, j > i && j-i <= 32
}

// msg adds the MSG part as the msg field when it is valid UTF-8. An empty
// MSG adds nothing.
func msg(p *parsed, b []byte) {
	if len(b) == 0 {
		return
	}
	if !utf8.Valid(b) {
		p.status = event.ParsePartial
		return
	}
	p.add("msg", string(b))
}

var months = []string{"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"}

// tagForm is a common RFC 3164 TAG with an optional [PID], then ':'.
var tagForm = regexp.MustCompile(`^([A-Za-z0-9_./-]{1,48})(?:\[([!-Z^-~]{1,128})\])?:`)

// parse3164 reads an RFC 3164 message after PRI: TIMESTAMP SP HOSTNAME SP
// MSG. Without a TIMESTAMP it reads no HOSTNAME: everything after PRI is MSG
// (RFC 3164 section 4.3.3), and the message is partial.
func parse3164(p *parsed, b []byte, d Dialect, rcv time.Time) {
	ts, dt, n := stamp3164(b, rcv)
	if n == 0 || (n < len(b) && b[n] != ' ') {
		p.status = event.ParsePartial
		msg(p, b)
		return
	}
	p.add("timestamp", ts)
	if slices.Contains(dt.Flags, "invalid-time") {
		p.status = event.ParsePartial
	}
	b = b[n:]
	host := ""
	if len(b) > 0 {
		h, after, ok := token(b[1:], 255)
		if !ok {
			p.status = event.ParsePartial
			p.time = &dt
			msg(p, b[1:])
			return
		}
		host = h
		p.add("hostname", h)
		b = after
	}
	if len(b) > 0 {
		b = b[1:]
	}
	if host != "" {
		p.subject, p.subjectType = host, SubjectSyslogHost
	}
	if d == DialectRTAC {
		// The header time is when the RTAC sent the message; the event
		// time is in MSG. It is not the event's device_time.
		if !rtac(p, b) {
			p.status = event.ParsePartial
			msg(p, b)
		}
		return
	}
	p.time = &dt
	if m := tagForm.FindSubmatch(b); m != nil {
		p.add("tag", string(m[1]))
		if m[2] != nil {
			p.add("pid", string(m[2]))
		}
		p.subject, p.subjectType = string(m[1]), SubjectSyslogApp
	}
	if len(b) > 0 {
		msg(p, b)
	}
}

// stamp3164 reads the time where RFC 3164 puts its TIMESTAMP, in one of
// three forms: "Mmm dd hh:mm:ss" (day space-padded or zero-padded), the
// RTAC's "Mmm dd yyyy hh:mm:ss", or an RFC 3339 time. It returns the text,
// its device time and its length; n is 0 when none fits.
func stamp3164(b []byte, rcv time.Time) (string, event.DeviceTime, int) {
	if _, ok := digits(string(b[:min(len(b), 4)]), 0, 4); ok && len(b) >= 20 && b[4] == '-' {
		// An RFC 3339 time: up to the next space.
		end := bytes.IndexByte(b, ' ')
		if end < 0 {
			end = len(b)
		}
		s := string(b[:end])
		if end <= 64 && utf8.ValidString(s) {
			return s, rfc3339Time(s, FormatRFC3339), end
		}
		return "", event.DeviceTime{}, 0
	}
	if len(b) < 15 {
		return "", event.DeviceTime{}, 0
	}
	mo := slices.Index(months, string(b[:3])) + 1
	if mo == 0 || b[3] != ' ' || b[6] != ' ' {
		return "", event.DeviceTime{}, 0
	}
	day := string(b[4:6])
	if day[0] == ' ' {
		day = "0" + day[1:]
	}
	dd, okDay := digits(day, 0, 2)
	if !okDay {
		return "", event.DeviceTime{}, 0
	}
	dt := event.DeviceTime{NativeEncoding: event.EncodingText, Offset: "unknown", OffsetBasis: event.BasisNone, ResolutionNS: 1_000_000_000}
	var y int
	var tm string
	n := 15
	if yy, ok := digits(string(b), 7, 4); ok && len(b) >= 20 && b[11] == ' ' {
		y, tm, n = yy, string(b[12:20]), 20
		dt.Format = FormatYear
	} else {
		tm = string(b[7:15])
		dt.Format = FormatRFC3164
		dt.Flags = []string{"year-absent", "year-assumed"}
	}
	dt.Native = string(b[:n])
	h, mi, s, frac, okTime := parseTime(tm)
	if !okTime || frac != "" || len(tm) != 8 {
		return "", event.DeviceTime{}, 0
	}
	if dt.Format == FormatRFC3164 {
		y = nearestYear(rcv, mo, dd, h, mi, s)
	}
	if y == 0 || dd < 1 || dd > daysIn(y, mo) || h > 23 || mi > 59 || s > 60 || (s == 60 && (h != 23 || mi != 59)) {
		dt.Flags = append(slices.DeleteFunc(dt.Flags, func(f string) bool { return f == "year-assumed" }), "invalid-time")
		return dt.Native, dt, n
	}
	setWall(&dt, y, mo, dd, h, mi, s, "")
	return dt.Native, dt, n
}

// nearestYear assumes the year of a time printed without one: of the
// receive year and the years either side, the one that puts the time
// nearest the receive time, read as UTC because the offset is unknown. It
// returns 0 when no candidate has that date (29 February), or when the
// receive time is unknown.
func nearestYear(rcv time.Time, mo, d, h, mi, s int) int {
	if rcv.IsZero() {
		return 0
	}
	best, bestDiff := 0, time.Duration(0)
	for _, y := range []int{rcv.Year() - 1, rcv.Year(), rcv.Year() + 1} {
		if d > daysIn(y, mo) {
			continue
		}
		diff := time.Date(y, time.Month(mo), d, h, mi, min(s, 59), 0, time.UTC).Sub(rcv)
		if diff < 0 {
			diff = -diff
		}
		if best == 0 || diff < bestDiff {
			best, bestDiff = y, diff
		}
	}
	return best
}

// offsetForm5424 is a TIME-OFFSET C4 can carry: Z, or ±hh:mm up to 14
// hours.
var offsetForm5424 = regexp.MustCompile(`^([+-])(0\d|1[0-4]):([0-5]\d)$`)

// rfc3339Time decodes an RFC 3339 time with its offset on the wire:
// yyyy-mm-ddThh:mm:ss[.frac](Z|±hh:mm). A time that does not fit keeps its
// text with invalid-time.
func rfc3339Time(s, format string) event.DeviceTime {
	dt := event.DeviceTime{Native: s, NativeEncoding: event.EncodingText, Format: format, Offset: "unknown", OffsetBasis: event.BasisNone, ResolutionNS: 1_000_000_000}
	bad := func() event.DeviceTime {
		dt.Offset, dt.OffsetBasis = "unknown", event.BasisNone
		dt.Flags = append(dt.Flags, "invalid-time")
		return dt
	}
	if len(s) < 20 || s[4] != '-' || s[7] != '-' || s[10] != 'T' {
		return bad()
	}
	y, ok1 := digits(s, 0, 4)
	mo, ok2 := digits(s, 5, 2)
	d, ok3 := digits(s, 8, 2)
	if !ok1 || !ok2 || !ok3 {
		return bad()
	}
	rest := s[11:]
	zone := strings.IndexAny(rest, "Z+-")
	if zone < 0 {
		return bad()
	}
	h, mi, sec, frac, ok := parseTime(rest[:zone])
	if !ok {
		return bad()
	}
	off := rest[zone:]
	switch {
	case off == "Z":
		dt.Offset = "+00:00"
	case offsetForm5424.MatchString(off):
		dt.Offset = off
	default:
		return bad()
	}
	dt.OffsetBasis = event.BasisOnWire
	dt.ResolutionNS = 1
	for i := len(frac); i < 9; i++ {
		dt.ResolutionNS *= 10
	}
	if y == 0 || mo < 1 || mo > 12 || d < 1 || d > daysIn(y, mo) || h > 23 || mi > 59 || sec > 60 {
		return bad()
	}
	setWall(&dt, y, mo, d, h, mi, sec, frac)
	if slices.Contains(dt.Flags, "invalid-time") {
		dt.Offset, dt.OffsetBasis = "unknown", event.BasisNone
	}
	return dt
}

// rtacPrefix starts the RTAC Logger MSG (S23 p. 636).
const rtacPrefix = "RTAC Logger: "

// rtac reads the RTAC Logger MSG: "RTAC Logger: " then five parts
// separated by ", ": event time, level, category, tag and description. The
// description may itself hold ", ", so the split stops at five parts. It
// reports false when the MSG does not have that shape.
func rtac(p *parsed, b []byte) bool {
	if !bytes.HasPrefix(b, []byte(rtacPrefix)) || !utf8.Valid(b) {
		return false
	}
	parts := strings.SplitN(string(b[len(rtacPrefix):]), ", ", 5)
	if len(parts) != 5 {
		return false
	}
	p.add("app", strings.TrimSuffix(rtacPrefix, ": "))
	for i, name := range []string{"event_time", "level", "category", "tag", "description"} {
		p.add(name, parts[i])
	}
	p.add("msg", string(b))
	dt := rtacTime(parts[0])
	p.time = &dt
	if slices.Contains(dt.Flags, "invalid-time") {
		p.status = event.ParsePartial
	}
	p.subject, p.subjectType = parts[3], SubjectRTACTag
	if len(parts[4]) <= rtacMaxValue {
		p.value = parts[4]
	}
	return true
}

// rtacTime decodes the RTAC event time, "yyyy-mm-dd hh:mm:ss.fff" in the
// manual's example. The RTAC states no offset for it.
func rtacTime(s string) event.DeviceTime {
	dt := event.DeviceTime{Native: s, NativeEncoding: event.EncodingText, Format: FormatRTAC, Offset: "unknown", OffsetBasis: event.BasisNone, ResolutionNS: 1_000_000_000}
	if len(s) < 19 || s[4] != '-' || s[7] != '-' || s[10] != ' ' {
		dt.Flags = append(dt.Flags, "invalid-time")
		return dt
	}
	y, ok1 := digits(s, 0, 4)
	mo, ok2 := digits(s, 5, 2)
	d, ok3 := digits(s, 8, 2)
	h, mi, sec, frac, ok4 := parseTime(s[11:])
	if ok4 {
		dt.ResolutionNS = 1
		for i := len(frac); i < 9; i++ {
			dt.ResolutionNS *= 10
		}
	}
	if !ok1 || !ok2 || !ok3 || !ok4 || y == 0 || mo < 1 || mo > 12 || d < 1 || d > daysIn(y, mo) || h > 23 || mi > 59 || sec > 60 {
		dt.Flags = append(dt.Flags, "invalid-time")
		return dt
	}
	setWall(&dt, y, mo, d, h, mi, sec, frac)
	return dt
}
