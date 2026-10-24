package syslog

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
)

// Message is a rendered message read back by ParseMessage. It exists so that
// tests, A6's harness and a receiving platform can check a message without
// their own parser.
type Message struct {
	Format    Format
	PRI       int
	Timestamp string // as rendered
	Hostname  string
	MsgID     string
	Params    []Param // in order, values unescaped
	Summary   string  // MSG, "" when absent
}

// Get returns the first value of a parameter.
func (m *Message) Get(name string) (string, bool) {
	for _, p := range m.Params {
		if p.Name == name {
			return p.Value, true
		}
	}
	return "", false
}

// All returns every value of a repeated parameter, in order.
func (m *Message) All(name string) []string {
	var out []string
	for _, p := range m.Params {
		if p.Name == name {
			out = append(out, p.Value)
		}
	}
	return out
}

// DeviceText returns the record's native bytes from dtext or dtext_b64. It
// reports false when the message carries neither (left out for size, or the
// event had no bytes).
func (m *Message) DeviceText() ([]byte, bool) {
	if v, ok := m.Get("dtext"); ok {
		return []byte(v), true
	}
	if v, ok := m.Get("dtext_b64"); ok {
		b, err := base64.StdEncoding.DecodeString(v)
		return b, err == nil
	}
	return nil, false
}

// ParseMessage reads a message in the exact shape Render produces, in
// either format. It rejects any control byte, any SD element other than
// otsec@32473, and anything after the SD element other than " " and a MSG.
func ParseMessage(b []byte) (*Message, error) {
	bad := func(format string, a ...any) (*Message, error) {
		return nil, &Error{Code: CodeEventInvalid, Field: "message", Detail: fmt.Sprintf(format, a...)}
	}
	for i, c := range b {
		if c < 0x20 || c == 0x7f {
			return bad("control byte 0x%02x at %d", c, i)
		}
	}
	s := string(b)
	if !strings.HasPrefix(s, "<") {
		return bad("no PRI")
	}
	end := strings.IndexByte(s, '>')
	if end < 2 || end > 4 {
		return bad("bad PRI")
	}
	pri, err := strconv.Atoi(s[1:end])
	if err != nil || pri > 191 || strconv.Itoa(pri) != s[1:end] {
		return bad("bad PRI %q", s[1:end])
	}
	m := &Message{PRI: pri}
	rest := s[end+1:]
	var sdStart string
	if strings.HasPrefix(rest, "1 ") {
		m.Format = FormatRFC5424
		f := strings.SplitN(rest[2:], " ", 6)
		if len(f) != 6 || f[2] != AppName || f[3] != "-" {
			return bad("RFC 5424 header")
		}
		m.Timestamp, m.Hostname, m.MsgID, sdStart = f[0], f[1], f[4], f[5]
	} else {
		m.Format = FormatRFC3164
		if len(rest) < 16 || rest[15] != ' ' {
			return bad("RFC 3164 timestamp")
		}
		m.Timestamp = rest[:15]
		f := strings.SplitN(rest[16:], " ", 4)
		if len(f) != 4 || f[1] != AppName+":" {
			return bad("RFC 3164 header")
		}
		m.Hostname, m.MsgID, sdStart = f[0], f[2], f[3]
	}
	if !strings.HasPrefix(sdStart, "["+SDID) {
		return bad("SD element %s expected", SDID)
	}
	i := len(SDID) + 1
	for {
		if i >= len(sdStart) {
			return bad("unterminated SD element")
		}
		if sdStart[i] == ']' {
			i++
			break
		}
		if sdStart[i] != ' ' {
			return bad("SP expected at %d", i)
		}
		i++
		eq := strings.IndexByte(sdStart[i:], '=')
		if eq < 1 || eq > 32 || i+eq+1 >= len(sdStart) || sdStart[i+eq+1] != '"' {
			return bad("PARAM-NAME at %d", i)
		}
		name := sdStart[i : i+eq]
		if strings.ContainsAny(name, ` ]"`) {
			return bad("PARAM-NAME %q", name)
		}
		i += eq + 2
		var v strings.Builder
		for {
			if i >= len(sdStart) {
				return bad("unterminated PARAM-VALUE for %s", name)
			}
			c := sdStart[i]
			if c == '\\' && i+1 < len(sdStart) && strings.IndexByte(`\"]`, sdStart[i+1]) >= 0 {
				v.WriteByte(sdStart[i+1])
				i += 2
				continue
			}
			if c == '"' {
				i++
				break
			}
			if c == ']' {
				return bad("unescaped ] in %s", name)
			}
			v.WriteByte(c)
			i++
		}
		m.Params = append(m.Params, Param{name, v.String()})
	}
	switch tail := sdStart[i:]; {
	case tail == "":
	case strings.HasPrefix(tail, " ") && len(tail) > 1:
		m.Summary = tail[1:]
	default:
		return bad("unexpected %q after the SD element", tail)
	}
	return m, nil
}

// CheckMessage checks a rendered message against a target: its size, and
// that it parses as the target's format. It is what A6 runs on a
// forwarder's output.
func CheckMessage(b []byte, t *Target) error {
	if len(b) > t.MaxMessageOctets {
		return &Error{Code: CodeTooLarge, Field: "message", Detail: fmt.Sprintf("%d octets, limit %d", len(b), t.MaxMessageOctets)}
	}
	m, err := ParseMessage(b)
	if err != nil {
		return err
	}
	if m.Format != t.Format {
		return &Error{Code: CodeEventInvalid, Field: "message", Detail: fmt.Sprintf("format %s, target wants %s", m.Format, t.Format)}
	}
	return nil
}

// Frame wraps a rendered message for a stream or datagram transport (RFC
// 6587, RFC 5426). RELP frames are built by FrameRELP.
func Frame(msg []byte, f Framing) ([]byte, error) {
	switch f {
	case FramingOctetCounting:
		return append([]byte(strconv.Itoa(len(msg))+" "), msg...), nil
	case FramingNonTransparent:
		// Safe only because a message never holds LF or NUL; check anyway,
		// because one LF would let device content start a second message.
		if bytes.IndexByte(msg, '\n') >= 0 || bytes.IndexByte(msg, 0) >= 0 {
			return nil, &Error{Code: CodeFrameUnsafe, Field: "message", Detail: "LF or NUL in a message for LF framing"}
		}
		return append(append([]byte{}, msg...), '\n'), nil
	case FramingDatagram:
		return append([]byte{}, msg...), nil
	}
	return nil, &Error{Code: CodeFraming, Field: "framing", Detail: fmt.Sprintf("%q is not a stream or datagram framing", f)}
}

// MaxTXNR is the largest RELP transaction number (librelp wraps after it).
const MaxTXNR = 999999999

// FrameRELP builds the RELP "syslog" command frame for one message:
// TXNR SP "syslog" SP DATALEN SP DATA LF.
func FrameRELP(txnr uint64, msg []byte) ([]byte, error) {
	if txnr < 1 || txnr > MaxTXNR {
		return nil, &Error{Code: CodeFraming, Field: "txnr", Detail: fmt.Sprintf("%d is outside 1 to %d", txnr, MaxTXNR)}
	}
	head := fmt.Sprintf("%d syslog %d ", txnr, len(msg))
	return append(append([]byte(head), msg...), '\n'), nil
}
