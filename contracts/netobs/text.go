package netobs

import (
	"fmt"
	"strings"
)

// Text is a value the sensor read from the wire as text: a banner, an HTTP
// Server header, a Telnet ID reply field, an SNMP sysDescr, a TLS SNI, a
// user name. It is hostile input (C13 §3.1). Value holds at most the first
// MaxTextBytes bytes of the original, escaped as printable ASCII: each byte
// 0x20 to 0x7E except '\' stands for itself, '\' is written "\\", and every
// other byte "\xHH" in lowercase hex. Nothing interprets Value.
type Text struct {
	Value     string `json:"value"`
	Length    int64  `json:"length"`
	Truncated bool   `json:"truncated"`
}

// NewText keeps the first MaxTextBytes bytes of b, escaped.
func NewText(b []byte) Text {
	t := Text{Length: int64(len(b)), Truncated: len(b) > MaxTextBytes}
	if t.Truncated {
		b = b[:MaxTextBytes]
	}
	t.Value = escape(b)
	return t
}

// Bytes returns the kept bytes Value stands for, or an error when Value is
// not in the escaped form.
func (t Text) Bytes() ([]byte, error) {
	if len(t.Value) > MaxTextEscaped {
		return nil, fmt.Errorf("value is %d bytes, above %d", len(t.Value), MaxTextEscaped)
	}
	out := make([]byte, 0, len(t.Value))
	for i := 0; i < len(t.Value); {
		ch := t.Value[i]
		switch {
		case ch < 0x20 || ch > 0x7e:
			return nil, fmt.Errorf("byte 0x%02x at %d is not printable ASCII", ch, i)
		case ch != '\\':
			out = append(out, ch)
			i++
		case i+1 < len(t.Value) && t.Value[i+1] == '\\':
			out = append(out, '\\')
			i += 2
		case i+3 < len(t.Value) && t.Value[i+1] == 'x' && lowerHex(t.Value[i+2]) && lowerHex(t.Value[i+3]):
			out = append(out, unhex(t.Value[i+2])<<4|unhex(t.Value[i+3]))
			i += 4
		default:
			return nil, fmt.Errorf("escape at %d is not \\\\ or \\xHH in lowercase", i)
		}
	}
	// Only the canonical form is accepted: "\x41" for 'A' would let two
	// values stand for the same bytes.
	if escape(out) != t.Value {
		return nil, fmt.Errorf("value is not in the canonical escaped form")
	}
	return out, nil
}

// check fails c unless t is in C13 §3.1's form: Value decodes to exactly
// min(Length, MaxTextBytes) bytes, and Truncated says Length exceeds it.
func (t Text) check(c *checker, field string) {
	b, err := t.Bytes()
	switch {
	case err != nil:
		c.fail(CodeForm, field+".value", "%v", err)
	case t.Length < 0:
		c.fail(CodeRange, field+".length", "%d is negative", t.Length)
	case int64(len(b)) != min(t.Length, MaxTextBytes):
		c.fail(CodeConflict, field+".value", "decodes to %d bytes; length %d keeps %d", len(b), t.Length, min(t.Length, MaxTextBytes))
	case t.Truncated != (t.Length > MaxTextBytes):
		c.fail(CodeConflict, field+".truncated", "%v, but length is %d", t.Truncated, t.Length)
	}
}

func escape(b []byte) string {
	var s strings.Builder
	for _, ch := range b {
		switch {
		case ch == '\\':
			s.WriteString(`\\`)
		case ch >= 0x20 && ch <= 0x7e:
			s.WriteByte(ch)
		default:
			fmt.Fprintf(&s, `\x%02x`, ch)
		}
	}
	return s.String()
}

func lowerHex(ch byte) bool { return ch >= '0' && ch <= '9' || ch >= 'a' && ch <= 'f' }

func unhex(ch byte) byte {
	if ch <= '9' {
		return ch - '0'
	}
	return ch - 'a' + 10
}
