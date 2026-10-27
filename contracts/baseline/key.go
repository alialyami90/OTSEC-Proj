package baseline

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"otsec.local/otsec/contracts/event"
)

// Source is the kind of record a key is built from. Closed.
type Source string

const (
	SourceSER    Source = "ser"
	SourceSyslog Source = "syslog"
)

// PRIAbsent is the facility and the severity of a Syslog message whose PRI
// could not be read (D4-4 item 4).
const PRIAbsent = "pri-absent"

// TextMax is the most bytes of a template that Text keeps.
const TextMax = 128

// Key is an event type. Two events are of one type exactly when their keys
// are equal; String is its canonical text form.
type Key struct {
	Source Source `json:"source"`
	// Element and State are set for SER: the element name and its state as
	// printed (C4 normalized.subject and normalized.value).
	Element string `json:"element,omitempty"`
	State   string `json:"state,omitempty"`
	// Facility and Severity are set for Syslog: decimal, from PRI, or both
	// PRIAbsent.
	Facility string `json:"facility,omitempty"`
	Severity string `json:"severity,omitempty"`
	// Template is set for Syslog: "sha256:" and the hex SHA-256 of the
	// template (TemplateOf). The RFC 5424 MSGID is not part of the key
	// (D4-9): a sender chooses it, so a compromised sender could hide a new
	// kind of message under a known MSGID. Two messages sharing one stay apart.
	Template string `json:"template,omitempty"`
}

// String is the key's canonical form, for example "ser|51P1P|Asserted" or
// "syslog|4|6|template|sha256:…". Each part has '%' and '|' percent-escaped,
// so the form is unambiguous and ParseKey reverses it.
func (k Key) String() string {
	switch k.Source {
	case SourceSER:
		return join("ser", k.Element, k.State)
	case SourceSyslog:
		return join("syslog", k.Facility, k.Severity, "template", k.Template)
	}
	return join(string(k.Source))
}

func join(parts ...string) string {
	r := strings.NewReplacer("%", "%25", "|", "%7C")
	for i, p := range parts {
		parts[i] = r.Replace(p)
	}
	return strings.Join(parts, "|")
}

// ParseKey reads the form String writes and checks the key.
func ParseKey(s string) (Key, error) {
	raw := strings.Split(s, "|")
	parts := make([]string, len(raw))
	for i, p := range raw {
		u, err := unescape(p)
		if err != nil {
			return Key{}, fmt.Errorf("baseline: key %q: %w", s, err)
		}
		parts[i] = u
	}
	var k Key
	switch {
	case len(parts) == 3 && parts[0] == "ser":
		k = Key{Source: SourceSER, Element: parts[1], State: parts[2]}
	case len(parts) == 5 && parts[0] == "syslog" && parts[3] == "template":
		k = Key{Source: SourceSyslog, Facility: parts[1], Severity: parts[2], Template: parts[4]}
	default:
		return Key{}, fmt.Errorf("baseline: %q is not a key", s)
	}
	if err := k.Validate(); err != nil {
		return Key{}, err
	}
	if k.String() != s {
		return Key{}, fmt.Errorf("baseline: %q is not in canonical form", s)
	}
	return k, nil
}

func unescape(p string) (string, error) {
	var b strings.Builder
	for i := 0; i < len(p); i++ {
		if p[i] != '%' {
			b.WriteByte(p[i])
			continue
		}
		switch {
		case strings.HasPrefix(p[i:], "%25"):
			b.WriteByte('%')
		case strings.HasPrefix(p[i:], "%7C"):
			b.WriteByte('|')
		default:
			return "", fmt.Errorf("bad escape at byte %d", i)
		}
		i += 2
	}
	return b.String(), nil
}

// Validate checks a key's form.
func (k Key) Validate() error {
	switch k.Source {
	case SourceSER:
		if k.Element == "" || k.State == "" {
			return fmt.Errorf("baseline: a SER key has an element and a state")
		}
		if k.Facility != "" || k.Severity != "" || k.Template != "" {
			return fmt.Errorf("baseline: a SER key has only an element and a state")
		}
		if !utf8.ValidString(k.Element) || !utf8.ValidString(k.State) {
			return fmt.Errorf("baseline: a SER key is UTF-8")
		}
	case SourceSyslog:
		if k.Element != "" || k.State != "" {
			return fmt.Errorf("baseline: a Syslog key has no element or state")
		}
		if (k.Facility == PRIAbsent) != (k.Severity == PRIAbsent) {
			return fmt.Errorf("baseline: facility and severity are both %s or neither", PRIAbsent)
		}
		if k.Facility != PRIAbsent && (!decimalIn(k.Facility, 23) || !decimalIn(k.Severity, 7)) {
			return fmt.Errorf("baseline: facility %q and severity %q are not RFC 5424 values", k.Facility, k.Severity)
		}
		if !sha256Ref.MatchString(k.Template) {
			return fmt.Errorf("baseline: template %q is not sha256:<hex>", k.Template)
		}
	default:
		return fmt.Errorf("baseline: key source %q is not ser or syslog", k.Source)
	}
	return nil
}

// decimalIn reports whether s is a decimal in 0..max, without leading zeros.
func decimalIn(s string, max int) bool {
	n, err := strconv.Atoi(s)
	return err == nil && n >= 0 && n <= max && strconv.Itoa(n) == s
}

// TemplateOf is a message's template: every maximal run of ASCII digits
// replaced by one "#".
func TemplateOf(msg string) string {
	var b strings.Builder
	digits := false
	for i := 0; i < len(msg); i++ {
		c := msg[i]
		if c >= '0' && c <= '9' {
			if !digits {
				b.WriteByte('#')
			}
			digits = true
			continue
		}
		digits = false
		b.WriteByte(c)
	}
	return b.String()
}

// textOf cuts a template to TextMax bytes at a UTF-8 boundary.
func textOf(t string) string {
	if len(t) <= TextMax {
		return t
	}
	n := TextMax
	for n > 0 && !utf8.RuneStart(t[n]) {
		n--
	}
	return t[:n]
}

func sha256Of(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// KeyOf reads the Syslog fields by the names the otsec-syslog parser
// writes (modules/telemetry/normalize, SyslogParser 0.1): "pri" and
// "msg". C4 leaves field names open, so a change to those names in the
// parser is a change to this contract.
//
// KeyOf is the type of a device event, with Text, the readable form shown
// in an alarm (for a template, its first TextMax bytes). ok is false when
// the event has no key: not a SER or Syslog device event, or a SER row
// with no normalized form. KeyOf does not look at flags; Classify does.
func KeyOf(e *event.Event) (k Key, text string, ok bool) {
	if e == nil || e.Origin != event.OriginDevice {
		return Key{}, "", false
	}
	switch e.Kind {
	case event.KindSER:
		n := e.Normalized
		if n == nil || n.Subject == "" || n.Value == "" {
			return Key{}, "", false
		}
		k = Key{Source: SourceSER, Element: n.Subject, State: n.Value}
		return k, textOf(n.Subject + " " + n.Value), true
	case event.KindSyslog:
		return syslogKey(e)
	}
	return Key{}, "", false
}

func syslogKey(e *event.Event) (Key, string, bool) {
	k := Key{Source: SourceSyslog, Facility: PRIAbsent, Severity: PRIAbsent}
	var msg string
	var hasMsg bool
	if e.Native != nil {
		for _, f := range e.Native.Fields {
			switch f.Name {
			case "pri":
				if n, err := strconv.Atoi(f.Value); err == nil && n >= 0 && n <= 191 && strconv.Itoa(n) == f.Value {
					k.Facility, k.Severity = strconv.Itoa(n/8), strconv.Itoa(n%8)
				}
			case "msg":
				msg, hasMsg = f.Value, true
			}
		}
		if !hasMsg {
			// No msg field: a failed parse kept the bytes only, or another
			// parser named its fields differently. The whole record is then
			// the message, so distinct records never merge into one empty
			// template.
			msg = string(e.Native.Bytes)
		}
	}
	t := TemplateOf(msg)
	k.Template = sha256Of([]byte(t))
	return k, textOf(t), true
}
