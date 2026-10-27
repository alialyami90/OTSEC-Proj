package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"

	"otsec.local/otsec/contracts/adapter"
)

// CheckAgainst checks a snapshot against the transcript of the session that
// read it. It confirms four things:
//
//   - the transcript is the one the snapshot names;
//   - each section's bytes are received operate-phase bytes, unredacted and
//     unframed, with the SHA-256 the section states;
//   - an absent section's reply is the rule's "not available" text;
//   - a present section's settings are exactly what the rule reads from its
//     bytes (doc.go): the same names and values, in the same order.
//
// The node runs it on every snapshot before storing it, as it runs C2's
// CheckLines on every result. So an adapter parser that drops, merges or
// splits a setting fails closed instead of producing a wrong baseline. The
// rule's tokenizer here is the contract's statement of the rule. The adapter
// has its own parser, and this check makes the two agree.
func (s Snapshot) CheckAgainst(t adapter.Transcript) error {
	if err := s.Validate(); err != nil {
		return err
	}
	c := &check{}
	sum := sha256.Sum256(t.Data)
	if hex.EncodeToString(sum[:]) != t.SHA256 || t.SHA256 != s.Transcript.SHA256 || int64(len(t.Data)) != s.Transcript.Length {
		c.fail("the transcript is not the one the snapshot names (sha256 %s, %d bytes)", s.Transcript.SHA256, s.Transcript.Length)
		return c.err("snapshot")
	}
	rule := Rules[s.Rule]
	for i, sec := range s.Sections {
		p := fmt.Sprintf("sections[%d] (%s)", i, sec.Class)
		sp := sec.Span
		if !c.replySpan(p, sp, t) {
			continue
		}
		text := t.Data[sp.Offset : sp.Offset+sp.Length]
		if sum := sha256.Sum256(text); hex.EncodeToString(sum[:]) != sec.SHA256 {
			c.fail("%s: sha256 does not match the section's bytes", p)
		}
		notAvailable := string(bytes.Trim(text, " \r\n")) == rule.NotAvailable
		if sec.State == Absent {
			if !notAvailable {
				c.fail("%s: absent, but the reply is not %q", p, rule.NotAvailable)
			}
			continue
		}
		if notAvailable {
			c.fail("%s: present, but the relay answered %q", p, rule.NotAvailable)
			continue
		}
		got, err := tokenize(text)
		if err != nil {
			c.fail("%s: %v", p, err)
			continue
		}
		if !equalSettings(got, sec.Settings) {
			c.fail("%s: the settings are not what rule %s reads from the section's bytes (%d read, %d reported)", p, rule.ID, len(got), len(sec.Settings))
		}
	}
	return c.err("snapshot")
}

// replySpan checks that a section's span is received operate-phase bytes,
// touches no redaction and holds no framing byte.
func (c *check) replySpan(p string, sp adapter.Span, t adapter.Transcript) bool {
	if sp.Offset < 0 || sp.Length <= 0 || sp.Offset+sp.Length > int64(len(t.Data)) {
		c.fail("%s: span lies outside the transcript", p)
		return false
	}
	covered := int64(0)
	for _, sg := range t.Segments {
		lo, hi := max(sp.Offset, sg.Offset), min(sp.Offset+sp.Length, sg.Offset+sg.Length)
		if lo >= hi {
			continue
		}
		if sg.Dir != adapter.Received || sg.Phase != adapter.PhaseOperate {
			c.fail("%s: span covers bytes that are not received in the operate phase", p)
			return false
		}
		covered += hi - lo
	}
	if covered != sp.Length {
		c.fail("%s: span is not covered by the transcript's segments", p)
		return false
	}
	for _, rd := range t.Redactions {
		if sp.Offset < rd.Offset+rd.Length && rd.Offset < sp.Offset+sp.Length {
			c.fail("%s: span overlaps a redaction", p)
			return false
		}
	}
	if bytes.ContainsAny(t.Data[sp.Offset:sp.Offset+sp.Length], "\x02\x03") {
		c.fail("%s: span includes an STX or ETX framing byte; a section is the message text inside them", p)
		return false
	}
	return true
}

var (
	// header is the command-response header of S22 p. 7.31: "Date: <d>
	// Time: <t>" on the RID line and "Time Source: <s>" on the TID line.
	header   = regexp.MustCompile(`Date: \S+ +Time: \S+|Time Source: \S+`)
	nameAt   = regexp.MustCompile(`^[A-Z0-9][A-Z0-9_]*`)
	assignAt = regexp.MustCompile(`^ *:= *`)
)

// tokenize reads a present section's settings by the rule in doc.go. It
// fails on any line it cannot place, rather than skip it.
func tokenize(text []byte) ([]Setting, error) {
	const (
		other = iota
		settingLine
	)
	var out []Setting
	seen := map[string]bool{}
	prev := other
	for off := 0; off < len(text); {
		end := off
		for end < len(text) && text[end] != '\r' && text[end] != '\n' {
			end++
		}
		next := end
		if next < len(text) && text[next] == '\r' {
			next++
		}
		if next < len(text) && text[next] == '\n' && (next == end || text[end] == '\r') {
			next++
		}
		line := string(text[off:end])
		off = next
		trimmed := strings.Trim(line, " ")
		switch {
		case trimmed == "":
			prev = other
		case header.MatchString(line):
			prev = other
		case strings.Contains(line, ":="):
			sets, err := settingsOf(line)
			if err != nil {
				return nil, err
			}
			for _, st := range sets {
				if seen[st.Name] {
					return nil, fmt.Errorf("%s is printed twice", st.Name)
				}
				seen[st.Name] = true
			}
			out = append(out, sets...)
			prev = settingLine
		case prev == settingLine:
			// A continuation of the last setting on the line before.
			if strings.Contains(trimmed, "  ") {
				return nil, fmt.Errorf("continuation %q holds two spaces together", trimmed)
			}
			if !valueText.MatchString(trimmed) {
				return nil, fmt.Errorf("continuation %q is not printable ASCII", trimmed)
			}
			out[len(out)-1].Value += " " + trimmed
		default:
			prev = other // a heading
		}
	}
	return out, nil
}

// settingsOf reads the settings of one setting line.
func settingsOf(line string) ([]Setting, error) {
	var out []Setting
	i := len(line) - len(strings.TrimLeft(line, " "))
	for {
		name := nameAt.FindString(line[i:])
		if name == "" || !settingName.MatchString(name) {
			return nil, fmt.Errorf("setting line %q does not tokenize at column %d", line, i)
		}
		i += len(name)
		a := assignAt.FindString(line[i:])
		if a == "" {
			return nil, fmt.Errorf("setting line %q does not tokenize at column %d: %s is not followed by :=", line, i, name)
		}
		i += len(a)
		vEnd := strings.Index(line[i:], "  ")
		if vEnd < 0 {
			vEnd = len(strings.TrimRight(line[i:], " "))
		}
		value := line[i : i+vEnd]
		if value == "" {
			return nil, fmt.Errorf("setting line %q: %s has an empty value", line, name)
		}
		if strings.Contains(value, ":=") {
			return nil, fmt.Errorf("setting line %q: the value of %s holds :=", line, name)
		}
		if !valueText.MatchString(value) {
			return nil, fmt.Errorf("setting line %q: the value of %s is not printable ASCII", line, name)
		}
		out = append(out, Setting{Name: name, Value: value})
		i += vEnd
		rest := strings.TrimLeft(line[i:], " ")
		if rest == "" {
			return out, nil
		}
		i = len(line) - len(rest)
	}
}

func equalSettings(a, b []Setting) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
