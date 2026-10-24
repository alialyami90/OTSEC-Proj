package register

import (
	"regexp"
	"strings"
)

// Verdict says what a register makes of one outgoing line.
type Verdict string

const (
	// VerdictOperation: the line is exactly an approved read-only operation.
	VerdictOperation Verdict = "operation"
	// VerdictSessionControl: the line is a session line; only the transport
	// may send it, in its listed phases.
	VerdictSessionControl Verdict = "session-control"
	// VerdictDenied: the line matches a deny rule.
	VerdictDenied Verdict = "denied"
	// VerdictUnlisted: the line matches nothing and is denied by default.
	VerdictUnlisted Verdict = "unlisted"
	// VerdictNotText: the line holds a byte outside printable ASCII.
	VerdictNotText Verdict = "not-text"
)

// Matcher classifies outgoing lines against a validated package.
type Matcher struct {
	p    *Package
	deny []compiled
}

type compiled struct {
	id string
	re *regexp.Regexp
}

// NewMatcher compiles a package that has passed Validate.
func NewMatcher(p *Package) (*Matcher, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return p.compile()
}

func (p *Package) compile() (*Matcher, error) {
	m := &Matcher{p: p}
	for _, d := range p.Denied {
		re, err := compileDeny(d.Pattern)
		if err != nil {
			return nil, err
		}
		m.deny = append(m.deny, compiled{d.ID, re})
	}
	return m, nil
}

func (m *Matcher) denied(line string) string {
	for _, d := range m.deny {
		if d.re.MatchString(line) {
			return d.id
		}
	}
	return ""
}

// Match classifies one line, without its line terminator, and returns the ID
// of the entry that decided it ("" for unlisted and not-text). Approved lines
// are exact: case, spacing and abbreviations must match the template.
func (m *Matcher) Match(line string) (Verdict, string) {
	for i := 0; i < len(line); i++ {
		if line[i] < 0x20 || line[i] > 0x7e {
			return VerdictNotText, ""
		}
	}
	if id := m.denied(line); id != "" {
		return VerdictDenied, id
	}
	for _, s := range m.p.SessionControl {
		if line == s.Line {
			return VerdictSessionControl, s.ID
		}
	}
	if lineRe.MatchString(line) {
		for i := range m.p.Operations {
			if args, ok := m.p.Operations[i].parse(line); ok {
				if r, err := m.p.Operations[i].Render(args); err == nil && r == line {
					return VerdictOperation, m.p.Operations[i].ID
				}
			}
		}
	}
	return VerdictUnlisted, ""
}

// Operation returns the invocable operation with this ID. Session-control
// lines and deny rules are never returned, so a C2 invocation cannot name
// them (C-A2-1).
func (m *Matcher) Operation(id string) (*Operation, bool) {
	o := m.p.operation(id)
	return o, o != nil
}

func (o *Operation) parse(line string) (map[string]string, bool) {
	tmpl := strings.Split(o.Line, " ")
	got := strings.Split(line, " ")
	if len(tmpl) != len(got) {
		return nil, false
	}
	args := map[string]string{}
	for i, tok := range tmpl {
		if mm := paramRe.FindStringSubmatch(tok); mm != nil {
			args[mm[1]] = got[i]
		} else if tok != got[i] {
			return nil, false
		}
	}
	return args, true
}
