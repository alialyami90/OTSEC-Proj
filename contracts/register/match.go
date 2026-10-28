package register

import (
	"fmt"
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
				if r, err := m.p.Operations[i].render(args); err == nil && r == line {
					return VerdictOperation, m.p.Operations[i].ID
				}
			}
		}
	}
	return VerdictUnlisted, ""
}

// Permit is the egress check: it allows a line only if it classifies as an
// operation or session line that may be sent in phase ph. It returns the
// deciding verdict and entry ID either way, and an error when the line must
// not be sent.
func (m *Matcher) Permit(ph Phase, line string) (Verdict, string, error) {
	v, id := m.Match(line)
	switch v {
	case VerdictOperation:
		if m.p.operation(id).InPhase(ph) {
			return v, id, nil
		}
	case VerdictSessionControl:
		for _, s := range m.p.SessionControl {
			if s.ID == id {
				for _, p := range s.Phases {
					if p == ph {
						return v, id, nil
					}
				}
			}
		}
	}
	return v, id, fmt.Errorf("register: %q (%s %s) may not be sent in phase %s", line, v, id, ph)
}

// Render produces the exact line for an invocable operation with the given
// parameters. It refuses any line that does not classify, through Match, as
// that same operation, so a parameter value can never produce a line a deny
// rule matches (A6 review of C3). Rendering is not the last check: every line
// the transport sends, whoever produced it, must pass Match at egress.
func (m *Matcher) Render(id string, args map[string]string) (string, error) {
	o, ok := m.Operation(id)
	if !ok {
		return "", fmt.Errorf("register: %q is not an invocable operation", id)
	}
	line, err := o.render(args)
	if err != nil {
		return "", err
	}
	if v, got := m.Match(line); v != VerdictOperation || got != id {
		return "", fmt.Errorf("register: %s renders %q, which classifies as %s %s", id, line, v, got)
	}
	return line, nil
}

// RenderRun produces the lines of a run, in order, one per step. Each goes
// through Render, so a step that no longer classifies as its own operation, or
// matches a deny rule, fails the whole run and no line of it is returned. The
// egress check stays per line: every line the transport sends must still pass
// Permit, and a run adds no line the register does not already permit.
func (m *Matcher) RenderRun(id string) ([]string, error) {
	r := m.p.Run(id)
	if r == nil {
		return nil, fmt.Errorf("register: %q is not a run", id)
	}
	lines := make([]string, len(r.Steps))
	for i, step := range r.Steps {
		l, err := m.Render(step, nil)
		if err != nil {
			return nil, fmt.Errorf("register: run %s step %d: %w", id, i+1, err)
		}
		lines[i] = l
	}
	return lines, nil
}

// Run returns the run with this ID.
func (m *Matcher) Run(id string) (*Run, bool) {
	r := m.p.Run(id)
	return r, r != nil
}

// Limits returns the limits of an operation's reply, and false when the
// operation has none (a 0.1 or 0.2 package, or an operation that no run
// uses).
func (m *Matcher) Limits(id string) (Limits, bool) {
	o := m.p.operation(id)
	if o == nil || o.Limits == nil {
		return Limits{}, false
	}
	return *o.Limits, true
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
