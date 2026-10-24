package sel751

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"

	"otsec.local/otsec/contracts/adapter"
)

// setting is one "NAME := value" from a SHO report (S22 Section 4 tables;
// the SHO P 1 layout in the C2 goldens is one setting per line, which is an
// assumption until H-13). A relay may print several settings on one line,
// separated by two or more spaces, so the parser takes every pair on a
// line.
type setting struct {
	name, value string
	span        adapter.Span // "NAME := value", as printed (C2 warning span)
}

var settingRE = regexp.MustCompile(`([A-Z][A-Z0-9_]*) *:= *(\S+(?: \S+)*?)(?: {2,}|$)`)

var errMalformedSetting = errors.New("sel751: a setting without a name or a value")

// parseSettings reads every setting of a SHO message. A line with a ":="
// must be settings and nothing else: the pairs tile it, with only spaces
// before, between and after them. Anything else on such a line, a ":=" the
// grammar does not account for, or a name printed twice, is an error: a
// check such as LANG := ENGLISH must never pass on a line the parser half
// read.
func parseSettings(m message) (map[string]setting, error) {
	out := map[string]setting{}
	for _, l := range m.lines() {
		t := l.trimmed()
		n := bytes.Count(t, []byte(":="))
		if n == 0 {
			continue
		}
		gs := settingRE.FindAllSubmatchIndex(t, -1)
		if len(gs) != n || !tiles(t, gs) {
			return nil, fmt.Errorf("%w: %q", errMalformedSetting, t)
		}
		for _, g := range gs {
			name := string(t[g[2]:g[3]])
			if _, dup := out[name]; dup {
				return nil, fmt.Errorf("%w: setting %q", errDuplicateKey, name)
			}
			out[name] = setting{name: name, value: string(t[g[4]:g[5]]), span: l.span(g[2], g[5])}
		}
	}
	return out, nil
}

// tiles reports whether the matches cover t from its first non-space byte
// to its end, each starting where the one before ended. Each match takes
// the spaces after its value, so nothing else lies between them.
func tiles(t []byte, gs [][]int) bool {
	at := len(t) - len(bytes.TrimLeft(t, " "))
	for _, g := range gs {
		if g[0] != at {
			return false
		}
		at = g[1]
	}
	return at == len(t)
}
