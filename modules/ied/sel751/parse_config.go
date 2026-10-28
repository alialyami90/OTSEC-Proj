package sel751

import (
	"errors"
	"fmt"
	"strings"
)

// A configuration setting as a SHO form prints it: the name and the value,
// verbatim. parseSection reads them by the rule sel-751-sho/2, which C9
// (contracts/config/doc.go) states line by line. The contract has its own
// reader of the same rule, CheckAgainst, and the node runs both: the two
// are written apart, so an error in one shows as a disagreement.
type cfgSetting struct{ name, value string }

var (
	errCfgTokenize  = errors.New("sel751: a SHO line that does not tokenize")
	errCfgEmptyVal  = errors.New("sel751: a setting with an empty value")
	errCfgAssign    = errors.New("sel751: a value that holds :=")
	errCfgPrintable = errors.New("sel751: a value that is not printable ASCII")
	errCfgSpaces    = errors.New("sel751: a continuation that holds two spaces together")
	errCfgNameTwice = errors.New("sel751: a setting name printed twice")
)

// maxSettingName is the longest setting name (S22 Table 4.84 and the
// settings sheets; C9's settingName).
const maxSettingName = 16

// parseSection reads the settings of one present SHO reply, in printed
// order. A line is blank (only spaces), a setting line (it holds ":="), a
// continuation (it holds none, and directly follows a setting line or
// another continuation) or a heading (anything else). It fails on any line
// it cannot place, rather than skipping it, and on a reply that prints a
// name twice. A reply with no setting is not an error here: the caller
// decides whether the form may be absent (C9, decision 6).
func parseSection(m message) ([]cfgSetting, error) {
	var out []cfgSetting
	seen := map[string]bool{}
	afterSetting := false
	for _, l := range m.lines() {
		raw := string(l.b)
		text := strings.Trim(raw, " ")
		switch {
		case text == "":
			afterSetting = false
		case strings.Contains(raw, ":="):
			ss, err := settingsOnLine(raw)
			if err != nil {
				return nil, err
			}
			for _, s := range ss {
				if seen[s.name] {
					return nil, fmt.Errorf("%w: %s", errCfgNameTwice, s.name)
				}
				seen[s.name] = true
			}
			out = append(out, ss...)
			afterSetting = true
		case afterSetting:
			if strings.Contains(text, "  ") {
				return nil, fmt.Errorf("%w: %q", errCfgSpaces, text)
			}
			if !printable(text) {
				return nil, fmt.Errorf("%w: %q", errCfgPrintable, text)
			}
			out[len(out)-1].value += " " + text
		default:
			// A heading.
		}
	}
	return out, nil
}

// settingsOnLine reads every "NAME := value" on one line. A name starts the
// line after its leading spaces, or follows the previous value after two or
// more spaces; a value ends at the first two spaces or at the line end.
func settingsOnLine(line string) ([]cfgSetting, error) {
	var out []cfgSetting
	i := skipSpaces(line, 0)
	for {
		j := i
		for j < len(line) && nameByte(line[j], j == i) {
			j++
		}
		name := line[i:j]
		if name == "" || len(name) > maxSettingName {
			return nil, fmt.Errorf("%w: %q at column %d", errCfgTokenize, line, i)
		}
		k := skipSpaces(line, j)
		if !strings.HasPrefix(line[k:], ":=") {
			return nil, fmt.Errorf("%w: %q at column %d: %s is not followed by :=", errCfgTokenize, line, j, name)
		}
		v := skipSpaces(line, k+2)
		end := len(line)
		if p := strings.Index(line[v:], "  "); p >= 0 {
			end = v + p
		}
		value := strings.TrimRight(line[v:end], " ")
		switch {
		case value == "":
			return nil, fmt.Errorf("%w: %s in %q", errCfgEmptyVal, name, line)
		case strings.Contains(value, ":="):
			return nil, fmt.Errorf("%w: %s in %q", errCfgAssign, name, line)
		case !printable(value):
			return nil, fmt.Errorf("%w: %s in %q", errCfgPrintable, name, line)
		}
		out = append(out, cfgSetting{name, value})
		i = skipSpaces(line, end)
		if i == len(line) {
			return out, nil
		}
	}
}

func skipSpaces(s string, i int) int {
	for i < len(s) && s[i] == ' ' {
		i++
	}
	return i
}

// nameByte reports whether c may sit in a setting name: A-Z, 0-9 and, after
// the first byte, an underscore.
func nameByte(c byte, first bool) bool {
	return c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || (!first && c == '_')
}

// printable reports whether s is printable ASCII with no space at either
// end, so the value survives a JSON round trip byte for byte.
func printable(s string) bool {
	if s == "" || s[0] == ' ' || s[len(s)-1] == ' ' {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < ' ' || s[i] > '~' {
			return false
		}
	}
	return true
}
