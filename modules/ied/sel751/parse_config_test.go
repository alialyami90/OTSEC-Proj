package sel751

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/adapter"
	"otsec.local/otsec/contracts/config"
)

func cfg(text string) message { return message{text: []byte(text), off: fuzzOff} }

func pairs(ss []cfgSetting) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = s.name + "=" + s.value
	}
	return out
}

// TestParseSectionRule is the rule sel-751-sho/2 (contracts/config/doc.go)
// line by line.
func TestParseSectionRule(t *testing.T) {
	for name, c := range map[string]struct {
		in   string
		want []string
		err  error
	}{
		"empty reply":              {"", nil, nil},
		"a heading and blanks":     {"Group 1\r\n\r\n  \r\n", nil, nil},
		"one setting":              {"CTR := 120\r\n", []string{"CTR=120"}, nil},
		"no space before the :=":   {"CTR:= 120\r\n", []string{"CTR=120"}, nil},
		"spaces around the :=":     {"  CTR   :=   120\r\n", []string{"CTR=120"}, nil},
		"two on a line":            {"MAXACC  := 2     LANG  := ENGLISH\r\n", []string{"MAXACC=2", "LANG=ENGLISH"}, nil},
		"three on a line":          {"A := 1  B := 2  C := 3\r\n", []string{"A=1", "B=2", "C=3"}, nil},
		"a value with one space":   {"TID := FEEDER 1\r\n", []string{"TID=FEEDER 1"}, nil},
		"underscore after first":   {"LEA_S_R := 180.00\r\n", []string{"LEA_S_R=180.00"}, nil},
		"a 16 character name":      {"ABCDEFGHIJKLMNOP := 1\r\n", []string{"ABCDEFGHIJKLMNOP=1"}, nil},
		"a value with a colon":     {"TIME := 12:30:00\r\n", []string{"TIME=12:30:00"}, nil},
		"bare LF and CR":           {"A := 1\nB := 2\rC := 3\r\n", []string{"A=1", "B=2", "C=3"}, nil},
		"an equation":              {"50P1P := 10.00 OR IN101\r\n", []string{"50P1P=10.00 OR IN101"}, nil},
		"a heading between":        {"A := 1\r\n\r\nPort 1\r\nB := 2\r\n", []string{"A=1", "B=2"}, nil},
		"a wrapped value":          {"SV1 := A AND B\r\n  AND C\r\n", []string{"SV1=A AND B AND C"}, nil},
		"two continuations":        {"SV1 := A\r\nB\r\nC\r\n", []string{"SV1=A B C"}, nil},
		"a header before the body": {"SEL-751  Date: 10/24/2026  Time: 09:15:04.112\r\nCTR := 120\r\n", []string{"CTR=120"}, nil},
		"a blank ends a wrap":      {"A := 1\r\n\r\nheading\r\nB := 2\r\n", []string{"A=1", "B=2"}, nil},

		"an empty value":                    {"A :=\r\n", nil, errCfgEmptyVal},
		"spaces then a name and :=":         {"A :=    B := 2\r\n", nil, errCfgAssign},
		"a name that starts with _":         {"_A := 1\r\n", nil, errCfgTokenize},
		"a lower-case name":                 {"ctr := 1\r\n", nil, errCfgTokenize},
		"a 17 character name":               {"ABCDEFGHIJKLMNOPQ := 1\r\n", nil, errCfgTokenize},
		"no name":                           {":= 1\r\n", nil, errCfgTokenize},
		"text before the name":              {"Hidden if X := 1\r\n", nil, errCfgTokenize},
		"a trailing word":                   {"A := 1  and more\r\n", nil, errCfgTokenize},
		"a := in a value":                   {"A := B := C\r\n", nil, errCfgAssign},
		"a control byte":                    {"A := 1\x01\r\n", nil, errCfgPrintable},
		"a high byte":                       {"A := \xe9\r\n", nil, errCfgPrintable},
		"a continuation holding two spaces": {"A := 1\r\nx  y\r\n", nil, errCfgSpaces},
		"a control byte in a continuation":  {"A := 1\r\nx\x00y\r\n", nil, errCfgPrintable},
		"a name twice":                      {"A := 1\r\nB := 2\r\nA := 3\r\n", nil, errCfgNameTwice},
		"a name twice on a line":            {"A := 1  A := 2\r\n", nil, errCfgNameTwice},
	} {
		got, err := parseSection(cfg(c.in))
		if c.err != nil {
			if !errors.Is(err, c.err) {
				t.Errorf("%s: %v, want %v", name, err, c.err)
			}
			continue
		}
		if err != nil || !reflect.DeepEqual(pairs(got), c.want) && !(len(got) == 0 && len(c.want) == 0) {
			t.Errorf("%s: %q, %v, want %q", name, pairs(got), err, c.want)
		}
	}
}

// Each present section of the contract's golden reads gives the settings its
// snapshot holds: the adapter's reader and the contract's agree (C9, decision
// 4). The goldens are constructed, not captured (simulated).
func TestParseSectionMatchesGoldens(t *testing.T) {
	dir := filepath.Join("..", "..", "..", "contracts", "config", "testdata")
	for _, n := range []string{"1", "2", "3"} {
		var tr adapter.Transcript
		b, err := os.ReadFile(filepath.Join(dir, "transcripts", "read-"+n+".json"))
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(b, &tr); err != nil {
			t.Fatal(err)
		}
		b, err = os.ReadFile(filepath.Join(dir, "valid", "snapshot-read-"+n+".json"))
		if err != nil {
			t.Fatal(err)
		}
		s, err := config.DecodeSnapshot(b)
		if err != nil {
			t.Fatal(err)
		}
		present := 0
		for _, sec := range s.Sections {
			if sec.State != config.Present {
				continue
			}
			present++
			m := message{text: tr.Data[sec.Span.Offset : sec.Span.Offset+sec.Span.Length], off: sec.Span.Offset}
			got, err := parseSection(m)
			if err != nil {
				t.Errorf("read %s %s: %v", n, sec.Class, err)
				continue
			}
			want := make([]string, len(sec.Settings))
			for i, st := range sec.Settings {
				want[i] = st.Name + "=" + st.Value
			}
			if !reflect.DeepEqual(pairs(got), want) {
				t.Errorf("read %s %s: %d settings, want %d:\n got %q\nwant %q", n, sec.Class, len(got), len(want), pairs(got), want)
			}
		}
		if present == 0 {
			t.Errorf("read %s has no present section", n)
		}
	}
}

// FuzzParseSection: for any input, no panic; on success every name is a valid
// name once, every value printable with no space at either end and no :=, and
// printing the settings back one per line and reading again gives the same
// settings (so a reader and a writer agree on the same thing).
func FuzzParseSection(f *testing.F) {
	for _, s := range []string{
		"Group 1\r\n\r\nCTR := 120\r\nMAXACC  := 2     LANG  := ENGLISH\r\n",
		"SV1 := A AND B\r\n  AND C\r\n",
		"A := 1\r\nA := 2\r\n",
		"A :=\r\n",
		"A := B := C\r\n",
		"x  y := 1\r\n",
		"SEL-751  Date: 10/24/2026\r\nCTR := 1\r\n",
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, text []byte) {
		if !framedText(text) {
			return
		}
		got, err := parseSection(message{text: text, off: fuzzOff})
		if err != nil {
			if got != nil {
				t.Fatalf("an error and %d settings", len(got))
			}
			return
		}
		seen := map[string]bool{}
		var b strings.Builder
		for _, s := range got {
			if s.name == "" || len(s.name) > maxSettingName || seen[s.name] {
				t.Fatalf("name %q", s.name)
			}
			seen[s.name] = true
			for i := 0; i < len(s.name); i++ {
				if !nameByte(s.name[i], i == 0) {
					t.Fatalf("name %q", s.name)
				}
			}
			if !printable(s.value) || strings.Contains(s.value, ":=") {
				t.Fatalf("%s value %q", s.name, s.value)
			}
			b.WriteString(s.name + " := " + s.value + "\r\n")
		}
		again, err := parseSection(cfg(b.String()))
		if err != nil || !reflect.DeepEqual(again, got) && !(len(again) == 0 && len(got) == 0) {
			t.Fatalf("printed back and read again: %q, %v; was %q", pairs(again), err, pairs(got))
		}
	})
}
