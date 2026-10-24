package register

import (
	"bufio"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"
)

const golden = "testdata/sel-751-phase0.json"

func load(t *testing.T) *Package {
	t.Helper()
	data, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	p, err := Decode(data)
	if err != nil {
		t.Fatalf("golden package invalid: %v", err)
	}
	return p
}

// mutate decodes the golden package loosely, applies f, and returns the
// re-encoded bytes for Decode to judge.
func mutate(t *testing.T, f func(m map[string]any)) []byte {
	t.Helper()
	data, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	f(m)
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func list(m map[string]any, key string) []any { return m[key].([]any) }
func entry(m map[string]any, key string, i int) map[string]any {
	return list(m, key)[i].(map[string]any)
}

func TestGoldenShape(t *testing.T) {
	p := load(t)
	if len(p.Operations) != 4 || len(p.SessionControl) != 2 || len(p.Denied) != 38 {
		t.Fatalf("got %d operations, %d session lines, %d deny rules; want 4, 2, 38",
			len(p.Operations), len(p.SessionControl), len(p.Denied))
	}
}

// TestPhase0Lossless checks that every field of A2's Phase 0 draft register
// survives the conversion (P1-A1 acceptance test).
func TestPhase0Lossless(t *testing.T) {
	p := load(t)
	data, err := os.ReadFile("../../docs/phase0/A2-command-register-draft.json")
	if err != nil {
		t.Fatal(err)
	}
	var draft struct {
		Commands []struct {
			ID, Pattern, Classification, Citation, Status, SideEffects, Notes string
			AccessLevel                                                       *string
		}
	}
	// The draft uses snake_case keys only for these two fields.
	data = []byte(strings.NewReplacer(`"side_effects"`, `"SideEffects"`, `"access_level"`, `"AccessLevel"`).Replace(string(data)))
	if err := json.Unmarshal(data, &draft); err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, c := range draft.Commands {
		var line, effects, notes, level string
		var cites []Citation
		var ev Evidence
		switch {
		case p.operation(c.ID) != nil:
			o := p.operation(c.ID)
			line, effects, notes, level, cites, ev = o.Line, o.SideEffects, o.Notes, o.AccessLevel, o.Citations, o.Evidence
		default:
			ok := false
			for _, s := range p.SessionControl {
				if s.ID == c.ID {
					line, effects, notes, level, cites, ev, ok = s.Line, s.SideEffects, s.Notes, s.AccessLevel, s.Citations, s.Evidence, true
				}
			}
			for _, d := range p.Denied {
				if d.ID == c.ID {
					line, effects, notes, level, cites, ev, ok = d.Pattern, d.SideEffects, d.Notes, d.AccessLevel, d.Citations, d.Evidence, true
				}
			}
			if !ok {
				t.Errorf("%s: missing from the package", c.ID)
				continue
			}
		}
		found++
		if line != c.Pattern || effects != c.SideEffects || notes != c.Notes {
			t.Errorf("%s: line, side effects or notes changed", c.ID)
		}
		if c.AccessLevel != nil && level != *c.AccessLevel {
			t.Errorf("%s: access level %q, draft %q", c.ID, level, *c.AccessLevel)
		}
		if got := joinCitations(cites); stripSources(got) != stripSources(c.Citation) {
			t.Errorf("%s: citations rejoin to %q, draft %q", c.ID, got, c.Citation)
		}
		want := c.Status
		if ev.Note != "" {
			want = strings.TrimSpace(strings.TrimPrefix(want, string(ev.Class)))
			if want != "("+ev.Note+")" && want != ev.Note {
				t.Errorf("%s: evidence %+v, draft %q", c.ID, ev, c.Status)
			}
		} else if string(ev.Class) != want {
			t.Errorf("%s: evidence %+v, draft %q", c.ID, ev, c.Status)
		}
	}
	if found != len(p.Operations)+len(p.SessionControl)+len(p.Denied) {
		t.Errorf("package has entries the draft does not")
	}
}

// stripSources drops a leading source ID from each part, so a source written
// once and one repeated before every part compare equal.
func stripSources(s string) string {
	parts := strings.Split(s, "; ")
	for i, p := range parts {
		if f := strings.SplitN(p, " ", 2); len(f) == 2 && len(f[0]) > 1 && f[0][0] == 'S' && strings.Trim(f[0][1:], "0123456789") == "" {
			parts[i] = f[1]
		}
	}
	return strings.Join(parts, "; ")
}

func joinCitations(cs []Citation) string {
	var parts []string
	prev := ""
	for _, c := range cs {
		if c.Source != prev && c.Source != "A2-P0" {
			parts = append(parts, c.Source+" "+c.Ref)
		} else {
			parts = append(parts, c.Ref)
		}
		prev = c.Source
	}
	return strings.Join(parts, "; ")
}

func corpus(t *testing.T, name string) []string {
	t.Helper()
	f, err := os.Open("../../tests/safety/register_review/" + name)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		raw := sc.Text()
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}
		// The corpus uses Python unicode_escape; \t and \xNN are what occurs.
		s, err := strconv.Unquote(`"` + strings.ReplaceAll(raw, `"`, `\"`) + `"`)
		if err != nil {
			t.Fatalf("%s: cannot decode %q: %v", name, raw, err)
		}
		out = append(out, s)
	}
	return out
}

// TestA6Corpora: A6's deny corpus never yields an invocable operation; every
// line of A6's allow corpus is an operation or a session line (ACC and QUI are
// session-control under C-A2-1).
func TestA6Corpora(t *testing.T) {
	m, err := NewMatcher(load(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range corpus(t, "sel-deny-corpus.txt") {
		if v, id := m.Match(l); v == VerdictOperation || v == VerdictSessionControl {
			t.Errorf("deny corpus %q classified %s (%s)", l, v, id)
		}
	}
	for _, l := range corpus(t, "allow-corpus.txt") {
		if v, _ := m.Match(l); v != VerdictOperation && v != VerdictSessionControl {
			t.Errorf("allow corpus %q classified %s", l, v)
		}
	}
}

func TestSessionControlNotInvocable(t *testing.T) {
	m, err := NewMatcher(load(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"sel.session.acc", "sel.session.qui", "sel.ser.clear", "sel.nonexistent"} {
		if _, ok := m.Operation(id); ok {
			t.Errorf("Operation(%q) returned an invocable operation", id)
		}
	}
	if o, ok := m.Operation("sel.ser.read_all"); !ok || o.Line != "SER" {
		t.Errorf("Operation(sel.ser.read_all) = %v, %v", o, ok)
	}
	if v, id := m.Match("ACC"); v != VerdictSessionControl || id != "sel.session.acc" {
		t.Errorf("Match(ACC) = %s %s", v, id)
	}
	for _, l := range []string{"ser", "SER ", " SER", "SER\t", "SHO  G", "SHO P 2", "ID\r"} {
		if v, _ := m.Match(l); v == VerdictOperation {
			t.Errorf("Match(%q) is an operation; approved lines are exact", l)
		}
	}
}

func TestFirmwareDecide(t *testing.T) {
	p := load(t)
	allowed, err := p.Firmware.Decide("SEL-751-R501-V0-Z104101-D20260910")
	if err != nil || allowed.Status != BranchAllow {
		t.Fatalf("R501-V0: %v %v", allowed, err)
	}
	for _, fid := range []string{
		"SEL-751-R501-V0-Z104101-D20260911", // not in Appendix A
		"sel-751-r501-v0-z104101-d20260910", // not exact
		"SEL-751-R302-V0-Z008008-D20220826", // whatever its suffix, R302 is denied or unknown
		"",
	} {
		if _, err := p.Firmware.Decide(fid); err == nil {
			t.Errorf("Decide(%q) allowed", fid)
		}
	}
	for _, k := range p.Firmware.Known {
		if k.Branch == "R400" && k.Version < 7 {
			if _, err := p.Firmware.Decide(k.FID); err == nil {
				t.Errorf("Decide(%s) allowed below R400 minimum V7", k.FID)
			}
		}
	}
	for _, b := range p.Firmware.Branches {
		if b.Branch == "R402" && (b.Status != BranchAllowWithCondition || b.Conditions[0].Setting != "EHTTP") {
			t.Errorf("R402 lost its EHTTP := N condition: %+v", b)
		}
	}
}

func TestRejects(t *testing.T) {
	cases := map[string]func(m map[string]any){
		"unknown top-level field": func(m map[string]any) { m["extra"] = true },
		"wrong contract":          func(m map[string]any) { m["contract"] = "otsec.register/1.0" },
		"revision zero":           func(m map[string]any) { m["revision"] = 0 },
		"free-form line": func(m map[string]any) {
			entry(m, "operations", 0)["line"] = "SER.*"
		},
		"lower-case line": func(m map[string]any) { entry(m, "operations", 0)["line"] = "ser" },
		"tab in line":     func(m map[string]any) { entry(m, "operations", 0)["line"] = "SHO\tG" },
		"double space":    func(m map[string]any) { entry(m, "operations", 0)["line"] = "SHO  G" },
		"state-changing operation": func(m map[string]any) {
			entry(m, "operations", 0)["classification"] = "state-changing"
		},
		"session line in operations": func(m map[string]any) {
			m["operations"] = append(list(m, "operations"), entry(m, "session_control", 0))
		},
		"session line without phase": func(m map[string]any) {
			entry(m, "session_control", 0)["phases"] = []any{}
		},
		"session line unknown phase": func(m map[string]any) {
			entry(m, "session_control", 0)["phases"] = []any{"operate"}
		},
		"approved line matches deny rule": func(m map[string]any) {
			entry(m, "operations", 0)["line"] = "TRI"
		},
		"duplicate ID": func(m map[string]any) {
			entry(m, "operations", 1)["id"] = entry(m, "operations", 0)["id"]
		},
		"no citation": func(m map[string]any) { entry(m, "operations", 0)["citations"] = []any{} },
		"unknown cited source": func(m map[string]any) {
			entry(m, "operations", 0)["citations"].([]any)[0].(map[string]any)["source"] = "S99"
		},
		"unknown evidence class": func(m map[string]any) { entry(m, "operations", 0)["evidence"] = map[string]any{"class": "probably"} },
		"no side effects":        func(m map[string]any) { entry(m, "operations", 0)["side_effects"] = "" },
		"bad deny pattern":       func(m map[string]any) { entry(m, "denied", 0)["pattern"] = "(?P<x" },
		"precondition read by deny rule": func(m map[string]any) {
			list(m, "preconditions")[0].(map[string]any)["read_by"] = "sel.ser.clear"
		},
		"precondition read by session line": func(m map[string]any) {
			list(m, "preconditions")[0].(map[string]any)["read_by"] = "sel.session.qui"
		},
		"unknown param kind": func(m map[string]any) {
			o := entry(m, "operations", 0)
			o["line"] = o["line"].(string) + " {n}"
			o["params"] = []any{map[string]any{"name": "n", "kind": "regex", "values": []any{"1"}}}
		},
		"firmware branch without rule": func(m map[string]any) {
			fw := m["firmware"].(map[string]any)
			fw["branches"] = fw["branches"].([]any)[1:]
		},
		"condition missing": func(m map[string]any) {
			for _, b := range m["firmware"].(map[string]any)["branches"].([]any) {
				if b.(map[string]any)["status"] == "allow-with-condition" {
					delete(b.(map[string]any), "conditions")
				}
			}
		},
		"unknown branch status": func(m map[string]any) {
			m["firmware"].(map[string]any)["branches"].([]any)[0].(map[string]any)["status"] = "maybe"
		},
	}
	for name, f := range cases {
		if _, err := Decode(mutate(t, f)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := Decode(append(mutate(t, func(map[string]any) {}), []byte(`{}`)...)); err == nil {
		t.Errorf("trailing data: accepted")
	}
}

func TestParams(t *testing.T) {
	lo, hi := uint64(1), uint64(1024)
	o := Operation{ID: "x.ser.rows", Line: "SER {n}", Params: []Param{{Name: "n", Kind: ParamUint, Min: &lo, Max: &hi}}}
	if err := o.validateTemplate(); err != nil {
		t.Fatal(err)
	}
	for v, ok := range map[string]bool{"1": true, "1024": true, "0": false, "1025": false, "01": false, "-1": false, "1 C": false, "": false} {
		_, err := o.Render(map[string]string{"n": v})
		if (err == nil) != ok {
			t.Errorf("Render(n=%q) err=%v, want ok=%v", v, err, ok)
		}
	}
	if _, err := o.Render(map[string]string{"n": "5", "m": "1"}); err == nil {
		t.Errorf("extra parameter accepted")
	}
	e := Operation{ID: "x.sho", Line: "SHO {set}", Params: []Param{{Name: "set", Kind: ParamEnum, Values: []string{"G", "P"}}}}
	if err := e.validateTemplate(); err != nil {
		t.Fatal(err)
	}
	if l, err := e.Render(map[string]string{"set": "G"}); err != nil || l != "SHO G" {
		t.Errorf("Render enum = %q %v", l, err)
	}
	if _, err := e.Render(map[string]string{"set": "g"}); err == nil {
		t.Errorf("lower-case enum value accepted")
	}
	bad := []Operation{
		{ID: "x.a", Line: "{n} SER", Params: []Param{{Name: "n", Kind: ParamEnum, Values: []string{"A"}}}},
		{ID: "x.b", Line: "SER {n}"},
		{ID: "x.c", Line: "SER", Params: []Param{{Name: "n", Kind: ParamEnum, Values: []string{"A"}}}},
		{ID: "x.d", Line: "SER {n}", Params: []Param{{Name: "n", Kind: ParamEnum, Values: []string{"a b"}}}},
		{ID: "x.e", Line: "SER {n}", Params: []Param{{Name: "n", Kind: ParamUint, Min: &hi, Max: &lo}}},
	}
	for _, b := range bad {
		if err := b.validateTemplate(); err == nil {
			t.Errorf("%s %q accepted", b.ID, b.Line)
		}
	}
}

func TestNotText(t *testing.T) {
	m, err := NewMatcher(load(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range []string{"SER\x00", "\xa5\xe0", "ID\n"} {
		if v, _ := m.Match(l); v != VerdictNotText {
			t.Errorf("Match(%q) = %s, want not-text", l, v)
		}
	}
}
