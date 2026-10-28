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
			o := entry(m, "operations", 1)
			o["line"] = o["line"].(string) + " {n}"
			o["params"] = []any{map[string]any{"name": "n", "kind": "regex", "values": []any{"1"}}}
		},
		"operation in auth phase":  func(m map[string]any) { entry(m, "operations", 0)["phases"] = []any{"auth"} },
		"operation in close phase": func(m map[string]any) { entry(m, "operations", 0)["phases"] = []any{"close"} },
		"probe operation above level 0": func(m map[string]any) {
			o := entry(m, "operations", 1)
			o["phases"] = []any{"probe", "operate"}
		},
		"auth line also in probe": func(m map[string]any) {
			for _, e := range list(m, "session_control") {
				if e.(map[string]any)["line"] == "ACC" {
					e.(map[string]any)["phases"] = []any{"auth", "probe"}
				}
			}
		},
		"operation repeated phase":    func(m map[string]any) { entry(m, "operations", 0)["phases"] = []any{"operate", "operate"} },
		"warning with max and equals": func(m map[string]any) { list(m, "warnings")[0].(map[string]any)["equals"] = "1" },
		"warning with no threshold":   func(m map[string]any) { delete(list(m, "warnings")[0].(map[string]any), "max") },
		"warning read by session line": func(m map[string]any) {
			list(m, "warnings")[0].(map[string]any)["read_by"] = "sel.session.qui"
		},
		"warning reuses an entry ID": func(m map[string]any) { list(m, "warnings")[0].(map[string]any)["id"] = "sel.id" },
		"warning without reason":     func(m map[string]any) { list(m, "warnings")[0].(map[string]any)["reason"] = "" },
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
	good := mutate(t, func(map[string]any) {})
	if _, err := Decode(good); err != nil {
		t.Fatalf("re-encoded golden rejected: %v", err)
	}
	for _, tail := range []string{`{}`, `]`, `}`, ` x`, `0`} {
		if _, err := Decode(append(append([]byte{}, good...), tail...)); err == nil {
			t.Errorf("trailing %q: accepted", tail)
		}
	}
	// Duplicate keys at the top level and nested (A3 C3-A3-2).
	for _, dup := range []struct{ old, new string }{
		{`"revision":1`, `"revision":1,"revision":2`},
		{`"line":"SER"`, `"line":"SER","line":"TRI"`},
		{`"class":"documented-untested"`, `"class":"documented-untested","class":"hardware-verified"`},
	} {
		bad := strings.Replace(string(good), dup.old, dup.new, 1)
		if bad == string(good) {
			t.Fatalf("test setup: %s not found", dup.old)
		}
		if _, err := Decode([]byte(bad)); err == nil {
			t.Errorf("duplicate key %s: accepted", dup.new)
		}
	}
}

func TestParams(t *testing.T) {
	lo, hi := uint64(1), uint64(1024)
	o := Operation{ID: "x.ser.rows", Line: "SER {n}", Params: []Param{{Name: "n", Kind: ParamUint, Min: &lo, Max: &hi}}}
	if err := o.validateTemplate(); err != nil {
		t.Fatal(err)
	}
	for v, ok := range map[string]bool{"1": true, "1024": true, "0": false, "1025": false, "01": false, "-1": false, "1 C": false, "": false} {
		_, err := o.render(map[string]string{"n": v})
		if (err == nil) != ok {
			t.Errorf("Render(n=%q) err=%v, want ok=%v", v, err, ok)
		}
	}
	if _, err := o.render(map[string]string{"n": "5", "m": "1"}); err == nil {
		t.Errorf("extra parameter accepted")
	}
	e := Operation{ID: "x.sho", Line: "SHO {set}", Params: []Param{{Name: "set", Kind: ParamEnum, Values: []string{"G", "P"}}}}
	if err := e.validateTemplate(); err != nil {
		t.Fatal(err)
	}
	if l, err := e.render(map[string]string{"set": "G"}); err != nil || l != "SHO G" {
		t.Errorf("Render enum = %q %v", l, err)
	}
	if _, err := e.render(map[string]string{"set": "g"}); err == nil {
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

// TestKeySpelling: encoding/json fills fields without regard to case, so a
// key spelled differently from its tag, alone or beside the real one, must be
// rejected (A6 review of C3).
func TestKeySpelling(t *testing.T) {
	good := string(mutate(t, func(map[string]any) {}))
	for _, c := range []struct{ old, new string }{
		{`"line":"ID"`, `"Line":"ID"`},
		{`"line":"ID"`, `"line":"ID","Line":"EVE"`},
		{`"revision":1`, `"REVISION":1`},
	} {
		bad := strings.Replace(good, c.old, c.new, 1)
		if bad == good {
			t.Fatalf("test setup: %s not found", c.old)
		}
		if _, err := Decode([]byte(bad)); err == nil {
			t.Errorf("%s: accepted", c.new)
		}
	}
}

// TestRenderRefusesDenied: a parameter value inside its range that renders a
// denied line is refused, although Validate samples only the range ends.
func TestRenderRefusesDenied(t *testing.T) {
	data := mutate(t, func(m map[string]any) {
		op := map[string]any{}
		for k, v := range entry(m, "operations", 1) {
			op[k] = v
		}
		op["id"] = "sel.test.sho_port"
		op["line"] = "SHO P {port}"
		op["params"] = []any{map[string]any{"name": "port", "kind": "uint", "min": 1, "max": 4}}
		m["operations"] = append(list(m, "operations"), op)
		deny := map[string]any{}
		for k, v := range entry(m, "denied", 0) {
			deny[k] = v
		}
		deny["id"] = "sel.test.port3"
		deny["pattern"] = "SHO P 3"
		m["denied"] = append(list(m, "denied"), deny)
	})
	p, err := Decode(data)
	if err != nil {
		t.Fatalf("test package rejected: %v", err)
	}
	m, err := NewMatcher(p)
	if err != nil {
		t.Fatal(err)
	}
	if l, err := m.Render("sel.test.sho_port", map[string]string{"port": "2"}); err != nil || l != "SHO P 2" {
		t.Errorf("Render(port=2) = %q, %v", l, err)
	}
	if _, err := m.Render("sel.test.sho_port", map[string]string{"port": "3"}); err == nil {
		t.Errorf("Render(port=3) produced a denied line")
	}
	if l, err := m.Render("sel.ser.read_all", nil); err != nil || l != "SER" {
		t.Errorf("Render(sel.ser.read_all) = %q, %v", l, err)
	}
	for _, id := range []string{"sel.session.acc", "sel.ser.clear", "nope"} {
		if _, err := m.Render(id, nil); err == nil {
			t.Errorf("Render(%s) accepted", id)
		}
	}
}

// TestProbeOperationLiteral checks that an operation sent before
// authentication cannot take parameters (C3-A2 change 1).
func TestProbeOperationLiteral(t *testing.T) {
	data := mutate(t, func(m map[string]any) {
		o := entry(m, "operations", 0)
		o["line"] = "ID {n}"
		o["params"] = []any{map[string]any{"name": "n", "kind": "uint", "min": 1, "max": 2}}
	})
	if _, err := Decode(data); err == nil || !strings.Contains(err.Error(), "runs in probe and has parameters") {
		t.Errorf("probe operation with a parameter: %v", err)
	}
}

// TestPermit checks the egress rule per phase: ID in probe and operate, the
// other operations in operate only, session lines in their listed phases,
// and nothing else anywhere (C3-A2 change 1, A3 8.3).
func TestPermit(t *testing.T) {
	m, err := NewMatcher(load(t))
	if err != nil {
		t.Fatal(err)
	}
	allow := map[Phase][]string{
		PhaseProbe:   {"ID", "QUI"},
		PhaseAuth:    {"ACC"},
		PhaseOperate: {"ID", "SER", "SHO G", "SHO P 1"},
		PhaseClose:   {"QUI"},
	}
	all := []string{"ID", "SER", "SHO G", "SHO P 1", "ACC", "QUI", "SER C", "2AC", "TRI", ""}
	for _, ph := range []Phase{PhaseProbe, PhaseAuth, PhaseOperate, PhaseClose, "other"} {
		for _, l := range all {
			want := false
			for _, a := range allow[ph] {
				want = want || a == l
			}
			if _, _, err := m.Permit(ph, l); (err == nil) != want {
				t.Errorf("Permit(%s, %q): err %v, want allowed %v", ph, l, err, want)
			}
		}
	}
}

// TestWarnings checks the posture warnings carried from ADR-0005 and how a
// reading raises them (C3-A2 change 2).
func TestWarnings(t *testing.T) {
	p := load(t)
	got := map[string]PostureWarning{}
	for _, w := range p.Warnings {
		got[w.Setting] = w
	}
	for _, s := range []string{"MAXACC", "FTPACC", "HTTPACC"} {
		w, ok := got[s]
		if !ok || w.Max == nil || *w.Max != 1 || w.ReadBy != "sel.settings.show_port1" {
			t.Fatalf("%s warning: %+v", s, w)
		}
		for v, want := range map[string]bool{"1": false, "2": true, "C": true, "": true, "-1": true, "1 ": true} {
			if w.Raised(v) != want {
				t.Errorf("%s Raised(%q) = %v", s, v, !want)
			}
		}
	}
	eq := PostureWarning{Equals: "N"}
	if eq.Raised("N") || !eq.Raised("Y") || !eq.Raised("n") {
		t.Errorf("equals warning raised wrongly")
	}
}

// TestContext: the 0.2 context reads and A1's D3-2 conditions. Each case
// edits A2's SEL-751 content, revision 4, which reads DATE_F with SHO G for
// SER.
func TestContext(t *testing.T) {
	data, err := os.ReadFile(content)
	if err != nil {
		t.Fatal(err)
	}
	edit := func(f func(m map[string]any)) []byte {
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
	ctx := func(m map[string]any) map[string]any { return entry(m, "context", 0) }
	op := func(m map[string]any, id string) map[string]any {
		for _, o := range list(m, "operations") {
			if o.(map[string]any)["id"] == id {
				return o.(map[string]any)
			}
		}
		t.Fatalf("no operation %s", id)
		return nil
	}
	p, err := Decode(edit(func(map[string]any) {}))
	if err != nil {
		t.Fatalf("revision 4 rejected: %v", err)
	}
	if got := p.ContextFor("sel.ser.read_all"); len(got) != 1 || got[0].Setting != "DATE_F" || got[0].ReadBy != "sel.settings.show_global" {
		t.Errorf("ContextFor(SER) = %+v", got)
	}
	if got := p.ContextFor("sel.settings.show_port1"); len(got) != 0 {
		t.Errorf("ContextFor(SHO P 1) = %+v", got)
	}
	for name, c := range map[string]struct {
		f    func(m map[string]any)
		want string
	}{
		"context in a 0.1 package": {func(m map[string]any) { m["contract"] = "otsec.register/0.1" }, "new in 0.2"},
		"a later minor":            {func(m map[string]any) { m["contract"] = "otsec.register/0.4" }, "want one of"},
		"unknown field":            {func(m map[string]any) { ctx(m)["default"] = "MDY" }, "not a field name"},
		"ID of another entry":      {func(m map[string]any) { ctx(m)["id"] = "sel.id" }, "duplicated"},
		"lower-case setting":       {func(m map[string]any) { ctx(m)["setting"] = "date_f" }, "needs a setting"},
		"no reason":                {func(m map[string]any) { ctx(m)["reason"] = "" }, "needs a setting"},
		"for nothing":              {func(m map[string]any) { ctx(m)["for"] = []any{} }, "needs a setting"},
		"no values":                {func(m map[string]any) { ctx(m)["values"] = []any{} }, "needs a setting"},
		"lower-case value":         {func(m map[string]any) { ctx(m)["values"] = []any{"MDY", "dmy"} }, `value "dmy"`},
		"repeated value":           {func(m map[string]any) { ctx(m)["values"] = []any{"MDY", "MDY"} }, `value "MDY"`},
		"read by a session line":   {func(m map[string]any) { ctx(m)["read_by"] = "sel.session.qui" }, "not an operation run in operate"},
		"read by a deny rule":      {func(m map[string]any) { ctx(m)["read_by"] = "sel.ser.clear" }, "not an operation run in operate"},
		"for a deny rule":          {func(m map[string]any) { ctx(m)["for"] = []any{"sel.ser.clear"} }, "not another operation"},
		"for itself":               {func(m map[string]any) { ctx(m)["for"] = []any{"sel.settings.show_global"} }, "not another operation"},
		"for twice":                {func(m map[string]any) { ctx(m)["for"] = []any{"sel.ser.read_all", "sel.ser.read_all"} }, "not another operation"},
		// D3-2: read at the same or a lower level than the operation it is for.
		"read above the level it is for": {func(m map[string]any) { op(m, "sel.settings.show_global")["access_level"] = "2" }, "above"},
		"for a level 0 operation":        {func(m map[string]any) { ctx(m)["for"] = []any{"sel.id"} }, "above"},
		"a level with no known order":    {func(m map[string]any) { op(m, "sel.settings.show_global")["access_level"] = "C" }, "above"},
		// Levels compare as numbers, not text: "10" sorts before "2" as text (A6 on #156).
		"read at 10 for an operation at 2": {func(m map[string]any) {
			op(m, "sel.settings.show_global")["access_level"] = "10"
			op(m, "sel.ser.read_all")["access_level"] = "2"
		}, "above"},
	} {
		_, err := Decode(edit(c.f))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
}
