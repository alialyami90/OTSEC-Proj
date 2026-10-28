package contract

// C3 0.3 limits and runs (#279, D4-13, P4-A2): B6's own cases. Expected
// outcomes come from D4-13 and the C3 0.3 text, not from the
// implementation: limits are new in 0.3, both numbers required and within
// C2's ceilings (1 MiB a reply, 60 s a step); a run is a named, ordered list
// of operations sent in one session, read-only without exception; a step is
// a literal operate-phase operation at access level 1 or lower with limits
// within the run's total and deadline (each at most 1 MiB and 600 s); at
// most 32 steps, none twice; the gate reads lead, the warning reads are in
// the run, and each step's context read comes before it; a run's ID shares
// the operation namespace; a run renders whole or not at all. Packages are
// built by editing the SEL-751 revision 4 golden's JSON. Ground truth:
// GT-HAND. Evidence class: desk.

import (
	"strings"
	"testing"

	"otsec.local/otsec/contracts/register"
)

const (
	c3SER   = "sel.ser.read_all"
	c3ShoG  = "sel.settings.show_global"
	c3ShoP1 = "sel.settings.show_port1"
	c3ID    = "sel.id"
)

func c3Limits(bytes, ms float64) map[string]any {
	return map[string]any{"max_reply_bytes": bytes, "timeout_ms": ms}
}

// c3Run is a valid run of the golden as 0.3: SHO P 1 (the language gate and
// the warnings), SHO G (SER's DATE_F context), then SER.
func c3Run(p map[string]any) map[string]any {
	return map[string]any{
		"id":              "sel.run.ser_with_context",
		"steps":           []any{c3ShoP1, c3ShoG, c3SER},
		"max_total_bytes": float64(1 << 20),
		"deadline_ms":     float64(120_000),
		"citations":       []any{map[string]any{"source": "S22", "ref": "Table 7.63 p.7.75"}},
		"evidence":        map[string]any{"class": "documented-untested"},
		"side_effects":    "None: three read-only lines in one session.",
	}
}

// c3V03 makes the golden a 0.3 package with limits on every operation a run
// may use and one run, then applies edit.
func c3V03(t *testing.T, edit func(p map[string]any)) []byte {
	t.Helper()
	b, err := c3Rev4(t, func(p map[string]any) {
		p["contract"] = "otsec.register/0.3"
		for _, id := range []string{c3SER, c3ShoG, c3ShoP1, c3ID} {
			c3Op(p, id)["limits"] = c3Limits(64<<10, 10_000)
		}
		p["runs"] = []any{c3Run(p)}
		if edit != nil {
			edit(p)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func c3R(p map[string]any) map[string]any { return p["runs"].([]any)[0].(map[string]any) }

func TestC3V03Versions(t *testing.T) {
	for _, c := range []struct {
		name string
		edit func(p map[string]any)
		ok   bool
	}{
		{"revision 4 restamped 0.3, no limits or runs", func(p map[string]any) { p["contract"] = "otsec.register/0.3" }, true},
		{"0.3 with limits on an operation and no run", func(p map[string]any) {
			p["contract"] = "otsec.register/0.3"
			c3Op(p, c3SER)["limits"] = c3Limits(1024, 1000)
		}, true},
		{"0.2 with limits and no run", func(p map[string]any) { c3Op(p, c3SER)["limits"] = c3Limits(1024, 1000) }, false},
		{"0.1 with limits and no run", func(p map[string]any) {
			p["contract"] = "otsec.register/0.1"
			delete(p, "context")
			c3Op(p, c3SER)["limits"] = c3Limits(1024, 1000)
		}, false},
		{"0.2 with a run", func(p map[string]any) {
			for _, id := range []string{c3SER, c3ShoG, c3ShoP1} {
				c3Op(p, id)["limits"] = c3Limits(1024, 1000)
			}
			p["runs"] = []any{c3Run(p)}
		}, false},
		{"0.4", func(p map[string]any) { p["contract"] = "otsec.register/0.4" }, false},
	} {
		b, err := c3Rev4(t, c.edit)
		if err != nil {
			t.Fatal(err)
		}
		_, err = register.Decode(b)
		if c.ok != (err == nil) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	// The revision 4 golden still reads as 0.2, unchanged.
	b, _ := c3Rev4(t, nil)
	if _, err := register.Decode(b); err != nil {
		t.Errorf("revision 4 as published: %v", err)
	}
}

func TestC3V03Limits(t *testing.T) {
	for _, c := range []struct {
		name   string
		limits any
		ok     bool
	}{
		{"1 byte, 1 ms", c3Limits(1, 1), true},
		{"at both ceilings", c3Limits(1<<20, 60_000), true},
		{"0 bytes", c3Limits(0, 1000), false},
		{"negative bytes", c3Limits(-1, 1000), false},
		{"1 MiB + 1", c3Limits(1<<20+1, 1000), false},
		{"0 ms", c3Limits(1024, 0), false},
		{"60 001 ms", c3Limits(1024, 60_001), false},
		{"timeout_ms missing", map[string]any{"max_reply_bytes": float64(1024)}, false},
		{"max_reply_bytes missing", map[string]any{"timeout_ms": float64(1000)}, false},
		{"an unknown field", map[string]any{"max_reply_bytes": float64(1024), "timeout_ms": float64(1000), "max_lines": float64(10)}, false},
		{"a fraction", c3Limits(1024.5, 1000), false},
		{"a string", map[string]any{"max_reply_bytes": "1024", "timeout_ms": float64(1000)}, false},
	} {
		b, err := c3Rev4(t, func(p map[string]any) {
			p["contract"] = "otsec.register/0.3"
			c3Op(p, c3ID)["limits"] = c.limits
		})
		if err != nil {
			t.Fatal(err)
		}
		_, err = register.Decode(b)
		if c.ok != (err == nil) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}

func TestC3V03RunRules(t *testing.T) {
	steps := func(ids ...string) func(p map[string]any) {
		return func(p map[string]any) {
			s := make([]any, len(ids))
			for i, id := range ids {
				s[i] = id
			}
			c3R(p)["steps"] = s
		}
	}
	for _, c := range []struct {
		name string
		edit func(p map[string]any)
		ok   bool
	}{
		{"the run as built", nil, true},
		{"SHO P 1 alone", steps(c3ShoP1), true},
		{"SHO P 1, ID (level 0)", steps(c3ShoP1, c3ID), true},
		{"step limits equal the run's totals", func(p map[string]any) {
			c3R(p)["max_total_bytes"], c3R(p)["deadline_ms"] = float64(64<<10), float64(10_000)
		}, true},
		{"run totals at C2's ceilings", func(p map[string]any) {
			c3R(p)["max_total_bytes"], c3R(p)["deadline_ms"] = float64(1<<20), float64(600_000)
		}, true},

		// Totals.
		{"max_total_bytes 0", func(p map[string]any) { c3R(p)["max_total_bytes"] = float64(0) }, false},
		{"max_total_bytes 1 MiB + 1", func(p map[string]any) { c3R(p)["max_total_bytes"] = float64(1<<20 + 1) }, false},
		{"deadline_ms 0", func(p map[string]any) { c3R(p)["deadline_ms"] = float64(0) }, false},
		{"deadline_ms 600 001", func(p map[string]any) { c3R(p)["deadline_ms"] = float64(600_001) }, false},
		{"a step's bytes above the run's", func(p map[string]any) { c3R(p)["max_total_bytes"] = float64(64<<10 - 1) }, false},
		{"a step's timeout above the run's deadline", func(p map[string]any) { c3R(p)["deadline_ms"] = float64(9_999) }, false},

		// Steps.
		{"no steps", steps(), false},
		{"a step twice", steps(c3ShoP1, c3ShoG, c3SER, c3SER), false},
		{"the gate read twice", steps(c3ShoP1, c3ShoG, c3ShoP1, c3SER), false},
		{"an unknown step", steps(c3ShoP1, "sel.ser.read_c"), false},
		{"a session line", steps(c3ShoP1, "sel.session.qui"), false},
		{"the ACC session line", steps("sel.session.acc", c3ShoP1), false},
		{"a deny rule", steps(c3ShoP1, "sel.ser.clear"), false},
		{"another run", func(p map[string]any) {
			r2 := c3Run(p)
			r2["id"], r2["steps"] = "sel.run.two", []any{c3ShoP1, c3ID}
			c3R(p)["steps"] = []any{c3ShoP1, "sel.run.two"}
			p["runs"] = append(p["runs"].([]any), r2)
		}, false},
		{"a step without limits", func(p map[string]any) { delete(c3Op(p, c3SER), "limits") }, false},
		{"a step at access level 2", func(p map[string]any) {
			c3Op(p, c3SER)["access_level"] = "2"
		}, false},
		{"a step at a non-numeric level", func(p map[string]any) {
			o := map[string]any{}
			for k, v := range c3Op(p, c3SER) {
				o[k] = v
			}
			o["id"], o["line"], o["access_level"] = "sel.b6.level_b", "B6LEVELB", "B"
			p["operations"] = append(p["operations"].([]any), o)
			c3R(p)["steps"] = []any{c3ShoP1, "sel.b6.level_b"}
		}, false},
		{"a probe-only step", func(p map[string]any) {
			c3Op(p, c3ID)["phases"] = []any{"probe"}
			c3R(p)["steps"] = []any{c3ShoP1, c3ID}
		}, false},

		// Order.
		{"the gate read not first", steps(c3ShoG, c3ShoP1, c3SER), false},
		{"no gate read", steps(c3ShoG, c3SER), false},
		{"SER before its context read", steps(c3ShoP1, c3SER, c3ShoG), false},
		{"SER without its context read", steps(c3ShoP1, c3SER), false},

		// Identity and form.
		{"run ID is an operation's", func(p map[string]any) { c3R(p)["id"] = c3SER }, false},
		{"run ID is a session line's", func(p map[string]any) { c3R(p)["id"] = "sel.session.qui" }, false},
		{"run ID is a deny rule's", func(p map[string]any) { c3R(p)["id"] = "sel.ser.clear" }, false},
		{"two runs with one ID", func(p map[string]any) { p["runs"] = append(p["runs"].([]any), c3Run(p)) }, false},
		{"no citation", func(p map[string]any) { c3R(p)["citations"] = []any{} }, false},
		{"an unknown source", func(p map[string]any) {
			c3R(p)["citations"] = []any{map[string]any{"source": "S999", "ref": "x"}}
		}, false},
		{"no side_effects", func(p map[string]any) { c3R(p)["side_effects"] = "" }, false},
		{"an unknown evidence class", func(p map[string]any) { c3R(p)["evidence"] = map[string]any{"class": "probably"} }, false},
		{"an unknown field in a run", func(p map[string]any) { c3R(p)["classification"] = "read-only" }, false},
		{"a step that is a line, not an ID", steps(c3ShoP1, "SHO G", c3SER), false},
	} {
		_, err := register.Decode(c3V03(t, c.edit))
		if c.ok != (err == nil) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}

// 33 steps are refused for their number, whatever else holds: build a
// package with enough literal operate-phase operations to fill them.
func TestC3V03RunStepCap(t *testing.T) {
	for _, n := range []int{32, 33} {
		b := c3V03(t, func(p map[string]any) {
			ops := p["operations"].([]any)
			s := []any{c3ShoP1, c3ShoG, c3SER, c3ID}
			for i := len(s); i < n; i++ {
				o := map[string]any{}
				for k, v := range c3Op(p, c3ID) {
					o[k] = v
				}
				o["id"] = "sel.b6.step" + string(rune('a'+i/26)) + string(rune('a'+i%26))
				// Literal lines no deny rule matches and no other entry holds.
				o["line"] = "B6STEP" + string(rune('A'+i/26)) + string(rune('A'+i%26))
				delete(o, "phases")
				ops = append(ops, o)
				s = append(s, o["id"])
			}
			p["operations"] = ops
			c3R(p)["steps"] = s
		})
		_, err := register.Decode(b)
		if (n <= register.MaxRunSteps) != (err == nil) {
			t.Errorf("%d steps: %v", n, err)
		}
		if n == 33 && err != nil && !strings.Contains(err.Error(), "steps") {
			t.Errorf("33 steps refused for another reason: %v", err)
		}
	}
}

// The matcher: a run renders as its steps' lines in order, every one of
// which Permit passes in operate; a name that is not a run renders nothing;
// Limits gives an operation's limits and nothing for one without.
func TestC3V03Matcher(t *testing.T) {
	p, err := register.Decode(c3V03(t, func(p map[string]any) { delete(c3Op(p, c3ID), "limits") }))
	if err != nil {
		t.Fatal(err)
	}
	m, err := register.NewMatcher(p)
	if err != nil {
		t.Fatal(err)
	}
	lines, err := m.RenderRun("sel.run.ser_with_context")
	if err != nil || strings.Join(lines, "|") != "SHO P 1|SHO G|SER" {
		t.Fatalf("RenderRun: %q, %v", lines, err)
	}
	for _, l := range lines {
		if v, _, err := m.Permit(register.PhaseOperate, l); err != nil || v != register.VerdictOperation {
			t.Errorf("Permit(%q): %v %v", l, v, err)
		}
	}
	for _, id := range []string{c3SER, "sel.session.qui", "sel.ser.clear", "sel.run.none", ""} {
		if lines, err := m.RenderRun(id); err == nil || lines != nil {
			t.Errorf("RenderRun(%q): %q, %v", id, lines, err)
		}
	}
	if _, ok := m.Run(c3SER); ok {
		t.Error("an operation's ID named a run")
	}
	if _, ok := m.Operation("sel.run.ser_with_context"); ok {
		t.Error("a run's ID named an operation")
	}
	if l, ok := m.Limits(c3SER); !ok || l.MaxReplyBytes != 64<<10 || l.TimeoutMS != 10_000 {
		t.Errorf("Limits(SER): %+v %v", l, ok)
	}
	if _, ok := m.Limits(c3ID); ok {
		t.Error("Limits on an operation without limits")
	}
	if _, ok := m.Limits("sel.run.ser_with_context"); ok {
		t.Error("Limits on a run")
	}
}
