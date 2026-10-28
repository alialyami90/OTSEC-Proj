package register

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
)

// The 0.3 additions: operations[].limits and runs[] (P4-A2, D4-13). Each case
// edits SEL-751 revision 4 (0.2) into a small 0.3 package whose run reads
// SHO P 1 (the gate: the LANG precondition, the three posture warnings and
// the R400..R402 conditions) and then SHO G (the DATE_F context read).

const testRun = "sel.test.read_shows"

// v3 turns the revision 4 bytes into a 0.3 package with limits on SHO P 1,
// SHO G and SER, and the run testRun, then applies f.
func v3(t *testing.T, f func(m map[string]any)) []byte {
	t.Helper()
	data, err := os.ReadFile(content)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	m["contract"] = "otsec.register/0.3"
	for _, id := range []string{"sel.settings.show_port1", "sel.settings.show_global", "sel.ser.read_all"} {
		opOf(t, m, id)["limits"] = map[string]any{"max_reply_bytes": 65536, "timeout_ms": 10000}
	}
	m["runs"] = []any{map[string]any{
		"id":              testRun,
		"steps":           []any{"sel.settings.show_port1", "sel.settings.show_global"},
		"max_total_bytes": 524288,
		"deadline_ms":     300000,
		"citations":       []any{map[string]any{"source": "S22", "ref": "Table 7.67 p.7.77"}},
		"evidence":        map[string]any{"class": "documented-untested"},
		"side_effects":    "none: SHO prints settings",
	}}
	if f != nil {
		f(m)
	}
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func opOf(t *testing.T, m map[string]any, id string) map[string]any {
	t.Helper()
	for _, o := range list(m, "operations") {
		if o.(map[string]any)["id"] == id {
			return o.(map[string]any)
		}
	}
	t.Fatalf("no operation %s", id)
	return nil
}

func run0(m map[string]any) map[string]any { return entry(m, "runs", 0) }
func steps(ids ...string) []any {
	out := make([]any, len(ids))
	for i, id := range ids {
		out[i] = id
	}
	return out
}

func TestRunValid(t *testing.T) {
	p, err := Decode(v3(t, nil))
	if err != nil {
		t.Fatal(err)
	}
	m, err := NewMatcher(p)
	if err != nil {
		t.Fatal(err)
	}
	lines, err := m.RenderRun(testRun)
	if err != nil || !slices.Equal(lines, []string{"SHO P 1", "SHO G"}) {
		t.Fatalf("RenderRun = %q, %v", lines, err)
	}
	// The egress check is still per line: every line is an operate operation.
	for _, l := range lines {
		if v, _, err := m.Permit(PhaseOperate, l); err != nil || v != VerdictOperation {
			t.Errorf("Permit(%q) = %s, %v", l, v, err)
		}
	}
	r, ok := m.Run(testRun)
	if !ok || r.MaxTotalBytes != 524288 || r.DeadlineMS != 300000 {
		t.Fatalf("Run = %+v, %v", r, ok)
	}
	if l, ok := m.Limits("sel.settings.show_global"); !ok || l != (Limits{65536, 10000}) {
		t.Errorf("Limits(SHO G) = %+v, %v", l, ok)
	}
	if _, ok := m.Limits("sel.id"); ok {
		t.Error("an operation with no limits has some")
	}
	if _, ok := m.Limits("sel.nothing"); ok {
		t.Error("an unknown operation has limits")
	}
	// A run is not an operation, and an operation is not a run.
	if _, ok := m.Operation(testRun); ok {
		t.Error("a run is invocable as an operation")
	}
	if _, err := m.Render(testRun, nil); err == nil {
		t.Error("Render accepts a run ID")
	}
	if _, err := m.RenderRun("sel.settings.show_global"); err == nil {
		t.Error("RenderRun accepts an operation ID")
	}
	if _, err := m.RenderRun("sel.nothing"); err == nil {
		t.Error("RenderRun accepts an unknown ID")
	}
}

// A run in a package that is not 0.3, and the revisions before 0.3, are
// unchanged: they carry neither limits nor runs.
func TestRunNeedsOnePointThree(t *testing.T) {
	for _, c := range []string{"otsec.register/0.1", "otsec.register/0.2"} {
		_, err := Decode(v3(t, func(m map[string]any) { m["contract"] = c; delete(m, "context") }))
		if err == nil || !strings.Contains(err.Error(), "new in 0.3") {
			t.Errorf("%s with limits: %v", c, err)
		}
		_, err = Decode(v3(t, func(m map[string]any) {
			m["contract"] = c
			delete(m, "context")
			for _, id := range []string{"sel.settings.show_port1", "sel.settings.show_global", "sel.ser.read_all"} {
				delete(opOf(t, m, id), "limits")
			}
		}))
		if err == nil || !strings.Contains(err.Error(), "runs are new in 0.3") {
			t.Errorf("%s with a run: %v", c, err)
		}
	}
	// Limits alone, with no run, are as new as runs: the gate on limits must
	// hold without a run to trip the other one (B3's mutant on #279).
	for _, c := range []string{"otsec.register/0.1", "otsec.register/0.2"} {
		_, err := Decode(v3(t, func(m map[string]any) {
			m["contract"] = c
			delete(m, "context")
			delete(m, "runs")
		}))
		if err == nil || !strings.Contains(err.Error(), "new in 0.3") {
			t.Errorf("%s with limits and no run: %v", c, err)
		}
	}
	// And at 0.3 the same package, limits and no run, is valid.
	if _, err := Decode(v3(t, func(m map[string]any) { delete(m, "runs") })); err != nil {
		t.Errorf("0.3 with limits and no run: %v", err)
	}
	for _, id := range []string{"sel-751-phase0.json", "sel-751-rev2.json", "sel-751-rev3.json", "sel-751.json"} {
		data, err := os.ReadFile("testdata/" + id)
		if err != nil {
			t.Fatal(err)
		}
		p, err := Decode(data)
		if err != nil || len(p.Runs) != 0 {
			t.Errorf("%s: %d runs, %v", id, len(p.Runs), err)
		}
		for _, o := range p.Operations {
			if o.Limits != nil {
				t.Errorf("%s: %s has limits", id, o.ID)
			}
		}
	}
}

func TestRunRejects(t *testing.T) {
	over := func(n int) []any {
		out := make([]any, n)
		for i := range out {
			out[i] = fmt.Sprintf("sel.test.step_%d", i)
		}
		return out
	}
	// addOps adds n read-only, literal, level 1 operations with limits, and
	// returns their IDs. SHO D1, SHO D2, ... are lines no deny rule matches.
	addOps := func(m map[string]any, n int) []any {
		ids := over(n)
		for i, id := range ids {
			m["operations"] = append(list(m, "operations"), map[string]any{
				"id": id, "classification": "read-only", "line": fmt.Sprintf("SHO D%d", i), "access_level": "1",
				"limits":    map[string]any{"max_reply_bytes": 1024, "timeout_ms": 1000},
				"citations": []any{map[string]any{"source": "S22", "ref": "Table 7.67 p.7.77"}},
				"evidence":  map[string]any{"class": "documented-untested"}, "side_effects": "none",
			})
		}
		return ids
	}
	gate := "sel.settings.show_port1"
	for name, c := range map[string]struct {
		f    func(m map[string]any)
		want string
	}{
		// Limits.
		"limits: no timeout":      {func(m map[string]any) { delete(opOf(t, m, gate)["limits"].(map[string]any), "timeout_ms") }, "limits"},
		"limits: no bytes":        {func(m map[string]any) { delete(opOf(t, m, gate)["limits"].(map[string]any), "max_reply_bytes") }, "limits"},
		"limits: zero bytes":      {func(m map[string]any) { opOf(t, m, gate)["limits"].(map[string]any)["max_reply_bytes"] = 0 }, "outside"},
		"limits: negative bytes":  {func(m map[string]any) { opOf(t, m, gate)["limits"].(map[string]any)["max_reply_bytes"] = -1 }, "outside"},
		"limits: over C2's bytes": {func(m map[string]any) { opOf(t, m, gate)["limits"].(map[string]any)["max_reply_bytes"] = 1<<20 + 1 }, "outside"},
		"limits: zero timeout":    {func(m map[string]any) { opOf(t, m, gate)["limits"].(map[string]any)["timeout_ms"] = 0 }, "outside"},
		"limits: over C2's step":  {func(m map[string]any) { opOf(t, m, gate)["limits"].(map[string]any)["timeout_ms"] = 60001 }, "outside"},
		"limits: unknown field":   {func(m map[string]any) { opOf(t, m, gate)["limits"].(map[string]any)["retries"] = 3 }, "not a field name"},
		"limits: not a number":    {func(m map[string]any) { opOf(t, m, gate)["limits"].(map[string]any)["timeout_ms"] = "10" }, "timeout_ms"},
		"limits: a fraction":      {func(m map[string]any) { opOf(t, m, gate)["limits"].(map[string]any)["timeout_ms"] = 1.5 }, "timeout_ms"},
		// The run's own bounds.
		"run: no total":           {func(m map[string]any) { delete(run0(m), "max_total_bytes") }, "max_total_bytes"},
		"run: total over C2":      {func(m map[string]any) { run0(m)["max_total_bytes"] = 1<<20 + 1 }, "max_total_bytes"},
		"run: no deadline":        {func(m map[string]any) { delete(run0(m), "deadline_ms") }, "deadline_ms"},
		"run: deadline over C2":   {func(m map[string]any) { run0(m)["deadline_ms"] = 600001 }, "deadline_ms"},
		"run: no steps":           {func(m map[string]any) { run0(m)["steps"] = []any{} }, "has 0 steps"},
		"run: 33 steps":           {func(m map[string]any) { run0(m)["steps"] = addOps(m, 33) }, "has 33 steps"},
		"run: no citation":        {func(m map[string]any) { run0(m)["citations"] = []any{} }, "no citation"},
		"run: unknown source":     {func(m map[string]any) { run0(m)["citations"] = []any{map[string]any{"source": "S99", "ref": "x"}} }, "unknown source"},
		"run: bad evidence class": {func(m map[string]any) { run0(m)["evidence"] = map[string]any{"class": "verified"} }, "evidence class"},
		"run: no side effects":    {func(m map[string]any) { run0(m)["side_effects"] = "" }, "side_effects"},
		"run: unknown field":      {func(m map[string]any) { run0(m)["retries"] = 3 }, "not a field name"},
		"run: ID of an operation": {func(m map[string]any) { run0(m)["id"] = "sel.id" }, "duplicated"},
		"run: ID not dotted":      {func(m map[string]any) { run0(m)["id"] = "READ" }, "dotted lower case"},
		"two runs, one ID": {func(m map[string]any) {
			m["runs"] = append(list(m, "runs"), run0(m))
		}, "duplicated"},
		// The steps.
		"step: unknown":                   {func(m map[string]any) { run0(m)["steps"] = steps(gate, "sel.settings.show_all") }, "not an operation"},
		"step: a session line":            {func(m map[string]any) { run0(m)["steps"] = steps(gate, "sel.session.qui") }, "not an operation"},
		"step: a deny rule":               {func(m map[string]any) { run0(m)["steps"] = steps(gate, "sel.ser.clear") }, "not an operation"},
		"step: twice":                     {func(m map[string]any) { run0(m)["steps"] = steps(gate, "sel.settings.show_global", gate) }, "twice"},
		"step: access level 2":            {func(m map[string]any) { opOf(t, m, gate)["access_level"] = "2" }, "above 1"},
		"step: access level 10":           {func(m map[string]any) { opOf(t, m, gate)["access_level"] = "10" }, "above 1"},
		"step: a level with no order":     {func(m map[string]any) { opOf(t, m, gate)["access_level"] = "C" }, "above 1"},
		"step: no limits":                 {func(m map[string]any) { delete(opOf(t, m, "sel.settings.show_global"), "limits") }, "no limits"},
		"step: reply over the total":      {func(m map[string]any) { run0(m)["max_total_bytes"] = 65535 }, "above the run's max_total_bytes"},
		"step: timeout over the deadline": {func(m map[string]any) { run0(m)["deadline_ms"] = 9999 }, "above the run's deadline_ms"},
		"step: probe only": {func(m map[string]any) {
			o := opOf(t, m, "sel.id")
			o["phases"] = []any{"probe"}
			o["limits"] = map[string]any{"max_reply_bytes": 1024, "timeout_ms": 1000}
			run0(m)["steps"] = steps(gate, "sel.settings.show_global", "sel.id")
		}, "does not run in operate"},
		"step: has parameters": {func(m map[string]any) {
			o := opOf(t, m, "sel.settings.show_global")
			o["line"] = "SHO {form}"
			o["params"] = []any{map[string]any{"name": "form", "kind": "enum", "values": []any{"G"}}}
		}, "has parameters"},
		// The gate and the other reads.
		"gate: not first":   {func(m map[string]any) { run0(m)["steps"] = steps("sel.settings.show_global", gate) }, "gate it"},
		"gate: missing":     {func(m map[string]any) { run0(m)["steps"] = steps("sel.settings.show_global") }, "gate it"},
		"gate: after steps": {func(m map[string]any) { run0(m)["steps"] = steps("sel.settings.show_global", "sel.ser.read_all", gate) }, "gate it"},
		"warning read outside the run": {func(m map[string]any) {
			entry(m, "warnings", 0)["read_by"] = "sel.id"
		}, "reads warning"},
		"context read missing": {func(m map[string]any) { run0(m)["steps"] = steps(gate, "sel.ser.read_all") }, "before step sel.ser.read_all"},
		"context read after the step": {func(m map[string]any) {
			run0(m)["steps"] = steps(gate, "sel.ser.read_all", "sel.settings.show_global")
		}, "before step sel.ser.read_all"},
	} {
		_, err := Decode(v3(t, c.f))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
}

// A run with SER after its context read is valid: the context read comes
// before the step it is for, and is sent once.
func TestRunContextBeforeStep(t *testing.T) {
	b := v3(t, func(m map[string]any) {
		run0(m)["steps"] = steps("sel.settings.show_port1", "sel.settings.show_global", "sel.ser.read_all")
	})
	p, err := Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	m, _ := NewMatcher(p)
	if lines, err := m.RenderRun(testRun); err != nil || !slices.Equal(lines, []string{"SHO P 1", "SHO G", "SER"}) {
		t.Fatalf("RenderRun = %q, %v", lines, err)
	}
}

// A package with no gate reads (no preconditions, warnings or conditions)
// may start a run with any step.
func TestRunNoGate(t *testing.T) {
	_, err := Decode(v3(t, func(m map[string]any) {
		m["preconditions"] = []any{}
		m["warnings"] = []any{}
		m["context"] = []any{}
		for _, b := range m["firmware"].(map[string]any)["branches"].([]any) {
			delete(b.(map[string]any), "conditions")
			if b.(map[string]any)["status"] == "allow-with-condition" {
				b.(map[string]any)["status"] = "allow"
			}
		}
		run0(m)["steps"] = steps("sel.settings.show_global")
	}))
	if err != nil {
		t.Fatal(err)
	}
}

// RenderRun fails as a whole: a step that no longer renders to its own
// operation fails the call and returns no line (the register may not be
// edited after validation, but the check is the same one Render makes).
func TestRenderRunAllOrNothing(t *testing.T) {
	p, err := Decode(v3(t, nil))
	if err != nil {
		t.Fatal(err)
	}
	m, err := NewMatcher(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{"ACC", "SER C", "TRI"} {
		q := *p
		q.Operations = slices.Clone(p.Operations)
		for i := range q.Operations {
			if q.Operations[i].ID == "sel.settings.show_global" {
				q.Operations[i].Line = line
			}
		}
		m.p = &q
		lines, err := m.RenderRun(testRun)
		if err == nil || lines != nil {
			t.Errorf("a step rendering %q: %q, %v", line, lines, err)
		}
	}
}

// The ceilings are C2's. register cannot import adapter, so
// contracts/adapter pins MaxSessionBytes, MaxStepMS and MaxDeadlineMS to
// adapter.MaxResponseBytes, MaxStepTimeoutMS and MaxDeadlineMS.
func TestCeilingsValues(t *testing.T) {
	if MaxSessionBytes != 1<<20 || MaxStepMS != 60_000 || MaxDeadlineMS != 600_000 || MaxRunSteps != 32 || MaxRunAccessLevel != 1 {
		t.Fatal("a ceiling moved; contracts/adapter, the schema and doc.go must move with it")
	}
}

// The schema's numeric bounds are the same ceilings.
func TestSchemaCeilings(t *testing.T) {
	data, err := os.ReadFile("schema/register.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var s struct {
		Defs struct {
			Limits struct {
				Properties map[string]struct{ Maximum int }
			}
			Run struct {
				Properties map[string]struct{ Maximum, MaxItems int }
			}
		} `json:"$defs"`
	}
	if err := json.Unmarshal(data, &s); err != nil {
		t.Fatal(err)
	}
	l, r := s.Defs.Limits.Properties, s.Defs.Run.Properties
	if l["max_reply_bytes"].Maximum != MaxSessionBytes || l["timeout_ms"].Maximum != MaxStepMS ||
		r["max_total_bytes"].Maximum != MaxSessionBytes || r["deadline_ms"].Maximum != MaxDeadlineMS || r["steps"].MaxItems != MaxRunSteps {
		t.Errorf("the schema's bounds %+v %+v are not the ceilings", l, r)
	}
}

// A package before 0.3 that carries a runs or limits key is refused whatever
// its value, [] and null included: a 0.2 reader refuses the key, so this
// reader must not read what it refuses (D4-16, B6 on #279).
func TestEmptyNewKeysBeforeOnePointThree(t *testing.T) {
	bare := func(c string, f func(m map[string]any)) []byte {
		return v3(t, func(m map[string]any) {
			m["contract"] = c
			delete(m, "runs")
			for _, o := range list(m, "operations") {
				delete(o.(map[string]any), "limits")
			}
			f(m)
		})
	}
	for _, c := range []string{"otsec.register/0.1", "otsec.register/0.2"} {
		withoutContext := func(m map[string]any) {
			if c == "otsec.register/0.1" {
				delete(m, "context")
			}
		}
		cases := map[string]func(m map[string]any){
			`"runs": []`:     func(m map[string]any) { m["runs"] = []any{} },
			`"runs": null`:   func(m map[string]any) { m["runs"] = nil },
			`"limits": null`: func(m map[string]any) { opOf(t, m, "sel.ser.read_all")["limits"] = nil },
		}
		for n, f := range cases {
			_, err := Decode(bare(c, func(m map[string]any) { withoutContext(m); f(m) }))
			if err == nil || !strings.Contains(err.Error(), "new in 0.3") {
				t.Errorf("%s with %s: %v", c, n, err)
			}
		}
		// The control: the same package with neither key is valid.
		if _, err := Decode(bare(c, withoutContext)); err != nil {
			t.Errorf("%s with neither key: %v", c, err)
		}
	}
	// At 0.3 an empty runs list is a package with no runs.
	if p, err := Decode(v3(t, func(m map[string]any) { m["runs"] = []any{} })); err != nil || len(p.Runs) != 0 {
		t.Errorf("0.3 with runs []: %v", err)
	}
}
