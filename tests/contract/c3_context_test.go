package contract

// C3 0.2 context reads (#156, D3-2, P3-A2): A6's own cases. Expected
// outcomes come from D3-2 and the C3 0.2 text: a context read permits its
// read_by line only in a run of an operation in for, never elsewhere; read_by
// is an operation of the package run in operate, at a level no higher than
// any operation in for, and not itself in for; levels that are not numbers
// compare only for equality; a 0.1 package carries no context. Packages are
// built by editing the SEL-751 revision 4 golden's JSON. Ground truth:
// GT-HAND.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"otsec.local/otsec/contracts/adapter"
	"otsec.local/otsec/contracts/register"
)

func c3Rev4(t *testing.T, edit func(p map[string]any)) ([]byte, error) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "contracts", "register", "testdata", "sel-751.json"))
	if err != nil {
		t.Fatal(err)
	}
	if edit == nil {
		return b, nil
	}
	var p map[string]any
	if err := json.Unmarshal(b, &p); err != nil {
		t.Fatal(err)
	}
	edit(p)
	return json.Marshal(p)
}

func c3Op(p map[string]any, id string) map[string]any {
	for _, o := range p["operations"].([]any) {
		if m := o.(map[string]any); m["id"] == id {
			return m
		}
	}
	panic("no operation " + id)
}

func c3Ctx(p map[string]any) map[string]any {
	return p["context"].([]any)[0].(map[string]any)
}

func TestC3ContextRules(t *testing.T) {
	for _, c := range []struct {
		name string
		edit func(p map[string]any)
		ok   bool
	}{
		{"revision 4 as published", nil, true},
		{"read_by below the level of for", func(p map[string]any) { c3Ctx(p)["read_by"] = "sel.id" }, true},
		{"read_by above the level of for", func(p map[string]any) { c3Op(p, "sel.settings.show_global")["access_level"] = "2" }, false},
		{"read_by at 10, for at 2 (numbers, not text)", func(p map[string]any) {
			c3Op(p, "sel.settings.show_global")["access_level"] = "10"
			c3Op(p, "sel.ser.read_all")["access_level"] = "2"
		}, false},
		{"read_by at a non-numeric level, for at 1", func(p map[string]any) { c3Op(p, "sel.settings.show_global")["access_level"] = "B" }, false},
		{"read_by at 1, for at a non-numeric level", func(p map[string]any) { c3Op(p, "sel.ser.read_all")["access_level"] = "B" }, false},
		{"read_by in for", func(p map[string]any) {
			c3Ctx(p)["for"] = []any{"sel.ser.read_all", "sel.settings.show_global"}
		}, false},
		{"for names read_by only", func(p map[string]any) { c3Ctx(p)["for"] = []any{"sel.settings.show_global"} }, false},
		{"for repeats an operation", func(p map[string]any) { c3Ctx(p)["for"] = []any{"sel.ser.read_all", "sel.ser.read_all"} }, false},
		{"for names no operation", func(p map[string]any) { c3Ctx(p)["for"] = []any{} }, false},
		{"for names an unknown operation", func(p map[string]any) { c3Ctx(p)["for"] = []any{"sel.ser.read_c"} }, false},
		{"read_by unknown", func(p map[string]any) { c3Ctx(p)["read_by"] = "sel.settings.show_all" }, false},
		{"read_by is a session line", func(p map[string]any) { c3Ctx(p)["read_by"] = "QUI" }, false},
		{"context on a 0.1 package", func(p map[string]any) { p["contract"] = "otsec.register/0.1" }, false},
		{"a later minor", func(p map[string]any) { p["contract"] = "otsec.register/0.4" }, false},
		{"values lower case", func(p map[string]any) { c3Ctx(p)["values"] = []any{"mdy"} }, false},
		{"values repeated", func(p map[string]any) { c3Ctx(p)["values"] = []any{"MDY", "MDY"} }, false},
		{"values empty", func(p map[string]any) { c3Ctx(p)["values"] = []any{} }, false},
		{"reason empty", func(p map[string]any) { c3Ctx(p)["reason"] = "" }, false},
		{"id an operation's id", func(p map[string]any) { c3Ctx(p)["id"] = "sel.ser.read_all" }, false},
		{"unknown field in context", func(p map[string]any) { c3Ctx(p)["permits"] = "SHO P 1" }, false},
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
}

// The line a context permits, in the runs it is for and no other.
func TestC3ContextCheckLines(t *testing.T) {
	b, _ := c3Rev4(t, nil)
	p, err := register.Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	if got := p.ContextFor("sel.ser.read_all"); len(got) != 1 || got[0].ReadBy != "sel.settings.show_global" {
		t.Fatalf("ContextFor(SER): %+v", got)
	}
	for _, op := range []string{"sel.settings.show_port1", "sel.settings.show_global", "sel.id"} {
		if got := p.ContextFor(op); len(got) != 0 {
			t.Errorf("ContextFor(%s): %+v", op, got)
		}
	}
	run := func(pkg *register.Package, op string, lines ...string) error {
		var segs []seg
		for _, l := range lines {
			segs = append(segs, seg{adapter.Sent, adapter.PhaseOperate, l + "\r\n"}, seg{adapter.Received, adapter.PhaseOperate, l + "\r\n=>"})
		}
		r := c2Result(cat(pProbe, pAuth, segs, pClose), "")
		r.RegisterVersion, r.OperationID = pkg.Revision, op
		return r.CheckLines(pkg, adapter.Invocation{InvocationID: r.InvocationID, OperationID: op})
	}
	for _, c := range []struct {
		name, op string
		lines    []string
		ok       bool
	}{
		{"SER alone", "sel.ser.read_all", []string{"SER"}, true},
		{"SHO G then SER", "sel.ser.read_all", []string{"SHO G", "SER"}, true},
		{"SHO G in a SHO P 1 run", "sel.settings.show_port1", []string{"SHO G", "SHO P 1"}, false},
		{"SHO G in an ID run", "sel.id", []string{"SHO G", "ID"}, false},
		// SHO P 1 reads the language precondition and the posture
		// warnings, so every run may send it (C3 0.1, unchanged).
		{"SHO P 1 in a SER run", "sel.ser.read_all", []string{"SHO P 1", "SER"}, true},
		{"SHO G with a parameter in a SER run", "sel.ser.read_all", []string{"SHO G DATE_F", "SER"}, false},
		{"SHO L in a SER run", "sel.ser.read_all", []string{"SHO L", "SER"}, false},
	} {
		err := run(p, c.op, c.lines...)
		if c.ok != (err == nil) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	// Revision 4 without its context: the same SHO G in a SER run is refused.
	nb, _ := c3Rev4(t, func(m map[string]any) { delete(m, "context") })
	np, err := register.Decode(nb)
	if err != nil {
		t.Fatal(err)
	}
	if run(np, "sel.ser.read_all", "SHO G", "SER") == nil {
		t.Error("SHO G in a SER run accepted with no context read")
	}
}
