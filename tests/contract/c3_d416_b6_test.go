package contract

// D4-16 (B1 on #279 and #293): a key added at a C3 version is refused by
// its presence in any package below that version, whatever the value, an
// empty list or null included, because an older reader refuses the key as
// unknown. The golden is revision 4, a 0.2 package; the 0.1 cases also drop
// its context. Ground truth: GT-HAND. Evidence class: desk.

import (
	"strings"
	"testing"

	"otsec.local/otsec/contracts/register"
)

func TestC3D416NewKeysBeforeOnePointThree(t *testing.T) {
	for _, contract := range []string{"otsec.register/0.1", "otsec.register/0.2"} {
		for _, c := range []struct {
			name, key string
			edit      func(p map[string]any)
		}{
			{"runs []", "runs", func(p map[string]any) { p["runs"] = []any{} }},
			{"runs null", "runs", func(p map[string]any) { p["runs"] = nil }},
			{"limits null", "limits", func(p map[string]any) { c3Op(p, c3SER)["limits"] = nil }},
			{"limits null on the last operation", "limits", func(p map[string]any) {
				ops := p["operations"].([]any)
				ops[len(ops)-1].(map[string]any)["limits"] = nil
			}},
		} {
			b, err := c3Rev4(t, func(p map[string]any) {
				p["contract"] = contract
				if contract == "otsec.register/0.1" {
					delete(p, "context")
				}
				c.edit(p)
			})
			if err != nil {
				t.Fatal(err)
			}
			_, err = register.Decode(b)
			if err == nil || !strings.Contains(err.Error(), c.key) {
				t.Errorf("%s with %s: want refused for its %s key, got %v", contract, c.name, c.key, err)
			}
		}
		// The control: the same package with neither key reads.
		b, err := c3Rev4(t, func(p map[string]any) {
			p["contract"] = contract
			if contract == "otsec.register/0.1" {
				delete(p, "context")
			}
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := register.Decode(b); err != nil {
			t.Errorf("%s with neither key: %v", contract, err)
		}
	}
	// At 0.3 the keys are the format's own: an empty or null runs is a
	// package with no runs.
	for _, v := range []any{[]any{}, nil} {
		b, err := c3Rev4(t, func(p map[string]any) { p["contract"] = "otsec.register/0.3"; p["runs"] = v })
		if err != nil {
			t.Fatal(err)
		}
		if pkg, err := register.Decode(b); err != nil || len(pkg.Runs) != 0 {
			t.Errorf("0.3 with runs %v: %v", v, err)
		}
	}
}

// The same rule one minor down: a 0.1 package with a context key is refused
// whatever its value, and a 0.2 package may carry an empty one.
func TestC3D416ContextKeyInOnePointOne(t *testing.T) {
	for _, v := range []any{[]any{}, nil} {
		b, err := c3Rev4(t, func(p map[string]any) { p["contract"] = "otsec.register/0.1"; p["context"] = v })
		if err != nil {
			t.Fatal(err)
		}
		if _, err := register.Decode(b); err == nil || !strings.Contains(err.Error(), "context") {
			t.Errorf("0.1 with context %v: want refused for its context key, got %v", v, err)
		}
		// The control: at 0.2 the key is the format's own, so an empty or
		// null context is a package with no context. The 0.3 keys (runs,
		// an operation's limits) are taken out so the package is 0.2 whole.
		b, err = c3Rev4(t, func(p map[string]any) {
			p["contract"] = "otsec.register/0.2"
			p["context"] = v
			delete(p, "runs")
			for _, o := range p["operations"].([]any) {
				delete(o.(map[string]any), "limits")
			}
		})
		if err != nil {
			t.Fatal(err)
		}
		if pkg, err := register.Decode(b); err != nil || len(pkg.Context) != 0 {
			t.Errorf("0.2 with context %v: want a package with no context, got %v", v, err)
		}
	}
}
