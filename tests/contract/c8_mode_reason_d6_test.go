package contract

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/audit"
	"otsec.local/otsec/contracts/store"
)

// F-028 (brief P4-4-DO): C8 0.13's sentence on store.mode_change
// (contracts/audit/doc.go) and C5's on ModeChange (contracts/store/startup.go).
// reason_code is the new C5 mode with each "-" written as "_": drain-only is
// recorded as drain_only, and collecting, blocked and failed as they are. No
// C5 mode name contains "_", so a reader recovers the mode by writing "_"
// back as "-". C8's pattern does not change, so the unmapped drain-only stays
// refused. Ground truth: GT-HAND from the two sentences, independent of
// platform/node's modeReason, which this file neither imports nor reads.
// Evidence class: desk.

// c8ModeReasons is the sentence's own table.
var c8ModeReasons = map[store.Mode]string{
	store.ModeCollecting: "collecting",
	store.ModeDrainOnly:  "drain_only",
	store.ModeBlocked:    "blocked",
	store.ModeFailed:     "failed",
}

// c8ModeReason is the sentence's rule: each "-" written as "_".
func c8ModeReason(m string) string { return strings.ReplaceAll(m, "-", "_") }

// c5ModesFromSource returns every constant that contracts/store declares in
// the form `Name Mode = "value"`, the form of each C5 mode, so that a mode
// added later is checked here without a change to this file.
func c5ModesFromSource(t *testing.T) []string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join("..", "..", "contracts", "store", "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	var modes []string
	fset := token.NewFileSet()
	for _, p := range files {
		if strings.HasSuffix(p, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, p, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range f.Decls {
			g, ok := d.(*ast.GenDecl)
			if !ok || g.Tok != token.CONST {
				continue
			}
			for _, s := range g.Specs {
				v := s.(*ast.ValueSpec)
				if id, ok := v.Type.(*ast.Ident); !ok || id.Name != "Mode" {
					continue
				}
				for _, e := range v.Values {
					lit, ok := e.(*ast.BasicLit)
					if !ok || lit.Kind != token.STRING {
						t.Fatalf("%s: a Mode constant that is not a string literal", fset.Position(e.Pos()))
					}
					m, err := strconv.Unquote(lit.Value)
					if err != nil {
						t.Fatal(err)
					}
					modes = append(modes, m)
				}
			}
		}
	}
	return modes
}

// c8ReasonSchemaPattern is reason_code's pattern in C8's published schema.
// It is ^[a-z][a-z0-9_]{0,47}$, which reads the same in Go's regexp and in
// the schema's ECMA-262 dialect.
func c8ReasonSchemaPattern(t *testing.T) *regexp.Regexp {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "contracts", "audit", "schema", "record.json"))
	if err != nil {
		t.Fatal(err)
	}
	var s struct {
		Properties struct {
			ReasonCode struct {
				Pattern string `json:"pattern"`
			} `json:"reason_code"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(b, &s); err != nil || s.Properties.ReasonCode.Pattern == "" {
		t.Fatalf("record.json: no reason_code pattern (%v)", err)
	}
	return regexp.MustCompile(s.Properties.ReasonCode.Pattern)
}

// c8ModeReasonFaults records a store.mode_change for each mode, its
// reason_code given by reason and its detail in the C5 spelling, as the node
// writes it, and returns what C8 refuses: audit.ValidatePending (the check
// that loses a refused record), the schema's pattern, or a reason_code that
// does not read back as its mode.
func c8ModeReasonFaults(t *testing.T, modes []string, reason func(string) string) []string {
	t.Helper()
	schema := c8ReasonSchemaPattern(t)
	var faults []string
	for _, m := range modes {
		r := reason(m)
		pending := fmt.Sprintf(`{"contract":%q,"node_id":"site-d6-node-1",`+
			`"time":{"utc":"2026-11-15T12:00:00.000001Z","resolution_ns":1000,"clock":{"sync":"synchronized","source":"ntp"}},`+
			`"actor":{"type":"system","id":"node"},"action":"store.mode_change","outcome":"info",`+
			`"reason_code":%q,"detail":%q}`, audit.ContractID, r, "database evidence: collecting to "+m)
		if _, err := audit.ValidatePending([]byte(pending)); err != nil {
			faults = append(faults, fmt.Sprintf("%s: ValidatePending: %v", m, err))
		}
		if !schema.MatchString(r) {
			faults = append(faults, fmt.Sprintf("%s: schema pattern refuses %q", m, r))
		}
		if back := strings.ReplaceAll(r, "_", "-"); back != m {
			faults = append(faults, fmt.Sprintf("%s: reason_code %q reads back as %q", m, r, back))
		}
	}
	return faults
}

func TestC8ModeChangeReasonEveryC5Mode(t *testing.T) {
	modes := c5ModesFromSource(t)
	for m, want := range c8ModeReasons {
		if !slices.Contains(modes, string(m)) {
			t.Fatalf("the scan of contracts/store found %q, not %q", modes, m)
		}
		if got := c8ModeReason(string(m)); got != want {
			t.Errorf("%s is recorded as %q; the sentence says %q", m, got, want)
		}
	}
	for _, f := range c8ModeReasonFaults(t, modes, c8ModeReason) {
		t.Error(f)
	}

	// The unmapped mode, as on main before F-028: drain-only, and only it,
	// is refused by both checks, for its reason_code.
	got := c8ModeReasonFaults(t, modes, func(m string) string { return m })
	if len(got) != 2 || !strings.HasPrefix(got[0], `drain-only: ValidatePending: `) ||
		!strings.Contains(got[0], `reason code "drain-only"`) || got[1] != `drain-only: schema pattern refuses "drain-only"` {
		t.Errorf("unmapped modes: got %q, want drain-only refused by ValidatePending and by the schema", got)
	}
}
