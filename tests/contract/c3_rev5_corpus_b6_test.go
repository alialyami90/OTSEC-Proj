package contract

// Register revision 5 (D4-13, #301) against B6's corpora, with no line
// skipped. D4-13 approves the 24 SHO forms of S22 Table 7.67 without a
// setting name, as exact lines; nothing else is newly approved. The list
// below is typed from D4-13 and B2's design note (docs/phase4/
// B2-register-rev5.md), not read from the package. Every deny-corpus line
// stays refused; every variant of each form (a setting name, spacing, case,
// abbreviation, chaining, control bytes, leading zeros, Spanish) is refused.
// Ground truth: GT-DOC through D4-13, GT-HAND. Evidence class: desk.

import (
	"bufio"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/register"
)

var rev5Forms = []string{
	"SHO 1", "SHO 2", "SHO 3", "SHO 4",
	"SHO L 1", "SHO L 2", "SHO L 3", "SHO L 4",
	"SHO G", "SHO P 1", "SHO P F", "SHO P 2", "SHO P 3", "SHO P 4",
	"SHO R", "SHO F", "SHO M", "SHO I",
	"SHO E 1", "SHO E 2", "SHO E 3",
	"SHO DNP 1", "SHO DNP 2", "SHO DNP 3",
}

func rev5Matcher(t *testing.T) (*register.Package, *register.Matcher) {
	t.Helper()
	b, err := os.ReadFile("../../contracts/register/testdata/sel-751.json")
	if err != nil {
		t.Fatal(err)
	}
	p, err := register.Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	if p.Revision != 5 {
		t.Fatalf("revision %d: this test is for revision 5", p.Revision)
	}
	m, err := register.NewMatcher(p)
	if err != nil {
		t.Fatal(err)
	}
	return p, m
}

// b6Corpus reads one of B6's corpora; \t and \xNN escapes are decoded, as
// the Python reader's unicode_escape does.
func b6Corpus(t *testing.T, name string) []string {
	t.Helper()
	f, err := os.Open("../safety/register_review/" + name)
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
		s, err := strconv.Unquote(`"` + strings.ReplaceAll(raw, `"`, `\"`) + `"`)
		if err != nil {
			t.Fatalf("%s: %q: %v", name, raw, err)
		}
		out = append(out, s)
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// refused fails unless line is neither an operation nor a session line, and
// is not permitted in the operate phase.
func refused(t *testing.T, m *register.Matcher, what, line string) {
	t.Helper()
	if v, id := m.Match(line); v == register.VerdictOperation || v == register.VerdictSessionControl {
		t.Errorf("%s %q classified %s (%s)", what, line, v, id)
	}
	if _, id, err := m.Permit(register.PhaseOperate, line); err == nil {
		t.Errorf("%s %q permitted in the operate phase (%s)", what, line, id)
	}
}

func TestB6Rev5DenyCorpus(t *testing.T) {
	_, m := rev5Matcher(t)
	lines := b6Corpus(t, "sel-deny-corpus.txt")
	if len(lines) < 190 {
		t.Fatalf("%d deny lines", len(lines))
	}
	for _, l := range lines {
		refused(t, m, "deny corpus", l)
	}
	for _, l := range b6Corpus(t, "allow-corpus.txt") {
		if v, _ := m.Match(l); v != register.VerdictOperation && v != register.VerdictSessionControl {
			t.Errorf("allow corpus %q classified %s", l, v)
		}
	}
}

// The operations are exactly ID, SER and the 24 forms, each read-only at
// access level 1 or lower with no parameter, and the run sends each form
// once.
func TestB6Rev5ApprovesOnlyTheTable(t *testing.T) {
	p, m := rev5Matcher(t)
	var got []string
	for _, o := range p.Operations {
		got = append(got, o.Line)
		if o.Classification != register.ReadOnly || len(o.Params) != 0 || (o.AccessLevel != "0" && o.AccessLevel != "1") {
			t.Errorf("%s (%q): %s, level %s, %d params", o.ID, o.Line, o.Classification, o.AccessLevel, len(o.Params))
		}
	}
	want := append([]string{"ID", "SER"}, rev5Forms...)
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("operation lines %q, want %q", got, want)
	}
	for _, f := range rev5Forms {
		if _, id, err := m.Permit(register.PhaseOperate, f); err != nil {
			t.Errorf("%q not permitted: %s %v", f, id, err)
		}
	}
	if len(p.Runs) != 1 {
		t.Fatalf("%d runs", len(p.Runs))
	}
	lines, err := m.RenderRun(p.Runs[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) < 2 || lines[0] != "SHO P 1" || lines[1] != "SHO G" {
		t.Errorf("the run does not lead with the language gate and SHO G: %q", lines)
	}
	run := slices.Clone(lines)
	slices.Sort(run)
	forms := slices.Clone(rev5Forms)
	slices.Sort(forms)
	if !slices.Equal(run, forms) {
		t.Errorf("run lines %q, want each of the 24 forms once", lines)
	}
}

// variants of an approved form that the register must refuse.
func rev5Variants(f string) []string {
	words := strings.Fields(f)
	out := []string{
		f + " X", f + " 1", f + " CTR", f + " A B", f + " ", " " + f, f + "\t", "\t" + f,
		f + ";SET", f + "; SET", f + "\r", f + "\n", f + "\x00", f + "\x1b",
		strings.ToLower(f), "MOS" + f[3:], "SHOW" + f[3:], "SH" + f[3:],
		strings.Join(words, "  "), strings.Join(words, ""), strings.Join(words, "\t"),
	}
	for i := 1; i < len(words); i++ {
		// One space removed, one doubled, and a leading zero on a number.
		out = append(out,
			strings.Join(words[:i], " ")+strings.Join(words[i:], " "),
			strings.Join(words[:i], " ")+"  "+strings.Join(words[i:], " "),
		)
		if _, err := strconv.Atoi(words[i]); err == nil {
			w := slices.Clone(words)
			w[i] = "0" + w[i]
			out = append(out, strings.Join(w, " "))
		}
	}
	// Each letter in the other case on its own.
	for i, r := range f {
		if r >= 'A' && r <= 'Z' {
			out = append(out, f[:i]+strings.ToLower(string(r))+f[i+1:])
		}
	}
	return out
}

func TestB6Rev5VariantsRefused(t *testing.T) {
	_, m := rev5Matcher(t)
	n := 0
	for _, f := range rev5Forms {
		for _, v := range rev5Variants(f) {
			refused(t, m, "variant of "+f, v)
			n++
		}
	}
	if n < 24*25 {
		t.Fatalf("only %d variants", n)
	}
}
