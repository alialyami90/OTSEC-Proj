package contract

// C2 0.6 (P4-A2, D4-13, D4-23, #331): C6's contract cases on the
// configuration read, written from the contract's own statement of 0.6
// (contracts/adapter/doc.go) and not from its tests:
//
//   - a register run is invocable under its own ID, with no parameters, at
//     the highest access level of its steps;
//   - Limits.ForRun gives the run's total bytes and deadline and its longest
//     step timeout, and refuses an ID that is not a run;
//   - the records sel.config.section and sel.config.absent are new in 0.6,
//     so a result stamped 0.5 cannot carry them;
//   - a run's result has exactly two shapes (CheckLines): ok, with every step
//     sent once and in order and one parsed record per step in step order;
//     or not ok, with a prefix of the steps and no record. So a missing,
//     extra, reordered or unparsed record is refused, and so is a failed run
//     that reports any record, failed.config_unparsable included.
//
// Ground truth: the contract text above and the signed SEL-751 register as
// it is in the tree (revision 5). C2's goldens are used as inputs only, each
// mutated one way. Evidence class: desk. No device.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"otsec.local/otsec/contracts/adapter"
	"otsec.local/otsec/contracts/register"
)

const c6Run = "sel.config.read_all"

func c6Rev5(t *testing.T) (*register.Package, *register.Matcher) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "contracts", "register", "testdata", "sel-751.json"))
	if err != nil {
		t.Fatal(err)
	}
	p, err := register.Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	m, err := register.NewMatcher(p)
	if err != nil {
		t.Fatal(err)
	}
	return p, m
}

func c6ConfigDir(parts ...string) string {
	return filepath.Join(append([]string{"..", "..", "contracts", "adapter", "testdata", "config"}, parts...)...)
}

func c6ConfigInvocation(t *testing.T) adapter.Invocation {
	t.Helper()
	b, err := os.ReadFile(c6ConfigDir("invocations", "valid", "sel-config-read.json"))
	if err != nil {
		t.Fatal(err)
	}
	inv, err := adapter.DecodeInvocation(b)
	if err != nil {
		t.Fatal(err)
	}
	return inv
}

// c6ConfigResult decodes a valid golden; each case changes its own copy.
func c6ConfigResult(t *testing.T, name string) adapter.Result {
	t.Helper()
	b, err := os.ReadFile(c6ConfigDir("results", "valid", name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	r, err := adapter.DecodeResult(b)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return r
}

// c6Accepts is the whole check a consumer makes of a run's result.
func c6Accepts(t *testing.T, r adapter.Result) error {
	t.Helper()
	p, _ := c6Rev5(t)
	if err := r.Validate(); err != nil {
		return err
	}
	return r.CheckLines(p, c6ConfigInvocation(t))
}

func TestC6C2V06RunIsInvocableByItsIDWithNoParameters(t *testing.T) {
	_, m := c6Rev5(t)
	look := adapter.RegisterLookup{M: m}
	level, err := look.Invocable(c6Run, nil)
	if err != nil {
		t.Fatalf("the run is not invocable: %v", err)
	}
	// The highest level of its steps, read here from the register itself.
	run, ok := m.Run(c6Run)
	if !ok {
		t.Fatal("the register has no run " + c6Run)
	}
	want := "0"
	for _, s := range run.Steps {
		o, ok := m.Operation(s)
		if !ok {
			t.Fatalf("step %s is not an operation", s)
		}
		if !register.LevelAtMost(o.AccessLevel, want) {
			want = o.AccessLevel
		}
	}
	if level != want || want == "0" {
		t.Fatalf("the run is invocable at level %q, want its highest step's %q (not 0)", level, want)
	}
	if _, err := look.Invocable(c6Run, map[string]string{"n": "1"}); err == nil {
		t.Fatal("the run was invocable with a parameter")
	}
}

func TestC6C2V06ForRunCarriesTheRunsLimits(t *testing.T) {
	_, m := c6Rev5(t)
	run, _ := m.Run(c6Run)
	base := adapter.Limits{StepTimeoutMS: 1, DeadlineMS: 1, MaxResponseBytes: 1}
	got, err := base.ForRun(m, c6Run)
	if err != nil {
		t.Fatal(err)
	}
	longest := int64(0)
	for _, s := range run.Steps {
		l, ok := m.Limits(s)
		if !ok {
			t.Fatalf("step %s has no limits", s)
		}
		longest = max(longest, l.TimeoutMS)
	}
	if got.DeadlineMS != run.DeadlineMS || got.MaxResponseBytes != run.MaxTotalBytes || got.StepTimeoutMS != longest {
		t.Fatalf("ForRun gave deadline %d, bytes %d, step %d; want the run's %d, %d and its longest step's %d",
			got.DeadlineMS, got.MaxResponseBytes, got.StepTimeoutMS, run.DeadlineMS, run.MaxTotalBytes, longest)
	}
	// Every step of revision 5 has the same timeout, so the longest is also
	// checked on a copy whose middle step waits longer.
	b, err := os.ReadFile(filepath.Join("..", "..", "contracts", "register", "testdata", "sel-751.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	for _, o := range doc["operations"].([]any) {
		if o := o.(map[string]any); o["id"] == run.Steps[len(run.Steps)/2] {
			o["limits"].(map[string]any)["timeout_ms"] = float64(longest + 5000)
		}
	}
	b, _ = json.Marshal(doc)
	p2, err := register.Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	m2, err := register.NewMatcher(p2)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := base.ForRun(m2, c6Run); err != nil || got.StepTimeoutMS != longest+5000 {
		t.Fatalf("ForRun with one step at %d ms gave step timeout %d (%v), want that step's", longest+5000, got.StepTimeoutMS, err)
	}
	for _, id := range []string{"sel.settings.show_group_1", "sel.ser.read_all", "sel.config.read_none"} {
		if _, err := base.ForRun(m, id); err == nil {
			t.Errorf("ForRun accepted %q, which is not a run", id)
		}
	}
}

func TestC6C2V06TheGoldensAreAccepted(t *testing.T) {
	// The controls: each mutation below starts from one of these.
	for _, n := range []string{"ok", "failed.config_unparsable"} {
		if err := c6Accepts(t, c6ConfigResult(t, n)); err != nil {
			t.Fatalf("%s: %v", n, err)
		}
	}
	r := c6ConfigResult(t, "ok")
	_, m := c6Rev5(t)
	run, _ := m.Run(c6Run)
	if len(r.Records) != len(run.Steps) || len(run.Steps) != 24 {
		t.Fatalf("ok holds %d records for %d steps, want 24 and 24", len(r.Records), len(run.Steps))
	}
}

func TestC6C2V06RecordsAreNewInZeroSix(t *testing.T) {
	r := c6ConfigResult(t, "ok")
	r.Schema = "otsec.adapter/0.5"
	if err := r.Validate(); err == nil {
		t.Fatal("a result stamped 0.5 carried sel.config records")
	}
}

func TestC6C2V06AnOkRunIsOneParsedRecordPerStepInOrder(t *testing.T) {
	cases := map[string]func(r *adapter.Result){
		"a record missing":  func(r *adapter.Result) { r.Records = r.Records[:len(r.Records)-1] },
		"a record repeated": func(r *adapter.Result) { r.Records = append(r.Records, r.Records[len(r.Records)-1]) },
		"two records swapped": func(r *adapter.Result) {
			r.Records[2], r.Records[3] = r.Records[3], r.Records[2]
		},
		"a record unparsed": func(r *adapter.Result) { r.Records[5].ParseOK = false },
		"no records":        func(r *adapter.Result) { r.Records = nil },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			r := c6ConfigResult(t, "ok")
			r.Records = slices.Clone(r.Records)
			mutate(&r)
			if err := c6Accepts(t, r); err == nil {
				t.Fatalf("an ok run with %s was accepted", name)
			}
		})
	}
}

func TestC6C2V06AFailedRunReportsNoRecord(t *testing.T) {
	ok := c6ConfigResult(t, "ok")
	for _, n := range []string{"failed.config_unparsable", "failed.timeout-in-run", "failed.device_error-required-class-absent"} {
		t.Run(n, func(t *testing.T) {
			r := c6ConfigResult(t, n)
			if err := c6Accepts(t, r); err != nil {
				t.Fatalf("the control is refused: %v", err)
			}
			r.Records = ok.Records[:1]
			if err := c6Accepts(t, r); err == nil {
				t.Fatalf("%s with a record was accepted", n)
			}
		})
	}
}

func TestC6C2V06ARunIsNeverPartial(t *testing.T) {
	// partial is not a run outcome, with records or without: the ok golden
	// relabelled partial is refused, and so is a partial with no record and
	// the one partial code that needs none (partial.read_rows_exceeded).
	r := c6ConfigResult(t, "ok")
	r.Status = adapter.StatusPartial
	r.Error = &adapter.Error{Code: adapter.PartialParseErrors}
	r.Records = slices.Clone(r.Records)
	r.Records[0].ParseOK, r.Records[0].Fields = false, nil
	if err := c6Accepts(t, r); err == nil {
		t.Fatal("a run reported partial.parse_errors was accepted")
	}
	r = c6ConfigResult(t, "ok")
	r.Status = adapter.StatusPartial
	r.Error = &adapter.Error{Code: adapter.PartialReadRowsExceeded, Detail: "rows 1025 over 1024"}
	r.Records = nil
	if err := c6Accepts(t, r); err == nil {
		t.Fatal("a run reported partial.read_rows_exceeded with no record was accepted")
	}
}

// c6Resend rewrites, in place, the operate sends of from as the lines in
// to, which have the same lengths, so every segment and span stays valid,
// and recomputes the transcript hash.
func c6Resend(t *testing.T, r *adapter.Result, from, to []string) {
	t.Helper()
	d := bytes.Clone(r.Transcript.Data)
	k := 0
	for _, s := range r.Transcript.Segments {
		if s.Dir != "tx" || s.Phase != adapter.PhaseOperate || k == len(from) {
			continue
		}
		if string(d[s.Offset:s.Offset+s.Length]) == from[k]+"\r\n" {
			copy(d[s.Offset:], to[k]+"\r\n")
			k++
		}
	}
	if k != len(from) {
		t.Fatalf("found %d of the sends %v", k, from)
	}
	r.Transcript.Data = d
	sum := sha256.Sum256(d)
	r.Transcript.SHA256 = hex.EncodeToString(sum[:])
}

func TestC6C2V06AFailedRunSentAPrefixOfItsSteps(t *testing.T) {
	// A failed run has no record, so only its sent lines say what it did:
	// they must be a prefix of the steps, each once and in order (C2 on
	// #423). Two sends swapped, and one step sent twice, are refused.
	cases := map[string][]string{
		"two steps swapped": {"SHO 4", "SHO 3"},
		"a step sent twice": {"SHO 3", "SHO 3"},
	}
	for _, n := range []string{"failed.timeout-in-run", "failed.config_unparsable"} {
		for name, to := range cases {
			t.Run(n+"/"+name, func(t *testing.T) {
				r := c6ConfigResult(t, n)
				c6Resend(t, &r, []string{"SHO 3", "SHO 4"}, to)
				if err := c6Accepts(t, r); err == nil {
					t.Fatalf("%s with %s was accepted", n, name)
				}
			})
		}
	}
}
