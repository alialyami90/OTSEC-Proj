package adapter

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/register"
)

// The configuration read is a register run (C3 0.3, revision 5); its goldens
// are in testdata/config and are written by testdata/generate_config.py.

const configRun = "sel.config.read_all"

func rev5(t *testing.T) (*register.Package, *register.Matcher) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "register", "testdata", "sel-751.json"))
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

func configInvocation(t *testing.T) Invocation {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "config", "invocations", "valid", "sel-config-read.json"))
	if err != nil {
		t.Fatal(err)
	}
	inv, err := DecodeInvocation(b)
	if err != nil {
		t.Fatal(err)
	}
	return inv
}

func configResult(t *testing.T, n string) Result {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "config", "results", "valid", n+".json"))
	if err != nil {
		t.Fatal(err)
	}
	r, err := DecodeResult(b)
	if err != nil {
		t.Fatalf("%s: %v", n, err)
	}
	return r
}

func TestConfigGoldens(t *testing.T) {
	p, m := rev5(t)
	inv := configInvocation(t)
	if err := inv.ValidateWith(RegisterLookup{M: m}); err != nil {
		t.Fatalf("invocation: %v", err)
	}
	want, err := Limits{}.ForRun(m, configRun)
	if err != nil {
		t.Fatal(err)
	}
	if inv.Limits.StepTimeoutMS != want.StepTimeoutMS || inv.Limits.DeadlineMS != want.DeadlineMS ||
		inv.Limits.MaxResponseBytes != want.MaxResponseBytes {
		t.Errorf("invocation limits %+v are not the run's %+v", inv.Limits, want)
	}
	fs, _ := filepath.Glob(filepath.Join("testdata", "config", "results", "valid", "*.json"))
	if len(fs) < 8 {
		t.Fatalf("%d result goldens", len(fs))
	}
	for _, f := range fs {
		n := strings.TrimSuffix(filepath.Base(f), ".json")
		r := configResult(t, n)
		if err := r.Validate(); err != nil {
			t.Errorf("%s: Validate: %v", n, err)
		}
		if err := r.CheckLines(p, inv); err != nil {
			t.Errorf("%s: CheckLines: %v", n, err)
		}
		if r.OperationID != configRun || r.Target != "simulated" {
			t.Errorf("%s: operation %q target %q", n, r.OperationID, r.Target)
		}
	}
}

func TestConfigGoldenShapes(t *testing.T) {
	ok := configResult(t, "ok")
	if ok.Status != StatusOK || len(ok.Records) != 24 {
		t.Fatalf("ok: status %s, %d records", ok.Status, len(ok.Records))
	}
	var absent int
	for _, rec := range ok.Records {
		if rec.Kind == RecordConfigAbsent {
			absent++
		}
	}
	if absent != 10 {
		t.Errorf("ok: %d absent records, want the 10 the relay was not ordered with", absent)
	}
	if all := configResult(t, "ok-all-present"); all.Status != StatusOK {
		for _, rec := range all.Records {
			if rec.Kind == RecordConfigAbsent {
				t.Error("ok-all-present holds an absent record")
			}
		}
	}
	for n, code := range map[string]Code{
		"failed.timeout-in-run":                     FailedTimeout,
		"failed.response_too_large-in-run":          FailedResponseTooLarge,
		"failed.access_level_dropped-in-run":        FailedAccessLevelDropped,
		"failed.device_error-required-class-absent": FailedDeviceError,
		"partial.parse_errors-in-run":               PartialParseErrors,
	} {
		r := configResult(t, n)
		if r.Error == nil || r.Error.Code != code {
			t.Errorf("%s: error %+v, want %s", n, r.Error, code)
		}
		// A failed run reports no record (D4-13): bytes kept, nothing read.
		if r.Status == StatusFailed && len(r.Records) != 0 {
			t.Errorf("%s: a failed run carries %d records", n, len(r.Records))
		}
	}
}

func TestConfigCheckLinesRefuses(t *testing.T) {
	p, _ := rev5(t)
	inv := configInvocation(t)
	ok := configResult(t, "ok")
	sho := func(line string) int { return sentSegment(t, ok, PhaseOperate, line) }
	withRecords := func(f func([]Record) []Record) Result {
		r := ok
		r.Records = f(slices.Clone(ok.Records))
		return r
	}
	cases := map[string]struct {
		r    Result
		want string
	}{
		"a step repeated":        {replaceSegment(ok, sho("SHO 2"), []byte("SHO 3\r\n")), "once each and in order"},
		"a step out of order":    {replaceSegment(ok, sho("SHO L 1"), []byte("SHO L 2\r\n")), "once each and in order"},
		"a line outside the run": {replaceSegment(ok, sho("SHO M"), []byte("SHO P 5\r\n")), "may not be sent"},
		"a read the run lacks":   {replaceSegment(ok, sho("SHO M"), []byte("SER\r\n")), "does not run or need"},
		"a record missing":       {withRecords(func(r []Record) []Record { return r[:23] }), "has 23 records for its 24 steps"},
		"a record added":         {withRecords(func(r []Record) []Record { return append(r, r[0]) }), "records for its 24 steps"},
		"records swapped": {withRecords(func(r []Record) []Record {
			r[3], r[4] = r[4], r[3]
			return r
		}), "is not in the reply to step"},
		"a SER row in a run": {withRecords(func(r []Record) []Record { r[5].Kind = "sel.ser.row"; return r }), "is not a configuration record"},
		"a record in the wrong reply": {withRecords(func(r []Record) []Record { r[2].Span = r[3].Span; return r }),
			"is not in the reply to step 3"},
		"register revision": {func() Result { r := ok; r.RegisterVersion = 4; return r }(), "package is revision 5"},
	}
	for n, c := range cases {
		err := c.r.CheckLines(p, inv)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", n, err, c.want)
		}
	}
}

// A configuration record belongs to a run; a single operation's result that
// carries one is refused, as is a run's result whose line is not a step.
func TestConfigRecordOnlyInARun(t *testing.T) {
	p := sel751Package(t)
	r := loadResult(t, "ok")
	r.Records = append(slices.Clone(r.Records), Record{Kind: RecordConfigSection, Span: r.Records[0].Span, ParseOK: true,
		Fields: []Field{{Name: "A", Value: "1"}}})
	if err := r.CheckLines(p, validInvocation(t)); err == nil || !strings.Contains(err.Error(), "is a record of a run") {
		t.Errorf("config record in a SER read: %v", err)
	}
}

func TestConfigRecordValidate(t *testing.T) {
	sp := configResult(t, "ok").Records[0].Span
	good := func() Record {
		return Record{Kind: RecordConfigSection, Span: sp, ParseOK: true, Fields: []Field{{Name: "A", Value: "1"}, {Name: "B", Value: "x y"}}}
	}
	cases := map[string]struct {
		rec  func(Record) Record
		want string
	}{
		"duplicate name":       {func(r Record) Record { r.Fields[1].Name = "A"; return r }, "reported twice"},
		"lowercase name":       {func(r Record) Record { r.Fields[0].Name = "a"; return r }, "needs a setting name"},
		"name too long":        {func(r Record) Record { r.Fields[0].Name = strings.Repeat("A", 17); return r }, "needs a setting name"},
		"control byte":         {func(r Record) Record { r.Fields[0].Value = "1\x01"; return r }, "printable ASCII"},
		"empty value":          {func(r Record) Record { r.Fields[0].Value = ""; return r }, "printable ASCII"},
		"parsed, no settings":  {func(r Record) Record { r.Fields = nil; return r }, "holds at least one setting"},
		"unparsed with fields": {func(r Record) Record { r.ParseOK = false; return r }, "carries no fields"},
		"absent with fields":   {func(r Record) Record { r.Kind = RecordConfigAbsent; return r }, "no fields"},
		"context span":         {func(r Record) Record { c := sp; r.ContextSpan = &c; return r }, "no context span"},
	}
	for n, c := range cases {
		r := configResult(t, "ok")
		r.Records = []Record{c.rec(good())}
		err := r.Validate()
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", n, err, c.want)
		}
	}
	// A 0.5 result cannot carry one.
	r := configResult(t, "ok")
	r.Schema = "otsec.adapter/0.5"
	if err := r.Validate(); err == nil || !strings.Contains(err.Error(), "is new in 0.6") {
		t.Errorf("0.5 result with config records: %v", err)
	}
}

func TestRunInvocable(t *testing.T) {
	_, m := rev5(t)
	reg := RegisterLookup{M: m}
	if lvl, err := reg.Invocable(configRun, nil); err != nil || lvl != "1" {
		t.Errorf("%s: level %q, %v", configRun, lvl, err)
	}
	if _, err := reg.Invocable(configRun, map[string]string{"x": "1"}); err == nil {
		t.Error("parameters on a run accepted")
	}
	// A revision 4 package has no such run.
	if _, err := sel751(t).Invocable(configRun, nil); err == nil {
		t.Error("run invocable in revision 4")
	}
	if _, err := (Limits{}).ForRun(m, "sel.ser.read_all"); err == nil {
		t.Error("ForRun accepts an operation that is not a run")
	}
}

func TestConfigExamplesHaveNotes(t *testing.T) {
	readme, err := os.ReadFile(filepath.Join("testdata", "config", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{"results/valid", "invocations/valid"} {
		fs, _ := filepath.Glob(filepath.Join("testdata", "config", dir, "*.json"))
		for _, f := range fs {
			if rel := dir + "/" + filepath.Base(f); !strings.Contains(string(readme), "`"+rel+"`") {
				t.Errorf("testdata/config/README.md has no note for %s", rel)
			}
		}
	}
}

// The run's invocation is the one the collector builds for the C1 relay
// example: the profile names the run, and the limits sit within its session
// limits.
func TestConfigInvocationCheckAgainst(t *testing.T) {
	a, p := c1Example(t)
	if err := configInvocation(t).CheckAgainst(a, p); err != nil {
		t.Fatalf("C1 relay example refused: %v", err)
	}
	other := configInvocation(t)
	other.OperationID = "sel.config.read_other"
	if got := codeOf(other.CheckAgainst(a, p)); got != RefusedNotInvocable {
		t.Errorf("a run the profile does not name: %s", got)
	}
}
