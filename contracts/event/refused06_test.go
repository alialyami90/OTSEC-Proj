package event

import (
	"encoding/json"
	"maps"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/version"
)

// C4 0.6 (docs/phase4/D4-c4-0.6-proposal.md, approved at 5e7f0487):
// E6-1, E6-2 and E6-3 as D4 unit tests, and E6-5's contract part.

const (
	obsRefused06      = "testdata/valid/health-observation-refused.json"
	baselineRefused06 = "testdata/valid/health-baseline-refused.json"
)

// laterMinor is one C4 minor above this reader's, computed from self so
// that no test reads a literal minor as later (self-check item 11).
func laterMinor() string {
	return version.ID{Name: self.Name, Major: self.Major, Minor: self.Minor + 1}.String()
}

// selfMinor is this reader's own C4 minor, computed from self.
func selfMinor() string { return self.String() }

// earlierMinor is the minor below 0.6, where both detector.* types are
// refused: 0.5.
const earlierMinor = "otsec.event/0.5"

const max64 = "18446744073709551615"

// obsOne is the observation-refused golden reduced to one reason, with
// no unsure: count 3, later-minor seqs 9 to 10, through 10.
func obsOne(t *testing.T) *Event {
	t.Helper()
	e := load(t, obsRefused06)
	e.Schema = selfMinor()
	e.Health.Details = map[string]string{
		"stream":                e.Health.Details["stream"],
		"since":                 e.Health.Details["since"],
		"through":               "10",
		"netobs":                e.Health.Details["netobs"],
		"count":                 "3",
		"reason.later-minor":    "3",
		"first_seq.later-minor": "9",
		"last_seq.later-minor":  "10",
	}
	return e
}

// codesOf returns the sorted, distinct codes of err.
func codesOf(err error) []Code {
	c := Codes(err)
	slices.Sort(c)
	return slices.Compact(c)
}

// refusal returns each *Error in err as "<detail> <code>", sorted, with
// the health.details. prefix dropped, so that a case pins which detail
// each refusal names and how many there are (D3's N1 on #772).
func refusal(err error) []string {
	var out []string
	if j, ok := err.(interface{ Unwrap() []error }); ok {
		for _, x := range j.Unwrap() {
			out = append(out, refusal(x)...)
		}
	} else if ve, ok := err.(*Error); ok {
		out = append(out, strings.TrimPrefix(ve.Field, "health.details.")+" "+string(ve.Code))
	}
	slices.Sort(out)
	return out
}

// refusalOf is the refusal of code naming each space-separated detail.
func refusalOf(code Code, details string) []string {
	var out []string
	for _, d := range strings.Fields(details) {
		out = append(out, d+" "+string(code))
	}
	slices.Sort(out)
	return out
}

// E6-1 (C4-0.6-1): the form of detector.observation-refused.
func TestObservationRefused06Form(t *testing.T) {
	if err := load(t, obsRefused06).Validate(); err != nil {
		t.Fatalf("the golden: %v", err)
	}
	if err := obsOne(t).Validate(); err != nil {
		t.Fatalf("one reason: %v", err)
	}
	accept := []struct {
		name string
		mut  func(d map[string]string)
	}{
		{"all three reasons, count at 2^64 - 1", func(d map[string]string) {
			d["reason.later-minor"], d["reason.malformed"], d["reason.detector-refused"] = "18446744073709551613", "1", "1"
			d["first_seq.malformed"], d["last_seq.malformed"] = "1", "2"
			d["first_seq.detector-refused"], d["last_seq.detector-refused"] = "3", "4"
			d["count"] = max64
		}},
		{"first_seq = last_seq = through", func(d map[string]string) { d["first_seq.later-minor"] = "10" }},
		{"first_seq 9, last_seq 10, through 10", func(d map[string]string) {}},
		{"last_seq 9, through 10", func(d map[string]string) { d["first_seq.later-minor"], d["last_seq.later-minor"] = "9", "9" }},
		{"netobs from netobs.Identifier03", func(d map[string]string) { d["netobs"] = "otsec.netobs/0.3" }},
		{"no unsure", func(d map[string]string) { delete(d, "unsure") }},
		{"unsure 9-10, through 10", func(d map[string]string) { d["unsure"] = "9-10" }},
		{"unsure 8-9, through 10", func(d map[string]string) { d["unsure"] = "8-9" }},
		{"unsure 10-10, through 10", func(d map[string]string) { d["unsure"] = "10-10" }},
		{"since with nanoseconds and an offset", func(d map[string]string) { d["since"] = "2026-11-21T09:00:00.123456789+14:00" }},
	}
	for _, tc := range accept {
		e := obsOne(t)
		tc.mut(e.Health.Details)
		if err := e.Validate(); err != nil {
			t.Errorf("%s: refused: %v", tc.name, err)
		}
	}

	refuse := []struct {
		name   string
		mut    func(d map[string]string)
		want   Code
		fields string
	}{
		{"reason at 0", func(d map[string]string) { d["reason.later-minor"] = "0" }, CodeEnum, "reason.later-minor"},
		{"reason at 01", func(d map[string]string) { d["reason.later-minor"] = "01" }, CodeEnum, "reason.later-minor"},
		{"reason at 2^64", func(d map[string]string) { d["reason.later-minor"] = "18446744073709551616" }, CodeEnum, "reason.later-minor"},
		{"reason.other, summed into count", func(d map[string]string) {
			d["reason.other"], d["first_seq.other"], d["last_seq.other"], d["count"] = "1", "1", "1", "4"
		}, CodeEnum, "first_seq.other last_seq.other reason.other"},
		{"first_seq without reason", func(d map[string]string) { d["first_seq.malformed"] = "1" }, CodeForbidden, "first_seq.malformed"},
		{"last_seq without reason", func(d map[string]string) { d["last_seq.malformed"] = "1" }, CodeForbidden, "last_seq.malformed"},
		{"reason without first_seq", func(d map[string]string) { delete(d, "first_seq.later-minor") }, CodeMissing, "first_seq.later-minor"},
		{"reason without last_seq", func(d map[string]string) { delete(d, "last_seq.later-minor") }, CodeMissing, "last_seq.later-minor"},
		{"count one above the sum", func(d map[string]string) { d["count"] = "4" }, CodeEnum, "count"},
		{"count one below the sum", func(d map[string]string) { d["count"] = "2" }, CodeEnum, "count"},
		{"count as the number of reasons", func(d map[string]string) { d["count"] = "1" }, CodeEnum, "count"},
		{"the wrapped sum", func(d map[string]string) {
			d["reason.later-minor"], d["reason.malformed"], d["count"] = max64, "2", "1"
			d["first_seq.malformed"], d["last_seq.malformed"] = "1", "2"
		}, CodeEnum, "count"},
		{"first_seq above last_seq", func(d map[string]string) { d["first_seq.later-minor"] = "11"; d["through"] = "11" }, CodeEnum, "first_seq.later-minor"},
		{"first_seq 10, last_seq 9", func(d map[string]string) { d["first_seq.later-minor"], d["last_seq.later-minor"] = "10", "9" }, CodeEnum, "first_seq.later-minor"},
		{"last_seq above through", func(d map[string]string) { d["last_seq.later-minor"] = "11" }, CodeEnum, "last_seq.later-minor"},
		{"last_seq 10, through 9", func(d map[string]string) { d["first_seq.later-minor"], d["through"] = "8", "9" }, CodeEnum, "last_seq.later-minor"},
		{"since not RFC 3339", func(d map[string]string) { d["since"] = "2026-11-21 09:00:00" }, CodeTimeFormat, "since"},
		{"stream not a token", func(d map[string]string) { d["stream"] = "Network Observation" }, CodeEnum, "stream"},
		{"netobs as a baseline identifier", func(d map[string]string) { d["netobs"] = "otsec.netbaseline/0.1" }, CodeEnum, "netobs"},
		{"netobs as free text", func(d map[string]string) { d["netobs"] = "netobs 0.3" }, CodeEnum, "netobs"},
		{"netobs empty", func(d map[string]string) { d["netobs"] = "" }, CodeEnum, "netobs"},
		{"an unknown detail", func(d map[string]string) { d["note"] = "x" }, CodeEnum, "note"},
		{"first_seq malformed", func(d map[string]string) { d["first_seq.later-minor"] = "x" }, CodeEnum, "first_seq.later-minor"},
		{"last_seq malformed", func(d map[string]string) { d["last_seq.later-minor"] = "x" }, CodeEnum, "last_seq.later-minor"},
		{"through malformed", func(d map[string]string) { d["through"] = "010" }, CodeEnum, "through"},
		{"count at 2^64, the sum at 2^64 - 1", func(d map[string]string) {
			d["reason.later-minor"], d["count"] = max64, "18446744073709551616"
		}, CodeEnum, "count"},
		{"no reason", func(d map[string]string) {
			for k := range d {
				if strings.Contains(k, "later-minor") {
					delete(d, k)
				}
			}
		}, CodeMissing, "reason"},
	}
	for _, s := range []string{"10-9", "9-11", "0-5", "9", "9-", "-10", "9-10-11", "nine to ten", ""} {
		refuse = append(refuse, struct {
			name   string
			mut    func(d map[string]string)
			want   Code
			fields string
		}{"unsure " + strconv.Quote(s), func(d map[string]string) { d["unsure"] = s }, CodeEnum, "unsure"})
	}
	for _, k := range []string{"stream", "since", "through", "netobs", "count"} {
		refuse = append(refuse, struct {
			name   string
			mut    func(d map[string]string)
			want   Code
			fields string
		}{"no " + k, func(d map[string]string) { delete(d, k) }, CodeMissing, k})
	}
	for _, tc := range refuse {
		e := obsOne(t)
		tc.mut(e.Health.Details)
		if got, want := refusal(e.Validate()), refusalOf(tc.want, tc.fields); !slices.Equal(got, want) {
			t.Errorf("%s: %v, want %v", tc.name, got, want)
		}
	}

	// unsure's relation is not checked over a missing through (D3's N2 on
	// #772): the golden, which has unsure, without through.
	e := load(t, obsRefused06)
	delete(e.Health.Details, "through")
	if got, want := refusal(e.Validate()), refusalOf(CodeMissing, "through"); !slices.Equal(got, want) {
		t.Errorf("the golden without through: %v, want %v", got, want)
	}
}

// E6-1: each refusal names the detail it concerns.
func TestObservationRefused06Fields(t *testing.T) {
	cases := []struct {
		mut   func(d map[string]string)
		field string
	}{
		{func(d map[string]string) { d["count"] = "4" }, "health.details.count"},
		{func(d map[string]string) { d["first_seq.later-minor"], d["last_seq.later-minor"] = "10", "9" }, "health.details.first_seq.later-minor"},
		{func(d map[string]string) { d["last_seq.later-minor"] = "11" }, "health.details.last_seq.later-minor"},
		{func(d map[string]string) { d["unsure"] = "9-11" }, "health.details.unsure"},
	}
	for _, tc := range cases {
		e := obsOne(t)
		tc.mut(e.Health.Details)
		err := e.Validate()
		var fields []string
		for _, x := range err.(interface{ Unwrap() []error }).Unwrap() {
			fields = append(fields, x.(*Error).Field)
		}
		if !slices.Equal(fields, []string{tc.field}) {
			t.Errorf("%v: fields %v, want [%s]", err, fields, tc.field)
		}
	}
}

// baselineOne is the baseline-refused golden at this reader's minor.
func baselineOne(t *testing.T) *Event {
	t.Helper()
	e := load(t, baselineRefused06)
	e.Schema = selfMinor()
	return e
}

// laterBaseline is otsec.netbaseline/0. + (baselineSelf's minor + 1). This
// package does not import contracts/netobs (netobs imports event), so it
// is computed from the stamp netobs.BaselineIdentifier carries today,
// otsec.netbaseline/0.1; tests/contract's E6-2 reads it from netobs.
func laterBaseline(t *testing.T) string {
	t.Helper()
	v, err := version.Parse("otsec.netbaseline/0.1")
	if err != nil {
		t.Fatal(err)
	}
	v.Minor++
	return v.String()
}

// E6-2 (C4-0.6-2): the form of detector.baseline-refused.
func TestBaselineRefused06Form(t *testing.T) {
	if err := baselineOne(t).Validate(); err != nil {
		t.Fatalf("the golden: %v", err)
	}
	accept := []map[string]string{
		{"schema": "unreadable", "cause": "malformed"},
		{"schema": "unreadable", "cause": "not-canonical"},
		{"schema": laterBaseline(t), "cause": "later-minor"},
		{"schema": "otsec.netbaseline/0.1", "cause": "not-canonical"},
	}
	for _, m := range accept {
		e := baselineOne(t)
		maps.Copy(e.Health.Details, m)
		if err := e.Validate(); err != nil {
			t.Errorf("%v: refused: %v", m, err)
		}
	}
	hash := baselineOne(t).Health.Details["hash"]
	refuse := []struct {
		name   string
		m      map[string]string
		want   Code
		fields string
	}{
		{"hash in upper case", map[string]string{"hash": "sha256:" + strings.ToUpper(hash[7:])}, CodeEnum, "hash"},
		{"hash with 63 digits", map[string]string{"hash": hash[:len(hash)-1]}, CodeEnum, "hash"},
		{"hash without sha256:", map[string]string{"hash": hash[7:]}, CodeEnum, "hash"},
		{"schema of another contract", map[string]string{"schema": Identifier}, CodeEnum, "schema"},
		{"schema as free text", map[string]string{"schema": "baseline 0.2"}, CodeEnum, "schema"},
		{"schema empty", map[string]string{"schema": ""}, CodeEnum, "schema"},
		{"cause outside the set", map[string]string{"cause": "expired"}, CodeEnum, "cause"},
		{"later-minor with unreadable", map[string]string{"schema": "unreadable", "cause": "later-minor"}, CodeEnum, "cause"},
		{"an unknown detail", map[string]string{"note": "x"}, CodeEnum, "note"},
	}
	for _, tc := range refuse {
		e := baselineOne(t)
		maps.Copy(e.Health.Details, tc.m)
		if got, want := refusal(e.Validate()), refusalOf(tc.want, tc.fields); !slices.Equal(got, want) {
			t.Errorf("%s: %v, want %v", tc.name, got, want)
		}
	}
	for _, k := range []string{"hash", "schema", "cause"} {
		e := baselineOne(t)
		delete(e.Health.Details, k)
		if got, want := refusal(e.Validate()), refusalOf(CodeMissing, k); !slices.Equal(got, want) {
			t.Errorf("no %s: %v, want %v", k, got, want)
		}
	}
}

// E6-3: minor gating. Each type is refused below 0.6, closed at this
// reader's minor, and open, with its known keys still checked, at a later
// one.
func TestDetectorTypes06Gating(t *testing.T) {
	for _, mk := range []func(*testing.T) *Event{obsOne, baselineOne} {
		e := mk(t)
		e.Schema = earlierMinor
		err := e.Validate()
		if got := codesOf(err); !slices.Equal(got, []Code{CodeForbidden}) || !strings.Contains(err.Error(), "new in otsec.event/0.6") {
			t.Errorf("%s at %s: %v, want only forbidden, new in 0.6", e.Health.Type, earlierMinor, err)
		}
		e = mk(t)
		e.Health.Details["added_later"] = "x"
		if got := codesOf(e.Validate()); !slices.Equal(got, []Code{CodeEnum}) {
			t.Errorf("%s: an unknown key at %s: %v, want only [enum]", e.Health.Type, selfMinor(), got)
		}
		e.Schema = laterMinor()
		if err := e.Validate(); err != nil {
			t.Errorf("%s: an unknown key at %s: %v", e.Health.Type, laterMinor(), err)
		}
	}

	// A later minor's reason, with its seqs, summed into count.
	e := obsOne(t)
	e.Schema = laterMinor()
	d := e.Health.Details
	d["reason.added-later"], d["first_seq.added-later"], d["last_seq.added-later"], d["count"] = "2", "4", "5", "5"
	if err := e.Validate(); err != nil {
		t.Errorf("a later minor's reason: %v", err)
	}
	for name, mut := range map[string]func(d map[string]string){
		"its reason left out of count":   func(d map[string]string) { d["count"] = "3" },
		"its last_seq above through":     func(d map[string]string) { d["last_seq.added-later"] = "11" },
		"its first_seq above last_seq":   func(d map[string]string) { d["first_seq.added-later"] = "6" },
		"its first_seq missing":          func(d map[string]string) { delete(d, "first_seq.added-later") },
		"its reason malformed":           func(d map[string]string) { d["reason.added-later"] = "02" },
		"a malformed through":            func(d map[string]string) { d["through"] = "010" },
		"a malformed netobs":             func(d map[string]string) { d["netobs"] = "x" },
		"a malformed unsure":             func(d map[string]string) { d["unsure"] = "9" },
		"a required key missing (count)": func(d map[string]string) { delete(d, "count") },
	} {
		e := obsOne(t)
		e.Schema = laterMinor()
		d := e.Health.Details
		d["reason.added-later"], d["first_seq.added-later"], d["last_seq.added-later"], d["count"] = "2", "4", "5", "5"
		mut(d)
		if e.Validate() == nil {
			t.Errorf("at %s, %s: accepted", laterMinor(), name)
		}
	}

	// A later minor's cause, with the known keys still checked.
	b := baselineOne(t)
	b.Schema = laterMinor()
	b.Health.Details["cause"] = "added-later"
	if err := b.Validate(); err != nil {
		t.Errorf("a later minor's cause: %v", err)
	}
	// Above self, cause is still a token (D3's N3 on #772, D4-121).
	b.Health.Details["cause"] = "any text\r\n<13>forged"
	if got, want := refusal(b.Validate()), refusalOf(CodeEnum, "cause"); !slices.Equal(got, want) {
		t.Errorf("at %s, a cause that is not a token: %v, want %v", laterMinor(), got, want)
	}
	b.Health.Details["cause"] = "added-later"
	b.Health.Details["hash"] = "sha256:x"
	if !slices.Contains(Codes(b.Validate()), CodeEnum) {
		t.Errorf("at %s, a malformed hash: accepted", laterMinor())
	}
	b = baselineOne(t)
	b.Schema = laterMinor()
	b.Health.Details["schema"], b.Health.Details["cause"] = "unreadable", "later-minor"
	if b.Validate() == nil {
		t.Errorf("at %s, later-minor with unreadable: accepted", laterMinor())
	}
}

// E6-5's contract part: every event this code builds is stamped 0.6, and
// this reader reads 0.6 strictly and a later minor forward. Replaces
// TestIdentifier05 (proposal §6, "Tests that change").
func TestIdentifier06(t *testing.T) {
	if Identifier != "otsec.event/0.6" || self.Minor != 6 {
		t.Fatalf("Identifier %s, self minor %d", Identifier, self.Minor)
	}
	if v, err := version.Parse(Identifier); err != nil || v != self {
		t.Fatalf("Identifier %s is not self %s: %v", Identifier, self, err)
	}
	e := counters05(t)
	e.Schema = selfMinor()
	e.Health.Details["note"] = "x"
	if !slices.Contains(Codes(e.Validate()), CodeEnum) {
		t.Errorf("an unknown detail at %s: accepted", selfMinor())
	}
	e.Schema = laterMinor()
	if err := e.Validate(); err != nil {
		t.Errorf("an unknown detail at %s: %v", laterMinor(), err)
	}
	// Decode reads 0.6 strictly: an unknown top-level field is refused at
	// 0.6 and passed over one minor later.
	b, err := os.ReadFile(folded05)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	m["added_later"] = "x"
	for schema, want := range map[string]Code{selfMinor(): CodeDecode, laterMinor(): ""} {
		m["schema"] = schema
		raw, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		_, err = Decode(raw)
		if got := Codes(err); (want == "" && err != nil) || (want != "" && !slices.Contains(got, want)) {
			t.Errorf("Decode at %s with an unknown field: %v, want %q", schema, err, want)
		}
	}
}
