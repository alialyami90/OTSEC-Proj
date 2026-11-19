package event

import (
	"os"
	"slices"
	"strings"
	"testing"
)

// folded05 is the E5-3 fixture: a folded 0.5 sensor.counters event with
// runs_folded, diff.packets, a 0.4 capture counter that rose and its
// capture_loss (docs/phase4/D4-c4-0.5-proposal.md §5).
const folded05 = "testdata/valid/health-sensor-counters-folded.json"

// E5-3: an earlier reader accepts a folded 0.5 event, so 0.5 needs no
// reader floor. This test was committed with the fixture before the 0.5
// code, and passed there against the C4 0.4 code of main at 067d2a62.
//
// The 0.3 leg is a one-time desk run, not repeated in CI: the repository
// at c9d4d6c8 (C4 0.3, #566; Identifier otsec.event/0.3, self minor 3),
// exported by git archive into a scratch directory, with this fixture
// copied to its contracts/event/testdata and a test, TestD4C405OldReader,
// that runs Decode and then Validate on it and fails on either error. Run
// on the owner's PC (Go 1.27.3, windows/amd64) on 2026-11-19 with
// "go test ./contracts/event -run TestD4C405OldReader -v -count=1":
//
//	=== RUN   TestD4C405OldReader
//	--- PASS: TestD4C405OldReader (0.01s)
//	PASS
//	ok  	otsec.local/otsec/contracts/event	0.538s
//
// Evidence class desk.
func TestCounters05OldReader(t *testing.T) {
	b, err := os.ReadFile(folded05)
	if err != nil {
		t.Fatal(err)
	}
	e, err := Decode(b)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if err := e.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if e.Health.Details["runs_folded"] != "2" || e.Health.Details[DetailCaptureLoss] != "drops_holder" {
		t.Fatalf("fixture details changed: %v", e.Health.Details)
	}
}

// counters05 is the 0.3 sensor.counters golden restamped 0.5: one run,
// with diff.packets and no capture loss.
func counters05(t *testing.T) *Event {
	e := load(t, "testdata/valid/health-sensor-counters.json")
	e.Schema = "otsec.event/0.5"
	return e
}

// E5-1 (C4-0.5-1): runs_folded is a decimal from 1 to 2^64 - 1 with no
// leading zero; any other form is refused as enum.
func TestCounters05RunsFoldedForm(t *testing.T) {
	for _, ok := range []string{"1", "2", "18446744073709551615"} {
		e := counters05(t)
		e.Health.Details[DetailRunsFolded] = ok
		if err := e.Validate(); err != nil {
			t.Errorf("runs_folded %q: %v", ok, err)
		}
	}
	for _, bad := range []string{"0", "01", "-1", "+1", "1.0", "", " 1", "0x1", "1e3",
		"18446744073709551616", "99999999999999999999", "100000000000000000000"} {
		e := counters05(t)
		e.Health.Details[DetailRunsFolded] = bad
		if got := Codes(e.Validate()); !slices.Equal(got, []Code{CodeEnum}) {
			t.Errorf("runs_folded %q: %v, want [enum]", bad, got)
		}
	}
	// The fixture without runs_folded reads as one run and is accepted:
	// its absence is not checked here (the writer's rule, E5-5).
	if err := counters05(t).Validate(); err != nil {
		t.Errorf("0.5 without runs_folded: %v", err)
	}
}

// E5-2 (C4-0.5-1): runs_folded is refused on an event of 0.4 or earlier,
// and it is not a counter, so diff.runs_folded and total.runs_folded are
// refused at 0.5.
func TestCounters05RunsFoldedPlace(t *testing.T) {
	for _, schema := range []string{"otsec.event/0.3", "otsec.event/0.4"} {
		e := counters05(t)
		e.Schema = schema
		e.Health.Details[DetailRunsFolded] = "1"
		err := e.Validate()
		want := "not a detail of sensor.counters in " + schema
		if !slices.Contains(Codes(err), CodeEnum) || err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("runs_folded at %s: %v, want enum %q", schema, err, want)
		}
	}
	for _, k := range []string{"diff.runs_folded", "total.runs_folded"} {
		e := counters05(t)
		e.Health.Details[DetailRunsFolded] = "1"
		e.Health.Details[k] = "1"
		err := e.Validate()
		if !slices.Equal(Codes(err), []Code{CodeEnum}) || !strings.Contains(err.Error(), "not a detail of sensor.counters in otsec.event/0.5") {
			t.Errorf("%s at 0.5: %v, want enum, not a detail", k, err)
		}
	}
}

// E5-4 (C4-0.5-2): in a folded event, capture_loss follows C4-0.4-2 on the
// summed values, and diff.packets is still required (C4-0.4-3).
func TestCounters05FoldedCaptureLoss(t *testing.T) {
	folded := func() *Event {
		e := load(t, folded05)
		if e.Health.Details[DetailRunsFolded] == "" {
			t.Fatal("fixture is not folded")
		}
		return e
	}
	if err := folded().Validate(); err != nil {
		t.Fatalf("folded fixture: %v", err)
	}
	cases := []struct {
		name string
		mut  func(d map[string]string)
		want Code
	}{
		{"holder rose, capture_loss absent", func(d map[string]string) { delete(d, DetailCaptureLoss) }, CodeMissing},
		{"capture_loss names a counter at 0", func(d map[string]string) { d["diff.drops_holder"] = "0" }, CodeEnum},
		{"capture_loss names one not carried", func(d map[string]string) { d[DetailCaptureLoss] = "drops_driver drops_holder" }, CodeEnum},
		{"a second counter rose, not named", func(d map[string]string) { d["diff.frames_overlong"] = "1" }, CodeEnum},
		{"diff.packets absent", func(d map[string]string) { delete(d, "diff.packets") }, CodeMissing},
	}
	for _, tc := range cases {
		e := folded()
		tc.mut(e.Health.Details)
		if got := Codes(e.Validate()); !slices.Equal(got, []Code{tc.want}) {
			t.Errorf("%s: %v, want [%s]", tc.name, got, tc.want)
		}
	}
}

// E5-8's contract-level part (C4-0.5-3): a folded event holding a sum at
// the maximum, with the counter named in capture_loss and runs_folded at
// its own maximum, is accepted; one above the maximum is refused. The
// wrapped sum that plain uint64 addition gives (0, with no capture_loss) is
// also accepted, which is why wrapping is the writer's rule, tested on the
// node (E5-8, D5): the validator cannot tell it from a run with no loss.
func TestCounters05Saturated(t *testing.T) {
	e := load(t, folded05)
	e.Health.Details["diff.drops_holder"] = "18446744073709551615"
	e.Health.Details[DetailRunsFolded] = "18446744073709551615"
	if err := e.Validate(); err != nil {
		t.Errorf("held at the maximum: %v", err)
	}
	e.Health.Details["diff.drops_holder"] = "18446744073709551616"
	if got := Codes(e.Validate()); !slices.Contains(got, CodeEnum) {
		t.Errorf("diff.drops_holder above the maximum: %v, want enum", got)
	}
	e = load(t, folded05)
	e.Health.Details["diff.drops_holder"] = "0"
	delete(e.Health.Details, DetailCaptureLoss)
	if err := e.Validate(); err != nil {
		t.Errorf("the wrapped form: %v (the validator was expected to accept it)", err)
	}
}

// Every event this code builds is stamped 0.5, and this reader reads 0.5
// strictly and a later minor forward (E5-7's contract leg, as E4-7's).
func TestIdentifier05(t *testing.T) {
	if Identifier != "otsec.event/0.5" || self.Minor != 5 {
		t.Fatalf("Identifier %s, self minor %d", Identifier, self.Minor)
	}
	e := counters05(t)
	e.Health.Details["note"] = "x"
	if !slices.Contains(Codes(e.Validate()), CodeEnum) {
		t.Error("an unknown detail at 0.5: accepted")
	}
	e.Schema = "otsec.event/0.6"
	if err := e.Validate(); err != nil {
		t.Errorf("an unknown detail at 0.6: %v", err)
	}
}
