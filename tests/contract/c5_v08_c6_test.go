package contract

import (
	"slices"
	"testing"

	"otsec.local/otsec/contracts/store"
)

// C5 0.8 (D4-53; docs/phase4/C5-c5-0.8.md sections 2 and 7), C6's contract
// tests. Evidence class: desk.

// c5v8Pairs is the closed table, written here from the approved text rather
// than read from the package: five 0.7 pairs and four 0.8 pairs.
var c5v8Pairs = map[[2]string]bool{
	{"evidence", "config.snapshot"}:               true,
	{"evidence", "config.difference"}:             true,
	{"evidence", "baseline.event"}:                true,
	{"working-state", "eventcheckpoint.learner"}:  true,
	{"working-state", "eventcheckpoint.detector"}: true,
	{"evidence", "identity"}:                      true,
	{"evidence", "finding"}:                       true,
	{"evidence", "advisory.set"}:                  true,
	{"working-state", "identity.read"}:            true,
}

// TestC5v08KindSeriesProduct: every kind against every series, known and
// near-miss; exactly the nine pairs pass.
func TestC5v08KindSeriesProduct(t *testing.T) {
	kinds := []string{"evidence", "working-state", "", "Evidence", "working_state", "state"}
	series := []string{
		"config.snapshot", "config.difference", "baseline.event", "eventcheckpoint.learner", "eventcheckpoint.detector",
		"identity", "finding", "advisory.set", "identity.read",
		"", "identity.reads", "Identity", "advisory", "advisory.sets", "findings", "identity.", ".read", "baseline.configuration",
	}
	passed := 0
	for _, k := range kinds {
		for _, s := range series {
			err := store.DocumentInfo{Kind: store.DocumentKind(k), Series: s}.Validate()
			want := c5v8Pairs[[2]string{k, s}]
			if (err == nil) != want {
				t.Errorf("(%q, %q): %v, want pass %v", k, s, err, want)
			}
			if err == nil {
				passed++
			}
		}
	}
	if passed != len(c5v8Pairs) {
		t.Errorf("%d pairs pass, want %d", passed, len(c5v8Pairs))
	}
}

// TestC5v08RemovableSeries: the four removable series of 0.8 (and since 0.9
// the two network checkpoints and the intake hold), the item 3 evidence series never among them,
// and a fresh slice on each call.
func TestC5v08RemovableSeries(t *testing.T) {
	got := store.RemovableSeries()
	want := []string{"config.snapshot", "eventcheckpoint.learner", "eventcheckpoint.detector", "identity.read",
		"netcheckpoint.learner", "netcheckpoint.detector", "netcheckpoint.intake"}
	if !slices.Equal(slices.Sorted(slices.Values(got)), slices.Sorted(slices.Values(want))) {
		t.Fatalf("RemovableSeries %v, want %v", got, want)
	}
	for _, s := range []string{"identity", "finding", "advisory.set", "config.difference", "baseline.event"} {
		if slices.Contains(got, s) {
			t.Errorf("%s is removable", s)
		}
		for _, stream := range []store.StreamID{"config/relay1", "advisory"} {
			if err := store.CheckRemoveConfig(stream, s, []store.Seq{1}); err == nil {
				t.Errorf("CheckRemoveConfig(%s, %s) passed", stream, s)
			}
		}
	}
	got[0] = "identity"
	if again := store.RemovableSeries(); slices.Contains(again, "identity") {
		t.Errorf("RemovableSeries shares its slice: %v", again)
	}
}
