package store

import (
	"slices"
	"testing"
)

// C5 0.7 (D4-20, D4-32, D4-39; docs/phase4/C5-c5-0.7.md section 5).
// Evidence class: desk.

func TestHoldCodesV07(t *testing.T) {
	if HoldApprovedDifference != "approved-difference" || HoldSupersededBaseline != "superseded-baseline" {
		t.Fatalf("codes %q %q", HoldApprovedDifference, HoldSupersededBaseline)
	}
	for _, c := range []HoldCode{HoldApprovedDifference, HoldSupersededBaseline} {
		if err := (HoldReason{Code: c, Ref: auditRef}).Validate(); err != nil {
			t.Errorf("%s: %v", c, err)
		}
		if err := (HoldReason{Code: c}).Validate(); !isCode(err, CodeInvalid) {
			t.Errorf("%s with no C8 record: %v", c, err)
		}
	}
}

// HoldPriority is the closed set, each code once, in the ruled order, and
// Validate accepts exactly its codes: a code added to the set without a
// priority is refused by Validate.
func TestHoldPriority(t *testing.T) {
	want := []HoldCode{"baseline", "unapproved-difference", "approved-difference",
		"acknowledged-difference", "restored-difference", "superseded-baseline"}
	got := HoldPriority()
	if !slices.Equal(got, want) {
		t.Fatalf("HoldPriority %v, want %v", got, want)
	}
	for _, c := range got {
		if err := (HoldReason{Code: c, Ref: auditRef}).Validate(); err != nil {
			t.Errorf("%s: %v", c, err)
		}
	}
	got[0] = "changed"
	if HoldPriority()[0] != HoldBaseline {
		t.Error("a caller changed the order")
	}
	for _, c := range []HoldCode{"", "approved", "superseded", "Baseline"} {
		if err := (HoldReason{Code: c, Ref: auditRef}).Validate(); !isCode(err, CodeInvalid) {
			t.Errorf("%q outside the set: %v", c, err)
		}
	}
}

// Every kind-by-series pair: the nine in the table (five since 0.7, four
// since 0.8) pass and the other nine are refused, as are an empty series,
// baseline.configuration and an unknown kind.
func TestDocumentInfo(t *testing.T) {
	evidence := []string{"config.snapshot", "config.difference", "baseline.event", "identity", "finding", "advisory.set"}
	working := []string{"eventcheckpoint.learner", "eventcheckpoint.detector", "identity.read"}
	for _, s := range append(slices.Clone(evidence), working...) {
		for _, k := range []DocumentKind{"evidence", "working-state"} {
			err := DocumentInfo{Kind: k, Series: s}.Validate()
			if ok := (k == "evidence") == slices.Contains(evidence, s); ok != (err == nil) {
				t.Errorf("%s %s: %v", k, s, err)
			} else if err != nil && !isCode(err, CodeInvalid) {
				t.Errorf("%s %s: %v, want CodeInvalid", k, s, err)
			}
		}
	}
	for _, i := range []DocumentInfo{
		{Kind: DocumentEvidence},
		{Kind: DocumentWorkingState},
		{Kind: DocumentEvidence, Series: "baseline.configuration"},
		{Kind: "state", Series: SeriesCheckpointLearner},
		{Series: SeriesConfigSnapshot},
	} {
		if err := i.Validate(); !isCode(err, CodeInvalid) {
			t.Errorf("%+v: %v", i, err)
		}
	}
}

func TestRemovableSeries(t *testing.T) {
	got := RemovableSeries()
	if !slices.Equal(got, []string{"config.snapshot", "eventcheckpoint.learner", "eventcheckpoint.detector", "identity.read"}) {
		t.Fatalf("RemovableSeries %v", got)
	}
	got[0] = SeriesConfigDifference
	if RemovableSeries()[0] != SeriesConfigSnapshot {
		t.Error("a caller changed the set")
	}
}

func TestCheckRemoveConfig(t *testing.T) {
	const s StreamID = "config/relay1"
	step := make([]Seq, RemoveConfigStep)
	for i := range step {
		step[i] = Seq(i + 1)
	}
	cases := []struct {
		name   string
		stream StreamID
		series string
		seqs   []Seq
		ok     bool
	}{
		{"a full step", s, SeriesConfigSnapshot, step, true},
		{"one learner checkpoint", s, SeriesCheckpointLearner, []Seq{7}, true},
		{"one detector checkpoint", s, SeriesCheckpointDetector, []Seq{7}, true},
		{"over a step", s, SeriesConfigSnapshot, append(slices.Clone(step), Seq(RemoveConfigStep+1)), false},
		{"no seqs", s, SeriesConfigSnapshot, nil, false},
		{"seq 0", s, SeriesConfigSnapshot, []Seq{3, 0}, false},
		{"a repeated seq", s, SeriesConfigSnapshot, []Seq{3, 4, 3}, false},
		{"not a stream token", "config/relay 1", SeriesConfigSnapshot, []Seq{1}, false},
		{"no stream", "", SeriesConfigSnapshot, []Seq{1}, false},
		{"a difference", s, SeriesConfigDifference, []Seq{1}, false},
		{"an event baseline", s, SeriesBaselineEvent, []Seq{1}, false},
		{"a configuration baseline", s, "baseline.configuration", []Seq{1}, false},
		{"no series", s, "", []Seq{1}, false},
	}
	for _, c := range cases {
		err := CheckRemoveConfig(c.stream, c.series, c.seqs)
		if c.ok != (err == nil) || (err != nil && !isCode(err, CodeInvalid)) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}
