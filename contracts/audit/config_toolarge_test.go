package audit

import (
	"testing"
)

// tooLarge makes r, a config.change_detected, the record of a difference
// over C9's MaxDifferenceBytes: no difference_digest, and difference_too_large
// (0.10, D4-42).
func tooLarge(r *Record) *Record {
	c := *r.Config
	c.DifferenceDigest, c.DifferenceTooLarge = "", true
	copied := *r
	copied.Config = &c
	return &copied
}

func TestDifferenceTooLargeFields(t *testing.T) {
	approved := tooLarge(configChain()[3])
	unapproved := tooLarge(configChain()[3])
	unapproved.Outcome, unapproved.ReasonCode, unapproved.Config.ApprovalSeq = OutcomeWarning, ReasonUnapprovedChange, 0
	for name, r := range map[string]*Record{"approved": approved, "unapproved": unapproved} {
		if err := r.Validate(); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, mut := range map[string]func(r *Record){
		"with a difference_digest": func(r *Record) { r.Config.DifferenceDigest = testDifference },
		"stamped 0.9":              func(r *Record) { r.Contract = "otsec.audit/0.9" },
		"stamped 0.7":              func(r *Record) { r.Contract = "otsec.audit/0.7" },
		"without changes_digest":   func(r *Record) { r.Config.ChangesDigest = "" },
		"neither":                  func(r *Record) { r.Config.DifferenceTooLarge = false },
	} {
		for _, base := range []*Record{approved, unapproved} {
			r := *base
			c := *base.Config
			r.Config = &c
			mut(&r)
			if err := r.Validate(); err == nil {
				t.Errorf("%s (%s): accepted", name, r.ReasonCode)
			}
		}
	}
	// Without it, difference_digest is required, and in its sha256 form.
	stored := configChain()[3]
	stored.Config.DifferenceDigest = testDifference[len("sha256:"):]
	if err := stored.Validate(); err == nil {
		t.Error("a bare-hex difference_digest accepted")
	}
	// difference_too_large belongs on config.change_detected and nowhere
	// else.
	for _, r := range []*Record{
		configChain()[1],
		comparedNoDifference(14, 8, "2026-10-26T15:00:05Z", 41),
		comparedSameChange(25, 12, "2026-10-26T19:00:05Z", testReadA, 43),
		restoreRec(),
		readsChain()[len(readsChain())-1],
		recordedRec(5, "event", testEventV1, "", 1),
		learnerNotRestored(5, 1, ""),
	} {
		c := *r.Config
		c.DifferenceTooLarge = true
		copied := *r
		copied.Config = &c
		if err := copied.Validate(); err == nil {
			t.Errorf("difference_too_large accepted on %s", r.Action)
		}
	}
}

// restoreRec is a valid config.baseline_restored of testAsset.
func restoreRec() *Record {
	return nodeRec(31, "2026-10-26T21:00:05Z", ActionConfigBaselineRestored, "", Config{BaselineDigest: testBaseline, SnapshotDigest: testEqual, ReadSeq: 15})
}

// A detection whose difference was too large stands in the chain as any
// other: the reads that find the same change name it by change_seq and
// changes_digest, which it still carries. VerifyConfig reads no stored
// document, so nothing in the chain refers to difference_digest.
func TestDifferenceTooLargeInAChain(t *testing.T) {
	recs := readsChain()
	for i, r := range recs {
		if r.Action == ActionConfigChangeDetected {
			recs[i] = tooLarge(r)
		}
	}
	if err := restoreRec().Validate(); err != nil {
		t.Fatalf("restoreRec: %v", err)
	}
	for _, r := range recs {
		if err := r.Validate(); err != nil {
			t.Fatalf("record %d (%s): %v", r.Seq, r.Action, err)
		}
	}
	if err := VerifyConfig(recs); err != nil {
		t.Fatal(err)
	}
	for i, r := range recs {
		if err := VerifyConfigFrom(recs[i:], r.Seq); err != nil {
			t.Errorf("from %d: %v", r.Seq, err)
		}
	}
}
