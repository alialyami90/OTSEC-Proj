package audit

import (
	"strings"
	"testing"

	"otsec.local/otsec/contracts/authz"
)

// Digests of baseline records in the tests: fixed strings, not of any stored
// document.
var (
	testEventV1 = "sha256:" + strings.Repeat("1", 64)
	testEventV2 = "sha256:" + strings.Repeat("2", 64)
	testEventV3 = "sha256:" + strings.Repeat("3", 64)
)

// recordedRec is the node's config.baseline_recorded on testAsset.
func recordedRec(seq uint64, kind authz.BaselineKind, digest, previous string, version int) *Record {
	return nodeRec(seq, "2026-10-26T14:00:00Z", ActionConfigBaselineRecorded, "",
		Config{Kind: kind, BaselineDigest: digest, PreviousDigest: previous, BaselineVersion: version})
}

func TestBaselineRecordedFields(t *testing.T) {
	good := map[string]*Record{
		"event, first":               recordedRec(5, authz.BaselineEvent, testEventV1, "", 1),
		"event, a re-learn":          recordedRec(5, authz.BaselineEvent, testEventV2, testEventV1, 2),
		"configuration, first":       recordedRec(5, authz.BaselineConfiguration, testBaseline, "", 0),
		"configuration, a successor": recordedRec(5, authz.BaselineConfiguration, testSnapshot, testBaseline, 0),
	}
	for name, r := range good {
		if err := r.Validate(); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	bad := map[string]func(r *Record){
		"stamped 0.7":                  func(r *Record) { r.Contract = "otsec.audit/0.7" },
		"by a person":                  func(r *Record) { r.Actor = adminActor },
		"as a warning":                 func(r *Record) { r.Outcome = OutcomeWarning },
		"with a reason code":           func(r *Record) { r.ReasonCode = "relearn" },
		"without config":               func(r *Record) { r.Config = nil },
		"without a target":             func(r *Record) { r.Target = nil },
		"without a correlation id":     func(r *Record) { r.CorrelationID = "" },
		"without a kind":               func(r *Record) { r.Config.Kind = "" },
		"of an unknown kind":           func(r *Record) { r.Config.Kind = "settings" },
		"without a digest":             func(r *Record) { r.Config.BaselineDigest = "" },
		"digest bare hex":              func(r *Record) { r.Config.BaselineDigest = testEventV1[7:] },
		"version 0":                    func(r *Record) { r.Config.BaselineVersion = 0 },
		"version 0 with a previous":    func(r *Record) { r.Config.BaselineVersion, r.Config.PreviousDigest = 0, testEventV2 },
		"version 1 with a previous":    func(r *Record) { r.Config.PreviousDigest = testEventV2 },
		"version 2 without a previous": func(r *Record) { r.Config.BaselineVersion, r.Config.PreviousDigest = 2, "" },
		"replacing itself":             func(r *Record) { r.Config.BaselineVersion, r.Config.PreviousDigest = 2, r.Config.BaselineDigest },
		"previous bare hex":            func(r *Record) { r.Config.BaselineVersion, r.Config.PreviousDigest = 2, testEventV2[7:] },
		"negative version":             func(r *Record) { r.Config.BaselineVersion = -1 },
		"a version on a configuration": func(r *Record) { r.Config.Kind, r.Config.BaselineVersion = authz.BaselineConfiguration, 1 },
		"with a decision":              func(r *Record) { r.Config.DecisionSeq = 10 },
		"with a payload hash":          func(r *Record) { r.Config.PayloadSHA256 = strings.Repeat("a", 64) },
		"with a window":                func(r *Record) { r.Config.WindowStart = "2026-10-26T16:00:00Z" },
		"with a reason":                func(r *Record) { r.Config.Reason = "relearn" },
		"with a snapshot":              func(r *Record) { r.Config.SnapshotDigest = testSnapshot },
		"with a difference":            func(r *Record) { r.Config.DifferenceDigest = testDifference },
		"with a read":                  func(r *Record) { r.Config.ReadSeq = 11 },
		"with an unchanged time":       func(r *Record) { r.Config.UnchangedAt = "2026-10-26T15:00:00Z" },
		"with an unchanged read":       func(r *Record) { r.Config.UnchangedReadSeq = 8 },
		"with an approval":             func(r *Record) { r.Config.ApprovalSeq = 10 },
		"with changes":                 func(r *Record) { r.Config.ChangesDigest = testChanges },
		"with a change seq":            func(r *Record) { r.Config.ChangeSeq = 23 },
		"with a snapshot seq":          func(r *Record) { r.Config.SnapshotSeq = 41 },
		"with a removal":               func(r *Record) { r.Config.RemovedCount = 2 },
		"with a kept digest":           func(r *Record) { r.Config.KeptDigest = testSnapshot },
	}
	for name, mut := range bad {
		r := recordedRec(5, authz.BaselineEvent, testEventV1, "", 1)
		mut(r)
		if err := r.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// baseline_version belongs here and nowhere else.
	for _, r := range []*Record{
		comparedNoDifference(14, 8, "2026-10-26T15:00:05Z", 41),
		configChain()[3],
		configChain()[1],
	} {
		r.Config.BaselineVersion = 1
		if err := r.Validate(); err == nil {
			t.Errorf("baseline_version accepted on %s", r.Action)
		}
	}
}

// The chain of recorded baselines of one asset and kind: each names the one
// before it, and an event baseline's version rises by one.
func TestBaselineRecordedSuccession(t *testing.T) {
	event := func(seq uint64, digest, previous string, version int) *Record {
		return recordedRec(seq, authz.BaselineEvent, digest, previous, version)
	}
	cfg := func(seq uint64, digest, previous string) *Record {
		return recordedRec(seq, authz.BaselineConfiguration, digest, previous, 0)
	}
	other := func(r *Record) *Record {
		c := *r
		t := *r.Target
		t.AssetID = "9c1d2e3f-4a5b-4c6d-8e7f-9a0b1c2d3e4f"
		c.Target = &t
		return &c
	}
	ok := map[string][]*Record{
		"nothing recorded":         nil,
		"one":                      {event(1, testEventV1, "", 1)},
		"a re-learn":               {event(1, testEventV1, "", 1), event(2, testEventV2, testEventV1, 2), event(3, testEventV3, testEventV2, 3)},
		"a window after the first": {event(1, testEventV2, testEventV1, 2), event(2, testEventV3, testEventV2, 3)},
		"two kinds are separate":   {event(1, testEventV1, "", 1), cfg(2, testBaseline, ""), event(3, testEventV2, testEventV1, 2), cfg(4, testSnapshot, testBaseline)},
		"two assets are separate":  {event(1, testEventV1, "", 1), other(event(2, testEventV1, "", 1)), event(3, testEventV2, testEventV1, 2)},
	}
	for name, recs := range ok {
		if err := VerifyConfig(recs); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	bad := map[string][]*Record{
		"a skipped baseline":                      {event(1, testEventV1, "", 1), event(2, testEventV3, testEventV2, 2)},
		"a skipped version":                       {event(1, testEventV1, "", 1), event(2, testEventV2, testEventV1, 3)},
		"a version that repeats":                  {event(1, testEventV1, "", 1), event(2, testEventV2, testEventV1, 1)},
		"a first after a first":                   {event(1, testEventV1, "", 1), event(2, testEventV2, "", 1)},
		"an older baseline again":                 {event(1, testEventV1, "", 1), event(2, testEventV2, testEventV1, 2), event(3, testEventV1, testEventV1, 3)},
		"a configuration that skips":              {cfg(1, testBaseline, ""), cfg(2, testEqual, testSnapshot)},
		"a configuration without one it replaces": {cfg(1, testBaseline, ""), cfg(2, testSnapshot, "")},
	}
	for name, recs := range bad {
		if err := VerifyConfig(recs); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// The recorded baselines do not disturb the other checks: a chain of the 0.7
// records with a baseline recorded in the middle still verifies.
func TestBaselineRecordedInAChain(t *testing.T) {
	chain := readsChain()
	chain = append([]*Record{recordedRec(1, authz.BaselineEvent, testEventV1, "", 1)}, chain...)
	chain = append(chain, recordedRec(99, authz.BaselineEvent, testEventV2, testEventV1, 2))
	if err := VerifyConfig(chain); err != nil {
		t.Fatal(err)
	}
}
