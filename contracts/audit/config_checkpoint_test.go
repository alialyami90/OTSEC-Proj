package audit

import (
	"strings"
	"testing"

	"otsec.local/otsec/contracts/authz"
)

// notRestoredRec is the node's config.checkpoint_not_restored on testAsset,
// with the correlation_id CheckpointCorrelationID gives (0.9, D4-40 item 6).
func notRestoredRec(seq uint64, reason, half string, checkpoint uint64, cfg Config) *Record {
	cfg.Kind, cfg.CheckpointHalf, cfg.CheckpointSeq = authz.BaselineEvent, half, checkpoint
	r := nodeRec(seq, "2026-10-26T16:00:00Z", ActionConfigCheckpointNotRestored, reason, cfg)
	r.Outcome = OutcomeWarning
	r.CorrelationID = CheckpointCorrelationID(half, checkpoint)
	return r
}

func learnerNotRestored(seq uint64, version int, previous string) *Record {
	return notRestoredRec(seq, ReasonCheckpointCorrupt, CheckpointLearner, 17, Config{BaselineVersion: version, PreviousDigest: previous})
}

func detectorNotRestored(seq uint64, baseline string) *Record {
	return notRestoredRec(seq, ReasonCheckpointMismatch, CheckpointDetector, 18, Config{BaselineDigest: baseline})
}

func TestCheckpointNotRestoredFields(t *testing.T) {
	good := map[string]*Record{
		"a learner's first":    learnerNotRestored(5, 1, ""),
		"a learner's re-learn": learnerNotRestored(5, 3, testEventV2),
		"a detector":           detectorNotRestored(5, testEventV2),
	}
	for _, reason := range []string{ReasonCheckpointCorrupt, ReasonCheckpointVersion, ReasonCheckpointMismatch, ReasonCheckpointRefused} {
		good["reason "+reason] = notRestoredRec(5, reason, CheckpointLearner, 17, Config{BaselineVersion: 1})
	}
	for name, r := range good {
		if err := r.Validate(); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	both := map[string]func(r *Record){
		"stamped 0.8":                 func(r *Record) { r.Contract = "otsec.audit/0.8" },
		"by a person":                 func(r *Record) { r.Actor = adminActor },
		"as info":                     func(r *Record) { r.Outcome, r.ReasonCode = OutcomeInfo, "" },
		"as failed":                   func(r *Record) { r.Outcome = OutcomeFailed },
		"without a reason code":       func(r *Record) { r.ReasonCode = "" },
		"an unknown class":            func(r *Record) { r.ReasonCode = "timeout" },
		"without config":              func(r *Record) { r.Config = nil },
		"without a target":            func(r *Record) { r.Target = nil },
		"without a correlation id":    func(r *Record) { r.CorrelationID = "" },
		"a request ID as correlation": func(r *Record) { r.CorrelationID = "6f1c2d3e-4a5b-4c6d-8e7f-9a0b1c2d3e4f" },
		"another seq in correlation":  func(r *Record) { r.CorrelationID = CheckpointCorrelationID(r.Config.CheckpointHalf, 99) },
		"without a kind":              func(r *Record) { r.Config.Kind = "" },
		"a configuration kind":        func(r *Record) { r.Config.Kind = authz.BaselineConfiguration },
		"without a half":              func(r *Record) { r.Config.CheckpointHalf, r.CorrelationID = "", "eventcheckpoint.:17" },
		"an unknown half": func(r *Record) {
			r.Config.CheckpointHalf = "feeder"
			r.CorrelationID = CheckpointCorrelationID("feeder", r.Config.CheckpointSeq)
		},
		"without a checkpoint seq": func(r *Record) {
			r.Config.CheckpointSeq = 0
			r.CorrelationID = CheckpointCorrelationID(r.Config.CheckpointHalf, 0)
		},
		"with a decision":        func(r *Record) { r.Config.DecisionSeq = 10 },
		"with a payload hash":    func(r *Record) { r.Config.PayloadSHA256 = strings.Repeat("a", 64) },
		"with a window":          func(r *Record) { r.Config.WindowStart = "2026-10-26T16:00:00Z" },
		"with a reason":          func(r *Record) { r.Config.Reason = "corrupt" },
		"with a snapshot":        func(r *Record) { r.Config.SnapshotDigest = testSnapshot },
		"with a difference":      func(r *Record) { r.Config.DifferenceDigest = testDifference },
		"with a read":            func(r *Record) { r.Config.ReadSeq = 11 },
		"with an unchanged time": func(r *Record) { r.Config.UnchangedAt = "2026-10-26T15:00:00Z" },
		"with an unchanged read": func(r *Record) { r.Config.UnchangedReadSeq = 8 },
		"with an approval":       func(r *Record) { r.Config.ApprovalSeq = 10 },
		"with changes":           func(r *Record) { r.Config.ChangesDigest = testChanges },
		"with a change seq":      func(r *Record) { r.Config.ChangeSeq = 23 },
		"with a snapshot seq":    func(r *Record) { r.Config.SnapshotSeq = 41 },
		"with a removal":         func(r *Record) { r.Config.RemovedCount = 2 },
		"with a kept digest":     func(r *Record) { r.Config.KeptDigest = testSnapshot },
	}
	learner := map[string]func(r *Record){
		"a learner with a baseline":       func(r *Record) { r.Config.BaselineDigest = testEventV1 },
		"a learner at version 0":          func(r *Record) { r.Config.BaselineVersion = 0 },
		"a learner at a negative version": func(r *Record) { r.Config.BaselineVersion = -1 },
		"version 1 with a previous":       func(r *Record) { r.Config.PreviousDigest = testEventV2 },
		"version 2 without a previous":    func(r *Record) { r.Config.BaselineVersion = 2 },
		"previous bare hex":               func(r *Record) { r.Config.BaselineVersion, r.Config.PreviousDigest = 2, testEventV2[7:] },
	}
	detector := map[string]func(r *Record){
		"a detector without a baseline":    func(r *Record) { r.Config.BaselineDigest = "" },
		"a detector's baseline bare hex":   func(r *Record) { r.Config.BaselineDigest = testEventV2[7:] },
		"a detector with a version":        func(r *Record) { r.Config.BaselineVersion = 2 },
		"a detector with a previous":       func(r *Record) { r.Config.PreviousDigest = testEventV1 },
		"a detector with the learner's id": func(r *Record) { r.CorrelationID = CheckpointCorrelationID(CheckpointLearner, 18) },
	}
	try := func(make func() *Record, muts map[string]func(*Record)) {
		for name, mut := range muts {
			r := make()
			mut(r)
			if err := r.Validate(); err == nil {
				t.Errorf("%s (%s): accepted", name, r.Config.CheckpointHalf)
			}
		}
	}
	try(func() *Record { return learnerNotRestored(5, 1, "") }, both)
	try(func() *Record { return detectorNotRestored(5, testEventV2) }, both)
	try(func() *Record { return learnerNotRestored(5, 1, "") }, learner)
	try(func() *Record { return detectorNotRestored(5, testEventV2) }, detector)

	// checkpoint_half and checkpoint_seq belong here and nowhere else.
	for _, r := range []*Record{
		recordedRec(5, authz.BaselineEvent, testEventV1, "", 1),
		comparedNoDifference(14, 8, "2026-10-26T15:00:05Z", 41),
		configChain()[3],
		configChain()[1],
	} {
		for name, set := range map[string]func(c *Config){
			"checkpoint_half": func(c *Config) { c.CheckpointHalf = CheckpointLearner },
			"checkpoint_seq":  func(c *Config) { c.CheckpointSeq = 17 },
		} {
			c := *r.Config
			set(&c)
			copied := *r
			copied.Config = &c
			if err := copied.Validate(); err == nil {
				t.Errorf("%s accepted on %s", name, r.Action)
			}
		}
	}
}

// In a chain: a learner's re-learn records the version after the latest
// recorded one, replacing it, and a detector is rebuilt from the asset's
// acknowledged event baseline. recs may start partway through the chain, so
// with no recording before it, a learner is held to version 1 only when recs
// holds the asset's version-1 recording, and a detector is held to nothing
// with no acknowledgement before it.
func TestCheckpointNotRestoredInAChain(t *testing.T) {
	const other = "9c1d2e3f-4a5b-4c6d-8e7f-9a0b1c2d3e4f"
	join := func(parts ...[]*Record) []*Record {
		var out []*Record
		for _, p := range parts {
			out = append(out, p...)
		}
		return out
	}
	rec := func(r ...*Record) []*Record { return r }
	v1 := recordedRec(1, authz.BaselineEvent, testEventV1, "", 1)
	v2 := recordedRec(2, authz.BaselineEvent, testEventV2, testEventV1, 2)
	otherV1 := recordedRec(3, authz.BaselineEvent, testEventV1, "", 1)
	otherV1.Target = &Target{AssetID: other}
	onOther := func(r *Record) *Record {
		r.Target = &Target{AssetID: other}
		return r
	}

	ok := map[string][]*Record{
		"a learner's first, then recorded":     join(rec(learnerNotRestored(1, 1, ""), v1)),
		"a re-learn after the first":           join(rec(v1, learnerNotRestored(5, 2, testEventV1))),
		"a re-learn after two":                 join(rec(v1, v2, learnerNotRestored(5, 3, testEventV2))),
		"twice, then recorded":                 join(rec(v1, learnerNotRestored(5, 2, testEventV1), learnerNotRestored(6, 2, testEventV1), v2)),
		"each asset's own recordings":          join(rec(v1, v2, otherV1, onOther(learnerNotRestored(5, 2, testEventV1)))),
		"a detector after the acknowledgement": join(rec(v1), ack08(testAsset, 30, testEventV1, "", OutcomeSucceeded), rec(detectorNotRestored(90, testEventV1))),
		"a detector after a denied acknowledgement": join(rec(v1), ack08(testAsset, 30, testEventV1, "", OutcomeSucceeded),
			rec(v2), ack08(testAsset, 31, testEventV2, testEventV1, OutcomeDenied), rec(detectorNotRestored(90, testEventV1))),
		"a detector after a re-acknowledgement": join(rec(v1), ack08(testAsset, 30, testEventV1, "", OutcomeSucceeded),
			rec(v2), ack08(testAsset, 31, testEventV2, testEventV1, OutcomeSucceeded), rec(detectorNotRestored(90, testEventV2))),
	}
	for name, recs := range ok {
		if err := VerifyConfig(recs); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	bad := map[string][]*Record{
		// In a full chain nothing is before recs, so each names nothing.
		"a detector with no acknowledgement in the chain": join(rec(detectorNotRestored(5, testEventV2))),
		"a detector with only a recording in the chain":   join(rec(v1, detectorNotRestored(5, testEventV1))),
		"a re-learn with no recording in the chain":       join(rec(learnerNotRestored(5, 2, testEventV1))),
		"a re-learn that skips a version":                 join(rec(v1, learnerNotRestored(5, 3, testEventV1))),
		"a re-learn that repeats a version":               join(rec(v1, v2, learnerNotRestored(5, 2, testEventV1))),
		"a re-learn replacing an older one":               join(rec(v1, v2, learnerNotRestored(5, 3, testEventV1))),
		"a first after a recording":                       join(rec(v1, learnerNotRestored(5, 1, ""))),
		"a re-learn before the first":                     join(rec(learnerNotRestored(1, 2, testEventV3), v1)),
		"another asset's recording":                       join(rec(otherV1, learnerNotRestored(5, 2, testEventV1), v1)),
		"a detector of another baseline":                  join(rec(v1), ack08(testAsset, 30, testEventV1, "", OutcomeSucceeded), rec(detectorNotRestored(90, testEventV2))),
		"a detector of a replaced baseline":               join(rec(v1), ack08(testAsset, 30, testEventV1, "", OutcomeSucceeded), rec(v2), ack08(testAsset, 31, testEventV2, testEventV1, OutcomeSucceeded), rec(detectorNotRestored(90, testEventV1))),
		"a detector of a recorded, unacked one":           join(rec(v1), ack08(testAsset, 30, testEventV1, "", OutcomeSucceeded), rec(v2, detectorNotRestored(90, testEventV2))),
	}
	for name, recs := range bad {
		if err := VerifyConfig(recs); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}

	// A view that starts after seq 1 (VerifyConfigFrom from the first
	// record): a recording or acknowledgement may be before it, unless the
	// view holds the asset's version-1 recording (C6 on #387).
	inView := map[string][]*Record{
		"a re-learn after a recording before the view":        join(rec(learnerNotRestored(5, 4, testEventV3))),
		"a detector after an acknowledgement before the view": join(rec(detectorNotRestored(5, testEventV2))),
	}
	for name, recs := range inView {
		if err := VerifyConfigFrom(recs, recs[0].Seq); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	v1At3 := recordedRec(3, authz.BaselineEvent, testEventV1, "", 1)
	notInView := map[string][]*Record{
		"a detector after the view's first recording, with no acknowledgement": join(rec(v1At3, detectorNotRestored(5, testEventV1))),
		"a re-learn before the view's first recording":                         join(rec(learnerNotRestored(2, 2, testEventV3), v1At3)),
	}
	for name, recs := range notInView {
		if err := VerifyConfigFrom(recs, recs[0].Seq); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
