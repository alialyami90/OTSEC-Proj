package audit

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/authz"
)

// Snapshot digests of the compared reads in readsChain: fixed strings, not
// of any stored document.
var (
	testReadA = "sha256:" + strings.Repeat("a", 64)
	testReadB = "sha256:" + strings.Repeat("b", 64)
	testReadC = "sha256:" + strings.Repeat("c", 64)
)

// runAt is a run of the configuration read on testAsset: the collector's
// acceptance of decision, at utc.
func runAt(seq, decision uint64, utc string) *Record {
	r := *configChain()[2]
	target := *r.Target
	r.Target, r.Seq, r.CollectorSeq, r.Time = &target, seq, decision, at(utc)
	r.CorrelationID = fmt.Sprintf("req-20261026-%04d", 100+decision)
	return &r
}

// nodeRec is a configuration record of the node on testAsset.
func nodeRec(seq uint64, utc string, action Action, reason string, cfg Config) *Record {
	return &Record{Contract: ContractID, NodeID: "site-a-node-1", Seq: seq, PrevHash: strings.Repeat("6", 64), Time: at(utc),
		Actor: Actor{Type: authz.PrincipalNode, ID: "site-a-node-1"}, Action: action, Outcome: OutcomeInfo, ReasonCode: reason,
		Target: &Target{AssetID: testAsset}, CorrelationID: "6f1c2d3e-4a5b-4c6d-8e7f-9a0b1c2d3e4f", Config: &cfg}
}

// comparedNoDifference and comparedSameChange are the node's results for read
// decision read, whose snapshot is the record snap of the asset's
// configuration stream.
func comparedNoDifference(seq, read uint64, utc string, snap uint64) *Record {
	return nodeRec(seq, utc, ActionConfigReadCompared, ReasonNoDifference, Config{BaselineDigest: testBaseline, SnapshotDigest: testEqual, ReadSeq: read, SnapshotSeq: snap})
}

func comparedSameChange(seq, read uint64, utc, snapshot string, snap uint64) *Record {
	return nodeRec(seq, utc, ActionConfigReadCompared, ReasonSameChange, Config{BaselineDigest: testBaseline, SnapshotDigest: snapshot,
		ReadSeq: read, SnapshotSeq: snap, ChangeSeq: 23, ChangesDigest: testChanges})
}

// readsChain is a valid chain of the 0.7 read records: the baseline
// acknowledged (decisions 6 and 7), a read (8) that showed no difference, an
// approval (10) and the read (11) that found the approved change (record 23),
// three reads (12, 13 and 14) that found the same change again, and the
// removal of the oldest two of the four compared reads, which leaves the two
// newest.
func readsChain() []*Record {
	chain := configChain()
	since(chain[3], 8, "2026-10-26T15:00:00Z")
	recs := acked(nil)
	recs = append(recs, runAt(13, 8, "2026-10-26T15:00:00Z"), comparedNoDifference(14, 8, "2026-10-26T15:00:05Z", 41))
	recs = append(recs, chain...)
	recs = append(recs,
		runAt(24, 12, "2026-10-26T19:00:00Z"), comparedSameChange(25, 12, "2026-10-26T19:00:05Z", testReadA, 43),
		runAt(26, 13, "2026-10-26T19:30:00Z"), comparedSameChange(27, 13, "2026-10-26T19:30:05Z", testReadB, 45),
		runAt(28, 14, "2026-10-26T19:45:00Z"), comparedSameChange(29, 14, "2026-10-26T19:45:05Z", testReadC, 47),
		nodeRec(30, "2026-10-26T20:00:00Z", ActionConfigReadsRemoved, "", Config{RemovedCount: 2, RemovedFirstSeq: 41, RemovedLastSeq: 43,
			RemovedDigest: RemovedReadsDigest([]string{testEqual, testReadA}), KeptDigest: testReadC}))
	return recs
}

func bySeq(recs []*Record, seq uint64) *Record {
	for _, r := range recs {
		if r.Seq == seq {
			return r
		}
	}
	panic(fmt.Sprintf("no record %d", seq))
}

func TestReadsChainVerifies(t *testing.T) {
	recs := readsChain()
	for _, r := range recs {
		if err := r.Validate(); err != nil {
			t.Fatalf("record %d (%s): %v", r.Seq, r.Action, err)
		}
	}
	if err := VerifyConfig(recs); err != nil {
		t.Fatal(err)
	}
}

// TestReadCompared: a read has one result, compares against the baseline a
// person acknowledged, reports no difference only when no recorded change is
// open, and repeats a change only by naming the newest one and its digest.
func TestReadCompared(t *testing.T) {
	const other = "3c8e5f21-9d4a-4b6c-8f32-8d5a1e7b9c24"
	// restored appends a run (decision 15) whose read was equal to the
	// baseline again, and its config.baseline_restored record.
	restored := func(recs []*Record) []*Record {
		return append(recs, runAt(31, 15, "2026-10-26T20:30:00Z"),
			nodeRec(32, "2026-10-26T20:30:05Z", ActionConfigBaselineRestored, "", Config{BaselineDigest: testBaseline, SnapshotDigest: testEqual, ReadSeq: 15}))
	}
	cases := map[string]struct {
		mut  func(recs []*Record) []*Record
		want string // "" accepts
	}{
		"no difference after a restore": {func(recs []*Record) []*Record {
			return append(restored(recs), runAt(33, 16, "2026-10-26T21:00:00Z"), comparedNoDifference(34, 16, "2026-10-26T21:00:05Z", 49))
		}, ""},
		"a second removal of what was compared since": {func(recs []*Record) []*Record {
			recs = append(restored(recs), runAt(33, 16, "2026-10-26T21:00:00Z"), comparedNoDifference(34, 16, "2026-10-26T21:00:05Z", 49))
			return append(recs, nodeRec(35, "2026-10-26T21:10:00Z", ActionConfigReadsRemoved, "", Config{RemovedCount: 1, RemovedFirstSeq: 45, RemovedLastSeq: 45,
				RemovedDigest: RemovedReadsDigest([]string{testReadB}), KeptDigest: testEqual}))
		}, ""},
		"no difference while a recorded change is open": {func(recs []*Record) []*Record {
			r := bySeq(recs, 25)
			r.ReasonCode, r.Config.SnapshotDigest, r.Config.ChangeSeq, r.Config.ChangesDigest = ReasonNoDifference, testEqual, 0, ""
			return recs
		}, "recorded a change against it"},
		"the same change after a restore": {func(recs []*Record) []*Record {
			return append(restored(recs), runAt(33, 16, "2026-10-26T21:00:00Z"), comparedSameChange(34, 16, "2026-10-26T21:00:05Z", testReadA, 49))
		}, "not the newest recorded change"},
		"the same change as an older record": {func(recs []*Record) []*Record {
			bySeq(recs, 25).Config.ChangeSeq = 22
			return recs
		}, "not the newest recorded change"},
		"the same change with another digest": {func(recs []*Record) []*Record {
			bySeq(recs, 25).Config.ChangesDigest = testOtherChanges
			return recs
		}, "but that change has"},
		"the same change before any was recorded": {func(recs []*Record) []*Record {
			r := bySeq(recs, 14)
			r.ReasonCode, r.Config.SnapshotDigest, r.Config.ChangeSeq, r.Config.ChangesDigest = ReasonSameChange, testReadA, 23, testChanges
			return recs
		}, "not the newest recorded change"},
		"a read with two results": {func(recs []*Record) []*Record {
			r := *bySeq(recs, 25)
			c := *r.Config
			r.Seq, r.Config = 40, &c
			return append(recs, &r)
		}, "second result"},
		"a detection of a read already compared": {func(recs []*Record) []*Record {
			d := *bySeq(recs, 23)
			c := *d.Config
			d.Seq, d.Config, d.Time = 40, &c, at("2026-10-26T19:40:00Z")
			c.ReadSeq = 13
			since(&d, 12, "2026-10-26T19:00:00Z")
			return append(recs, &d)
		}, "second result"},
		"a read that is not a run": {func(recs []*Record) []*Record {
			bySeq(recs, 25).Config.ReadSeq = 99
			return recs
		}, "not an earlier run"},
		"a read of another asset": {func(recs []*Record) []*Record {
			bySeq(recs, 24).Target.AssetID = other
			return recs
		}, "not an earlier run"},
		"a baseline no acknowledgement set": {func(recs []*Record) []*Record {
			bySeq(recs, 25).Config.BaselineDigest = testSnapshot
			return recs
		}, "acknowledged configuration baseline"},
		"removing all but one compared read": {func(recs []*Record) []*Record {
			c := bySeq(recs, 30).Config
			c.RemovedCount, c.RemovedDigest = 3, RemovedReadsDigest([]string{testEqual, testReadA, testReadB})
			return recs
		}, "newest stay"},
		"removing every compared read": {func(recs []*Record) []*Record {
			c := bySeq(recs, 30).Config
			c.RemovedCount, c.RemovedFirstSeq, c.RemovedLastSeq = 4, 41, 44
			c.RemovedDigest = RemovedReadsDigest([]string{testEqual, testReadA, testReadB, testReadC})
			return recs
		}, "newest stay"},
		"removing reads that are not the oldest": {func(recs []*Record) []*Record {
			c := bySeq(recs, 30).Config
			c.RemovedCount, c.RemovedDigest = 1, RemovedReadsDigest([]string{testReadA})
			return recs
		}, "removed_digest is not"},
		"removing in another order": {func(recs []*Record) []*Record {
			bySeq(recs, 30).Config.RemovedDigest = RemovedReadsDigest([]string{testReadA, testEqual})
			return recs
		}, "removed_digest is not"},
		"keeping a read that is gone": {func(recs []*Record) []*Record {
			bySeq(recs, 30).Config.KeptDigest = testEqual
			return recs
		}, "kept_digest is not the newest"},
		"keeping the second newest read": {func(recs []*Record) []*Record {
			bySeq(recs, 30).Config.KeptDigest = testReadB
			return recs
		}, "kept_digest is not the newest"},
		"removing the same reads twice": {func(recs []*Record) []*Record {
			r := *bySeq(recs, 30)
			c := *r.Config
			r.Seq, r.Config = 40, &c
			return append(recs, &r)
		}, "newest stay"},
		"removing the reads of another asset": {func(recs []*Record) []*Record {
			bySeq(recs, 30).Target.AssetID = other
			return recs
		}, "newest stay"},
		"a result for an earlier read than the previous": {func(recs []*Record) []*Record {
			return append(recs, runAt(31, 15, "2026-10-26T21:00:00Z"), runAt(32, 16, "2026-10-26T21:05:00Z"),
				comparedSameChange(33, 16, "2026-10-26T21:05:05Z", testReadA, 51), comparedSameChange(34, 15, "2026-10-26T21:10:05Z", testReadB, 53))
		}, "results follow the order of the reads"},
		"two detections of one read": {func(recs []*Record) []*Record {
			d := *bySeq(recs, 23)
			c := *d.Config
			d.Seq, d.Config, d.Time = 24, &c, at("2026-10-26T18:00:06Z")
			out := append([]*Record{}, recs[:9]...)
			return append(append(out, &d), recs[9:]...)
		}, "results follow the order of the reads"},
		"a read taken before a change repeating it": {func(recs []*Record) []*Record {
			det := nodeRec(33, "2026-10-26T21:05:05Z", ActionConfigChangeDetected, ReasonUnapprovedChange, Config{BaselineDigest: testBaseline, SnapshotDigest: testSnapshot,
				DifferenceDigest: testDifference, ChangesDigest: testOtherChanges, ReadSeq: 16, UnchangedAt: "2026-10-26T21:00:00Z", UnchangedReadSeq: 15})
			det.Outcome = OutcomeWarning
			same := comparedSameChange(34, 15, "2026-10-26T21:10:05Z", testReadA, 51)
			same.Config.ChangeSeq, same.Config.ChangesDigest = 33, testOtherChanges
			return append(recs, runAt(31, 15, "2026-10-26T21:00:00Z"), runAt(32, 16, "2026-10-26T21:05:00Z"), det, same)
		}, "results follow the order of the reads"},
		"the baseline's own read repeating a later change": {func(recs []*Record) []*Record {
			return append(recs, comparedSameChange(31, 6, "2026-10-26T21:00:05Z", testReadA, 51))
		}, "results follow the order of the reads"},
		"a result for the read a detection already has": {func(recs []*Record) []*Record {
			return append(recs, comparedSameChange(31, 11, "2026-10-26T21:00:05Z", testReadA, 51))
		}, "second result"},
		"the same decision number after a collector reset": {func(recs []*Record) []*Record {
			reset := &Record{Contract: ContractID, NodeID: "site-a-node-1", Seq: 31, PrevHash: strings.Repeat("6", 64), Time: at("2026-10-26T21:00:00Z"),
				Actor: Actor{Type: authz.PrincipalNode, ID: "site-a-node-1"}, Action: ActionCollectorSeqReset, Outcome: OutcomeInfo,
				PreviousHigh: new(uint64), InstallKeyID: "collector-2"}
			return append(recs, reset, runAt(32, 12, "2026-10-26T21:10:00Z"), comparedSameChange(33, 12, "2026-10-26T21:10:05Z", testReadA, 51))
		}, ""},
		"a result after a collector reset for a read of the epoch before": {func(recs []*Record) []*Record {
			reset := &Record{Contract: ContractID, NodeID: "site-a-node-1", Seq: 31, PrevHash: strings.Repeat("6", 64), Time: at("2026-10-26T21:00:00Z"),
				Actor: Actor{Type: authz.PrincipalNode, ID: "site-a-node-1"}, Action: ActionCollectorSeqReset, Outcome: OutcomeInfo,
				PreviousHigh: new(uint64), InstallKeyID: "collector-2"}
			return append(recs, reset, comparedSameChange(33, 14, "2026-10-26T21:10:05Z", testReadA, 51))
		}, "not an earlier run"},
		"results of a run of another operation": {func(recs []*Record) []*Record {
			run := runAt(31, 15, "2026-10-26T21:00:00Z")
			run.OperationID = "sel.ser.read_recent"
			return append(recs, run, comparedSameChange(32, 15, "2026-10-26T21:00:05Z", testReadA, 51))
		}, "names a run of sel.ser.read_recent"},
		"a compared read whose stream seq does not increase": {func(recs []*Record) []*Record {
			return append(recs, runAt(31, 15, "2026-10-26T21:00:00Z"), comparedSameChange(32, 15, "2026-10-26T21:00:05Z", testReadA, 47))
		}, "stream seqs increase"},
		"a removal over a wider range than its reads": {func(recs []*Record) []*Record {
			bySeq(recs, 30).Config.RemovedFirstSeq, bySeq(recs, 30).Config.RemovedLastSeq = 1, 1000000
			return recs
		}, "is not the snapshot_seq of the first and last"},
		"a removal whose range ends early": {func(recs []*Record) []*Record {
			bySeq(recs, 30).Config.RemovedLastSeq = 42
			return recs
		}, "is not the snapshot_seq of the first and last"},
		"a removal whose range starts late": {func(recs []*Record) []*Record {
			bySeq(recs, 30).Config.RemovedFirstSeq = 42
			return recs
		}, "is not the snapshot_seq of the first and last"},
		"removing before any read was compared": {func(recs []*Record) []*Record {
			r := bySeq(recs, 30)
			return append(recs[:3:3], r)
		}, "newest stay"},
	}
	for name, c := range cases {
		err := VerifyConfig(c.mut(cloneChain(readsChain())))
		switch {
		case c.want == "" && err != nil:
			t.Errorf("%s: %v", name, err)
		case c.want != "" && (!errors.Is(err, ErrChainBroken) || !strings.Contains(err.Error(), c.want)):
			t.Errorf("%s: got %v, want %q", name, err, c.want)
		}
	}
}

// TestReadCompareAcknowledgement: a configuration acknowledgement ends the
// open change like a restore does, so that when the baseline the change was
// recorded against is acknowledged again, the next read can report no
// difference from it.
func TestReadCompareAcknowledgement(t *testing.T) {
	// ackTo is the collector's acceptance (decision n) and the node's
	// acknowledgement of baseline, replacing previous.
	ackTo := func(seq, n uint64, baseline, previous string) []*Record {
		v := testAdmin()
		v.Kind = authz.KindNodeBaselineAck
		return []*Record{{Contract: ContractID, NodeID: "site-a-node-1", Seq: seq, PrevHash: strings.Repeat("6", 64), Time: at("2026-10-26T20:10:00Z"),
			Actor: adminActor, Action: ActionCollectorRequest, Outcome: OutcomeAllowed, CorrelationID: fmt.Sprintf("req-20261026-%04d", n), CollectorSeq: n, Verified: v},
			{Contract: ContractID, NodeID: "site-a-node-1", Seq: seq + 1, PrevHash: strings.Repeat("6", 64), Time: at("2026-10-26T20:10:01Z"),
				Actor: adminActor, Action: ActionConfigBaselineAcknowledge, Outcome: OutcomeSucceeded, Target: &Target{AssetID: testAsset},
				CorrelationID: fmt.Sprintf("req-20261026-%04d", n), Config: &Config{DecisionSeq: n, PayloadSHA256: v.PayloadSHA256, Kind: authz.BaselineConfiguration,
					BaselineDigest: baseline, PreviousDigest: previous}}}
	}
	recs := cloneChain(readsChain()[:12])
	recs = append(recs, ackTo(29, 20, testSnapshot, testBaseline)...)
	recs = append(recs, ackTo(31, 21, testBaseline, testSnapshot)...)
	next := nodeRec(34, "2026-10-26T21:00:05Z", ActionConfigReadCompared, ReasonNoDifference, Config{BaselineDigest: testBaseline, SnapshotDigest: testEqual, ReadSeq: 15, SnapshotSeq: 49})
	recs = append(recs, runAt(33, 15, "2026-10-26T21:00:00Z"), next)
	if err := VerifyConfig(recs); err != nil {
		t.Fatalf("no difference from the baseline acknowledged again: %v", err)
	}
	// A configuration acknowledgement is where an asset's read operation may
	// change; before it, a result of another operation breaks the chain.
	other := runAt(33, 15, "2026-10-26T21:00:00Z")
	other.OperationID = "sel.config.read_settings"
	if err := VerifyConfig(append(recs[:len(recs)-2:len(recs)-2], other, next)); err != nil {
		t.Errorf("a result of another operation after the acknowledgement: %v", err)
	}
	// The baseline the second acknowledgement replaced is not the one reads
	// compare against.
	next.Config.BaselineDigest = testSnapshot
	if err := VerifyConfig(recs); err == nil || !strings.Contains(err.Error(), "acknowledged configuration baseline") {
		t.Errorf("a read compared with the replaced baseline: %v", err)
	}
}

// TestReadRecordFields: the fields of the two 0.7 read records, and of the
// detection that now carries the digest of its changes.
func TestReadRecordFields(t *testing.T) {
	base := func() map[string]*Record {
		chain := readsChain()
		return map[string]*Record{"no_difference": bySeq(chain, 14), "same_change": bySeq(chain, 25), "removed": bySeq(chain, 30),
			"detected": bySeq(chain, 23)}
	}
	bad := map[string]struct {
		rec string
		mut func(r *Record)
	}{
		"compared as a warning":                  {"no_difference", func(r *Record) { r.Outcome = OutcomeWarning }},
		"compared without a reason":              {"no_difference", func(r *Record) { r.ReasonCode = "" }},
		"compared with another reason":           {"no_difference", func(r *Record) { r.ReasonCode = ReasonUnapprovedChange }},
		"compared by a person":                   {"no_difference", func(r *Record) { r.Actor = adminActor }},
		"compared without a target":              {"no_difference", func(r *Record) { r.Target = nil }},
		"compared without a correlation":         {"no_difference", func(r *Record) { r.CorrelationID = "" }},
		"compared without a read":                {"no_difference", func(r *Record) { r.Config.ReadSeq = 0 }},
		"compared without a snapshot":            {"no_difference", func(r *Record) { r.Config.SnapshotDigest = "" }},
		"compared without a baseline":            {"no_difference", func(r *Record) { r.Config.BaselineDigest = "" }},
		"compared with a bare hex baseline":      {"no_difference", func(r *Record) { r.Config.BaselineDigest = testBaseline[7:] }},
		"compared stamped 0.6":                   {"no_difference", func(r *Record) { r.Contract = "otsec.audit/0.6" }},
		"compared without a snapshot_seq":        {"no_difference", func(r *Record) { r.Config.SnapshotSeq = 0 }},
		"same change with the empty digest":      {"same_change", func(r *Record) { r.Config.ChangesDigest = EmptyChangesDigest }},
		"detection with the empty digest":        {"detected", func(r *Record) { r.Config.ChangesDigest = EmptyChangesDigest }},
		"detection with a snapshot_seq":          {"detected", func(r *Record) { r.Config.SnapshotSeq = 41 }},
		"restore with a snapshot_seq":            {"detected", func(r *Record) { restoreOf(r); r.Config.SnapshotSeq = 41 }},
		"removal with a snapshot_seq":            {"removed", func(r *Record) { r.Config.SnapshotSeq = 41 }},
		"approval with a snapshot_seq":           {"approval", func(r *Record) { r.Config.SnapshotSeq = 41 }},
		"no difference naming a change":          {"no_difference", func(r *Record) { r.Config.ChangeSeq = 23 }},
		"no difference with a changes digest":    {"no_difference", func(r *Record) { r.Config.ChangesDigest = testChanges }},
		"compared with a difference digest":      {"same_change", func(r *Record) { r.Config.DifferenceDigest = testDifference }},
		"compared with an approval":              {"same_change", func(r *Record) { r.Config.ApprovalSeq = 10 }},
		"compared with an unchanged read":        {"same_change", func(r *Record) { r.Config.UnchangedReadSeq = 8 }},
		"compared with a window":                 {"same_change", func(r *Record) { r.Config.WindowStart = "2026-10-26T16:00:00Z" }},
		"compared with a removal field":          {"same_change", func(r *Record) { r.Config.RemovedCount = 1 }},
		"same change without a change":           {"same_change", func(r *Record) { r.Config.ChangeSeq = 0 }},
		"same change without a digest":           {"same_change", func(r *Record) { r.Config.ChangesDigest = "" }},
		"same change with a bare hex digest":     {"same_change", func(r *Record) { r.Config.ChangesDigest = testChanges[7:] }},
		"same change of the baseline itself":     {"same_change", func(r *Record) { r.Config.SnapshotDigest = testBaseline }},
		"removal by a person":                    {"removed", func(r *Record) { r.Actor = adminActor }},
		"removal as a warning":                   {"removed", func(r *Record) { r.Outcome = OutcomeWarning }},
		"removal with a reason":                  {"removed", func(r *Record) { r.ReasonCode = ReasonNoDifference }},
		"removal without a target":               {"removed", func(r *Record) { r.Target = nil }},
		"removal without a correlation":          {"removed", func(r *Record) { r.CorrelationID = "" }},
		"removal stamped 0.6":                    {"removed", func(r *Record) { r.Contract = "otsec.audit/0.6" }},
		"removal with a baseline":                {"removed", func(r *Record) { r.Config.BaselineDigest = testBaseline }},
		"removal with a snapshot":                {"removed", func(r *Record) { r.Config.SnapshotDigest = testEqual }},
		"removal with a read":                    {"removed", func(r *Record) { r.Config.ReadSeq = 8 }},
		"removal with a changes digest":          {"removed", func(r *Record) { r.Config.ChangesDigest = testChanges }},
		"removal with a decision":                {"removed", func(r *Record) { r.Config.DecisionSeq = 10 }},
		"removal of nothing":                     {"removed", func(r *Record) { r.Config.RemovedCount = 0 }},
		"removal of a negative count":            {"removed", func(r *Record) { r.Config.RemovedCount = -1 }},
		"removal from stream seq 0":              {"removed", func(r *Record) { r.Config.RemovedFirstSeq = 0 }},
		"removal range reversed":                 {"removed", func(r *Record) { r.Config.RemovedFirstSeq, r.Config.RemovedLastSeq = 43, 41 }},
		"removal of more than the range holds":   {"removed", func(r *Record) { r.Config.RemovedCount = 4 }},
		"removal without a removed digest":       {"removed", func(r *Record) { r.Config.RemovedDigest = "" }},
		"removal with a bare hex removed digest": {"removed", func(r *Record) { r.Config.RemovedDigest = testReadA[7:] }},
		"removal without a kept digest":          {"removed", func(r *Record) { r.Config.KeptDigest = "" }},
		"detection without a changes digest":     {"detected", func(r *Record) { r.Config.ChangesDigest = "" }},
		"detection with a bare hex changes":      {"detected", func(r *Record) { r.Config.ChangesDigest = testChanges[7:] }},
		"detection with a change seq":            {"detected", func(r *Record) { r.Config.ChangeSeq = 22 }},
		"detection with a removal field":         {"detected", func(r *Record) { r.Config.RemovedLastSeq = 2 }},
		"detection stamped 0.6 with the digest":  {"detected", func(r *Record) { r.Contract = "otsec.audit/0.6" }},
		"restore with a changes digest":          {"detected", func(r *Record) { restoreOf(r); r.Config.ChangesDigest = testChanges }},
		"restore with a change seq":              {"detected", func(r *Record) { restoreOf(r); r.Config.ChangeSeq = 23 }},
		"restore with a removal field":           {"detected", func(r *Record) { restoreOf(r); r.Config.KeptDigest = testReadA }},
		"approval with a changes digest":         {"approval", func(r *Record) { r.Config.ChangesDigest = testChanges }},
		"acknowledgement with a removal field": {"approval", func(r *Record) {
			r.Action, r.Config.Kind = ActionConfigBaselineAcknowledge, authz.BaselineConfiguration
			r.Config.RemovedCount = 1
		}},
		"another action with the removal config":  {"other", func(r *Record) { r.Config = &Config{RemovedCount: 1} }},
		"removal digest with a different casing":  {"removed", func(r *Record) { r.Config.KeptDigest = "sha256:" + strings.Repeat("B", 64) }},
		"compared with a removal range":           {"no_difference", func(r *Record) { r.Config.RemovedFirstSeq = 1 }},
		"compared with a kept digest":             {"no_difference", func(r *Record) { r.Config.KeptDigest = testReadA }},
		"compared with a decision":                {"no_difference", func(r *Record) { r.Config.DecisionSeq = 10 }},
		"compared with previous_digest":           {"no_difference", func(r *Record) { r.Config.PreviousDigest = testSnapshot }},
		"compared with a collector_seq":           {"no_difference", func(r *Record) { r.CollectorSeq = 12 }},
		"compared with a kind":                    {"no_difference", func(r *Record) { r.Config.Kind = authz.BaselineConfiguration }},
		"same change over the baseline":           {"same_change", func(r *Record) { r.Config.SnapshotDigest = testBaseline }},
		"removal range of one for a count of two": {"removed", func(r *Record) { r.Config.RemovedLastSeq = 41 }},
	}
	for name, c := range bad {
		recs := base()
		if c.rec == "approval" || c.rec == "other" {
			chain := configChain()
			recs[c.rec] = chain[1]
			if c.rec == "other" {
				recs[c.rec] = chain[2]
			}
		}
		r := recs[c.rec]
		c.mut(r)
		if err := r.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	ok := map[string]struct {
		rec string
		mut func(r *Record)
	}{
		"no difference":                    {"no_difference", func(r *Record) {}},
		"the same change":                  {"same_change", func(r *Record) {}},
		"a removal":                        {"removed", func(r *Record) {}},
		"a removal of one":                 {"removed", func(r *Record) { r.Config.RemovedCount = 1 }},
		"a removal over a wider range":     {"removed", func(r *Record) { r.Config.RemovedFirstSeq, r.Config.RemovedLastSeq = 41, 99 }},
		"a detection with its digest":      {"detected", func(r *Record) {}},
		"a 0.6 detection without a digest": {"detected", func(r *Record) { r.Contract, r.Config.ChangesDigest = "otsec.audit/0.6", "" }},
		"a 0.5 detection without a digest": {"detected", func(r *Record) { r.Contract, r.Config.ChangesDigest = "otsec.audit/0.5", "" }},
	}
	for name, c := range ok {
		r := base()[c.rec]
		c.mut(r)
		if err := r.Validate(); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// restoreOf turns a detection into a config.baseline_restored record with
// the fields a restore has.
func restoreOf(r *Record) {
	r.Action, r.Outcome, r.ReasonCode = ActionConfigBaselineRestored, OutcomeInfo, ""
	r.Config = &Config{BaselineDigest: testBaseline, SnapshotDigest: testEqual, ReadSeq: 11}
}

func TestRemovedReadsDigest(t *testing.T) {
	a, b := RemovedReadsDigest([]string{testReadA, testReadB}), RemovedReadsDigest([]string{testReadB, testReadA})
	if a == b {
		t.Error("the digest ignores the order of the reads")
	}
	if !digestPattern.MatchString(a) {
		t.Errorf("not a digest: %s", a)
	}
	if RemovedReadsDigest([]string{testReadA}) == RemovedReadsDigest([]string{testReadA, testReadA}) {
		t.Error("the digest ignores a repeated read")
	}
	// Fixed, so that the node's remover and this contract cannot drift: the
	// SHA-256 of "<digest>\n" for each digest, in order.
	const want = "sha256:864f51ecf848c035c5c4549e5a7c5151e6786d7eb37a91e1cec7f674e81fa821"
	if a != want {
		t.Errorf("digest of two reads is %s, want %s", a, want)
	}
}
