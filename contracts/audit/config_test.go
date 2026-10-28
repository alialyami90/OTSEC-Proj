package audit

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/authz"
	"otsec.local/otsec/contracts/event"
)

// The configuration test values. The digests are SHA-256 of fixed test
// texts, not of any stored document: testBaseline is "otsec test
// configuration baseline" (as in C7's tests), testSnapshot "otsec test
// configuration snapshot" and testDifference "otsec test configuration
// difference".
const (
	testAsset      = "2b7d4e10-8c3f-4a5b-9e21-7c4f0d6a8b13"
	testBaseline   = "sha256:ee1d5cd04fcee7fd33c68453b7fb6a9ec1f7124bf9e88b03f1a4bb6640310e89"
	testSnapshot   = "sha256:2b4627fd426546888575da7c26ef571798f2d583d0027e686f016ed6b1de60ef"
	testDifference = "sha256:c5e3dc4f27577c98a210d2eed87dc6294382624e4ac9a02811831fb8a866beb6"
	testEqual      = "sha256:82fa24899a1607be48de01641e58ec3add0b30db75eada80ec4da264b3d4c439"
	// testChanges is the digest over the changes in testDifference
	// ("otsec test configuration changes"); testOtherChanges is another one
	// ("otsec test other changes").
	testChanges      = "sha256:c5facef81edb1ee68ab3b14c9dbfa8d2c3b7195a9753274c26e487807c2f36ed"
	testOtherChanges = "sha256:c511b92b6eb5abcd146f928c8826f7a4abe73dd852267876eae938f9755dfe5d"
)

func at(utc string) Time {
	return Time{UTC: utc, ResolutionNS: 1000, Clock: Clock{Sync: event.SyncSynchronized, Source: "ntp"}}
}

// configChain is a valid run of records: the collector accepts an approval
// (decision 10), the node records it, the collector accepts a configuration
// read (decision 11), and the node records the difference that read found,
// covered by the approval.
func configChain() []*Record {
	base := func(seq uint64, utc string) Record {
		return Record{Contract: ContractID, NodeID: "site-a-node-1", Seq: seq, PrevHash: strings.Repeat("6", 64), Time: at(utc)}
	}
	verified := testAdmin()
	verified.Kind = authz.KindNodeChangeApproval
	node := Actor{Type: authz.PrincipalNode, ID: "site-a-node-1"}

	accept := base(20, "2026-10-26T15:30:00Z")
	accept.Actor, accept.Action, accept.Outcome = adminActor, ActionCollectorRequest, OutcomeAllowed
	accept.CorrelationID, accept.CollectorSeq, accept.Verified = "req-20261026-0007", 10, verified

	approved := base(21, "2026-10-26T15:30:01Z")
	approved.Actor, approved.Action, approved.Outcome = adminActor, ActionConfigChangeApproved, OutcomeSucceeded
	approved.Target, approved.CorrelationID = &Target{AssetID: testAsset}, "req-20261026-0007"
	approved.Config = &Config{DecisionSeq: 10, PayloadSHA256: verified.PayloadSHA256, BaselineDigest: testBaseline,
		WindowStart: "2026-10-26T16:00:00Z", WindowEnd: "2026-10-26T20:00:00Z", Reason: "Replace CT ratio after relay test (work order 4711)"}

	read := base(22, "2026-10-26T18:00:00Z")
	read.Actor = Actor{Type: authz.PrincipalSystem, ID: "scheduler", Role: authz.RoleCollector}
	read.Action, read.Outcome, read.CorrelationID, read.CollectorSeq = ActionCollectorRequest, OutcomeAllowed, "req-20261026-0008", 11
	read.Target, read.OperationID, read.RegisterRevision = &Target{AssetID: testAsset, CredentialRef: "cred_7f3k2m9q4x"}, "sel.config.read_all", 4

	detected := base(23, "2026-10-26T18:00:05Z")
	detected.Actor, detected.Action, detected.Outcome, detected.ReasonCode = node, ActionConfigChangeDetected, OutcomeInfo, ReasonApprovedChange
	detected.Target, detected.CorrelationID = &Target{AssetID: testAsset}, "6f1c2d3e-4a5b-4c6d-8e7f-9a0b1c2d3e4f"
	detected.Config = &Config{BaselineDigest: testBaseline, SnapshotDigest: testSnapshot, DifferenceDigest: testDifference,
		ChangesDigest: testChanges, ReadSeq: 11, UnchangedAt: "2026-10-26T14:00:00Z", UnchangedReadSeq: 6, ApprovalSeq: 10}

	return []*Record{&accept, &approved, &read, &detected}
}

// acked is what configChain's records stand on in a chain: the read of the
// baseline (decision 6, at 14:00), the collector's acceptance of its
// acknowledgement (decision 7), and the node's succeeded
// config.baseline_acknowledged of testBaseline, then recs.
func acked(recs []*Record) []*Record {
	read := *configChain()[2]
	readTarget := *read.Target
	read.Target, read.Seq, read.CollectorSeq, read.Time, read.CorrelationID = &readTarget, 10, 6, at("2026-10-26T14:00:00Z"), "req-20261026-0003"
	v := testAdmin()
	v.Kind = authz.KindNodeBaselineAck
	accept := &Record{Contract: ContractID, NodeID: "site-a-node-1", Seq: 11, PrevHash: strings.Repeat("6", 64), Time: at("2026-10-26T14:10:00Z"),
		Actor: adminActor, Action: ActionCollectorRequest, Outcome: OutcomeAllowed, CorrelationID: "req-20261026-0004", CollectorSeq: 7, Verified: v}
	ack := &Record{Contract: ContractID, NodeID: "site-a-node-1", Seq: 12, PrevHash: strings.Repeat("6", 64), Time: at("2026-10-26T14:10:01Z"),
		Actor: adminActor, Action: ActionConfigBaselineAcknowledge, Outcome: OutcomeSucceeded, Target: &Target{AssetID: testAsset},
		CorrelationID: "req-20261026-0004", Config: &Config{DecisionSeq: 7, PayloadSHA256: v.PayloadSHA256, Kind: authz.BaselineConfiguration, BaselineDigest: testBaseline}}
	return append([]*Record{&read, accept, ack}, recs...)
}

// since sets the detection's unchanged read: decision seq, at utc.
func since(d *Record, seq uint64, utc string) {
	d.Config.UnchangedReadSeq, d.Config.UnchangedAt = seq, utc
}

// earlyAlarm is an earlier read (decision 8) of the same asset and the
// unapproved difference it found at 15:00:05, before configChain's approval.
func earlyAlarm(recs []*Record) []*Record {
	read, alarm := *recs[2], *recs[3]
	readTarget, cfg := *read.Target, *alarm.Config
	read.Target, read.Seq, read.CollectorSeq, read.Time, read.CorrelationID = &readTarget, 18, 8, at("2026-10-26T15:00:00Z"), "req-20261026-0005"
	alarm.Config, alarm.Seq, alarm.Time = &cfg, 19, at("2026-10-26T15:00:05Z")
	alarm.Outcome, alarm.ReasonCode = OutcomeWarning, ReasonUnapprovedChange
	cfg.ReadSeq, cfg.ApprovalSeq, cfg.UnchangedAt, cfg.UnchangedReadSeq = 8, 0, "2026-10-26T14:00:00Z", 6
	return []*Record{&read, &alarm}
}

// restore is a read (decision 9) at 17:00 that found the configuration
// equal to the baseline again, and its config.baseline_restored record.
func restore(recs []*Record) []*Record {
	read, rec := *recs[2], *recs[3]
	readTarget := *read.Target
	read.Target, read.Seq, read.CollectorSeq, read.Time, read.CorrelationID = &readTarget, 20, 9, at("2026-10-26T17:00:00Z"), "req-20261026-0006"
	rec.Seq, rec.Time, rec.Action, rec.Outcome, rec.ReasonCode = 21, at("2026-10-26T17:00:04Z"), ActionConfigBaselineRestored, OutcomeInfo, ""
	rec.Config = &Config{BaselineDigest: testBaseline, SnapshotDigest: testEqual, ReadSeq: 9}
	return []*Record{&read, &rec}
}

func cloneChain(recs []*Record) []*Record {
	out := make([]*Record, len(recs))
	for i, r := range recs {
		c := *r
		if r.Config != nil {
			cfg := *r.Config
			c.Config = &cfg
		}
		if r.Verified != nil {
			v := *r.Verified
			c.Verified = &v
		}
		if r.Target != nil {
			tg := *r.Target
			c.Target = &tg
		}
		out[i] = &c
	}
	return out
}

func TestConfigChainVerifies(t *testing.T) {
	recs := configChain()
	for _, r := range recs {
		if err := r.Validate(); err != nil {
			t.Fatalf("record %d (%s): %v", r.Seq, r.Action, err)
		}
	}
	if err := VerifyConfig(acked(recs)); err != nil {
		t.Fatal(err)
	}
	if err := ApprovalCovers(recs[1], recs[3]); err != nil {
		t.Fatal(err)
	}
}

// TestConfigFields: each configuration action carries exactly its fields,
// with the body's own rule, and none on a record stamped 0.4.
func TestConfigFields(t *testing.T) {
	bad := map[string]struct {
		rec int
		mut func(r *Record)
	}{
		"approval stamped 0.4":              {1, func(r *Record) { r.Contract = "otsec.audit/0.4" }},
		"detection stamped 0.4":             {3, func(r *Record) { r.Contract = "otsec.audit/0.4" }},
		"verified kind stamped 0.4":         {0, func(r *Record) { r.Contract = "otsec.audit/0.4" }},
		"verified kind not an admin kind":   {0, func(r *Record) { r.Verified.Kind = authz.KindRun }},
		"approval without config":           {1, func(r *Record) { r.Config = nil }},
		"config on another action":          {0, func(r *Record) { r.Config = &Config{BaselineDigest: testBaseline} }},
		"approval without target":           {1, func(r *Record) { r.Target = nil }},
		"approval without correlation":      {1, func(r *Record) { r.CorrelationID = "" }},
		"approval by the node":              {1, func(r *Record) { r.Actor = Actor{Type: authz.PrincipalNode, ID: "site-a-node-1"} }},
		"approval as info":                  {1, func(r *Record) { r.Outcome = OutcomeInfo }},
		"approval without decision":         {1, func(r *Record) { r.Config.DecisionSeq = 0 }},
		"approval payload hash prefixed":    {1, func(r *Record) { r.Config.PayloadSHA256 = "sha256:" + r.Config.PayloadSHA256[7:] }},
		"approval baseline bare hex":        {1, func(r *Record) { r.Config.BaselineDigest = testBaseline[7:] }},
		"approval with a kind":              {1, func(r *Record) { r.Config.Kind = authz.BaselineConfiguration }},
		"approval with a read":              {1, func(r *Record) { r.Config.ReadSeq = 11 }},
		"approval window over 24 h":         {1, func(r *Record) { r.Config.WindowEnd = "2026-10-27T16:00:01Z" }},
		"approval window reversed":          {1, func(r *Record) { r.Config.WindowStart, r.Config.WindowEnd = r.Config.WindowEnd, r.Config.WindowStart }},
		"approval window not UTC":           {1, func(r *Record) { r.Config.WindowStart = "2026-10-26T19:00:00+03:00" }},
		"approval reason empty":             {1, func(r *Record) { r.Config.Reason = "" }},
		"approval reason with a line break": {1, func(r *Record) { r.Config.Reason = "a\nb" }},
		"approval reason over 256 bytes":    {1, func(r *Record) { r.Config.Reason = strings.Repeat("x", 257) }},
		"ack without kind": {1, func(r *Record) {
			r.Action, r.Config.WindowStart, r.Config.WindowEnd, r.Config.Reason = ActionConfigBaselineAcknowledge, "", "", ""
		}},
		"ack with a window": {1, func(r *Record) { r.Action, r.Config.Kind = ActionConfigBaselineAcknowledge, authz.BaselineEvent }},
		"ack of an unknown kind": {1, func(r *Record) {
			r.Action, r.Config.Kind, r.Config.WindowStart, r.Config.WindowEnd, r.Config.Reason = ActionConfigBaselineAcknowledge, "settings", "", "", ""
		}},
		"approval with previous_digest":  {1, func(r *Record) { r.Config.PreviousDigest = testSnapshot }},
		"detection with previous_digest": {3, func(r *Record) { r.Config.PreviousDigest = testSnapshot }},
		"ack replacing itself": {1, func(r *Record) {
			r.Action, r.Config.Kind, r.Config.WindowStart, r.Config.WindowEnd, r.Config.Reason = ActionConfigBaselineAcknowledge, authz.BaselineEvent, "", "", ""
			r.Config.PreviousDigest = testBaseline
		}},
		"ack previous bare hex": {1, func(r *Record) {
			r.Action, r.Config.Kind, r.Config.WindowStart, r.Config.WindowEnd, r.Config.Reason = ActionConfigBaselineAcknowledge, authz.BaselineEvent, "", "", ""
			r.Config.PreviousDigest = testSnapshot[7:]
		}},
		"detection by a person":               {3, func(r *Record) { r.Actor = adminActor }},
		"detection with a window":             {3, func(r *Record) { r.Config.WindowStart = "2026-10-26T16:00:00Z" }},
		"detection with a decision":           {3, func(r *Record) { r.Config.DecisionSeq = 10 }},
		"detection without snapshot":          {3, func(r *Record) { r.Config.SnapshotDigest = "" }},
		"detection without difference":        {3, func(r *Record) { r.Config.DifferenceDigest = "" }},
		"detection of the baseline":           {3, func(r *Record) { r.Config.SnapshotDigest = testBaseline }},
		"detection without read":              {3, func(r *Record) { r.Config.ReadSeq, r.Config.ApprovalSeq = 0, 0 }},
		"detection approval after read":       {3, func(r *Record) { r.Config.ApprovalSeq = 11 }},
		"detection without unchanged_at":      {3, func(r *Record) { r.Config.UnchangedAt = "" }},
		"detection unchanged at its own read": {3, func(r *Record) { r.Config.UnchangedReadSeq = 11 }},
		"detection unchanged after its read":  {3, func(r *Record) { r.Config.UnchangedReadSeq = 12 }},
		"approval with unchanged_read_seq":    {1, func(r *Record) { r.Config.UnchangedReadSeq = 6 }},
		"restore with a difference": {3, func(r *Record) {
			r.Action, r.Outcome, r.ReasonCode = ActionConfigBaselineRestored, OutcomeInfo, ""
			r.Config.UnchangedAt, r.Config.ApprovalSeq = "", 0
		}},
		"restore with unchanged_read_seq": {3, func(r *Record) {
			r.Action, r.Outcome, r.ReasonCode = ActionConfigBaselineRestored, OutcomeInfo, ""
			r.Config = &Config{BaselineDigest: testBaseline, SnapshotDigest: testEqual, ReadSeq: 11, UnchangedReadSeq: 6}
		}},
		"restore as warning": {3, func(r *Record) {
			r.Action, r.Outcome, r.ReasonCode = ActionConfigBaselineRestored, OutcomeWarning, ReasonUnapprovedChange
			r.Config = &Config{BaselineDigest: testBaseline, SnapshotDigest: testEqual, ReadSeq: 11}
		}},
		"restore by a person": {3, func(r *Record) {
			r.Action, r.Outcome, r.ReasonCode, r.Actor = ActionConfigBaselineRestored, OutcomeInfo, "", adminActor
			r.Config = &Config{BaselineDigest: testBaseline, SnapshotDigest: testEqual, ReadSeq: 11}
		}},
		"restore stamped 0.4": {3, func(r *Record) {
			r.Action, r.Outcome, r.ReasonCode, r.Contract = ActionConfigBaselineRestored, OutcomeInfo, "", "otsec.audit/0.4"
			r.Config = &Config{BaselineDigest: testBaseline, SnapshotDigest: testEqual, ReadSeq: 11}
		}},
		"detection unchanged_at local":     {3, func(r *Record) { r.Config.UnchangedAt = "2026-10-26T20:00:04+03:00" }},
		"approved without approval_seq":    {3, func(r *Record) { r.Config.ApprovalSeq = 0 }},
		"unapproved with approval_seq":     {3, func(r *Record) { r.Outcome, r.ReasonCode = OutcomeWarning, ReasonUnapprovedChange }},
		"detection as warning, other code": {3, func(r *Record) { r.Outcome, r.ReasonCode, r.Config.ApprovalSeq = OutcomeWarning, "changed", 0 }},
		"detection with collector_seq":     {3, func(r *Record) { r.CollectorSeq = 12 }},
	}
	for name, c := range bad {
		recs := cloneChain(configChain())
		c.mut(recs[c.rec])
		if err := recs[c.rec].Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	ok := map[string]struct {
		rec int
		mut func(r *Record)
	}{
		"unapproved difference": {3, func(r *Record) {
			r.Outcome, r.ReasonCode, r.Config.ApprovalSeq = OutcomeWarning, ReasonUnapprovedChange, 0
		}},
		"no earlier read in the epoch": {3, func(r *Record) { r.Config.UnchangedReadSeq = 0 }},
		"approval refused by the node": {1, func(r *Record) { r.Outcome, r.ReasonCode = OutcomeDenied, "asset_not_collected" }},
		"configuration baseline acknowledged": {1, func(r *Record) {
			r.Action, r.Config.Kind, r.Config.WindowStart, r.Config.WindowEnd, r.Config.Reason = ActionConfigBaselineAcknowledge, authz.BaselineConfiguration, "", "", ""
		}},
		"event baseline refused": {1, func(r *Record) {
			r.Action, r.Outcome, r.ReasonCode = ActionConfigBaselineAcknowledge, OutcomeDenied, "baseline_not_held"
			r.Config.Kind, r.Config.WindowStart, r.Config.WindowEnd, r.Config.Reason = authz.BaselineEvent, "", "", ""
		}},
		"restore": {3, func(r *Record) {
			r.Action, r.Outcome, r.ReasonCode = ActionConfigBaselineRestored, OutcomeInfo, ""
			r.Config = &Config{BaselineDigest: testBaseline, SnapshotDigest: testEqual, ReadSeq: 11}
		}},
		"ack replacing a baseline": {1, func(r *Record) {
			r.Action, r.Config.Kind, r.Config.WindowStart, r.Config.WindowEnd, r.Config.Reason = ActionConfigBaselineAcknowledge, authz.BaselineConfiguration, "", "", ""
			r.Config.PreviousDigest = testSnapshot
		}},
		"claimed kind on info": {0, func(r *Record) {
			r.Outcome, r.CollectorSeq, r.Claimed, r.Verified = OutcomeInfo, 0, r.Verified, nil
		}},
	}
	for name, c := range ok {
		recs := cloneChain(configChain())
		c.mut(recs[c.rec])
		if err := recs[c.rec].Validate(); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestApprovalCovers: order decides "in advance", the window must overlap
// the time the change happened in, and the asset and baseline must match.
func TestApprovalCovers(t *testing.T) {
	cases := map[string]struct {
		mut  func(approval, detected *Record)
		want bool
	}{
		"as recorded": {func(a, d *Record) {}, true},
		"window starts at the detection": {func(a, d *Record) {
			a.Config.WindowStart, a.Config.WindowEnd = "2026-10-26T18:00:05Z", "2026-10-26T22:00:00Z"
		}, false},
		"window starts just before it": {func(a, d *Record) {
			a.Config.WindowStart, a.Config.WindowEnd = "2026-10-26T18:00:04Z", "2026-10-26T22:00:00Z"
		}, true},
		"window ends at unchanged_at": {func(a, d *Record) {
			a.Config.WindowStart, a.Config.WindowEnd = "2026-10-26T10:00:00Z", "2026-10-26T14:00:00Z"
		}, false},
		"window ends just after it": {func(a, d *Record) {
			a.Config.WindowStart, a.Config.WindowEnd = "2026-10-26T10:00:01Z", "2026-10-26T14:00:01Z"
		}, true},
		"decided with the read":  {func(a, d *Record) { a.Config.DecisionSeq = 11 }, false},
		"decided after the read": {func(a, d *Record) { a.Config.DecisionSeq = 12 }, false},
		"another asset":          {func(a, d *Record) { a.Target.AssetID = "3c8e5f21-9d4a-4b6c-8f32-8d5a1e7b9c24" }, false},
		"another node":           {func(a, d *Record) { a.NodeID = "site-a-node-2" }, false},
		"another baseline": {func(a, d *Record) {
			a.Config.BaselineDigest = testSnapshot
		}, false},
		"approval refused by the node": {func(a, d *Record) { a.Outcome, a.ReasonCode = OutcomeDenied, "asset_not_collected" }, false},
	}
	for name, c := range cases {
		recs := cloneChain(configChain())
		c.mut(recs[1], recs[3])
		err := ApprovalCovers(recs[1], recs[3])
		if (err == nil) != c.want {
			t.Errorf("%s: covers %v, want %v (%v)", name, err == nil, c.want, err)
		}
	}
	recs := configChain()
	if ApprovalCovers(recs[3], recs[1]) == nil || ApprovalCovers(recs[1], recs[1]) == nil {
		t.Error("ApprovalCovers accepted records of the wrong actions")
	}
}

// TestVerifyConfig: a node cannot silence an alarm with an approval the
// collector never accepted, one of another kind or person, one from before
// a collector reinstall, or one accepted after the difference was found.
func TestVerifyConfig(t *testing.T) {
	nodeActor := Actor{Type: authz.PrincipalNode, ID: "site-a-node-1"}
	reset := &Record{Contract: ContractID, NodeID: "site-a-node-1", Seq: 30, PrevHash: strings.Repeat("6", 64), Time: at("2026-10-26T17:30:00Z"),
		Actor: nodeActor, Action: ActionCollectorSeqReset, Outcome: OutcomeInfo, PreviousHigh: new(uint64), InstallKeyID: "collector-2"}
	// Each case names the reason VerifyConfig must give, so a case refused
	// for another reason fails.
	cases := map[string]struct {
		mut  func(recs []*Record) []*Record
		want string
	}{
		"no acceptance":                 {func(recs []*Record) []*Record { return recs[1:] }, "no earlier acceptance"},
		"acceptance after the approval": {func(recs []*Record) []*Record { return []*Record{recs[1], recs[0], recs[2], recs[3]} }, "no earlier acceptance"},
		"acceptance of another kind": {func(recs []*Record) []*Record {
			recs[0].Verified.Kind = authz.KindCredentialRevoke
			return recs
		}, "follows an acceptance of"},
		"acceptance without a kind": {func(recs []*Record) []*Record {
			recs[0].Verified.Kind = ""
			return recs
		}, "follows an acceptance of"},
		"acceptance of other bytes": {func(recs []*Record) []*Record {
			recs[1].Config.PayloadSHA256 = strings.Repeat("ab", 32)
			return recs
		}, "does not match the acceptance"},
		"approval by another person": {func(recs []*Record) []*Record {
			recs[1].Actor = Actor{Type: authz.PrincipalHuman, ID: "bob@site-a", Role: authz.RoleAdmin}
			return recs
		}, "does not match the acceptance"},
		"ack following an approval's acceptance": {func(recs []*Record) []*Record {
			r := recs[1]
			r.Action, r.Config.Kind, r.Config.WindowStart, r.Config.WindowEnd, r.Config.Reason = ActionConfigBaselineAcknowledge, authz.BaselineConfiguration, "", "", ""
			return recs
		}, "follows an acceptance of"},
		"a collector reset between approval and read": {func(recs []*Record) []*Record {
			since(recs[3], 0, "2026-10-26T17:30:00Z")
			return []*Record{recs[0], recs[1], reset, recs[2], recs[3]}
		}, "not an earlier succeeded approval in its epoch"},
		"no read decision": {func(recs []*Record) []*Record { return []*Record{recs[0], recs[1], recs[3]} }, "not an earlier run"},
		"read of another asset": {func(recs []*Record) []*Record {
			recs[2].Target.AssetID = "3c8e5f21-9d4a-4b6c-8f32-8d5a1e7b9c24"
			return recs
		}, "not an earlier run"},
		"approval refused by the node": {func(recs []*Record) []*Record {
			recs[1].Outcome, recs[1].ReasonCode = OutcomeDenied, "asset_not_collected"
			return recs
		}, "not an earlier succeeded approval"},
		"approval_seq names no approval": {func(recs []*Record) []*Record {
			recs[3].Config.ApprovalSeq = 9
			return recs
		}, "not an earlier succeeded approval"},
		"approval that does not cover": {func(recs []*Record) []*Record {
			recs[1].Config.WindowStart, recs[1].Config.WindowEnd = "2026-10-26T19:00:00Z", "2026-10-26T20:00:00Z"
			return recs
		}, "does not cover"},
		// An approval accepted after a change was found unapproved never
		// silences it, though a later read records it again (P4-A3, V-M2).
		"late approval for a change already found": {func(recs []*Record) []*Record {
			since(recs[3], 8, "2026-10-26T15:00:00Z")
			return append(earlyAlarm(recs), recs...)
		}, "still open"},
		"a restore before the alarm": {func(recs []*Record) []*Record {
			// The restore's read is decision 8 and the alarm's 9.
			back, alarm := restore(recs), earlyAlarm(recs)
			back[0].CollectorSeq, back[1].Config.ReadSeq = 8, 8
			alarm[0].CollectorSeq, alarm[1].Config.ReadSeq = 9, 9
			since(alarm[1], 8, "2026-10-26T17:00:00Z")
			alarm[0].Time, alarm[1].Time = at("2026-10-26T17:10:00Z"), at("2026-10-26T17:10:05Z")
			since(recs[3], 9, "2026-10-26T17:10:00Z")
			return append(append(back, alarm...), recs...)
		}, "still open"},
		"a restore of another baseline": {func(recs []*Record) []*Record {
			back := restore(recs)
			back[1].Config.BaselineDigest = testDifference
			since(recs[3], 9, "2026-10-26T17:00:00Z")
			return append(append(earlyAlarm(recs), back...), recs...)
		}, "acknowledged configuration baseline"},
		"a restore naming no read": {func(recs []*Record) []*Record {
			back := restore(recs)
			return append(append(earlyAlarm(recs), back[1]), recs...)
		}, "not an earlier run"},
	}
	for name, c := range cases {
		recs := acked(c.mut(cloneChain(configChain())))
		err := VerifyConfig(recs)
		if !errors.Is(err, ErrChainBroken) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want %q", name, err, c.want)
		}
	}
	// A repeat answer stands for the first decision when the first reply was
	// lost, and the same reset rule holds after it.
	recs := cloneChain(configChain())
	recs[0].RepeatOf, recs[0].CollectorSeq = 10, 12
	recs[2].CollectorSeq, recs[3].Config.ReadSeq = 13, 13
	if err := VerifyConfig(acked(recs)); err != nil {
		t.Fatalf("repeat answer: %v", err)
	}
	// After the alarm the configuration was seen equal to the baseline
	// again, and the node recorded it, so a new change may be approved.
	recs = cloneChain(configChain())
	since(recs[3], 9, "2026-10-26T17:00:00Z")
	if err := VerifyConfig(acked(append(append(earlyAlarm(recs), restore(recs)...), recs...))); err != nil {
		t.Fatalf("approved change after a return to the baseline: %v", err)
	}
	// An unapproved difference needs nothing but its read and its baseline.
	recs = cloneChain(configChain())
	recs[3].Outcome, recs[3].ReasonCode, recs[3].Config.ApprovalSeq = OutcomeWarning, ReasonUnapprovedChange, 0
	if err := VerifyConfig(acked(recs[2:])); err != nil {
		t.Fatalf("unapproved difference: %v", err)
	}
}

// TestUnchangedRead: a detection's unchanged_at is the time of the asset's
// last run of the same operation before its read, a record already in the
// chain, so the node cannot move the start of the change earlier to bring
// it inside an approval's window (B6 on #250, finding 1).
func TestUnchangedRead(t *testing.T) {
	// run is another run on the asset (decision 9 at 17:00) between the
	// approval and configChain's read.
	run := func(recs []*Record, op, asset string) []*Record {
		r := *recs[2]
		target := *r.Target
		r.Target, r.Seq, r.CollectorSeq, r.Time, r.CorrelationID, r.OperationID = &target, 21, 9, at("2026-10-26T17:00:00Z"), "req-20261026-0006", op
		r.Target.AssetID = asset
		return []*Record{recs[0], recs[1], &r, recs[2], recs[3]}
	}
	const other = "3c8e5f21-9d4a-4b6c-8f32-8d5a1e7b9c24"
	cases := map[string]struct {
		mut  func(recs []*Record) []*Record
		want string // "" accepts
	}{
		"the last run": {func(recs []*Record) []*Record {
			since(recs[3], 9, "2026-10-26T17:00:00Z")
			return run(recs, "sel.config.read_all", testAsset)
		}, ""},
		"an older run than the last": {func(recs []*Record) []*Record {
			return run(recs, "sel.config.read_all", testAsset)
		}, "last run before read 11 is 9"},
		"the last run at a time it did not have": {func(recs []*Record) []*Record {
			since(recs[3], 9, "2026-10-26T15:00:00Z")
			return run(recs, "sel.config.read_all", testAsset)
		}, "is not the time of record"},
		"a time no run had": {func(recs []*Record) []*Record {
			since(recs[3], 6, "2026-10-26T13:00:00Z")
			return recs
		}, "is not the time of record"},
		"a run of another operation is not a read of the configuration": {func(recs []*Record) []*Record {
			return run(recs, "sel.ser.read_all", testAsset)
		}, ""},
		"a run on another asset": {func(recs []*Record) []*Record {
			return run(recs, "sel.config.read_all", other)
		}, ""},
		"no unchanged read while the epoch has one": {func(recs []*Record) []*Record {
			since(recs[3], 0, "2026-10-26T14:00:00Z")
			return recs
		}, "last run before read 11 is 6"},
		"an unchanged read of another epoch": {func(recs []*Record) []*Record {
			reset := &Record{Contract: ContractID, NodeID: "site-a-node-1", Seq: 30, PrevHash: strings.Repeat("6", 64), Time: at("2026-10-26T17:30:00Z"),
				Actor: Actor{Type: authz.PrincipalNode, ID: "site-a-node-1"}, Action: ActionCollectorSeqReset, Outcome: OutcomeInfo,
				PreviousHigh: new(uint64), InstallKeyID: "collector-2"}
			recs[3].Outcome, recs[3].ReasonCode, recs[3].Config.ApprovalSeq = OutcomeWarning, ReasonUnapprovedChange, 0
			return []*Record{recs[0], recs[1], reset, recs[2], recs[3]}
		}, "no earlier run on the asset is in its epoch"},
		"the epoch's reset when it has no earlier run": {func(recs []*Record) []*Record {
			reset := &Record{Contract: ContractID, NodeID: "site-a-node-1", Seq: 30, PrevHash: strings.Repeat("6", 64), Time: at("2026-10-26T17:30:00Z"),
				Actor: Actor{Type: authz.PrincipalNode, ID: "site-a-node-1"}, Action: ActionCollectorSeqReset, Outcome: OutcomeInfo,
				PreviousHigh: new(uint64), InstallKeyID: "collector-2"}
			recs[3].Outcome, recs[3].ReasonCode, recs[3].Config.ApprovalSeq = OutcomeWarning, ReasonUnapprovedChange, 0
			since(recs[3], 0, "2026-10-26T17:30:00Z")
			return []*Record{recs[0], recs[1], reset, recs[2], recs[3]}
		}, ""},
	}
	for name, c := range cases {
		err := VerifyConfig(acked(c.mut(cloneChain(configChain()))))
		switch {
		case c.want == "" && err != nil:
			t.Errorf("%s: %v", name, err)
		case c.want != "" && (!errors.Is(err, ErrChainBroken) || !strings.Contains(err.Error(), c.want)):
			t.Errorf("%s: got %v, want %q", name, err, c.want)
		}
	}
	// In the first epoch a detection with no earlier run has nothing to
	// bound the change: recs must start before that run.
	recs := cloneChain(configChain())
	recs[3].Outcome, recs[3].ReasonCode, recs[3].Config.ApprovalSeq = OutcomeWarning, ReasonUnapprovedChange, 0
	since(recs[3], 0, "2026-10-26T14:00:00Z")
	all := acked(recs)
	if err := VerifyConfig(all[1:]); err == nil || !strings.Contains(err.Error(), "no collector reset") {
		t.Errorf("no earlier run and no reset: %v", err)
	}
}

// TestBaselineAcknowledged: detections, restores and approvals name the
// configuration baseline a person last acknowledged for the asset (R4.8;
// B6 on #250, finding 2).
func TestBaselineAcknowledged(t *testing.T) {
	unapproved := func(recs []*Record) []*Record {
		recs[3].Outcome, recs[3].ReasonCode, recs[3].Config.ApprovalSeq = OutcomeWarning, ReasonUnapprovedChange, 0
		return recs[2:]
	}
	cases := map[string]struct {
		build func() []*Record
		want  string
	}{
		"no acknowledgement in recs": {func() []*Record { return configChain() }, "no earlier acknowledgement"},
		"no acknowledgement, unapproved": {func() []*Record {
			return unapproved(configChain())
		}, "no earlier acknowledgement"},
		"detection against another baseline": {func() []*Record {
			recs := unapproved(cloneChain(configChain()))
			recs[1].Config.BaselineDigest = testDifference
			return acked(recs)
		}, "acknowledged configuration baseline is " + testBaseline},
		"approval of changes to another baseline": {func() []*Record {
			recs := cloneChain(configChain())
			recs[1].Config.BaselineDigest = testDifference
			return acked(recs[:2])
		}, "acknowledged configuration baseline is " + testBaseline},
		"only an event baseline acknowledged": {func() []*Record {
			all := acked(unapproved(cloneChain(configChain())))
			all[2].Config.Kind = authz.BaselineEvent
			return all
		}, "no earlier acknowledgement"},
		"the acknowledgement was refused": {func() []*Record {
			all := acked(unapproved(cloneChain(configChain())))
			all[2].Outcome, all[2].ReasonCode = OutcomeDenied, "baseline_not_held"
			return all
		}, "no earlier acknowledgement"},
		"acknowledged after the detection": {func() []*Record {
			all := acked(unapproved(cloneChain(configChain())))
			return []*Record{all[0], all[3], all[4], all[1], all[2]}
		}, "no earlier acknowledgement"},
		"a restore of a baseline since replaced": {func() []*Record {
			recs := cloneChain(configChain())
			back := restore(recs)
			all := acked(back)
			v := testAdmin()
			v.Kind, v.Nonce = authz.KindNodeBaselineAck, "AAECAwQFBgcICQoLDA0ODx"
			accept := *all[1]
			accept.Seq, accept.CollectorSeq, accept.Verified = 13, 8, v
			ack := *all[2]
			cfg := *ack.Config
			cfg.DecisionSeq, cfg.PayloadSHA256, cfg.BaselineDigest, cfg.PreviousDigest = 8, v.PayloadSHA256, testSnapshot, testBaseline
			ack.Seq, ack.Config = 14, &cfg
			return []*Record{all[0], all[1], all[2], &accept, &ack, all[3], all[4]}
		}, "acknowledged configuration baseline is " + testSnapshot},
	}
	for name, c := range cases {
		err := VerifyConfig(c.build())
		if !errors.Is(err, ErrChainBroken) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want %q", name, err, c.want)
		}
	}
}

// ackChain is two acknowledgements of asset baselines of one kind: the
// first sets testBaseline (decision 30), the second replaces it with
// testSnapshot (decision 31).
func ackChain() []*Record {
	var out []*Record
	for i, d := range []struct {
		seq            uint64
		baseline, prev string
	}{{30, testBaseline, ""}, {31, testSnapshot, testBaseline}} {
		v := testAdmin()
		v.Kind = authz.KindNodeBaselineAck
		v.Nonce = fmt.Sprintf("AAECAwQFBgcICQoLDA0OD%d", i)
		accept := &Record{Contract: ContractID, NodeID: "site-a-node-1", Seq: uint64(40 + 2*i), PrevHash: strings.Repeat("6", 64),
			Time: at("2026-10-26T19:00:00Z"), Actor: adminActor, Action: ActionCollectorRequest, Outcome: OutcomeAllowed,
			CorrelationID: fmt.Sprintf("req-ack-%d", i), CollectorSeq: d.seq, Verified: v}
		ack := &Record{Contract: ContractID, NodeID: "site-a-node-1", Seq: uint64(41 + 2*i), PrevHash: strings.Repeat("6", 64),
			Time: at("2026-10-26T19:00:01Z"), Actor: adminActor, Action: ActionConfigBaselineAcknowledge, Outcome: OutcomeSucceeded,
			Target: &Target{AssetID: testAsset}, CorrelationID: fmt.Sprintf("req-ack-%d", i),
			Config: &Config{DecisionSeq: d.seq, PayloadSHA256: v.PayloadSHA256, Kind: authz.BaselineEvent, BaselineDigest: d.baseline, PreviousDigest: d.prev}}
		out = append(out, accept, ack)
	}
	return out
}

// TestBaselineSuccession: each acknowledgement names the baseline the last
// one set (B4 on #250), so C8 alone shows each asset's succession.
func TestBaselineSuccession(t *testing.T) {
	recs := ackChain()
	for _, r := range recs {
		if err := r.Validate(); err != nil {
			t.Fatalf("record %d: %v", r.Seq, err)
		}
	}
	if err := VerifyConfig(recs); err != nil {
		t.Fatal(err)
	}
	// A window that starts after the first acknowledgement cannot check
	// the second's previous_digest, and accepts it.
	if err := VerifyConfig(recs[2:]); err != nil {
		t.Fatalf("window after the first: %v", err)
	}
	for name, mut := range map[string]func(recs []*Record){
		"second names no previous": func(recs []*Record) { recs[3].Config.PreviousDigest = "" },
		"second names another":     func(recs []*Record) { recs[3].Config.PreviousDigest = testDifference },
		"a configuration ack first": func(recs []*Record) {
			recs[1].Config.Kind = authz.BaselineConfiguration
			recs[3].Config.PreviousDigest = ""
		},
	} {
		recs := cloneChain(ackChain())
		mut(recs)
		err := VerifyConfig(recs)
		if name == "a configuration ack first" {
			// Another kind is another succession: the event ack is the first.
			if err != nil {
				t.Errorf("%s: %v", name, err)
			}
			continue
		}
		if !errors.Is(err, ErrChainBroken) {
			t.Errorf("%s: got %v", name, err)
		}
	}
	// A denied acknowledgement moves nothing.
	recs = cloneChain(ackChain())
	recs[1].Outcome, recs[1].ReasonCode = OutcomeDenied, "baseline_not_held"
	recs[3].Config.PreviousDigest = ""
	recs[3].Config.BaselineDigest = testSnapshot
	if err := VerifyConfig(recs); err != nil {
		t.Fatalf("after a denied acknowledgement: %v", err)
	}
}

// ackRun is the collector's acceptance (decision) of a baseline
// acknowledgement and the node's record of it, for asset, setting digest
// after prev, as a C7 0.6 node.baseline_ack of the given kind.
func ackRun(asset string, decision uint64, kind authz.BaselineKind, digest, prev string, outcome Outcome) []*Record {
	v := testAdmin()
	v.Kind = authz.KindNodeBaselineAck
	v.Nonce = fmt.Sprintf("AAECAwQFBgcICQoL%06d", decision)
	accept := &Record{Contract: ContractID, NodeID: "site-a-node-1", Seq: 2 * decision, PrevHash: strings.Repeat("6", 64),
		Time: at("2026-10-26T15:10:00Z"), Actor: adminActor, Action: ActionCollectorRequest, Outcome: OutcomeAllowed,
		CorrelationID: fmt.Sprintf("req-ack-%d", decision), CollectorSeq: decision, Verified: v}
	ack := &Record{Contract: ContractID, NodeID: "site-a-node-1", Seq: 2*decision + 1, PrevHash: strings.Repeat("6", 64),
		Time: at("2026-10-26T15:10:01Z"), Actor: adminActor, Action: ActionConfigBaselineAcknowledge, Outcome: outcome,
		Target: &Target{AssetID: asset}, CorrelationID: fmt.Sprintf("req-ack-%d", decision),
		Config: &Config{DecisionSeq: decision, PayloadSHA256: v.PayloadSHA256, Kind: kind, BaselineDigest: digest, PreviousDigest: prev}}
	if outcome == OutcomeDenied {
		ack.ReasonCode = "baseline_not_held"
	}
	return []*Record{accept, ack}
}

// aToBToA acknowledges testSnapshot after testBaseline, then testBaseline
// again after it: the baseline is the one the alarm was raised against.
func aToBToA(asset string, first uint64) []*Record {
	return append(ackRun(asset, first, authz.BaselineConfiguration, testSnapshot, testBaseline, OutcomeSucceeded),
		ackRun(asset, first+1, authz.BaselineConfiguration, testBaseline, testSnapshot, OutcomeSucceeded)...)
}

// shifted is recs on another asset, with every decision number moved up by
// 100, so that two assets' records share a chain.
func shifted(recs []*Record, asset string) []*Record {
	out := cloneChain(recs)
	for _, r := range out {
		for _, n := range []*uint64{&r.CollectorSeq, &r.RepeatOf} {
			if *n != 0 {
				*n += 100
			}
		}
		if r.Target != nil {
			r.Target.AssetID = asset
		}
		if c := r.Config; c != nil {
			for _, n := range []*uint64{&c.DecisionSeq, &c.ReadSeq, &c.UnchangedReadSeq, &c.ApprovalSeq} {
				if *n != 0 {
					*n += 100
				}
			}
		}
	}
	return out
}

// TestAlarmEndedByAcknowledgement is the C8 0.6 rule (D4-18): a succeeded
// configuration-kind acknowledgement ends every open configuration alarm of
// its asset raised before it, whatever baseline it was raised against; only
// an alarm raised after the latest acknowledgement blocks a later approval.
func TestAlarmEndedByAcknowledgement(t *testing.T) {
	const other = "3c8e5f21-9d4a-4b6c-8f32-8d5a1e7b9c24"
	// The alarm of 15:00:05 against testBaseline, and the approved detection
	// of 18:00:05 against it that a late approval cannot cover.
	late := func() (prefix, suffix []*Record) {
		recs := cloneChain(configChain())
		since(recs[3], 8, "2026-10-26T15:00:00Z")
		return acked(earlyAlarm(recs)), recs
	}
	join := func(parts ...[]*Record) []*Record {
		var all []*Record
		for _, p := range parts {
			all = append(all, p...)
		}
		return all
	}
	still := func(name string, err error) {
		t.Helper()
		if !errors.Is(err, ErrChainBroken) || !strings.Contains(err.Error(), "still open") {
			t.Errorf("%s: got %v, want an open alarm", name, err)
		}
	}
	prefix, suffix := late()
	still("no acknowledgement after the alarm", VerifyConfig(join(prefix, suffix)))

	// Acknowledging B and then A again ends the alarm against A, and the
	// approved detection after it stands.
	if err := VerifyConfig(join(prefix, aToBToA(testAsset, 40), suffix)); err != nil {
		t.Fatalf("A to B to A after the alarm: %v", err)
	}
	// An alarm raised after the latest acknowledgement still blocks it: a
	// second read (decision 9, 16:30) found the difference again.
	prefix, suffix = late()
	again := earlyAlarm(cloneChain(suffix))
	again[0].CollectorSeq, again[0].Time = 9, at("2026-10-26T16:30:00Z")
	again[1].Config.ReadSeq, again[1].Time = 9, at("2026-10-26T16:30:05Z")
	again[1].Config.UnchangedReadSeq, again[1].Config.UnchangedAt = 8, "2026-10-26T15:00:00Z"
	since(suffix[3], 9, "2026-10-26T16:30:00Z")
	still("alarm after the latest acknowledgement", VerifyConfig(join(prefix, aToBToA(testAsset, 40), again, suffix)))

	// An event-kind acknowledgement ends no configuration alarm.
	prefix, suffix = late()
	still("event-kind acknowledgement", VerifyConfig(join(prefix, ackChain(), suffix)))

	// A denied acknowledgement moves nothing: neither the alarm nor the
	// baseline.
	prefix, suffix = late()
	denied := join(
		ackRun(testAsset, 40, authz.BaselineConfiguration, testSnapshot, testBaseline, OutcomeDenied),
		ackRun(testAsset, 41, authz.BaselineConfiguration, testBaseline, testSnapshot, OutcomeDenied))
	still("denied acknowledgements", VerifyConfig(join(prefix, denied, suffix)))

	// The acknowledgement that ended the alarm also moved the baseline: B
	// stays active when the return to A is refused, so a detection against
	// A names a baseline that is no longer acknowledged.
	prefix, suffix = late()
	stuck := join(ackRun(testAsset, 40, authz.BaselineConfiguration, testSnapshot, testBaseline, OutcomeSucceeded),
		ackRun(testAsset, 41, authz.BaselineConfiguration, testBaseline, testSnapshot, OutcomeDenied))
	if err := VerifyConfig(join(prefix, stuck, suffix)); !errors.Is(err, ErrChainBroken) ||
		!strings.Contains(err.Error(), "acknowledged configuration baseline is "+testSnapshot) {
		t.Errorf("baseline moved by the first acknowledgement: got %v", err)
	}

	// An acknowledgement of one asset ends no alarm of another.
	prefix, suffix = late()
	prefix2, suffix2 := late()
	prefix2, suffix2 = shifted(prefix2, other), shifted(suffix2, other)
	if err := VerifyConfig(join(prefix2, aToBToA(other, 140), suffix2)); err != nil {
		t.Fatalf("the other asset's own chain: %v", err)
	}
	still("acknowledgement of another asset", VerifyConfig(join(prefix2, prefix, aToBToA(testAsset, 40), suffix, suffix2)))
}
