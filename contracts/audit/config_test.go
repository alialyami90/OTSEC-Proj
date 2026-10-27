package audit

import (
	"errors"
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
		ReadSeq: 11, UnchangedAt: "2026-10-26T17:00:04Z", ApprovalSeq: 10}

	return []*Record{&accept, &approved, &read, &detected}
}

// earlyAlarm is an earlier read (decision 8) of the same asset and the
// unapproved difference it found at 15:00:05, before configChain's approval.
func earlyAlarm(recs []*Record) []*Record {
	read, alarm := *recs[2], *recs[3]
	readTarget, cfg := *read.Target, *alarm.Config
	read.Target, read.Seq, read.CollectorSeq, read.Time, read.CorrelationID = &readTarget, 18, 8, at("2026-10-26T15:00:00Z"), "req-20261026-0005"
	alarm.Config, alarm.Seq, alarm.Time = &cfg, 19, at("2026-10-26T15:00:05Z")
	alarm.Outcome, alarm.ReasonCode = OutcomeWarning, ReasonUnapprovedChange
	cfg.ReadSeq, cfg.ApprovalSeq, cfg.UnchangedAt = 8, 0, "2026-10-26T14:00:00Z"
	return []*Record{&read, &alarm}
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
	if err := VerifyConfig(recs); err != nil {
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
		"detection by a person":            {3, func(r *Record) { r.Actor = adminActor }},
		"detection with a window":          {3, func(r *Record) { r.Config.WindowStart = "2026-10-26T16:00:00Z" }},
		"detection with a decision":        {3, func(r *Record) { r.Config.DecisionSeq = 10 }},
		"detection without snapshot":       {3, func(r *Record) { r.Config.SnapshotDigest = "" }},
		"detection without difference":     {3, func(r *Record) { r.Config.DifferenceDigest = "" }},
		"detection of the baseline":        {3, func(r *Record) { r.Config.SnapshotDigest = testBaseline }},
		"detection without read":           {3, func(r *Record) { r.Config.ReadSeq, r.Config.ApprovalSeq = 0, 0 }},
		"detection approval after read":    {3, func(r *Record) { r.Config.ApprovalSeq = 11 }},
		"detection without unchanged_at":   {3, func(r *Record) { r.Config.UnchangedAt = "" }},
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
		"approval refused by the node": {1, func(r *Record) { r.Outcome, r.ReasonCode = OutcomeDenied, "asset_not_collected" }},
		"configuration baseline acknowledged": {1, func(r *Record) {
			r.Action, r.Config.Kind, r.Config.WindowStart, r.Config.WindowEnd, r.Config.Reason = ActionConfigBaselineAcknowledge, authz.BaselineConfiguration, "", "", ""
		}},
		"event baseline refused": {1, func(r *Record) {
			r.Action, r.Outcome, r.ReasonCode = ActionConfigBaselineAcknowledge, OutcomeDenied, "baseline_not_held"
			r.Config.Kind, r.Config.WindowStart, r.Config.WindowEnd, r.Config.Reason = authz.BaselineEvent, "", "", ""
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
			a.Config.WindowStart, a.Config.WindowEnd = "2026-10-26T13:00:04Z", "2026-10-26T17:00:04Z"
		}, false},
		"window ends just after it": {func(a, d *Record) {
			a.Config.WindowStart, a.Config.WindowEnd = "2026-10-26T13:00:05Z", "2026-10-26T17:00:05Z"
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
	cases := map[string]func(recs []*Record) []*Record{
		"no acceptance": func(recs []*Record) []*Record { return recs[1:] },
		"acceptance after the approval": func(recs []*Record) []*Record {
			return []*Record{recs[1], recs[0], recs[2], recs[3]}
		},
		"acceptance of another kind": func(recs []*Record) []*Record {
			recs[0].Verified.Kind = authz.KindCredentialRevoke
			return recs
		},
		"acceptance without a kind": func(recs []*Record) []*Record {
			recs[0].Verified.Kind = ""
			return recs
		},
		"acceptance of other bytes": func(recs []*Record) []*Record {
			recs[1].Config.PayloadSHA256 = strings.Repeat("ab", 32)
			return recs
		},
		"approval by another person": func(recs []*Record) []*Record {
			recs[1].Actor = Actor{Type: authz.PrincipalHuman, ID: "bob@site-a", Role: authz.RoleAdmin}
			return recs
		},
		"ack following an approval's acceptance": func(recs []*Record) []*Record {
			r := recs[1]
			r.Action, r.Config.Kind, r.Config.WindowStart, r.Config.WindowEnd, r.Config.Reason = ActionConfigBaselineAcknowledge, authz.BaselineConfiguration, "", "", ""
			return recs
		},
		"a collector reset between approval and read": func(recs []*Record) []*Record {
			return []*Record{recs[0], recs[1], reset, recs[2], recs[3]}
		},
		"no read decision": func(recs []*Record) []*Record { return []*Record{recs[0], recs[1], recs[3]} },
		"read of another asset": func(recs []*Record) []*Record {
			recs[2].Target.AssetID = "3c8e5f21-9d4a-4b6c-8f32-8d5a1e7b9c24"
			return recs
		},
		"approval refused by the node": func(recs []*Record) []*Record {
			recs[1].Outcome, recs[1].ReasonCode = OutcomeDenied, "asset_not_collected"
			return recs
		},
		"approval_seq names no approval": func(recs []*Record) []*Record {
			recs[3].Config.ApprovalSeq = 9
			return recs
		},
		"approval that does not cover": func(recs []*Record) []*Record {
			recs[1].Config.WindowStart, recs[1].Config.WindowEnd = "2026-10-26T19:00:00Z", "2026-10-26T20:00:00Z"
			return recs
		},
		// An approval accepted after a change was found unapproved never
		// silences it, though a later read records it again (P4-A3, V-M2).
		"late approval for a change already found": func(recs []*Record) []*Record {
			early := earlyAlarm(recs)
			recs[3].Config.UnchangedAt = "2026-10-26T14:00:00Z"
			return append(early, recs...)
		},
		"late approval, unchanged at the alarm itself": func(recs []*Record) []*Record {
			early := earlyAlarm(recs)
			recs[3].Config.UnchangedAt = "2026-10-26T15:00:05Z"
			return append(early, recs...)
		},
	}
	for name, mut := range cases {
		recs := mut(cloneChain(configChain()))
		if err := VerifyConfig(recs); !errors.Is(err, ErrChainBroken) {
			t.Errorf("%s: got %v", name, err)
		}
	}
	// A repeat answer stands for the first decision when the first reply was
	// lost, and the same reset rule holds after it.
	recs := cloneChain(configChain())
	recs[0].RepeatOf, recs[0].CollectorSeq = 10, 12
	recs[2].CollectorSeq, recs[3].Config.ReadSeq = 13, 13
	if err := VerifyConfig(recs); err != nil {
		t.Fatalf("repeat answer: %v", err)
	}
	// After the alarm the configuration was seen equal to the baseline
	// again (unchanged_at after it), so a new change may be approved.
	recs = cloneChain(configChain())
	if err := VerifyConfig(append(earlyAlarm(recs), recs...)); err != nil {
		t.Fatalf("approved change after a return to the baseline: %v", err)
	}
	// An unapproved difference needs nothing but its read.
	recs = cloneChain(configChain())
	recs[3].Outcome, recs[3].ReasonCode, recs[3].Config.ApprovalSeq = OutcomeWarning, ReasonUnapprovedChange, 0
	if err := VerifyConfig(recs[2:]); err != nil {
		t.Fatalf("unapproved difference: %v", err)
	}
}
