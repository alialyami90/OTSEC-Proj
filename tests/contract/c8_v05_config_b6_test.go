package contract

// C8 0.5 (#250, B3; contracts/audit/config.go): B6's own cases for V-M2,
// "a configuration change without a prior approval raises an alarm, and an
// approval silences only the alarm". Each V-M2 case of the GT-INJ
// configuration series (tests/integration/gt_inj/config.json) is written
// here as the chain the node would leave, and VerifyConfig must accept the
// approved case and refuse every chain in which an approval silences a
// change it does not cover. Expected outcomes come from V-M2's text and
// D4-9, not from B3's tests or goldens.
//
// Ground truth: independent (V-M2's pass rule, B1's D4-9 ruling that a
// refused approval covers nothing). Evidence class: desk; the digests are
// SHA-256 of fixed texts, the times invented.

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/audit"
	"otsec.local/otsec/contracts/authz"
)

const (
	vm2Node   = "site-a-node1"
	vm2Asset  = "4c1d9e2a-7b3f-4e8a-9d10-2f6b8c4a1e57"
	vm2Other  = "8e2f0a3b-1c4d-4f5e-8a6b-7c9d0e1f2a3b"
	vm2Person = "alice"
	vm2Other2 = "mallory"
)

func vm2Digest(s string) string {
	sum := sha256.Sum256([]byte(s))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func vm2Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

var (
	vm2BaseA = vm2Digest("b6 baseline A")
	vm2BaseB = vm2Digest("b6 baseline B, never acknowledged")
	vm2Snap  = vm2Digest("b6 snapshot after the change")
	vm2Diff  = vm2Digest("b6 difference")
)

// vm2Chain builds records in order, numbering them from 1.
type vm2Chain struct{ recs []*audit.Record }

func (c *vm2Chain) add(r *audit.Record) *audit.Record {
	r.NodeID = vm2Node
	r.Seq = uint64(len(c.recs) + 1)
	c.recs = append(c.recs, r)
	return r
}

// accept is the collector's allowed decision on a signed admin request.
func (c *vm2Chain) accept(seq uint64, principal, payload string, kind authz.RequestKind) {
	c.add(&audit.Record{Action: audit.ActionCollectorRequest, Outcome: audit.OutcomeAllowed, CollectorSeq: seq,
		Actor:    audit.Actor{Type: authz.PrincipalHuman, ID: principal},
		Verified: &audit.Admin{AdminKeyID: "b6-key", Principal: principal, Nonce: payload, PayloadSHA256: vm2Hex(payload), Kind: kind}})
}

// read is the collector's allowed decision on a configuration read.
func (c *vm2Chain) read(seq uint64, asset string) {
	c.add(&audit.Record{Action: audit.ActionCollectorRequest, Outcome: audit.OutcomeAllowed, CollectorSeq: seq,
		Actor: audit.Actor{Type: authz.PrincipalNode, ID: vm2Node}, OperationID: "sel.config.read_all",
		Target: &audit.Target{AssetID: asset}})
}

func (c *vm2Chain) ack(decision uint64, principal, payload, asset, baseline string) {
	c.add(&audit.Record{Action: audit.ActionConfigBaselineAcknowledge, Outcome: audit.OutcomeSucceeded,
		Actor: audit.Actor{Type: authz.PrincipalHuman, ID: principal}, Target: &audit.Target{AssetID: asset},
		CorrelationID: "ack-" + payload,
		Config: &audit.Config{DecisionSeq: decision, PayloadSHA256: vm2Hex(payload), Kind: authz.BaselineConfiguration,
			BaselineDigest: baseline}})
}

func (c *vm2Chain) approve(decision uint64, principal, payload, asset, baseline, start, end string) {
	c.add(&audit.Record{Action: audit.ActionConfigChangeApproved, Outcome: audit.OutcomeSucceeded,
		Actor: audit.Actor{Type: authz.PrincipalHuman, ID: principal}, Target: &audit.Target{AssetID: asset},
		CorrelationID: "approve-" + payload,
		Config: &audit.Config{DecisionSeq: decision, PayloadSHA256: vm2Hex(payload), BaselineDigest: baseline,
			WindowStart: start, WindowEnd: end, Reason: "b6 test window"}})
}

func (c *vm2Chain) detect(readSeq uint64, asset, baseline, at, unchanged string, approval uint64) {
	r := &audit.Record{Action: audit.ActionConfigChangeDetected, Outcome: audit.OutcomeWarning,
		ReasonCode: audit.ReasonUnapprovedChange, Time: audit.Time{UTC: at},
		Actor: audit.Actor{Type: authz.PrincipalNode, ID: vm2Node}, Target: &audit.Target{AssetID: asset},
		CorrelationID: "detect-" + at,
		Config: &audit.Config{BaselineDigest: baseline, SnapshotDigest: vm2Snap, DifferenceDigest: vm2Diff,
			ReadSeq: readSeq, UnchangedAt: unchanged, ApprovalSeq: approval}}
	if approval != 0 {
		r.Outcome, r.ReasonCode = audit.OutcomeInfo, audit.ReasonApprovedChange
	}
	c.add(r)
}

func (c *vm2Chain) reset() {
	c.add(&audit.Record{Action: audit.ActionCollectorSeqReset, Outcome: audit.OutcomeSucceeded,
		Actor: audit.Actor{Type: authz.PrincipalNode, ID: vm2Node}})
}

// The GT-INJ timeline in real times: R0 the baseline read at 09:00, its
// acknowledgement, Rm at 09:01:45 still finding the baseline, the change,
// R1 at 09:03 finding it (tests/integration/gt_inj/config.json).
const (
	vm2R0   = "2026-11-02T09:00:00Z"
	vm2Rm   = "2026-11-02T09:01:45Z"
	vm2R1   = "2026-11-02T09:03:00Z"
	vm2Open = "2026-11-02T09:01:30Z" // an approval window start, before Rm
	vm2End  = "2026-11-02T09:10:00Z"
)

// base is R0 and its acknowledgement, then Rm: collector decisions 1 to 3.
func vm2Base() *vm2Chain {
	c := &vm2Chain{}
	c.read(1, vm2Asset)
	c.accept(2, vm2Person, "ack A", authz.KindNodeBaselineAck)
	c.ack(2, vm2Person, "ack A", vm2Asset, vm2BaseA)
	c.read(3, vm2Asset)
	return c
}

func TestC8V05B6VM2Cases(t *testing.T) {
	cases := []struct {
		name  string
		build func(c *vm2Chain)
		want  string // "" accepts; otherwise the refusal names it
	}{
		{"approved in its window: the approval silences the alarm", func(c *vm2Chain) {
			c.accept(4, vm2Person, "approve 1", authz.KindNodeChangeApproval)
			c.approve(4, vm2Person, "approve 1", vm2Asset, vm2BaseA, vm2Open, vm2End)
			c.read(5, vm2Asset)
			c.detect(5, vm2Asset, vm2BaseA, vm2R1, vm2Rm, 4)
		}, ""},
		{"no approval: the alarm stands", func(c *vm2Chain) {
			c.read(5, vm2Asset)
			c.detect(5, vm2Asset, vm2BaseA, vm2R1, vm2Rm, 0)
		}, ""},
		{"no approval, but the detection claims one", func(c *vm2Chain) {
			c.read(5, vm2Asset)
			c.detect(5, vm2Asset, vm2BaseA, vm2R1, vm2Rm, 4)
		}, "not an earlier succeeded approval"},
		{"an approval for another device", func(c *vm2Chain) {
			c.accept(4, vm2Person, "approve other", authz.KindNodeChangeApproval)
			c.approve(4, vm2Person, "approve other", vm2Other, vm2BaseA, vm2Open, vm2End)
			c.read(5, vm2Asset)
			c.detect(5, vm2Asset, vm2BaseA, vm2R1, vm2Rm, 4)
		}, "another node or asset"},
		{"an approval whose window ended before Rm", func(c *vm2Chain) {
			c.accept(4, vm2Person, "approve ended", authz.KindNodeChangeApproval)
			c.approve(4, vm2Person, "approve ended", vm2Asset, vm2BaseA, "2026-11-02T08:50:00Z", "2026-11-02T09:01:40Z")
			c.read(5, vm2Asset)
			c.detect(5, vm2Asset, vm2BaseA, vm2R1, vm2Rm, 4)
		}, "window does not overlap"},
		{"backdated: accepted after the read that found the change", func(c *vm2Chain) {
			c.read(4, vm2Asset)
			c.accept(5, vm2Person, "approve late", authz.KindNodeChangeApproval)
			c.approve(5, vm2Person, "approve late", vm2Asset, vm2BaseA, "2026-11-02T08:00:00Z", vm2End)
			c.detect(4, vm2Asset, vm2BaseA, vm2R1, vm2Rm, 5)
		}, "not accepted before the read"},
		{"a non-approver: the collector refused, so no acceptance exists", func(c *vm2Chain) {
			c.add(&audit.Record{Action: audit.ActionCollectorRequest, Outcome: audit.OutcomeDenied, CollectorSeq: 4,
				ReasonCode: "admin_unverified", Actor: audit.Actor{Type: authz.PrincipalHuman, ID: vm2Other2}})
			c.approve(4, vm2Other2, "approve refused", vm2Asset, vm2BaseA, vm2Open, vm2End)
			c.read(5, vm2Asset)
			c.detect(5, vm2Asset, vm2BaseA, vm2R1, vm2Rm, 4)
		}, "no earlier acceptance"},
		{"an approval written as another person than the one verified", func(c *vm2Chain) {
			c.accept(4, vm2Person, "approve 1", authz.KindNodeChangeApproval)
			c.approve(4, vm2Other2, "approve 1", vm2Asset, vm2BaseA, vm2Open, vm2End)
			c.read(5, vm2Asset)
			c.detect(5, vm2Asset, vm2BaseA, vm2R1, vm2Rm, 4)
		}, "does not match the acceptance"},
		{"a baseline acknowledgement's acceptance used as an approval", func(c *vm2Chain) {
			c.accept(4, vm2Person, "ack again", authz.KindNodeBaselineAck)
			c.approve(4, vm2Person, "ack again", vm2Asset, vm2BaseA, vm2Open, vm2End)
			c.read(5, vm2Asset)
			c.detect(5, vm2Asset, vm2BaseA, vm2R1, vm2Rm, 4)
		}, "not node.change_approval"},
		{"an approval from before a collector reinstall", func(c *vm2Chain) {
			c.accept(4, vm2Person, "approve 1", authz.KindNodeChangeApproval)
			c.approve(4, vm2Person, "approve 1", vm2Asset, vm2BaseA, vm2Open, vm2End)
			c.reset()
			c.read(5, vm2Asset)
			c.detect(5, vm2Asset, vm2BaseA, vm2R1, vm2Rm, 4)
		}, "not an earlier succeeded approval in its epoch"},
		// The late-approval rule: an alarm is not silenced by an approval
		// accepted after it, while the configuration stays changed.
		{"an approval accepted after the alarm, the change never undone", func(c *vm2Chain) {
			c.read(4, vm2Asset)
			c.detect(4, vm2Asset, vm2BaseA, vm2R1, vm2Rm, 0)
			c.accept(5, vm2Person, "approve after", authz.KindNodeChangeApproval)
			c.approve(5, vm2Person, "approve after", vm2Asset, vm2BaseA, "2026-11-02T08:00:00Z", "2026-11-02T12:00:00Z")
			c.read(6, vm2Asset)
			c.detect(6, vm2Asset, vm2BaseA, "2026-11-02T09:30:00Z", vm2Rm, 5)
		}, "not seen equal to baseline"},
	}
	for _, tc := range cases {
		c := vm2Base()
		tc.build(c)
		err := audit.VerifyConfig(c.recs)
		switch {
		case tc.want == "" && err != nil:
			t.Errorf("%s: refused: %v", tc.name, err)
		case tc.want != "" && err == nil:
			t.Errorf("%s: accepted", tc.name)
		case tc.want != "" && !strings.Contains(err.Error(), tc.want):
			t.Errorf("%s: refused for another reason: %v", tc.name, err)
		}
	}
}

// Finding 1 on #250: unchanged_at is the node's word. The late-approval
// rule and the window overlap both rest on it, but nothing ties it to a
// read in the chain. Here the alarm stands, an approval is accepted after
// it, the configuration is never read again unchanged, and the next
// detection claims an unchanged_at after the alarm: the alarm is silenced.
func TestC8V05B6UnchangedAtIsARecordedRead(t *testing.T) {
	c := vm2Base()
	c.read(4, vm2Asset)
	c.detect(4, vm2Asset, vm2BaseA, vm2R1, vm2Rm, 0)
	c.accept(5, vm2Person, "approve after", authz.KindNodeChangeApproval)
	c.approve(5, vm2Person, "approve after", vm2Asset, vm2BaseA, "2026-11-02T08:00:00Z", "2026-11-02T12:00:00Z")
	c.read(6, vm2Asset)
	// No read between the alarm (decision 4) and this one (6) found the
	// baseline; the node claims one at 09:20.
	c.detect(6, vm2Asset, vm2BaseA, "2026-11-02T09:30:00Z", "2026-11-02T09:20:00Z", 5)
	if err := audit.VerifyConfig(c.recs); err == nil {
		t.Error("an approval accepted after the alarm silenced it, on an unchanged_at no recorded read supports")
	}
}

// Finding 2 on #250: a detection names its baseline, but nothing ties that
// baseline to an acknowledgement. Here the only acknowledged baseline is
// A; the node compares against B, which no person acknowledged, and an
// approval against B silences the change.
func TestC8V05B6BaselineIsAcknowledged(t *testing.T) {
	for _, approved := range []bool{false, true} {
		c := vm2Base()
		var seq uint64
		if approved {
			c.accept(4, vm2Person, "approve B", authz.KindNodeChangeApproval)
			c.approve(4, vm2Person, "approve B", vm2Asset, vm2BaseB, vm2Open, vm2End)
			seq = 4
		}
		c.read(5, vm2Asset)
		c.detect(5, vm2Asset, vm2BaseB, vm2R1, vm2Rm, seq)
		if err := audit.VerifyConfig(c.recs); err == nil {
			t.Errorf("approved %v: a detection against a baseline no one acknowledged was accepted", approved)
		} else if !strings.Contains(err.Error(), "baseline") {
			t.Errorf("approved %v: refused, but not for the baseline: %v", approved, err)
		}
	}
}
