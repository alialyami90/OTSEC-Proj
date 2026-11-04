package collector

import (
	"context"
	"testing"
	"time"

	"otsec.local/otsec/contracts/authz"
)

// The collector's side of the two configuration kinds (C7 0.6, D4-40): a
// key allowed them gets an acceptance numbered like any decision, an asset
// the collector does not collect from is refused after the nonce is spent,
// and a key without them is refused at authority, numbered, with its nonce
// unspent.

const testBaselineDigest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"

// withAdminKinds pins the test key with a list of kinds.
func withAdminKinds(kinds ...authz.RequestKind) pipeOption {
	return func(c *PipelineConfig, _ *pipeFixture) {
		for i := range c.AdminKeys {
			c.AdminKeys[i].Kinds = kinds
		}
	}
}

var configKinds = []authz.RequestKind{authz.KindNodeChangeApproval, authz.KindNodeBaselineAck}

// configRequest is a signed configuration kind for assetID, with an approval
// window of [start, end) from the fixture's clock. It returns the payload's
// nonce too.
func (f *pipeFixture) configRequest(t *testing.T, kind authz.RequestKind, assetID string, start, end time.Duration) (*authz.CollectorRequest, string) {
	t.Helper()
	req := &authz.CollectorRequest{Contract: authz.ContractID, Kind: kind, RequestID: "req-" + string(kind),
		OnBehalfOf: pipeAdmin, PolicyVersion: policyVersion}
	p := f.adminPayload(t, req)
	now := f.clock.now().UTC().Truncate(time.Second)
	switch kind {
	case authz.KindNodeChangeApproval:
		p.NodeChangeApproval = &authz.NodeChangeApprovalBody{AssetID: assetID, BaselineDigest: testBaselineDigest,
			WindowStart: now.Add(start).Format(time.RFC3339), WindowEnd: now.Add(end).Format(time.RFC3339), Reason: "relay firmware update"}
	case authz.KindNodeBaselineAck:
		p.NodeBaselineAck = &authz.NodeBaselineAckBody{AssetID: assetID, Kind: authz.BaselineEvent, BaselineDigest: testBaselineDigest}
	}
	return f.signPayload(t, req, p), p.Nonce
}

func (f *pipeFixture) nonceSpent(t *testing.T, nonce string) bool {
	t.Helper()
	_, ok := f.reopenState(t).doc.AdminNonces[nonce]
	return ok
}

func TestConfigKindsAccepted(t *testing.T) {
	for _, kind := range configKinds {
		t.Run(string(kind), func(t *testing.T) {
			// The list replaces the 0.5 defaults, so it names install too.
			f := newPipeline(t, withAdminKinds(append([]authz.RequestKind{authz.KindCredentialInstall}, configKinds...)...))
			f.installCanary(t)
			// A run decided first: an approval numbered after it cannot
			// cover what that run reads (C8 ApprovalCovers).
			run, _ := f.run(t, pipeRun("sel.ser.read_all", pipeCred))
			req, nonce := f.configRequest(t, kind, testAsset, -time.Minute, time.Hour)
			reply, work := f.pipe.Handle(context.Background(), req)
			switch {
			case !reply.Accepted() || work != nil:
				t.Fatalf("reply %+v, work %v", reply, work != nil)
			case reply.CollectorSeq <= run.CollectorSeq:
				t.Fatalf("collector_seq %d is not above the earlier run's %d", reply.CollectorSeq, run.CollectorSeq)
			case !f.nonceSpent(t, nonce):
				t.Fatal("the nonce is not spent")
			}
			a, err := reply.AdminAcceptance(req)
			if err != nil || a.Principal != pipeAdmin || a.Nonce != nonce {
				t.Fatalf("acceptance %+v: %v", a, err)
			}
			// The exact bytes again: the repeat answer, which names the
			// first decision and runs nothing.
			again, _ := f.pipe.Handle(context.Background(), req)
			if !again.Accepted() || again.RepeatOf != reply.CollectorSeq || again.CollectorSeq <= reply.CollectorSeq {
				t.Fatalf("resend %+v", again)
			}
		})
	}
}

func TestConfigKindsRefused(t *testing.T) {
	const otherAsset = "9c1e2f30-4b5a-4c6d-8e7f-0a1b2c3d4e5f"
	for _, kind := range configKinds {
		t.Run(string(kind), func(t *testing.T) {
			// A key pinned with no list keeps the 0.5 kinds: refused at
			// authority, numbered, and its nonce not spent (D4-2).
			f := newPipeline(t)
			req, nonce := f.configRequest(t, kind, testAsset, -time.Minute, time.Hour)
			reply, _ := f.pipe.Handle(context.Background(), req)
			if refusalOf(reply) != authz.RefuseAdminUnverified || adminCheckOf(reply) != authz.AdminCheckAuthority || reply.CollectorSeq == 0 || f.nonceSpent(t, nonce) {
				t.Fatalf("a key without the kind: %+v, nonce spent %v", reply, f.nonceSpent(t, nonce))
			}
			// So is a key whose list names other kinds.
			f = newPipeline(t, withAdminKinds(authz.KindCredentialInstall))
			req, _ = f.configRequest(t, kind, testAsset, -time.Minute, time.Hour)
			if reply, _ := f.pipe.Handle(context.Background(), req); adminCheckOf(reply) != authz.AdminCheckAuthority {
				t.Fatalf("a key listing other kinds: %+v", reply)
			}

			// An asset the collector does not collect from: refused only
			// after the nonce is spent, so a resend is a replay.
			f = newPipeline(t, withAdminKinds(configKinds...))
			req, nonce = f.configRequest(t, kind, otherAsset, -time.Minute, time.Hour)
			reply, _ = f.pipe.Handle(context.Background(), req)
			if refusalOf(reply) != authz.RefuseAssetNotEnrolled || reply.CollectorSeq == 0 || !f.nonceSpent(t, nonce) {
				t.Fatalf("an asset not enrolled: %+v", reply)
			}
			if again, _ := f.pipe.Handle(context.Background(), req); adminCheckOf(again) != authz.AdminCheckReplay {
				t.Fatalf("resend of a refused request: %+v", again)
			}
		})
	}
}

// TestChangeApprovalWindow: the approval's window is judged at the
// collector's clock. One that has ended, or starts more than
// MaxApprovalLead ahead, is refused at window with its nonce unspent; one
// that starts later but within the lead is accepted.
func TestChangeApprovalWindow(t *testing.T) {
	for name, c := range map[string]struct {
		start, end time.Duration
		ok         bool
	}{
		"ended":                   {-2 * time.Hour, -time.Hour, false},
		"starts past the lead":    {authz.MaxApprovalLead + time.Hour, authz.MaxApprovalLead + 2*time.Hour, false},
		"starts later, within it": {authz.MaxApprovalLead - time.Hour, authz.MaxApprovalLead, true},
		"open now":                {-time.Minute, 4 * time.Hour, true},
		"longer than the most":    {0, authz.MaxApprovalWindow + time.Second, false},
	} {
		t.Run(name, func(t *testing.T) {
			f := newPipeline(t, withAdminKinds(configKinds...))
			req, nonce := f.configRequest(t, authz.KindNodeChangeApproval, testAsset, c.start, c.end)
			reply, _ := f.pipe.Handle(context.Background(), req)
			if reply.Accepted() != c.ok || reply.CollectorSeq == 0 || f.nonceSpent(t, nonce) != c.ok {
				t.Fatalf("reply %+v, nonce spent %v", reply, f.nonceSpent(t, nonce))
			}
			if !c.ok && refusalOf(reply) != authz.RefuseAdminUnverified {
				t.Fatalf("refusal %+v", reply.Refusal)
			}
		})
	}
}
