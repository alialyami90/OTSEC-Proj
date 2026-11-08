package collector

import (
	"context"
	"encoding/json"
	"testing"

	"otsec.local/otsec/contracts/authz"
)

// The collector's side of node.network_baseline_ack (C7 0.10, D4-68): it is
// accepted with no asset or sensor check, numbered, and every accepted 0.10
// admin reply names the pinned keys and their digest. A key whose list does
// not name the kind is refused at authority, and a 0.9 request cannot ask
// for it.

const testDraftDigest = "sha256:2222222222222222222222222222222222222222222222222222222222222222"

func (f *pipeFixture) networkAck(t *testing.T, contract string) *authz.CollectorRequest {
	t.Helper()
	req := &authz.CollectorRequest{Contract: contract, Kind: authz.KindNodeNetworkBaselineAck, RequestID: "req-network-ack",
		OnBehalfOf: pipeAdmin, PolicyVersion: policyVersion}
	p := f.adminPayload(t, req)
	// A sensor the collector knows nothing of: the node checks it.
	p.NodeNetworkBaselineAck = &authz.NodeNetworkBaselineAckBody{SensorID: "5a1f0c3e-2b4d-4e6f-8a9b-0c1d2e3f4a5b",
		DraftDigest: testDraftDigest, BaselineDigest: testBaselineDigest}
	return f.signPayload(t, req, p)
}

func TestNetworkAckAccepted(t *testing.T) {
	f := newPipeline(t, withAdminKinds(authz.KindNodeNetworkBaselineAck))
	req := f.networkAck(t, authz.ContractID)
	reply, work := f.pipe.Handle(context.Background(), req)
	if !reply.Accepted() || work != nil || reply.CollectorSeq == 0 {
		t.Fatalf("reply %+v, work %v", reply, work != nil)
	}
	a, err := reply.AdminAcceptance(req)
	if err != nil {
		t.Fatal(err)
	}
	want := authz.AdminKeyEntries(f.pipe.cfg.AdminKeys)
	if a.KeysDigest != authz.AdminKeysDigest(want) || len(a.Keys) != len(want) {
		t.Fatalf("keys %+v, digest %s", a.Keys, a.KeysDigest)
	}
	// The repeat answer names the keys too.
	again, _ := f.pipe.Handle(context.Background(), req)
	if !again.Accepted() || again.RepeatOf != reply.CollectorSeq || again.Admin == nil || again.Admin.KeysDigest != a.KeysDigest {
		t.Fatalf("resend %+v", again)
	}
	// The reply goes on the wire and validates there.
	b, err := json.Marshal(reply)
	if err != nil {
		t.Fatal(err)
	}
	var back authz.CollectorReply
	if err := json.Unmarshal(b, &back); err != nil || back.Validate() != nil {
		t.Fatalf("round trip: %v %v", err, back.Validate())
	}
}

func TestNetworkAckRefused(t *testing.T) {
	for name, kinds := range map[string][]authz.RequestKind{
		"no list":                nil,
		"only node.baseline_ack": {authz.KindNodeBaselineAck},
	} {
		t.Run(name, func(t *testing.T) {
			var f *pipeFixture
			if kinds == nil {
				f = newPipeline(t)
			} else {
				f = newPipeline(t, withAdminKinds(kinds...))
			}
			reply, _ := f.pipe.Handle(context.Background(), f.networkAck(t, authz.ContractID))
			if refusalOf(reply) != authz.RefuseAdminUnverified || adminCheckOf(reply) != authz.AdminCheckAuthority || reply.CollectorSeq == 0 {
				t.Fatalf("%+v", reply)
			}
		})
	}
	// Stamped 0.9, the request cannot ask for the kind.
	f := newPipeline(t, withAdminKinds(authz.KindNodeNetworkBaselineAck))
	req := f.networkAck(t, "otsec.authz/0.9")
	b, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authz.DecodeRequest(b); err == nil {
		t.Fatal("a 0.9 request for the kind decoded")
	}
}

// A 0.9 request's acceptance carries no keys: a 0.9 node decodes replies
// strictly.
func TestKeysOnlyFor010(t *testing.T) {
	f := newPipeline(t, withAdminKinds(authz.KindNodeBaselineAck))
	req := &authz.CollectorRequest{Contract: "otsec.authz/0.9", Kind: authz.KindNodeBaselineAck, RequestID: "req-ack-0.9",
		OnBehalfOf: pipeAdmin, PolicyVersion: policyVersion}
	p := f.adminPayload(t, req)
	p.NodeBaselineAck = &authz.NodeBaselineAckBody{AssetID: testAsset, Kind: authz.BaselineEvent, BaselineDigest: testBaselineDigest}
	req = f.signPayload(t, req, p)
	reply, _ := f.pipe.Handle(context.Background(), req)
	if !reply.Accepted() || reply.Admin == nil || reply.Admin.KeysDigest != "" || reply.Admin.Keys != nil {
		t.Fatalf("%+v", reply)
	}
}
