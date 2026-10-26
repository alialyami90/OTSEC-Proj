package collector

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"otsec.local/otsec/contracts/adapter"
	"otsec.local/otsec/contracts/authz"
)

// testManifestSHA256 is the SHA-256 of "otsec test quarantine manifest",
// as in the contract's tests; no manifest has it. The collector only
// carries it.
const testManifestSHA256 = "47468d8ca5f3ebb058dc452f3669a7ed64c69b953a20294801b75147fd43f636"

// stamped returns a copy of req with its contract stamp changed. The stamp
// is outside the signed payload.
func stamped(req *authz.CollectorRequest, contract string) *authz.CollectorRequest {
	out := *req
	out.Contract = contract
	return &out
}

// nodeRequest is a signed node kind: the body exists only in the payload.
func (f *pipeFixture) nodeRequest(t *testing.T, kind authz.RequestKind) *authz.CollectorRequest {
	t.Helper()
	req := &authz.CollectorRequest{Contract: authz.ContractID, Kind: kind, RequestID: "req-" + string(kind),
		OnBehalfOf: pipeAdmin, PolicyVersion: policyVersion}
	p := f.adminPayload(t, req)
	switch kind {
	case authz.KindNodeQuarantineClear:
		p.NodeQuarantineClear = &authz.NodeQuarantineClearBody{AssetID: testAsset, ManifestSHA256: testManifestSHA256}
	case authz.KindNodeSeqResetAck:
		p.NodeSeqResetAck = &authz.NodeSeqResetAckBody{}
	}
	return f.signPayload(t, req, p)
}

// snapshot is what a decision could change: the state file without its
// collector_seq, and the credential store's file.
func (f *pipeFixture) snapshot(t *testing.T) []byte {
	t.Helper()
	doc := f.reopenState(t).doc
	doc.CollectorSeq = 0
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	creds, err := os.ReadFile(f.path)
	if err != nil {
		t.Fatal(err)
	}
	return append(append(b, 0), creds...)
}

// TestAdminRepeat (C7 0.5, A1 on #184): for every admin kind, the same
// signed request sent again gets the repeat answer: accepted, a fresh
// collector_seq above the first, repeat_of naming the first decision, and
// the same admin acceptance. The repeat runs nothing: where the action
// could run again, the state is first put back so that it would show, and
// the repeat leaves it so; otherwise nothing but collector_seq changes.
func TestAdminRepeat(t *testing.T) {
	type tc struct {
		setup func(t *testing.T) *pipeFixture
		req   func(t *testing.T, f *pipeFixture) *authz.CollectorRequest
		// undo puts back what the first decision did, where a re-run
		// would do it again; check then shows the repeat left it undone.
		undo  func(t *testing.T, f *pipeFixture)
		check func(t *testing.T, f *pipeFixture)
	}
	installed := func(t *testing.T) *pipeFixture {
		f := newPipeline(t)
		f.installCanary(t)
		return f
	}
	credSuspended := func(t *testing.T) *pipeFixture {
		f := installed(t)
		if _, _, err := f.store.Suspend(pipeCred, 1, authz.SuspendOperator); err != nil {
			t.Fatal(err)
		}
		return f
	}
	fresh := func(t *testing.T) *pipeFixture { return newPipeline(t) }
	for name, c := range map[string]tc{
		"credential.install": {
			setup: fresh,
			req: func(t *testing.T, f *pipeFixture) *authz.CollectorRequest {
				return installRequest(t, f, pipeRef(1), canary)
			},
		},
		"credential.revoke": {
			setup: installed,
			req: func(t *testing.T, f *pipeFixture) *authz.CollectorRequest {
				return f.signed(t, &authz.CollectorRequest{Contract: authz.ContractID, Kind: authz.KindCredentialRevoke, RequestID: "req-revoke",
					OnBehalfOf: pipeAdmin, PolicyVersion: policyVersion, CredentialRevoke: &authz.CredentialRevokeBody{RefID: pipeCred, Reason: authz.RevokeOperator}})
			},
		},
		"credential.clear_suspension": {
			setup: credSuspended,
			req: func(t *testing.T, f *pipeFixture) *authz.CollectorRequest {
				return f.signed(t, &authz.CollectorRequest{Contract: authz.ContractID, Kind: authz.KindCredentialClearSusp, RequestID: "req-clear",
					OnBehalfOf: pipeAdmin, PolicyVersion: policyVersion, CredentialClearSusp: &authz.CredentialClearSuspBody{RefID: pipeCred, Version: 1}})
			},
			undo: func(t *testing.T, f *pipeFixture) {
				if _, _, err := f.store.Suspend(pipeCred, 1, authz.SuspendOperator); err != nil {
					t.Fatal(err)
				}
			},
			check: func(t *testing.T, f *pipeFixture) {
				if st := f.store.Status(pipeCred); st[0].State != authz.CredentialSuspended {
					t.Fatalf("the repeat cleared the credential again: %+v", st)
				}
			},
		},
		"asset.clear_suspension": {
			setup: func(t *testing.T) *pipeFixture { return suspendedPipeline(t, nil) },
			req: func(t *testing.T, f *pipeFixture) *authz.CollectorRequest {
				return f.signed(t, &authz.CollectorRequest{Contract: authz.ContractID, Kind: authz.KindAssetClearSusp, RequestID: "req-asset-clear",
					OnBehalfOf: pipeAdmin, PolicyVersion: policyVersion, AssetClearSusp: &authz.AssetClearSuspBody{AssetID: testAsset, Ref: suspendingRun}})
			},
			undo: func(t *testing.T, f *pipeFixture) {
				if err := f.state.SuspendAsset(testAsset, adapter.FailedAuthRejected, suspendingRun); err != nil {
					t.Fatal(err)
				}
			},
			check: func(t *testing.T, f *pipeFixture) {
				if err := f.reopenState(t).CheckSuspended(testAsset); err == nil {
					t.Fatal("the repeat cleared the asset again")
				}
			},
		},
		"node.quarantine_clear": {
			setup: fresh,
			req: func(t *testing.T, f *pipeFixture) *authz.CollectorRequest {
				return f.nodeRequest(t, authz.KindNodeQuarantineClear)
			},
		},
		"node.seq_reset_ack": {
			setup: fresh,
			req: func(t *testing.T, f *pipeFixture) *authz.CollectorRequest {
				return f.nodeRequest(t, authz.KindNodeSeqResetAck)
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := c.setup(t)
			ctx := context.Background()
			req := c.req(t, f)
			first, work := f.pipe.Handle(ctx, req)
			if !first.Accepted() || work != nil || first.RepeatOf != 0 {
				t.Fatalf("first: %+v", first)
			}
			acc, err := first.AdminAcceptance(req)
			if err != nil {
				t.Fatalf("first: %v", err)
			}
			if c.undo != nil {
				c.undo(t, f)
			}
			taken := f.installsTaken(t)
			before := f.snapshot(t)
			last := first.CollectorSeq
			for i := 0; i < 2; i++ {
				p := f.pipe
				if i == 1 {
					p = f.restart(t) // after the first repeat, so it reads its number
				}
				again, work := p.Handle(ctx, req)
				if !again.Accepted() || work != nil || again.RepeatOf != first.CollectorSeq || again.CollectorSeq <= last {
					t.Fatalf("repeat %d: %+v, first %+v", i, again, first)
				}
				last = again.CollectorSeq
				got, err := again.AdminAcceptance(req)
				if err != nil {
					t.Fatalf("repeat %d: %v", i, err)
				}
				if *got != *acc {
					t.Fatalf("repeat %d names %+v, first %+v", i, got, acc)
				}
			}
			if !bytes.Equal(f.snapshot(t), before) {
				t.Fatal("a repeat changed the state or the credential store")
			}
			if f.installsTaken(t) != taken {
				t.Fatal("a repeat spent the install budget")
			}
			if c.check != nil {
				c.check(t, f)
			}
			if a := f.alarmList(); len(a) != 0 {
				t.Fatalf("alarms: %v", a)
			}
		})
	}
}

// TestAdminRepeatOnlyTheSameBytes: only the exact payload accepted is
// repeated. The same nonce on other signed bytes, a request that was
// refused, and a request first sent stamped 0.4 are replays.
func TestAdminRepeatOnlyTheSameBytes(t *testing.T) {
	f := newPipeline(t)
	ctx := context.Background()

	base := &authz.CollectorRequest{Contract: authz.ContractID, Kind: authz.KindNodeSeqResetAck, RequestID: "req-ack",
		OnBehalfOf: pipeAdmin, PolicyVersion: policyVersion}
	p := f.adminPayload(t, base)
	p.NodeSeqResetAck = &authz.NodeSeqResetAckBody{}
	if reply, _ := f.pipe.Handle(ctx, f.signPayload(t, base, p)); !reply.Accepted() {
		t.Fatalf("ack: %+v", reply)
	}
	p.ExpiresAt = f.clock.now().Add(9 * time.Minute).Format(time.RFC3339) // same nonce, other bytes
	reply, _ := f.pipe.Handle(ctx, f.signPayload(t, base, p))
	wantAdminRefusal(t, "same nonce, other payload", reply, authz.AdminCheckReplay)

	rejected := installRequest(t, f, pipeRef(1), []byte("ACC")) // the register refuses this secret
	if reply, _ := f.pipe.Handle(ctx, rejected); refusalOf(reply) != authz.RefuseSecretRejected {
		t.Fatalf("ACC: %+v", reply)
	}
	reply, _ = f.pipe.Handle(ctx, rejected)
	wantAdminRefusal(t, "refused, then resent", reply, authz.AdminCheckReplay)

	old := stamped(installRequest(t, f, pipeRef(1), canary), "otsec.authz/0.4")
	if reply, _ := f.pipe.Handle(ctx, old); !reply.Accepted() || reply.Admin != nil {
		t.Fatalf("0.4 install: %+v", reply)
	}
	reply, _ = f.pipe.Handle(ctx, stamped(old, authz.ContractID))
	wantAdminRefusal(t, "accepted at 0.4, resent at 0.5", reply, authz.AdminCheckReplay)

	if n := len(f.reopenState(t).doc.AdminDecisions); n != 1 {
		t.Fatalf("%d decisions kept, want only the 0.5 acceptance", n)
	}
}

// TestAdminRepeatExpires: the repeat entry lives exactly as long as its
// nonce. Past the request's window the resend is refused for the window,
// and the entry goes when the nonce does.
func TestAdminRepeatExpires(t *testing.T) {
	f := newPipeline(t)
	ctx := context.Background()
	req := f.nodeRequest(t, authz.KindNodeQuarantineClear)
	if reply, _ := f.pipe.Handle(ctx, req); !reply.Accepted() {
		t.Fatalf("first: %+v", reply)
	}
	f.clock.t = f.clock.t.Add(authz.MaxAdminLifetime + time.Minute)
	reply, _ := f.pipe.Handle(ctx, req)
	wantAdminRefusal(t, "expired repeat", reply, authz.AdminCheckWindow)
	if reply, _ := f.pipe.Handle(ctx, f.nodeRequest(t, authz.KindNodeSeqResetAck)); !reply.Accepted() {
		t.Fatalf("next: %+v", reply)
	}
	doc := f.reopenState(t).doc
	if len(doc.AdminNonces) != 1 || len(doc.AdminDecisions) != 1 {
		t.Fatalf("%d nonces and %d decisions kept, want 1 and 1", len(doc.AdminNonces), len(doc.AdminDecisions))
	}
	for n := range doc.AdminDecisions {
		if _, ok := doc.AdminNonces[n]; !ok {
			t.Fatal("a decision outlived its nonce")
		}
	}
}

// TestAdminDecisionsInState: the state file's decisions are checked on
// open: each names a held nonce, a SHA-256 and a number handed out.
func TestAdminDecisionsInState(t *testing.T) {
	f := newPipeline(t)
	if reply, _ := f.pipe.Handle(context.Background(), f.nodeRequest(t, authz.KindNodeSeqResetAck)); !reply.Accepted() {
		t.Fatalf("ack: %+v", reply)
	}
	good := f.reopenState(t).doc
	nonce := f.reopenState(t).anyNonce()
	d := good.AdminDecisions[nonce]
	for name, decisions := range map[string]map[string]adminDecision{
		"nonce not held": {newAdminNonce(t): d},
		"bad hash":       {nonce: {PayloadSHA256: "ABC", CollectorSeq: d.CollectorSeq}},
		"seq zero":       {nonce: {PayloadSHA256: d.PayloadSHA256}},
		"seq ahead":      {nonce: {PayloadSHA256: d.PayloadSHA256, CollectorSeq: good.CollectorSeq + 1}},
	} {
		doc := good
		doc.AdminDecisions = decisions
		if err := checkStateDoc(doc); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if err := checkStateDoc(good); err != nil {
		t.Fatal(err)
	}
	if err := f.state.RecordAdminDecision(newAdminNonce(t), d.PayloadSHA256, d.CollectorSeq); err == nil {
		t.Fatal("a decision recorded for a nonce not spent")
	}
}
