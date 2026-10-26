package collector

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"otsec.local/otsec/contracts/authz"
)

// testAdminPriv is the test administrator's key: the contract golden's
// seed, a test key only (D2-5). No real admin key exists in this
// repository.
var testAdminPriv = func() ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("otsec test admin key 1"))
	return ed25519.NewKeyFromSeed(seed[:])
}()

// testAdminKey pins testAdminPriv for pipeAdmin.
func testAdminKey() authz.AdminKey {
	pub := testAdminPriv.Public().(ed25519.PublicKey)
	return authz.AdminKey{KeyID: authz.AdminKeyID(pub), PublicKey: pub, Principal: pipeAdmin.ID, Status: authz.KeyActive}
}

func newAdminNonce(t testing.TB) string {
	t.Helper()
	b := make([]byte, authz.AdminNonceLen)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// adminPayload is the payload an administrator would sign for req to this
// fixture's collector now: req's body moved inside, a fresh nonce, ten
// minutes to live.
func (f *pipeFixture) adminPayload(t testing.TB, req *authz.CollectorRequest) authz.AdminRequest {
	t.Helper()
	now := f.clock.now()
	return authz.AdminRequest{
		Format: authz.AdminRequestFormat, Kind: req.Kind, Principal: req.OnBehalfOf,
		AdminKeyID: testAdminKey().KeyID, NodeID: testNode, InstallKeyID: f.store.InstallKey().KeyID,
		Nonce:     newAdminNonce(t),
		IssuedAt:  now.Format(time.RFC3339),
		ExpiresAt: now.Add(10 * time.Minute).Format(time.RFC3339),

		CredentialInstall: req.CredentialInstall, CredentialRevoke: req.CredentialRevoke,
		CredentialClearSusp: req.CredentialClearSusp, AssetClearSusp: req.AssetClearSusp,
	}
}

// signed returns req as the administrator's signed request: the body
// moves into the payload, which testAdminPriv signs.
func (f *pipeFixture) signed(t testing.TB, req *authz.CollectorRequest) *authz.CollectorRequest {
	t.Helper()
	return f.signPayload(t, req, f.adminPayload(t, req))
}

// signPayload returns req carrying p signed by testAdminPriv, and no body
// in the clear.
func (f *pipeFixture) signPayload(t testing.TB, req *authz.CollectorRequest, p authz.AdminRequest) *authz.CollectorRequest {
	t.Helper()
	env, err := authz.SignAdminRequest(testAdminPriv, p)
	if err != nil {
		t.Fatal(err)
	}
	out := *req
	out.CredentialInstall, out.CredentialRevoke, out.CredentialClearSusp, out.AssetClearSusp = nil, nil, nil, nil
	out.AdminSigned = env
	return &out
}

// restart is the collector after a restart: its state and store opened
// again from their files, and a new pipeline over them.
func (f *pipeFixture) restart(t *testing.T) *Pipeline {
	t.Helper()
	st := f.reopenState(t)
	store, err := OpenCredStore(f.path, CredStoreConfig{NodeID: testNode, Now: f.clock.now, Generations: st})
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewPipeline(PipelineConfig{
		NodeID: testNode, PolicyVersion: policyVersion, State: st, Creds: store,
		Registers: NewRegisters(st, nil), Runner: f.runner,
		AdminKeys: []authz.AdminKey{testAdminKey()}, Now: f.clock.now,
		Alarm: func(err error) { f.alarmMu.Lock(); f.alarms = append(f.alarms, err); f.alarmMu.Unlock() },
	})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// installsTaken is how much of the install budget the state shows spent.
func (f *pipeFixture) installsTaken(t *testing.T) int {
	t.Helper()
	return len(f.reopenState(t).doc.Installs)
}

func adminCheckOf(r authz.CollectorReply) authz.AdminCheck {
	if r.Refusal == nil {
		return ""
	}
	return r.Refusal.Check
}

// wantAdminRefusal checks that reply is admin_unverified for check, with the
// fixed detail and nothing else.
func wantAdminRefusal(t *testing.T, name string, reply authz.CollectorReply, check authz.AdminCheck) {
	t.Helper()
	want := authz.AdminRefusal(check)
	if reply.Status != authz.ReplyRefused || reply.Refusal == nil || *reply.Refusal != *want {
		t.Fatalf("%s: reply %+v, want %+v", name, reply, want)
	}
}

// TestAdminSignedAccepted: each admin kind, signed by a pinned key for
// this collector, is decided as the 0.3 request in the clear was.
func TestAdminSignedAccepted(t *testing.T) {
	f := suspendedPipeline(t, nil) // no administrators' folder: the signed clear needs none
	ctx := context.Background()
	f.installCanary(t)
	if _, _, err := f.store.Suspend(pipeCred, 1, authz.SuspendOperator); err != nil {
		t.Fatal(err)
	}
	for _, req := range []*authz.CollectorRequest{
		{Contract: authz.ContractID, Kind: authz.KindCredentialClearSusp, RequestID: "req-clear", OnBehalfOf: pipeAdmin,
			PolicyVersion: policyVersion, CredentialClearSusp: &authz.CredentialClearSuspBody{RefID: pipeCred, Version: 1}},
		{Contract: authz.ContractID, Kind: authz.KindAssetClearSusp, RequestID: "req-asset-clear", OnBehalfOf: pipeAdmin,
			PolicyVersion: policyVersion, AssetClearSusp: &authz.AssetClearSuspBody{AssetID: testAsset, Ref: suspendingRun}},
		{Contract: authz.ContractID, Kind: authz.KindCredentialRevoke, RequestID: "req-revoke", OnBehalfOf: pipeAdmin,
			PolicyVersion: policyVersion, CredentialRevoke: &authz.CredentialRevokeBody{RefID: pipeCred, Reason: authz.RevokeOperator}},
	} {
		if reply, _ := f.pipe.Handle(ctx, f.signed(t, req)); !reply.Accepted() {
			t.Fatalf("%s: %+v", req.Kind, reply)
		}
	}
	if err := f.reopenState(t).CheckSuspended(testAsset); err != nil {
		t.Fatalf("signed asset clear did not clear: %v", err)
	}
	if st := f.store.Status(pipeCred); st[0].State != authz.CredentialRevoked {
		t.Fatalf("not revoked: %+v", st)
	}
	if a := f.alarmList(); len(a) != 0 {
		t.Fatalf("alarms on accepted requests: %v", a)
	}
}

// TestSignedAssetClearChecksTheSuspension: a signed clear still names the
// suspension, and one that names another changes nothing.
func TestSignedAssetClearChecksTheSuspension(t *testing.T) {
	f := suspendedPipeline(t, nil)
	for name, body := range map[string]authz.AssetClearSuspBody{
		"other ref":   {AssetID: testAsset, Ref: laterRun},
		"other asset": {AssetID: otherAsset, Ref: suspendingRun},
	} {
		req := &authz.CollectorRequest{Contract: authz.ContractID, Kind: authz.KindAssetClearSusp, RequestID: "req-asset-clear",
			OnBehalfOf: pipeAdmin, PolicyVersion: policyVersion, AssetClearSusp: &body}
		if reply, _ := f.pipe.Handle(context.Background(), f.signed(t, req)); reply.Accepted() {
			t.Fatalf("%s accepted", name)
		}
		f.stillSuspended(t, suspendingRun)
	}
}

// TestAdminRefusalsComeFirst: every request of an admin kind that is not a
// pinned administrator's request for this collector, now, is refused with
// admin_unverified naming the check, before the install budget or the
// store is touched, and raises an alarm.
func TestAdminRefusalsComeFirst(t *testing.T) {
	type tc struct {
		check authz.AdminCheck
		req   func(t *testing.T, f *pipeFixture) *authz.CollectorRequest
		opt   pipeOption
	}
	ref := pipeRef(1)
	signedWith := func(m func(*authz.AdminRequest)) func(t *testing.T, f *pipeFixture) *authz.CollectorRequest {
		return func(t *testing.T, f *pipeFixture) *authz.CollectorRequest {
			bare := bareInstall(t, f, ref, canary)
			p := f.adminPayload(t, bare)
			m(&p)
			return f.signPayload(t, bare, p)
		}
	}
	otherPriv := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	for name, c := range map[string]tc{
		"unsigned": {authz.AdminCheckEnvelope, func(t *testing.T, f *pipeFixture) *authz.CollectorRequest {
			return bareInstall(t, f, ref, canary)
		}, nil},
		"no key pinned": {authz.AdminCheckKey, func(t *testing.T, f *pipeFixture) *authz.CollectorRequest {
			return installRequest(t, f, ref, canary)
		}, func(c *PipelineConfig, _ *pipeFixture) { c.AdminKeys = nil }},
		"key revoked": {authz.AdminCheckKey, func(t *testing.T, f *pipeFixture) *authz.CollectorRequest {
			return installRequest(t, f, ref, canary)
		}, func(c *PipelineConfig, _ *pipeFixture) { c.AdminKeys[0].Status = authz.KeyRevoked }},
		"another admin's key": {authz.AdminCheckSignature, func(t *testing.T, f *pipeFixture) *authz.CollectorRequest {
			req := installRequest(t, f, ref, canary)
			req.AdminSigned.Signature = ed25519.Sign(otherPriv, authz.AdminSigningInput(req.Kind, req.AdminSigned.Payload))
			return req
		}, nil},
		"signed for another operation": {authz.AdminCheckSignature, func(t *testing.T, f *pipeFixture) *authz.CollectorRequest {
			req := f.signed(t, &authz.CollectorRequest{Contract: authz.ContractID, Kind: authz.KindCredentialClearSusp, RequestID: "req-clear",
				OnBehalfOf: pipeAdmin, PolicyVersion: policyVersion, CredentialClearSusp: &authz.CredentialClearSuspBody{RefID: pipeCred, Version: 1}})
			req.Kind = authz.KindCredentialRevoke
			return req
		}, nil},
		"sealed secret swapped": {authz.AdminCheckSignature, func(t *testing.T, f *pipeFixture) *authz.CollectorRequest {
			req := installRequest(t, f, ref, canary)
			var p authz.AdminRequest
			if err := json.Unmarshal(req.AdminSigned.Payload, &p); err != nil {
				t.Fatal(err)
			}
			p.CredentialInstall.Sealed = f.sealFor(t, ref, otherSecret)
			b, err := json.Marshal(p)
			if err != nil {
				t.Fatal(err)
			}
			req.AdminSigned.Payload = b
			return req
		}, nil},
		"principal":        {authz.AdminCheckPayload, signedWith(func(p *authz.AdminRequest) { p.Principal.ID = "other@site-a" }), nil},
		"other node":       {authz.AdminCheckBinding, signedWith(func(p *authz.AdminRequest) { p.NodeID = "site-a-node2" }), nil},
		"old install key":  {authz.AdminCheckBinding, signedWith(func(p *authz.AdminRequest) { p.InstallKeyID = "install-0000000000000000" }), nil},
		"expired":          {authz.AdminCheckWindow, signedWith(func(p *authz.AdminRequest) { p.ExpiresAt = p.IssuedAt }), nil},
		"issued in future": {authz.AdminCheckWindow, signedWith(func(p *authz.AdminRequest) { p.IssuedAt = p.ExpiresAt }), nil},
	} {
		t.Run(name, func(t *testing.T) {
			var opts []pipeOption
			if c.opt != nil {
				opts = append(opts, c.opt)
			}
			f := newPipeline(t, opts...)
			before := f.installsTaken(t)
			reply, work := f.pipe.Handle(context.Background(), c.req(t, f))
			if work != nil {
				t.Fatal("work for a refused request")
			}
			wantAdminRefusal(t, name, reply, c.check)
			if f.installsTaken(t) != before {
				t.Fatal("the install budget was spent")
			}
			if st := f.store.Status(pipeCred); len(st) != 0 {
				t.Fatalf("the store changed: %+v", st)
			}
			a := f.alarmList()
			if len(a) != 1 || !strings.Contains(a[0].Error(), string(c.check)) {
				t.Fatalf("alarms %v", a)
			}
		})
	}
}

// TestAdminReplayRefused (A6): a signed request is good for one decision,
// across a restart, and a request a later check refused has still spent
// its nonce.
func TestAdminReplayRefused(t *testing.T) {
	f := newPipeline(t)
	ctx := context.Background()
	rejected := installRequest(t, f, pipeRef(1), []byte("ACC")) // the register refuses this secret
	if reply, _ := f.pipe.Handle(ctx, rejected); refusalOf(reply) != authz.RefuseSecretRejected {
		t.Fatalf("ACC: %+v", reply)
	}
	install := installRequest(t, f, pipeRef(1), canary)
	if reply, _ := f.pipe.Handle(ctx, install); !reply.Accepted() {
		t.Fatalf("install: %+v", reply)
	}
	taken := f.installsTaken(t)
	for name, p := range map[string]*Pipeline{"same run": f.pipe, "after restart": f.restart(t)} {
		for what, req := range map[string]*authz.CollectorRequest{"accepted": install, "refused later": rejected} {
			reply, _ := p.Handle(ctx, req)
			wantAdminRefusal(t, name+", "+what, reply, authz.AdminCheckReplay)
		}
	}
	if f.installsTaken(t) != taken {
		t.Fatal("a replay spent the install budget")
	}
	// After the request expires it is refused for its window, and the
	// nonce is dropped as the next one is spent.
	f.clock.t = f.clock.t.Add(authz.MaxAdminLifetime + time.Minute)
	reply, _ := f.pipe.Handle(ctx, install)
	wantAdminRefusal(t, "expired replay", reply, authz.AdminCheckWindow)
	if reply, _ := f.pipe.Handle(ctx, installRequest(t, f, pipeRef(2), otherSecret)); !reply.Accepted() {
		t.Fatalf("install: %+v", reply)
	}
	if n := len(f.reopenState(t).doc.AdminNonces); n != 1 {
		t.Fatalf("%d nonces kept, want 1", n)
	}
}

// TestAdminNonceCapacity: past MaxAdminNonces unexpired nonces, signed
// requests are refused until some expire, and the state survives it.
func TestAdminNonceCapacity(t *testing.T) {
	f := newPipeline(t)
	exp := f.clock.now().Add(5 * time.Minute)
	for i := 0; i < MaxAdminNonces; i++ {
		if err := f.state.SpendAdminNonce(newAdminNonce(t), exp); err != nil {
			t.Fatalf("nonce %d: %v", i, err)
		}
	}
	reply, _ := f.pipe.Handle(context.Background(), installRequest(t, f, pipeRef(1), canary))
	wantAdminRefusal(t, "full", reply, authz.AdminCheckCapacity)
	if _, err := OpenState(f.state.path, f.clock.now); err != nil {
		t.Fatalf("a full state does not open: %v", err)
	}
	f.clock.t = exp.Add(time.Second)
	f.installCanary(t)
}

// TestAdminRepliesDoNotLeak (A6, D2-11): an unverified request is refused
// with the same reply and the same alarm whether its sealed secret is the
// stored one or not, and neither holds the payload, the sealed secret or
// the signature.
func TestAdminRepliesDoNotLeak(t *testing.T) {
	f := newPipeline(t)
	f.installCanary(t)
	ctx := context.Background()
	breakers := map[string]func(*authz.CollectorRequest){
		"bad signature": func(r *authz.CollectorRequest) { r.AdminSigned.Signature[0] ^= 1 },
		"unknown key":   func(r *authz.CollectorRequest) { r.AdminSigned.KeyID = "ed25519-0000000000000000" },
		"unsigned":      func(r *authz.CollectorRequest) { r.AdminSigned = nil },
	}
	for name, breakIt := range breakers {
		var replies, alarms []string
		var secretBytes [][]byte
		for _, secret := range [][]byte{canary, otherSecret} { // canary is stored: the right guess
			req := installRequest(t, f, pipeRef(2), secret)
			var p authz.AdminRequest
			if err := json.Unmarshal(req.AdminSigned.Payload, &p); err != nil {
				t.Fatal(err)
			}
			secretBytes = append(secretBytes, req.AdminSigned.Payload, req.AdminSigned.Signature,
				[]byte(p.CredentialInstall.Sealed.Ciphertext), secret)
			if name == "unsigned" {
				req = bareInstall(t, f, pipeRef(2), secret)
				secretBytes = append(secretBytes, []byte(req.CredentialInstall.Sealed.Ciphertext))
			}
			breakIt(req)
			n := len(f.alarmList())
			reply, _ := f.pipe.Handle(ctx, req)
			reply.CollectorSeq = 0
			b, err := json.Marshal(reply)
			if err != nil {
				t.Fatal(err)
			}
			replies = append(replies, string(b))
			for _, a := range f.alarmList()[n:] {
				alarms = append(alarms, a.Error())
			}
		}
		if replies[0] != replies[1] {
			t.Errorf("%s: replies differ:\n%s\n%s", name, replies[0], replies[1])
		}
		if len(alarms) != 2 || alarms[0] != alarms[1] {
			t.Errorf("%s: alarms differ: %q", name, alarms)
		}
		all := []byte(strings.Join(append(replies, alarms...), "\n"))
		for _, s := range secretBytes {
			if len(s) >= 8 && bytes.Contains(all, s) {
				t.Errorf("%s: a reply or alarm holds signed or secret bytes", name)
			}
		}
	}
	if st := f.store.Status(pipeCred); len(st) != 1 {
		t.Fatalf("the store changed: %+v", st)
	}
}

// TestOlderContractRefusal: a credential request stamped below 0.4 is
// refused as before, without the 0.4 check field its reader does not know.
func TestOlderContractRefusal(t *testing.T) {
	f := newPipeline(t)
	req := bareInstall(t, f, pipeRef(1), canary)
	req.Contract = "otsec.authz/0.3"
	reply, _ := f.pipe.Handle(context.Background(), req)
	if refusalOf(reply) != authz.RefusePrincipal || adminCheckOf(reply) != "" {
		t.Fatalf("reply %+v", reply)
	}
}

// TestAdminNoncesInState: the state file's nonces are checked on open.
func TestAdminNoncesInState(t *testing.T) {
	f := newPipeline(t)
	exp := f.clock.now().Add(time.Minute)
	if err := f.state.SpendAdminNonce(newAdminNonce(t), exp); err != nil {
		t.Fatal(err)
	}
	if err := f.state.SpendAdminNonce(f.reopenState(t).anyNonce(), exp); err == nil {
		t.Fatal("a spent nonce spent again")
	}
	good := f.reopenState(t).doc
	for name, nonces := range map[string]map[string]string{
		"bad nonce": {"short": exp.Format(time.RFC3339)},
		"bad time":  {newAdminNonce(t): "soon"},
		"too many": func() map[string]string {
			m := map[string]string{}
			for i := 0; i <= MaxAdminNonces; i++ {
				m[newAdminNonce(t)] = exp.Format(time.RFC3339)
			}
			return m
		}(),
	} {
		doc := good
		doc.AdminNonces = nonces
		if err := checkStateDoc(doc); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	bad := good
	bad.AdminClockUTC = "yesterday"
	if err := checkStateDoc(bad); err == nil {
		t.Error("bad admin clock accepted")
	}
	if err := checkStateDoc(good); err != nil {
		t.Fatal(err)
	}
}

func (s *State) anyNonce() string {
	for n := range s.doc.AdminNonces {
		return n
	}
	panic(fmt.Sprint("no nonce in ", s.path))
}

// TestAdminClockBack (A6 on #153): once a nonce is dropped, putting the
// clock back into its request's window does not make the request good
// again, across a restart too, and the collector raises an alarm while
// the clock is behind its last admin decision.
func TestAdminClockBack(t *testing.T) {
	f := newPipeline(t)
	ctx := context.Background()
	start := f.clock.now()
	install := installRequest(t, f, pipeRef(1), canary)
	if reply, _ := f.pipe.Handle(ctx, install); !reply.Accepted() {
		t.Fatalf("install: %+v", reply)
	}
	// The clock jumps forward past the request's expiry and a later
	// request is decided, which drops the first nonce.
	f.clock.t = start.Add(time.Hour)
	if reply, _ := f.pipe.Handle(ctx, installRequest(t, f, pipeRef(2), otherSecret)); !reply.Accepted() {
		t.Fatalf("install 2: %+v", reply)
	}
	if n := len(f.reopenState(t).doc.AdminNonces); n != 1 {
		t.Fatalf("%d nonces kept, want 1", n)
	}
	// The clock comes back inside the first request's window.
	f.clock.t = start.Add(time.Minute)
	alarms := len(f.alarmList())
	for name, p := range map[string]*Pipeline{"same run": f.pipe, "after restart": f.restart(t)} {
		reply, _ := p.Handle(ctx, install)
		wantAdminRefusal(t, name, reply, authz.AdminCheckWindow)
	}
	behind := 0
	for _, a := range f.alarmList()[alarms:] {
		if strings.Contains(a.Error(), "behind the last admin decision") {
			behind++
		}
	}
	if behind != 2 {
		t.Fatalf("%d clock alarms, want 2: %v", behind, f.alarmList()[alarms:])
	}
	// The state refuses it by itself too.
	if err := f.reopenState(t).SpendAdminNonce(newAdminNonce(t), start.Add(10*time.Minute)); err == nil {
		t.Fatal("a nonce expiring before the admin clock was spent")
	}
	// A request the administrator signs now, by a clock that is right, is
	// judged at the admin clock and accepted while the collector's clock is
	// behind.
	f.clock.t = start.Add(time.Hour)
	fresh := installRequest(t, f, pipeRef(3), canary)
	f.clock.t = start.Add(time.Minute)
	if reply, _ := f.pipe.Handle(ctx, fresh); !reply.Accepted() {
		t.Fatalf("a fresh request while the clock is behind: %+v", reply)
	}
	// A clock within the skew raises no alarm.
	f.clock.t = start.Add(time.Hour - time.Minute)
	alarms = len(f.alarmList())
	f.pipe.Handle(ctx, installRequest(t, f, pipeRef(4), otherSecret))
	for _, a := range f.alarmList()[alarms:] {
		if strings.Contains(a.Error(), "behind the last admin decision") {
			t.Fatalf("alarm inside the skew: %v", a)
		}
	}
}
