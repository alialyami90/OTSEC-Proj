package collector

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/authz"
	"otsec.local/otsec/contracts/register"
	"otsec.local/otsec/modules/security/collectorwire"
)

const (
	pipeInvocation = "6f1c2b9e-3d4a-4c1e-9b7a-2f0e8d5c1a30" // result-ok.json
	pipeEndpoint   = "port1-telnet"
	pipeCred       = "cred_slice0001"
	policyVersion  = 3
)

var (
	schedule  = authz.Principal{Type: authz.PrincipalSchedule, ID: "sch-ser-751-feeder-3"}
	pipeAdmin = authz.Principal{Type: authz.PrincipalHuman, ID: "admin@site-a"}
)

func readFixture(t testing.TB, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// simAsset is the C1 simulated SEL-751 fixture with its endpoint moved to
// the loopback address (D2-10).
func simAsset(t testing.TB) asset.Asset {
	t.Helper()
	a, err := asset.Decode(readFixture(t, "sel-751-simulated.json"))
	if err != nil {
		t.Fatal(err)
	}
	a.Endpoints[0].Host, a.Endpoints[0].Port = "127.0.0.1", 2323
	return a
}

func simProfile(t testing.TB) asset.CapabilityProfile {
	t.Helper()
	p, err := asset.DecodeProfile(readFixture(t, "profile-sel-751-ascii.json"))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// signedRegister signs a register payload with a release key, as a release
// does.
func signedRegister(t testing.TB, payload []byte, priv ed25519.PrivateKey, keyID string) []byte {
	t.Helper()
	b, err := json.Marshal(register.Envelope{
		Contract: register.ContractID, Algorithm: "ed25519", KeyID: keyID,
		Payload: payload, Signature: ed25519.Sign(priv, authz.RegisterSigningInput(payload)),
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// fakeRunner stands in for the SEL-751 runner. script decides what the
// session does; by default it logs in, confirms, sends QUI and returns
// result-ok.json.
type fakeRunner struct {
	mu     sync.Mutex
	calls  int
	plans  []RunPlan
	secret []byte
	script func(ctx context.Context, plan RunPlan, r *fakeRunner) RunReport
	result []byte
}

func (f *fakeRunner) Run(ctx context.Context, plan RunPlan) RunReport {
	f.mu.Lock()
	f.calls++
	f.plans = append(f.plans, plan)
	f.mu.Unlock()
	if f.script != nil {
		return f.script(ctx, plan, f)
	}
	return f.login(ctx, plan, true)
}

func (f *fakeRunner) login(ctx context.Context, plan RunPlan, quit bool) RunReport {
	if plan.Secret != nil {
		if err := plan.Floor.BeforeACC(ctx); err != nil {
			panic(err)
		}
		plan.Secret.Use(func(b []byte) error { f.secret = append([]byte(nil), b...); return nil })
		plan.Floor.Confirmed(ctx)
	}
	return RunReport{Outcome: f.outcome(plan), QUISent: quit}
}

func (f *fakeRunner) outcome(plan RunPlan) collectorwire.RunOutcome {
	return collectorwire.RunOutcome{Wire: collectorwire.WireID, InvocationID: plan.Invocation.InvocationID, Result: f.result, Audit: []json.RawMessage{}}
}

func (f *fakeRunner) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

type pipeFixture struct {
	*credFixture
	state     *State
	registers *Registers
	runner    *fakeRunner
	pipe      *Pipeline
	alarms    []error
	alarmMu   sync.Mutex
	release   ed25519.PrivateKey
}

type pipeOption func(*PipelineConfig, *pipeFixture)

func newPipeline(t *testing.T, opts ...pipeOption) *pipeFixture {
	t.Helper()
	f := &pipeFixture{credFixture: newCredStore(t), runner: &fakeRunner{result: readFixture(t, "result-ok.json")}}
	f.state = f.gens
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	f.release = priv
	f.registers = NewRegisters(f.state, []authz.TrustAnchor{{KeyID: "release-2026", PublicKey: pub, Status: authz.KeyActive}})
	if _, err := f.registers.Activate(signedRegister(t, readFixture(t, "register-sel-751.json"), priv, "release-2026")); err != nil {
		t.Fatal(err)
	}
	cfg := PipelineConfig{
		NodeID: testNode, PolicyVersion: policyVersion,
		Assets: []Enrolled{{Asset: simAsset(t), Profile: simProfile(t)}},
		State:  f.state, Creds: f.store, Registers: f.registers, Runner: f.runner,
		Now:   f.clock.now,
		NewID: func() string { return pipeInvocation },
		Alarm: func(err error) { f.alarmMu.Lock(); f.alarms = append(f.alarms, err); f.alarmMu.Unlock() },
	}
	for _, o := range opts {
		o(&cfg, f)
	}
	var err error
	if f.pipe, err = NewPipeline(cfg); err != nil {
		t.Fatal(err)
	}
	return f
}

func withAsset(m func(*asset.Asset)) pipeOption {
	return func(c *PipelineConfig, _ *pipeFixture) { m(&c.Assets[0].Asset) }
}

func (f *pipeFixture) alarmList() []error {
	f.alarmMu.Lock()
	defer f.alarmMu.Unlock()
	return append([]error(nil), f.alarms...)
}

func pipeRef(version uint32) authz.CredentialRef {
	r := telnetRef(pipeCred, testAsset, version)
	r.EndpointID = pipeEndpoint
	return r
}

func pipeRun(op, cred string) *authz.CollectorRequest {
	return &authz.CollectorRequest{
		Contract: authz.ContractID, Kind: authz.KindRun, RequestID: "req-1",
		OnBehalfOf: schedule, PolicyVersion: policyVersion,
		Run: &authz.RunBody{AssetID: testAsset, OperationID: op, Params: map[string]string{}, CredentialRef: cred, RegisterVersion: 2},
	}
}

func installRequest(t *testing.T, f *pipeFixture, ref authz.CredentialRef, secret []byte) *authz.CollectorRequest {
	return &authz.CollectorRequest{
		Contract: authz.ContractID, Kind: authz.KindCredentialInstall, RequestID: "req-install",
		OnBehalfOf: pipeAdmin, PolicyVersion: policyVersion,
		CredentialInstall: &authz.CredentialInstallBody{Ref: ref, Sealed: f.sealFor(t, ref, secret)},
	}
}

// installCanary installs the canary credential through the pipeline.
func (f *pipeFixture) installCanary(t *testing.T) {
	t.Helper()
	reply, work := f.pipe.Handle(context.Background(), installRequest(t, f, pipeRef(1), canary))
	if !reply.Accepted() || work != nil {
		t.Fatalf("install: %+v", reply)
	}
}

// run sends a run request and, when accepted, runs the work.
func (f *pipeFixture) run(t *testing.T, req *authz.CollectorRequest) (authz.CollectorReply, *collectorwire.RunOutcome) {
	t.Helper()
	reply, work := f.pipe.Handle(context.Background(), req)
	if reply.Accepted() != (work != nil) {
		t.Fatalf("accepted %v with work %v", reply.Accepted(), work != nil)
	}
	if work == nil {
		return reply, nil
	}
	o := work(context.Background())
	return reply, &o
}

func refusalOf(r authz.CollectorReply) authz.RefusalCode {
	if r.Refusal == nil {
		return ""
	}
	return r.Refusal.Code
}

func TestRunAccepted(t *testing.T) {
	f := newPipeline(t)
	f.installCanary(t)
	reply, o := f.run(t, pipeRun("sel.ser.read_all", pipeCred))
	if !reply.Accepted() || reply.InvocationID != pipeInvocation {
		t.Fatalf("reply %+v", reply)
	}
	if o == nil || o.InvocationID != pipeInvocation || !bytes.Equal(o.Result, f.runner.result) {
		t.Fatal("outcome is not the runner's")
	}
	if !bytes.Equal(f.runner.secret, canary) {
		t.Fatal("the runner did not get the credential's secret")
	}
	plan := f.runner.plans[0]
	if plan.Endpoint.Host != "127.0.0.1" || plan.Credential.ID != pipeCred || plan.Invocation.Limits.MinIntervalMS != 60000 {
		t.Fatalf("plan %+v", plan)
	}
	if len(plan.Invocation.Expected) != 2 || plan.Invocation.ProfileID != "sel-751-ascii" {
		t.Fatalf("expected identity %+v", plan.Invocation.Expected)
	}
	// The result passed the collector's own checks, so nothing alarmed.
	if a := f.alarmList(); len(a) != 0 {
		t.Fatalf("alarms: %v", a)
	}
	// The session is over: the slot is wiped, the device is free, and the
	// floor is clear because the login was confirmed and QUI was sent.
	if plan.Secret.EchoSpans(canary) != nil {
		t.Fatal("secret handle still holds the secret")
	}
	if err := f.state.CheckFloor(testAsset); err != nil {
		t.Fatalf("floor after a clean session: %v", err)
	}
	if !f.pipe.claim(testAsset) {
		t.Fatal("the asset is still busy")
	}
	f.pipe.release(testAsset)
	// Each decision has a number, rising.
	if reply.CollectorSeq <= 1 {
		t.Fatalf("collector_seq %d", reply.CollectorSeq)
	}
}

func TestLevelZeroRunHasNoSecret(t *testing.T) {
	f := newPipeline(t)
	reply, _ := f.run(t, pipeRun("sel.id", ""))
	if !reply.Accepted() {
		t.Fatalf("reply %+v", reply)
	}
	if p := f.runner.plans[0]; p.Secret != nil || p.Credential != nil {
		t.Fatal("a level 0 run was given a credential")
	}
}

// A monitor, or any person, cannot cause a run: C7 refuses it at decoding,
// and the pipeline refuses it again.
func TestPersonCannotRun(t *testing.T) {
	f := newPipeline(t)
	f.installCanary(t)
	for _, p := range []authz.Principal{
		{Type: authz.PrincipalHuman, ID: "monitor@site-a"},
		{Type: authz.PrincipalHuman, ID: "admin@site-a"},
		{Type: authz.PrincipalNode, ID: "site-a-node1"},
		{Type: authz.PrincipalSystem, ID: "scheduler"},
	} {
		req := pipeRun("sel.ser.read_all", pipeCred)
		req.OnBehalfOf = p
		b, _ := json.Marshal(req)
		if _, err := authz.DecodeRequest(b); codeOf(err) != authz.RefusePrincipal {
			t.Errorf("%s decoded: %v", p.ID, err)
		}
		if reply, _ := f.run(t, req); refusalOf(reply) != authz.RefusePrincipal {
			t.Errorf("%s: %+v", p.ID, reply)
		}
	}
	if f.runner.count() != 0 {
		t.Fatal("the runner was called")
	}
}

// Every refusal comes before the runner, keeps the device free and carries
// a collector_seq.
func TestRunRefusals(t *testing.T) {
	cases := []struct {
		name  string
		opts  []pipeOption
		setup func(t *testing.T, f *pipeFixture)
		req   func() *authz.CollectorRequest
		want  authz.RefusalCode
	}{
		{name: "policy version", req: func() *authz.CollectorRequest { r := pipeRun("sel.id", ""); r.PolicyVersion = 2; return r }, want: authz.RefusePolicyVersion},
		{name: "asset not enrolled", req: func() *authz.CollectorRequest {
			r := pipeRun("sel.id", "")
			r.Run.AssetID = assetB
			return r
		}, want: authz.RefuseAssetNotEnrolled},
		{name: "D2-4 device-observed listener", opts: []pipeOption{withAsset(func(a *asset.Asset) {
			a.Endpoints = append(a.Endpoints, asset.Endpoint{ID: "syslog", Transport: asset.SyslogUDP, Host: "127.0.0.1", Target: asset.DeviceObserved,
				DownstreamSecurity: a.Endpoints[0].DownstreamSecurity})
		})}, want: authz.RefuseAssetNotEnrolled},
		{name: "D2-10 documentation address", opts: []pipeOption{withAsset(func(a *asset.Asset) { a.Endpoints[0].Host = "192.0.2.21" })}, want: authz.RefuseAssetNotEnrolled},
		{name: "D2-10 mapped", opts: []pipeOption{withAsset(func(a *asset.Asset) { a.Endpoints[0].Host = "::ffff:127.0.0.1" })}, want: authz.RefuseAssetNotEnrolled},
		{name: "D2-10 private", opts: []pipeOption{withAsset(func(a *asset.Asset) { a.Endpoints[0].Host = "10.0.0.5" })}, want: authz.RefuseAssetNotEnrolled},
		{name: "no verified register", opts: []pipeOption{func(c *PipelineConfig, f *pipeFixture) { c.Registers = NewRegisters(f.state, nil) }}, want: authz.RefuseRegisterUnverified},
		{name: "no adapter hosted", opts: []pipeOption{func(c *PipelineConfig, _ *pipeFixture) { c.Runner = nil }}, want: authz.RefuseNotInvocable},
		{name: "register version", req: func() *authz.CollectorRequest { r := pipeRun("sel.id", ""); r.Run.RegisterVersion = 1; return r }, want: authz.RefuseRegisterVersion},
		{name: "unknown operation", req: func() *authz.CollectorRequest { return pipeRun("sel.trip", "") }, want: authz.RefuseUnknownOperation},
		{name: "session line", req: func() *authz.CollectorRequest { return pipeRun("sel.acc", "") }, want: authz.RefuseUnknownOperation},
		{name: "level 1 without credential", req: func() *authz.CollectorRequest { return pipeRun("sel.ser.read_all", "") }, want: authz.RefuseCredentialMismatch},
		{name: "level 0 with credential", req: func() *authz.CollectorRequest { return pipeRun("sel.id", pipeCred) }, want: authz.RefuseCredentialMismatch},
		{name: "parameters", req: func() *authz.CollectorRequest {
			r := pipeRun("sel.id", "")
			r.Run.Params = map[string]string{"rows": "10"}
			return r
		}, want: authz.RefuseBadParams},
		{name: "asset suspended", opts: []pipeOption{withAsset(func(a *asset.Asset) {
			a.Suspension = &asset.Suspension{Reason: "operator", Since: "2026-10-24T10:00:00Z", Ref: "admin@site-a"}
		})}, want: authz.RefuseAssetNotEnrolled},
		{name: "failed-auth floor", setup: func(t *testing.T, f *pipeFixture) { f.state.BeginAuth(testAsset) }, want: authz.RefuseRateLimited},
		{name: "minimum interval", setup: func(t *testing.T, f *pipeFixture) { f.state.BeginRun(testAsset) }, want: authz.RefuseRateLimited},
		{name: "busy", setup: func(t *testing.T, f *pipeFixture) { f.pipe.claim(testAsset) }, want: authz.RefuseBusy},
		{name: "credential missing", req: func() *authz.CollectorRequest { return pipeRun("sel.ser.read_all", "cred_absent001") }, want: authz.RefuseCredentialUnusable},
		{name: "credential suspended", setup: func(t *testing.T, f *pipeFixture) {
			f.installCanary(t)
			f.store.Suspend(pipeCred, 1, authz.SuspendAuthFailed)
		}, req: func() *authz.CollectorRequest { return pipeRun("sel.ser.read_all", pipeCred) }, want: authz.RefuseCredentialUnusable},
		{name: "state unavailable", setup: func(t *testing.T, f *pipeFixture) {
			os.Mkdir(f.state.path+".tmp", 0o700)
			f.state.BeginRun(assetB) // fails and breaks the state
		}, want: authz.RefuseStateUnavailable},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newPipeline(t, c.opts...)
			if c.setup != nil {
				c.setup(t, f)
			}
			req := pipeRun("sel.id", "")
			if c.req != nil {
				req = c.req()
			}
			reply, _ := f.run(t, req)
			if got := refusalOf(reply); got != c.want {
				t.Fatalf("got %q (%+v), want %q", got, reply.Refusal, c.want)
			}
			if f.runner.count() != 0 {
				t.Fatal("the runner was called")
			}
			if c.want != authz.RefuseStateUnavailable && reply.CollectorSeq == 0 {
				t.Fatal("refusal has no collector_seq")
			}
			if c.name != "busy" && !f.pipe.claim(testAsset) {
				t.Fatal("a refused run left the asset busy")
			}
		})
	}
}

// T-9 at the pipeline: a failed authentication leaves the floor set and
// suspends the credential; the next request inside the floor is refused
// with rate_limited before any connection.
func TestFailedAuthRefusesNextRun(t *testing.T) {
	f := newPipeline(t)
	f.installCanary(t)
	f.runner.script = func(ctx context.Context, plan RunPlan, r *fakeRunner) RunReport {
		plan.Floor.BeforeACC(ctx)
		plan.Secret.Use(func([]byte) error { return nil })
		// The relay asked for the password again: auth-failed (T-10).
		return RunReport{Outcome: r.outcome(plan), QUISent: true, Suspend: authz.SuspendAuthFailed}
	}
	if reply, _ := f.run(t, pipeRun("sel.ser.read_all", pipeCred)); !reply.Accepted() {
		t.Fatalf("first run: %+v", reply)
	}
	if st := f.store.Status(pipeCred); st[0].State != authz.CredentialSuspended || st[0].Reason != string(authz.SuspendAuthFailed) {
		t.Fatalf("credential %+v", st)
	}
	f.clock.t = f.clock.t.Add(2 * time.Minute) // past the minimum interval
	reply, _ := f.run(t, pipeRun("sel.id", ""))
	if refusalOf(reply) != authz.RefuseRateLimited {
		t.Fatalf("second run inside the floor: %+v", reply)
	}
	if f.runner.count() != 1 {
		t.Fatal("the second run reached the runner")
	}
	// After the floor, level 0 runs again; the suspended credential does not.
	f.runner.script = nil
	f.clock.t = f.clock.t.Add(31 * time.Minute)
	if reply, _ := f.run(t, pipeRun("sel.id", "")); !reply.Accepted() {
		t.Fatalf("after the floor: %+v", reply)
	}
	f.clock.t = f.clock.t.Add(2 * time.Minute)
	if reply, _ := f.run(t, pipeRun("sel.ser.read_all", pipeCred)); refusalOf(reply) != authz.RefuseCredentialUnusable {
		t.Fatalf("suspended credential: %+v", reply)
	}
}

// No TIDLE reconnect: a session that reached Level 1 and closed without QUI
// sets the floor again, so no new session lands on the open level.
func TestUncleanExitSetsFloor(t *testing.T) {
	f := newPipeline(t)
	f.installCanary(t)
	f.runner.script = func(ctx context.Context, plan RunPlan, r *fakeRunner) RunReport {
		rep := r.login(ctx, plan, false)
		rep.TIDLE = 5 * time.Minute
		return rep
	}
	f.run(t, pipeRun("sel.ser.read_all", pipeCred))
	if err := f.state.CheckFloor(testAsset); codeOf(err) != authz.RefuseRateLimited {
		t.Fatalf("floor after an exit without QUI: %v", err)
	}
	// TIDLE 5 min read in the session gives a 6 min floor.
	f.clock.t = f.clock.t.Add(5*time.Minute + 59*time.Second)
	if err := f.state.CheckFloor(testAsset); codeOf(err) != authz.RefuseRateLimited {
		t.Fatalf("floor ended early: %v", err)
	}
	f.clock.t = f.clock.t.Add(2 * time.Second)
	if err := f.state.CheckFloor(testAsset); err != nil {
		t.Fatalf("floor after TIDLE plus one minute: %v", err)
	}
}

// A report the runner leaves at its zero value is read cautiously.
func TestZeroReportIsCautious(t *testing.T) {
	f := newPipeline(t)
	f.installCanary(t)
	f.runner.script = func(ctx context.Context, plan RunPlan, r *fakeRunner) RunReport {
		r.login(ctx, plan, true)
		return RunReport{Outcome: r.outcome(plan)} // QUISent left false
	}
	f.run(t, pipeRun("sel.ser.read_all", pipeCred))
	if err := f.state.CheckFloor(testAsset); codeOf(err) != authz.RefuseRateLimited {
		t.Fatalf("zero report cleared the floor: %v", err)
	}
}

func TestRunnerPanic(t *testing.T) {
	f := newPipeline(t)
	f.installCanary(t)
	f.runner.script = func(ctx context.Context, plan RunPlan, r *fakeRunner) RunReport {
		r.login(ctx, plan, true)
		panic("adapter bug")
	}
	reply, o := f.run(t, pipeRun("sel.ser.read_all", pipeCred))
	if !reply.Accepted() || o.InvocationID != pipeInvocation || len(o.Result) != 0 {
		t.Fatalf("outcome after a panic: %+v", o)
	}
	if len(f.alarmList()) == 0 {
		t.Fatal("no alarm for the panic")
	}
	if f.runner.plans[0].Secret.EchoSpans(canary) != nil || !f.pipe.claim(testAsset) {
		t.Fatal("panic left the secret or the busy flag behind")
	}
	if err := f.state.CheckFloor(testAsset); codeOf(err) != authz.RefuseRateLimited {
		t.Fatal("panic after login left the floor clear")
	}
}

// The collector checks the result before sending it; a failure alarms, and
// the outcome is still sent for the node to quarantine.
func TestResultChecksAlarm(t *testing.T) {
	f := newPipeline(t)
	// result-ok.json is a sel.ser.read_all session: claimed as sel.id, its
	// SER line is not allowed, which is the safety case.
	reply, o := f.run(t, pipeRun("sel.id", ""))
	if !reply.Accepted() || !bytes.Equal(o.Result, f.runner.result) {
		t.Fatal("outcome not sent")
	}
	a := f.alarmList()
	if len(a) != 1 || !strings.Contains(a[0].Error(), "SAFETY") {
		t.Fatalf("alarms %v", a)
	}

	f = newPipeline(t)
	f.runner.result = []byte(`{"schema":"otsec.adapter/0.1"}`)
	f.run(t, pipeRun("sel.id", ""))
	if len(f.alarmList()) != 1 {
		t.Fatalf("invalid result did not alarm: %v", f.alarmList())
	}
}

func TestCredentialRequests(t *testing.T) {
	f := newPipeline(t, func(c *PipelineConfig, _ *pipeFixture) { c.InstallLimit = 2 })
	ctx := context.Background()
	// The register refuses this secret (A6, #75): refused, and it spends
	// one install from the budget.
	if reply, _ := f.pipe.Handle(ctx, installRequest(t, f, pipeRef(1), []byte("ACC"))); refusalOf(reply) != authz.RefuseSecretRejected {
		t.Fatalf("ACC as a secret: %+v", reply)
	}
	f.installCanary(t)
	// The budget of two is spent.
	if reply, _ := f.pipe.Handle(ctx, installRequest(t, f, pipeRef(2), otherSecret)); refusalOf(reply) != authz.RefuseRateLimited {
		t.Fatalf("third install in the window: %+v", reply)
	}
	f.clock.t = f.clock.t.Add(time.Hour)
	if reply, _ := f.pipe.Handle(ctx, installRequest(t, f, pipeRef(2), otherSecret)); !reply.Accepted() {
		t.Fatalf("install after the window: %+v", reply)
	}

	f.store.Suspend(pipeCred, 2, authz.SuspendOperator)
	clear := &authz.CollectorRequest{Contract: authz.ContractID, Kind: authz.KindCredentialClearSusp, RequestID: "req-clear",
		OnBehalfOf: pipeAdmin, PolicyVersion: policyVersion, CredentialClearSusp: &authz.CredentialClearSuspBody{RefID: pipeCred, Version: 2}}
	if reply, _ := f.pipe.Handle(ctx, clear); !reply.Accepted() {
		t.Fatalf("clear: %+v", reply)
	}
	revoke := &authz.CollectorRequest{Contract: authz.ContractID, Kind: authz.KindCredentialRevoke, RequestID: "req-revoke",
		OnBehalfOf: pipeAdmin, PolicyVersion: policyVersion, CredentialRevoke: &authz.CredentialRevokeBody{RefID: pipeCred, Reason: authz.RevokeOperator}}
	if reply, _ := f.pipe.Handle(ctx, revoke); !reply.Accepted() {
		t.Fatalf("revoke: %+v", reply)
	}
	sched := *revoke
	sched.OnBehalfOf = schedule
	if reply, _ := f.pipe.Handle(ctx, &sched); refusalOf(reply) != authz.RefusePrincipal {
		t.Fatalf("revoke by a schedule: %+v", reply)
	}
}

func TestRefuseIsNumbered(t *testing.T) {
	f := newPipeline(t)
	a := f.pipe.Refuse(context.Background(), "", &authz.Refusal{Code: authz.RefuseUnknownField})
	b := f.pipe.Refuse(context.Background(), "", &authz.Refusal{Code: authz.RefuseMalformed})
	if a.CollectorSeq == 0 || b.CollectorSeq != a.CollectorSeq+1 || a.Status != authz.ReplyRefused {
		t.Fatalf("refusals %+v %+v", a, b)
	}
}

func TestNewPipelineChecksConfig(t *testing.T) {
	f := newPipeline(t)
	base := PipelineConfig{NodeID: testNode, PolicyVersion: 1, State: f.state, Creds: f.store, Registers: f.registers, Runner: f.runner}
	other := simAsset(t)
	other.NodeID = "site-a-node2"
	for name, cfg := range map[string]PipelineConfig{
		"no state": func() PipelineConfig { c := base; c.State = nil; return c }(),
		"policy 0": func() PipelineConfig { c := base; c.PolicyVersion = 0; return c }(),
		"other node": func() PipelineConfig {
			c := base
			c.Assets = []Enrolled{{Asset: other, Profile: simProfile(t)}}
			return c
		}(),
		"enrolled twice": func() PipelineConfig {
			c := base
			e := Enrolled{Asset: simAsset(t), Profile: simProfile(t)}
			c.Assets = []Enrolled{e, e}
			return c
		}(),
	} {
		if _, err := NewPipeline(cfg); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// The locks also hold for an asset that never passed C1 validation, so they
// do not depend on the loader.
func TestCollectionEndpointLocks(t *testing.T) {
	a := simAsset(t)
	for name, m := range map[string]func(*asset.Endpoint){
		"device-observed": func(e *asset.Endpoint) { e.Target = asset.DeviceObserved },
		"no target":       func(e *asset.Endpoint) { e.Target = "" },
		"documented":      func(e *asset.Endpoint) { e.Target = asset.Documented },
		"localhost":       func(e *asset.Endpoint) { e.Host = "localhost" },
		"host name":       func(e *asset.Endpoint) { e.Host = "relay-7.station.local" },
	} {
		b := a
		b.Endpoints = append([]asset.Endpoint(nil), a.Endpoints...)
		m(&b.Endpoints[0])
		if _, err := collectionEndpoint(b); codeOf(err) != authz.RefuseAssetNotEnrolled {
			t.Errorf("%s: %v", name, err)
		}
	}
	two := a
	two.Endpoints = append([]asset.Endpoint(nil), a.Endpoints[0], a.Endpoints[0])
	two.Endpoints[1].ID = "port2-telnet"
	if _, err := collectionEndpoint(two); codeOf(err) != authz.RefuseInvalid {
		t.Errorf("two outbound endpoints: %v", err)
	}
	if ep, err := collectionEndpoint(a); err != nil || ep.ID != pipeEndpoint {
		t.Errorf("valid asset: %v", err)
	}
}

func TestLoopbackLiteral(t *testing.T) {
	for host, ok := range map[string]bool{
		"127.0.0.1": true, "127.10.20.30": true, "::1": true,
		"localhost": false, "192.0.2.21": false, "0.0.0.0": false, "::": false, "::ffff:127.0.0.1": false,
		"fe80::1%eth0": false, "::1%lo": false, "": false, "127.0.0.1:23": false, "relay.local": false,
	} {
		if got := loopbackLiteral(host) == nil; got != ok {
			t.Errorf("loopbackLiteral(%q) = %v, want %v", host, got, ok)
		}
	}
}

// The adapter's dialer reaches only the run's endpoint (W-3, D2-10).
func TestEndpointDialer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	ep := asset.Endpoint{ID: pipeEndpoint, Host: "127.0.0.1", Port: port}
	dial := endpointDialer(ep)
	ctx := context.Background()
	c, err := dial(ctx, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatalf("own endpoint: %v", err)
	}
	c.Close()
	for _, a := range []struct{ network, addr string }{
		{"tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port+1))},
		{"tcp", net.JoinHostPort("127.0.0.2", strconv.Itoa(port))},
		{"tcp", "localhost:" + strconv.Itoa(port)},
		{"udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port))},
		{"unix", "/tmp/x"},
	} {
		if _, err := dial(ctx, a.network, a.addr); !errors.Is(err, errDialRefused) {
			t.Errorf("%s %s: %v", a.network, a.addr, err)
		}
	}
	remote := endpointDialer(asset.Endpoint{Host: "192.0.2.21", Port: 23})
	if _, err := remote(ctx, "tcp", "192.0.2.21:23"); !errors.Is(err, errDialRefused) {
		t.Errorf("non-loopback endpoint dialed: %v", err)
	}
}

func TestRegisterActivation(t *testing.T) {
	f := newPipeline(t)
	payload := readFixture(t, "register-sel-751.json")
	// A signature by an unknown key, a bad signature and a tampered payload
	// are refused; the active package stays.
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	bad := map[string][]byte{
		"unknown key": signedRegister(t, payload, other, "other-key"),
		"wrong key":   signedRegister(t, payload, other, "release-2026"),
		"not json":    []byte("{"),
	}
	tampered := signedRegister(t, payload, f.release, "release-2026")
	var env register.Envelope
	json.Unmarshal(tampered, &env)
	env.Payload = bytes.Replace(env.Payload, []byte(`"revision": 2`), []byte(`"revision": 9`), 1)
	bad["tampered"], _ = json.Marshal(env)
	for name, b := range bad {
		if _, err := f.registers.Activate(b); !errors.Is(err, authz.ErrRegisterRejected) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if pkg, _, ok := f.registers.Active("sel-751"); !ok || pkg.Revision != 2 {
		t.Fatal("a rejected package changed the active one")
	}
	// Revision 3 activates and raises the persisted floor; revision 2 is
	// then a rollback, also after a restart.
	rev3 := bytes.Replace(payload, []byte(`"revision": 2`), []byte(`"revision": 3`), 1)
	if _, err := f.registers.Activate(signedRegister(t, rev3, f.release, "release-2026")); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenState(f.state.path, f.clock.now)
	if err != nil {
		t.Fatal(err)
	}
	pub := f.release.Public().(ed25519.PublicKey)
	fresh := NewRegisters(reopened, []authz.TrustAnchor{{KeyID: "release-2026", PublicKey: pub, Status: authz.KeyActive}})
	if _, err := fresh.Activate(signedRegister(t, payload, f.release, "release-2026")); !errors.Is(err, authz.ErrRegisterRejected) {
		t.Fatalf("rollback after restart: %v", err)
	}
	revoked := NewRegisters(reopened, []authz.TrustAnchor{{KeyID: "release-2026", PublicKey: pub, Status: authz.KeyRevoked}})
	if _, err := revoked.Activate(signedRegister(t, rev3, f.release, "release-2026")); !errors.Is(err, authz.ErrRegisterRejected) {
		t.Fatalf("revoked key: %v", err)
	}
}
