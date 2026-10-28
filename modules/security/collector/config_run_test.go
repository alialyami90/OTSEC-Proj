package collector

import (
	"bytes"
	"context"
	"testing"
	"time"

	"otsec.local/otsec/contracts/adapter"
	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/authz"
)

// B3 on #331 (D4-13 conditions 1 and 2): a configuration run is applied to
// the stores exactly as a single operation is: the failed-auth floor, the
// asset's and the credential's suspension, with the codes of the single
// operation. The plan is built here, as decideRun builds it, and run through
// the hosted SEL-751 runner against a far end that plays a C2 0.6 golden or a
// change to one. The tests from "C7 0.7" down send the run as a request.
// Simulated evidence only.

const configRun = "sel.config.read_all"

func configGoldenResult(t testing.TB, name string) adapter.Result {
	t.Helper()
	r, err := adapter.DecodeResult(readFixtureFrom(t, "../../../contracts/adapter/testdata/config/results/valid/"+name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// configWork readies a run of the configuration read on f, as decideRun
// does after the checks the run does not reach yet, and returns its work.
// The register is revision 5, signed, and the profile is the C1 fixture that
// names the run.
func configWork(t *testing.T, f *pipeFixture, limit func(*adapter.Limits)) *runWork {
	t.Helper()
	p := f.pipe
	rev5 := readFixtureFrom(t, "../../../contracts/register/testdata/sel-751.json")
	if _, err := f.registers.Activate(signedRegister(t, rev5, f.release, "release-2026")); err != nil {
		t.Fatal(err)
	}
	prof, err := asset.DecodeProfile(readFixtureFrom(t, "../../../contracts/asset/testdata/valid/profile-sel-751-ascii.json"))
	if err != nil {
		t.Fatal(err)
	}
	e := p.assets[testAsset]
	e.Profile = prof
	ep, err := collectionEndpoint(e.Asset)
	if err != nil {
		t.Fatal(err)
	}
	pkg, m, ok := f.registers.Active("sel-751")
	if !ok || pkg.Revision != 5 {
		t.Fatalf("active register %v %v", pkg, ok)
	}
	req := pipeRun(configRun, pipeCred)
	req.Run.RegisterVersion = 5
	inv, err := p.invocation(req, e, ep)
	if err != nil {
		t.Fatalf("invocation: %v", err)
	}
	if inv.Limits, err = inv.Limits.ForRun(m, configRun); err != nil {
		t.Fatal(err)
	}
	if limit != nil {
		limit(&inv.Limits)
	}
	if !p.claim(testAsset) {
		t.Fatal("busy")
	}
	release := func() { p.release(testAsset) }
	h, ref, err := p.cfg.Creds.Acquire(pipeCred, authz.Use{
		NodeID: p.cfg.NodeID, AssetID: testAsset, EndpointID: ep.ID, Transport: authz.Transport(ep.Transport),
		AckScope: ackScope(&ep), AccessLevel: "1",
	}, pkg)
	if err != nil {
		release()
		t.Fatalf("acquire: %v", err)
	}
	if err := p.cfg.State.BeginRun(testAsset); err != nil {
		t.Fatal(err)
	}
	plan := RunPlan{
		Invocation: inv, Asset: e.Asset, Profile: e.Profile, Endpoint: ep, Register: pkg,
		Credential: &ref, Secret: h, Floor: NewFloorGate(p.cfg.State, testAsset),
		Dial: endpointDialer(ep), NextSeq: p.cfg.State.NextSeq, Principal: schedule,
	}
	plan.Floor.Alarm = p.cfg.Alarm
	plan.Audit = newRunAudit(p, &plan)
	return &runWork{p: p, plan: plan, release: release}
}

// turnsUpTo is the ok golden's turns through the reply to line, that reply
// changed by f, and then the closing QUI exchange when quit.
func turnsUpTo(t *testing.T, line string, quit bool, f func(reply []byte) []byte) []turn {
	t.Helper()
	all := replayTurns(configGoldenResult(t, "ok"))
	for i, tn := range all {
		if string(tn.expect) == line+"\r\n" {
			out := append([]turn(nil), all[:i+1]...)
			out[i].reply = f(append([]byte(nil), tn.reply...))
			if quit {
				out = append(out, all[len(all)-1])
			}
			return out
		}
	}
	t.Fatalf("no turn %q", line)
	return nil
}

func TestConfigRunAppliesTheStoresLikeAnOperation(t *testing.T) {
	trim := func(b []byte) []byte { return bytes.TrimSuffix(b, []byte("=>")) }
	cases := []struct {
		name   string
		turns  []turn
		code   adapter.Code
		quit   bool // the session ended with QUI
		floor  bool // the failed-auth floor holds after the run
		asset  bool // the asset is suspended
		cred   bool // the credential is suspended
		hangUp bool
		limit  func(*adapter.Limits)
	}{
		{name: "ok", turns: replayTurns(configGoldenResult(t, "ok")), quit: true},
		{name: "config_unparsable", turns: replayTurns(configGoldenResult(t, "failed.config_unparsable")),
			code: adapter.FailedConfigUnparsable, quit: true},
		{name: "device_error", turns: replayTurns(configGoldenResult(t, "failed.device_error-required-class-absent")),
			code: adapter.FailedDeviceError, quit: true},
		// The relay is at Level 0 and the login was confirmed: no QUI, and
		// the floor runs from the session's end.
		{name: "access_level_dropped", turns: replayTurns(configGoldenResult(t, "failed.access_level_dropped-in-run")),
			code: adapter.FailedAccessLevelDropped, floor: true},
		{name: "timeout", turns: replayTurns(configGoldenResult(t, "failed.timeout-in-run")),
			code: adapter.FailedTimeout, quit: true, limit: func(l *adapter.Limits) { l.StepTimeoutMS = 3000 }},
		// An unexpected prompt mid-run: QUI, and the code that suspends the
		// asset and the credential for a single operation.
		{name: "unexpected_access_level", turns: func() []turn {
			ts := turnsUpTo(t, "SHO 2", true, func(b []byte) []byte { return append(trim(b), "=>>"...) })
			return ts
		}(), code: adapter.FailedUnexpectedLevel, quit: true, asset: true, cred: true},
		// "Password: ?" at Level 1 is not answered and not even QUI is sent.
		{name: "unexpected_password_prompt", turns: turnsUpTo(t, "SHO 2", false, func(b []byte) []byte {
			return append(trim(b), "\r\nPassword: ?"...)
		}), code: adapter.FailedUnexpectedPasswordPrompt, floor: true, asset: true},
		// The relay hangs up in the middle of the run: no QUI could be sent.
		{name: "transport_closed", turns: turnsUpTo(t, "SHO 2", false, func(b []byte) []byte { return trim(b) }),
			code: adapter.FailedTransportClosed, floor: true, hangUp: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f, l := hostedFixture(t)
			w := configWork(t, f, c.limit)
			done := farEndOn(l, c.turns, c.hangUp)
			out := w.Run(context.Background())
			if err := <-done; err != nil {
				t.Errorf("far end: %v", err)
			}
			res, err := adapter.DecodeResult(out.Result)
			if err != nil {
				t.Fatalf("result: %v", err)
			}
			if resultCode(res) != c.code || res.Session.QuitSent != c.quit {
				t.Fatalf("result %q, quit_sent %v; want %q, %v", resultCode(res), res.Session.QuitSent, c.code, c.quit)
			}
			if c.code != "" && len(res.Records) != 0 {
				t.Errorf("a failed run reports %d records", len(res.Records))
			}
			if a := f.alarmList(); len(a) != 0 {
				t.Errorf("alarms: %v", a)
			}
			if err := f.state.CheckFloor(testAsset); (err != nil) != c.floor {
				t.Errorf("floor after the run: %v, want set %v", err, c.floor)
			}
			if err := f.state.CheckSuspended(testAsset); (err != nil) != c.asset {
				t.Errorf("asset after the run: %v, want suspended %v", err, c.asset)
			}
			if st := f.store.Status(pipeCred); len(st) != 1 || (st[0].State == authz.CredentialSuspended) != c.cred {
				t.Errorf("credential after the run: %+v, want suspended %v", st, c.cred)
			}
		})
	}
}

// --- C7 0.7: the pipeline takes a register run in a request ---

// configPipeline is a pipeline over the fake runner, with register revision 5
// (which has the run) active, the C1 profile that names it, and the test
// credential installed.
func configPipeline(t *testing.T, opts ...pipeOption) *pipeFixture {
	t.Helper()
	f := newPipeline(t, opts...)
	rev5 := readFixtureFrom(t, "../../../contracts/register/testdata/sel-751.json")
	if _, err := f.registers.Activate(signedRegister(t, rev5, f.release, "release-2026")); err != nil {
		t.Fatal(err)
	}
	f.installCanary(t)
	return f
}

func configReq(cred string) *authz.CollectorRequest {
	r := pipeRun(configRun, cred)
	r.Run.RegisterVersion = 5
	return r
}

// hosting is a runner that hosts only the operations it lists.
type hosting struct {
	*fakeRunner
	hosted map[string]bool
}

func (h hosting) Hosts(id string) bool { return h.hosted[id] }

// A run request is accepted and the invocation takes the run's limits from
// the signed register: the collector's defaults (120 s, 1 MiB) would cut the
// run short. The level the credential is checked at is the run's highest
// step. The reply names the run's deadline to the node (D4-24).
func TestConfigRunIsAcceptedAsARequest(t *testing.T) {
	f := configPipeline(t)
	reply, work := f.pipe.Handle(context.Background(), configReq(pipeCred))
	if !reply.Accepted() || work == nil {
		t.Fatalf("reply %+v", reply)
	}
	defer work.Discard()
	plan := work.(*runWork).plan
	_, m, _ := f.registers.Active("sel-751")
	want, err := DefaultLimits.ForRun(m, configRun)
	if err != nil {
		t.Fatal(err)
	}
	want.MinIntervalMS = plan.Invocation.Limits.MinIntervalMS // the profile's
	if plan.Invocation.OperationID != configRun || plan.Invocation.Limits != want {
		t.Fatalf("invocation %q with limits %+v, want the run's %+v", plan.Invocation.OperationID, plan.Invocation.Limits, want)
	}
	if want.DeadlineMS != 300000 || want.MaxResponseBytes != 524288 || want == DefaultLimits {
		t.Fatalf("run limits %+v are not the signed register's", want)
	}
	if plan.Credential == nil || plan.Credential.AccessLevel != "1" || plan.Secret == nil {
		t.Fatalf("credential %+v", plan.Credential)
	}
	if reply.RunDeadlineMS != 300000 {
		t.Fatalf("run_deadline_ms %d, want 300000", reply.RunDeadlineMS)
	}
	if err := reply.Validate(); err != nil {
		t.Fatal(err)
	}
}

// The reply carries run_deadline_ms only to a request stamped 0.7 or later,
// because a node built for 0.6 decodes replies strictly; an operation gets
// the invocation's own deadline.
func TestRunDeadlineIsForNewStampsOnly(t *testing.T) {
	for _, c := range []struct {
		stamp string
		want  uint64
	}{{authz.ContractID, uint64(DefaultLimits.DeadlineMS)}, {"otsec.authz/0.6", 0}, {"otsec.authz/0.5", 0}} {
		f := configPipeline(t)
		req := pipeRun("sel.ser.read_all", pipeCred)
		req.Run.RegisterVersion = 5
		req.Contract = c.stamp
		reply, work := f.pipe.Handle(context.Background(), req)
		if !reply.Accepted() || work == nil {
			t.Fatalf("%s: %+v", c.stamp, reply)
		}
		work.Discard()
		if reply.RunDeadlineMS != c.want {
			t.Errorf("stamped %s: run_deadline_ms %d, want %d", c.stamp, reply.RunDeadlineMS, c.want)
		}
		if err := reply.Validate(); err != nil {
			t.Errorf("stamped %s: %v", c.stamp, err)
		}
	}
}

// A request stamped before 0.7 cannot name a run: it is refused as the 0.6
// collector refuses it.
func TestConfigRunStampedBefore07(t *testing.T) {
	f := configPipeline(t)
	req := configReq(pipeCred)
	req.Contract = "otsec.authz/0.6"
	reply, work := f.pipe.Handle(context.Background(), req)
	if work != nil || refusalOf(reply) != authz.RefuseUnknownOperation || reply.RunDeadlineMS != 0 {
		t.Fatalf("reply %+v", reply)
	}
}

// B6 on #334: a run ID with parameters, or with a step the policy denies, is
// refused before any credential is read. The credential named here does not
// exist, so a refusal other than the one under test (credential_unusable)
// would show the credential was looked at first; the control row shows it is
// looked at when the run is allowed. Nothing is recorded for the floor or
// the interval, and the device is free.
func TestConfigRunRefusalsComeBeforeTheCredential(t *testing.T) {
	const absent = "cred_absent001"
	cases := []struct {
		name string
		opts []pipeOption
		req  func() *authz.CollectorRequest
		want authz.RefusalCode
	}{
		{name: "control: allowed, credential missing", req: func() *authz.CollectorRequest { return configReq(absent) }, want: authz.RefuseCredentialUnusable},
		{name: "parameters", req: func() *authz.CollectorRequest {
			r := configReq(absent)
			r.Run.Params = map[string]string{"form": "G"}
			return r
		}, want: authz.RefuseBadParams},
		{name: "no credential for a level 1 run", req: func() *authz.CollectorRequest { return configReq("") }, want: authz.RefuseCredentialMismatch},
		{name: "not hosted by the adapter", opts: []pipeOption{func(c *PipelineConfig, f *pipeFixture) {
			c.Runner = hosting{f.runner, map[string]bool{"sel.ser.read_all": true}}
		}}, req: func() *authz.CollectorRequest { return configReq(absent) }, want: authz.RefuseNotInvocable},
		{name: "register revision before the run", req: func() *authz.CollectorRequest {
			r := configReq(absent)
			r.Run.RegisterVersion = 3
			return r
		}, want: authz.RefuseRegisterVersion},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := configPipeline(t, c.opts...)
			reply, work := f.pipe.Handle(context.Background(), c.req())
			if work != nil || refusalOf(reply) != c.want {
				t.Fatalf("reply %+v (%+v), want %q", reply, reply.Refusal, c.want)
			}
			if reply.CollectorSeq == 0 || reply.RunDeadlineMS != 0 {
				t.Errorf("reply %+v", reply)
			}
			if f.runner.count() != 0 {
				t.Error("the runner was called")
			}
			if err := f.state.CheckInterval(testAsset, time.Hour); err != nil {
				t.Errorf("a refused run began: %v", err)
			}
			if err := f.state.CheckFloor(testAsset); err != nil {
				t.Errorf("a refused run set the floor: %v", err)
			}
			if !f.pipe.claim(testAsset) {
				t.Error("a refused run left the asset busy")
			}
		})
	}
}

// A hosted runner is asked about an operation too, so a name the adapter does
// not host is refused for an operation as for a run; a runner that does not
// say is trusted as before.
func TestHosterAppliesToOperations(t *testing.T) {
	f := configPipeline(t, func(c *PipelineConfig, f *pipeFixture) {
		c.Runner = hosting{f.runner, map[string]bool{configRun: true}}
	})
	op := pipeRun("sel.ser.read_all", pipeCred)
	op.Run.RegisterVersion = 5
	reply, work := f.pipe.Handle(context.Background(), op)
	if work != nil || refusalOf(reply) != authz.RefuseNotInvocable {
		t.Fatalf("reply %+v", reply)
	}
	reply, work = f.pipe.Handle(context.Background(), configReq(pipeCred))
	if work == nil {
		t.Fatalf("reply %+v", reply)
	}
	work.Discard()
}
