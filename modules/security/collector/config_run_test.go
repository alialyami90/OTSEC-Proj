package collector

import (
	"bytes"
	"context"
	"testing"

	"otsec.local/otsec/contracts/adapter"
	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/authz"
)

// B3 on #331 (D4-13 conditions 1 and 2): a configuration run, which the
// pipeline does not yet accept from a request (RunBody.ValidateAgainst knows
// operations only), is applied to the stores exactly as a single operation
// is: the failed-auth floor, the asset's and the credential's suspension,
// with the codes of the single operation. The plan is built here, as
// decideRun builds it, and run through the hosted SEL-751 runner against a
// far end that plays a C2 0.6 golden or a change to one. Simulated evidence
// only.

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

// The pipeline does not take a run's ID in a request yet: it refuses it as an
// unknown operation, and fails closed.
func TestConfigRunIsRefusedAsARequestUntilWired(t *testing.T) {
	f, _ := hostedFixture(t)
	rev5 := readFixtureFrom(t, "../../../contracts/register/testdata/sel-751.json")
	if _, err := f.registers.Activate(signedRegister(t, rev5, f.release, "release-2026")); err != nil {
		t.Fatal(err)
	}
	req := pipeRun(configRun, pipeCred)
	req.Run.RegisterVersion = 5
	reply, o := f.run(t, req)
	if o != nil || refusalOf(reply) != authz.RefuseUnknownOperation {
		t.Fatalf("reply %+v", reply)
	}
}
