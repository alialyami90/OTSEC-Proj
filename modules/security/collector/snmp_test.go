package collector

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"otsec.local/otsec/contracts/adapter"
	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/authz"
	"otsec.local/otsec/modules/security/collectorwire"
	"otsec.local/otsec/modules/security/snmpegress"
)

// The SNMP path through the pipeline (P4-3-C3 deliverable 5). The agent is a
// loopback UDP socket that answers discovery at most; every message it sees
// is checked again here with snmpegress.Check. Evidence class: simulated.
// No SNMP agent or device is contacted.

const snmpRunID = "sel27x1.snmp.identity"

// snmpProfile is the test profile for the SEL-2731 whose firmware
// allowlist names C2's test package, sel-27x1-rstp. It is test data; no
// SNMP profile is published yet. C6's slice helper reads the same file.
func snmpProfile(t *testing.T) asset.CapabilityProfile {
	t.Helper()
	p, err := asset.DecodeProfile(readFixture(t, "profile-sel-27x1-rstp.json"))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

type snmpFixture struct {
	*pipeFixture
	agent *net.UDPConn
	asset asset.Asset
	ref   authz.CredentialRef
}

// newSNMPPipeline enrolls the SEL-2731M asset beside the SEL-751, with its
// endpoint moved to a loopback UDP socket (D2-10), activates C2's test
// package under the release key, and installs the USM keys through the
// pipeline.
func newSNMPPipeline(t *testing.T, runner Runner) *snmpFixture {
	t.Helper()
	l, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	a := *snmpAsset(t)
	a.Endpoints[0].Host, a.Endpoints[0].Port = "127.0.0.1", l.LocalAddr().(*net.UDPAddr).Port
	a.Profile = &asset.ProfileRef{ID: "sel-27x1-rstp", Version: "0.1"}
	pkgBytes, err := os.ReadFile(filepath.Join("..", "..", "..", "contracts", "adapter", "testdata", "snmp", "register.json"))
	if err != nil {
		t.Fatal(err)
	}
	enroll := func(c *PipelineConfig, f *pipeFixture) {
		if _, err := f.registers.Activate(signedRegister(t, pkgBytes, f.release, "release-2026")); err != nil {
			t.Fatal(err)
		}
		c.Assets = append(c.Assets, Enrolled{Asset: a, Profile: snmpProfile(t)})
		c.SNMPRunner = runner
	}
	f := &snmpFixture{pipeFixture: newPipeline(t, enroll), agent: l, asset: a}
	f.ref = snmpRef(t, &a, 1)
	reply, work := f.pipe.Handle(context.Background(), installRequest(t, f.pipeFixture, f.ref, usmKeys()))
	if !reply.Accepted() || work != nil {
		t.Fatalf("install: %+v", reply)
	}
	return f
}

// edit changes the enrolled SEL-2731M asset or profile after the credential
// is installed, as a later enrollment would.
func (f *snmpFixture) edit(m func(*Enrolled)) {
	e := f.pipe.assets[f.asset.AssetID]
	m(&e)
	f.pipe.assets[f.asset.AssetID] = e
}

func (f *snmpFixture) runReq(cred string) *authz.CollectorRequest {
	r := pipeRun(snmpRunID, cred)
	r.Run.AssetID, r.Run.RegisterVersion = f.asset.AssetID, 1
	return r
}

// serve answers each datagram with answer's reply (nil: none) and passes
// every datagram on, in order.
func (f *snmpFixture) serve(answer func(req []byte) []byte) <-chan []byte {
	ch := make(chan []byte, 16)
	go func() {
		defer close(ch)
		buf := make([]byte, 65535)
		for {
			n, from, err := f.agent.ReadFromUDP(buf)
			if err != nil {
				return
			}
			req := append([]byte(nil), buf[:n]...)
			ch <- req
			if b := answer(req); b != nil {
				f.agent.WriteToUDP(b, from)
			}
		}
	}()
	return ch
}

// received collects the n datagrams the agent saw, failing if fewer come.
func received(t *testing.T, ch <-chan []byte, n int) [][]byte {
	t.Helper()
	var got [][]byte
	for len(got) < n {
		select {
		case b := <-ch:
			got = append(got, b)
		case <-time.After(5 * time.Second):
			t.Fatalf("the agent saw %d datagrams, want %d", len(got), n)
		}
	}
	select {
	case b := <-ch:
		t.Fatalf("the agent saw a datagram beyond the %d expected: % x", n, b)
	case <-time.After(100 * time.Millisecond):
	}
	return got
}

// egressAllows is the check again, outside the client, for step's operation.
func egressAllows(t *testing.T, f *snmpFixture, step string, engineKnown bool, msg []byte) {
	t.Helper()
	pkg, _, _ := f.registers.Active("sel-27x1-rstp")
	op := pkg.SNMPOperation(step)
	eo := snmpegress.Op{PDU: snmpegress.PDU(op.PDU), OIDs: op.OIDs, Subtree: op.Subtree,
		MaxRepetitions: op.MaxRepetitions, MaxReplyBytes: int(op.Limits.MaxReplyBytes)}
	s := snmpegress.Session{EngineKnown: engineKnown, EngineID: mustHexT(t, snmpEngine), UserName: f.ref.USM.UserName, PrivKey: usmKeys()[32:]}
	if rule := snmpegress.Check(msg, eo, s); rule != snmpegress.Allowed {
		t.Fatalf("egress rule %s for % x", rule, msg)
	}
}

func mustHexT(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// resultOf decodes and validates the outcome's result.
func resultOf(t *testing.T, o *collectorwire.RunOutcome) adapter.Result {
	t.Helper()
	res, err := adapter.DecodeResult(o.Result)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if err := res.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	return res
}

func codeOfResult(res adapter.Result) adapter.Code {
	if res.Error == nil {
		return ""
	}
	return res.Error.Code
}

// nothingSuspended checks the run suspended neither the asset nor the
// credential.
func (f *snmpFixture) nothingSuspended(t *testing.T) {
	t.Helper()
	if err := f.state.CheckSuspended(f.asset.AssetID); err != nil {
		t.Fatalf("asset: %v", err)
	}
	if st := f.store.Status(f.ref.ID); len(st) != 1 || st[0].State != authz.CredentialActive {
		t.Fatalf("credential %+v", st)
	}
}

// The register is the one the profile's firmware allowlist names, never the
// product family's; "none" finds nothing, and the SEL-751 is unchanged (C1
// on deliverable 5, condition 3).
func TestSNMPRegisterByAllowlist(t *testing.T) {
	f := newSNMPPipeline(t, &fakeRunner{})
	pkg, _, ok := f.pipe.registerFor(snmpProfile(t))
	if !ok || pkg.Family != "sel-27x1-rstp" || pkg.Run(snmpRunID) == nil {
		t.Fatalf("sel-2731 profile: %v %+v", ok, pkg)
	}
	pkg, _, ok = f.pipe.registerFor(simProfile(t))
	if !ok || pkg.Family != "sel-751" {
		t.Fatalf("sel-751 profile: %v %+v", ok, pkg)
	}
	none := simProfile(t)
	none.Firmware.Allowlist = "none"
	if _, _, ok := f.pipe.registerFor(none); ok {
		t.Fatal("allowlist none found a package by product family")
	}
	// The SEL-751 runs as before beside the SNMP asset.
	f.installCanary(t)
	if reply, o := f.run(t, pipeRun("sel.ser.read_all", pipeCred)); !reply.Accepted() || o == nil || f.runner.count() != 1 {
		t.Fatalf("SEL-751 run: %+v", reply)
	}
	if len(f.alarmList()) != 0 {
		t.Fatalf("alarms %v", f.alarmList())
	}
}

func TestSNMPRunRefusals(t *testing.T) {
	for _, c := range []struct {
		name string
		edit func(*Enrolled)
		req  func(*snmpFixture) *authz.CollectorRequest
		want authz.RefusalCode
	}{
		{"allowlist none", func(e *Enrolled) { e.Profile.Firmware.Allowlist = "none" },
			func(f *snmpFixture) *authz.CollectorRequest { return f.runReq(f.ref.ID) }, authz.RefuseRegisterUnverified},
		{"another register revision", nil,
			func(f *snmpFixture) *authz.CollectorRequest {
				r := f.runReq(f.ref.ID)
				r.Run.RegisterVersion = 3
				return r
			}, authz.RefuseRegisterVersion},
		{"a contract before runs", nil,
			func(f *snmpFixture) *authz.CollectorRequest {
				r := f.runReq(f.ref.ID)
				r.Contract = "otsec.authz/0.6"
				return r
			}, authz.RefuseUnknownOperation},
		{"parameters", nil,
			func(f *snmpFixture) *authz.CollectorRequest {
				r := f.runReq(f.ref.ID)
				r.Run.Params = map[string]string{"n": "1"}
				return r
			}, authz.RefuseBadParams},
		{"no credential", nil,
			func(f *snmpFixture) *authz.CollectorRequest { return f.runReq("") }, authz.RefuseCredentialMismatch},
		{"a step alone", nil,
			func(f *snmpFixture) *authz.CollectorRequest {
				r := f.runReq(f.ref.ID)
				r.Run.OperationID = "sel27x1.snmp.system"
				return r
			}, authz.RefuseNotInvocable},
		{"another engine ID declared", func(e *Enrolled) {
			for i, at := range e.Asset.Attributes {
				if at.Name == asset.AttrSNMPEngineID {
					e.Asset.Attributes[i].Value = "80007c4f03020000273102"
					for j := range at.Observations {
						e.Asset.Attributes[i].Observations[j].Value = "80007c4f03020000273102"
					}
				}
			}
		}, func(f *snmpFixture) *authz.CollectorRequest { return f.runReq(f.ref.ID) }, authz.RefuseCredentialMismatch},
	} {
		t.Run(c.name, func(t *testing.T) {
			runner := &fakeRunner{}
			f := newSNMPPipeline(t, runner)
			if c.edit != nil {
				f.edit(c.edit)
			}
			reply, _ := f.run(t, c.req(f))
			if refusalOf(reply) != c.want {
				t.Fatalf("got %+v, want %s", reply, c.want)
			}
			if runner.count() != 0 {
				t.Fatal("a refused run reached the runner")
			}
		})
	}
	// No SNMP runner: refused, and the SEL-751 runner is never used.
	f := newSNMPPipeline(t, nil)
	if reply, _ := f.run(t, f.runReq(f.ref.ID)); refusalOf(reply) != authz.RefuseNotInvocable || f.runner.count() != 0 {
		t.Fatalf("no SNMP runner: %+v", reply)
	}
}

// Discovery with no answer: two unauthenticated requests, each one the
// egress check allows, and failed.timeout, which suspends nothing. The
// runner's clock is stepped, an hour behind the wall clock, and does not
// move: each read still waits its full step timeout in real time (C5 and C1
// on #461). Before the fix every read timed out at once.
func TestSNMPRunDiscoveryTimeout(t *testing.T) {
	stepped := time.Now().Add(-time.Hour)
	r := &SNMPRunner{Adapter: adapter.AdapterRef{ID: "sel-27x1-snmpv3", Version: "0.1.0"}, Now: func() time.Time { return stepped }}
	f := newSNMPPipeline(t, r)
	r.Alarm = f.pipe.cfg.Alarm
	ch := f.serve(func([]byte) []byte { return nil })
	start := time.Now()
	reply, o := f.run(t, f.runReq(f.ref.ID))
	if !reply.Accepted() {
		t.Fatalf("refused: %+v", reply)
	}
	// Two reads of the 3000 ms step timeout, less a margin for the timer.
	if waited := time.Since(start); waited < 5500*time.Millisecond {
		t.Fatalf("the reads waited %v in all, want about 6s", waited)
	}
	for _, m := range received(t, ch, 2) {
		egressAllows(t, f, "sel27x1.snmp.system", false, m)
	}
	res := resultOf(t, o)
	if codeOfResult(res) != adapter.FailedTimeout {
		t.Fatalf("code %q", codeOfResult(res))
	}
	f.nothingSuspended(t)
	if len(f.alarmList()) != 0 {
		t.Fatalf("alarms %v", f.alarmList())
	}
}

// Discovery answered with another engine ID: refused.engine_id_mismatch,
// nothing authenticated is sent, and nothing is suspended.
func TestSNMPRunEngineMismatch(t *testing.T) {
	r := &SNMPRunner{Adapter: adapter.AdapterRef{ID: "sel-27x1-snmpv3", Version: "0.1.0"}}
	f := newSNMPPipeline(t, r)
	r.Alarm = f.pipe.cfg.Alarm
	other := mustHexT(t, "80007c4f03020000273199")
	ch := f.serve(func(req []byte) []byte { return discoveryReport(t, req, other) })
	reply, o := f.run(t, f.runReq(f.ref.ID))
	if !reply.Accepted() {
		t.Fatalf("refused: %+v", reply)
	}
	egressAllows(t, f, "sel27x1.snmp.system", false, received(t, ch, 1)[0])
	res := resultOf(t, o)
	if codeOfResult(res) != adapter.RefusedEngineIDMismatch {
		t.Fatalf("code %q", codeOfResult(res))
	}
	f.nothingSuspended(t)
	if len(f.alarmList()) != 0 {
		t.Fatalf("alarms %v", f.alarmList())
	}
}

// Discovery answered with the pinned engine ID: the next message is the
// authPriv request, encrypted with the installed key, which the egress check
// allows. It gets no answer: failed.timeout, nothing suspended. The runner
// has the pipeline's test clock.
func TestSNMPRunAuthPrivThroughEgress(t *testing.T) {
	r := &SNMPRunner{Adapter: adapter.AdapterRef{ID: "sel-27x1-snmpv3", Version: "0.1.0"}}
	f := newSNMPPipeline(t, r)
	r.Alarm, r.Now = f.pipe.cfg.Alarm, f.clock.now
	engine := mustHexT(t, snmpEngine)
	first := true
	ch := f.serve(func(req []byte) []byte {
		if !first {
			return nil
		}
		first = false
		return discoveryReport(t, req, engine)
	})
	reply, o := f.run(t, f.runReq(f.ref.ID))
	if !reply.Accepted() {
		t.Fatalf("refused: %+v", reply)
	}
	got := received(t, ch, 3)
	egressAllows(t, f, "sel27x1.snmp.system", false, got[0])
	for _, m := range got[1:] {
		egressAllows(t, f, "sel27x1.snmp.system", true, m)
	}
	res := resultOf(t, o)
	if codeOfResult(res) != adapter.FailedTimeout {
		t.Fatalf("code %q", codeOfResult(res))
	}
	f.nothingSuspended(t)
	if len(f.alarmList()) != 0 {
		t.Fatalf("alarms %v", f.alarmList())
	}
}

// An authenticated FID mismatch suspends the asset and never the
// credential (Result.SuspendsCredential; D4-54).
func TestSNMPIdentityMismatchSuspendsAssetOnly(t *testing.T) {
	runner := &fakeRunner{result: readFixtureFrom(t, "../../../contracts/adapter/testdata/snmp/results/valid/failed.identity_mismatch.json")}
	f := newSNMPPipeline(t, runner)
	runner.script = func(_ context.Context, plan RunPlan, r *fakeRunner) RunReport {
		return RunReport{Outcome: r.outcome(plan), QUISent: true}
	}
	if reply, _ := f.run(t, f.runReq(f.ref.ID)); !reply.Accepted() {
		t.Fatalf("refused: %+v", reply)
	}
	var ref *authz.Refusal
	if err := f.state.CheckSuspended(f.asset.AssetID); !errors.As(err, &ref) || ref.Code != authz.RefuseAssetSuspended {
		t.Fatalf("asset: %v", err)
	}
	if st := f.store.Status(f.ref.ID); len(st) != 1 || st[0].State != authz.CredentialActive {
		t.Fatalf("credential %+v", st)
	}
}

// The runner refuses before it opens a socket when the FID is undeclared or
// not allowed, or when there is no credential (C2 2.3 step 1).
func TestSNMPRunnerRefusesBeforeSending(t *testing.T) {
	setFID := func(a *asset.Asset, fid string) {
		for i, at := range a.Attributes {
			if at.Name == asset.AttrFirmwareID {
				if fid == "" {
					a.Attributes = append(a.Attributes[:i], a.Attributes[i+1:]...)
					return
				}
				for j := range at.Observations {
					a.Attributes[i].Observations[j].Value = fid
				}
			}
		}
	}
	for _, c := range []struct {
		name string
		edit func(*RunPlan)
		want adapter.Code
	}{
		{"FID undeclared", func(p *RunPlan) { setFID(&p.Asset, "") }, adapter.RefusedFirmwareUndeclared},
		{"FID not allowed", func(p *RunPlan) { setFID(&p.Asset, "SEL-2731M-R999-V1-Z003001-D20260408") }, adapter.RefusedFirmwareNotAllowed},
		{"no credential", func(p *RunPlan) { p.Credential, p.Secret = nil, nil }, adapter.RefusedCredentialUnavailable},
	} {
		t.Run(c.name, func(t *testing.T) {
			a, pkg := snmpAsset(t), snmpRegister(t)
			ref := snmpRef(t, a, 1)
			plan := RunPlan{Asset: *a, Register: pkg, Endpoint: a.Endpoints[0], Credential: &ref,
				Dial: func(context.Context, string, string) (net.Conn, error) {
					t.Fatal("the runner dialled")
					return nil, errors.New("dialled")
				}}
			c.edit(&plan)
			r := &SNMPRunner{}
			if o := r.session(context.Background(), plan, time.Now); o.Code != c.want || len(o.Segments) != 0 {
				t.Fatalf("got %q with %d segments, want %q", o.Code, len(o.Segments), c.want)
			}
		})
	}
}

// --- a discovery Report, by hand -----------------------------------------
//
// Enough BER (RFC 3412 and 3414, as C2's fixtures read them) to read the
// discovery request's msgID and request-id and answer with a Report naming
// an engine ID. Test code only: it shares nothing with the client or the
// egress check.

func berTLV(t *testing.T, b []byte) (byte, []byte, []byte) {
	t.Helper()
	if len(b) < 2 {
		t.Fatalf("BER element cut short: % x", b)
	}
	tag, n, off := b[0], int(b[1]), 2
	if n&0x80 != 0 {
		k := n & 0x7f
		n = 0
		for i := 0; i < k; i++ {
			n = n<<8 | int(b[2+i])
		}
		off += k
	}
	if off+n > len(b) {
		t.Fatalf("BER element cut short: % x", b)
	}
	return tag, b[off : off+n], b[off+n:]
}

func ber(tag byte, parts ...[]byte) []byte {
	v := bytes.Join(parts, nil)
	var hdr []byte
	switch n := len(v); {
	case n < 0x80:
		hdr = []byte{tag, byte(n)}
	case n < 0x100:
		hdr = []byte{tag, 0x81, byte(n)}
	default:
		hdr = []byte{tag, 0x82, byte(n >> 8), byte(n)}
	}
	return append(hdr, v...)
}

func berInt(v int64) []byte {
	b := big.NewInt(v).Bytes()
	if len(b) == 0 || b[0]&0x80 != 0 {
		b = append([]byte{0}, b...)
	}
	return ber(0x02, b)
}

// discoveryReport answers a discovery request with an unauthenticated
// usmStatsUnknownEngineIDs Report from engine.
func discoveryReport(t *testing.T, req []byte, engine []byte) []byte {
	_, msg, _ := berTLV(t, req)
	_, _, rest := berTLV(t, msg) // msgVersion
	_, hdr, rest := berTLV(t, rest)
	_, msgID, _ := berTLV(t, hdr)
	_, _, rest = berTLV(t, rest) // msgSecurityParameters
	_, scoped, _ := berTLV(t, rest)
	_, _, r := berTLV(t, scoped) // contextEngineID
	_, _, r = berTLV(t, r)       // contextName
	_, pdu, _ := berTLV(t, r)
	_, reqID, _ := berTLV(t, pdu)
	id := func(b []byte) int64 { return new(big.Int).SetBytes(b).Int64() }
	usm := ber(0x30, ber(0x04, engine), berInt(0), berInt(0), ber(0x04), ber(0x04), ber(0x04))
	unknownEngineIDs := []byte{0x2b, 6, 1, 6, 3, 15, 1, 1, 4, 0}
	report := ber(0xa8, berInt(id(reqID)), berInt(0), berInt(0),
		ber(0x30, ber(0x30, ber(0x06, unknownEngineIDs), ber(0x41, []byte{1}))))
	return ber(0x30, berInt(3), ber(0x30, berInt(id(msgID)), berInt(1472), ber(0x04, []byte{0}), berInt(3)),
		ber(0x04, usm), ber(0x30, ber(0x04, engine), ber(0x04), report))
}
