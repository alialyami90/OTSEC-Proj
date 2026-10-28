package collector

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"otsec.local/otsec/contracts/adapter"
	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/audit"
	"otsec.local/otsec/contracts/authz"
	"otsec.local/otsec/modules/security/collectorwire"
)

// The SEL-751 runner tests drive the whole pipeline, with A2's sel751.Run
// hosted, against a far end on a loopback TCP port that replays a C2
// golden's transcript (contracts/adapter/testdata/results/valid). Every
// transcript is invented (C2 testdata README): simulated evidence only.

// The C2 goldens were written with the test secret "otsec-lab-pw-1", which
// is 14 bytes: the SEL-751 profile's secret policy refuses it at install.
// Their transcripts hold only the redaction marker, so the far end sends
// and expects canary, a test value that installs, and the stored
// transcript and its digest are the golden's.

func goldenResult(t testing.TB, name string) adapter.Result {
	t.Helper()
	r, err := adapter.DecodeResult(readFixtureFrom(t, "../../../contracts/adapter/testdata/results/valid/"+name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// turn is one step of the scripted far end: the bytes it must receive
// (none for the first), then the bytes it answers with.
type turn struct{ expect, reply []byte }

// replayTurns cuts a golden transcript into turns. A redacted echo is sent
// as the secret itself, as a relay that echoes would; the credential line
// is expected as the secret and CR LF.
func replayTurns(r adapter.Result) []turn {
	tr := r.Transcript
	red := map[int64]bool{}
	for _, rd := range tr.Redactions {
		red[rd.Offset] = true
	}
	wire := func(sg adapter.Segment) []byte {
		b := tr.Data[sg.Offset : sg.Offset+sg.Length]
		var out []byte
		for i := int64(0); i < int64(len(b)); i++ {
			if red[sg.Offset+i] {
				out = append(out, canary...)
				i += int64(len(adapter.RedactionMarker)) - 1
				continue
			}
			out = append(out, b[i])
		}
		return out
	}
	turns := []turn{{}}
	for _, sg := range tr.Segments {
		if sg.Dir == adapter.Sent {
			turns = append(turns, turn{expect: wire(sg)})
			continue
		}
		last := &turns[len(turns)-1]
		last.reply = append(last.reply, wire(sg)...)
	}
	return turns
}

// farEndOn accepts one connection on l and plays turns on it. With hangUp
// it closes after the last reply; otherwise anything more it receives is a
// line the script does not have.
func farEndOn(l net.Listener, turns []turn, hangUp bool) <-chan error {
	done := make(chan error, 1)
	go func() {
		// A run that never connects ends the far end, not the test binary.
		_ = l.(*net.TCPListener).SetDeadline(time.Now().Add(10 * time.Second))
		c, err := l.Accept()
		if err != nil {
			done <- fmt.Errorf("no connection: %w", err)
			return
		}
		defer c.Close()
		for i, st := range turns {
			if len(st.expect) > 0 {
				got := make([]byte, len(st.expect))
				_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
				if _, err := io.ReadFull(c, got); err != nil || !bytes.Equal(got, st.expect) {
					done <- fmt.Errorf("turn %d: received %q (%v), want %q", i, got, err, st.expect)
					return
				}
			}
			if len(st.reply) > 0 {
				if _, err := c.Write(st.reply); err != nil {
					done <- fmt.Errorf("turn %d: %v", i, err)
					return
				}
			}
		}
		if !hangUp {
			_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
			if extra, _ := io.ReadAll(c); len(extra) > 0 {
				done <- fmt.Errorf("after the script: received %q", extra)
				return
			}
		}
		done <- nil
	}()
	return done
}

// hostedFixture is a pipeline hosting the SEL-751 runner, with the asset's
// endpoint on a loopback listener and canary installed. extra options
// apply after its own.
func hostedFixture(t *testing.T, extra ...pipeOption) (*pipeFixture, net.Listener) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	port := l.Addr().(*net.TCPAddr).Port
	f := newPipeline(t, append([]pipeOption{
		withAsset(func(a *asset.Asset) { a.Endpoints[0].Port = port }),
		func(c *PipelineConfig, f *pipeFixture) { c.Runner = &SEL751Runner{Alarm: c.Alarm} },
	}, extra...)...)
	// The register on main (revision 4): its context read puts SHO G before
	// SER, as the C2 goldens do (C3 0.2, D3-2).
	if _, err := f.registers.Activate(signedRegister(t, readFixtureFrom(t, "../../../contracts/register/testdata/sel-751.json"), f.release, "release-2026")); err != nil {
		t.Fatal(err)
	}
	reply, work := f.pipe.Handle(context.Background(), installRequest(t, f, pipeRef(1), canary))
	if !reply.Accepted() || work != nil {
		t.Fatalf("install: %+v", reply)
	}
	return f, l
}

// hostedReq is pipeRun at the register revision hostedFixture activates.
func hostedReq(op, cred string) *authz.CollectorRequest {
	r := pipeRun(op, cred)
	r.Run.RegisterVersion = 4
	return r
}

// hostedRun runs one request against a far end playing turns.
func hostedRun(t *testing.T, f *pipeFixture, l net.Listener, req *authz.CollectorRequest, turns []turn, hangUp bool) (authz.CollectorReply, adapter.Result, []*audit.Record, []byte) {
	t.Helper()
	done := farEndOn(l, turns, hangUp)
	reply, o := f.run(t, req)
	if o == nil {
		t.Fatalf("no outcome: %+v", reply)
	}
	if err := <-done; err != nil {
		t.Errorf("far end: %v", err)
	}
	wire, err := collectorwire.EncodeOutcome(*o)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(wire, canary) {
		t.Fatal("the secret is in the outcome")
	}
	res, err := adapter.DecodeResult(o.Result)
	if err != nil {
		t.Fatalf("result: %v", err)
	}
	return reply, res, reportedRecords(t, reply, *o, res), wire
}

// reportedRecords applies the node's checks (collectorclient) to the
// outcome's records: each valid C8 0.2, reported by the collector, numbered
// above the reply and rising, correlated to the invocation, with at most
// one paired open and close whose digest is the result's.
func reportedRecords(t *testing.T, reply authz.CollectorReply, o collectorwire.RunOutcome, res adapter.Result) []*audit.Record {
	t.Helper()
	var recs []*audit.Record
	last := reply.CollectorSeq
	opens, closes := 0, 0
	for i, raw := range o.Audit {
		r, err := audit.ValidatePending(raw)
		if err != nil {
			t.Fatalf("record %d: %v\n%s", i, err, raw)
		}
		if !audit.CollectorReported(r) || r.CollectorSeq <= last || r.Actor.Type != authz.PrincipalSchedule || r.Actor.Role != authz.RoleCollector {
			t.Fatalf("record %d: %+v after collector_seq %d", i, r, last)
		}
		if r.Action != audit.ActionCredentialSuspend && r.CorrelationID != res.InvocationID {
			t.Fatalf("record %d correlates to %q", i, r.CorrelationID)
		}
		last = r.CollectorSeq
		switch r.Action {
		case audit.ActionDeviceSessionOpen:
			opens++
		case audit.ActionDeviceSessionClose:
			closes++
			if r.TranscriptSHA256 != res.Transcript.SHA256 {
				t.Fatalf("close names %s, result has %s", r.TranscriptSHA256, res.Transcript.SHA256)
			}
		}
		recs = append(recs, r)
	}
	if opens > 1 || opens != closes || (len(res.Transcript.Data) > 0) != (opens == 1) {
		t.Fatalf("%d opens and %d closes for a transcript of %d bytes", opens, closes, len(res.Transcript.Data))
	}
	return recs
}

// shape is each record as action[/outcome[/reason]] for comparison.
func shape(recs []*audit.Record) string {
	var out []string
	for _, r := range recs {
		s := string(r.Action) + "/" + string(r.Outcome)
		if r.ReasonCode != "" {
			s += "/" + r.ReasonCode
		}
		out = append(out, s)
	}
	return strings.Join(out, " ")
}

func resultCode(r adapter.Result) adapter.Code {
	if r.Error == nil {
		return ""
	}
	return r.Error.Code
}

// checkFields pins what T-1 to T-12 and the slice suite reconcile
// against, beyond action, outcome and reason (A6 on #112): the actor, the
// target, device.op's operation_id and its bytes_sent_digest recomputed
// here from the transcript's operate-phase lines (none when there are
// none, as on a Level 0 read), and each posture warning's detail, which is
// the register's setting name.
func checkFields(t *testing.T, recs []*audit.Record, res adapter.Result, op string, level1 bool) {
	t.Helper()
	var sent []byte
	operated := false
	for _, sg := range res.Transcript.Segments {
		if sg.Dir == adapter.Sent && sg.Phase == adapter.PhaseOperate {
			operated = true
			sent = append(sent, res.Transcript.Data[sg.Offset:sg.Offset+sg.Length]...)
		}
	}
	warnings := 0
	for _, r := range recs {
		if r.Actor.ID != schedule.ID {
			t.Errorf("%s: actor %+v", r.Action, r.Actor)
		}
		tg := r.Target
		if tg == nil || tg.AssetID != testAsset || tg.Family != "sel-751" || tg.Transport != authz.TransportTelnet || tg.DownstreamSecurity != authz.DownstreamPlaintext {
			t.Errorf("%s: target %+v", r.Action, tg)
			continue
		}
		if level1 != (tg.CredentialRef == pipeCred && tg.CredentialVersion == 1) || (!level1 && (tg.CredentialRef != "" || tg.CredentialVersion != 0)) {
			t.Errorf("%s: credential %s version %d on a level 1 run %v", r.Action, tg.CredentialRef, tg.CredentialVersion, level1)
		}
		switch r.Action {
		case audit.ActionDeviceOp:
			if r.OperationID != op {
				t.Errorf("device.op names %q, want %q", r.OperationID, op)
			}
			want := ""
			if operated {
				sum := sha256.Sum256(sent)
				want = "sha256:" + hex.EncodeToString(sum[:])
			}
			if r.BytesSentDigest != want {
				t.Errorf("device.op digest %q, want %q", r.BytesSentDigest, want)
			}
		case audit.ActionDevicePostureWarning:
			if warnings >= len(res.Warnings) || r.Detail != res.Warnings[warnings].Setting || r.Detail == "" {
				t.Errorf("posture warning %d: detail %q, result warnings %+v", warnings, r.Detail, res.Warnings)
			}
			warnings++
		}
	}
	if warnings != len(res.Warnings) {
		t.Errorf("%d posture warning records for %d warnings", warnings, len(res.Warnings))
	}
}

func TestSEL751RunnerGoldens(t *testing.T) {
	cases := []struct {
		golden string
		hangUp bool
		want   string
		// floorSet: after the run the asset's failed-auth floor holds.
		floorSet  bool
		credSusp  bool
		assetSusp asset.SuspensionReason
	}{
		{golden: "ok", want: "device.session.open/succeeded credential.use/succeeded device.posture_warning/warning/maxacc_above_1 device.op/succeeded device.session.close/succeeded"},
		{golden: "ok-with-echo", want: "device.session.open/succeeded credential.use/succeeded device.posture_warning/warning/maxacc_above_1 device.op/succeeded device.session.close/succeeded"},
		{golden: "failed.auth_rejected", floorSet: true, credSusp: true, assetSusp: asset.SuspendAuthFailed,
			want: "device.session.open/succeeded credential.use/failed/auth_rejected device.session.close/succeeded credential.suspend/succeeded/auth_failed"},
		{golden: "refused.identity_mismatch", assetSusp: asset.SuspendIdentityMismatch,
			want: "device.session.open/succeeded device.refused/denied/identity_mismatch device.session.close/succeeded"},
		// Level 1 was confirmed and the relay hung up before QUI, so the
		// floor is set again for TIDLE (C7-A6-2).
		// The golden ends at Level 1 without QUI, so the floor is set
		// again.
		{golden: "refused.language_not_english", floorSet: true, assetSusp: asset.SuspendLanguageNotEnglish,
			want: "device.session.open/succeeded credential.use/succeeded device.refused/denied/language_not_english device.session.close/failed/qui_not_sent"},
		// A failure before the operate phase names its code on device.op
		// (A3 on #122): before the login, and after a confirmed one.
		{golden: "failed.identity_unreadable",
			want: "device.session.open/succeeded device.op/failed/identity_unreadable device.session.close/succeeded"},
		{golden: "failed.identity_mismatch", credSusp: true, assetSusp: asset.SuspendIdentityMismatch,
			want: "device.session.open/succeeded credential.use/succeeded device.posture_warning/warning/maxacc_above_1 device.op/failed/identity_mismatch device.session.close/succeeded credential.suspend/succeeded/identity_mismatch"},
		{golden: "failed.device_error",
			want: "device.session.open/succeeded credential.use/succeeded device.posture_warning/warning/maxacc_above_1 device.op/failed/device_error device.session.close/succeeded"},
		// A login that was not confirmed is named by credential.use alone.
		{golden: "failed.unexpected_access_level", floorSet: true, credSusp: true, assetSusp: asset.SuspendUnexpectedLevel,
			want: "device.session.open/succeeded credential.use/failed/unexpected_access_level device.session.close/succeeded credential.suspend/succeeded/unexpected_access_level"},
		{golden: "refused.password_prompt_absent", assetSusp: asset.SuspendPasswordPromptAbsent,
			want: "device.session.open/succeeded device.refused/denied/password_prompt_absent device.session.close/succeeded"},
		{golden: "failed.transport_closed", hangUp: true, floorSet: true,
			want: "device.session.open/succeeded credential.use/succeeded device.posture_warning/warning/maxacc_above_1 device.op/failed/transport_closed device.session.close/failed/qui_not_sent"},
		// A partial result is an operation that ran (A6 on #112).
		{golden: "partial.parse_errors", want: "device.session.open/succeeded credential.use/succeeded device.posture_warning/warning/maxacc_above_1 device.op/succeeded device.session.close/succeeded"},
	}
	for _, c := range cases {
		t.Run(c.golden, func(t *testing.T) {
			t.Parallel()
			f, l := hostedFixture(t)
			want := goldenResult(t, c.golden)
			_, res, recs, _ := hostedRun(t, f, l, hostedReq("sel.ser.read_all", pipeCred), replayTurns(want), c.hangUp)
			if resultCode(res) != resultCode(want) || res.Transcript.SHA256 != want.Transcript.SHA256 {
				t.Fatalf("result %s (transcript %s), want %s (%s)", resultCode(res), res.Transcript.SHA256, resultCode(want), want.Transcript.SHA256)
			}
			if got := shape(recs); got != c.want {
				t.Errorf("records\n got %s\nwant %s", got, c.want)
			}
			checkFields(t, recs, res, "sel.ser.read_all", true)
			if a := f.alarmList(); len(a) != 0 {
				t.Errorf("alarms: %v", a)
			}
			if err := f.state.CheckFloor(testAsset); (err != nil) != c.floorSet {
				t.Errorf("floor after the run: %v, want set %v", err, c.floorSet)
			}
			if err := f.state.CheckSuspended(testAsset); (err != nil) != (c.assetSusp != "") {
				t.Errorf("asset after the run: %v, want suspended %q", err, c.assetSusp)
			}
			st := f.store.Status(pipeCred)
			if len(st) != 1 || (st[0].State == authz.CredentialSuspended) != c.credSusp {
				t.Errorf("credential after the run: %+v, want suspended %v", st, c.credSusp)
			}
		})
	}
}

// A run cut off before the operate phase names its code on device.op,
// whether the login had not happened or was confirmed; one cut off before
// the login was confirmed is named by credential.use alone (A3 on #122, A6
// on #124). The relay hangs up after the reply to the last line listed.
func TestSEL751RunnerFailureBeforeOperate(t *testing.T) {
	ok := replayTurns(goldenResult(t, "ok"))
	for _, c := range []struct {
		name  string
		last  string // the last line the far end answers
		turns int
		want  string
	}{
		{"before the login", "ID\r\n", 4,
			"device.session.open/succeeded device.op/failed/transport_closed device.session.close/succeeded"},
		{"login not confirmed", "ACC\r\n", 5,
			"device.session.open/succeeded credential.use/failed/transport_closed device.session.close/succeeded"},
		{"after a confirmed login", string(canary) + "\r\n", 6,
			"device.session.open/succeeded credential.use/succeeded device.op/failed/transport_closed device.session.close/failed/qui_not_sent"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := string(ok[c.turns-1].expect); got != c.last {
				t.Fatalf("turn %d expects %q, want %q: the ok golden changed", c.turns, got, c.last)
			}
			f, l := hostedFixture(t)
			_, res, recs, _ := hostedRun(t, f, l, hostedReq("sel.ser.read_all", pipeCred), ok[:c.turns], true)
			if resultCode(res) != adapter.FailedTransportClosed {
				t.Fatalf("result %s", resultCode(res))
			}
			if got := shape(recs); got != c.want {
				t.Errorf("records\n got %s\nwant %s", got, c.want)
			}
			checkFields(t, recs, res, "sel.ser.read_all", true)
		})
	}
}

// A Level 0 ID read through the runner: no secret reaches the adapter, so
// sel751 runs it (a nil *SecretHandle in Config.Secret would fail it as
// failed.internal; A2 on #97), and nothing is recorded as a credential use.
func TestSEL751RunnerLevel0(t *testing.T) {
	f, l := hostedFixture(t)
	ok := replayTurns(goldenResult(t, "ok"))
	turns := append(ok[:4:4], ok[len(ok)-1]) // wake, QUI probe, ID; then the closing QUI
	_, res, recs, _ := hostedRun(t, f, l, hostedReq("sel.id", ""), turns, false)
	if res.Status != adapter.StatusOK || res.Session.CredentialSent || !res.Session.QuitSent {
		t.Fatalf("result %s: %+v", resultCode(res), res.Session)
	}
	if got, want := shape(recs), "device.session.open/succeeded device.op/succeeded device.session.close/succeeded"; got != want {
		t.Errorf("records\n got %s\nwant %s", got, want)
	}
	// sel.id is sent in the probe phase, so device.op has no digest.
	checkFields(t, recs, res, "sel.id", false)
	if err := f.state.CheckFloor(testAsset); err != nil {
		t.Errorf("floor after a clean Level 0 run: %v", err)
	}
}

// A line answered by "Password: ?" may have landed as a password, and a
// Level 0 run has no floor gate to record it: the runner sets the floor
// itself (A3 on #99), keyed on the end state, not on the wake (A6 on #112).
func TestSEL751RunnerPasswordPromptSetsFloor(t *testing.T) {
	ok := replayTurns(goldenResult(t, "ok"))
	for _, c := range []struct {
		name  string
		turns []turn
		wake  bool
		check func(t *testing.T, res adapter.Result)
	}{
		{name: "wake answered by the prompt", wake: true,
			turns: replayTurns(goldenResult(t, "failed.internal-wake-password-prompt")),
			check: func(t *testing.T, res adapter.Result) {
				if want := goldenResult(t, "failed.internal-wake-password-prompt"); res.Transcript.SHA256 != want.Transcript.SHA256 {
					t.Errorf("transcript %s, want the golden's %s", res.Transcript.SHA256, want.Transcript.SHA256)
				}
			}},
		// The relay greets with its prompt, so no wake is sent, and ID is
		// answered by the password prompt.
		{name: "ID answered by the prompt, no wake",
			turns: []turn{{reply: []byte("\r\n=")}, {expect: ok[2].expect, reply: ok[2].reply}, {expect: []byte("ID\r\n"), reply: []byte("ID\r\nPassword: ? ")}}},
	} {
		t.Run(c.name, func(t *testing.T) {
			f, l := hostedFixture(t)
			_, res, recs, _ := hostedRun(t, f, l, hostedReq("sel.id", ""), c.turns, false)
			if resultCode(res) != adapter.FailedInternal || res.Session.WakeSent != c.wake || res.Session.CredentialSent {
				t.Fatalf("result %s: %+v", resultCode(res), res.Session)
			}
			if c.check != nil {
				c.check(t, res)
			}
			if got, want := shape(recs), "device.session.open/succeeded device.op/failed/internal device.session.close/succeeded"; got != want {
				t.Errorf("records\n got %s\nwant %s", got, want)
			}
			if err := f.state.CheckFloor(testAsset); err == nil {
				t.Fatal("no floor after a line answered by the password prompt")
			}
		})
	}
}

// endsAtPasswordPrompt follows sel751's prompt rule.
func TestEndsAtPasswordPrompt(t *testing.T) {
	tr := func(parts ...string) adapter.Transcript {
		var t adapter.Transcript
		for i, p := range parts {
			dir := adapter.Received
			if i%2 == 1 {
				dir = adapter.Sent
			}
			if strings.HasPrefix(p, "rx:") {
				dir, p = adapter.Received, p[3:]
			}
			t.Segments = append(t.Segments, adapter.Segment{Dir: dir, Offset: int64(len(t.Data)), Length: int64(len(p))})
			t.Data = append(t.Data, p...)
		}
		return t
	}
	for _, c := range []struct {
		name string
		t    adapter.Transcript
		want bool
	}{
		{"prompt", tr("\r\n=", "ID\r\n", "ID\r\nPassword: ? "), true},
		{"first in the reply", tr("Password: ?"), true},
		{"NUL inside", tr("\r\nPass\x00word: ?\x00 "), true},
		{"XON and XOFF", tr("\r\nPassword: ?\x11 \x13"), true},
		{"split across reads", tr("\r\nPassw", "rx:ord: ? "), true},
		{"after STX", tr("\x02Password: ?"), true},
		{"inside a setting", tr("\r\nDEVID=Password: ?"), false},
		{"Level 1 after the prompt", tr("Password: ? ", "Canary-7f3K\r\n", "\r\n=>"), false},
		{"a line sent after it", tr("Password: ? ", "QUI\r\n"), false},
		{"Level 0 prompt", tr("\r\n="), false},
		{"empty", adapter.Transcript{}, false},
		{"segment outside the data", adapter.Transcript{Data: []byte("Password: ?"), Segments: []adapter.Segment{{Dir: adapter.Received, Offset: 0, Length: 99}}}, false},
	} {
		if got := endsAtPasswordPrompt(c.t); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}

// An echo of the secret cut off by the far end is redacted in the stored
// transcript (EchoSpans' partial rule, which needs the reply right after
// the secret to be the first one scanned; A6 on #106), and the secret
// reaches neither the outcome nor the records.
func TestSEL751RunnerCutEcho(t *testing.T) {
	f, l := hostedFixture(t)
	turns := replayTurns(goldenResult(t, "ok"))
	// The turn after the credential line: the relay echoes the first part
	// of the secret and hangs up.
	var i int
	for i = range turns {
		if bytes.Equal(turns[i].expect, append(append([]byte(nil), canary...), '\r', '\n')) {
			break
		}
	}
	if i == len(turns)-1 {
		t.Fatal("no credential line in the script")
	}
	turns = turns[:i+1]
	turns[i].reply = append([]byte(nil), canary[:5]...)
	_, res, recs, wire := hostedRun(t, f, l, hostedReq("sel.ser.read_all", pipeCred), turns, true)
	if bytes.Contains(res.Transcript.Data, canary[:5]) || bytes.Contains(wire, canary[:5]) {
		t.Fatalf("part of the secret is stored: %q", res.Transcript.Data)
	}
	if len(res.Transcript.Redactions) == 0 {
		t.Fatal("no redaction")
	}
	if !strings.HasPrefix(shape(recs), "device.session.open/succeeded credential.use/") {
		t.Errorf("records %s", shape(recs))
	}
}

// A context read is permitted only by a package that declares it (A3 on
// D3-2): the C2 ok golden, with SHO G between SHO P 1 and SER, checked
// against revision 3, which has no context, is a line on the wire the
// register does not allow.
func TestContextReadRefusedUnderRev3(t *testing.T) {
	f := newPipeline(t) // revision 3 active
	f.installCanary(t)
	var m map[string]any
	if err := json.Unmarshal(readFixtureFrom(t, "../../../contracts/adapter/testdata/results/valid/ok.json"), &m); err != nil {
		t.Fatal(err)
	}
	m["register_version"] = 3
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if r, err := adapter.DecodeResult(b); err != nil || !bytes.Contains(r.Transcript.Data, []byte("SHO G\r\n")) {
		t.Fatalf("the ok golden has no SHO G: %v", err)
	}
	f.runner.result = b
	f.run(t, pipeRun("sel.ser.read_all", pipeCred))
	a := f.alarmList()
	if len(a) != 1 || !strings.Contains(a[0].Error(), "does not allow") || !strings.Contains(a[0].Error(), "SHO G") {
		t.Fatalf("alarms: %v", a)
	}
}
