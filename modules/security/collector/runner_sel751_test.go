package collector

import (
	"bytes"
	"context"
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
// endpoint on a loopback listener and canary installed.
func hostedFixture(t *testing.T) (*pipeFixture, net.Listener) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	port := l.Addr().(*net.TCPAddr).Port
	f := newPipeline(t,
		withAsset(func(a *asset.Asset) { a.Endpoints[0].Port = port }),
		func(c *PipelineConfig, f *pipeFixture) { c.Runner = &SEL751Runner{Alarm: c.Alarm} },
	)
	reply, work := f.pipe.Handle(context.Background(), installRequest(t, f, pipeRef(1), canary))
	if !reply.Accepted() || work != nil {
		t.Fatalf("install: %+v", reply)
	}
	return f, l
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
		{golden: "refused.password_prompt_absent", assetSusp: asset.SuspendPasswordPromptAbsent,
			want: "device.session.open/succeeded device.refused/denied/password_prompt_absent device.session.close/succeeded"},
		{golden: "failed.transport_closed", hangUp: true, floorSet: true,
			want: "device.session.open/succeeded credential.use/succeeded device.posture_warning/warning/maxacc_above_1 device.op/failed/transport_closed device.session.close/failed/qui_not_sent"},
	}
	for _, c := range cases {
		t.Run(c.golden, func(t *testing.T) {
			t.Parallel()
			f, l := hostedFixture(t)
			want := goldenResult(t, c.golden)
			_, res, recs, _ := hostedRun(t, f, l, pipeRun("sel.ser.read_all", pipeCred), replayTurns(want), c.hangUp)
			if resultCode(res) != resultCode(want) || res.Transcript.SHA256 != want.Transcript.SHA256 {
				t.Fatalf("result %s (transcript %s), want %s (%s)", resultCode(res), res.Transcript.SHA256, resultCode(want), want.Transcript.SHA256)
			}
			if got := shape(recs); got != c.want {
				t.Errorf("records\n got %s\nwant %s", got, c.want)
			}
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

// A Level 0 ID read through the runner: no secret reaches the adapter, so
// sel751 runs it (a nil *SecretHandle in Config.Secret would fail it as
// failed.internal; A2 on #97), and nothing is recorded as a credential use.
func TestSEL751RunnerLevel0(t *testing.T) {
	f, l := hostedFixture(t)
	ok := replayTurns(goldenResult(t, "ok"))
	turns := append(ok[:4:4], ok[len(ok)-1]) // wake, QUI probe, ID; then the closing QUI
	_, res, recs, _ := hostedRun(t, f, l, pipeRun("sel.id", ""), turns, false)
	if res.Status != adapter.StatusOK || res.Session.CredentialSent || !res.Session.QuitSent {
		t.Fatalf("result %s: %+v", resultCode(res), res.Session)
	}
	if got, want := shape(recs), "device.session.open/succeeded device.op/succeeded device.session.close/succeeded"; got != want {
		t.Errorf("records\n got %s\nwant %s", got, want)
	}
	for _, r := range recs {
		if r.Target.CredentialRef != "" {
			t.Errorf("%s names a credential on a Level 0 run", r.Action)
		}
	}
	if err := f.state.CheckFloor(testAsset); err != nil {
		t.Errorf("floor after a clean Level 0 run: %v", err)
	}
}

// A wake answered by "Password: ?" may have been taken as a blank password,
// and a Level 0 run has no floor gate to record it: the runner sets the
// floor itself (A3 on #99).
func TestSEL751RunnerWakeHitsPasswordPrompt(t *testing.T) {
	f, l := hostedFixture(t)
	turns := []turn{{}, {expect: []byte("\r\n"), reply: []byte("\r\nPassword: ? ")}}
	_, res, recs, _ := hostedRun(t, f, l, pipeRun("sel.id", ""), turns, false)
	if resultCode(res) != adapter.FailedInternal || !res.Session.WakeSent {
		t.Fatalf("result %s: %+v", resultCode(res), res.Session)
	}
	if got, want := shape(recs), "device.session.open/succeeded device.session.close/succeeded"; got != want {
		t.Errorf("records\n got %s\nwant %s", got, want)
	}
	if err := f.state.CheckFloor(testAsset); err == nil {
		t.Fatal("no floor after a wake answered by the password prompt")
	}
	// Any other failed.internal leaves the floor alone.
	if wakeHitPassword(adapter.Result{Error: &adapter.Error{Code: adapter.FailedInternal}, Session: adapter.SessionFacts{WakeSent: true}}) {
		t.Error("a failed.internal with no password prompt counted")
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
	_, res, recs, wire := hostedRun(t, f, l, pipeRun("sel.ser.read_all", pipeCred), turns, true)
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
