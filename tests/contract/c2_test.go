package contract

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"os"
	"path/filepath"

	"otsec.local/otsec/contracts/adapter"
	"otsec.local/otsec/contracts/register"
)

// C2 otsec.adapter/0.1: A6's probes from the C2 review (C2-A6.md, P1 to P17
// and the safe-path controls). Each negative case is a session that
// validated at e1d6374 or aa68287 and must be refused; the expected verdicts
// come from doc.go's rules and S22 pp. 7.16, 7.28, 7.33, ADR-0005, AP-27,
// C-17, C-19, D16 and C7-A2-5. Transcripts are A6's own, synthetic.

type seg struct {
	dir   adapter.Direction
	phase adapter.Phase
	b     string
}

const (
	fid      = "SEL-751-R501-V0-Z104101-D20260910"
	hdr      = "\x02\r\nSEL-751          Date: 10/24/2026  Time: 09:15:00\r\nFEEDER 1         Time Source: Internal\r\n\r\n"
	quiReply = "QUI\r\n" + hdr + "\x03="
	idReply  = "ID\r\n\x02\"FID=" + fid + "\",\"0000\"\r\n\x03="
	lvl1     = "\r\n" + hdr + "Level 1\r\n\x03=>"
	serReply = "SER\r\n\x02\r\nSEL-751\r\n\r\n#  DATE TIME ELEMENT STATE\r\n1  10/24/2026 09:10:01.004  IN101  Asserted\r\n\x03=>"
)

var (
	pProbe = []seg{
		{adapter.Received, adapter.PhaseProbe, "\r\n="},
		{adapter.Sent, adapter.PhaseProbe, "QUI\r\n"},
		{adapter.Received, adapter.PhaseProbe, quiReply},
		{adapter.Sent, adapter.PhaseProbe, "ID\r\n"},
		{adapter.Received, adapter.PhaseProbe, idReply},
	}
	pAuth = []seg{
		{adapter.Sent, adapter.PhaseAuth, "ACC\r\n"},
		{adapter.Received, adapter.PhaseAuth, "ACC\r\nPassword: ?"},
		{adapter.Sent, adapter.PhaseAuth, adapter.RedactionMarker + "\r\n"},
		{adapter.Received, adapter.PhaseAuth, lvl1},
	}
	pOperate = []seg{
		{adapter.Sent, adapter.PhaseOperate, "SER\r\n"},
		{adapter.Received, adapter.PhaseOperate, serReply},
	}
	pClose = []seg{{adapter.Sent, adapter.PhaseClose, "QUI\r\n"}}
)

func cat(parts ...[]seg) []seg {
	var out []seg
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// c2Result builds a result whose transcript is segs, with the credential
// redaction placed on the marker and the firmware_id item on the first FID.
func c2Result(segs []seg, code adapter.Code) adapter.Result {
	var data []byte
	var t adapter.Transcript
	for _, s := range segs {
		off := int64(len(data))
		data = append(data, s.b...)
		t.Segments = append(t.Segments, adapter.Segment{Offset: off, Length: int64(len(s.b)), Dir: s.dir, Phase: s.phase, At: "2026-10-24T09:15:00Z"})
		if s.dir == adapter.Sent && strings.HasPrefix(s.b, adapter.RedactionMarker) {
			t.Redactions = append(t.Redactions, adapter.Redaction{Offset: off, Length: int64(len(adapter.RedactionMarker)), Reason: adapter.RedactCredential, Component: "transport"})
		}
	}
	if data == nil {
		data = []byte{}
	}
	sum := sha256.Sum256(data)
	t.Data, t.SHA256 = data, hex.EncodeToString(sum[:])
	cred := len(t.Redactions) == 1
	r := adapter.Result{
		Schema: "otsec.adapter/0.1", InvocationID: "0b6c2f4e-1d3a-4c5b-8e7f-9a0b1c2d3e4f",
		Adapter: adapter.AdapterRef{ID: "a6-probe", Version: "0"}, RegisterVersion: 1, OperationID: "sel.ser.read_all",
		Target: "simulated", Status: adapter.StatusOK,
		StartedAt: "2026-10-24T09:15:00Z", EndedAt: "2026-10-24T09:15:02Z",
		Transcript: t,
		Session: adapter.SessionFacts{
			Connected: len(data) > 0, LanguageProbe: adapter.ProbeNotRun,
			PasswordPrompt: cred, CredentialSent: cred, EchoScan: adapter.EchoScanNotApplicable,
			AccessLevel: "0",
		},
		Identity: adapter.IdentityCheck{Result: adapter.IdentityNotChecked},
	}
	for _, s := range segs {
		if s.phase == adapter.PhaseProbe && s.dir == adapter.Sent && s.b == "QUI\r\n" {
			r.Session.LanguageProbe = adapter.ProbeAccepted
		}
		if s.phase == adapter.PhaseClose && s.dir == adapter.Sent {
			r.Session.QuitSent = true
		}
		if s.dir == adapter.Received && strings.HasSuffix(s.b, "=>") {
			r.Session.AccessLevel = "1"
		}
	}
	if cred {
		r.Session.EchoScan = adapter.EchoScanPerformed
	}
	if i := bytes.Index(data, []byte(fid)); i >= 0 {
		r.Identity = adapter.IdentityCheck{Result: adapter.IdentityMatch, Items: []adapter.IdentityItem{
			{Name: "firmware_id", Expected: fid, Observed: fid, Span: adapter.Span{Offset: int64(i), Length: int64(len(fid))}}}}
	}
	if code != "" {
		r.Status = code.Status()
		r.Error = &adapter.Error{Code: code}
	}
	return r
}

func TestC2SessionRules(t *testing.T) {
	base := c2Result(cat(pProbe, pAuth, pOperate, pClose), "")
	if err := base.Validate(); err != nil {
		t.Fatalf("A6 base result does not validate: %v", err)
	}

	noProbe := c2Result(cat(pProbe[:1], pProbe[3:], pAuth, pOperate, pClose), "")
	noProbe.Session.LanguageProbe = adapter.ProbeNotRun

	promptClaimed := c2Result(cat(pProbe, []seg{pAuth[0], {adapter.Received, adapter.PhaseAuth, "ACC\r\n" + hdr + "Level 1\r\n\x03=>"}, pAuth[2], pAuth[3]}, pOperate, pClose), "")

	timeoutThenQui := c2Result(cat(pProbe, pAuth[:3], pClose), adapter.FailedTimeout)
	timeoutThenQui.Session.AccessLevel = "0"

	lateIdentity := c2Result(cat(pProbe[:3], pAuth, []seg{{adapter.Sent, adapter.PhaseOperate, "ID\r\n"}, {adapter.Received, adapter.PhaseOperate, idReply[:len(idReply)-1] + "=>"}}, pClose), "")

	notQui := c2Result(cat(pProbe, pAuth, pOperate, []seg{{adapter.Sent, adapter.PhaseClose, "ACC\r\n"}}), "")

	timeoutAtL1NoQui := c2Result(cat(pProbe, pAuth, pOperate[:1]), adapter.FailedTimeout)

	elevatedNotSeen := c2Result(pProbe[:1], adapter.RefusedSessionElevated)
	elevatedNotSeen.Session.AccessLevel = "1"

	levelClaimed := c2Result(cat(pProbe, pClose), "")
	levelClaimed.Session.AccessLevel = "1"

	notAPrompt := c2Result(cat([]seg{{adapter.Received, adapter.PhaseProbe, "\r\n\"CID=E754\",\"0000\"\r\nDEVID="}}, pProbe[1:], pAuth, pOperate, pClose), "")

	for _, tc := range []struct {
		name string
		r    adapter.Result
	}{
		{"ok without the language probe (ADR-0005, F-007)", noProbe},
		{"password_prompt claimed, auth rx shows no prompt (C-17)", promptClaimed},
		{"timeout after the password, then QUI (C-19)", timeoutThenQui},
		{"identity item only after the password (AP-27)", lateIdentity},
		{"quit_sent with a close line that is not QUI", notQui},
		{"timeout at Level 1 without QUI (D18)", timeoutAtL1NoQui},
		{"session_elevated with only \"=\" received", elevatedNotSeen},
		{"access_level 1 with no \"=>\" received", levelClaimed},
		{"probe line after a field ending \"=\", no prompt", notAPrompt},
	} {
		if err := tc.r.Validate(); err == nil {
			t.Errorf("accepted: %s", tc.name)
		} else {
			t.Logf("refused: %s: %v", tc.name, err)
		}
	}
}

func TestC2ResultDecodeStrict(t *testing.T) {
	b, _ := json.Marshal(c2Result(cat(pProbe, pAuth, pOperate, pClose), ""))
	extra := bytes.Replace(b, []byte(`{"schema"`), []byte(`{"a6_unknown":1,"schema"`), 1)
	if _, err := adapter.DecodeResult(extra); err == nil {
		t.Errorf("accepted: 0.1 result with an unknown field")
	}
}

type lvl0 struct{}

func (lvl0) Invocable(string, map[string]string) (string, error) { return "0", nil }

func TestC2Level0NoCredential(t *testing.T) {
	inv := `{"schema":"otsec.adapter/0.1","invocation_id":"0b6c2f4e-1d3a-4c5b-8e7f-9a0b1c2d3e4f",
"requested_at":"2026-10-24T09:00:00Z","principal_ref":"sched_a6a6a6a6","asset_id":"0b6c2f4e-1d3a-4c5b-8e7f-9a0b1c2d3e4f",
"endpoint_id":"telnet-1","profile_id":"sel-751-ascii","operation_id":"sel.id","credential_ref":"cred_a6a6a6a6",
"expected_identity":[{"name":"firmware_id","value":"` + fid + `"}],
"limits":{"connect_timeout_ms":5000,"step_timeout_ms":5000,"deadline_ms":60000,"max_response_bytes":65536,"connect_retries":0,"min_interval_ms":60000}}`
	v, err := adapter.DecodeInvocation([]byte(inv))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if err := v.ValidateWith(lvl0{}); err == nil {
		t.Errorf("accepted: level-0 operation with a credential_ref (C7-A2-5)")
	} else {
		var ce *adapter.CodedError
		errors.As(err, &ce)
		t.Logf("refused %v", ce.Code)
	}
}

func TestC2ProbeReplyGrammar(t *testing.T) {
	for _, tc := range []struct {
		rx   string
		want bool
	}{
		{"QUI\r\n=", true},
		{"QUIT\r\n=", true},
		{"=", true},
		{"Q\x02U\x00I\r\n=", true},
		{"QUI\r\n\x02\r\n\x03=\x03", true},
		{"= ", false},
		{"QUI\r\n=>", false},
		{"\r\nLevel 1\r\n=", false},
		{"QUI\r\nInvalid Command\r\n=", false},
		{"ABCDEFGHIJKLMNOPQ Date: 10/24/2026 Time: 09:15:00\r\nX Time Source: Internal\r\n=", false},
		{"=\r\n=", false},
		{"qui\r\n=", false},
		{"QUI\r\n\xff=", false},
		{"Nivel 0\r\n=", false},
	} {
		if got := adapter.ProbeReplyAccepted([]byte(tc.rx)); got != tc.want {
			t.Errorf("ProbeReplyAccepted(%q) = %v, want %v", tc.rx, got, tc.want)
		}
	}
}

func TestC2LineBeforePrompt(t *testing.T) {
	accNoPrompt := c2Result(cat(pProbe[:4], []seg{{adapter.Received, adapter.PhaseProbe, idReply[:len(idReply)-2]}}, pAuth, pOperate, pClose), "")
	twoSer := c2Result(cat(pProbe, pAuth, pOperate[:1], pOperate, pClose), "")
	for name, r := range map[string]adapter.Result{
		"ACC sent before the ID reply's prompt": accNoPrompt,
		"SER sent twice with no prompt between": twoSer,
	} {
		if err := r.Validate(); err == nil {
			t.Errorf("accepted: %s", name)
		} else {
			t.Logf("refused: %s: %v", name, err)
		}
	}
	for _, c := range []adapter.Code{adapter.FailedTimeout, adapter.FailedTransportClosed} {
		t.Logf("%s: suspends credential %q", c, c.SuspendsCredential())
	}
}

// Change 12 and 13 cases (C2-A6.md re-check at aa68287).
func TestC2NoQUIAfterUnansweredACC(t *testing.T) {
	// QUI after a timeout that followed ACC with no prompt yet: the relay's
	// "Password: ?" may still arrive and take QUI as a password attempt.
	accTimeout := c2Result(cat(pProbe, pAuth[:1], []seg{{adapter.Received, adapter.PhaseAuth, "ACC\r\n"}}, pClose), adapter.FailedTimeout)
	// The same after "Password: ?" was received but before the credential.
	pwTimeout := c2Result(cat(pProbe, pAuth[:2], pClose), adapter.FailedTimeout)
	// A probe-phase timeout after the QUI probe, then QUI again: the port's
	// language is not yet known (D16).
	probeTimeout := c2Result(cat(pProbe[:2], []seg{{adapter.Received, adapter.PhaseProbe, "QUI\r\n"}}, pClose), adapter.FailedTimeout)
	probeTimeout.Session.LanguageProbe = adapter.ProbeRejected
	// A rejected probe whose reply still ends in "=", then QUI to a port
	// that is not English (D16: nothing more is sent).
	rejectedQui := c2Result(cat(pProbe[:2], []seg{{adapter.Received, adapter.PhaseProbe, "QUI\r\nComando no valido\r\n="}}, pClose), adapter.RefusedLanguageProbe)
	rejectedQui.Session.LanguageProbe = adapter.ProbeRejected
	for name, r := range map[string]adapter.Result{
		"timeout after ACC, then QUI":            accTimeout,
		"timeout at Password: ?, then QUI":       pwTimeout,
		"timeout after the QUI probe, QUI again": probeTimeout,
		"rejected probe, then QUI":               rejectedQui,
	} {
		if err := r.Validate(); err == nil {
			t.Errorf("accepted: %s", name)
		} else {
			t.Logf("refused: %s: %v", name, err)
		}
	}
}

func TestC2CheckLines(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "contracts", "register", "testdata", "sel-751.json"))
	if err != nil {
		t.Fatal(err)
	}
	p, err := register.Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	inv := adapter.Invocation{InvocationID: "0b6c2f4e-1d3a-4c5b-8e7f-9a0b1c2d3e4f", OperationID: "sel.ser.read_all"}
	mk := func(op string) adapter.Result {
		r := c2Result(cat(pProbe, pAuth, []seg{{adapter.Sent, adapter.PhaseOperate, op}, pOperate[1]}, pClose), "")
		r.RegisterVersion = p.Revision
		return r
	}
	if err := mk("SER\r\n").CheckLines(p, inv); err != nil {
		t.Fatalf("A6 base fails CheckLines: %v", err)
	}
	for _, op := range []string{"SER C\r\n", "SER R\r\n", "ser c\r\n", "SER\x02\r\n", "SER\x00\r\n", "SER\x11\r\n", "SER\r\nSER C\r\n", "SER\rC\r\n", "SER \r\n", " SER\r\n", "SER\t\r\n", "STA\r\n", "ID\r\n", "QUI\r\n", "ACC\r\n", "2AC\r\n", "TRI\r\n", "SER\xff\r\n"} {
		err := mk(op).CheckLines(p, inv)
		if err == nil {
			t.Errorf("accepted by CheckLines: operate line %q", op)
		} else {
			t.Logf("refused %q: %v", op, err)
		}
	}
	// The wrong invocation, and the wrong register revision.
	other := inv
	other.OperationID = "sel.id"
	if mk("SER\r\n").CheckLines(p, other) == nil {
		t.Errorf("accepted: a result checked against another invocation")
	}
	r := mk("SER\r\n")
	r.RegisterVersion = p.Revision + 1
	if r.CheckLines(p, inv) == nil {
		t.Errorf("accepted: register_version not the package revision")
	}
	// A probe-phase line that is not QUI or a level-0 operation.
	rp := c2Result(cat(pProbe[:4], []seg{pProbe[4], {adapter.Sent, adapter.PhaseProbe, "SER\r\n"}, {adapter.Received, adapter.PhaseProbe, "SER\r\n\x03="}}, pAuth, pOperate, pClose), "")
	rp.RegisterVersion = p.Revision
	if err := rp.CheckLines(p, inv); err == nil {
		t.Errorf("accepted: SER in the probe phase")
	} else {
		t.Logf("refused SER in probe: %v", err)
	}
}

// The fixes must not refuse the safe paths (C2-A6.md re-check at 9a8553b).
func TestC2SafePaths(t *testing.T) {
	opTimeout := c2Result(cat(pProbe, pAuth, pOperate[:1], pClose), adapter.FailedTimeout)
	absent := c2Result(cat(pProbe, pAuth[:1], []seg{{adapter.Received, adapter.PhaseAuth, "ACC\r\n" + hdr + "Level 1\r\n\x03=>"}}, pClose), adapter.RefusedPasswordPromptAbsent)
	absent.Session.AccessLevel = "1"
	rejected := c2Result(cat(pProbe[:2], []seg{{adapter.Received, adapter.PhaseProbe, "QUI\r\nComando no valido\r\n="}}), adapter.RefusedLanguageProbe)
	rejected.Session.LanguageProbe = adapter.ProbeRejected
	for name, r := range map[string]adapter.Result{
		"timeout at Level 1 in operate, then QUI":   opTimeout,
		"password prompt absent, Level 1, then QUI": absent,
		"rejected probe, nothing more sent":         rejected,
	} {
		if err := r.Validate(); err != nil {
			t.Errorf("REFUSED safe path: %s: %v", name, err)
		}
	}
}
