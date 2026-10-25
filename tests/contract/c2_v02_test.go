package contract

import (
	"strings"
	"testing"

	"otsec.local/otsec/contracts/adapter"
)

// C2 otsec.adapter/0.2 (D2-14): A6's probes from the #100 review. They try
// to break the byte binding of failed.unexpected_password_prompt and the
// rule that a result of an earlier minor cannot carry a newer rule or code
// (Code.Since). Each refused case names what its error must say, so a
// refusal for an unrelated reason does not count. Transcripts are A6's own,
// synthetic.

const schema02 = "otsec.adapter/0.2"

// pwPromptAtL1 is Level 1 reached, SER sent, and the reply ending in
// "Password: ?": the state failed.unexpected_password_prompt names.
func pwPromptAtL1(reply string) []seg {
	return cat(pProbe, pAuth, []seg{
		{adapter.Sent, adapter.PhaseOperate, "SER\r\n"},
		{adapter.Received, adapter.PhaseOperate, reply},
	})
}

func pwResult(segs []seg) adapter.Result {
	r := c2Result(segs, adapter.FailedUnexpectedPasswordPrompt)
	r.Schema = schema02
	return r
}

// probeRejectedAtL1 is the probe reply that shows a level prompt but does
// not match the probe grammar (D16: nothing is sent after it, not even QUI).
func probeRejectedAtL1(schema string) adapter.Result {
	r := c2Result([]seg{
		{adapter.Sent, adapter.PhaseProbe, "\r\n"},
		{adapter.Received, adapter.PhaseProbe, "\r\n="},
		{adapter.Sent, adapter.PhaseProbe, "QUI\r\n"},
		{adapter.Received, adapter.PhaseProbe, "QUI\r\n\x02Comando no valido\r\n\x03=>"},
	}, adapter.RefusedLanguageProbe)
	r.Schema = schema
	r.Session.WakeSent = true
	r.Session.LanguageProbe = adapter.ProbeRejected
	return r
}

func TestC2v02Controls(t *testing.T) {
	for name, r := range map[string]adapter.Result{
		"unexpected password prompt at Level 1": pwResult(pwPromptAtL1("SER\r\n\r\nPassword: ? ")),
		"probe rejected at Level 1, 0.2":        probeRejectedAtL1(schema02),
	} {
		if err := r.Validate(); err != nil {
			t.Errorf("%s: refused: %v", name, err)
		}
	}
}

func TestC2v02Probes(t *testing.T) {
	statusRefused := pwResult(pwPromptAtL1("SER\r\n\r\nPassword: ? "))
	statusRefused.Status = adapter.StatusRefused

	newerCode := pwResult(pwPromptAtL1("SER\r\n\r\nPassword: ? "))
	newerCode.Error = &adapter.Error{Code: "failed.some_code_from_0_3"}

	levelZero := pwResult(pwPromptAtL1("SER\r\n\r\nPassword: ? "))
	levelZero.Session.AccessLevel = "0"

	quitClaimed := pwResult(pwPromptAtL1("SER\r\n\r\nPassword: ? "))
	quitClaimed.Session.QuitSent = true

	codeAt01 := pwResult(pwPromptAtL1("SER\r\n\r\nPassword: ? "))
	codeAt01.Schema = "otsec.adapter/0.1"

	for _, tc := range []struct {
		name string
		r    adapter.Result
		want string // a part of the error
	}{
		{"the password prompt, then \"=>\" in the same reply",
			pwResult(pwPromptAtL1("SER\r\n\r\nPassword: ? \r\n=>")), "Password: ?"},
		{"a second SER sent into the password prompt",
			pwResult(append(pwPromptAtL1("SER\r\n\r\nPassword: ? "), []seg{
				{adapter.Sent, adapter.PhaseOperate, "SER\r\n"},
				{adapter.Received, adapter.PhaseOperate, "SER\r\n\r\nPassword: ? "},
			}...)), "sent before"},
		{"status refused for a failed code", statusRefused, "implies status"},
		{"a code from a later minor in a 0.2 result", newerCode, "not in the " + adapter.Contract + " taxonomy"},
		{"access_level 0 while the bytes show Level 1", levelZero, "access_level"},
		{"quit_sent claimed with no QUI in the bytes", quitClaimed, "quit_sent"},
		{"the 0.2 code in a 0.1 result (Code.Since)", codeAt01, "new in 0.2"},
		{"the 0.2 probe QUI exemption claimed by a 0.1 result", probeRejectedAtL1("otsec.adapter/0.1"), "QUI"},
	} {
		err := tc.r.Validate()
		switch {
		case err == nil:
			t.Errorf("accepted: %s", tc.name)
		case !strings.Contains(err.Error(), tc.want):
			t.Errorf("%s: refused for another reason: %v", tc.name, err)
		default:
			t.Logf("refused: %s: %v", tc.name, err)
		}
	}
}
