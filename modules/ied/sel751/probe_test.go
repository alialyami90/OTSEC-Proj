package sel751

import (
	"bytes"
	"testing"

	"otsec.local/otsec/contracts/adapter"
)

// TestProbeUnanswered: no prompt after the QUI probe, because the step timed
// out or the connection closed, is an unanswered probe. Nothing more is sent
// (D16), the code is the timeout's or the close's, and it suspends nothing:
// a slow link is not a language fault (C2 0.4; A6, V-S12). A reply that ends
// in a prompt is still judged by the grammar, and a rejected one still
// suspends.
func TestProbeUnanswered(t *testing.T) {
	probe := script(golden(t, "refused.language_probe_rejected"))
	if !bytes.Equal(probe[len(probe)-1].expect, []byte("QUI\r\n")) {
		t.Fatalf("the golden's last line is not the QUI probe: %q", probe[len(probe)-1].expect)
	}
	with := func(reply string) []step {
		steps := append([]step(nil), probe...)
		steps[len(steps)-1] = step{expect: []byte("QUI\r\n"), reply: []byte(reply)}
		return steps
	}
	cases := []struct {
		name   string
		steps  []step
		hangUp bool
		want   adapter.Code
		probe  adapter.ProbeOutcome
	}{
		{"silence until the step timeout", with(""), false, adapter.FailedTimeout, adapter.ProbeUnanswered},
		{"the echo, then silence", with("QUI\r\n"), false, adapter.FailedTimeout, adapter.ProbeUnanswered},
		// Part of a reply with no prompt is not judged: the grammar needs the
		// whole reply, and a prompt ends one.
		{"part of an off-grammar reply, then silence", with("QUI\r\n\x02Comando no"), false, adapter.FailedTimeout, adapter.ProbeUnanswered},
		{"the echo, then the connection closed", with("QUI\r\n"), true, adapter.FailedTransportClosed, adapter.ProbeUnanswered},
		{"the control: an off-grammar reply that ends in a prompt", with("QUI\r\n\x02Comando no valido\r\n\x03="), false,
			adapter.RefusedLanguageProbe, adapter.ProbeRejected},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := load(t)
			f.inv.Limits.StepTimeoutMS = 300
			res, fl := runSteps(t, f, Config{}, c.steps, c.hangUp)
			if err := res.Validate(); err != nil {
				t.Fatalf("result does not validate: %v", err)
			}
			if res.Error == nil || res.Error.Code != c.want || res.Session.LanguageProbe != c.probe {
				t.Fatalf("result %s %+v, probe %s; want %s, %s", res.Status, res.Error, res.Session.LanguageProbe, c.want, c.probe)
			}
			if len(fl.calls) != 0 {
				t.Errorf("floor touched: %v", fl.calls)
			}
			var last adapter.Segment
			for _, sg := range res.Transcript.Segments {
				if sg.Dir == adapter.Sent {
					last = sg
				}
			}
			tr := res.Transcript
			if last.Phase != adapter.PhaseProbe || string(tr.Data[last.Offset:last.Offset+last.Length]) != "QUI\r\n" || res.Session.QuitSent {
				t.Errorf("something was sent after the probe")
			}
			s := res.Error.Code.Suspends()
			switch {
			case c.probe == adapter.ProbeUnanswered && s != "":
				t.Errorf("an unanswered probe suspends %q", s)
			case c.probe == adapter.ProbeRejected && s == "":
				t.Errorf("a rejected probe suspends nothing")
			}
			if c.probe == adapter.ProbeUnanswered && res.Error.Detail == "" {
				t.Errorf("no detail")
			}
		})
	}
}
