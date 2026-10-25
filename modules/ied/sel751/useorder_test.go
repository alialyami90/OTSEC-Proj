package sel751

import (
	"bytes"
	"testing"

	"otsec.local/otsec/contracts/adapter"
	"otsec.local/otsec/contracts/authz"
)

// orderedSecret records the order of the slot's calls and what each
// EchoSpans call was given.
type orderedSecret struct {
	secret
	calls  []string
	echoRx [][]byte
}

func (s *orderedSecret) Use(f func([]byte) error) error {
	s.calls = append(s.calls, "use")
	return s.secret.Use(f)
}

func (s *orderedSecret) EchoSpans(rx []byte) [][2]int {
	s.calls = append(s.calls, "echo")
	s.echoRx = append(s.echoRx, append([]byte(nil), rx...))
	return s.secret.EchoSpans(rx)
}

// TestUseOrder pins the order collector.SecretHandle relies on (A6 on
// #106): the "Password: ?" reply is committed before Use, with no
// EchoSpans call, so the first EchoSpans call after Use is given exactly the
// relay's reply to the password line, the bytes the partial-echo rule is
// for. Every reply after that is scanned too.
func TestUseOrder(t *testing.T) {
	for _, g := range []string{"ok", "ok-with-echo", "failed.auth_rejected", "failed.transport_closed"} {
		t.Run(g, func(t *testing.T) {
			want := golden(t, g)
			// The golden's replies after the credential line, as sent on the
			// wire (an echo redaction is the secret itself).
			steps := script(want)
			var after [][]byte
			seen := false
			for _, st := range steps {
				if bytes.Equal(st.expect, []byte(testSecret+"\r\n")) {
					seen = true
				}
				if seen && len(st.reply) > 0 {
					after = append(after, st.reply)
				}
			}
			if !seen || len(after) == 0 {
				t.Fatal("the golden has no reply after the credential line")
			}
			sec := &orderedSecret{secret: secret{b: []byte(testSecret)}}
			res, _ := runSteps(t, load(t), Config{Secret: sec}, steps, g == "failed.transport_closed")
			if res.Error != nil && want.Error != nil && res.Error.Code != want.Error.Code {
				t.Fatalf("result %s, want %s", res.Error.Code, want.Error.Code)
			}
			if len(sec.calls) == 0 || sec.calls[0] != "use" {
				t.Fatalf("calls %v: EchoSpans before Use", sec.calls)
			}
			if len(sec.echoRx) == 0 || !bytes.Equal(sec.echoRx[0], after[0]) {
				t.Fatalf("first EchoSpans after Use got %q, want the reply to the password line %q", sec.echoRx, after[0])
			}
			if len(sec.echoRx) != len(after) {
				t.Errorf("%d replies scanned after Use, want %d", len(sec.echoRx), len(after))
			}
			if res.Session.EchoScan != adapter.EchoScanPerformed {
				t.Errorf("echo_scan %q", res.Session.EchoScan)
			}
		})
	}
}

// TestTestSecretInstalls: the test secret is one the collector would
// install for a SEL-751 under the current register (A3 on #112, A1): at
// most 12 characters from ! to ~, and starting with no command mnemonic.
func TestTestSecretInstalls(t *testing.T) {
	f := load(t)
	if err := authz.ValidateSecret([]byte(testSecret), authz.SecretPolicies["sel-751"], f.reg); err != nil {
		t.Fatalf("test secret refused by the SEL-751 policy under register revision %d: %v", f.reg.Revision, err)
	}
}
