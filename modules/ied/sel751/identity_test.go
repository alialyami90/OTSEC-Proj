package sel751

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"otsec.local/otsec/contracts/adapter"
)

// withIDReply is the refused.identity_mismatch golden's script, which ends
// with the ID reply, with that reply replaced by edit's.
func withIDReply(t *testing.T, edit func([]byte) []byte) []step {
	t.Helper()
	steps := script(golden(t, "refused.identity_mismatch"))
	last := &steps[len(steps)-1]
	if !bytes.HasPrefix(last.reply, []byte("ID\r\n\x02")) {
		t.Fatalf("the golden's last reply is not the ID reply: %q", last.reply)
	}
	last.reply = edit(bytes.Clone(last.reply))
	return steps
}

// TestIDUnreadable: an ID reply this adapter cannot read compares nothing.
// It is failed.identity_unreadable, which suspends neither the asset nor the
// credential; ACC is not sent and the floor is not touched, and the reply's
// bytes are kept as received. Only a FID that was read and differs is
// refused.identity_mismatch (A6 on #118).
func TestIDUnreadable(t *testing.T) {
	mismatch := golden(t, "refused.identity_mismatch")
	declared, other := mismatch.Identity.Items[0].Expected, mismatch.Identity.Items[0].Observed
	unframed := func(b []byte) []byte {
		return bytes.ReplaceAll(bytes.ReplaceAll(b, []byte{stx}, nil), []byte{etx}, nil)
	}
	doc, err := os.ReadFile(filepath.Join("..", "..", "..", "tests", "fixtures", "ied", "sel", "751", "documented-example", "id-response-fig7-38.txt"))
	if err != nil {
		t.Fatal(err)
	}
	// Figure 7.38 as the relay would send it but with no STX and ETX: the
	// echo, the message, then the prompt (CR LF line ends assumed).
	docLines := bytes.ReplaceAll(bytes.TrimPrefix(doc, []byte("=ID <Enter>\n")), []byte("\n"), []byte("\r\n"))

	cases := []struct {
		name string
		edit func([]byte) []byte
		want adapter.Code
	}{
		// Not read, so not accepted either: ACC is not sent to a FID that
		// matches but was not framed.
		{"no STX and no ETX, the declared FID", func(b []byte) []byte {
			return unframed(bytes.Replace(b, []byte(other), []byte(declared), 1))
		}, adapter.FailedIdentityUnreadable},
		{"no STX and no ETX, another FID", unframed, adapter.FailedIdentityUnreadable},
		{"no STX and no ETX, Figure 7.38", func([]byte) []byte { return append(append([]byte("ID\r\n"), docLines...), '=') },
			adapter.FailedIdentityUnreadable},
		{"no ETX", func(b []byte) []byte { return bytes.ReplaceAll(b, []byte{etx}, nil) }, adapter.FailedIdentityUnreadable},
		{"no STX", func(b []byte) []byte { return bytes.ReplaceAll(b, []byte{stx}, nil) }, adapter.FailedIdentityUnreadable},
		{"no FID line", func(b []byte) []byte {
			i := bytes.Index(b, []byte(`"FID=`))
			j := bytes.Index(b[i:], []byte("\r\n"))
			return append(b[:i:i], b[i+j+2:]...)
		}, adapter.FailedIdentityUnreadable},
		{"an empty FID", func(b []byte) []byte {
			i := bytes.Index(b, []byte(`"FID=`)) + len(`"FID=`)
			j := bytes.IndexByte(b[i:], '"')
			return append(b[:i:i], b[i+j:]...)
		}, adapter.FailedIdentityUnreadable},
		{"the FID key twice", func(b []byte) []byte {
			i := bytes.Index(b, []byte(`"FID=`))
			j := bytes.Index(b[i:], []byte("\r\n")) + 2
			line := bytes.Clone(b[i : i+j])
			return append(b[:i+j:i+j], append(line, b[i+j:]...)...)
		}, adapter.FailedIdentityUnreadable},
		// The control: a FID that was read and differs is still a mismatch.
		{"a FID that differs", func(b []byte) []byte { return b }, adapter.RefusedIdentityMismatch},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			steps := withIDReply(t, c.edit)
			reply := steps[len(steps)-1].reply
			res, fl := runSteps(t, load(t), Config{}, steps, false)
			if err := res.Validate(); err != nil {
				t.Fatalf("result does not validate: %v", err)
			}
			if res.Error == nil || res.Error.Code != c.want {
				t.Fatalf("result %s %+v, want %s", res.Status, res.Error, c.want)
			}
			if len(fl.calls) != 0 {
				t.Errorf("floor touched: %v", fl.calls)
			}
			if res.Session.CredentialSent || bytes.Contains(res.Transcript.Data, []byte("ACC")) {
				t.Errorf("ACC or the credential was sent")
			}
			if !bytes.HasSuffix(res.Transcript.Data, reply) {
				t.Errorf("the reply is not kept as received")
			}
			if c.want == adapter.RefusedIdentityMismatch {
				if res.Identity.Result != adapter.IdentityMismatch || res.Error.Code.Suspends() == "" {
					t.Errorf("mismatch: identity %s, suspends %q", res.Identity.Result, res.Error.Code.Suspends())
				}
				return
			}
			if res.Status != adapter.StatusFailed || res.Identity.Result != adapter.IdentityNotChecked || len(res.Identity.Items) != 0 {
				t.Errorf("status %s, identity %+v", res.Status, res.Identity)
			}
			if s, sc := res.Error.Code.Suspends(), res.Error.Code.SuspendsCredential(); s != "" || sc != "" {
				t.Errorf("suspends asset %q, credential %q", s, sc)
			}
			if len(res.Observations) != 0 {
				t.Errorf("observations from an unread reply: %+v", res.Observations)
			}
			if res.Error.Detail == "" {
				t.Errorf("no detail")
			}
		})
	}
}
