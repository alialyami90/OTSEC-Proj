package sel751

import (
	"bufio"
	"bytes"
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"otsec.local/otsec/contracts/adapter"
)

// FuzzRun drives the whole dialogue against a far end that answers each
// line with fuzzer-chosen bytes: the first chunk on connect, then one chunk
// per line received, then it hangs up. Whatever it sends, Run must return a
// result that passes Validate, CheckLines and CheckAgainst, never put the
// secret in the transcript, and never panic.
func FuzzRun(f *testing.F) {
	ok := script(golden(f, "ok"))
	var seed [][]byte
	for _, st := range ok {
		seed = append(seed, bytes.ReplaceAll(st.reply, []byte(testSecret), []byte("x")))
	}
	f.Add(bytes.Join(seed, []byte{0xF7}))
	f.Add([]byte("\r\n=\xF7QUI\r\n=\xF7\x02\"FID=x\",\"0000\"\r\n\x03=\xF7\r\nPassword: ?\xF7\r\nPassword: ?"))
	f.Add([]byte("\xF7\r\n=\xF7\r\n=\xF7\x02\x03=\xF7=>\xF7\r\nPassword: ?\xF7=>>"))
	f.Add([]byte("\r\nPassword: ?"))
	f.Add([]byte("\r\n=>"))
	in := load(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		chunks := bytes.Split(data, []byte{0xF7})
		near, far := net.Pipe()
		go func() {
			defer far.Close()
			_ = far.SetDeadline(time.Now().Add(10 * time.Second))
			r := bufio.NewReader(far)
			for i, c := range chunks {
				if i > 0 {
					if _, err := r.ReadBytes('\n'); err != nil {
						return
					}
				}
				if len(c) > 0 {
					if _, err := far.Write(c); err != nil {
						return
					}
				}
			}
		}()
		inv := in.inv
		inv.Limits.StepTimeoutMS = 60
		cfg := Config{Asset: in.asset, Profile: in.profile, Register: in.reg, Endpoint: inv.EndpointID,
			Secret: &secret{b: []byte(testSecret)}, Floor: &floor{}, Now: clock(),
			hooks: &hooks{quiet: time.Millisecond, wakeWait: 5 * time.Millisecond},
			Dial:  func(context.Context, string, string) (net.Conn, error) { return near, nil }}
		got := Run(context.Background(), inv, cfg)
		if gap := c2Gap(got); gap != "" {
			t.Skip(gap)
		}
		x := in
		x.inv = inv
		check(t, x, got)
		if t.Failed() {
			t.Logf("%s\n%q", jsonOf(t, got.Session), got.Transcript.Data)
			if got.Error != nil {
				t.Logf("%s %s", got.Error.Code, got.Error.Detail)
			}
		}
	})
}

// c2Gap names the C2 0.1 gaps Run meets, where no result exists that both
// follows the safety rules and passes Validate. Run follows the safety rule
// and the collector quarantines the result (#82). Each is raised with A1.
func c2Gap(r adapter.Result) string {
	if r.Error == nil {
		return ""
	}
	switch {
	case strings.Contains(r.Error.Detail, "unexpected password prompt"):
		// QUI would be a password attempt (C-19); closing without it breaks
		// the D18 rule for a session that reached Level 1.
		return "C2 gap 1: Password: ? at Level 1"
	case r.Error.Code == adapter.RefusedLanguageProbe && r.Session.AccessLevel != "0":
		// D16 sends nothing after a rejected probe; D18 wants QUI once a
		// level prompt above 0 was seen.
		return "C2 gap 2: the probe reply shows a level above 0"
	}
	return ""
}
