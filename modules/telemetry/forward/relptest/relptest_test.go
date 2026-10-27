package relptest

import (
	"errors"
	"fmt"
	"testing"
)

func TestParseCommand(t *testing.T) {
	good := map[string]Command{
		"1 open 30 relp_version=0\ncommands=syslog\n": {1, "open", []byte("relp_version=0\ncommands=syslog")},
		"2 syslog 3 abc\n":    {2, "syslog", []byte("abc")},
		"999999999 close 0\n": {999999999, "close", nil},
	}
	for in, want := range good {
		c, n, err := ParseCommand([]byte(in + "next"))
		if err != nil || n != len(in) || c.TXNR != want.TXNR || c.Command != want.Command || string(c.Data) != string(want.Data) {
			t.Errorf("%q: %+v %d %v", in, c, n, err)
		}
	}
	for _, in := range []string{"", "1", "1 sys", "2 syslog 3 ab", "2 syslog 3 abc"} {
		if _, _, err := ParseCommand([]byte(in)); !errors.Is(err, ErrIncomplete) {
			t.Errorf("%q: %v, want incomplete", in, err)
		}
	}
	for _, in := range []string{
		"0 syslog 1 a\n", "01 syslog 1 a\n", "1234567890 syslog 1 a\n", "1 rsp 1 a\n", "1 SYSLOG 1 a\n",
		"1 syslogx 1 a\n", "1 syslog 01 a\n", "1 syslog 0 \n", "1 syslog 1 ab\n", "1 syslog 65536 a\n",
		"1  syslog 1 a\n", "1 syslog 1\n",
	} {
		if _, _, err := ParseCommand([]byte(in)); err == nil || errors.Is(err, ErrIncomplete) {
			t.Errorf("%q: %v, want a violation", in, err)
		}
	}
}

// FuzzParseCommand: a parsed frame re-encodes to exactly the bytes it was
// read from, and nothing panics.
func FuzzParseCommand(f *testing.F) {
	for _, s := range []string{"1 open 30 relp_version=0\ncommands=syslog\n", "2 syslog 3 abc\n", "3 close 0\n", "0 syslog 1 a\n", "1 syslog 01 a\n"} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		c, n, err := ParseCommand(b)
		if err != nil {
			return
		}
		enc := fmt.Sprintf("%d %s %d", c.TXNR, c.Command, len(c.Data))
		if len(c.Data) > 0 {
			enc += " " + string(c.Data)
		}
		enc += "\n"
		if string(b[:n]) != enc {
			t.Fatalf("%q parsed as %+v", b[:n], c)
		}
	})
}
