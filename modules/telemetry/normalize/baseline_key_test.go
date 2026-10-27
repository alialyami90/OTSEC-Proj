package normalize

import (
	"encoding/json"
	"os"
	"testing"

	"otsec.local/otsec/contracts/baseline"
	"otsec.local/otsec/contracts/event"
)

// TestSyslogGoldensKeyAsC10Says ties C10's Syslog key to this parser's field
// names: KeyOf reads "pri" and "msg" as Syslog writes them, so a
// rename here breaks this test before it breaks a baseline. The goldens
// are documented examples, not device captures.
func TestSyslogGoldensKeyAsC10Says(t *testing.T) {
	cases := []struct {
		file, facility, severity, text string
	}{
		// <190>: local7.info. The RTAC time inside MSG becomes digit runs.
		{"rtac-user-logon.json", "23", "6", "RTAC Logger: #-#-# #:#:#.#, Informational, Security, SystemTags. User_Logged_On, 'SEL logged on device via Web'."},
		// <37>: auth.notice. The address is digits, so another source address is the same type.
		{"sel2488-login-failed.json", "4", "5", "Login: Login to web: failed from #.#.#.#"},
		// <34>: auth.crit.
		{"sel2730m-invalid-login.json", "4", "2", "Invalid login attempt by: root at #.#.#.#"},
	}
	for _, c := range cases {
		b, err := os.ReadFile("testdata/syslog/" + c.file)
		if err != nil {
			t.Fatal(err)
		}
		// The goldens are pending events, as the parser hands them to the
		// store: seq 0.
		var e event.Event
		if err := json.Unmarshal(b, &e); err != nil {
			t.Fatal(err)
		}
		if err := e.ValidatePending(); err != nil {
			t.Fatalf("%s: %v", c.file, err)
		}
		k, text, use, why := baseline.Classify(&e, false)
		if use != baseline.UseFull || why != baseline.ExcludedNone {
			t.Errorf("%s: %s %q", c.file, use, why)
		}
		if k.Source != baseline.SourceSyslog || k.Facility != c.facility || k.Severity != c.severity {
			t.Errorf("%s: key %+v", c.file, k)
		}
		if text != c.text {
			t.Errorf("%s: template %q, want %q", c.file, text, c.text)
		}
	}
}
