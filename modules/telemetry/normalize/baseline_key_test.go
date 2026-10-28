package normalize

import (
	"encoding/json"
	"os"
	"strings"
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

// TestRelayMessageRowKeysAsC10Says: a SER row this parser does not read,
// such as the relay's own "Relay Settings Changed" (S22 p. 10.39), is
// stored with its bytes, and C10 keys it on their template, so it forms a
// type and alarms as new once the baseline is active (B2, B1 on #254). The
// rows are constructed in the C2 column layout; p. 10.39 does not show the
// layout, so it is a reading, not a capture.
func TestRelayMessageRowKeysAsC10Says(t *testing.T) {
	inv, a := c2Fixtures(t)
	read := func(rows ...testRow) []event.Event {
		out, err := Normalize(withRows(t, rows), inv, a, testInput(nil))
		if err != nil {
			t.Fatal(err)
		}
		return out.Events
	}
	first := read(
		testRow{"3    10/24/2026 09:10:00.512   Relay Settings Changed", false},
		testRow{serLine(2, "10/24/2026", "09:10:01.004", "IN101", "Asserted"), true},
		testRow{serLine(1, "10/24/2026", "09:10:01.251", "IN101", "Deasserted"), true},
	)
	later := read(
		testRow{"2    10/25/2026 11:00:07.003   Relay Settings Changed", false},
		testRow{serLine(1, "10/25/2026", "11:00:08.000", "IN101", "Asserted"), true},
	)
	changed, text, use, why := baseline.Classify(&first[0], false)
	if first[0].Collection.ParseStatus != event.ParseFailed || why != baseline.ExcludedNone || use == baseline.UseNone {
		t.Fatalf("relay row: %s %q, parse %s", use, why, first[0].Collection.ParseStatus)
	}
	if changed.Template == "" || !strings.Contains(text, "Relay Settings Changed") {
		t.Errorf("relay row key %+v %q", changed, text)
	}
	again, _, _, _ := baseline.Classify(&later[0], false)
	parsed, _, _, _ := baseline.Classify(&first[1], false)
	if again != changed || parsed == changed || parsed.Element != "IN101" {
		t.Errorf("changed %v, again %v, parsed %v", changed, again, parsed)
	}
}
