package adapter

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// mutated decodes a golden, applies f to it as JSON, and decodes the result
// with DecodeResult.
func mutated(t *testing.T, path string, f func(r, session map[string]any)) error {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(append([]string{"testdata"}, strings.Split(path, "/")...)...))
	if err != nil {
		t.Fatal(err)
	}
	var r map[string]any
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	if err := d.Decode(&r); err != nil {
		t.Fatal(err)
	}
	f(r, r["session"].(map[string]any))
	if b, err = json.Marshal(r); err != nil {
		t.Fatal(err)
	}
	_, err = DecodeResult(b)
	return err
}

func telnetOf(s map[string]any) map[string]any { return s["telnet"].(map[string]any) }

// Each rule of session.telnet (0.10, D2-c2-0.10 §2), with its twin that
// passes. want "" is the control: the same golden, one step short of the
// rule, which must decode.
func TestTelnetRules(t *testing.T) {
	const ok10, snmp10 = "results/valid/ok-0.10.json", "snmp/results/valid/ok-0.10.json"
	set := func(k string, v any) func(_, s map[string]any) {
		return func(_, s map[string]any) { telnetOf(s)[k] = v }
	}
	drop := func(k string) func(_, s map[string]any) { return func(_, s map[string]any) { delete(telnetOf(s), k) } }
	schema := func(v string, then func(r, s map[string]any)) func(r, s map[string]any) {
		return func(r, s map[string]any) { r["schema"] = v; then(r, s) }
	}
	telnet := map[string]any{"refusals": 0, "command_octets_received": 0, "read_to_eof": false, "rexmit_octets": 0}
	for _, c := range []struct {
		name, golden string
		f            func(r, s map[string]any)
		want         string
	}{
		// Rule 1: presence.
		{"ok", ok10, func(_, _ map[string]any) {}, ""},
		{"connected telnet without it", ok10, func(_, s map[string]any) { delete(s, "telnet") }, "carries session.telnet from 0.10"},
		{"0.11 without it reads forward", ok10, schema("otsec.adapter/0.11", func(_, s map[string]any) { delete(s, "telnet") }), ""},
		{"0.9 with it", ok10, schema("otsec.adapter/0.9", func(_, _ map[string]any) {}), "session.telnet is new in 0.10, so a 0.9 result cannot carry it"},
		{"0.9 without it", ok10, schema("otsec.adapter/0.9", func(_, s map[string]any) { delete(s, "telnet") }), ""},
		{"snmp without it", snmp10, func(_, _ map[string]any) {}, ""},
		{"snmp with it", snmp10, func(_, s map[string]any) { s["telnet"] = telnet }, "belongs to a connected session that is not SNMPv3"},
		{"not connected with it", "results/valid/failed.connect.json", schema("otsec.adapter/0.10", func(_, s map[string]any) { s["telnet"] = telnet }),
			"belongs to a connected session that is not SNMPv3"},
		{"not connected without it", "results/valid/failed.connect.json", schema("otsec.adapter/0.10", func(_, _ map[string]any) {}), ""},
		// Rule 2: present, and in range.
		{"no refusals", ok10, drop("refusals"), "session.telnet.refusals is required"},
		{"no command octets", ok10, drop("command_octets_received"), "session.telnet.command_octets_received is required"},
		{"no read_to_eof", ok10, drop("read_to_eof"), "session.telnet.read_to_eof is required"},
		{"refusals null", ok10, set("refusals", nil), "session.telnet.refusals is required"},
		{"negative refusals", ok10, set("refusals", -1), "refusals -1 is outside"},
		{"refusals 2^53", ok10, func(_, s map[string]any) {
			telnetOf(s)["refusals"], telnetOf(s)["command_octets_received"] = int64(1)<<53, int64(1)<<53
		}, "refusals 9007199254740992 is outside"},
		{"counts 2^53 - 1", ok10, func(_, s map[string]any) {
			telnetOf(s)["refusals"], telnetOf(s)["command_octets_received"] = 0, int64(MaxTelnetCount)
		}, ""},
		{"command octets 2^53", ok10, set("command_octets_received", int64(1)<<53), "command_octets_received 9007199254740992 is outside"},
		{"fractional count", ok10, set("refusals", json.Number("1.5")), "cannot unmarshal"},
		// Rule 3: at least three command octets a refusal.
		{"command octets 3 x refusals - 1", ok10, func(_, s map[string]any) {
			telnetOf(s)["refusals"], telnetOf(s)["command_octets_received"] = 3, 8
		}, "command_octets_received 8 is less than 3 x refusals 3"},
		{"command octets 3 x refusals", ok10, func(_, s map[string]any) {
			telnetOf(s)["refusals"], telnetOf(s)["command_octets_received"] = 3, 9
		}, ""},
		// Rule 4: EOF only after QUI.
		{"read_to_eof without QUI", "results/valid/ok-0.10-read-to-eof.json", func(_, s map[string]any) { s["quit_sent"] = false },
			"read_to_eof needs quit_sent"},
		{"read_to_eof with QUI", "results/valid/ok-0.10-read-to-eof.json", func(_, _ map[string]any) {}, ""},
		// Rule 5: exactly one of the count and the token.
		{"both", ok10, set("rexmit_unknown", "in-flight"), "exactly one of rexmit_octets and rexmit_unknown"},
		{"neither", ok10, drop("rexmit_octets"), "exactly one of rexmit_octets and rexmit_unknown"},
		{"count null beside a token", "results/valid/ok-0.10-rexmit-in-flight.json", set("rexmit_octets", nil), ""},
		// "" is present, not absent: only null is absent (D6 on #684).
		{"empty token beside a count", ok10, set("rexmit_unknown", ""), "rexmit_unknown is empty; only null is absent"},
		{"empty token beside a count at 0.11", ok10, schema("otsec.adapter/0.11", set("rexmit_unknown", "")),
			"rexmit_unknown is empty; only null is absent"},
		{"empty token alone", ok10, func(_, s map[string]any) { telnetOf(s)["rexmit_unknown"] = ""; delete(telnetOf(s), "rexmit_octets") },
			"rexmit_unknown is empty; only null is absent"},
		{"null token beside a count", ok10, set("rexmit_unknown", nil), ""},
		{"count null alone", ok10, set("rexmit_octets", nil), "exactly one of rexmit_octets and rexmit_unknown"},
		{"negative count", ok10, set("rexmit_octets", -1), "rexmit_octets -1 is outside"},
		{"count 2^53", ok10, set("rexmit_octets", int64(1)<<53), "rexmit_octets 9007199254740992 is outside"},
		{"count 2^53 - 1", ok10, set("rexmit_octets", int64(MaxTelnetCount)), ""},
		{"fractional rexmit", ok10, set("rexmit_octets", json.Number("0.5")), "cannot unmarshal"},
		{"token outside the three", "results/valid/ok-0.10-rexmit-in-flight.json", set("rexmit_unknown", "no-socket"),
			`rexmit_unknown "no-socket" is not one of the otsec.adapter/0.10 tokens`},
		{"later token at 0.11", "results/valid/ok-0.10-rexmit-in-flight.json",
			schema("otsec.adapter/0.11", set("rexmit_unknown", "no-socket")), ""},
		{"later token of 32 octets", "results/valid/ok-0.10-rexmit-in-flight.json",
			schema("otsec.adapter/0.11", set("rexmit_unknown", strings.Repeat("a", 32))), ""},
		{"later token of 33 octets", "results/valid/ok-0.10-rexmit-in-flight.json",
			schema("otsec.adapter/0.11", set("rexmit_unknown", strings.Repeat("a", 33))), "is not lowercase letters and hyphens, at most 32 octets"},
		{"later token off the form", "results/valid/ok-0.10-rexmit-in-flight.json",
			schema("otsec.adapter/0.11", set("rexmit_unknown", "No_Socket")), "is not lowercase letters and hyphens"},
		// Strictness inside the object.
		{"unknown field at 0.10", ok10, set("added_in_0_11", 1), `key "added_in_0_11" is not a field name`},
		{"unknown field at 0.11", ok10, schema("otsec.adapter/0.11", set("added_in_0_11", 1)), ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			err := mutated(t, c.golden, c.f)
			switch {
			case c.want == "" && err != nil:
				t.Errorf("refused: %v", err)
			case c.want != "" && err == nil:
				t.Errorf("accepted, want %q", c.want)
			case c.want != "" && !strings.Contains(err.Error(), c.want):
				t.Errorf("error does not mention %q:\n%v", c.want, err)
			}
		})
	}
}

// A writer leaves out what it has not set, and never writes null.
func TestTelnetFactsMarshal(t *testing.T) {
	n, f := int64(0), false
	b, err := json.Marshal(TelnetFacts{Refusals: &n, CommandOctetsReceived: &n, ReadToEOF: &f, RexmitUnknown: RexmitUnsupported})
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"refusals":0,"command_octets_received":0,"read_to_eof":false,"rexmit_unknown":"unsupported"}`; string(b) != want {
		t.Errorf("%s, want %s", b, want)
	}
}
