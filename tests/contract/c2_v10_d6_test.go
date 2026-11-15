package contract

// C2 0.10 (docs/phase4/D2-c2-0.10-proposal.md, approved in D4-102): D6's
// tests 1 to 6 of section 8, for brief P4-4-CC deliverable 4. Expected
// outcomes come from the rule text of sections 1 and 2, not from the code
// or D2's tests. The session.telnet object is D6's, written from section
// 1's example. The results it sits in are C2's invented examples of earlier
// minors, edited one field at a time; nothing is a capture. Test 6 (ii) and
// the forward half read every golden of the minors they name. Test 6 (i),
// the 0.9 code itself, is the a6-c2-old-reader job, which runs
// tests/contract/c2oldreader. Ground truth: GT-HAND. Evidence class: desk.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/adapter"
	"otsec.local/otsec/contracts/version"
)

var c2v10Testdata = filepath.Join("..", "..", "contracts", "adapter", "testdata")

// c2v10Bases are the examples the tests edit: C2's goldens of earlier
// minors, each valid at 0.10 once stamped and given what 0.9 and 0.10 ask
// of a connected Telnet session.
var c2v10Bases = map[string]string{
	"sel":  "results/valid/ok-0.9.json",               // connected Telnet, QUI sent
	"auth": "results/valid/failed.auth_rejected.json", // connected Telnet, no QUI
	"busy": "results/valid/refused.session_busy.json", // not connected
	"snmp": "snmp/results/valid/ok-0.9.json",          // connected SNMPv3
}

// c2v10Telnet is section 1's session.telnet.
func c2v10Telnet() map[string]any {
	return map[string]any{
		"refusals":                json.Number("2"),
		"command_octets_received": json.Number("9"),
		"read_to_eof":             false,
		"rexmit_octets":           json.Number("0"),
	}
}

func c2v10Read(t *testing.T, b []byte) map[string]any {
	t.Helper()
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var m map[string]any
	if err := d.Decode(&m); err != nil {
		t.Fatal(err)
	}
	return m
}

// c2v10Example is a base stamped 0.<minor>. A connected Telnet base gets
// local_addr and connected_at from 0.9 where it lacks them, and D6's
// session.telnet from 0.10.
func c2v10Example(t *testing.T, base string, minor int) map[string]any {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(c2v10Testdata, filepath.FromSlash(c2v10Bases[base])))
	if err != nil {
		t.Fatal(err)
	}
	m := c2v10Read(t, b)
	m["schema"] = fmt.Sprintf("otsec.adapter/0.%d", minor)
	s := m["session"].(map[string]any)
	if base == "auth" && minor >= 9 {
		s["local_addr"] = "192.0.2.10:49152"
		s["connected_at"] = m["started_at"]
	}
	if minor >= 10 && (base == "sel" || base == "auth") {
		s["telnet"] = c2v10Telnet()
	}
	return m
}

func c2v10Decode(t *testing.T, m map[string]any) (adapter.Result, error) {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return adapter.DecodeResult(b)
}

// c2v10 decodes the base at 0.<minor> after edit, which gets the session
// and its telnet object (nil where there is none).
func c2v10(t *testing.T, base string, minor int, edit func(s, tn map[string]any)) (adapter.Result, error) {
	t.Helper()
	m := c2v10Example(t, base, minor)
	if edit != nil {
		s := m["session"].(map[string]any)
		tn, _ := s["telnet"].(map[string]any)
		edit(s, tn)
	}
	return c2v10Decode(t, m)
}

type c2v10Case struct {
	name   string
	base   string
	minor  int
	edit   func(s, tn map[string]any)
	refuse bool
	reason string // when refused, a phrase of the rule text the error must hold
}

func (c c2v10Case) run(t *testing.T) {
	t.Helper()
	_, err := c2v10(t, c.base, c.minor, c.edit)
	switch {
	case c.refuse && err == nil:
		t.Errorf("%s (%s at 0.%d): accepted", c.name, c.base, c.minor)
	case c.refuse && !strings.Contains(err.Error(), c.reason):
		t.Errorf("%s (%s at 0.%d): refused for another reason: %v", c.name, c.base, c.minor, err)
	case !c.refuse && err != nil:
		t.Errorf("%s (%s at 0.%d): %v", c.name, c.base, c.minor, err)
	}
}

func c2v10Set(k string, v any) func(s, tn map[string]any) {
	return func(_, tn map[string]any) { tn[k] = v }
}

func c2v10Set2(k1 string, v1 any, k2 string, v2 any) func(s, tn map[string]any) {
	return func(_, tn map[string]any) { tn[k1] = v1; tn[k2] = v2 }
}

// The examples are valid as edited, so each refusal below is the one
// edit's doing.
func TestC2v10ExamplesAreValid(t *testing.T) {
	for base := range c2v10Bases {
		for _, minor := range []int{10, 11} {
			c2v10Case{name: "the example", base: base, minor: minor}.run(t)
		}
	}
}

// Test 1, rule 1: where session.telnet must and may be.
func TestC2v10TelnetPresence(t *testing.T) {
	drop := func(s, _ map[string]any) { delete(s, "telnet") }
	add := func(s, _ map[string]any) { s["telnet"] = c2v10Telnet() }
	for _, c := range []c2v10Case{
		{name: "connected Telnet without it", base: "sel", minor: 10, edit: drop, refuse: true},
		{name: "connected Telnet failed run without it", base: "auth", minor: 10, edit: drop, refuse: true},
		{name: "not connected with it", base: "busy", minor: 10, edit: add, refuse: true},
		{name: "not connected with it", base: "busy", minor: 11, edit: add, refuse: true},
		{name: "SNMPv3 with it", base: "snmp", minor: 10, edit: add, refuse: true},
		{name: "SNMPv3 with it", base: "snmp", minor: 11, edit: add, refuse: true},
		{name: "0.9 with it", base: "sel", minor: 9, edit: add, refuse: true, reason: "session.telnet is new in 0.10"},
		{name: "0.1 with it", base: "auth", minor: 1, edit: add, refuse: true, reason: "session.telnet is new in 0.10"},
		// A later minor is not held to the "must carry" half.
		{name: "connected Telnet without it", base: "sel", minor: 11, edit: drop},
		{name: "connected Telnet failed run without it", base: "auth", minor: 11, edit: drop},
	} {
		c.run(t)
	}
}

// Test 2, rule 2 (D4's N1): the three fields are required, and absent or
// null is never read as 0 or false.
func TestC2v10TelnetRequiredFields(t *testing.T) {
	for _, f := range []string{"refusals", "command_octets_received", "read_to_eof"} {
		c2v10Case{name: f + " absent", base: "sel", minor: 10, edit: func(_, tn map[string]any) { delete(tn, f) }, refuse: true}.run(t)
		c2v10Case{name: f + " null", base: "sel", minor: 10, edit: c2v10Set(f, nil), refuse: true}.run(t)
	}
}

// Test 2, rule 2: each count is an integer from 0 to 2^53 - 1.
func TestC2v10TelnetCountRange(t *testing.T) {
	const top, over = "9007199254740991", "9007199254740992"
	n := func(s string) json.Number { return json.Number(s) }
	for _, c := range []c2v10Case{
		{name: "refusals -1", edit: c2v10Set("refusals", n("-1")), refuse: true},
		{name: "command_octets_received -1", edit: c2v10Set2("refusals", n("0"), "command_octets_received", n("-1")), refuse: true},
		{name: "command_octets_received 2^53", edit: c2v10Set2("refusals", n("0"), "command_octets_received", n(over)), refuse: true},
		{name: "refusals 2^53", edit: c2v10Set2("refusals", n(over), "command_octets_received", n(top)), refuse: true},
		// 3 x 6148914691236517206 is 2 modulo 2^64, so only the range
		// refuses it (rule 3 alone would read 9 >= 2).
		{name: "refusals that wraps 3 x refusals", edit: c2v10Set("refusals", n("6148914691236517206")), refuse: true},
		{name: "refusals 1.5", edit: c2v10Set("refusals", n("1.5")), refuse: true},
		{name: "command_octets_received 9.5", edit: c2v10Set("command_octets_received", n("9.5")), refuse: true},
		{name: "refusals a string", edit: c2v10Set("refusals", "2"), refuse: true},
		{name: "read_to_eof a number", edit: c2v10Set("read_to_eof", n("0")), refuse: true},
		{name: "command_octets_received 2^53 - 1", edit: c2v10Set2("refusals", n("0"), "command_octets_received", n(top))},
		{name: "refusals at its largest, (2^53 - 1) / 3", edit: c2v10Set2("refusals", n("3002399751580330"), "command_octets_received", n(top))},
		{name: "both 0", edit: c2v10Set2("refusals", n("0"), "command_octets_received", n("0"))},
	} {
		c.base, c.minor = "sel", 10
		c.run(t)
	}
}

// Test 2, rule 3: command_octets_received is at least 3 x refusals.
func TestC2v10TelnetCommandOctetsBound(t *testing.T) {
	n := func(s string) json.Number { return json.Number(s) }
	for _, c := range []c2v10Case{
		{name: "2 refusals, 5 octets", edit: c2v10Set2("refusals", n("2"), "command_octets_received", n("5")), refuse: true},
		{name: "1 refusal, 2 octets", edit: c2v10Set2("refusals", n("1"), "command_octets_received", n("2")), refuse: true},
		{name: "2 refusals, 6 octets", edit: c2v10Set2("refusals", n("2"), "command_octets_received", n("6"))},
		{name: "1 refusal, 3 octets", edit: c2v10Set2("refusals", n("1"), "command_octets_received", n("3"))},
	} {
		for _, minor := range []int{10, 11} {
			c.base, c.minor = "sel", minor
			c.run(t)
		}
	}
}

// Test 3, rule 4: read_to_eof true needs quit_sent true. C2 binds quit_sent
// to the bytes, so the twins are two runs: one that sent no QUI, and one
// that did.
func TestC2v10ReadToEOFNeedsQuitSent(t *testing.T) {
	for _, c := range []c2v10Case{
		{name: "read_to_eof true without QUI", base: "auth", edit: c2v10Set("read_to_eof", true), refuse: true},
		{name: "read_to_eof false without QUI", base: "auth", edit: c2v10Set("read_to_eof", false)},
		{name: "read_to_eof true after QUI", base: "sel", edit: c2v10Set("read_to_eof", true)},
	} {
		for _, minor := range []int{10, 11} {
			c.minor = minor
			c.run(t)
		}
	}
}

// Test 4, rule 5: exactly one of rexmit_octets and rexmit_unknown, where
// null is absent (D6's N3).
func TestC2v10RexmitExactlyOne(t *testing.T) {
	drop := func(_, tn map[string]any) { delete(tn, "rexmit_octets") }
	for _, c := range []c2v10Case{
		{name: "both", edit: c2v10Set("rexmit_unknown", adapter.RexmitInFlight), refuse: true},
		{name: "neither", edit: drop, refuse: true},
		{name: "rexmit_octets null alone", edit: c2v10Set("rexmit_octets", nil), refuse: true},
		{name: "rexmit_octets null beside a token", edit: c2v10Set2("rexmit_octets", nil, "rexmit_unknown", adapter.RexmitInFlight)},
		{name: "rexmit_unknown null beside a count", edit: c2v10Set("rexmit_unknown", nil)},
		{name: "rexmit_unknown null alone", edit: func(s, tn map[string]any) { drop(s, tn); tn["rexmit_unknown"] = nil }, refuse: true},
	} {
		for _, minor := range []int{10, 11} {
			c.base, c.minor = "sel", minor
			c.run(t)
		}
	}
}

// Test 4, rule 5: an empty rexmit_unknown is present, since only null is
// absent. Beside a count it makes two, and it is none of the three tokens
// and not of the later form ("lowercase letters and hyphens").
func TestC2v10RexmitEmptyTokenIsPresent(t *testing.T) {
	for _, c := range []c2v10Case{
		{name: "rexmit_unknown empty beside a count", edit: c2v10Set("rexmit_unknown", ""), refuse: true},
		{name: "rexmit_unknown empty alone", edit: c2v10Set2("rexmit_octets", nil, "rexmit_unknown", ""), refuse: true},
	} {
		for _, minor := range []int{10, 11} {
			c.base, c.minor = "sel", minor
			c.run(t)
		}
	}
}

// Test 4, rule 5: rexmit_octets is an integer from 0 to 2^53 - 1.
func TestC2v10RexmitOctetsRange(t *testing.T) {
	n := func(s string) json.Number { return json.Number(s) }
	for _, c := range []c2v10Case{
		{name: "-1", edit: c2v10Set("rexmit_octets", n("-1")), refuse: true},
		{name: "0.5", edit: c2v10Set("rexmit_octets", n("0.5")), refuse: true},
		{name: "2^53", edit: c2v10Set("rexmit_octets", n("9007199254740992")), refuse: true},
		{name: "2^53 - 1", edit: c2v10Set("rexmit_octets", n("9007199254740991"))},
		{name: "12", edit: c2v10Set("rexmit_octets", n("12"))},
	} {
		for _, minor := range []int{10, 11} {
			c.base, c.minor = "sel", minor
			c.run(t)
		}
	}
}

// Test 4, rule 5: at 0.10 the token is one of the three.
func TestC2v10RexmitTokensAt010(t *testing.T) {
	token := func(v string) func(s, tn map[string]any) {
		return c2v10Set2("rexmit_octets", nil, "rexmit_unknown", v)
	}
	for _, v := range []string{"in-flight", "call-failed", "unsupported"} {
		c2v10Case{name: v, base: "sel", minor: 10, edit: token(v)}.run(t)
	}
	for _, v := range []string{"not-read", "In-Flight", "in_flight", "in-flight ", "unknown"} {
		c2v10Case{name: fmt.Sprintf("%q", v), base: "sel", minor: 10, edit: token(v), refuse: true}.run(t)
	}
}

// Test 4, rule 5: a later minor's token decodes forward and is read as
// unknown, never as a count; one that breaks the form is refused.
func TestC2v10RexmitLaterToken(t *testing.T) {
	token := func(v string) func(s, tn map[string]any) {
		return c2v10Set2("rexmit_octets", nil, "rexmit_unknown", v)
	}
	of32 := strings.Repeat("ab-", 10) + "cd"
	for _, v := range []string{"not-read", of32, "-"} {
		r, err := c2v10(t, "sel", 11, token(v))
		if err != nil {
			t.Errorf("0.11 token %q: %v", v, err)
			continue
		}
		tn := r.Session.Telnet
		if tn == nil || tn.RexmitUnknown != v || tn.RexmitOctets != nil {
			t.Errorf("0.11 token %q: read as %+v, want the token and no count", v, tn)
		}
	}
	for _, v := range []string{of32 + "e", "Not-Read", "not_read", "not-read2", "not read"} {
		c2v10Case{name: fmt.Sprintf("%q", v), base: "sel", minor: 11, edit: token(v), refuse: true}.run(t)
	}
}

// Test 5, strictness: an unknown field inside session.telnet is refused at
// 0.10 and ignored at 0.11, where the known fields still read.
func TestC2v10TelnetStrict(t *testing.T) {
	for _, f := range []string{"added_in_0_11", "Refusals"} {
		c2v10Case{name: "unknown field " + f, base: "sel", minor: 10, edit: c2v10Set(f, json.Number("5")), refuse: true}.run(t)
	}
	r, err := c2v10(t, "sel", 11, c2v10Set("added_in_0_11", json.Number("5")))
	if err != nil {
		t.Fatalf("0.11 with an unknown field in session.telnet: %v", err)
	}
	tn := r.Session.Telnet
	if tn == nil || tn.Refusals == nil || *tn.Refusals != 2 || tn.CommandOctetsReceived == nil || *tn.CommandOctetsReceived != 9 ||
		tn.ReadToEOF == nil || *tn.ReadToEOF || tn.RexmitOctets == nil || *tn.RexmitOctets != 0 || tn.RexmitUnknown != "" {
		t.Errorf("0.11 with an unknown field: session.telnet read as %+v", tn)
	}
}

type c2v10Golden struct {
	rel   string // slash-separated, under contracts/adapter/testdata
	minor int
	valid bool
	b     []byte
}

// c2v10Goldens is every C2 result golden of major 0 (results/valid and
// results/invalid, at any depth), with its minor.
func c2v10Goldens(t *testing.T) []c2v10Golden {
	t.Helper()
	var out []c2v10Golden
	err := filepath.WalkDir(c2v10Testdata, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".json") {
			return err
		}
		rel, _ := filepath.Rel(c2v10Testdata, p)
		rel = filepath.ToSlash(rel)
		valid := strings.Contains("/"+rel, "/results/valid/")
		if !valid && !strings.Contains("/"+rel, "/results/invalid/") {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		var head struct {
			Schema string `json:"schema"`
		}
		if json.Unmarshal(b, &head) != nil {
			return nil
		}
		id, err := version.Parse(head.Schema)
		if err != nil || id.Name != "adapter" || id.Major != 0 {
			return nil
		}
		out = append(out, c2v10Golden{rel: rel, minor: id.Minor, valid: valid, b: b})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// Test 6 (ii), the in-tree proxy (D1's 6862737844 on #671): every 0.10
// golden, with session.telnet removed and stamped 0.9, validates under
// 0.10's code. Control: the same golden with session.telnet kept is
// refused as new in 0.10.
func TestC2v10GoldensStamped09(t *testing.T) {
	var all, telnet int
	for _, g := range c2v10Goldens(t) {
		if g.minor != 10 || !g.valid {
			continue
		}
		all++
		m := c2v10Read(t, g.b)
		m["schema"] = "otsec.adapter/0.9"
		s := m["session"].(map[string]any)
		tn, has := s["telnet"]
		delete(s, "telnet")
		if _, err := c2v10Decode(t, m); err != nil {
			t.Errorf("%s, without session.telnet, stamped 0.9: %v", g.rel, err)
		}
		if !has {
			continue
		}
		telnet++
		s["telnet"] = tn
		if _, err := c2v10Decode(t, m); err == nil || !strings.Contains(err.Error(), "session.telnet is new in 0.10") {
			t.Errorf("%s, with session.telnet, stamped 0.9: %v, want refused as new in 0.10", g.rel, err)
		}
	}
	// At 0f10fa02: five SEL Telnet goldens and one SNMPv3.
	if all < 6 || telnet < 5 {
		t.Errorf("%d 0.10 goldens, %d with session.telnet; want at least 6 and 5", all, telnet)
	}
}

// Test 6, forward: every 0.9 golden still validates under 0.10. A valid one
// decodes, and an invalid one is still refused by DecodeResult. Every valid
// golden of an earlier minor decodes too. (An earlier minor's invalid
// golden may be one that only CheckLines refuses, as the 0.6
// config/results/invalid/failed-with-24-records.json is by its README.)
func TestC2v10ForwardOldGoldens(t *testing.T) {
	var valid9, invalid9 int
	for _, g := range c2v10Goldens(t) {
		if g.minor > 9 || (!g.valid && g.minor != 9) {
			continue
		}
		_, err := adapter.DecodeResult(g.b)
		switch {
		case g.valid && err != nil:
			t.Errorf("%s (0.%d): %v", g.rel, g.minor, err)
		case !g.valid && err == nil:
			t.Errorf("%s (0.%d): accepted", g.rel, g.minor)
		}
		if g.minor == 9 && g.valid {
			valid9++
		} else if g.minor == 9 {
			invalid9++
		}
	}
	// At 0f10fa02: three valid 0.9 goldens and nineteen invalid ones.
	if valid9 < 3 || invalid9 < 19 {
		t.Errorf("%d valid and %d invalid 0.9 goldens; want at least 3 and 19", valid9, invalid9)
	}
}
