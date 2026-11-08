package contract

// C2 0.9 (docs/phase4/D2-c2-0.9.md, approved under D4-69): D6's tests 1
// and 4 of section 6. Expected outcomes come from the rule text of
// sections 1.3 and 3, not from the code. The results are C2's invented
// 0.9 examples, edited one field at a time; nothing is a capture.
// Ground truth: GT-HAND. Evidence class: desk.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/adapter"
)

// c2v9 is C2's 0.9 ok example for sel (the SEL Telnet one) or snmp, as a
// map, with edit applied, decoded and validated.
func c2v9(t *testing.T, kind string, edit func(m map[string]any)) error {
	t.Helper()
	p := filepath.Join("..", "..", "contracts", "adapter", "testdata", "results", "valid", "ok-0.9.json")
	if kind == "snmp" {
		p = filepath.Join("..", "..", "contracts", "adapter", "testdata", "snmp", "results", "valid", "ok-0.9.json")
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if edit != nil {
		edit(m)
	}
	if b, err = json.Marshal(m); err != nil {
		t.Fatal(err)
	}
	_, err = adapter.DecodeResult(b)
	return err
}

func c2v9Session(m map[string]any) map[string]any { return m["session"].(map[string]any) }

func c2v9Segments(m map[string]any) []any {
	return m["transcript"].(map[string]any)["segments"].([]any)
}

// Both examples are valid as written, so every refusal below is the one
// field's doing.
func TestC2v09ExamplesAreValid(t *testing.T) {
	for _, k := range []string{"sel", "snmp"} {
		if err := c2v9(t, k, nil); err != nil {
			t.Errorf("%s: %v", k, err)
		}
	}
}

// Test 1, rule 1: connected true exactly when both fields are present.
func TestC2v09ConnectedNeedsBothFields(t *testing.T) {
	for _, k := range []string{"sel", "snmp"} {
		for name, edit := range map[string]func(map[string]any){
			"connected without local_addr":     func(m map[string]any) { delete(c2v9Session(m), "local_addr") },
			"connected without connected_at":   func(m map[string]any) { delete(c2v9Session(m), "connected_at") },
			"connected without either":         func(m map[string]any) { s := c2v9Session(m); delete(s, "local_addr"); delete(s, "connected_at") },
			"local_addr with connected false":  func(m map[string]any) { c2v9Session(m)["connected"] = false },
			"local_addr empty, connected true": func(m map[string]any) { c2v9Session(m)["local_addr"] = "" },
		} {
			if err := c2v9(t, k, edit); err == nil {
				t.Errorf("%s, %s: accepted", k, name)
			}
		}
	}
}

// Test 1, rule 2: local_addr is an IP literal and port in canonical form.
func TestC2v09LocalAddrForm(t *testing.T) {
	bad := []string{
		"relay.example:49152",          // a hostname
		"[fe80::1%eth0]:49152",         // a zone
		"[::ffff:192.0.2.10]:49152",    // IPv4-mapped IPv6 (D4, D6 and D3 on #541)
		"0.0.0.0:40000",                // unspecified IPv4 (section 6)
		"[::]:40000",                   // unspecified IPv6 (section 6)
		"192.0.2.10:0",                 // port 0
		"192.0.2.10",                   // no port
		"192.0.2.10:65536",             // port out of range
		"[2001:DB8::1]:49152",          // upper case: not canonical
		"[2001:db8:0:0:0:0:0:1]:49152", // not compressed: not canonical
		"[2001:db8::1]:049152",         // a leading zero on the port
		"2001:db8::1:49152",            // IPv6 without brackets
		"192.0.2.010:49152",            // a leading zero in an octet
		" 192.0.2.10:49152",            // a space
	}
	for _, k := range []string{"sel", "snmp"} {
		for _, a := range bad {
			if err := c2v9(t, k, func(m map[string]any) { c2v9Session(m)["local_addr"] = a }); err == nil {
				t.Errorf("%s: local_addr %q accepted", k, a)
			}
		}
		for _, a := range []string{"192.0.2.10:1", "192.0.2.10:65535", "[2001:db8::1]:49152", "[2001:db8::a:b]:40161"} {
			if err := c2v9(t, k, func(m map[string]any) { c2v9Session(m)["local_addr"] = a }); err != nil {
				t.Errorf("%s: local_addr %q refused: %v", k, a, err)
			}
		}
	}
	// The writer's helper agrees: what LocalAddrOf writes, ValidLocalAddr
	// accepts, and a mapped or zoned socket address comes out plain.
	for in, want := range map[string]string{
		"[::ffff:192.0.2.10]:49152": "192.0.2.10:49152",
		"[fe80::1%eth0]:49152":      "[fe80::1]:49152",
		"[2001:DB8::1]:49152":       "[2001:db8::1]:49152",
		"0.0.0.0:49152":             "",
		"192.0.2.10:0":              "",
	} {
		if got := adapter.LocalAddrOf(addrString(in)); got != want {
			t.Errorf("LocalAddrOf(%s) = %q, want %q", in, got, want)
		}
	}
}

type addrString string

func (a addrString) Network() string { return "tcp" }
func (a addrString) String() string  { return string(a) }

// Test 1, rules 3 and 4: started_at <= connected_at <= ended_at, no later
// than the first segment, and for SNMPv3 equal to the first segment, which
// is sent.
func TestC2v09ConnectedAtBounds(t *testing.T) {
	at := func(v string) func(map[string]any) {
		return func(m map[string]any) { c2v9Session(m)["connected_at"] = v }
	}
	for k, cases := range map[string]map[string]func(map[string]any){
		"sel": {
			"before started_at":       at("2026-10-24T09:14:59.9Z"),
			"after ended_at":          at("2026-10-24T09:15:01.9Z"),
			"after the first segment": at("2026-10-24T09:15:00.05Z"),
			"not a time":              at("2026-10-24 09:15:00Z"),
			"not UTC":                 at("2026-10-24T09:15:00.0+00:00"),
			"ten fractional digits":   at("2026-10-24T09:15:00.0000000000Z"),
		},
		"snmp": {
			"before the first segment": at("2026-10-24T09:14:59.9Z"),
			"after the first segment":  at("2026-10-24T09:15:00.05Z"),
			"first segment received": func(m map[string]any) {
				c2v9Segments(m)[0].(map[string]any)["dir"] = "rx"
			},
		},
	} {
		for name, edit := range cases {
			if err := c2v9(t, k, edit); err == nil {
				t.Errorf("%s, connected_at %s: accepted", k, name)
			}
		}
	}
	// A TCP session connects before its first byte: earlier is allowed.
	if err := c2v9(t, "sel", at("2026-10-24T09:15:00Z")); err != nil {
		t.Errorf("sel, connected_at equal to started_at and the first segment: %v", err)
	}
}

// Test 1, the 0.8 rule: a 0.8 result carrying either field fails, and one
// without them still passes.
func TestC2v09FieldsAreNewIn09(t *testing.T) {
	to08 := func(m map[string]any) { m["schema"] = "otsec.adapter/0.8" }
	for _, k := range []string{"sel", "snmp"} {
		if err := c2v9(t, k, to08); err == nil || !strings.Contains(err.Error(), "0.9") {
			t.Errorf("%s: a 0.8 result with both fields: %v", k, err)
		}
		if err := c2v9(t, k, func(m map[string]any) { to08(m); delete(c2v9Session(m), "connected_at") }); err == nil {
			t.Errorf("%s: a 0.8 result with local_addr: accepted", k)
		}
		if err := c2v9(t, k, func(m map[string]any) {
			to08(m)
			s := c2v9Session(m)
			delete(s, "local_addr")
			delete(s, "connected_at")
		}); err != nil {
			t.Errorf("%s: a 0.8 result without the fields: %v", k, err)
		}
	}
}

// Test 4: a ten-digit fraction is refused in each of the four time fields
// (section 3), and nine digits pass. Results of every minor are bounded,
// so a 0.8 result is checked too.
func TestC2v09TimesHaveAtMostNineDigits(t *testing.T) {
	const ten, nine = "2026-10-24T09:15:00.0000000000Z", "2026-10-24T09:15:00.000000000Z"
	set := map[string]func(m map[string]any, v string){
		"started_at": func(m map[string]any, v string) { m["started_at"] = v },
		"ended_at": func(m map[string]any, v string) {
			m["ended_at"] = "2026-10-24T09:15:01." + strings.TrimPrefix(v, "2026-10-24T09:15:00.")
		},
		"connected_at": func(m map[string]any, v string) { c2v9Session(m)["connected_at"] = v },
		"segment at":   func(m map[string]any, v string) { c2v9Segments(m)[0].(map[string]any)["at"] = v },
	}
	for _, k := range []string{"sel", "snmp"} {
		for field, f := range set {
			if err := c2v9(t, k, func(m map[string]any) { f(m, ten) }); err == nil {
				t.Errorf("%s: ten digits in %s accepted", k, field)
			}
			ok := func(m map[string]any) {
				f(m, nine)
				if k == "snmp" && (field == "connected_at" || field == "segment at") {
					// connected_at equals the first segment's at.
					c2v9Session(m)["connected_at"] = nine
					c2v9Segments(m)[0].(map[string]any)["at"] = nine
				}
			}
			if err := c2v9(t, k, ok); err != nil {
				t.Errorf("%s: nine digits in %s refused: %v", k, field, err)
			}
		}
		// Every minor: a 0.8 result with a ten-digit started_at.
		if err := c2v9(t, k, func(m map[string]any) {
			m["schema"] = "otsec.adapter/0.8"
			s := c2v9Session(m)
			delete(s, "local_addr")
			delete(s, "connected_at")
			m["started_at"] = ten
		}); err == nil {
			t.Errorf("%s: a 0.8 result with ten digits accepted", k)
		}
	}
}
