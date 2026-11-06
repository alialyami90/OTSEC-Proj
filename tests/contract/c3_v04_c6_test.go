package contract

// C3 0.4 (otsec.register/0.4, docs/phase4/C2-c1-0.3-c3-0.4.md §2 at
// 92026c9, D4-16, D4-49 Q3): C6's own cases. Expected outcomes come from the
// rule text. The SNMP operations are written here from §2.1's example, not
// copied from C2's tests; they are added to register revision 4, which
// already lists S29. Ground truth: GT-HAND.
//
// The property under test is that a SET cannot be written (V-M1 (b)), not
// even through the reader: a case variant or a repeated key must not let a
// package say one thing to a person and another to the decoder.

import (
	"encoding/json"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/register"
)

func c3SNMPOps() []any {
	common := func(m map[string]any) map[string]any {
		m["limits"] = map[string]any{"max_reply_bytes": 1472, "timeout_ms": 3000}
		m["citations"] = []any{map[string]any{"source": "S29", "ref": "pp. 46 to 47"}}
		m["evidence"] = map[string]any{"class": "documented-untested"}
		m["side_effects"] = "none: a read"
		return m
	}
	return []any{
		common(map[string]any{"id": "sel27x1.snmp.system", "pdu": "get", "oids": []any{"1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.5.0"}}),
		common(map[string]any{"id": "sel27x1.snmp.entity", "pdu": "getbulk", "subtree": "1.3.6.1.2.1.47.1.1.1",
			"max_repetitions": 16, "walk": map[string]any{"max_varbinds": 512, "max_requests": 32}}),
	}
}

// c3Rev4V04 is revision 4 at contract 0.4 with the two SNMP operations.
func c3Rev4V04(t *testing.T, edit func(p map[string]any)) []byte {
	t.Helper()
	b, err := c3Rev4(t, func(p map[string]any) {
		p["contract"] = "otsec.register/0.4"
		p["snmp_operations"] = c3SNMPOps()
		if edit != nil {
			edit(p)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func c3SNMPOp(p map[string]any, i int) map[string]any {
	return p["snmp_operations"].([]any)[i].(map[string]any)
}

func TestC3V04Rules(t *testing.T) {
	for _, c := range []struct {
		name string
		edit func(p map[string]any)
		ok   bool
	}{
		{"revision 4 with two SNMP operations", nil, true},
		{"the identity run", func(p map[string]any) {
			p["runs"] = []any{map[string]any{"id": "sel27x1.snmp.identity", "steps": []any{"sel27x1.snmp.system", "sel27x1.snmp.entity"},
				"max_total_bytes": 65536, "deadline_ms": 30000,
				"citations": []any{map[string]any{"source": "S29", "ref": "p. 46"}}, "evidence": map[string]any{"class": "documented-untested"}, "side_effects": "none: reads"}}
		}, true},

		// D4-16: the key is refused below 0.4, whatever its value.
		{"0.3 with snmp_operations", func(p map[string]any) { p["contract"] = "otsec.register/0.3" }, false},
		{"0.3 with snmp_operations []", func(p map[string]any) {
			p["contract"] = "otsec.register/0.3"
			p["snmp_operations"] = []any{}
		}, false},
		{"0.3 with snmp_operations null", func(p map[string]any) {
			p["contract"] = "otsec.register/0.3"
			p["snmp_operations"] = nil
		}, false},
		{"0.2 with snmp_operations", func(p map[string]any) { p["contract"] = "otsec.register/0.2" }, false},
		{"0.5", func(p map[string]any) { p["contract"] = "otsec.register/0.5" }, false},

		// §2.1: read PDUs only.
		{"getnext walk", func(p map[string]any) {
			o := c3SNMPOp(p, 1)
			o["pdu"] = "getnext"
			delete(o, "max_repetitions")
		}, true},
		{"pdu set", func(p map[string]any) { c3SNMPOp(p, 0)["pdu"] = "set" }, false},
		{"pdu getresponse", func(p map[string]any) { c3SNMPOp(p, 0)["pdu"] = "getresponse" }, false},
		{"pdu snmpv2-trap", func(p map[string]any) { c3SNMPOp(p, 0)["pdu"] = "snmpv2-trap" }, false},
		{"a security level", func(p map[string]any) { c3SNMPOp(p, 0)["security_level"] = "noAuthNoPriv" }, false},
		{"a user name", func(p map[string]any) { c3SNMPOp(p, 0)["user"] = "admin" }, false},
		{"a context name", func(p map[string]any) { c3SNMPOp(p, 0)["context_name"] = "" }, false},
		{"non_repeaters on a getbulk", func(p map[string]any) { c3SNMPOp(p, 1)["non_repeaters"] = 0 }, false},
		{"a state-changing classification", func(p map[string]any) { c3SNMPOp(p, 0)["classification"] = "state-changing" }, false},
		{"an SNMP operation in operations", func(p map[string]any) {
			p["operations"] = append(p["operations"].([]any), c3SNMPOps()[0])
		}, false},
		{"an oid in a line operation", func(p map[string]any) {
			o := p["operations"].([]any)[0].(map[string]any)
			o["oids"] = []any{"1.3.6.1.2.1.1.1.0"}
		}, false},
	} {
		_, err := register.Decode(c3Rev4V04(t, c.edit))
		if c.ok != (err == nil) {
			t.Errorf("%s: decode %v, want ok %v", c.name, err, c.ok)
		}
	}
}

// The reader takes exactly one spelling of each key, once. Otherwise a
// package could show a reviewer "pdu": "set" while the decoder read "get",
// or the reverse.
func TestC3V04KeysSpelledOnce(t *testing.T) {
	base := string(c3Rev4V04(t, nil))
	const get = `"pdu":"get"`
	if strings.Count(base, get) != 1 {
		t.Fatalf("want one %s in the package, have %d", get, strings.Count(base, get))
	}
	// A reader that let the last key win, or matched keys without regard to
	// case, would decode each of these as a valid get.
	for name, with := range map[string]string{
		"pdu twice, set first": `"pdu":"set","pdu":"get"`,
		"case variant first":   `"Pdu":"set","pdu":"get"`,
		"oids twice":           `"pdu":"get","oids":["1.3.6.1.2.1.1.1.0"]`,
		"limits twice":         `"pdu":"get","limits":{"max_reply_bytes":1048576,"timeout_ms":60000}`,
	} {
		b := strings.Replace(base, get, with, 1)
		if !json.Valid([]byte(b)) {
			t.Fatalf("%s: the probe is not JSON", name)
		}
		if _, err := register.Decode([]byte(b)); err == nil {
			t.Errorf("%s: decoded", name)
		}
	}
}
