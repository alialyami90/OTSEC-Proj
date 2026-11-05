package contract

// C1 0.3 (otsec.asset/0.3, docs/phase4/C2-c1-0.3-c3-0.4.md at 92026c9, D4-49
// Q1, Q3 and Q4): C6's own cases. Expected outcomes come from the rule text,
// not from the code. Records are built from C2's SNMPv3 golden by editing
// its JSON; every value is invented. Ground truth: GT-HAND.
//
// The property under test is V-M7's: an operator-entered or passively
// inferred identity never yields confirmed, through derivation too (§1.1).
// A reader acts on Effective(), so the property is checked there.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/asset"
)

func c1SNMP(t *testing.T, edit func(m map[string]any)) ([]byte, error) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "contracts", "asset", "testdata", "valid", "sel-2731m-snmpv3.json"))
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
	return json.Marshal(m)
}

func c1Attr(m map[string]any, name string) map[string]any {
	for _, a := range m["attributes"].([]any) {
		if at := a.(map[string]any); at["name"] == name {
			return at
		}
	}
	panic("no attribute " + name)
}

func c1Obs(m map[string]any, name string, i int) map[string]any {
	return c1Attr(m, name)["observations"].([]any)[i].(map[string]any)
}

func c1Src(m map[string]any, name string, i int) map[string]any {
	return c1Obs(m, name, i)["source"].(map[string]any)
}

// c1Derived appends a derived observation of kind k from ref to the named
// attribute, with the attribute's own value.
func c1Derived(m map[string]any, name, ref, k string) {
	at := c1Attr(m, name)
	at["observations"] = append(at["observations"].([]any), map[string]any{
		"value":          at["value"],
		"evidence_class": "inferred",
		"source":         map[string]any{"method": "derived", "kind": k, "ref": ref, "observed_at": "2026-11-05T09:30:00Z"},
	})
	at["confidence"] = "corroborated"
}

// c1OperatorOnly leaves the named attribute with one operator-entry
// observation of its value.
func c1OperatorOnly(m map[string]any, name string) {
	at := c1Attr(m, name)
	at["observations"] = []any{map[string]any{
		"value":          at["value"],
		"evidence_class": "operator-declared",
		"source":         map[string]any{"method": "operator-entry", "kind": "operator", "ref": "operator:commissioning-sheet-07", "observed_at": "2026-11-05T04:00:00Z"},
	}}
	at["confidence"] = "single-source"
}

func TestC1V03Rules(t *testing.T) {
	for _, c := range []struct {
		name string
		edit func(m map[string]any)
		ok   bool
	}{
		{"golden", nil, true},

		// §1.1: a rule cannot raise its inputs to device-read.
		{"derived device-read from device-read inputs", func(m map[string]any) {
			c1Derived(m, "device_class", "model, hostname", "device-read")
		}, true},
		{"derived device-read naming its own attribute, whose only other evidence is operator", func(m map[string]any) {
			c1Derived(m, "device_class", "device_class", "device-read")
		}, false},
		{"derived device-read pair, each naming the other, over operator inputs", func(m map[string]any) {
			c1OperatorOnly(m, "model")
			c1Derived(m, "model", "device_class", "device-read")
			c1Derived(m, "device_class", "model", "device-read")
		}, false},
		{"derived device-read from an operator input", func(m map[string]any) {
			c1Derived(m, "device_class", "vendor", "device-read")
		}, false},
		{"derived device-read from an attribute not in the record", func(m map[string]any) {
			c1Derived(m, "device_class", "serial_number", "device-read")
		}, false},
		{"derived device-read with an empty input name", func(m map[string]any) {
			c1Derived(m, "device_class", "model,", "device-read")
		}, false},
		{"derived operator from operator inputs", func(m map[string]any) {
			c1Derived(m, "device_class", "vendor", "operator")
		}, true},
		{"derived passive", func(m map[string]any) {
			c1Derived(m, "device_class", "vendor", "passive")
		}, true},

		// §1.1: the kind follows the method.
		{"kind missing on a session read", func(m map[string]any) { delete(c1Src(m, "model", 0), "kind") }, false},
		{"syslog-received labelled device-read", func(m map[string]any) {
			s := c1Src(m, "hostname", 0)
			s["method"], s["kind"] = "syslog-received", "device-read"
			delete(s, "span")
			delete(s, "read")
			c1Obs(m, "hostname", 0)["evidence_class"] = "device-observed"
		}, false},
		{"session read labelled operator", func(m map[string]any) { c1Src(m, "model", 0)["kind"] = "operator" }, false},
		{"kind in upper case", func(m map[string]any) { c1Src(m, "model", 0)["kind"] = "Device-Read" }, false},

		// §1.2: the read path.
		{"read on a derived observation", func(m map[string]any) {
			c1Derived(m, "device_class", "model", "device-read")
			c1Obs(m, "device_class", 1)["source"].(map[string]any)["read"] = map[string]any{"transport": "snmpv3", "operation": "sel27x1.snmp.entity", "oid": "1.3.6.1.2.1.1.1.0"}
		}, false},
		{"read on an inbound transport", func(m map[string]any) {
			c1Src(m, "model", 0)["read"] = map[string]any{"transport": "syslog-udp", "operation": "sel27x1.snmp.entity"}
		}, false},
		{"read transport unknown", func(m map[string]any) {
			c1Src(m, "model", 0)["read"] = map[string]any{"transport": "snmpv2c", "operation": "sel27x1.snmp.entity", "oid": "1.3.6.1.2.1.1.1.0"}
		}, false},
		{"read without an operation", func(m map[string]any) {
			delete(c1Src(m, "model", 0)["read"].(map[string]any), "operation")
		}, false},
		{"read operation is a session line", func(m map[string]any) {
			c1Src(m, "model", 0)["read"].(map[string]any)["operation"] = "QUI"
		}, false},
		{"header in lower case", func(m map[string]any) {
			c1Src(m, "snmp_engine_id", 1)["read"].(map[string]any)["header"] = "msgauthoritativeengineid"
		}, false},
		{"header another USM field", func(m map[string]any) {
			c1Src(m, "snmp_engine_id", 1)["read"].(map[string]any)["header"] = "msgAuthoritativeEngineBoots"
		}, false},
		{"oid with a leading zero", func(m map[string]any) {
			c1Src(m, "model", 0)["read"].(map[string]any)["oid"] = "1.3.6.1.2.1.47.1.1.1.1.010.1"
		}, false},
		{"oid an arc of 2^32", func(m map[string]any) {
			c1Src(m, "model", 0)["read"].(map[string]any)["oid"] = "1.3.6.1.4.1.4294967296"
		}, false},

		// §1.3: the snmpv3 transport.
		{"snmpv3 without a port", func(m map[string]any) {
			delete(m["endpoints"].([]any)[0].(map[string]any), "port")
		}, false},
		{"snmpv3 plaintext-unauthenticated", func(m map[string]any) {
			m["endpoints"].([]any)[0].(map[string]any)["downstream_security"] = map[string]any{"level": "plaintext-unauthenticated"}
		}, false},
		{"snmpv2c endpoint", func(m map[string]any) {
			m["endpoints"].([]any)[0].(map[string]any)["transport"] = "snmpv2c"
		}, false},
		{"snmpv1 endpoint", func(m map[string]any) {
			m["endpoints"].([]any)[0].(map[string]any)["transport"] = "snmpv1"
		}, false},

		// §1.4: the engine ID is what pinned-key pins.
		{"pre_credential engine ID and firmware ID", func(m map[string]any) {
			m["identity_binding"].(map[string]any)["pre_credential"] = []any{"snmp_engine_id", "firmware_id"}
		}, false},
		{"pre_credential empty", func(m map[string]any) {
			m["identity_binding"].(map[string]any)["pre_credential"] = []any{}
		}, false},
		{"address-only binding", func(m map[string]any) {
			b := m["identity_binding"].(map[string]any)
			b["method"], b["strength"] = "address-only", "spoofable"
			b["attributes"] = []any{"ip_address"}
			delete(b, "pre_credential")
		}, false},
		{"engine ID with no operator-declared value", func(m map[string]any) {
			at := c1Attr(m, "snmp_engine_id")
			at["observations"] = at["observations"].([]any)[1:]
			at["confidence"] = "single-source"
		}, false},
		{"engine ID missing", func(m map[string]any) {
			var keep []any
			for _, a := range m["attributes"].([]any) {
				if a.(map[string]any)["name"] != "snmp_engine_id" {
					keep = append(keep, a)
				}
			}
			m["attributes"] = keep
			b := m["identity_binding"].(map[string]any)
			b["attributes"] = []any{"firmware_id"}
		}, false},
		{"engine ID of 5 octets", func(m map[string]any) { c1SetEngineID(m, strings.Repeat("ab", 5)) }, true},
		{"engine ID of 32 octets", func(m map[string]any) { c1SetEngineID(m, strings.Repeat("ab", 32)) }, true},
		{"engine ID of 4 octets", func(m map[string]any) { c1SetEngineID(m, strings.Repeat("ab", 4)) }, false},
		{"engine ID of 33 octets", func(m map[string]any) { c1SetEngineID(m, strings.Repeat("ab", 33)) }, false},
		{"engine ID of an odd digit count", func(m map[string]any) { c1SetEngineID(m, "80007c4f030200002731010") }, false},
		{"engine ID in upper case", func(m map[string]any) { c1SetEngineID(m, "80007C4F03020000273101") }, false},
		{"engine ID with 0x", func(m map[string]any) { c1SetEngineID(m, "0x80007c4f03020000273101") }, false},
		{"engine ID with colons", func(m map[string]any) { c1SetEngineID(m, "80:00:7c:4f:03:02:00:00:27:31:01") }, false},

		// §1.6: a 0.2 record carries none of 0.3.
		{"0.2 with an snmpv3 endpoint", func(m map[string]any) {
			// Without kind and read, so that the endpoint alone is what 0.2 refuses.
			m["schema"] = "otsec.asset/0.2"
			for _, a := range m["attributes"].([]any) {
				for _, o := range a.(map[string]any)["observations"].([]any) {
					delete(o.(map[string]any)["source"].(map[string]any), "kind")
					delete(o.(map[string]any)["source"].(map[string]any), "read")
				}
			}
		}, false},
	} {
		b, err := c1SNMP(t, c.edit)
		if err != nil {
			t.Fatal(err)
		}
		_, err = asset.Decode(b)
		if c.ok != (err == nil) {
			t.Errorf("%s: decode %v, want ok %v", c.name, err, c.ok)
		}
	}
}

func c1SetEngineID(m map[string]any, v string) {
	at := c1Attr(m, "snmp_engine_id")
	at["value"] = v
	for _, o := range at["observations"].([]any) {
		o.(map[string]any)["value"] = v
	}
}

// V-M7 through derivation, as a reader sees it. In every record that
// decodes, at every minor, a derived observation that Effective() leaves
// device-read has only inputs that Effective() also reads as device-read.
func TestC1V03DerivedKindHoldsAfterEffective(t *testing.T) {
	for _, c := range []struct {
		name string
		edit func(m map[string]any)
	}{
		{"own minor, inputs read", func(m map[string]any) {
			c1Derived(m, "device_class", "model, hostname", "device-read")
		}},
		// A later minor's input is device-read on a method 0.3 does not
		// know. Validate takes it (a later minor's unknown method is not
		// an error); Effective() reads the input as operator, so the
		// derived observation built on it may not stay device-read.
		{"later minor, input on an unknown method", func(m map[string]any) {
			m["schema"] = "otsec.asset/0.4"
			c1OperatorOnly(m, "hostname")
			at := c1Attr(m, "hostname")
			at["observations"] = append(at["observations"].([]any), map[string]any{
				"value":          at["value"],
				"evidence_class": "device-observed",
				"source": map[string]any{"method": "snmp-inform", "kind": "device-read", "ref": "3e9d5a71-0b2c-4f86-a1d4-6c8e2f0b9a53",
					"observed_at": "2026-11-05T04:20:00Z"},
			})
			at["confidence"] = "corroborated"
			c1Derived(m, "device_class", "hostname", "device-read")
		}},
		// A later minor's input carries a kind 0.3 does not know.
		{"later minor, input of an unknown kind", func(m map[string]any) {
			m["schema"] = "otsec.asset/0.4"
			c1Src(m, "hostname", 0)["kind"] = "witnessed"
			delete(c1Src(m, "hostname", 0), "read")
			c1Derived(m, "device_class", "hostname", "device-read")
		}},
	} {
		b, err := c1SNMP(t, c.edit)
		if err != nil {
			t.Fatal(err)
		}
		a, err := asset.Decode(b)
		if err != nil {
			continue // refused: nothing for a reader to act on
		}
		e := a.Effective()
		for _, at := range e.Attributes {
			for j, ob := range at.Observations {
				if ob.Source.Method != asset.Derived || ob.EffectiveKind() != asset.DeviceRead {
					continue
				}
				for _, name := range strings.Split(ob.Source.Ref, ",") {
					in, _ := e.Attribute(strings.TrimSpace(name))
					backed := false
					for _, io := range in.Observations {
						backed = backed || (io.EffectiveKind() == asset.DeviceRead && io.Value == in.Value)
					}
					if !backed {
						t.Errorf("%s: %s observations[%d] reads as device-read, but its input %s reads as %v", c.name, at.Name, j, name, kinds(in))
					}
				}
			}
		}
	}
}

func kinds(at asset.Attribute) []asset.SourceKind {
	var out []asset.SourceKind
	for _, o := range at.Observations {
		out = append(out, o.EffectiveKind())
	}
	return out
}
