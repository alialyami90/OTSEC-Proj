package register

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
)

// The 0.4 additions: snmp_operations and SNMP runs (C3 0.4,
// docs/phase4/C2-c1-0.3-c3-0.4.md §2, D4-53). Each case edits the 0.3 test
// package (runs_test.go) into a 0.4 package that also holds the approved
// text's two example operations and its identity run.

const (
	snmpSystem = "sel27x1.snmp.system"
	snmpEntity = "sel27x1.snmp.entity"
	snmpRun    = "sel27x1.snmp.identity"
)

func snmpGet() map[string]any {
	return map[string]any{
		"id":           snmpSystem,
		"pdu":          "get",
		"oids":         []any{"1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.5.0"},
		"limits":       map[string]any{"max_reply_bytes": 1472, "timeout_ms": 3000},
		"citations":    []any{map[string]any{"source": "T1", "ref": "pp. 46 to 47"}},
		"evidence":     map[string]any{"class": "documented-untested"},
		"side_effects": "none: reads two system-group scalars",
	}
}

func snmpBulk() map[string]any {
	return map[string]any{
		"id":              snmpEntity,
		"pdu":             "getbulk",
		"subtree":         "1.3.6.1.2.1.47.1.1.1",
		"max_repetitions": 16,
		"walk":            map[string]any{"max_varbinds": 512, "max_requests": 32},
		"limits":          map[string]any{"max_reply_bytes": 1472, "timeout_ms": 3000},
		"citations":       []any{map[string]any{"source": "T1", "ref": "pp. 46 and 75"}},
		"evidence":        map[string]any{"class": "documented-untested"},
		"side_effects":    "none: walks entPhysicalTable within the bounds",
	}
}

// v4 is the 0.3 test package at 0.4 with the two SNMP operations and an SNMP
// run beside the line run, then f.
func v4(t *testing.T, f func(m map[string]any)) []byte {
	t.Helper()
	return v3(t, func(m map[string]any) {
		m["contract"] = "otsec.register/0.4"
		m["sources"] = append(list(m, "sources"), map[string]any{"id": "T1", "title": "SEL-2730M and SEL-2731M SNMP reference (test source)"})
		m["snmp_operations"] = []any{snmpGet(), snmpBulk()}
		m["runs"] = append(list(m, "runs"), map[string]any{
			"id":              snmpRun,
			"steps":           steps(snmpSystem, snmpEntity),
			"max_total_bytes": 65536,
			"deadline_ms":     30000,
			"citations":       []any{map[string]any{"source": "T1", "ref": "pp. 46 to 47"}},
			"evidence":        map[string]any{"class": "documented-untested"},
			"side_effects":    "none: two reads",
		})
		if f != nil {
			f(m)
		}
	})
}

func snmpOp(m map[string]any, i int) map[string]any { return entry(m, "snmp_operations", i) }
func snmpRunOf(m map[string]any) map[string]any     { return entry(m, "runs", 1) }

func oidsOf(n int) []any {
	out := make([]any, n)
	for i := range out {
		out[i] = fmt.Sprintf("1.3.6.1.2.1.1.%d.0", i+1)
	}
	return out
}

func TestSNMPValid(t *testing.T) {
	p, err := Decode(v4(t, nil))
	if err != nil {
		t.Fatal(err)
	}
	g, b := p.SNMPOperation(snmpSystem), p.SNMPOperation(snmpEntity)
	if g == nil || g.PDU != PDUGet || len(g.OIDs) != 2 || g.Limits.MaxReplyBytes != 1472 {
		t.Fatalf("get = %+v", g)
	}
	if b == nil || b.PDU != PDUGetBulk || b.Subtree != "1.3.6.1.2.1.47.1.1.1" || b.MaxRepetitions != 16 || *b.Walk != (Walk{512, 32}) {
		t.Fatalf("getbulk = %+v", b)
	}
	if p.SNMPOperation("sel.id") != nil || p.SNMPOperation(snmpRun) != nil {
		t.Error("a line operation or a run is an SNMP operation")
	}
	// An SNMP operation is never a line: the matcher does not render it, does
	// not render its run, and has no limits for it under the line accessor.
	m, err := NewMatcher(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := m.Operation(snmpSystem); ok {
		t.Error("an SNMP operation is invocable as a line")
	}
	if _, err := m.Render(snmpSystem, nil); err == nil {
		t.Error("an SNMP operation rendered a line")
	}
	if _, err := m.RenderRun(snmpRun); err == nil {
		t.Error("an SNMP run rendered lines")
	}
	if lines, err := m.RenderRun(testRun); err != nil || len(lines) != 2 {
		t.Errorf("the line run beside it: %q, %v", lines, err)
	}
}

// The bounds at their edges are valid, and getnext walks without
// max_repetitions.
func TestSNMPEdgesValid(t *testing.T) {
	arcs := make([]string, 128)
	for i := range arcs {
		arcs[i] = "1"
	}
	copy(arcs, []string{"1", "3", "6", "1"})
	for name, f := range map[string]func(m map[string]any){
		"get of 16 oids":     func(m map[string]any) { snmpOp(m, 0)["oids"] = oidsOf(MaxGetOIDs) },
		"get of one oid":     func(m map[string]any) { snmpOp(m, 0)["oids"] = oidsOf(1) },
		"128 arcs":           func(m map[string]any) { snmpOp(m, 0)["oids"] = []any{strings.Join(arcs, ".")} },
		"an arc of 2^32-1":   func(m map[string]any) { snmpOp(m, 0)["oids"] = []any{"1.3.6.1.4.1.4294967295.0"} },
		"an arc of 0":        func(m map[string]any) { snmpOp(m, 0)["oids"] = []any{"1.3.6.1.0"} },
		"max_repetitions 1":  func(m map[string]any) { snmpOp(m, 1)["max_repetitions"] = 1 },
		"max_repetitions 32": func(m map[string]any) { snmpOp(m, 1)["max_repetitions"] = MaxRepetitionsCeiling },
		"walk at its ceilings": func(m map[string]any) {
			snmpOp(m, 1)["walk"] = map[string]any{"max_varbinds": 2048, "max_requests": 64}
		},
		"walk at 1 and 1": func(m map[string]any) { snmpOp(m, 1)["walk"] = map[string]any{"max_varbinds": 1, "max_requests": 1} },
		"max_reply_bytes 484": func(m map[string]any) {
			snmpOp(m, 0)["limits"] = map[string]any{"max_reply_bytes": 484, "timeout_ms": 1}
		},
		"limits at the ceilings": func(m map[string]any) {
			snmpOp(m, 0)["limits"] = map[string]any{"max_reply_bytes": MaxSNMPMessageBytes, "timeout_ms": MaxStepMS}
			snmpRunOf(m)["max_total_bytes"], snmpRunOf(m)["deadline_ms"] = MaxSessionBytes, MaxDeadlineMS
		},
		"getnext": func(m map[string]any) {
			snmpOp(m, 1)["pdu"] = "getnext"
			delete(snmpOp(m, 1), "max_repetitions")
		},
		"an SNMP-only run of one step": func(m map[string]any) { snmpRunOf(m)["steps"] = steps(snmpEntity) },
		"no SNMP run":                  func(m map[string]any) { m["runs"] = list(m, "runs")[:1] },
		"snmp_operations empty":        func(m map[string]any) { m["snmp_operations"] = []any{}; m["runs"] = list(m, "runs")[:1] },
	} {
		if _, err := Decode(v4(t, f)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// A package of SNMP operations only is valid at 0.4: at least one operation
// of either kind.
func TestSNMPOnlyPackage(t *testing.T) {
	only := func(f func(m map[string]any)) []byte {
		return v4(t, func(m map[string]any) {
			for _, k := range []string{"preconditions", "warnings", "context", "operations", "session_control", "denied"} {
				m[k] = []any{}
			}
			m["runs"] = list(m, "runs")[1:]
			for _, b := range m["firmware"].(map[string]any)["branches"].([]any) {
				delete(b.(map[string]any), "conditions")
				if b.(map[string]any)["status"] == "allow-with-condition" {
					b.(map[string]any)["status"] = "allow"
				}
			}
			if f != nil {
				f(m)
			}
		})
	}
	p, err := Decode(only(nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Operations) != 0 || len(p.SNMPOperations) != 2 {
		t.Fatalf("%d line and %d SNMP operations", len(p.Operations), len(p.SNMPOperations))
	}
	_, err = Decode(only(func(m map[string]any) { m["snmp_operations"] = []any{}; m["runs"] = []any{} }))
	if err == nil || !strings.Contains(err.Error(), "no operations") {
		t.Errorf("no operation of either kind: %v", err)
	}
}

func TestSNMPInvalid(t *testing.T) {
	setPDU := func(v any) func(m map[string]any) { return func(m map[string]any) { snmpOp(m, 0)["pdu"] = v } }
	oid := func(v any) func(m map[string]any) { return func(m map[string]any) { snmpOp(m, 0)["oids"] = []any{v} } }
	cases := map[string]func(m map[string]any){
		// The PDU is closed: no SET can be written (V-M1 (b)).
		"pdu set":       setPDU("set"),
		"pdu SET":       setPDU("SET"),
		"pdu Get":       setPDU("Get"),
		"pdu inform":    setPDU("inform"),
		"pdu trap":      setPDU("trap"),
		"pdu report":    setPDU("report"),
		"pdu response":  setPDU("response"),
		"pdu empty":     setPDU(""),
		"pdu missing":   func(m map[string]any) { delete(snmpOp(m, 0), "pdu") },
		"pdu a number":  setPDU(163),
		"set on a walk": func(m map[string]any) { snmpOp(m, 1)["pdu"] = "set" },
		// A get names 1 to 16 OIDs and nothing of a walk.
		"get of no oid":              func(m map[string]any) { snmpOp(m, 0)["oids"] = []any{} },
		"get without oids":           func(m map[string]any) { delete(snmpOp(m, 0), "oids") },
		"get of 17 oids":             func(m map[string]any) { snmpOp(m, 0)["oids"] = oidsOf(MaxGetOIDs + 1) },
		"get with a subtree":         func(m map[string]any) { snmpOp(m, 0)["subtree"] = "1.3.6.1.2.1.1" },
		"get with a walk":            func(m map[string]any) { snmpOp(m, 0)["walk"] = map[string]any{"max_varbinds": 1, "max_requests": 1} },
		"get with max_repetitions":   func(m map[string]any) { snmpOp(m, 0)["max_repetitions"] = 1 },
		"get repeats an oid":         func(m map[string]any) { snmpOp(m, 0)["oids"] = []any{"1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.1.0"} },
		"getbulk with oids":          func(m map[string]any) { snmpOp(m, 1)["oids"] = oidsOf(1) },
		"getbulk without a subtree":  func(m map[string]any) { delete(snmpOp(m, 1), "subtree") },
		"getbulk without a walk":     func(m map[string]any) { delete(snmpOp(m, 1), "walk") },
		"getbulk max_repetitions 0":  func(m map[string]any) { delete(snmpOp(m, 1), "max_repetitions") },
		"getbulk max_repetitions 33": func(m map[string]any) { snmpOp(m, 1)["max_repetitions"] = MaxRepetitionsCeiling + 1 },
		"getbulk max_repetitions -1": func(m map[string]any) { snmpOp(m, 1)["max_repetitions"] = -1 },
		"getbulk with non_repeaters": func(m map[string]any) { snmpOp(m, 1)["non_repeaters"] = 1 },
		"getnext with max_repetitions": func(m map[string]any) {
			snmpOp(m, 1)["pdu"] = "getnext"
		},
		"walk max_varbinds 0":    func(m map[string]any) { snmpOp(m, 1)["walk"] = map[string]any{"max_varbinds": 0, "max_requests": 1} },
		"walk max_varbinds 2049": func(m map[string]any) { snmpOp(m, 1)["walk"] = map[string]any{"max_varbinds": 2049, "max_requests": 1} },
		"walk max_requests 0":    func(m map[string]any) { snmpOp(m, 1)["walk"] = map[string]any{"max_varbinds": 1, "max_requests": 0} },
		"walk max_requests 65":   func(m map[string]any) { snmpOp(m, 1)["walk"] = map[string]any{"max_varbinds": 1, "max_requests": 65} },
		"walk with another key":  func(m map[string]any) { snmpOp(m, 1)["walk"].(map[string]any)["max_bytes"] = 1 },
		"subtree outside 1.3.6.1": func(m map[string]any) {
			snmpOp(m, 1)["subtree"] = "1.3.6.2.1"
		},
		// Every OID is literal dotted decimal under 1.3.6.1.
		"oid 1.3.6.1":         oid("1.3.6.1"),
		"oid under 1.3.6.2":   oid("1.3.6.2.1.0"),
		"oid under 0":         oid("0.0.1.3.6.1"),
		"oid leading zero":    oid("1.3.6.1.02.1.0"),
		"oid empty arc":       oid("1.3.6.1..1"),
		"oid trailing dot":    oid("1.3.6.1.2."),
		"oid leading dot":     oid(".1.3.6.1.2"),
		"oid an arc of 2^32":  oid("1.3.6.1.4.1.4294967296.0"),
		"oid a signed arc":    oid("1.3.6.1.+2.1"),
		"oid a negative arc":  oid("1.3.6.1.-2.1"),
		"oid a space":         oid("1.3.6.1.2.1 .1.0"),
		"oid a name":          oid("1.3.6.1.mib-2.1.1.0"),
		"oid a wildcard":      oid("1.3.6.1.2.1.1.*"),
		"oid a parameter":     oid("1.3.6.1.2.1.1.{n}"),
		"oid hex arc":         oid("1.3.6.1.0x2.1"),
		"oid non-ASCII digit": oid("1.3.6.1.٢.1"),
		"oid empty":           oid(""),
		"oid a number":        oid(1),
		"oid of 129 arcs":     oid("1.3.6.1" + strings.Repeat(".1", 125)),
		"limits missing":      func(m map[string]any) { delete(snmpOp(m, 0), "limits") },
		"limits null":         func(m map[string]any) { snmpOp(m, 0)["limits"] = nil },
		"max_reply_bytes 483": func(m map[string]any) {
			snmpOp(m, 0)["limits"] = map[string]any{"max_reply_bytes": 483, "timeout_ms": 3000}
		},
		"max_reply_bytes 65,508": func(m map[string]any) {
			snmpOp(m, 0)["limits"] = map[string]any{"max_reply_bytes": MaxSNMPMessageBytes + 1, "timeout_ms": 3000}
		},
		"max_reply_bytes 1 MiB": func(m map[string]any) {
			snmpOp(m, 0)["limits"] = map[string]any{"max_reply_bytes": MaxSessionBytes, "timeout_ms": 3000}
		},
		"timeout_ms 0": func(m map[string]any) {
			snmpOp(m, 0)["limits"] = map[string]any{"max_reply_bytes": 1472, "timeout_ms": 0}
		},
		"timeout_ms 60001": func(m map[string]any) {
			snmpOp(m, 0)["limits"] = map[string]any{"max_reply_bytes": 1472, "timeout_ms": MaxStepMS + 1}
		},
		"no citations": func(m map[string]any) { snmpOp(m, 0)["citations"] = []any{} },
		"unknown source": func(m map[string]any) {
			snmpOp(m, 0)["citations"] = []any{map[string]any{"source": "S99", "ref": "p. 1"}}
		},
		"no evidence":        func(m map[string]any) { delete(snmpOp(m, 0), "evidence") },
		"no side effects":    func(m map[string]any) { snmpOp(m, 0)["side_effects"] = "" },
		"id not dotted":      func(m map[string]any) { snmpOp(m, 0)["id"] = "system" },
		"id of a line op":    func(m map[string]any) { snmpOp(m, 0)["id"] = "sel.id" },
		"id of a run":        func(m map[string]any) { snmpOp(m, 0)["id"] = testRun },
		"id repeated":        func(m map[string]any) { snmpOp(m, 1)["id"] = snmpSystem },
		"a classification":   func(m map[string]any) { snmpOp(m, 0)["classification"] = "read-only" },
		"an access level":    func(m map[string]any) { snmpOp(m, 0)["access_level"] = "1" },
		"a community":        func(m map[string]any) { snmpOp(m, 0)["community"] = "public" },
		"a version":          func(m map[string]any) { snmpOp(m, 0)["version"] = "v2c" },
		"a value to set":     func(m map[string]any) { snmpOp(m, 0)["value"] = "1" },
		"a line on SNMP":     func(m map[string]any) { snmpOp(m, 0)["line"] = "SNMP GET" },
		"snmp_operations {}": func(m map[string]any) { m["snmp_operations"] = map[string]any{} },
		// Runs: one session on one transport, so never mixed.
		"SNMP then line run": func(m map[string]any) { snmpRunOf(m)["steps"] = steps(snmpSystem, "sel.settings.show_global") },
		"line then SNMP run": func(m map[string]any) {
			run0(m)["steps"] = steps("sel.settings.show_port1", "sel.settings.show_global", snmpSystem)
		},
		"SNMP step twice":   func(m map[string]any) { snmpRunOf(m)["steps"] = steps(snmpSystem, snmpSystem) },
		"SNMP step unknown": func(m map[string]any) { snmpRunOf(m)["steps"] = steps(snmpSystem, "sel27x1.snmp.nothing") },
		"SNMP step over the run's bytes": func(m map[string]any) {
			snmpRunOf(m)["max_total_bytes"] = 1471
		},
		"SNMP step over the run's deadline": func(m map[string]any) { snmpRunOf(m)["deadline_ms"] = 2999 },
		"SNMP run over the deadline ceiling": func(m map[string]any) {
			snmpRunOf(m)["deadline_ms"] = MaxDeadlineMS + 1
		},
	}
	for name, f := range cases {
		if _, err := Decode(v4(t, f)); err == nil {
			t.Errorf("%s: valid", name)
		}
	}
}

// snmp_operations is new in 0.4: a package below 0.4 that carries the key is
// refused whatever its value (D4-16), and the 0.3 control without it reads.
func TestSNMPKeyBeforeOnePointFour(t *testing.T) {
	for _, c := range []string{"otsec.register/0.1", "otsec.register/0.2", "otsec.register/0.3"} {
		for n, v := range map[string]any{"two operations": []any{snmpGet(), snmpBulk()}, "[]": []any{}, "null": nil} {
			_, err := Decode(v3(t, func(m map[string]any) {
				m["contract"] = c
				if c != "otsec.register/0.3" {
					delete(m, "runs")
					for _, o := range list(m, "operations") {
						delete(o.(map[string]any), "limits")
					}
				}
				if c == "otsec.register/0.1" {
					delete(m, "context")
				}
				m["sources"] = append(list(m, "sources"), map[string]any{"id": "T1", "title": "test"})
				m["snmp_operations"] = v
			}))
			if err == nil || !strings.Contains(err.Error(), "new in 0.4") {
				t.Errorf("%s with snmp_operations %s: %v", c, n, err)
			}
		}
	}
	if _, err := Decode(v3(t, nil)); err != nil {
		t.Errorf("0.3 without the key: %v", err)
	}
	// Validate on a decoded struct holds the same line.
	p, err := Decode(v4(t, nil))
	if err != nil {
		t.Fatal(err)
	}
	p.Contract = "otsec.register/0.3"
	if err := p.Validate(); err == nil || !strings.Contains(err.Error(), "new in 0.4") {
		t.Errorf("Validate at 0.3 with SNMP operations: %v", err)
	}
}

func TestValidOID(t *testing.T) {
	for s, want := range map[string]bool{
		"1.3.6.1.2.1.1.1.0":                   true,
		"1.3.6.1.0":                           true,
		"1.3.6.1.4.1.4294967295":              true,
		"1.3.6.1":                             false,
		"1.3.6.1.":                            false,
		"1.3.6.10.1":                          false,
		"1.3.6.1.4.1.4294967296":              false,
		"1.3.6.1.00":                          false,
		"1.3.6.1.1 ":                          false,
		"1.3.6.1.1" + ".1" + "\x00":           false,
		"1.3.6.1" + strings.Repeat(".1", 124): true,
		"1.3.6.1" + strings.Repeat(".1", 125): false,
	} {
		if ValidOID(s) != want {
			t.Errorf("ValidOID(%q) = %v", s, !want)
		}
	}
}

func TestInSubtree(t *testing.T) {
	const sub = "1.3.6.1.2.1.47.1.1.1"
	for oid, want := range map[string]bool{
		"1.3.6.1.2.1.47.1.1.1.1.2.1": true,
		"1.3.6.1.2.1.47.1.1.1.1":     true,
		sub:                          false, // the subtree itself is not inside it
		"1.3.6.1.2.1.47.1.1.10":      false, // a prefix by text, not by arcs
		"1.3.6.1.2.1.47.1.1.2.1":     false,
		"1.3.6.1.2.1.47.1.1":         false,
	} {
		if InSubtree(oid, sub) != want {
			t.Errorf("InSubtree(%q) = %v", oid, !want)
		}
	}
}

// The schema's SNMP bounds are the same constants.
func TestSchemaSNMPBounds(t *testing.T) {
	data, err := os.ReadFile("schema/register.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	type bound struct{ Minimum, Maximum, MaxItems int }
	var s struct {
		Defs struct {
			SNMPOperation struct {
				Properties struct {
					PDU            struct{ Enum []string }
					OIDs           bound `json:"oids"`
					MaxRepetitions bound `json:"max_repetitions"`
					Walk           struct{ Properties map[string]bound }
					Limits         struct {
						AllOf []struct{ Properties map[string]bound } `json:"allOf"`
					}
				}
			} `json:"snmpOperation"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(data, &s); err != nil {
		t.Fatal(err)
	}
	p := s.Defs.SNMPOperation.Properties
	if !slices.Equal(p.PDU.Enum, []string{string(PDUGet), string(PDUGetNext), string(PDUGetBulk)}) ||
		p.OIDs.MaxItems != MaxGetOIDs || p.MaxRepetitions.Maximum != MaxRepetitionsCeiling ||
		p.Walk.Properties["max_varbinds"].Maximum != MaxWalkVarbinds || p.Walk.Properties["max_requests"].Maximum != MaxWalkRequests {
		t.Errorf("the schema's SNMP bounds %+v are not the constants", p)
	}
	if a := p.Limits.AllOf; len(a) != 2 || a[1].Properties["max_reply_bytes"].Minimum != MinSNMPMessageBytes ||
		a[1].Properties["max_reply_bytes"].Maximum != MaxSNMPMessageBytes {
		t.Errorf("the schema's SNMP max_reply_bytes %+v is not %d..%d", a, MinSNMPMessageBytes, MaxSNMPMessageBytes)
	}
}
