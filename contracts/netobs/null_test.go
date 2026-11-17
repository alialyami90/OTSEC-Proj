package netobs

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/internal/strictjson"
)

// Records for P4-4-NULL (D1's ruling on #732): each kind of 0.2 and 0.3
// channel record with every optional field the 34 paths need set. Every
// value is illustrative: no sensor produced them.

// nullFunction is a DNP3 first sight with sa, a PRP LAN on each cited
// frame and a redaction on the second.
func nullFunction(schema string) *Observation {
	o := fxObservation02()
	o.Schema = schema
	o.Citation.Frames[0].LAN, o.Citation.Frames[1].LAN = "a", "a"
	o.Coverage.PRP.LANsSeen = []string{"a"}
	return o
}

// nullRepeat is nullFunction seen again: not a first sight, no bytes.
func nullRepeat(schema string) *Observation {
	o := nullFunction(schema)
	o.FirstSight, o.Frames = false, nil
	return o
}

// nullModbus is a Modbus 8 request with its sub-function, seen again.
func nullModbus(schema string) *Observation {
	o := nullRepeat(schema)
	o.Protocol, o.IP.Dport = "modbus", ptr(502)
	o.Function = &Function{Code: 8, Sub: ptr(1), Objects: []string{}, Unit: ptr(1)}
	return o
}

// nullModbus3 is a Modbus 3 request, which carries no sub-function.
func nullModbus3(schema string) *Observation {
	o := nullModbus(schema)
	o.Function.Code, o.Function.Sub = 3, nil
	return o
}

// nullOther is nullRepeat with its function replaced by set.
func nullOther(schema string, kind Kind, protocol string, set func(o *Observation)) *Observation {
	o := nullRepeat(schema)
	o.Kind, o.Protocol, o.Function = kind, protocol, nil
	set(o)
	return o
}

func nullText(s string) *Text { return &Text{Value: s, Length: int64(len(s))} }

func nullService(schema string) *Observation {
	return nullOther(schema, KindService, "dnp3", func(o *Observation) {
		o.Service = &Service{Basis: "content", Version: nullText("v1")}
	})
}

func nullTelnet(schema string) *Observation {
	return nullOther(schema, KindInsecure, "telnet", func(o *Observation) {
		o.Insecure = &Insecure{Reason: "telnet", Login: &Login{User: nullText("operator"), Attempts: 1, Slot: "none", Why: "no-slot"}}
	})
}

func nullHTTP(schema string) *Observation {
	return nullOther(schema, KindInsecure, "http", func(o *Observation) {
		o.Insecure = &Insecure{Reason: "http-plain", RedirectOnly: ptr(true)}
	})
}

func nullSNMPv3(schema string) *Observation {
	return nullOther(schema, KindEncrypted, "snmp", func(o *Observation) {
		o.Encrypted = &Encrypted{Scheme: "snmpv3", SNMPv3: &SNMPv3{EngineID: "8000000001", User: *nullText("monitor"),
			Level: "authPriv", Boots: ptr(int64(3)), Time: ptr(int64(1000))}}
	})
}

func nullTLS(schema string) *Observation {
	return nullOther(schema, KindEncrypted, "tls", func(o *Observation) {
		o.Encrypted = &Encrypted{Scheme: "tls", TLS: &TLS{Version: "1.2", SNI: nullText("relay")}}
	})
}

func nullIdentity(schema string) *Observation {
	return nullOther(schema, KindIdentity, "telnet", func(o *Observation) {
		o.Identity = &Identity{Attribute: "fid", Value: *nullText("FID-TEST"), Via: "telnet"}
	})
}

// nullUndecoded is an undecoded UDP record, which carries ip (D6's N3 on
// #735: ip null read as layer 2 on main).
func nullUndecoded(schema string) *Observation {
	return nullOther(schema, KindUndecoded, "unknown", func(o *Observation) {
		o.IP.L4, o.Direction = "udp", DirectionNone
		o.Undecoded = &Undecoded{Basis: "port", Packets: 3}
	})
}

func nullHeartbeat(schema string) *Heartbeat {
	if schema == Identifier03 {
		return fxHeartbeat03()
	}
	return fxHeartbeat02()
}

// nullRow is one of the 34 paths of D4's list (comment 6946933575 on
// #732), in the record that carries it.
type nullRow struct {
	row  int
	path []any
	rec  func(schema string) any
}

func obs(f func(string) *Observation) func(string) any { return func(s string) any { return f(s) } }

var (
	hbRec    = func(s string) any { return nullHeartbeat(s) }
	coverage = []struct {
		row  int
		path []any
	}{
		{10, []any{"degraded"}}, {11, []any{"vlans_seen"}}, {12, []any{"untagged_seen"}},
		{13, []any{"vlans_overflow"}}, {14, []any{"prp"}}, {15, []any{"prp", "lans_seen"}},
		{16, []any{"prp", "duplicates_discarded"}}, {17, []any{"decodes"}},
	}
)

func nullRows() []nullRow {
	rows := []nullRow{
		// Row group: the record's own fields.
		{1, []any{"first_sight"}, obs(nullRepeat)},
		{2, []any{"l2", "vlan"}, obs(nullFunction)},
		// Row group: function.
		{3, []any{"function", "code"}, obs(nullModbus3)},
		{4, []any{"function", "sub"}, obs(nullModbus)},
		{5, []any{"function", "objects"}, obs(nullFunction)},
		{6, []any{"function", "sa"}, obs(nullFunction)},
		// Row group: the citation.
		{7, []any{"citation", "frames", 0, "lan"}, obs(nullFunction)},
		{8, []any{"citation", "frames", 1, "redactions"}, obs(nullFunction)},
		{9, []any{"citation", "frames", 1, "redactions", 0, "offset"}, obs(nullRepeat)},
		// Row group: encrypted.
		{18, []any{"encrypted", "snmpv3", "boots"}, obs(nullSNMPv3)},
		{19, []any{"encrypted", "snmpv3", "time"}, obs(nullSNMPv3)},
		{20, []any{"encrypted", "snmpv3", "user"}, obs(nullSNMPv3)},
		{21, []any{"encrypted", "snmpv3", "user", "truncated"}, obs(nullSNMPv3)},
		{22, []any{"encrypted", "tls"}, obs(nullTLS)},
		{23, []any{"encrypted", "tls", "sni"}, obs(nullTLS)},
		{24, []any{"encrypted", "tls", "sni", "truncated"}, obs(nullTLS)},
		// Row group: identity and service.
		{25, []any{"identity", "value"}, obs(nullIdentity)},
		{26, []any{"identity", "value", "truncated"}, obs(nullIdentity)},
		{27, []any{"service", "version"}, obs(nullService)},
		{28, []any{"service", "version", "truncated"}, obs(nullService)},
		// Row group: insecure.
		{29, []any{"insecure", "login"}, obs(nullTelnet)},
		{30, []any{"insecure", "login", "user"}, obs(nullTelnet)},
		{31, []any{"insecure", "login", "user", "truncated"}, obs(nullTelnet)},
		{32, []any{"insecure", "login", "why"}, obs(nullTelnet)},
		{33, []any{"insecure", "redirect_only"}, obs(nullHTTP)},
		// Row group: the heartbeat.
		{34, []any{"ring_oldest_utc"}, hbRec},
	}
	// Row group: the coverage statement, on an observation and on a
	// heartbeat.
	for _, cv := range coverage {
		p := append([]any{"coverage"}, cv.path...)
		rows = append(rows, nullRow{cv.row, p, obs(nullFunction)}, nullRow{cv.row, p, hbRec})
	}
	return rows
}

// field is path in the checker's field form: "a.b[0].c".
func field(path []any) string {
	s := ""
	for _, p := range path {
		switch k := p.(type) {
		case string:
			if s != "" {
				s += "."
			}
			s += k
		case int:
			s += fmt.Sprintf("[%d]", k)
		}
	}
	return s
}

// decodeRuleOff decodes b as DecodeFromSensorIn does, and validates it
// without the null rule: the null paths are not passed, so refuseNulls
// refuses nothing. It is the control's reader.
func decodeRuleOff(b []byte, schema string, rec any) error {
	switch rec.(type) {
	case *Heartbeat:
		var h Heartbeat
		if err := strictjson.Decode(b, &h); err != nil {
			return err
		}
		return h.validateChannel(schema, keyPaths(b), nil)
	default:
		var o Observation
		if err := strictjson.Decode(b, &o); err != nil {
			return err
		}
		return o.validateChannel(schema, keyPaths(b), nil)
	}
}

// P4-4-NULL (D1's ruling on #732, D4's option A): each of the 34 paths
// that a 0.2 or 0.3 channel record accepted with null is refused, as form
// at that path and nothing else, at both minors. Controls: each record
// decodes as built; with the rule off, each null is accepted, as before
// the rule.
func TestChannelNullRefusedAt34Paths(t *testing.T) {
	seen := map[int]bool{}
	for _, schema := range channelIdentifiers {
		for _, r := range nullRows() {
			seen[r.row] = true
			f := field(r.path)
			name := fmt.Sprintf("%s, row %d, %T %s", schema, r.row, r.rec(schema), f)
			if _, err := DecodeFromSensorIn(mustJSON(t, r.rec(schema)), schema); err != nil {
				t.Errorf("control, %s: the record as built: %v", name, err)
				continue
			}
			b := encodeWith(t, r.rec(schema), func(m map[string]any) { setPath(m, nil, r.path...) })
			if _, err := DecodeFromSensorIn(b, schema); !refusedOnly(err, CodeForm, f) {
				t.Errorf("%s null: %v, want only form at %s", name, err, f)
			}
			if err := decodeRuleOff(b, schema, r.rec(schema)); !onlyTextKeysMissing(err, f) {
				t.Errorf("control, rule off, %s null: %v, want accepted", name, err)
			}
		}
	}
	if len(seen) != 34 {
		t.Errorf("%d rows of D4's list covered, want 34", len(seen))
	}
}

// onlyTextKeysMissing reports whether err is nil, or, for a Text at
// field read with the rule off, only the missing refusals of that Text's
// own keys (TestChannelRequiredKeysMissing): a null Text decodes as a Text
// with none of them, and nothing is refused at field itself.
func onlyTextKeysMissing(err error, field string) bool {
	if err == nil {
		return true
	}
	j, ok := err.(interface{ Unwrap() []error })
	if !ok {
		return false
	}
	for _, e := range j.Unwrap() {
		x, ok := e.(*Error)
		if !ok || x.Code != CodeMissing || !strings.HasPrefix(x.Field, field+".") {
			return false
		}
	}
	return true
}

// nullPaths lists every key and list element of a decoded document by its
// path, as setPath takes it.
func nullPaths(v any, at []any, out *[][]any) {
	switch x := v.(type) {
	case map[string]any:
		for k, e := range x {
			p := append(append([]any{}, at...), k)
			*out = append(*out, p)
			nullPaths(e, p, out)
		}
	case []any:
		for i, e := range x {
			p := append(append([]any{}, at...), i)
			*out = append(*out, p)
			nullPaths(e, p, out)
		}
	}
}

// No value on the 0.2 or 0.3 channel is null: every key and every list
// element of each record above, set to null one at a time, is refused.
// A sweep, beyond the 34 rows, so that a path no row names is covered.
// Every refusal but schema's and type's, which are read before the record
// has a type, has form at the null's own path as its first error, so the
// link counts it as form (D6's N1 on #735), and no path carries two form
// errors (N2).
func TestChannelNullRefusedEverywhere(t *testing.T) {
	recs := []func(string) any{hbRec}
	for _, f := range []func(string) *Observation{nullFunction, nullRepeat, nullModbus, nullModbus3, nullService, nullTelnet,
		nullHTTP, nullSNMPv3, nullTLS, nullIdentity, nullUndecoded} {
		recs = append(recs, obs(f))
	}
	recs = append(recs, func(s string) any { return fxEnd03("tcp") }, func(s string) any { return fxEnd03("udp") })
	for _, schema := range channelIdentifiers {
		for _, rec := range recs {
			if schema == Identifier02 {
				if o, ok := rec(schema).(*Observation); ok && o.Schema == Identifier03 {
					continue // fxEnd03 is 0.3 only
				}
			}
			var doc map[string]any
			if err := json.Unmarshal(mustJSON(t, rec(schema)), &doc); err != nil {
				t.Fatal(err)
			}
			var paths [][]any
			nullPaths(doc, nil, &paths)
			for _, p := range paths {
				b := encodeWith(t, rec(schema), func(m map[string]any) { setNull(m, p) })
				f := field(p)
				_, err := DecodeFromSensorIn(b, schema)
				switch {
				case err == nil:
					t.Errorf("%s, %T %s null: accepted", schema, rec(schema), f)
				case f == "schema" || f == "type":
				case !firstFormAt(err, f):
					t.Errorf("%s, %T %s null: %v, want form at %s first", schema, rec(schema), f, err, f)
				}
				if p := twoForms(err); p != "" {
					t.Errorf("%s, %T %s null: two form errors at %s: %v", schema, rec(schema), f, p, err)
				}
			}
		}
	}
}

// firstFormAt reports whether err's first error is form at field.
func firstFormAt(err error, field string) bool {
	var e *Error
	return errors.As(err, &e) && e.Code == CodeForm && e.Field == field
}

// twoForms is a path that carries two form errors in err, or "".
func twoForms(err error) string {
	j, ok := err.(interface{ Unwrap() []error })
	if !ok {
		return ""
	}
	seen := map[string]bool{}
	for _, e := range j.Unwrap() {
		if x, ok := e.(*Error); ok && x.Code == CodeForm {
			if seen[x.Field] {
				return x.Field
			}
			seen[x.Field] = true
		}
	}
	return ""
}

// setNull is setPath for a path that may end at a list element.
func setNull(m map[string]any, path []any) {
	if i, ok := path[len(path)-1].(int); ok {
		var cur any = m
		for _, p := range path[:len(path)-1] {
			switch k := p.(type) {
			case string:
				cur = cur.(map[string]any)[k]
			case int:
				cur = cur.([]any)[k]
			}
		}
		cur.([]any)[i] = nil
		return
	}
	setPath(m, nil, path...)
}

// The rule refuses null, not absence or an empty list: an optional field
// left out, and a list written [], still decode at both minors.
func TestChannelAbsentAndEmptyStillDecode(t *testing.T) {
	for _, schema := range channelIdentifiers {
		for _, c := range []struct {
			name string
			rec  any
			mut  func(m map[string]any)
		}{
			{"sub left out", nullModbus(schema), func(m map[string]any) { delete(m["function"].(map[string]any), "sub") }},
			{"sa left out", nullFunction(schema), func(m map[string]any) { delete(m["function"].(map[string]any), "sa") }},
			{"vlan left out", nullFunction(schema), func(m map[string]any) { delete(m["l2"].(map[string]any), "vlan") }},
			{"login left out", nullTelnet(schema), func(m map[string]any) { delete(m["insecure"].(map[string]any), "login") }},
			{"sni left out", nullTLS(schema), func(m map[string]any) {
				delete(m["encrypted"].(map[string]any)["tls"].(map[string]any), "sni")
			}},
			{"ring_oldest_utc left out", nullHeartbeat(schema), func(m map[string]any) { delete(m, "ring_oldest_utc") }},
			{"degraded []", nullFunction(schema), func(m map[string]any) { setPath(m, []any{}, "coverage", "degraded") }},
			{"prp.lans_seen []", nullFunction(schema), func(m map[string]any) {
				setPath(m, []any{}, "coverage", "prp", "lans_seen")
				delete(m["citation"].(map[string]any)["frames"].([]any)[0].(map[string]any), "lan")
				delete(m["citation"].(map[string]any)["frames"].([]any)[1].(map[string]any), "lan")
			}},
			{"objects []", nullFunction(schema), func(m map[string]any) { setPath(m, []any{}, "function", "objects") }},
			{"heartbeat degraded []", nullHeartbeat(schema), func(m map[string]any) { setPath(m, []any{}, "coverage", "degraded") }},
		} {
			b := encodeWith(t, c.rec, c.mut)
			if _, err := DecodeFromSensorIn(b, schema); err != nil {
				t.Errorf("%s, %s: %v", schema, c.name, err)
			}
		}
	}
}

// formAt reports whether err holds a form refusal at field.
func formAt(err error, field string) bool {
	if err == nil {
		return false
	}
	var errs []error
	if j, ok := err.(interface{ Unwrap() []error }); ok {
		errs = j.Unwrap()
	} else {
		errs = []error{err}
	}
	for _, e := range errs {
		if x, ok := e.(*Error); ok && x.Code == CodeForm && x.Field == field {
			return true
		}
	}
	return false
}

// D3's condition (2) on #732 (review 5937824561): a null list element,
// alone ([null]) or after a value ([v, null]), is refused as form at the
// element's path, at both minors. Control, with the rule off: an element
// of a list of numbers or objects has no form refusal at its path (a
// number reads as 0, an object as its zero value); an element of a list of
// text is refused as form at its path by its own check, as "", whether
// the rule is on or off (own).
func TestChannelNullListElements(t *testing.T) {
	iface := map[string]any{"name": "eth1", "carrier": "up", "packets": 1000}
	for _, schema := range channelIdentifiers {
		for _, c := range []struct {
			rec   any
			path  []any
			list  []any
			field string
			own   bool
		}{
			{nullFunction(schema), []any{"coverage", "vlans_seen"}, []any{nil}, "coverage.vlans_seen[0]", false},
			{nullFunction(schema), []any{"coverage", "vlans_seen"}, []any{1, nil}, "coverage.vlans_seen[1]", false},
			{nullHeartbeat(schema), []any{"coverage", "vlans_seen"}, []any{1, nil}, "coverage.vlans_seen[1]", false},
			{nullHeartbeat(schema), []any{"interfaces"}, []any{nil}, "interfaces[0]", false},
			{nullHeartbeat(schema), []any{"interfaces"}, []any{iface, nil}, "interfaces[1]", false},
			{nullRepeat(schema), []any{"citation", "frames", 1, "redactions"}, []any{nil}, "citation.frames[1].redactions[0]", false},
			{nullFunction(schema), []any{"coverage", "decodes"}, []any{nil}, "coverage.decodes[0]", true},
			{nullFunction(schema), []any{"coverage", "decodes"}, []any{"dnp3", nil}, "coverage.decodes[1]", true},
			{nullFunction(schema), []any{"function", "objects"}, []any{nil}, "function.objects[0]", true},
			{nullFunction(schema), []any{"function", "objects"}, []any{"g12v1", nil}, "function.objects[1]", true},
			{nullHeartbeat(schema), []any{"coverage", "degraded"}, []any{nil}, "coverage.degraded[0]", true},
		} {
			b := encodeWith(t, c.rec, func(m map[string]any) { setPath(m, c.list, c.path...) })
			if _, err := DecodeFromSensorIn(b, schema); !formAt(err, c.field) {
				t.Errorf("%s, %T %s: %v, want form at %s", schema, c.rec, field(c.path), err, c.field)
			}
			if err := decodeRuleOff(b, schema, c.rec); formAt(err, c.field) != c.own {
				t.Errorf("control, rule off, %s, %s: %v, want form there %v", schema, c.field, err, c.own)
			}
		}
	}
}

// D3's condition (1) on #732 and B1 on #735: a sensor-hello and a tick
// refuse every null, each key and each list element, at both minors, prior
// and its lists included, by the one rule: form at the null's own path,
// and nothing else, so the connection closes as hello or tick. schema and
// type are read before the strict decode, and refused there. Control:
// each as built decodes.
func TestHelloAndTickNullRefused(t *testing.T) {
	span := []Span{{FromUTC: "2026-11-07T09:00:00Z", ToUTC: "2026-11-07T09:30:00Z"}}
	for _, schema := range channelIdentifiers {
		h := fxSensorHello()
		h.Schema, h.Prior = schema, fxPrior()
		h.Prior.Lost = span
		k := fxTick()
		k.Schema, k.Lost = schema, span
		for _, rec := range []any{h, k} {
			if _, err := DecodeFromSensorIn(mustJSON(t, rec), schema); err != nil {
				t.Errorf("control, %s, %T as built: %v", schema, rec, err)
				continue
			}
			var doc map[string]any
			if err := json.Unmarshal(mustJSON(t, rec), &doc); err != nil {
				t.Fatal(err)
			}
			var paths [][]any
			nullPaths(doc, nil, &paths)
			for _, p := range paths {
				b := encodeWith(t, rec, func(m map[string]any) { setNull(m, p) })
				f := field(p)
				m, err := DecodeFromSensorIn(b, schema)
				switch {
				case err == nil:
					t.Errorf("%s, %T %s null: accepted", schema, rec, f)
				case f == "schema" || f == "type":
				case !refusedOnly(err, CodeForm, f):
					t.Errorf("%s, %T %s null: %v, want only form at %s", schema, rec, f, err, f)
				}
				want := TypeTick
				if _, ok := rec.(*SensorHello); ok {
					want = TypeSensorHello
				}
				if f != "type" && m.Type != want {
					t.Errorf("%s, %s null: type %q, so the connection would not close as its message", schema, f, m.Type)
				}
			}
		}
	}
}

// deletePath removes the key at path from a decoded document.
func deletePath(m map[string]any, path []any) {
	var cur any = m
	for _, p := range path[:len(path)-1] {
		switch k := p.(type) {
		case string:
			cur = cur.(map[string]any)[k]
		case int:
			cur = cur.([]any)[k]
		}
	}
	delete(cur.(map[string]any), path[len(path)-1].(string))
}

// as01 is o as a 0.1 channel record.
func as01(o *Observation) *Observation {
	cv := fxCoverage()
	cv.PRP.LANsSeen = o.Coverage.PRP.LANsSeen
	o.Schema, o.MadeUTC, o.Coverage = Identifier, "", cv
	return o
}

// D1's ruling on #735: a key that C13 marks required, and that a 0.2 or
// 0.3 channel record could leave out to be read as its Go zero value, is
// refused as missing at both minors. Required by C13 0.1's text: function
// code and objects (§4.3, no "?"), the SNMPv3 user and the identity value
// (§4.3, Text with no "?"), every key of a Text (§3.1, "refuses any other
// form"), and a redaction's offset (§3.2). Controls: each record with the
// key decodes (TestChannelNullRefusedAt34Paths), and the same record
// without it still decodes on the 0.1 channel, which this rule leaves as it
// was.
func TestChannelRequiredKeysMissing(t *testing.T) {
	for _, r := range []struct {
		path []any
		rec  func(string) *Observation
	}{
		{[]any{"function", "code"}, nullModbus3},
		{[]any{"function", "objects"}, nullFunction},
		{[]any{"function", "objects"}, nullModbus3},
		{[]any{"encrypted", "snmpv3", "user"}, nullSNMPv3},
		{[]any{"identity", "value"}, nullIdentity},
		{[]any{"citation", "frames", 1, "redactions", 0, "offset"}, nullRepeat},
		{[]any{"identity", "value", "truncated"}, nullIdentity},
		{[]any{"encrypted", "snmpv3", "user", "truncated"}, nullSNMPv3},
		{[]any{"encrypted", "tls", "sni", "truncated"}, nullTLS},
		{[]any{"service", "version", "truncated"}, nullService},
		{[]any{"insecure", "login", "user", "truncated"}, nullTelnet},
	} {
		f := field(r.path)
		for _, schema := range channelIdentifiers {
			b := encodeWith(t, r.rec(schema), func(m map[string]any) { deletePath(m, r.path) })
			if _, err := DecodeFromSensorIn(b, schema); !refusedOnly(err, CodeMissing, f) {
				t.Errorf("%s, %s left out: %v, want only missing at %s", schema, f, err, f)
			}
		}
		b := encodeWith(t, as01(r.rec(Identifier02)), func(m map[string]any) { deletePath(m, r.path) })
		if _, err := DecodeChannel(b); err != nil {
			t.Errorf("control, 0.1 channel, %s left out: %v", f, err)
		}
		// D6's N4 on #735: required does not reach a stored record of any
		// channel minor, which reads as it did.
		for _, schema := range channelIdentifiers {
			o := asStored(r.rec(schema))
			o.FirstSight, o.Frames = false, nil // a first sight's bytes are its capture, not the body
			if o.Function != nil {
				o.Node.FunctionClass, o.Node.FunctionTable = ClassOther, FunctionTable
			}
			b := encodeWith(t, o, func(m map[string]any) { deletePath(m, r.path) })
			if _, err := DecodeStored(b); err != nil {
				t.Errorf("control, stored %s, %s left out: %v", schema, f, err)
			}
		}
	}
	// A Text's value or length left out is refused as missing too. Each is
	// also refused by the value's own check, as the length no longer
	// matches, on every channel; so this leg checks the missing refusal,
	// not that it is the only one.
	for _, k := range []string{"value", "length"} {
		for _, schema := range channelIdentifiers {
			b := encodeWith(t, nullIdentity(schema), func(m map[string]any) { deletePath(m, []any{"identity", "value", k}) })
			if _, err := DecodeFromSensorIn(b, schema); !hasCode(err, CodeMissing) {
				t.Errorf("%s, identity.value.%s left out: %v, want missing", schema, k, err)
			}
		}
	}
}

// D6's N1 on #735: a heartbeat whose counters.packets is null, with its
// interface's packets not 0, is refused with form first, as on main, though
// the interface sum also fails; the link counts a record by its first code.
func TestHeartbeatNullCountFormFirst(t *testing.T) {
	for _, schema := range channelIdentifiers {
		h := nullHeartbeat(schema)
		if h.Interfaces[0].Packets == 0 {
			t.Fatal("the fixture's interface packets must not be 0")
		}
		b := encodeWith(t, h, func(m map[string]any) { setPath(m, nil, "counters", "packets") })
		_, err := DecodeFromSensorIn(b, schema)
		if cs := Codes(err); len(cs) < 2 || cs[0] != CodeForm || !firstFormAt(err, "counters.packets") {
			t.Errorf("%s: %v, want form at counters.packets first, and the sum's conflict after", schema, err)
		}
	}
}

// TestHeartbeatPerFieldFormAtNullMovedFirst covers the branch that moves a
// per-field form at a null path ahead of an earlier error (D6's N5 on #735):
// a heartbeat whose coverage carries VLAN 0 (range) and whose egress_check is
// null is counted form, not range. Control: without the move the codes come
// out [range form].
func TestHeartbeatPerFieldFormAtNullMovedFirst(t *testing.T) {
	for _, schema := range channelIdentifiers {
		h := nullHeartbeat(schema)
		b := encodeWith(t, h, func(m map[string]any) {
			setPath(m, []any{0}, "coverage", "vlans_seen")
			setPath(m, nil, "egress_check")
		})
		_, err := DecodeFromSensorIn(b, schema)
		if cs := Codes(err); len(cs) < 2 || cs[0] != CodeForm || !firstFormAt(err, "egress_check") {
			t.Errorf("%s: %v, want form at egress_check first, and the VLAN's range after", schema, err)
		}
	}
}
