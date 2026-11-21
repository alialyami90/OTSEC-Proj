package contract

// C4 otsec.event/0.6 (docs/phase4/D4-c4-0.6-proposal.md, approved at
// 5e7f0487 on #768, D4-121), row E6-4: every earlier reader accepts every
// 0.6 event, so 0.6's types need no reader floor (§4). Brief
// P4-4-C4-06-E64A. This file holds E6-4 (a), its strict leg and the pins
// for (c), committed in the C4 0.5 code before the 0.6 code lands, as
// E4-4 and E5-3 were.
//
// testdata/c4-v06 holds D6's 0.6 fixtures, one of each new type plus
// network-observation, SER, Syslog, sensor.counters, collection.run and
// netobs.alert. They are written from the proposal's text before any code
// writes minor 6, not from D4's code, which does not exist yet: so they
// test the text as D6 reads it, and a misreading would show only once the
// 0.6 code reads them at its own minor, strictly and with its closed
// detail sets.
//
//   - detector.observation-refused (§2.1) is the 15-detail form: stream,
//     since, through, netobs, unsure, count, and the three reasons each
//     with its first_seq and last_seq. Its netobs is C13's identifier at
//     5e7f0487, otsec.netobs/0.3, which the node takes from
//     netobs.SelfIdentifier() once that exists.
//   - detector.baseline-refused (§2.2): a hash, a stamp that parses with
//     the name netbaseline, and cause not-canonical.
//   - SER, Syslog, network-observation and netobs.alert are
//     testdata/cc-d0's 0.4 events with the C4 stamp 0.6, and with the two
//     C13 bodies stamped 0.3; 0.6 changes none of them (§1).
//   - sensor.counters is testdata/c4-v05's folded event with the stamp
//     0.6 (§1: unchanged).
//   - collection.run's details are node-defined (§3.3), so they are read
//     from platform/node (runRecord, sessionDetails) at 5e7f0487. C4
//     checks none of them.
//
// The legs (§6, E6-4):
//
//   - (a) TestC4v06E64aEarlierReaders: event.Decode accepts each fixture,
//     and the event re-encodes with no key lost, added or changed,
//     compared key by key with the fixture.
//   - The strict leg, TestC4v06E64aStrictLeg: the network-observation and
//     collection.run fixtures restamped to the reader's own minor, which
//     event.Decode reads strictly, are accepted. Its standing control: the
//     same with one key added to the envelope, at the top and nested, is
//     refused as decode. It tests the fixtures, not a 0.6 field (N12).
//   - The pins for (c), TestC4v06E64aFillPins: c4v6Fill sets every
//     exported field of event.Event, nested types included, and the key
//     paths of its network-observation and collection.run events must be
//     c4v6Pinned05, the set that fill gives in the 0.5 code (D6's N17).
//     From the 0.6 code on, the same comparison is (c)'s head leg. D6 owes
//     (c)'s run on the 0.6 code, with its control, after step 1
//     (P4-4-C4-06-S1).
//   - (b) A one-time desk run on the C4 0.3 code at 4bcffe88 and the C4 0.4
//     code at d48b2f0a, recorded below.
//
// (b), one-time legs (desk, Go 1.27.3 windows/amd64, 2026-11-21), each on
// the tree of `git archive <sha>`, with this file and testdata/c4-v06
// copied in:
//
//	4bcffe88, whose Identifier is otsec.event/0.3:
//	go test ./tests/contract/ -run TestC4v06E64 -count=1 -v
//	--- PASS: TestC4v06E64aEarlierReaders (0.00s)
//	--- PASS: TestC4v06E64aStrictLeg (0.00s)
//	--- PASS: TestC4v06E64aFillPins (0.00s)
//	PASS
//	ok  	otsec.local/otsec/tests/contract	0.351s
//
//	d48b2f0a, whose Identifier is otsec.event/0.4:
//	go test ./tests/contract/ -run TestC4v06E64 -count=1 -v
//	--- PASS: TestC4v06E64aEarlierReaders (0.00s)
//	--- PASS: TestC4v06E64aStrictLeg (0.00s)
//	--- PASS: TestC4v06E64aFillPins (0.00s)
//	PASS
//	ok  	otsec.local/otsec/tests/contract	0.315s
//
// In both runs every subtest passed: the eight fixtures of (a), and the
// two of the strict leg, restamped 0.3 and 0.4. The 0.3 reader accepts
// the 0.6 sensor.counters because it reads a later minor's details
// forward, as E5-3 recorded for 0.5. The pins leg passing on both trees
// means the fill's key paths are the same at 4bcffe88, d48b2f0a and
// 5e7f0487: a desk run, for envelope keys only.
//
// Controls (desk, Go 1.27.3 windows/amd64, on the 0.5 code at 5e7f0487;
// the diffs, commands and outputs are in the PR):
//
//   - The 0.5 reader patched to refuse a health type that is not one of
//     C4's Health* constants (checkPlatformEvent): (a) fails for the two
//     detector.* fixtures and collection.run. That would mean 0.6 needs a
//     reader floor.
//   - The network-observation fixture with one added envelope key: the
//     strict leg fails (decode), and so does (a) (the key is lost).
//   - A field added to event.Event, and in another run to event.Clock:
//     the pins leg fails, naming the new key path.
//
// Ground truth: GT-HAND, from the approved text. The SER row is D6's
// transcription of SEL-751 Figure 10.16 (testdata/cc-d0); every other
// value is constructed. None is device output. Evidence class: desk, and
// CI-Linux and CI-Windows for the leg on main.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/event"
)

const c4v6Dir = "testdata/c4-v06"

// c4v6Stamp is the fixtures' own C4 stamp (§1).
const c4v6Stamp = "otsec.event/0.6"

var c4v6Fixtures = []struct {
	file string
	kind event.Kind
	typ  string // health.type, on a telemetry-health event
}{
	{"event-0.6-detector-observation-refused.json", event.KindHealth, "detector.observation-refused"},
	{"event-0.6-detector-baseline-refused.json", event.KindHealth, "detector.baseline-refused"},
	{"event-0.6-network-observation.json", event.KindNetworkObservation, ""},
	{"event-0.6-ser.json", event.KindSER, ""},
	{"event-0.6-syslog.json", event.KindSyslog, ""},
	{"event-0.6-sensor-counters.json", event.KindHealth, event.HealthSensorCounters},
	{"event-0.6-collection-run.json", event.KindHealth, "collection.run"},
	{"event-0.6-netobs-alert.json", event.KindHealth, event.HealthNetobsAlert},
}

func c4v6Read(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(c4v6Dir, name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// c4v6Tree decodes JSON with each number kept as written, so that a seq
// or a count compares exactly.
func c4v6Tree(t *testing.T, b []byte) any {
	t.Helper()
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var v any
	if err := d.Decode(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

func c4v6Join(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}

// c4v6Diff lists, by key path, each key of want that got lost or changed,
// and each key that got added.
func c4v6Diff(path string, want, got any) []string {
	switch w := want.(type) {
	case map[string]any:
		g, ok := got.(map[string]any)
		if !ok {
			return []string{path + ": not an object"}
		}
		var out []string
		for k, wv := range w {
			if gv, ok := g[k]; ok {
				out = append(out, c4v6Diff(c4v6Join(path, k), wv, gv)...)
			} else {
				out = append(out, c4v6Join(path, k)+": lost")
			}
		}
		for k := range g {
			if _, ok := w[k]; !ok {
				out = append(out, c4v6Join(path, k)+": added")
			}
		}
		return out
	case []any:
		g, ok := got.([]any)
		if !ok || len(g) != len(w) {
			return []string{path + ": not the same array"}
		}
		var out []string
		for i := range w {
			out = append(out, c4v6Diff(fmt.Sprintf("%s[%d]", path, i), w[i], g[i])...)
		}
		return out
	}
	if want != got {
		return []string{fmt.Sprintf("%s: %v, re-encoded %v", path, want, got)}
	}
	return nil
}

func TestC4v06E64aEarlierReaders(t *testing.T) {
	for _, c := range c4v6Fixtures {
		t.Run(c.file, func(t *testing.T) {
			b := c4v6Read(t, c.file)
			e, err := event.Decode(b)
			if err != nil {
				t.Fatalf("the %s reader refuses the 0.6 event: %v", event.Identifier, err)
			}
			typ := ""
			if e.Health != nil {
				typ = e.Health.Type
			}
			if e.Schema != c4v6Stamp || e.Kind != c.kind || typ != c.typ || e.ID.Seq == 0 {
				t.Fatalf("schema %q, kind %q, health.type %q, seq %d: want a stored %s %s %s", e.Schema, e.Kind, typ, e.ID.Seq, c4v6Stamp, c.kind, c.typ)
			}
			if c.typ == "detector.observation-refused" {
				for _, k := range []string{"netobs", "unsure"} {
					if _, ok := e.Health.Details[k]; !ok {
						t.Errorf("the counts fixture lacks %s (E6-4)", k)
					}
				}
			}
			re, err := json.Marshal(e)
			if err != nil {
				t.Fatal(err)
			}
			for _, d := range c4v6Diff("", c4v6Tree(t, b), c4v6Tree(t, re)) {
				t.Errorf("re-encoded by the %s reader: %s", event.Identifier, d)
			}
		})
	}
}

func TestC4v06E64aStrictLeg(t *testing.T) {
	for _, c := range []struct {
		file   string
		nested []string // envelope objects the control adds a key to
	}{
		{"event-0.6-network-observation.json", []string{"source.asset.binding", "received.clock"}},
		{"event-0.6-collection-run.json", []string{"source", "received.clock"}},
	} {
		t.Run(c.file, func(t *testing.T) {
			// restamp gives the fixture at the reader's own minor, with
			// d6_added in the object at path when path is not "-".
			restamp := func(path string) []byte {
				m := c4v6Tree(t, c4v6Read(t, c.file)).(map[string]any)
				m["schema"] = event.Identifier
				if path != "-" {
					obj := m
					if path != "" {
						for _, p := range strings.Split(path, ".") {
							obj = obj[p].(map[string]any)
						}
					}
					obj["d6_added"] = "x"
				}
				b, err := json.Marshal(m)
				if err != nil {
					t.Fatal(err)
				}
				return b
			}
			e, err := event.Decode(restamp("-"))
			if err != nil {
				t.Fatalf("restamped %s, read strictly: %v", event.Identifier, err)
			}
			if e.Schema != event.Identifier {
				t.Fatalf("schema %q", e.Schema)
			}
			for _, p := range append([]string{""}, c.nested...) {
				if _, err := event.Decode(restamp(p)); !slices.Equal(event.Codes(err), []event.Code{event.CodeDecode}) {
					t.Errorf("restamped %s with a key added at %q: %v, want only %s: the read is not strict", event.Identifier, p, err, event.CodeDecode)
				}
			}
		})
	}
}

// c4v6Pinned05 is the key-path set of c4v6Fill's events in the C4 0.5 code
// (event.Identifier otsec.event/0.5, at 5e7f0487), the same for both
// events because the fill sets every field whatever the kind. A key inside
// netobs (a json.RawMessage) or health.details (a map) is open, not an
// envelope field, so the paths stop there (§1, "no flag" stays desk).
var c4v6Pinned05 = []string{
	"collection", "collection.alignment", "collection.invocation_id", "collection.method", "collection.native_position",
	"collection.operation_id", "collection.parse_status", "collection.parser", "collection.parser.name", "collection.parser.version",
	"device_time", "device_time.accuracy_ns", "device_time.flags", "device_time.format", "device_time.native",
	"device_time.native_encoding", "device_time.offset", "device_time.offset_basis", "device_time.quality",
	"device_time.quality.accuracy_relative_ns", "device_time.quality.clock_failure", "device_time.quality.leap_seconds_known",
	"device_time.quality.scope", "device_time.quality.sync", "device_time.quality.time_source", "device_time.resolution_ns",
	"device_time.utc", "device_time.wall_clock",
	"flags",
	"health", "health.details", "health.related", "health.related[].node_id", "health.related[].seq", "health.related[].stream",
	"health.type",
	"id", "id.node_id", "id.seq", "id.stream",
	"kind",
	"native", "native.alignment_key", "native.bytes", "native.context_span", "native.context_span.length",
	"native.context_span.offset", "native.evidence", "native.evidence.length", "native.evidence.ref", "native.evidence.sha256",
	"native.fields", "native.fields[].name", "native.fields[].value", "native.record_length", "native.record_sha256",
	"native.span", "native.span.length", "native.span.offset",
	"netobs",
	"normalized", "normalized.category", "normalized.mapping", "normalized.mapping.table", "normalized.mapping.version",
	"normalized.subject", "normalized.subject_type", "normalized.value",
	"origin",
	"received", "received.clock", "received.clock.source", "received.clock.sync", "received.resolution_ns", "received.utc",
	"schema",
	"source", "source.asset", "source.asset.binding", "source.asset.binding.confidence", "source.asset.binding.method",
	"source.asset.id", "source.evidence_class", "source.origin_auth", "source.sender", "source.sender.address",
	"source.sender.asset_id", "source.sender.tls_leaf_sha256",
}

// c4v6Raw is the type of event.Event's netobs, which must hold JSON.
var c4v6Raw = reflect.TypeOf(json.RawMessage(nil))

// c4v6Fill returns an event with every exported field of event.Event set,
// so that a field a later minor adds to it, or to a type under it, is set
// and marshalled. A field of a kind the fill does not set fails the test.
func c4v6Fill(t *testing.T, kind event.Kind, typ string) *event.Event {
	t.Helper()
	var e event.Event
	c4v6FillValue(t, "Event", reflect.ValueOf(&e).Elem())
	e.Kind = kind
	if typ != "" {
		e.Health.Type = typ
	}
	return &e
}

func c4v6FillValue(t *testing.T, path string, v reflect.Value) {
	t.Helper()
	if v.Type() == c4v6Raw {
		v.SetBytes([]byte(`{"x":"x"}`))
		return
	}
	switch v.Kind() {
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if f := v.Type().Field(i); f.IsExported() {
				c4v6FillValue(t, path+"."+f.Name, v.Field(i))
			}
		}
	case reflect.Pointer:
		v.Set(reflect.New(v.Type().Elem()))
		c4v6FillValue(t, path, v.Elem())
	case reflect.Slice:
		v.Set(reflect.MakeSlice(v.Type(), 1, 1))
		c4v6FillValue(t, path+"[]", v.Index(0))
	case reflect.Map:
		k, x := reflect.New(v.Type().Key()).Elem(), reflect.New(v.Type().Elem()).Elem()
		c4v6FillValue(t, path+"{key}", k)
		c4v6FillValue(t, path+"{}", x)
		v.Set(reflect.MakeMap(v.Type()))
		v.SetMapIndex(k, x)
	case reflect.String:
		v.SetString("x")
	case reflect.Bool:
		v.SetBool(true)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		v.SetInt(1)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		v.SetUint(1)
	default:
		t.Fatalf("%s: the fill sets no %s; extend it before reading the pins", path, v.Kind())
	}
}

// c4v6Paths returns the sorted key paths of the JSON object b, with "[]"
// for an array's elements, stopping at netobs and health.details.
func c4v6Paths(t *testing.T, b []byte) []string {
	t.Helper()
	var out []string
	var walk func(path string, v any)
	walk = func(path string, v any) {
		switch x := v.(type) {
		case map[string]any:
			if path == "netobs" || path == "health.details" {
				return
			}
			for k, y := range x {
				p := c4v6Join(path, k)
				out = append(out, p)
				walk(p, y)
			}
		case []any:
			for _, y := range x {
				walk(path+"[]", y)
			}
		}
	}
	walk("", c4v6Tree(t, b))
	slices.Sort(out)
	return slices.Compact(out)
}

func TestC4v06E64aFillPins(t *testing.T) {
	for _, c := range []struct {
		kind event.Kind
		typ  string
	}{
		{event.KindNetworkObservation, ""},
		{event.KindHealth, "collection.run"},
	} {
		b, err := json.Marshal(c4v6Fill(t, c.kind, c.typ))
		if err != nil {
			t.Fatal(err)
		}
		got := c4v6Paths(t, b)
		var added, gone []string
		for _, p := range got {
			if !slices.Contains(c4v6Pinned05, p) {
				added = append(added, p)
			}
		}
		for _, p := range c4v6Pinned05 {
			if !slices.Contains(got, p) {
				gone = append(gone, p)
			}
		}
		if len(added) > 0 || len(gone) > 0 {
			t.Errorf("%s %q in the %s code: key paths not in the 0.5 pins %q, pinned paths missing %q", c.kind, c.typ, event.Identifier, added, gone)
		}
	}
}
