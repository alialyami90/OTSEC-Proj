package event

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/internal/strictjson"
)

// serFixture is a byte-exact copy of A2's documented-example transcription
// of SEL-751 Figure 10.16 (a2Fixture; provenance in its SOURCE.md). The copy
// is marked -text so that no checkout converts its line endings.
const (
	serFixture = "testdata/sel751-fig10-16.txt"
	a2Fixture  = "../../tests/fixtures/ied/sel/751/documented-example/ser-report-fig10-16.txt"
)

// The copy must be A2's file. A2's file has no -text attribute, so a Windows
// checkout may have turned its LF into CRLF; that conversion, and only that,
// is undone before comparing.
func TestFixtureCopyIsA2Transcription(t *testing.T) {
	ours, err := os.ReadFile(serFixture)
	if err != nil {
		t.Fatal(err)
	}
	theirs, err := os.ReadFile(a2Fixture)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ours, []byte("\r")) {
		t.Fatal("the evidence copy gained CR bytes: check testdata/.gitattributes")
	}
	if !bytes.Equal(ours, bytes.ReplaceAll(theirs, []byte("\r\n"), []byte("\n"))) {
		t.Fatal("testdata/sel751-fig10-16.txt differs from A2's fixture")
	}
}

func load(t *testing.T, path string) *Event {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields() // golden files must not carry typos the reader would ignore
	var e Event
	if err := dec.Decode(&e); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return &e
}

func TestValidExamples(t *testing.T) {
	files, _ := filepath.Glob("testdata/valid/*.json")
	if len(files) < 10 {
		t.Fatalf("expected the golden examples, found %d", len(files))
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Decode(b); err != nil {
			t.Errorf("%s: %v", f, err)
		}
	}
}

// Every (collection method, origin_auth) pair outside AllowedOriginAuth is
// rejected, and every pair inside it is accepted (A6 C4 review item 5, rated
// by A3 in C4-A3.md).
func TestOriginAuthPairs(t *testing.T) {
	methods := []CollectionMethod{MethodAdapterPoll, MethodSyslogReceive, MethodHostPush}
	auths := []OriginAuth{AuthNone, AuthTLSServerOnly, AuthTLSMutual, AuthSession, AuthPlatform}
	for _, m := range methods {
		for _, a := range auths {
			e := load(t, "testdata/valid/sel751-fig10-16-row8.json")
			e.Collection.Method = m
			e.Source.OriginAuth = a
			allowed := slices.Contains(AllowedOriginAuth[m], a)
			rejected := slices.Contains(Codes(e.Validate()), CodeEnum)
			if allowed == rejected {
				t.Errorf("%s with %s: allowed %v, rejected %v", m, a, allowed, rejected)
			}
		}
	}
	if !reflect.DeepEqual(AllowedOriginAuth[MethodAdapterPoll], []OriginAuth{AuthSession}) {
		t.Error("adapter-poll must allow session only: its link strength is C1 downstream_security")
	}
}

// Decode reads every event the same way (A1 D1-9, A6 C4 review item 6).
func TestDecode(t *testing.T) {
	b, err := os.ReadFile("testdata/valid/sel751-fig10-16-row8.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	insert := func(raw []byte, after, text string) []byte {
		i := bytes.Index(raw, []byte(after))
		if i < 0 {
			t.Fatalf("%q not in example", after)
		}
		i += len(after)
		return append(append(append([]byte{}, raw[:i]...), text...), raw[i:]...)
	}
	rejected := map[string][]byte{
		"case-variant duplicate":     insert(b, `"origin": "device",`, ` "ORIGIN": "platform",`),
		"exact duplicate":            insert(b, `"origin": "device",`, ` "origin": "platform",`),
		"nested duplicate":           insert(b, `"seq": 1`, `, "seq": 2`),
		"case-variant key alone":     bytes.Replace(b, []byte(`"origin": "device"`), []byte(`"Origin": "device"`), 1),
		"unknown field at 0.1":       insert(b, `"kind": "ser",`, ` "severity": "high",`),
		"field of another object":    insert(b, `"kind": "ser",`, ` "seq": 5,`),
		"trailing data":              append(append([]byte{}, b...), []byte(" {}")...),
		"not an object":              []byte(`[]`),
		"later minor, duplicate key": insert(bytes.Replace(b, []byte(`"otsec.event/0.1"`), []byte(`"otsec.event/0.9"`), 1), `"kind": "ser",`, ` "severity": "a", "severity": "b",`),
	}
	for name, doc := range rejected {
		if _, err := Decode(doc); !slices.Contains(Codes(err), CodeDecode) {
			t.Errorf("%s: got %v, want %s", name, err, CodeDecode)
		}
	}
	accepted := map[string][]byte{
		"later minor, new field": insert(bytes.Replace(b, []byte(`"otsec.event/0.1"`), []byte(`"otsec.event/0.9"`), 1), `"kind": "ser",`, ` "severity": {"level": "high"},`),
	}
	for name, doc := range accepted {
		if _, err := Decode(doc); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	// health.details keys are map keys, not field names: one that equals a
	// field name of Health is not a duplicate or a case variant.
	g, err := os.ReadFile("testdata/valid/health-ser-gap.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(insert(g, `"details": {`, ` "related": "x", "type": "y",`)); err != nil {
		t.Errorf("details key named like a field: %v", err)
	}
	_ = doc
}

// Each invalid example and the code it must produce. testdata/NOTES.md says
// what each shows.
var invalid = map[string]Code{
	"precision-overclaim":                CodePrecision,
	"received-precision-overclaim":       CodePrecision,
	"utc-with-unknown-offset":            CodeOffset,
	"utc-inconsistent":                   CodeOffset,
	"known-offset-without-basis":         CodeOffset,
	"bytes-tampered":                     CodeEvidence,
	"span-outside-evidence":              CodeEvidence,
	"seq-zero":                           CodeID,
	"node-id-uppercase":                  CodeID,
	"stream-with-colon":                  CodeID,
	"category-without-mapping":           CodeUnjustifiedMeaning,
	"failed-parse-with-normalized":       CodeForbidden,
	"missing-native":                     CodeMissing,
	"received-without-z":                 CodeTimeFormat,
	"other-major":                        CodeSchema,
	"device-event-platform-auth":         CodeEnum,
	"content-field-configured":           CodeEnum,
	"no-asset-no-flag":                   CodeMissing,
	"platform-event-with-native":         CodeForbidden,
	"closed-enum-unknown":                CodeEnum,
	"adapter-poll-without-invocation":    CodeMissing,
	"context-span-outside-evidence":      CodeEvidence,
	"evidence-ref-mismatch":              CodeEvidence,
	"origin-auth-mismatch":               CodeEnum,
	"wall-clock-missing":                 CodeMissing,
	"leap-second-with-utc":               CodeOffset,
	"evidence-class-missing":             CodeMissing,
	"evidence-class-not-observed":        CodeEnum,
	"platform-event-with-evidence-class": CodeForbidden,
	"tls-leaf-at-0.1":                    CodeForbidden,
	"tls-leaf-without-mutual":            CodeForbidden,
	"tls-leaf-not-hex":                   CodeEvidence,
	"tls-mutual-without-leaf":            CodeMissing,
	// C4 0.3 (C13 observations).
	"network-observation-without-netobs":      CodeMissing,
	"netobs-on-other-kind":                    CodeForbidden,
	"netobs-at-0.2":                           CodeForbidden,
	"netobs-not-object":                       CodeEnum,
	"network-observation-from-device":         CodeEnum,
	"network-observation-with-evidence-class": CodeForbidden,
	"network-observation-no-asset-no-flag":    CodeMissing,
	// D4-71: observed-address.
	"network-observation-sender-address": CodeEnum,
	"observed-address-configured":        CodeEnum,
	"netobs-alert-sender-address":        CodeEnum,
	"netobs-alert-configured":            CodeEnum,
	"observed-address-at-0.2":            CodeForbidden,
	"observed-address-on-syslog":         CodeForbidden,
}

func TestInvalidExamples(t *testing.T) {
	files, _ := filepath.Glob("testdata/invalid/*.json")
	if len(files) != len(invalid) {
		t.Fatalf("%d invalid files, %d expectations", len(files), len(invalid))
	}
	for _, f := range files {
		name := strings.TrimSuffix(filepath.Base(f), ".json")
		want, ok := invalid[name]
		if !ok {
			t.Errorf("%s: no expectation", f)
			continue
		}
		err := load(t, f).Validate()
		if err == nil {
			t.Errorf("%s: accepted, want %s", name, want)
			continue
		}
		if got := Codes(err); !slices.Contains(got, want) {
			t.Errorf("%s: codes %v, want %s (%v)", name, got, want, err)
		}
	}
}

// Acceptance: every native SER example round-trips to C4 and back to
// identical native bytes, and those bytes are exactly the record inside the
// documented report.
func TestSERRoundTrip(t *testing.T) {
	report, err := os.ReadFile(serFixture)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(report)
	files, _ := filepath.Glob("testdata/valid/sel751-fig10-16-row*.json")
	if len(files) != 8 {
		t.Fatalf("want the 8 rows of Figure 10.16, found %d", len(files))
	}
	var lines [][]byte
	for _, l := range bytes.Split(report, []byte("\n")) {
		if len(l) > 0 && l[0] >= '1' && l[0] <= '8' {
			lines = append(lines, l)
		}
	}
	seen := map[string]bool{}
	for _, f := range files {
		e := load(t, f)
		if e.Native.Evidence.SHA256 != hex.EncodeToString(sum[:]) || e.Native.Evidence.Length != int64(len(report)) {
			t.Fatalf("%s: evidence does not identify the fixture", f)
		}
		span := report[e.Native.Span.Offset : e.Native.Span.Offset+e.Native.Span.Length]
		if !bytes.Equal(span, e.Native.Bytes) {
			t.Fatalf("%s: bytes differ from the fixture at the span", f)
		}
		wire, err := json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		var back Event
		if err := json.Unmarshal(wire, &back); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(back.Native.Bytes, span) || back.Validate() != nil {
			t.Fatalf("%s: native bytes did not survive a C4 round trip", f)
		}
		if !reflect.DeepEqual(&back, e) {
			t.Fatalf("%s: event changed in a round trip", f)
		}
		seen[string(span)] = true
	}
	for _, l := range lines {
		if !seen[string(l)] {
			t.Fatalf("row %q of the figure has no event", l)
		}
	}
}

// Acceptance: a time that claims more precision than its resolution is
// rejected, for every rendered time field.
func TestPrecision(t *testing.T) {
	cases := []struct {
		frac string
		res  int64
		ok   bool
	}{
		{"", 1_000_000_000, true},
		{".6", 100_000_000, true},
		{".602", 1_000_000, true},
		{".602", 1_000_000_000, false},
		{".602", 10_000_000, false},
		{".6020", 1_000_000, false}, // padding is a claim too
		{".514", 59_605, true},      // IEC 61850 UtcTime: 2^-24 s rounds to ms here
		{".513999998", 59_605, false},
		{".123456789", 1, true},
	}
	for _, c := range cases {
		e := load(t, "testdata/valid/sel751-fig10-16-row8.json")
		e.DeviceTime.WallClock = "2007-02-28T13:54:09" + c.frac
		e.DeviceTime.ResolutionNS = c.res
		err := e.Validate()
		if c.ok != (err == nil) {
			t.Errorf("fraction %q at %d ns: err=%v, want ok=%v", c.frac, c.res, err, c.ok)
		}
		if !c.ok && !slices.Contains(Codes(err), CodePrecision) {
			t.Errorf("fraction %q: codes %v, want precision", c.frac, Codes(err))
		}
	}
}

func TestEventID(t *testing.T) {
	id := EventID{NodeID: "site-a-node1", Stream: "sel751-feeder1/ser", Seq: 42}
	if id.String() != "site-a-node1:sel751-feeder1/ser:42" {
		t.Fatal(id.String())
	}
	back, err := ParseEventID(id.String())
	if err != nil || back != id {
		t.Fatalf("%v %v", back, err)
	}
	for _, bad := range []string{"", "a:b", "a:b:0", "a:b:01", "A:b:1", "a:B:1", "a:b:c:1", "a:b:-1", "-a:b:1", "a:b:18446744073709551616"} {
		if _, err := ParseEventID(bad); err == nil {
			t.Errorf("ParseEventID(%q) accepted", bad)
		}
	}
	long := NodeID(strings.Repeat("a", 64))
	if long.Valid() || !NodeID(strings.Repeat("a", 63)).Valid() {
		t.Error("node ID length limit is 63")
	}
}

// A producer validates before the store assigns seq (C5): seq 0 is the only
// pending value, and a stored event must have a real one.
func TestValidatePending(t *testing.T) {
	e := load(t, "testdata/valid/sel751-fig10-16-row8.json")
	e.ID.Seq = 0
	if err := e.ValidatePending(); err != nil {
		t.Fatalf("pending event with seq 0: %v", err)
	}
	if !slices.Contains(Codes(e.Validate()), CodeID) {
		t.Fatal("Validate accepted seq 0")
	}
	e.ID.Seq = 1
	if !slices.Contains(Codes(e.ValidatePending()), CodeID) {
		t.Fatal("ValidatePending accepted a producer-chosen seq")
	}
	e.ID.Seq = 0
	e.Native.Evidence.Ref = "sha256:" + strings.Repeat("0", 64)
	if !slices.Contains(Codes(e.ValidatePending()), CodeEvidence) {
		t.Fatal("ValidatePending skipped a rule other than seq")
	}
}

func TestCodesOnJoin(t *testing.T) {
	e := load(t, "testdata/valid/sel751-fig10-16-row8.json")
	e.ID.Seq = 0
	e.Schema = "otsec.audit/0.1"
	got := Codes(e.Validate())
	sort.Slice(got, func(i, j int) bool { return got[i] < got[j] })
	if !reflect.DeepEqual(got, []Code{CodeID, CodeSchema}) {
		t.Fatal(got)
	}
}

func TestReaderAcceptsLaterMinorAndUnknownFields(t *testing.T) {
	b, _ := os.ReadFile("testdata/valid/sel751-fig10-16-row8.json")
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	m["schema"] = "otsec.event/0.7"
	m["future_field"] = map[string]any{"x": 1}
	m["kind"] = "ser"
	b, _ = json.Marshal(m)
	var e Event
	if err := json.Unmarshal(b, &e); err != nil {
		t.Fatal(err)
	}
	if err := e.Validate(); err != nil {
		t.Fatalf("a 0.x reader must accept a later minor with unknown fields: %v", err)
	}
	e.Kind = "a-kind-from-0.7"
	if err := e.Validate(); err != nil {
		t.Fatalf("kind is an open set: %v", err)
	}
}

// A6 C4 re-check S-2 and S-3: a leap second is 23:59:60 in UTC, so on a
// known offset it is checked after the offset is applied; and invalid-time
// means there is no wall clock to give.
func TestDeviceTimeLeapSecondAndInvalidTime(t *testing.T) {
	for _, c := range []struct {
		wall, offset string
		ok           bool
	}{
		{"2016-12-31T15:59:60.602", "-08:00", true},
		{"2016-12-31T23:59:60.602", "+00:00", true},
		{"2017-01-01T05:29:60.602", "+05:30", true},
		{"2016-12-31T23:59:60.602", "-08:00", false},
		{"2016-12-31T15:59:60.602", "+00:00", false},
		// With the offset unknown, the minute cannot be tied to UTC.
		{"2016-12-31T15:59:60.602", "unknown", true},
	} {
		e := load(t, "testdata/valid/constructed-leap-second.json")
		e.DeviceTime.WallClock, e.DeviceTime.Offset = c.wall, c.offset
		if c.offset != "unknown" {
			e.DeviceTime.OffsetBasis = BasisDeviceSetting
		}
		err := e.Validate()
		if c.ok && err != nil {
			t.Errorf("%s at %s: %v", c.wall, c.offset, err)
		}
		if !c.ok && !slices.Contains(Codes(err), CodeTimeFormat) {
			t.Errorf("%s at %s: got %v, want %s", c.wall, c.offset, err, CodeTimeFormat)
		}
	}

	e := load(t, "testdata/valid/constructed-invalid-date.json")
	e.DeviceTime.WallClock = "2007-03-02T13:54:09.602"
	if !slices.Contains(Codes(e.Validate()), CodeForbidden) {
		t.Fatal("invalid-time with a wall_clock validated")
	}
}

// C6-A6-2: a health detail key never contains '=', so C6's hd="key=value"
// splits back one way only.
func TestHealthDetailKeys(t *testing.T) {
	for key, ok := range map[string]bool{"skipped_from": true, "reason": true, "a=b": false, "Reason": false, "": false, "a b": false} {
		e := load(t, "testdata/valid/health-ser-gap.json")
		e.Health.Details = map[string]string{key: "c"}
		if got := !slices.Contains(Codes(e.Validate()), CodeEnum); got != ok {
			t.Errorf("detail key %q: accepted %v, want %v", key, got, ok)
		}
	}
}

// D1-23: only device-observed is a claim that the far end was a device.
func TestSimulated(t *testing.T) {
	for _, c := range []struct {
		class asset.EvidenceClass
		want  bool
	}{
		{asset.DeviceObserved, false},
		{asset.Simulated, true},
		{"", true},
		{"a-class-from-0.7", true},
	} {
		if got := (Source{EvidenceClass: c.class}).Simulated(); got != c.want {
			t.Errorf("Simulated() with %q = %v, want %v", c.class, got, c.want)
		}
	}
	e := load(t, "testdata/valid/sel751-fig10-16-row1.json")
	e.Source.EvidenceClass = asset.DeviceObserved
	if err := e.Validate(); err != nil {
		t.Fatalf("device-observed refused: %v", err)
	}
	// The enum is open to later minors (A6 D1-23 review change 1): a later
	// minor's class is kept and read as simulated; an event of this
	// reader's minor or earlier takes only the two, at 0.1 and, as each
	// minor moves the boundary, up to this reader's minor, now 0.3 (A6).
	e.Source.EvidenceClass = "lab-replay"
	for _, schema := range []string{"otsec.event/0.1", "otsec.event/0.2", "otsec.event/0.3"} {
		e.Schema = schema
		if !slices.Contains(Codes(e.Validate()), CodeEnum) {
			t.Errorf("%s event with an unknown class validated", schema)
		}
	}
	e.Schema = "otsec.event/0.4"
	if err := e.Validate(); err != nil || !e.Source.Simulated() {
		t.Errorf("0.4 event with an unknown class: err=%v simulated=%v", err, e.Source.Simulated())
	}
	e.Source.EvidenceClass = "Not A Token"
	if !slices.Contains(Codes(e.Validate()), CodeEnum) {
		t.Error("0.4 event with a malformed class validated")
	}
}

// C4 0.3: netobs at exactly MaxNetobsBytes passes, and one byte more is
// refused (D6).
func TestNetobsBound(t *testing.T) {
	e := load(t, "testdata/valid/constructed-network-observation.json")
	body := func(n int) json.RawMessage {
		const head, tail = `{"pad":"`, `"}`
		return json.RawMessage(head + strings.Repeat("x", n-len(head)-len(tail)) + tail)
	}
	e.Netobs = body(MaxNetobsBytes)
	if err := e.Validate(); err != nil {
		t.Fatalf("netobs at MaxNetobsBytes refused: %v", err)
	}
	e.Netobs = body(MaxNetobsBytes + 1)
	if !slices.Contains(Codes(e.Validate()), CodeForbidden) {
		t.Fatal("netobs one byte over MaxNetobsBytes validated")
	}
}

// D4-71 (B2): a netobs.alert binds its asset by observed-address and
// inferred, and by nothing else. Every other method and every other
// confidence is refused, so an alert's resolution never reads upstream as
// configured or as the asset's own sending.
func TestNetobsAlertBinding(t *testing.T) {
	e := load(t, "testdata/valid/health-netobs-alert.json")
	if e.Health.Type != HealthNetobsAlert || e.Source.Asset.Binding != (Binding{BindObservedAddress, ConfidenceInferred}) {
		t.Fatalf("fixture is not an observed-address/inferred netobs.alert: %+v %+v", e.Health, e.Source.Asset)
	}
	if err := e.Validate(); err != nil {
		t.Fatalf("observed-address/inferred alert refused: %v", err)
	}
	for _, m := range []BindingMethod{BindAdapterTarget, BindSenderAddress, BindContentField, BindOperator} {
		for _, cf := range []BindingConfidence{ConfidenceConfigured, ConfidenceAsserted, ConfidenceInferred} {
			e.Source.Asset.Binding = Binding{m, cf}
			if err := e.Validate(); !slices.Contains(Codes(err), CodeEnum) {
				t.Errorf("alert bound %s/%s: %v, want enum", m, cf, err)
			}
		}
	}
	for _, cf := range []BindingConfidence{ConfidenceConfigured, ConfidenceAsserted} {
		e.Source.Asset.Binding = Binding{BindObservedAddress, cf}
		if err := e.Validate(); !slices.Contains(Codes(err), CodeEnum) {
			t.Errorf("alert bound observed-address/%s: %v, want enum", cf, err)
		}
	}
}

// event02 is Event as C4 0.2 declared it: no Netobs field.
type event02 struct {
	Schema     string      `json:"schema"`
	ID         EventID     `json:"id"`
	Origin     Origin      `json:"origin"`
	Kind       Kind        `json:"kind"`
	Source     Source      `json:"source"`
	Collection *Collection `json:"collection,omitempty"`
	Received   Received    `json:"received"`
	DeviceTime *DeviceTime `json:"device_time,omitempty"`
	Native     *Native     `json:"native,omitempty"`
	Normalized *Normalized `json:"normalized,omitempty"`
	Health     *Health     `json:"health,omitempty"`
	Flags      []string    `json:"flags,omitempty"`
}

// A 0.2 reader reads a 0.3 observation with strictjson.Forward, as Decode
// does for a later minor: it keeps the kind and drops netobs without error.
func TestReader02KeepsObservationKind(t *testing.T) {
	b, err := os.ReadFile("testdata/valid/constructed-network-observation.json")
	if err != nil {
		t.Fatal(err)
	}
	var e event02
	if err := strictjson.Forward(b, &e); err != nil {
		t.Fatalf("0.2 reader refused a 0.3 observation: %v", err)
	}
	if e.Kind != KindNetworkObservation {
		t.Fatalf("kind %q, want %q", e.Kind, KindNetworkObservation)
	}
}

// D4-72: sensor.counters carries the sensor's own counter differences,
// never totals, and is new in 0.3.
func TestSensorCounters(t *testing.T) {
	fresh := func() *Event { return load(t, "testdata/valid/health-sensor-counters.json") }
	if err := fresh().Validate(); err != nil {
		t.Fatalf("valid sensor.counters refused: %v", err)
	}
	cases := []struct {
		name string
		code Code
		mut  func(e *Event)
	}{
		{"at 0.2", CodeForbidden, func(e *Event) { e.Schema = "otsec.event/0.2" }},
		{"not reported by the sensor", CodeEnum, func(e *Event) { e.Health.Details["reported_by"] = "node" }},
		{"no reported_by", CodeEnum, func(e *Event) { delete(e.Health.Details, "reported_by") }},
		{"no sensor", CodeMissing, func(e *Event) { delete(e.Health.Details, "sensor_id") }},
		{"no run", CodeMissing, func(e *Event) { e.Health.Details["run_id"] = "run-1" }},
		{"a total", CodeForbidden, func(e *Event) { e.Health.Details["packets"] = "48211" }},
		{"a total, named so", CodeForbidden, func(e *Event) { e.Health.Details["total.packets"] = "48211" }},
		{"a negative difference", CodeEnum, func(e *Event) { e.Health.Details["diff.packets"] = "-1" }},
		{"a padded difference", CodeEnum, func(e *Event) { e.Health.Details["diff.packets"] = "012" }},
		{"an unknown counter", CodeEnum, func(e *Event) { e.Health.Details["diff.frames"] = "1" }},
		{"an unknown detail", CodeEnum, func(e *Event) { e.Health.Details["note"] = "x" }},
		{"no difference", CodeMissing, func(e *Event) {
			for k := range e.Health.Details {
				if strings.HasPrefix(k, "diff.") {
					delete(e.Health.Details, k)
				}
			}
		}},
	}
	for _, tc := range cases {
		e := fresh()
		tc.mut(e)
		if got := Codes(e.Validate()); !slices.Contains(got, tc.code) {
			t.Errorf("%s: got %v, want %s", tc.name, got, tc.code)
		}
	}
	// Every counter of C13 §6 is accepted as a difference, and a later
	// minor may add details.
	e := fresh()
	for _, n := range SensorCounters {
		e.Health.Details["diff."+n] = "18446744073709551615"
	}
	if err := e.Validate(); err != nil {
		t.Errorf("every counter: %v", err)
	}
	e = fresh()
	e.Schema, e.Health.Details["since_utc"] = "otsec.event/0.4", "2026-10-24T12:05:00Z"
	if err := e.Validate(); slices.Contains(Codes(err), CodeEnum) {
		t.Errorf("a later minor's detail: %v", err)
	}
}
