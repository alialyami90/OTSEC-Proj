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
		if err := load(t, f).Validate(); err != nil {
			t.Errorf("%s: %v", f, err)
		}
	}
}

// Each invalid example and the code it must produce. testdata/NOTES.md says
// what each shows.
var invalid = map[string]Code{
	"precision-overclaim":          CodePrecision,
	"received-precision-overclaim": CodePrecision,
	"utc-with-unknown-offset":      CodeOffset,
	"utc-inconsistent":             CodeOffset,
	"known-offset-without-basis":   CodeOffset,
	"bytes-tampered":               CodeEvidence,
	"span-outside-evidence":        CodeEvidence,
	"seq-zero":                     CodeID,
	"node-id-uppercase":            CodeID,
	"stream-with-colon":            CodeID,
	"category-without-mapping":     CodeUnjustifiedMeaning,
	"failed-parse-with-normalized": CodeForbidden,
	"missing-native":               CodeMissing,
	"received-without-z":           CodeTimeFormat,
	"other-major":                  CodeSchema,
	"device-event-platform-auth":   CodeEnum,
	"content-field-configured":     CodeEnum,
	"no-asset-no-flag":             CodeMissing,
	"platform-event-with-native":   CodeForbidden,
	"closed-enum-unknown":          CodeEnum,
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
