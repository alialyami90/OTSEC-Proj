package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/adapter"
	"otsec.local/otsec/contracts/audit"
)

// invalidWant is the error each invalid example must produce. Every file in
// testdata/invalid must be listed, so a new example cannot pass by failing
// for an unrelated reason.
var invalidWant = map[string]string{
	"snapshot-missing-class":               "has 24 classes and a snapshot holds every one",
	"snapshot-classes-out-of-order":        "holds port.1 (\"SHO P 1\") here, not global",
	"snapshot-required-class-absent":       "group.1 cannot be absent",
	"snapshot-absent-with-settings":        "an absent section has no settings",
	"snapshot-present-without-settings":    "a present section holds at least one setting",
	"snapshot-port-not-sensitive":          "sensitive is true for port.1",
	"snapshot-unknown-rule":                `rule "sel-751-sho/3" is not a rule`,
	"snapshot-setting-twice":               "SET01 is printed twice in one section",
	"snapshot-value-two-spaces":            "no two spaces together",
	"snapshot-value-holds-assign":          "no :=",
	"snapshot-ref-not-transcript":          `ref "sha256:" + sha256`,
	"snapshot-other-major":                 "not readable as otsec.config/0.2",
	"snapshot-unknown-field-in-own-minor":  `key "zz_new" is not a field name`,
	"snapshot-wrong-kind":                  `kind "config.baseline" is not "config.snapshot"`,
	"snapshot-without-register-version":    "register_version is required",
	"snapshot-target-documented":           "target must be",
	"snapshot-sections-overlap":            "comes before the end of the section before it",
	"difference-changed-equal-values":      "changed with equal values",
	"difference-added-with-from":           "added carries to only",
	"difference-out-of-order":              "changes are in class order",
	"difference-required-section-appeared": "group.1 cannot be absent under rule sel-751-sho/2, so it cannot appear",
	"difference-without-changes":           "changes is required",
	"difference-digest-without-prefix":     `from needs a snapshot_digest "sha256:<hex>"`,
	"difference-sensitive-unmarked":        "sensitive is true for port.2",
}

func decodeAny(b []byte) error {
	var probe struct {
		Kind string `json:"kind"`
	}
	if err := json.Unmarshal(b, &probe); err != nil {
		return err
	}
	if probe.Kind == KindDifference {
		_, err := DecodeDifference(b)
		return err
	}
	_, err := DecodeSnapshot(b)
	return err
}

func files(t *testing.T, dir string) []string {
	t.Helper()
	m, err := filepath.Glob(filepath.Join("testdata", dir, "*.json"))
	if err != nil || len(m) == 0 {
		t.Fatalf("no examples in testdata/%s", dir)
	}
	sort.Strings(m)
	return m
}

func read(t testing.TB, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", rel))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestValidExamples(t *testing.T) {
	for _, f := range files(t, "valid") {
		b, _ := os.ReadFile(f)
		if err := decodeAny(b); err != nil {
			t.Errorf("%s: %v", f, err)
		}
	}
}

func TestInvalidExamples(t *testing.T) {
	seen := map[string]bool{}
	for _, f := range files(t, "invalid") {
		name := strings.TrimSuffix(filepath.Base(f), ".json")
		seen[name] = true
		want, ok := invalidWant[name]
		if !ok {
			t.Errorf("%s: not listed in invalidWant", f)
			continue
		}
		b, _ := os.ReadFile(f)
		err := decodeAny(b)
		if err == nil {
			t.Errorf("%s: accepted", f)
		} else if !strings.Contains(err.Error(), want) {
			t.Errorf("%s: error does not mention %q:\n%v", f, want, err)
		}
	}
	for name := range invalidWant {
		if !seen[name] {
			t.Errorf("invalidWant lists %s but testdata/invalid has no such file", name)
		}
	}
}

// Every example has a one-line note in testdata/README.md.
func TestExamplesHaveNotes(t *testing.T) {
	readme := string(read(t, "README.md"))
	for _, dir := range []string{"valid", "invalid", "transcripts"} {
		for _, f := range files(t, dir) {
			rel := dir + "/" + filepath.Base(f)
			if !strings.Contains(readme, "`"+rel+"`") {
				t.Errorf("testdata/README.md has no note for %s", rel)
			}
		}
	}
}

func transcript(t testing.TB, n string) adapter.Transcript {
	t.Helper()
	var tr adapter.Transcript
	if err := json.Unmarshal(read(t, "transcripts/read-"+n+".json"), &tr); err != nil {
		t.Fatal(err)
	}
	return tr
}

func snapshot(t testing.TB, n string) (Snapshot, []byte) {
	t.Helper()
	b := read(t, "valid/snapshot-read-"+n+".json")
	s, err := DecodeSnapshot(b)
	if err != nil {
		t.Fatal(err)
	}
	return s, b
}

// Each snapshot is exactly what the rule reads from its own transcript.
// generate.py tokenizes with its own Python reading of the rule, so this
// checks two implementations against each other.
func TestSnapshotsMatchTheirTranscripts(t *testing.T) {
	for _, n := range []string{"1", "2", "3"} {
		s, _ := snapshot(t, n)
		if err := s.CheckAgainst(transcript(t, n)); err != nil {
			t.Errorf("read %s: %v", n, err)
		}
	}
	s, _ := snapshot(t, "1")
	if err := s.CheckAgainst(transcript(t, "2")); err == nil || !strings.Contains(err.Error(), "not the one the snapshot names") {
		t.Errorf("read 1 against read 2's transcript: %v", err)
	}
}

// The golden differences are what Compare computes: Go's reading of the
// rule against generate.py's.
func TestCompareGoldens(t *testing.T) {
	_, b1 := snapshot(t, "1")
	for n, golden := range map[string]string{"2": "valid/difference-1-2.json", "3": "valid/difference-1-3.json"} {
		_, bn := snapshot(t, n)
		got, err := Compare(b1, bn)
		if err != nil {
			t.Fatalf("read 1 to %s: %v", n, err)
		}
		want, err := DecodeDifference(read(t, golden))
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, want) {
			g, _ := json.MarshalIndent(got, "", "  ")
			t.Errorf("read 1 to %s: Compare gives\n%s\nnot %s", n, g, golden)
		}
	}
}

// P4-A2's acceptance case: the same configuration read twice, with another
// time, a header printed again mid-reply, other columns, another order and
// other wraps, gives an empty difference, although the bytes differ.
func TestSameConfigurationOtherBytesIsNoChange(t *testing.T) {
	s1, b1 := snapshot(t, "1")
	s2, b2 := snapshot(t, "2")
	d, err := Compare(b1, b2)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Changes) != 0 {
		t.Errorf("changes %+v", d.Changes)
	}
	differ := map[string]bool{}
	for i := range s1.Sections {
		if s1.Sections[i].SHA256 != s2.Sections[i].SHA256 {
			differ[s1.Sections[i].Class] = true
		}
	}
	for _, c := range []string{"group.1", "group.2", "group.3", "group.4", "report"} {
		if !differ[c] {
			t.Errorf("%s has the same bytes in reads 1 and 2, so the case tests nothing there", c)
		}
	}
	if d.From.SnapshotDigest == d.To.SnapshotDigest || d.From.SnapshotDigest != Digest(b1) {
		t.Errorf("digests %s and %s", d.From.SnapshotDigest, d.To.SnapshotDigest)
	}
}

// SameChanges (D4-20): a change that stays is one change however many reads
// show it. Another end snapshot of the same changes is the same; another
// baseline, other changes, or another asset is not.
func TestSameChanges(t *testing.T) {
	s3, b3 := snapshot(t, "3")
	_, b1 := snapshot(t, "1")
	_, b2 := snapshot(t, "2")
	d13, err := Compare(b1, b3)
	if err != nil {
		t.Fatal(err)
	}
	// Read 3 again, later: other time and invocation, the same settings.
	later := []byte(strings.NewReplacer(s3.RetrievedAt, "2026-10-25T09:00:00Z", s3.InvocationID, "8d1f4b2a-3c5e-4f60-9a7b-1c2d3e4f5a6b").Replace(string(b3)))
	d13b, err := Compare(b1, later)
	if err != nil {
		t.Fatal(err)
	}
	if d13b.To.SnapshotDigest == d13.To.SnapshotDigest {
		t.Fatal("the later read has the same digest, so the case tests nothing")
	}
	if len(d13.Changes) == 0 || !d13.SameChanges(d13b) || !d13b.SameChanges(d13) {
		t.Errorf("the same changes at another time: %v", d13.SameChanges(d13b))
	}
	d12, err := Compare(b1, b2)
	if err != nil {
		t.Fatal(err)
	}
	if d13.SameChanges(d12) || d12.SameChanges(d13) {
		t.Error("a change and no change are the same")
	}
	if !d12.SameChanges(d12) {
		t.Error("two differences with no change are not the same")
	}
	// The same changes from another baseline are another change.
	d23, err := Compare(b2, b3)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(d23.Changes, d13.Changes) || d23.SameChanges(d13) {
		t.Errorf("another baseline: equal changes %v, same %v", reflect.DeepEqual(d23.Changes, d13.Changes), d23.SameChanges(d13))
	}
	// One value changed is another change; another asset is another change.
	other := d13
	other.Changes = append([]Change(nil), d13.Changes...)
	to := "9"
	other.Changes[0].To = &to
	if d13.SameChanges(other) {
		t.Error("a different value is the same change")
	}
	other = d13
	other.AssetID += "x"
	if d13.SameChanges(other) {
		t.Error("another asset is the same change")
	}
}

// ChangesDigest (C8 0.7's changes_digest): equal exactly when the changes are
// equal, whatever snapshots they come from, and not the baseline's.
func TestChangesDigest(t *testing.T) {
	s3, b3 := snapshot(t, "3")
	_, b1 := snapshot(t, "1")
	_, b2 := snapshot(t, "2")
	d13, _ := Compare(b1, b3)
	later := []byte(strings.NewReplacer(s3.RetrievedAt, "2026-10-25T09:00:00Z", s3.InvocationID, "8d1f4b2a-3c5e-4f60-9a7b-1c2d3e4f5a6b").Replace(string(b3)))
	d13b, err := Compare(b1, later)
	if err != nil {
		t.Fatal(err)
	}
	d23, _ := Compare(b2, b3)
	d12, _ := Compare(b1, b2)
	if !digestPattern.MatchString(d13.ChangesDigest()) {
		t.Errorf("digest %q", d13.ChangesDigest())
	}
	if d13.ChangesDigest() != d13b.ChangesDigest() || d13.ChangesDigest() != d23.ChangesDigest() {
		t.Error("the same changes from other snapshots or another baseline have different digests")
	}
	if d13.ChangesDigest() == d12.ChangesDigest() {
		t.Error("a change and no change have one digest")
	}
	// No changes is "[]", whether the slice is empty or nil.
	empty := Difference{}
	if d12.ChangesDigest() != empty.ChangesDigest() || d12.ChangesDigest() != Digest([]byte("[]")) {
		t.Errorf("no changes: %s, want %s", d12.ChangesDigest(), Digest([]byte("[]")))
	}
	// C8 0.7 names the same value, so the audit chain can refuse a "change"
	// that holds nothing: the two constants must not drift.
	if d12.ChangesDigest() != audit.EmptyChangesDigest {
		t.Errorf("no changes: %s, but C8 names %s", d12.ChangesDigest(), audit.EmptyChangesDigest)
	}
	// One value moved is another digest, and "<" is not escaped.
	other := d13
	other.Changes = append([]Change(nil), d13.Changes...)
	to := "A<B"
	other.Changes[0].To = &to
	if other.ChangesDigest() == d13.ChangesDigest() {
		t.Error("another value, the same digest")
	}
	one := Difference{Changes: []Change{{Class: "global", Kind: Changed, Name: "X", From: &to, To: &to}}}
	want := Digest([]byte(`[{"class":"global","kind":"changed","name":"X","from":"A<B","to":"A<B","sensitive":false}]`))
	if one.ChangesDigest() != want {
		t.Errorf("encoding: %s, want %s", one.ChangesDigest(), want)
	}
}

// Reversed, every change is its inverse.
func TestCompareReversed(t *testing.T) {
	_, b1 := snapshot(t, "1")
	_, b3 := snapshot(t, "3")
	fwd, err := Compare(b1, b3)
	if err != nil {
		t.Fatal(err)
	}
	back, err := Compare(b3, b1)
	if err != nil {
		t.Fatal(err)
	}
	inverse := map[ChangeKind]ChangeKind{Changed: Changed, Added: Removed, Removed: Added,
		SectionAppeared: SectionDisappeared, SectionDisappeared: SectionAppeared}
	if len(fwd.Changes) != len(back.Changes) {
		t.Fatalf("%d changes forward, %d back", len(fwd.Changes), len(back.Changes))
	}
	for i, f := range fwd.Changes {
		b := back.Changes[i]
		if b.Kind != inverse[f.Kind] || b.Class != f.Class || b.Name != f.Name || !reflect.DeepEqual(b.From, f.To) || !reflect.DeepEqual(b.To, f.From) {
			t.Errorf("change %d: %+v back is %+v", i, f, b)
		}
	}
}

func TestNotComparable(t *testing.T) {
	s1, b1 := snapshot(t, "1")
	for name, f := range map[string]func(*Snapshot){
		"asset":  func(s *Snapshot) { s.AssetID = "2b7d4e10-8c3f-4a5b-9e21-7c4f0d6a8b14" },
		"target": func(s *Snapshot) { s.Target = "device-observed" },
	} {
		o := s1
		f(&o)
		b, _ := json.Marshal(o)
		if _, err := Compare(b1, b); !errors.Is(err, ErrNotComparable) {
			t.Errorf("another %s: %v", name, err)
		}
	}
}

func TestDigest(t *testing.T) {
	if got := Digest([]byte("abc")); got != "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Errorf("Digest(abc) = %s", got)
	}
	_, b := snapshot(t, "1")
	if !digestPattern.MatchString(Digest(b)) {
		t.Error("Digest does not match its own pattern")
	}
}

// CheckAgainst catches every way a parser can misreport a section. Each
// mutation starts from read 1, which passes.
func TestCheckAgainstCatches(t *testing.T) {
	tr := transcript(t, "1")
	section := func(s *Snapshot, class string) *Section {
		for i := range s.Sections {
			if s.Sections[i].Class == class {
				return &s.Sections[i]
			}
		}
		t.Fatalf("no class %s", class)
		return nil
	}
	setting := func(sec *Section, name string) *Setting {
		for i := range sec.Settings {
			if sec.Settings[i].Name == name {
				return &sec.Settings[i]
			}
		}
		t.Fatalf("no setting %s", name)
		return nil
	}
	cases := map[string]struct {
		mutate func(*Snapshot)
		want   string
	}{
		"a setting dropped": {func(s *Snapshot) {
			g := section(s, "group.1")
			g.Settings = append(g.Settings[:3:3], g.Settings[4:]...)
		}, "not what rule sel-751-sho/2 reads"},
		"a value misread": {func(s *Snapshot) { setting(section(s, "group.1"), "50P1P").Value = "10.0" }, "not what rule"},
		"a name misread":  {func(s *Snapshot) { setting(section(s, "group.1"), "CTRN").Name = "CTRM" }, "not what rule"},
		"two settings swapped": {func(s *Snapshot) {
			g := section(s, "logic.1")
			g.Settings[0], g.Settings[1] = g.Settings[1], g.Settings[0]
		}, "not what rule"},
		"a wrapped value cut at its first piece": {func(s *Snapshot) {
			setting(section(s, "report"), "ER").Value = "R_TRIG 51P1P OR R_TRIG 51G1P OR R_TRIG 50P1P"
		}, "not what rule"},
		"a heading read as a setting's continuation": {func(s *Snapshot) {
			v := setting(section(s, "group.1"), "TID")
			v.Value += " Config Settings"
		}, "not what rule"},
		"a section hash wrong": {func(s *Snapshot) { section(s, "global").SHA256 = strings.Repeat("0", 64) }, "sha256 does not match"},
		"a span over the STX": {func(s *Snapshot) {
			g := section(s, "global")
			g.Span.Offset--
			g.Span.Length++
		}, "does not start right after the echo"},
		"a span over the command sent": {func(s *Snapshot) {
			g := section(s, "global")
			g.Span.Offset -= 12
			g.Span.Length += 12
		}, "covers bytes that were sent"},
		"a span that ends early": {func(s *Snapshot) {
			g := section(s, "group.1")
			g.Span.Length -= 40
		}, "not followed by ETX and the prompt"},
		"a span that starts late": {func(s *Snapshot) {
			g := section(s, "group.1")
			g.Span.Offset += 2
			g.Span.Length -= 2
		}, "does not start right after the echo"},
		"a span that reaches into the next reply": {func(s *Snapshot) {
			g := section(s, "logic.1")
			g.Span.Length += 12
		}, "covers bytes that were sent"},
		"an absent section that answered settings": {func(s *Snapshot) {
			g := section(s, "dnp.1")
			g.State, g.Settings = Absent, nil
		}, `absent, but the reply is not "Invalid Command"`},
		"a present section that answered Invalid Command": {func(s *Snapshot) {
			g := section(s, "dnp.2")
			g.State, g.Settings = Present, []Setting{{Name: "BI_00", Value: "ENABLED"}}
		}, `present, but the relay answered "Invalid Command"`},
	}
	for name, c := range cases {
		s, _ := snapshot(t, "1")
		c.mutate(&s)
		err := s.CheckAgainst(tr)
		if err == nil {
			t.Errorf("%s: accepted", name)
		} else if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: error does not mention %q:\n%v", name, c.want, err)
		}
	}

	// The session itself changed, with the snapshot naming the new bytes.
	sessions := map[string]struct {
		edit func([]byte) []byte
		want string
	}{
		"SHO 1 sent again where SHO 2 belongs": {func(b []byte) []byte {
			// Group 2's settings are then what the relay printed for Group 1:
			// the section is bound to SHO 2, so it fails.
			return bytes.Replace(b, []byte("SHO 2\r\n"), []byte("SHO 1\r\n"), 2)
		}, `not "SHO 2"`},
		"an echo of another command": {func(b []byte) []byte {
			i := bytes.Index(b, []byte("SHO 2\r\n"))
			j := i + bytes.Index(b[i+1:], []byte("SHO 2\r\n")) + 1
			return append(append(append([]byte{}, b[:j]...), "SHO 1\r\n"...), b[j+7:]...)
		}, `does not start right after the echo of "SHO 2"`},
		"no ETX after a reply": {func(b []byte) []byte {
			i := bytes.Index(b, []byte("SHO G\r\n\x02"))
			j := i + bytes.IndexByte(b[i:], 0x03)
			b = append([]byte{}, b...)
			b[j] = ' '
			return b
		}, "not followed by ETX and the prompt"},
		"no prompt after a reply": {func(b []byte) []byte {
			i := bytes.Index(b, []byte("SHO G\r\n\x02"))
			j := i + bytes.IndexByte(b[i:], 0x03)
			b = append([]byte{}, b...)
			b[j+1], b[j+2] = ' ', ' '
			return b
		}, "not followed by ETX and the prompt"},
	}
	for name, c := range sessions {
		s, _ := snapshot(t, "1")
		bad := tr
		bad.Data = c.edit(tr.Data)
		if len(bad.Data) != len(tr.Data) || bytes.Equal(bad.Data, tr.Data) {
			t.Fatalf("%s: the edit must change bytes in place", name)
		}
		sum := sha256.Sum256(bad.Data)
		bad.SHA256 = hex.EncodeToString(sum[:])
		s.Transcript.SHA256, s.Transcript.Ref = bad.SHA256, "sha256:"+bad.SHA256
		err := s.CheckAgainst(bad)
		if err == nil {
			t.Errorf("%s: accepted", name)
		} else if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: error does not mention %q:\n%v", name, c.want, err)
		}
	}
}

// The rule, line by line (doc.go). Each case pins one clause, so a change to
// the rule shows here.
func TestTokenizeRule(t *testing.T) {
	type st = Setting
	cases := []struct {
		name, text string
		want       []Setting
		err        string
	}{
		{"three per line", "CTR      := 120            CTRN     := 120     PTR       := 180.00\r\n",
			[]st{{"CTR", "120"}, {"CTRN", "120"}, {"PTR", "180.00"}}, ""},
		{"a name one space from :=", "LEA_S_R := 180.00          SINGLEV := N\r\n", []st{{"LEA_S_R", "180.00"}, {"SINGLEV", "N"}}, ""},
		{"a name touching :=", "IRIGC    := NONE    DST_BEGM:= OFF\r\n", []st{{"IRIGC", "NONE"}, {"DST_BEGM", "OFF"}}, ""},
		{"a leading digit", "51SAT := 1\r\n", []st{{"51SAT", "1"}}, ""},
		{"single spaces stay in a value", "TID      := FEEDER RELAY\r\nULTRIP := NOT ( 51P1P OR 52A )\r\n",
			[]st{{"TID", "FEEDER RELAY"}, {"ULTRIP", "NOT ( 51P1P OR 52A )"}}, ""},
		{"a trailing space ends a value", "RID := SEL-751 \r\n", []st{{"RID", "SEL-751"}}, ""},
		{"a continuation joins with one space", "ER := A OR B\r\n      OR C\r\n   OR D\r\nLER := 15\r\n",
			[]st{{"ER", "A OR B OR C OR D"}, {"LER", "15"}}, ""},
		{"a continuation goes to the last setting of its line", "X := 1   ER := A\r\n OR B\r\n",
			[]st{{"X", "1"}, {"ER", "A OR B"}}, ""},
		{"a heading after a blank line is not a continuation", "TID := FEEDER\r\n\r\nConfig Settings\r\nCTR := 120\r\n",
			[]st{{"TID", "FEEDER"}, {"CTR", "120"}}, ""},
		{"a header before the first setting line is not semantic",
			"\r\nSEL-751          Date: 10/27/2026  Time: 09:31:08.000\r\nFEEDER RELAY     Time Source: Internal\r\n\r\nRID := SEL-751\r\n",
			[]st{{"RID", "SEL-751"}}, ""},
		{"a header right after a setting line fails",
			"LL := 4.84\r\nSEL-751          Date: 10/27/2026  Time: 09:31:08.000\r\nFEEDER RELAY     Time Source: Internal\r\nEFLOC := N\r\n",
			nil, "two spaces"},
		{"a header-shaped heading after a blank line is a heading", "A := 1\r\n\r\nX Date: 2026/10/27 Time: 09:31:08\r\nB := 2\r\n",
			[]st{{"A", "1"}, {"B", "2"}}, ""},
		{"header text in a value is the value", "TID      := Time Source: GPS\r\n", []st{{"TID", "Time Source: GPS"}}, ""},
		{"header text in a value keeps the line's other settings",
			"RID      := X Date: 10/27/2026 Time: 09:31          TID      := Time Source: GPS\r\n",
			[]st{{"RID", "X Date: 10/27/2026 Time: 09:31"}, {"TID", "Time Source: GPS"}}, ""},
		{"LF and CR line ends", "A := 1\nB := 2\rC := 3", []st{{"A", "1"}, {"B", "2"}, {"C", "3"}}, ""},
		{"headings and blank lines only around settings", "\r\nGroup 1\r\nRelay Settings\r\n\r\nID Settings\r\nRID := SEL-751\r\n\r\n",
			[]st{{"RID", "SEL-751"}}, ""},
		{"an empty value fails", "FAULT :=\r\n", nil, "empty value"},
		{"an empty value before the next setting fails", "A :=   B := 2\r\n", nil, "holds :="},
		{"a value holding := fails", "MPTX01 := A := B\r\n", nil, "holds :="},
		{"a name printed twice fails", "A := 1\r\nA := 2\r\n", nil, "printed twice"},
		{"a setting line that does not tokenize fails", "Note: x := 1\r\n", nil, "does not tokenize"},
		{"a lower-case name fails", "abc := 1\r\n", nil, "does not tokenize"},
		{"a continuation holding two spaces fails", "ER := A\r\n  OR B  OR C\r\n", nil, "two spaces"},
		{"a value that is not printable ASCII fails", "0:=\x00\r\n", nil, "not printable ASCII"},
		{"a continuation that is not printable ASCII fails", "ER := A\r\n  OR \x7f\r\n", nil, "not printable ASCII"},
	}
	for _, c := range cases {
		got, err := tokenize([]byte(c.text))
		switch {
		case c.err != "" && (err == nil || !strings.Contains(err.Error(), c.err)):
			t.Errorf("%s: error %v, want %q", c.name, err, c.err)
		case c.err == "" && err != nil:
			t.Errorf("%s: %v", c.name, err)
		case c.err == "" && !reflect.DeepEqual(got, c.want):
			t.Errorf("%s: %+v, want %+v", c.name, got, c.want)
		}
	}
}

// Whatever the bytes, tokenize returns settings a snapshot may hold, or an
// error; it never panics.
func FuzzTokenize(f *testing.F) {
	for _, n := range []string{"1", "2", "3"} {
		s, _ := snapshot(f, n)
		tr := transcript(f, n)
		for _, sec := range s.Sections {
			f.Add(tr.Data[sec.Span.Offset : sec.Span.Offset+sec.Span.Length])
		}
	}
	f.Add([]byte("ER := A\r\n OR B\r\n\r\nX\r\nY := 1  Z:=2"))
	f.Fuzz(func(t *testing.T, text []byte) {
		got, err := tokenize(text)
		if err != nil {
			return
		}
		seen := map[string]bool{}
		for _, s := range got {
			if !settingName.MatchString(s.Name) || !valueText.MatchString(s.Value) || strings.Contains(s.Value, "  ") || strings.Contains(s.Value, ":=") || seen[s.Name] {
				t.Fatalf("tokenize(%q) gave %+v", text, s)
			}
			seen[s.Name] = true
		}
	})
}

// The rule holds exactly the SHO forms of S22 Table 7.67 (p. 7.77), each
// without the setting-name parameter and with an explicit port or map (#231).
// The rule is S22 Table 7.67 in the order the run sends it (0.2).
func TestRuleIsTable767(t *testing.T) {
	want := []string{"SHO P 1", "SHO G", "SHO 1", "SHO 2", "SHO 3", "SHO 4", "SHO L 1", "SHO L 2", "SHO L 3", "SHO L 4",
		"SHO P F", "SHO P 2", "SHO P 3", "SHO P 4", "SHO R", "SHO F", "SHO M", "SHO I",
		"SHO E 1", "SHO E 2", "SHO E 3", "SHO DNP 1", "SHO DNP 2", "SHO DNP 3"}
	var got []string
	ids := map[string]bool{}
	for _, c := range RuleSEL751SHO.Classes {
		got = append(got, c.Command)
		if ids[c.ID] {
			t.Errorf("class %s twice", c.ID)
		}
		ids[c.ID] = true
		if strings.HasPrefix(c.Command, "SHO P ") != c.Sensitive {
			t.Errorf("%s: only the port classes are sensitive", c.ID)
		}
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("commands %v, want %v", got, want)
	}
	for _, id := range []string{"group.1", "logic.1", "global", "port.f", "port.1", "report", "front-panel"} {
		if c, _, _ := RuleSEL751SHO.class(id); c.MayBeAbsent {
			t.Errorf("%s is standard and cannot be absent", id)
		}
	}
}

func schemaDefs(t *testing.T, file string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("schema", file))
	if err != nil {
		t.Fatal(err)
	}
	var s map[string]any
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatalf("%s: %v", file, err)
	}
	if s["$schema"] != "https://json-schema.org/draft/2020-12/schema" {
		t.Fatalf("%s: not a 2020-12 schema", file)
	}
	return s["$defs"].(map[string]any)
}

func enumOf(t *testing.T, defs map[string]any, name string) []string {
	t.Helper()
	var out []string
	for _, v := range defs[name].(map[string]any)["enum"].([]any) {
		out = append(out, v.(string))
	}
	sort.Strings(out)
	return out
}

func sorted[T ~string](xs []T) []string {
	out := make([]string, len(xs))
	for i, x := range xs {
		out[i] = string(x)
	}
	sort.Strings(out)
	return out
}

// The schemas' enums equal the Go lists, so the two cannot drift, and the
// schemas' patterns are the Go patterns.
func TestSchemaMatchesGo(t *testing.T) {
	s := schemaDefs(t, "snapshot.schema.json")
	d := schemaDefs(t, "difference.schema.json")
	if got, want := enumOf(t, s, "sectionState"), sorted(SectionStates); !reflect.DeepEqual(got, want) {
		t.Errorf("sectionState %v, Go has %v", got, want)
	}
	if got, want := enumOf(t, d, "changeKind"), sorted(ChangeKinds); !reflect.DeepEqual(got, want) {
		t.Errorf("changeKind %v, Go has %v", got, want)
	}
	pattern := func(defs map[string]any, path ...string) string {
		var v any = defs
		for _, p := range path {
			v = v.(map[string]any)[p]
		}
		return v.(string)
	}
	for _, c := range []struct{ got, want string }{
		{pattern(s, "setting", "properties", "name", "pattern"), settingName.String()},
		{pattern(s, "setting", "properties", "value", "pattern"), valueText.String()},
		{pattern(s, "uuid", "pattern"), uuidPattern.String()},
		{pattern(d, "ref", "properties", "snapshot_digest", "pattern"), digestPattern.String()},
		{pattern(d, "value", "pattern"), valueText.String()},
	} {
		if c.got != c.want {
			t.Errorf("schema pattern %q, Go has %q", c.got, c.want)
		}
	}
}
