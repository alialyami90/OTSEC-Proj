package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/adapter"
	"otsec.local/otsec/contracts/register"
)

// The end-to-end path of a configuration read: a C2 run result (simulated
// golden), the register that permitted it, a snapshot, and the contract's
// own check against the transcript.

func runFixture(t *testing.T, name string) (*register.Matcher, adapter.Invocation, adapter.Result) {
	t.Helper()
	read := func(p ...string) []byte {
		b, err := os.ReadFile(filepath.Join(p...))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	pkg, err := register.Decode(read("..", "register", "testdata", "sel-751.json"))
	if err != nil {
		t.Fatal(err)
	}
	m, err := register.NewMatcher(pkg)
	if err != nil {
		t.Fatal(err)
	}
	inv, err := adapter.DecodeInvocation(read("..", "adapter", "testdata", "config", "invocations", "valid", "sel-config-read.json"))
	if err != nil {
		t.Fatal(err)
	}
	r, err := adapter.DecodeResult(read("..", "adapter", "testdata", "config", "results", "valid", name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := r.CheckLines(pkg, inv); err != nil {
		t.Fatal(err)
	}
	return m, inv, r
}

func TestFromResultChecksAgainstTranscript(t *testing.T) {
	for _, n := range []string{"ok", "ok-all-present", "ok-with-echo"} {
		m, inv, r := runFixture(t, n)
		s, err := FromResult(RuleSEL751SHO.ID, m, inv, r)
		if err != nil {
			t.Fatalf("%s: %v", n, err)
		}
		if err := s.CheckAgainst(r.Transcript); err != nil {
			t.Errorf("%s: CheckAgainst: %v", n, err)
		}
		if got := len(s.Sections); got != len(RuleSEL751SHO.Classes) {
			t.Errorf("%s: %d sections", n, got)
		}
	}
	m, inv, r := runFixture(t, "ok")
	s, _ := FromResult(RuleSEL751SHO.ID, m, inv, r)
	var absent int
	for _, sec := range s.Sections {
		if sec.State == Absent {
			absent++
		}
	}
	if absent != 10 {
		t.Errorf("%d absent sections, want 10", absent)
	}
	port1 := s.Sections[10]
	if port1.Class != "port.1" || !port1.Sensitive || len(port1.Settings) != 7 {
		t.Errorf("port.1 section: %+v", port1)
	}
	if s.Sections[0].Span.Offset < port1.Span.Offset {
		t.Error("group.1 was read before port.1, but the run reads the gate first")
	}
	// The wrapped value joins by one space (rule).
	for _, st := range s.Sections[0].Settings {
		if st.Name == "S1C" && st.Value != "IN101 AND NOT IN102" {
			t.Errorf("wrapped value %q", st.Value)
		}
	}
}

func TestFromResultRefuses(t *testing.T) {
	m, inv, ok := runFixture(t, "ok")
	other := inv
	other.InvocationID = "00000000-0000-4000-8000-000000000000"
	short := ok
	short.Records = ok.Records[:23]
	unparsed := ok
	unparsed.Records = append([]adapter.Record(nil), ok.Records...)
	unparsed.Records[5].ParseOK, unparsed.Records[5].Fields = false, nil
	wrongKind := ok
	wrongKind.Records = append([]adapter.Record(nil), ok.Records...)
	wrongKind.Records[5].Kind = "sel.ser.row"
	cases := map[string]struct {
		rule string
		inv  adapter.Invocation
		r    adapter.Result
		want string
	}{
		"unknown rule":     {"sel-751-sho/9", inv, ok, "is not a rule"},
		"other invocation": {RuleSEL751SHO.ID, other, ok, "is not of invocation"},
		"missing record":   {RuleSEL751SHO.ID, inv, short, "23 records"},
		"unparsed section": {RuleSEL751SHO.ID, inv, unparsed, "did not parse"},
		"not a config rec": {RuleSEL751SHO.ID, inv, wrongKind, "not a configuration record"},
		"not a run":        {RuleSEL751SHO.ID, func() adapter.Invocation { i := inv; i.OperationID = "sel.ser.read_all"; return i }(), ok, "is not of invocation"},
	}
	for _, n := range []string{"partial.parse_errors-in-run", "failed.timeout-in-run"} {
		_, _, r := runFixture(t, n)
		cases[n] = struct {
			rule string
			inv  adapter.Invocation
			r    adapter.Result
			want string
		}{RuleSEL751SHO.ID, inv, r, "from an ok result"}
	}
	for n, c := range cases {
		if _, err := FromResult(c.rule, m, c.inv, c.r); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", n, err, c.want)
		}
	}
}

// A parser that drops, merges or splits a setting makes a snapshot that
// CheckAgainst refuses (the node never stores it).
func TestFromResultAdapterParserDisagrees(t *testing.T) {
	m, inv, r := runFixture(t, "ok")
	mut := map[string]func(*adapter.Record){
		"drops a setting":   func(rec *adapter.Record) { rec.Fields = rec.Fields[1:] },
		"changes a value":   func(rec *adapter.Record) { rec.Fields[0].Value += "0" },
		"swaps two":         func(rec *adapter.Record) { rec.Fields[0], rec.Fields[1] = rec.Fields[1], rec.Fields[0] },
		"splits the wrap":   func(rec *adapter.Record) { rec.Fields[2].Value = "IN101 AND" },
		"renames a setting": func(rec *adapter.Record) { rec.Fields[0].Name = "S1Z" },
	}
	for n, f := range mut {
		x := r
		x.Records = append([]adapter.Record(nil), r.Records...)
		i := 2 // SHO 1
		x.Records[i].Fields = append([]adapter.Field(nil), r.Records[i].Fields...)
		f(&x.Records[i])
		s, err := FromResult(RuleSEL751SHO.ID, m, inv, x)
		if err != nil {
			t.Errorf("%s: %v", n, err)
			continue
		}
		if err := s.CheckAgainst(x.Transcript); err == nil {
			t.Errorf("%s: CheckAgainst accepted the snapshot", n)
		}
	}
}
