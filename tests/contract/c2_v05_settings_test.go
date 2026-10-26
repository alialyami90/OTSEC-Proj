package contract

// C2 0.5 settings (A2, #164; D3-2, P3-A2): A6's negative pass. Expected
// results come from the 0.5 rule text (contracts/adapter/doc.go, lines.go):
// a setting's span selects exactly its value, in received bytes; the value
// is printable ASCII with no space at either end; a name is reported once;
// settings are new in 0.5; and CheckLines refuses a setting that no context
// read of the invocation's operation names, or whose span does not lie in
// the reply to the line that reads it (from the end of that send to the
// next send). Cases are made by editing the valid ok-with-settings example;
// each provenance case passes Validate, so only CheckLines can refuse it.
// Ground truth: GT-HAND.

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/adapter"
	"otsec.local/otsec/contracts/register"
)

func c2v05(t *testing.T) (adapter.Result, *register.Package, adapter.Invocation) {
	t.Helper()
	read := func(p ...string) []byte {
		b, err := os.ReadFile(filepath.Join(append([]string{"..", "..", "contracts"}, p...)...))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	r, err := adapter.DecodeResult(read("adapter", "testdata", "results", "valid", "ok-with-settings.json"))
	if err != nil {
		t.Fatal(err)
	}
	p, err := register.Decode(read("register", "testdata", "sel-751.json"))
	if err != nil {
		t.Fatal(err)
	}
	inv, err := adapter.DecodeInvocation(read("adapter", "testdata", "invocations", "valid", "sel-ser-read.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Validate(); err != nil {
		t.Fatalf("the example: %v", err)
	}
	if err := r.CheckLines(p, inv); err != nil {
		t.Fatalf("the example: %v", err)
	}
	return r, p, inv
}

// c2Reply is the received bytes after the sent line (exactly line+CRLF in
// operate) up to the next send.
func c2Reply(t *testing.T, r adapter.Result, line string) (start, end int) {
	t.Helper()
	segs := r.Transcript.Segments
	for i, sg := range segs {
		if sg.Dir == adapter.Sent && string(r.Transcript.Data[sg.Offset:sg.Offset+sg.Length]) == line+"\r\n" {
			start, end = int(sg.Offset+sg.Length), len(r.Transcript.Data)
			for _, nx := range segs[i+1:] {
				if nx.Dir == adapter.Sent {
					return start, int(nx.Offset)
				}
			}
			return start, end
		}
	}
	t.Fatalf("no sent line %q", line)
	return 0, 0
}

func c2Find(t *testing.T, r adapter.Result, needle string, from, to int) adapter.Span {
	t.Helper()
	i := bytes.Index(r.Transcript.Data[from:to], []byte(needle))
	if i < 0 {
		t.Fatalf("no %q in [%d,%d)", needle, from, to)
	}
	return adapter.Span{Offset: int64(from + i), Length: int64(len(needle))}
}

func TestC2V05SettingProvenance(t *testing.T) {
	base, p, inv := c2v05(t)
	g0, g1 := c2Reply(t, base, "SHO G")
	p0, p1 := c2Reply(t, base, "SHO P 1")
	s0, s1 := c2Reply(t, base, "SER")
	id0, id1 := c2Reply(t, base, "ID")
	end := len(base.Transcript.Data)
	for _, c := range []struct {
		name string
		st   adapter.Setting
		want string // "" when CheckLines accepts it
	}{
		{"DATE_F in the SHO G reply (the example)", adapter.Setting{Name: "DATE_F", Value: "MDY", Span: c2Find(t, base, "MDY", g0, g1)}, ""},
		{"DATE_F's bytes taken from the SHO P 1 reply", adapter.Setting{Name: "DATE_F", Value: "ENGLISH", Span: c2Find(t, base, "ENGLISH", p0, p1)}, "does not lie in the reply"},
		{"DATE_F's bytes taken from the SER reply", adapter.Setting{Name: "DATE_F", Value: "FEEDER", Span: c2Find(t, base, "FEEDER", s0, s1)}, "does not lie in the reply"},
		{"DATE_F's bytes taken from the ID reply (probe phase)", adapter.Setting{Name: "DATE_F", Value: "FID", Span: c2Find(t, base, "FID", id0, id1)}, "does not lie in the reply"},
		{"DATE_F's bytes taken from the reply to the closing QUI", adapter.Setting{Name: "DATE_F", Value: "FEEDER", Span: c2Find(t, base, "FEEDER", s1+5, end)}, "does not lie in the reply"},
		{"DATE_F on the last byte of the SHO G reply", adapter.Setting{Name: "DATE_F", Value: string(base.Transcript.Data[g1-1 : g1]), Span: adapter.Span{Offset: int64(g1 - 1), Length: 1}}, ""},
		// Provenance is per reply, not per label: another setting's value in
		// the same reply is accepted under DATE_F's name. The adapter's
		// parser, not the contract, ties the value to "DATE_F :=" (noted on
		// #164; a value outside MDY, YMD and DMY is read as unknown).
		{"DATE_F on PHROT's value in the SHO G reply", adapter.Setting{Name: "DATE_F", Value: "ABC", Span: c2Find(t, base, "ABC", g0, g1)}, ""},
		{"a SHO G setting no context read names", adapter.Setting{Name: "FNOM", Value: "60", Span: c2Find(t, base, "60", g0, g1)}, "not a context read"},
		{"MAXACC, read by SHO P 1 for a posture warning, not a context read", adapter.Setting{Name: "MAXACC", Value: "2", Span: c2Find(t, base, "2", p0, p1)}, "not a context read"},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := base
			r.Settings = []adapter.Setting{c.st}
			if err := r.Validate(); err != nil {
				t.Fatalf("Validate: %v (each case is meant to pass it)", err)
			}
			err := r.CheckLines(p, inv)
			switch {
			case c.want == "" && err != nil:
				t.Errorf("refused: %v", err)
			case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)):
				t.Errorf("%v, want %q", err, c.want)
			}
		})
	}
	// The setting is for sel.ser.read_all only: the same SHO G reply, in an
	// invocation of another operation, gives no setting.
	other := inv
	other.OperationID = "sel.settings.show_global"
	r := base
	r.Settings = []adapter.Setting{{Name: "DATE_F", Value: "MDY", Span: c2Find(t, base, "MDY", g0, g1)}}
	if err := r.CheckLines(p, other); err == nil || !strings.Contains(err.Error(), "not a context read of sel.settings.show_global") {
		t.Errorf("DATE_F in a run of sel.settings.show_global: %v", err)
	}
}

func TestC2V05SettingValues(t *testing.T) {
	base, _, _ := c2v05(t)
	g0, g1 := c2Reply(t, base, "SHO G")
	mdy := c2Find(t, base, "MDY", g0, g1)
	d := base.Transcript.Data
	S := func(n, v string, s adapter.Span) adapter.Setting { return adapter.Setting{Name: n, Value: v, Span: s} }
	sp := func(off, n int64) adapter.Span { return adapter.Span{Offset: off, Length: n} }
	for _, c := range []struct {
		name string
		st   []adapter.Setting
		want string
	}{
		{"a leading space", []adapter.Setting{S("DATE_F", " MDY", sp(mdy.Offset-1, 4))}, "printable ASCII"},
		{"the CR after the value", []adapter.Setting{S("DATE_F", string(d[mdy.Offset:mdy.Offset+4]), sp(mdy.Offset, 4))}, "printable ASCII"},
		{"a CRLF and the next line", []adapter.Setting{S("DATE_F", string(d[mdy.Offset:mdy.Offset+6]), sp(mdy.Offset, 6))}, "printable ASCII"},
		{"empty", []adapter.Setting{S("DATE_F", "", sp(mdy.Offset, 0))}, "printable ASCII"},
		{"the STX before Global Settings", []adapter.Setting{S("DATE_F", string(d[g0+7:g0+9]), sp(int64(g0+7), 2))}, ""},
		{"a value that is not at its span", []adapter.Setting{S("DATE_F", "DMY", mdy)}, `does not select the value "DMY"`},
		{"a span one byte late", []adapter.Setting{S("DATE_F", "MDY", sp(mdy.Offset+1, 3))}, "does not select"},
		{"the span on the sent SHO G line", []adapter.Setting{S("DATE_F", "SHO", c2Find(t, base, "SHO G\r\n", g0-7, g0))}, ""},
		{"crossing into the sent SER line", []adapter.Setting{S("DATE_F", string(d[g1-2:g1+2]), sp(int64(g1-2), 4))}, "sent bytes"},
		{"reported twice", []adapter.Setting{S("DATE_F", "MDY", mdy), S("DATE_F", "MDY", mdy)}, "reported twice"},
		{"a lowercase name", []adapter.Setting{S("date_f", "MDY", mdy)}, "setting name"},
		{"a name of 17 characters", []adapter.Setting{S("DATE_F_ABCDEFGHIJ", "MDY", mdy)}, "setting name"},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := base
			r.Settings = c.st
			err := r.Validate()
			if c.want == "" {
				if err == nil {
					t.Errorf("accepted %+v", c.st)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("%v, want %q", err, c.want)
			}
		})
	}
	// Settings are new in 0.5; a 0.4 result cannot carry them, and a later
	// minor reads them.
	r := base
	r.Schema = "otsec.adapter/0.4"
	if err := r.Validate(); err == nil || !strings.Contains(err.Error(), "new in 0.5") {
		t.Errorf("settings at 0.4: %v", err)
	}
	r.Schema = "otsec.adapter/0.6"
	if err := r.Validate(); err != nil {
		t.Errorf("settings at 0.6: %v", err)
	}
}
