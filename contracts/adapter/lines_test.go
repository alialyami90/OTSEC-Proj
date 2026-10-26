package adapter

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/register"
)

func sel751Package(t *testing.T) *register.Package {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "register", "testdata", "sel-751.json"))
	if err != nil {
		t.Fatal(err)
	}
	p, err := register.Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// replaceSegment returns r with segment i's bytes replaced by b. Later
// segments, redactions and spans move with the bytes; the hash is recomputed.
func replaceSegment(r Result, i int, b []byte) Result {
	t := r.Transcript
	sg := t.Segments[i]
	end := sg.Offset + sg.Length
	delta := int64(len(b)) - sg.Length
	data := slices.Concat(t.Data[:sg.Offset], b, t.Data[end:])
	segs := slices.Clone(t.Segments)
	segs[i].Length = int64(len(b))
	for j := i + 1; j < len(segs); j++ {
		segs[j].Offset += delta
	}
	move := func(sp *Span) {
		if sp.Offset >= end {
			sp.Offset += delta
		}
	}
	reds := slices.Clone(t.Redactions)
	for j := range reds {
		if reds[j].Offset >= end {
			reds[j].Offset += delta
		}
	}
	r.Observations = slices.Clone(r.Observations)
	for j := range r.Observations {
		move(&r.Observations[j].Span)
	}
	r.Warnings = slices.Clone(r.Warnings)
	for j := range r.Warnings {
		move(&r.Warnings[j].Span)
	}
	r.Records = slices.Clone(r.Records)
	for j := range r.Records {
		move(&r.Records[j].Span)
		if cs := r.Records[j].ContextSpan; cs != nil {
			c := *cs
			move(&c)
			r.Records[j].ContextSpan = &c
		}
	}
	r.Identity.Items = slices.Clone(r.Identity.Items)
	for j := range r.Identity.Items {
		move(&r.Identity.Items[j].Span)
	}
	sum := sha256.Sum256(data)
	r.Transcript = Transcript{Data: data, SHA256: hex.EncodeToString(sum[:]), Segments: segs, Redactions: reds}
	return r
}

// sentSegment is the index of the first sent segment in phase ph whose bytes
// are line plus CRLF.
func sentSegment(t *testing.T, r Result, ph Phase, line string) int {
	t.Helper()
	for i, sg := range r.Transcript.Segments {
		if sg.Dir == Sent && sg.Phase == ph && string(r.Transcript.Data[sg.Offset:sg.Offset+sg.Length]) == line+"\r\n" {
			return i
		}
	}
	t.Fatalf("no sent %s line %q", ph, line)
	return -1
}

// Every valid example sends only lines the SEL-751 register permits for the
// invocation (A3 C2 review change 3).
func TestCheckLinesAcceptsExamples(t *testing.T) {
	p, inv := sel751Package(t), validInvocation(t)
	for _, f := range files(t, "results/valid") {
		n := strings.TrimSuffix(filepath.Base(f), ".json")
		r := loadResult(t, n)
		if err := r.CheckLines(p, inv); err != nil {
			t.Errorf("%s: %v", n, err)
		}
	}
}

func TestCheckLinesRefuses(t *testing.T) {
	p, inv := sel751Package(t), validInvocation(t)
	base := loadResult(t, "failed.device_error")
	ser := sentSegment(t, base, PhaseOperate, "SER")
	cases := map[string]struct {
		r    Result
		want string
	}{
		"PAS in operate":      {replaceSegment(base, ser, []byte("PAS 1 X\r\n")), "may not be sent in phase operate"},
		"SER C":               {replaceSegment(base, ser, []byte("SER C\r\n")), "may not be sent in phase operate"},
		"read not needed":     {replaceSegment(base, ser, []byte("ID\r\n")), "does not run or need"},
		"two lines":           {replaceSegment(base, ser, []byte("SER\r\nSER\r\n")), "one line with one line end"},
		"ID in auth":          {replaceSegment(base, sentSegment(t, base, PhaseAuth, "ACC"), []byte("ID\r\n")), "may not be sent in phase auth"},
		"ACC in probe":        {replaceSegment(base, sentSegment(t, base, PhaseProbe, "ID"), []byte("ACC\r\n")), "may not be sent in phase probe"},
		"register revision":   {func() Result { r := base; r.RegisterVersion = 1; return r }(), "package is revision 4"},
		"other invocation ID": {func() Result { r := base; r.InvocationID = "00000000-0000-4000-8000-000000000000"; return r }(), "is for invocation"},
	}
	// Nothing the platform sends can carry a framing or flow-control byte:
	// the egress check refuses it (A3, STX/ETX note).
	for _, b := range []byte{0x00, 0x02, 0x03, 0x11, 0x13} {
		cases["SER with byte "+hex.EncodeToString([]byte{b})] = struct {
			r    Result
			want string
		}{replaceSegment(base, ser, []byte("SER"+string(b)+"\r\n")), "not-text"}
		m, _ := register.NewMatcher(p)
		if _, _, err := m.Permit(register.PhaseOperate, "SER"+string(b)); err == nil {
			t.Errorf("egress check permits SER with byte %#x", b)
		}
	}
	for n, c := range cases {
		err := c.r.CheckLines(p, inv)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", n, err, c.want)
		}
	}
}

// A context read (C3 0.2, D3-2) is permitted only in an invocation of an
// operation it is for: SHO G reads DATE_F for SER, and is refused in a run
// of anything else (A1's condition, A6's deny case).
func TestCheckLinesContext(t *testing.T) {
	p, inv := sel751Package(t), validInvocation(t)
	if inv.OperationID != "sel.ser.read_all" || len(p.ContextFor(inv.OperationID)) != 1 {
		t.Fatalf("the SEL-751 package has no context read for %s", inv.OperationID)
	}
	base := loadResult(t, "failed.device_error")
	shoG := replaceSegment(base, sentSegment(t, base, PhaseOperate, "SER"), []byte("SHO G\r\n"))
	if err := shoG.CheckLines(p, inv); err != nil {
		t.Errorf("SHO G in a SER run: %v", err)
	}
	other := *p
	other.Context = slices.Clone(p.Context)
	other.Context[0].For = []string{"sel.settings.show_port1"}
	if err := shoG.CheckLines(&other, inv); err == nil || !strings.Contains(err.Error(), "does not run or need") {
		t.Errorf("SHO G for another operation's context: %v", err)
	}
}

// A setting comes from the reply to the context read that names it (A4 on
// #164): a span that selects the same bytes elsewhere in the transcript, or
// a setting no context read names, is refused, though Validate passes both.
func TestCheckLinesSettingProvenance(t *testing.T) {
	p, inv := sel751Package(t), validInvocation(t)
	base := loadResult(t, "ok")
	if err := base.CheckLines(p, inv); err != nil {
		t.Fatalf("ok: %v", err)
	}
	d := base.Transcript.Data
	at := func(needle string, after int) Span {
		i := bytes.Index(d[after:], []byte(needle))
		if i < 0 {
			t.Fatalf("no %q", needle)
		}
		return Span{Offset: int64(after + i), Length: int64(len(needle))}
	}
	ser := base.Transcript.Segments[sentSegment(t, base, PhaseOperate, "SER")]
	for n, c := range map[string]struct {
		st   Setting
		want string
	}{
		// IN101 is in a SER row, so the value matches its bytes but not
		// the reply to SHO G.
		"from the SER reply": {Setting{Name: "DATE_F", Value: "IN101", Span: at("IN101", int(ser.Offset))}, "does not lie in the reply"},
		// PHROT is a setting the SHO G reply prints, but no context read
		// names it.
		"another setting": {Setting{Name: "PHROT", Value: "ABC", Span: at("ABC", 0)}, "not a context read"},
	} {
		r := base
		r.Settings = []Setting{c.st}
		if err := r.Validate(); err != nil {
			t.Fatalf("%s: Validate: %v", n, err)
		}
		if err := r.CheckLines(p, inv); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", n, err, c.want)
		}
	}
}

// A prompt counts only at the start of a line (A3 change 4, A6 change 1).
func TestPromptOf(t *testing.T) {
	for rx, want := range map[string]string{
		"=":                      "=",
		"\r\n=":                  "=",
		"\x03=":                  "=",
		"\x03\r\n= ":             "=",
		"Level 1\r\n=>":          "=>",
		"\x03=>>":                "=>>",
		"ACC\r\nPassword: ? ":    "Password: ?",
		"\x13\x11\r\n=\x00":      "=",
		"MAXACC  :=":             "",
		"\"DEVID=":               "",
		"x=>":                    "",
		"a=>>":                   "",
		"==>":                    "",
		"":                       "",
		"SEL-751   ":             "",
		"Enter Password: ?":      "",
		"\r\nPassword: ?\r\n":    "",
		"Level 1\r\n=>\r\nmore=": "",
	} {
		if got := promptOf([]byte(rx)); got != want {
			t.Errorf("%q: prompt %q, want %q", rx, got, want)
		}
	}
}

// A record was received with the segment that holds its last byte (A4 C2
// review change 5).
func TestReceivedAt(t *testing.T) {
	r := loadResult(t, "ok")
	rec := r.Records[0]
	var want string
	for _, sg := range r.Transcript.Segments {
		if rec.Span.Offset >= sg.Offset && rec.Span.Offset < sg.Offset+sg.Length {
			want = sg.At
		}
	}
	if got := r.Transcript.ReceivedAt(rec.Span); got == "" || got != want {
		t.Errorf("record received at %q, want %q", got, want)
	}
	if got := r.Transcript.ReceivedAt(Span{Offset: 0, Length: 2}); got != "" {
		t.Errorf("sent bytes received at %q", got)
	}
}

// An echo of the password is redacted wherever it is received after the
// password, not only in the auth phase (A3 change 8).
func TestEchoRedactedAfterAuthPhase(t *testing.T) {
	r := loadResult(t, "ok")
	last := len(r.Transcript.Segments) - 1
	sg := r.Transcript.Segments[last]
	old := r.Transcript.Data[sg.Offset : sg.Offset+sg.Length]
	r = replaceSegment(r, last, append(slices.Clone(old), RedactionMarker...))
	r.Transcript.Redactions = append(r.Transcript.Redactions, Redaction{
		Offset: sg.Offset + sg.Length, Length: int64(len(RedactionMarker)), Reason: RedactEcho, Component: "transport"})
	if err := r.Validate(); err != nil {
		t.Errorf("close-phase echo redaction refused: %v", err)
	}
}

// The result's target is the C1 endpoint's target (D1-24).
func TestResultCheckAgainst(t *testing.T) {
	a, _ := c1Example(t)
	inv := validInvocation(t)
	r := loadResult(t, "ok")
	if err := r.CheckAgainst(inv, a); err != nil {
		t.Fatalf("ok example refused: %v", err)
	}
	for n, f := range map[string]func(*Result, *Invocation){
		"device claimed on a simulated endpoint": func(r *Result, _ *Invocation) { r.Target = "device-observed" },
		"other invocation":                       func(r *Result, _ *Invocation) { r.InvocationID = "00000000-0000-4000-8000-000000000000" },
		"other operation":                        func(r *Result, _ *Invocation) { r.OperationID = "sel.id" },
		"endpoint not on the asset":              func(_ *Result, i *Invocation) { i.EndpointID = "port2-telnet" },
	} {
		r2, i2 := r, inv
		f(&r2, &i2)
		if err := r2.CheckAgainst(i2, a); err == nil {
			t.Errorf("%s: accepted", n)
		}
	}
}

// A setting's value is printable ASCII with no space at either end, so it
// survives a JSON round trip byte for byte (A4 on #164): a span that takes
// in the CR after DATE_F's value selects its bytes, and is still refused.
func TestSettingValuePrintable(t *testing.T) {
	r := loadResult(t, "ok")
	st := r.Settings[0]
	st.Span.Length++
	st.Value = string(r.Transcript.Data[st.Span.Offset : st.Span.Offset+st.Span.Length])
	if st.Value != "MDY\r" {
		t.Fatalf("value %q", st.Value)
	}
	r.Settings = []Setting{st}
	if err := r.Validate(); err == nil || !strings.Contains(err.Error(), "printable ASCII") {
		t.Errorf("Validate: %v", err)
	}
}
