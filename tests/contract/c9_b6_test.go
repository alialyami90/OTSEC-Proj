package contract

// C9 0.1 (#247, B2; rule sel-751-sho/1 in contracts/config/doc.go): B6's
// own cases. The replies are what B6's recording simulator prints for SHO
// (#248: Figure 7.43 from B6's transcription, the General Global Settings,
// the Port 1 defaults of Table 4.104), and the expected settings are B6's
// reading of the same bytes (testdata/c9_b6/generate.py, the simulator's
// Printed class). CheckAgainst is B2's reading. A snapshot built from B6's
// reading that CheckAgainst accepts is the two readings agreeing.
//
// The sessions are built here, not taken from contracts/config/testdata:
// for each class, the command sent, its echo, the reply framed by STX and
// ETX, and the prompt (S22 p. 7.28). Classes the simulator does not print
// (SHO L, SHO P F, SHO R, SHO F) carry one constructed setting, the same
// in every session, so they never differ.
//
// Ground truth: same-source (manual) for the replies, which are B6's
// transcription of S22; independent for the properties (a layout, a
// repeated header or a cut is not a change; a reply read as another
// command's is not a section). Evidence class: simulated. No device.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/adapter"
	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/config"
)

type c9Reply struct {
	Text      string      `json:"text"`
	Settings  [][2]string `json:"settings"`
	Changed   []string    `json:"changed"`
	Duplicate string      `json:"duplicate"`
}

func c9Replies(t *testing.T) map[string]c9Reply {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "c9_b6", "replies.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]c9Reply
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func (r c9Reply) settings() []config.Setting {
	out := make([]config.Setting, len(r.Settings))
	for i, s := range r.Settings {
		out[i] = config.Setting{Name: s[0], Value: s[1]}
	}
	return out
}

// c9Part is one class's command and reply in a built session.
type c9Part struct {
	cmd      string // the line sent; "" sends the class's own command
	text     string // the message text, inside STX and ETX
	settings []config.Setting
	absent   bool
	// spanLen, when positive, makes the section's span the first spanLen
	// bytes of text, as an adapter that cut the reply short would report.
	spanLen int
	// unended: the session ends after text, with no ETX and no prompt, as
	// when the relay stops mid-reply.
	unended bool
}

const c9Constructed = "\r\nB6CONST  := 1\r\n"

// c9Defaults is a session in which every class answers: the simulator's
// replies where it prints the class, the constructed setting elsewhere,
// Invalid Command for every class that may be absent.
func c9Defaults(t *testing.T) map[string]c9Part {
	r := c9Replies(t)
	parts := map[string]c9Part{}
	for _, cl := range config.RuleSEL751SHO.Classes {
		var p c9Part
		switch {
		case strings.HasPrefix(cl.ID, "group."):
			g := r["group"+strings.TrimPrefix(cl.ID, "group.")]
			p = c9Part{text: g.Text, settings: g.settings()}
		case cl.ID == "global":
			p = c9Part{text: r["global"].Text, settings: r["global"].settings()}
		case cl.ID == "port.1":
			p = c9Part{text: r["port1"].Text, settings: r["port1"].settings()}
		case cl.MayBeAbsent:
			p = c9Part{text: "\r\nInvalid Command\r\n", absent: true}
		default:
			p = c9Part{text: c9Constructed, settings: []config.Setting{{Name: "B6CONST", Value: "1"}}}
		}
		parts[cl.ID] = p
	}
	return parts
}

// c9Build writes the session and the snapshot of it, in the rule's order.
func c9Build(t *testing.T, parts map[string]c9Part, invocation string) (config.Snapshot, adapter.Transcript) {
	t.Helper()
	var tr adapter.Transcript
	add := func(b string, dir adapter.Direction) int64 {
		off := int64(len(tr.Data))
		tr.Data = append(tr.Data, b...)
		tr.Segments = append(tr.Segments, adapter.Segment{Offset: off, Length: int64(len(b)), Dir: dir,
			Phase: adapter.PhaseOperate, At: "2026-10-27T09:10:00Z"})
		return off
	}
	s := config.Snapshot{
		Schema: config.Contract, Kind: config.KindSnapshot, AssetID: a6Asset,
		InvocationID: invocation, OperationID: "sel.config.read_all",
		Adapter:         adapter.AdapterRef{ID: "b6-built", Version: "0.0.0"},
		RegisterVersion: 5, Target: asset.Simulated, RetrievedAt: "2026-10-27T09:10:06Z",
		Rule: config.RuleSEL751SHO.ID,
	}
	for _, cl := range config.RuleSEL751SHO.Classes {
		p, ok := parts[cl.ID]
		if !ok {
			t.Fatalf("no part for %s", cl.ID)
		}
		cmd := p.cmd
		if cmd == "" {
			cmd = cl.Command
		}
		add(cmd+"\r\n", adapter.Sent)
		// The echo, STX, the text, ETX and the prompt, received together.
		at := add(cmd+"\r\n\x02"+p.text+map[bool]string{false: "\x03\r\n=>", true: ""}[p.unended], adapter.Received)
		off := at + int64(len(cmd)+3)
		n := int64(len(p.text))
		if p.spanLen > 0 {
			n = int64(p.spanLen)
		}
		sum := sha256.Sum256(tr.Data[off : off+n])
		sec := config.Section{Command: cl.Command, Class: cl.ID, State: config.Present, Sensitive: cl.Sensitive,
			Span: adapter.Span{Offset: off, Length: n}, SHA256: hex.EncodeToString(sum[:]), Settings: p.settings}
		if p.absent {
			sec.State, sec.Settings = config.Absent, nil
		}
		s.Sections = append(s.Sections, sec)
	}
	sum := sha256.Sum256(tr.Data)
	tr.SHA256 = hex.EncodeToString(sum[:])
	s.Transcript = config.Evidence{Ref: "sha256:" + tr.SHA256, SHA256: tr.SHA256, Length: int64(len(tr.Data))}
	return s, tr
}

func c9Stored(t *testing.T, s config.Snapshot) []byte {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

const (
	c9Inv1 = "6b1f0e2a-3c4d-4e5f-8a9b-0c1d2e3f4a5b"
	c9Inv2 = "7c2a1f3b-4d5e-4f6a-9b0c-1d2e3f4a5b6c"
)

// The simulator's header for a SHO reply, as Table 7.16 prints it on the
// RID and TID lines (S22 p. 7.31; the simulator's _header).
const c9Header = "751                                       Date: 10/27/2026 Time: 09:31:08.000\r\n" +
	"FEEDER RELAY                              Time Source: Internal\r\n"

// B6's reading and B2's agree on every reply the simulator prints: Figure
// 7.43 for each group (158 settings), one setting per line, an injected
// change, a removal with an addition, the General Global Settings with a
// SELOGIC equation on its own line, and Port 1.
func TestC9B6ReadingsAgree(t *testing.T) {
	r := c9Replies(t)
	if n := len(r["group1"].Settings); n != 158 {
		t.Fatalf("Figure 7.43 reads as %d settings in B6's reading, want 158", n)
	}
	s, tr := c9Build(t, c9Defaults(t), c9Inv1)
	if err := s.CheckAgainst(tr); err != nil {
		t.Fatalf("the simulator's session: %v", err)
	}
	for _, name := range []string{"group1-one-per-line", "group1-50P1P-9.50", "group1-LL-removed-B6TEST-added"} {
		parts := c9Defaults(t)
		parts["group.1"] = c9Part{text: r[name].Text, settings: r[name].settings()}
		s, tr := c9Build(t, parts, c9Inv1)
		if err := s.CheckAgainst(tr); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// Layout, a repeated header and another invocation are not changes
// (doc.go: only settings are semantic).
func TestC9B6LayoutIsNotAChange(t *testing.T) {
	r := c9Replies(t)
	a, _ := c9Build(t, c9Defaults(t), c9Inv1)
	fig := r["group1"].Text
	at := strings.Index(fig, "LL       := 4.84\r\n") + len("LL       := 4.84\r\n")
	for name, text := range map[string]string{
		"one setting per line":              r["group1-one-per-line"].Text,
		"a header first":                    "\r\n" + c9Header + fig[2:],
		"a header right after a setting":    fig[:at] + c9Header + fig[at:],
		"a header in the one-per-line form": "\r\n" + c9Header + r["group1-one-per-line"].Text[2:],
	} {
		parts := c9Defaults(t)
		parts["group.1"] = c9Part{text: text, settings: r["group1"].settings()}
		if name == "one setting per line" || name == "a header in the one-per-line form" {
			parts["group.1"] = c9Part{text: text, settings: r["group1-one-per-line"].settings()}
		}
		b, tr := c9Build(t, parts, c9Inv2)
		if err := b.CheckAgainst(tr); err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		d, err := config.Compare(c9Stored(t, a), c9Stored(t, b))
		if err != nil {
			t.Errorf("%s: %v", name, err)
		} else if len(d.Changes) != 0 {
			t.Errorf("%s: %d changes, want none: %+v", name, len(d.Changes), d.Changes)
		}
	}
}

// A change the injector made is exactly that change, and nothing else.
func TestC9B6InjectedChangeIsThatChange(t *testing.T) {
	r := c9Replies(t)
	a, _ := c9Build(t, c9Defaults(t), c9Inv1)
	str := func(p *string) string {
		if p == nil {
			return "<none>"
		}
		return *p
	}
	for name, want := range map[string][]string{
		"group1-50P1P-9.50":              {"group.1 changed 50P1P 10.00 9.50"},
		"group1-LL-removed-B6TEST-added": {"group.1 added B6TEST <none> 7", "group.1 removed LL 4.84 <none>"},
	} {
		parts := c9Defaults(t)
		parts["group.1"] = c9Part{text: r[name].Text, settings: r[name].settings()}
		b, _ := c9Build(t, parts, c9Inv2)
		d, err := config.Compare(c9Stored(t, a), c9Stored(t, b))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var got []string
		for _, c := range d.Changes {
			got = append(got, strings.Join([]string{c.Class, string(c.Kind), c.Name, str(c.From), str(c.To)}, " "))
		}
		if strings.Join(got, "\n") != strings.Join(want, "\n") {
			t.Errorf("%s: changes\n%s\nwant\n%s", name, strings.Join(got, "\n"), strings.Join(want, "\n"))
		}
	}
}

// A reply that prints a setting twice is no snapshot, whichever settings
// an adapter reports for it.
func TestC9B6DuplicateIsNoSnapshot(t *testing.T) {
	r := c9Replies(t)
	dup := r["group1-duplicate"]
	fig := r["group1"].settings()
	withLater := append([]config.Setting(nil), fig...)
	twice := append([]config.Setting(nil), fig...)
	for i, s := range fig {
		if s.Name == dup.Duplicate {
			withLater[i].Value = "2.50"
			twice = append(twice[:i+1:i+1], append([]config.Setting{{Name: s.Name, Value: "2.50"}}, fig[i+1:]...)...)
		}
	}
	for name, settings := range map[string][]config.Setting{
		"the first printing": fig, "the second printing": withLater, "both printings": twice,
	} {
		parts := c9Defaults(t)
		parts["group.1"] = c9Part{text: dup.Text, settings: settings}
		s, tr := c9Build(t, parts, c9Inv1)
		if err := s.CheckAgainst(tr); err == nil {
			t.Errorf("%s: a reply printing %s twice was accepted", name, dup.Duplicate)
		}
	}
}

// A section is the reply to its own class's command (doc.go: "what the
// relay sent after it echoed the command line"). A reply to another
// command, here SHO 1 sent again where SHO 2 belongs, is not Group 2's
// settings, even when its bytes tokenize.
func TestC9B6SectionIsItsOwnCommandsReply(t *testing.T) {
	r := c9Replies(t)
	parts := c9Defaults(t)
	parts["group.2"] = c9Part{cmd: "SHO 1", text: r["group1"].Text, settings: r["group1"].settings()}
	s, tr := c9Build(t, parts, c9Inv1)
	if err := s.CheckAgainst(tr); err == nil {
		t.Error("group.2 read from the reply to SHO 1 was accepted")
	}
}

// A section is the whole reply, up to the ETX and prompt (doc.go: "before
// the next prompt"). A span an adapter ends early, or a reply the relay
// never finished, drops settings, which a later complete read would report
// as added: neither is a section.
func TestC9B6SectionIsTheWholeReply(t *testing.T) {
	r := c9Replies(t)
	cut := r["group1-cut"]
	parts := c9Defaults(t)
	parts["group.1"] = c9Part{text: r["group1"].Text, settings: cut.settings(), spanLen: len(cut.Text)}
	s, tr := c9Build(t, parts, c9Inv1)
	if err := s.CheckAgainst(tr); err == nil {
		t.Errorf("a span ending at %d of the reply's %d bytes, %d of 158 settings, was accepted", len(cut.Text), len(r["group1"].Text), len(cut.Settings))
	}
	// The last class of the session, so nothing follows the cut.
	last := config.RuleSEL751SHO.Classes[len(config.RuleSEL751SHO.Classes)-1].ID
	parts = c9Defaults(t)
	parts[last] = c9Part{text: cut.Text, settings: cut.settings(), unended: true}
	s, tr = c9Build(t, parts, c9Inv1)
	if err := s.CheckAgainst(tr); err == nil {
		t.Error("a reply with no ETX and no prompt after it, the session's last, was accepted")
	}
}

// A free-text value is a value whatever its words (doc.go: a header is the
// command-response header). TID printed as "Time Source: GPS" is a
// setting; reading the line as a header drops TID from the snapshot.
func TestC9B6FreeTextIsNotAHeader(t *testing.T) {
	r := c9Replies(t)
	for _, v := range []string{"Time Source: GPS", "Date: 10/27/2026 Time: 09:31"} {
		parts := c9Defaults(t)
		g := r["group1"]
		settings := g.settings()
		for i := range settings {
			if settings[i].Name == "TID" {
				settings[i].Value = v
			}
		}
		parts["group.1"] = c9Part{text: strings.Replace(g.Text, "TID      := FEEDER RELAY", "TID      := "+v, 1), settings: settings}
		s, tr := c9Build(t, parts, c9Inv1)
		if err := s.CheckAgainst(tr); err != nil {
			t.Errorf("TID %q: %v", v, err)
		}
	}
}
