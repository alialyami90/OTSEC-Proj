package syslog

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/event"
)

var update = flag.Bool("update", false, "rewrite testdata/rendered from Render")

func loadTarget(t *testing.T, name string) *Target {
	t.Helper()
	b, err := os.ReadFile("testdata/targets/valid/" + name + ".json")
	if err != nil {
		t.Fatal(err)
	}
	tg, err := ParseTarget(b)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return tg
}

func loadEvent(t *testing.T, name string) *event.Event {
	t.Helper()
	b, err := os.ReadFile("../event/testdata/valid/" + name + ".json")
	if err != nil {
		t.Fatal(err)
	}
	e, err := event.Decode(b)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return e
}

func TestValidTargets(t *testing.T) {
	want := map[string]struct {
		mode     Mode
		insecure bool
	}{
		"relp-tls-required":      {ModeA, false},
		"relp-plain-best-effort": {ModeA, true},
		"tls-best-effort":        {ModeB, false},
		"tcp-lf-insecure":        {ModeB, true},
		"udp-rfc3164":            {ModeB, true},
		"relp-tls-audit":         {ModeA, false},
	}
	files, _ := filepath.Glob("testdata/targets/valid/*.json")
	if len(files) != len(want) {
		t.Fatalf("%d valid targets, %d expectations", len(files), len(want))
	}
	for name, w := range want {
		tg := loadTarget(t, name)
		if tg.Mode() != w.mode || tg.Insecure() != w.insecure {
			t.Errorf("%s: mode %s insecure %v, want %s %v", name, tg.Mode(), tg.Insecure(), w.mode, w.insecure)
		}
	}
}

var invalidTargets = map[string]Code{
	"required-on-tls":                    CodeRequiredClass,
	"required-on-tcp":                    CodeRequiredClass,
	"required-on-udp":                    CodeRequiredClass,
	"required-on-relp":                   CodeRequiredClass,
	"tls-lf-framing":                     CodeFraming,
	"udp-octet-counting":                 CodeFraming,
	"size-below-floor":                   CodeSize,
	"rfc3164-over-1024":                  CodeSize,
	"relp-tls-without-tls":               CodeTLS,
	"tcp-with-tls":                       CodeTLS,
	"mode-b-without-replay":              CodeDelivery,
	"required-with-replay":               CodeDelivery,
	"misspelt-class":                     CodeUnknownField,
	"case-variant-class":                 CodeUnknownField,
	"other-major":                        CodeSchema,
	"unknown-transport":                  CodeEnum,
	"audit-over-udp":                     CodeAudit,
	"audit-over-tls":                     CodeAudit,
	"audit-target-too-small":             CodeAudit,
	"required-without-client-credential": CodeTLS,
	"required-without-durable-ack":       CodeDelivery,
	"malformed-spki-pin":                 CodeTLS,
	"insecure-without-acknowledgement":   CodeAck,
	"acknowledgement-production-scope":   CodeAck,
	"acknowledgement-on-tls":             CodeAck,
}

func TestInvalidTargets(t *testing.T) {
	files, _ := filepath.Glob("testdata/targets/invalid/*.json")
	if len(files) != len(invalidTargets) {
		t.Fatalf("%d invalid targets, %d expectations", len(files), len(invalidTargets))
	}
	for _, f := range files {
		name := strings.TrimSuffix(filepath.Base(f), ".json")
		want, ok := invalidTargets[name]
		if !ok {
			t.Errorf("%s: no expectation", name)
			continue
		}
		b, _ := os.ReadFile(f)
		_, err := ParseTarget(b)
		// Each file breaks one rule, so it fails with that code alone. An
		// unknown transport also cannot be required.
		got := Codes(err)
		only := slices.Equal(got, []Code{want}) || (name == "unknown-transport" && slices.Equal(got, []Code{CodeEnum, CodeRequiredClass}))
		if !only {
			t.Errorf("%s: codes %v, want only %s (%v)", name, got, want, err)
		}
	}
}

// Acceptance: a required target on any transport other than RELP over TLS
// is rejected. Each transport starts from a target that is valid for it as
// best-effort, so the class is the only thing that changes.
func TestRequiredOnlyOnRELPTLS(t *testing.T) {
	starts := map[Transport]string{
		TransportRELPTLS: "relp-tls-required",
		TransportRELP:    "relp-plain-best-effort",
		TransportTLS:     "tls-best-effort",
		TransportTCP:     "tcp-lf-insecure",
		TransportUDP:     "udp-rfc3164",
	}
	for tr, name := range starts {
		tg := loadTarget(t, name)
		tg.Class = ClassRequired
		err := tg.Validate()
		rejected := slices.Contains(Codes(err), CodeRequiredClass)
		if rejected != (tr != TransportRELPTLS) {
			t.Errorf("required on %s: rejected %v (%v)", tr, rejected, err)
		}
	}
}

// A1 D1-15: the audit stream goes only to a required relp-tls target. Every
// valid target of another transport is refused when it is given audit, even
// with room for a whole record.
func TestAuditOnlyOnRequiredRELPTLS(t *testing.T) {
	for _, name := range []string{"relp-tls-required", "relp-plain-best-effort", "tls-best-effort", "tcp-lf-insecure", "udp-rfc3164"} {
		tg := loadTarget(t, name)
		tg.Audit, tg.Format = true, FormatRFC5424
		tg.MaxMessageOctets = MinAuditOctets
		err := tg.Validate()
		rejected := slices.Contains(Codes(err), CodeAudit)
		if rejected != (tg.Transport != TransportRELPTLS) {
			t.Errorf("audit on %s: rejected %v (%v)", tg.Transport, rejected, err)
		}
	}
	tg := loadTarget(t, "relp-tls-audit")
	tg.Class = ClassBestEffort
	if !slices.Contains(Codes(tg.Validate()), CodeAudit) {
		t.Error("a best-effort audit target validated")
	}
	tg = loadTarget(t, "relp-tls-audit")
	tg.MaxMessageOctets = MinAuditOctets - 1
	if !slices.Contains(Codes(tg.Validate()), CodeAudit) {
		t.Error("an audit target one octet too small validated")
	}
}

// TestSchemaMatchesTarget keeps schema/target.json and the Go types in step.
func TestSchemaMatchesTarget(t *testing.T) {
	b, err := os.ReadFile("schema/target.json")
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err := json.Unmarshal(b, &root); err != nil {
		t.Fatal(err)
	}
	compare(t, "target", reflect.TypeOf(Target{}), root)
	tls, _ := root["properties"].(map[string]any)["tls"].(map[string]any)
	compare(t, "tls", reflect.TypeOf(TLSConfig{}), tls)
}

func compare(t *testing.T, path string, typ reflect.Type, node map[string]any) {
	t.Helper()
	props, _ := node["properties"].(map[string]any)
	var goNames, goRequired, schemaNames, schemaRequired []string
	for i := 0; i < typ.NumField(); i++ {
		name, opts, _ := strings.Cut(typ.Field(i).Tag.Get("json"), ",")
		goNames = append(goNames, name)
		if !strings.Contains(opts, "omitempty") {
			goRequired = append(goRequired, name)
		}
	}
	for k := range props {
		schemaNames = append(schemaNames, k)
	}
	for _, r := range node["required"].([]any) {
		schemaRequired = append(schemaRequired, r.(string))
	}
	for _, s := range [][]string{goNames, goRequired, schemaNames, schemaRequired} {
		sort.Strings(s)
	}
	if !reflect.DeepEqual(goNames, schemaNames) || !reflect.DeepEqual(goRequired, schemaRequired) {
		t.Errorf("%s: Go %v required %v; schema %v required %v", path, goNames, goRequired, schemaNames, schemaRequired)
	}
	if node["additionalProperties"] != false {
		t.Errorf("%s: schema is not strict", path)
	}
}

// Golden renderings: each file is Render's output for one C4 example on one
// target, frozen. testdata/NOTES.md says how they were checked.
var goldens = []struct{ file, event, target string }{
	{"sel751-row8.rfc5424.txt", "sel751-fig10-16-row8", "tls-best-effort"},
	{"sel751-row8.rfc3164.txt", "sel751-fig10-16-row8", "udp-rfc3164"},
	{"rtac-syslog.rfc5424.txt", "rtac-syslog-user-logon", "relp-tls-required"},
	{"health-ser-gap.rfc5424.txt", "health-ser-gap", "relp-tls-required"},
	{"constructed-invalid-date.rfc5424.txt", "constructed-invalid-date", "tls-best-effort"},
}

func TestGoldenRenderings(t *testing.T) {
	for _, g := range goldens {
		got, _, err := Render(loadEvent(t, g.event), loadTarget(t, g.target))
		if err != nil {
			t.Fatalf("%s: %v", g.file, err)
		}
		path := "testdata/rendered/" + g.file
		if *update {
			if err := os.WriteFile(path, got, 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		want, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s:\n got %s\nwant %s", g.file, got, want)
		}
	}
}

// Every C4 example on every target renders within the limit, reads back,
// carries its event ID, and returns the device bytes exactly when it keeps
// them.
func TestRenderReadBack(t *testing.T) {
	events, _ := filepath.Glob("../event/testdata/valid/*.json")
	targets, _ := filepath.Glob("testdata/targets/valid/*.json")
	for _, ef := range events {
		e := loadEvent(t, strings.TrimSuffix(filepath.Base(ef), ".json"))
		for _, tf := range targets {
			tg := loadTarget(t, strings.TrimSuffix(filepath.Base(tf), ".json"))
			msg, out, err := Render(e, tg)
			if err != nil {
				t.Errorf("%s on %s: %v", ef, tf, err)
				continue
			}
			if err := CheckMessage(msg, tg); err != nil {
				t.Errorf("%s on %s: %v", ef, tf, err)
				continue
			}
			m, _ := ParseMessage(msg)
			if eid, _ := m.Get("eid"); eid != e.ID.String() {
				t.Errorf("%s: eid %q", ef, eid)
			}
			if rcv, _ := m.Get("rcv"); rcv != e.Received.UTC {
				t.Errorf("%s: rcv %q", ef, rcv)
			}
			text, ok := m.DeviceText()
			switch {
			case e.Native == nil || e.Native.Bytes == nil:
				if ok {
					t.Errorf("%s: device text without native bytes", ef)
				}
			case !tg.SendsDeviceContent():
				if v, _ := m.Get("content_omitted"); ok || v != OmitConfig || out.TextOmitted {
					t.Errorf("%s on %s: device content off by configuration not marked (%q, %+v)", ef, tf, v, out)
				}
			case out.TextOmitted:
				if v, _ := m.Get("dtext_omitted"); ok || v != OmitSize {
					t.Errorf("%s on %s: omission not marked", ef, tf)
				}
			case !bytes.Equal(text, e.Native.Bytes):
				t.Errorf("%s on %s: device text %q", ef, tf, text)
			}
		}
	}
}

func TestHeaderTimestampAtMostSixDigits(t *testing.T) {
	e := loadEvent(t, "health-ser-gap")
	e.Received.UTC, e.Received.ResolutionNS = "2026-10-24T12:05:05.123456789Z", 1
	msg, _, err := Render(e, loadTarget(t, "relp-tls-required"))
	if err != nil {
		t.Fatal(err)
	}
	m, _ := ParseMessage(msg)
	if m.Timestamp != "2026-10-24T12:05:05.123456Z" {
		t.Errorf("TIMESTAMP %q", m.Timestamp)
	}
	if rcv, _ := m.Get("rcv"); rcv != e.Received.UTC {
		t.Errorf("rcv %q", rcv)
	}
}

// withBytes returns the RTAC example carrying b as its record (and its
// whole evidence), and s as its normalized subject.
func withBytes(t *testing.T, b []byte, subject string) *event.Event {
	e := loadEvent(t, "rtac-syslog-user-logon")
	sum := sha256.Sum256(b)
	h := hex.EncodeToString(sum[:])
	e.Native.Bytes, e.Native.RecordSHA256, e.Native.RecordLength = b, h, int64(len(b))
	e.Native.Evidence.SHA256, e.Native.Evidence.Length, e.Native.Evidence.Ref = h, int64(len(b)), ""
	e.Native.Span = &event.Span{Offset: 0, Length: int64(len(b))}
	e.Normalized.Subject = subject
	if err := e.Validate(); err != nil {
		t.Fatal(err)
	}
	return e
}

// Hostile device content (A3 AP-20, E-A4-02, E-A4-04): whatever the device
// sends, the result is exactly one message, it reads back with the same
// device bytes and subject, and LF framing cannot be split.
func TestHostileContent(t *testing.T) {
	cases := map[string]string{
		"lf injection":         "x\n<13>1 2026-10-24T00:00:00Z forged otsec - SER [otsec@32473 eid=\"forged\"] forged",
		"crlf":                 "line\r\nline",
		"nul":                  "a\x00b",
		"sd escape":            `"] [fake@1 a="b"] \`,
		"bom":                  "\ufeff<13>forged",
		"invalid utf-8":        "\xff\xfe\x80",
		"line separator":       "a\u2028b",
		"c1 control":           "a\u0085b",
		"backslashes":          `\\\"\]`,
		"looks like a summary": "] ser 51P1P Asserted",
		// Format characters and noncharacters travel as base64 (C6-A3-6,
		// C6-A6-3): they cannot forge structure, but they can reorder or
		// hide what an analyst reads.
		"right-to-left override": "TRIP\u202eDENEPO",
		"isolate":                "x\u2066y\u2069",
		"zero width space":       "a\u200bb",
		"left-to-right mark":     "a\u200eb",
		"noncharacter":           "a\ufffeb",
	}
	on := true
	for _, target := range []string{"tcp-lf-insecure", "udp-rfc3164", "relp-tls-required"} {
		tg := loadTarget(t, target)
		tg.DeviceContent = &on // escaping is what is under test
		for name, s := range cases {
			e := withBytes(t, []byte(s), s)
			msg, out, err := Render(e, tg)
			if err != nil {
				t.Fatalf("%s on %s: %v", name, target, err)
			}
			if bytes.ContainsAny(msg, "\n\r\x00") {
				t.Fatalf("%s on %s: control byte in %q", name, target, msg)
			}
			if _, err := Frame(msg, FramingNonTransparent); err != nil {
				t.Errorf("%s: %v", name, err)
			}
			m, err := ParseMessage(msg)
			if err != nil {
				t.Fatalf("%s on %s: %v (%q)", name, target, err, msg)
			}
			if text, ok := m.DeviceText(); !out.TextOmitted && (!ok || !bytes.Equal(text, []byte(s))) {
				t.Errorf("%s on %s: device text %q", name, target, text)
			}
			subj, ok := m.Get("subj")
			if b64, ok64 := m.Get("subj_b64"); ok64 {
				subj, ok = decodeB64(t, b64), true
			}
			if !ok || subj != s {
				t.Errorf("%s on %s: subject %q", name, target, subj)
			}
			if len(m.All("eid")) != 1 {
				t.Errorf("%s on %s: %d eid parameters", name, target, len(m.All("eid")))
			}
			if strings.Contains(m.Summary, s) {
				t.Errorf("%s on %s: hostile subject in MSG %q", name, target, m.Summary)
			}
		}
	}
}

func decodeB64(t *testing.T, s string) string {
	m := &Message{Params: []Param{{"dtext_b64", s}}}
	b, ok := m.DeviceText()
	if !ok {
		t.Fatalf("bad base64 %q", s)
	}
	return string(b)
}

// Acceptance: a message over the limit is reduced only by the profile's
// steps, in order, and is never split or cut.
func TestOversize(t *testing.T) {
	big := bytes.Repeat([]byte("A"), 3000)
	e := withBytes(t, big, "SystemTags. User_Logged_On")
	on := true
	for _, name := range []string{"tls-best-effort", "udp-rfc3164"} {
		tg := loadTarget(t, name)
		tg.DeviceContent = &on // the size steps apply to text the target sends
		for _, limit := range []int{tg.MaxMessageOctets, 1024, 900, 700} {
			tg.MaxMessageOctets = limit
			msg, out, err := Render(e, tg)
			if err != nil {
				if !slices.Contains(Codes(err), CodeTooLarge) {
					t.Errorf("%s at %d: %v", name, limit, err)
				}
				continue
			}
			if len(msg) > limit {
				t.Errorf("%s at %d: %d octets", name, limit, len(msg))
			}
			m, err := ParseMessage(msg)
			if err != nil {
				t.Fatalf("%s at %d: %v", name, limit, err)
			}
			if !out.TextOmitted {
				t.Errorf("%s at %d: 3000-octet text not omitted", name, limit)
			}
			if v, _ := m.Get("dtext_omitted"); v != OmitSize {
				t.Errorf("%s at %d: no dtext_omitted=size", name, limit)
			}
			// Identity, time and the record's hash survive every step.
			for _, p := range []string{"eid", "rcv", "rsha256", "rlen", "origin", "auth"} {
				if _, ok := m.Get(p); !ok {
					t.Errorf("%s at %d: %s cut", name, limit, p)
				}
			}
			if out.SummaryDropped != (m.Summary == "") {
				t.Errorf("%s at %d: SummaryDropped %v, summary %q", name, limit, out.SummaryDropped, m.Summary)
			}
		}
	}
	// A summary is dropped only after the text.
	tg := loadTarget(t, "tls-best-effort")
	full, _, _ := Render(e, tg)
	noText, _ := assemble(e, tg, params(e, OmitSize, true), summary(e, true))
	tg.MaxMessageOctets = len(noText) - 1
	msg, out, err := Render(e, tg)
	if err != nil || !out.TextOmitted || !out.SummaryDropped || len(msg) > tg.MaxMessageOctets || len(full) <= len(msg) {
		t.Errorf("summary step: %v %+v %d", err, out, len(msg))
	}
	// When the fixed fields alone do not fit, Render fails rather than cut.
	g := loadEvent(t, "health-ser-gap")
	g.Health.Details["reason"] = strings.Repeat("r", 600)
	tg = loadTarget(t, "relp-tls-required")
	tg.MaxMessageOctets = MinMaxOctets
	if _, _, err := Render(g, tg); !slices.Contains(Codes(err), CodeTooLarge) {
		t.Errorf("fixed fields over the limit: %v", err)
	}
}

func TestRenderRejectsInvalidInput(t *testing.T) {
	e := loadEvent(t, "sel751-fig10-16-row8")
	e.ID.Seq = 0
	if _, _, err := Render(e, loadTarget(t, "tls-best-effort")); !slices.Contains(Codes(err), CodeEventInvalid) {
		t.Errorf("pending event: %v", err)
	}
	tg := loadTarget(t, "tls-best-effort")
	tg.Class = ClassRequired
	if _, _, err := Render(loadEvent(t, "sel751-fig10-16-row8"), tg); !slices.Contains(Codes(err), CodeRequiredClass) {
		t.Errorf("invalid target: %v", err)
	}
}

func TestFrame(t *testing.T) {
	msg := []byte("<133>1 x")
	if got, _ := Frame(msg, FramingOctetCounting); string(got) != "8 <133>1 x" {
		t.Errorf("octet counting %q", got)
	}
	if got, _ := Frame(msg, FramingNonTransparent); string(got) != "<133>1 x\n" {
		t.Errorf("LF %q", got)
	}
	for _, bad := range []string{"a\nb", "a\x00b"} {
		if _, err := Frame([]byte(bad), FramingNonTransparent); !slices.Contains(Codes(err), CodeFrameUnsafe) {
			t.Errorf("%q: %v", bad, err)
		}
	}
	if _, err := Frame(msg, FramingRELP); err == nil {
		t.Error("RELP framing accepted by Frame")
	}
	if got, _ := FrameRELP(7, msg); string(got) != "7 syslog 8 <133>1 x\n" {
		t.Errorf("RELP %q", got)
	}
	if _, err := FrameRELP(0, msg); err == nil {
		t.Error("TXNR 0 accepted")
	}
}

// The TB5 grammar: what a collector may send back, and nothing else.
func TestParseRELPResponse(t *testing.T) {
	out := func(n uint64) bool { return n == 1 || n == 2 || n == 3 }
	ok := []struct {
		in   string
		want RELPResponse
		used int
	}{
		{"2 rsp 6 200 OK\n", RELPResponse{TXNR: 2, OK: true}, 15},
		{"3 rsp 9 500 error\n", RELPResponse{TXNR: 3}, 18},
		{"0 serverclose 0\n", RELPResponse{Close: true}, 16},
		{"1 rsp 37 200 OK\nrelp_version=0\ncommands=syslog\n", RELPResponse{TXNR: 1, OK: true, Data: []byte("relp_version=0\ncommands=syslog")}, 47},
		{"2 rsp 6 200 OK\n3 rsp 6 200 OK\n", RELPResponse{TXNR: 2, OK: true}, 15},
	}
	for _, c := range ok {
		got, used, err := ParseRELPResponse([]byte(c.in), out)
		if err != nil || used != c.used || got.TXNR != c.want.TXNR || got.OK != c.want.OK || got.Close != c.want.Close || !bytes.Equal(got.Data, c.want.Data) {
			t.Errorf("%q: got %+v used %d err %v", c.in, got, used, err)
		}
	}
	for _, in := range []string{"", "2", "2 ", "2 rs", "2 rsp 6", "2 rsp 6 200 O", "2 rsp 6 200 OK"} {
		if _, _, err := ParseRELPResponse([]byte(in), out); !errors.Is(err, ErrIncomplete) {
			t.Errorf("%q: %v, want incomplete", in, err)
		}
	}
	bad := []string{
		"9 rsp 6 200 OK\n",                               // not outstanding
		"0 rsp 6 200 OK\n",                               // rsp for TXNR 0
		"2 syslog 6 200 OK\n",                            // a command the node never accepts
		"2 RSP 6 200 OK\n",                               // case
		"02 rsp 6 200 OK\n",                              // leading zero
		"1234567890 rsp 6 200 OK\n",                      // TXNR over 9 digits
		"2 rsp 4097 " + strings.Repeat("x", 4097) + "\n", // DATALEN over the bound
		"2 rsp 99999 x",                                  // DATALEN over 4 digits
		"2 rsp 6 200 OKx",                                // no LF after DATA
		"2 rsp 6 201 OK\n",                               // unknown status
		"2 rsp 3 200\n",                                  // 200 without OK
		"2 rsp 6 200 OX\n",                               // 200 without OK
		"2 rsp 0\n",                                      // rsp without status
		"1 serverclose 0\n",                              // serverclose with a TXNR
		"0 serverclose 2 xx\n",                           // serverclose with data
		"2  rsp 6 200 OK\n",                              // double space
		"x rsp 6 200 OK\n",                               // no TXNR
		"2 serverclosex 0\n",                             // command too long
	}
	for _, in := range bad {
		if _, _, err := ParseRELPResponse([]byte(in), out); !slices.Contains(Codes(err), CodeRELPViolation) {
			t.Errorf("%q: %v, want violation", in, err)
		}
	}
	if _, _, err := ParseRELPResponse([]byte("2 rsp 6 200 OK\n"), nil); !slices.Contains(Codes(err), CodeRELPViolation) {
		t.Error("rsp accepted with no outstanding transactions")
	}
}

// Every format character and noncharacter fails printable, so it never
// travels as escaped text.
func TestPrintableRejectsFormatAndNoncharacters(t *testing.T) {
	for _, r := range []rune{0x200b, 0x200e, 0x200f, 0x202a, 0x202e, 0x2066, 0x2069, 0xfeff, 0xfffe, 0xffff, 0xfdd0, 0x1fffe, 0x00ad} {
		if printable("a" + string(r) + "b") {
			t.Errorf("U+%04X is printable", r)
		}
	}
	for _, ok := range []string{"51P1P Asserted", "Überstrom", "電流", "a b"} {
		if !printable(ok) {
			t.Errorf("%q is not printable", ok)
		}
	}
}

// C6-A3-2: required and audit targets authenticate the node.
func TestMutualTLSOnRequiredAndAudit(t *testing.T) {
	for _, name := range []string{"relp-tls-required", "relp-tls-audit"} {
		tg := loadTarget(t, name)
		tg.TLS.ClientCredentialRef = ""
		if !slices.Contains(Codes(tg.Validate()), CodeTLS) {
			t.Errorf("%s without a client key validated", name)
		}
	}
	tg := loadTarget(t, "tls-best-effort")
	if tg.TLS.ClientCredentialRef != "" || tg.Validate() != nil {
		t.Error("a best-effort tls target should validate without a client key")
	}
	tg.TLS.SPKIPins = []string{"47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="}
	if err := tg.Validate(); err != nil {
		t.Errorf("a well-formed pin: %v", err)
	}
	tg = loadTarget(t, "tls-best-effort")
	tg.DurableAck = &DurableAck{VerifiedUTC: "2026-10-24T09:00:00Z", EvidenceRef: "x"}
	if !slices.Contains(Codes(tg.Validate()), CodeDelivery) {
		t.Error("durable_ack on a best-effort target validated")
	}
}

// The mode A cursor rule (C6-A3-1, C6-A1-1).
func TestWindow(t *testing.T) {
	ok := func(n uint64) RELPResponse { return RELPResponse{TXNR: n, OK: true} }
	open := RELPResponse{TXNR: 1, OK: true, Data: []byte("relp_version=0\nrelp_software=x\ncommands=syslog")}

	w := NewWindow(8, 1)
	if err := w.Send(2); !errors.Is(err, ErrBadOpen) {
		t.Fatalf("send before open answered: %v", err)
	}
	if adv, err := w.Answer(open); adv != 0 || err != nil {
		t.Fatalf("open: %d %v", adv, err)
	}
	for n := uint64(2); n <= 4; n++ {
		if err := w.Send(n); err != nil {
			t.Fatal(err)
		}
	}
	// An OK for 4 while 2 and 3 are in flight advances nothing.
	if adv, err := w.Answer(ok(4)); adv != 0 || err != nil {
		t.Fatalf("ok 4 first: %d %v", adv, err)
	}
	// A second response for 4 is a violation, not a second acknowledgement.
	if _, _, err := ParseRELPResponse([]byte("4 rsp 6 200 OK\n"), w.Outstanding); !slices.Contains(Codes(err), CodeRELPViolation) {
		t.Fatalf("repeated response for 4: %v", err)
	}
	if adv, _ := w.Answer(ok(2)); adv != 2 {
		t.Fatalf("ok 2: advance %d, want 2", adv)
	}
	if adv, _ := w.Answer(ok(3)); adv != 4 {
		t.Fatalf("ok 3: advance %d, want 4 (3 and the earlier 4)", adv)
	}

	// A 500 for the earliest outstanding transaction ends the session and
	// advances nothing, even after a later OK.
	w = NewWindow(8, 1)
	w.Answer(open)
	w.Send(2)
	w.Send(3)
	if adv, _ := w.Answer(ok(3)); adv != 0 {
		t.Fatal("ok 3 before 2 advanced")
	}
	if adv, err := w.Answer(RELPResponse{TXNR: 2}); adv != 0 || !errors.Is(err, ErrRefused) {
		t.Fatalf("500 for 2: %d %v", adv, err)
	}
	if err := w.Send(4); !errors.Is(err, ErrRefused) {
		t.Fatalf("send after refusal: %v", err)
	}

	// serverclose ends the session.
	w = NewWindow(8, 1)
	w.Answer(open)
	w.Send(2)
	if _, err := w.Answer(RELPResponse{Close: true}); !errors.Is(err, ErrSessionClosed) {
		t.Fatalf("serverclose: %v", err)
	}

	// The open must offer syslog.
	for _, data := range []string{"relp_version=0", "commands=syslogx", "commands=", ""} {
		w = NewWindow(8, 1)
		if _, err := w.Answer(RELPResponse{TXNR: 1, OK: true, Data: []byte(data)}); !errors.Is(err, ErrBadOpen) {
			t.Errorf("open offers %q: %v", data, err)
		}
	}
	w = NewWindow(8, 1)
	if _, err := w.Answer(RELPResponse{TXNR: 1, OK: true, Data: []byte("commands=foo,syslog")}); err != nil {
		t.Errorf("syslog in a list: %v", err)
	}

	// The window bounds frames in flight.
	w = NewWindow(2, 1)
	w.Answer(open)
	w.Send(2)
	w.Send(3)
	if err := w.Send(4); !errors.Is(err, ErrWindowFull) {
		t.Fatalf("third frame in a window of 2: %v", err)
	}
}

// C6-A1-3: a buffer of MaxRELPFrameLen octets is never incomplete, so a
// caller that buffers no more than that per frame is bounded.
func TestRELPFrameBound(t *testing.T) {
	all := func(uint64) bool { return true }
	longest := "999999999 rsp 4096 200 OK\n" + strings.Repeat("x", 4096-7) + "\n"
	if len(longest) != MaxRELPFrameLen-len("serverclose")+len("rsp") {
		t.Fatalf("longest rsp is %d octets", len(longest))
	}
	if _, used, err := ParseRELPResponse([]byte(longest), all); err != nil || used != len(longest) {
		t.Fatalf("longest rsp: used %d, %v", used, err)
	}
	for _, prefix := range []string{"999999999 rsp 4096 ", "1 ", "1 rsp 5 ", ""} {
		buf := []byte(prefix + strings.Repeat("y", MaxRELPFrameLen))[:MaxRELPFrameLen]
		if _, _, err := ParseRELPResponse(buf, all); errors.Is(err, ErrIncomplete) {
			t.Errorf("%q padded to %d octets is incomplete", prefix, MaxRELPFrameLen)
		}
	}
}

// A1 D1-22 and its amendment: an insecure target carries an
// acknowledgement and, unless an admin turned it on, no device content; a
// secure target sends device content unless turned off.
func TestInsecureTargetsAcknowledgedAndContentOff(t *testing.T) {
	e := loadEvent(t, "sel751-fig10-16-row8")
	off, on := false, true
	content := []string{"dtext", "dtext_b64", "subj", "subj_b64", "stype", "val", "val_b64", "cat", "map"}
	kept := []string{"eid", "kind", "asset", "rcv", "dt", "dwall", "rsha256", "rlen"}
	for _, c := range []struct {
		target  string
		setting *bool
		content bool
	}{
		{"tcp-lf-insecure", nil, false},
		{"udp-rfc3164", nil, false},
		{"relp-plain-best-effort", nil, false},
		{"tcp-lf-insecure", &on, true},
		{"tls-best-effort", nil, true},
		{"relp-tls-required", nil, true},
		{"tls-best-effort", &off, false},
	} {
		tg := loadTarget(t, c.target)
		tg.DeviceContent = c.setting
		msg, out, err := Render(e, tg)
		if err != nil {
			t.Fatalf("%s: %v", c.target, err)
		}
		m, _ := ParseMessage(msg)
		marker, marked := m.Get("content_omitted")
		if out.TextOmitted || marked == c.content || (marked && marker != OmitConfig) {
			t.Errorf("%s device_content %v: content_omitted %q (%v), outcome %+v", c.target, c.setting, marker, marked, out)
		}
		for _, p := range content {
			if _, has := m.Get(p); has && !c.content {
				t.Errorf("%s device_content %v: %s sent", c.target, c.setting, p)
			}
		}
		if _, has := m.DeviceText(); has != c.content {
			t.Errorf("%s device_content %v: device text %v", c.target, c.setting, has)
		}
		if want := "ser"; !c.content && m.Summary != want {
			t.Errorf("%s device_content %v: summary %q, want %q", c.target, c.setting, m.Summary, want)
		}
		for _, p := range kept {
			if _, has := m.Get(p); !has {
				t.Errorf("%s device_content %v: %s missing", c.target, c.setting, p)
			}
		}
	}
	for _, name := range []string{"tcp-lf-insecure", "udp-rfc3164", "relp-plain-best-effort"} {
		tg := loadTarget(t, name)
		for _, broken := range []func(a *Acknowledgement){
			func(a *Acknowledgement) { a.By = "" },
			func(a *Acknowledgement) { a.By = "not a principal" },
			func(a *Acknowledgement) { a.At = "2026-10-24T09:00:00+03:00" },
			func(a *Acknowledgement) { a.Reason = " " },
			func(a *Acknowledgement) { a.Scope = "same-segment" },
		} {
			a := *tg.Acknowledgement
			broken(&a)
			tg2 := *tg
			tg2.Acknowledgement = &a
			if !slices.Contains(Codes(tg2.Validate()), CodeAck) {
				t.Errorf("%s with %+v validated", name, a)
			}
		}
	}
}
