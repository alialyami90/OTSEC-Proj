package baseline

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/event"
)

const assetA = "2f1c5e0a-8b7d-4c3e-9a1f-0d2e3c4b5a69"

func serRow(subject, value string, align event.Alignment, flags ...string) *event.Event {
	e := &event.Event{
		Origin: event.OriginDevice, Kind: event.KindSER,
		Source:     event.Source{Asset: &event.AssetRef{ID: assetA}},
		Collection: &event.Collection{Method: event.MethodAdapterPoll, Alignment: align, ParseStatus: event.ParseOK},
		Native:     &event.Native{AlignmentKey: "sha256:" + strings.Repeat("a", 64)},
		Flags:      flags,
	}
	if subject != "" {
		e.Normalized = &event.Normalized{Subject: subject, SubjectType: "relay-word-bit", Value: value, Category: event.Unmapped}
	}
	return e
}

func syslogMsg(fields ...string) *event.Event {
	e := &event.Event{
		Origin: event.OriginDevice, Kind: event.KindSyslog,
		Source:     event.Source{Asset: &event.AssetRef{ID: assetA}},
		Collection: &event.Collection{Method: event.MethodSyslogReceive, ParseStatus: event.ParseOK},
		Native:     &event.Native{Bytes: []byte("raw")},
	}
	for i := 0; i+1 < len(fields); i += 2 {
		e.Native.Fields = append(e.Native.Fields, event.Field{Name: fields[i], Value: fields[i+1]})
	}
	return e
}

func mustKey(t *testing.T, e *event.Event) (Key, string) {
	t.Helper()
	k, text, ok := KeyOf(e)
	if !ok {
		t.Fatal("no key")
	}
	if err := k.Validate(); err != nil {
		t.Fatalf("KeyOf built an invalid key %+v: %v", k, err)
	}
	return k, text
}

func TestSERKeyIsElementAndState(t *testing.T) {
	a, text := mustKey(t, serRow("51P1P", "Asserted", event.AlignOK))
	d, _ := mustKey(t, serRow("51P1P", "Deasserted", event.AlignOK))
	if a == d {
		t.Error("Asserted and Deasserted are two types")
	}
	if got := a.String(); got != "ser|51P1P|Asserted" {
		t.Errorf("String %q", got)
	}
	if text != "51P1P Asserted" {
		t.Errorf("text %q", text)
	}
	if _, _, ok := KeyOf(serRow("", "", event.AlignOK)); ok {
		t.Error("a SER row with no normalized form has no key")
	}
}

func TestSyslogKeyFromPRI(t *testing.T) {
	// <38> is facility 4 (auth), severity 6 (informational).
	k, text := mustKey(t, syslogMsg("pri", "38", "version", "1", "msgid", "ID47", "msg", "user 5 logged on"))
	if k.Facility != "4" || k.Severity != "6" || k.Template != sha256Of([]byte("user # logged on")) || text != "user # logged on" {
		t.Errorf("RFC 5424 with MSGID: %+v %q", k, text)
	}
}

// TestMSGIDIsNotInTheKey: D4-4 item 4 keys Syslog on facility, severity and
// the template only. A sender that reuses one MSGID for different messages
// gets one type per template, and a MSGID alone never splits a type.
func TestMSGIDIsNotInTheKey(t *testing.T) {
	a, _ := mustKey(t, syslogMsg("pri", "38", "version", "1", "msgid", "LOG", "msg", "user 5 logged on"))
	b, _ := mustKey(t, syslogMsg("pri", "38", "version", "1", "msgid", "LOG", "msg", "port 502 opened"))
	if a == b {
		t.Errorf("two messages sharing MSGID LOG merged: %v", a)
	}
	c, _ := mustKey(t, syslogMsg("pri", "38", "version", "1", "msgid", "ID47", "msg", "user 7 logged on"))
	d, _ := mustKey(t, syslogMsg("pri", "38", "version", "1", "msgid", "-", "msg", "user 9 logged on"))
	if a != c || a != d {
		t.Errorf("one template split by MSGID: %v %v %v", a, c, d)
	}
}

func TestTemplateReplacesDigitRuns(t *testing.T) {
	if got := TemplateOf("port 502 from 10.0.0.12 at 12:03:59.123"); got != "port # from #.#.#.# at #:#:#.#" {
		t.Errorf("TemplateOf %q", got)
	}
	a, text := mustKey(t, syslogMsg("pri", "13", "msg", "login failed for user7 after 3 tries"))
	b, _ := mustKey(t, syslogMsg("pri", "13", "msg", "login failed for user8 after 15 tries"))
	if a != b {
		t.Error("messages that differ only by digits are one type")
	}
	if text != "login failed for user# after # tries" {
		t.Errorf("text %q", text)
	}
	c, _ := mustKey(t, syslogMsg("pri", "14", "msg", "login failed for user7 after 3 tries"))
	if a == c {
		t.Error("another severity is another type")
	}
}

// The limit D4-4 item 4 states: RTAC tags that differ only by a number merge.
func TestRTACTagsDifferingByNumberMerge(t *testing.T) {
	m := func(tag string) *event.Event {
		msg := "RTAC Logger: 2026-10-27 12:00:00.000, Info, System, " + tag + ", Logged on"
		return syslogMsg("pri", "134", "app", "RTAC Logger", "tag", tag, "msg", msg)
	}
	a, _ := mustKey(t, m("Breaker 1"))
	b, _ := mustKey(t, m("Breaker 2"))
	if a != b {
		t.Error("the stated limit no longer holds; C10's doc must change with it")
	}
}

func TestSyslogWithoutPRI(t *testing.T) {
	// A failed parse keeps the bytes and nothing else.
	e := syslogMsg()
	e.Native.Bytes = []byte("garbage 12 without a header")
	k, text := mustKey(t, e)
	if k.Facility != PRIAbsent || k.Severity != PRIAbsent || k.Template == "" {
		t.Errorf("%+v", k)
	}
	if text != "garbage # without a header" {
		t.Errorf("the whole record is the message: %q", text)
	}
	if !strings.HasPrefix(k.String(), "syslog|pri-absent|pri-absent|template|sha256:") {
		t.Errorf("String %q", k.String())
	}
	// An out-of-range PRI is not read either.
	k2, _ := mustKey(t, syslogMsg("pri", "192", "msg", "x"))
	if k2.Facility != PRIAbsent {
		t.Errorf("PRI 192 is outside RFC 5424: %+v", k2)
	}
}

func TestLongTemplateIsHashedAndTextCut(t *testing.T) {
	long := strings.Repeat("é", 200) // 400 bytes
	a, text := mustKey(t, syslogMsg("pri", "13", "msg", long))
	b, _ := mustKey(t, syslogMsg("pri", "13", "msg", long+"x"))
	if a == b {
		t.Error("the template's identity is its whole hash, not its displayed prefix")
	}
	if len(text) > TextMax || !strings.HasPrefix(long, text) || len(text) != 128 {
		t.Errorf("text cut to %d bytes", len(text))
	}
}

func TestKeyStringRoundTrips(t *testing.T) {
	keys := []Key{
		{Source: SourceSER, Element: "A|B%", State: "Asserted"},
		{Source: SourceSER, Element: "51P1P", State: "Deasserted"},
		{Source: SourceSyslog, Facility: PRIAbsent, Severity: PRIAbsent, Template: "sha256:" + strings.Repeat("0", 64)},
	}
	for _, k := range keys {
		got, err := ParseKey(k.String())
		if err != nil || got != k {
			t.Errorf("%q: %+v %v", k.String(), got, err)
		}
	}
	for _, bad := range []string{"", "ser|x", "ser|a|b|c", "syslog|4|6|msgid|ID47", "syslog|4|6|template|x",
		"syslog|4|9|template|sha256:" + strings.Repeat("0", 64), "syslog|04|6|template|sha256:" + strings.Repeat("0", 64),
		"syslog|pri-absent|6|template|sha256:" + strings.Repeat("0", 64), "syslog|4|6", "ser|a%2|b", "ser|a%7c|b", "other|a|b"} {
		if _, err := ParseKey(bad); err == nil {
			t.Errorf("ParseKey(%q) accepted", bad)
		}
	}
}

// TestC4Goldens keys C4's own frozen examples: each SEL-751 row is a type
// of element and state, the ser.gap health event belongs to no baseline,
// and the Phase 1 RTAC example, whose field names are not the parser's,
// falls back to its whole record as the message.
func TestC4Goldens(t *testing.T) {
	files, _ := filepath.Glob("../event/testdata/valid/*.json")
	if len(files) == 0 {
		t.Fatal("no C4 goldens")
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		e, err := event.Decode(b)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		k, _, use, why := Classify(e, false)
		name := filepath.Base(f)
		switch {
		case strings.HasPrefix(name, "health-"):
			if why != ExcludedPlatform {
				t.Errorf("%s: %s %q", name, use, why)
			}
		case strings.HasPrefix(name, "sel751-") || strings.HasPrefix(name, "constructed-invalid") || strings.HasPrefix(name, "constructed-leap"):
			if k.Source != SourceSER || k.Element != e.Normalized.Subject || k.State != e.Normalized.Value {
				t.Errorf("%s: key %+v", name, k)
			}
		case strings.Contains(name, "rtac"):
			if k.Source != SourceSyslog || k.Facility != PRIAbsent || k.Template != sha256Of([]byte(TemplateOf(string(e.Native.Bytes)))) {
				t.Errorf("%s: key %+v", name, k)
			}
		default:
			t.Errorf("%s: no expectation", name)
		}
	}
}
