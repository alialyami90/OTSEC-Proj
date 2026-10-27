package contract

// C10 otsec.baseline/0.1 (#254, B4; contracts/baseline): B6's own tests.
// They tie C10 to B6's GT-INJ event series (tests/integration/gt_inj,
// #251), which was written before C10 and from which V-M4's acceptance
// test will read its expected alarms: the series' parameters must be C10
// Params, and C10's key must split the series' events into exactly the
// types the series was built on. If either fails, the product and the
// ground truth would disagree on what an event type is, and every V-M4
// number would mean nothing. The rest checks C10's arithmetic and D4-4's
// rulings from their text, not from B4's tests or goldens.
//
// Ground truth: independent (D4-4 and D4-9's text, the GT-INJ type
// definitions, integer arithmetic). Evidence class: desk; the GT-INJ
// events are synthetic.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/baseline"
	"otsec.local/otsec/contracts/event"
	"otsec.local/otsec/modules/telemetry/normalize"
)

const c10Asset = "5e3a1c2d-9b8f-4e7a-8c6d-1f2e3d4c5b6a"

// c10Series is the part of a GT-INJ event file these tests read.
type c10Series struct {
	Params json.RawMessage `json:"params"`
	Events []c10GTEvent    `json:"events"`
}

type c10GTEvent struct {
	ID       string `json:"id"`
	Asset    string `json:"asset"`
	Received string `json:"received_utc"`
	Source   string `json:"source"`
	Element  string `json:"element"`
	State    string `json:"state"`
	Facility int    `json:"facility"`
	Severity int    `json:"severity"`
	MsgID    string `json:"msgid"`
	Msg      string `json:"msg"`
}

func c10Load(t *testing.T, name string) c10Series {
	t.Helper()
	b, err := os.ReadFile("../integration/gt_inj/" + name)
	if err != nil {
		t.Fatal(err)
	}
	var s c10Series
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	if len(s.Events) == 0 {
		t.Fatalf("%s: no events", name)
	}
	return s
}

// c10GTKey is the type GT-INJ built the event on (generate.py key_of): SER
// element and state; Syslog facility, severity and the text with each
// ASCII digit run made "#". The msgid is not in it (D4-9).
func c10GTKey(e c10GTEvent) string {
	if e.Source == "ser" {
		return "ser " + e.Element + " " + e.State
	}
	var b strings.Builder
	digits := false
	for i := 0; i < len(e.Msg); i++ {
		if c := e.Msg[i]; c >= '0' && c <= '9' {
			if !digits {
				b.WriteByte('#')
			}
			digits = true
			continue
		}
		digits = false
		b.WriteByte(e.Msg[i])
	}
	return fmt.Sprintf("syslog %d %d %s", e.Facility, e.Severity, b.String())
}

// c10Event is the C4 event the platform would store for a GT-INJ event:
// a Syslog message through the real parser, as RFC 5424 with the msgid
// in its place, or a parsed SER row.
func c10Event(t *testing.T, e c10GTEvent) *event.Event {
	t.Helper()
	rcv := event.Received{UTC: e.Received, ResolutionNS: 1000, Clock: event.Clock{Sync: event.SyncSynchronized}}
	if e.Source == "syslog" {
		msg := fmt.Sprintf("<%d>1 %s gt-inj-host gtinj - %s - %s", e.Facility*8+e.Severity, e.Received, e.MsgID, e.Msg)
		ev, err := normalize.Syslog(normalize.SyslogInput{
			Node: "site-a-node1", Stream: "syslog/gt-inj", Message: []byte(msg), Sender: "127.0.0.2",
			Auth: event.AuthNone, AssetID: c10Asset, EvidenceClass: asset.Simulated, Dialect: normalize.DialectRFC, Received: rcv,
		})
		if err != nil {
			t.Fatalf("%s: %v", e.ID, err)
		}
		return &ev
	}
	row := fmt.Sprintf("1    11/02/2026 09:00:00.000   %s %s", e.Element, e.State)
	sum := sha256.Sum256([]byte(row))
	return &event.Event{
		Origin: event.OriginDevice, Kind: event.KindSER, Received: rcv,
		Source:     event.Source{Asset: &event.AssetRef{ID: c10Asset}},
		Collection: &event.Collection{Method: event.MethodAdapterPoll, Alignment: event.AlignOK, ParseStatus: event.ParseOK},
		Native:     &event.Native{Bytes: []byte(row), RecordSHA256: hex.EncodeToString(sum[:]), RecordLength: int64(len(row))},
		Normalized: &event.Normalized{Subject: e.Element, SubjectType: "relay-word-bit", Value: e.State, Category: event.Unmapped},
	}
}

// TestC10B6GTINJParamsAreC10Params: GT-INJ's parameters are C10 Params by
// name, every one set, none left over, at C10's defaults and inside its
// bounds, so the learner can be given the series' own params.
func TestC10B6GTINJParamsAreC10Params(t *testing.T) {
	for _, name := range []string{"events.json", "events-heldout.json"} {
		raw := c10Load(t, name).Params
		var p baseline.Params
		d := json.NewDecoder(bytes.NewReader(raw))
		d.DisallowUnknownFields()
		if err := d.Decode(&p); err != nil {
			t.Fatalf("%s: params are not C10 Params: %v", name, err)
		}
		// Every field of Params is in the series: re-encoded, the two hold
		// the same names and values.
		var got, want map[string]any
		back, _ := json.Marshal(p)
		json.Unmarshal(back, &got)
		json.Unmarshal(raw, &want)
		if fmt.Sprint(got) != fmt.Sprint(want) {
			t.Errorf("%s: params\n got %v\nwant %v", name, got, want)
		}
		switch {
		case p.MinDurationS != int64(baseline.DefaultMinDuration.Seconds()) || p.MinEvents != baseline.DefaultMinEvents:
			t.Errorf("%s: observation %d s, %d events; C10's defaults are %v, %d", name, p.MinDurationS, p.MinEvents, baseline.DefaultMinDuration, baseline.DefaultMinEvents)
		case p.AlarmHoldS < baseline.MinAlarmHoldS || p.MaxAlarmsPerHold > baseline.MaxAlarmsPerHoldCeiling || p.MaxAlarmsPerHold < 1:
			t.Errorf("%s: alarm bounds %d s, %d", name, p.AlarmHoldS, p.MaxAlarmsPerHold)
		case p.MaxTypes > baseline.MaxTypesCeiling || p.TimeClock != baseline.ClockReceived:
			t.Errorf("%s: max_types %d, time_clock %q", name, p.MaxTypes, p.TimeClock)
		}
	}
}

// TestC10B6GTINJKeysPartitionAlike: C10's key (KeyOf, through the real
// Syslog parser) puts two GT-INJ events in one type exactly when GT-INJ
// built them on one type. That covers D4-9 both ways: the three controls
// (a known text under another msgid) share their known type, and the new
// type that reuses a known msgid with a new text is a type of its own.
func TestC10B6GTINJKeysPartitionAlike(t *testing.T) {
	for _, name := range []string{"events.json", "events-heldout.json"} {
		c10ToGT, gtToC10 := map[string]string{}, map[string]string{}
		for _, e := range c10Load(t, name).Events {
			ev := c10Event(t, e)
			k, text, use, why := baseline.Classify(ev, false)
			if use != baseline.UseFull || why != baseline.ExcludedNone {
				t.Fatalf("%s %s: %s %q", name, e.ID, use, why)
			}
			gt, c := c10GTKey(e), k.String()
			if e.Source == "syslog" {
				if k.Facility != fmt.Sprint(e.Facility) || k.Severity != fmt.Sprint(e.Severity) {
					t.Errorf("%s %s: key %+v from PRI %d.%d", name, e.ID, k, e.Facility, e.Severity)
				}
				if want := strings.SplitN(gt, " ", 4)[3]; text != want {
					t.Errorf("%s %s: template %q, GT-INJ %q", name, e.ID, text, want)
				}
			}
			if prev, ok := c10ToGT[c]; ok && prev != gt {
				t.Errorf("%s: C10 merges %q and %q into %s", name, prev, gt, c)
			}
			if prev, ok := gtToC10[gt]; ok && prev != c {
				t.Errorf("%s: C10 splits %q into %s and %s", name, gt, prev, c)
			}
			c10ToGT[c], gtToC10[gt] = gt, c
		}
		if len(c10ToGT) < 10 {
			t.Errorf("%s: only %d types", name, len(c10ToGT))
		}
	}
}

// TestC10B6RateBoundAndTolerance: C10's two formulas against integer
// arithmetic written from their text: the larger of rate_min and
// max_per_bucket x rate_factor_pct / 100 rounded up; interval x pct / 100
// rounded up.
func TestC10B6RateBoundAndTolerance(t *testing.T) {
	ceil := func(a, b int64) int64 { return (a + b - 1) / b }
	for _, f := range []int64{100, 101, 150, 300, 333} {
		for _, min := range []int64{0, 1, 2, 7} {
			for m := int64(0); m <= 40; m++ {
				want := max(min, ceil(m*f, 100))
				if got := baseline.RateBound(m, baseline.Params{RateFactorPct: f, RateMin: min}); got != want {
					t.Errorf("RateBound(%d, factor %d, min %d) = %d, want %d", m, f, min, got, want)
				}
			}
		}
	}
	for _, pct := range []int64{0, 1, 10, 33, 50, 100} {
		for _, i := range []int64{1, 2, 3, 59, 60, 61, 1799, 1800, 1801, 3599, 3600, 86401} {
			if got, want := baseline.Tolerance(i, pct), ceil(i*pct, 100); got != want {
				t.Errorf("Tolerance(%d, %d) = %d, want %d", i, pct, got, want)
			}
		}
	}
}

// TestC10B6TemplateIsASCIIDigitRuns: D4-4 item 4, "msg with every digit
// run replaced"; C10 says ASCII digits, so other scripts' digits stay.
func TestC10B6TemplateIsASCIIDigitRuns(t *testing.T) {
	for in, want := range map[string]string{
		"":                        "",
		"no digits":               "no digits",
		"7":                       "#",
		"a1b22c333d":              "a#b#c#d",
		"10.20.30.40:514":         "#.#.#.#:#",
		"-12 +3":                  "-# +#",
		"0x1F":                    "#x#F",
		"Breaker 1 and Breaker 2": "Breaker # and Breaker #",
		"٣٤ １２":                   "٣٤ １２", // Arabic-Indic and full-width digits
	} {
		if got := baseline.TemplateOf(in); got != want {
			t.Errorf("TemplateOf(%q) = %q, want %q", in, got, want)
		}
	}
}

// c10Row is a SER row with alignment key k, flagged possible-duplicate
// when dup.
func c10Row(k string, dup bool) *event.Event {
	e := &event.Event{Origin: event.OriginDevice, Kind: event.KindSER, Source: event.Source{Asset: &event.AssetRef{ID: c10Asset}},
		Collection: &event.Collection{Method: event.MethodAdapterPoll, Alignment: event.AlignOK, ParseStatus: event.ParseOK},
		Native:     &event.Native{AlignmentKey: k, RecordSHA256: strings.Repeat("ab", 32)},
		Normalized: &event.Normalized{Subject: "IN101", SubjectType: "relay-word-bit", Value: "Asserted", Category: event.Unmapped}}
	if dup {
		e.Flags = []string{"possible-duplicate"}
	}
	return e
}

// TestC10B6PossibleDuplicatesD44Item3: matched against the previous read
// only, one to one, never within the current read; an unflagged row
// always counts.
func TestC10B6PossibleDuplicatesD44Item3(t *testing.T) {
	A, B := "sha256:"+strings.Repeat("a", 64), "sha256:"+strings.Repeat("b", 64)
	cases := []struct {
		name string
		prev []string
		cur  []*event.Event
		want []bool
	}{
		{"k identical rows before suppress at most k", []string{A, A}, []*event.Event{c10Row(A, true), c10Row(A, true), c10Row(A, true)}, []bool{false, false, true}},
		{"never compared within the current read", nil, []*event.Event{c10Row(A, true), c10Row(A, true)}, []bool{true, true}},
		{"a row only in the current read is not a duplicate", []string{B}, []*event.Event{c10Row(A, true)}, []bool{true}},
		{"an unflagged row counts and spends nothing", []string{A}, []*event.Event{c10Row(A, false), c10Row(A, true)}, []bool{true, false}},
		{"each previous row is matched once, whatever its order", []string{A, B, A}, []*event.Event{c10Row(B, true), c10Row(A, true), c10Row(B, true), c10Row(A, true)}, []bool{false, false, true, false}},
	}
	for _, c := range cases {
		if got := baseline.PossibleDuplicates(c.prev, c.cur); fmt.Sprint(got) != fmt.Sprint(c.want) {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
	// The alignment alone marks a possible duplicate (C4 sets both).
	r := c10Row(A, false)
	r.Collection.Alignment = event.AlignPossibleDuplicate
	if got := baseline.PossibleDuplicates([]string{A}, []*event.Event{r}); got[0] {
		t.Error("a row aligned possible-duplicate, unflagged, was not matched")
	}
}

// TestC10B6ClassifyD44Item2: catch-up SER rows (first-read, gap-before,
// and every row of the first good read after a V-S12 failure) count for
// the type only; Syslog is pushed, so it has no catch-up; platform events,
// unresolved senders and other kinds belong to no asset's baseline.
func TestC10B6ClassifyD44Item2(t *testing.T) {
	syslog := c10Event(t, c10GTEvent{ID: "s", Source: "syslog", Received: "2026-11-02T09:00:00.000Z", Facility: 4, Severity: 5, MsgID: "LOGIN", Msg: "Login failed from 10.0.0.9"})
	row := func(a event.Alignment) *event.Event {
		e := c10Row("sha256:"+strings.Repeat("c", 64), false)
		e.Collection.Alignment = a
		return e
	}
	unresolved := c10Row("", false)
	unresolved.Flags = []string{"asset-unresolved"}
	noAsset := c10Row("", false)
	noAsset.Source.Asset = nil
	other := c10Row("", false)
	other.Kind = event.KindSOELog
	platform := &event.Event{Origin: event.OriginPlatform, Kind: event.KindHealth}
	cases := []struct {
		name  string
		e     *event.Event
		after bool
		use   baseline.Use
		why   baseline.Exclusion
	}{
		{"SER aligned ok", row(event.AlignOK), false, baseline.UseFull, baseline.ExcludedNone},
		{"SER first read", row(event.AlignFirstRead), false, baseline.UseTypeOnly, baseline.ExcludedNone},
		{"SER gap before", row(event.AlignGapBefore), false, baseline.UseTypeOnly, baseline.ExcludedNone},
		{"SER after a V-S12 failure", row(event.AlignOK), true, baseline.UseTypeOnly, baseline.ExcludedNone},
		{"Syslog", syslog, false, baseline.UseFull, baseline.ExcludedNone},
		{"Syslog, the asset's SER read failed", syslog, true, baseline.UseFull, baseline.ExcludedNone},
		{"asset-unresolved", unresolved, false, baseline.UseNone, baseline.ExcludedUnresolved},
		{"no asset", noAsset, false, baseline.UseNone, baseline.ExcludedUnresolved},
		{"another kind", other, false, baseline.UseNone, baseline.ExcludedKind},
		{"a platform event", platform, false, baseline.UseNone, baseline.ExcludedPlatform},
	}
	for _, c := range cases {
		if _, _, use, why := baseline.Classify(c.e, c.after); use != c.use || why != c.why {
			t.Errorf("%s: %s %q, want %s %q", c.name, use, why, c.use, c.why)
		}
	}
}

// TestC10B6SyslogKeyLeavesOutWhatASenderChooses: D4-4 item 4 and D4-9.
// The same PRI and text from another app name, host, msgid or time is the
// same type; another facility, severity or text is another; a message
// whose PRI cannot be read is pri-absent, not a guess.
func TestC10B6SyslogKeyLeavesOutWhatASenderChooses(t *testing.T) {
	key := func(msg string) baseline.Key {
		ev, err := normalize.Syslog(normalize.SyslogInput{
			Node: "site-a-node1", Stream: "syslog/gt-inj", Message: []byte(msg), Sender: "127.0.0.2", Auth: event.AuthNone,
			AssetID: c10Asset, EvidenceClass: asset.Simulated, Dialect: normalize.DialectRFC,
			Received: event.Received{UTC: "2026-11-02T09:00:00.000Z", ResolutionNS: 1000, Clock: event.Clock{Sync: event.SyncSynchronized}},
		})
		if err != nil {
			t.Fatalf("%q: %v", msg, err)
		}
		k, _, ok := baseline.KeyOf(&ev)
		if !ok {
			t.Fatalf("%q: no key", msg)
		}
		return k
	}
	base := key("<37>1 2026-11-02T09:00:00Z hostA appA - LOGIN - Login failed from 10.0.0.9")
	for _, same := range []string{
		"<37>1 2026-11-02T09:00:00Z hostA appB - LOGIN - Login failed from 10.0.0.9",
		"<37>1 2026-11-02T09:00:00Z hostB appA - LOGIN - Login failed from 10.0.0.9",
		"<37>1 2026-11-02T09:00:00Z hostA appA - OTHER - Login failed from 10.0.0.9",
		"<37>1 2026-11-02T09:00:00Z hostA appA - - - Login failed from 10.0.0.9",
		"<37>1 2026-11-03T17:59:59Z hostA appA - LOGIN - Login failed from 192.168.1.250",
	} {
		if k := key(same); k != base {
			t.Errorf("%q: %v, want %v", same, k, base)
		}
	}
	for _, other := range []string{
		"<38>1 2026-11-02T09:00:00Z hostA appA - LOGIN - Login failed from 10.0.0.9",  // severity 6
		"<133>1 2026-11-02T09:00:00Z hostA appA - LOGIN - Login failed from 10.0.0.9", // facility 16
		"<37>1 2026-11-02T09:00:00Z hostA appA - LOGIN - Login refused from 10.0.0.9",
	} {
		if k := key(other); k == base {
			t.Errorf("%q: the same type as %q", other, base)
		}
	}
	if k := key("no PRI here 12"); k.Facility != baseline.PRIAbsent || k.Severity != baseline.PRIAbsent {
		t.Errorf("no PRI: %+v", k)
	}
}

// TestC10B6CatchUpCountsForNewTypeOnly: D4-9 (B1 on #254, amending D4-4
// item 2): a type-only row, first-read included, counts toward the
// new-type rule alone, so a first read's backlog cannot lift MaxPerWindow
// and switch the repeats rule off, and a catch-up read after an outage
// cannot raise repeats, rate or time.
func TestC10B6CatchUpCountsForNewTypeOnly(t *testing.T) {
	rules := []baseline.Rule{baseline.RuleNewType, baseline.RuleRepeats, baseline.RuleRate, baseline.RuleTime, baseline.RuleAbsence}
	for _, u := range []baseline.Use{baseline.UseFull, baseline.UseTypeOnly, baseline.UseNone} {
		for _, r := range rules {
			want := u == baseline.UseFull || (u == baseline.UseTypeOnly && r == baseline.RuleNewType)
			if got := u.Applies(r); got != want {
				t.Errorf("%s toward %s: %v, want %v", u, r, got, want)
			}
		}
	}
	// Every catch-up class is type-only (Classify), so all of them reach
	// new-type alone.
	for _, a := range []event.Alignment{event.AlignFirstRead, event.AlignGapBefore} {
		r := c10Row("sha256:"+strings.Repeat("d", 64), false)
		r.Collection.Alignment = a
		if _, _, use, _ := baseline.Classify(r, false); use.Applies(baseline.RuleRepeats) || !use.Applies(baseline.RuleNewType) {
			t.Errorf("%s: %s", a, use)
		}
	}
}

// c10Baseline is a recorded baseline: one type seen 200 times in full,
// and one seen only in a first read's backlog, six rows at one instant.
func c10Baseline(t *testing.T, backlogWindow int64) *baseline.Baseline {
	t.Helper()
	var p baseline.Params
	if err := json.Unmarshal(c10Load(t, "events.json").Params, &p); err != nil {
		t.Fatal(err)
	}
	full := baseline.Type{Key: baseline.Key{Source: baseline.SourceSER, Element: "IN101", State: "Asserted"}, Text: "IN101 Asserted",
		Count: 200, Full: 200, MaxPerWindow: 1, MaxPerBucket: 2, FirstUTC: "2026-11-02T06:05:00Z", LastUTC: "2026-11-15T20:35:00Z"}
	for h := 6; h < 16; h++ {
		full.HoursUTC[h] = 20
	}
	backlog := baseline.Type{Key: baseline.Key{Source: baseline.SourceSER, Element: "52A", State: "Asserted"}, Text: "52A Asserted",
		Count: 6, Full: 0, MaxPerWindow: backlogWindow, FirstUTC: "2026-11-02T00:00:01Z", LastUTC: "2026-11-02T00:00:01Z"}
	types := []baseline.Type{full, backlog}
	if types[0].Key.String() > types[1].Key.String() {
		types[0], types[1] = types[1], types[0]
	}
	return &baseline.Baseline{
		Schema: baseline.Identifier, NodeID: "site-a-node1", AssetID: c10Asset, Version: 1,
		Learner: baseline.Learner{Name: "b6-hand", Version: "0.1"}, Params: p,
		Period:      baseline.Period{StartUTC: "2026-11-02T00:00:00Z", EndUTC: "2026-11-16T00:00:00Z", CollectedS: 14 * 86400},
		Counts:      baseline.Counts{Events: 206, Full: 200, TypeOnly: 6},
		Types:       types,
		RecordedUTC: "2026-11-16T00:00:01Z",
	}
}

// TestC10B6BacklogLeavesNoWindow: a type seen only in catch-up has
// max_per_window 0; the old reading (6, its backlog at one instant) is
// refused. The record is stored and hashed as encoded (D4-4 item 5).
func TestC10B6BacklogLeavesNoWindow(t *testing.T) {
	b := c10Baseline(t, 0)
	enc, err := baseline.Encode(b, 0)
	if err != nil {
		t.Fatalf("a baseline with a catch-up-only type: %v", err)
	}
	sum := sha256.Sum256(enc)
	if h := baseline.Hash(enc); h != "sha256:"+hex.EncodeToString(sum[:]) {
		t.Errorf("Hash %s", h)
	}
	back, err := baseline.Decode(enc)
	if err != nil {
		t.Fatal(err)
	}
	if again, err := baseline.Encode(back, 0); err != nil || !bytes.Equal(again, enc) {
		t.Errorf("decode and encode again changed the stored bytes (%v)", err)
	}
	if err := c10Baseline(t, 6).Validate(); err == nil || !strings.Contains(err.Error(), "max_per_window") {
		t.Errorf("a backlog counted in max_per_window was accepted (%v)", err)
	}
}
