package baseline

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/event"
)

// valid is a small baseline that passes Validate: 14 days with one 2 h gap,
// two SER types and one Syslog type. Synthetic; no device produced it.
func valid() *Baseline {
	tmpl := "sha256:" + strings.Repeat("1", 64)
	hours := func(at int, n int64) (h [24]int64) { h[at] = n; return }
	return &Baseline{
		Schema: Identifier, NodeID: "site-a", AssetID: assetA, Version: 1,
		Learner: Learner{Name: "otsec-detection", Version: "0.1"},
		Params: Params{
			MinDurationS: 14 * 86400, MinEvents: 200,
			RepeatsN: 5, RepeatsWindowS: 600,
			RateBucketS: 3600, RateFactorPct: 200, RateMin: 2,
			PeriodicMinOccurrences: 6, PeriodicTolerancePct: 10,
			TimeClock: ClockReceived, MaxTypes: 4096,
			AlarmHoldS: 3600, MaxAlarmsPerHold: 16,
		},
		Period: Period{
			StartUTC: "2026-11-01T00:00:00Z", EndUTC: "2026-11-15T02:00:00Z",
			CollectedS: 14 * 86400,
			Gaps:       []Gap{{FromUTC: "2026-11-03T10:00:00Z", ToUTC: "2026-11-03T12:00:00Z", Reason: "failed.timeout"}},
		},
		Counts: Counts{Events: 260, Full: 250, TypeOnly: 5, Unkeyed: 3, NotCounted: 2},
		Types: []Type{
			{Key: Key{Source: SourceSER, Element: "51P1P", State: "Asserted"}, Text: "51P1P Asserted",
				Count: 10, Full: 5, HoursUTC: hours(14, 5), MaxPerWindow: 2, MaxPerBucket: 2,
				FirstUTC: "2026-11-01T14:00:00Z", LastUTC: "2026-11-14T14:30:00Z"},
			{Key: Key{Source: SourceSER, Element: "IN101", State: "Deasserted"}, Text: "IN101 Deasserted",
				Count: 5, Full: 5, HoursUTC: hours(3, 5), MaxPerWindow: 1, MaxPerBucket: 1,
				FirstUTC: "2026-11-02T03:00:00Z", LastUTC: "2026-11-12T03:00:00Z"},
			{Key: Key{Source: SourceSyslog, Facility: "4", Severity: "6", Template: tmpl}, Text: "heartbeat #",
				Count: 240, Full: 240, HoursUTC: [24]int64{10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10},
				MaxPerWindow: 1, MaxPerBucket: 1, Periodic: &Periodic{IntervalS: 5040, ToleranceS: 504},
				FirstUTC: "2026-11-01T00:00:00Z", LastUTC: "2026-11-15T01:00:00Z"},
		},
		RecordedUTC: "2026-11-15T02:00:01Z",
	}
}

func TestValidBaseline(t *testing.T) {
	if err := valid().Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestBaselineRules(t *testing.T) {
	cases := []struct {
		name string
		edit func(*Baseline)
		want Code
	}{
		{"other major", func(b *Baseline) { b.Schema = "otsec.baseline/1.0" }, CodeSchema},
		{"another contract", func(b *Baseline) { b.Schema = "otsec.event/0.1" }, CodeSchema},
		{"asset id", func(b *Baseline) { b.AssetID = "A" }, CodeForm},
		{"first replaces nothing", func(b *Baseline) { b.Previous = Hash([]byte("x")) }, CodeConflict},
		{"relearn names previous", func(b *Baseline) { b.Version = 2 }, CodeForm},
		{"rate factor under 100", func(b *Baseline) { b.Params.RateFactorPct = 99 }, CodeRange},
		{"no alarm hold", func(b *Baseline) { b.Params.AlarmHoldS = 0 }, CodeRange},
		{"clock", func(b *Baseline) { b.Params.TimeClock = "wall" }, CodeForm},
		{"collected is period less gaps", func(b *Baseline) { b.Period.CollectedS++ }, CodeConflict},
		{"gap outside period", func(b *Baseline) { b.Period.Gaps[0].ToUTC = "2026-11-16T00:00:00Z" }, CodeOrder},
		{"not utc", func(b *Baseline) { b.Period.StartUTC = "2026-11-01T00:00:00+00:00" }, CodeForm},
		{"period not ended: events", func(b *Baseline) { b.Params.MinEvents = 1000 }, CodeConflict},
		{"period not ended: time", func(b *Baseline) { b.Params.MinDurationS = 15 * 86400 }, CodeConflict},
		{"counts sum", func(b *Baseline) { b.Counts.Events++ }, CodeConflict},
		{"types sum", func(b *Baseline) { b.Types[0].Count++ }, CodeConflict},
		{"hours sum to full", func(b *Baseline) { b.Types[0].HoursUTC[0]++ }, CodeConflict},
		{"types ordered", func(b *Baseline) { b.Types[0], b.Types[1] = b.Types[1], b.Types[0] }, CodeOrder},
		{"type repeated", func(b *Baseline) { b.Types[1].Key = b.Types[0].Key }, CodeOrder},
		{"bad key", func(b *Baseline) { b.Types[0].Key.Facility = "4" }, CodeForm},
		{"tolerance from pct", func(b *Baseline) { b.Types[2].Periodic.ToleranceS = 600 }, CodeRange},
		{"periodic on too few", func(b *Baseline) { b.Params.PeriodicMinOccurrences = 300 }, CodeConflict},
		{"type outside period", func(b *Baseline) { b.Types[1].FirstUTC = "2026-10-31T00:00:00Z" }, CodeOrder},
		{"text bound", func(b *Baseline) { b.Types[0].Text = strings.Repeat("x", TextMax+1) }, CodeForm},
		{"max per bucket over full", func(b *Baseline) { b.Types[0].MaxPerBucket = 6 }, CodeRange},
		{"types nil", func(b *Baseline) { b.Types = nil; b.Counts = Counts{Events: 260, Unkeyed: 258, NotCounted: 2} }, CodeMissing},
		{"recorded before end", func(b *Baseline) { b.RecordedUTC = "2026-11-15T01:00:00Z" }, CodeOrder},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := valid()
			tc.edit(b)
			if got := Codes(b.Validate()); !slices.Contains(got, tc.want) {
				t.Errorf("codes %v, want %s", got, tc.want)
			}
		})
	}
}

func TestRelearnNamesPrevious(t *testing.T) {
	first, _ := json.Marshal(valid())
	b := valid()
	b.Version, b.Previous = 2, Hash(first)
	if err := b.Validate(); err != nil {
		t.Fatal(err)
	}
}

// D4-4 item 5: the hash is over the stored bytes exactly, so the same
// record written differently has another hash, and nothing re-encodes it.
func TestHashIsOverExactBytes(t *testing.T) {
	a, _ := json.Marshal(valid())
	var ind bytes.Buffer
	if err := json.Indent(&ind, a, "", " "); err != nil {
		t.Fatal(err)
	}
	if Hash(a) == Hash(ind.Bytes()) {
		t.Error("two encodings of one record must not share a hash")
	}
	if !sha256Ref.MatchString(Hash(a)) {
		t.Errorf("form %q", Hash(a))
	}
	// Both encodings decode to the same valid record.
	ra, err1 := Decode(a)
	rb, err2 := Decode(ind.Bytes())
	if err1 != nil || err2 != nil {
		t.Fatal(err1, err2)
	}
	if ja, _ := json.Marshal(ra); !bytes.Equal(ja, a) {
		t.Error("decode is lossy")
	}
	_ = rb
}

func TestDecodeIsStrictForThisMinor(t *testing.T) {
	a, _ := json.Marshal(valid())
	for name, b := range map[string][]byte{
		"duplicate key": bytes.Replace(a, []byte(`"version":1,`), []byte(`"version":1,"version":2,`), 1),
		"case variant":  bytes.Replace(a, []byte(`"version":1,`), []byte(`"VERSION":1,`), 1),
		"unknown field": bytes.Replace(a, []byte(`"version":1,`), []byte(`"version":1,"extra":1,`), 1),
		"trailing":      append(slices.Clone(a), []byte(" {}")...),
	} {
		if _, err := Decode(b); !slices.Contains(Codes(err), CodeDecode) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A later minor's added field is ignored.
	later := bytes.Replace(a, []byte(`"schema":"otsec.baseline/0.1",`), []byte(`"schema":"otsec.baseline/0.2","added":true,`), 1)
	if _, err := Decode(later); err != nil {
		t.Errorf("a later minor must decode: %v", err)
	}
}

func TestLookup(t *testing.T) {
	b := valid()
	if ty, ok := b.Lookup(Key{Source: SourceSER, Element: "IN101", State: "Deasserted"}); !ok || ty.Count != 5 {
		t.Errorf("lookup: %v %v", ty, ok)
	}
	if _, ok := b.Lookup(Key{Source: SourceSER, Element: "IN101", State: "Asserted"}); ok {
		t.Error("a type not learnt is not found")
	}
}

func TestRateBoundAndTolerance(t *testing.T) {
	p := valid().Params // factor 200 %, min 2
	for _, c := range []struct{ max, want int64 }{{0, 2}, {1, 2}, {3, 6}, {7, 14}} {
		if got := RateBound(c.max, p); got != c.want {
			t.Errorf("RateBound(%d) = %d, want %d", c.max, got, c.want)
		}
	}
	p.RateFactorPct = 150
	if got := RateBound(3, p); got != 5 {
		t.Errorf("RateBound rounds up: %d", got)
	}
	if got := Tolerance(5040, 10); got != 504 {
		t.Errorf("Tolerance %d", got)
	}
	if got := Tolerance(101, 10); got != 11 {
		t.Errorf("Tolerance rounds up: %d", got)
	}
}

func TestClassify(t *testing.T) {
	unresolved := syslogMsg("pri", "13", "msg", "x")
	unresolved.Source.Asset = nil
	unresolved.Flags = []string{"asset-unresolved"}
	// The flag alone excludes, whatever else the event names.
	flagged := syslogMsg("pri", "13", "msg", "x")
	flagged.Flags = []string{"asset-unresolved"}
	platform := &event.Event{Origin: event.OriginPlatform, Kind: event.KindHealth}
	other := serRow("51P1P", "Asserted", event.AlignOK)
	other.Kind = event.KindDeviceLog
	cases := []struct {
		name         string
		e            *event.Event
		afterFailure bool
		use          Use
		why          Exclusion
	}{
		{"ser ok", serRow("51P1P", "Asserted", event.AlignOK), false, UseFull, ExcludedNone},
		{"ser first read", serRow("51P1P", "Asserted", event.AlignFirstRead), false, UseTypeOnly, ExcludedNone},
		{"ser gap before", serRow("51P1P", "Asserted", event.AlignGapBefore, "gap-before"), false, UseTypeOnly, ExcludedNone},
		{"ser after failure", serRow("51P1P", "Asserted", event.AlignOK), true, UseTypeOnly, ExcludedNone},
		{"ser possible duplicate", serRow("51P1P", "Asserted", event.AlignPossibleDuplicate, "possible-duplicate"), false, UseFull, ExcludedNone},
		{"ser unkeyed", serRow("", "", event.AlignOK), false, UseNone, ExcludedUnkeyed},
		{"syslog", syslogMsg("pri", "13", "msg", "x"), false, UseFull, ExcludedNone},
		{"syslog after failure is live", syslogMsg("pri", "13", "msg", "x"), true, UseFull, ExcludedNone},
		{"asset unresolved", unresolved, false, UseNone, ExcludedUnresolved},
		{"flag alone", flagged, false, UseNone, ExcludedUnresolved},
		{"platform", platform, false, UseNone, ExcludedPlatform},
		{"other kind", other, false, UseNone, ExcludedKind},
	}
	for _, c := range cases {
		_, _, use, why := Classify(c.e, c.afterFailure)
		if use != c.use || why != c.why {
			t.Errorf("%s: %s %q, want %s %q", c.name, use, why, c.use, c.why)
		}
	}
}

func row(key string, flagged bool) *event.Event {
	e := serRow("51P1P", "Asserted", event.AlignOK)
	e.Native.AlignmentKey = key
	if flagged {
		e.Collection.Alignment = event.AlignPossibleDuplicate
		e.Flags = []string{"possible-duplicate"}
	}
	return e
}

// D4-4 item 3: matched against the previous read only, one to one.
func TestPossibleDuplicates(t *testing.T) {
	k1, k2 := "sha256:"+strings.Repeat("1", 64), "sha256:"+strings.Repeat("2", 64)
	cases := []struct {
		name string
		prev []string
		cur  []*event.Event
		want []bool
	}{
		{"unflagged always counts", []string{k1}, []*event.Event{row(k1, false)}, []bool{true}},
		{"flagged and in prev", []string{k1}, []*event.Event{row(k1, true)}, []bool{false}},
		{"flagged, not in prev", []string{k2}, []*event.Event{row(k1, true)}, []bool{true}},
		{"k identical suppress at most k", []string{k1, k1}, []*event.Event{row(k1, true), row(k1, true), row(k1, true)}, []bool{false, false, true}},
		{"never within the current read", nil, []*event.Event{row(k1, true), row(k1, true)}, []bool{true, true}},
		{"an unflagged row spends no match", []string{k1}, []*event.Event{row(k1, false), row(k1, true)}, []bool{true, false}},
	}
	for _, c := range cases {
		if got := PossibleDuplicates(c.prev, c.cur); !slices.Equal(got, c.want) {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}

// The goldens in testdata are synthetic: see testdata/NOTES.md.
func TestGoldens(t *testing.T) {
	for _, dir := range []string{"valid", "invalid"} {
		files, _ := filepath.Glob(filepath.Join("testdata", dir, "*.json"))
		if len(files) == 0 {
			t.Fatalf("no %s goldens", dir)
		}
		for _, f := range files {
			b, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			var verr error
			if strings.HasPrefix(filepath.Base(f), "alarm-") {
				var a Alarm
				if err := json.Unmarshal(b, &a); err != nil {
					t.Fatal(f, err)
				}
				verr = a.Validate()
			} else {
				_, verr = Decode(b)
			}
			if (dir == "valid") != (verr == nil) {
				t.Errorf("%s: %v", f, verr)
			}
		}
	}
}
