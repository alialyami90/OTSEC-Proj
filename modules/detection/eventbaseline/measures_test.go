package eventbaseline_test

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"otsec.local/otsec/contracts/baseline"
	"otsec.local/otsec/modules/detection/eventbaseline"
)

// The V-M4 measures (docs/verification.md, "R4.8 observation period and
// measures"), produced by tests and not by hand: recall per departure kind,
// precision, latency per kind, the held-out alarm count per asset-day, the
// alarms before the acknowledgement, and what each alarm carries. They run on
// B6's GT-INJ series, which is synthetic: everything here is `simulated`, and
// says nothing about the false-positive rate on a real device.
// docs/phase4/B4-measures.md has the numbers and the commands. Run with -v
// to see them.

// gtDeparture is one injected departure in events.json.
type gtDeparture struct {
	ID          string   `json:"id"`
	Kind        string   `json:"kind"`
	Asset       string   `json:"asset"`
	Type        []any    `json:"type"`
	At          string   `json:"at"`
	BeforeAck   bool     `json:"before_ack"`
	CatchUp     string   `json:"catch_up"`
	Events      []string `json:"events"`
	ExpectRules []string `json:"expect_rules"`
	GapFrom     string   `json:"gap_from"`
	Removed     []string `json:"removed"`
}

func loadDepartures(t testing.TB) []gtDeparture {
	t.Helper()
	b, err := os.ReadFile("../../../tests/integration/gt_inj/events.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Departures []gtDeparture `json:"departures"`
	}
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	return f.Departures
}

// measured is an alarm with how it was raised.
type measured struct {
	a     *baseline.Alarm
	asset string
	key   string
	// by is the sequence number of the event whose Observe call raised it,
	// or 0 when a Tick did; at is that call's time.
	by uint64
	at time.Time
}

// run feeds the detectors every event of the series from its first, the
// period's and the pre-acknowledgement departure's included, with a Tick every
// tick of simulated time from the acknowledgement on (0: one Tick at the end).
func run(t testing.TB, base map[string]*eventbaseline.Result, ack time.Time, events []gtEvent, last time.Time, tick time.Duration) (out []measured) {
	t.Helper()
	ds := map[string]*eventbaseline.Detector{}
	for name, r := range base {
		d, err := eventbaseline.NewDetector(eventbaseline.DetectorConfig{Baseline: r.Baseline, Hash: r.Hash, ActiveFrom: ack})
		if err != nil {
			t.Fatal(err)
		}
		ds[name] = d
	}
	keys := map[string]string{}
	for _, e := range events {
		if k, _, ok := baseline.KeyOf(toEvent(t, e)); ok {
			keys[k.String()] = gtKey(e)
		}
	}
	take := func(name string, o eventbaseline.Output, by uint64, at time.Time) {
		for _, a := range o.Alarms {
			if err := a.Validate(); err != nil {
				t.Fatalf("invalid alarm: %v", err)
			}
			out = append(out, measured{a: a, asset: name, key: keys[a.Key.String()], by: by, at: at})
		}
	}
	next := map[string]time.Time{}
	for name := range ds {
		next[name] = ack.Add(tick)
	}
	for _, e := range events {
		at := ts(t, e.Received)
		if tick > 0 && !at.Before(ack) {
			for ; next[e.Asset].Before(at); next[e.Asset] = next[e.Asset].Add(tick) {
				o, err := ds[e.Asset].Tick(next[e.Asset])
				if err != nil {
					t.Fatal(err)
				}
				take(e.Asset, o, 0, next[e.Asset])
			}
		}
		o, err := ds[e.Asset].Observe(eventbaseline.Obs{Event: toEvent(t, e)})
		if err != nil {
			t.Fatalf("%s: %v", e.ID, err)
		}
		take(e.Asset, o, seqOf(t, e.ID), at)
	}
	names := make([]string, 0, len(ds))
	for name := range ds {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if tick > 0 {
			for ; !next[name].After(last); next[name] = next[name].Add(tick) {
				o, err := ds[name].Tick(next[name])
				if err != nil {
					t.Fatal(err)
				}
				take(name, o, 0, next[name])
			}
			continue
		}
		o, err := ds[name].Tick(last)
		if err != nil {
			t.Fatal(err)
		}
		take(name, o, 0, last)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].a.AtUTC < out[j].a.AtUTC })
	return out
}

func seqSet(a *baseline.Alarm) map[uint64]bool {
	m := map[uint64]bool{}
	for _, id := range a.Events {
		m[id.Seq] = true
	}
	return m
}

// matches reports whether alarm m is the alarm of departure d: the rule of its
// kind, on its asset and type, citing every event of the departure (absence:
// raised inside the gap, which it must be to have been the missing events').
func matches(t testing.TB, m measured, d gtDeparture) bool {
	if ruleOf(d.Kind) != m.a.Rule || m.asset != d.Asset || m.key != typeKey(d.Type) {
		return false
	}
	if d.Kind == "absence" {
		at := ts(t, m.a.AtUTC)
		lastRemoved := ts(t, d.Removed[len(d.Removed)-1])
		return !at.Before(ts(t, d.GapFrom)) && !at.After(lastRemoved.Add(24*time.Hour))
	}
	have := seqSet(m.a)
	for _, id := range d.Events {
		if !have[seqOf(t, id)] {
			return false
		}
	}
	return true
}

// TestV_M4RecallPrecisionLatency: V-M4's measures on B6's GT-INJ series.
//
//   - Recall per kind: the number of injected departures of the kind that
//     raise their alarm over the number injected, at least 3 of each kind, and
//     100% (the target). The departure before the acknowledgement is a control,
//     not counted.
//   - Precision: alarms that match an injected departure over all alarms,
//     which are every alarm the series raises, with the pre-acknowledgement
//     events fed in as well.
//   - Latency, per kind: the event-driven rules are raised by the Observe
//     call of the event that broke the baseline (the last event the alarm
//     cites) and AtUTC is that event's received time, so 0 s. Absence is
//     raised on the first Tick past the deadline, with the deadline = the
//     last occurrence + interval + tolerance as its AtUTC; with a Tick every
//     minute the Tick follows the deadline by less than a minute.
//
// What it cannot show: the collection cycle, the delivery and the feeder add
// to every figure here, and none of them is in this package.
func TestV_M4RecallPrecisionLatency(t *testing.T) {
	s := load(t, "events.json")
	deps := loadDepartures(t)
	base := learn(t, s, nil)
	ack, end := ts(t, s.Period.Ack), ts(t, s.Period.TestEnd)
	const tick = time.Minute
	got := run(t, base, ack, s.Events, end, tick)

	// Recall per kind.
	kinds := []string{"new", "repeats", "rate", "time", "absence"}
	injected, caught := map[string]int{}, map[string]int{}
	used := map[int]bool{}
	byDep := map[string]measured{}
	for _, d := range deps {
		if d.BeforeAck {
			continue
		}
		injected[d.Kind]++
		for i, m := range got {
			if !used[i] && matches(t, m, d) {
				used[i] = true
				caught[d.Kind]++
				byDep[d.ID] = m
				break
			}
		}
	}
	for _, k := range kinds {
		if injected[k] < 3 {
			t.Errorf("%s: %d injected departures, V-M4 needs at least 3", k, injected[k])
		}
		t.Logf("recall %-8s %d of %d", k, caught[k], injected[k])
		if caught[k] != injected[k] {
			t.Errorf("%s: %d of %d injected departures alarmed, target 100%%", k, caught[k], injected[k])
		}
	}

	// Precision.
	if len(used) != len(got) {
		for i, m := range got {
			if !used[i] {
				t.Errorf("an alarm that matches no injected departure: %s %s %s at %s", m.a.Rule, m.asset, m.key, m.a.AtUTC)
			}
		}
	}
	t.Logf("precision %d of %d alarms match an injected departure", len(used), len(got))

	// Latency.
	type span struct{ min, max time.Duration }
	lat := map[string]span{}
	note := func(kind string, d time.Duration) {
		sp, ok := lat[kind]
		if !ok || d < sp.min {
			sp.min = d
		}
		if !ok || d > sp.max {
			sp.max = d
		}
		lat[kind] = sp
	}
	for _, d := range deps {
		m, ok := byDep[d.ID]
		if !ok {
			continue
		}
		at := ts(t, m.a.AtUTC)
		if d.Kind == "absence" {
			// AtUTC is the deadline; the Tick that raised it came after it.
			if m.by != 0 || !m.at.After(at) {
				t.Errorf("%s: absence alarm at %s raised by event %d at %s", d.ID, at, m.by, m.at)
			}
			note("absence", m.at.Sub(at))
			if m.at.Sub(at) > tick {
				t.Errorf("%s: the Tick that raised the absence alarm came %s after its deadline, past the cadence %s", d.ID, m.at.Sub(at), tick)
			}
			continue
		}
		breaking := m.a.Events[len(m.a.Events)-1]
		if m.by != breaking.Seq {
			t.Errorf("%s: %s alarm raised by event %d, not by the breaking event %d", d.ID, d.Kind, m.by, breaking.Seq)
		}
		var rcv time.Time
		for _, e := range s.Events {
			if seqOf(t, e.ID) == breaking.Seq {
				rcv = ts(t, e.Received)
			}
		}
		if !at.Equal(rcv) {
			t.Errorf("%s: AtUTC %s is not the received time %s of the breaking event", d.ID, at, rcv)
		}
		note(d.Kind, at.Sub(rcv))
	}
	for _, k := range kinds {
		t.Logf("latency %-8s %s to %s", k, lat[k].min, lat[k].max)
	}
}

// TestV_M4NoAlarmBeforeTheAcknowledgement: zero departure alarms during the
// observation period and before the operator's acknowledgement. The
// learner has no alarm output at all, and a detector given every event of the
// period and the departure that comes before the acknowledgement raises
// nothing for them, and carries nothing of them into the alarms after it:
// the alarms are the same as when only the events from the acknowledgement
// on are fed (V-M4).
func TestV_M4NoAlarmBeforeTheAcknowledgement(t *testing.T) {
	s := load(t, "events.json")
	base := learn(t, s, nil)
	ack, end := ts(t, s.Period.Ack), ts(t, s.Period.TestEnd)

	all := run(t, base, ack, s.Events, end, 0)
	for _, m := range all {
		if ts(t, m.a.AtUTC).Before(ack) {
			t.Errorf("alarm before the acknowledgement %s: %s %s %s at %s", ack, m.a.Rule, m.asset, m.key, m.a.AtUTC)
		}
	}
	var after []gtEvent
	for _, e := range s.Events {
		if !ts(t, e.Received).Before(ack) {
			after = append(after, e)
		}
	}
	only := run(t, base, ack, after, end, 0)
	desc := func(ms []measured) (out []string) {
		for _, m := range ms {
			out = append(out, fmt.Sprintf("%s %s %s %s %v %s | %s", m.a.Rule, m.asset, m.key, m.a.AtUTC, m.a.Events, m.a.BaselineValue, m.a.Observation))
		}
		return out
	}
	if a, b := desc(all), desc(only); strings.Join(a, "\n") != strings.Join(b, "\n") {
		t.Errorf("events before the acknowledgement changed the alarms after it:\nall events:\n%s\nfrom the acknowledgement:\n%s", strings.Join(a, "\n"), strings.Join(b, "\n"))
	}
	// The pre-acknowledgement departure is in the series and would have alarmed
	// as a new type, had the baseline been active.
	var control bool
	for _, d := range loadDepartures(t) {
		if d.BeforeAck {
			control = true
			if !ts(t, d.At).Before(ack) || ts(t, d.At).Before(ts(t, s.Period.End)) {
				t.Errorf("%s is meant to fall between the period's end and the acknowledgement", d.ID)
			}
		}
	}
	if !control {
		t.Error("the series has no departure before the acknowledgement: the test is vacuous")
	}
	// A Tick before the acknowledgement is refused, not answered with alarms.
	d, err := eventbaseline.NewDetector(eventbaseline.DetectorConfig{Baseline: base["gt-inj-syslog"].Baseline, Hash: base["gt-inj-syslog"].Hash, ActiveFrom: ack})
	if err != nil {
		t.Fatal(err)
	}
	if o, err := d.Tick(ack.Add(-time.Hour)); err == nil || len(o.Alarms) != 0 {
		t.Errorf("a Tick before the acknowledgement: %d alarms, error %v", len(o.Alarms), err)
	}
}

// TestV_M4HeldOutAlarmsPerAssetDay: on the held-out benign series, which is as
// long as the observation period, the departure alarms per asset-day are at
// most the agreed bound, 0 on a synthetic series (V-M4).
func TestV_M4HeldOutAlarmsPerAssetDay(t *testing.T) {
	s := load(t, "events.json")
	h := load(t, "events-heldout.json")
	base := learn(t, s, nil)
	ack := ts(t, s.Period.Ack)
	last := ts(t, h.Events[len(h.Events)-1].Received)
	got := run(t, base, ack, h.Events, last, time.Minute)
	days := float64(last.Sub(ack)) / float64(24*time.Hour)
	assetDays := days * float64(len(base))
	rate := float64(len(got)) / assetDays
	t.Logf("held-out: %d alarms over %.1f asset-days (%d assets, %.1f days, %d events): %.3f per asset-day, bound 0", len(got), assetDays, len(base), days, len(h.Events), rate)
	const bound = 0.0
	if rate > bound {
		t.Errorf("%.3f alarms per asset-day, bound %.0f", rate, bound)
		for _, m := range got {
			t.Logf("  %s %s %s at %s", m.a.Rule, m.asset, m.key, m.a.AtUTC)
		}
	}
	if days < float64(s.Params.MinDurationS)/86400-1 {
		t.Errorf("the held-out series is %.1f days, shorter than the observation period", days)
	}
}

// TestV_M4EveryAlarmExplainsItself: every alarm of the series carries its rule,
// the baseline value, the parameters, the observation and the IDs of the events
// that broke it, and what it says agrees with the baseline it was raised
// against and the events it cites (V-M4). Alarm.Validate fixes the form
// (the rule's own parameter names in order, a baseline value and an
// observation, events for every rule but absence); this checks the content.
func TestV_M4EveryAlarmExplainsItself(t *testing.T) {
	s := load(t, "events.json")
	base := learn(t, s, nil)
	got := run(t, base, ts(t, s.Period.Ack), s.Events, ts(t, s.Period.TestEnd), 0)
	if len(got) != 16 {
		t.Fatalf("%d alarms, the series expects 16", len(got))
	}
	want := map[baseline.Rule][]string{
		baseline.RuleNewType: nil,
		baseline.RuleRepeats: {"repeats_n", "repeats_window_s"},
		baseline.RuleRate:    {"rate_bucket_s", "rate_factor_pct", "rate_min"},
		baseline.RuleTime:    nil,
		baseline.RuleAbsence: {"interval_s", "tolerance_s"},
	}
	pv := map[string]string{
		"repeats_n": fmt.Sprint(s.Params.RepeatsN), "repeats_window_s": fmt.Sprint(s.Params.RepeatsWindowS),
		"rate_bucket_s": fmt.Sprint(s.Params.RateBucketS), "rate_factor_pct": fmt.Sprint(s.Params.RateFactorPct), "rate_min": fmt.Sprint(s.Params.RateMin),
	}
	seen := map[baseline.Rule]bool{}
	for _, m := range got {
		a := m.a
		seen[a.Rule] = true
		who := fmt.Sprintf("%s %s %s", a.Rule, m.asset, m.key)
		r := base[m.asset]
		if a.Baseline != r.Hash || a.BaselineVersion != r.Baseline.Version {
			t.Errorf("%s: alarm names baseline %s v%d, raised against %s v%d", who, a.Baseline, a.BaselineVersion, r.Hash, r.Baseline.Version)
		}
		if a.Clock != baseline.ClockReceived {
			t.Errorf("%s: clock %q", who, a.Clock)
		}
		// The parameters are the baseline's, in the rule's order.
		var names []string
		for _, p := range a.Params {
			names = append(names, p.Name)
			if p.Name == "interval_s" || p.Name == "tolerance_s" {
				continue
			}
			if p.Value != pv[p.Name] {
				t.Errorf("%s: parameter %s = %s, the baseline's is %s", who, p.Name, p.Value, pv[p.Name])
			}
		}
		if strings.Join(names, ",") != strings.Join(want[a.Rule], ",") {
			t.Errorf("%s: parameters %v, want %v", who, names, want[a.Rule])
		}
		var ty *baseline.Type
		for i := range r.Baseline.Types {
			if r.Baseline.Types[i].Key == a.Key {
				ty = &r.Baseline.Types[i]
			}
		}
		if a.Rule == baseline.RuleNewType {
			if ty != nil {
				t.Errorf("%s: the baseline has this type", who)
			}
		} else if ty == nil {
			t.Fatalf("%s: the type is not in the baseline it was raised against", who)
		}
		// The baseline value states the baseline's own numbers for the type.
		switch a.Rule {
		case baseline.RuleRepeats:
			if v := fmt.Sprintf("max_per_window %d, below repeats_n %d", ty.MaxPerWindow, s.Params.RepeatsN); a.BaselineValue != v {
				t.Errorf("%s: baseline value %q, the baseline holds %q", who, a.BaselineValue, v)
			}
		case baseline.RuleRate:
			if v := fmt.Sprintf("max_per_bucket %d, bound %d", ty.MaxPerBucket, baseline.RateBound(ty.MaxPerBucket, s.Params)); a.BaselineValue != v {
				t.Errorf("%s: baseline value %q, the baseline holds %q", who, a.BaselineValue, v)
			}
		case baseline.RuleTime:
			var seenHours []string
			for h, n := range ty.HoursUTC {
				if n > 0 {
					seenHours = append(seenHours, fmt.Sprint(h))
				}
			}
			if !strings.HasPrefix(a.BaselineValue, "seen in UTC hours "+seenHours[0]+"-") || !strings.HasSuffix(a.BaselineValue, "-"+seenHours[len(seenHours)-1]) {
				t.Errorf("%s: baseline value %q, the baseline saw hours %v", who, a.BaselineValue, seenHours)
			}
		}
		if a.Rule == baseline.RuleAbsence {
			if ty.Periodic == nil {
				t.Fatalf("%s: not a periodic type in the baseline", who)
			}
			if a.Params[0].Value != fmt.Sprint(ty.Periodic.IntervalS) || a.Params[1].Value != fmt.Sprint(ty.Periodic.ToleranceS) {
				t.Errorf("%s: parameters %v, the baseline's are interval %d tolerance %d", who, a.Params, ty.Periodic.IntervalS, ty.Periodic.ToleranceS)
			}
		}
		if a.BaselineValue == "" || a.Observation == "" || a.KeyText == "" {
			t.Errorf("%s: missing explanation: %q / %q / %q", who, a.BaselineValue, a.Observation, a.KeyText)
		}
		// The events cited are the stream's, they are in order, and each was
		// received no later than the alarm.
		if a.Rule != baseline.RuleAbsence && (len(a.Events) == 0 || a.EventsTotal < int64(len(a.Events))) {
			t.Errorf("%s: events %v total %d", who, a.Events, a.EventsTotal)
		}
		prev := uint64(0)
		for _, id := range a.Events {
			if id.NodeID != gtNode || id.Seq <= prev {
				t.Errorf("%s: event ID %v out of order or from another node", who, id)
			}
			prev = id.Seq
			for _, e := range s.Events {
				if seqOf(t, e.ID) == id.Seq && (gtKey(e) != m.key && a.Rule != baseline.RuleAbsence || ts(t, e.Received).After(ts(t, a.AtUTC))) {
					t.Errorf("%s: cites %s, which is %s received %s", who, e.ID, gtKey(e), e.Received)
				}
			}
		}
		t.Logf("%-8s %-13s %s\n    baseline: %s\n    observed: %s\n    params %v, %d events, at %s", a.Rule, m.asset, m.key, a.BaselineValue, a.Observation, a.Params, a.EventsTotal, a.AtUTC)
	}
	for _, rule := range []baseline.Rule{baseline.RuleNewType, baseline.RuleRepeats, baseline.RuleRate, baseline.RuleTime, baseline.RuleAbsence} {
		if !seen[rule] {
			t.Errorf("the series raised no %s alarm", rule)
		}
	}
}
