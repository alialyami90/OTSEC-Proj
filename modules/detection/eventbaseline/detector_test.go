package eventbaseline_test

import (
	"errors"
	"slices"
	"testing"
	"time"

	"otsec.local/otsec/contracts/baseline"
	"otsec.local/otsec/contracts/event"
	"otsec.local/otsec/modules/detection/eventbaseline"
)

// The baseline every rule below runs against, learnt in the first 2000 s
// (all in UTC hour 0):
//   - A: one event at 0. Max per window 1, per bucket 1; hour 0 only.
//   - B: five events 100 s apart, ending at 2000. Periodic, interval 100 s,
//     tolerance 50 s, so its deadline is 2150.
//
// The detector is active from activeS.
func active(t *testing.T, activeS int, mut func(*baseline.Params)) *eventbaseline.Detector {
	t.Helper()
	return build(t, activeS, mut, false)
}

// activeB is active with B in the baseline, so every test that is not about
// absence stays clear of B's alarm.
func activeB(t *testing.T, activeS int) *eventbaseline.Detector {
	t.Helper()
	return build(t, activeS, nil, true)
}

func build(t *testing.T, activeS int, mut func(*baseline.Params), withB bool) *eventbaseline.Detector {
	t.Helper()
	l := learner(t, mut)
	observe(t, l, ser("A", "Asserted", at(0), ""))
	if withB {
		for s := 1600; s <= 2000; s += 100 {
			observe(t, l, ser("B", "Asserted", at(s), ""))
		}
	}
	r, err := l.Finish(at(2000))
	if err != nil {
		t.Fatal(err)
	}
	if withB {
		if ty := typeOf(t, r, "B", "Asserted"); ty.Periodic == nil || ty.Periodic.IntervalS != 100 {
			t.Fatalf("B is not periodic: %+v", ty)
		}
	}
	d, err := eventbaseline.NewDetector(eventbaseline.DetectorConfig{Baseline: r.Baseline, Hash: r.Hash, ActiveFrom: at(activeS)})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func feed(t *testing.T, d *eventbaseline.Detector, evs ...*event.Event) (out []*baseline.Alarm) {
	t.Helper()
	for _, e := range evs {
		o, err := d.Observe(eventbaseline.Obs{Event: e})
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, o.Alarms...)
	}
	return out
}

func tick(t *testing.T, d *eventbaseline.Detector, s int) []*baseline.Alarm {
	t.Helper()
	o, err := d.Tick(at(s))
	if err != nil {
		t.Fatal(err)
	}
	return o.Alarms
}

func ruleList(as []*baseline.Alarm) (out []baseline.Rule) {
	for _, a := range as {
		out = append(out, a.Rule)
	}
	return out
}

func seqs(ids []event.EventID) (out []uint64) {
	for _, id := range ids {
		out = append(out, id.Seq)
	}
	return out
}

func ids(evs ...*event.Event) (out []uint64) {
	for _, e := range evs {
		out = append(out, e.ID.Seq)
	}
	return out
}

func wantRules(t *testing.T, got []*baseline.Alarm, want ...baseline.Rule) {
	t.Helper()
	if !slices.Equal(ruleList(got), want) {
		t.Fatalf("rules %v, want %v", ruleList(got), want)
	}
	for _, a := range got {
		if err := a.Validate(); err != nil {
			t.Errorf("%s alarm: %v", a.Rule, err)
		}
		if _, err := a.Health(); err != nil {
			t.Errorf("%s alarm health: %v", a.Rule, err)
		}
	}
}

// TestDetectorRepeats: more than repeats_n in the window alarms, listing the
// repeats_n + 1 events of the window the breaking event closed; exactly
// repeats_n does not, and two events exactly a window apart are in different
// windows.
func TestDetectorRepeats(t *testing.T) {
	mut := func(p *baseline.Params) { p.RepeatsWindowS = 100; p.RateMin = 100 }
	mk := func(s ...int) (evs []*event.Event) {
		for _, x := range s {
			evs = append(evs, ser("A", "Asserted", at(x), ""))
		}
		return evs
	}
	d := active(t, 2100, mut)
	evs := mk(3000, 3050, 3090, 3099)
	got := feed(t, d, evs...)
	wantRules(t, got, baseline.RuleRepeats)
	if !slices.Equal(seqs(got[0].Events), ids(evs...)) || got[0].EventsTotal != 4 || got[0].AtUTC != at(3099).Format(time.RFC3339Nano) {
		t.Errorf("alarm %+v", got[0])
	}
	if p := got[0].Params; len(p) != 2 || p[0].Name != "repeats_n" || p[0].Value != "3" || p[1].Value != "100" {
		t.Errorf("params %v", p)
	}
	// The fourth a window after the first: the first is out of the window.
	wantRules(t, feed(t, active(t, 2100, mut), mk(3000, 3050, 3090, 3100)...))
	// Exactly repeats_n.
	wantRules(t, feed(t, active(t, 2100, mut), mk(3000, 3050, 3090)...))
}

// TestDetectorRepeatsOffWhenTheBaselineSawN: where the baseline's maximum
// reached repeats_n, a burst of that size is normal.
func TestDetectorRepeatsOffWhenTheBaselineSawN(t *testing.T) {
	l := learner(t, func(p *baseline.Params) { p.RepeatsWindowS = 100; p.RateMin = 100 })
	observe(t, l, ser("A", "Asserted", at(0), ""), ser("A", "Asserted", at(1), ""), ser("A", "Asserted", at(2), ""), ser("A", "Asserted", at(1900), ""))
	r, err := l.Finish(at(2000))
	if err != nil {
		t.Fatal(err)
	}
	if m := typeOf(t, r, "A", "Asserted").MaxPerWindow; m != 3 {
		t.Fatalf("max_per_window %d", m)
	}
	d, _ := eventbaseline.NewDetector(eventbaseline.DetectorConfig{Baseline: r.Baseline, Hash: r.Hash, ActiveFrom: at(2100)})
	wantRules(t, feed(t, d, ser("A", "Asserted", at(3000), ""), ser("A", "Asserted", at(3001), ""), ser("A", "Asserted", at(3002), ""), ser("A", "Asserted", at(3003), ""), ser("A", "Asserted", at(3004), "")))
}

// TestDetectorRate: a bucket above the bound alarms once, on the event that
// passes it; a later bucket starts again.
func TestDetectorRate(t *testing.T) {
	d := active(t, 2100, func(p *baseline.Params) { p.RateBucketS = 100; p.RepeatsN = 50 })
	e := []*event.Event{ser("A", "Asserted", at(3000), ""), ser("A", "Asserted", at(3010), ""), ser("A", "Asserted", at(3020), "")}
	wantRules(t, feed(t, d, e[:2]...))
	got := feed(t, d, e[2])
	wantRules(t, got, baseline.RuleRate)
	if !slices.Equal(seqs(got[0].Events), ids(e...)) || got[0].EventsTotal != 3 {
		t.Errorf("events %v total %d: the bucket's events up to the one that passed the bound", seqs(got[0].Events), got[0].EventsTotal)
	}
	if got[0].BaselineValue != "max_per_bucket 1, bound 2" {
		t.Errorf("baseline value %q", got[0].BaselineValue)
	}
	// The same bucket again, and the next bucket at the bound, raise nothing.
	wantRules(t, feed(t, d, ser("A", "Asserted", at(3030), ""), ser("A", "Asserted", at(3100), ""), ser("A", "Asserted", at(3110), "")))
}

// TestDetectorTime: an hour in which the baseline never saw the type.
func TestDetectorTime(t *testing.T) {
	d := active(t, 2100, func(p *baseline.Params) { p.RateMin = 100 })
	wantRules(t, feed(t, d, ser("A", "Asserted", at(3599), "")))
	got := feed(t, d, ser("A", "Asserted", at(3600), ""))
	wantRules(t, got, baseline.RuleTime)
	if got[0].Clock != baseline.ClockReceived || got[0].BaselineValue != "seen in UTC hours 0" {
		t.Errorf("alarm %+v", got[0])
	}
}

// TestDetectorNewType: on the first occurrence only, and a catch-up row of
// a new type alarms too, saying so; a catch-up row of a known type raises
// nothing at all.
func TestDetectorNewType(t *testing.T) {
	d := active(t, 2100, func(p *baseline.Params) { p.RateMin = 100 })
	c1, c2 := ser("C", "Asserted", at(3000), ""), ser("C", "Asserted", at(3001), "")
	got := feed(t, d, c1, c2)
	wantRules(t, got, baseline.RuleNewType)
	if !slices.Equal(seqs(got[0].Events), ids(c1)) || got[0].KeyText != "C Asserted" {
		t.Errorf("alarm %+v", got[0])
	}
	got = feed(t, d, ser("D", "Asserted", at(3010), event.AlignGapBefore))
	wantRules(t, got, baseline.RuleNewType)
	if got[0].Observation != "first occurrence, received "+at(3010).Format(time.RFC3339Nano)+", catch_up: gap-before" {
		t.Errorf("observation %q", got[0].Observation)
	}
	var back []*event.Event
	for range 20 {
		back = append(back, ser("A", "Asserted", at(3020), event.AlignGapBefore))
	}
	wantRules(t, feed(t, d, back...))
}

// TestDetectorAbsence: a periodic type missing past interval + tolerance
// alarms at the deadline. An occurrence at the deadline is in time.
func TestDetectorAbsence(t *testing.T) {
	d := activeB(t, 2100)
	wantRules(t, tick(t, d, 2150))
	got := tick(t, d, 2151)
	wantRules(t, got, baseline.RuleAbsence)
	if got[0].AtUTC != at(2150).Format(time.RFC3339Nano) || len(got[0].Events) != 0 || got[0].EventsTotal != 0 {
		t.Errorf("alarm %+v", got[0])
	}
	if p := got[0].Params; len(p) != 2 || p[0].Value != "100" || p[1].Value != "50" {
		t.Errorf("params %v", p)
	}
	wantRules(t, tick(t, d, 9000)) // once

	// An occurrence exactly at the deadline is in time, and starts the next.
	d = activeB(t, 2100)
	wantRules(t, feed(t, d, ser("B", "Asserted", at(2150), "")))
	wantRules(t, tick(t, d, 2300))
	wantRules(t, tick(t, d, 2301), baseline.RuleAbsence)

	// One a nanosecond late: the alarm for the deadline comes first.
	d = activeB(t, 2100)
	got = feed(t, d, ser("B", "Asserted", at(2150).Add(1), ""))
	wantRules(t, got, baseline.RuleAbsence)
	if got[0].AtUTC != at(2150).Format(time.RFC3339Nano) {
		t.Errorf("at %s", got[0].AtUTC)
	}

	// A deadline that ran out before the acknowledgement alarms nothing, until
	// the type occurs again.
	d = activeB(t, 2200)
	wantRules(t, tick(t, d, 3000))
	wantRules(t, feed(t, d, ser("B", "Asserted", at(3000), "")))
	wantRules(t, tick(t, d, 3150))
	wantRules(t, tick(t, d, 3151), baseline.RuleAbsence)
}

// TestDetectorHolds: one alarm per rule and type per hold, the breaks held
// meanwhile are listed on the next alarm; at most max_alarms_per_hold per
// asset, with one notice.
func TestDetectorHolds(t *testing.T) {
	d := active(t, 2100, func(p *baseline.Params) { p.RateMin = 100 })
	a1, a2, a3 := ser("A", "Asserted", at(3700), ""), ser("A", "Asserted", at(3800), ""), ser("A", "Asserted", at(7300), "")
	wantRules(t, feed(t, d, a1), baseline.RuleTime)
	wantRules(t, feed(t, d, a2))
	got := feed(t, d, a3)
	wantRules(t, got, baseline.RuleTime)
	if !slices.Equal(seqs(got[0].Events), ids(a2, a3)) || got[0].EventsTotal != 2 {
		t.Errorf("events %v total %d: the held break and the new one", seqs(got[0].Events), got[0].EventsTotal)
	}

	d = active(t, 2100, func(p *baseline.Params) { p.RateMin = 100; p.MaxAlarmsPerHold = 2 })
	var notices int
	var alarms int
	for i, el := range []string{"C", "D", "E", "F"} {
		o, err := d.Observe(eventbaseline.Obs{Event: ser(el, "Asserted", at(3000+i), "")})
		if err != nil {
			t.Fatal(err)
		}
		alarms += len(o.Alarms)
		if o.Held != nil {
			notices++
			if o.Held.AssetID != unitAsset || o.Held.HoldS != 3600 {
				t.Errorf("notice %+v", o.Held)
			}
		}
	}
	if alarms != 2 || notices != 1 || d.HeldNow() != 2 {
		t.Errorf("%d alarms, %d notices, %d held: two alarms, one notice, two held", alarms, notices, d.HeldNow())
	}
	// The hold ends an hour after its first alarm; a new type then alarms.
	wantRules(t, feed(t, d, ser("G", "Asserted", at(3000+3600), "")), baseline.RuleNewType)
}

// TestDetectorNotCounted: a possible duplicate that was not counted breaks
// no rule and is shown on the next alarm of its type.
func TestDetectorNotCounted(t *testing.T) {
	d := active(t, 2100, func(p *baseline.Params) { p.RateMin = 100; p.RepeatsN = 50 })
	dup := ser("A", "Asserted", at(3000), event.AlignPossibleDuplicate)
	o, err := d.Observe(eventbaseline.Obs{Event: dup, NotCounted: true})
	if err != nil || len(o.Alarms) != 0 {
		t.Fatalf("%v %v", o, err)
	}
	got := feed(t, d, ser("A", "Asserted", at(3700), ""))
	wantRules(t, got, baseline.RuleTime)
	if !slices.Equal(seqs(got[0].NotCounted), ids(dup)) || got[0].NotCountedTotal != 1 {
		t.Errorf("not counted %v of %d", seqs(got[0].NotCounted), got[0].NotCountedTotal)
	}
}

// TestDetectorBeforeActivationAndOrder: nothing alarms before the
// acknowledgement; an event before one already taken is an error, and an
// event of another asset too.
func TestDetectorBeforeActivationAndOrder(t *testing.T) {
	d := active(t, 3000, nil)
	wantRules(t, feed(t, d, ser("Z", "Asserted", at(2500), "")))
	wantRules(t, feed(t, d, ser("Z", "Asserted", at(3100), "")), baseline.RuleNewType)
	if _, err := d.Observe(eventbaseline.Obs{Event: ser("A", "Asserted", at(3050), "")}); !errors.Is(err, eventbaseline.ErrOrder) {
		t.Errorf("out of order: %v", err)
	}
	if _, err := d.Tick(at(3050)); !errors.Is(err, eventbaseline.ErrOrder) {
		t.Errorf("tick back: %v", err)
	}
	other := ser("A", "Asserted", at(3200), "")
	other.Source.Asset.ID = "6a6a6a6a-0001-4a6a-8a6a-000000000001"
	if _, err := d.Observe(eventbaseline.Obs{Event: other}); !errors.Is(err, eventbaseline.ErrAsset) {
		t.Errorf("other asset: %v", err)
	}
}
