package eventbaseline_test

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"
	"time"

	"otsec.local/otsec/contracts/baseline"
	"otsec.local/otsec/contracts/event"
	"otsec.local/otsec/modules/detection/eventbaseline"
)

const unitAsset = "5e3a1c2d-9b8f-4e7a-8c6d-1f2e3d4c5b6a"

var t0 = time.Date(2026, 1, 5, 0, 0, 0, 0, time.UTC)

func unitParams() baseline.Params {
	return baseline.Params{
		MinDurationS: 1000, MinEvents: 1,
		RepeatsN: 3, RepeatsWindowS: 600,
		RateBucketS: 3600, RateFactorPct: 200, RateMin: 2,
		PeriodicMinOccurrences: 4, PeriodicSpreadPct: 10, AbsenceTolerancePct: 50,
		TimeClock: baseline.ClockReceived, MaxTypes: 4096, AlarmHoldS: 3600, MaxAlarmsPerHold: 8,
	}
}

var nextSeq uint64

// ser builds a parsed SER row received at at.
func ser(elem, state string, at time.Time, align event.Alignment) *event.Event {
	nextSeq++
	row := fmt.Sprintf("%d %s %s", nextSeq, elem, state)
	sum := sha256.Sum256([]byte(row))
	if align == "" {
		align = event.AlignOK
	}
	return &event.Event{
		ID:     event.EventID{NodeID: gtNode, Stream: "events/unit", Seq: nextSeq},
		Origin: event.OriginDevice, Kind: event.KindSER,
		Received:   event.Received{UTC: at.UTC().Format(time.RFC3339Nano), ResolutionNS: 1000, Clock: event.Clock{Sync: event.SyncSynchronized}},
		Source:     event.Source{Asset: &event.AssetRef{ID: unitAsset}},
		Collection: &event.Collection{Method: event.MethodAdapterPoll, Alignment: align, ParseStatus: event.ParseOK},
		Native:     &event.Native{Bytes: []byte(row), RecordSHA256: hex.EncodeToString(sum[:]), RecordLength: int64(len(row))},
		Normalized: &event.Normalized{Subject: elem, SubjectType: "relay-word-bit", Value: state, Category: event.Unmapped},
	}
}

func learner(t *testing.T, mut func(*baseline.Params)) *eventbaseline.Learner {
	t.Helper()
	p := unitParams()
	if mut != nil {
		mut(&p)
	}
	l, err := eventbaseline.NewLearner(eventbaseline.LearnerConfig{Node: gtNode, AssetID: unitAsset, Params: p, Version: 1})
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func observe(t *testing.T, l *eventbaseline.Learner, evs ...*event.Event) {
	t.Helper()
	for _, e := range evs {
		if err := l.Observe(eventbaseline.Obs{Event: e}); err != nil {
			t.Fatal(err)
		}
	}
}

// finish ends the period 2000 s after t0, after the last event.
func finish(t *testing.T, l *eventbaseline.Learner) *eventbaseline.Result {
	t.Helper()
	r, err := l.Finish(t0.Add(2000 * time.Second))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func typeOf(t *testing.T, r *eventbaseline.Result, elem, state string) baseline.Type {
	t.Helper()
	ty, ok := r.Baseline.Lookup(baseline.Key{Source: baseline.SourceSER, Element: elem, State: state})
	if !ok {
		t.Fatalf("type %s %s not learnt", elem, state)
	}
	return *ty
}

func at(s int) time.Time { return t0.Add(time.Duration(s) * time.Second) }

// TestLearnerWindowIsHalfOpen: two occurrences exactly repeats_window_s apart
// are in different windows; one second less and they share one (C10).
func TestLearnerWindowIsHalfOpen(t *testing.T) {
	for _, tc := range []struct {
		gap  int
		want int64
	}{{600, 1}, {599, 2}} {
		l := learner(t, nil)
		observe(t, l, ser("A", "Asserted", at(0), ""), ser("A", "Asserted", at(tc.gap), ""))
		if got := typeOf(t, finish(t, l), "A", "Asserted").MaxPerWindow; got != tc.want {
			t.Errorf("gap %d s: max_per_window %d, want %d", tc.gap, got, tc.want)
		}
	}
}

// TestLearnerBucketsRunFromTheEpoch: three events in one clock hour, two in
// the next.
func TestLearnerBucketsRunFromTheEpoch(t *testing.T) {
	l := learner(t, nil)
	observe(t, l, ser("A", "Asserted", at(10), ""), ser("A", "Asserted", at(20), ""), ser("A", "Asserted", at(30), ""),
		ser("A", "Asserted", at(3600), ""), ser("A", "Asserted", at(3700), ""))
	ty := typeOf(t, finish2(t, l, 4000), "A", "Asserted")
	if ty.MaxPerBucket != 3 || ty.Full != 5 || ty.HoursUTC[0] != 3 || ty.HoursUTC[1] != 2 {
		t.Errorf("max_per_bucket %d, full %d, hours %v", ty.MaxPerBucket, ty.Full, ty.HoursUTC[:2])
	}
}

func finish2(t *testing.T, l *eventbaseline.Learner, s int) *eventbaseline.Result {
	t.Helper()
	r, err := l.Finish(at(s))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// TestLearnerTypeOnlyCountsForTheTypeOnly: catch-up rows give the type and
// its Count, and nothing else (D4-9).
func TestLearnerTypeOnlyCountsForTheTypeOnly(t *testing.T) {
	l := learner(t, nil)
	for range 5 {
		observe(t, l, ser("A", "Asserted", at(5), event.AlignFirstRead))
	}
	observe(t, l, ser("B", "Asserted", at(6), ""))
	r := finish(t, l)
	a := typeOf(t, r, "A", "Asserted")
	if a.Count != 5 || a.Full != 0 || a.MaxPerWindow != 0 || a.MaxPerBucket != 0 || a.HoursUTC != [24]int64{} {
		t.Errorf("catch-up learnt more than the type: %+v", a)
	}
	if c := r.Baseline.Counts; c.TypeOnly != 5 || c.Full != 1 || c.Events != 6 {
		t.Errorf("counts %+v", c)
	}
}

// TestLearnerPeriodic: found at periodic_min_occurrences, not one fewer; the
// spread test is in integers and exact; the median is the upper middle.
func TestLearnerPeriodic(t *testing.T) {
	series := func(times ...int) *eventbaseline.Result {
		l := learner(t, nil)
		for _, s := range times {
			observe(t, l, ser("H", "Asserted", at(s), ""))
		}
		return finish(t, l)
	}
	if ty := typeOf(t, series(0, 100, 200, 300), "H", "Asserted"); ty.Periodic == nil || ty.Periodic.IntervalS != 100 || ty.Periodic.ToleranceS != 50 {
		t.Errorf("4 occurrences at 100 s: %+v", ty.Periodic)
	}
	if ty := typeOf(t, series(0, 100, 200), "H", "Asserted"); ty.Periodic != nil {
		t.Errorf("3 occurrences are fewer than periodic_min_occurrences: %+v", ty.Periodic)
	}
	// Gaps 100, 100, 110: median (upper middle of 3) is 100, and 110 is
	// exactly 10% over it: periodic. Gaps 100, 100, 111: not.
	if ty := typeOf(t, series(0, 100, 200, 310), "H", "Asserted"); ty.Periodic == nil {
		t.Errorf("a gap exactly at the spread is periodic")
	}
	if ty := typeOf(t, series(0, 100, 200, 311), "H", "Asserted"); ty.Periodic != nil {
		t.Errorf("a gap one second past the spread is not: %+v", ty.Periodic)
	}
	// Gaps 90, 100, 110, 110: upper middle gaps[2] = 110; 90 is 18% below it.
	if ty := typeOf(t, series(0, 90, 190, 300, 410), "H", "Asserted"); ty.Periodic != nil {
		t.Errorf("median is the upper middle (110), so 90 is outside 10%%: %+v", ty.Periodic)
	}
}

// TestLearnerRefusals: an event of another asset, an event out of order and
// a finish before the minima are errors that name what is wrong, and take
// nothing; events that belong to no baseline are counted aside.
func TestLearnerRefusals(t *testing.T) {
	l := learner(t, nil)
	observe(t, l, ser("A", "Asserted", at(100), ""))
	other := ser("A", "Asserted", at(200), "")
	other.Source.Asset.ID = "6a6a6a6a-0001-4a6a-8a6a-000000000001"
	if err := l.Observe(eventbaseline.Obs{Event: other}); !errors.Is(err, eventbaseline.ErrAsset) {
		t.Errorf("other asset: %v", err)
	}
	if err := l.Observe(eventbaseline.Obs{Event: ser("A", "Asserted", at(99), "")}); !errors.Is(err, eventbaseline.ErrOrder) {
		t.Errorf("out of order: %v", err)
	}
	unresolved := ser("A", "Asserted", at(300), "")
	unresolved.Source.Asset = nil
	unresolved.Flags = []string{"asset-unresolved"}
	observe(t, l, unresolved)
	if n := l.Excluded()[baseline.ExcludedUnresolved]; n != 1 {
		t.Errorf("excluded %v", l.Excluded())
	}
	if _, err := l.Finish(at(500)); !errors.Is(err, eventbaseline.ErrNotDone) {
		t.Errorf("finish before the minimum duration: %v", err)
	}
	if _, err := l.Finish(at(50)); err == nil {
		t.Errorf("finish before the last event")
	}
	r := finish(t, l)
	if r.Baseline.Counts.Events != 1 {
		t.Errorf("the refused events were counted: %+v", r.Baseline.Counts)
	}
}

// TestLearnerGapsExtendThePeriod: an interval of failed collection does not
// count toward the minimum duration (R4.8).
func TestLearnerGapsExtendThePeriod(t *testing.T) {
	l := learner(t, nil)
	observe(t, l, ser("A", "Asserted", at(0), ""))
	l.Gap(at(100), at(400), "failed.timeout")
	if pr := l.Progress(at(1200)); pr.CollectedS != 900 || pr.Done {
		t.Errorf("progress %+v: 1200 s less a 300 s gap is 900 of 1000", pr)
	}
	if pr := l.Progress(at(1300)); pr.CollectedS != 1000 || !pr.Done {
		t.Errorf("progress %+v", pr)
	}
	r, err := l.Finish(at(1300))
	if err != nil {
		t.Fatal(err)
	}
	if g := r.Baseline.Period.Gaps; len(g) != 1 || g[0].Reason != "failed.timeout" || r.Baseline.Period.CollectedS != 1000 {
		t.Errorf("period %+v", r.Baseline.Period)
	}
}

// TestLearnerMaxTypesKeepsTheHighestCounts: past max_types the types with
// the highest count are kept, ties by key, whenever they were met; a later
// high-count type displaces an earlier low-count one (C10, D4-15).
func TestLearnerMaxTypesKeepsTheHighestCounts(t *testing.T) {
	has := func(r *eventbaseline.Result, el string) bool {
		_, ok := r.Baseline.Lookup(baseline.Key{Source: baseline.SourceSER, Element: el, State: "Asserted"})
		return ok
	}
	l := learner(t, func(p *baseline.Params) { p.MaxTypes = 2 })
	observe(t, l, ser("A", "Asserted", at(1), ""), ser("B", "Asserted", at(2), ""), ser("C", "Asserted", at(3), ""), ser("C", "Asserted", at(4), ""), ser("D", "Asserted", at(5), ""))
	r := finish(t, l)
	if len(r.Baseline.Types) != 2 || !has(r, "C") || !has(r, "A") || has(r, "B") || has(r, "D") {
		t.Errorf("kept %d types, A:%v B:%v C:%v D:%v: C (2 events) displaces the first-met B, and A wins the tie with B and D by key",
			len(r.Baseline.Types), has(r, "A"), has(r, "B"), has(r, "C"), has(r, "D"))
	}
	if c := r.Baseline.Counts; c.TypesOverflow != 2 || c.Events != 5 || c.Full != 5 {
		t.Errorf("counts %+v", c)
	}
	// Ties alone: the first two keys.
	l = learner(t, func(p *baseline.Params) { p.MaxTypes = 2 })
	observe(t, l, ser("D", "Asserted", at(1), ""), ser("C", "Asserted", at(2), ""), ser("B", "Asserted", at(3), ""), ser("A", "Asserted", at(4), ""))
	if r = finish(t, l); !has(r, "A") || !has(r, "B") || has(r, "C") || has(r, "D") {
		t.Errorf("a tie keeps the lowest keys, not the first met")
	}
}

// TestLearnerWorkingSetBoundary: the learner holds MaxTypesCeiling types; the
// next type met is counted and never held, and a repeat of it is not
// counted twice.
func TestLearnerWorkingSetBoundary(t *testing.T) {
	l := learner(t, nil)
	for i := range baseline.MaxTypesCeiling {
		observe(t, l, ser(fmt.Sprintf("T%04d", i), "Asserted", at(1), ""))
	}
	if h, o := l.TypesHeld(); h != baseline.MaxTypesCeiling || o != 0 {
		t.Fatalf("after %d types: held %d, overflow %d", baseline.MaxTypesCeiling, h, o)
	}
	observe(t, l, ser("X", "Asserted", at(2), ""), ser("X", "Asserted", at(3), ""), ser("T0000", "Asserted", at(4), ""))
	if h, o := l.TypesHeld(); h != baseline.MaxTypesCeiling || o != 1 {
		t.Errorf("the 4097th type: held %d, overflow %d", h, o)
	}
	r := finish(t, l)
	// 4096 types do not fit the byte cap, so the record is cut by count, and
	// everything left out, and the type never held, is counted.
	if c := r.Baseline.Counts; c.TypesOverflow != int64(1+baseline.MaxTypesCeiling-len(r.Baseline.Types)) || c.Events != baseline.MaxTypesCeiling+3 {
		t.Errorf("%d types, counts %+v", len(r.Baseline.Types), c)
	}
	if _, ok := r.Baseline.Lookup(baseline.Key{Source: baseline.SourceSER, Element: "T0000", State: "Asserted"}); !ok {
		t.Errorf("T0000, the highest count, was left out")
	}
}

// TestLearnerByteCapLeavesOutTheLeastCounted: a record that does not fit the
// cap drops the types with the lowest count, ties by key.
func TestLearnerByteCapLeavesOutTheLeastCounted(t *testing.T) {
	build := func(maxBytes int) *eventbaseline.Result {
		l, err := eventbaseline.NewLearner(eventbaseline.LearnerConfig{Node: gtNode, AssetID: unitAsset, Params: unitParams(), Version: 1, MaxBytes: maxBytes})
		if err != nil {
			t.Fatal(err)
		}
		observe(t, l, ser("A", "Asserted", at(1), ""), ser("B", "Asserted", at(2), ""), ser("B", "Asserted", at(3), ""), ser("C", "Asserted", at(4), ""), ser("C", "Asserted", at(5), ""), ser("C", "Asserted", at(6), ""))
		return finish(t, l)
	}
	full := build(0)
	if len(full.Baseline.Types) != 3 {
		t.Fatalf("%d types", len(full.Baseline.Types))
	}
	for cap := len(full.Bytes) - 1; cap > 0; cap-- {
		r := build(cap)
		if len(r.Baseline.Types) < 3 {
			if len(r.Bytes) > cap {
				t.Errorf("%d bytes over the cap %d", len(r.Bytes), cap)
			}
			if _, ok := r.Baseline.Lookup(baseline.Key{Source: baseline.SourceSER, Element: "C", State: "Asserted"}); !ok {
				t.Errorf("the most counted type was left out")
			}
			if _, ok := r.Baseline.Lookup(baseline.Key{Source: baseline.SourceSER, Element: "A", State: "Asserted"}); ok {
				t.Errorf("the least counted type was kept")
			}
			if r.Baseline.Counts.TypesOverflow != int64(3-len(r.Baseline.Types)) || r.Baseline.Counts.Events != 6 {
				t.Errorf("counts %+v", r.Baseline.Counts)
			}
			return
		}
	}
	t.Fatal("no cap left a type out")
}
