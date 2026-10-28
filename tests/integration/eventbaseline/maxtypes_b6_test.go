// Package eventbaseline holds B6's independent checks of the event-behaviour
// learner (#287) against D4-15 item 2 and C10's Counts text, not against
// the implementation: the baseline keeps the max_types types with the
// highest Count, a tie going to the lower key in byte order (Key.String);
// the learner holds at most MaxTypesCeiling types while it observes;
// TypesOverflow is the types left out at Finish plus the distinct types
// first met while the working set was full, those counted up to
// MaxTypesCeiling and a lower bound past it; and the events in no type are
// Full + TypeOnly - the sum of Type.Count. Synthetic SER rows; ground truth
// GT-HAND. Evidence class: desk.
package eventbaseline

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"testing"
	"time"

	"otsec.local/otsec/contracts/baseline"
	"otsec.local/otsec/contracts/event"
	"otsec.local/otsec/modules/detection/eventbaseline"
)

const (
	b6Node  = "site-a-node1"
	b6Asset = "7b1d4c2e-3f5a-4e6b-9c8d-0a1b2c3d4e5f"
)

var b6T0 = time.Date(2026, 2, 2, 0, 0, 0, 0, time.UTC)

func b6Params(maxTypes int) baseline.Params {
	return baseline.Params{
		MinDurationS: 1000, MinEvents: 1,
		RepeatsN: 3, RepeatsWindowS: 600,
		RateBucketS: 3600, RateFactorPct: 200, RateMin: 2,
		PeriodicMinOccurrences: 4, PeriodicSpreadPct: 10, AbsenceTolerancePct: 50,
		TimeClock: baseline.ClockReceived, MaxTypes: int64(maxTypes), AlarmHoldS: 3600, MaxAlarmsPerHold: 8,
	}
}

type b6Feed struct {
	t   *testing.T
	l   *eventbaseline.Learner
	seq uint64
	at  time.Time
}

func newB6Feed(t *testing.T, maxTypes int) *b6Feed {
	l, err := eventbaseline.NewLearner(eventbaseline.LearnerConfig{Node: b6Node, AssetID: b6Asset, Params: b6Params(maxTypes), Version: 1})
	if err != nil {
		t.Fatal(err)
	}
	return &b6Feed{t: t, l: l, at: b6T0}
}

// row feeds one parsed SER row of element elem, 1 ms after the last.
func (f *b6Feed) row(elem string) {
	f.t.Helper()
	f.seq++
	f.at = f.at.Add(time.Millisecond)
	native := fmt.Sprintf("%d %s ASSERTED", f.seq, elem)
	sum := sha256.Sum256([]byte(native))
	e := &event.Event{
		ID:     event.EventID{NodeID: b6Node, Stream: "events/b6", Seq: f.seq},
		Origin: event.OriginDevice, Kind: event.KindSER,
		Received:   event.Received{UTC: f.at.Format(time.RFC3339Nano), ResolutionNS: 1000, Clock: event.Clock{Sync: event.SyncSynchronized}},
		Source:     event.Source{Asset: &event.AssetRef{ID: b6Asset}},
		Collection: &event.Collection{Method: event.MethodAdapterPoll, Alignment: event.AlignOK, ParseStatus: event.ParseOK},
		Native:     &event.Native{Bytes: []byte(native), RecordSHA256: hex.EncodeToString(sum[:]), RecordLength: int64(len(native))},
		Normalized: &event.Normalized{Subject: elem, SubjectType: "relay-word-bit", Value: "ASSERTED", Category: event.Unmapped},
	}
	if err := f.l.Observe(eventbaseline.Obs{Event: e}); err != nil {
		f.t.Fatal(err)
	}
}

func (f *b6Feed) finish() *eventbaseline.Result {
	f.t.Helper()
	r, err := f.l.Finish(b6T0.Add(2000 * time.Second))
	if err != nil {
		f.t.Fatal(err)
	}
	if err := r.Baseline.Validate(); err != nil {
		f.t.Fatalf("the learner's baseline does not validate: %v", err)
	}
	return r
}

// accounts checks C10's sums on any result: every event is Full, TypeOnly
// or NotCounted, and Full + TypeOnly - the sum of Count is in no type.
func accounts(t *testing.T, r *eventbaseline.Result, fed, inNoType int64) {
	t.Helper()
	c := r.Baseline.Counts
	var sum int64
	for _, ty := range r.Baseline.Types {
		sum += ty.Count
	}
	if c.Events != fed || c.Events != c.Full+c.TypeOnly+c.NotCounted || c.Full+c.TypeOnly-sum != inNoType {
		t.Errorf("counts %+v, sum of Count %d: want %d events, %d in no type", c, sum, fed, inNoType)
	}
}

// Of more types than max_types, the highest counts are kept, a tie at the
// cut going to the lower key; the rest are TypesOverflow.
func TestB6MaxTypesKeepsTheHighestCounts(t *testing.T) {
	f := newB6Feed(t, 3)
	// Counts: Z 5, Y 4, B 3, A 3, C 3, D 1. The cut at 3 falls in the tie
	// of A, B and C at 3; the lowest key, A, is kept. Fed in an order where
	// the kept tie member is neither first nor last met.
	counts := []struct {
		elem string
		n    int
	}{{"C", 3}, {"Z", 5}, {"A", 3}, {"D", 1}, {"Y", 4}, {"B", 3}}
	var fed int64
	for round := 0; round < 5; round++ {
		for _, c := range counts {
			if round < c.n {
				f.row(c.elem)
				fed++
			}
		}
	}
	r := f.finish()
	var got []string
	for _, ty := range r.Baseline.Types {
		got = append(got, fmt.Sprintf("%s=%d", ty.Key.Element, ty.Count))
	}
	sort.Strings(got)
	if fmt.Sprint(got) != "[A=3 Y=4 Z=5]" {
		t.Errorf("kept %v, want [A=3 Y=4 Z=5]", got)
	}
	if r.Baseline.Counts.TypesOverflow != 3 || r.OverflowSaturated {
		t.Errorf("TypesOverflow %d (saturated %v), want 3 left out at Finish", r.Baseline.Counts.TypesOverflow, r.OverflowSaturated)
	}
	accounts(t, r, fed, 3+3+1)
}

// Past MaxTypesCeiling held types, a new type is counted once by key however
// often it occurs, and never held, even when it would out-count a held one.
func TestB6WorkingSetCountsDistinctTypes(t *testing.T) {
	f := newB6Feed(t, baseline.MaxTypesCeiling)
	var fed int64
	for i := 0; i < baseline.MaxTypesCeiling; i++ {
		f.row(fmt.Sprintf("H%05d", i))
		fed++
	}
	// Ten late types, each 20 times: more than any held type's 1.
	for rep := 0; rep < 20; rep++ {
		for i := 0; i < 10; i++ {
			f.row(fmt.Sprintf("L%02d", i))
			fed++
		}
	}
	held, over := f.l.TypesHeld()
	if held != baseline.MaxTypesCeiling || over != 10 {
		t.Fatalf("working set %d held, %d overflow; want %d and 10", held, over, baseline.MaxTypesCeiling)
	}
	r := f.finish()
	kept := int64(len(r.Baseline.Types))
	for _, ty := range r.Baseline.Types {
		if ty.Key.Element[0] == 'L' {
			t.Fatalf("type %s first met past the working set was held", ty.Key)
		}
	}
	// The byte cap may keep fewer than 4096; every held type left out is
	// counted too.
	if want := int64(baseline.MaxTypesCeiling) - kept + 10; r.Baseline.Counts.TypesOverflow != want || r.OverflowSaturated {
		t.Errorf("TypesOverflow %d (saturated %v), kept %d: want %d", r.Baseline.Counts.TypesOverflow, r.OverflowSaturated, kept, want)
	}
	accounts(t, r, fed, fed-kept)
}

// Past MaxTypesCeiling distinct overflow types the count stops and says it
// is a lower bound.
func TestB6OverflowSaturates(t *testing.T) {
	f := newB6Feed(t, baseline.MaxTypesCeiling)
	n := 2*baseline.MaxTypesCeiling + 5
	for i := 0; i < n; i++ {
		f.row(fmt.Sprintf("T%05d", i))
	}
	held, over := f.l.TypesHeld()
	r := f.finish()
	kept := int64(len(r.Baseline.Types))
	if held != baseline.MaxTypesCeiling || over != baseline.MaxTypesCeiling || !r.OverflowSaturated ||
		r.Baseline.Counts.TypesOverflow != int64(baseline.MaxTypesCeiling)-kept+int64(baseline.MaxTypesCeiling) {
		t.Errorf("held %d, overflow %d, saturated %v, TypesOverflow %d, kept %d", held, over, r.OverflowSaturated, r.Baseline.Counts.TypesOverflow, kept)
	}
	accounts(t, r, int64(n), int64(n)-kept)
}

// One more distinct type than the ceiling, met once more after the set is
// full, does not saturate.
func TestB6OverflowAtTheCeilingIsExact(t *testing.T) {
	f := newB6Feed(t, baseline.MaxTypesCeiling)
	for i := 0; i < 2*baseline.MaxTypesCeiling; i++ {
		f.row(fmt.Sprintf("T%05d", i))
	}
	f.row(fmt.Sprintf("T%05d", 2*baseline.MaxTypesCeiling-1)) // seen again
	if _, over := f.l.TypesHeld(); over != baseline.MaxTypesCeiling {
		t.Fatalf("overflow %d, want %d", over, baseline.MaxTypesCeiling)
	}
	if r := f.finish(); r.OverflowSaturated {
		t.Error("a key already counted, met again, saturated the count")
	}
}

// The same events give the same bytes.
func TestB6Deterministic(t *testing.T) {
	var hashes []string
	for range 2 {
		f := newB6Feed(t, 2)
		for _, e := range []string{"B", "A", "C", "A", "B", "C", "D"} {
			f.row(e)
		}
		hashes = append(hashes, f.finish().Hash)
	}
	if hashes[0] != hashes[1] {
		t.Errorf("hashes differ: %v", hashes)
	}
}
