package eventbaseline_test

import (
	"bytes"
	"fmt"
	"regexp"
	"strconv"
	"testing"
	"time"

	"otsec.local/otsec/contracts/baseline"
	"otsec.local/otsec/contracts/event"
	"otsec.local/otsec/modules/detection/eventbaseline"
)

// The new-type rule's pending records are bounded (D4-26, F1). Everything
// here is `simulated`.

// pairRun runs one detector over the neutrality scenario with the new-type
// memory at 8 types and the pair cap and sweeping as given, and returns every
// call's output and the detector.
func pairRun(t *testing.T, cap int, prune bool) ([]string, *eventbaseline.Detector) {
	t.Helper()
	defer eventbaseline.SetNewSeenMax(8)()
	defer eventbaseline.SetPairCap(cap)()
	defer eventbaseline.SetPairPruning(prune)()
	nextSeq = 0 // the same event IDs in every run
	d := active(t, 2100, nil)
	var outs []string
	obs := func(e *event.Event) {
		o, err := d.Observe(eventbaseline.Obs{Event: e})
		if err != nil {
			t.Fatal(err)
		}
		outs = append(outs, alarmsJSON(t, o))
	}
	base := 2100
	// Eight types fill the new-type memory, so every type after them is a new
	// type again each time it recurs and the pairs are what hold it.
	for i := 0; i < 8; i++ {
		obs(ser(fmt.Sprintf("F%d", i), "Asserted", at(base+1+i), ""))
	}
	for h := 1; h <= 40; h++ {
		t0 := base + h*7200
		for i := 0; i < 5; i++ { // five types once each: an alarm, then an empty pair
			obs(ser(fmt.Sprintf("U%d_%d", h, i), "Asserted", at(t0+60*(1+i)), ""))
		}
		y := fmt.Sprintf("Y%d", h) // an alarm, a break held by its pair, an alarm that lists it
		obs(ser(y, "Asserted", at(t0+360), ""))
		obs(ser(y, "Asserted", at(t0+960), ""))
		obs(ser(y, "Asserted", at(t0+4560), ""))
	}
	return outs, d
}

// TestPairSweepChangesNoOutput: dropping the new-type pairs whose hold ended
// and that list nothing changes no alarm, held notice or listed event. The
// scenario has 248 types and a pair cap of 64, so without sweeping the cap is
// reached and the output differs (the third run: a type with no pair is not
// held by it); with it the live pairs stay
// under the cap, and the output equals that of a detector with no cap and no
// sweeping at all.
func TestPairSweepChangesNoOutput(t *testing.T) {
	swept, ds := pairRun(t, 64, true)
	free, df := pairRun(t, 1<<30, false)
	capped, dc := pairRun(t, 64, false)
	if len(swept) != len(free) {
		t.Fatal("different numbers of calls")
	}
	alarms := 0
	for i := range swept {
		if swept[i] != free[i] {
			t.Fatalf("call %d: sweeping changed the output\n swept %s\n free  %s", i, swept[i], free[i])
		}
		if swept[i] != "{\"Alarms\":null,\"Held\":null}" {
			alarms++
		}
	}
	if ds.PairCount() > 64 || ds.BeyondNow() != 0 {
		t.Errorf("swept detector holds %d pairs and %d unlisted breaks", ds.PairCount(), ds.BeyondNow())
	}
	if df.PairCount() <= 64 {
		t.Errorf("the case is vacuous: with no sweeping and no cap the detector holds only %d pairs", df.PairCount())
	}
	if dc.PairCount() != 64 {
		t.Errorf("the case is vacuous: without sweeping the cap of 64 was not reached (%d pairs)", dc.PairCount())
	}
	same := true
	for i := range capped {
		same = same && capped[i] == free[i]
	}
	if same {
		t.Error("the case is vacuous: the cap changed no output without sweeping")
	}
	t.Logf("%d calls, %d with alarms; live pairs %d swept, %d without a cap, %d at the cap without sweeping", len(swept), alarms, ds.PairCount(), df.PairCount(), dc.PairCount())
}

// plainDetector is a detector whose baseline holds the type A only, active
// from activeS.
func plainDetector(t *testing.T, activeS int, mut func(*baseline.Params)) (*eventbaseline.Detector, eventbaseline.DetectorConfig) {
	t.Helper()
	l := learner(t, mut)
	observe(t, l, ser("A", "Asserted", at(0), ""))
	r, err := l.Finish(at(2000))
	if err != nil {
		t.Fatal(err)
	}
	cfg := eventbaseline.DetectorConfig{Baseline: r.Baseline, Hash: r.Hash, ActiveFrom: at(activeS)}
	d, err := eventbaseline.NewDetector(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return d, cfg
}

var beyondNote = regexp.MustCompile(`; (\d+) more held breaks beyond the cap of (\d+) tracked new types are not listed`)

// TestPairCapFloodStaysBoundedAndCountsStayExact: 114,688 distinct new types
// in one hold, then more in later holds, leave the detector's pairs at the
// cap and its snapshot at a size that does not grow with the flood, and every
// break is accounted for: an alarm (with the breaks it lists), a break held
// and listed by a pair, or a break held and counted for an alarm to state.
func TestPairCapFloodStaysBoundedAndCountsStayExact(t *testing.T) {
	const n1 = 114688
	d, dcfg := plainDetector(t, 2100, nil)
	base := at(2100)
	var total int64  // breaks fed
	var listed int64 // EventsTotal of the alarms
	var stated int64 // counts the alarms state
	var alarms, notices int
	step := 0
	feed1 := func(when time.Time) eventbaseline.Output {
		o, err := d.Observe(eventbaseline.Obs{Event: ser(fmt.Sprintf("Q%07d", step), "Asserted", when, "")})
		if err != nil {
			t.Fatal(err)
		}
		step++
		total++
		for _, a := range o.Alarms {
			alarms++
			listed += a.EventsTotal
			if err := a.Validate(); err != nil {
				t.Fatalf("alarm %v: %v", a.Observation, err)
			}
			if beyond := beyondNote.FindString(a.Observation); len(a.Observation)-len(beyond) >= 120 {
				t.Fatalf("an observation of %d bytes before the note: the note may not fit", len(a.Observation)-len(beyond)) // detector.go: raise
			}
			if m := beyondNote.FindStringSubmatch(a.Observation); m != nil {
				c, _ := strconv.ParseInt(m[1], 10, 64)
				stated += c
				if m[2] != strconv.Itoa(eventbaseline.MaxNewTypePairs) {
					t.Fatalf("the note names a cap of %s", m[2])
				}
			}
		}
		if o.Held != nil {
			notices++
		}
		return o
	}
	ledger := func(what string) {
		t.Helper()
		if got := listed + d.ListedHeld() + d.BeyondNow() + stated; got != total {
			t.Fatalf("%s: %d breaks, but alarms list %d, pairs hold %d, %d are unlisted and %d were stated: %d", what, total, listed, d.ListedHeld(), d.BeyondNow(), stated, got)
		}
	}

	// Hold 1: n1 distinct new types, a millisecond apart (115 s).
	for i := 0; i < n1; i++ {
		feed1(base.Add(time.Second + time.Duration(i)*time.Millisecond))
	}
	max := int(unitParams().MaxAlarmsPerHold)
	if alarms != max || notices != 1 {
		t.Errorf("%d alarms and %d held notices in the flood, want %d and 1", alarms, notices, max)
	}
	if d.HeldNow() != n1-int64(max) {
		t.Errorf("held now %d, want %d", d.HeldNow(), n1-max)
	}
	if want := int64(n1 - eventbaseline.MaxNewTypePairs); d.BeyondNow() != want || d.PairCount() != eventbaseline.MaxNewTypePairs {
		t.Errorf("%d unlisted breaks and %d pairs, want %d and %d", d.BeyondNow(), d.PairCount(), want, eventbaseline.MaxNewTypePairs)
	}
	ledger("after the flood")
	snap := mustSnap(t, d.Snapshot)
	t.Logf("%d distinct new types: %d pairs, %d unlisted, snapshot %d bytes", n1, d.PairCount(), d.BeyondNow(), len(snap))
	if len(snap) > 1<<20 {
		t.Errorf("the snapshot of a detector after %d distinct new types is %d bytes", n1, len(snap))
	}

	// Hold 2: one more type, two hours on. Its alarm states the count.
	o := feed1(base.Add(2 * time.Hour))
	if len(o.Alarms) != 1 {
		t.Fatalf("the next hold's break raised %d alarms", len(o.Alarms))
	}
	m := beyondNote.FindStringSubmatch(o.Alarms[0].Observation)
	if m == nil || m[1] != strconv.Itoa(n1-eventbaseline.MaxNewTypePairs) || d.BeyondNow() != 0 {
		t.Errorf("the alarm after the flood says %q, unlisted now %d", o.Alarms[0].Observation, d.BeyondNow())
	}
	ledger("after the next hold's alarm")

	// Holds 3 and 4: floods again, which fill the cap and force the sweep to
	// drop pairs that list breaks (the second pass), so those are counted.
	for round, start := range []time.Duration{4 * time.Hour, 6 * time.Hour} {
		for i := 0; i < 20000; i++ {
			feed1(base.Add(start + time.Duration(i)*time.Millisecond))
		}
		if d.PairCount() > eventbaseline.MaxNewTypePairs {
			t.Fatalf("round %d: %d pairs", round, d.PairCount())
		}
		ledger(fmt.Sprintf("after flood %d", round+3))
	}
	feed1(base.Add(8 * time.Hour))
	ledger("at the end")
	t.Logf("%d breaks: %d alarms list %d, %d stated, %d unlisted, %d held and listed; %d pairs", total, alarms, listed, stated, d.BeyondNow(), d.ListedHeld(), d.PairCount())

	// The snapshot restores to the same bytes, whatever the flood did.
	end := mustSnap(t, d.Snapshot)
	if len(end) > 1<<20 {
		t.Errorf("the snapshot after the floods is %d bytes", len(end))
	}
	if r, err := eventbaseline.RestoreDetector(dcfg, end); err != nil || !bytes.Equal(mustSnap(t, r.Snapshot), end) {
		t.Errorf("restore: %v", err)
	}
}

// TestPairSweepDropsListedPairsLast: when the cap is reached and every pair
// lists held breaks, the ones whose hold ended are dropped to make room, and
// the breaks they listed are counted for the next alarm to state, not lost.
// The asset's hold is used up by an alarm of another rule first, so that no
// new-type alarm is raised and no pair is left empty for the first pass.
func TestPairSweepDropsListedPairsLast(t *testing.T) {
	defer eventbaseline.SetPairCap(100)()
	d, _ := plainDetector(t, 2100, func(p *baseline.Params) { p.MaxAlarmsPerHold = 1 })
	feed2 := func(e *event.Event) eventbaseline.Output {
		o, err := d.Observe(eventbaseline.Obs{Event: e})
		if err != nil {
			t.Fatal(err)
		}
		return o
	}
	// Three of A in an hour: a rate alarm (bound 2), which is the hold's one.
	var rate int
	for i := 0; i < 3; i++ {
		rate += len(feed2(ser("A", "Asserted", at(2101+i), "")).Alarms)
	}
	if rate != 1 {
		t.Fatalf("%d alarms from the rate break", rate)
	}
	for i := 0; i < 300; i++ {
		if o := feed2(ser(fmt.Sprintf("Q%03d", i), "Asserted", at(2200+i), "")); len(o.Alarms) != 0 {
			t.Fatalf("a new-type alarm in a used-up hold: %v", o.Alarms[0].Observation)
		}
	}
	if d.PairCount() != 101 || d.ListedHeld() != 100 || d.BeyondNow() != 200 || d.HeldNow() != 300 {
		t.Fatalf("pairs %d, listed %d, unlisted %d, held %d; want 101 (the rate pair too), 100, 200, 300", d.PairCount(), d.ListedHeld(), d.BeyondNow(), d.HeldNow())
	}
	o := feed2(ser("Z", "Asserted", at(2200+7200), ""))
	if len(o.Alarms) != 1 {
		t.Fatalf("%d alarms in the next hold", len(o.Alarms))
	}
	m := beyondNote.FindStringSubmatch(o.Alarms[0].Observation)
	if m == nil || m[1] != "300" || o.Alarms[0].EventsTotal != 1 {
		t.Errorf("the alarm says %q with %d events: want 300 breaks not listed, the 200 beyond the cap and the 100 whose pairs were dropped", o.Alarms[0].Observation, o.Alarms[0].EventsTotal)
	}
	if d.PairCount() != 2 || d.ListedHeld() != 0 || d.BeyondNow() != 0 {
		t.Errorf("after the sweep: pairs %d, listed %d, unlisted %d", d.PairCount(), d.ListedHeld(), d.BeyondNow())
	}
}
