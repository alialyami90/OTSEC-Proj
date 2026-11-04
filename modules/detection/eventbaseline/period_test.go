package eventbaseline_test

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"otsec.local/otsec/contracts/baseline"
	"otsec.local/otsec/modules/detection/eventbaseline"
)

// The period's end, T, is the first instant at which both minima hold, so
// it is a function of the events and gaps alone (D4-45). These tests are on
// the unit clock: at(s) is s seconds after t0.

// take observes e with the open gap's start open, and fails unless the
// learner answers want (nil: taken).
func take(t *testing.T, l *eventbaseline.Learner, s int, open time.Time, want error) {
	t.Helper()
	err := l.Observe(eventbaseline.Obs{Event: ser("A", "Asserted", at(s), ""), OpenGapFrom: open})
	if want == nil && err != nil || want != nil && !errors.Is(err, want) {
		t.Fatalf("an event at %d s: %v, want %v", s, err, want)
	}
}

// wantEnd fails unless End(open) is at(s), or is not final when s < 0.
func wantEnd(t *testing.T, l *eventbaseline.Learner, open time.Time, s int) {
	t.Helper()
	end, ok := l.End(open)
	switch {
	case s < 0 && ok:
		t.Fatalf("End is final at %s, want not final", end.Format(time.RFC3339))
	case s >= 0 && (!ok || !end.Equal(at(s))):
		t.Fatalf("End is %s (final %v), want %s", end.Format(time.RFC3339), ok, at(s).Format(time.RFC3339))
	}
}

// finishAt records the baseline at each of the times, each from a copy of
// l, and fails unless every record is the same bytes and ends at at(end).
func finishAt(t *testing.T, l *eventbaseline.Learner, mut func(*baseline.Params), end int, times ...int) *eventbaseline.Result {
	t.Helper()
	p := unitParams()
	if mut != nil {
		mut(&p)
	}
	cfg := eventbaseline.LearnerConfig{Node: gtNode, AssetID: unitAsset, Params: p, Version: 1}
	snap := mustSnap(t, l.Snapshot)
	var first *eventbaseline.Result
	for _, s := range times {
		c, err := eventbaseline.RestoreLearner(cfg, snap)
		if err != nil {
			t.Fatal(err)
		}
		r, err := c.Finish(at(s))
		if err != nil {
			t.Fatalf("finishing at %d s: %v", s, err)
		}
		want := at(end).Format(time.RFC3339Nano)
		if r.Baseline.Period.EndUTC != want || r.Baseline.RecordedUTC != want {
			t.Fatalf("finishing at %d s: period ends %s, recorded %s, want both %s", s, r.Baseline.Period.EndUTC, r.Baseline.RecordedUTC, want)
		}
		if first == nil {
			first = r
		} else if !bytes.Equal(r.Bytes, first.Bytes) || r.Hash != first.Hash {
			t.Fatalf("finishing at %d s gave other bytes than at %d s", s, times[0])
		}
	}
	return first
}

// TestPeriodEndsWhenTheDurationIsMet: with the events minimum met first, T
// is the instant the collected time reaches the duration minimum. Events at
// T are taken, in any number; the first after it is refused.
func TestPeriodEndsWhenTheDurationIsMet(t *testing.T) {
	l := learner(t, nil) // 1000 s, 1 event
	var none time.Time
	take(t, l, 0, none, nil)
	take(t, l, 500, none, nil)
	wantEnd(t, l, none, 1000)
	take(t, l, 1000, none, nil)
	take(t, l, 1000, none, nil)
	take(t, l, 1001, none, eventbaseline.ErrPeriodEnded)
	take(t, l, 5000, none, eventbaseline.ErrPeriodEnded)
	r := finishAt(t, l, nil, 1000, 1000, 1001, 4000, 86400)
	if c := r.Baseline.Counts; c.Events != 4 || r.Baseline.Period.CollectedS != 1000 {
		t.Errorf("%d events, %d s collected, want 4 and 1000", c.Events, r.Baseline.Period.CollectedS)
	}
	if _, err := l.Finish(at(999)); !errors.Is(err, eventbaseline.ErrNotDone) {
		t.Errorf("finishing before T: %v", err)
	}
}

// TestPeriodEndsAtTheEventThatMeetsTheMinimum: with the duration met first,
// T is the time of the event that meets the events minimum, and that event
// and others at its time are taken.
func TestPeriodEndsAtTheEventThatMeetsTheMinimum(t *testing.T) {
	mut := func(p *baseline.Params) { p.MinEvents = 3 }
	l := learner(t, mut)
	var none time.Time
	take(t, l, 0, none, nil)
	take(t, l, 1200, none, nil)
	wantEnd(t, l, none, -1)
	take(t, l, 1500, none, nil)
	wantEnd(t, l, none, 1500)
	take(t, l, 1500, none, nil)
	take(t, l, 1500, none, nil)
	take(t, l, 1501, none, eventbaseline.ErrPeriodEnded)
	r := finishAt(t, l, mut, 1500, 1500, 2000, 86400)
	if r.Baseline.Counts.Events != 5 {
		t.Errorf("%d events, want 5", r.Baseline.Counts.Events)
	}
}

// TestPeriodGapMovesTheEndLater: a gap fed before T moves it later by the
// gap's time in the period; a gap that begins after T does not move it.
func TestPeriodGapMovesTheEndLater(t *testing.T) {
	l := learner(t, nil)
	var none time.Time
	take(t, l, 0, none, nil)
	if err := l.Gap(at(200), at(500), "failed.timeout"); err != nil {
		t.Fatal(err)
	}
	wantEnd(t, l, none, 1300)
	take(t, l, 1300, none, nil)
	take(t, l, 1301, none, eventbaseline.ErrPeriodEnded)
	if err := l.Gap(at(1400), at(1600), "failed.timeout"); err != nil {
		t.Fatal(err)
	}
	wantEnd(t, l, none, 1300)
	r := finishAt(t, l, nil, 1300, 1300, 2000)
	if g := r.Baseline.Period.Gaps; len(g) != 1 || r.Baseline.Period.CollectedS != 1000 {
		t.Errorf("gaps %v, %d s collected, want the one before T and 1000 s", g, r.Baseline.Period.CollectedS)
	}
}

// TestPeriodWaitsOnAGapOpenAcrossTheEnd: an open gap counts as not
// collected from its start. When the duration is not met before it, T is
// not known: every event in the outage is taken, and once the gap is fed T
// is after it. When it is, T is known and later events are refused, but T
// is not final until the gap is fed, so the record holds it.
func TestPeriodWaitsOnAGapOpenAcrossTheEnd(t *testing.T) {
	t.Run("duration not met before the gap", func(t *testing.T) {
		l := learner(t, nil)
		var none time.Time
		take(t, l, 0, none, nil)
		open := at(600)
		take(t, l, 700, open, nil)
		wantEnd(t, l, open, -1)
		take(t, l, 1200, open, nil) // after the T the gap would not have moved
		wantEnd(t, l, open, -1)
		if err := l.Gap(open, at(1500), "failed.timeout"); err != nil {
			t.Fatal(err)
		}
		wantEnd(t, l, none, 1900)
		take(t, l, 1900, none, nil)
		take(t, l, 1950, none, eventbaseline.ErrPeriodEnded)
		r := finishAt(t, l, nil, 1900, 1900, 3000)
		if r.Baseline.Counts.Events != 4 || r.Baseline.Period.CollectedS != 1000 {
			t.Errorf("%d events, %d s collected, want 4 and 1000", r.Baseline.Counts.Events, r.Baseline.Period.CollectedS)
		}
	})
	t.Run("duration met before the gap", func(t *testing.T) {
		mut := func(p *baseline.Params) { p.MinEvents = 3 }
		l := learner(t, mut)
		var none time.Time
		take(t, l, 0, none, nil)
		take(t, l, 1100, none, nil)
		open := at(1050)
		take(t, l, 1200, open, nil) // meets the events minimum: T is 1200 s
		wantEnd(t, l, open, -1)
		take(t, l, 1300, open, eventbaseline.ErrPeriodEnded)
		wantEnd(t, l, at(1200), -1)   // nor one that began at T
		wantEnd(t, l, at(1201), 1200) // a gap that began after T does not hold it
		if err := l.Gap(open, at(1250), "failed.timeout"); err != nil {
			t.Fatal(err)
		}
		wantEnd(t, l, none, 1200)
		r := finishAt(t, l, mut, 1200, 1250, 2000)
		if g := r.Baseline.Period.Gaps; len(g) != 1 || g[0].ToUTC != at(1200).Format(time.RFC3339Nano) || r.Baseline.Period.CollectedS != 1050 {
			t.Errorf("gaps %v, %d s collected, want the gap clipped to T and 1050 s", g, r.Baseline.Period.CollectedS)
		}
	})
}

// TestPeriodLearnerOfTheEarlierVersionIsRefused: a snapshot of learner 0.1,
// whose period ended when it was finished, is not restored (ErrSnapshotVersion).
func TestPeriodLearnerOfTheEarlierVersionIsRefused(t *testing.T) {
	if eventbaseline.LearnerVersion != "0.2" {
		t.Fatalf("learner version %s: this test changes 0.2 to 0.1", eventbaseline.LearnerVersion)
	}
	l := learner(t, nil)
	take(t, l, 0, time.Time{}, nil)
	snap := mustSnap(t, l.Snapshot)
	i := bytes.Index(snap, []byte(eventbaseline.LearnerName))
	j := bytes.Index(snap[i:], []byte("0.2"))
	if i < 0 || j < 0 || j > len(eventbaseline.LearnerName)+2 {
		t.Fatalf("no learner version after the name in the snapshot")
	}
	old := append([]byte{}, snap...)
	old[i+j+2] = '1'
	cfg := eventbaseline.LearnerConfig{Node: gtNode, AssetID: unitAsset, Params: unitParams(), Version: 1}
	if r, err := eventbaseline.RestoreLearner(cfg, reseal(old)); !errors.Is(err, eventbaseline.ErrSnapshotVersion) || r != nil {
		t.Errorf("a learner 0.1 snapshot: %v", err)
	}
	if _, err := eventbaseline.RestoreLearner(cfg, snap); err != nil {
		t.Errorf("its own snapshot: %v", err)
	}
}
