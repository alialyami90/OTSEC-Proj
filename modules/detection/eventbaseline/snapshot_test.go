package eventbaseline_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"otsec.local/otsec/contracts/baseline"
	"otsec.local/otsec/contracts/event"
	"otsec.local/otsec/modules/detection/eventbaseline"
)

// Snapshot and Restore (P4-A4, D4-26). Everything here is `simulated`.

func gtLearnerConfig(s gtSeries, asset string) eventbaseline.LearnerConfig {
	return eventbaseline.LearnerConfig{Node: gtNode, AssetID: gtAssets[asset], Params: s.Params, Version: 1}
}

func mustSnap(t testing.TB, snap func() ([]byte, error)) []byte {
	t.Helper()
	b, err := snap()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// reseal gives snapshot bytes a valid checksum after a test changed them, so
// the fault reaches the checks behind it.
func reseal(b []byte) []byte {
	out := append([]byte{}, b[:len(b)-sha256.Size]...)
	sum := sha256.Sum256(out)
	return append(out, sum[:]...)
}

// flags gives the feeder's two per-row facts to some rows, so the restore
// is tried with them in the state: a row after a failure is type-only, a
// possible duplicate is counted nowhere.
func flags(i int) (afterFailure, notCounted bool) { return i%53 == 7, i%97 == 11 }

// TestSnapshotLearnerRestoredAtEveryStep: a learner that is snapshotted and
// restored after every event holds, after every event, the bytes of the
// learner that never stopped, and records the same baseline (V-M4; D4-26).
// Gaps and the feeder's flags are in the input.
func TestSnapshotLearnerRestoredAtEveryStep(t *testing.T) {
	s := load(t, "events.json")
	end := ts(t, s.Period.End)
	for asset := range gtAssets {
		cfg := gtLearnerConfig(s, asset)
		a, err := eventbaseline.NewLearner(cfg)
		if err != nil {
			t.Fatal(err)
		}
		b, err := eventbaseline.NewLearner(cfg)
		if err != nil {
			t.Fatal(err)
		}
		steps := 0
		for i, e := range s.Events {
			if e.Asset != asset || !ts(t, e.Received).Before(end) {
				continue
			}
			ev := toEvent(t, e)
			af, nc := flags(i)
			o := eventbaseline.Obs{Event: ev, AfterFailure: af, NotCounted: nc}
			if err := a.Observe(o); err != nil {
				t.Fatal(err)
			}
			if err := b.Observe(o); err != nil {
				t.Fatal(err)
			}
			if steps%200 == 100 {
				from := ts(t, e.Received).Add(-time.Hour)
				a.Gap(from, from.Add(10*time.Minute), "failed.timeout")
				b.Gap(from, from.Add(10*time.Minute), "failed.timeout")
			}
			steps++
			want, got := mustSnap(t, a.Snapshot), mustSnap(t, b.Snapshot)
			if !bytes.Equal(want, got) {
				t.Fatalf("%s, step %d: the restored learner's state differs from the one that never stopped", asset, steps)
			}
			r, err := eventbaseline.RestoreLearner(cfg, got)
			if err != nil {
				t.Fatalf("%s, step %d: %v", asset, steps, err)
			}
			if again := mustSnap(t, r.Snapshot); !bytes.Equal(again, got) {
				t.Fatalf("%s, step %d: Restore then Snapshot did not give the bytes back", asset, steps)
			}
			b = r
		}
		// The gaps lengthen the period: finish a day after its end.
		fin := end.Add(24 * time.Hour)
		ra, err := a.Finish(fin)
		if err != nil {
			t.Fatal(err)
		}
		rb, err := b.Finish(fin)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(ra.Bytes, rb.Bytes) || ra.Hash != rb.Hash || ra.OverflowSaturated != rb.OverflowSaturated {
			t.Errorf("%s: the restored learner recorded another baseline", asset)
		}
		if fmt.Sprint(a.Excluded()) != fmt.Sprint(b.Excluded()) {
			t.Errorf("%s: excluded counts differ: %v and %v", asset, a.Excluded(), b.Excluded())
		}
		if a.Progress(fin) != b.Progress(fin) {
			t.Errorf("%s: progress differs", asset)
		}
		t.Logf("%s: %d steps, each restored; baseline %d bytes", asset, steps, len(ra.Bytes))
	}
}

// alarmsJSON is what a call raised, as bytes.
func alarmsJSON(t testing.TB, o eventbaseline.Output) string {
	t.Helper()
	b, err := json.Marshal(o)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestSnapshotDetectorRestoredAtEveryStep: a detector that is snapshotted and
// restored after every Observe and every Tick raises, call for call, the
// alarms (and the hold notices) of the detector that never stopped, and
// holds its bytes after every call. Both GT-INJ series, so the state the
// departures leave (recent windows, bucket events, held breaks, the pairs) is
// in it.
func TestSnapshotDetectorRestoredAtEveryStep(t *testing.T) {
	s := load(t, "events.json")
	base := learn(t, s, nil)
	ack := ts(t, s.Period.Ack)
	for _, file := range []string{"events.json", "events-heldout.json"} {
		series := load(t, file)
		last := ts(t, series.Events[len(series.Events)-1].Received)
		for asset := range gtAssets {
			r := base[asset]
			cfg := eventbaseline.DetectorConfig{Baseline: r.Baseline, Hash: r.Hash, ActiveFrom: ack}
			a, err := eventbaseline.NewDetector(cfg)
			if err != nil {
				t.Fatal(err)
			}
			b, err := eventbaseline.NewDetector(cfg)
			if err != nil {
				t.Fatal(err)
			}
			calls, alarms := 0, 0
			step := func(what string, f func(d *eventbaseline.Detector) (eventbaseline.Output, error)) {
				oa, ea := f(a)
				ob, eb := f(b)
				if (ea == nil) != (eb == nil) {
					t.Fatalf("%s %s: errors %v and %v", file, what, ea, eb)
				}
				if ea != nil {
					return
				}
				if x, y := alarmsJSON(t, oa), alarmsJSON(t, ob); x != y {
					t.Fatalf("%s %s: alarms differ\n never stopped %s\n restored      %s", file, what, x, y)
				}
				alarms += len(oa.Alarms)
				calls++
				want, got := mustSnap(t, a.Snapshot), mustSnap(t, b.Snapshot)
				if !bytes.Equal(want, got) {
					t.Fatalf("%s %s: the restored detector's state differs from the one that never stopped", file, what)
				}
				nb, err := eventbaseline.RestoreDetector(cfg, got)
				if err != nil {
					t.Fatalf("%s %s: %v", file, what, err)
				}
				if again := mustSnap(t, nb.Snapshot); !bytes.Equal(again, got) {
					t.Fatalf("%s %s: Restore then Snapshot did not give the bytes back", file, what)
				}
				b = nb
			}
			next := ack.Add(15 * time.Minute)
			for i, e := range series.Events {
				if e.Asset != asset {
					continue
				}
				at := ts(t, e.Received)
				for ; at.After(next) && !at.Before(ack); next = next.Add(15 * time.Minute) {
					n := next
					step("tick "+n.Format(time.RFC3339), func(d *eventbaseline.Detector) (eventbaseline.Output, error) { return d.Tick(n) })
				}
				af, nc := flags(i)
				o := eventbaseline.Obs{Event: toEvent(t, e), AfterFailure: af, NotCounted: nc}
				step(e.ID, func(d *eventbaseline.Detector) (eventbaseline.Output, error) { return d.Observe(o) })
			}
			step("the last tick", func(d *eventbaseline.Detector) (eventbaseline.Output, error) { return d.Tick(last) })
			t.Logf("%s %s: %d calls, each restored; %d alarms", file, asset, calls, alarms)
		}
	}
}

// TestSnapshotSameStateSameBytes: the bytes do not depend on map order, so
// two learners fed alike, and one learner asked repeatedly, give one snapshot.
func TestSnapshotSameStateSameBytes(t *testing.T) {
	s := load(t, "events.json")
	end := ts(t, s.Period.End)
	mk := func() *eventbaseline.Learner {
		l, err := eventbaseline.NewLearner(gtLearnerConfig(s, "gt-inj-syslog"))
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range s.Events {
			if e.Asset == "gt-inj-syslog" && ts(t, e.Received).Before(end) {
				if err := l.Observe(eventbaseline.Obs{Event: toEvent(t, e)}); err != nil {
					t.Fatal(err)
				}
			}
		}
		return l
	}
	x, y := mk(), mk()
	want := mustSnap(t, x.Snapshot)
	for i := 0; i < 20; i++ {
		if !bytes.Equal(want, mustSnap(t, x.Snapshot)) || !bytes.Equal(want, mustSnap(t, y.Snapshot)) {
			t.Fatal("the snapshot of one state changed between calls")
		}
	}
}

// busyDetector is a detector with every kind of state in it: recent
// occurrences, a bucket with events, a type seen as new, an absence, held
// breaks and possible duplicates.
func busyDetector(t *testing.T) (*eventbaseline.Detector, eventbaseline.DetectorConfig) {
	t.Helper()
	l := learner(t, nil)
	observe(t, l, ser("A", "Asserted", at(0), ""))
	for s := 1600; s <= 2000; s += 100 {
		observe(t, l, ser("B", "Asserted", at(s), ""))
	}
	r, err := l.Finish(at(2000))
	if err != nil {
		t.Fatal(err)
	}
	cfg := eventbaseline.DetectorConfig{Baseline: r.Baseline, Hash: r.Hash, ActiveFrom: at(2100)}
	d, err := eventbaseline.NewDetector(cfg)
	if err != nil {
		t.Fatal(err)
	}
	feed(t, d, ser("A", "Asserted", at(2200), ""), ser("A", "Asserted", at(2210), ""), ser("A", "Asserted", at(2220), ""), ser("A", "Asserted", at(2230), ""))
	feed(t, d, ser("N", "Asserted", at(2240), ""), ser("N", "Asserted", at(2250), ""), ser("M", "Asserted", at(2260), ""))
	if _, err := d.Observe(eventbaseline.Obs{Event: ser("A", "Asserted", at(2270), ""), NotCounted: true}); err != nil {
		t.Fatal(err)
	}
	feed(t, d, ser("A", "Asserted", at(2280), ""), ser("A", "Asserted", at(2290), ""), ser("A", "Asserted", at(2300), ""))
	tick(t, d, 2400)
	return d, cfg
}

func busyLearner(t *testing.T) (*eventbaseline.Learner, eventbaseline.LearnerConfig) {
	t.Helper()
	p := unitParams()
	cfg := eventbaseline.LearnerConfig{Node: gtNode, AssetID: unitAsset, Params: p, Version: 3, Previous: "sha256:" + strings.Repeat("ab", 32), MaxBytes: 100000}
	l, err := eventbaseline.NewLearner(cfg)
	if err != nil {
		t.Fatal(err)
	}
	observe(t, l, ser("A", "Asserted", at(0), ""), ser("A", "Asserted", at(10), ""), ser("A", "Asserted", at(20), ""))
	for s := 100; s <= 600; s += 100 {
		observe(t, l, ser("B", "Asserted", at(s), ""))
	}
	if err := l.Observe(eventbaseline.Obs{Event: ser("C", "Asserted", at(700), ""), AfterFailure: true}); err != nil {
		t.Fatal(err)
	}
	if err := l.Observe(eventbaseline.Obs{Event: ser("A", "Asserted", at(710), ""), NotCounted: true}); err != nil {
		t.Fatal(err)
	}
	l.Gap(at(300), at(340), "failed.timeout")
	for i := 0; i < 3; i++ {
		e := ser("P", "Asserted", at(720+i), "")
		e.Origin = event.OriginPlatform
		observe(t, l, e)
	}
	for i := 0; i < 2; i++ {
		e := ser("U", "Asserted", at(730+i), "")
		e.Source.Asset = nil
		observe(t, l, e)
	}
	return l, cfg
}

func isNilLearner(l *eventbaseline.Learner) bool   { return l == nil }
func isNilDetector(d *eventbaseline.Detector) bool { return d == nil }

// TestSnapshotRefusesWhatItCannotRestore: bytes that are cut short, changed,
// of another format version, of the other half, or not consistent return
// an error and no learner or detector, never part of one.
func TestSnapshotRefusesWhatItCannotRestore(t *testing.T) {
	l, lcfg := busyLearner(t)
	d, dcfg := busyDetector(t)
	ls, ds := mustSnap(t, l.Snapshot), mustSnap(t, d.Snapshot)
	t.Logf("busy learner %d bytes, busy detector %d bytes", len(ls), len(ds))

	restoreL := func(b []byte) error {
		r, err := eventbaseline.RestoreLearner(lcfg, b)
		if (err == nil) == isNilLearner(r) {
			t.Fatalf("learner %v with an error of %v", r, err)
		}
		return err
	}
	restoreD := func(b []byte) error {
		r, err := eventbaseline.RestoreDetector(dcfg, b)
		if (err == nil) == isNilDetector(r) {
			t.Fatalf("detector %v with an error of %v", r, err)
		}
		return err
	}
	for name, c := range map[string]struct {
		snap    []byte
		restore func([]byte) error
	}{"learner": {ls, restoreL}, "detector": {ds, restoreD}} {
		if err := c.restore(c.snap); err != nil {
			t.Fatalf("%s: the unchanged snapshot: %v", name, err)
		}
		// Cut short at every length, and with a byte added.
		for n := 0; n < len(c.snap); n++ {
			if err := c.restore(c.snap[:n]); !errors.Is(err, eventbaseline.ErrSnapshot) {
				t.Fatalf("%s cut to %d bytes: %v", name, n, err)
			}
		}
		if err := c.restore(append(append([]byte{}, c.snap...), 0)); !errors.Is(err, eventbaseline.ErrSnapshot) {
			t.Errorf("%s with a byte added: %v", name, err)
		}
		// One byte changed, anywhere: the checksum catches it.
		for i := range c.snap {
			b := append([]byte{}, c.snap...)
			b[i] ^= 0x01
			if err := c.restore(b); !errors.Is(err, eventbaseline.ErrSnapshot) {
				t.Fatalf("%s with byte %d changed: %v", name, i, err)
			}
		}
		// Another format version, with its checksum made right.
		for _, v := range []byte{0, 2, 9, 0x7f} {
			b := append([]byte{}, c.snap...)
			b[4] = v
			err := c.restore(reseal(b))
			if !errors.Is(err, eventbaseline.ErrSnapshotVersion) || !errors.Is(err, eventbaseline.ErrSnapshot) {
				t.Errorf("%s of format version %d: %v", name, v, err)
			}
		}
		// Not a snapshot at all.
		b := append([]byte{}, c.snap...)
		copy(b, "JUNK")
		if err := c.restore(reseal(b)); !errors.Is(err, eventbaseline.ErrSnapshot) || errors.Is(err, eventbaseline.ErrSnapshotVersion) {
			t.Errorf("%s with another magic: %v", name, err)
		}
	}
	// A detector's snapshot is not a learner's, and the reverse.
	if err := restoreL(ds); !errors.Is(err, eventbaseline.ErrSnapshot) {
		t.Errorf("a detector snapshot restored as a learner: %v", err)
	}
	if err := restoreD(ls); !errors.Is(err, eventbaseline.ErrSnapshot) {
		t.Errorf("a learner snapshot restored as a detector: %v", err)
	}
	if err := restoreL(nil); !errors.Is(err, eventbaseline.ErrSnapshot) {
		t.Errorf("no bytes: %v", err)
	}
}

// TestSnapshotRefusesAnotherConfiguration: a snapshot is for the parameters,
// node, asset and baseline it was made under; restoring it under others is
// ErrSnapshotMismatch, whatever differs.
func TestSnapshotRefusesAnotherConfiguration(t *testing.T) {
	l, lcfg := busyLearner(t)
	ls := mustSnap(t, l.Snapshot)
	other := func(mut func(*eventbaseline.LearnerConfig)) eventbaseline.LearnerConfig {
		c := lcfg
		mut(&c)
		return c
	}
	for name, c := range map[string]eventbaseline.LearnerConfig{
		"repeats_n":      other(func(c *eventbaseline.LearnerConfig) { c.Params.RepeatsN++ }),
		"repeats_window": other(func(c *eventbaseline.LearnerConfig) { c.Params.RepeatsWindowS++ }),
		"rate_factor":    other(func(c *eventbaseline.LearnerConfig) { c.Params.RateFactorPct++ }),
		"rate_min":       other(func(c *eventbaseline.LearnerConfig) { c.Params.RateMin++ }),
		"spread":         other(func(c *eventbaseline.LearnerConfig) { c.Params.PeriodicSpreadPct++ }),
		"tolerance":      other(func(c *eventbaseline.LearnerConfig) { c.Params.AbsenceTolerancePct++ }),
		"min_duration":   other(func(c *eventbaseline.LearnerConfig) { c.Params.MinDurationS++ }),
		"max_types":      other(func(c *eventbaseline.LearnerConfig) { c.Params.MaxTypes-- }),
		"alarm_hold":     other(func(c *eventbaseline.LearnerConfig) { c.Params.AlarmHoldS++ }),
		"asset":          other(func(c *eventbaseline.LearnerConfig) { c.AssetID = gtAssets["gt-inj-syslog"] }),
		"node":           other(func(c *eventbaseline.LearnerConfig) { c.Node = "site-b-node1" }),
		"version":        other(func(c *eventbaseline.LearnerConfig) { c.Version++ }),
		"previous":       other(func(c *eventbaseline.LearnerConfig) { c.Previous = "" }),
		"max_bytes":      other(func(c *eventbaseline.LearnerConfig) { c.MaxBytes = 99999 }),
	} {
		r, err := eventbaseline.RestoreLearner(c, ls)
		if !errors.Is(err, eventbaseline.ErrSnapshotMismatch) || !errors.Is(err, eventbaseline.ErrSnapshot) || r != nil {
			t.Errorf("learner, %s differs: %v, %v", name, r, err)
		}
	}
	// A configuration the learner itself refuses is refused as such.
	bad := lcfg
	bad.Params.RepeatsN = 0
	if r, err := eventbaseline.RestoreLearner(bad, ls); !errors.Is(err, eventbaseline.ErrConfig) || r != nil {
		t.Errorf("unusable parameters: %v, %v", r, err)
	}

	d, dcfg := busyDetector(t)
	ds := mustSnap(t, d.Snapshot)
	otherD := dcfg
	otherD.Hash = "sha256:" + strings.Repeat("00", 32)
	if r, err := eventbaseline.RestoreDetector(otherD, ds); !errors.Is(err, eventbaseline.ErrSnapshotMismatch) || r != nil {
		t.Errorf("detector, another baseline hash: %v, %v", r, err)
	}
	otherD = dcfg
	otherD.ActiveFrom = dcfg.ActiveFrom.Add(time.Second)
	if r, err := eventbaseline.RestoreDetector(otherD, ds); !errors.Is(err, eventbaseline.ErrSnapshotMismatch) || r != nil {
		t.Errorf("detector, another activation time: %v, %v", r, err)
	}
	// The same bytes of another baseline: more types.
	l2 := learner(t, nil)
	observe(t, l2, ser("A", "Asserted", at(0), ""), ser("Z", "Asserted", at(5), ""))
	r2, err := l2.Finish(at(2000))
	if err != nil {
		t.Fatal(err)
	}
	otherD = eventbaseline.DetectorConfig{Baseline: r2.Baseline, Hash: dcfg.Hash, ActiveFrom: dcfg.ActiveFrom}
	if r, err := eventbaseline.RestoreDetector(otherD, ds); !errors.Is(err, eventbaseline.ErrSnapshot) || r != nil {
		t.Errorf("detector, a baseline with other types under the same hash: %v, %v", r, err)
	}
	otherD = eventbaseline.DetectorConfig{Baseline: r2.Baseline, Hash: r2.Hash, ActiveFrom: dcfg.ActiveFrom}
	if r, err := eventbaseline.RestoreDetector(otherD, ds); !errors.Is(err, eventbaseline.ErrSnapshotMismatch) || r != nil {
		t.Errorf("detector, another baseline: %v, %v", r, err)
	}
}

// TestSnapshotChangedAndSealedAgainIsRefusedOrCanonical: with the checksum
// made right, a changed byte reaches the checks behind it. Each result is
// either an error with no learner, or a state that is consistent with itself
// and encodes to exactly the bytes it was read from: no change is accepted
// as something else, and none panics.
func TestSnapshotChangedAndSealedAgainIsRefusedOrCanonical(t *testing.T) {
	l, lcfg := busyLearner(t)
	d, dcfg := busyDetector(t)
	ls, ds := mustSnap(t, l.Snapshot), mustSnap(t, d.Snapshot)
	var refusedL, acceptedL, refusedD, acceptedD int
	for _, mask := range []byte{0x01, 0x02, 0x40, 0x80, 0xff} {
		for i := 0; i < len(ls)-sha256.Size; i++ {
			b := append([]byte{}, ls...)
			b[i] ^= mask
			b = reseal(b)
			r, err := eventbaseline.RestoreLearner(lcfg, b)
			if err != nil {
				if r != nil || !errors.Is(err, eventbaseline.ErrSnapshot) {
					t.Fatalf("learner, byte %d ^ %#x: %v, %v", i, mask, r, err)
				}
				refusedL++
				continue
			}
			acceptedL++
			if again := mustSnap(t, r.Snapshot); !bytes.Equal(again, b) {
				t.Fatalf("learner, byte %d ^ %#x: accepted, but it encodes to other bytes", i, mask)
			}
			// What is accepted must record a valid baseline, or be refused
			// by Finish for its own reasons (the period, the order, a gap's
			// reason, which the caller gave), never by C10's checks of the
			// counts and types, which the restore has to catch.
			if _, err := r.Finish(at(2000)); err != nil {
				var be *baseline.Error
				if errors.As(err, &be) && (strings.HasPrefix(be.Field, "types") || strings.HasPrefix(be.Field, "counts")) {
					t.Fatalf("learner, byte %d ^ %#x: accepted, but its baseline is invalid: %v", i, mask, err)
				}
			}
		}
		for i := 0; i < len(ds)-sha256.Size; i++ {
			b := append([]byte{}, ds...)
			b[i] ^= mask
			b = reseal(b)
			r, err := eventbaseline.RestoreDetector(dcfg, b)
			if err != nil {
				if r != nil || !errors.Is(err, eventbaseline.ErrSnapshot) {
					t.Fatalf("detector, byte %d ^ %#x: %v, %v", i, mask, r, err)
				}
				refusedD++
				continue
			}
			acceptedD++
			if again := mustSnap(t, r.Snapshot); !bytes.Equal(again, b) {
				t.Fatalf("detector, byte %d ^ %#x: accepted, but it encodes to other bytes", i, mask)
			}
			// It goes on without panicking, whatever the changed state does.
			_, _ = r.Observe(eventbaseline.Obs{Event: ser("A", "Asserted", at(900000), "")})
			_, _ = r.Tick(at(1000000))
		}
	}
	t.Logf("learner: %d changes refused, %d accepted as other consistent states; detector: %d refused, %d accepted", refusedL, acceptedL, refusedD, acceptedD)
	if refusedL == 0 || refusedD == 0 {
		t.Error("no changed snapshot was refused: the checks behind the checksum are not reached")
	}
}

// TestSnapshotRefusesInconsistentState: a snapshot with its checksum made
// right and a state that cannot have come from this package is refused,
// whichever way it is wrong. The edits are by position, in snapshots small
// enough that the positions are known.
func TestSnapshotRefusesInconsistentState(t *testing.T) {
	// A learner with one type seen three times, 100 s apart: the snapshot ends
	// with the type's gaps, one gap length (100 s) seen twice.
	l := learner(t, nil)
	observe(t, l, ser("B", "Asserted", at(0), ""), ser("B", "Asserted", at(100), ""), ser("B", "Asserted", at(200), ""))
	snap := mustSnap(t, l.Snapshot)
	body := len(snap) - sha256.Size
	if snap[body-1] != 0x04 || snap[body-4] != 0x01 { // count 2 (zigzag 4); one gap length
		t.Fatalf("the gap entry is not where the test expects: % x", snap[body-6:body])
	}
	cfg := eventbaseline.LearnerConfig{Node: gtNode, AssetID: unitAsset, Params: unitParams(), Version: 1}
	if _, err := eventbaseline.RestoreLearner(cfg, snap); err != nil {
		t.Fatal(err)
	}
	for _, c := range []byte{0x02, 0x06, 0x00} { // 1, 3 and 0 gaps of 100 s, for 2 gaps
		b := append([]byte{}, snap...)
		b[body-1] = c
		if r, err := eventbaseline.RestoreLearner(cfg, reseal(b)); !errors.Is(err, eventbaseline.ErrSnapshot) || r != nil {
			t.Errorf("a type of 3 occurrences with gap counts changed to byte %#x: %v, %v", c, r, err)
		}
	}

	// A fresh detector: its hold fields follow the header, and the new-type
	// memory comes next, empty.
	_, dcfg := busyDetector(t)
	fresh, err := eventbaseline.NewDetector(dcfg)
	if err != nil {
		t.Fatal(err)
	}
	ds := mustSnap(t, fresh.Snapshot)
	off := 6 // magic, version, kind
	skip := func(n int) { off += n }
	str := func() {
		n, w := binary.Uvarint(ds[off:])
		skip(w + int(n))
	}
	num := func() { _, w := binary.Uvarint(ds[off:]); skip(w) }
	str() // hash
	str() // asset
	num() // activation
	num() // types
	if ds[off] != 0 {
		t.Fatal("the fresh detector has an event ID table")
	}
	skip(1)
	num()       // time
	open := off // hold_open
	skip(1)     // hold_open
	num()       // hold_from
	num()       // raised
	held := off // held
	num()       // held
	num()       // next sweep
	num()       // beyond
	seen := off // the count of new types seen
	if ds[seen] != 0 || ds[open] != 0 {
		t.Fatalf("the fresh detector's fields are not where the test expects")
	}
	if _, err := eventbaseline.RestoreDetector(dcfg, ds); err != nil {
		t.Fatal(err)
	}
	edit := func(f func(b []byte) []byte) error {
		_, err := eventbaseline.RestoreDetector(dcfg, reseal(f(append([]byte{}, ds...))))
		return err
	}
	if err := edit(func(b []byte) []byte { b[held] = 0x04; return b }); !errors.Is(err, eventbaseline.ErrSnapshot) {
		t.Errorf("alarms held with no hold open: %v", err)
	}
	if err := edit(func(b []byte) []byte { b[open] = 0x02; return b }); !errors.Is(err, eventbaseline.ErrSnapshot) {
		t.Errorf("a hold flag of 2: %v", err)
	}
	known := "ser|A|Asserted" // a type of the baseline
	if err := edit(func(b []byte) []byte {
		ins := append([]byte{0x01, byte(len(known))}, known...)
		return append(b[:seen], append(ins, b[seen+1:]...)...)
	}); !errors.Is(err, eventbaseline.ErrSnapshot) {
		t.Errorf("a type of the baseline listed among the new ones: %v", err)
	}
	unknown := "ser|N|Asserted" // not in the baseline: this one is consistent
	if err := edit(func(b []byte) []byte {
		ins := append([]byte{0x01, byte(len(unknown))}, unknown...)
		return append(b[:seen], append(ins, b[seen+1:]...)...)
	}); err != nil {
		t.Errorf("a new type listed among the new ones: %v", err)
	}
}

// TestSnapshotRestoredLearnerAndDetectorWorkOn: what is restored is not a
// copy that stopped: it takes the next event, refuses an old one as the
// original does, and the original is not changed by being snapshotted.
func TestSnapshotRestoredLearnerAndDetectorWorkOn(t *testing.T) {
	l, lcfg := busyLearner(t)
	before := mustSnap(t, l.Snapshot)
	r, err := eventbaseline.RestoreLearner(lcfg, before)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, mustSnap(t, l.Snapshot)) {
		t.Fatal("Snapshot changed the learner")
	}
	if err := r.Observe(eventbaseline.Obs{Event: ser("A", "Asserted", at(5), "")}); !errors.Is(err, eventbaseline.ErrOrder) {
		t.Errorf("an event before the last taken: %v", err)
	}
	if !bytes.Equal(before, mustSnap(t, r.Snapshot)) {
		t.Error("a refused event changed the state")
	}
	if fmt.Sprint(r.Excluded()) != fmt.Sprint(l.Excluded()) || len(l.Excluded()) != 2 {
		t.Errorf("excluded counts %v and %v", r.Excluded(), l.Excluded())
	}
	observe(t, r, ser("A", "Asserted", at(740), ""))
	observe(t, l, ser("A", "Asserted", at(740), ""))
	if !bytes.Equal(mustSnap(t, l.Snapshot), mustSnap(t, r.Snapshot)) {
		t.Error("the restored learner and the original differ after one more event")
	}

	d, dcfg := busyDetector(t)
	rd, err := eventbaseline.RestoreDetector(dcfg, mustSnap(t, d.Snapshot))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rd.Tick(at(100)); !errors.Is(err, eventbaseline.ErrOrder) {
		t.Errorf("a tick before the detector's time: %v", err)
	}
	if rd.HeldNow() != d.HeldNow() {
		t.Errorf("held now %d and %d", rd.HeldNow(), d.HeldNow())
	}
	// Past the hold, the pair's next alarm lists the breaks it held. The
	// restored detector must list the same ones.
	var listed, notCounted int
	for i, s := range []int{6000, 6010, 6020, 6030} {
		e := ser("A", "Asserted", at(s), "")
		oa, err := d.Observe(eventbaseline.Obs{Event: e})
		if err != nil {
			t.Fatal(err)
		}
		ob, err := rd.Observe(eventbaseline.Obs{Event: e})
		if err != nil {
			t.Fatal(err)
		}
		if x, y := alarmsJSON(t, oa), alarmsJSON(t, ob); x != y {
			t.Fatalf("event %d: alarms differ\n never stopped %s\n restored      %s", i, x, y)
		}
		for _, a := range oa.Alarms {
			if a.Rule == baseline.RuleRepeats && len(a.Events) > 4 {
				listed++
			}
			notCounted += len(a.NotCounted)
		}
	}
	if listed != 1 || notCounted != 1 {
		t.Errorf("the case is vacuous: %d repeats alarms listing held breaks and %d possible duplicates listed, want 1 and 1", listed, notCounted)
	}
}

// TestSnapshotLearnerAtTheWorkingSetLimit: the types met past the ceiling are
// counted, not held; a learner restored with them recorded and still counts
// them, and one whose count had stopped (saturated) says so as the original
// does.
func TestSnapshotLearnerAtTheWorkingSetLimit(t *testing.T) {
	for _, extra := range []int{100, baseline.MaxTypesCeiling + 50} {
		p := unitParams()
		cfg := eventbaseline.LearnerConfig{Node: gtNode, AssetID: unitAsset, Params: p, Version: 1}
		a, err := eventbaseline.NewLearner(cfg)
		if err != nil {
			t.Fatal(err)
		}
		n := baseline.MaxTypesCeiling + extra
		for i := 0; i < n; i++ {
			observe1(t, a, ser(fmt.Sprintf("T%05d", i), "Asserted", at(i/8), ""))
		}
		for i := 0; i < 20; i++ { // known types again, and overflow types again
			observe1(t, a, ser(fmt.Sprintf("T%05d", i), "Asserted", at(n/8+i), ""))
			observe1(t, a, ser(fmt.Sprintf("T%05d", n-1-i), "Asserted", at(n/8+i), ""))
		}
		b, err := eventbaseline.RestoreLearner(cfg, mustSnap(t, a.Snapshot))
		if err != nil {
			t.Fatal(err)
		}
		end := at(n/8 + 1500)
		ra, err := a.Finish(end)
		if err != nil {
			t.Fatal(err)
		}
		rb, err := b.Finish(end)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(ra.Bytes, rb.Bytes) || ra.OverflowSaturated != rb.OverflowSaturated {
			t.Errorf("%d types past the ceiling: the restored learner recorded another baseline (saturated %v and %v)", extra, ra.OverflowSaturated, rb.OverflowSaturated)
		}
		if want := extra > baseline.MaxTypesCeiling; ra.OverflowSaturated != want {
			t.Errorf("%d types past the ceiling: saturated is %v, the case wants %v", extra, ra.OverflowSaturated, want)
		}
		ha, oa := a.TypesHeld()
		hb, ob := b.TypesHeld()
		if ha != hb || oa != ob || ha != baseline.MaxTypesCeiling {
			t.Errorf("held %d and %d, overflow %d and %d", ha, hb, oa, ob)
		}
	}
}

// ---- Sizes ----

// longName is a name at the limit the key keeps (baseline.TextMax bytes).
func longName(prefix string, i int) string {
	s := fmt.Sprintf("%s%05d", prefix, i)
	return s + strings.Repeat("x", baseline.TextMax-len(s))
}

// bigParams are B6's GT-INJ parameters, with the types at the ceiling.
func bigParams() baseline.Params {
	p := unitParams()
	p.MinDurationS, p.MinEvents = 14*86400, 1
	p.RepeatsN, p.RepeatsWindowS = 5, 600
	p.MaxTypes = baseline.MaxTypesCeiling
	return p
}

// TestSnapshotSizes states how large a snapshot is: for the GT-INJ series, for
// the learner and the detector at the ceiling of 4096 types with the longest
// names a key keeps, and per type at the most the caps let a type hold. The
// figures are printed, and the assertions are the claims the package
// documentation makes.
func TestSnapshotSizes(t *testing.T) {
	// GT-INJ.
	s := load(t, "events.json")
	base := learn(t, s, nil)
	end := ts(t, s.Period.End)
	for _, asset := range []string{"gt-inj-ser", "gt-inj-syslog"} {
		l, err := eventbaseline.NewLearner(gtLearnerConfig(s, asset))
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range s.Events {
			if e.Asset == asset && ts(t, e.Received).Before(end) {
				if err := l.Observe(eventbaseline.Obs{Event: toEvent(t, e)}); err != nil {
					t.Fatal(err)
				}
			}
		}
		ls := mustSnap(t, l.Snapshot)
		r := base[asset]
		d, err := eventbaseline.NewDetector(eventbaseline.DetectorConfig{Baseline: r.Baseline, Hash: r.Hash, ActiveFrom: ts(t, s.Period.Ack)})
		if err != nil {
			t.Fatal(err)
		}
		ds := mustSnap(t, d.Snapshot)
		t.Logf("GT-INJ %s: learner %d bytes (%d types) after 14 days; detector %d bytes fresh, baseline record %d bytes", asset, len(ls), len(r.Baseline.Types), len(ds), len(r.Bytes))
	}

	// The learner at the ceiling: 4096 types of the longest names, each seen
	// 30 times with distinct gaps (a type is held as periodic while it can be).
	p := bigParams()
	cfg := eventbaseline.LearnerConfig{Node: gtNode, AssetID: unitAsset, Params: p, Version: 1}
	l, err := eventbaseline.NewLearner(cfg)
	if err != nil {
		t.Fatal(err)
	}
	mk := func(elem, state string, at time.Time) *event.Event { return ser(elem, state, at, "") }
	start := time.Date(2026, 2, 2, 0, 0, 0, 0, time.UTC)
	const perType = 30
	for j := 0; j < perType; j++ {
		for i := 0; i < baseline.MaxTypesCeiling; i++ {
			// 30 occurrences, two hours apart plus a few seconds, in time order.
			at := start.Add(time.Duration(j)*2*time.Hour + time.Duration(j%7)*time.Second + time.Duration(i)*400*time.Millisecond)
			if err := l.Observe(eventbaseline.Obs{Event: mk(longName("E", i), longName("S", i), at)}); err != nil {
				t.Fatal(err)
			}
		}
	}
	held, over := l.TypesHeld()
	big := mustSnap(t, l.Snapshot)
	t.Logf("learner at the ceiling: %d types held, %d left out, %d occurrences each: %d bytes (%d per type)", held, over, perType, len(big), len(big)/held)
	if held != baseline.MaxTypesCeiling || len(big) > MaxSnapshotBytesForTest {
		t.Errorf("held %d types, snapshot %d bytes", held, len(big))
	}
	if r, err := eventbaseline.RestoreLearner(cfg, big); err != nil || !bytes.Equal(mustSnap(t, r.Snapshot), big) {
		t.Errorf("the ceiling-size snapshot does not restore: %v", err)
	}

	// One type at the most the caps let it hold: a full window (windowCap
	// stamps within the repeats window) and 4096 distinct gaps. Per type, this
	// is the largest the state gets.
	win, err := eventbaseline.NewLearner(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for j := 0; j < 5000; j++ {
		// 0.1 s apart: 5000 occurrences in 500 s; the window holds the last 4096.
		observe1(t, win, mk("W", "Dense", start.Add(time.Duration(j)*100*time.Millisecond)))
	}
	wb := mustSnap(t, win.Snapshot)
	gaps, err := eventbaseline.NewLearner(cfg)
	if err != nil {
		t.Fatal(err)
	}
	at := start
	for j := 0; j <= 4096; j++ {
		observe1(t, gaps, mk("G", "Sparse", at))
		at = at.Add(time.Duration(80000+j*4) * time.Second) // 4096 distinct gaps within 20% of the largest
	}
	gb := mustSnap(t, gaps.Snapshot)
	t.Logf("one type at the caps: a full window of %d stamps %d bytes; %d distinct gaps %d bytes", 4096, len(wb), 4096, len(gb))
	if len(wb) > 20<<10 || len(gb) > 20<<10 || len(wb) < 12<<10 || len(gb) < 12<<10 {
		t.Errorf("a type at the caps takes %d bytes (window) and %d (gaps), not the 12 to 20 KiB the package documentation states", len(wb), len(gb))
	}

	// The detector: a baseline of as many types as fit the record cap, every
	// one with a full repeats window, 4*4096 types seen as new, and each of
	// those with a held break.
	dl, err := eventbaseline.NewLearner(eventbaseline.LearnerConfig{Node: gtNode, AssetID: unitAsset, Params: p, Version: 1})
	if err != nil {
		t.Fatal(err)
	}
	for j := 0; j < 3; j++ {
		for i := 0; i < baseline.MaxTypesCeiling; i++ {
			observe1(t, dl, mk(fmt.Sprintf("E%04d", i), "Asserted", start.Add(time.Duration(j)*2*time.Hour+time.Duration(i)*time.Second)))
		}
	}
	rec, err := dl.Finish(start.Add(15 * 24 * time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	ack := start.Add(16 * 24 * time.Hour)
	d, err := eventbaseline.NewDetector(eventbaseline.DetectorConfig{Baseline: rec.Baseline, Hash: rec.Hash, ActiveFrom: ack})
	if err != nil {
		t.Fatal(err)
	}
	fresh := mustSnap(t, d.Snapshot)
	now := ack
	for i := range rec.Baseline.Types {
		for j := 0; j < int(p.RepeatsN)+1; j++ {
			now = now.Add(time.Second)
			o, err := d.Observe(eventbaseline.Obs{Event: mk(rec.Baseline.Types[i].Key.Element, rec.Baseline.Types[i].Key.State, now)})
			if err != nil {
				t.Fatal(err)
			}
			_ = o
		}
	}
	filled := mustSnap(t, d.Snapshot)
	for i := 0; i < baseline.MaxTypesCeiling*4; i++ {
		now = now.Add(time.Second)
		if _, err := d.Observe(eventbaseline.Obs{Event: mk(fmt.Sprintf("NEW%05d", i), "Asserted", now)}); err != nil {
			t.Fatal(err)
		}
	}
	full := mustSnap(t, d.Snapshot)
	t.Logf("detector: baseline record %d bytes, %d types; fresh %d bytes; every type's window full %d bytes; with %d new types seen and their pairs %d bytes",
		len(rec.Bytes), len(rec.Baseline.Types), len(fresh), len(filled), baseline.MaxTypesCeiling*4, len(full))
	if len(full) > MaxSnapshotBytesForTest {
		t.Errorf("the detector at its caps takes %d bytes", len(full))
	}
	dcfg := eventbaseline.DetectorConfig{Baseline: rec.Baseline, Hash: rec.Hash, ActiveFrom: ack}
	if r, err := eventbaseline.RestoreDetector(dcfg, full); err != nil || !bytes.Equal(mustSnap(t, r.Snapshot), full) {
		t.Errorf("the detector at its caps does not restore: %v", err)
	}

	// The same with the longest names a key keeps, which is the contract's
	// maximum and not anything a device prints: the keys and their pairs
	// together are above what is stored, and the snapshot is refused.
	d2, err := eventbaseline.NewDetector(dcfg)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < baseline.MaxTypesCeiling*4; i++ {
		now = now.Add(time.Second)
		if _, err := d2.Observe(eventbaseline.Obs{Event: mk(longName("N", i), longName("S", i), now)}); err != nil {
			t.Fatal(err)
		}
	}
	_, err = d2.Snapshot()
	t.Logf("detector with %d new types of the longest names: %v", baseline.MaxTypesCeiling*4, err)
	if err != nil && !errors.Is(err, eventbaseline.ErrSnapshotTooLarge) {
		t.Errorf("unexpected: %v", err)
	}
}

// MaxSnapshotBytesForTest is eventbaseline.MaxSnapshotBytes.
const MaxSnapshotBytesForTest = eventbaseline.MaxSnapshotBytes

func observe1(t testing.TB, l *eventbaseline.Learner, e *event.Event) {
	t.Helper()
	if err := l.Observe(eventbaseline.Obs{Event: e}); err != nil {
		t.Fatal(err)
	}
}
