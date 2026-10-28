package eventbaseline

import (
	"fmt"
	"math"
	"strings"

	"otsec.local/otsec/contracts/baseline"
	"otsec.local/otsec/contracts/event"
)

// SetPairCap lowers the new-type pair cap for a test; SetPairPruning turns
// the sweep of expired pairs off. Each returns the function that puts it back.
func SetPairCap(n int) (restore func()) {
	old := pairCap
	pairCap = n
	return func() { pairCap = old }
}

func SetPairPruning(on bool) (restore func()) {
	old := pairPrune
	pairPrune = on
	return func() { pairPrune = old }
}

// PairCount is the number of pending (rule, type) records the detector holds.
func (d *Detector) PairCount() int { return len(d.pairs) }

// SetNewSeenMax lowers the new-type memory for a test.
func SetNewSeenMax(n int) (restore func()) {
	old := newSeenMax
	newSeenMax = n
	return func() { newSeenMax = old }
}

// ListedHeld is the held breaks the detector's pending records list, which
// the next alarm of each pair will carry.
func (d *Detector) ListedHeld() (n int64) {
	for _, pd := range d.pairs {
		n += pd.total
	}
	return n
}

// widest is a number at its widest encoding: ten bytes as a varint.
const widest = math.MaxInt64

// WideIDs are MaxStreams event IDs, each of a distinct (node, stream) pair
// with the longest node ID and stream the C4 patterns allow, and the widest
// seq.
func WideIDs() []event.EventID {
	ids := make([]event.EventID, MaxStreams)
	for i := range ids {
		ids[i] = event.EventID{
			NodeID: event.NodeID(fmt.Sprintf("%s%02d", strings.Repeat("n", 61), i)),
			Stream: event.Stream(fmt.Sprintf("%s%02d", strings.Repeat("s", 126), i)),
			Seq:    math.MaxUint64,
		}
	}
	return ids
}

// wideStamps are n window stamps, each step the widest a non-decreasing
// window has (math.MaxInt64; the sums wrap, which the encoder does not
// look at).
func wideStamps(n int) []int64 {
	s := make([]int64, n)
	for j := range s {
		if j == 0 {
			s[j] = widest
		} else {
			s[j] = s[j-1] + widest
		}
	}
	return s
}

// WideKey is the i-th of MaxTypes distinct keys at the longest canonical
// form: an element and a state of baseline.TextMax bytes, every byte '%' or
// '|', which the key's text form escapes to three bytes each.
func WideKey(i int) baseline.Key {
	el := []byte(strings.Repeat("%", baseline.TextMax))
	for b := 0; b < 16; b++ {
		if i&(1<<b) != 0 {
			el[len(el)-1-b] = '|'
		}
	}
	return baseline.Key{Source: baseline.SourceSER, Element: string(el), State: strings.Repeat("%", baseline.TextMax)}
}

// WidenLearner sets l to the largest snapshot its format allows: every list
// at the bound Restore reads it to (MaxTypes types, MaxTypes overflow
// digests, MaxGaps gaps, windowCap stamps a type, gapBudget gap lengths in
// all), every string at the longest Restore takes, and every number at its
// widest encoding. The state is not consistent and does not restore; it is
// an upper bound on the bytes of every state that does.
func WidenLearner(l *Learner) {
	l.started, l.overflowSaturated = true, true
	l.startNS, l.lastNS, l.events, l.full, l.typeOnly, l.notCnt, l.gapDrops = widest, widest, widest, widest, widest, widest, widest
	l.excluded = map[baseline.Exclusion]int64{}
	for i := 0; i < 64; i++ {
		l.excluded[baseline.Exclusion(fmt.Sprintf("%064d", i))] = widest
	}
	l.gaps = nil
	for range MaxGaps {
		t := strings.Repeat("9", maxGapTime)
		l.gaps = append(l.gaps, baseline.Gap{FromUTC: t, ToUTC: t, Reason: strings.Repeat("a", 64)})
	}
	l.overflow = map[digest]struct{}{}
	l.types = map[baseline.Key]*learnt{}
	for i := 0; i < MaxTypes; i++ {
		l.overflow[digestOf(WideKey(MaxTypes+i))] = struct{}{}
		ty := &learnt{key: WideKey(i), text: strings.Repeat("x", baseline.TextMax),
			count: widest, full: widest, first: widest, last: widest, maxWin: widest,
			bucket: widest, inBucket: widest, maxBucket: widest, gapMin: widest, gapMax: widest,
			haveFull: true, lastFullNS: widest, win: wideStamps(windowCap), gaps: map[int64]int64{}}
		for h := range ty.hours {
			ty.hours[h] = widest
		}
		l.types[ty.key] = ty
	}
	// The gap budget spent as gapBudget/128 types of 128 lengths each, so
	// as many types as can have a two-byte count of gaps have one.
	const per = 128
	for i := 0; i < gapBudget/per; i++ {
		ty := l.types[WideKey(i)]
		for j := 0; j < per; j++ {
			ty.gaps[math.MinInt64+int64(j)] = widest
		}
	}
	l.gapsHeld = gapBudget
}

// WidenDetector sets d to the largest snapshot its format allows, as
// WidenLearner does for a learner: for every baseline type a full repeats
// window (RepeatsN + 1), bucket and not-counted lists of baseline.MaxEventIDs;
// newSeenMax new types; a pair for each of the four rules on each baseline
// type and pairCap new-type pairs; heldIDBudget held IDs; every ID over
// MaxStreams streams at the longest names; every number at its widest.
func WidenDetector(d *Detector) {
	ids := WideIDs()
	list := func(n int) []event.EventID {
		out := make([]event.EventID, n)
		for i := range out {
			out[i] = ids[i%len(ids)]
		}
		return out
	}
	d.lastNS, d.holdFrom, d.raised, d.held, d.nextSweep, d.beyond = widest, widest, widest, widest, widest, widest
	d.holdOpen = true
	d.newSeen = map[digest]struct{}{}
	for i := 0; len(d.newSeen) < newSeenMax; i++ {
		if dg := digestOf(WideKey(i)); !d.inBaseline[dg] {
			d.newSeen[dg] = struct{}{}
		}
	}
	for _, w := range d.types {
		w.recent = nil
		for j, ns := range wideStamps(int(d.p.RepeatsN) + 1) {
			w.recent = append(w.recent, stamp{ns, ids[j%len(ids)]})
		}
		w.bucket, w.inBucket, w.last, w.notCountedTotal = widest, widest, widest, widest
		w.absent = true
		w.ids, w.notCounted = list(baseline.MaxEventIDs), list(baseline.MaxEventIDs)
	}
	d.pairs, d.newPairs = map[pair]*pending{}, 0
	for k := range d.types {
		for _, r := range knownRules[1:] {
			d.pairs[pair{r, digestOf(k)}] = &pending{}
		}
	}
	for dg := range d.newSeen {
		if d.newPairs == pairCap {
			break
		}
		d.pairs[pair{baseline.RuleNewType, dg}] = &pending{}
		d.newPairs++
	}
	d.heldIDs = 0
	for _, pd := range d.pairs {
		pd.born, pd.lastAlarm, pd.raisedOnce, pd.total = widest, widest, true, widest
		if n := min(baseline.MaxEventIDs, heldIDBudget-d.heldIDs); n > 0 {
			pd.ids = list(n)
			d.heldIDs += n
		}
	}
}

// SetHeldIDBudget lowers the detector-wide budget of listed held IDs.
func SetHeldIDBudget(n int) (restore func()) {
	old := heldIDBudget
	heldIDBudget = n
	return func() { heldIDBudget = old }
}

// HeldIDs is the detector's count of listed held IDs and the IDs its pending
// records list, which must be equal.
func (d *Detector) HeldIDs() (counted, listed int) {
	for _, pd := range d.pairs {
		listed += len(pd.ids)
	}
	return d.heldIDs, listed
}

// SetGapBudget lowers the learner-wide budget of distinct gap lengths.
func SetGapBudget(n int) (restore func()) {
	old := gapBudget
	gapBudget = n
	return func() { gapBudget = old }
}

// onlyType is the learner's one type.
func (l *Learner) onlyType() *learnt {
	if len(l.types) != 1 {
		panic("the fault wants a learner of one type")
	}
	for _, ty := range l.types {
		return ty
	}
	return nil
}

// LearnerFaults are states a learner of one type, seen three times 100 s
// apart, cannot reach and that Snapshot still encodes; RestoreLearner must
// refuse each (C6's survivors on #364, and the D4-30 checks).
var LearnerFaults = map[string]func(l *Learner){
	"K12 a window step that overflows": func(l *Learner) {
		ty := l.onlyType()
		ty.win = []int64{math.MaxInt64, ty.lastFullNS}
	},
	"K13 the smallest gap not among the gaps": func(l *Learner) { l.onlyType().gapMin-- },
	"K14 the window not ending at the last full occurrence": func(l *Learner) {
		ty := l.onlyType()
		ty.lastFullNS = ty.win[len(ty.win)-2]
	},
	"K29 the left-out count saturated below the ceiling": func(l *Learner) { l.overflowSaturated = true },
	"a gap reason that is not a token": func(l *Learner) {
		l.gaps = []baseline.Gap{{FromUTC: fmtNS(l.startNS), ToUTC: fmtNS(l.lastNS), Reason: "Not a token"}}
	},
}

// DetectorFaults are states a detector cannot reach and that Snapshot still
// encodes, for a detector over a baseline whose first type is watched;
// RestoreDetector must refuse each.
var DetectorFaults = map[string]func(d *Detector){
	"K17 a pair of an unknown rule": func(d *Detector) {
		d.pairs[pair{"bogus", digestOf(d.b.Types[0].Key)}] = &pending{born: d.lastNS}
	},
	"K18 a pair listing more IDs than it counts": func(d *Detector) {
		d.pairs[pair{baseline.RuleRepeats, digestOf(d.b.Types[0].Key)}] = &pending{born: d.lastNS, ids: []event.EventID{faultID(1)}}
	},
	"K19 an event ID of seq 0": func(d *Detector) {
		d.pairs[pair{baseline.RuleRepeats, digestOf(d.b.Types[0].Key)}] = &pending{born: d.lastNS, ids: []event.EventID{faultID(0)}, total: 1}
	},
	"K22 a bucket listing more IDs than it counts": func(d *Detector) {
		w := d.types[d.b.Types[0].Key]
		w.ids, w.inBucket = []event.EventID{faultID(1)}, 0
	},
	"K30 a repeats step that overflows": func(d *Detector) {
		w := d.types[d.b.Types[0].Key]
		w.recent = []stamp{{math.MaxInt64, faultID(1)}, {d.lastNS, faultID(2)}}
	},
	"K35 an open hold with more alarms than it allows": func(d *Detector) {
		d.holdOpen, d.holdFrom, d.raised = true, d.lastNS, d.p.MaxAlarmsPerHold+1
	},
	"K35 an open hold that starts after the detector's time": func(d *Detector) {
		d.holdOpen, d.holdFrom, d.raised = true, d.lastNS+1, 0
	},
	"K36 the detector's time before its activation": func(d *Detector) { d.lastNS = d.activeNS - 1 },
}

// HoldTwoIDs gives the detector's first type a repeats record listing two
// held IDs, which is consistent, and over a held-ID budget of one.
func HoldTwoIDs(d *Detector) {
	d.pairs[pair{baseline.RuleRepeats, digestOf(d.b.Types[0].Key)}] = &pending{born: d.lastNS, ids: []event.EventID{faultID(1), faultID(2)}, total: 2}
	d.heldIDs += 2
}

func faultID(seq uint64) event.EventID {
	return event.EventID{NodeID: "site-a-node1", Stream: "events/unit", Seq: seq}
}
