package eventbaseline

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"sort"
	"time"

	"otsec.local/otsec/contracts/baseline"
	"otsec.local/otsec/contracts/node"
)

// LearnerName and LearnerVersion are stamped on every baseline this package
// records (baseline.Learner).
const (
	LearnerName    = "otsec-eventbaseline"
	LearnerVersion = "0.1"
)

// LearnerConfig is everything a Learner is built from.
type LearnerConfig struct {
	Node    node.ID
	AssetID string
	Params  baseline.Params
	// Version is 1 for an asset's first baseline; a re-learn passes one
	// more and the hash of the record it replaces in Previous.
	Version  int
	Previous string
	// MaxBytes is the node's cap on a stored baseline; zero or above
	// baseline.MaxBytes means baseline.MaxBytes.
	MaxBytes int
}

// Learner learns one asset's event-behaviour baseline over its observation
// period. It holds no clock and does no I/O: the caller feeds it the asset's
// stored events in received order (Observe), tells it of collection failures
// (Gap), and asks it to finish at a time it chooses (Finish).
type Learner struct {
	cfg   LearnerConfig
	p     baseline.Params
	types map[baseline.Key]*learnt
	// overflow holds the keys of types past Params.MaxTypes, so
	// Counts.TypesOverflow counts types and not events. It stops growing at
	// MaxTypes too; overflowSaturated then says the count is a lower bound.
	overflow          map[baseline.Key]struct{}
	overflowSaturated bool

	started  bool
	startNS  int64
	lastNS   int64
	events   int64
	full     int64
	typeOnly int64
	notCnt   int64
	// excluded counts events that belong to no asset's baseline, by why
	// (baseline.Exclusion), for the site-level total the node keeps.
	excluded map[baseline.Exclusion]int64
	gaps     []baseline.Gap
}

// learnt is one type's running state.
type learnt struct {
	key   baseline.Key
	text  string
	count int64
	full  int64
	hours [24]int64
	first int64
	last  int64

	// Repeats window: the full occurrences in (t - window, t], oldest
	// first, at most windowCap.
	win    []int64
	maxWin int64
	// Rate bucket in progress.
	bucket         int64
	inBucket       int64
	maxBucket      int64
	prevFull       int64
	gaps           map[int64]int64 // gap in whole seconds -> times seen
	gapMin, gapMax int64
	notPeriodic    bool
	haveFull       bool
	lastFullNS     int64
}

// NewLearner starts a learner for one asset.
func NewLearner(c LearnerConfig) (*Learner, error) {
	if err := checkParams(c.Params); err != nil {
		return nil, err
	}
	if c.Version < 1 {
		return nil, fmt.Errorf("%w: version %d is below 1", ErrConfig, c.Version)
	}
	return &Learner{
		cfg: c, p: c.Params,
		types:    map[baseline.Key]*learnt{},
		overflow: map[baseline.Key]struct{}{},
		excluded: map[baseline.Exclusion]int64{},
	}, nil
}

// Observe takes one stored event of the asset. Events that belong to no
// asset's baseline (platform events, other kinds, asset-unresolved) are
// counted in Excluded and nothing else; an event of another asset is an
// error and is not counted.
func (l *Learner) Observe(o Obs) error {
	e := o.Event
	if e == nil {
		return fmt.Errorf("%w: nil event", ErrConfig)
	}
	if e.Source.Asset != nil && e.Source.Asset.ID != l.cfg.AssetID {
		return fmt.Errorf("%w: %s, learning %s", ErrAsset, e.Source.Asset.ID, l.cfg.AssetID)
	}
	k, text, use, why := baseline.Classify(e, o.AfterFailure)
	if use == baseline.UseNone {
		l.excluded[why]++
		return nil
	}
	t, err := received(e)
	if err != nil {
		return err
	}
	if l.started && t < l.lastNS {
		return fmt.Errorf("%w: %s is before %s", ErrOrder, fmtNS(t), fmtNS(l.lastNS))
	}
	if !l.started {
		l.started, l.startNS = true, t
	}
	l.lastNS = t
	l.events++
	if o.NotCounted {
		l.notCnt++
		return nil
	}
	if use == baseline.UseFull {
		l.full++
	} else {
		l.typeOnly++
	}
	ty := l.types[k]
	if ty == nil {
		if int64(len(l.types)) >= l.p.MaxTypes {
			if _, ok := l.overflow[k]; !ok {
				if int64(len(l.overflow)) >= l.p.MaxTypes {
					l.overflowSaturated = true
				} else {
					l.overflow[k] = struct{}{}
				}
			}
			return nil
		}
		ty = &learnt{key: k, text: text, first: t, gaps: map[int64]int64{}}
		l.types[k] = ty
	}
	ty.count++
	ty.last = t
	if use == baseline.UseFull {
		ty.addFull(t, &l.p)
	}
	return nil
}

func (ty *learnt) addFull(t int64, p *baseline.Params) {
	ty.full++
	ty.hours[hourOf(t)]++

	win := nsOf(p.RepeatsWindowS)
	for len(ty.win) > 0 && ty.win[0] <= t-win {
		ty.win = ty.win[1:]
	}
	if len(ty.win) == windowCap {
		ty.win = ty.win[1:]
	}
	ty.win = append(ty.win, t)
	ty.maxWin = max(ty.maxWin, int64(len(ty.win)))

	b := t / nsOf(p.RateBucketS)
	if ty.inBucket == 0 || b != ty.bucket {
		ty.bucket, ty.inBucket = b, 0
	}
	ty.inBucket++
	ty.maxBucket = max(ty.maxBucket, ty.inBucket)

	if ty.haveFull && !ty.notPeriodic {
		g := (t - ty.lastFullNS + int64(time.Second)/2) / int64(time.Second)
		if len(ty.gaps) == 0 {
			ty.gapMin, ty.gapMax = g, g
		}
		ty.gapMin, ty.gapMax = min(ty.gapMin, g), max(ty.gapMax, g)
		ty.gaps[g]++
		// No median can hold every gap within spread% when the largest
		// and the smallest are further apart than twice that of the
		// largest: the type can never be found periodic, so stop holding.
		if (ty.gapMax-ty.gapMin)*100 > 2*ty.gapMax*p.PeriodicSpreadPct || len(ty.gaps) > gapCap {
			ty.notPeriodic, ty.gaps = true, nil
		}
	}
	ty.haveFull, ty.lastFullNS = true, t
}

// periodic returns the interval of a type found periodic: at least
// periodic_min_occurrences full occurrences, and every gap within
// periodic_spread_pct of the median (the upper middle of the sorted gaps),
// all in integers.
func (ty *learnt) periodic(p *baseline.Params) (interval int64, ok bool) {
	if ty.notPeriodic || ty.full < p.PeriodicMinOccurrences {
		return 0, false
	}
	vals := make([]int64, 0, len(ty.gaps))
	for g := range ty.gaps {
		vals = append(vals, g)
	}
	slices.Sort(vals)
	n := ty.full - 1 // gaps
	var seen int64
	m := int64(-1)
	for _, g := range vals {
		seen += ty.gaps[g]
		if seen > n/2 {
			m = g
			break
		}
	}
	if m < 1 {
		return 0, false
	}
	for _, g := range []int64{ty.gapMin, ty.gapMax} {
		if abs(g-m)*100 > m*p.PeriodicSpreadPct {
			return 0, false
		}
	}
	return m, true
}

func abs(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}

// Gap records an interval in which the asset's collection failed (a V-S12
// failure) and which therefore does not count toward the observation period.
// Gaps are given in order, as they close.
func (l *Learner) Gap(from, to time.Time, reason string) {
	l.gaps = append(l.gaps, baseline.Gap{
		FromUTC: from.UTC().Format(time.RFC3339Nano), ToUTC: to.UTC().Format(time.RFC3339Nano), Reason: reason,
	})
}

// Progress is how far the observation period has come.
type Progress struct {
	Started    bool
	CollectedS int64 // seconds with successful collection so far
	Events     int64
	// Done is true when both minima are met: the baseline can be recorded.
	Done bool
}

// Progress reports the period's progress at now.
func (l *Learner) Progress(now time.Time) Progress {
	if !l.started {
		return Progress{}
	}
	c, _ := l.collected(now.UnixNano())
	return Progress{Started: true, CollectedS: c, Events: l.events,
		Done: c >= l.p.MinDurationS && l.events >= l.p.MinEvents}
}

// collected returns the seconds from the first event to end less the gaps
// inside it, and the gaps clipped to the period.
func (l *Learner) collected(endNS int64) (int64, []baseline.Gap) {
	var gaps []baseline.Gap
	var gapNS int64
	for _, g := range l.gaps {
		f, _ := time.Parse(time.RFC3339Nano, g.FromUTC)
		t, _ := time.Parse(time.RFC3339Nano, g.ToUTC)
		fn, tn := max(f.UnixNano(), l.startNS), min(t.UnixNano(), endNS)
		if tn <= fn {
			continue
		}
		gapNS += tn - fn
		gaps = append(gaps, baseline.Gap{FromUTC: fmtNS(fn), ToUTC: fmtNS(tn), Reason: g.Reason})
	}
	return (endNS - l.startNS - gapNS) / int64(time.Second), gaps
}

// Excluded returns the events that belong to no asset's baseline, by why.
func (l *Learner) Excluded() map[baseline.Exclusion]int64 { return maps.Clone(l.excluded) }

// ErrNotDone: Finish was called before both minima were met.
var ErrNotDone = errors.New("eventbaseline: the observation period has not ended")

// Result is a finished baseline, the bytes it is stored as and their hash.
type Result struct {
	Baseline *baseline.Baseline
	Bytes    []byte
	Hash     string
	// OverflowSaturated is true when the learner stopped counting types
	// left out, so Counts.TypesOverflow is a lower bound.
	OverflowSaturated bool
}

// Finish ends the period at now and records the baseline. It refuses before
// both minima are met (ErrNotDone). Types past Params.MaxTypes, or past
// what fits in the byte cap, are left out; the learner keeps the first
// MaxTypes it met (a learner that kept the highest counts would hold every
// type until the end), and drops from those, lowest count first and ties by
// key, until the record fits.
func (l *Learner) Finish(now time.Time) (*Result, error) {
	if pr := l.Progress(now); !pr.Started || !pr.Done {
		return nil, fmt.Errorf("%w: %d s collected of %d, %d events of %d", ErrNotDone, pr.CollectedS, l.p.MinDurationS, pr.Events, l.p.MinEvents)
	}
	endNS := now.UnixNano()
	if endNS < l.lastNS {
		return nil, fmt.Errorf("%w: finishing at %s, before the last event taken at %s", ErrOrder, fmtNS(endNS), fmtNS(l.lastNS))
	}
	collected, gaps := l.collected(endNS)
	b := &baseline.Baseline{
		Schema: baseline.Identifier, NodeID: l.cfg.Node, AssetID: l.cfg.AssetID,
		Version: l.cfg.Version, Previous: l.cfg.Previous,
		Learner: baseline.Learner{Name: LearnerName, Version: LearnerVersion},
		Params:  l.p,
		Period:  baseline.Period{StartUTC: fmtNS(l.startNS), EndUTC: fmtNS(endNS), CollectedS: collected, Gaps: gaps},
		Counts: baseline.Counts{Events: l.events, Full: l.full, TypeOnly: l.typeOnly, NotCounted: l.notCnt,
			TypesOverflow: int64(len(l.overflow))},
		RecordedUTC: fmtNS(endNS),
	}
	all := make([]*learnt, 0, len(l.types))
	for _, ty := range l.types {
		all = append(all, ty)
	}
	// Most-counted first, so a cut leaves the least-counted out.
	sort.Slice(all, func(i, j int) bool {
		if all[i].count != all[j].count {
			return all[i].count > all[j].count
		}
		return all[i].key.String() < all[j].key.String()
	})
	build := func(n int) {
		b.Types = make([]baseline.Type, 0, n)
		for _, ty := range all[:n] {
			b.Types = append(b.Types, ty.record(&l.p))
		}
		slices.SortFunc(b.Types, func(a, c baseline.Type) int {
			as, cs := a.Key.String(), c.Key.String()
			switch {
			case as < cs:
				return -1
			case as > cs:
				return 1
			}
			return 0
		})
		b.Counts.TypesOverflow = int64(len(l.overflow) + len(all) - n)
	}
	limit := l.cfg.MaxBytes
	// With no type at all the record is the same whatever the limit. With
	// some, find by bisection the most types that encode within the limit:
	// the encoded size only grows with the number of types, and a size
	// refusal is baseline.CodeRange on the whole record.
	try := func(n int) ([]byte, error) {
		build(n)
		return baseline.Encode(b, limit)
	}
	var out []byte
	var err error
	if len(all) == 0 {
		out, err = try(0)
	} else {
		lo, hi, best := 1, len(all), 0
		for lo <= hi {
			mid := (lo + hi) / 2
			o, e := try(mid)
			var be *baseline.Error
			switch {
			case e == nil:
				out, best, lo = o, mid, mid+1
			case errors.As(e, &be) && be.Field == "baseline" && be.Code == baseline.CodeRange:
				hi = mid - 1
			default:
				return nil, e
			}
		}
		if best == 0 {
			return nil, fmt.Errorf("eventbaseline: not even one type fits %d bytes", cmpLimit(limit))
		}
		build(best)
	}
	if err != nil {
		return nil, err
	}
	return &Result{Baseline: b, Bytes: out, Hash: baseline.Hash(out), OverflowSaturated: l.overflowSaturated}, nil
}

func cmpLimit(limit int) int {
	if limit <= 0 || limit > baseline.MaxBytes {
		return baseline.MaxBytes
	}
	return limit
}

// record is the type as the baseline stores it.
func (ty *learnt) record(p *baseline.Params) baseline.Type {
	t := baseline.Type{
		Key: ty.key, Text: ty.text, Count: ty.count, Full: ty.full, HoursUTC: ty.hours,
		MaxPerWindow: ty.maxWin, MaxPerBucket: ty.maxBucket,
		FirstUTC: fmtNS(ty.first), LastUTC: fmtNS(ty.last),
	}
	if iv, ok := ty.periodic(p); ok {
		t.Periodic = &baseline.Periodic{IntervalS: iv, ToleranceS: baseline.Tolerance(iv, p.AbsenceTolerancePct)}
	}
	return t
}
