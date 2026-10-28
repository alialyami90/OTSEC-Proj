package eventbaseline

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"otsec.local/otsec/contracts/baseline"
	"otsec.local/otsec/contracts/event"
)

// Held is the notice for the first alarm an asset could not raise in a hold,
// because it had reached Params.MaxAlarmsPerHold. The node raises it as a
// C4 health event of type baseline.HealthAlarmsHeld, with details asset_id,
// held and hold_s. Held counts the alarms not raised so far in this hold;
// Detector.HeldNow gives the count later.
type Held struct {
	AssetID string
	HoldS   int64
	Held    int64
}

// Output is what one call of the detector raises.
type Output struct {
	Alarms []*baseline.Alarm
	// Held is set when this call first met the asset's alarm limit in a hold.
	Held *Held
}

// DetectorConfig is everything a Detector is built from.
type DetectorConfig struct {
	Baseline *baseline.Baseline
	// Hash is baseline.Hash of the stored record's bytes, as C7 0.6
	// node.baseline_ack named it. The alarms carry it.
	Hash string
	// ActiveFrom is when the operator's acknowledgement entered the audit
	// chain. Departures are alarmed from then on. A periodic type whose
	// interval and tolerance ran out before then is given ActiveFrom +
	// interval + tolerance as its deadline (D4-15).
	ActiveFrom time.Time
}

// Detector raises the departure alarms of one asset against its active
// baseline. It holds no clock: time comes from the events it is given and
// from the now it is ticked with, so the same input gives the same alarms.
type Detector struct {
	b     *baseline.Baseline
	hash  string
	p     *baseline.Params
	types map[baseline.Key]*watch
	// periodic lists the watched periodic types in key order.
	periodic []*watch
	// newSeen holds the digests of the new types alarmed (at most
	// newSeenMax); inBaseline those of the baseline's types.
	newSeen    map[digest]struct{}
	inBaseline map[digest]bool
	activeNS   int64
	lastNS     int64

	pairs map[pair]*pending
	// newPairs counts the pairs of the new-type rule, the only ones whose
	// number is not bounded by the baseline (MaxNewTypePairs).
	newPairs int
	// nextSweep is the time before which the new-type pairs are not swept
	// again for ones that expired.
	nextSweep int64
	// beyond counts the breaks held for want of a pair to record them in,
	// or of room in heldIDBudget to list them, since an alarm last stated
	// it; heldIDs counts the IDs the pending records list.
	beyond  int64
	heldIDs int
	// The asset's hold: it opened at holdFrom with raised alarms.
	holdOpen bool
	holdFrom int64
	raised   int64
	held     int64
}

// watch is a baseline type being watched.
type watch struct {
	t    *baseline.Type
	hour [24]bool
	// Repeats: the last RepeatsN+1 full occurrences, oldest first.
	recent []stamp
	// Rate bucket in progress.
	bucket   int64
	inBucket int64
	ids      []event.EventID
	// Absence.
	last   int64
	absent bool
	// notCounted are the possible duplicates not yet shown on an alarm.
	notCounted      []event.EventID
	notCountedTotal int64
}

type stamp struct {
	ns int64
	id event.EventID
}

type pair struct {
	rule baseline.Rule
	key  digest
}

// pending is what breaks of a pair added up since its last alarm.
type pending struct {
	// born is when the record was made; a pair that never raised ends its
	// hold AlarmHoldS after it.
	born       int64
	lastAlarm  int64
	raisedOnce bool
	ids        []event.EventID
	total      int64
}

// NewDetector builds the detector of one asset's active baseline.
func NewDetector(c DetectorConfig) (*Detector, error) {
	b := c.Baseline
	if b == nil {
		return nil, fmt.Errorf("%w: no baseline", ErrConfig)
	}
	if err := checkParams(b.Params); err != nil {
		return nil, err
	}
	if err := b.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrConfig, err)
	}
	if len(b.Types) > MaxTypes {
		return nil, fmt.Errorf("%w: the baseline has %d types, above %d (D4-30)", ErrConfig, len(b.Types), MaxTypes)
	}
	d := &Detector{
		b: b, hash: c.Hash, p: &b.Params,
		types: map[baseline.Key]*watch{}, newSeen: map[digest]struct{}{}, inBaseline: map[digest]bool{},
		pairs: map[pair]*pending{}, activeNS: c.ActiveFrom.UnixNano(), lastNS: c.ActiveFrom.UnixNano(),
	}
	for i := range b.Types {
		t := &b.Types[i]
		w := &watch{t: t}
		for h, n := range t.HoursUTC {
			w.hour[h] = n > 0
		}
		if t.Periodic != nil {
			last, err := time.Parse(time.RFC3339Nano, t.LastUTC)
			if err != nil {
				return nil, fmt.Errorf("%w: %v", ErrConfig, err)
			}
			w.last = last.UnixNano()
			// A type whose deadline ran out before the acknowledgement has its
			// deadline start at the acknowledgement (D4-15): none is ever left
			// unarmed, so a source that falls silent during the wait and never
			// returns still alarms, and nothing alarms before activation.
			if w.deadline() < c.ActiveFrom.UnixNano() {
				w.last = c.ActiveFrom.UnixNano()
			}
			d.periodic = append(d.periodic, w)
		}
		d.types[t.Key] = w
		d.inBaseline[digestOf(t.Key)] = true
	}
	return d, nil
}

func (w *watch) deadline() int64 {
	return w.last + nsOf(w.t.Periodic.IntervalS+w.t.Periodic.ToleranceS)
}

// Observe takes one stored event of the asset and returns the alarms it
// raises, absence alarms that fell due before it first.
func (d *Detector) Observe(o Obs) (Output, error) {
	e := o.Event
	if e == nil {
		return Output{}, fmt.Errorf("%w: nil event", ErrConfig)
	}
	if e.Source.Asset != nil && e.Source.Asset.ID != d.b.AssetID {
		return Output{}, fmt.Errorf("%w: %s, watching %s", ErrAsset, e.Source.Asset.ID, d.b.AssetID)
	}
	k, text, use, _ := baseline.Classify(e, o.AfterFailure)
	if use == baseline.UseNone {
		return Output{}, nil
	}
	t, err := received(e)
	if err != nil {
		return Output{}, err
	}
	if t < d.activeNS {
		return Output{}, nil // before the acknowledgement: no departure alarm
	}
	if t < d.lastNS {
		return Output{}, fmt.Errorf("%w: %s is before %s", ErrOrder, fmtNS(t), fmtNS(d.lastNS))
	}
	out := d.advance(t)
	d.lastNS = t

	w := d.types[k]
	if w == nil {
		if o.NotCounted {
			return out, nil
		}
		if dg := digestOf(k); !d.seenNew(dg) {
			if len(d.newSeen) < newSeenMax {
				d.newSeen[dg] = struct{}{}
			}
			d.raiseNew(&out, k, text, e, t, use)
		}
		return out, nil
	}
	if o.NotCounted {
		w.notCountedTotal++
		if len(w.notCounted) < baseline.MaxEventIDs {
			w.notCounted = append(w.notCounted, e.ID)
		}
		return out, nil
	}
	if use.Applies(baseline.RuleRepeats) {
		d.repeats(&out, w, k, text, e, t)
	}
	if use.Applies(baseline.RuleRate) {
		d.rate(&out, w, k, text, e, t)
	}
	if use.Applies(baseline.RuleTime) {
		d.timeRule(&out, w, k, text, e, t)
	}
	if use.Applies(baseline.RuleAbsence) && w.t.Periodic != nil {
		w.last, w.absent = t, false
	}
	return out, nil
}

// Tick raises the absence alarms that have fallen due by now. A deadline is
// due once now is past it: an occurrence at the deadline is in time.
//
// now is a watermark: no event received before now may remain to be
// observed. Tick moves the detector's time to now, and Observe refuses an
// event received before it with ErrOrder, so a Tick with the wall clock ahead
// of events not yet observed loses their alarms. See the package documentation,
// "Replay and alarm identity".
func (d *Detector) Tick(now time.Time) (Output, error) {
	ns := now.UnixNano()
	if ns < d.lastNS {
		return Output{}, fmt.Errorf("%w: tick at %s, before %s", ErrOrder, fmtNS(ns), fmtNS(d.lastNS))
	}
	d.lastNS = ns
	return d.advance(ns), nil
}

func (d *Detector) seenNew(dg digest) bool { _, ok := d.newSeen[dg]; return ok }

// HeldNow is the number of alarms the asset could not raise in the hold now
// open, or 0.
func (d *Detector) HeldNow() int64 { return d.held }

// BeyondNow is the number of breaks that were held and are listed nowhere,
// because the new-type rule already tracked MaxNewTypePairs types: they are
// counted in HeldNow while their hold lasts, and the next alarm of the asset
// states the count in its Observation and starts it again from zero.
func (d *Detector) BeyondNow() int64 { return d.beyond }

// advance raises absence alarms for every deadline before now.
func (d *Detector) advance(now int64) (out Output) {
	for _, w := range d.periodic {
		if w.absent || w.deadline() >= now {
			continue
		}
		w.absent = true
		pd := w.t.Periodic
		d.raise(&out, now, raise{
			rule: baseline.RuleAbsence, key: w.t.Key, keyText: w.t.Text, at: w.deadline(), w: w,
			params: []baseline.Param{{Name: "interval_s", Value: dec(pd.IntervalS)}, {Name: "tolerance_s", Value: dec(pd.ToleranceS)}},
			value:  fmt.Sprintf("periodic, interval %d s, tolerance %d s, last seen %s", pd.IntervalS, pd.ToleranceS, fmtNS(w.last)),
			obs:    fmt.Sprintf("not seen by %s, the end of interval + tolerance", fmtNS(w.deadline())),
		})
	}
	return out
}

func (d *Detector) raiseNew(out *Output, k baseline.Key, text string, e *event.Event, t int64, use baseline.Use) {
	obs := fmt.Sprintf("first occurrence, received %s", fmtNS(t))
	if use == baseline.UseTypeOnly {
		if e.Collection != nil && e.Collection.Alignment != "" {
			obs += ", catch_up: " + string(e.Collection.Alignment)
		} else {
			obs += ", catch_up: after-failure"
		}
	}
	d.raise(out, t, raise{
		rule: baseline.RuleNewType, key: k, keyText: text, at: t, ids: []event.EventID{e.ID}, brk: e.ID,
		value: fmt.Sprintf("not among the %d types of baseline version %d (%d left out)", len(d.b.Types), d.b.Version, d.b.Counts.TypesOverflow),
		obs:   obs,
	})
}

func (d *Detector) repeats(out *Output, w *watch, k baseline.Key, text string, e *event.Event, t int64) {
	n := int(d.p.RepeatsN) + 1
	win := nsOf(d.p.RepeatsWindowS)
	w.recent = append(w.recent, stamp{t, e.ID})
	if len(w.recent) > n {
		w.recent = w.recent[1:]
	}
	if w.t.MaxPerWindow >= d.p.RepeatsN || len(w.recent) < n || w.recent[0].ns <= t-win {
		return
	}
	var ids []event.EventID
	for _, s := range w.recent {
		ids = append(ids, s.id)
	}
	d.raise(out, t, raise{
		rule: baseline.RuleRepeats, key: k, keyText: text, at: t, ids: ids, brk: e.ID, w: w,
		params: []baseline.Param{{Name: "repeats_n", Value: dec(d.p.RepeatsN)}, {Name: "repeats_window_s", Value: dec(d.p.RepeatsWindowS)}},
		value:  fmt.Sprintf("max_per_window %d, below repeats_n %d", w.t.MaxPerWindow, d.p.RepeatsN),
		obs:    fmt.Sprintf("%d in the window (%s, %s]", n, fmtNS(t-win), fmtNS(t)),
	})
}

func (d *Detector) rate(out *Output, w *watch, k baseline.Key, text string, e *event.Event, t int64) {
	b := t / nsOf(d.p.RateBucketS)
	if w.inBucket == 0 || b != w.bucket {
		w.bucket, w.inBucket, w.ids = b, 0, nil
	}
	w.inBucket++
	if len(w.ids) < baseline.MaxEventIDs {
		w.ids = append(w.ids, e.ID)
	}
	bound := baseline.RateBound(w.t.MaxPerBucket, *d.p)
	if w.inBucket != bound+1 {
		return
	}
	d.raise(out, t, raise{
		rule: baseline.RuleRate, key: k, keyText: text, at: t, ids: slices.Clone(w.ids), idsTotal: w.inBucket, brk: e.ID, w: w,
		params: []baseline.Param{{Name: "rate_bucket_s", Value: dec(d.p.RateBucketS)}, {Name: "rate_factor_pct", Value: dec(d.p.RateFactorPct)}, {Name: "rate_min", Value: dec(d.p.RateMin)}},
		value:  fmt.Sprintf("max_per_bucket %d, bound %d", w.t.MaxPerBucket, bound),
		obs:    fmt.Sprintf("%d in the bucket from %s", w.inBucket, fmtNS(b*nsOf(d.p.RateBucketS))),
	})
}

func (d *Detector) timeRule(out *Output, w *watch, k baseline.Key, text string, e *event.Event, t int64) {
	h := hourOf(t)
	if w.hour[h] {
		return
	}
	d.raise(out, t, raise{
		rule: baseline.RuleTime, key: k, keyText: text, at: t, ids: []event.EventID{e.ID}, brk: e.ID, w: w,
		value: "seen in UTC hours " + hoursText(w.hour),
		obs:   fmt.Sprintf("received %s, UTC hour %d", fmtNS(t), h),
	})
}

// hoursText lists the hours as ranges, "1-5,9".
func hoursText(h [24]bool) string {
	var parts []string
	for i := 0; i < 24; i++ {
		if !h[i] {
			continue
		}
		j := i
		for j+1 < 24 && h[j+1] {
			j++
		}
		if j == i {
			parts = append(parts, strconv.Itoa(i))
		} else {
			parts = append(parts, fmt.Sprintf("%d-%d", i, j))
		}
		i = j
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, ",")
}

func dec(n int64) string { return strconv.FormatInt(n, 10) }

// raise is one break of the baseline, before the holds decide whether it
// becomes an alarm.
type raise struct {
	rule    baseline.Rule
	key     baseline.Key
	keyText string
	at      int64
	params  []baseline.Param
	value   string
	obs     string
	// ids are the events to list, idsTotal how many there are (len(ids)
	// when 0), and brk the one event that broke the baseline, which is all
	// a held break adds to the next alarm of its pair.
	ids      []event.EventID
	idsTotal int64
	brk      event.EventID
	w        *watch
}

// raise applies the holds (Params.AlarmHoldS, MaxAlarmsPerHold) and, if the
// break is not held, appends its alarm.
//
// Each (rule, type) has a pending record that holds its hold and the breaks
// held since its last alarm. The records of the four rules on baseline types
// are bounded by the baseline. The new-type rule's are not, so they are
// bounded here (D4-26, F1): at MaxNewTypePairs the ones whose hold ended and
// that list nothing are dropped, which changes no output (see sweepNewPairs),
// and a break that still finds none is raised or held on the asset's hold
// alone and, if held, counted in d.beyond for the next alarm to state. A held
// break past heldIDBudget is counted there too (hold).
func (d *Detector) raise(out *Output, now int64, r raise) {
	hold := nsOf(d.p.AlarmHoldS)
	pr := pair{r.rule, digestOf(r.key)}
	pd := d.pairs[pr]
	if pd == nil {
		pd = d.newPair(pr, r.at)
	}
	if d.holdOpen && r.at >= d.holdFrom+hold {
		d.holdOpen, d.raised, d.held = false, 0, 0
	}
	switch {
	case pd != nil && pd.raisedOnce && r.at < pd.lastAlarm+hold:
		d.hold(pd, r)
		return
	case d.holdOpen && d.raised >= d.p.MaxAlarmsPerHold:
		if pd != nil {
			d.hold(pd, r)
		} else {
			d.beyond++
		}
		d.held++
		if d.held == 1 {
			out.Held = &Held{AssetID: d.b.AssetID, HoldS: d.p.AlarmHoldS, Held: 1}
		}
		return
	}
	// Raise it, with the breaks held since this pair's last alarm.
	var ids []event.EventID
	var total int64
	if pd != nil {
		ids = slices.Clone(pd.ids)
		total = pd.total
	}
	for _, id := range r.ids {
		if !slices.Contains(ids, id) {
			total++
			if len(ids) < baseline.MaxEventIDs {
				ids = append(ids, id)
			}
		}
	}
	if r.idsTotal > int64(len(r.ids)) {
		total += r.idsTotal - int64(len(r.ids))
	}
	obs := r.obs
	if d.beyond > 0 {
		note := fmt.Sprintf("; %d more held breaks beyond the detector's caps are not listed", d.beyond)
		obs += note // every rule's observation is under 120 bytes, so the note fits ExplainMax whole
		d.beyond = 0
	}
	a := &baseline.Alarm{
		Schema: baseline.Identifier, AssetID: d.b.AssetID, Baseline: d.hash, BaselineVersion: d.b.Version,
		Rule: r.rule, Key: r.key, KeyText: r.keyText, Params: r.params,
		BaselineValue: clip(r.value, baseline.ExplainMax), Observation: clip(obs, baseline.ExplainMax), Clock: baseline.ClockReceived,
		AtUTC: fmtNS(r.at), Events: ids, EventsTotal: total,
	}
	if r.w != nil {
		a.NotCounted, a.NotCountedTotal = r.w.notCounted, r.w.notCountedTotal
		r.w.notCounted, r.w.notCountedTotal = nil, 0
	}
	out.Alarms = append(out.Alarms, a)
	if pd != nil {
		d.heldIDs -= len(pd.ids)
		*pd = pending{born: pd.born, lastAlarm: r.at, raisedOnce: true}
	}
	if !d.holdOpen {
		d.holdOpen, d.holdFrom, d.raised, d.held = true, r.at, 0, 0
	}
	d.raised++
}

// newPair adds the record of a pair that has none, or returns nil when the
// pair is a new-type one and MaxNewTypePairs are tracked already.
func (d *Detector) newPair(pr pair, at int64) *pending {
	if pr.rule == baseline.RuleNewType {
		if d.newPairs >= pairCap {
			d.sweepNewPairs(at)
		}
		if d.newPairs >= pairCap {
			return nil
		}
		d.newPairs++
	}
	pd := &pending{born: at}
	d.pairs[pr] = pd
	return pd
}

// sweepNewPairs makes room among the new-type pairs, at most once in an alarm
// hold. First it drops the ones whose hold ended and that list no break. Such a
// pair acts exactly as no pair does: the next break of its type is not held by
// it, and it adds nothing to the next alarm, so this changes no output. That is
// only so for the new-type rule, whose breaks are stamped with the event's
// received time and so never earlier than at, which the Observe order
// guarantees; an absence alarm is stamped with its deadline, which can be
// earlier than the time it was noticed, so the pairs of the other rules are
// kept (and are bounded by the baseline's types).
//
// If that leaves no room, it drops the ones whose hold ended and that list
// breaks no alarm has yet listed. Those breaks stay counted (d.beyond, which
// the next alarm states), but they will not be listed if their type recurs.
func (d *Detector) sweepNewPairs(at int64) {
	if !pairPrune || at < d.nextSweep {
		return
	}
	hold := nsOf(d.p.AlarmHoldS)
	d.nextSweep = at + hold
	ended := func(pd *pending) bool {
		if pd.raisedOnce {
			return at >= pd.lastAlarm+hold
		}
		return at >= pd.born+hold
	}
	for pr, pd := range d.pairs {
		if pr.rule == baseline.RuleNewType && ended(pd) && len(pd.ids) == 0 && pd.total == 0 {
			delete(d.pairs, pr)
			d.newPairs--
		}
	}
	if d.newPairs < pairCap {
		return
	}
	for pr, pd := range d.pairs {
		if pr.rule == baseline.RuleNewType && ended(pd) {
			d.beyond += pd.total
			d.heldIDs -= len(pd.ids)
			delete(d.pairs, pr)
			d.newPairs--
		}
	}
}

// hold adds a held break's event to what the pair's next alarm will list. A
// break whose ID would be listed when heldIDBudget IDs are listed already is
// counted in d.beyond instead, so the alarm's list stays the first of its
// total (C10) and the next alarm's note states it (D4-30).
func (d *Detector) hold(pd *pending, r raise) {
	if r.brk == (event.EventID{}) {
		return
	}
	if len(pd.ids) > 0 && pd.ids[len(pd.ids)-1] == r.brk {
		return
	}
	if len(pd.ids) < baseline.MaxEventIDs {
		if d.heldIDs >= heldIDBudget {
			d.beyond++
			return
		}
		pd.ids = append(pd.ids, r.brk)
		d.heldIDs++
	}
	pd.total++
}

func clip(s string, max int) string {
	if len(s) > max {
		return s[:max]
	}
	return s
}
