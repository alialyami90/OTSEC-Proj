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
	// interval and tolerance ran out before then raises no absence alarm
	// until it has occurred again.
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
	newSeen  map[baseline.Key]struct{}
	activeNS int64
	lastNS   int64

	pairs map[pair]*pending
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
	key  baseline.Key
}

// pending is what breaks of a pair added up since its last alarm.
type pending struct {
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
	d := &Detector{
		b: b, hash: c.Hash, p: &b.Params,
		types: map[baseline.Key]*watch{}, newSeen: map[baseline.Key]struct{}{},
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
			// A type whose deadline ran out before the acknowledgement is
			// not armed until it occurs again: the wait for the
			// acknowledgement alarms nothing (B6's reading of V-M4). A type
			// that never returns is therefore not alarmed (a limit).
			w.absent = w.deadline() < c.ActiveFrom.UnixNano()
			d.periodic = append(d.periodic, w)
		}
		d.types[t.Key] = w
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
		if _, seen := d.newSeen[k]; !seen {
			if len(d.newSeen) < baseline.MaxTypesCeiling*4 {
				d.newSeen[k] = struct{}{}
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
func (d *Detector) Tick(now time.Time) (Output, error) {
	ns := now.UnixNano()
	if ns < d.lastNS {
		return Output{}, fmt.Errorf("%w: tick at %s, before %s", ErrOrder, fmtNS(ns), fmtNS(d.lastNS))
	}
	d.lastNS = ns
	return d.advance(ns), nil
}

// HeldNow is the number of alarms the asset could not raise in the hold now
// open, or 0.
func (d *Detector) HeldNow() int64 { return d.held }

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
func (d *Detector) raise(out *Output, now int64, r raise) {
	hold := nsOf(d.p.AlarmHoldS)
	pr := pair{r.rule, r.key}
	pd := d.pairs[pr]
	if pd == nil {
		pd = &pending{}
		d.pairs[pr] = pd
	}
	if d.holdOpen && r.at >= d.holdFrom+hold {
		d.holdOpen, d.raised, d.held = false, 0, 0
	}
	switch {
	case pd.raisedOnce && r.at < pd.lastAlarm+hold:
		pd.hold(r)
		return
	case d.holdOpen && d.raised >= d.p.MaxAlarmsPerHold:
		pd.hold(r)
		d.held++
		if d.held == 1 {
			out.Held = &Held{AssetID: d.b.AssetID, HoldS: d.p.AlarmHoldS, Held: 1}
		}
		return
	}
	// Raise it, with the breaks held since this pair's last alarm.
	ids := slices.Clone(pd.ids)
	total := pd.total
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
	a := &baseline.Alarm{
		Schema: baseline.Identifier, AssetID: d.b.AssetID, Baseline: d.hash, BaselineVersion: d.b.Version,
		Rule: r.rule, Key: r.key, KeyText: r.keyText, Params: r.params,
		BaselineValue: clip(r.value), Observation: clip(r.obs), Clock: baseline.ClockReceived,
		AtUTC: fmtNS(r.at), Events: ids, EventsTotal: total,
	}
	if r.w != nil {
		a.NotCounted, a.NotCountedTotal = r.w.notCounted, r.w.notCountedTotal
		r.w.notCounted, r.w.notCountedTotal = nil, 0
	}
	out.Alarms = append(out.Alarms, a)
	*pd = pending{lastAlarm: r.at, raisedOnce: true}
	if !d.holdOpen {
		d.holdOpen, d.holdFrom, d.raised, d.held = true, r.at, 0, 0
	}
	d.raised++
}

// hold adds a held break's event to what the pair's next alarm will list.
func (pd *pending) hold(r raise) {
	if r.brk == (event.EventID{}) {
		return
	}
	if len(pd.ids) > 0 && pd.ids[len(pd.ids)-1] == r.brk {
		return
	}
	pd.total++
	if len(pd.ids) < baseline.MaxEventIDs {
		pd.ids = append(pd.ids, r.brk)
	}
}

func clip(s string) string {
	if len(s) > baseline.ExplainMax {
		return s[:baseline.ExplainMax]
	}
	return s
}
