package baseline

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"time"

	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/internal/strictjson"
	"otsec.local/otsec/contracts/node"
	"otsec.local/otsec/contracts/version"
)

// Identifier is this contract's identifier, stamped on every record.
const Identifier = "otsec.baseline/0.1"

var self = version.ID{Name: "baseline", Major: 0, Minor: 1}

// Proposed defaults from docs/verification.md, "R4.8 observation period and
// measures". They are parameters, recorded in every baseline, never
// constants a learner may assume.
const (
	DefaultMinDuration = 14 * 24 * time.Hour
	DefaultMinEvents   = 200
)

// MaxTypesCeiling is the most types any baseline may hold. Params.MaxTypes
// is at or below it.
const MaxTypesCeiling = 4096

// MaxBytes is C10's own cap on a stored baseline. It is set at or below
// the MaxRecordBytes of C5 0.4's configuration class, which stores the
// record, so a baseline that fits is never refused there. A type
// takes about 270 to 630 bytes encoded compact (desk measurement), so a
// baseline is bounded by bytes before it reaches MaxTypesCeiling. A learner
// fits the baseline to MaxBytes, or to the node's configured cap if lower,
// leaving out the types with the lowest Count; Encode refuses one that does
// not fit.
const MaxBytes = 512 << 10

// MaxAlarmsPerHoldCeiling bounds Params.MaxAlarmsPerHold, and
// MinAlarmHoldS is the shortest Params.AlarmHoldS. The platform class
// refuses new events when full, so a departure storm must not fill it: per
// asset an hour holds at most (8 + 1 held) × MaxAlarmBytes (B5 on #254).
// Eight is still more than the five rules.
const (
	MaxAlarmsPerHoldCeiling = 8
	MinAlarmHoldS           = 3600
)

// Clock is the clock a time rule used. Closed.
type Clock string

const (
	ClockReceived Clock = "received" // received.utc, the default
	ClockDevice   Clock = "device"   // device time, only where the offset is known (V-S3)
)

// Baseline is one asset's event-behaviour baseline, recorded once when its
// observation period ends. It never changes: a re-learn is a new record
// with Version + 1 and Previous set to Hash of the record it replaces.
type Baseline struct {
	Schema  string  `json:"schema"`
	NodeID  node.ID `json:"node_id"`
	AssetID string  `json:"asset_id"`
	// Version is 1 for an asset's first baseline and one more for each
	// re-learn.
	Version int `json:"version"`
	// Previous is Hash of the baseline this one replaces. Set exactly when
	// Version is above 1.
	Previous string  `json:"previous,omitempty"`
	Learner  Learner `json:"learner"`
	Params   Params  `json:"params"`
	Period   Period  `json:"period"`
	Counts   Counts  `json:"counts"`
	// Types are the types learnt, ordered by Key.String, each once.
	Types []Type `json:"types"`
	// RecordedUTC is when the node recorded the baseline (RFC 3339, Z).
	RecordedUTC string `json:"recorded_utc"`
}

// Learner names the code that learnt the baseline.
type Learner struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Params are every parameter the learner and the five rules use. All
// durations are whole seconds; all factors are whole percent, so the rules
// need no floating point.
type Params struct {
	// The observation period ends when both are reached. Only time with
	// successful collection counts toward MinDurationS.
	MinDurationS int64 `json:"min_duration_s"`
	MinEvents    int64 `json:"min_events"`
	// Repeats: an alarm when one type occurs more than RepeatsN times within
	// RepeatsWindowS and the baseline's MaxPerWindow for it is below
	// RepeatsN. The window of an occurrence at t holds the occurrences in
	// (t - RepeatsWindowS, t]: two exactly RepeatsWindowS apart are in
	// different windows (B6 on #254).
	RepeatsN       int64 `json:"repeats_n"`
	RepeatsWindowS int64 `json:"repeats_window_s"`
	// Rate: buckets of RateBucketS from the Unix epoch, on received time.
	// For a polled SER source RateBucketS is at least the collection
	// interval (D4-4 item 2). A type's bound is the larger of RateMin and
	// MaxPerBucket × RateFactorPct / 100, rounded up; a bucket above it
	// alarms.
	RateBucketS   int64 `json:"rate_bucket_s"`
	RateFactorPct int64 `json:"rate_factor_pct"`
	RateMin       int64 `json:"rate_min"`
	// Absence: a type is periodic when it occurred at least
	// PeriodicMinOccurrences times with full use and every gap between
	// consecutive occurrences lies within PeriodicSpreadPct of the median
	// gap (|gap - median| × 100 ≤ median × PeriodicSpreadPct). The median
	// is the upper middle of the sorted gaps, gaps[len/2], and is the
	// type's IntervalS. With last its latest occurrence and deadline last +
	// IntervalS + Tolerance(IntervalS, AbsenceTolerancePct), an occurrence
	// in (last, deadline] is in time; if none comes, the absence alarm is
	// raised at deadline (B6 on #254). Learning
	// a period wants a tight spread; tolerating jitter wants a looser bound,
	// so the two are separate (B6's GT-INJ, #251).
	PeriodicMinOccurrences int64 `json:"periodic_min_occurrences"`
	PeriodicSpreadPct      int64 `json:"periodic_spread_pct"`
	AbsenceTolerancePct    int64 `json:"absence_tolerance_pct"`
	// TimeClock is the clock of Type.HoursUTC and of the time rule.
	TimeClock Clock `json:"time_clock"`
	// MaxTypes bounds Types. Types past it, or past what fits in MaxBytes,
	// are counted in Counts.TypesOverflow and are new types once the
	// baseline is active.
	MaxTypes int64 `json:"max_types"`
	// Alarm bounds, so a departure storm cannot fill the platform class.
	// An alarm for one (asset, rule, key) is raised at most once per
	// AlarmHoldS; later breaks of that pair within the hold raise nothing
	// new and are counted in the next alarm's EventsTotal. An asset raises
	// at most MaxAlarmsPerHold alarms per hold; past that the node raises
	// one HealthAlarmsHeld event per hold and no alarm until it ends.
	AlarmHoldS       int64 `json:"alarm_hold_s"`
	MaxAlarmsPerHold int64 `json:"max_alarms_per_hold"`
}

// Period is the observation period and its coverage.
type Period struct {
	// StartUTC is the received time of the first event stored for the asset
	// after the baseline was enabled; EndUTC is when both minima were met.
	StartUTC string `json:"start_utc"`
	EndUTC   string `json:"end_utc"`
	// CollectedS is the time in the period with successful collection: the
	// period less its gaps.
	CollectedS int64 `json:"collected_s"`
	// Gaps are the intervals in which the asset's collection failed (a
	// V-S12 failure), in order and not overlapping. Each extended the period
	// by its length.
	Gaps []Gap `json:"gaps,omitempty"`
}

// Gap is one interval of failed collection.
type Gap struct {
	FromUTC string `json:"from_utc"`
	ToUTC   string `json:"to_utc"`
	// Reason is the V-S12 failure, for example the C2 code
	// "failed.timeout" (an open token).
	Reason string `json:"reason"`
}

// Counts is the baseline's coverage of the asset's events in the period.
type Counts struct {
	// Events is every device event of the asset stored in the period:
	// Full + TypeOnly + NotCounted. Every stored SER and Syslog event has a
	// key (KeyOf), so none is left out.
	Events     int64 `json:"events"`
	Full       int64 `json:"full"`
	TypeOnly   int64 `json:"type_only"`
	NotCounted int64 `json:"not_counted"` // possible duplicates suppressed (PossibleDuplicates)
	// TypesOverflow is the number of types left out, past Params.MaxTypes
	// or past MaxBytes; their events are in Full and TypeOnly but in no Type.
	// A learner keeps the types with the highest Count, ties by key.
	TypesOverflow int64 `json:"types_overflow"`
}

// Type is one event type learnt.
type Type struct {
	Key Key `json:"key"`
	// Text is KeyOf's readable form for the first occurrence.
	Text string `json:"text"`
	// Count is every counted occurrence; Full is those with UseFull.
	Count int64 `json:"count"`
	Full  int64 `json:"full"`
	// HoursUTC counts the Full occurrences by UTC hour of TimeClock.
	HoursUTC [24]int64 `json:"hours_utc"`
	// MaxPerWindow is the most counted occurrences in any interval of
	// Params.RepeatsWindowS.
	MaxPerWindow int64 `json:"max_per_window"`
	// MaxPerBucket is the most Full occurrences in one rate bucket.
	MaxPerBucket int64 `json:"max_per_bucket"`
	// Periodic is set when the type was found periodic.
	Periodic *Periodic `json:"periodic,omitempty"`
	FirstUTC string    `json:"first_utc"`
	LastUTC  string    `json:"last_utc"`
}

// Periodic is a regular interval with its tolerance. The absence rule alarms
// when the type has not occurred within IntervalS + ToleranceS of its last
// occurrence.
type Periodic struct {
	IntervalS  int64 `json:"interval_s"`
	ToleranceS int64 `json:"tolerance_s"`
}

// Tolerance is a periodic type's tolerance: interval × pct / 100, rounded up.
func Tolerance(intervalS, pct int64) int64 { return ceilDiv(intervalS*pct, 100) }

// RateBound is a type's rate bound: the larger of p.RateMin and
// maxPerBucket × p.RateFactorPct / 100, rounded up. A bucket holding more
// Full occurrences than the bound breaks the rate rule.
func RateBound(maxPerBucket int64, p Params) int64 {
	return max(p.RateMin, ceilDiv(maxPerBucket*p.RateFactorPct, 100))
}

func ceilDiv(a, b int64) int64 { return (a + b - 1) / b }

// Hash is the baseline hash (D4-4 item 5): "sha256:" and the lowercase hex
// SHA-256 of b, the record's bytes exactly as stored. node.baseline_ack
// names it; nothing re-encodes the record to compute it.
func Hash(b []byte) string { return sha256Of(b) }

// Code is a validation failure. Closed list.
type Code string

const (
	CodeSchema   Code = "schema"   // identifier missing, malformed, or another contract or major
	CodeDecode   Code = "decode"   // not one JSON object, a duplicate key, or a key in the wrong case
	CodeMissing  Code = "missing"  // a required field is absent
	CodeForm     Code = "form"     // a field's value is not in its form
	CodeRange    Code = "range"    // a number outside its range
	CodeOrder    Code = "order"    // times or entries out of order, or repeated
	CodeConflict Code = "conflict" // fields that must agree do not
)

// Error is one validation failure.
type Error struct {
	Code   Code
	Field  string
	Detail string
}

func (e *Error) Error() string {
	return fmt.Sprintf("baseline: %s: %s: %s", e.Field, e.Code, e.Detail)
}

// Codes returns the codes of every *Error in err, which may be a join.
func Codes(err error) []Code {
	var out []Code
	if ve, ok := err.(*Error); ok {
		return append(out, ve.Code)
	}
	if j, ok := err.(interface{ Unwrap() []error }); ok {
		for _, x := range j.Unwrap() {
			out = append(out, Codes(x)...)
		}
	}
	return out
}

type checker struct{ errs []error }

func (c *checker) fail(code Code, field, format string, a ...any) {
	c.errs = append(c.errs, &Error{Code: code, Field: field, Detail: fmt.Sprintf(format, a...)})
}

var (
	sha256Ref = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	utcForm   = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$`)
	tokenForm = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,63}$`)
)

// utc parses an RFC 3339 UTC time with a Z suffix, or fails c.
func (c *checker) utc(field, s string) (time.Time, bool) {
	if s == "" {
		c.fail(CodeMissing, field, "required")
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if !utcForm.MatchString(s) || err != nil {
		c.fail(CodeForm, field, "%q is not RFC 3339 UTC with Z", s)
		return time.Time{}, false
	}
	return t, true
}

func (c *checker) schema(s string) {
	got, err := version.Parse(s)
	if err != nil || !self.Accepts(got) {
		c.fail(CodeSchema, "schema", "%q is not %s or another 0.x minor of it", s, Identifier)
	}
}

// Validate checks every rule of the contract that holds on one record.
func (b *Baseline) Validate() error {
	c := &checker{}
	c.schema(b.Schema)
	if !b.NodeID.Valid() {
		c.fail(CodeForm, "node_id", "%q is not a node ID", b.NodeID)
	}
	if !asset.ValidAssetID(b.AssetID) {
		c.fail(CodeForm, "asset_id", "%q is not a lowercase UUID", b.AssetID)
	}
	switch {
	case b.Version < 1:
		c.fail(CodeRange, "version", "%d is below 1", b.Version)
	case b.Version == 1 && b.Previous != "":
		c.fail(CodeConflict, "previous", "a first baseline replaces nothing")
	case b.Version > 1 && !sha256Ref.MatchString(b.Previous):
		c.fail(CodeForm, "previous", "a re-learnt baseline names the one it replaces as sha256:<hex>")
	}
	if b.Learner.Name == "" || b.Learner.Version == "" {
		c.fail(CodeMissing, "learner", "name and version are required")
	}
	b.Params.check(c)
	start, end := b.Period.check(c)
	b.checkCounts(c)
	b.checkTypes(c, start, end)
	if rec, ok := c.utc("recorded_utc", b.RecordedUTC); ok && !end.IsZero() && rec.Before(end) {
		c.fail(CodeOrder, "recorded_utc", "before the period's end")
	}
	return errors.Join(c.errs...)
}

func (p *Params) check(c *checker) {
	positive := []struct {
		name string
		v    int64
	}{
		{"min_duration_s", p.MinDurationS}, {"min_events", p.MinEvents},
		{"repeats_n", p.RepeatsN}, {"repeats_window_s", p.RepeatsWindowS},
		{"rate_bucket_s", p.RateBucketS}, {"rate_min", p.RateMin},
		{"max_types", p.MaxTypes}, {"alarm_hold_s", p.AlarmHoldS},
		{"max_alarms_per_hold", p.MaxAlarmsPerHold},
	}
	for _, f := range positive {
		if f.v < 1 {
			c.fail(CodeRange, "params."+f.name, "%d is below 1", f.v)
		}
	}
	if p.RateFactorPct < 100 {
		c.fail(CodeRange, "params.rate_factor_pct", "%d is below 100: the bound would be under the maximum seen", p.RateFactorPct)
	}
	if p.PeriodicMinOccurrences < 3 {
		c.fail(CodeRange, "params.periodic_min_occurrences", "%d is below 3: two occurrences give one gap and no median to test", p.PeriodicMinOccurrences)
	}
	if p.PeriodicSpreadPct < 0 || p.PeriodicSpreadPct > 100 {
		c.fail(CodeRange, "params.periodic_spread_pct", "%d is outside 0 to 100", p.PeriodicSpreadPct)
	}
	if p.AbsenceTolerancePct < 0 || p.AbsenceTolerancePct > 100 {
		c.fail(CodeRange, "params.absence_tolerance_pct", "%d is outside 0 to 100", p.AbsenceTolerancePct)
	}
	if p.AlarmHoldS != 0 && p.AlarmHoldS < MinAlarmHoldS {
		c.fail(CodeRange, "params.alarm_hold_s", "%d is below %d", p.AlarmHoldS, MinAlarmHoldS)
	}
	if p.MaxAlarmsPerHold > MaxAlarmsPerHoldCeiling {
		c.fail(CodeRange, "params.max_alarms_per_hold", "%d is above %d", p.MaxAlarmsPerHold, MaxAlarmsPerHoldCeiling)
	}
	if p.MaxTypes > MaxTypesCeiling {
		c.fail(CodeRange, "params.max_types", "%d is above %d", p.MaxTypes, MaxTypesCeiling)
	}
	if p.TimeClock != ClockReceived && p.TimeClock != ClockDevice {
		c.fail(CodeForm, "params.time_clock", "%q is not %s or %s", p.TimeClock, ClockReceived, ClockDevice)
	}
}

func (p *Period) check(c *checker) (start, end time.Time) {
	start, ok1 := c.utc("period.start_utc", p.StartUTC)
	end, ok2 := c.utc("period.end_utc", p.EndUTC)
	if !ok1 || !ok2 {
		return time.Time{}, time.Time{}
	}
	if end.Before(start) {
		c.fail(CodeOrder, "period.end_utc", "before start_utc")
		return start, end
	}
	var gaps time.Duration
	last := start
	for i, g := range p.Gaps {
		f := fmt.Sprintf("period.gaps[%d]", i)
		from, ok1 := c.utc(f+".from_utc", g.FromUTC)
		to, ok2 := c.utc(f+".to_utc", g.ToUTC)
		if !tokenForm.MatchString(g.Reason) {
			c.fail(CodeForm, f+".reason", "%q is not a token", g.Reason)
		}
		if !ok1 || !ok2 {
			continue
		}
		if from.Before(last) || to.Before(from) || to.After(end) {
			c.fail(CodeOrder, f, "gaps lie inside the period, in order, without overlap")
			continue
		}
		gaps += to.Sub(from)
		last = to
	}
	if want := int64((end.Sub(start) - gaps) / time.Second); p.CollectedS != want {
		c.fail(CodeConflict, "period.collected_s", "%d, but the period less its gaps is %d s", p.CollectedS, want)
	}
	return start, end
}

func (b *Baseline) checkCounts(c *checker) {
	n := b.Counts
	for _, f := range []struct {
		name string
		v    int64
	}{{"events", n.Events}, {"full", n.Full}, {"type_only", n.TypeOnly}, {"not_counted", n.NotCounted}, {"types_overflow", n.TypesOverflow}} {
		if f.v < 0 {
			c.fail(CodeRange, "counts."+f.name, "negative")
		}
	}
	if n.Events != n.Full+n.TypeOnly+n.NotCounted {
		c.fail(CodeConflict, "counts.events", "%d is not full + type_only + not_counted", n.Events)
	}
	if n.Events < b.Params.MinEvents {
		c.fail(CodeConflict, "counts.events", "%d is below params.min_events %d: the period had not ended", n.Events, b.Params.MinEvents)
	}
	if b.Period.CollectedS < b.Params.MinDurationS {
		c.fail(CodeConflict, "period.collected_s", "%d is below params.min_duration_s %d: the period had not ended", b.Period.CollectedS, b.Params.MinDurationS)
	}
}

func (b *Baseline) checkTypes(c *checker, start, end time.Time) {
	if b.Types == nil {
		c.fail(CodeMissing, "types", "required, and empty when no type was learnt")
	}
	if int64(len(b.Types)) > b.Params.MaxTypes && b.Params.MaxTypes > 0 {
		c.fail(CodeRange, "types", "%d types, above params.max_types %d", len(b.Types), b.Params.MaxTypes)
	}
	// With TypesOverflow set, Types holds max_types or fewer: a learner
	// stops at max_types or at MaxBytes, whichever comes first.
	if b.Counts.TypesOverflow > 0 && len(b.Types) == 0 {
		c.fail(CodeConflict, "counts.types_overflow", "types overflowed, so at least one type was kept")
	}
	var count, full int64
	prev := ""
	for i, t := range b.Types {
		f := fmt.Sprintf("types[%d]", i)
		if err := t.Key.Validate(); err != nil {
			c.fail(CodeForm, f+".key", "%v", err)
			continue
		}
		ks := t.Key.String()
		if i > 0 && ks <= prev {
			c.fail(CodeOrder, f+".key", "types are ordered by key and each appears once (%q after %q)", ks, prev)
		}
		prev = ks
		t.check(c, f, &b.Params, start, end)
		count += t.Count
		full += t.Full
	}
	if b.Counts.TypesOverflow == 0 && (count != b.Counts.Full+b.Counts.TypeOnly || full != b.Counts.Full) {
		c.fail(CodeConflict, "types", "type counts sum to %d (full %d), not counts.full + counts.type_only %d (full %d)",
			count, full, b.Counts.Full+b.Counts.TypeOnly, b.Counts.Full)
	}
}

func (t *Type) check(c *checker, f string, p *Params, start, end time.Time) {
	if t.Text == "" || len(t.Text) > TextMax {
		c.fail(CodeForm, f+".text", "required, at most %d bytes", TextMax)
	}
	if t.Count < 1 || t.Full < 0 || t.Full > t.Count {
		c.fail(CodeRange, f+".count", "count %d and full %d: 0 <= full <= count, count >= 1", t.Count, t.Full)
	}
	var hours int64
	for _, h := range t.HoursUTC {
		if h < 0 {
			c.fail(CodeRange, f+".hours_utc", "negative")
		}
		hours += h
	}
	if hours != t.Full {
		c.fail(CodeConflict, f+".hours_utc", "sum %d, not full %d", hours, t.Full)
	}
	if t.MaxPerWindow < 1 || t.MaxPerWindow > t.Count {
		c.fail(CodeRange, f+".max_per_window", "%d is outside 1 to count %d", t.MaxPerWindow, t.Count)
	}
	if t.MaxPerBucket < 0 || t.MaxPerBucket > t.Full || (t.Full > 0) != (t.MaxPerBucket > 0) {
		c.fail(CodeRange, f+".max_per_bucket", "%d is outside 1 to full %d (0 only when full is 0)", t.MaxPerBucket, t.Full)
	}
	if pd := t.Periodic; pd != nil {
		if pd.IntervalS < 1 || pd.ToleranceS != Tolerance(pd.IntervalS, p.AbsenceTolerancePct) {
			c.fail(CodeRange, f+".periodic", "interval %d s and tolerance %d s: interval >= 1, and tolerance is Tolerance(interval, absence_tolerance_pct) = %d", pd.IntervalS, pd.ToleranceS, Tolerance(pd.IntervalS, p.AbsenceTolerancePct))
		}
		if t.Full < p.PeriodicMinOccurrences {
			c.fail(CodeConflict, f+".periodic", "found periodic on %d full occurrences, below params.periodic_min_occurrences %d", t.Full, p.PeriodicMinOccurrences)
		}
	}
	first, ok1 := c.utc(f+".first_utc", t.FirstUTC)
	last, ok2 := c.utc(f+".last_utc", t.LastUTC)
	if ok1 && ok2 && (last.Before(first) || (!start.IsZero() && (first.Before(start) || last.After(end)))) {
		c.fail(CodeOrder, f, "first_utc <= last_utc, both inside the period")
	}
}

// Encode validates b and encodes it compact, as it is stored: the bytes
// Hash is taken over. It refuses an encoding above limit (MaxBytes when
// limit is 0 or above it) with CodeRange, so the learner must leave out
// more types.
func Encode(b *Baseline, limit int) ([]byte, error) {
	if err := b.Validate(); err != nil {
		return nil, err
	}
	out, err := json.Marshal(b)
	if err != nil {
		return nil, &Error{Code: CodeForm, Field: "baseline", Detail: err.Error()}
	}
	if limit <= 0 || limit > MaxBytes {
		limit = MaxBytes
	}
	if len(out) > limit {
		return nil, &Error{Code: CodeRange, Field: "baseline", Detail: fmt.Sprintf("%d bytes encoded, above %d", len(out), limit)}
	}
	return out, nil
}

// Decode reads one stored baseline record so every reader reads it the same
// way, then validates it. A record stamped with this minor or an earlier one
// is read strictly (exact field names, no duplicates, nothing after the
// object); a later 0.x minor's added fields are ignored, as
// contracts/README.md requires of every reader.
func Decode(b []byte) (*Baseline, error) {
	if len(b) > MaxBytes {
		return nil, &Error{Code: CodeRange, Field: "baseline", Detail: fmt.Sprintf("%d bytes, above %d", len(b), MaxBytes)}
	}
	var r Baseline
	if err := strictjson.Forward(b, &r); err != nil {
		return nil, &Error{Code: CodeDecode, Field: "baseline", Detail: err.Error()}
	}
	if got, err := version.Parse(r.Schema); err == nil && got.Name == self.Name && got.Minor <= self.Minor {
		r = Baseline{}
		if err := strictjson.Decode(b, &r); err != nil {
			return nil, &Error{Code: CodeDecode, Field: "baseline", Detail: err.Error()}
		}
	}
	return &r, r.Validate()
}

// Lookup returns the learnt type with key k, if any. Types is ordered, so
// this is a binary search.
func (b *Baseline) Lookup(k Key) (*Type, bool) {
	s := k.String()
	i, ok := slices.BinarySearchFunc(b.Types, s, func(t Type, s string) int {
		ts := t.Key.String()
		switch {
		case ts < s:
			return -1
		case ts > s:
			return 1
		}
		return 0
	})
	if !ok {
		return nil, false
	}
	return &b.Types[i], true
}
