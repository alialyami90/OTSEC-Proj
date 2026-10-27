package baseline

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/event"
	"otsec.local/otsec/contracts/version"
)

// HealthDeparture is the C4 health type of a departure alarm.
const HealthDeparture = "baseline.departure"

// HealthAlarmsHeld is the C4 health type the node raises, once per hold,
// when an asset reaches Params.MaxAlarmsPerHold: details asset_id, held
// (the alarms not raised) and hold_s. It is not an Alarm.
const HealthAlarmsHeld = "baseline.alarms-held"

// MaxEventIDs is the most event IDs an alarm lists in Events, and in
// NotCounted; EventsTotal and NotCountedTotal give the full counts.
const MaxEventIDs = 32

// Rule is a departure rule from "R4.8 observation period and measures".
// Closed.
type Rule string

const (
	RuleNewType Rule = "new-type" // a type not in the baseline, on its first occurrence
	RuleRepeats Rule = "repeats"  // more than repeats_n in repeats_window_s, where the baseline's maximum was below repeats_n
	RuleRate    Rule = "rate"     // a bucket above the type's RateBound
	RuleTime    Rule = "time"     // an hour in which the baseline never saw the type
	RuleAbsence Rule = "absence"  // a periodic type missing past interval + tolerance
)

// ruleParams are the parameters each rule's alarm shows, in order.
var ruleParams = map[Rule][]string{
	RuleNewType: nil,
	RuleRepeats: {"repeats_n", "repeats_window_s"},
	RuleRate:    {"rate_bucket_s", "rate_factor_pct", "rate_min"},
	RuleTime:    nil,
	RuleAbsence: {"interval_s", "tolerance_s"},
}

// Param is one parameter as the alarm shows it: a decimal value.
type Param struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Alarm is a departure alarm: everything an operator needs to see why it
// was raised, without reading the learner (V-M4: the rule, the baseline
// value, the parameters, the observation and the IDs of the events that
// broke it).
type Alarm struct {
	Schema  string `json:"schema"`
	AssetID string `json:"asset_id"`
	// Baseline is Hash of the active baseline; BaselineVersion its Version.
	Baseline        string `json:"baseline"`
	BaselineVersion int    `json:"baseline_version"`
	Rule            Rule   `json:"rule"`
	Key             Key    `json:"key"`
	KeyText         string `json:"key_text"`
	// Params are exactly the rule's parameters, in the rule's order.
	Params []Param `json:"params"`
	// BaselineValue is what the baseline holds for the rule, for example
	// "max_per_bucket 3, bound 6"; Observation is what broke it, for
	// example "9 in the bucket from 2026-11-03T14:00:00Z".
	BaselineValue string `json:"baseline_value"`
	Observation   string `json:"observation"`
	// Clock is the clock the rule ran on: received, except that the time
	// rule may use device when the offset is known.
	Clock Clock `json:"clock"`
	// AtUTC is the received time of the last event that broke the baseline,
	// or for absence the time the interval ran out.
	AtUTC string `json:"at_utc"`
	// Events are the IDs of the first MaxEventIDs events that broke the
	// baseline, in order, including breaks held since the last alarm for
	// the same rule and key; EventsTotal counts them all. An alarm lists only
	// events received up to its raise: for repeats, the RepeatsN + 1 in the
	// window the breaking event closed; for rate, the bucket's events up to
	// and including the one that passed the bound. Absence alone may have
	// none.
	Events      []event.EventID `json:"events,omitempty"`
	EventsTotal int64           `json:"events_total"`
	// NotCounted are the first MaxEventIDs possible duplicates of the type
	// that were not counted (PossibleDuplicates), so an operator can see
	// what was left out; NotCountedTotal counts them all.
	NotCounted      []event.EventID `json:"not_counted,omitempty"`
	NotCountedTotal int64           `json:"not_counted_total"`
}

// Validate checks every rule of the contract that holds on one alarm.
func (a *Alarm) Validate() error {
	c := &checker{}
	c.schema(a.Schema)
	if !asset.ValidAssetID(a.AssetID) {
		c.fail(CodeForm, "asset_id", "%q is not a lowercase UUID", a.AssetID)
	}
	if !sha256Ref.MatchString(a.Baseline) {
		c.fail(CodeForm, "baseline", "%q is not sha256:<hex>", a.Baseline)
	}
	if a.BaselineVersion < 1 {
		c.fail(CodeRange, "baseline_version", "%d is below 1", a.BaselineVersion)
	}
	want, ok := ruleParams[a.Rule]
	if !ok {
		c.fail(CodeForm, "rule", "%q is not a departure rule", a.Rule)
	}
	if err := a.Key.Validate(); err != nil {
		c.fail(CodeForm, "key", "%v", err)
	}
	if a.KeyText == "" || len(a.KeyText) > TextMax {
		c.fail(CodeForm, "key_text", "required, at most %d bytes", TextMax)
	}
	if ok {
		var got []string
		for _, p := range a.Params {
			got = append(got, p.Name)
			if !decimalIn(p.Value, int(^uint(0)>>1)) {
				c.fail(CodeForm, "params", "%s = %q is not a decimal", p.Name, p.Value)
			}
		}
		if !slices.Equal(got, want) {
			c.fail(CodeConflict, "params", "rule %s shows %v, not %v", a.Rule, want, got)
		}
	}
	if a.BaselineValue == "" || a.Observation == "" {
		c.fail(CodeMissing, "baseline_value/observation", "an alarm explains itself")
	}
	switch {
	case a.Clock == ClockDevice && a.Rule != RuleTime:
		c.fail(CodeConflict, "clock", "only the time rule may use device time")
	case a.Clock != ClockReceived && a.Clock != ClockDevice:
		c.fail(CodeForm, "clock", "%q is not %s or %s", a.Clock, ClockReceived, ClockDevice)
	}
	c.utc("at_utc", a.AtUTC)
	if len(a.Events) == 0 && a.Rule != RuleAbsence {
		c.fail(CodeMissing, "events", "every rule but absence names the events that broke the baseline")
	}
	for _, l := range []struct {
		field string
		n     int
		total int64
	}{{"events", len(a.Events), a.EventsTotal}, {"not_counted", len(a.NotCounted), a.NotCountedTotal}} {
		if l.n > MaxEventIDs {
			c.fail(CodeRange, l.field, "%d IDs, above %d", l.n, MaxEventIDs)
		}
		// The list holds the first min(total, MaxEventIDs) IDs.
		if l.total < int64(l.n) || (l.n < MaxEventIDs && l.total != int64(l.n)) {
			c.fail(CodeConflict, l.field+"_total", "%d, but %d IDs are listed: the list holds the first min(total, %d)", l.total, l.n, MaxEventIDs)
		}
	}
	checkIDs(c, "events", a.Events)
	checkIDs(c, "not_counted", a.NotCounted)
	return errors.Join(c.errs...)
}

func checkIDs(c *checker, field string, ids []event.EventID) {
	for i, id := range ids {
		if !id.NodeID.Valid() || !id.Stream.Valid() || id.Seq == 0 {
			c.fail(CodeForm, fmt.Sprintf("%s[%d]", field, i), "%v is not a valid event ID", id)
		}
	}
}

// Health is the alarm as a C4 health event body: type HealthDeparture,
// Related the breaking events, and every other field as a detail. The
// detail keys are: schema, asset_id, baseline, baseline_version, rule, key
// (Key.String), key_text, baseline_value, observation, clock, at_utc,
// events_total, not_counted_total, param.<name> for each parameter, and
// not_counted (the EventID.String forms, space-separated) when there are
// any. AlarmFromHealth reverses it.
func (a *Alarm) Health() (event.Health, error) {
	if err := a.Validate(); err != nil {
		return event.Health{}, err
	}
	d := map[string]string{
		"schema": a.Schema, "asset_id": a.AssetID,
		"baseline": a.Baseline, "baseline_version": strconv.Itoa(a.BaselineVersion),
		"rule": string(a.Rule), "key": a.Key.String(), "key_text": a.KeyText,
		"baseline_value": a.BaselineValue, "observation": a.Observation,
		"clock": string(a.Clock), "at_utc": a.AtUTC,
		"events_total": strconv.FormatInt(a.EventsTotal, 10), "not_counted_total": strconv.FormatInt(a.NotCountedTotal, 10),
	}
	for _, p := range a.Params {
		d["param."+p.Name] = p.Value
	}
	if len(a.NotCounted) > 0 {
		var s []string
		for _, id := range a.NotCounted {
			s = append(s, id.String())
		}
		d["not_counted"] = strings.Join(s, " ")
	}
	return event.Health{Type: HealthDeparture, Related: slices.Clone(a.Events), Details: d}, nil
}

// AlarmFromHealth reads an alarm back from a C4 health event body and
// validates it. A detail it does not know is an error unless the alarm's
// schema is a later 0.x minor, which may add details.
func AlarmFromHealth(h event.Health) (*Alarm, error) {
	if h.Type != HealthDeparture {
		return nil, &Error{Code: CodeSchema, Field: "health.type", Detail: fmt.Sprintf("%q is not %s", h.Type, HealthDeparture)}
	}
	d := h.Details
	a := &Alarm{
		Schema: d["schema"], AssetID: d["asset_id"], Baseline: d["baseline"],
		Rule: Rule(d["rule"]), KeyText: d["key_text"],
		BaselineValue: d["baseline_value"], Observation: d["observation"],
		Clock: Clock(d["clock"]), AtUTC: d["at_utc"], Events: slices.Clone(h.Related),
	}
	var errs []error
	for _, n := range []struct {
		name string
		to   *int64
	}{{"events_total", &a.EventsTotal}, {"not_counted_total", &a.NotCountedTotal}} {
		v, err := strconv.ParseInt(d[n.name], 10, 64)
		if err != nil || strconv.FormatInt(v, 10) != d[n.name] {
			errs = append(errs, &Error{Code: CodeForm, Field: n.name, Detail: fmt.Sprintf("%q is not a decimal", d[n.name])})
		}
		*n.to = v
	}
	if v, err := strconv.Atoi(d["baseline_version"]); err == nil && strconv.Itoa(v) == d["baseline_version"] {
		a.BaselineVersion = v
	} else {
		errs = append(errs, &Error{Code: CodeForm, Field: "baseline_version", Detail: fmt.Sprintf("%q is not a decimal", d["baseline_version"])})
	}
	k, err := ParseKey(d["key"])
	if err != nil {
		errs = append(errs, &Error{Code: CodeForm, Field: "key", Detail: err.Error()})
	}
	a.Key = k
	for _, name := range ruleParams[a.Rule] {
		if v, ok := d["param."+name]; ok {
			a.Params = append(a.Params, Param{Name: name, Value: v})
		}
	}
	if s := d["not_counted"]; s != "" {
		for _, f := range strings.Split(s, " ") {
			id, err := event.ParseEventID(f)
			if err != nil {
				errs = append(errs, &Error{Code: CodeForm, Field: "not_counted", Detail: err.Error()})
				continue
			}
			a.NotCounted = append(a.NotCounted, id)
		}
	}
	known := map[string]bool{"schema": true, "asset_id": true, "baseline": true, "baseline_version": true,
		"rule": true, "key": true, "key_text": true, "baseline_value": true, "observation": true,
		"clock": true, "at_utc": true, "not_counted": true, "events_total": true, "not_counted_total": true}
	for _, name := range ruleParams[a.Rule] {
		known["param."+name] = true
	}
	got, perr := version.Parse(a.Schema)
	later := perr == nil && self.Accepts(got) && got.Minor > self.Minor
	for name := range d {
		if !known[name] && !later {
			errs = append(errs, &Error{Code: CodeConflict, Field: "health.details", Detail: fmt.Sprintf("%q is not a detail of rule %s", name, a.Rule)})
		}
	}
	if err := a.Validate(); err != nil {
		errs = append(errs, err)
	}
	return a, errors.Join(errs...)
}
