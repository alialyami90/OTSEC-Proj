package node

import (
	"fmt"
	"strings"

	"otsec.local/otsec/contracts/baseline"
	"otsec.local/otsec/modules/detection/eventbaseline"
)

// EventBaseline is one asset's event-behaviour baseline setting (R4.8,
// docs/phase4/B5-event-baseline-feeder.md): the asset's SER rows and Syslog
// messages are observed for the period Params names, a baseline is recorded
// in the asset's configuration stream, and once an administrator
// acknowledges it, departures from it are alarmed.
//
// Params is a whole baseline.Params. C10 fixes the two minima's proposed
// values (baseline.DefaultMinDuration, baseline.DefaultMinEvents) and says
// every parameter is recorded in the baseline and never a constant a learner
// may assume, so the node supplies no defaults: the administrator states
// them, and the example in the README is a starting point.
type EventBaseline struct {
	AssetID string          `json:"asset_id"`
	Params  baseline.Params `json:"params"`
}

// EventBaselineQuotaRecords is how many baselines the configuration quota
// must hold for each asset that has an event baseline and no configuration
// read: the active baseline, one recorded and awaiting acknowledgement, the
// superseded one that stays held (D4-20 rule 2), and room for the next, each
// at most baseline.MaxBytes.
const EventBaselineQuotaRecords = 4

// EventCheckpointRecords is how many checkpoints the quota must hold for each
// event-baseline asset: the learner and detector snapshot the node commits
// with its position (feeder slice 1c), and room for the next while the last
// is still held. A checkpoint is a record of the asset's configuration
// stream, so it is bounded by the class's record cap, ConfigRecordBytes: the
// node refuses a snapshot above it and keeps the last checkpoint (the object
// goes on, and the refusal is a health event; B4 on #343).
const EventCheckpointRecords = 2

// EventBaselineQuotaFloor is the bytes a node's configuration quota must
// hold for its event baselines: EventBaselineQuotaRecords x baseline.MaxBytes
// and EventCheckpointRecords x ConfigRecordBytes for each event-baseline
// asset whose configuration the schedule does not read. An asset whose
// configuration is read is covered by its D4-20 floor, which is far larger
// (ConfigQuotaFloorRecords x ConfigRecordBytes holds both).
func (c *Config) EventBaselineQuotaFloor() int64 {
	reads := map[string]bool{}
	for _, s := range c.Schedule {
		if s.ReadsConfiguration() {
			reads[s.AssetID] = true
		}
	}
	var n int64
	for _, e := range c.EventBaselines {
		if !reads[e.AssetID] {
			n++
		}
	}
	return n * (EventBaselineQuotaRecords*int64(baseline.MaxBytes) + EventCheckpointRecords*ConfigRecordBytes)
}

// EventBaselineFor is the event-baseline setting of an asset.
func (c *Config) EventBaselineFor(assetID string) (EventBaseline, bool) {
	for _, e := range c.EventBaselines {
		if e.AssetID == assetID {
			return e, true
		}
	}
	return EventBaseline{}, false
}

// checkEventBaselines checks event_baselines against the assets and the
// schedule. fail records one problem.
func (c *Config) checkEventBaselines(fail func(format string, args ...any)) {
	seen := map[string]bool{}
	for i, e := range c.EventBaselines {
		p := fmt.Sprintf("event_baselines[%d]", i)
		a, ok := c.Asset(e.AssetID)
		switch {
		case seen[e.AssetID]:
			fail("%s: asset %s listed twice", p, e.AssetID)
			continue
		case !ok:
			fail("%s.asset_id %q is not in assets", p, e.AssetID)
			continue
		}
		seen[e.AssetID] = true
		if !c.producesEvents(a.AssetID) {
			fail("%s: asset %s has no scheduled SER collection and no inbound Syslog endpoint, so it has no events to observe", p, e.AssetID)
		}
		if err := checkEventBaselineParams(e.Params); err != nil {
			fail("%s.params: %v", p, err)
		}
	}
	if len(c.EventBaselines) > 0 {
		if _, ok := c.Store.Quotas["configuration"]; !ok {
			fail("event_baselines needs store.quotas.configuration: the baseline record is stored in the asset's configuration stream")
		}
	}
}

// producesEvents reports whether the node stores events of the asset: a
// scheduled SER read (second segment "ser", last starting with "read", as
// ConfigReadOperation does for configuration, so a state-changing operation
// never counts), or an inbound Syslog endpoint.
func (c *Config) producesEvents(assetID string) bool {
	for _, s := range c.Schedule {
		if s.AssetID == assetID && serReadOperation(s.Operation) {
			return true
		}
	}
	if a, ok := c.Asset(assetID); ok {
		for _, ep := range a.Endpoints {
			if ep.Transport.Inbound() {
				return true
			}
		}
	}
	return false
}

// serReadOperation reports whether a register operation ID reads an asset's
// SER, as in sel.ser.read_all.
func serReadOperation(op string) bool {
	parts := strings.Split(op, ".")
	return len(parts) >= 3 && parts[1] == "ser" && strings.HasPrefix(parts[len(parts)-1], "read")
}

// checkEventBaselineParams is C10's range check on the parameters
// (baseline.Params), then the learner's own: the learner 0.1 runs on the
// received clock only. C10 states its check on a whole baseline, so the
// ranges are repeated here and pinned by TestEventBaselineParamsMatchC10.
func checkEventBaselineParams(p baseline.Params) error {
	for _, f := range []struct {
		name string
		v    int64
	}{
		{"min_duration_s", p.MinDurationS}, {"min_events", p.MinEvents},
		{"repeats_n", p.RepeatsN}, {"repeats_window_s", p.RepeatsWindowS},
		{"rate_bucket_s", p.RateBucketS}, {"rate_min", p.RateMin},
		{"max_types", p.MaxTypes}, {"alarm_hold_s", p.AlarmHoldS},
		{"max_alarms_per_hold", p.MaxAlarmsPerHold},
	} {
		if f.v < 1 {
			return fmt.Errorf("%s %d is below 1", f.name, f.v)
		}
	}
	switch {
	case p.RateFactorPct < 100:
		return fmt.Errorf("rate_factor_pct %d is below 100", p.RateFactorPct)
	case p.PeriodicMinOccurrences < 3:
		return fmt.Errorf("periodic_min_occurrences %d is below 3", p.PeriodicMinOccurrences)
	case p.PeriodicSpreadPct < 0 || p.PeriodicSpreadPct > 100:
		return fmt.Errorf("periodic_spread_pct %d is outside 0 to 100", p.PeriodicSpreadPct)
	case p.AbsenceTolerancePct < 0 || p.AbsenceTolerancePct > 100:
		return fmt.Errorf("absence_tolerance_pct %d is outside 0 to 100", p.AbsenceTolerancePct)
	case p.AlarmHoldS < baseline.MinAlarmHoldS:
		return fmt.Errorf("alarm_hold_s %d is below %d", p.AlarmHoldS, baseline.MinAlarmHoldS)
	case p.MaxAlarmsPerHold > baseline.MaxAlarmsPerHoldCeiling:
		return fmt.Errorf("max_alarms_per_hold %d is above %d", p.MaxAlarmsPerHold, baseline.MaxAlarmsPerHoldCeiling)
	case p.MaxTypes > baseline.MaxTypesCeiling:
		return fmt.Errorf("max_types %d is above %d", p.MaxTypes, baseline.MaxTypesCeiling)
	}
	// The learner has the last word: it refuses a clock it does not run on
	// and a repeats_n past its window cap.
	_, err := eventbaseline.NewLearner(eventbaseline.LearnerConfig{Node: "check", AssetID: "check", Params: p, Version: 1})
	return err
}
