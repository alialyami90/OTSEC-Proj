package eventbaseline

import (
	"errors"
	"fmt"
	"time"

	"otsec.local/otsec/contracts/baseline"
	"otsec.local/otsec/contracts/event"
)

// Errors a caller can act on. The learner and the detector never drop an
// event silently: an event they cannot take is returned to the caller.
var (
	// ErrOrder: the event was received before one already taken. Both
	// halves read an asset's events in non-decreasing received order (ties
	// in any fixed order); the feeder sorts, because the node reads several
	// streams.
	ErrOrder = errors.New("eventbaseline: event received before one already taken")
	// ErrAsset: the event belongs to another asset.
	ErrAsset = errors.New("eventbaseline: event of another asset")
	// ErrConfig: a parameter the learner or detector cannot work with.
	ErrConfig = errors.New("eventbaseline: unusable configuration")
)

// Obs is one stored event, with what only the caller knows.
type Obs struct {
	Event *event.Event
	// AfterFailure is true for every row of the first successful read after
	// a recorded V-S12 collection failure of the asset (baseline.Classify).
	AfterFailure bool
	// NotCounted is true for a possible-duplicate SER row that
	// baseline.PossibleDuplicates did not count. It is kept out of every
	// rule and listed on the alarms of its type (D4-4 item 3).
	NotCounted bool
}

// Limits of the state either half holds per type, so that a flood cannot
// grow memory without bound. They are stated here and in the package
// documentation, because each is a place the stored numbers stop being exact.
const (
	// windowCap bounds the occurrences the learner holds to find a type's
	// most in one repeats window: MaxPerWindow saturates at windowCap.
	// MaxRepeatsN is the largest repeats_n, so the saturated value is
	// always at least repeats_n and the repeats rule is exact.
	windowCap   = 4096
	MaxRepeatsN = windowCap - 1
	// gapCap bounds the distinct gap lengths, in seconds, that the learner
	// holds for one type. A type with more is not found periodic.
	gapCap = 4096
)

// MaxNewTypePairs bounds the new-type rule's pending records (D4-26, F1): the
// (rule, type) pairs that hold a repeated alarm of one type and list the
// breaks held since the last. The other rules' pairs are bounded by the
// baseline's types. With this and the new-type memory (4*MaxTypesCeiling), a
// flood of distinct new types leaves the detector's state, and its snapshot,
// under a bound that does not grow with the flood.
const MaxNewTypePairs = 4096

// pairCap and pairPrune are MaxNewTypePairs and whether expired pairs are
// swept; the tests change them to reach the cap and to show that sweeping
// changes no output.
var (
	pairCap    = MaxNewTypePairs
	pairPrune  = true
	newSeenMax = baseline.MaxTypesCeiling * 4
)

// received parses e's received.utc to nanoseconds since the epoch.
func received(e *event.Event) (int64, error) {
	t, err := time.Parse(time.RFC3339Nano, e.Received.UTC)
	if err != nil {
		return 0, fmt.Errorf("eventbaseline: event %v: received.utc %q: %w", e.ID, e.Received.UTC, err)
	}
	return t.UnixNano(), nil
}

func fmtNS(ns int64) string { return time.Unix(0, ns).UTC().Format(time.RFC3339Nano) }

func hourOf(ns int64) int { return time.Unix(0, ns).UTC().Hour() }

func checkParams(p baseline.Params) error {
	switch {
	case p.RepeatsN < 1 || p.RepeatsN > MaxRepeatsN:
		return fmt.Errorf("%w: repeats_n %d is outside 1 to %d", ErrConfig, p.RepeatsN, MaxRepeatsN)
	case p.RepeatsWindowS < 1, p.RateBucketS < 1, p.MaxTypes < 1:
		return fmt.Errorf("%w: repeats_window_s, rate_bucket_s and max_types are at least 1", ErrConfig)
	case p.RateFactorPct < 100:
		return fmt.Errorf("%w: rate_factor_pct %d is below 100", ErrConfig, p.RateFactorPct)
	case p.PeriodicMinOccurrences < 3:
		return fmt.Errorf("%w: periodic_min_occurrences %d is below 3", ErrConfig, p.PeriodicMinOccurrences)
	case p.TimeClock != baseline.ClockReceived:
		return fmt.Errorf("%w: learner 0.1 runs on the received clock only (D4-4 item 1)", ErrConfig)
	}
	return nil
}

// nsOf converts whole seconds to nanoseconds.
func nsOf(s int64) int64 { return s * int64(time.Second) }
