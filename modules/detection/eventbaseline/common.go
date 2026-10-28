package eventbaseline

import (
	"crypto/sha256"
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

// Limits of the state either half holds, so that a flood cannot grow memory
// or a snapshot without bound. With them, a snapshot of either half at every
// configured ceiling fits MaxSnapshotBytes (D4-30; TestSnapshotMaximalCase).
// They are stated here and in the package documentation, because each is a
// place the stored numbers stop being exact or a type stops being covered.
const (
	// MaxTypes is the most types the learner holds and the most a baseline
	// the detector watches may have: C10 0.2's baseline.MaxTypesCeiling
	// (D4-30). params.max_types above it is refused, and a type first met
	// while MaxTypes are held is counted in types_overflow, never learnt. A
	// 0.1 record of more types is valid C10, but this detector refuses it,
	// and the asset re-learns.
	MaxTypes = baseline.MaxTypesCeiling
	// windowCap bounds the occurrences either half holds to find a type's
	// most in one repeats window: MaxPerWindow saturates at windowCap.
	// MaxRepeatsN is the largest repeats_n, so the saturated value is
	// always at least repeats_n and the repeats rule is exact; it is
	// baseline.MaxEventIDs - 1, so a repeats alarm lists its whole window.
	windowCap   = baseline.MaxEventIDs
	MaxRepeatsN = windowCap - 1
	// gapCap bounds the distinct gap lengths, in seconds, that the learner
	// holds for one type, and gapBudget (below) those it holds for all types
	// together. A type that would pass either is not found periodic.
	gapCap = 4096
	// MaxGaps bounds the collection gaps the learner holds. A gap past it is
	// merged into the last one, which counts the time between them as not
	// collected: the period gets longer, never shorter.
	MaxGaps = 256
	// MaxStreams bounds the (node, stream) pairs the event IDs a detector
	// holds may name. An asset's events come from the streams the node
	// configures (its SER stream and the listeners it sends to), so a
	// detector past it is refused a snapshot (ErrSnapshotTooLarge).
	MaxStreams = 16
)

// gapBudget bounds the distinct gap lengths the learner holds over all
// types. heldIDBudget bounds the event IDs the detector's pending records
// list over all pairs together; a break held past it is counted in the next
// alarm's note, as one past MaxNewTypePairs is, not listed. Variables so a
// test can lower them.
var (
	gapBudget    = 16384
	heldIDBudget = 2048
)

// MaxNewTypePairs bounds the new-type rule's pending records (D4-26, F1): the
// (rule, type) pairs that hold a repeated alarm of one type and list the
// breaks held since the last. The other rules' pairs are bounded by the
// baseline's types. With this and the new-type memory (4*MaxTypes), a flood
// of distinct new types leaves the detector's state, and its snapshot, under
// a bound that does not grow with the flood.
const MaxNewTypePairs = MaxTypes

// pairCap and pairPrune are MaxNewTypePairs and whether expired pairs are
// swept; the tests change them to reach the cap and to show that sweeping
// changes no output.
var (
	pairCap    = MaxNewTypePairs
	pairPrune  = true
	newSeenMax = MaxTypes * 4
)

// digest is what the learner's left-out set, the detector's new-type memory
// and the detector's pending records keep of a key: the first 16 bytes of
// the SHA-256 of Key.String. Only whether a key is there is asked of them;
// an alarm takes its key and text from the event that raises it (D4-30).
type digest [16]byte

func digestOf(k baseline.Key) (d digest) {
	sum := sha256.Sum256([]byte(k.String()))
	copy(d[:], sum[:])
	return d
}

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
	case p.MaxTypes > MaxTypes:
		return fmt.Errorf("%w: max_types %d is above %d, the most this learner holds (D4-30)", ErrConfig, p.MaxTypes, MaxTypes)
	case p.TimeClock != baseline.ClockReceived:
		return fmt.Errorf("%w: learner 0.1 runs on the received clock only (D4-4 item 1)", ErrConfig)
	}
	return nil
}

// nsOf converts whole seconds to nanoseconds.
func nsOf(s int64) int64 { return s * int64(time.Second) }
