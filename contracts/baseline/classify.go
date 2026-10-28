package baseline

import (
	"slices"

	"otsec.local/otsec/contracts/event"
)

// Use is what an event counts toward. Closed.
type Use string

const (
	// UseNone: the event belongs to no asset's baseline.
	UseNone Use = "none"
	// UseTypeOnly: the type set and the new-type rule only. It is not in
	// rate, hour or window learning, and the repeats, rate and time rules
	// skip it (catch-up, D4-4 item 2 as D4-9 amends it).
	UseTypeOnly Use = "type-only"
	// UseFull: every rule.
	UseFull Use = "full"
)

// Applies says whether an event of this use counts toward rule r, both in
// learning and once the baseline is active: a full event toward every rule,
// a type-only one toward new-type only (D4-9), a none one toward none. Its
// window, bucket, hour and period learning follow the same split: only
// full events feed them.
func (u Use) Applies(r Rule) bool {
	switch u {
	case UseFull:
		_, ok := ruleParams[r]
		return ok
	case UseTypeOnly:
		return r == RuleNewType
	}
	return false
}

// Exclusion says why an event has UseNone. Closed.
type Exclusion string

const (
	ExcludedNone       Exclusion = ""
	ExcludedPlatform   Exclusion = "platform"         // a platform event
	ExcludedUnresolved Exclusion = "asset-unresolved" // site-level total only
	ExcludedKind       Exclusion = "kind"             // a kind other than ser and syslog
	ExcludedInvalid    Exclusion = "invalid"          // not a valid C4 event (no native record_sha256); the store refuses one
)

// Classify says how the baseline of the event's asset counts e, and under
// which key. afterFailure is true for every row of the first successful
// read after a recorded V-S12 collection failure of the asset; the learner
// knows that, the event does not.
//
// A possible-duplicate SER row is classified like any other row here; the
// learner first decides with PossibleDuplicates whether it counts at all.
func Classify(e *event.Event, afterFailure bool) (k Key, text string, use Use, why Exclusion) {
	switch {
	case e == nil || e.Origin != event.OriginDevice:
		return Key{}, "", UseNone, ExcludedPlatform
	case slices.Contains(e.Flags, "asset-unresolved") || e.Source.Asset == nil:
		return Key{}, "", UseNone, ExcludedUnresolved
	case e.Kind != event.KindSER && e.Kind != event.KindSyslog:
		return Key{}, "", UseNone, ExcludedKind
	}
	k, text, ok := KeyOf(e)
	if !ok {
		return Key{}, "", UseNone, ExcludedInvalid
	}
	if e.Kind == event.KindSER && (afterFailure || catchUp(e)) {
		return k, text, UseTypeOnly, ExcludedNone
	}
	return k, text, UseFull, ExcludedNone
}

// catchUp reports a SER row aligned first-read or gap-before: rows that may
// have waited in the device's buffer for longer than one collection cycle.
func catchUp(e *event.Event) bool {
	if e.Collection == nil {
		return false
	}
	a := e.Collection.Alignment
	return a == event.AlignFirstRead || a == event.AlignGapBefore
}

// PossibleDuplicates applies D4-4 item 3 to one SER read. prev is the
// previous read's alignment keys, every row the device returned in order,
// stored or not; cur is the current read's stored rows in order. It returns,
// for each row of cur, whether it counts.
//
// A row not flagged possible-duplicate always counts. A flagged row counts
// unless prev still holds an unmatched row with its alignment key; then
// that row is matched and the flagged row does not count. Each row of prev
// is matched at most once, so k identical rows suppress at most k flagged
// rows, and rows of cur are never compared with each other.
func PossibleDuplicates(prev []string, cur []*event.Event) []bool {
	left := map[string]int{}
	for _, k := range prev {
		left[k]++
	}
	out := make([]bool, len(cur))
	for i, e := range cur {
		out[i] = true
		if !possibleDuplicate(e) || e.Native == nil {
			continue
		}
		if k := e.Native.AlignmentKey; k != "" && left[k] > 0 {
			left[k]--
			out[i] = false
		}
	}
	return out
}

// possibleDuplicate reports the C4 flag or the alignment it goes with.
func possibleDuplicate(e *event.Event) bool {
	return slices.Contains(e.Flags, "possible-duplicate") ||
		(e.Collection != nil && e.Collection.Alignment == event.AlignPossibleDuplicate)
}
