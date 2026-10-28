// Package eventbaseline is the learner and the detector of the event
// behaviour baseline (R4.8, P4-A4): it learns, per asset, what the asset's
// SER rows and Syslog messages normally look like, and raises explainable
// alarms when the asset departs from it. The record and the alarm are
// contract C10, otsec.baseline/0.1 (contracts/baseline); the rules are
// docs/verification.md, "R4.8 observation period and measures", and B1's
// rulings D4-4 and D4-9. Deterministic rules only; no machine learning.
//
// # Shape
//
// Neither half holds a clock, a store or a goroutine. The caller feeds
// events in received order and supplies time; the same input gives the same
// output. The node owns the lifecycle (observation, awaiting
// acknowledgement, active, re-learn), reads the asset's events from C5, and
// stores the record in C5 0.4's configuration class.
//
//   - Learner: NewLearner, Observe for each stored event of the asset, Gap
//     for each closed V-S12 collection failure, Progress for health, and
//     Finish once both minima are met. Finish returns the baseline, the
//     compact bytes it is stored as (baseline.Encode) and their hash
//     (baseline.Hash), which C7 0.6 node.baseline_ack names.
//   - Detector: NewDetector over the stored record, the hash and the time
//     the acknowledgement entered the audit chain; Observe for each event;
//     Tick for the passage of time (absence). Each returns the alarms
//     (baseline.Alarm, which converts to a C4 health event) and, at most
//     once per hold, a notice that the asset reached its alarm limit.
//
// The caller decides two things only it knows (Obs): that a SER row is the
// first of a successful read after a V-S12 failure (AfterFailure), and that
// baseline.PossibleDuplicates did not count a row (NotCounted).
//
// # What each rule does here
//
//   - New type: the first occurrence of a key not in the baseline, from
//     any use, including a catch-up row (the alarm says so). Later
//     occurrences of the same new type raise nothing.
//   - Repeats: more than repeats_n full occurrences in (t - window, t],
//     where the baseline's maximum for the type was below repeats_n. The
//     alarm lists the repeats_n + 1 events of the window the breaking event
//     closed.
//   - Rate: the bucket (Unix-epoch buckets of rate_bucket_s, received time)
//     passes baseline.RateBound. It alarms on the event that passes the
//     bound, and lists the bucket's events up to and including it.
//   - Time: a full occurrence in a UTC hour in which the baseline never saw
//     the type. Learner 0.1 always uses received time.
//   - Absence: a periodic type not seen by last + interval + tolerance. An
//     occurrence exactly at the deadline is in time; the alarm is raised
//     when time (an event or a Tick) is past the deadline, and is stamped
//     with the deadline. It lists no events.
//
// Catch-up rows (baseline.UseTypeOnly) count toward the type set and the
// new-type rule only. Events of other assets are an error (ErrAsset);
// platform events, other kinds and asset-unresolved events belong to no
// baseline and are ignored (counted by the learner in Excluded).
//
// # Alarm bounds
//
// One alarm per (rule, type) per Params.AlarmHoldS, and at most
// Params.MaxAlarmsPerHold per asset per hold, as C10 fixes. A break held back
// is not lost: its event is listed on the next alarm of the same rule and
// type, and EventsTotal counts it. The hold opens at the asset's first alarm
// and ends AlarmHoldS later. The notice (Held) goes out on the first alarm
// the limit held back; Detector.HeldNow gives the count so far.
//
// # Replay and alarm identity
//
// A Detector holds no clock and does no I/O, so its Output is a pure function
// of the baseline (its Hash and ActiveFrom) and the calls made: Observe's
// events in order, with their received times. Two runs over the same events
// give byte-identical alarms in every field, and so do two runs that differ
// only in when Tick is called, because an absence alarm's content comes from
// its deadline, never from the time it was noticed (a later Observe advances
// to its event's time first, and so raises the same alarm). The Held notice
// is Held: 1 whenever it is sent; only HeldNow grows.
//
// Tick is a watermark, and that is the precondition of the paragraph above.
// Tick(now) says that no event received before now remains to be observed:
// it moves the detector's time to now, and an Observe of an event received
// before that is refused with ErrOrder and raises nothing, so its alarm is
// lost. The feeder must therefore tick with a watermark, no later than the
// received time of any event it has yet to Observe (for example the least
// received time of what it has read but not yet passed on, or of what it
// could still read), and never with the wall clock. A store stall (F-016)
// can leave seconds between an event's receive and its Observe, so a wall
// clock tick overtakes events. Ticks that respect the watermark change no
// alarm; one that does not loses alarms, and TestDetectorTickIsAWatermark
// pins the refusal.
//
// A run that starts from a later event, or leaves events out, does not
// reproduce the same alarms. Windows, buckets and the holds depend on what
// came before, so the fields that can differ are: whether an alarm is raised
// at all (the holds), Events and EventsTotal (they include breaks held since
// the pair's last alarm, so Events[0] is not the breaking event), NotCounted
// and NotCountedTotal, and BaselineValue and Observation for repeats and rate.
// A replay that dedupes alarms should therefore replay from the baseline's
// activation, and key an alarm by its asset, Baseline (the hash), Rule, Key
// and AtUTC. That is unique: alarms of one rule and key are at least
// Params.AlarmHoldS (3600 s at the least) apart, and AtUTC is the received
// time of the event that broke the baseline, or the deadline for absence. The
// breaking event's own ID is not a safe key part: Events lists the first 32
// breaks, and an absence alarm may list none.
//
// # Limits
//
// These are places this implementation is not exact or not complete. Each is
// tested or stated here so that it is seen.
//
//   - Order. Events must arrive in non-decreasing received order for the
//     asset (ties in any fixed order). Anything earlier is returned as
//     ErrOrder and not taken. The node reads several streams for one asset,
//     so the feeder sorts; a late event is the feeder's to handle.
//   - Max per window saturates at 4096 occurrences (windowCap), which is why
//     repeats_n is at most 4095: the repeats rule is exact within its range.
//   - Periodic types. Gaps are whole seconds, rounded to nearest. A type
//     that can never meet periodic_spread_pct is dropped from periodic
//     tracking as soon as that is certain, and one with more than 4096
//     distinct gap lengths is not found periodic.
//   - Max types (D4-15). While learning, at most baseline.MaxTypesCeiling
//     types are held per asset; a type first met while that many are held is
//     counted (Counts.TypesOverflow) and never held. Finish keeps the
//     max_types with the highest count, ties by key, then leaves out the
//     lowest counts until the record fits the byte cap, and counts every
//     type left out. This is exact for an asset that shows 4096 types or
//     fewer in its period; past that the asset is pathological and the
//     overflow count says so (Result.OverflowSaturated: the count itself
//     stopped at 4096). After activation a type left out alarms as new.
//   - The new-type memory is bounded (16,384 types); a flood of distinct
//     new types beyond that alarms on each occurrence, under the alarm
//     bounds.
//   - Absence (D4-15). A periodic type whose deadline ran out before the
//     acknowledgement is given activation + interval + tolerance as its
//     deadline, so a source that fell silent during the wait and never
//     returns still alarms, at most one interval and tolerance after
//     activation. Nothing alarms before activation.
//   - The held-alarm notice carries a count that grows after it is sent.
//   - Every value learnt on a synthetic series says nothing about a real
//     device (V-M4 reports it as simulated).
package eventbaseline
