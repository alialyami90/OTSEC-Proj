// Package eventbaseline is the learner and the detector of the event
// behaviour baseline (R4.8, P4-A4): it learns, per asset, what the asset's
// SER rows and Syslog messages normally look like, and raises explainable
// alarms when the asset departs from it. The record and the alarm are
// contract C10, otsec.baseline/0.2 (contracts/baseline); the rules are
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
// and NotCountedTotal, BaselineValue and Observation for repeats and rate, and
// the Observation of any rule once the pair cap has dropped a record (it then
// ends with the count of breaks not listed).
// A replay that dedupes alarms should therefore replay from the baseline's
// activation, and key an alarm by its asset, Baseline (the hash), Rule, Key
// and AtUTC. That is unique: alarms of one rule and key are at least
// Params.AlarmHoldS (3600 s at the least) apart, and AtUTC is the received
// time of the event that broke the baseline, or the deadline for absence. The
// breaking event's own ID is not a safe key part: Events lists the first 32
// breaks, and an absence alarm may list none.
//
// # Snapshot and Restore
//
// A node that restarts cannot replay a 14-day period: the records are
// forwarded and pruned. Learner.Snapshot and Detector.Snapshot return the
// whole state as bytes, and RestoreLearner and RestoreDetector build the
// learner or detector back from them. Restoring a snapshot taken at any
// point gives a learner or detector whose every later call returns what the
// one that never stopped would have returned: the same alarms, the same
// baseline bytes, the same errors (TestSnapshotLearnerRestoredAtEveryStep and
// TestSnapshotDetectorRestoredAtEveryStep restore after every call of the
// GT-INJ series and compare the whole state, byte for byte, after each).
//
// The format is versioned (the header says 1), deterministic (one state gives
// one set of bytes: keys and maps are in order, numbers in their shortest
// form, so Restore then Snapshot returns the bytes it was given) and ends in
// a SHA-256 of everything before it. A snapshot is bound to what it was taken
// under: the learner's to the node, asset, baseline version, previous hash,
// byte cap and every parameter, and the detector's to the baseline hash, asset
// and activation time. Restoring under others is ErrSnapshotMismatch. Bytes
// that are cut short, changed, of another format or learner version
// (ErrSnapshotVersion), of the other half, or not consistent with
// themselves (counts that do not add up, keys out of order) are ErrSnapshot.
// Every restore error returns no learner or detector, never part of one.
//
// What the snapshot does not hold, the caller does. It holds no stream
// position: the node stores, in the same record as the snapshot, the position
// of the last event it passed to Observe, so a restart resumes at the next
// one. An event replayed after the snapshot's last one is taken a second time
// (the learner counts it twice, the detector may alarm twice); one earlier
// is refused with ErrOrder. The feeder's own facts (whether a read follows a
// V-S12 failure, a failure still open, which rows are possible duplicates)
// are the feeder's, passed in Obs and Gap as before.
//
// The seal detects corruption, not tampering: it is a SHA-256, not a MAC,
// so a restore trusts the store as much as the node does.
//
// Size. Snapshot takes the caller's bound in bytes (the node passes what its
// checkpoint record can hold), and never more than MaxSnapshotBytes
// (1.25 MiB). A state that does not fit is refused with ErrSnapshotTooLarge,
// within about one type's bytes of the bound rather than after it is built
// in full, and the learner or detector goes on unharmed, so the node keeps
// its previous snapshot and says so. Every list the state holds is capped
// (MaxTypes, windowCap, gapCap and gapBudget, MaxGaps, the new-type memory,
// MaxNewTypePairs, the held-ID budget, MaxStreams), so no state reaches the
// bound: TestSnapshotMaximalCase measures the widest state each half's format
// allows, every list at its cap, every string at its longest and every
// number at its widest encoding, at 1,167,117 bytes for the learner and
// 910,592 for the detector, under ConfigRecordBytes less 64 KiB, C5's
// envelope and the feeder's own state (D4-30). TestSnapshotSizes gives
// reachable figures: the GT-INJ learner after 14 days is 1.2 to 1.6 KB; a
// learner of 512 types with 128-byte names, 30 occurrences each, is about
// 250 KB; a detector of 512 types with every repeats window full and the
// new-type memory full of long names is about 140 KB at repeats_n 5.
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
//   - Max per window saturates at 32 occurrences (windowCap), which is why
//     repeats_n is at most 31 (MaxRepeatsN): the repeats rule is exact
//     within its range, and a repeats alarm lists its whole window. A
//     larger repeats_n is refused, not clamped.
//   - Periodic types. Gaps are whole seconds, rounded to nearest. A type
//     that can never meet periodic_spread_pct is dropped from periodic
//     tracking as soon as that is certain, and one with more than 4096
//     distinct gap lengths, or one met when the learner holds 16,384 gap
//     lengths over all types, is not found periodic (GapBudgetDrops counts
//     the latter). Past MaxGaps (256) collection gaps, a gap is merged into
//     the last, so the period is longer, never shorter. A gap whose reason
//     is not a token, that ends before it starts, or whose time is outside
//     the years 1 to 9999 is refused (ErrGap).
//   - Max types (D4-15, D4-30). At most 512 types per asset (MaxTypes, C10
//     0.2's ceiling) are held while learning; a type first met while that
//     many are held is counted (Counts.TypesOverflow) and never held. The
//     basis is documented-untested: an SEL-751 reports at most 96 Relay Word
//     bits in SER (751 IM, Table 4.122), so at most 192 SER types. A chatty
//     non-SEL Syslog source may exceed 512; types_overflow above zero then
//     says the asset is only partly baselined, and the node reports it as
//     status. Finish keeps the max_types with the highest count, ties by
//     key, then leaves out the lowest counts until the record fits the byte
//     cap, and counts every type left out. Left-out types are remembered by
//     a 16-byte SHA-256 prefix of their key, up to 512 of them
//     (Result.OverflowSaturated says the count stopped). After activation a
//     type left out alarms as new.
//   - The new-type memory holds 2048 types (16-byte digests); a flood of
//     distinct new types beyond that alarms on each occurrence, under the
//     alarm bounds. A digest collision can only make a new type look seen,
//     so it can hide a new-type alarm of that asset and nothing else. The
//     detector's record of held breaks per (rule, type) for the new-type
//     rule is bounded too (MaxNewTypePairs, 512; F1, D4-26), and the IDs all
//     records list together are bounded at 2048. Once an alarm hold ends, a
//     record that lists nothing is dropped (no change to any output); if the
//     cap is still reached, records whose hold ended are dropped with the
//     breaks they list. Those breaks, and any held past the ID budget, are
//     counted and stated by the next alarm ("N more held breaks beyond the
//     detector's caps are not listed"). The count is exact; the events are
//     not listed. The other rules' records are bounded by the baseline's
//     types and are not swept.
//   - Streams. The IDs a detector holds may name at most 16 (node, stream)
//     pairs (MaxStreams); a detector past that is refused a snapshot.
//   - Absence (D4-15). A periodic type whose deadline ran out before the
//     acknowledgement is given activation + interval + tolerance as its
//     deadline, so a source that fell silent during the wait and never
//     returns still alarms, at most one interval and tolerance after
//     activation. Nothing alarms before activation.
//   - The held-alarm notice carries a count that grows after it is sent.
//   - Every value learnt on a synthetic series says nothing about a real
//     device (V-M4 reports it as simulated).
package eventbaseline
