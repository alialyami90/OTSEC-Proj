// Package baseline is contract C10, otsec.baseline/0.1: the event-behaviour
// baseline of one asset (R4.8), the event-type key it is learnt on, and the
// departure alarm raised against it.
//
// The semantics are fixed by docs/verification.md, "R4.8 observation period
// and measures", and by B1's rulings D4-4 (docs/phase4/B1-decisions.md).
// This package states them as code so the learner (modules/detection) and
// B6's tests read one definition. It holds no learner: no I/O, no storage,
// no clock.
//
// # What it covers
//
//   - The event-type key (KeyOf). For SER, the element name and its state as
//     printed: C4 normalized.subject and normalized.value, so 51P1P Asserted
//     and 51P1P Deasserted are two types. For Syslog, the facility and the
//     severity from the C4 "pri" field, and the message template: the C4
//     "msg" field with every run of ASCII digits replaced by "#". The field names are
//     the otsec-syslog parser's; without a "msg" field the whole record is
//     the message. A message whose PRI cannot be read has facility and
//     severity "pri-absent". The template's identity is its SHA-256, so a
//     long message costs a fixed size; Text keeps its first TextMax bytes
//     for the alarm. APP-NAME, the tag and the RFC 5424 MSGID are not part
//     of the key (D4-4 item 4): a sender that reuses one MSGID for
//     different messages still gets one type per template.
//   - Which events a baseline counts (Classify). Platform events, events of
//     kinds other than ser and syslog, and events flagged asset-unresolved
//     belong to no asset's baseline (A6's invariant). The node counts
//     asset-unresolved events in a site-level total only, so a stranger flood
//     stays visible without entering any asset's normal. A SER row with no
//     normalized form is unkeyed: it is counted in the baseline's coverage,
//     and its parse failure is already a V-S12 health event.
//   - Catch-up (D4-4 item 2). Every row of one SER read shares one
//     received.utc, so a read that returns many old rows at once is not a
//     burst. Rows aligned first-read or gap-before, and every row of the
//     first successful read after a recorded V-S12 collection failure, are
//     UseTypeOnly: they count toward the type set, the new-type rule and the
//     repeats rule, never toward rate or hour learning, and the rate and
//     time rules skip them.
//   - Repeats. A repeat, the same record_sha256 again, is an occurrence, not
//     a duplicate to drop: the repeats rule needs it.
//   - possible-duplicate rows (D4-4 item 3, PossibleDuplicates). A SER row
//     flagged possible-duplicate is matched against the previous read only,
//     one to one: k identical rows there suppress at most k flagged rows.
//     Rows are never compared within the current read. A suppressed row is
//     not counted; the baseline counts it, and an alarm lists it under
//     NotCounted. Syslog events never carry the flag.
//   - The clock (D4-4 item 1). Rate and time rules run on received.utc. The
//     time rule may use device time only when the event's offset is known
//     (V-S3); the baseline's Params.TimeClock says which, and every alarm
//     names the clock it used. Learner 0.1 always uses received time.
//   - The baseline record (Baseline). Recorded once when the observation
//     period ends: the asset, the period and its coverage, the parameters,
//     and every type learnt with its counts, hours, window and bucket maxima
//     and any period found. A re-learn is a new record with Version + 1 that
//     names the record it replaces in Previous. It is stored compact
//     (Encode) in C5 0.4's configuration class, and is at most MaxBytes:
//     past max_types, or past what fits, the types with the lowest count
//     are left out and counted in types_overflow, and are new types once
//     the baseline is active.
//   - The baseline hash (Hash, D4-4 item 5): SHA-256 over the stored
//     record's exact bytes, with no canonical JSON. C7 0.6 node.baseline_ack
//     names it; C9 uses the same rule for configuration baselines.
//   - The departure alarm (Alarm): the rule, its parameters, the baseline
//     value, the observation, the clock, and the IDs of the events that broke
//     the baseline. It travels as a C4 platform event of health type
//     HealthDeparture (Alarm.Health, AlarmFromHealth), so the store and the
//     C6 forwarder carry it unchanged.
//
// # What it leaves out
//
//   - The lifecycle (recording, awaiting acknowledgement, active, re-learn)
//     belongs to the node and C5 0.4. A baseline is active only after an
//     operator's signed node.baseline_ack is in the audit chain (C7 0.6, C8
//     0.5); until then no departure alarm is raised.
//   - How the learner finds the previous read's rows and the V-S12 failures.
//   - Network baselines (that is IDS, R6) and machine learning.
//
// # Limits
//
//   - The digit rule merges messages that differ only by a number, including
//     RTAC tags such as "Breaker 1" and "Breaker 2" (D4-4 item 4). A dialect
//     rule may follow in a later minor if B6's tests or a real capture show
//     that the merge hides a distinction that matters.
//   - Hours are UTC hours of the received time, so a site's local working day
//     shifts by an hour across daylight saving.
//   - Every value learnt on a simulator or a synthetic series says nothing
//     about a real device (V-M4 reports it as simulated).
package baseline
