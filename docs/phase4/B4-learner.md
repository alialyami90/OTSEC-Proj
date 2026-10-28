# The event-behaviour learner and detector (P4-A4, R4.8)

B4, 2026-10-28. Package `modules/detection/eventbaseline`; documentation in its `doc.go`. Everything here is `simulated`: it ran on B6's synthetic GT-INJ series only, and no device was contacted.

## What it is

- `Learner`: feeds on an asset's stored events, in received order, and records a C10 baseline (`baseline.Baseline`, its compact bytes and hash) when both minima are met. A V-S12 failure (`Gap`) does not count toward the period.
- `Detector`: over the stored record, its hash and the time the operator's acknowledgement entered the audit chain, raises C10 alarms for the five rules. `Observe` takes events; `Tick` takes the passage of time (absence). No clock inside: the same input gives the same alarms.
- The lifecycle (recording, awaiting acknowledgement, active, re-learn), the C5 reads and the C5 0.4 configuration-class write belong to the node (B5). The feeder passes `AfterFailure` (first successful read after a V-S12 failure) and `NotCounted` (`baseline.PossibleDuplicates`).

## Evidence

`go test ./modules/detection/eventbaseline` (Linux, Go 1.27.3, `-race`):

- `TestGTINJAlarmsAreExactlyTheExpectedOnes`: the baselines learnt from GT-INJ's 14 observation days, activated at its acknowledgement, raise B6's 16 expected alarms and no other. Each one's rule, asset, type, time and cited event IDs match. Syslog events go through the real `normalize.Syslog`, as RFC 5424 with the msgid in place. Every alarm validates and fits its health event.
- `TestGTINJHeldOutRaisesNothing`: the held-out benign series raises 0 alarms.
- `TestGTINJSameInputSameAlarms`: two runs record byte-identical baselines and raise identical alarms.
- Boundary tests: the half-open repeats window; epoch buckets; type-only rows leave the type set and nothing else; the periodic threshold, the spread boundary and the median; gaps extending the period; max types; the byte cap dropping the least-counted type; the repeats window and rate bound on the detector; the hour; new-type once and for catch-up rows; the absence deadline (at, one nanosecond past, and re-anchored at activation); the alarm hold and the per-asset limit with its notice; not-counted duplicates on the next alarm; order, asset and activation errors.
- Mutants, each caught by a named test: the learner and detector window boundaries, the absence boundary, the rate bound, the hour test inverted, type-only rows learnt as full, the spread comparison, the median index, and the activation guard.

B6's independent V-M4 run is still to come; this is the implementer's check.

## Rulings applied (B1, D4-15) and limits

1. **Absence is re-anchored at activation.** A periodic type whose deadline ran out before the acknowledgement gets activation + interval + tolerance; one whose deadline is still ahead keeps it. None is left unarmed. `TestDetectorAbsence` has the type that goes silent and never returns (it alarms at exactly activation + interval + tolerance, and not a second before), the deadline exactly at activation, and a type that occurs first. Mutants: the old arming, and the deadline test at activation (`<=`), each fail it. B6's held-out series starts 16.5 hours after the acknowledgement; until B6 regenerates it, `TestGTINJHeldOutRaisesNothing` activates its replay at the first event, and says why.
2. **Max types keeps the highest counts.** The learner holds at most `MaxTypesCeiling` (4096) types per asset; a type first met past that is counted in `TypesOverflow` and never held. `Finish` keeps the `max_types` with the highest count (ties by key), then leaves out the lowest counts until the record fits the byte cap. Tests: a later high-count type displaces an earlier low-count one; ties by key; the ceiling boundary (4096th held, 4097th counted once and never held); the byte cap. Mutants: first-met selection, ties reversed, the ceiling off by one either way, the max_types cut removed, and lowest-first ordering. Exact up to 4096 types per asset; past that the asset is pathological and the overflow count says so. B5 should show it to the operator at acknowledgement.
3. **Events must arrive in received order for the asset** (`ErrOrder` otherwise). The feeder sorts.
4. `max_per_window` saturates at 4096, so `repeats_n` is at most 4095. A type with more than 4096 distinct gap lengths is not found periodic.
5. The held-alarms notice goes out on the first alarm the limit held back, with `held` 1; `Detector.HeldNow` gives the count later. If B5 wants the final count in the health event, the node must read it at the end of the hold.
6. Learner 0.1 runs on received time only (`time_clock` must be `received`).

## Next

- B5: wire the feeder (C5 reads sorted by received time, the V-S12 failure and the previous read's alignment keys), the C5 0.4 configuration-class record, the signed `node.baseline_ack`, and health progress. 
- B6: V-M4 acceptance on the real binaries.
