# Snapshot and Restore for the learner and the detector (P4-A4, D4-26)

B4, 2026-10-28. Everything here is `simulated`: B6's GT-INJ series and generated states, run through `modules/detection/eventbaseline`. No device was contacted.

## Why

A node that restarts cannot replay a 14-day observation period: the records are forwarded and then pruned. The learner and the detector therefore need their state to be written down and read back. B5's feeder (#340) stores each stream's position beside the bytes; this change is the bytes.

## What was added

```go
func (l *Learner)  Snapshot(maxBytes int) ([]byte, error)
func RestoreLearner(c LearnerConfig, snap []byte) (*Learner, error)
func (d *Detector) Snapshot(maxBytes int) ([]byte, error)
func RestoreDetector(c DetectorConfig, snap []byte) (*Detector, error)

const MaxSnapshotBytes = 8 << 20
var ErrSnapshot, ErrSnapshotVersion, ErrSnapshotMismatch, ErrSnapshotTooLarge
```

`Snapshot` does not change the object. `maxBytes` is the caller's bound: the node passes what its checkpoint record holds (C5 on #343). Zero, below zero or above `MaxSnapshotBytes` means `MaxSnapshotBytes`. The encoder checks the size after each type and after the held breaks, so an oversize state is refused within about one type's bytes of the bound, not after it is built in full (C4, 2026-10-28). `Restore*` builds a new one; on any error it returns nil and an error, so there is never a partial state.

## The format

- Header: `OTEB`, the format version (1), a kind byte (`L` learner, `D` detector). The last 32 bytes are the SHA-256 of everything before them.
- Body: varints (signed ones zig-zagged), and strings as a length and the bytes. Keys use `Key.String()`. Maps are written in key order and numbers in their shortest form; the reader refuses anything else. So **one state has exactly one encoding**, and `Restore` then `Snapshot` returns the bytes it was given (checked after every call in the tests).
- Stamps (the learner's repeats window, the detector's recent occurrences) are written as the first value and then the steps. Event IDs are written as a number into a table of (node, stream) pairs, and the seq.
- **Bound to what it was taken under.** The learner's snapshot holds the node, asset, baseline version, previous hash, byte cap, the learner's name and version and every parameter (as the JSON of `Params`). The detector's holds the baseline hash, the asset, the number of types and the activation time. Restoring under another is `ErrSnapshotMismatch`. A different format version or learner version is `ErrSnapshotVersion`. Both are `ErrSnapshot`, as is anything cut short, changed, of the other half, or not consistent with itself.
- **Checked whole before use.** Every list is bounded by the caps (4096 types, 4096 window stamps, 4096 gap lengths, 32 event IDs, 16,384 new types) and by the bytes left, so no length in the input causes a large allocation. Counts must add up the way the code makes them add up (events = full + type-only + not-counted; a type's hours sum to its full count; gap counts sum to full - 1; the type counts sum to full + type-only until types are left out; and so on), keys are in order and once each, and a type of the baseline is never among the new types seen.

## What a restore guarantees

A learner or detector restored from a snapshot taken at **any** point returns, from then on, what the one that never stopped would return: the same alarms and hold notices, the same baseline bytes and hash, the same errors.

| Claim | Test (all in `snapshot_test.go`) |
| --- | --- |
| Learner: after every event of both GT-INJ assets (with the feeder's `AfterFailure` and `NotCounted` flags on some rows, and gaps), the restored learner's whole state equals the one that never stopped, and `Finish` gives identical bytes, hash, excluded counts and progress | `TestSnapshotLearnerRestoredAtEveryStep`: 769 and 783 restores |
| Detector: after every `Observe` and every 15-minute `Tick` of both GT-INJ series (the departures series and the held-out one), the restored detector raises byte-identical output and holds identical state | `TestSnapshotDetectorRestoredAtEveryStep`: 1830, 1911, 1891 and 1983 restores |
| The held breaks a pair lists on its next alarm, and the possible duplicates, survive a restore | `TestSnapshotRestoredLearnerAndDetectorWorkOn` |
| The working-set limit: types counted and not held, and a saturated overflow count, survive | `TestSnapshotLearnerAtTheWorkingSetLimit` |
| Same state, same bytes, whatever the map order | `TestSnapshotSameStateSameBytes` |
| A snapshot cut at every length, or with any one byte changed, or with a byte added, is refused | `TestSnapshotRefusesWhatItCannotRestore` |
| Another format version (0, 2, 9, 127, with the checksum made right), another magic, the other half's snapshot, no bytes: refused, and the version one is `ErrSnapshotVersion` | the same |
| Another value of any of 9 parameters, the node, asset, version, previous hash, byte cap; another baseline hash, activation time or baseline: `ErrSnapshotMismatch` | `TestSnapshotRefusesAnotherConfiguration` |
| With the checksum made right, every byte changed five ways: refused, or accepted only as a state that encodes back to the same bytes and records a valid baseline (learner) or goes on without a panic (detector). 4,480 learner changes (3,901 refused) and 2,295 detector changes (1,709 refused). | `TestSnapshotChangedAndSealedAgainIsRefusedOrCanonical` |
| States that cannot have come from the code (a gap count that does not add up, a hold flag of 2, alarms held with no hold open, a baseline type listed as new) are refused | `TestSnapshotRefusesInconsistentState` |
| A state above the caller's bound is refused with `ErrSnapshotTooLarge`, returns no bytes, and the learner or detector goes on exactly as a twin restored before the refusal; a bound of exactly the snapshot's size takes it; 0, -1 and above `MaxSnapshotBytes` mean `MaxSnapshotBytes` | `TestSnapshotTooLargeIsRefusedAndHarmless` (added by C4: B4's text named it, but it was not in `7dbe6b0`) |

Mutation check (local, not committed): 42 mutants of `snapshot.go` that drop or replace one field or one consistency check (each learner and detector field, the id table, the pairs, the hold fields, the new-type memory, the checks on counts, order and gaps) are each killed by at least one test. Seven survived at first (the pairs' event IDs, the saturation flag, the excluded counts and four consistency checks) and are why `TestSnapshotRestoredLearnerAndDetectorWorkOn`, `TestSnapshotLearnerAtTheWorkingSetLimit` and `TestSnapshotRefusesInconsistentState` exist. A stronger fuzz check (an accepted change must still record a valid baseline) also found a missing check on the sum of the type counts, now made.

## Sizes

`go test ./modules/detection/eventbaseline -run TestSnapshotSizes -v -count=1` prints every figure.

| State | Bytes |
| --- | --- |
| GT-INJ learner after the 14 days | 1,235 (7 types) and 1,576 (5 types) |
| GT-INJ detector, fresh | 229 and 221 |
| Learner at the 4096-type ceiling, names at the 128-byte limit, 30 occurrences each | **1,946,050** (475 per type) |
| One type at the most the caps let it hold: a full repeats window of 4096 stamps | 16,931 |
| One type at the most the caps let it hold: 4096 distinct gap lengths (built over years of simulated time; not reachable in 14 days) | 16,958 |
| Detector, baseline of 1910 types (the most that fit the 512 KiB record), fresh | 15,454 |
| Same, every type's repeats window full (6 stamps and IDs) | 340,931 |
| Same, plus the new-type memory full (16,384 types) and a held break for each | 1,340,486 |
| Detector with 16,384 new types of 128-byte names, and their held breaks | above 8 MiB: refused |

**The largest snapshot is `MaxSnapshotBytes`, 8 MiB (8,388,608 bytes).** That is the size B5 can bound the checkpoint at. What reaches it:

- *Learner.* The fixed part at 4096 types is about 2 MB. What adds to it is the repeats window and the gap lengths of a type, 17 KB each at the caps, so the limit is reached with about 370 types at that maximum. A window of 4096 stamps needs 4096 occurrences of one type inside the repeats window (a flood). 4096 distinct gap lengths needs 4097 occurrences at least 5.7 hours apart, which no 14-day period holds: at `periodic_spread_pct` 10 a type that is still held as periodic has at most about 550 distinct gap lengths in 14 days (2 KB). The state itself has no byte bound beyond these caps; the limit is the bound.
- *Detector.* Bounded by the baseline (at most what fits 512 KiB, so about 2000 types), the new-type memory (16,384 keys) and the pair cap (`MaxNewTypePairs`, 4096; F1 below). With the cap, a flood of 114,688 distinct new types leaves a snapshot of 553 KB.

A state above the limit is not truncated. `Snapshot` returns `ErrSnapshotTooLarge`, the object is unharmed, and the node keeps its previous snapshot and raises a health event. A restart then resumes at the older snapshot's position and replays from there, which is correct because the output is deterministic.

## F1: the detector's pairs, and how they are bounded (B1's ruling, D4-26)

`Detector.pairs` holds one record for every (rule, type) that raised or held a break. The new-type memory stops at 16,384 keys, but past that every distinct new type still raised (under the alarm holds) and still added a record, and nothing removed one. Measured before the fix (not committed): the snapshot was 0.98 MB at 16,384, 2.3 MB at 49,152 and 4.8 MB at 114,688 distinct new types, and refused at 245,760. A sender that varies its message text can do this to its own asset (the template normalisation only folds digits).

B1's four rules, and what was built:

1. A record whose alarm hold ended and that lists no held break is dropped. A missing record and an expired empty one act alike, so no output changes. Test: `TestPairSweepChangesNoOutput` (the output equals that of a detector with no cap and no sweeping, and the capped detector without the sweep differs, so the test is not vacuous).
2. The rest are capped at `MaxNewTypePairs` (4096), a constant beside the new-type memory's 16,384. The sweep covers new-type records only: an absence alarm is stamped with its deadline, so dropping an absence record is not output-neutral.
3. Past the cap no break is lost silently or re-alarms without bound. A break held with no record is counted (`d.beyond`); when the cap is still reached after pass 1, pass 2 drops records whose hold ended that list breaks, and adds the breaks they listed to the count. The next alarm ends its observation with "; N more held breaks beyond the cap of M tracked new types are not listed" and resets the count. Test: `TestPairSweepDropsListedPairsLast`.
4. A flood of 114,688 distinct new types keeps the records at the cap and the snapshot at 553 KB, and the counts stay exact: over three floods (154,690 breaks) every break is an alarm, a break listed by an alarm or a record, or a break counted and stated. Test: `TestPairCapFloodStaysBoundedAndCountsStayExact`.

What changes for an operator: in a flood the alarm lists fewer held events than before, and says how many it does not list. Sweeps run at most once per alarm hold. The snapshot carries the next sweep time, the count not yet stated and each record's birth, and a restore rebuilds the record count and refuses a state where a record is in the wrong place. `ErrSnapshotTooLarge` stays as the backstop.

## What the feeder must do (for B5)

The learner and the detector need nothing more from the caller. The feeder keeps its own state, in the same record as the snapshot, committed together:

1. **The position** through which every event of the asset was passed to `Observe`, per (asset, stream), and the watermark. On a listener stream, seq order is commit order and can differ from received order, so "the last event passed" is not enough: an event with a higher seq can be passed while a lower one still waits (C5 on #364). On restore, a re-read event at or before the watermark is skipped, not taken twice; one taken twice is counted twice by the learner and may alarm twice in the detector, and one earlier than the last taken is refused with `ErrOrder`. The detector's output is deterministic, so a replay gives its alarms again with the same identity, and a replay that dedupes by (asset, baseline hash, rule, key, `AtUTC`) is safe (doc.go, "Replay and alarm identity").
2. **The previous read's alignment keys**, per stream: the `prev` argument of `baseline.PossibleDuplicates`, every row the device returned, stored or not. Neither half holds it. The store has it for a read that stored rows: `normalize.Output.Records` puts the read's whole alignment state on its last SER row as the `SourceCursor`. A read that stored no rows saves its state with `SaveSourceCursor` and no event, and the store keeps only the latest cursor, so the feeder checkpoints `prev` with the snapshot (C5 on #364).
3. **The V-S12 state**: whether the next successful read is the first after a failure (`Obs.AfterFailure`), and the start of a failure still open (`Learner.Gap` is called when it closes).
4. **The learner's `LearnerConfig`** (the parameters, version, previous hash and byte cap) unchanged. A restore under other parameters is refused, not adapted: changing a parameter is a new baseline.
5. **The watermark** for `Tick` is at least the snapshot's time (a `Tick` before it is `ErrOrder`).

## Not shown

- The format has been tried only against states this package makes. It has never been read by another version (there is none), so `ErrSnapshotVersion` is tested with edited bytes.
- The times above are for this machine; none is a requirement.
- The state sizes of a real device's history are unknown (the same limit as every figure in `B4-measures.md`).
- How the node stores the snapshot, when it takes one, and what it does on `ErrSnapshotTooLarge` are B5's.
