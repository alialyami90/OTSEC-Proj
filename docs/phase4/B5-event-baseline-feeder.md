# The event-baseline feeder in the node (P4-A5, node PR 2c, R4.8)

B5, 2026-10-28; updated by C5 the same day to the rulings. Nothing here is measured yet; every result will be `simulated`.

## Rulings

- **State across a restart: option A** ([D4-26](B1-decisions.md) item 1). Snapshots from B4 (#344), written with the per-stream positions they reflect, then a required C5 consumer committed after the snapshot is durable. On restore each stream resumes from the later of the snapshot's position and the consumer's cursor. A snapshot that does not restore raises an alarm and starts an audited re-learn naming the replaced baseline; it is never a silent restart.
- **Where the checkpoint lives** (B4's review of #343, option (b)). A record of the asset's own configuration stream `config/<asset>`, bounded by `ConfigRecordBytes` (1.5 MiB), with a new `ConfigDocuments` kind. The quota floor counts `EventCheckpointRecords` (2) records per event-baseline asset (#343). A learner too large to checkpoint (near the 4096-type ceiling with long names) is refused: the node keeps the last checkpoint and raises a health event. The node asks B4 (now C4) for the byte bound as a parameter of `Snapshot`.
- **`config.baseline_recorded` in C8 0.8** (D4-26 items 2 and 4, #346), event kind only. The node stores the baseline first and writes the record after; at start it folds the chain and writes any missing record. A baseline whose record is not yet in the chain is not awaiting acknowledgement and cannot be acknowledged.
- **`correlation_id`** ([D4-29](B1-decisions.md), C1 on #346). On `config.baseline_recorded` it is the 64 hex digits of `baseline_digest`, without `sha256:`. The acknowledgement keeps its signed C7 request ID, and the two join on `baseline_digest`.
- **Order.** The one below, which the B-to-C handoff set (`handoffs/HANDOFF-SUMMARY.md`, slices 1a to 1d): snapshots before the lifecycle. D4-26 item 3 had the lifecycle first with state in memory only; doing the snapshots first means no build of the lifecycle ever runs without its state kept. C1 to confirm on this PR.

## What is there, and what is missing

`modules/detection/eventbaseline` (B4, #330) holds the learner and the detector. Neither holds a clock, a store or a goroutine. The node owns everything else, and none of it exists yet:

1. Which assets observe, and with what parameters.
2. Reading an asset's events from C5 in received order, from the SER stream (`ser/<asset>`, evidence database) and from every listener stream that can hold the asset's Syslog (`syslog/<listener>`, syslog database).
3. The two inputs only the node knows: `AfterFailure` (the first successful read after a V-S12 failure) and `NotCounted` (`baseline.PossibleDuplicates` over the previous read's alignment keys).
4. The lifecycle: observing, baseline recorded and awaiting acknowledgement, active, re-learn.
5. Storing the C10 record in `config/<asset>` (the configuration class already validates it, `ConfigDocuments`).
6. `node.baseline_ack` of kind `event`: the node's part, on the relay of #339.
7. The detector's alarms as C4 health events of type `baseline.HealthDeparture`, and the held notice.
8. Health: progress toward both minima, the recorded baseline's hash while it awaits acknowledgement, the active baseline.

## The decision that needs a ruling: state across a restart

The learner holds up to 4096 types of counts, windows and gaps in memory. A restart in the middle of a 14-day period must not lose it, and the streams cannot be read back from the period's start, because forwarded records are pruned. There are three ways to keep it:

- **A. A snapshot API on the learner and the detector, and a C5 consumer.** B4 adds `Learner.Snapshot() ([]byte, error)`, `RestoreLearner(cfg, []byte)`, and the same for the detector: deterministic, bounded (the learner's bound is its type ceiling, window cap and gap cap), versioned. The node writes the snapshot atomically beside its cursors and commits a required C5 consumer (`node-eventbaseline`, as `node-suspensions` does for the audit stream) on each stream it reads only after the snapshot is durable. A crash re-reads from the committed cursor into the restored state, so no event is counted twice or lost. **Recommended.**
- **B. Keep the events.** A consumer pinned at the period's start. The streams would hold 14 days or more of every observed asset's events, so an event flood fills the class quota, and replay after a day of activation is unbounded. Rejected.
- **C. Restart the period.** A restart discards the learner and starts again. A node that restarts for an update every week never learns. Rejected, and it breaks V-M4's "a baseline does not change silently".

I ask B4 for A, with an `Equal`-after-restore test: a learner or detector restored from a snapshot at any point gives byte-identical output to one that ran straight through.

## Design

- **Configuration.** A top-level node config array `event_baselines`: `{"asset_id": ..., "params": {...}}`, where `params` is a full `baseline.Params` (C10 has no defaults but the two minima, 14 days and 200 events; "never constants a learner may assume") validated with its own check. The node ships an example block with the values `modules/detection/eventbaseline` tests use, as a starting point, not as a default. An asset in it that no schedule entry or listener can feed is refused at load. The node's quota rules (D4-20) count one baseline record per observing asset.
- **One reader per stream, not per asset.** A Syslog listener's stream carries several assets' events, so the feeder reads each stream once and hands each event to its asset's learner or detector by `source.asset`. An event whose asset is not observing is skipped. An `asset-unresolved` event goes to a site-level counter in status (C10), never to an asset.
- **Received order** (as built in slice 1b). The feeder reads batches from every stream of an asset, merges by `received.utc` (ties: an event before a run's health record, then by stream, then seq), and passes an event only when it is no later than the asset's watermark, the least of its streams' bounds. A stream read to its end bounds it at the node's clock less `FeedLateness` (2 minutes): a record committed later has a received time no earlier than that, as long as no record waits longer than `FeedLateness` between being stamped and being committed. A stream with more to read bounds it at the commit time of the last record read, less `FeedLateness`. A SER read whose last row is not yet read holds it before that read. The proposal's "latest committed time" bound alone was not safe: a Syslog message stamped before a batch commits can commit after it, and an idle stream would have held every other stream back. An event that arrives behind the watermark (a commit stalled past `FeedLateness`, or a backward clock step) is counted as late for the asset and not passed, and it stays stored and forwarded. Ticks take the watermark, never the clock directly, so a commit delayed within `FeedLateness` changes nothing (#303, `TestDetectorTickIsAWatermark`; the node's `TestFeedDelayedCommitChangesNothing`). The cost is that a departure is alarmed up to `FeedLateness` later.
- **`AfterFailure`.** From the asset's health events in `platform/health`: a collection failure opens a gap `[first failure, next success)`, and the first successful SER read after it is `AfterFailure` for all its rows, and the learner is told with `Gap`. The gap's bounds come from the health events' received times.
- **`NotCounted`.** The last stored row of a SER read carries the read's whole alignment state as its `SourceCursor`, so the feeder takes the previous read's keys from there (and keeps them in the checkpoint), and applies `PossibleDuplicates` to each read's stored rows. A read is the rows that share one `received.utc` and one `collection.invocation_id`, and it is held until its last row is read. A read that stored no rows saves its state without an event, so the next read is compared with the older state.
- **Lifecycle, from the chain.** The state is derived from what C5 and C8 hold, as the holds are (`holds.go`): the newest C10 record in `config/<asset>` that no succeeded `config.baseline_acknowledged` of kind `event` names is "awaiting acknowledgement"; the acknowledged one is "active", with the time its acknowledgement entered the chain as `ActiveFrom`. A C10 record counts only once its `config.baseline_recorded` (C8 0.8) is in the chain: the node stores the record, then writes the audit record, and at start repairs a missing one before it derives any state. A lost snapshot is a re-learn, and the node says so (an alarm, and the re-learn record names the replaced hash in `Previous`).
- **`node.baseline_ack`, event kind.** On acceptance the node holds a baseline of that asset and kind whose stored bytes hash to `baseline_digest`; if not, it refuses and audits. The same gates as #339 apply (taint, key binding, verified payload), and it is a `nodeActKinds` kind with its own part. A configuration-kind acknowledgement is B3's run wiring PR; the two share the relay.
- **Snapshot storage.** The learner and detector snapshots, the per-stream positions and the previous read's alignment keys go in one checkpoint record of `config/<asset>` (the Rulings above), written atomically before the `node-eventbaseline` consumer is committed on each stream.
- **Alarms.** `Output.Alarms` become C4 health events through `Alarm.Health`, written to `platform/health` through the node's normal event path (so the C6 forwarder carries them), deduplicated across a restart by `(asset, baseline hash, rule, key, at_utc)` (the replay key in the package doc). The held notice becomes a `HealthAlarmsHeld` event.
- **Bounds.** At most 4096 types per learner, a batch cap per tick, and the feeder runs between runs in the scheduler's goroutine with a time budget, so a flood of events cannot delay a collection run.

## What I build first, in order

1. Config and layout (`event_baselines`, the consumers, the quota count), with tests. No dependence on B4.
2. The merge reader and its watermark, over C5, with tests that delay an Observe past a tick (#303).
3. The snapshot, the checkpoint record, the consumers and the restart tests (needs #344 and the byte bound): restart-at-every-step equivalence on GT-INJ, and a crash before and after the cursor commit.
4. The lifecycle, `config.baseline_recorded` and `node.baseline_ack` (event) (needs #346 and #339's gates): a crash test with the baseline stored and no record, a refused acknowledgement of a digest that is not stored, and a refused acknowledgement of a baseline not yet recorded. V-M4 is claimed only on the real binaries, with C6, after this slice.

Slices 1 (#343) and 2 have no dependence on C4.

## Questions still open

- **C4:** the byte bound on `Snapshot` as a parameter (refusing above it with an error), and whether an oversize snapshot can be detected before it is fully built. Asked on #343 and again on 2026-10-28.
- **C4:** exporting `baseline.Params.Validate()`, so the node drops its copy of the checks and the pin test.
