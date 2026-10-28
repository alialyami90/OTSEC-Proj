# The event-baseline feeder in the node (P4-A5, node PR 2c, R4.8)

B5, 2026-10-28. A proposal for B1 and B4 to rule on, with what I will build while they do. Nothing here is measured yet; every result will be `simulated`.

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

## Design, if A is ruled

- **Configuration.** A top-level node config array `event_baselines`: `{"asset_id": ..., "params": {...}}`, where `params` is a full `baseline.Params` (C10 has no defaults but the two minima, 14 days and 200 events; "never constants a learner may assume") validated with its own check. The node ships an example block with the values `modules/detection/eventbaseline` tests use, as a starting point, not as a default. An asset in it that no schedule entry or listener can feed is refused at load. The node's quota rules (D4-20) count one baseline record per observing asset.
- **One reader per stream, not per asset.** A Syslog listener's stream carries several assets' events, so the feeder reads each stream once and hands each event to its asset's learner or detector by `source.asset`. An event whose asset is not observing is skipped. An `asset-unresolved` event goes to a site-level counter in status (C10), never to an asset.
- **Received order.** The feeder reads batches from every stream of an asset, merges by `received.utc` (ties by stream, then seq), and passes an event only when it is no later than every stream's low watermark: the least received time of an unread record, or the stream's latest committed time when it has none. Ticks use that watermark and never the wall clock (#303, `TestDetectorTickIsAWatermark`).
- **`AfterFailure`.** From the asset's health events in `platform/health`: a collection failure opens a gap `[first failure, next success)`, and the first successful SER read after it is `AfterFailure` for all its rows, and the learner is told with `Gap`. The gap's bounds come from the health events' received times.
- **`NotCounted`.** The feeder keeps the previous SER read's alignment keys per asset in the snapshot, and applies `PossibleDuplicates` to each read's stored rows. A read is the rows that share one `received.utc` and one `collection.run_id`.
- **Lifecycle, from the chain.** The state is derived from what C5 and C8 hold, as the holds are (`holds.go`): the newest C10 record in `config/<asset>` that no succeeded `config.baseline_acknowledged` of kind `event` names is "awaiting acknowledgement"; the acknowledged one is "active", with the time its acknowledgement entered the chain as `ActiveFrom`. verification.md says the recording is "hashed in the audit chain", and C8 0.6 has no record for it: the C5 record's own hash is the only chain-side evidence until one exists. I propose a C8 info action `config.baseline_recorded` (asset, kind, digest, version, previous) in C8 0.7, written in the same commit step as the C10 record; B3 and B1 decide. A lost snapshot is a re-learn, and the node says so (an alarm, and the re-learn record names the replaced hash in `Previous`).
- **`node.baseline_ack`, event kind.** On acceptance the node holds a baseline of that asset and kind whose stored bytes hash to `baseline_digest`; if not, it refuses and audits. The same gates as #339 apply (taint, key binding, verified payload), and it is a `nodeActKinds` kind with its own part. A configuration-kind acknowledgement is B3's run wiring PR; the two share the relay.
- **Alarms.** `Output.Alarms` become C4 health events through `Alarm.Health`, written to `platform/health` through the node's normal event path (so the C6 forwarder carries them), deduplicated across a restart by `(asset, baseline hash, rule, key, at_utc)` (the replay key in the package doc). The held notice becomes a `HealthAlarmsHeld` event.
- **Bounds.** At most 4096 types per learner, a batch cap per tick, and the feeder runs between runs in the scheduler's goroutine with a time budget, so a flood of events cannot delay a collection run.

## What I build first, in order

1. Config and layout (`event_baselines`, the consumers, the quota count), with tests. No dependence on B4.
2. The merge reader and its watermark, over C5, with tests that delay an Observe past a tick (#303).
3. The lifecycle and `node.baseline_ack` (event), using the learner and detector as they are, with the learner state kept in memory only. Until B4's snapshot API lands, a restart restarts the period, and `otsec health` says so. This slice is not shippable alone, and I will not claim V-M4 on it.
4. The snapshot, the consumers and the restart tests, when B4's API is in.

## Questions

- **B1:** A (snapshots and a required consumer), or another way? Is the order above right?
- **B4:** Can the snapshot API come first, as a small PR? What is the largest snapshot, with the 4096-type ceiling? It sets the checkpoint size, which I would bound in the layout.
- **B1 and B3:** C8 0.6 has no record for "baseline recorded", which verification.md asks for ("recorded once, versioned and hashed in the audit chain"). Add `config.baseline_recorded` in C8 0.7, or accept the C5 record alone? Without it the node can still derive the state, but the chain would not show a recording that was never acknowledged.
