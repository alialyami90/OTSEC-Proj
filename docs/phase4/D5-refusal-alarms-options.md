# The node's refusal alarms for C13 option (b) (options)

**Status: proposed, not approved.** Owner D5. Brief P4-NODE-REFUSE-OPT. D1's approval 7010466389 on #763 makes option (b) of `docs/phase4/D4-c13-forward-read-options.md` conditional on two node changes: condition 1, a refused stored observation that is alarmed and durably counted (D1's 7001264083 on #760, item 4), lands with or before (b)'s code; condition 3, `network-baseline-refused` with the detector off (D1's 7010372954, with D3's three conditions in 7010365557), lands no later than the change that puts a baseline into `detectorConfig`. Under D4-99 the options are settled here first. No code changes in this PR, and no C13 change.

**Evidence class: `desk`.** Read at `main` `5938aec8`: `observeTo`, `observationOf`, `startDetector`, `checkpointDetector`, `raiseDetector`, `DetectorStatus` (`platform/node/netdetector.go`); `tickSensor`, `reportDrops`, `lastDropCounts`, `parseDropCounts` (`platform/node/sensor.go`); `sensorHealth`, `sensorHealthEvent` (`platform/node/sensorceiling.go`); `Status.Alarm`, `Status.Raise`, `Status.add` (`platform/node/status.go`); `Detector.Observe` (`modules/detection/netdetect/detector.go`); `ObservationFromEvent` (`contracts/netobs/observation.go`); the health types in `contracts/event/event.go`; `ClassNetworkObservation` and `AlarmNetworkFull` (`contracts/store/class.go`); `Link.drop` and the `Drop*` reasons (`platform/sensorlink/link.go`). Nothing was run.

Inputs: D5's 7009772447 and 7010354192, D3's 7009793907 and 7010365557, D1's 7010466389 and 7010372954 on #763; D1's 7001264083 on #760.

## 1. What `main` does today

- **A refused stored observation.** `observeTo` calls `observationOf` (`event.Decode`, then `ObservationFromEvent`, which calls `DecodeStored`). On any error it passes `nil` to `Detector.Observe`, which refuses it and still takes its seq. `Observe` also refuses a decoded record of another sensor or with no readable `first_utc`. Each refusal adds 1 to `DetectorStatus.Refused` (`observations_refused`), in process memory only. No alarm is raised, no reason is kept, and nothing is written to the health stream. `Through` moves past the record, and the next checkpoint lets the stream be pruned past it.
- **No reason is classifiable yet.** `DecodeStored` returns plain `*netobs.Error` values. `netobs.ErrLaterMinor` does not exist on `main`; it comes with (b)'s code (condition 2). `ObservationFromEvent` can return a decoded observation together with a `conflict` error; `observeTo` drops it to `nil`.
- **A refused baseline cannot happen yet.** `detectorConfig` sets no `DetectorConfig.Baseline`, so `NewDetector` takes the no-baseline branch.
- **`network-detector-not-restored` repeats.** While `r.detector` is nil, `tickSensor` calls `startDetector` at every tick. When the restore fails, `startDetector` raises not-restored through `Status.Raise` before it tries `NewDetector`. If anything after that fails, the start fails and the next tick raises not-restored again. `Status.add` does not deduplicate, so each repeat takes a slot of the `MaxStatusAlarms` (200) ring. The text "starts again from the oldest retained observation" is false whenever the fresh start then fails. `tickSensor` raises `network-detector-not-started` once per down stretch (`detectorDown`).
- **Node alarms write no health event.** `Status.Alarm` and `Status.Raise` write the status file and the OS log only. Health events come from the store's own alarms (`storeAlarm`, as `store.<code>`) and from the writers that call `health` or `sensorHealth`.
- **The ceiling drop.** The observation stream is pruned only through consumer cursors; `netretain` prunes the alert stream only. When the detector is off its cursor holds, the class fills, and at its quota the store refuses new observations with `CodeQuotaReached`. The link then drops them under `class-full`, counted by reason and asset, written as `intake.drop-counted` by `reportDrops`, and the store raises `network-full` once per fill (#602, D4-76). D3's third condition therefore needs no new code, only a test that shows it with the detector held off (section 6, T9).

## 2. `network-observation-refused`

### 2.1 Reasons

The reason is taken from the first refusal on the record's path, in this order:

| Reason | Where | How the node tells it |
|---|---|---|
| `later-minor` | `observationOf` | `errors.Is(err, netobs.ErrLaterMinor)` (exists only once (b)'s code has merged) |
| `malformed` | `observationOf` | any other error: `event.Decode`, `ObservationFromEvent`'s kind or conflict check, or `DecodeStored` |
| `detector-refused` | `Detector.Observe` | `observationOf` succeeded and `Observe` returned an error |

A record whose seq is at or below `Through` is not a refusal (`Observe` returns nothing).

**What the detail may carry.** A `netobs.Error`'s `Detail` can quote values from the record, and the alarm goes to the OS log, which never holds device or packet text (`Status.Raise`'s rule). So the alarm and the health event carry the reason, the error's `Code` and `Field`, and seq numbers, never `Detail` or the error string.

### 2.2 When it is raised (a real choice)

"Once per run" cannot mean the sensor's `run_id`: a refused record did not decode, so its run is unknown. So "run" here is the node's process run.

- **R1. Once per process run and reason.** An in-memory set of the reasons raised, as `tickSensor` keeps for `sensor-record-refused` (`in.refused`). Every later refusal of that reason only raises the counts. A restart raises it again at the first new refusal. At most three raises per process.
- **R2. Once per stretch.** Raised at the first refusal of a reason, cleared at a checkpoint whose interval saw none of that reason, raised again at the next. It shows a second occurrence weeks later in the same process, but a source that refuses one record every other minute raises up to 30 an hour per reason, up to 90 an hour in all, and fills the 200-slot ring in a few hours.

**Recommendation: R1.** A rollback, the cause of `later-minor`, always restarts the process, so R2 adds nothing for it. For the other two reasons the counts and their health event (section 2.4) show every later occurrence, so R1 loses no information and cannot fill the ring.

### 2.3 What it says

Raised with `Status.Alarm` on the network database, stream the observation stream, as `raiseDetector` does now. One text per reason:

- `later-minor`: "a stored observation was written by a later build (a C13 minor above this build's `<self>`), so this build refused it at judging: the detector did not judge it and raised no network alert for it. Every such record is counted in status (`observations_refused_by`) and on the health stream. First at seq `<n>`. Remedy: move this node forward to a build that reads it; records already passed are not judged again."
- `malformed`: "a stored observation did not decode (`<code>` at `<field>`), so the detector did not judge it and raised no network alert for it. Every such record is counted. First at seq `<n>`."
- `detector-refused`: "the detector refused a stored observation (`<another sensor's, or no readable time>`), so it raised no network alert for it. Every such record is counted. First at seq `<n>`."

### 2.4 The durable counts (a real choice)

All three options keep the counts by reason in memory, show them in status, and write them as one health event. They differ in when the event is written and how a start reads it back.

- **A. The B3 drop-count pattern (#597), as first proposed in 7009772447.** Written when the counts change, at most once every `SensorDropReportEvery` (1 minute) unless final, by the `reportDrops` path, and read back at start by the `lastDropCounts` scan. Errors: a crash loses the refusals after the last write that sit before the last checkpoint (they are not replayed), and counts twice those that sit after the last checkpoint and were already written (the replay refuses them again). A start whose checkpoint did not restore replays every retained observation, so it recounts every retained refused record unless that start also begins the counts again.
- **B. Written at each checkpoint, carrying `through` (recommended).** After each detector checkpoint commits (`checkpointDetector`, from `tickDetector` at the steps Tick asks for, at most once a `TickInterval` (60 s), and at the stop), the node writes the counts event if the counts changed since the last one written, with `through` set to the checkpoint's `Through`. At start:
  - if the detector restores at `Through` T and the newest counts event has `through` = T, the counts are exact: the replay starts after T, so nothing is counted twice or missed;
  - if the newest event's `through` is below T (the process stopped between the checkpoint and the event, the write failed, or the ceiling held it), the counts are restored and status marks them a lower bound, with the seq range they may miss (`observations_refused_exact: false`, `observations_refused_unsure: "<a>-<b>"`). A loss is never hidden: the node knows the range it cannot vouch for;
  - if the checkpoint did not restore, the detector starts at the oldest retained observation and the counts begin again (`since` = now, `through` = 0). The earlier event stays on the health stream as the record of the earlier counts, and the replay counts each retained refused record once.
  A failed or held write is tried again at the next checkpoint step, as `reportDrops` retries. It costs the same writes as A and one detail more.
- **C. Counts in the detector checkpoint.** Exact and atomic, but it is a new `otsec.netcheckpoint` key: a C13 minor, with CH-35's bridge items 1 and 2 on a rollback (7009772447). The brief excludes a C13 change. Not proposed.

**Recommendation: B.** It is exact on a clean stop and on a crash at any point except between a checkpoint and its counts event, and in that case status says which seqs the counts may miss. A errs in both directions after a crash and needs B's fresh-start rule anyway.

**The health event.** No existing type fits. `intake.drop-counted` is for records that were not stored; a refused observation is stored and not judged, and reading refusals as drops would change what every reader of that type sums. So the event needs a new C4 health type (section 7). Proposed name `detector.observation-refused` (D4 names it). Details, every value a decimal or a node-held name: `stream`, `since`, `through`, `count`, `reason.<r>` for each reason above 0, and `first_seq.<r>` and `last_seq.<r>`, the lowest and highest seq refused for that reason since `since`. The two seq keys are the durable answer to "which ones" once the records are pruned past; they are cheap (six keys at most) and can be struck if the reviewers find them unnecessary. Like every sensor health event it is written by `sensorHealth`, under the platform class's ceiling, and a held write is counted in `health_held`.

**Status.** `observations_refused` stays the total, so a reader of `otsec.nodestatus/0.1` keeps working. Added: `observations_refused_by` (by reason), `observations_refused_since`, `observations_refused_exact` and `observations_refused_unsure`.

## 3. `network-baseline-refused`

### 3.1 The design

- **The cause.** `NewDetector` (D4's code, the D4 row with condition 3 in the forward-read note's section 4) returns an error the node tests with `errors.As` (or `errors.Is` on a sentinel), carrying the baseline's hash, its stamped `schema`, and the cause: `later-minor` (stamped above `baselineSelf`), `not-canonical`, or `malformed`. `RestoreDetector` calls `NewDetector`, so the same error reaches the node from a restore too.
- **Raised once per down stretch.** In `startDetector`'s caller, `tickSensor`: when the start fails with that error, the node raises `network-baseline-refused` once, keeps it raised while the start keeps failing for that cause, and clears it when the detector starts. `network-detector-not-started` is not raised for that cause, and `network-detector-not-restored` is not raised (section 4 places that raise after a successful start). One cause, one alarm.
- **The detector stays off** (D1's 7010372954): `r.detector` stays nil, `Through` does not move, and the observation stream is not pruned. The baseline-free rules do not run.
- **What it says:** "the approved network baseline `<hash>` (`<schema>`) was refused by this build (`<written by a later netbaseline minor | not canonical | malformed>`), so the network detector is off and no network alert is raised. The observation stream is kept for judging and grows until its class quota, past which new observations are dropped and counted (`class-full`, `network-full`). Remedy: approve a baseline this build reads, or move this node forward to a build that reads this one."
- **Its health event.** One event at the raise, type `detector.baseline-refused` (D4 names it), details `hash`, `schema`, `cause`. Written by `sensorHealth`; a held or failed write is tried again at each tick step while the alarm stands, and not after it clears.
- **D3's third condition** (the ceiling drop is the existing counted, alarmed drop): it holds on `main` today (section 1); T9 shows it.

### 3.2 When it lands (a real choice)

- **L1. With condition 1's change, before any baseline is wired.** The tests need a baseline in `detectorConfig`, so this adds a test-only way to set one, and D4's classified error has to exist first.
- **L2. In the change that wires the approved baseline into `detectorConfig` (recommended).** That change brings the baseline, D4's classification and the alarm together, and its tests use the real path. It meets condition 3's "no later than". Nothing reaches the refusal before it.

**Recommendation: L2,** with the not-restored fix of section 4 moved forward into condition 1's change, since that defect is live on `main` for any start that fails after a failed restore.

## 4. `network-detector-not-restored`: the repeat and the text

**Fix:** keep the restore's error in `startDetector` and raise not-restored only after the start has succeeded, after its last step that can fail, as `AlarmAlertUnreadable` is raised now (D6's N4 on #682). Then:

- a start that fails raises nothing from `startDetector`; `tickSensor` raises not-started once, and its text adds "the stored checkpoint did not restore either: `<error>`" when the restore failed too;
- the start that succeeds raises not-restored once, and its text is then true: "the detector's checkpoint did not restore, so the detector started again from the oldest retained observation: `<error>`";
- a start that fails for the baseline raises only `network-baseline-refused` (section 3).

The `<error>` here is a restore error (`RestoreDetector`'s or the alert read's), which names checkpoint fields and seqs, not record text; the change checks that before it keeps the error in the alarm. This lands with condition 1's change.

## 5. The health stream's budget

On `main` both new events go through `sensorHealth`, under the platform class's ceiling, as `reportDrops` does. `detector.observation-refused` is written at most once per checkpoint and only when the counts changed; `detector.baseline-refused` once per down stretch. When the CH-45 pool is wired (`platform/sensorlink/health.go`, not wired under F-027's gate), both names join the pool's list in `D5-sensor-node.md` section 1.9 item 5 (each name at most 4 an hour), so the sensor's share S is unchanged. Under B, a counts event the pool holds back leaves the counts a lower bound with the range stated (section 2.4) until it is written.

## 6. Tests

Each test names its control; the mutant is the change that must make it fail. All in `platform/node` unless stated.

- **T1 (with (b)'s code).** A replayed stored observation stamped one minor above `self` (computed from `self`, self-check item 11) is refused under `later-minor`, raises `network-observation-refused` once, writes its counts event, and its count is exact after a clean restart. *Mutant:* the alarm removed. *Control:* the same record at `self` is judged and not counted.
- **T2.** A stored record whose `netobs` does not decode is refused under `malformed`. A marker string placed in the record's offending field appears in neither the status file nor the OS log. *Control:* the valid record is judged. *Mutant:* the error string put in the detail, which shows the marker.
- **T3.** A stored observation of another sensor is refused under `detector-refused`. *Control:* the node's sensor's record is judged.
- **T4.** Five refusals of one reason raise one alarm; three reasons raise three. *Mutant:* a raise per record, which raises five.
- **T5 (B's exactness).** A clean stop and start restores exact counts and `through`. A seam that fails the counts write after a checkpoint commits, then a restart, gives the counts as a lower bound with the range between the last event's `through` and the restored `Through`. *Mutant:* the start ignores `through`, which reports them exact.
- **T6.** A checkpoint that does not restore starts the counts again, and each retained refused record is counted once. *Control:* the same store with a restorable checkpoint keeps the earlier counts.
- **T7 (section 4).** A restore failure followed by a failing fresh start for three ticks raises no not-restored and one not-started; the start that then succeeds raises exactly one not-restored. *Mutant:* the raise put back before `NewDetector`, which raises three.
- **T8 (with the baseline's wiring, L2).** A baseline stamped above `baselineSelf` raises `network-baseline-refused` once over several ticks, with its health event naming hash, schema and cause; no not-started and no not-restored; `Through` stays and nothing is pruned. Replacing it with a baseline the build reads starts the detector and clears the alarm. *Control:* a readable baseline from the start raises nothing. *Mutant:* the baseline-free rules run on refusal, which moves `Through`.
- **T9 (D3's third condition, with T8).** With the detector held off and a small observation quota, records past the quota are dropped under `class-full`, counted, written as `intake.drop-counted`, and `network-full` is raised once. *Control:* the detector on, the stream pruned, nothing dropped.
- **T10.** Each new event, at its largest (every reason, 20-digit values), with the longest node ID, renders for a default Syslog target within three quarters of its 2,048 octets, as `TestSensorDropEventFits` pins for `intake.drop-counted`.
- **Link (with (b)'s code), `platform/sensorlink` and node:** a held record of a later minor is committed as held and then refused at judging under `later-minor`. *Control:* a held record at `self` is judged.
- **Changed:** `TestDetectorBridgeLaterRecords`'s observation leg changes from "taken and not refused" to "refused under `later-minor`" when (b)'s code merges; its alert leg (`AlertsUnreadable == 0`) stays.

## 7. Contract and document text

- **C4 (`contracts/event`, D4's, through D1):** the two health types of sections 2.4 and 3.1 added to the open list of platform event types, which "later minors may add". That is a C4 minor, with no field change. D4 judges whether it meets the open C4 `event.Decode` item (D3's F4 on #763); it adds no field read on the network-observation or sensor-health paths. A type known only to the node would be an unshared representation of a shared concept (CLAUDE.md section 5.4), so this note does not propose writing one without C4.
- **C5:** none. No class, alarm code, hold code or store format changes; `network-full` and `class-full` are used as they are.
- **C8:** none. A refusal is node state, not an act by a person; the baseline's approval is already audited where it happens.
- **C13:** none, as the brief requires. (b)'s `ErrLaterMinor` is condition 2's, D4's.
- **`docs/phase4/D5-sensor-node.md` (mine), in the code changes:** the alarm list gains the two alarms; section 1.9 item 5's pool list gains the two event names; section 9's accepted limits gain "after a restart a refusal alarm is raised again at the first new refusal" and B's lower-bound case.

## 8. Limits

- A refused record is not judged again. Moving forward to a build that reads it does not replay records the detector has passed, and they are pruned at the next checkpoint. The count and the seq range are what remains. Holding them from pruning would be a new store mechanism and is not proposed.
- The counts event can be held by the platform ceiling or the pool; the counts are then a stated lower bound until it is written.
- `later-minor` and T1 need (b)'s `ErrLaterMinor`. If condition 1's change lands first, until (b) merges a later-minor record still reads forward, as on `main`.

## 9. Recommendation and order

R1, B and L2. Order:

1. **Condition 1's change (D5), with or before (b)'s code:** sections 2 and 4, T2 to T7 and T10, the C4 types (D4, through D1) merged first or in step. T1, the link test and the change to `TestDetectorBridgeLaterRecords` land with (b)'s code.
2. **Condition 3's change:** section 3 with T8 and T9, in the change that wires the approved baseline into `detectorConfig`, after D4's classified error.
