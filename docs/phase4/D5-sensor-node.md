# D5: the node's side of the passive network sensor (P4-4-A5, revised for option (b) under P4-4-L3)

D5 wrote this note on 2026-11-07 for brief P4-4-A5. **D5 revised it on 2026-11-11 for brief P4-4-L3** (`docs/agent-handoffs.md`, "Phase 4 item 4, second part", D4-86), after the owner chose option (b) (D4-85): the sensor is a separate Linux host at each site, and the node dials it.

- **Part 1** is the node's side under option (b), a design for D1's approval. Its requirements are D3's rules (`docs/phase4/D3-sensor-link.md`, SL-1 to SL-29 and SL-R1 to SL-R8), the reviews on #624, and the points D1 carried from the fresh D6 review of `f9d3a1d1`. Each item names the code on `main` it changes and the test that would show it.
- **Part 2** is the note of 2026-11-07. The sections written for a sensor on the node, over a named pipe with a service SID, are marked **History**: they apply again only if option (a) or (c) is reopened. The sections that still hold say what option (b) changes in them.

**Evidence.** Everything in this note is `desk`. A statement about what exists names the file and function it was read from, on `main` at `551b03dd`. Every other statement is a requirement and is **not built**. No test was run for this revision, nothing was installed, and no device or network was contacted. Nothing is `hardware-verified`.

# Part 1: the node's side under option (b) (P4-4-L3)

## 1.0 What the node has today (`desk`, `551b03dd`)

- `Runtime.ServeSensor(ctx, io.Reader)` (`platform/node/sensor.go`) reads any byte stream in C13 0.1's framing into one `sensorlink.Link`. It takes no peer identity and cannot write back, and the node has one intake (`Runtime.sensor`). Only tests call it: `platform/node/*_test.go`, and D6's `tests/security/sensor_status_boundary_d6_test.go`, `sensor_unreachable_d6_test.go` and `detector_before_clock_d6_test.go`.
- The link refuses a record under another `sensor_id` (`RefusedSensorID`) and a seq at or below the run's last (`Link.takeSeq`). Its run and seq live in memory only (`Stats.LastCommittedSeq`), so nothing of them survives a restart. There is no hello and no acknowledgement (`platform/sensorlink/link.go`).
- `network_sensor` names one sensor (`NetworkSensor.SensorID`, `platform/node/netsensor.go`), and its streams are in one database, `network` (`NetworkDB`).
- **A fault in the intake's start fails the node's start.** `Start` returns `node: the sensor's intake: ...` when `startSensor` fails (`platform/node/runtime.go`), and `startSensor` fails when the hold's records can't be read (`loadIntake`) or a release can't be recovered (`Link.RecoverHold`).
- **The sensor's periodic work runs inside `Runtime.Tick`** (`tickSensor`), on the goroutine that also resumes blocked and drain-only databases, the evidence database among them, and prunes (`runtime.go`, `service.go`). The detector's drive reads up to the barrier with no bound per tick (`netdetector.go`, `observeTo`).
- **The scheduler's run path takes the link's lock.** `dispatchHold`, `resultHold` and `abandonHold` (`platform/node/netintake.go`) call `Link.Dispatch`, `Result` and `Abandon`, which take `Link.cmu` (`platform/sensorlink/hold.go`). The read loop holds `cmu` through each commit to the network database and each save of a hold record to the configuration database (`Link.observe`).
- **The platform class can stop SER collection.** The health stream is in the evidence database (`layout.go`) with class `platform`, whose full action is refuse-new (`contracts/store/class.go`). While an entry's `collection.missed` can't be written, its runs are not sent (`missed.go` `heldMissed`, `schedule.go` `runOnce`). The sensor writes to that class today: `intake.drop-counted`, at most once a minute for each of its two classes (`sensor.go` `reportDrops`), and the network database's store alarms, queued as health events (`runtime.go` `storeAlarm`, `Tick`).
- No `sensor.coverage-gap` event is built: no file on `main` names it. §1 of Part 2 proposed it.
- The node configuration is read at start only. `reload` reloads the suspensions and halted assets, nothing else (`reload.go`).
- The node does not apply `node.network_baseline_ack`. `modules/security/netack` holds its checks, and no file under `platform/` or `cmd/` outside the tests imports it. `relayKinds` does not list the kind (`adminrelay.go`), and nothing on the node runs the network learner, so no draft is ever recorded and `netack.Adopt` would refuse every acknowledgement (`network_draft_not_latest`).

## 1.1 The dialer and the firewall rule (brief item 1)

**Requirement, not built:** a new file `platform/sensorlink/dial.go`, with one dialer per enrolled sensor. The node's sensor manager (§1.8, item 2) starts it after `Start` returns, never inside `Start`.

| Setting | Value | Rule |
| --- | --- | --- |
| Versions | `MinVersion` and `MaxVersion` both TLS 1.3 | SL-12 |
| Resumption | `SessionTicketsDisabled`, and no `ClientSessionCache`, so every handshake is a full one. Go's client sends no early data (an assumption, §1.13) | SL-12 |
| Server check | no system roots and no name check. `VerifyConnection` takes the leaf's `SubjectPublicKeyInfo`, computes its pin, and accepts only the pin of the enrolment in force at that moment, read through an atomic pointer that a revocation replaces before it closes the link (§1.3) | SL-2, SL-12, SL-R2 |
| Client certificate | `GetClientCertificate` returns a self-signed certificate made in memory at each node start, whose key is the node's link key, a `crypto.Signer` from the key register. Nothing is written to disk. Its dates mean nothing: the node enforces the enrolment's `not_after` (SL-8) | SL-2 |
| Protocol name | ALPN `otsec.netobs/0.2` on both ends, refused if it isn't negotiated, so the link agent's port can't be mistaken for another TLS service (asked of C13 0.2) | SL-19 |
| Timeouts | TCP connect 5 s; handshake 10 s; read deadline 30 s, three missed heartbeats; write deadline 10 s for each node message | SL-12, SL-20 |
| Back-off | 1 s, doubling to 60 s, with ±20 % jitter. It resets after a connection whose hello was accepted and which lasted 60 s | SL-20 |
| Connections | At most one per sensor. The dialer is the only caller, and the intake refuses a second concurrent connection for the same sensor (`second-connection`, counted) | SL-12 |
| Memory | One frame at a time, at most `MaxChannelFrame` (64 KiB) and its decoded record, as `Link.Serve` reads now | SL-20 |
| When it dials | Only while §1.2's configuration equals the live enrolment, the enrolment is not revoked, not fork-held and not expired, and the sensor's state is known (§1.3). Otherwise it does not dial, and the alarm says why | SL-4, SL-9 |

- **The link key** is a `tls-key` entry of the node key register used for sensor links only. Today a `tls-key` stays `pending` until a CA-issued chain is installed (`modules/security/nodekey/register.go`, `StatePending`, `Install`). A sensor-link key has no CA. **This needs a change in D3's package**: a `tls-key` entry marked for sensor links, active with no certificate, which `LoadCertificate` refuses, so a forward target or listener can't use it; and a function that returns its signer and pin, which only `platform/sensorlink` imports (an import test). The pin goes in status, for the administrator to read (SL-5 step 2).
- **`ServeSensor` changes shape.** It becomes `ServeSensor(ctx, peer sensorlink.Peer, conn io.ReadWriter)`: `peer` is the authenticated `sensor_id`, generation and pin from the handshake, and the link that serves it is chosen from `peer`, never from a record (SL-10). D6's tests that call today's signature move with the third part's brief.
- **The firewall rule.** `platform/winsvc` `Install` adds one rule today, which blocks the node service's outbound TCP to port 23 (`install_windows.go`). **Requirement:** a subcommand `otsec install-sensor-rules -config <file>` in `cmd/otsec`, which an administrator runs elevated after each enrolment. It adds, for each configured sensor, a rule named `OTSEC node to sensor <sensor_id>`: outbound, allow, service `otsec-node`, TCP, that sensor's address and port. The node never changes a firewall rule itself (CLAUDE.md §10). **Assumption, not read:** that Windows' default outbound policy is allow, so the rule matters only where a site blocks outbound by default. The guard that holds on every site is SL-9: the node dials only the enrolled address. No inbound rule is added and no listener is opened (SL-18).
- **Tests.** In `platform/sensorlink`, over loopback TLS with test keys: `TestDialRefusesTLS12`; `TestDialNoResumption`, whose control is a client session cache, which makes the second connection resume; `TestDialRefusesOtherPin`, whose control is a `VerifyConnection` that accepts any key; `TestDialPinReadAtHandshake`, where the enrolment changes between two dials; `TestDialHandshakeStall`, a peer that accepts TCP and sends nothing, closed by the handshake timeout; `TestDialBackoff` on the test clock; `TestOneConnectionPerSensor`; and an import test for the link key's signer. On the rig: SL-T3, SL-T7, SL-T8 and SL-T11. The firewall rule is read back in the dispatched Windows workflow (`a5-windows-experiments.yml`), where a hosted runner allows it, and is `unknown` where it doesn't.

## 1.2 The `network_sensor` configuration, and one sensor or two (brief item 2)

**Requirement, not built.** The section keeps its node-wide fields (`evidence_class`, `outage_hours`, `alert_retention_days`, `node_addresses`, `node_macs`, `node_vlans`) and gains:

- `link_key_ref`: the node's link key in the key register (§1.1). One key for the node, as SL-R8 assumes.
- `sensors`: one or two entries, each with `sensor_id`, `address` (an IP literal) and `port`, and `sensor_spki` (the pin). The pin is the **trust anchor**, since there is no CA (SL-2). The link key is the **credential**. The **permitted peer** is the three together, which must equal the live enrolment (SL-9).
- `retired`: at most four `sensor_id`s whose streams are kept until pruned (§1.6).

The top-level `sensor_id` is refused, with a message that names `sensors`. Every check on the section's shape stays a load failure, as D3 asks: a duplicate ID, address or pin, an address that isn't an IP literal, an ID both in `sensors` and in `retired`. **A mismatch with the enrolment is never a load failure.** It is an alarm at run time (§1.3), so a sensor's paperwork can't stop SER or Syslog collection (SL-9, SL-20). Code: `NetworkSensor` and `checkNetworkSensor` (`netsensor.go`), `networkLayout`, `Config.Consumers` (`layout.go`), and every reader of `NetworkSensor.SensorID`.

**One sensor or two.** A PRP network has two LANs. With one host on both, the capture stage discards duplicates (SL-3). With two hosts, nothing sees both copies, so the node gets each flow twice under two `sensor_id`s (O-12). What each choice costs on the node:

| | One sensor | Two sensors (D5's proposal: `MaxSensors` = 2) |
| --- | --- | --- |
| Intake | One link and one hold, as built | A link and a hold for each. `dispatchHold`, `resultHold` and `abandonHold` call each sensor's link, so each LAN's sensor ties the run. `collection.run` carries `after_seq.<sensor_id>` and `open_flow.<sensor_id>`, and `runSessionOf` reads its own sensor's keys, and the plain keys of a 0.1 record as the single sensor's. The handover barrier (`intakeRecords`) is kept for each sensor |
| Store | One database | **A database for each sensor, `network-<sensor_id>`.** A quota is per class in its database, so this keeps a flood seen by one sensor from dropping the other's records. It costs a second set of network quotas in the volume rule. The other way, both sensors in one database, costs no volume, and one sensor's flood then drops the other's records. Neither touches SER or Syslog. The constant `NetworkDB` and the places that test for it change (`commitcap.go`, `runtime.go` `startDB`'s `WallMark`, `netretention.go`, `sensor.go`, `netdetector.go`) |
| Baseline and detector | One baseline, one acknowledgement, one detector | One of each for each sensor, on its own `netbaseline/<sensor_id>` stream as now. A person signs an acknowledgement for each. On PRP the two baselines are nearly the same, and traffic that is on both LANs alerts twice, once from each sensor. **No merge across sensors is designed:** it would compare frames across two streams, and nothing yet shows it is needed. Traffic on one LAN only alerts from that LAN's sensor, which is useful in itself |
| Status | One `sensor` section | A list |

With two sensors the node's work doubles, and nothing else changes. **Whether a site gets a second host is the owner's choice** (O-12, and their open answer on whether the station LAN is PRP, D4-86). D1 also chooses whether the third part builds two sensors now, or the list shape with one entry and the second later.

**Tests.** `TestNetworkSensorsShape`: none, three, or a duplicate ID, address or pin refused, and the old top-level `sensor_id` refused naming `sensors`. `TestTwoSensorsSeparateDatabases`: sensor A's observation class filled, B's records still commit; its control is both sensors in one database, where B's records drop. `TestCollectionRunAfterSeqPerSensor`, and `TestRunSessionReadsPlainAfterSeq` for a 0.1 record. In the new package named at the end of §1.8.

## 1.3 Enrolment, revocation and expiry (brief item 3)

**Where the state lives.** D3 asks that the live enrolments and the revoked pins never depend on the audit stream alone, which is pruned (SL-6). The D5 review on #624 proposed a configuration-class document "as suspensions are". On `main` the suspensions are not one: they are a checkpoint file, `suspensions.json` in the store directory, folded from the audit stream, with the C5 consumer `node-suspensions` holding the audit stream's prune point at the file's `through_seq` (`suspend.go`, `loadSuspensions`, `pruneConsumers`). **This design follows that pattern, and needs no C5 change:**

- **`sensors.json`** in the store directory, schema `otsec.node-sensors/0.1`, written whole to a temporary file and renamed. It holds `through_seq`; for each `sensor_id` its generation, pin, address, the node's pin, `not_after`, the decision's `decision_seq` and payload hash, its state (`live`, `revoked` or `fork-held`) and the highest generation, run counter and `run_id` accepted (§1.4); the revoked pins, never removed; the revocation records owed; and the last `sensor.link_refused` time for each sensor and reason (§1.8).
- **A consumer `node-sensors`** on the audit stream, added by `pruneConsumers` beside `node-suspensions` and `node-holds`, so the audit stream is never pruned past the file. A pruned audit stream then never loses a live enrolment and never brings back a revoked pin.
- **Its own fold.** `foldSensors`, in a new file `platform/node/sensorstate.go`, reads the audit stream from the file's `through_seq`, and runs in the sensor manager, never in the scheduler's `fold`. The reason is in `loadSuspensions`: an error in the suspension fold holds every run on the node (`asset-suspensions-unknown`). A sensor record that doesn't parse, or a fold that fails, must make only the sensor's state unknown: nothing dials, `sensor-state-unknown` is raised, and collection goes on.
- **With the file lost and the stream pruned past what it needs,** the state is unknown and nothing dials. An administrator's new enrolment, at a generation above every one still in the chain, is then applied, and `sensor.enrolled` records the previous state as unknown. **Limit:** a revoked pin that only the lost file held could be enrolled again by a new signature.

**Enrolment** (SL-5 step 5, SL-6). `relayKinds` and `nodeActKinds` gain `node.sensor_enrol` and `node.sensor_revoke` (`adminrelay.go`), and `applyAdminPart` gains two cases, bound to the install key as `node.baseline_ack` is (`admin_actions.go`). Each case calls the sensor manager. The manager:

1. writes `policy.apply` with `admin_keys` first when the acceptance names a new key set (C8 0.12's rule, `netack.NeedsGrantRecord`);
2. checks SL-6's list: the node's pin is its link key's; the generation is one above the last, or 1; the pin is neither revoked nor fork-held; `not_after` is at most 366 days after `issued_at`. A failed check writes `sensor.enrolled` with outcome `denied` and its reason, and changes nothing;
3. writes `sensor.enrolled` with `c5.AuditBeforeAct`, and applies nothing if that write fails (the part stays pending and is tried again);
4. applies it in memory, writes `sensors.json`, and starts the dialer if the configuration matches. A mismatch raises `sensor-not-enrolled` (D3's draft name, which this note keeps), and dials nothing.

**Revocation** (SL-R2, SL-R3). Once the collector's acceptance is folded:

1. mark the pin revoked in memory and write `sensors.json`;
2. close the connection and stop the dialer. A dial already in its handshake fails at `VerifyConnection`, which reads the revoked state;
3. release every run that sensor's hold still holds: tied where its result came, untied otherwise, each in one release (`Link.release`), so no held record is left;
4. take each stream's `through_seq` as its last committed seq;
5. write C8 `sensor.revoked`, with `through_seq` for the observation and alert streams;
6. commit a health event `sensor.revoked` to the health stream, not to the alert stream.

- If step 1 fails, the dialer stays off for the rest of the run and `sensor-state-not-durable` is raised. At the next start the fold derives the revocation from the decision in the chain. **That needs the relayed `collector.request` record to name the target** (`relayRecord`, `adminrelay.go`, as it already does for an asset clear): asked of C8 0.13 (§1.10).
- If step 5 fails, the link stays closed, the record is owed in `sensors.json` and in status, and the manager writes it once when the audit chain takes writes again.
- **How soon "at once" is.** `relayAdmin` runs between runs, never during one, every `RelayEverySeconds` (15 s), and a run lasts at most `MaxDeadlineMS` (600 s) (`adminrelay.go`, `schedule.go` `Run`, `contracts/adapter`). So a revocation is applied within about 15 s when no run is in progress, and at worst about 615 s after it is signed. **That pulls against SL-R2's "at once". D1 chooses:** (a) accept the bound, with the local stop below as the fast path; or (b) relay the two sensor kinds from the sensor manager as well, which needs the collector's pipe to take a second client while a run is in progress. Whether it does is `unknown`: not read for this note.
- **The local stop** (SL-9, SL-R2): since the configuration is read at start only, it is "edit or remove the entry, and restart the node service". It needs no collector and no audit write. The restart pauses collection for the length of a start. D1 may prefer a stop file in `admin_dir` read by the manager every 15 s, which needs no restart and is new code. D5 recommends the restart: nothing new to build.

**Expiry** (SL-8). `sensor-enrolment-expiring` from `CertWarning` (30 days, `certperiod.go`) before `not_after`, repeated hourly in status (HR-13's precedent). At `not_after`, `sensor-enrolment-expired`: a running link is not cut, and the next dial is refused, which writes `sensor.link_refused` with reason `expired` under the time cap (§1.8). Each stretch gives one health event.

**Tests**, in the new package named at the end of §1.8, on the test clock: `TestSensorEnrolApplied`; `TestSensorEnrolDenied` for each of `generation`, `revoked-key`, `forked-key`, `node-key` and `not-after`; `TestSensorEnrolAuditFirst`, whose control applies before the audit write and so applies with the write failing; `TestSensorRevokeClosesFirst`, with the audit write made to fail: the link closes, and the record is owed and written once; `TestSensorRevokeHeldCommitted`: records held at the revocation are at or below `through_seq`; `TestSensorStateSurvivesPrune`, with the audit stream pruned: a revoked pin is still refused, and the control, with the consumer removed, enrols it again; `TestSensorFoldErrorKeepsCollection`: a sensor record that doesn't parse leaves runs going, and the control, the sensor fold joined to the suspension fold, holds every run; `TestSensorExpiry`. On the rig: SL-T4, SL-T5 and SL-T10, with the node killed between the close and the audit write, and SL-T5's start leg with an expired, a revoked and a fork-held enrolment: the node starts, collects SER and Syslog, and raises the alarm (D6 on #624). SL-T20's node leg: after the node's link key is replaced, an enrolment that names the old pin is `denied` (`node-key`) and nothing dials.

## 1.4 Replay, resume and the acknowledgement (from SL-13 to SL-16)

**The position.** `otsec.sensorpos/0.1`: the generation, the run counter, the `run_id` and a seq, at most `MaxLinkCursorBytes` (160) bytes. **Requirement, not built:** the node keeps it as the observation stream's source cursor, which C5 already has: committed in the same transaction as each observation (`Record.SourceCursor`, `contracts/store/commit.go`), and on its own with `store.DB.SaveSourceCursor` (`platform/store/outbox.go`, which is not part of C5) when no record carries it. The cursor written is always the link's position at that moment, never the committed record's own seq, so a release that commits older held records never moves it back.

- **At an accepted hello**, the position for the new run is saved with `SaveSourceCursor` before the hello is accepted, and the run is written to `sensors.json` too. A save that fails closes the connection, is counted, and raises `sensor-position-not-saved`. At start the node takes the higher of the two copies. Two copies with one run counter and two `run_id`s are a fork (`fork-held`).
- **The hello checks** are SL-14's table, from the position: `run-regressed`, `run-forked` and `binding`. Each closes the connection and writes `sensor.link_refused` under the cap (§1.8). `run-forked` also writes `fork-held` to `sensors.json` and stops the dialer until a new enrolment with a new key, or a revocation (SL-16).
- **The acknowledgement** names the run and `durable_through`: the highest seq of the run such that every record at or below it is committed, held by the intake hold (its save has returned), or dropped or refused with the position saved. It is sent at most once a second or every 256 records, after the save, never before. Its only effect at the sensor is the trim (SL-15, SL-19). A dropped or refused tail moves the position by `SaveSourceCursor`, at most once a second.
- **Resume.** After a restart the node's hello carries the higher of the source cursor's seq and the highest seq the restored hold holds for that run. A resent record at or below it is a duplicate: dropped, counted as `duplicates`, never stored twice. A gap is counted as today (`SeqGaps`). A gap the sensor does not declare (C13 0.2's evicted-record counter) raises `sensor-gap-undeclared` once a stretch (SL-14).
- **Room in the record.** The cursor counts in `Record.Bytes`. C13 §10 pins the worst stored observation at about 34 KiB of the 64 KiB cap, so 160 bytes fit, and `TestWorstStoredObservationFits` adds them.
- **Tests**, in `platform/sensorlink`: `TestHelloRunRegressed`, `TestHelloRunForked`, `TestHelloBinding`; `TestPositionSavedBeforeHello`, whose control saves after accepting and, with a kill between, sees a fork at the next start; `TestResumeNoDuplicate`, cut after a commit and before the acknowledgement; `TestAckOnlyDurable`, whose control acknowledges on receipt and, after a kill, has acknowledged a record that is not stored; `TestPositionMonotoneOnRelease`. On the rig, SL-T9 (a) to (k), and (g) with the fork hold after a node restart (D6 on #624).

## 1.5 Clock skew (brief item 4)

**Why it matters** (`desk`). The hold ties a flow whose start, on the sensor's clock, falls within the session's start and end, on the node host's clock, widened by `g` = `DefaultTieGraceS`, 30 s (`hold.go` `Result`). The detector's clock is the latest `first_utc` it has read, the sensor's clock, and it judges a session once that clock passes its end plus `g` (`netdetect` `Observe`, `judge`). Skew moves both.

**The measure.** At each accepted heartbeat, and at the hello, the node takes `o` = its wall time at receipt minus the sensor's send time. C13 0.2 must stamp that time when the record is written to the connection, not when it was queued (§1.10). So `o` is the clock difference plus the delay, and the delay is never negative. The estimate `E` is the smallest `o` of the last 30 heartbeats, five minutes: the least delayed sample, as NTP takes its least delayed one.

**The bound: |E| at most 5 s.** `sensor-clock-skew` is raised above 5 s and cleared at 4 s or less, so an estimate near the line does not flap. The reasons:

- 5 s is a sixth of `g`, and leaves 25 s of `g` for what it is for: the time between the collector's recorded start and its first frame, and the run's own timing.
- A site clock under NTP on a LAN keeps well within a second, so 5 s is a fault, not jitter.
- R6.4's latency is measured on one host's clock in the timed replay (D6's plan §5), so the bound does not touch it.

**Past the bound** (SL-17):

1. The alarm is in status, repeated hourly, and one health event is written for the stretch.
2. **No tie is made.** `Dispatch` holds nothing for that sensor, every run it holds gives way untied at the onset (as `giveWay` does), and the late index (§1.6) ties nothing.
3. **The alerts are aggregated.** Observations committed while skewed carry a node mark, and `collection.run` of a session ended while skewed carries `skewed`. The detector puts their `own-session-unseen` and `own-session-outside-record` alerts under one key for each rule and sensor, `clock-skew`, instead of one for each asset. With C13 §7.3's coalescing that is at most 2 records a window for each rule: 4 records every 300 s, 48 an hour for each sensor, whatever the schedule. Without it, with 256 run endpoints (`MaxDetectorEndpoints`), it would be up to 1,024 records a window. The mark and the key are D4's to add (asked of C13 0.2, §1.10).
4. **Nothing is suppressed.** Every flow and session is judged, and every alert names the skew alarm as its cause.

While skewed, comparisons against the node's times use the sensor's time less `E`. Before the first estimate, which the hello gives, the hold works as today.

**Tests.** `TestSkewEstimateTakesLeastDelay`, with synthetic delays; `TestSkewAlarmHysteresis` (5 s and 4 s); `TestSkewTiesNothing`, whose control makes the tie, so the flow commits tied; and D4's `TestSkewAlertsAggregated`: 50 sessions while skewed give at most 4 records a window, where the control, keyed by asset, gives at least 50. On the rig: the sensor's clock offset by 10 s raises the alarm within a minute of the hello (the gate's skew line).

## 1.6 Records that arrive late after an outage (brief item 5)

**What happens today** (`desk`). The hold watches a run's endpoint from `Dispatch` until `Result`, `Abandon` or its deadline (`hold.go`). While the link is down nothing is held, so `Result` releases at once with `after_seq` the head. When the backlog arrives, the session's own records find no holding run (`runFor`) and no open entry, and commit untied (`Link.observe`, `commitOne`). An untied record never marks its session seen (`netdetect` `track`). So when the backlog moves the detector's clock past the session's end plus `g`, the session raises `own-session-unseen`, and each of its flows raises `own-session-outside-record`. **Both are false.**

**Requirement, not built: part (e) of the hold, the late index.** For each sensor, the node keeps the released sessions of the last `outage_hours`, the same planned outage that sizes the unresolved budget: invocation, asset, endpoint, transport, local address, connected, start and end.

- A record that reaches neither a holding run nor the open table, whose key and start (sensor time less `E`) match an indexed session under `Result`'s rules (the 5-tuple for a 0.9 result, the window for a 0.8 result, the failed dial's window), commits tied. If it is not an end, its flow joins the open table, as part (d) does.
- **Bound: `HoldLateEntries` = 4,096 sessions, oldest out first.** That is at least 68 hours at one run a minute, the fastest an entry runs (`MinIntervalSeconds`), and fewer hours with several entries. At about 200 bytes an entry it is under 1 MiB of memory.
- **It is memory only.** Its source is `collection.run`, which is already stored. At start it is rebuilt from the health stream, newest first, at most 4,096 runs back and no further than `outage_hours`, as `lastDropCounts` reads (`sensor.go`).
- **Past the bounds** a late record commits untied and alerts, counted under `late_untied` as `horizon` or `evicted`. It fails loud and is never suppressed (SL-17).

**Why the detector needs no change.** It judges a session only once its clock, the latest `first_utc` read in seq order, passes the session's end plus `g` (`judge`). The sensor sends in seq order. If C13 0.2 states that the first record of each flow is sent in capture order, the session's own flow, which starts in its window, is read before any flow that starts after the window. A late tied record then reaches the detector before its session is judged, and marks it seen. **That ordering is asked of C13 0.2 (§1.10), and the design rests on it.**

- **Records lost are not late.** The sensor must declare the capture interval of records it evicted as degraded coverage (asked of C13 0.2). `covers` then keeps `own-session-unseen` from judging sessions in it (`own.go`).
- **The barrier does not wait** (`intakeRecords.barrier`, `netintake.go`). Waiting would hold every session's handover for the length of an outage. The late index gets the same result with nothing held.
- **The buffer the sensor must cover: `outage_hours` of records at the site's normal rate.** The hello declares the oldest record the sensor holds. If the sensor's buffer covers less than `outage_hours`, the node raises `sensor-buffer-short`. How the sensor counts what overflows is D4's (C13 0.2 item 4).

**Tests.** In `platform/sensorlink`: `TestLateRecordTied`, a result with nothing held and the flow's records after it, committed tied, whose control, with no late index, commits them untied; `TestLateIndexRebuiltAtStart`; `TestLatePastHorizon`; `TestLateIndexBound`. At the node: `TestLateRecordsNoOwnSessionUnseen`, the session handed over and its tied records after its `after_seq`, no alert; the control, untied, alerts. On the rig: the link cut for 10 minutes across 5 scheduled runs, then restored, with no `own-session-unseen` and no `own-session-outside-record`.

## 1.7 Retiring and replacing a sensor (brief item 6)

- **A replacement keeps its `sensor_id`.** A new host, a re-image or a new key is a new enrolment of the same `sensor_id` at the next generation (SL-16, SL-R6). Its streams, baseline and detector carry on, and the open table clears at the new run, as on any new run today. Nothing is retired.
- **Retiring is for a `sensor_id` withdrawn:** a LAN no longer watched, or a revoked sensor not replaced. Today a sensor taken out of the configuration leaves its database on disk, unopened, never pruned and never deleted (Part 2 §5, `layout.go`).
- **Requirement, not built.** A `sensor_id` in `network_sensor.retired` keeps its database and its `netbaseline` stream in the layout, with no dialer, link or detector. A consumer `node-retired` on its observation stream confirms through the head at each manager tick, so the observations become prunable. The alert stream keeps its forward targets, or the retention consumer (`netretain`, `alert_retention_days`) where there is none. Network baselines are evidence and are never removed (C5 0.9). Status shows what each retired sensor still holds. Once both streams are empty, status says so, and the administrator removes the entry; the database then stays on disk unopened, like every store file. A retired database counts in the volume rule until then.
- **Tests.** `TestRetiredSensorPruned`: observations pruned, alerts kept until forwarded or past retention; `TestRetiredSensorNotDialled`; and the load check of §1.2.

## 1.8 `sensor-blind`, and why a sensor never stops collection (brief items 7 and 8)

**`sensor-blind`** (item 7). Today status shows the last heartbeat's counters and nothing compares them over time (`sensor.go`). **Requirement, not built:** while heartbeats are accepted, a C13 `packets` counter unchanged for `SensorBlindAfter` = 300 s of the node's monotonic time raises `sensor-blind`, as does C13 0.2's capture-state signal when it says the interface has no carrier. The counters run per run, so the comparison starts again at the first heartbeat of a new run. It is raised once a stretch, opens a coverage gap with cause `blind`, and clears at the first heartbeat whose `packets` has risen. `sensor-unreachable` (no heartbeat for 60 s) and `sensor-blind` (heartbeats, and no packets for 300 s) never stand together: blindness is judged only while heartbeats arrive.

- **Why 300 s. Assumption:** a mirrored station LAN always carries something within five minutes, such as GOOSE retransmissions, PTP, SCADA polling or ARP. It is not shown for any site, the owner has not yet said which protocols run (D4-66), and D2 can check it against the SEL manuals. It is not configurable until a site needs it.
- **Tests.** `TestSensorBlindFlatPackets` on the test clock, whose control compares counters across runs and raises a false alarm at a run change; `TestSensorBlindClears`. On the rig: heartbeats with flat counters raise the alarm within 300 s and one tick.

**A sensor never stops SER or Syslog collection** (item 8, SL-20). Each coupling of §1.0, and what changes:

1. **The start.** `startSensor`'s error no longer fails `Start` (`runtime.go`). The node starts without that sensor's intake, raises `sensor-intake-not-started` and tries again at each manager tick. Shape checks stay load failures (§1.2). A missing or mismatched enrolment is an alarm (§1.3).
2. **The tick.** The sensor's work moves into a **sensor manager** with its own goroutine and its own 60 s ticker (a new file, `platform/node/sensormgr.go`): what `tickSensor` does now, the fold of §1.3, the dialers, skew, blindness, expiry, gaps and the late index. `Runtime.Tick` only takes the manager's status snapshot, without waiting. The detector's drive is also bounded, at `DetectorTickRecords` = 5,000 observations or 10 s a tick, with the rest at the next tick and `backlog` in status. The final drop-count write of `Close` moves to the manager's stop.
3. **The run path.** `Link.cmu` becomes a lock with a deadline. The scheduler waits at most `HoldLockWait` = 2 s in `Dispatch`, `Result` or `Abandon`. Past it, `Dispatch` holds nothing and the run's flows commit untied (`dispatch_timeouts`), and `Result` gives no session, so `collection.run` has none (`runs_session_missing`), and the held flows give way at their deadline (`TickHold`). 2 s is far above one commit's normal time and far below a run's own timeouts, so collection never waits on a sensor for more than 2 s a call, three calls a run.
4. **The platform class.** Every health event a sensor can cause is written only while the platform class holds less than three quarters of its quota: `SensorHealthCeiling` = 3/4 × `store.quotas.platform`. That covers `intake.drop-counted`, the coverage gaps, skew, blindness, expiry, and the store alarms of the sensor's network database. The precedent is item 3's ceiling on the configuration class (`Item3Ceiling`, `item3layout.go`; `saveIntake`). Past the ceiling an event is not written, it is counted in status (`health_held`), and the next one written carries the counts; drop counts are cumulative already. So the last quarter is always left for `collection.run` and `collection.missed`. Events an administrator causes (`sensor.revoked` and the enrolment's) are outside the ceiling, because a sensor can't cause them. Within the ceiling, each type has a time cap (below).
5. **The coverage gap,** which D6 found unbounded. A gap opens when `sensor-unreachable` or `sensor-blind` is raised, not at each dropped connection, and closes at the next heartbeat that clears it. At most 4 `sensor.coverage-gap` records an hour for each sensor, two gaps. Past that the node keeps the stretch in memory, and writes one closing record with the first start, the last end, the number of gaps and the seconds unwatched once the cap allows. A gap is never dropped silently.
6. **A stalled handshake** (SL-12) writes nothing stored. It is counted in status by reason (`dial_failures`: `connect`, `handshake-timeout`, `tls`, `peer-key`), and a stall that lasts becomes `sensor-unreachable` and one gap.
7. **`sensor.link_refused`, capped across a restart without the event-baseline read.** The cap is D3's: at most once an hour for each sensor and reason, at most 6 × 2 × 24 = 288 records a day with two sensors. Within a run it runs on the monotonic clock. Across a restart it starts from `sensors.json`'s last record time for each sensor and reason, which the node writes with each record, folded forward from the audit records after the file's `through_seq`. It does not rely on the audit read at start, which runs only when the node has event baselines (`newEventRun`, `eventbaselines_run.go`). **An unreadable file, or a fold that fails, holds the cap from the start**, as if every reason had been written then, and raises `sensor-state-unknown`; the start goes on. **A time after now is taken as now**, so a clock stepped back can hold the cap for at most an hour, not until the old time comes round.
8. **Faults stay in the sensor's network database.** The link's commits and position saves go there only. What else a sensor's work writes, each bounded: the hold's records and the detector's checkpoints in the configuration class, under item 3's ceiling (`saveIntake`); health events under the sensor ceiling; audit records under the cap, or caused by an administrator; `sensors.json` in the store directory.

**The test that would show it: SL-T13 over the real link** (P4-4-R1, `CI-Linux`), with SER collection running against the simulator on a schedule and Syslog arriving over TCP and UDP. Its legs:

| Leg | What the sensor does |
| --- | --- |
| (a) flood | Observations at the link's full rate, resolved and unresolved, for twice the time the observation quota takes to fill |
| (b) cut and stall | The connection killed every 5 s for 10 minutes; then a peer at the enrolled address that accepts TCP and never completes TLS |
| (c) blind | Heartbeats with flat counters |
| (d) audit (D3) | Accepted and refused hellos in turn, under every reason it can cause, for more than an hour of test clock, with a small audit class, and the node restarted repeatedly under it |
| (e) gap flapping | One heartbeat, then 61 s of silence, for two hours of test clock |
| (f) skew | A 10 s offset across 20 scheduled runs |
| (g) two sensors | A floods, B is normal |

Throughout: every scheduled run is sent and stores its rows; no `collection.missed` and no collection alarm; Syslog received equals sent, within the listener's own limits; each run's length within 10 % of the same leg with no sensor section; no wait of more than 2 s on the link's lock; the sensor's health events below the ceiling; `sensor.link_refused` within the cap; B's commits unchanged by A.

**Controls,** each of which must make a leg fail:

1. The sensor ceiling removed: the platform class fills, `collection.missed` is refused and the entry's runs are held. This is the control for the coupling of §1.0.
2. `HoldLockWait` removed, and the network commit slowed through a seam: runs grow longer.
3. The time cap removed, or started afresh at each start: the audit class fills, or the restart leg exceeds the count (D3).
4. D3's: the observation class's quota check removed, so the flood takes the volume and the evidence database refuses.

Node-level legs on the test clock go in a new package, not in `platform/node`, whose Windows run is near its 720 s warning (D4-44). `platform/node` gains the wiring and one start test.

## 1.9 Bounds set in this note

| Bound | Value | Why | Past it |
| --- | --- | --- | --- |
| Connect, handshake, read, write | 5 s, 10 s, 30 s, 10 s | Three missed heartbeats for the read | Closed, counted, back-off |
| Back-off | 1 s to 60 s, ±20 % | Bounded redial | — |
| `MaxSensors` | 2 | One for each PRP LAN | Load refused |
| Retired sensors | 4 | Withdrawals waiting to prune | Load refused |
| Skew | 5 s raise, 4 s clear, over 30 heartbeats | §1.5 | Alarm, no ties, aggregated alerts |
| Late index | `outage_hours`, and 4,096 sessions | §1.6 | Untied and counted, alerts |
| Sensor buffer | `outage_hours` at the site's rate | The node's planned outage | `sensor-buffer-short`; losses declared |
| Acknowledgement | at most 1 a second, or every 256 records | Bounded node-to-sensor traffic | — |
| Position | 160 bytes; a save of its own at most 1 a second | Within the record cap | — |
| `HoldLockWait` | 2 s | §1.8 item 3 | Untied, or no session, counted |
| Detector per tick | 5,000 observations or 10 s | §1.8 item 2 | Next tick; `backlog` |
| `SensorBlindAfter` | 300 s | §1.8, an assumption | Alarm and gap |
| `SensorHealthCeiling` | 3/4 of the platform quota | §1.8 item 4 | Held, counted, carried |
| Coverage-gap records | 4 an hour for each sensor | §1.8 item 5 | Merged into one closing record |
| Skew, blind and expiry events | one a stretch, at most one an hour each | — | Status only |
| `sensor.link_refused` | one an hour for each sensor and reason | D3 §11.2 | Counted; the next record's `count` |
| Expiry warning | 30 days, hourly | SL-8 | — |
| Revocation | about 15 s, at worst about 615 s | §1.3; D1's choice | — |

## 1.10 What the node needs from other contracts and roles

**From C13 0.2 (D4, P4-4-L2), so the two designs meet:**

1. SL-13's hellos. The node's carries the position of §1.4. The sensor's carries its clock, the oldest seq it holds with its capture time, and how its end was pinned, by signature or by hand (SL-5), which status shows.
2. The acknowledgement: a run and a seq, meaning "durable at the node" as §1.4 defines it. The node sends nothing else (SL-19).
3. In each heartbeat, a send time stamped when it is written to the connection (§1.5).
4. Records evicted from the sensor's buffer: a counter, and the capture interval they covered, as degraded coverage with a reason of its own, in the next heartbeat or hello (§1.4, §1.6).
5. A statement that the first record of each flow is sent in capture order, and that a resend keeps seq order (§1.6).
6. A capture-state signal for `sensor-blind`: link or carrier state, beside the counters (§1.8).
7. The node's mark for an observation committed while skewed, and the detector's `clock-skew` key for the own-session rules (§1.5), with D4's detector change.
8. ALPN `otsec.netobs/0.2` (§1.1).
9. With two sensors on PRP: each coverage statement says which LAN it sees and that the duplicate discard is off.
10. `MaxLinkCursorBytes` added to the margin of `TestWorstStoredObservationFits` (§1.4).
11. The configuration digest in the coverage statement (SL-19), which `sensor-coverage-mismatch` checks.

**From C5: no change to classes or quotas.** The design uses the source cursor C5 already has, and the store's `SaveSourceCursor`, which is not part of C5. **D1 is asked to confirm** that C5 0.9 allows more than one database that holds the network classes (§1.2), since its text says only that such a database holds nothing else.

**From C7 0.11 (D3):** the two kinds as D3's §11.1 proposes them. Nothing more for the node.

**From C8 0.13 (D3):** the three actions as D3's §11.2 proposes them, and two additions: the relayed `collector.request` record of a sensor kind names its target, the `sensor_id`, generation and pin, and for a revocation `suspect_from`, so the node can derive a revocation from the chain alone (SL-R2); and `sensor.revoked` may be written late, owed, with the decision's `decision_seq`.

**From D3's `modules/security/nodekey`:** the sensor-link key of §1.1.

**From D6:** the tests in `tests/security` that call `ServeSensor` move to its new shape with the third part.

## 1.11 What applying `node.network_baseline_ack` takes (for the third part's brief; not built)

SL-R5's "acknowledged again" and the baseline legs of SL-T10 wait on it. What it takes:

1. **The network learner on the node.** `netdetect`'s learner runs, its draft is checkpointed (`netcheckpoint.learner`), and a frozen draft is recorded as `baseline.network` on `netbaseline/<sensor_id>`. Without a recorded draft `netack.Adopt` refuses every acknowledgement.
2. **The relay.** `node.network_baseline_ack` joins `relayKinds` and `nodeActKinds` (`adminrelay.go`), and `applyAdminPart` gains its case, bound to the install key as `node.baseline_ack` is (`admin_actions.go`).
3. **The node's part.** `policy.apply` with `admin_keys` first when `netack.NeedsGrantRecord` says so. The latest draft, and `network-baseline-<sensor_id>.json` from `admin_dir` under the protected-file rule, passed to `netack.Adopt`. C8 `config.baseline_acknowledged` of kind `network` written before anything is stored, `denied` with `Adopt`'s reason when it refuses. The accepted bytes stored as `baseline.network`, evidence, never removed.
4. **The detector takes it.** `DetectorConfig` gains the accepted baseline (`detectorConfig`, `netdetector.go`), the detector's checkpoint names the baseline it judged with, and a newly accepted one starts a new detector half, as the event baselines do.
5. **SL-R5 itself.** An acknowledgement before the latest `sensor.revoked` of its sensor is not in force. The detector then runs as before acknowledgement, and `sensor-baseline-void` stands while that sensor feeds. A re-key keeps it (SL-R6).
6. **Tests.** The `netack` cases already in `modules/security/netack`, run end to end through the relay; SL-T10's baseline legs; a revocation voids, and a re-key does not.

## 1.12 Choices left

**For D1:**

1. One sensor or two, and a database for each or one shared (§1.2); and whether the third part builds two now.
2. The revocation bound against SL-R2's "at once" (§1.3).
3. The local stop by restart, or a stop file (§1.3).
4. The bounds of §1.9, the skew bound, `SensorBlindAfter` and the sensor ceiling above all.
5. **A tension D1 should see:** SL-17 makes no tie while the clock is skewed. With a 5 s bound, an ordinary NTP fault on the sensor host turns every scheduled run into an alert. §1.5 aggregates them, and D5 keeps D3's rule as written.

**For the owner, through D1, with what each costs on the node:**

- **O-12 on PRP:** one host with two ports (the node needs nothing more), two hosts (a second link, database, baseline and acknowledgement, and alerts twice for traffic on both LANs), or one LAN only (as built, with the other LAN's own traffic unseen).
- **O-6, the network between node and sensor:** a cable of its own needs a free network port on the node's hardware for each sensor, which is not checked for any machine.

## 1.13 Limits

- **Nothing in Part 1 is built or has run.** Every test named is a plan.
- **Assumptions, each marked where used:** that `VerifyConnection` runs with normal verification off, that Go's TLS client sends no early data, and that no client session cache means no resumption, which `TestDialNoResumption` and `TestDialRefusesOtherPin` decide; that Windows' default outbound policy is allow (§1.1); that a station LAN is never quiet for 300 s (§1.8); and that the collector's pipe can or cannot take a second client during a run (§1.3), which is `unknown`.
- **Not designed here:** a merge of two sensors' records; the sensor itself; its update path; a central role.
- **`sensors.json` has the limit of `suspensions.json`:** whether a rename on Windows is durable without a folder flush is D4-65's open question for the owner.
- **Accepted limits that carry over** (Part 2 §9, `D5-c5-0.9.md`): drop counts can lose the last minute in a crash; one full alarm per fill.

# Part 2: the note of 2026-11-07 (P4-4-A5)

Sections 1 (options (a) and (c)), 2 (the pipe), 7 and the pipe and SID rows of 8 are **History**. Sections 3, 4, 5 and 6 still hold, with the changes each one's marker gives. Section 9's points are carried in Part 1 or stand as written.

D5, 2026-11-07. This is the design note for brief P4-4-A5 (`docs/agent-handoffs.md`, item 4, Stage A, D4-66). Everything in it is `desk`. Nothing here has run, and no code is proposed for merging in this stage.

The note covers six topics:

1. how the sensor process is supervised;
2. the channel to the node;
3. how C13 records reach the store, and how much room they get;
4. where the cited packet bytes live;
5. switching the sensor on and off;
6. what status shows.

It also covers the install side of C-11 on Windows and where the tests go.

ADR-0009 has not named an option yet. So each section gives the node's side for options (a) and (c), a sensor process on the site node, and separately for option (b), a sensor on its own Linux host. Where a section depends on C13's shape, it says so. The C5 changes that this note asks for are drafted beside C13 once the ADR names the option (Order step 2). They are not drafted here.

## 1. Supervision

**Under option (b):** the comparison for options (a) and (c) is **History**. The subsection on option (b) is superseded by Part 1 §1.1 and §1.3: the enrolment is D3's (SL-4 to SL-7), not SC-11's. The heartbeat, `sensor-unreachable`, the restart count and the coverage gaps still hold, with the gaps bounded by Part 1 §1.8.

### Options (a) and (c): a sensor process on the site node

**History** (option (b) chosen, D4-85).

The brief asks for a comparison of two ways to run the sensor: as its own SCM service, like the collector, or as a child process of the node.

| | Its own SCM service | A child of the node |
| --- | --- | --- |
| **Account** | Its own virtual account, `NT SERVICE\otsec-sensor`, with its own service SID. The installer already creates the node and the collector this way (`platform/winsvc/install_windows.go`, `createService`). | The node's account. Running the child under another account needs `CreateProcessAsUser` and a token, which in turn needs privileges the node is denied (W-2, no `SeImpersonatePrivilege`). On Linux the node isn't root, so it can't drop the child into another user either. |
| **What a decoder exploit reaches** | Only what the sensor's account can open. The store directory's protected DACL (W-4) and the node keys don't grant it anything. | Everything the node's account can open: the store, the node keys and the collector pipe. This defeats D3's hostile-input row, which requires that a decoder crash or exploit cannot reach the store or keys. |
| **Restart** | The SCM restarts it, with the recovery action the installer gives the node and the collector: restart after 60 s, failure count reset after a day. | The node has to restart it. That means a supervisor loop inside the node, which ADR-0002 item 5 rules out ("no orchestrator"). |
| **Firewall and pipe ACLs** | Rules per service SID, as HR-9 does for the collector. | The child shares the node's SID, so no rule can tell the two apart. |
| **Crash dumps** | The sensor can be excluded from WER on its own, like the collector (T-5). Its memory holds packets, which may include Telnet and FTP passwords and SNMP community strings. | The exclusion would have to cover the node too. |
| **Enable and disable** | Two switches: the installer installs or removes the service, and the node's configuration has a section (§5). | One switch, the node's configuration. |

**Recommendation: its own SCM service** on Windows, and a systemd unit with its own user on Linux. This is ADR-0002 item 2: each separate process runs as its own principal and names the boundary it enforces. The only cost is the second switch in §5, and the node turns that into a check.

Under this choice the node doesn't start, stop or restart the sensor. It doesn't have the SCM rights to, and it shouldn't get them. The node watches the sensor over the channel instead (§2):

- **The heartbeat.** The sensor sends one every 10 s. The node raises `sensor-unreachable` after 60 s with no heartbeat accepted, as it does for `forward-unreachable`. It times this on its own monotonic clock from the later of the last accepted heartbeat and its start; a reconnect never resets it (D4-73). It is raised once per quiet stretch, status shows `unreachable` until the next accepted heartbeat clears it, and a step of the wall clock moves nothing. `sensor-unreachable` is raised at the first Tick at or after 60 s of quiet, so at most 60 s + `TickInterval` (≤ 120 s today) (D1 on #581).
- **Restarts are counted.** Each time the channel reconnects after a gap, the node counts a sensor restart and shows the count in status. A decoder that crashes on the same packet every time restarts every 60 s indefinitely, and status shows that loop.
- **Coverage gaps are records.** While the sensor isn't capturing, the network isn't watched. The node commits a `sensor.coverage-gap` health event when the channel drops, and closes it with the end time when the channel returns. The gap is forwarded like any other health event. A quiet alert stream therefore can't be read as a quiet network over a period when nothing was capturing (R6.1). It also holds at a node start: a gap is open until the first heartbeat arrives.

### Option (b): a sensor on its own Linux host

**Superseded by Part 1** (§1.1 to §1.4). "A revocable credential like a node's (SC-11)" is replaced by D3's enrolment, because SC-11 is not built. The buffer on the sensor host is sized in Part 1 §1.6.

The node supervises nothing. Restarting the sensor is that host's job: a systemd unit with its own user. The node sees only the link, which uses mutual TLS. **The node opens it, and the node never listens for it** (AP-34, "never a listener open to the station LAN"; settled with D3 on #526):

- **Enrollment.** The sensor is enrolled with a revocable credential like a node's (SC-11). The node accepts only that sensor's certificate, and the sensor accepts only the node's.
- **The listener is on the sensor host.** It is bound to that host's management interface only, never its monitoring interface, and its host firewall allows only the node's address. The node dials out to it, as it dials out to its forward targets, and its own firewall allows that one destination. The node gains no inbound port.
- **Records still flow from the sensor to the node** over the connection the node opened. The node reads them, as in §2.
- **Health.** The heartbeat, `sensor-unreachable` and the coverage-gap records work as above. A link outage is also a coverage gap, unless the sensor buffers its records and the gap is in the records it sends. A disk buffer on the sensor host is the sensor's design, so it belongs to D4.
- **Attack surface.** The sensor host's own management interface and update path count as attack surface (D3's ADR row). Nothing on the node's side reduces that.

## 2. The channel to the node

**Under option (b):** the named pipe, its DACL, the service SID and the Unix socket with `SO_PEERCRED` are **History**. The rules for hostile records still hold: the frame cap, strict decoding, bounded and quoted device text, `sensor-record-refused`, and the node as the store's only writer. Back-pressure changes: the sensor buffers while the link is down or the node does not acknowledge (Part 1 §1.4, §1.6).

**Options (a) and (c): a local named pipe, using the collector's pattern** (`deploy/README.md`, Windows host rules: "a named pipe IPC on which each end checks the other's service SID").

- The node creates the pipe. Its DACL grants connect only to `NT SERVICE\otsec-sensor`, and the node checks the client's service SID on every connection. The sensor checks that the server is the node.
- On Linux, the channel is a Unix socket in a directory that only the two users can reach, with `SO_PEERCRED` checked.

**Every record that arrives is hostile input.** The sensor parses attacker-controlled packets, so what it sends is only as trustworthy as its decoders. The node therefore does the following:

- caps each frame's length;
- decodes and validates each record against C13 before it commits anything, as `ConfigDocuments` does for configuration records;
- bounds and quotes any device text, as C2's record values are (D3, `contracts/adapter/doc.go`);
- never writes a record's text raw into status or a Syslog forward.

A record that fails these checks is dropped and counted, and the node raises `sensor-record-refused` once per condition. The connection stays up, so one malformed record doesn't stop capture.

**Only the node writes the store.** The sensor never opens the store or a node key, and the store directory's DACL doesn't grant it access. This keeps C5's single writer per database (`Database.Writer`) as it is, and keeps the store outside the decoder's boundary.

**Back-pressure.** A passive sensor can't slow the network. When the node isn't reading, because the database is drain-only or a class is full, the sensor's in-memory queue fills, and the sensor drops and counts. Each heartbeat carries the sensor's counts: drops in the capture driver, in the decoder queue, and on the channel. The node persists them as health events, so every loss at every stage is recorded once.

**What option (b) changes:** the transport is TLS over the site LAN instead of the pipe, on a connection the node opens (§1). The validation, the counting and the single writer stay the same.

## 3. C13 records in the store: database, classes and quotas

**Under option (b): still holds.** With two sensors, each gets a database of its own (Part 1 §1.2).

**A database of its own, `network`.** It follows the precedent of `syslog` and `configuration`: received Syslog has its own database "so a Syslog storm cannot hold the evidence database's lock" (`platform/node/layout.go`). A flood of observations must not hold the lock of the SER, Syslog or audit databases either. The database exists only when the sensor section is in the configuration (§5).

**Separate classes, because a quota is per class.** C5's class set is closed (`contracts/store/class.go`), so each class below is a C5 change, drafted at Order step 2:

| Class (draft name) | Holds | Full action | Why |
| --- | --- | --- | --- |
| `network-observation` | C13 observations: flows and services seen | `drop-and-count` | The sender is the monitored network, which can't be slowed. At its quota, new observations are dropped and counted, and the alarm says so. |
| `network-alert` | C13 alerts, with their cited packets as the record's capture | `drop-and-count`, on a quota of its own | An attacker can produce observations at will, from new flows or spoofed addresses. Without a separate quota, a flood of observations would push out the alerts it should trigger. A separate class keeps that room for alerts. |

This is the HR-11 lesson. A flood of unknown senders once had a rate budget only (A3's option (b)), and the absolute bound was a class of its own (`syslog-unknown`, C5 0.4).

**Unresolved observations.** An observation whose addresses resolve to no asset (`asset-unresolved`) is the cheapest thing for an attacker to forge. The node gives unresolved observations a rate budget, sized like a listener's unknown share: they may take at most a quarter of the observation quota over the planned outage, with drops counted and status showing the share. That is a rate bound, not an absolute one.

The absolute bound would be a third class, `network-unresolved`. I recommend starting with the rate budget, for two reasons:

- the local consumer below keeps the observation class draining;
- the first unresolved address is itself an alert, which goes to the alert class, aggregated as below.

D1 ruled a rate budget for 0.1, with D3's agreement, once the ring redaction (§4) and the aggregation below are in. A third class is the fix only if D6's flood test shows starvation (§9). If the ruling is a third class, the cost is one more quota in the volume sizing.

**Alerts an attacker can forge cheaply are aggregated (D3).** The alert class is meant to be the safe one. An attacker who spoofs many source addresses could still fill it with forged first-seen alerts, pushing out the real ones. So an alert whose trigger costs an attacker nothing is aggregated:

- This covers a new unresolved address, and a new pair from an unresolved source.
- There is one alert per kind per window. It carries a count and a bounded sample of the cited frames, not one alert per address.
- The window and the sample size are C13's, with D4's baseline note. The class's `MaxRecordBytes` bounds the sample's bytes.

The node enforces this bound where alerts enter the store, whichever side raises them. If the sensor raises them, the node does not trust it to aggregate. A record of an aggregated kind beyond one per window is refused and counted (`sensor-record-refused`), so a compromised sensor cannot use those kinds to fill the class either. An alert of any other kind is unaffected.

**Pruning needs a consumer.** C5 never prunes a stream with no consumer, and never evicts unconfirmed records (ADR-0004 item 9). Observations are not forwarded as they arrive: whether they are C4 events is C13's choice, and the configuration documents set the precedent that typed documents are not. So with no consumer the observation stream would fill once and then drop everything new, forever.

The node's detection module, the network baseline and its detector (D4's note), is therefore a **required local C5 consumer** of the observation stream:

- Its cursor moves once an observation is folded into a checkpoint that is committed, as `node-suspensions` and `node-holds` do for the audit stream.
- What is folded becomes prunable.
- The alert stream is consumed by the forward targets, like any event stream that is forwarded, if C13 makes alerts C4 events.

**The detector consumer as built (P4-4-B5, PR B2, D1 in D4-74).** `platform/node/netdetector.go`. Desk and CI only: no sensor has produced a record and no device was contacted.

- **The consumer.** `node-netdetector` is a required consumer of the observation stream whenever the sensor section is set. The detector reads the observations the sensor committed, and the node's own sessions from the `collection.run` records on the health stream. It commits the alerts it raises to the alert stream, each with its capture.
- **The handover barrier.** A session must reach the detector before any observation past its `after_seq` (D4's finding 4 on #576). Each tick reads the observation head, then the barrier, then the health stream. The barrier is the lowest seq of the runs whose release may still precede a `collection.run`.
  - A run enters the barrier at the observation head before its release. This seq is never above its `after_seq`.
  - Once released, the run's barrier seq moves to its `after_seq`.
  - The run leaves the barrier once its `collection.run` is stored or failed.
  - The driver reads observations up to the barrier, or up to the head when the barrier is higher. It hands each session over, in health-stream seq order, once it has read the observations up to that session's `after_seq`.
  - A released run whose `collection.run` was not stored counts in `runs_session_missing`, as does a `collection.run` that doesn't parse (D3 on #590). So does a session the detector refuses, other than for ordering or for `pending-full`, which have their own counts (D6's N3 on #590).
  - The driver's position on the health stream moves past a `collection.run` only once it is handed over or counted. A run the driver stops before, at an alert not committed, is read again at the next tick. A read of the health stream that fails moves nothing (D6's N1 on #590).
- **Checkpoint cadence.** The node writes `netcheckpoint.detector` at each tick where the detector took an observation or a session. The tick at a clean stop counts too.
  - A session counts toward that, even with `through` unmoved. Without it, a session skipped at the tail would be judged when a restart handed it over again.
  - The cursor moves to the stored checkpoint's `through` only after the checkpoint commits. The older checkpoints are then removed, as `identity.read`'s are.
  - Item 3's ceiling holds the checkpoint as it holds the intake's records (`D5-c5-0.9.md` §8).
  - A checkpoint or cursor that is not stored keeps the old cursor, raises `network-detector-checkpoint-failed` once, and is counted. The next tick tries again. A cursor save or a removal of older checkpoints that failed is tried again at each tick, even when no new checkpoint is due (D6's N2 on #590).
  - A checkpoint is at most `MaxDetectorCheckpointBytes` (1,354,752 bytes). The desk rows' checkpoints are about 3.4 KB.
  - At one tick a minute, the node writes at most 1,440 checkpoints a day, so at most about 1.8 GiB a day of configuration writes in the worst case. Only the newest one or two are ever stored.
- **Restore and replay.** At start, after the intake's start repair, the node restores from the newest checkpoint. It passes `RestoreDetector` the alerts committed after the checkpoint's `last_alert_seq`, so an alert raised again in the replay is held back.
  - Desk row: a crash after an alert commits and before its checkpoint gives one alert (`TestDetectorReplayNoDuplicate`).
  - A first start, with no checkpoint, stores one at `through` 0 before it reads anything, so a crash before the next checkpoint still restores and holds back.
  - A checkpoint that doesn't restore raises `network-detector-not-restored`, and the detector starts again from the oldest retained observation. Its first checkpoint is stored at once, and every older one, the one that didn't restore too, is then removed.
  - Such a fresh start raises again the alerts of the observations still retained, which were committed before. They are stored again: a limit, as the checkpoint that would hold them back is the one that didn't restore.
- **The before-retained guard.** The detector begins at the oldest retained observation. If the observations right after its `through` were pruned, as at a first start over a pruned stream, the node judges a connected session that is not `open_flow` only if `started_at − g` is at or after `T + g`.
  - `T` is the node's commit time of the first record the detector reads, even if that record is refused (D1 on D4's F1 and D3's B2 on #590).
  - `T` is not the record's `first_utc`, which is a flow's start, so a flow's end record would let an older session be judged. It is not the sensor's clock either.
  - It is not `received.utc`, which a held record's later commit takes out of seq order.
  - Otherwise the node calls `Skip` and the session counts as `before-retained`.
  - The guard is computed from the stream, so it also holds after a restore from the first start's checkpoint. The stream counts as pruned when its first retained seq is past `through + 1`, or when nothing is retained and its head is past `through`.
  - A session handed over before any record is read has no `T`, so it is skipped.
  - Desk row: a trailing skip, then a checkpoint, then a restart, gives no ordering fault and no alert (`TestDetectorTrailingSkip`).
  - Desk row: the fin end of a flow from 07:00 to 09:30 and a session at 08:15 give `before-retained` 1 and no `own-session-unseen` (`TestDetectorGuardCommitTime`).
  - Desk rows on a stream the store's prune step really pruned (D6's R1 to R4 on #590): a session at `T + 2g` is judged and one a nanosecond earlier is skipped, whether the first record read is stored or refused (`TestDetectorGuardEdge`); a session before any record is read is skipped (`TestDetectorGuardNothingRead`).
- **An alert's capture.** The node keeps a frame index that maps a cited frame's SHA-256 to the first-sight capture holding it. It holds at most `FrameIndexEntries` (4,096) entries, drops the oldest first, and is rebuilt at start from the retained first sights.
  - The capture holds the cited frames the node still has, in citation order.
  - A frame counts as missing, in `frames_missing`, when its capture is gone or pruned, or when its bytes there don't hash to the cited SHA-256.
  - An alert whose frames are all missing has a header-only capture.
  - `own-session-unseen` has no capture.
- **An alert that isn't committed** (D1's F1 on #590). Alerts commit in the order raised.
  - If the store refuses an alert for its class's quota or record cap, the alert is dropped and counted, as §8 of `D5-c5-0.9.md` drops a full class's records, and the detector goes on. It is counted by reason (`class-full`, `record-cap`) and by its C13 rule and destination asset, with one bucket, `asset-unresolved`, for every unresolved destination (AP-36 (3), PR B3).
  - Those counts are in status beside `network-full`, and in an `intake.drop-counted` event of class `network-alert` on `platform/health`. The event is written as the observation class's is: at most once a minute when the counts changed, and at a clean stop. A restart restores them from the last event, so they count since `alert_drops_since`.
  - The event names at most `SensorDropDetailAssets` (8) pairs as `<rule>.<asset>` details, with no prefix, since a detail key is at most 64 characters and the longest rule and an asset ID take 63. It sums the rest in `other`. Pairs with an enrolled asset are named before the unresolved buckets, then by the most drops (D1 on B3). At its worst case it renders in 1,465 octets, within three quarters of a default Syslog target's 2,048 (`TestSensorAlertDropEventFits`, desk Linux).
  - `network-alert-not-stored` is raised once for a stretch of drops or held alerts, and again only after an alert commits (D1 on B3, D6's E15 on #590).
  - Any other failure keeps the alert and those after it. The detector then reads nothing more and is not checkpointed until they commit, so neither its checkpoint nor its cursor passes an alert that isn't stored.
  - Each tick tries the commit again. A restart reads the observations again from the last checkpoint and raises the alert again.

**Sizing.** Each class gets a floor that the node checks at load, like the configuration floor (D4-20 rule 5):

- the alert floor holds a number of the largest alerts, each alert plus its packets at the alert's `MaxRecordBytes`;
- the observation floor holds the consumer's lag at its slowest checkpoint interval.

Both numbers wait for C13's record sizes. The volume rule in `deploy/README.md` gains both quotas, times `DiskBytesPerQuotaByte` (2.5), plus the `network` database's reserves.

## 4. Where the cited packet bytes live

**Under option (b):** an alert's capture in the store still holds. The capture ring is now on the sensor host, where D3's SL-22 and the owner's O-11 govern it. The ring's DACL for the sensor's Windows account and the WER exclusion are **History**.

R6.5 needs every alert's packets to be retrievable. C13 has every observation and alert cite its packets as a capture ID, frame numbers and the SHA-256 of the cited bytes. The proposal splits by record kind:

- **An alert carries its cited packets as its C5 capture.** The store already keeps each capture once, keyed by its SHA-256, and deletes it only in the prune step that removes the last record referring to it (EP-6). So an alert's packets live exactly as long as the alert does. The alert class's `MaxRecordBytes` bounds the bytes per alert (C13 sets how many frames an alert may cite).
- **An observation carries only its citation.** The bytes stay in the sensor's capture ring: a fixed set of capture files in the sensor's own data directory, with a fixed total size set in the sensor's configuration and counted in the volume rule. An observation's packets can be retrieved while the ring holds them, and its hash and frame numbers last for as long as the observation does. Keeping every observation's bytes in the store would let an attacker turn traffic straight into used storage.
- **The ring is written redacted (D3, D4-67 on #524).** Raw capture files would hold every cleartext credential on the segment at rest, the platform's own SEL Level 1 password included. That covers Telnet and FTP passwords, SNMPv1 and v2c communities, and HTTP Basic headers. So the sensor applies D4-67's positional redaction before it writes a frame to the ring, never after. Two rules follow:
  - **It fails closed.** Where a slot can't be placed, the client-sent bytes of that login are not written. This is D4-67's rule for the store, applied to the ring.
  - **Ring frames carry the same markers as a citation.** A cited SHA-256 is over the redacted bytes, so it checks against what the ring keeps, and an alert's stored capture and the ring agree byte for byte.

  This protects the disk at rest, a stolen node and other local readers. It does not protect against a compromised sensor, which still sees live traffic (AP-33's scope). GT-PCAP's key search searches the ring's directory as well as the store (D6). The WER exclusion in §1 is still needed for the packets the sensor holds in memory.
- **Nothing leaves the site, by construction.** The forwarder reads events only. `modules/telemetry/forward` never calls `Outbox.ReadCapture` (grep, at `7e09898`). On the node, only quarantine export, identity and the event-baseline feeder read captures. So cited bytes are never forwarded upstream; their hash and frame numbers are (D3's stored-captures row).
- **Retention.** An alert's bytes go when the alert is pruned, which needs every required consumer to have confirmed it. The ring's retention is its size divided by the traffic rate, and status shows the age of the oldest file in the ring. A fixed retention in days would need deletion that C5 doesn't do, so I don't propose one. If the owner needs one, it is D3's row and a C5 question.
- **Who may read them.** The ring's directory gets a protected DACL: the sensor's account, plus whatever D3's row names for the security role. The node's account doesn't read the ring, and status never shows packet bytes. Reading an alert's packets from the store goes through a security-role export, like quarantine export. D3's row decides the role.

## 5. Switching the sensor on and off

**Under option (b): still holds,** with "installed" read as "enrolled" (Part 1 §1.3) and the section's new shape (Part 1 §1.2). "The node creates no pipe" is **History**: with the section absent, the node dials nothing.

**On means two things:** the installer has installed the sensor service, and the node's configuration has a `network_sensor` section. The section holds:

- the class quotas;
- the unresolved budget's outage hours;
- the expected coverage: interfaces, SPAN or TAP, and the protocols to decode.

The node then checks the sensor against it. If the coverage statement in the first heartbeat doesn't match the configuration, the node raises `sensor-coverage-mismatch`. That catches, for example, a monitoring interface that is missing or renamed.

**Off is the section being absent.** The node behaves as it does today:

- The layout has no `network` database, and C5 opens only the databases its layout names. A `network` database left from an earlier enabled period stays on disk unopened and is never deleted, as with every store file.
- The node creates no pipe, so an installed sensor service has nothing to connect to. It logs that to its own event log source and retries. The node raises nothing.
- Status has no sensor section, the node raises no sensor alarms, and the volume rule has no network terms.

**Nothing else changes.** I propose D6 test this the way the brief words it. A node configuration without the section, run with the sensor installed and with it absent, gives these results:

- the same layout;
- the same start line, except for its timings;
- the same status apart from times;
- no alarm that mentions the sensor.

A node with the section and no sensor running starts and collects normally. It shows `sensor-unreachable` and an open coverage gap, and nothing else changes.

**What option (b) changes:** "installed" is the remote host's enrollment instead of a service on the node.

## 6. Status

**Under option (b): still holds.** Part 1 adds, for each sensor: the link's state and its dial failures by reason; the enrolment's generation, pin, `not_after` and state, and how the sensor's end was pinned; the node's link-key pin; the position and `duplicates`; the skew estimate; `blind`; the late index's counts; `backlog`; `health_held`; and the records owed.

Status gets a `sensor` section, written as the other sections are, and `otsec health` prints a line for each item:

- whether it is enabled and connected, and the time of the last heartbeat;
- the sensor's version and its coverage statement (§5);
- packets and bytes seen, and drops by stage: capture driver, decoder queue, channel, and node, split into full class and unresolved budget;
- observations and alerts stored;
- the restart count since the node started, and the open coverage gap, if any;
- the oldest file in the capture ring;
- the C-11 interface check (§7): `ok`, or what is bound;
- the intake hold's counts (`hold`: held records and runs, ties, the caps' releases, the open table's counts and checkpoint failures), the start repair's runs (`runs_repaired`, `runs_repair_refused`), and the runs whose `collection.run` has no session (`runs_session_missing`) (D4-72, `D5-c5-0.9.md` §8);
- beside `network-full`, the alerts the store refused, by reason (`alerts_dropped`) and by `<rule>.<asset>` (`alerts_dropped_by_rule_asset`), since `alert_drops_since`, and when they were last written (`alert_drops_written`) (AP-36 (3), PR B3);
- the detector's part (`detector`, D4-74):
  - `through` and `checkpointed`, and whether it was `restored`;
  - the counts since start: alerts committed, `alerts_frames_missing` (alerts whose `frames_missing` is above 0), alerts dropped and counted, the alerts pending a commit and the failed commits, observations refused, and checkpoints written and failed;
  - the sessions not judged, by reason: `pending-full`, `tied-evicted`, `before-retained` and `session-missing`. A rise in `pending-full` or `tied-evicted` raises `network-session-not-judged` (D1's F2 on #590);
  - `open_flow_seen` and `endpoints_not_tracked`;
  - the run endpoints `own-session-unseen` has not seen yet (`not_yet_seen`);
  - `early_closes`, and the same as a rate per hour since start;
  - `mismatches` and `ordering_faults`.

Status never shows packet bytes or device text, and banners are shown bounded and quoted (D3).

The alarm codes in this note are `sensor-unreachable`, `sensor-record-refused`, `sensor-coverage-mismatch` and `sensor-interface-bound`, the intake hold's `intake-checkpoint-failed`, `intake-record-not-removed` and `intake-repair-refused`, and the detector's `network-detector-not-started`, `network-detector-not-restored`, `network-detector-checkpoint-failed`, `network-detector-mismatch`, `network-detector-ordering`, `network-session-not-judged`, `network-endpoints-not-tracked` and `network-alert-not-stored`. They are draft names. The node's alarm codes and C6's health events are named with the C5 draft.

## 7. C-11 on Windows: the install side

**History** (option (b) chosen, D4-85). Under option (b), C-11 is on the sensor host, under D3's SL-26 to SL-29 and the C-11 rig of P4-4-R1. The paragraph on Linux below is carried there.

C-11 says the sensor never transmits on its monitoring interface. A TAP guarantees that by construction. On a SPAN port with a host NIC, it rests on host settings, which the installer under `deploy/` makes and the sensor checks at each start:

1. **Unbind every protocol from the monitoring NIC except the capture driver's filter**, using `Disable-NetAdapterBinding`. That covers IPv4 and IPv6, the Microsoft client and server, LLDP, and the link-layer topology discovery drivers. Without an IP stack the interface sends no ARP, DHCP, IPv6 router solicitation, LLMNR or NetBIOS. Without the LLDP and LLTD drivers it sends no discovery frames. Those are the frames C-11's threat row names.
2. **Firewall rules for the sensor's service SID**, HR-9 style: block all outbound and all inbound for `otsec-sensor` on every interface. Those rules act on IP traffic only, so they back up step 1 if the IP stack is ever bound again. They don't replace it. The sensor's channel to the node is a local pipe, so these rules don't affect it.
3. **No out-of-band controller on the monitoring NIC.** On the SEL-3355-2, Intel AMT sits on ETH1 and transmits regardless of what the OS binds (ADR-0007 item 8). The monitoring NIC must not be ETH1 unless AMT is checked as disabled at commissioning.
4. **A check at each sensor start:** read the NIC's bindings back. If anything other than the capture filter is bound, for example after a Windows update or a technician's change, the sensor raises `sensor-interface-bound` and the node shows it. The sensor keeps capturing, because stopping capture wouldn't stop the OS from transmitting. The alarm is what gets the binding fixed.

The capture driver can itself send frames, as Npcap's `pcap_sendpacket` can. Nothing in steps 1 to 4 prevents that. It rests on the sensor's code never calling a send path, and on D6's C-11 test: zero frames over the GT-PCAP replay and the sensor's start and stop.

Which accounts may open the driver is part of the driver choice in ADR-0009. The sensor must not run as LocalSystem or in Administrators. I understand Npcap's installer can restrict the driver to Administrators, which would force exactly that. I haven't verified this, and D4 records it in the ADR.

On Linux, for CI and for option (b)'s host, the same steps are:

- the interface up, with no address, ARP off and IPv6 disabled on it;
- no DHCP client on it;
- the sensor's user holding `CAP_NET_RAW` only.

`CAP_NET_RAW` also allows sending, so the same caveat applies. An nftables `netdev` egress drop on the interface would add enforcement in the kernel. Whether it also catches every `AF_PACKET` send path is unverified, so the ADR marks it `unknown` until a test shows it. D6's C-11 rig can settle this: a veth pair in its own network namespace, the rule in place, and a deliberate `AF_PACKET` send from the sensor's end that must not reach the peer. D6 adds it as a rig case once ADR-0009 needs it.

## 8. Tests and where they go

**Under option (b):** the rule on packages still holds, and Part 1 §1.8 applies it. The pipe, the service SID, the sensor's account, the ring's DACL and the NIC rebinding rows are **History**. The other rows still hold, run over the link.

On Windows, the `platform/node` test step already runs 530 to 648 s against its 720 s budget (#520's runs). So:

- The node's side of the channel goes in a package of its own: the pipe or socket, record validation, the heartbeat, coverage gaps, status and the on/off check. A draft name is `platform/sensorlink`.
- The node gains only the wiring and one start test.
- The installer's NIC steps go in `platform/winsvc`, tested in the dispatched Windows workflow. A hosted runner may not allow its adapters to be rebound, so a step that can't run there is reported `unknown`, not skipped silently.

Three rules for these tests, from D6's testability review:

- **The test clock.** The 10 s heartbeat and the 60 s `sensor-unreachable` run on the test clock, as GT-INJ's tests do. A 60 s wait on the wall clock against a deadline that moves is the H11 kind of race.
- **Forced drops are asserted exactly.** Decoder-queue and channel drops are forced with a small queue or a seam, and their counts are asserted exactly. Capture-driver drops can't be forced on a hosted runner, so they are read and reported, never asserted.
- **Status comparisons name what they ignore.** §5's "the same status apart from times" strips a listed set of field names. The list is committed with the test, so the normalizer can't hide a difference.

These tests would show the design holds:

| Property | Test |
| --- | --- |
| Off changes nothing | §5's comparison, with and without the sensor installed. |
| Only the sensor's SID connects | A client under another service SID is refused, as in the collector's pipe tests. |
| Hostile records are refused | Oversized frames, malformed C13, and banners with control characters are each dropped and counted, and the connection stays up. |
| A flood of observations doesn't take the alerts' room | Fill `network-observation` to its quota; alerts still store, and observations are counted as dropped. |
| A flood of unresolved addresses doesn't take resolved assets' room | Spend the unresolved budget; resolved observations still store. |
| Spoofed addresses can't fill the alert class (D3) | Spoof N source addresses in one window. The alert class grows by a bound that doesn't depend on N, and a real alert in the same window still stores. Do the same with the sensor sending one first-seen alert per address: the node refuses all but one per window, and counts them. |
| The ring holds no cleartext credential (D3, D4-67) | Replay GT-PCAP's Telnet, FTP, SNMPv1 and v2c, and HTTP Basic sessions, including a midstream login. The ring's files contain none of the known test secrets, in any of V-M1 M3's four forms: raw, hex in either case, and base64. The cases include GT-PCAP's §2D ones: one byte per frame, a retransmitted segment, PRP duplicates and a server that echoes. The midstream login's client bytes are absent, and every cited hash matches the ring's bytes (D6). |
| Observations are pruned once consumed | The consumer's cursor moves after a checkpoint, and a prune frees the space. |
| Gaps are recorded | Kill the sensor: `sensor-unreachable` is raised after 60 s, and the gap record is closed when the sensor returns. |
| A gap is open at start (D6) | A node start opens a coverage gap, and the first heartbeat closes it. |
| Restarts are counted (D6) | Each reconnect after a gap adds one to the restart count. |
| Coverage is checked (D6) | A heartbeat whose coverage statement doesn't match the configuration raises `sensor-coverage-mismatch`. |
| The sensor's account reaches nothing of the node's (D6, D3's AP-30) | From the sensor's account, opening the store directory, the node keys or the credential store fails. |
| The ring's DACL holds (D6) | The node's account and the monitoring role are refused when they open the ring. |
| A re-bound NIC is caught (D6, §7 step 4) | Re-bind IPv4 on the monitoring NIC and start the sensor: `sensor-interface-bound` is raised. Where a hosted runner can't re-bind, the step reports `unknown`. |
| Packets stay at the site | A forwarded alert carries the hash and frame numbers and no packet bytes. |

## 9. Open points

**Under option (b):** the points stand as written, except the driver access on Windows, which is **History**, and the sensor's buffer, now sized in Part 1 §1.6.

- **The class names, full actions, floors and alarm codes** are drafts for the C5 change at Order step 2. They depend on C13's record shapes.
- **A third class for unresolved observations, or a rate budget** (§3). D1 ruled a rate budget for 0.1, on condition that the ring redaction and the alert aggregation are in. D6's spoofing-flood test decides: if alerts or SER and Syslog are starved, `network-unresolved` becomes a C5 class before the gate. D1 records this with the decision that approves C13 and the C5 draft.
- **The aggregation window and sample size** (§3): C13's and D4's.
- **Retention of the capture ring by size only** (§4): if the owner needs a retention in days, that is D3's row and a C5 question.
- **Driver access on Windows, and egress enforcement on Linux** (§7): `unknown` until ADR-0009's runs show them.
- **Option (b)'s buffering on the sensor host:** D4's design.
- **A detector checkpoint with sessions and no clock** (found on desk Linux while writing D6's rows on #590) is fixed by B4 (#593): with no `clock_utc`, a checkpoint may hold `session_through` and pending sessions, so a collection that runs before the sensor has sent anything no longer fails the checkpoint (`TestDetectorSessionBeforeClock`, desk Linux).
- **Restore reads the health stream from the detector's `SessionThrough`** (#596), the last session it took, so a `collection.run` before it is not read again, and a run after it is read and taken, after a crash before its checkpoint too (`TestDetectorHealthReadRestored`, `TestDetectorHealthReadAfterCrash`, desk Linux). A checkpoint that doesn't restore reads from the first retained record, as on a first start.
- **The alert drop counts don't close AP-36 (3)'s hiding case** (D1 on B3). Naming enrolled assets first keeps decoys to unresolved addresses from pushing a real asset's drop into `other`, but a spoofed source address can still land decoys on an enrolled asset. Past 8 named pairs, a restart can move a pair's attribution into `other`. The total is never lost across a clean stop; a crash can lose up to the last minute's counts, as D5-c5-0.9 §4 says.
- **`runs_session_missing` counts since start** (D4 on #590). A `collection.run` that doesn't parse, before the last session the restored detector took, is not counted again after a restart. One after it is, and so is a session after it that the detector refused for ordering, which can raise `network-detector-ordering` again: the detector's `SessionThrough` moves only at a session it takes (D4 on #600).
