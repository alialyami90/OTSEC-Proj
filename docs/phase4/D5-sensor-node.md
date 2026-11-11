# D5: the node's side of the passive network sensor (P4-4-A5, revised for option (b) under P4-4-L3)

D5 wrote this note on 2026-11-07 for brief P4-4-A5. **D5 revised it on 2026-11-11 for brief P4-4-L3** (`docs/agent-handoffs.md`, "Phase 4 item 4, second part", D4-86), after the owner chose option (b) (D4-85): the sensor is a separate Linux host at each site, and the node dials it. **This text answers the reviews of `a50ee61c` and of `4d03075a`:** D4's B1 and B2, D3's L1 to L4 and its three changes, D6's B1 to B7 and its four points, `records-auditor`'s points, and D1's rulings on #628 and on C13 0.2 (#627). §1.16 maps each finding to the section that answers it.

- **Part 1** is the node's side under option (b), a design for D1's approval. Its requirements are D3's rules (`docs/phase4/D3-sensor-link.md`, SL-1 to SL-29 and SL-R1 to SL-R8), C13 0.2 as proposed in #627 and D1's rulings. **C13 0.2 is cited as `docs/phase4/D4-c13-0.2-proposal.md` (#627)** (clauses CH-1 to CH-47), by file and PR, not by head (D1's ruling). The two documents were reviewed together; the pair of heads that every reviewer passed is recorded in D1's merge comment on each PR. **D1's rulings are cited where they are recorded:** "ruling N on #628" is D1's comment "Reviews of `a50ee61c`, and D1's rulings" on #628 (rulings 1 to 15); "recorded ruling N" is D1's comment "Rounds two and three, and D1's further rulings" on #628 (comment 6803459738, rulings 1 to 4); "ruling N on #627" is D1's comment "Reviews of `674ce453`, and D1's rulings" on #627 (rulings 1 to 8), whose table of the twelve differences is cited as "difference N"; and D1's later rulings on #627 are its comments "Round two at `873c0eb5`" (6803089547) and "Rounds three to five, and D1's ruling on CH-40" (6803460354), and each CH number here was checked against that head. Where #628 and that head still differ, §1.11 lists it for D1. Each item names the code on `main` it changes and the test that would show it, with its control.
- **Part 2** is the note of 2026-11-07. The sections written for a sensor on the node, over a named pipe with a service SID, are marked **History**: they apply again only if option (a) or (c) is reopened. The sections that still hold say what option (b) changes in them.

**Evidence.** Everything in this note is `desk`. A statement about what exists names the file and function it was read from, on `main` at `551b03dd`. Every other statement is a requirement and is **not built**. No test was run for this note, nothing was installed, and no device or network was contacted. Nothing is `hardware-verified`. A figure marked **unmeasured** is a choice with a stated reason, not a measurement.

# Part 1: the node's side under option (b) (P4-4-L3)

## 1.0 Findings about `main`

D5 found four ways, D6 five more, and D5 a tenth on the second read, in which a sensor's work on the node can reach SER collection, Syslog receive, forwarding or the node's start. D3 and D6 each read the functions and agree that F1 to F9 are real, and `records-auditor` checked all nine against `origin/main`. **Each is `desk`, read on `main` at `551b03dd`, and none was reproduced by a run. No record can arrive from a sensor today:** no product code calls `ServeSensor` or `sensorlink.Link.Serve` (only tests do: `platform/node/*_test.go`, and D6's `tests/security/sensor_status_boundary_d6_test.go`, `sensor_unreachable_d6_test.go` and `detector_before_clock_d6_test.go`), so the intake that is merged has nothing that feeds it. **But F2, F5 to F7, F9 and F10 are reachable by configuration alone, on `main` today** (D6, and D1's comment 6803782160): they need only a `network_sensor` section in the node's configuration, with no sensor at all, and `main` accepts that section, though only with `evidence_class` `simulated` (`checkNetworkSensor`). For F2, `Start` (`runtime.go`) returns the error of `startSensor`, which runs whenever the section is set and fails when the hold's records cannot be read (`loadIntake`) or recovered (`Link.RecoverHold`); for F7, the same `Start` returns the error of `startDB` for the network database, which exists only with the section. Both need the section and nothing more.

| | Found by | File and function | What it does |
| --- | --- | --- | --- |
| F1 | D5 | `platform/node/missed.go` `heldMissed`; `schedule.go` `runOnce`; `layout.go` (the health stream in the evidence database, class `platform`); `contracts/store/class.go` (`platform` is refuse-new) | While an entry's `collection.missed` can't be written, its runs are not sent. A sensor's health events that filled the platform class would stop SER collection. Today the sensor writes `intake.drop-counted` (`sensor.go` `reportDrops`) and the network database's store alarms (`runtime.go` `storeAlarm`, `Tick`) there |
| F2 | D5 | `platform/node/runtime.go` `Start`, `startSensor` (`sensor.go`) | A fault in the intake's start (`loadIntake`, `Link.RecoverHold`) fails the node's start |
| F3 | D5 | `runtime.go` `Tick`, `tickSensor` (`sensor.go`), `tickDetector` and `observeTo` (`netdetector.go`) | The sensor's work, with a detector drive that has no bound, runs inside `Tick`, before `Prune` and the status write |
| F4 | D5 | `netintake.go` `dispatchHold`, `resultHold`, `abandonHold`; `platform/sensorlink/hold.go` `Dispatch`, `Result`, `Abandon`; `link.go` `observe` | The scheduler's run path takes `Link.cmu`, which the read loop holds through each network commit and each hold save |
| F5 (D6 B1a) | D6 | `runtime.go` `Tick`, `view` | `Tick` holds `r.state`'s write lock across `c5.Resume` of a blocked or drain-only database, up to `StartupDeadline` (5 min). Every `Log`, `Store` and `Mode` call takes the read lock through `view`: the scheduler's run path, and the Syslog intake's appends |
| F6 (D6 B1b) | D6 | `prune.go` `Prune`, `pruneDB`; `schedule.go` `cannotKeep` | One mutex, `pruneMu`, over every database, and `pruneDB` loops while a class is above target. `cannotKeep` calls `Prune` on the run path, **only when adapter-evidence is near its limit** (its used bytes plus `QuarantineRoom` above its quota), which is when collection most needs it |
| F7 (D6 B1c) | D6 | `runtime.go` `startDB`, `adopt`; `Start` | A database that opens and then fails a read fails the node's start; each database's startup runs in turn before any collection |
| F8 (D6 B1d) | D6 | `suspend.go` `pruneConsumers` | **A property of the design proposed here, not of `main`:** `main` has no `node-sensors` consumer. #628's first text added one, and a required audit consumer whose cursor stops would hold the audit stream; a full audit class stops credentialed collection (D1-11, `TestAuditFullSendsNothing`) |
| F9 (D6 B1e) | D6 | `runtime.go` `modeChanged`, `Tick` | Each mode change of any database writes a `store.mode_change` audit record and a health event, with no cap |
| F10 | D5, second read | `platform/node/forwarding.go` `NewForwarding`, `liveStore.db`; `modules/telemetry/forward/forward.go` (the send loop over `cfg.Streams`, and `peek`) | Each target has one forwarder session over every stream, the sensor's alert stream among them. `liveStore` returns an error when a stream's database is not open, `peek` returns it, and the send loop returns it, which ends that target's session for **every** stream. So a sensor database that is not open stops that target's forwarding of SER and Syslog events too (D6's item 2 on `4d03075a` reached the same path through `Forwarding.Check`) |

Also read for this note (`desk`): `Runtime.Collecting` iterates every database, but no product code calls it, so it reaches nothing. And no file under `platform/node`, `platform/sensorlink` or `cmd/otsec` calls `recover`, so a panic in the sensor's work, today inside `Tick`, ends the node (D6; §1.9 item 9).

**D1's ruling on #628 (comment 6803782160, "A correction to D1's record of the couplings, and what holds until they are closed"), which replaces the earlier "they gate the dialer":**

1. **Until F1 to F10 are closed, no configuration outside the tests carries a `network_sensor` section.**
2. **It is a release blocker:** no release ships before F1 to F10 are closed.
3. **Closing them is the first brief of the third part,** to D5, before any dialer: each of F1 to F10 as listed here, closed as §1.9 says, with its test and its control, reviewed by D6 and D3.
4. **No code that feeds the intake merges before then:** neither a caller of `ServeSensor` nor one of `sensorlink.Link.Serve`.

D3 records them in the threat model (AP-19, AP-34 (5), SL-20; HR-13 as the precedent), and D6 gives the set a finding number in `docs/verification.md`.

**Other facts this design rests on** (`desk`):

- `ServeSensor(ctx, io.Reader)` (`sensor.go`) takes no peer identity and cannot write back, and the node has one intake (`Runtime.sensor`). The link refuses a record under another `sensor_id` (`RefusedSensorID`) and a seq at or below the run's last (`Link.takeSeq`), and keeps its run and seq in memory only (`link.go`).
- `network_sensor` names one sensor (`NetworkSensor.SensorID`, `netsensor.go`), in one database, `network` (`NetworkDB`).
- No `sensor.coverage-gap` event is built: no file names it.
- The configuration is read at start only; `reload` reloads the suspensions and halted assets, nothing else (`reload.go`).
- The node does not apply `node.network_baseline_ack`: nothing under `platform/` or `cmd/` imports `modules/security/netack`, `relayKinds` does not list the kind (`adminrelay.go`), and no network learner runs on the node (§1.12).

## 1.1 The dialer and the firewall rule (brief item 1)

**Requirement, not built:** a new file `platform/sensorlink/dial.go`, with one dialer for each enrolled sensor. The sensor manager (§1.9) starts it after `Start` returns, never inside `Start`.

| Setting | Value | Rule |
| --- | --- | --- |
| Versions | `MinVersion` and `MaxVersion` both TLS 1.3 | SL-12 |
| Resumption | `SessionTicketsDisabled`, and no `ClientSessionCache`, so every handshake is a full one. Go's client sends no early data (an assumption, §1.14) | SL-12 |
| Peer check | **Normal verification is off, and `VerifyConnection` is the only check.** It refuses a resumed session (`DidResume`), a version other than TLS 1.3, and a connection whose ALPN was not negotiated; then it computes the leaf's pin and accepts only the pin of the enrolment in force at that moment, read through an atomic pointer that a revocation or a new enrolment replaces before it closes the link (§1.3). The configuration is built in one function, and a test shows that `InsecureSkipVerify` appears in that one product file only. D3 adds the matching line to HR-15's review rule (a client with no `RootCAs`) | SL-2, SL-12, SL-R2, HR-15 |
| Client certificate | `GetClientCertificate` returns a self-signed certificate made in memory at each node start, whose key is the node's link key. Nothing is written to disk. Its dates mean nothing: the node enforces the enrolment's `not_after` (SL-8) | SL-2 |
| ALPN | `otsec.netobs/0` (the major only) on both ends, refused if not negotiated (difference 8 on #627; CH-1) | SL-19 |
| Timeouts | TCP connect 5 s (node-local); C13 0.2's handshake 10 s, `sensor-hello` 10 s, idle 30 s (CH-4); a write deadline of 10 s for each node message (node-local); an `ack` at least every 10 s (CH-9) | SL-12, SL-20 |
| Back-off | 1 s, doubling to 60 s, with ±20 % jitter. It resets only after a connection whose hello was accepted and which lasted 60 s | SL-20 |
| Redial after `run-complete` | CH-38: **without back-off only when the node itself saw the run finished** (the agent closed cleanly, and T had reached the run's `newest_seq` as the hello and ticks last stated it), **and at least `RedialFloor` = 10 s has passed since the last such redial** (recorded ruling 2 (#628, comment 6803459738)), so at most 360 an hour. Otherwise the back-off applies. A clean close the node did not see as finished takes the back-off (D3's L1) | SL-20 |
| Connections | At most one for each sensor. The dialer is the only caller, and the intake refuses a second concurrent connection for the same sensor (`second-connection`) | SL-12 |
| Memory | One frame at a time, at most `MaxChannelFrame` (64 KiB) and its decoded record, as `Link.Serve` reads now; the node's own frames are under C13's 1 KiB (CH-2) | SL-20 |
| When it dials | Only while the configuration equals the live enrolment, the enrolment is neither revoked, fork-held, expired nor held by a pending revocation file (§1.3), the sensor's state is known, and **the address is no asset's** (below). Otherwise it does not dial, and the alarm says why | SL-4, SL-9, P1 |

- **The node never dials a device** (D3's L4, ruling 5). A sensor's IP address must be no IP address that any asset in the node's configuration has, in any endpoint or identity field. The comparison is on the IP alone, with any port, since a device's other ports are still the device. It is checked in four places:
  - **at load, and the reverse at load** (an asset added with an enrolled sensor's address): **never a refused configuration** (recorded ruling 1 (#628, comment 6803459738), D3's change 3). That sensor is not started and is never dialled, `sensor-address-is-asset` stands and names both, and collection for the asset goes on;
  - at enrolment: `sensor.enrolled` `denied`, reason `asset-address`;
  - at each dial, against the configuration as loaded;
  - in `otsec install-sensor-rules`, which refuses to write the rule.
  - Test: `TestSensorAddressNotAsset`, for each of the four places and the reverse, with the node started and a run stored in the two load cases; its control, the check removed, dials the simulator's device address and the test's listener sees the SYN.
- **The link key** is a node key register entry of **a kind of its own** (D3's condition), not a mark on `tls-key`, so every existing reader refuses it by default: `LoadCertificate` refuses it, and so a forward target or listener cannot use it. A function that returns its signer and pin, and refuses every other kind, sits in a package that only `platform/sensorlink` imports (an import test). Today a `tls-key` stays `pending` until a CA chain is installed (`modules/security/nodekey/register.go`, `StatePending`, `Install`). The change is D3's, briefed in the third part (ruling 15). The pin goes in status, for the administrator to read (SL-5 step 2). A local administrator can use the key (D3-7); that limit carries over.
- **`ServeSensor` changes shape** (CH-25, D5-12): `ServeSensor(ctx, peer sensorlink.Peer, conn io.ReadWriter)`. **`sensorlink.Peer` can be made only from a finished handshake:** its fields are unexported and its one constructor takes a `tls.ConnectionState` whose pin the enrolment accepted, so no later caller can hand `ServeSensor` an identity it invented (D3's condition). The link that serves it is chosen from `peer`, never from a record (SL-10). D6's three tests that call today's form move with the third part.
- **The node's close reasons** are C13's closed set as ruled on #627 (difference 7 on #627; CH-11 and CH-37): `store` (§1.4), `position-not-saved` (§1.4), `second-connection`, `enrolment` for a revocation, the revocation fast path or a new enrolment that replaces the pin (§1.3), and `shutdown` when the node stops (CH-11, CH-37). **An edited `network_sensor` entry closes as `shutdown`, not `enrolment`:** the configuration is read at start only, so the open connection ends because the node stops, and the restarted node does not dial because the entry no longer equals the enrolment (SL-9; CH-37). After an `enrolment` decision the node takes no further record of the connection and sends no `ack`, and the close is a TLS close with no message (CH-37).
- **The firewall rule.** `platform/winsvc` `Install` adds one rule today, which blocks the node service's outbound TCP to port 23 (`install_windows.go`). **Requirement:** a subcommand `otsec install-sensor-rules -config <file>` in `cmd/otsec`, which an administrator runs elevated after each enrolment. It adds, for each configured sensor, a rule named `OTSEC node to sensor <sensor_id>`: outbound, allow, service `otsec-node`, TCP, that sensor's address and port, and refuses an address that is an asset's. The node never changes a firewall rule itself (CLAUDE.md §10). A block rule still wins over it (D3). **Assumption, not read:** that Windows' default outbound policy is allow, so the rule matters only where a site blocks outbound by default. The guard on every site is that the node dials only the enrolled address. No inbound rule is added and no listener is opened (SL-18).
- **Tests.** In `platform/sensorlink`, over loopback TLS with test keys: `TestDialRefusesTLS12`; `TestDialNoResumption`, whose control is a client session cache, which makes the second connection resume; `TestDialRefusesOtherPin`, whose control is a `VerifyConnection` that accepts any key; `TestDialPinReadAtHandshake`; `TestDialRefusesNoALPN`; `TestDialHandshakeStall`; `TestDialBackoff` on the test clock; `TestRedialAfterRunComplete`, whose control redials at once after any clean close, and its leg for `RedialFloor`; `TestOneConnectionPerSensor`; `TestInsecureSkipVerifyOneFile`; and an import test for the link key's signer. On the rig: SL-T3, SL-T7, SL-T8, SL-T11, and SL-T13's leg (h) (§1.9). The firewall rule is read back in the dispatched Windows workflow (`a5-windows-experiments.yml`) where a hosted runner allows it, and is `unknown` where it doesn't.

## 1.2 The `network_sensor` configuration, and one sensor or two (brief item 2)

**Requirement, not built.** The section keeps its node-wide fields (`evidence_class`, `outage_hours`, `alert_retention_days`, `node_addresses`, `node_macs`, `node_vlans`) and gains:

- `link_key_ref`: the node's link key in the key register (§1.1). One key for the node, as SL-R8 assumes.
- `sensors`: a list, each entry with `sensor_id`, `address` (an IP literal) and `port`, `sensor_spki` (the pin) and `config_digest` (D5-4, §1.15). The pin is the **trust anchor**, since there is no CA (SL-2). The link key is the **credential**. The **permitted peer** is the `sensor_id`, address and pin together, which must equal the live enrolment (SL-9).
- `retired`: `sensor_id`s whose streams are kept until drained and pruned (§1.7), at most `MaxSensors`. **Why that number:** a retired database costs its quotas in the volume rule and a share of the platform ceiling (§1.9), and a node only ever retires what it ran.
- `max_skew_ms` (§1.5, CH-22): 2,000 ms, the node's fixed bound, not a site setting.
- `blind_after_s` (§1.8), `late_bound_s` (CH-23, **180 s** by default, 30 s to 3,600 s, recorded ruling 2 (#628, comment 6803459738)) and `backlog_tie_s` (CH-39, 60 s by default, at most 120 s, recorded ruling 2 (#628, comment 6803459738); §1.6).

**One sensor or two (ruling 1).** The list holds at most `MaxSensors` = 2. **The third part builds one:** a second entry is not started, and `sensor-not-built` stands, until a second is built; the node starts and collects as without it. A second waits for the owner's answer on PRP (O-12), and nothing that merges two sensors' records is designed before it. What a second would cost, for that decision:

| | One sensor (built in the third part) | Two sensors (later, on O-12) |
| --- | --- | --- |
| Intake | One link and one hold | A link and a hold for each. `dispatchHold`, `resultHold` and `abandonHold` call each sensor's link. `collection.run` carries `after_seq.<sensor_id>` and `open_flow.<sensor_id>`, and `runSessionOf` reads its own sensor's keys, and the plain keys of a record from before as the single sensor's. The handover barrier (`intakeRecords`) is kept for each sensor |
| Store | One database, `network-<sensor_id>` | A database for each, so a quota, which is per class in its database, keeps one sensor's flood from dropping the other's records. A second set of network quotas in the volume rule |
| Baseline and detector | One of each | One of each for each sensor, on its own `netbaseline/<sensor_id>` stream. A person signs an acknowledgement for each. On PRP, traffic on both LANs alerts twice (CH-30 option (ii)) |

**The database's name.** It is `network-<sensor_id>` from the third part on. A `network` database left by a node that ran the merged pipe-era intake stays on disk unopened and is never deleted, as every store file is (Part 2 §5). No site has one: `evidence_class` must be `simulated` (`checkNetworkSensor`). The places that test for `NetworkDB` change (`commitcap.go`, `runtime.go` `startDB`'s `WallMark`, `netretention.go`, `sensor.go`, `netdetector.go`), and the sensor databases move out of `Runtime.dbs` (§1.9 item 1).

**No sensor check fails the node's start or refuses its configuration, except the section's own shape** (recorded ruling 1 (#628, comment 6803459738), D3 and D6). The shape checks stay load failures, as SL-9 says: the top-level `sensor_id` (refused with a message that names `sensors`), a third entry, a duplicate ID, address or pin, an address that isn't an IP literal, and an ID both in `sensors` and in `retired`. **Everything else that concerns a sensor leaves the node to start and collect, with that sensor not started and an alarm standing:** an address that is an asset's, or an asset with an enrolled sensor's address (§1.1); the platform floor (§1.9 item 5); a second entry before a second is built; and a mismatch with the enrolment (§1.3). A sensor's paperwork or sizing never stops SER or Syslog collection (SL-9, SL-20). Code: `NetworkSensor` and `checkNetworkSensor` (`netsensor.go`), `networkLayout`, `Config.Consumers` (`layout.go`), and every reader of `NetworkSensor.SensorID`.

**Tests**, in the new package of §1.9: `TestNetworkSensorsShape` (none, three, a duplicate and the old top-level `sensor_id` refused at load; two while one is built, and an asset's address, each starting the node with that sensor not started and its alarm, whose control is a load refusal), and for the later second sensor `TestTwoSensorsSeparateDatabases` (A's observation class filled, B's records still commit; control: one shared database, where B's drop), `TestCollectionRunAfterSeqPerSensor` and `TestRunSessionReadsPlainAfterSeq`.

## 1.3 Enrolment, revocation and expiry (brief item 3)

### Where the state lives

D3 asks that the live enrolments and the revoked pins never depend on the audit stream alone, which is pruned (SL-6). On `main` the suspensions are kept as a checkpoint file, `suspensions.json` in the store directory, folded from the audit stream, with the C5 consumer `node-suspensions` holding the stream's prune point (`suspend.go`, `loadSuspensions`, `pruneConsumers`). This design follows that pattern and needs no C5 change, with D3's conditions:

- **`sensors.json`**, schema `otsec.node-sensors/0.1`, written whole to a temporary file and renamed. It holds `through_seq`; for each `sensor_id` its generation, pin, address, the node's pin, `not_after`, the decision's `decision_seq` and payload hash, its state (`live`, `revoked`, `fork-held`), and the first `pinned_by` of the generation (CH-33); the revoked pins, never removed; and the revocation records owed. **Nothing that changes at the sensor's will is in it** (D3's preference): run counters and refusal times are in a second file, `sensorrun.json` (§1.4, §1.9 item 6), so a reconnect loop never rewrites the file that holds the pins.
- **A consumer `node-sensors`** on the audit stream, added by `pruneConsumers` beside `node-suspensions` and `node-holds`. Its cursor is kept **one write behind the file**: after a new file is written, the cursor moves to the previous file's `through_seq`, so a file that a power cut rolls back still finds its records (D4-65's open question about a rename's durability does not wait).
- **A rolled-back or old file** (D3's condition 1): a file whose `through_seq` is below the cursor is folded forward only if every audit record after it is still in the stream. A gap makes the state unknown, and nothing dials. A revoked pin therefore never comes back live from an old file.
- **Its own fold.** `foldSensors`, in a new file `platform/node/sensorstate.go`, reads the audit stream from the file's `through_seq` in pages of 64, each read under a 1 s deadline, yielding between pages, and runs in the sensor manager, never in the scheduler's `fold`. A sensor record that doesn't parse, or a fold that fails, makes only the sensor's state unknown: nothing dials, `sensor-state-unknown` is raised, and collection goes on. The reason is in `loadSuspensions`: an error in the suspension fold holds every run (`asset-suspensions-unknown`).
- **A read error and a bad record are not the same** (D3's change 2 on `4d03075a`, keeping `main`'s distinction, `badRecord` in `suspend.go`):
  - **A read error** (a deadline passed, the database busy or not open) is retried at the next manager tick **with the cursor held**. The state is `sensor-state-unread` meanwhile, and the revoked pins stay in force. Two rules keep it from failing open (D3 on `e2ff17c7`; SL-R2, P5):
    - **After a start, nothing dials until one fold has read through the audit stream's head.** Before that the state in memory is the file's, which may predate a revocation whose file write failed. A read error later in the run keeps only the links this run has already confirmed by such a fold.
    - **A read error never delays a revocation.** An accepted `node.sensor_revoke` that the scheduler hands over is applied in memory at once, whatever the fold's state, and the fast path's hold stays until it is.
    - Test: `TestSensorUnreadAtStartDialsNothing` (a failed revocation write, a restart, and a first read that fails: nothing is dialled; control: the node dials under the file).
  - **A record that cannot be parsed** makes the state unknown: nothing dials, and `sensor-state-unknown` is raised.
  - **The cursor moves on** past what the fold could not use only for such a record, or when the audit class holds more than three quarters of its quota, so the cursor never holds the audit class past that fill (F8). **Before it moves, the manager writes to `sensors.json` every revoked pin it has read,** and the file's revoked pins stay in force through the unknown state and the next enrolment. So a slow read never loses an enrolment or a revocation (SL-6), and a bad record loses at most the enrolments after it, never a revocation already read.
  - Nothing dials after an unknown state until a new enrolment, which the fold then reads from its own record. The cursor is saved at most once a minute, outside any loop over records.
  - Test: `TestSensorStateReadErrorRetried` (a read that fails once: the state returns at the next tick and the stream is intact; control: the cursor moved on at once, which loses the enrolment once the stream is pruned).
- **A failed write of `fork-held`** fails closed like a failed revocation write: the dialer stays off for the run, and the fold derives the hold from `sensor.link_refused` (`run-forked`) at the next start (D3's condition 3).
- **With the file lost and the stream pruned past what it needs,** the state is unknown and nothing dials. An administrator's new enrolment, at a generation above every one still in the chain, is then applied, and `sensor.enrolled` records the previous state as unknown. **Limit:** a revoked pin that only the lost file held could be enrolled again by a new signature.

### Enrolment

`relayKinds` and `nodeActKinds` gain `node.sensor_enrol` and `node.sensor_revoke` (`adminrelay.go`), and `applyAdminPart` gains two cases, bound to the install key as `node.baseline_ack` is (`admin_actions.go`). **Each case only hands the decision to the sensor manager over a buffered channel and returns** (D3's note 3): the part shows `pending` until the manager reports it done, so the scheduler never waits on the manager. The manager:

1. writes `policy.apply` with `admin_keys` first when the acceptance names a new key set (C8 0.12's rule, `netack.NeedsGrantRecord`);
2. checks SL-6's list: the node's pin is its link key's; the generation is one above the last, or 1; the pin is neither revoked nor fork-held; `not_after` is at most 366 days after `issued_at`; and the address is no asset's (§1.1). A failed check writes `sensor.enrolled` with outcome `denied` and its reason, and changes nothing;
3. writes `sensor.enrolled` with `c5.AuditBeforeAct`, and applies nothing if that write fails (the part stays pending and is tried again);
4. **closes that sensor's open connection, if any, with `enrolment`** (D3's L3 (iii)), so the old pin is replaced at once (SL-6, SL-R6);
5. applies it in memory, writes `sensors.json`, and starts the dialer if the configuration matches. A mismatch raises `sensor-not-enrolled` and dials nothing. **An enrolment that is live but not configured** shows in status (D3's note 5).

**What a new enrolment does to the position** (CH-12; ruling 5 on #627 with D3's condition). It depends on the signed `reason` **and on whether the sensor's pin is unchanged**, never on the reason alone; D3 adds to C7 0.11 that `renew` needs the same pin and `rekey` and `replace` a different one.

- **`renew` with the pin unchanged:** the generation rises, and **the node's saved position carries over** (the run counter, `run_id`, T, G, D and the totals in the cursor, and the run in `sensorrun.json`), as the agent's buffer does. So an expired enrolment, renewed, loses nothing, and the sensor's old runs are not closed as `run-regressed`. `sensors.json` keeps the generation's reason and pin, which decide this (CH-18).
- **Any other enrolment (`new`, `rekey`, `replace`):** run 1 of the new generation begins, and the node's position for the sensor starts again (SL-16).
- **On `replace`,** the old host may never send the hello that would declare its discarded tail, so the node writes its own count of the old generation's unsent tail, the last `newest_seq` that host stated less T, in a `sensor.run-loss` event.

### Revocation

Once the collector's acceptance is folded:

1. mark the pin revoked in memory and write `sensors.json`;
2. close the connection with `enrolment` and stop the dialer. A dial in its handshake fails at `VerifyConnection`. **Steps 3 to 5 begin only after the read loop has returned** (`Link.Serve` and `ServeSensor` return), so no record is being committed (D3's L3 (i));
3. release every run that sensor's hold still holds, tied where its result came and untied otherwise, each in one release (`Link.release`), so no held record is left;
4. take the observation stream's `through_seq` as its last committed seq. **The alert stream's `through_seq` is taken once the detector has judged every observation at or below the observation stream's `through_seq`** (D3's L3 (ii)), so no alert from the sensor's earlier observations lands above it unmarked;
5. write C8 `sensor.revoked`, with both `through_seq` values. Until step 4's alert half is done, the record is owed;
6. commit a health event `sensor.revoked` to the health stream, not to the alert stream.

- **From the fold of the acceptance to the close: within 1 s** (ruling 2), tested by `TestSensorRevokeCloseWithinOneSecond` on the test clock; its control takes the close after the audit write, which a failing write then holds open.
- If step 1 fails, the dialer stays off for the rest of the run and `sensor-state-not-durable` is raised. At the next start the fold derives the revocation from the decision in the chain, which needs the relayed `collector.request` record to name the target, as fields and only for an accepted, verified request (C8 0.13, D3 drafts it).
- If step 5 fails, the link stays closed, the record is owed in `sensors.json` and in status, and the manager writes it once when the audit chain takes writes again.
- **How soon "at once" is (ruling 2, option (a)).** `relayAdmin` runs between runs, never during one, every `RelayEverySeconds` (15 s), and a run lasts at most `MaxDeadlineMS` (600 s) (`adminrelay.go`, `schedule.go` `Run`). So, from signing to the close, about 15 s when no run is in progress, and about 615 s at worst **when the collector answers. While `collectorHold` holds requests, `relayAdmin` sends nothing, and the bound is open.** The collector's pipe takes no second client (D3: a change to the privileged process that this gain does not justify). **Why minutes are tolerable:** every record committed in the window is at or below `through_seq` and after `suspect_from`, so every reader shows it as from a revoked sensor (SL-R3).
- **The fast path (ruling 3, D3's).** Every 15 s the manager reads `admin_dir` under the protected-file rule, as `scanAdmin` does (`adminrelay.go`), and when an `admin-request-*.json` file of kind `node.sensor_revoke` names a live sensor and is not yet decided, it **stops dialling that sensor and closes its connection** (`enrolment`), and raises `sensor-revoke-pending` while it holds. The payload is read for its `sensor_id` and pin only, before any signature is checked, so this can only stop a link, never start one or change state. It lifts if the collector refuses the request, if the file goes away undecided, or **when the request's own expiry passes** (D3), so a stale file cannot hold a link down while `collectorHold` stands; it becomes the revocation above if the collector accepts. No new file format. Test: `TestSensorRevokeFastPath` (a pending file stops the dial within 15 s; a refusal lifts it, and so does the request's expiry; control: the file ignored).
- **The local stop** (SL-9): "edit or remove the entry, and restart the node service". It needs no collector and no audit write, and leaves `service.start` in the chain. The restart pauses collection for the length of a start.

### Expiry and `pinned_by`

- `sensor-enrolment-expiring` from `CertWarning` (30 days, `certperiod.go`) before `not_after`, repeated hourly in status (HR-13's precedent). At `not_after`, `sensor-enrolment-expired`: a running link is not cut, and the next dial is refused, which writes `sensor.link_refused` with reason `expired` under the cap (§1.9 item 6).
- **`pinned_by`** (ruling 4): shown in status, with a standing alarm `sensor-pinned-by-console` while a live sensor reports `console`. No refusal.
- **Limit** (D3's condition 4): whoever can write the store directory can change a pin or remove a revocation with no signature. That is a compromised node (SL-5). Status shows each enrolment's `decision_seq` and payload hash, so that an off-host copy of the chain can be compared.

**Tests**, in the new package of §1.9, on the test clock: `TestSensorEnrolApplied`; `TestRenewCarriesPosition` (a `renew` with the pin unchanged: the old runs resume, not `run-regressed`; control: the position started again at every enrolment); `TestReplaceCountsUnsentTail`; `TestEditedEntryClosesShutdown` (CH-37's M-9 leg); `TestSensorEnrolDenied` for each of `generation`, `revoked-key`, `forked-key`, `node-key`, `not-after` and `asset-address`; `TestSensorEnrolAuditFirst` (control: apply before the audit write, which then applies with the write failing); `TestSensorEnrolClosesOldConnection` (control: the old connection kept, which takes a record under the old pin); `TestSensorRevokeClosesFirst`, with the audit write made to fail; `TestSensorRevokeAfterReadLoop` (a record in commit at the revocation lands at or below `through_seq`; control: `through_seq` taken at the close); `TestSensorRevokeAlertThrough` (alerts raised later from earlier observations are at or below the alert `through_seq`; control: taken at the revocation); `TestSensorStateSurvivesPrune` (control: the consumer removed, which enrols a revoked pin again); `TestSensorStateOldFile` (a file below the cursor with a gap after it: unknown; control: folded anyway, which brings a revoked pin back); `TestSensorFoldErrorKeepsCollection` (control: the sensor fold joined to the suspension fold, which holds every run); `TestSensorStateReadErrorRetried`; `TestSensorCursorMovesAtFill` (an unparseable record with a small audit class: the cursor moves at three quarters and the revoked pins are written first; control: the cursor held, which fills the class); `TestSensorExpiry`. On the rig: SL-T4, SL-T5 with an expired, a revoked and a fork-held enrolment at start (the node starts, collects SER and Syslog, and alarms), SL-T10 with the node killed between the close and the audit write, and SL-T20's node leg (an enrolment that names the old node pin is `denied`, `node-key`).

## 1.4 Replay, resume and the acknowledgement: one position (from SL-13 to SL-16; D4's B1, D6's B3, ruling 6)

**One number.** The node's position for each sensor is the observation stream's source cursor, which C5 already has, and nothing else. The taken position T that every `ack` names, the `taken` that `node-hello` sends (CH-6) and the resume point after a restart are all that cursor's seq. **Requirement, not built:**

- **What it holds:** the generation, the run counter, the `run_id`, T, G and D of CH-15, and **the run's total refused and total dropped records** (ruling 6). In a fixed text form, `sp1 <gen> <counter> <run_id> <T> <G> <D> <refused> <dropped>`, with every decimal at most 20 digits, it is at most 187 bytes. **`MaxLinkCursorBytes` = 192,** the node's own constant (`records-auditor`; difference 11 on #627), so the worst stored observation, about 34 KiB of the 64 KiB cap (C13 §10), keeps its room; R-5 runs with it.
- **When it is written:** in the same transaction as each committed observation (`Record.SourceCursor`, `contracts/store/commit.go`), and on its own with `store.DB.SaveSourceCursor` (`platform/store/outbox.go`, not part of C5) when nothing commits: after a refusal, a drop, a duplicate or a gap, at most once a second (`AckMaxDelay`, CH-9), and **before every hold save** (below). The value written is never below the position already saved, so a release that commits older held records never moves it back.
- **The `ack` never names more than the saved cursor.** A record is counted into T only once it is committed, saved in the hold's checkpoint, a duplicate, a gap, or refused or dropped for a final reason (D5-1) **with its total in a saved cursor.** So a node crash can never erase the only trace of a record the sensor has trimmed (ruling 2 on #627), and **no committed record is ever above the `taken` sent in `node-hello`**, so a resend is always a duplicate (CH-14).
- **A held record is never stored twice** (D6's item 3 on `4d03075a`, and D6 on `7f5b97d4`; D1's ruling to fix it, not state it). The case: a node killed between a hold save and the next cursor save restores its hold with record n while the saved T, and so `taken`, is below n. Two orders follow. The resend of n can arrive while the hold still holds n, or after the hold has released n: `Link.TickHold` releases a hold past its deadline whether or not a connection is open, and `Link.RecoverHold` commits at start a release the kill interrupted (`hold.go`). **The mechanism, which needs no new state (D1's option (a)):**
  1. **Before the hold saves record n, the node saves the position through n − 1** (`SaveSourceCursor`, with the run's totals). So every record below a held one is durably disposed of: committed, held, a duplicate, a gap, or refused or dropped with its total saved. The cost is one cursor save per held record. Held records are the flows between the node's own address and a run's endpoint, at most `HoldRecordCap` (23) a run (`hold.go`).
  2. **Every commit that stores records released from the hold moves the saved position past them in that same transaction, but only within the run the position belongs to** (D6 on `f7971f82`). The node keeps one position for a sensor: the highest run accepted (its counter and `run_id`) and T in it. A seq counts within one run.
     - **A released record of the position's own run:** T moves to the higher of the T already saved and the highest seq released. Item 1 makes that valid, since everything below each released record is already durable.
     - **A released record of an earlier run** never changes T. That happens on `main` in the ordinary course: an engine restart starts a new run, the node saves the new run with T = 0 before it accepts its hello, and the old run's held record is released by `Link.giveWay`, `Result` or `TickHold`. **If the release commits it,** it is stored as the earlier run's record, the cursor written in that commit is the position unchanged, and nothing is counted: a committed record is neither refused nor dropped. No resend of it can come, since the sensor can no longer offer that run (`run-regressed`), so it cannot be stored twice. **If the release refuses or drops it,** that count goes into the refused or dropped total of the run the cursor now holds, the newer run's, the only totals the cursor carries (CH-18); status names the run it came from. **Nothing of the new run is dropped:** its records at or below the old run's seq are read against the new run's own T.
     - This holds for `Link.Result`'s release, `Link.TickHold`'s deadline release, `Link.giveWay`, and `Link.RecoverHold`'s commit at start (`commitBatch`, `release`, `hold.go`; the cursor value in `Link.record`, `link.go`). The store writes the batch's cursor in the same transaction as its records (`platform/store/commit.go`; D6). **`RecoverHold` also compares the saved position,** not the stream's head alone, so that a release which stored nothing but moved the position is not run again after a second kill (D6's note).
  3. **A record the release does not store has its count in the same step.** One that the unresolved budget drops, or that the record cap or C13 refuses, has its total raised in the cursor written by that release's commit. If the whole release stores nothing, a `SaveSourceCursor` carries the totals and the new position before any `ack` passes them (ruling 2 on #627). A store error that is not final (D5-1) leaves the records held, the position unmoved, and the release is tried again at the next tick.
  4. **The duplicate check uses the position saved now, not the one at the hello.** A record whose seq is at or below the run's saved T at the moment it is read is a duplicate: dropped, counted under `duplicate`, never stored. A release in mid-connection can move T above L, the highest seq read on the connection, but only past restored held records. So a resend of n is a duplicate whether it arrives before the release (the hold drops it, matched by `run_id` and `seq`, as `HeldRecord` carries them) or after (its seq is at or below T). **No `ack` names a seq above both the highest seq the node has read on the connection and the latest tick's `sent_seq`** (D3's note; CH-17): when a release raises T above both, the `ack` names the lower figure until the reads catch up, so it never makes the agent close on an `ack` above what it sent.
  5. **At start,** `RecoverHold` runs before any connection (`startSensor`, `sensor.go`), so the first `node-hello`'s `taken` already includes every record it released.
  - So **no committed record is ever above the `taken` sent in `node-hello`, and no record is stored twice, in either order.**
- **What is volatile:** only the split of the totals by reason and by asset, which the `intake.drop-counted` event carries (§1.9 item 5). A crash loses the split since the last such event; the totals survive.
- **A second copy of the run** (counter and `run_id`) is in `sensorrun.json`, written at each **new** run accepted, not at each resume, so a lost network database cannot bring back an old run as new. At start the node takes the higher copy; equal counters with different `run_id`s are a fork (`fork-held`).
- **At a new run** (CH-13 row 6) the cursor is saved with T = 0 **before the hello is accepted**, and so before the first record is taken. **`prior` is durable at the node** (CH-16): its counts, spans, `previous_end` and `started_by` are saved with the new run in `sensorrun.json` before the hello is accepted, and stay there until the `sensor.run-loss` event that carries them commits, so a node crash, or an event held past the ceiling, does not lose the sensor's declaration. A save that fails closes the connection with `position-not-saved`, is counted, and raises `sensor-position-not-saved`.
- **The hello checks** are CH-13's table: `binding`, `run-regressed`, `run-forked`, resume, new run, `pinned_by`, the digest and the buffer floor. On a resume, `prior` must be absent and `drops_channel` must not be below the D the node holds for the run, else `hello`; and row 5a, a resume whose `newest_seq` is below the node's taken seq, is `run-regressed`. **CH-14 changes `platform/sensorlink`'s order:** a record that decodes strictly takes its `seq` before any refusal, `sensor-id` included, so no false gap is counted. `run-forked` writes `fork-held` to `sensors.json` and stops the dialer until a new enrolment with a new key, or a revocation (SL-16).
- **A store error that is not final** (drain-only, a closed database, an I/O fault) is not taken: the link closes the connection with `store`, T does not move, and the dialer backs off, so the sensor's buffer holds the records (D5-1). This replaces `Link.storeDrop`'s `DropStore` branch, which today drops and counts them (`link.go`).
- **G against D:** `sensor-gap-undeclared` is raised once for each rise of the excess in a run (CH-15), as a status alarm, with its health events under the cap of §1.9 item 5 (D4's point 5; D3's note 3 on #627). A declared loss writes its health event from the rise of D, whichever message carried it (D3's note 4 on #627).
- **Tests**, in `platform/sensorlink`: `TestHelloRunRegressed`, `TestHelloRunForked`, `TestHelloBinding`; `TestPositionSavedBeforeFirstRecord` (control: saved after, which after a kill reads as a fork); `TestResumeNoDuplicate` (killed after a commit and before the `ack`: the resend is a duplicate; control: a `taken` below a committed record, which stores it twice; and the legs killed after a hold save and before the next cursor save: (i) the resend arrives while n is held and is dropped by the hold; (ii) the hold's deadline passes before the resume, `TickHold` commits n, and the resend is a duplicate by the saved T; (iii) the kill inside a release, `RecoverHold` commits n at start, and the first `taken` includes n; (iv) a restored record that the budget drops at its release has its total in that release's cursor; (v) an engine restart while run R holds n, and n released after run R + 1's hello: R + 1's T does not move, and its records with a seq at or below n are stored; in (i) to (iv), n is stored once; controls: for (v), the move applied whatever the run, which drops R + 1's records as duplicates; controls: the duplicate match against held records only, and a release commit that does not move the position, each of which stores n twice; and the cursor not saved before the hold save, under which moving T past n loses a refusal's count); `TestAckNeverAboveCursor` (control: an `ack` from memory, which after a kill has acknowledged a record whose count is gone); `TestTotalsSurviveCrash` (a flood of drops, then a kill: the totals in the cursor equal the drops; control: totals in the minute event only); `TestPositionMonotoneOnRelease`; `TestStoreErrorNotTaken` (control: `main`'s `DropStore`). On the rig: SL-T9 (a) to (k), and (g) with the fork hold after a node restart.

## 1.5 Clock skew (brief item 4)

**Why it matters** (`desk`). The hold ties a flow whose start, on the sensor's clock, falls within the session's start and end, on the node host's clock, widened by `g` = `DefaultTieGraceS`, 30 s (`hold.go` `Result`). The detector's clock is the latest `first_utc` it has read, and it judges a session once that clock passes its end plus `g` (`netdetect` `Observe`, `judge`).

**The measure** (CH-22 as ruled). At each `sensor-hello` and each accepted `tick`, never at a heartbeat or a record, the node takes `o` = its wall time at receipt minus the message's `sensor_utc`. The delay in `o` is never negative. A tick that arrives less than `TickMinSpacing` (5 s) after the previous accepted tick on the connection, other than the first after the hello, is counted under `tick_early` and does no further work: no skew sample, no gap check, no timer reset (difference 10 on #627; CH-8).

- **The alarm** uses `E`, the smallest `o` of the connection's last 6 ticks: raised when |E| is above 2,000 ms, cleared at 1,500 ms or less (difference 5 on #627; CH-22).
- **The tie** uses the latest sample too: **no tie is made while the latest `o` is outside 2,000 ms,** even before the alarm's minimum catches up (D3's L2 (iii)). So a clock stepped back ties nothing from its first tick.
- **The sign, and which comparisons use it** (D4's finding 1 on `4d03075a`; D4, D6). The convention is CH-22's: `o` = the node's wall time at receipt − the message's `sensor_utc`, so a positive `o`, and a positive E, means the sensor's clock is behind the node's. **A sensor time is brought to the node's clock by adding E:** `t_node = t_sensor + E`. *Worked example:* the sensor runs 1.5 s behind the node and the network adds 0.01 s, so `o` = E = +1.51 s; a flow the sensor stamps `10:00:00.000` happened at about `10:00:01.51` on the node's clock, which is the time the node compares with a session's start and end. (Subtracting E, as the text at `4d03075a`, D3's text and the first wording of D1's short-break ruling had it, moves the time by 2E the wrong way, a 4 s error at the 2,000 ms bound; D1 corrected that wording on #627, comment 6803089547.) While neither the alarm nor the latest sample is outside the bound, the node's tie comparisons (`Result`'s window, part (d)'s expiry, the late index, and §1.6's `made_utc` check) use `t_sensor + E`. **Nothing stored is re-timed:** capture times stay as the sensor wrote them. While the skew stands, no comparison is made, because no tie is made.
- **Bound: 2,000 ms,** an order below `g`. **Assumption:** a site clock under NTP on a LAN keeps well within a second. The owner has not chosen the time source (O-10), so this is unshown (§1.14).

**While the skew stands** (SL-17):

1. `sensor-clock-skew` in status, repeated hourly, and its health events under the cap (§1.9 item 5).
2. **No tie is made:** `Dispatch` holds nothing for that sensor, every run it holds gives way untied at the onset (as `giveWay` does), and the late index ties nothing.
3. **The alerts are aggregated** (ruling 13 on #628; difference 4 on #627; CH-41). An observation committed while the skew stands carries `node.skewed: true`, and `collection.run` of a session ended then carries `skewed`. The detector puts their `own-session-unseen` and `own-session-outside-record` alerts under one key for each rule and sensor, `asset_id` `clock-skew`. **The aggregated alert names the assets it covers, up to 8** (as `SensorDropDetailAssets`, `sensor.go`), enrolled ones first, **and counts the rest.** With C13 §7.3's coalescing that is at most 4 records every 300 s for each sensor, whatever the schedule; without it, up to 1,024 a window at 256 run endpoints (`MaxDetectorEndpoints`).
4. **A flow that matches no session even at |E| plus `g` keeps its asset's own key** (D6's question 5): the aggregation covers only flows that would have tied but for the skew, so a spoofed session that matches no run still alerts on its own.
5. **Nothing is suppressed.** Every flow and session is judged, and every aggregated alert names the skew alarm as its cause.

**Limit** (D6): skew can be caused from the management network, by delaying ticks or forging an unauthenticated time source (O-10). The aggregation then covers the window, and item 4 keeps a flow that matches no session visible. Recorded for AP-35 (D3).

**Tests.** `TestSkewEstimateTakesLeastDelay`; `TestSkewCorrectionAddsE` (a sensor 1.5 s behind: a flow at the session's start ties; control: `t_sensor − E`, which pushes it 3 s out of a window narrowed for the test); `TestSkewAlarmHysteresis` (2,000 ms and 1,500 ms); `TestSkewIgnoresHeartbeat`; `TestSkewStepBackTiesNothing` (control: ties gated on E, which ties during the first minute); `TestSkewTiesNothing`; and D4's `TestSkewAlertsAggregated` (50 sessions give at most 4 records a window and name 8 assets with a count of the rest; control: keyed by asset, at least 50) and `TestSkewUnmatchedFlowKeepsKey` (control: every flow of the window aggregated, which puts a flow that matches no run under `clock-skew`, D3). On the rig: the test source states a `sensor_utc` offset by 10 s, since a time namespace cannot move a namespace's wall clock (D6, not read), and the alarm is raised within one tick of the hello.

## 1.6 Records after a break, and late records (brief item 5)

**What happens today** (`desk`). The hold watches a run's endpoint from `Dispatch` until `Result`, `Abandon` or its deadline (`hold.go`). While the link is down nothing is held, so `Result` releases at once. When the backlog arrives, the session's records find no holding run (`runFor`) and no open entry, and commit untied (`Link.observe`, `commitOne`). An untied record never marks its session seen (`netdetect` `track`), so the session raises `own-session-unseen` and each flow `own-session-outside-record`.

**The rule for a break (ruling 1 on #627, ruling 7 on #628, D3's B3).** The node bounds a backlog record's clock error only by what it measured itself: the length of the break on its own clock.

- **"Break" and "backlog record" are C13's terms, defined in CH-39,** and #628 uses them as defined there. The bound is **`backlog_tie_s`: 60 s by default, at most 120 s,** a node setting (recorded ruling 2 (#628, comment 6803459738); CH-39). A break runs, on the node's monotonic clock, from the last accepted frame of a sensor's connection (CH-44) to the accepted hello of the next; after a node start, the first break is unknown and counts as longer than `backlog_tie_s` (CH-39).
- **Per outage, not per connection** (CH-39). The backlog of a break is every record the node reads from the break's end until it has read through the `newest_seq` of the first hello after the break whose `current` is true (CH-7). So every old run flushed after an outage, on however many connections (CH-16), is judged by the same break. Records numbered after the break ended but read before the backlog is through count as backlog too: it errs on the side of untied. **A second break that begins before a backlog is through** extends that backlog, and its records are judged by the **longest** break of the unfinished backlog, not by the latest, so a short second break never gives ties to records that a long first break left untied (CH-39).
- **After a break longer than `backlog_tie_s`, no backlog record takes a tie.** Each is committed untied with `node.backlog: true`, the node marks each `collection.run` whose window overlaps the break (CH-39), and their `own-session-unseen` and `own-session-outside-record` alerts are aggregated under one key for each rule and sensor, `asset_id` `sensor-records-late`, naming up to 8 assets and counting the rest, as §1.5 does for skew. **An outage raises one alert per rule and window, and not one for each session.** A flow that matches no session at all keeps its own key, as in §1.5.
- **After a break at or below `backlog_tie_s`, a backlog record takes a tie only if its own clock agrees with the node's** (D3's change 1 on `4d03075a`, adopted in D1's comment "Round two at `873c0eb5`" on #627, 6803089547; CH-39): its `made_utc` brought to the node's clock, `made_utc + E` with CH-22's sign (§1.5), must fall between the start and the end of the break on the node's wall clock, within `max_skew_ms` (2,000 ms). A record outside that is committed untied with `node.backlog: true`, under the same `sensor-records-late` key. So a clock moved and put back inside a short break ties nothing that the break could not have produced. The node keeps the wall time beside the monotonic time of both instants. What stays is a step made and undone between two ticks, or records the engine writes after the clock is put back, which D3 records in AP-35.
- **Why 60 s.** It is `SensorUnreachableAfter`, so every break whose backlog loses its ties has already raised `sensor-unreachable`, while a single reconnect (back-off 1 s, handshake and hello at most 10 s each) keeps its ties, under the `made_utc` check. CH-39 gives the same figure, and its 120 s ceiling: above about 60 s a spoofed session can reach a neighbouring scheduled run's window (D3).
- **This changes what brief item 5 asked.** After a break longer than 60 s, the sessions in it do alert, once each window under the aggregated key, instead of not at all. That is D1's fail-closed choice, and D5 agrees with it: the alternative ties on a clock nobody measured.

**The late index (part (e) of the hold), for what remains.** A record can still arrive after its session's result with no break: the engine may write a connection's record only at its end (A6 on #627), and a break of at most `backlog_tie_s` keeps ties, under the `made_utc` check. **Requirement, not built:**

- **Only a session released with no flow tied enters the index** (D3's L2 (i)), with invocation, asset, endpoint, transport, local address, connected, start and end.
- **An entry ties one flow and is then spent**, under `Result`'s rules: the 5-tuple for a 0.9 result, the first flow in the window for a 0.8 result, a failed dial's window. So a second flow on a tied session's key, or a second flow in a 0.8 window, commits untied and alerts, as on `main` (AP-35). If the tied flow is not ended, it joins the open table (part (d)).
- **Horizon: 15 minutes on the node's clock** after the session's end: `MaxFlowIdleS` (600 s), plus `backlog_tie_s` at its 120 s ceiling, plus `g`, plus room for the engine's own pipeline, which E-D4-03 measures (**unmeasured**). Past it a record commits untied and alerts, counted `late_untied` (`horizon`).
- **Bound: `HoldLateEntries` = 1,024,** oldest out first, counted `late_untied` (`evicted`), with `sensor-late-index-short` raised once a stretch when an entry is evicted inside its horizon. The scheduler runs one run at a time, so 15 minutes hold far fewer than 1,024 sessions at any schedule `MinIntervalSeconds` allows unless runs last under a second. Each entry is about 200 bytes (**unmeasured**), so under 256 KiB.
- **It is memory only.** Its source is `collection.run`. At start it is rebuilt from the health stream, newest first, no further than 15 minutes back, as `lastDropCounts` reads (`sensor.go`); a session pruned from the stream before that is counted `evicted`.

**Why the detector needs no further change, and when it would.** It judges a session only once its capture clock passes the end plus `g` (`judge`). The late index works if a flow's record that starts in a session's window is read before any record of a flow that starts after the window plus `g`. **That is stated in 0.2 and marked [S2]** (difference 2 on #627): C13 0.1 already asks a flow's `start` at its first frame. If E-D4-03 shows that the engine writes only at a connection's end, the detector judges a session once its clock passes the end plus `g` plus `flow_idle_s` (D4's fallback), which delays `own-session-unseen` only.

**Lost records** (difference 3 on #627; CH-40, CH-46). The agent declares the capture spans of records it evicted or could not read before the node acknowledged them, as `lost` in `sensor-hello` and `tick`, and as `prior.lost` for whole runs and discarded generations: the run's full set, at most 8 disjoint spans. **The node follows CH-40:**

- **It keeps the run's spans durably** (CH-40, CH-18; D6 on `e2ff17c7`). The spans the node holds for a run are in `sensorrun.json`, beside `prior`, saved before the message that carried them is acted on. They change only with an eviction, so the sensor cannot make the node rewrite the file beyond what a rise in D already allows. After a node restart, a resume's unchanged `lost` list is therefore not new, and passes.
- **It checks each span.** **An impossible span closes the connection:** a span whose `from_utc` is after its `to_utc` closes it (`tick`, or `hello` for a span in a hello). **A span that widens with no rise closes it the same way:** a span that is new, or wider than the spans the node holds for the run, must come with a rise in that run's `drops_channel`, or, for `prior.lost`, a `prior.records_lost` above 0. **A span that reaches past the present is cut once, and not closed** (CH-40 of `docs/phase4/D4-c13-0.2-proposal.md` (#627), from D6 and D3 on round three, recorded ruling 4 (#628, comment 6803459738) and D1's ruling on CH-40 (#627, comment 6803460354); the sensor's clock may have been stepped back since, CH-21):
  - **The node holds each span twice: as the sensor stated it, and with its cut end.** Both are in `sensorrun.json`.
  - **The cut end is fixed once,** when the span is accepted as new or widened, at the earliest of three times: the span's stated `to_utc`; the message's `sensor_utc`; and **the node's own receipt time plus `max_skew_ms`** (2,000 ms). The third term does not use E, because E is itself derived from `sensor_utc`, the sensor's word (D3's correction, recorded ruling 4 (#628, comment 6803459738), which replaces the earlier "receipt time less E"). *Example:* the node receives the message at `12:00:10`, so the third term is `12:00:12`; a span stated to end at `12:05:00` in a message whose `sensor_utc` is `12:03:00` is cut at `12:00:12`. A cut is counted under `spans_cut`, and the `lost` gap and the alarm below are raised as for any new span. **A span whose window is empty after the cut** (its `from_utc` at or after the cut end) writes no `node.lost` entry.
  - **Later messages are compared with the span as stated, never with the cut one.** An unchanged stated span is not new and not wider, so an honest sensor is not closed a tick later, nor cut or counted again. A span stated wider needs a rise in the counters, as any widening does, and its new part gets a cut end of its own, fixed once in the same way. The cut end never moves forward, so a span cannot follow time and keep `own-session-unseen` off for good. `node.lost` and the detector's degraded interval use the cut end.
  - Test: `TestLostSpanCutOnce` (a span reaching an hour ahead, repeated unchanged in later ticks: cut once at the receipt time plus 2,000 ms, connection open, the degraded interval ends at the cut; a `sensor_utc` and an E both stated an hour ahead do not move the cut; a span starting after the cut writes no `node.lost`; controls: the cut at the receipt time less E, which an hour-ahead `sensor_utc` moves; the cut recomputed at each message, which lets it follow time, and a comparison with the cut span, which closes on the next tick).
- **It shows each loss.** Every new or widened span opens a **coverage gap with cause `lost`**, under the gap's own budget (§1.9 item 5), and raises **`sensor-records-lost`**, a status alarm for the stretch.
- **It marks it.** On the next observation of that run that it stores, the node sets `node.lost`, **a list of at most 8 `{from_utc, to_utc}`**; a new run's `prior.lost` goes on the first observation of the new run.
- The detector reads each span as a degraded interval, so a session inside a declared loss raises no false `own-session-unseen` (`covers`, `own.go`). If no observation of the run follows, the mark is not placed, and such a session may alert: it fails loud (CH-40). `sensor-gap-undeclared` and the coverage gap keep the loss loud.

**Late records** (CH-23): a record later than `late_bound_s` is stored with `node.late: true`, counted, and raises `sensor-records-late` once for each connection that carries one, under the cap of §1.9 item 5. Lateness uses E. `late` is the sensor's own word (`made_utc`), so it never decides a tie: the break rule above does.

**The buffer the sensor must cover** (difference 9 on #627): `buffer_bytes` at least the site's record rate times `outage_hours`, a sizing rule that **cannot be checked until a station's rate is measured.** The node shows `buffered_bytes` against `buffer_bytes` from each tick, and raises `sensor-buffer-filling` once a stretch past three quarters. **`sensor-buffer-small`** stands while a sensor's hello states a `buffer_bytes` below the 256 MiB site floor (CH-13 row 9, CH-20): a buffer that small cannot be caught by `sensor-buffer-filling`, since no tick arrives during the outage that fills it.

**Tests.** `TestBreakOverBoundNoTie` (a break of 61 s on the test clock: the backlog's flows commit untied and alert under `sensor-records-late`; control: tied); `TestBreakUnderBoundTies`; `TestShortBreakMadeUtcCheck` (a clock set back 10 minutes inside a 30 s break: its backlog records are untied; control: the check removed, which ties them, D3); `TestFirstBreakAfterStartUnknown`; `TestBacklogEndsAtCurrentRun`; `TestLateIndexTiesOnce` (a second flow on a tied session's key alerts; control: the entry not spent); `TestLateIndexOnlyUntiedSessions`; `TestLateRecordTied` (control: no index, untied); `TestLateIndexRebuiltAtStart`; `TestLatePastHorizon`; `TestLateIndexBound`; `TestLostIntervalNoOwnSessionUnseen` (control: no `node.lost`, which alerts); `TestLostSpanChecks` (a reversed span, and a new span with no rise in `drops_channel`, each closing; a span that ends after the message's `sensor_utc` cut, not closed; control: each accepted unchecked); `TestLostSpansListOfEight`; `TestLostSpansSurviveRestart` (a node restart, then a resume with unchanged spans: accepted; control: spans in memory only, which closes every dial); `TestLostSpanCutNotClosed` (a span ending after `sensor_utc`: counted under `spans_cut`, gap and alarm raised, connection open; control: closed); `TestLostSpanCutOnce`; `TestPriorDurableUntilEvent` (killed after the hello and before `sensor.run-loss` commits: the event is written at restart; control: `prior` in memory only); `TestBufferSmallAlarm`. On the rig: the link cut for 30 s across one run (ties kept), and for 10 minutes across 5 runs (one aggregated alert per rule and window, naming the asset).

## 1.7 Retiring and replacing a sensor (brief item 6)

- **A replacement keeps its `sensor_id`.** A new host, a re-image or a new key is a new enrolment of the same `sensor_id` at the next generation (SL-16, SL-R6). Its streams, baseline and detector carry on, and the open table clears at the new run. Nothing is retired.
- **Retiring is for a `sensor_id` withdrawn:** a LAN no longer watched, or a revoked sensor not replaced. Today a sensor taken out of the configuration leaves its database on disk, unopened, never pruned and never deleted (Part 2 §5, `layout.go`).
- **Requirement, not built (ruling 12, D6's B6).** At the first start with a `sensor_id` newly in `retired`, the sensor manager, in order:
  1. opens its database as any sensor database (§1.9 item 1), with no dialer and no link;
  2. releases everything its hold holds, untied, and commits it;
  3. runs its detector to the observation stream's head, commits the alerts, and stores a last checkpoint;
  4. only then adds the consumer `node-retired`, which confirms the observation stream through the head, so nothing unjudged is pruned.
  - Status shows the drain. If a step cannot finish (its database will not open, or a commit fails), the manager tries again at each tick and does not confirm. After 24 hours it writes a health event that **declares what it drops,** the seq range and the count, and only then confirms. A retired sensor's records are never pruned unjudged without that event.
  - The alert stream keeps its forward targets, or the retention consumer (`netretain`, `alert_retention_days`) where there is none. Network baselines are evidence and are never removed (C5 0.9). Once both streams are empty, status says so, and the administrator removes the entry; the database then stays on disk unopened.
- **Tests.** `TestRetiredSensorDrained` (held records committed, every observation judged, then pruned; control: the design of the first text, which prunes unjudged observations and strands held ones); `TestRetiredDrainStuckDeclares`; `TestRetiredSensorNotDialled`.

## 1.8 `sensor-blind`, reachability and coverage unknown (brief item 7)

- **`sensor-unreachable`** (ruling 3 on #627; CH-44): only an **accepted** frame resets its timer: an accepted tick that is not early, or a heartbeat or record taken, on a connection whose hello was accepted. A refused record, a failed hello, an early tick, an unknown type or a connect does not (AP-36 (2), D4-73). Code: `tickSensor`'s timer (`sensor.go`), moved to the manager.
- **`sensor-blind`** (difference 6 on #627), per interface (`interfaces[]`, CH-31): an interface whose `packets` has not risen across the heartbeats of the last `blind_after_s`, or whose `carrier` is `down`, is blind, judged from heartbeats that are not late. `sensor-blind` is raised when **any** interface is blind, naming it; a coverage gap with cause `blind` opens when **every** interface is. The counters run per run, so the comparison starts again at a new run.
- **`blind_after_s`:** a node setting, 300 s by default (difference 6 on #627), 60 s to 3,600 s. **Assumption** (A7 on #627): a mirrored station LAN carries something within the bound. D2's N-6 on #627 documents traffic every few seconds wherever a SEL DAN is mirrored, which supports a shorter setting there. With the manager's 1 s drive the alarm comes within the bound and one second.
- **Coverage unknown** (ruling 3 on #627, CH-44, D3's note 1): while accepted ticks arrive and no heartbeat that is not late has come for 60 s, as while a backlog drains, neither `sensor-unreachable` nor `sensor-blind` can stand. Status shows `coverage: unknown`, and **`sensor-no-heartbeat`** is raised once a stretch, the name and figure of CH-44 in `docs/phase4/D4-c13-0.2-proposal.md` (#627) (D6's B5 on #627: a tail that wedges the sensor shows here). A flat interface count seen only in late heartbeats is recorded afterwards as a past blind stretch, in one `sensor.past-blind` health event under the cap (CH-44).
- **Tests.** `TestUnreachableOnlyAcceptedFrame` (control: any frame resets, which hides a sensor whose every hello fails); `TestSensorBlindAnyInterface` (control: blind only when all are); `TestSensorBlindIgnoresLate`; `TestCoverageUnknownDuringBacklog`; `TestPastBlindStretchRecorded`. On the rig: K-2 and K-3 of #627.

## 1.9 A sensor never stops SER or Syslog collection or the node's start (brief item 8)

Each finding of §1.0, and what closes it. **D1's ruling on #628 (comment 6803782160): every row below is closed, with its test, in the first brief of the third part, before any dialer or other caller of `ServeSensor` or `sensorlink.Link.Serve` merges, and before any release.**

### 1. The sensor store set (ruling 8; F5, F6, F7, F9, F10)

**The mechanism D5 chooses: the sensor databases are never in `Runtime.dbs`.** They form a separate set, owned by the sensor manager, which opens, resumes, prunes and closes them on its own goroutine, and records their mode changes. **Its lock (`sensorStores.mu`) is held only to read or swap a handle, never across a store call** (D6's item 2 on `4d03075a`):

- **The accessor never waits.** It takes the lock to read the handle and add a reference, and returns at once: the handle, or "not open".
- **`Resume`, prune and open run with the lock released,** as `Tick`'s `OpenBusy` branch already does on `main`. Before a `Resume`, the manager swaps the handle out under the lock, so the accessor returns "not open" for that database while it runs, and swaps it back after.
- **A handle is closed only when no caller holds a reference to it,** so no reader's call is cut by a close.

So:

- `r.state`, the lock that `view` takes for every `Log`, `Store` and `Mode` call of the scheduler and the Syslog intake, is never held over a sensor database: `Tick`'s `Resume` loop iterates `r.dbs` only (F5).
- `pruneMu` and `Runtime.Prune` cover `r.dbs` only, so `cannotKeep`'s `Prune` never waits on a network database (F6). The manager prunes its own set after each drive, with the same `pruneDB` passes.
- `Start` opens `r.dbs` only. A sensor database is opened by the manager after `Start` returns; one that will not open, adopt or resume is an alarm (`sensor-store-not-open`), stays closed, and is tried again at each manager tick, under `StartupDeadline`, never a failed start (F7).
- The configuration database stays shared, as it is today: the hold's records and the detector's checkpoints are writes to it, each one call under the store's own mutex and item 3's ceiling (`saveIntake`), as configuration reads' writes are. The audit and evidence databases are touched only by single reads and writes, each under its own call (the fold in pages of 64; cursor saves at most once a minute; the detector's paged reads of the health stream).
- `Runtime.Log` and `Runtime.Store` for a sensor stream go through the manager's accessor; `Runtime.Collecting` (no product caller) does not count the sensor set.
- **The forwarder (F10).** `NewForwarding` gives each target a second session that carries the sensor's streams only, apart from the session that carries every other stream. A sensor database that is not open then ends that second session's attempt, and the session for SER, Syslog, audit and health events goes on. It costs a second connection to each target. `Forwarding.Check` reads each stream through the accessor, which never waits.
- **Disk space.** The volume rule (`deploy/README.md`) counts the sensor set as it counts every database: each class's quota times `DiskBytesPerQuotaByte`, with each database's two reserves (D6).
- **Mode changes (F9):** a sensor database's `store.mode_change` audit record and its health event are written at most once an hour for each database, the rest counted and carried in the next record's detail; the health event is under the ceiling.

**Code changed:** `runtime.go` (`Start`, `startDB`, `Tick`, `Log`, `Store`, `Close`), `prune.go`, `layout.go` (`Layout` returns the sensor set apart), and a new `platform/node/sensormgr.go`. **Tests**, each with a control: `TestSensorDrainOnlyDoesNotStallSyslog` (a sensor database held drain-only with a slow-prune seam while Syslog arrives, a run is due and a target forwards SER events: Syslog commits, the run is sent within 2 s, SER events reach the target, and `Tick` returns; controls: `main`'s `Tick`, and the manager's lock held across `Resume`); `TestSensorStoreNotOpenForwardingGoesOn` (a sensor database not open while SER events forward: they reach the target; control: one session for every stream, `main`'s `NewForwarding`); `TestCannotKeepPrunesEvidenceOnly` (adapter-evidence near its limit and a network class over target, with a slow prune seam; control: `main`'s `Prune`); `TestSensorStoreFailsOpenNodeStarts` (a network database whose first read fails: the node starts and stores a run; control: `main`'s `startDB`); `TestSensorModeChangeCapped` (control: uncapped).

### 2. The start (F2)

`startSensor`'s error no longer fails `Start`. The node starts without that sensor's intake, raises `sensor-intake-not-started` and tries again at each manager tick. **Said plainly (D6):** while the intake is not started, `repairIntake` does not run, so a run whose release committed before a crash has no `collection.run` until it does. Shape checks stay load failures (§1.2). Test: `TestHoldRecordUnreadableNodeStarts` (a hold record that cannot be read: the node starts and stores a run; control: `main`'s `Start`).

### 3. The detector's drive (ruling 10; F3; D4's note, D6's B4)

- The sensor manager drives the detector **about once a second**, with at most 1,000 observations or 200 ms a drive, yielding between drives (**unmeasured**; the figures only keep one drive short). No budget a minute caps the rate: a backlog is worked off as fast as the drives allow.
- **The checkpoint at most once every 60 s,** and at a clean stop, since a worst-case checkpoint is 1,354,752 bytes.
- **The lag alarm: `network-detector-lag`** when the oldest observation the detector has not read was committed more than **60 s** ago on the node's clock, raised once a stretch, cleared below 30 s, with the lag in status. 60 s is one checkpoint interval, and C13 §7.3 means a first alert to be committed "at once", which a minute of lag already departs from. A flood therefore delays alerts visibly, never silently.
- A bounded drive keeps the existing ordering rule: no session is handed over after observations past its `after_seq`, and `nd.health` passes only runs handed over (D4).
- `Runtime.Tick` takes the manager's status snapshot without waiting, and does nothing else for the sensor. The final drop-count write of `Close` moves to the manager's stop.
- **Tests:** `TestTickReturnsWithSlowDetector` (a slow detector seam: `Tick` returns and the evidence database resumes; control: `tickSensor` inside `Tick`); `TestDetectorLagAlarm` (control: no alarm, where the backlog grows silently); and SL-T13 leg (a)'s pass condition from D6's plan §5: the labelled case sent in the middle of the flood has its alert stored, with the latency reported against the node's clock, **and when that latency is above 60 s, `network-detector-lag` stood** (D6).

### 4. The run path and the link's lock (ruling 11; F4; D6's B5, D3's condition)

- **Fairness:** the scheduler goes first. A count of waiting scheduler calls is kept beside `Link.cmu`; the read loop releases the lock after each record and, while a scheduler call waits, does not take it again until that call has had it. So a scheduler call waits for at most the one record in commit.
- **`HoldLockWait` = 2 s,** the most any scheduler call waits (**unmeasured**: D6 cites F-016's commits held 3 s and up to 37.9 s on the hosted Windows runner, so on a slow disk it can trip).
- **Past it, the session is kept, marked, and judged:** `Dispatch` holds nothing (the run's flows commit untied); `Result` gives `collection.run` the session's facts with `hold: timeout` and `after_seq` read without the lock, so the detector still judges the session. Its own-session alerts are aggregated under the key `hold-timeout`, naming assets up to 8, as §1.5 does (D3's condition: a cap that protects collection must not switch off the independent check).
- **An alarm, not only a counter:** `network-session-not-tied` once a stretch, when `dispatch_timeouts` or `result_timeouts` rises.
- **Tests:** SL-T13 leg (a) asserts `dispatch_timeouts` and `result_timeouts` stay 0 on the rig, with an unfair lock as the control; `TestResultTimeoutKeepsSession` (control: the session dropped, as the first text had it).

### 5. The platform-class ceiling, in bytes (ruling 9; F1; D6's B2)

**Collection's need is reserved first. The sensor's share is worked out from its caps. The quota must hold both.**

- **Each health record is at most 4,096 bytes stored** (**unmeasured**: the node builds each sensor event to render in at most 2,048 octets, as `TestSensorDropEventFits` pins for `intake.drop-counted`, and allows as much again for the C4 envelope and the store). A size test pins it for every sensor event, **and for `collection.run` and `collection.missed` with the per-sensor keys of §1.2** (D6).
- **Collection's need over the outage:** `C = R × 2 × 4,096 × H` bytes, where `R` is the schedule's runs an hour (the sum of 3,600 / `every_seconds` over its entries), 2 is the run's own records (its `collection.*` record and a `collection.missed`), and `H` is `outage_hours`. **`C` is a lower bound** (`records-auditor`, D6): it counts collection's run records only. Other writers to the platform class are not counted by `C` or `S`: the node's own databases' store alarms and mode changes, forwarding's and the Syslog intake's health events, and the node's other health events (`runtime.go` `health`, `modeHealth`, `storeAlarm`). They write there today with no floor. So `C` reserves collection's own records against the sensor, not against every writer.
- **The sensor's caps, for each sensor, an hour:**
  - `intake.drop-counted` for two classes, at most once every 10 minutes each (from once a minute: the totals are now durable in the cursor, §1.4): 12;
  - `sensor.coverage-gap`: 4, **its own budget, never behind another event** (D6);
  - a pool of 24 for every other sensor event, at most 4 an hour for each name, and `sensor.counters` at most once every 10 minutes (CH-45): the skew, blind, no-heartbeat, expiry, gap-undeclared, records-late, records-lost, buffer-filling, buffer-small, coverage-mismatch, pinned-by-console, lag, session-not-tied and identity alarms' events, `sensor.past-blind`, `sensor.run-loss`, `sensor.counters`, and the sensor database's store alarms (CH-45's list, and the node's own). **When the pool is spent, what waits:** `sensor.counters` first, then `sensor.run-loss`, then the alarms' events; a waiting event is merged into the next of its name, and counted in `health_held`;
  - mode changes, at most 1 for each database (item 1);
  - so 41 records an hour for a sensor, and 3 for a retired one (its mode change and 2 store alarms).
- **The sensor's share:** `S = (41 × sensors + 3 × retired) × 4,096 × H` bytes.
- **No refusal at load** (recorded ruling 1 (#628, comment 6803459738), D3's change 3, D6's item 1). When `store.quotas.platform` is below `C + S`, the node starts, **the sensor is not started** (no intake, no dial), and `sensor-platform-floor` stands, naming both terms. Adding a schedule entry raises `R`, so this case can arise with no change to the sensor, which is why it must not refuse a start. **This brief adds no check where there is no `network_sensor` section.** Recorded ruling 1 keeps collection's own need not fitting for the existing configuration floor, and adds no new floor when no sensor is configured; `main` has no platform floor today. A configuration check run before deployment may still report either case as an error.
- **The ceiling, at run time:** a sensor event is written only while the platform class holds less than `quota − C` bytes after it. So collection's own `C` is always left against the sensor, whatever the upstream does.
- **Worked example** (arithmetic, not a measurement): one sensor, no retired one, `H` = 24, and a schedule of 10 entries every 600 s (`R` = 60). `C` = 60 × 2 × 4,096 × 24 = 11,796,480 bytes (11.25 MiB). `S` = 41 × 4,096 × 24 = 4,030,464 bytes (3.84 MiB). `C + S` = 15,826,944 bytes (15.09 MiB), within the 64 MiB the README's example gives the class (`platform/node/README.md`).
- **Held events and a restart:** an event past the ceiling is not written. Its counts, and a held coverage gap's first start, last end and number, are kept in `sensorrun.json`, written at most once a minute when they change, so a restart finds them and writes one merged record when room returns. Status shows `health_held`. A held gap is therefore never dropped silently; a crash can lose up to the last minute's held counts, stated.
- **Tests:** SL-T13 control 1 (the ceiling removed: the class fills, `collection.missed` is refused and the entry's runs are held); the outage leg (the forward target down for `H` hours on the test clock, with the ceiling in place: no run is held); `TestPlatformFloorShortNodeStarts` (a quota below `C + S`: the node starts and stores a run, the sensor is not started, and the alarm stands; control: a load refusal); `TestCoverageGapNotBehindPool` (the pool spent: a gap is still written; control: one shared pool); `TestHeldEventsSurviveRestart` (control: held in memory only).

### 6. The audit class (F8)

- **`sensor.link_refused`:** D3's cap, at most once an hour for each sensor and reason, at most 6 × 2 × 24 = 288 records a day at the list's maximum. Within a run it runs on the monotonic clock. Across a restart it starts from `sensorrun.json`'s last record time for each sensor and reason, written with each record, folded forward from the audit records after `sensors.json`'s `through_seq`. It does not rely on the audit read at start that runs only with event baselines (`newEventRun`, `eventbaselines_run.go`). An unreadable file, or a fold that fails, holds the cap from the start and raises `sensor-state-unknown`; the start goes on. A time after now is taken as now.
- **SL-10's case** (D3's note 2): a record under another `sensor_id` is refused (`sensor-id`), raises `sensor-identity` once a stretch, and writes `sensor.link_refused` (`sensor-id`) under this cap. A tick under another `sensor_id` counts the same way (D3's note 8 on #627).
- **The `node-sensors` cursor** holds the audit stream through a read error, and moves on only for an unparseable record or past three quarters of the audit class's quota, after writing the revoked pins it has read (§1.3).
- Other audit records a sensor's work writes are caused by an administrator (`sensor.enrolled`, `sensor.revoked`, `policy.apply`), or are mode changes under item 1's cap.

### 7. Faults stay in the sensor's database

The link's commits and position saves go to the sensor's database only. What else a sensor's work writes, each bounded: the hold's records and the detector's checkpoints in the configuration class, under item 3's ceiling; health events under item 5; audit records under item 6; `sensors.json` and `sensorrun.json` in the store directory.

### 8. The tests that show it

**In process, on the test clock** (a new package, `platform/node/sensortest`, not `platform/node`, whose Windows run is near its 720 s warning, D4-44; `platform/node` gains the wiring and one start test): every test named in items 1 to 6, and SL-T13's legs (d) and (e), which need hours of test clock and so cannot run over a real link.

**On the rig, in real time, over the real link** (P4-4-R1, `CI-Linux`), with SER collection against the simulator on a schedule, Syslog over TCP and UDP, and small platform and audit quotas:

| Leg | What the sensor does | Where |
| --- | --- | --- |
| (a) flood | Observations at the link's full rate, resolved and unresolved, for twice the time the observation quota takes to fill, with GT-PCAP's labelled case in the middle | Rig |
| (b) cut and stall | The connection killed every 5 s for 10 minutes; then a peer at the enrolled address that accepts TCP and never completes TLS | Rig |
| (c) blind | Heartbeats with flat counters, on one interface and on all | Rig |
| (d) audit (D3) | Accepted and refused hellos in turn, under every reason it can cause, for more than an hour of test clock, with the node restarted repeatedly | In process |
| (e) gap flapping | One heartbeat, then 61 s of silence, for two hours of test clock | In process |
| (f) skew | A `sensor_utc` offset of 10 s across 20 scheduled runs | Rig |
| (g) two sensors | A floods, B is normal (when a second is built) | Rig |
| (h) clean close loop (D3's L1) | A source that closes cleanly after every hello | Rig |

**Pass conditions, absolute** (D6's B7, in place of the first text's 10 %): every scheduled run is sent and stores its rows; no `collection.missed` and no collection alarm; Syslog received equals sent within the listener's own limits; **the longest wait of any scheduler call on the link's lock is under 2 s,** measured by the node and shown in status; `dispatch_timeouts` and `result_timeouts` stay 0; the sensor's health events stay below the ceiling; `sensor.link_refused` stays within the cap; in (a), the labelled case's alert is stored, with its latency reported; in (h), the dials stay within 10 a minute; in (g), B's commits are unchanged by A.

**Controls,** each of which must make a leg fail: (1) the ceiling removed; (2) the fairness rule removed, with a seam that slows the network commit; (3) the time cap removed, or started afresh at each start; (4) D3's: the observation class's quota check removed, so the flood takes the volume; (5) the redial floor removed, for leg (h).

### 9. A fault in the sensor's code is contained (D6's item 4)

- **What `main` has** (`desk`): no `recover` in `platform/node`, `platform/sensorlink` or `cmd/otsec`, so a panic in the sensor's work ends the node, and with it SER and Syslog collection. If it comes from a stored observation, the detector reads it again after each restart.
- **Requirement, not built.** The sensor manager's goroutine, each connection's read loop, and the `sensorlink` calls the scheduler makes (`Dispatch`, `Result`, `Abandon`) each `recover`.
  - In the manager or a read loop, a recovered panic raises `sensor-failed`, naming the sensor, and **stops that sensor's work until a restart:** its connection is closed, nothing is dialled and the detector is not driven. The node and every other stream go on.
  - Before each detector step the manager notes the observation's seq in memory. After a panic there, it writes that seq to `sensorrun.json` as the sensor's poison record. At the next start the detector counts that observation as refused and passes it, so a stored observation cannot crash the sensor's work at every start.
  - In a scheduler call, a recovered panic is taken as a timeout (item 4): the run goes on, untied, with its session kept and marked.
  - **Limit:** `recover` does not catch a fatal runtime error (memory exhausted, a concurrent map write). Those still end the process, and the service manager restarts it after 60 s.
- **Test:** `TestSensorPanicContained` (a seam that panics in the detector's drive: a run is still sent and stored, `sensor-failed` stands, and after a restart the poison record is passed; control: no `recover`, which ends the node).

### 10. The node's stop (D6's item 4)

- **The order:** `Runtime.Close` first stops the sensor manager, then closes `Runtime.dbs` as today.
- **The bound:** the manager gets `SensorStopTimeout` = 10 s. It cancels its context, which every store call it makes takes, so a `Resume` or a prune stops at its next step. It writes the final drop counts and the position within that time if it can, and closes every handle that no caller holds.
- **Past 10 s,** `Close` goes on without it: a sensor database still in a call is left to the process's exit, which releases its lock, and the node's own databases close as today. So a sensor database stuck in a `Resume` never holds the node's stop, and the local stop of §1.3 stays a restart.
- **Test:** `TestCloseWithStuckSensorResume` (a sensor `Resume` that never returns: `Close` returns within 10 s and the evidence database is closed cleanly; control: an unbounded wait for the manager).

## 1.10 Bounds set in this note

| Bound | Value | Why | Past it |
| --- | --- | --- | --- |
| TCP connect, write | 5 s, 10 s | Node-local | Closed, counted, back-off |
| Handshake, hello, idle | 10 s, 10 s, 30 s | C13 0.2 (CH-4) | Closed, counted, back-off |
| Back-off | 1 s to 60 s, ±20 % | Bounded redial | — |
| `RedialFloor` | 10 s between immediate redials after `run-complete`, only when the node saw the run finished | CH-38; recorded ruling 2 (#628, comment 6803459738) | Back-off |
| `MaxSensors` | 2 in the shape, 1 built | Ruling 1 | A third entry: load refused (shape). A second before it is built: not started, alarm |
| Retired sensors | at most `MaxSensors` | §1.2 | Load refused (shape) |
| Skew | 2,000 ms raise, 1,500 ms clear on E; no tie while the latest sample is outside 2,000 ms | §1.5 | Alarm, no ties, aggregated alerts |
| `max_skew_ms` | 2,000 ms, fixed | CH-22 | — |
| `TickMinSpacing` | 5 s | CH-8 | Counted under `tick_early`, no further work |
| `MaxLostSpans` | 8 spans in a `lost` list and in `node.lost` | CH-40 | The two nearest spans merged by the sensor |
| Aggregated alerts | 8 assets named, the rest counted | Ruling 13 | — |
| `backlog_tie_s` | 60 s by default, at most 120 s, on the node's clock | CH-39; recorded ruling 2 (#628, comment 6803459738) | No tie for the backlog; at or below it, the `made_utc` check |
| Late index | 15 minutes, 1,024 entries | §1.6, unmeasured | Untied, counted, alarm |
| `late_bound_s` | 180 s, 30 s to 3,600 s | CH-23; recorded ruling 2 (#628, comment 6803459738) | `node.late`, counted |
| Sensor buffer | `outage_hours` at the site's rate, as a sizing rule | Row 9 of D1's table on #627 | `sensor-buffer-filling` at 3/4 |
| `ack` | within 1 s of T moving, and at least every 10 s | C13 0.2 (CH-9) | — |
| `MaxLinkCursorBytes` | 192 | §1.4 | — |
| `HoldLockWait` | 2 s, the scheduler first | §1.9 item 4, unmeasured | Session kept and marked; alarm |
| Detector drive | about 1 a second; 1,000 observations or 200 ms a drive | §1.9 item 3, unmeasured | Next drive |
| Detector checkpoint | at most once every 60 s | Ruling 10 | — |
| Detector lag | 60 s raise, 30 s clear | §1.9 item 3 | `network-detector-lag` |
| `blind_after_s` | 300 s by default, 60 s to 3,600 s | Row 6 of D1's table on #627, an assumption | Alarm; a gap when all are blind |
| Coverage unknown | 60 s of accepted ticks with no heartbeat that is not late | §1.8, CH-44 | `sensor-no-heartbeat` |
| Sensor buffer floor | 256 MiB, as a hello states `buffer_bytes` | CH-13 row 9, CH-20 | `sensor-buffer-small`, standing |
| Health record | 4,096 bytes stored | §1.9 item 5, unmeasured | — |
| Sensor health events | 12 drop-counts, 4 coverage gaps on their own budget, and a pool of 24 others an hour, at most 4 an hour for each name and `sensor.counters` once every 10 minutes; mode changes 1 an hour for each database | §1.9 item 5 | Waiting order stated; merged, carried |
| Platform floor and ceiling | `C + S` checked at load; `quota − C` at run time | Ruling 9; recorded ruling 1 (#628, comment 6803459738) | Below the floor: the sensor not started, alarm. Past the ceiling: events held |
| `SensorStopTimeout` | 10 s | §1.9 item 10 | `Close` goes on without the manager |
| `sensor.link_refused` | one an hour for each sensor and reason | D3 §11.2 | Counted; the next record's `count` |
| Expiry warning | 30 days, hourly | SL-8 | — |
| Revocation | fold to close within 1 s; signing to close about 15 s, about 615 s at worst, open under `collectorHold`; the fast path within 15 s | Rulings 2 and 3 | — |

## 1.11 What the node needs from other contracts and roles

**From C13 0.2 (D4, #627).** Status of D5's first asks, as ruled on #627:

| First ask | Status |
| --- | --- |
| 1. Hellos with "the oldest seq held" | **Superseded:** CH-7's `newest_seq` and `drops_channel`, which D3 and D5 accept |
| 2. The `ack` and its meaning | Met by CH-9 and CH-17, with ruling 2's durable totals |
| 3. A send time in each heartbeat | **Superseded:** the `tick` (CH-8, CH-21); the heartbeat's `at_utc` is its made time |
| 4. The capture interval of evicted records | Ruled into 0.2 (difference 3): the declared interval and `node.lost` |
| 5. Flows sent in capture order | Ruled into 0.2 and marked [S2] (difference 2), with the detector's fallback |
| 6. A capture-state signal | Met by CH-31's `carrier` |
| 7. The skew mark and key | Ruled into 0.2 (difference 4): `node.skewed` and the `clock-skew` key |
| 8. ALPN | Ruled: `otsec.netobs/0` (difference 8) |
| 9. PRP with two sensors | Met by CH-30 option (ii) |
| 10. Room for the cursor | **Not an ask of C13:** `MaxLinkCursorBytes` is the node's constant (`records-auditor`); R-5 runs with 192 bytes |
| 11. The configuration digest | Met by CH-32 |

**This design and `docs/phase4/D4-c13-0.2-proposal.md` (#627) do not differ** on any name, figure or rule they share, checked against #627's §12 bounds table, CH-8, CH-22, CH-40 and CH-45 at that head; the tick spacing (`TickMinSpacing`), `max_skew_ms` and `MaxLostSpans` are listed in §1.2 and §1.10 for that reason. CH-45 took the coverage gaps' own budget and the total of 41; CH-40 and CH-18 took the spans kept in `sensorrun.json`, `spans_cut`, and the cut fixed once with later messages compared with the stated span. The cut's third term is the node's receipt time plus `max_skew_ms`, and an empty window writes no `node.lost` entry (CH-40 of `docs/phase4/D4-c13-0.2-proposal.md` (#627); recorded ruling 4 (#628, comment 6803459738)).

**Agreed with `docs/phase4/D4-c13-0.2-proposal.md` (#627), and used here:** the hellos, with `current` (CH-7); the break, the backlog per outage judged by its longest break, `backlog_tie_s` and the `made_utc + E` window (CH-39); E's sign (CH-22); `RedialFloor` 10 s (CH-38); `late_bound_s` 180 s (CH-23); `node.lost` as a list with its checks, `spans_cut`, the spans kept in `sensorrun.json`, the `lost` gap and `sensor-records-lost` (CH-40, CH-18); `prior` durable in `sensorrun.json` (CH-16, CH-13 row 6); a `renew` with the pin unchanged carrying the position over, and the node's own count on `replace` (CH-12); `sensor-buffer-small` (CH-13 row 9, CH-20); the closes `enrolment` and `shutdown` (CH-11, CH-37); `sensor-no-heartbeat` and `sensor.past-blind` (CH-44); the three aggregate keys naming up to 8 assets (CH-41, CH-47); what the node keeps (CH-18); the health-event budget of 41 an hour with the coverage gaps' own 4, `sensor.counters` once every 10 minutes, and the byte ceiling (CH-45); an unclean previous run in `sensor.run-loss` (CH-42); and the resume row's `drops_channel` check (CH-13 row 5).

**From C5: no change to classes or quotas.** The design uses the source cursor and the store's `SaveSourceCursor`. **D1 is asked to confirm** that C5 0.9 allows more than one database holding the network classes, and a database set kept apart from the runtime's own list (§1.9 item 1), which is the node's layout and not C5's.

**From C7 0.11 (D3):** the two kinds as D3's §11.1 proposes them.

**From C8 0.13 (D3):** the three actions as D3's §11.2 proposes them; the relayed `collector.request` record names a sensor kind's target as fields, only for an accepted, verified request; `sensor.revoked` may be written late, with `decision_seq` and the `through_seq` values; and the denial reason `asset-address`.

**From D3's `modules/security/nodekey`:** the link key of §1.1, a kind of its own. **From D6:** its three tests that call `ServeSensor` move with the third part. **From D7:** the release floor of §1.15 (ruling 14).

## 1.12 What applying `node.network_baseline_ack` takes (for the third part's brief; not built)

SL-R5's "acknowledged again" and the baseline legs of SL-T10 wait on it. What it takes:

1. **The network learner on the node.** `netdetect`'s learner runs, its draft is checkpointed (`netcheckpoint.learner`), and a frozen draft is recorded as `baseline.network` on `netbaseline/<sensor_id>`. Without a recorded draft `netack.Adopt` refuses every acknowledgement.
2. **The relay.** `node.network_baseline_ack` joins `relayKinds` and `nodeActKinds` (`adminrelay.go`), and `applyAdminPart` gains its case, bound to the install key as `node.baseline_ack` is (`admin_actions.go`).
3. **The node's part.** `policy.apply` with `admin_keys` first when `netack.NeedsGrantRecord` says so. The latest draft, and `network-baseline-<sensor_id>.json` from `admin_dir` under the protected-file rule, passed to `netack.Adopt`. C8 `config.baseline_acknowledged` of kind `network` written before anything is stored, `denied` with `Adopt`'s reason when it refuses. The accepted bytes stored as `baseline.network`, evidence, never removed.
4. **The detector takes it.** `DetectorConfig` gains the accepted baseline (`detectorConfig`, `netdetector.go`), the detector's checkpoint names the baseline it judged with, and a newly accepted one starts a new detector half, as the event baselines do.
5. **SL-R5 itself.** An acknowledgement before the latest `sensor.revoked` of its sensor is not in force. The detector then runs as before acknowledgement, and `sensor-baseline-void` stands while that sensor feeds. A re-key keeps it (SL-R6).
6. **Tests.** The `netack` cases already in `modules/security/netack`, run end to end through the relay; SL-T10's baseline legs; a revocation voids, and a re-key does not.

## 1.13 Choices left

Rulings 1 to 15 settle the choices of the first text. What is still open:

- **For the owner, through D1:** O-12 on PRP (one host with two ports, two hosts, or one LAN only; a second sensor waits on it, ruling 1); O-6, the network between node and sensor (a cable of its own needs a free port on the node's hardware for each sensor, not checked for any machine); and O-10, the time source, on which the skew bound's assumption rests.

## 1.14 Limits

- **Nothing in Part 1 is built or has run.** Every test named is a plan.
- **Assumptions, each marked where used:** that Go's TLS client sends no early data, and that no session cache means no resumption (`TestDialNoResumption` decides); that Windows' default outbound policy is allow (§1.1); that a site clock keeps within a second, which rests on O-10 (§1.5); that a station LAN is never quiet for `blind_after_s` (§1.8, A7).
- **Unmeasured figures, each a choice with its reason:** the health record's 4,096 bytes; `HoldLockWait`; the detector's drive bounds; the late index's horizon and entry size.
- **After a break longer than `backlog_tie_s`,** the sessions in it alert under one aggregated key: D1's fail-closed choice (§1.6).
- **`sensors.json` and `sensorrun.json`** share `suspensions.json`'s open question about a rename's durability on Windows (D4-65); §1.3's cursor rule turns a rolled-back file into a correct fold or an unknown state.
- **Volatile:** the split of drop and refusal totals by reason and asset since the last `intake.drop-counted` event; up to a minute of held event counts.
- **`recover` catches a panic, not a fatal runtime error** (§1.9 item 9).
- **`C` is a lower bound:** the platform class's other writers are not counted (§1.9 item 5).
- **Not designed here:** a merge of two sensors' records; the second sensor itself (ruling 1); the sensor; its update path; a central role.

## 1.15 C13 0.2's points D5-1 to D5-12, as ruled, and the 0.1 rollback

| | Point | D5's answer, with D1's rulings on #627 |
| --- | --- | --- |
| D5-1 | Final outcomes | A C13 refusal, and a drop by the unresolved budget, at a full class or at the record cap. Any other store error closes the connection with `store` and is not taken (§1.4) |
| D5-2 | Durable counts | The run's refused and dropped totals in the cursor, with the commit or a cursor save, before the `ack` passes them (ruling 2 on #627; §1.4) |
| D5-3 | What the node keeps | Generation, counter, `run_id`, T, G, D and the two totals, in the cursor; in `sensorrun.json`, the run's second copy, `prior` until its event commits, the run's `lost` spans and its `config_digest` (CH-18) |
| D5-4 | The expected `config_digest` | `sensors[].config_digest`, read at the sensor's console at commissioning; a mismatch raises `sensor-coverage-mismatch` only. A patch of the sensor then needs a configuration edit and a restart, and the alarm stands until then |
| D5-5 | `pinned_by` | Status, with a standing alarm for `console` and no refusal (ruling 4) |
| D5-6 | The dialer | CH-4, CH-9, CH-10 and CH-38 (`RedialFloor` 10 s), with the node-local connect and write deadlines (§1.1) |
| D5-7 | The hold and `newest_seq` | Withdrawn on #627: the late index (§1.6), under the break rule. `newest_seq` serves status, `sensor-buffer-filling` and the end of a backlog |
| D5-8 | Reachability | Only an accepted frame resets the timer; `sensor-no-heartbeat` while a backlog drains (§1.8, CH-44) |
| D5-9 | Health events; the intake reader | No event for each heartbeat; `sensor.counters` and `sensor.run-loss` under the caps (§1.9 item 5), `sensor.run-loss` also for an unclean previous run (ruling 4 on #627). The intake checkpoint keeps `otsec.netcheckpoint.intake/0.1`: a held body is raw JSON (`HeldRecord.Observation`) decoded with `json.Unmarshal` (`Link.record`) |
| D5-10 | Sensors per node | The list shape, at most two, one built (ruling 1) |
| D5-11 | Names, bounds, caps | §1.10, and the caps of §1.9 item 5 |
| D5-12 | Two-way `ServeSensor` | §1.1. The read loop is synchronous, so `node-hello` goes out only after the previous connection's records are finished or untaken |

**The 0.1 rollback** (CH-35, ruling 14). `desk`: `Runtime.detectorCheckpoints` (`platform/node/netdetector.go`) keeps only documents whose `schema` equals `netobs.CheckpointIdentifier`, which `contracts/netobs/checkpoint.go` defines as `otsec.netcheckpoint/0.1`. So a 0.1 node does not see a 0.2 checkpoint at all. It starts as if for the first time, with no alarm, raises the alerts of the retained observations again and stores them a second time, and never removes the 0.2 document, which can be 1,354,752 bytes in the configuration class. The start-up rules allow a rollback: the detector starts in the manager, not in `Start`, and C5 checks a configuration document only at its commit (`platform/store/commit.go`). What makes CH-35 hold:

1. **A reader build, released on its own before any build that writes 0.2.** Its `detectorCheckpoints` recognises any `otsec.netcheckpoint/0.x` detector document, raises `network-detector-not-restored` for a minor it cannot read, starts from the oldest retained observation, and removes the document once its own first checkpoint has committed. **It is a release rule** (D6): D7's record names that build as the lowest a 0.2 node may roll back to, and the 0.2 writer ships no earlier than the release after it. A rollback to an older build gets the silent restart above.
2. **In the same build, the tie goes into a held observation's raw JSON** instead of a re-encoding with the build's own type (D4), so a rolled-back node keeps `made_utc` and `late` in the held bodies it commits.
3. **The duplicate alerts stay a stated limit.** Reading `last_alert_seq` alone out of a document the build cannot otherwise read would let a malformed document hold real alerts back, which suppresses; a duplicate fails loud. So the reader build raises the retained observations' alerts again, and says so.
4. **The configuration rolls back with the binary:** a build before this design refuses `sensors` at load, so D7's record names the configuration shape beside the build.
5. **The test:** in the reader build, a 0.2 detector checkpoint written from #627's text as a fixture; the node raises `network-detector-not-restored`, starts, and removes the document after its first checkpoint. Its control is `main`'s exact match, which raises nothing.

## 1.16 The reviews, and where each is answered

**Of `a50ee61c`:**

| Finding | Answered in |
| --- | --- |
| D4 B1: two positions | §1.4 (ruling 6) |
| D4 B2: stale asks in §1.10 | §1.11's table |
| D3 L1: redial after `run-complete` | §1.1, §1.9 leg (h) |
| D3 L2: the late index ties too much; an unmeasured clock; E lags a step back | §1.6 (rulings 1 and 7), §1.5 |
| D3 L3: revocation order; a connection open at a new enrolment | §1.3, revocation steps 2 and 4, enrolment step 4 |
| D3 L4: the node never dials a device | §1.1, §1.3 enrolment step 2 (ruling 5) |
| D6 B1: the other paths | §1.0 F5 to F9, §1.9 items 1 and 6 (ruling 8) |
| D6 B2: the ceiling | §1.9 item 5 (ruling 9) |
| D6 B3: one position | §1.4 |
| D6 B4: the detector's bound | §1.9 item 3 (ruling 10) |
| D6 B5: `HoldLockWait` | §1.9 item 4 (ruling 11) |
| D6 B6: retiring | §1.7 (ruling 12) |
| D6 B7: tests for item 8 | §1.9 items 2, 3 and 8 |
| D3's conditions: dialer, `sensors.json`, revocation, `HoldLockWait`, nodekey | §1.1, §1.3, §1.9 item 4 |
| D3's notes 1 to 6 | §1.8, §1.9 item 6, §1.3 enrolment, §1.2, §1.1 |
| D4's notes: comparisons never re-time; R6.4 and the tick | §1.5, §1.9 item 3 |
| D6's notes: the late index's horizon, unmarked figures, the skew limit, the 0.1 rollback, the database name | §1.6, §1.14, §1.5, §1.15, §1.2 |
| Rulings 2, 3, 13 and 14 | §1.3, §1.5, §1.15 |
| `records-auditor` | The stale 5 s (§1.12 item 5 at `a50ee61c`) and the two event caps are gone; `blind_after_s` is the one name; §1.15 says where `CheckpointIdentifier` is defined; `MaxLinkCursorBytes` is the node's (§1.11) |

**Of `4d03075a`:**

| Finding | Answered in |
| --- | --- |
| Recorded ruling 1 (#628, comment 6803459738): no sensor check fails the start or refuses the configuration | §1.2, §1.1 (the asset address), §1.9 item 5 (the floor) |
| Recorded ruling 2: `backlog_tie_s`, `late_bound_s` 180 s, `RedialFloor` 10 s, the cursor at 192 bytes | §1.6, §1.2, §1.1, §1.10 |
| D3's change 1: the `made_utc` check for a short break | §1.6 |
| D3's change 2: a read error must not give up the audit records | §1.3, "A read error and a bad record are not the same" |
| D3's change 3: three load refusals | §1.1, §1.2, §1.9 item 5 |
| D3's notes: one redial figure, one break-bound name, the `hold-timeout` key, the fast path's expiry, a control for `TestSkewUnmatchedFlowKeepsKey` | §1.1, §1.6, §1.11, §1.3, §1.5 |
| D6's item 1: the floor | §1.9 item 5 |
| D6's item 2: the lock carries F5 into the forwarder | §1.0 F10, §1.9 item 1 |
| D6's item 3: a held record stored twice | §1.4 |
| D6's item 4: a panic, and the stop | §1.9 items 9 and 10 |
| D6's notes: `C`'s other writers, the size test for `collection.run`, the pool's order, disk space, the lag alarm in leg (a) | §1.9 items 1, 3 and 5 |
| D4 at `4d03075a`, finding 1: E's sign | §1.5, with the formula and a worked example; §1.6's `made_utc` check |
| D4 at `4d03075a`, finding 2, and recorded ruling 2: `backlog_tie_s`, the `made_utc` window, `late_bound_s` 180 s, `RedialFloor` 10 s | §1.6, §1.2, §1.1, §1.10 |
| D4 at `4d03075a`, finding 3, and recorded ruling 3: `node.lost` as a list with its checks; `prior` durable; `renew` carrying the position; `sensor-buffer-small`; `shutdown` for an edited entry; the resume row's `drops_channel` | §1.6 "Lost records"; §1.4; §1.3 "What a new enrolment does to the position"; §1.6 and §1.10; §1.1; §1.4 |
| `records-auditor`: the citations of #627's rulings, §1.16's stale reference, the CH numbers, Part 2 §3's database name, `C` as a lower bound, F6's condition, F8 as the design's | Throughout: a ruling of #627 is cited by its number (1 to 8) or as a row of its table of the twelve differences; #627 is cited by file and PR; Part 2 §3's marker; §1.9 item 5; §1.0 |

**A note not taken, with the reason:** D6's alternative for the rollback's duplicate alerts, reading `last_alert_seq` forward from a document the build cannot read, is not taken (§1.15 item 3): an unverified field could hold real alerts back.

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

**Under option (b):** the comparison for options (a) and (c) is **History**. The subsection on option (b) is superseded by Part 1 §1.1 and §1.3: the enrolment is D3's (SL-4 to SL-7), not SC-11's. The heartbeat, `sensor-unreachable`, the restart count and the coverage gaps still hold, with the gaps bounded by Part 1 §1.9 item 5, and `sensor-unreachable` timed as Part 1 §1.8 says.

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

**Under option (b): still holds,** except the database's name: it is `network-<sensor_id>` (Part 1 §1.2), where this section says `network`. With two sensors, each gets a database of its own.

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

**Under option (b):** the rule on packages still holds, and Part 1 §1.9 item 8 applies it. The pipe, the service SID, the sensor's account, the ring's DACL and the NIC rebinding rows are **History**. The other rows still hold, run over the link.

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
