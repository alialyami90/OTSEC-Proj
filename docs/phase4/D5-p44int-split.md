# P4-4-INT, deliverable 1: the split between D5 and D4

Status: **ruled by D1** (6909558363 on #719), on D5's proposal at `2fb8f9a1` and D4's answer 6909550043 (A1 to A5, G4); G1 to G3 ruled in 6908172734. D4 confirms this amended file with a narrow read (D1's item 4). Evidence class: `desk`, read at `main` `c8a9b783` (D4 read `b2a97387`). This file holds no code and changes no contract.

Sources: brief P4-4-INT (`docs/agent-handoffs.md`, "After D4-109: work resumes"); P4-4-CC's "Owed" table (rows owned by "the C13 0.2 intake brief"); C13 0.2 §15 and CH-31, CH-40, CH-41, CH-47 (`docs/phase4/D4-c13-0.2-proposal.md`, with D4-106 item 1.3); C13 0.3 §12 (`docs/phase4/D4-c13-0.3-proposal.md`); D4-102 item 5 (c), D4-104 item 1.3, D4-106 item 1.6, D4-107 items 3.1 and 5.2, D4-108 item 4, D4-111 items 4 and 7; `docs/phase4/D5-sensor-node.md` §1.4, §1.6, §1.8, §1.9 and §1.15.

## 1. The PRs and their order

| Order | PR | Owner | Paths | Reviewers | Merges when |
| --- | --- | --- | --- | --- | --- |
| 1 | **INT-D4a:** the refusal of a 0.1 counter sent as `null` on the 0.2 channel (D4-107 item 3.1), alone | D4 | `contracts/netobs/` | D6 (detection accuracy), D2 (protocol), D5 (the node's calls) | its reviewers accept it at its head and it passes D1's merge check |
| 2 | **INT-D5:** the node's intake on C13 0.2 and 0.3, unwired, with its owed tests and D4's A2 to A4 | D5 | `platform/node/` and its test packages, and `platform/sensorlink/` (G1) | D6 (reliability, the owed tests), D3 (trust boundaries), D4 (C13's meaning) | after INT-D4a has merged; opens on it |
| 3 | **INT-D4b:** the detector work: it reads the `node.lost`, `node.skewed` and `node.backlog` marks, adds the aggregate keys (`clock-skew`, `sensor-records-late`, `hold-timeout`) with `assets` and `assets_total`, and the `hold-timeout` cause on `netdetect.Session` | D4 | `modules/detection/` | D6, D2, and D5 for the `Session` change (a node call) | after D1 approves G4's checkpoint minor (§4), and after D4's HR-23 and HR-25 work (D4-112 item 8) unless D1 reorders |
| 4 | **INT-D5b:** T-12, `TestResultTimeoutKeepsSession`, and the node filling `Session`'s cause | D5 | `platform/node/` and its test packages, and `platform/sensorlink/` | D6, D3, D4 | after INT-D4b has merged |

**Why this order.** INT-D5 makes the node the first product reader of the 0.2 channel. If it merged before INT-D4a, an intermediate `main` would read a 0.1 counter sent as `null` as 0 (D4-107 item 3.1). INT-D4a alone weakens nothing: the node still reads C13 0.1 through `ServeSensor` (D4-103). Between INT-D5 and INT-D4b, a `hold-timeout` or skewed session alerts under its own asset's key, which is louder than CH-47's aggregate and hides nothing, and F-027's gate keeps every path unwired (D4's A1). T-12 and `TestResultTimeoutKeepsSession` need the cause on `Session`, so they wait for INT-D5b (D4's A5).

D5 may build INT-D5 on a branch while INT-D4a is in review. INT-D5 opens for review only after INT-D4a merges, rebased on it.

**P4-4-DE starts after INT-D5 merges** (D4-111 item 7). §3 lists the legs moved to it.

## 2. Every owed test, by owner and PR

Names in *italics* are proposed here, because no text fixes them; the owner may rename one in its PR, and the PR names the row it closes. Every other name is the one the contract, the decision log or D4's answer gives. Each test is a named pass in both `go` jobs, with its control shown failing (self-check item 1). None of these tests exists on `main` at `c8a9b783` (`git grep "func <name>"` finds none).

### 2.1 INT-D4a (D4)

| Row closed | Test | Package | Control |
| --- | --- | --- | --- |
| D4-107 item 3.1 (P4-4-CC table, last row) | `TestHeartbeat02NullCounterRefused`: each 0.1 counter in a 0.2 heartbeat sent as `null` is refused as `form`; the PR also checks the other 0.2 channel messages for a 0.1 count that decodes `null` as 0 | `contracts/netobs` | the presence check alone, as on `main` |

### 2.2 INT-D4b (D4)

| Row closed | Test | Package | Control |
| --- | --- | --- | --- |
| S-7, the detector leg | `TestLostSpanSessionNotJudged`: a session inside a `node.lost` window raises no `own-session-unseen`, one outside it does; a restore leg with the spans held in `Degraded` | `netdetect` | a detector that ignores `node.lost` |
| T-6 | `TestSkewAggregateTwoPerWindow`: 50 sessions, at most 2 records a window per rule under `clock-skew`, `assets` 8, `assets_total` 50, enrolled assets first; a flow that matches no session keeps its own key. Its restore leg waits on G4 | `netdetect` | keyed by asset |
| CH-47 `sensor-records-late` (no §15 row) | `TestRecordsLateAggregate` | `netdetect` | keyed by asset |
| U-3, the detector leg | `TestFunctionCiteSpansTwoFlows`: on `dnp3-udp-temp-port`'s shape, `cite.1` names the request and the 129, in that order. If it passes on `main`'s `cite`, the PR says so and the test pins it | `netdetect` | a `cite` that keeps only the frames of the observation's own flow |
| T-9's "a `hold-timeout` alert names its assets"; CH-47's second cause | `TestHoldTimeoutAlertNamesAssets`. Its restore leg waits on G4 | `netdetect` | `Session`'s cause ignored |
| G4's checkpoint minor | the restore legs above, at the minor D1 approves | `netdetect` | as G4's approved text states |

U-3's other control, "a node that refuses an alert whose `cite` spans two flows", and the alert's capture rest on `alertCapture`, which looks frames up by hash; §15 gives that leg to the rig, so nothing is added to INT-D5 for it (D4).

### 2.3 INT-D5 (D5)

**C13 0.2 §15, the node legs** (P4-4-CC table, "C13 0.2 §15's other node legs"):

| Row | Name |
| --- | --- |
| H-10 (legs other than those in §3) | `TestRunFileRolledBack` |
| H-7, the `position-not-saved` leg on an ordinary resume (§3) | *`TestResumeSaveFailsPositionNotSaved`* |
| S-4 | `TestPriorDurableUntilEvent` |
| S-7, the node leg, CH-40's mark (D4's A3): `node.lost` on the next stored observation of the run, at most 8 entries; a new run's `prior.lost` on its first observation; a window cut to nothing writes no entry; control, no mark | `TestLostSpanMarksNextObservation` |
| S-10 (a) to (f) | `TestLostSpansSurviveRestart`, `TestLostSpanRiseJudgedAgainstDs`, `TestLostSpanOneCutEnd`, `TestLostSpanCutOnce` (and (d) in `platform/node/sensortest`) |
| A-3, the release legs | *`TestHoldReleaseMovesTOnce`* |
| A-4 | *`TestRefusedRecordCountedOnceAcrossRestart`* |
| G-3, the node leg | *`TestDigestConflictAfterRestart`* |
| T-6, the node's mark (D4's A4): each observation carries `node.skewed` while `sensor-clock-skew` stands; control, no mark while the alarm stands | a leg of `TestSkewLatestSampleMarks`, or its own test *`TestSkewAlarmMarksObservations`* |
| T-8, the intake leg | *`TestBacklogTieInBreak`* |
| T-10 | `TestSkewLatestSampleMarks` |
| T-13 | `TestTieStoredTimeAfterNodeStep`, `TestTieRecordBeforeSensorStep`, `TestTieNodeMovedSinceSample`, and `TestSkewCountPrecedence` for (r) |
| W-8 | `TestTransmittedAfterNodeRestart`, `TestTransmittedFirstHeartbeatEvicted`, `TestEgressDroppedAfterNodeRestart`, `TestEgressNeverCarriedNoAlarm`, `TestCaptureLossAcrossRestart` |
| K-5 | `TestPoolPerNameCap` |
| K-6 | `TestPoolWaitOrder` |
| M-10, the legs other than those in §3 | *`TestStateUnreadClosesConnections`* |
| R-5, the cursor leg in `Record.Bytes`: a cursor at `MaxLinkCursorBytes` (4,096) saved, one byte over refused | *`TestCursorAtMaxLinkCursorBytes`* |
| Gap legs V-1 to V-10, V-13, V-14, V-16, V-17 (in `platform/node/sensortest`) | `TestGapNodeAndSensorStopped`, `TestGapLinkCutCovered`, `TestGapQuietLinkCovered`, `TestGapHostStoppedStaysOpen`, `TestGapRestartInLongBreak`, `TestGapLostOwnBudget` and `TestLostGapNotBehindOtherGaps`, `TestGapSilentEngineStaysOpen`, `TestGapChainCount`, `TestGapLostDatabaseReachesBack` (without V-9's re-arm leg, §3), `TestGapNeverBackOpen`, `TestGapSensorFailedOpen`, `TestGapHeldInW`, `TestGapHeartbeatSilence`, `TestGapFlatCountsCarrierUp` |

**The intake legs of §15's Contract rows** (confirmed by D4, with A2). P4-4-CC coded the pure checks in `contracts/netobs`; the leg owed here is that the node applies each verdict as the row states (closes, refuses with the connection open, counts, raises). One test per row, in *`TestIntake<Row>`* form (for example *`TestIntakeM1ClosedSet`*):

- M-1 (the node's direction), M-2 (a sensor frame above 64 KiB closes), M-3 (heartbeat first, second hello), M-8 (each node close reason reachable through the intake);
- H-1 (every CH-13 row in the D4-106 item 1 order, without the `sensor.link_refused` legs), H-2, H-4 (without its `sensor.link_refused` and dial legs);
- S-1, S-2, S-5 (with the kill before row 6's save), S-9;
- **K-1** (D4's A2): a falling `interfaces[].packets` within a run is refused as `order` by `Follows` and counted `counter-decrease` (CH-31); control, an intake that does not call `Follows` with the run's previous heartbeat. It may be a leg of S-2's test;
- T-1, T-4, T-5 (without its `sensor.link_refused` leg);
- G-4 (across a node restart), R-1, U-1 (the `undecoded` observation stored as any observation).

Rows with no node leg: M-6 (dialer: P4-4-DE), A-1 (the agent judges an `ack`), T-9 (the contract, and INT-D4b), P-1 (its refusals take the refused-record path that M-1's and R-1's legs test), G-1, R-2, R-3, U-2's form.

**C13 0.3:**

| Row | Name |
| --- | --- |
| N-9's node half: the three counts are absent from `counters` and `sensor.counters`; control, a node that maps `overlap_table_full` to `diff.overlap_table_full` | *`TestOverlapCountsNotInSensorCounters`* |
| N-18's node legs (W-7's case 4, and D6's variant) | *`TestQuietSpellOwnRunsNoAlert`* |
| Item 5 (c)'s code: the open table expires only after a later flow `start`; the arriving record is matched before the expiry check; an entry past its bound at a restart waits for the next `start` taken after it | *`TestOpenExpiryAfterLaterStart`*, *`TestOpenExpiryMatchFirst`*, *`TestOpenExpiryWaitsAfterRestart`* |
| N-14 | **owed**, unless P4-4-HR24's stage 3 merges before INT-D5 opens; then D5 adds N-14's node legs (1) to (4) to INT-D5. Not merged at `c8a9b783` (no detector code judges CH-51) |

**C4 0.4, and the decision log's rows:**

| Owed test | Source | Name |
| --- | --- | --- |
| E4-6's builder leg: the node's own worst-case `sensor.counters` within 2,048 octets on the default target | P4-4-CC table | *`TestSensorCountersWorstCaseFits`* |
| E4-7's node leg | P4-4-CC table | `TestHeldPoolEventBuiltAtWrite` |
| The stored record's schema is the minor the node checked strictly on the channel; control, a node that stores the schema the sensor sent | D4-104 item 1.3 | *`TestStoredSchemaIsChannelMinor`* |
| Its tied leg: hold, tie, stored body; no field the channel refused, the schema the channel checked; control, a hold that stores the sensor's raw frame | D4-106 item 1.6 (D3's N1 on #682) | *`TestStoredSchemaIsChannelMinorTied`* |
| D3's condition 1: a first hello with a changed `pinned_by` that closes at row 5 or 6 keeps nothing, and the next well-formed hello is accepted; control, the value kept at row 7 | D4-106 item 1.6 | *`TestPinnedByCloseKeepsNothing`* |
| A sensor connection live at `sensor-failed` is closed (§1.9 item 9) | D4-107 item 5.2 | *`TestSensorFailedClosesConnection`* |
| R-6's node leg: on an accepted 0.3 connection a 0.2-stamped observation is refused as `schema`, not stored, the connection open; control, a node that decodes every frame with `DecodeFromSensor` | D4-108 item 4 | *`TestIntakeDecodesAtHelloMinor`* |

### 2.4 INT-D5b (D5)

| Owed test | Source | Name |
| --- | --- | --- |
| T-12: a panic in a scheduler call is taken as a timeout, raises no `sensor-failed`, does not stop the sensor, opens no `sensor-failed` gap, and the session goes under `hold-timeout` | §15 T-12; P4-4-CC table (P4-4-F27's F4 row) | `TestSchedulerPanicTakenAsTimeout` |
| The result timeout keeps the session | P4-4-CC table (P4-4-F27's F4 row) | `TestResultTimeoutKeepsSession` |
| The node fills `Session`'s `hold-timeout` cause; control, a node that leaves it empty, so the session alerts under its asset's own key | D1's ruling item 1 | *`TestNodeFillsHoldTimeoutCause`* |

## 3. Legs moved to P4-4-DE (G2, granted)

These legs need the dialer or a re-arm, which P4-4-INT excludes. Every other leg of these rows stays with INT-D5 (D1, 6908172734).

| Row | Leg moved to P4-4-DE |
| --- | --- |
| M-10 | "no SYN leaves for any sensor until the state is read", and "the node dials again" once it is read |
| H-7 | every `renew` leg; INT-D5 keeps only the `position-not-saved` leg on an ordinary resume |
| H-10 | "the unanswered pair gets no further dial", `sensor-dial-limit`, and the re-arm's request file refused |
| V-9 | the second case's "no `taken` is sent and no source port leaves until a re-arm" |
| H-4 | "a fork-held sensor is still not dialled after a node restart", a dial decision (CH-18; D4) |
| H-1, H-4, T-5 | the `sensor.link_refused` legs (already P4-4-DE's by the table; G3) |

INT-D5's tests drive the intake through a test connection handed to the node, as the §15 V-rows' preamble already has it ("every dial is refused until the cut ends" is the test source's behaviour, not a dialer's).

## 4. Gaps raised to D1 (none is filled in code)

- **G1, the brief's paths: granted** (6908172734). `platform/sensorlink/` is added to D5's paths for P4-4-INT, for item 5 (c)'s open-table expiry (`Hold` in `hold.go`, whose `OpenExpired` N-18 reads), S-10's tests, and `Link.Serve`, which reads an `io.Reader` today while the 0.2 channel writes `node-hello` and `ack`. D1 amends the brief in its next records PR.
- **G2, legs that need the dialer: granted** (6908172734). §3 names each moved leg.
- **G3, `sensor.link_refused`: confirmed** (6908172734). P4-4-CC's "Owed" table governs over D4-106 item 1.6's first bullet. **INT-D5's closes that C8-4 audits write no `sensor.link_refused` record** until P4-4-DE adds it. This weakens no guarantee on `main`: the 0.1 intake writes none today, and nothing is wired.
- **G4, the detector checkpoint: option (a)** (D4's 6909550043; D1's 6909558363 item 2). `otsec.netcheckpoint/0.3` has no field for an aggregated window's `assets` and `assets_total`, nor for a pending session's aggregate cause. A restored aggregate window would give an alert with no `assets`, which `Alert.Validate` refuses as `conflict` (CH-47), and a restored pending session would alert under its asset's own key. Option (a): the checkpoint's next minor gains the window's `assets` and `assets_total` and the pending session's cause, with the read of 0.3 stated. D4 drafts it as a proposal; D5 and D6 review it; D1 approves it before INT-D4b merges. Option (b), clearing aggregated windows at restore, was rejected as a quiet loss (P5). D1 records it as an open item in its next decision entry. INT-D5's node restore reads the checkpoint through `contracts/netobs`; if the minor changes the node's restore path, D5's review of the proposal says so.

## 5. D4-111 item 4.1

None of the four PRs is planned to let the node write an audit record of a sensor kind stamped 0.13 or above: INT writes no C8 sensor record (G3), and `audit.ContractID` (`otsec.audit/0.11` at `c8a9b783`) and every node-local audit constant stay as on `main`. INT-D5 and INT-D5b each show, outside `_test.go` files, `git grep` of `sensor.link_refused`, `sensor.enrolled`, `sensor.revoked`, `node.sensor_enrol`, `node.sensor_revoke`, `ActionSensorEnrolled`, `ActionSensorRevoked`, `ActionSensorLinkRefused`, `KindNodeSensorEnrol` and `KindNodeSensorRevoke` in `cmd/`, `platform/` and `modules/` printing nothing, and the diff of `audit.ContractID` empty. If a PR changes that, item 4.1 falls on it, and the `relayKinds` probe reruns on its head by a D6 instance before it merges.

## 6. F-027's gate (no product wiring)

All four PRs are unwired (D4-96). Each shows, outside `_test.go` files and test-only packages:

- `git grep -n "ServeSensor"` in `cmd/`, `platform/` and `modules/`: only the definition;
- `git grep -n "network_sensor"` outside the tests: only the configuration's own type and its checks, as on `main`, and no configuration file or default carrying the section;
- `git grep -n "\.Serve("` on a `sensorlink.Link`: only `ServeSensor`;
- the callers of every new exported function that judges a hello, a `tick`, an `ack` or a record's place, and of every new intake entry point: only the definition and `ServeSensor`;
- for INT-D4b, the callers of the new `Session` cause outside tests: only the node's detector path that `main` already has, and INT-D5b's filling of it;
- no dialer, enrolment, listener or firewall code (P4-4-DE).

The wiring comes only in P4-4-DE's PR that passes the last owed test (D4-96).

## 7. Still owed after the four PRs

The rig legs (the sensor's brief and D6's rig brief), U-3's two-flow `cite` control among them; N-14 if P4-4-HR24's stage 3 has not merged before INT-D5 opens; §3's legs (P4-4-DE).
