# P4-4-INT, deliverable 1: the split between D5 and D4 (proposal)

Status: **proposed by D5, for D4 to agree or amend, and for D1 to rule** (D4-99, D4-111 item 7). Evidence class: `desk`, read at `main` `c8a9b783`. This file holds no code and changes no contract.

Sources: brief P4-4-INT (`docs/agent-handoffs.md`, "After D4-109: work resumes"); P4-4-CC's "Owed" table (rows owned by "the C13 0.2 intake brief"); C13 0.2 §15 (`docs/phase4/D4-c13-0.2-proposal.md`, with D4-106 item 1.3); C13 0.3 §12 (`docs/phase4/D4-c13-0.3-proposal.md`); D4-102 item 5 (c), D4-104 item 1.3, D4-106 item 1.6, D4-107 items 3.1 and 5.2, D4-108 item 4, D4-111 items 4 and 7; `docs/phase4/D5-sensor-node.md` §1.4, §1.6, §1.8, §1.9 and §1.15.

## 1. The PRs and their order

| Order | PR | Owner | Paths | Reviewers | Merges when |
| --- | --- | --- | --- | --- | --- |
| 1 | **INT-D4:** the detector's `hold-timeout`, and the refusal of a 0.1 counter sent as `null` on the 0.2 channel | D4 | `modules/detection/`, `contracts/netobs/` | D6 (detection accuracy), D2 (protocol), D5 (the node's calls) | its reviewers accept it at its head and it passes D1's merge check |
| 2 | **INT-D5:** the node's intake on C13 0.2 and 0.3, unwired | D5 | `platform/node/` and its test packages; `platform/sensorlink/` if D1 grants gap G1 (§4) | D6 (reliability, the owed tests), D3 (trust boundaries), D4 (C13's meaning) | after INT-D4 has merged, rebased on it, with its reviewers' acceptance and D1's merge check |

**Why INT-D4 merges first.** INT-D5 makes the node the first product reader of the 0.2 channel. If it merged before INT-D4, an intermediate `main` would read a 0.1 counter sent as `null` as 0 (D4-107 item 3.1), which the 0.2 intake must refuse. And two of INT-D5's owed tests, `TestSchedulerPanicTakenAsTimeout` (T-12) and `TestResultTimeoutKeepsSession`, need INT-D4's detector change. INT-D4 alone weakens nothing on `main`: the node still reads C13 0.1 through `ServeSensor` (D4-103), and nothing on `main` reads the 0.2 channel.

D5 may build INT-D5 on a branch while INT-D4 is in review. INT-D5 opens for review only after INT-D4 merges, and is then rebased on it.

**P4-4-DE starts after INT-D5 merges** (D4-111 item 7). Its rows are listed in §3 only where a §15 row is split between the two briefs.

## 2. Every owed test, by owner and PR

Names in *italics* are proposed here, because no text fixes them; the owner may rename one in its PR, and the PR names the row it closes. Every other name is the one the contract or the decision log gives. Each test is a named pass in both `go` jobs, with its control shown failing (self-check item 1). None of these tests exists on `main` at `c8a9b783` (`git grep "func <name>"` finds none).

### 2.1 INT-D4 (D4)

| Owed test | Source | Name |
| --- | --- | --- |
| A 0.1 counter sent as JSON `null` on the 0.2 channel is refused; control, the decoder that reads it as 0 | D4-107 item 3.1; P4-4-CC table | *`TestNull01CounterRefusedOn02`* (`contracts/netobs`) |
| S-7's detector leg: `node.lost` on the next stored observation; a session inside the span raises no `own-session-unseen`, one outside it does | C13 0.2 §15 S-7 | *`TestLostSpanSessionNotUnseen`* (`modules/detection/netdetect`) |
| T-6: 50 sessions while skewed, at most 2 records a window per own-session rule under `clock-skew`, 8 assets named with `assets_total` 50 | §15 T-6 | *`TestSkewAggregateTwoPerWindow`* |
| U-3: GT-PCAP's `dnp3-udp-temp-port` shape in the detector | §15 U-3 | *`TestUDPTempPortService`* |
| The detector's `hold-timeout` change itself, with T-9's "a `hold-timeout` alert names its assets" exercised from the detector | P4-4-INT deliverable 2; §15 T-9 | *`TestHoldTimeoutAlertNamesAssets`* |

### 2.2 INT-D5 (D5)

**C13 0.2 §15, the node legs** (P4-4-CC table, "C13 0.2 §15's other node legs"):

| Row | Name |
| --- | --- |
| H-10 (legs other than those in §3) | `TestRunFileRolledBack` |
| H-7, the `position-not-saved` leg on an ordinary resume (§3) | *`TestResumeSaveFailsPositionNotSaved`* |
| S-4 | `TestPriorDurableUntilEvent` |
| S-10 (a) to (f) | `TestLostSpansSurviveRestart`, `TestLostSpanRiseJudgedAgainstDs`, `TestLostSpanOneCutEnd`, `TestLostSpanCutOnce` (and (d) in `platform/node/sensortest`) |
| A-3, the release legs | *`TestHoldReleaseMovesTOnce`* |
| A-4 | *`TestRefusedRecordCountedOnceAcrossRestart`* |
| G-3, the node leg | *`TestDigestConflictAfterRestart`* |
| T-8, the intake leg | *`TestBacklogTieInBreak`* |
| T-10 | `TestSkewLatestSampleMarks` |
| T-12 (needs INT-D4) | `TestSchedulerPanicTakenAsTimeout` |
| T-13 | `TestTieStoredTimeAfterNodeStep`, `TestTieRecordBeforeSensorStep`, `TestTieNodeMovedSinceSample`, and `TestSkewCountPrecedence` for (r) |
| W-8 | `TestTransmittedAfterNodeRestart`, `TestTransmittedFirstHeartbeatEvicted`, `TestEgressDroppedAfterNodeRestart`, `TestEgressNeverCarriedNoAlarm`, `TestCaptureLossAcrossRestart` |
| K-5 | `TestPoolPerNameCap` |
| K-6 | `TestPoolWaitOrder` |
| M-10, the legs other than those in §3 | *`TestStateUnreadClosesConnections`* |
| R-5, the cursor leg in `Record.Bytes`: a cursor at `MaxLinkCursorBytes` (4,096) saved, one byte over refused | *`TestCursorAtMaxLinkCursorBytes`* |
| Gap legs V-1 to V-10, V-13, V-14, V-16, V-17 (in `platform/node/sensortest`) | `TestGapNodeAndSensorStopped`, `TestGapLinkCutCovered`, `TestGapQuietLinkCovered`, `TestGapHostStoppedStaysOpen`, `TestGapRestartInLongBreak`, `TestGapLostOwnBudget` and `TestLostGapNotBehindOtherGaps`, `TestGapSilentEngineStaysOpen`, `TestGapChainCount`, `TestGapLostDatabaseReachesBack` (legs other than V-9's re-arm leg, §3), `TestGapNeverBackOpen`, `TestGapSensorFailedOpen`, `TestGapHeldInW`, `TestGapHeartbeatSilence`, `TestGapFlatCountsCarrierUp` |

**The intake legs of §15's Contract rows.** P4-4-CC coded the pure checks in `contracts/netobs`; the leg owed here is that the node applies each verdict as the row states (closes, refuses with the connection open, counts, raises). One test per row, in *`TestIntake<Row>`* form (for example *`TestIntakeM1ClosedSet`*): M-1 (the node's direction), M-2 (a sensor frame above 64 KiB closes), M-3 (heartbeat first, second hello), M-8 (each node close reason reachable through the intake), H-1 (every CH-13 row in the D4-106 item 1 order, without the `sensor.link_refused` legs), H-2, H-4 (without its `sensor.link_refused` and dial legs), S-1, S-2, S-5 (with the kill before row 6's save), S-9, T-1, T-4, T-5 (without its `sensor.link_refused` leg), G-4 (across a node restart), R-1, U-1 (the `undecoded` observation stored as any observation). Rows with no node leg, by this reading: M-6 (dialer: P4-4-DE), A-1 (the agent's close: the sensor's brief), T-9 (contract and INT-D4), P-1, K-1, G-1, R-2, R-3, U-2's form. **D4 to confirm this reading.**

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
| `TestResultTimeoutKeepsSession` (P4-4-F27's F4 row; needs INT-D4) | P4-4-CC table | `TestResultTimeoutKeepsSession` |
| The stored record's schema is the minor the node checked strictly on the channel; control, a node that stores the schema the sensor sent | D4-104 item 1.3 | *`TestStoredSchemaIsChannelMinor`* |
| Its tied leg: hold, tie, stored body; no field the channel refused, the schema the channel checked; control, a hold that stores the sensor's raw frame | D4-106 item 1.6 (D3's N1 on #682) | *`TestStoredSchemaIsChannelMinorTied`* |
| D3's condition 1: a first hello with a changed `pinned_by` that closes at row 5 or 6 keeps nothing, and the next well-formed hello is accepted; control, the value kept at row 7 | D4-106 item 1.6 | *`TestPinnedByCloseKeepsNothing`* |
| A sensor connection live at `sensor-failed` is closed (§1.9 item 9) | D4-107 item 5.2 | *`TestSensorFailedClosesConnection`* |
| R-6's node leg: on an accepted 0.3 connection a 0.2-stamped observation is refused as `schema`, not stored, the connection open; control, a node that decodes every frame with `DecodeFromSensor` | D4-108 item 4 | *`TestIntakeDecodesAtHelloMinor`* |

## 3. Rows split with P4-4-DE

These legs of rows that the table gives to this brief need the dialer or the enrolment, which P4-4-INT excludes. D5 proposes that they move to P4-4-DE; **D1 rules** (gap G2, §4).

| Row | Leg that needs P4-4-DE |
| --- | --- |
| M-10 | "no SYN leaves for any sensor until the state is read", and "the node dials again" once it is read |
| H-7 | every `renew` leg (the table already gives H-7's `renew` leg to P4-4-DE); INT-D5 keeps only the `position-not-saved` leg on an ordinary resume |
| H-10 | "the unanswered pair gets no further dial", `sensor-dial-limit`, and the re-arm's request file refused |
| V-9 | the second case's "no `taken` is sent and no source port leaves until a re-arm" |
| H-1, H-4, T-5 | the `sensor.link_refused` legs (already P4-4-DE's by the table), and H-4's "not dialled after a node restart" |

INT-D5's tests drive the intake through a test connection handed to the node, as the §15 V-rows' preamble already has it ("every dial is refused until the cut ends" is the test source's behaviour, not a dialer's).

## 4. Gaps raised to D1 (none is filled in code)

- **G1, the brief's paths.** P4-4-INT lets D5 modify only `platform/node/` and its test packages. Three owed items live in `platform/sensorlink/`: item 5 (c)'s open-table expiry (the open table is `Hold` in `hold.go`, whose `OpenExpired` N-18 reads), S-10's tests (§15 says "Node tests in `platform/sensorlink`"), and the channel move itself (`Link.Serve` reads an `io.Reader` today; the 0.2 channel writes `node-hello` and `ack`). D5 asks D1 to add `platform/sensorlink/` to D5's paths for INT-D5. D5 owns it by role.
- **G2, legs that need the dialer** (§3). The table gives M-10, H-10 and V-9 whole to this brief, but parts of them need a dialer or a re-arm, which this brief excludes. D5 proposes the split in §3.
- **G3, a record that disagrees with the brief** (a records point, no code). D4-106 item 1.6's first bullet says each close that C8-4 audits writing its `sensor.link_refused` record is owed by the C13 0.2 intake brief; P4-4-CC's table and P4-4-DE give those legs to the dialer-and-enrolment brief. D5 reads the table and the briefs as the later text and follows them. So **INT-D5's closes that C8-4 audits write no `sensor.link_refused` record** until P4-4-DE adds it. This weakens no guarantee on `main`: the 0.1 intake writes none today, and nothing is wired. D1 to confirm.

## 5. D4-111 item 4.1

Neither PR is planned to let the node write an audit record of a sensor kind stamped 0.13 or above: INT writes no C8 sensor record (§4 G3), and `audit.ContractID` and every node-local audit constant stay as on `main`. INT-D5 shows, outside `_test.go` files, `git grep` of `sensor.link_refused`, `sensor.enrolled`, `sensor.revoked`, `node.sensor_enrol`, `node.sensor_revoke`, `ActionSensorEnrolled`, `ActionSensorRevoked`, `ActionSensorLinkRefused`, `KindNodeSensorEnrol` and `KindNodeSensorRevoke` in `cmd/`, `platform/` and `modules/` printing nothing, and the diff of `audit.ContractID` empty. If either PR changes that, item 4.1 falls on it, and the `relayKinds` probe reruns on its head by a D6 instance before it merges.

## 6. F-027's gate (no product wiring)

Both PRs are unwired (D4-96). Each PR shows, outside `_test.go` files and test-only packages:

- `git grep -n "ServeSensor"` in `cmd/`, `platform/` and `modules/`: only the definition;
- `git grep -n "network_sensor"` outside the tests: only the configuration's own type and its checks, as on `main`, and no configuration file or default carrying the section;
- `git grep -n "\.Serve("` on a `sensorlink.Link`: only `ServeSensor`;
- the callers of every new exported function that judges a hello, a `tick`, an `ack` or a record's place, and of every new intake entry point: only the definition and `ServeSensor`;
- no dialer, enrolment, listener or firewall code (P4-4-DE).

The wiring comes only in P4-4-DE's PR that passes the last owed test (D4-96).

## 7. Still owed after both PRs

The rig legs (the sensor's brief and D6's rig brief); N-14 if P4-4-HR24's stage 3 has not merged before INT-D5 opens; §3's legs (P4-4-DE, if D1 rules so).
