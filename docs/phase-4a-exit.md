# Phase 4 first exit report (items 1 and 2)

Owner: C1 (the A1 role). Date: 2026-11-04. Status: **draft. The gate is not yet decided: the SER half of V-M4 has not run (D4-47).** Every other gate item is met on `main`, as C6's gate table in `docs/verification.md` records ("Phase 4 first exit gate status").

This report closes the first two items of Phase 4: configuration retrieval, its baseline and prior approval (item 1, R3.6 and R3.7), and the event-behaviour baseline (item 2, R4.8). The owner ruled that the two finish together and that work stops at the end of each Phase 4 item for the owner's check (D4-34). It follows the milestone format in `CLAUDE.md` §9 and mirrors `docs/phase-3-exit.md`. No device was contacted. Every result is `desk` (Go and Python tests on a CI runner or an agent's container) or `simulated` (the real binaries against C6's recording simulator, on loopback). No result is `hardware-verified` (B-01). The owner's PC was not used in Phase 4 (D4-12), so GitHub Actions was the only shared test path.

In older records A*n* and B*n* mean the role that C*n* now holds (D3-12, D4-28).

## Milestone

**Phase 4, items 1 and 2: configuration monitoring and the event-behaviour baseline, on the simulated SEL-751.** The objectives, from the Phase 4 briefs in `docs/agent-handoffs.md` and the gate there ("Phase 4 first exit gate"):

- retrieve the SEL-751's configuration by the highest safe rung it offers (R3.7), store it as a versioned snapshot, and detect a meaningful difference (C9);
- raise an alarm for a configuration change that no prior approval covers, where "prior" is the order in the audit chain, and let an approval silence only the alarm (R3.6; C7 0.6, C8 0.5);
- learn an event-behaviour baseline per asset over an observation period, make it active only after an operator acknowledges it, and raise explained departure alarms (R4.8; C10);
- keep the evidence each alarm cites (C5 0.4 holds, D4-19, D4-20);
- close the Phase 3 carry-over: the node key register (#176), signed quarantine-clear and sequence-reset files (relay PR 2), HR-11's absolute bound, and the Phase 3 carried checks.

## Implemented (on `main`)

| Component | Owner | Main PRs | Reviewers |
| --- | --- | --- | --- |
| C9 0.1 to 0.4 (snapshot, semantic difference, size bounds, `Difference.Encode`); C3 0.3 (operation limits and runs); SEL-751 register revision 5 (24 `SHO` forms and the run `sel.config.read_all`); C2 0.6 `config.read` and the SEL-751 configuration read; the measured maximal result; capability-matrix citations after C6's V-M3 desk check | A2 role (B2, C2) | #247, #279, #293, #301, #331, #338, #345, #363, #378, #388, #392, #395 | A6 role, A3 role, A5 role |
| C7 0.6 and 0.7 (change approvals, baseline acknowledgements, the approver role, a run request naming a register run); C8 0.5 to 0.10; the collector accepting `node.change_approval` and `node.baseline_ack`; the collector's POSIX-semantics state replace; `govulncheck`; HR-11 and HR-13 to HR-15 in the threat model | A3 role (B3, C3) | #250, #257, #258, #259, #269, #272, #298, #300, #309, #318, #322, #326, #332, #334, #341, #346, #381, #387, #393 | A6 role, A2 role, A5 role |
| C10 0.1 and 0.2; the event-behaviour learner and detector, alarm identity, measures, snapshot and restore, the lifecycle, learner 0.2 (D4-45); V-M4's alarm oracle draft; the receiver's batch split, unknown-sender stream, unknown queue share and UDP read buffer | A4 role (B4, C4) | #254, #274, #284, #287, #291, #303, #317, #330, #335, #364, #369, #384, #403, #414 | A6 role, A2 role, A5 role |
| C5 0.4 to 0.7 in the SQLite store (configuration class, holds, `syslog-unknown`, the commit cap, the per-record WAL term, document series, the bounded remover); the node's configuration database, holds, configuration-read writer, reconcile and `HoldsConsumer`; the event-baseline feeder (slices 1a to 1c), its checkpoint, and the restart and open-gap handling (D4-45); HR-13 in the node; relay PR 2a and 2b; the Windows CI budget step | A5 role (B5, C5) | #246, #262, #264, #273, #281, #282, #290, #296, #297, #299, #302, #305, #308, #311, #313, #320, #324, #328, #339, #343, #347, #365, #372, #375, #376, #382, #390, #400, #405, #406, #408, #413, #415, #418 | A6 role, A3 role, A4 role |
| The simulator's `SHO` forms and settings-change injector; the GT-INJ schedules (V-M2, V-M4, and the 60 s SER series); contract tests for every new contract version; the Phase 3 carried checks on hosted Windows; the stepped test clock and its release-build refusal; V-M2, V-M3 and V-M4 on the real binaries; the gate table | A6 role (B6, C6) | #241, #242, #245, #248, #249, #251, #253, #256, #261, #263, #266, #268, #270, #275, #283, #288, #292, #304, #307, #321, #373, #379, #391, #394, #398, #401, #402, #407, #410, #411, #417, #420, #423, #426 | A1 role, and the owners of what each test covers |
| D4-1 to D4-47; Go 1.27.3; CI timeouts and legs; the C-team handoff | A1 role (B1, C1) | #238, #239, #277, #289, #306, #310, #319, #323, #327, #333, #337, #362, #367, #371, #374, #377, #380, #389, #397, #399, #409, #412, #416, #419, #424 | Affected owners for each ruling |

#176 (the node reading its TLS keys from the key register) merged on 2026-10-28.

Contract versions on `main`:

| Contract | Phase 3 exit | Now | What Phase 4 added |
| --- | --- | --- | --- |
| C1 | `otsec.asset/0.2` | `0.2` | Unchanged. |
| C2 | `otsec.adapter/0.5` | `0.6` | `config.read`: a run is all or nothing, and "Invalid Command" is never a language refusal (D4-23); `failed.config_unparsable`: a reply the rule cannot read, or a read too big for one C9 snapshot, ends the run with no record (D4-25). |
| C3 | `otsec.register/0.2` | `0.3` | `runs` and `limits`; a pre-0.3 package carrying either is refused (D4-13, D4-16). SEL-751 content revision 5. |
| C4 | `otsec.event/0.2` | `0.2` | Unchanged. |
| C5 | `otsec.store/0.3` | `0.7` | The configuration class, held records, `syslog-unknown`, the commit cap (0.4); the per-record WAL term and `events` as a rowid table (0.5, D4-14); hold code `acknowledged-difference` (0.6, D4-18); the last hold codes, document series and a bounded remover; the class also holds event-baseline checkpoints (0.7, D4-32, D4-39). |
| C6 | `otsec.syslog/0.3` | `0.3` | Unchanged. |
| C7 | `otsec.authz/0.5` | `0.7` | Change approvals, baseline acknowledgements and the approver role (0.6, D4-2); a run request may name a register run, its limits from the signed register only (0.7, D4-27). |
| C8 | `otsec.audit/0.4` | `0.10` | Approval and acknowledgement records (0.5); an acknowledgement ends open configuration alarms (0.6, D4-18); `config.read_compared` and `config.reads_removed` (0.7); `config.baseline_recorded` (0.8); `config.checkpoint_not_restored` and `VerifyConfigFrom` (0.9); `difference_too_large` (0.10, D4-42). |
| C9 | none | `otsec.config/0.4` | New: the configuration snapshot and its semantic difference, bounded in settings and bytes (D4-25, D4-42). |
| C10 | none | `otsec.baseline/0.2` | New: the event-behaviour baseline of one asset; a checkpoint at every configured ceiling fits one record (D4-30). Learner 0.2 ends the period where both minima first hold (D4-45), and refuses a 0.1 checkpoint, so a node upgraded mid-period relearns from the start. |

Every change bumped the minor, kept a reader for the previous version, and had the A6 role's contract tests before merge.

## Independently verified

C6's gate table and the findings log (F-016 to F-023) in `docs/verification.md` are the record. C6 wrote each test from the rule text and the GT-INJ schedules, which were committed before the product first ran against them, and mutated the code under test.

| Check | Result |
| --- | --- |
| **V-M2** (R3.6) on the real binaries | **Pass**, `simulated` (F-022, #420). All 21 changes of `gt_inj/config.json`, 169 of 169 checks, on the tagged node and collector, locally and in the `integration-long` leg. An alarm is raised exactly for the 15 changes with no valid prior approval (none, another device, an ended window, backdated, a non-approver); the 3 approved changes raise none and link their approval; the 3 non-approver approvals are refused and recorded. Deleting or editing an approval fails audit-chain verification. 4 of 4 product mutants in `configread.go` killed. The non-semantic changes are read under D4-46. |
| **V-M3** (R3.7) for the SEL-751 | **Pass**, `desk` and `simulated` (#394, F-022). Every matrix cell checked against S22, with three findings fixed in #388. On the binaries, every session is exactly the signed register's `sel.config.read_all` over Telnet; the untagged node refuses at start a configuration naming a method, a rung or an FTP endpoint. |
| **V-M4** (R4.8), Syslog half | **Pass**, `simulated` (F-019, F-020, #402, #410, #411, #417). Exactly the 10 expected alarms (recall 10 of 10, every kind in full: repeats 3, absence 3, rate 2, new 1, time 1; precision 10 of 10), none before the acknowledgement. The held-out series raises none. Three runs store the same baseline bytes, whose period ends at the series' T, 2026-11-16T00:00:08Z, with 773 events, and the repeat raises the same alarms in every field. Release builds refuse the test clock. |
| **V-M4**, short case on the untagged node | **Pass**, `simulated` (F-023, #423). Recorded, active only on the acknowledgement, then exactly the new-type and repeats alarms, plus a time alarm when the burst falls in an hour the period never saw. |
| **V-M4**, SER half | **Not run yet.** The series `events-ser60.json` (913 reads at least 60 s apart, 6 expected alarms) is merged (#426, C4 accepted, no alarm difference). The harness that serves the rows at the series' read times is C6's next PR (D4-47). |
| **V-S7** with revision 5 | **Pass** (#304, F-023). The deny corpus runs against revision 5 with no line skipped: exactly the 24 `SHO` forms approved, 699 variants refused. `check.py` passes every V-M2 recording against the signed revision 5, and four injected controls fail. |
| **Contract tests** | C9, C10, C5 0.4 and 0.5, C7 0.6, C8 0.5, C3 0.3 (#249, #253, #256, #268, #283, #292, #304); C2 0.6, 9 of 11 mutants killed, both survivors equivalent (F-023). |
| **HR-11's absolute bound** | **Pass**, `simulated` (#321). An unknown flood across an upstream outage, over UDP and TLS, fills only its class while a known device is still stored and forwarded. |
| **Phase 3 carried checks** | Built and merged: the DMY and YMD slice reconcile on the real binaries (#270), the canary scans of command lines and start environments on Windows (#242, #261), the slice and unknown-restart legs against the installed services on hosted Windows (#263), and the admin relay with `config\admin`'s ACLs there (#266). |

### Defects found by independent tests in Phase 4

- **A baseline that depended on scheduling** (F-020). A repeat run on the same series learnt different baselines, because the period ended at the feeder step that noticed the minima, not at the instant they held. No alarm changed on this series. Fixed by D4-45, #413, #414 and #415; three runs now store the same bytes.
- **A late `collection.missed` can move a baseline's end** (F-021). Accepted as a limitation of D4-45; it needs a fault, and its sign is `evidence.not_stored`.
- **An unknown flood shares a datagram listener's queue** (F-017). Unknown senders now hold at most a quarter of it (D4-21, #317, #379).
- **Wrong rulings, caught in review.** C6 and C5 found errors in the text of D4-41, D4-45 and D4-46 before or after merge; each was corrected with an attribution note. #416 was FAIL, then PASS at `667ad0c`.
- **Oracle and detector defects in the A6 role's own harness** (F-018, F-019): a loss detector that read counts before stacks, and an oracle that misread the rule name `new-type`. Both were found by product runs and fixed with a test. The untagged short case also assumed no time alarm, but a burst in a UTC hour the period never saw raises one; the test now derives it from the stored times (C4 on #423).
- **A series no node could produce** (D4-47). 387 of `gt-inj-ser`'s 1,025 read gaps were under the 60 s floor the node and collector enforce. C6 found it while building the harness, and #426 replaced the series with `events-ser60.json`, keeping the same 6 alarms.
- **V-M3 desk findings** (#394): three citation errors in the capability matrix, fixed in #388.
- **An approved oversize difference** (C2 on #392) and **a held baseline after a prune** (C4 on #387): design gaps found in review, ruled as D4-42 and D4-41, and built (#393, #408).

### Where tests ran

- **CI** is the main test path (D2-13). It now has **fourteen `ci.yml` jobs**: Go on Linux and Windows, pytest, `integration`, and ten `integration-long` legs, plus `govulncheck` on Linux and Windows targets (D4-3). Every merge was checked by the A1 role against green checks on the PR's head, with the merged result checked when `main` had moved.
- **The owner's PC** was not used (D4-12).
- **Agents' Linux containers.** C6's gate runs were also run locally on Linux, as each finding states.

## Exit-gate items

| Gate item (`docs/agent-handoffs.md`, "Phase 4 first exit gate") | State |
| --- | --- |
| V-M2, V-M3 (for the SEL-751) and V-M4 pass on the real binaries, `simulated` | **Open: V-M4's SER half.** V-M2 and V-M3 met. V-M4's Syslog half and short case met. The SER half waits on C6's harness (D4-47). |
| C9, C10, C2 0.6, C5 0.4, C7 0.6 and C8 0.5 merged, with reviewers' records and the A6 role's contract tests | **Met.** |
| V-S7 still passes with the new register lines, and the deny corpus covers every `SHO` form added | **Met.** |
| #176 and relay PR 2 merged; HR-11's absolute bound merged, or recorded as the open condition before any `device-observed` listener | **Met.** The threat model's HR-11 row is not yet updated (#352, C3). |
| No safety or security objection open | **None open.** C6 has none (#423). C3 has none against items 1 and 2 (#429), on the condition that the SER harness changes only test harness and CI; if it touches `cmd/`, `modules/`, `platform/`, `contracts/` or the release-build test-clock refusal, C3 reviews it before the gate. |

## Owner decisions needed

1. **Accept Phase 4 items 1 and 2**, with the conditions in this report.
2. **Confirm item 3 next**: vulnerability applicability with SNMPv3 identity (R1.8 with R9), in ADR-0008's order.

## Failed or incomplete

- **V-M4's SER half** (above).
- **The Windows `platform/node` time budget** (D4-22's 720 s) is breached on five of ten green runs (815, 1526, 720.5, 743 and 731 s; the others 622, 558, 652, 629 and 586 s), and 1526 s is 85% of the 30-minute package timeout under a 45-minute job (D4-44). One runner can take 2.5 times as long as another. Running the tests in parallel saved nothing on one runner (#427: parallel 652 and 743 s, serial 629 s). A profile on the hosted Windows runner (#428, closed unmerged) put 8.48 s of 18.97 s of blocking in five node tests in recreating the recovery reserve (about 20 MB with a flush) at each runtime start, F-013's design; 6.79 s went to commit syncs and 1.78 s to close checkpoints. C5 cut the starts per test where no case depends on a fresh one (#421, #425, #430): about 5% of the package's fsyncs on desk (29,164 to 27,816). The remaining cost is starts the tests need, and a Windows-only wait not yet identified: four of the slowest tests (`ConfigReadHoldsAfterRestart` and three relay tests) take 0.13 to 0.49 s on desk and 10 to 47 s on Windows, which is neither flushes nor starts (C5). **Ruling (C1):** the 720 s figure stays a warning, and the hard guard is the 30-minute timeout. Options, store-side ones with C3, come back if a green run passes 1620 s (90%) or any run times out.
- **One unexplained Windows failure** of `TestUnknownSendersCannotDisplaceDevices` (a known sender stored 7 of 20, job 126728488246). It passed on re-run. It is not classed as a flake; #410 added diagnostics.
- **`config.reads_removed`** (D4-20 rule 3) is contract only: it is defined in C8 0.7 (`contracts/audit/config.go`) and used in `contracts/store/remove.go`, but nothing in `platform/`, `modules/` or `cmd/` writes it, so retained reads are not removed.
- **V-M3's "lower rung refused at start" is vacuous for the SEL-751**: rung 3 is its only built rung, rung 1 is absent and rung 2 waits for hardware test Q3, so no lower rung exists to name (D4-40 point 3). A schedule naming an operation the register lacks is refused at run time, before any connection, not at start.
- **Not run, carried from Phases 2 and 3:** V-S7's 24-hour soak, (c) and (d); V-S6's link cut in the middle of a SER read; V-S9's file-system exhaustion; V-S15 on the SER path; V-S18 and V-S20.

## Unverified assumptions

Everything in the Phase 2 and Phase 3 lists still stands. Phase 4 adds:

- **The configuration run's replies.** The simulator answers `SHO L`, `P F`, `R` and `F` with SYNTHESIZED placeholders; that the relay echoes each line but a password, and answers "Invalid Command" for a form it lacks, are H-13 assumptions (F-022). The layout the rule reads (S22 Figure 7.43) is itself `documented-untested` (H-13): STX and ETX framing with the prompt after ETX, the continuation of a wrapped value (S22 prints no example), the header not repeating within a reply, and which classes a relay can lack. A relay that prints otherwise fails closed with `failed.config_unparsable` and the bytes kept, so it gets no baseline rather than a wrong one (C2).
- **The size bounds are not measurements.** `MaxSettings` is S22's 8,734 plus an assumed 25%; the run's 512 KiB total and 300 s deadline are set from the manual; D4-42's worst-case difference is computed from the settings sheets' widths (`difference_max.py`). None is from a capture (C2).
- **Revision 5's read-only classification** of each `SHO` form on real firmware waits on H-16.
- **Retrieval sees a real change** made with the vendor tool (R3.1, R3.5).
- **The real false-positive rate** of the event-behaviour rules needs a real device's history over at least one observation period.

## Architectural decisions

D4-1 to D4-47 are in `docs/phase4/B1-decisions.md`. These matter most for later phases:

- **D4-2:** an approver is a per-key allowed kind, and an approval takes its signer and nonce from the C7 envelope.
- **D4-18 and D4-19:** an acknowledgement ends the asset's open configuration alarms, and a return to baseline keeps the alarm's evidence held.
- **D4-20:** retention of configuration evidence, with D4-46's reading that a retained read keeps both snapshots.
- **D4-23 and D4-25:** a configuration run is all or nothing, and a snapshot is bounded so a valid run always fits the record cap.
- **D4-26, D4-30 and D4-32:** the feeder's state survives a restart through a checkpoint in the configuration class, at every ceiling.
- **D4-41:** on a pruned view, the holds fold takes the configuration baseline from the store's held baseline, and the audit prune waits for the holds.
- **D4-42:** an oversize difference is recorded without a stored difference, and an approved one raises nothing.
- **D4-45:** a baseline's period ends at the first instant both minima hold, fixed by its input.
- **D4-47:** the SER read floor is a safety property, so the test series respects it and no test-only lower interval exists.

## Open risks

- **No hardware (B-01).** No SEL family may be called supported.
- **HR-11's residuals:** the hourly budget refills after a forward clock step and a restart; spoofed UDP sources; F-017's shared queue under a long stall.
- **Baseline poisoning.** A baseline learnt from Syslog alone can be poisoned while it is learning, and the detection knobs have no ceilings (C3 on slice 1c).
- **A permanently missing configuration record stops audit pruning for good** (D4-41). It fails safe, and the audit class then fills to D4-19's stop rule.
- **A flapping device fills the configuration class** under D4-19, and configuration monitoring then stops; the node says so.
- **The SER buffer can wrap during a hold.**
- **Rollback below C8 0.10.** Once a node has written `difference_too_large`, rolling back below 0.10 makes start-up verification fail closed. Readers must be upgraded before writers.
- **A stuck event-baseline feeder holds collection's pruning.** `node-eventbaseline` is a `Required` consumer on the Syslog and SER streams it reads (#405), so a feeder that stays not started or stuck on a record holds their pruning, and at the quota D4-19's stop rule applies to collection. It fails safe and visible (the consumer's lag in health, `event-baseline-not-started`, `event-baseline-stream-stuck`), but a detection fault can, at the quota, stop intake. `node-holds` is the other new `Required` consumer, on the audit stream; it holds the prune only behind an existing delivery cursor and never makes an unforwarded record prunable (#408) (C3).
- **Late events are not baselined.** An event committed behind the feeder's watermark is counted as `Late` and not fed to the learner or detector, so a departure carried only by late events is not alarmed. The count is in status (C3).
- **The admin request's replay window.** A signed request can be replayed to the collector only within `MaxAdminLifetime` (15 minutes), and the collector spends its nonce. After an audit prune past both acceptances, a restart and a resend within those 15 minutes, a second record can be written for one request, and `VerifyConfig` accepts it. It adds no authority beyond what was signed; the one change is that a denial can become a success if the baseline it names became the acknowledged one meanwhile (C3 on #406).
- **The tagged test-clock build.** In an `otsec_testclock` build, whoever can write the clock file controls the node's and the collector's time. CI pins that release builds refuse it (#407, `tests/security/testclock_c6_test.go`). A tagged build must never be deployed (C3).
- **F-016:** Windows store flushes stall on the hosted runner's disk.
- **C10's 512-type ceiling and the SEL-400 series.** A 400-series relay can have about 507 types, just under the 512 ceiling (D4-38, `documented-untested`). Revisit before a 400-series adapter is briefed; until then `counts.types_overflow` shows a partly baselined asset.
- **Register text that approvers read is wrong about OUT101.** `sel.session.acc`'s `side_effects` say that SALARM's 1 s pulse (three wrong passwords, or a Level 2 or C access) "closes the alarm contact" through the default `OUT101 := HALARM OR SALARM`. OUT101 is fail-safe by default (`OUT101FS := Y`), so its coil de-energizes, and whether a contact opens or closes depends on the site's wiring (S22 Table 4.83, p. 2.31). `device-capabilities.md` is already correct (#388). The next register revision must fix the register's text (C2, #395).
- **Carried:** residual SER loss with repeated keys (D1-17), plaintext Telnet to the relay (lab only, ADR-0005), PEN 32473, the 31-minute floor on a flaky link, a port-server path refused until H-13.

## Limitations recorded in Phase 4

- **A restart's gap starts at the checkpoint's watermark**, so a restart after T with the last checkpoint before T moves the end later (D4-45; the record states its period).
- **A late `collection.missed` is clamped to the watermark** (F-021).
- **A recorded baseline awaiting acknowledgement is forgotten in a cut view**; the guard then refuses that acknowledgement, so the node fails closed (C3 on #384).
- **The configuration fold trusts the node's own audit stream** without `VerifyChain`, and on a pruned view it also trusts the configuration store's holds (D4-41, #408), so a tampered hold table is read as state. The full chain upstream catches a forged audit record; it does not catch a tampered hold, but the reconcile at start corrects a hold against the records in view (C3 on #390 and #429).
- **D4-46 was ruled after a product run**: V-M2 reads `config.json`'s "difference R0 to R1" for a non-semantic change as both snapshots stored and different, `no_difference`, and no difference record. `config.json` was not edited.
- **The default quota holds only a few days of SER transcripts at the minimum interval.** Each SER read keeps the whole buffer as adapter evidence; at one read a minute over the 7-day series that was about 45 MB, and the default 64 MiB quota pruned the first 50 rows' transcripts. The pruning was visible (the run failed), not silent. Sizing the quota for SER is a deployment item (C6).
- **Which gate runs used the `otsec_testclock` build:** V-M2 and V-M4's GT-INJ feed. The V-M4 short case and V-M3's start case run untagged.

## Lessons

- **Repeat runs find what single runs cannot.** F-020 showed only on a second run of the same input.
- **The oracle is code too.** F-019's defect was in the A6 role's oracle; a product run found it, because the oracle's self-tests used its own names.
- **Measure before optimizing.** Parallel tests looked like the cure for the Windows budget; a paired run on one runner showed no saving.
- **Rulings get reviewed like code.** Three of the A1 role's rulings (D4-41, D4-45 and D4-46) needed corrections from C5 and C6.
- **Safety floors are not test knobs.** The 60 s SER floor shaped the test series, not the other way round (D4-47); a test-only fsync skip was refused for the same reason.

## Where the eight capabilities stand

| Capability (brief §1) | Phase 4 items 1 and 2 | Planned |
| --- | --- | --- |
| 1.1 Asset management and monitoring | Unchanged from Phase 3. | Phase 4, item 3 (R1.8, with R9). |
| 1.2 Secure engineering and remote access | Not built. | Phase 4, item 5. |
| 1.3 Configuration and baseline monitoring | SEL-751 configuration read by command line (rung 3), versioned snapshots, semantic difference, prior-approval alarms and evidence holds, end to end on the real binaries, `simulated`. | Other families, and `config.reads_removed`. Not covered: the 175 touchscreen settings, which no `SHO` form prints (owner, 2026-10-28: not required). |
| 1.4 Syslog and SER collection | Event-behaviour baselines with explained departure alarms for Syslog; SER pending. | V-M4's SER half. |
| 1.5 Custom IED command framework | C3 0.3 runs and limits; revision 5. | Each new family extends it. |
| 1.6 Intrusion detection | Not built. | Phase 4, item 4. |
| 1.7 Modular and additive architecture | Every contract change was additive, with readers for earlier minors. | — |
| 1.8 Centralized and distributed deployment | Single-site node only. | Phase 4, item 6. |

## Next coordinated tasks

1. **Before the gate:** C6's V-M4 SER harness (reviewed by C4 and C5, its `ci.yml` leg by C1); C3's confirmation that no objection is open.
2. **After the gate:** C3 closes #352 and writes a fresh HR-11 row from `main`; C5's #421 and #425 and the fixture-time work on the Windows budget; `config.reads_removed` in the node.
3. **Phase 4 item 3**, after the owner's check (D4-34).

## Owner sign-off

Pending.
