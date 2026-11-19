# Handoff: continuing in Claude Code CLI

Written by D1 on 2026-11-10, with `main` at `82daa04` (#604). The work moved from Claude project threads to Claude Code CLI on the owner's PC. This file is what a CLI session needs to continue. Everything in it is `desk` evidence, read from the repository, the decision log and GitHub on that day.

Read [CLAUDE.md](CLAUDE.md) first, then this file, then your role's file in [.claude/agents/](.claude/agents/). For the reasons behind recent work, read [docs/phase4/B1-decisions.md](docs/phase4/B1-decisions.md) from D4-58 to its last entry.

## Where the work stands

| Phase | Result |
| --- | --- |
| 0 to 3 | Accepted by the owner |
| 4, items 1 and 2: configuration baselines, the event-behaviour baseline | Accepted (D4-48) |
| 4, item 3: vulnerability applicability with the asset module | Accepted (D4-62); report in `docs/phase-4-item3-exit.md` |
| 4, item 4: network IDS | **In progress.** Contracts approved (D4-68). The node side is merged (D4-70 to D4-76). The sensor is not briefed |
| 4, items 5 and 6: secure engineering access, the central role | Not briefed |

**What is on `main`.** Two Go binaries: `cmd/otsec` (the site node) and `cmd/otsec-collector` (the privileged collector). For item 4 the node has the sensor intake with its hold for the node's own sessions, the two network store classes, the detector consumer and its checkpoints, alert retention, alert drop counts by rule and asset, `sensor-unreachable`, the network baseline acknowledgement (C7 0.10, C8 0.12), and one full alarm per fill. C13 `otsec.netobs/0.1`, C4 0.3, C5 0.9 and C2 0.9 are coded. No sensor process exists yet, and nothing captures traffic.

**Evidence ceiling.** Every result is `desk`, `simulated`, `CI-Linux` or `CI-Windows`. No device has been contacted, nothing is `hardware-verified`, and no SEL family may be called supported.

**CI on `main` at `82daa04`.** `ci` passed on the push ([run 42506206650](https://github.com/alialyami90/OTSEC-Proj/actions/runs/42506206650)). The weekly `govulncheck` passed on 2026-11-09 ([run 42629797940](https://github.com/alialyami90/OTSEC-Proj/actions/runs/42629797940)).

## The one blocker, and the next action

**The owner chose option (b) for the passive sensor on 2026-11-11** (D4-85): a separate Linux machine at each site that feeds the node. It supersedes their choice of option (a) on 2026-11-10 (D4-78), after D4's evidence in PR #618 showed that under (a) Suricata's Windows build needs Npcap even to start, Zeek has no Windows binary, Npcap needs a paid licence, and its safe install mode is unknown (D4-84). The link's contracts, the engine run and the test rig are briefed (D4-86), and no sensor is built. [ADR-0009](docs/decisions/ADR-0009-passive-sensor.md) is accepted for option (b) on `main` (#618). D3's trust design for the link is merged (#624): `docs/phase4/D3-sensor-link.md`. The options are (a) Zeek or Suricata on the Windows site node with a capture driver, (b) a separate Linux sensor at each site that feeds the node, and (c) the project's own Go decoders in a separate process on the node. D1 recommended (b). The ADR's table gives the evidence for each.

**CHECKPOINT (D1), 2026-11-19, later (D4-120), PAUSED at the owner's word (D4-120 item 8).** No agent is running. Open PRs: #768, #769 and #770, none past review; resume with D4-120 item 8's order, then item 7. Merged since D4-119: #760 (C13 §15 in code), #762, #763, #764, #748 (INT-D5 2c), #766 and #765 (D4-120 item 1). Approved: the C13 rollback ruling and options (b) for later C13 and C4 minors, and the refusal alarms (D4-120 item 2). **Next, in order: D4-120 item 7.** New open items: D4-120 items 3.1 to 3.8. A disclosure slip on #764 was contained (D4-120 item 4): any brief that touches HR-23, finding 1 or a stock Zeek report names the held-rows rule.

**Earlier checkpoint (D1), 2026-11-19 (D4-119), superseded by the checkpoint above for what is open.** Work resumed at D4-118 item 7. Merged: #750, #741 (C13's absent keys, approved), #746, #753 (C4 0.5, approved), #752, #751, #757, #758, #754, #755 (C4 0.5's validator), #759, #756 and #747 (INT-D5 2b) (D4-119 item 1). **Next, in order: D4-119 item 7.** Open PRs: `gh pr list`. New open items: D4-119 items 3.1 to 3.7. Test findings: D4-119 item 4. Two items added to the self-check list (D4-119 item 5.3).

**Earlier checkpoint (D1), 2026-11-17, night, PAUSED at the owner's word (D4-118), superseded by the checkpoint above for what is open.** No agent is running. Merged since D4-117: #742 (INT-D5 part 2a), #744 (§8.4 item 3's mount check) and #745 (#718's TCP cells restated). Open, none yet past review: #741 (C13 absent keys; D4 revises to D3's and D6's findings), #746 (fuzz pad; D4's fixes pushed at `3054d6bf`, not re-reviewed), #747 (INT-D5 part 2b, reviews not started) and #748 (INT-D5 part 2c, partial; D5's 6958574117 waits on D1's ruling). **Resume with D4-118 item 7, in order.** New open items: D4-118 items 2.2, 2.4, 2.5, 4, 5.1 and 5.3. HR-23's counted run still waits on #746, D4-118 items 2.2 and 2.5, `dnp3-tcp-master-short`, `table.py`, finding 1's open item (D4-112 item 4.5), D1 naming the rows judged inside the job (D4-112 item 1.3) and §8.4's items that need the (C) image.

**Earlier checkpoint (D1), 2026-11-17, evening (D4-117), superseded by the checkpoint above for what is open.** Merged since D4-116: #739 (D4-116 itself was #740). Open: #741 (D4's absent-key proposal, revising to D4-117 item 3) and #742 (INT-D5 part 2a, reviewers to start together when D4 is free). Running: D4's `run.sh` script-hash check. D4's queue: D4-117 item 5. New open items: D4-117 items 2 (D6's restatement, before `table.py` and the counted run), 3.2 (the `objects_unread` signal, in #741's revision), 3.3 (stacked frames, in #741's revision), 3.4 and 3.5 (in #741's revision), 3.6 (before P4-4-DE) and 3.9 (the code change).

**Earlier checkpoint (D1), 2026-11-17, later (D4-116), superseded by the checkpoint above for what is open.** Merged this session, after D4-115: #726, #731, #732, #733, #734, #735, #736, #737 and #738 (D4-116 item 1). Open: #739 (HR-23's TCP statement; D2 accepts, D6 reviewing). Running: INT-D5 part 2 (D5, brief P4-4-INT-D5P2), as three PRs 2a, 2b and 2c (D4-116 item 3.1) and D4's per-key proposal for absent C13 keys (D4-116 item 4.3). D4's queue: D4-116 item 8. New open items: D4-116 items 2.4, 3.5, 4.3, 4.4 and 6. In the checkpoints below, D4-115's queue items 1 to 4 are done.

**Earlier checkpoint (D1), 2026-11-17 (D4-115), superseded by the checkpoint above for what is open.** Merged this session: #722, #723, #724, #727, #728 and #729 (D4-115 item 2). Open: #726 (INT-D4a, D6's N1 and N2 to fix). D4's fuzz work (P4-4-HR23-FUZZ) is on branch `agent/telemetry-hr23-fuzz`, with no PR yet. D4's queue: D4-115 item 8. New open items: D4-115 items 4, 5, 6.3 and 7. In the checkpoints below, steps 2 (#724) and 6 (#722) are done, and step 4's D7 part (#723) is done; finding 1's open item (D4-112 item 4.5) stays open. The order stands for the rest.

**Earlier checkpoint (D1), 2026-11-16, late, paused at the owner's word (D4-114), superseded by the checkpoint above for what is open.** When it was written, no agent was running and nothing had merged in that session. The order of the earlier checkpoint below stands. Where each step stands, and D4's queue: D4-114 items 3 to 5.
- Step 1, D4's fuzz PR: branch `agent/telemetry-hr23-fuzz`, no PR yet (D4-114 item 3.1).
- Step 2, PR 1b: #724 (item 3.4).
- Step 4, D7's P1: #723, to a fresh D7 with D1's rulings (item 4).
- Step 6, the HR-25 rows: #722 (item 3.2).
- **D4's queue, in order:** the fuzz PR; reviews of #722 and #724; the TSV hashes in `pins.env` after #724 merges; step 3; finding 1's open item; §8.4's items after #723 merges, before the counted run; the HR-25 design PR (with item 5).

**Earlier checkpoint (D1), 2026-11-16, paused at the owner's word (D4-112, D4-113), superseded by the checkpoint above for what is open; its order stands.** No PR is open, and no agent is running. Merged this session, after D4-109: #708, #710 to #720. P4-NODE-WT is complete. HR-23's build (#715) and its stage-2 cases (#718) are on `main`.
- **The owner owes** "Waiting on the owner" item 3 (D4-112 item 3.4) and item 18 (D4-112 item 1), including the steps D1 described to the owner directly.
- **Next, in order, each waiting on the step named** (D4-112 item 8; D4-113):
  1. D4's fuzz-workflow PR (D4-112 item 4.2). Then D6 runs and judges the fuzz run (design §4.5 and §4.6).
  2. P4-4-HR2325S PR 1b, D3's M2 (D4-113 item 3.1).
  3. D4's `table.py`: the HR-23 rows and the tokens `reqhdr`, `svc` and `X=code` (D4-113 item 3.2). It also makes the job hold the rows of D4-112 item 1.3 from per-row publication, if the job has to change for that.
  4. D7's P1 (D4-112 item 4.6) and finding 1's open item (D4-112 item 4.5).
  5. HR-23's counted run, after steps 1 to 4. Before it starts, D1 names to the run's author the rows that are judged inside the job and not published row by row (D4-112 item 1.3).
  6. D3's records PR, the HR-25 and R-1 rows (D4-112 item 6; D4-113 item 2.3), before step 7.
  7. D4's HR-25 design PR for option (a) (D4-112 item 3).
  8. P4-4-HR2325S PRs 2 and 3 (D4-112 item 3.5).
  9. HR-25's build.

  Beside these:
  - **P4-4-INT's four PRs,** in #719's order, with G4 before INT-D4b (D4-113 item 4). INT-D4a may go ahead of D4's HR-23 and HR-25 work, when D4 is free between tasks (D4-113 item 4). Then P4-4-DE.
  - **HR-24's stage 2 (D6) and stage 3 (D4), and P4-4-HR22S,** as the night checkpoint's item 5 below has them. HR-24 must close on a measured fix before item 4's gate (D4-95, D4-98), and N-14 waits on HR-24's stage 3.
  - **The rest of the night checkpoint's item 5** stands wherever steps 1 to 9 do not replace it.

  D4's PRs wait on D4's one-instance queue (D4-89).

**Earlier checkpoint (D1), 2026-11-16 (D4-112), superseded by the checkpoints above.** Merged since the checkpoint below was written: #710, #712, #714, #716 (D4-111), #717 and #711. P4-NODE-WT is complete. Open PRs: `gh pr list`. Where each stands:
- #715 (HR-23's build, D4): D2, D3 and D7 accept earlier heads. A fresh D4 is building option (B') for D3's M1, under D1's 6907928324. Then D2, D3 and D6 re-read the diff, and D7 confirms the new pin.
- #718 (P4-4-HR2325S PR 1, D6): two blocking findings, on the short-129 rows and on `dnp3-mal-udp-limit`. A fresh D6 writer restates the rows from #715's amended design note once it is pushed (D1's 6907176282).
- #719 (P4-4-INT's split, D5): G1 to G3 ruled. The order waits for D4's agreement.
- **The owner owes:** one disclosure step that D1 described to the owner directly (D4-112 item 1.2); and the decision on reporting finding 1 to the Zeek project (D4-112 item 1.4).
- **Next, in order, each waiting on the step named** (D4-112 item 8):
  1. #715 merges;
  2. D4's fuzz-workflow PR;
  3. #718 restated and merged;
  4. HR-23's counted run, after D7's P1 and finding 1's open item (D4-112 items 4.5 and 4.6);
  5. D3's records PR (D4-112 item 6), before D4's HR-25 design PR;
  6. D4's HR-25 design PR for option (a);
  7. P4-4-HR2325S PRs 2 and 3;
  8. HR-25's build.

  P4-4-INT (#719, after D4 agrees the split) and then P4-4-DE may run beside these.

**Earlier checkpoint (D1), 2026-11-15, later (D4-110, D4-111), superseded by the checkpoint above.** Merged: #708 (D4-110 and three briefs), #713 (F-027's `relayKinds` probe, killed on `CI-Linux` and `CI-Windows`). Open PRs: `gh pr list`. Where each stands:
- #710 (P4-COL-2) and #712 (P4-C8-T): accepted; merge after `ci-long` and D1's merge check.
- #714 (HR-25's builder, D6): D2, D4 and D3 accept `4a1abee3`; merge after `ci-long` and D1's merge check. D3's F1 is D4-111 item 8.
- #711 (P4-NODE-WT, D5): option (B) (D4-111 item 6). D6's `ci.yml` change runs `platform/node` alone; then a fresh D5 rebases #711 onto it.
- HR-23's stage-3 build (D4): under way, its counted run held (D4-111 item 5).
- **Next, in order:** brief P4-4-HR2325S (D6) after #714 merges; HR-25's build (D4) after HR-23's; the counted runs after P4-4-HR2325S; then P4-4-INT and P4-4-DE (D5), after #711. The night checkpoint's items 3 to 5 stand where these do not replace them.

**Earlier checkpoint (D1), 2026-11-15, resumed (D4-110), superseded by the checkpoint above.** Work resumed at the owner's word, in the order of the checkpoint below. In progress: item 1's first step (D6's builder and captures, row `pin-builder`); item 2 as brief P4-NODE-WT (D5); item 4 (D6's `relayKinds` probe). Issued for D3, one after the other: P4-COL-2 (D4-107 item 5.1) and P4-C8-T (D4-108 item 3.1). Open PRs: `gh pr list`.

**Earlier checkpoint (D1), 2026-11-15, night: work paused at the owner's word (D4-104 to D4-109), superseded by the checkpoint above for what is running; its "Next" list stands.** No agent is running, and no PR is open. P4-4-CC is complete: deliverables 0 to 6 are merged, and their floors are in `docs/release.md` §7 (D4-109 item 1). D4-104 to D4-109 record this session's rulings and open items.
- **Merged this session (25):** #681, #686, #683, #691, #685, #694, #682, #695, #693, #690, #687, #684, #696, #692, #697, #700, #701, #702, #689, #698, #699, #703, #704, #705, and this records PR.
- **Next, when work resumes, in this order:**
  1. P4-4-HR25 deliverable 3: D6's builder and captures, then D4's build with its `pins.env` lines and coverage site map, then the counted run (D4-107 item 1.5; D4-108 item 2).
  2. The Windows `platform/node` time brief (D4-107 item 5.4). It names `TestSensorStartupStuckDoesNotHoldStart`.
  3. The C13 0.2 intake brief and the dialer-and-enrolment brief. They hold most of P4-4-CC's "Owed" table, and F-027's gate waits on them.
  4. D6's elevated run of the `relayKinds` probe, before F-027's gate lifts (D4-108 item 3.2).
  5. The rest of D4-102's "Next": HR-23's and HR-24's next stages, P4-4-HR22S, P4-COL-1's follow-up risk (D4-107 item 5.1), and D3's `time.utc` fix (D4-108 item 3.1).
- **Waiting on the owner:** unchanged (D4-101 item 8, and "Waiting on the owner" below).

**Earlier checkpoint (D1), 2026-11-15, evening (D4-104 to D4-108), superseded by the checkpoints above.** It listed P4-4-CC's deliverables 0 to 5 as merged, and #703 as open.

**Earlier checkpoint (D1), 2026-11-15, later (D4-104 to D4-107), superseded by the checkpoint above.** It listed #689, #698, #699 and #700 as open, and named deliverable 6, D3's records PR and HR-25's deliverable 3 as next.

**Earlier checkpoint (D1), 2026-11-15, superseded by the checkpoints above (D4-104 to D4-106).** It listed the PRs open in the morning of 2026-11-15.

**Earlier checkpoint (D1), 2026-11-14, later (D4-102, D4-103), superseded by the checkpoints above.** The next steps were D4-102's "Next". D4-103 issued the first of them, brief P4-4-CC.

**Earlier checkpoint (D1), 2026-11-14, work paused at the owner's word (D4-101), superseded by the checkpoints above.** No agent was running.
- **Merged this session:** #670, #671 (C2 0.10, a proposal, not yet approved), #674, #678, #676 (P4-4-F27 (3)) and #672 (P4-4-F27 (4), the link-key reader).
- **Open PRs, in the order to resume them:**
  1. #675 (HR-23's design, option (i)): D4 fixes D6's P1, P2 and N-A (6866817721), text only; then D6 re-reads and pins stage 2.
  2. #673 (C13 0.3): first review, by D5, D3 and D6 together; the `insecure` timing choice, (A) or (B), is settled in its comments.
  3. #677 (SL-3, and the HR-22, HR-23 and new HR-25 rows): first review, by D4, D5 and D6 together.
  4. Then D1 approves C2 0.10, C13 0.3 and SL-3 together in a decision entry.
- **Then, as briefs allow:**
  - P4-4-F27 (4) second half: D5's F11 wiring, with D4-101 item 4's owed test;
  - P4-4-DO (F-028);
  - P4-4-HR25 (after #675);
  - HR-24's stage 2 (after the three contracts are approved);
  - the Windows `platform/node` time brief;
  - P4-4-HR22S.
- **Open items and questions for the owner:** D4-101 items 7 and 8.

**Earlier checkpoint (D1), 2026-11-13, superseded by the two checkpoints of 2026-11-14 above and kept for its history.** When it was written, no agent was running and no PR was open. Its "Next, in order" list is history: D4-100 replaced items 3, 4 and 6 with briefs, and P4-4-F27 (3) and the link-key reader of (4) are merged (D4-101). The first full CI of `main` at `459594ff` (#663's tree) passed: `ci` run 43442328706 (4 of 4) and `ci-long` run 43442328628 (20 of 20).

- **Merged on 2026-11-13, after D4-92:**
  - #657 and #659 (the DNP3 unsolicited case and its pin);
  - #658 (D4-95);
  - #660 (P4-4-F27, D4-96);
  - #662 (P4-4-F27 step 1, the forwarder's sensor session);
  - #663 (step 2, the sensor manager, F2, F5, F6, F7, F9's cap and F10, as `459594ff`);
  - #664 (HR-24 stage 1, the design `docs/phase4/D4-hr24-design.md`);
  - #665 (D4-97, the working rules and `ci-long.yml`);
  - #666 (HR-23 and HR-24 rows).
- **The counted run 43419437949** (`dnp3-udp-unsolicited`, 30 of 30 failed) widened HR-23. See the row in `docs/threat-model.md`.
- **Next, in order.** Each task is a fresh agent, under CLAUDE.md's working rules.
  1. **P4-4-F27 step (3), D5.** Covers F1 (the ceiling, with F9's health event and the forwarder's sensor-stream reports, D6's N3 on #662), F3 and F4, with item 9's `recover` in the scheduler calls. Also carries the owed items:
     - `after_seq` (with D4);
     - `tickSensor(final)` in `Close`;
     - holds after `sensor-failed`;
     - a published intake that keeps appending through `liveAppender` when a retry brings the network database back `drain-only` (D6's item 3 on #663, 6853957658).

     The brief's table in `docs/agent-handoffs.md` lists the owed tests.
  2. **P4-4-F27 step (4).** D3 builds the link-key reader under `modules/security/`, settling NK-2 against NK-5. Then D5 wires F11. That is allowed under the wiring ban because step (4) reads a local file and dials nothing (D1's ruling 3 on #660, 6851490813). Its dial legs stay owed.
  3. **The `drain-only` audit gap on `main`** (D3's finding on #663, 6852333699). D1 ruled that the writer is to map it to `drain_only` (6852845352); nothing is built. D3 drafts the C8 0.13 sentence and D5 the C5 one. D5 adds `modeReason` and its node test, and D6 adds the contract test and an F-number.
  4. **Before HR-24 stage 2 can pin:**
     - D4 drafts the C13 minor (`docs/phase4/D4-hr24-design.md` §7.1, and §7.2 items 4 and 7);
     - D2 drafts the C2 minor (`refusals`, `command_octets_received`, the collector's `BytesRetrans` with D3);
     - D3 amends SL-3 for the frame stage's new pipe.

     D1 approves each. The stage-2 risks are in D1's merge comment on #664.
  5. **Dropped: the build summaries** (D4-99).
  6. **D1's own records change:**
     - rule on whether HR-23's fix part (b) needs a change outside the approved engine's script, (D6's note 5 on #666, in D1's merge comment there, 6854399648), and on ADR-0009's third turning condition (HR-23's row, and D4's point 7 on #657, 6852704517);
     - the follow-up list in D1's merge comment on #655, which predates D4-97: D1 takes or drops each item there and carries none further;
     - D6 records in F-027 (`docs/verification.md`) the closings of #662 and #663 (F2, F5, F6, F7, F9's cap, F10), corrects its F11 sentence, and updates points 3 and 4 of its gate for D4-96.
  7. **The approved contracts in code** (C13 0.2, C7 0.11, C8 0.13, C4 0.4, with D6's contract tests): the first of the later briefs of the third part, after P4-4-F27. Item 3's C8 sentence folds into it.
  8. **Issued briefs not yet delivered:** P4-D6-RR, P4-D6-I100, P4-D6-MUT and P4-D7-2 (D4-88, D4-90).
  9. **D4-98's follow-ups:** the list at the end of D4-98 in `docs/phase4/B1-decisions.md`.
  10. **`platform/node` on Windows** took 770 s on #669's head and 777 s on `main`, over its 720 s budget (D6 on #669). D5 looks at it with step (3).
  11. **D4's harness:** `table.py`'s `dnp3.log` path filters `NOT_REQUESTS` (D4's reading on #657).
- **The sensor's own brief** can be issued under the adopted #640 rows (D4-98). Applying them at a site waits for that site's facts ("Waiting on the owner" item 1).
- **F-027's gate stands (D4-96):** no `network_sensor` section outside the tests, no release, and no product wiring of any sensor path.
- **CI under D4-97:** add `full-ci` after the last review, and merge only on the merge check in CLAUDE.md, "Testing and merging".

**Next action before the checkpoint (D1), from 2026-11-13 (D4-92, D4-94, D4-95):** the link's contracts are approved (D4-92) and the Modbus signature is not adopted (D4-94). P4-4-L7 is merged (#654, #655, #656), and P4-D6-GT3 (#657). Next: brief P4-4-F27 (D5 closes F1 to F11, `docs/agent-handoffs.md`, "The third part of item 4"); brief P4-4-HR24's design stage (D4, D4-95); the owner's answers on the sensor host (#640, `docs/phase4/D1-sensor-host-recommendation.md`); then the later briefs of the third part ("What follows in the third part"), after P4-4-F27's deliverables merge. **F-027's gate (D4-87, D4-88, D4-96): until every owed test of §1.9 has passed, no configuration outside the tests carries a `network_sensor` section, no release ships, and no product wiring of any path to or from a sensor merges (no product caller of `ServeSensor` or of `Link.Serve` other than `ServeSensor`, and no wired dialer, enrolment, sensor fold or intake entry point). Code for those paths may merge unwired, reached only from tests.** The paragraph below is the state before 2026-11-13, kept for its history.

**Earlier next action (D1):** carry the five briefs of "Phase 4 item 4, second part" to their results (D4-86): P4-4-S2, P4-4-L1, P4-4-L2, P4-4-L3 and P4-4-R1, in `docs/agent-handoffs.md`. On 2026-11-13 (D4-90): L1 to L5 are merged as documents, R1 is merged, and S2 is done. **The engine is approved: Zeek 9.0.1 with the project's script** (D1's ruling on #637, merged as `d6c2a7f6`), and Modbus on a moved port is a high risk that is not closed (HR-22, which D3 writes under P4-4-L6). **No contract is approved:** the cross-reviews that P4-4-L5 asked for failed C13 0.2 (D5, 6 findings, on #634) and the node's design (D4, 5 findings, on #633). **Next:** brief P4-4-L6 (D4, D5 and D3) amends them, and D1 then approves C13 0.2, the node's design, C7 0.11, C8 0.13 and C4 0.4 together. P4-4-E2 (the Modbus signature measured) and P4-D6-GT2 (the owed GT-PCAP cases) start too; P4-D6-RR, P4-D6-I100, P4-D6-MUT and P4-D7-2 are briefed (D4-88). Then bring the owner a recommendation on the sensor's host (O-1 to O-12), and issue the implementation briefs as the third part. **Until F-027's couplings F1 to F11 (`docs/verification.md`; `docs/phase4/D5-sensor-node.md` §1.0) are closed and tested, no configuration outside the tests carries a `network_sensor` section, no release ships, no caller of `ServeSensor` outside the tests merges, and no caller of `sensorlink.Link.Serve` other than `ServeSensor` (D4-87, D4-88).** After the sensor is built, D6 runs V-M6 over GT-PCAP, and D1 opens item 4's exit gate. Nothing on items 5 or 6 starts before the owner says so (D4-34).

## Open PRs and branches

- **Open PRs:** list them with `gh pr list`. #609, which adds `reference/` and `tools/` to `.gitignore` (D4-80), merged on 2026-11-10 as `cdbf61e8`. A PR that D1 wrote merges on D6's acceptance, and D1 merges it (D4-85). On 2026-11-11 at 15:10Z (D4-84): #615 (D7), #616 (D5) and #617 (D6) are merged. #612, #613 and #614 merged that day too (D4-85). #621 (D4-85) merged as `afc5a802`, and #622 (D4-86) as `1f5b307f`. Later that day (D4-87): #624 (D3's design of the sensor link) merged as `551b03dd`, #618 (D4, the sensor's evidence and ADR-0009's decision for option (b)) as `c9222b35`, and #623 (D6, GT-PCAP's new cases and the engine run's pass conditions) as `96c35ef8`. #620 (D4, the forwarder's rsyslog tests) merged as `8e29891e`, green after the hosted runners recovered; #627 (D4, C13 0.2, proposed) as `624beb58`; and #628 (D5, the node's side of the link) as `d06fdb86`. Later on 2026-11-11 (D4-88): #629 merged as `8ecdecc6`, #619 as `1f7ed8b5`, #625 as `17f746dc`, #626 as `4d0c7154`, #632 as `f771fec9`, #631 as `3176c60f` and #630 as `8f23629d`. #634 merged as `cdd7eebc`, #633 as `f93557b2` and #635 as `8cd5628e` (brief P4-4-L5). On 2026-11-12: #638 (D4-89, the rule on subagents) merged as `8a67c79d`, and #637 (D4's write-up of the counted engine run) as `d6c2a7f6`. #636 (D4-88) merged as `72f09c81` on 2026-11-12. D4-91 (D6's exception to the rule on subagents) is in D1's PR for it, and the approval of P4-4-L6's documents takes the next number. Each role's open items are in its file in `.claude/agents/`.
- **Branches.** The remote had 248 branches when this file was written, and 253 on 2026-11-10 at about 21:45Z (D4-81). The owner approved deleting 150 merged ones (D4-62), with the script `reference/carried/delete-merged-branches-2026-11-06.ps1`, in which each delete is leased to a recorded SHA. Four unmerged mutant branches are kept on purpose: `claude/b6-mut-acl-1`, `claude/b6-mut-acl-2`, `claude/b6-mut-unknown-restart` and `claude/b6-diag-expired-links`. D1 sorted the 102 branches that are not on the script into three groups, in `reference/carried/branch-cleanup-2026-11-10.md` (D4-81): 49 meet the owner's rule, 6 hold a tree that equals a commit on `main`, and 47 are kept. The owner approved the first two groups on 2026-11-11, and both scripts ran that day: 207 branches deleted, 49 left (D4-83). The third group stays.

## Waiting on the owner

**Settled on D1's recommendations (D4-98, 2026-11-13):**
- HR-22 and HR-23 are not accepted. HR-23 must be fixed before item 4's gate; HR-22 stands open at it.
- D3's effort is `high`.
- HR-24's Windows measurement runs on a hosted runner.
- The #640 rows are adopted as the product's recommendation.
- R6.7's list is decided, and needs a C13 change.
- D4-65's items are decided.

What D4-98 leaves with the owner:

1. **The sites' facts:** questions 1 to 5 of `docs/phase4/D1-sensor-host-recommendation.md`, the protocols on each site's networks, which SEL switches the sites run, and the model naming for set authors (`SEL-2731M`). Until questions 1 to 4 are answered, the rows that depend on them are not applied at a site. A row that sets a site's security policy (O-5, O-10) needs the owner's word for that site.
2. **Item 3's other questions:** severity scores in reports (C3 §1.3, R9.2), and the v1 and v2c approval key (HR-17, R1.8). These are the owner's requirements, so D4-98 does not settle them.
3. **The DNP3 Secure Authentication text** (IEEE 1815's SA clause or IEC 62351-5), a licensed copy only the owner can provide (D4-68), and IEEE 1815's transport-layer clause, so that HR-25's sequence rule is read against the standard (D4-112 item 3.4).
4. **HR-18:** who publishes the advisory set and holds its signing key. No real advisory is entered until then.
5. **The release key's holder** (TB9), for O-7's signed image. O-7 was adopted under the delegation, and the owner may reverse it.
6. **Purchases and site changes,** when the time comes: lab TAPs and machines, and a site's outage window or switch change (#640).
7. **The word to start D8's first brief.** D1 recommends that it waits (D4-98).

**Returns to the owner before item 4's gate:**
- HR-24, with stage 3's measurement and its named misses (D1 on #664);
- HR-23, if its measured fix does not close the row (D4-98).

8. **Authorization for any device contact:** a lab relay or switch before any H-test or Q3, and any SNMPv3 contact.
9. **Test runs on the owner's PC** are resumed for ordinary local runs (D4-83, 2026-11-11). Runs that create Windows services stay in the owner's elevated session. Nothing is owed here.
10. **The branch cleanup is done** (D4-83). Nothing is owed here.
11. **ADR-0007** (Windows site node) is still `proposed`.
12. **D7 and D8** (D4-79): D7's first brief is done (#615, D4-84). What is still owed is in items 5 and 7 above.
13. **Nothing: D1 merges its own reviewed PRs** (D4-85, which supersedes D4-82).
14. **Nothing: the owner chose option (b)** (D4-85).
15. **Nothing: D1 decided that mutants are committed as patch files with a dispatch-only workflow,** and no scratch branch is pushed (D4-85). D6's mutants for the closing legs are brief P4-D6-MUT (D4-88, D4-90).
16. **Switching on GitHub's private vulnerability reporting,** which `SECURITY.md` relies on (D4-85). `LICENSE.md` and `SECURITY.md` are added.
17. **Nothing: the owner leaves the fourteen firewall rules** that the approved prompts left for temporary test programs (D4-85).
18. **Finding 1 (D4-112 item 1):** the disclosure steps D1 described to the owner directly (item 1.2), and whether to report finding 1 to the Zeek project (item 1.4), on which its per-row publication waits (item 1.3).
19. **The measured sensor image's offline copies** (D4-114 item 4.2; `docs/release.md` §8.4 item 4): after HR-23's counted run, two copies of the saved image and its source bundle on the owner's offline storage, outside the checkout, before the job's artifact expires.
20. **The stock Zeek reports the fuzz runs find** (D4-116 item 2.4): whether to report privately to the Zeek project the six seen under clang 18's whole `undefined` group in smoke run 44024284021, and any the counted campaign finds on the stock build, as with finding 1 (item 18). No sanitizer line or input was printed or uploaded, but the public harness and a summary's per-target counts show where a report can be found again, so the counted campaign's public summary and step times withhold them until you decide.

## Test policy

1. **GitHub Actions first.** `ci.yml` and `govulncheck.yml` are the gate, with `ci-long.yml`'s twenty `integration-long` legs run on a PR under the `full-ci` label, and D1's merge check in CLAUDE.md (D4-97). The merge rules are in CLAUDE.md, "Testing and merging". When a head's CI is older than `main`, verify the merged result before merging.
2. **The owner's PC second.** It is the second Windows run, and the fallback when GitHub Actions is unavailable or a run needs a real installation. A local run never replaces a green CI run for a merge. Label a PC result with its class (`desk` for Go and Python tests, `simulated` for the real binaries against the simulator), the Windows version and the commit SHA.
3. **Never register the PC as a GitHub self-hosted runner,** and never put machine keys on it. The repository is public, so any outside PR could run code on a self-hosted runner.

Limits on the PC:

- **Run no package in full that holds a listener on an address other than loopback** (`tests/security`, `tests/integration/syslogreceive`). Each run raises a Windows Firewall prompt for the owner, and one test listens on the PC's own LAN address. Run tests by name with `-run`, and never with a pattern that matches `TestD210CollectorRefusesNonLoopback` (`tests/security/collector_lock_test.go`) or `TestDualStackKeysByIPv4` (`tests/integration/syslogreceive/receive_test.go`); GitHub Actions runs the full set (D4-84). D6 owes a change so that those tests bind off loopback only on CI, and fail there if skipped, before the next local run of either package.
- A run that is not elevated skips 162 of `platform/node`'s tests. State the skip count with any result from the PC (D4-84).
- Install nothing beyond what the owner approved: a portable Go inside the project folder, and a Python venv inside it with `pytest` and `asyncssh==2.24.1`. No installer, no admin rights requested, no system settings, no permanent PATH change, no pip install outside the venv.
- A run that creates Windows services happens only in the owner's own elevated session, with the owner present, or on the GitHub-hosted runner.
- Every endpoint is the simulator on loopback. No device, and no site network.

Other rules that hold: re-run a failing job at most once (one exception, for D1 alone: a job that failed in a set-up step before any project code ran, with its failing line quoted on the PR, may be re-run again once the same step has passed in another run in this repository, or 60 minutes after it last failed, at most three times by the clock for one head; each such re-run is recorded on the PR, D4-85; and a job in which project code ran counts as a set-up failure under that exception when all of these hold: a set-up step of that job failed, and its failing line is quoted on the PR; every test that failed in the job failed on its own required-and-missing check for what that step installs, and the message that names the missing thing is quoted on the PR; and nothing else in the job failed: no assertion, timeout, panic, build error or connection error. A test that fails in any other way is a first result and gets the ordinary single re-run, and D6 confirms the three points from the job's log when it reviews the green run (D6 on #629, D4-88)); never push an empty commit to retrigger CI; never call a timeout or a property failure a flake; a failure in code the PR doesn't touch is a finding to reproduce against `main`; before opening a code PR, check the latest scheduled run on `main`.

The toolchain is Go 1.27.3 (`go.mod`), 64-bit. A 32-bit build is not a declared target (D4-72).

## Working in the CLI

- **Start `claude` inside `OTSEC-Proj`.** The agent files are found from the working directory up to the repository root, so a session started in the folder above the checkout loads none of them. Check with `/agents`.
- **The main session acts as D1** and calls D2 to D8 as subagents with a bounded brief (CLAUDE.md section 5.2). `records-auditor` and `ci-triage` are helper agents that own no path. The first checks a documentation PR before its review, and is read-only by instruction: its Bash tool is not restricted. The second reads a failed CI run from files D1 saves for it, and has no tool that can change anything.
- **Independent review means a separate subagent.** D6 reviews in its own subagent, from the requirement and the contract text. Never report a review that one context did of its own work as independent.
- **Only the agents in `.claude/agents/` run, and one instance of each role at a time, except D6** (the owner's rule, D4-89, with D6's exception, D4-91; CLAUDE.md, "Subagents"). `.claude/settings.json` wires `.claude/hooks/agent_guard.py`, which refuses any other agent type and a second instance of a role that is running (other than D6 and the helpers), and it denies the `Workflow` tool. Two tasks for one role, other than D6, run one after the other. The helpers `ci-triage` and `records-auditor`, and D6 since 2026-11-13 (D4-91), are the exception: each may run several instances at once. Each D6 instance has one task: one review or one brief. Two D6 instances never work on the same PR or branch at the same time; a later instance may re-review a later head, or continue a branch, after the earlier one has finished. A D6 instance that writes files works in its own worktree. A D6 instance never reviews work another D6 instance wrote, and D1's brief names who wrote what it reviews. When two D6 instances write at the same time, D1's briefs give out any new F-number, H-row or GT-PCAP case id, so that no two take the same one. No tool enforces these conditions (CLAUDE.md, "Subagents"). The hook's tests run by name, with the venv's Python on the PC: `tools\venv\Scripts\python.exe -m pytest -q .claude/hooks/test_agent_guard.py`.
- **Branches.** One branch and one PR per task, and one `git worktree` per role working at the same time. Stage by explicit path.
- **Lessons from earlier sessions:** stopping a role's agent before relaunching it, checking a quiet agent's branch and PR, and unique scratch names (D4-114 item 6).
- **A cloud session** (claude.ai/code) runs in a Linux container that is reclaimed when it ends. Push everything before a pause, and keep `.claude/worktrees/` in `.git/info/exclude` there too.
- **Working files** go in the repository, or in a scratch folder outside it that no record cites. A file that a record must cite goes in the repository or in `reference/`.
- **GitHub.** A CLI session uses the owner's own credentials and can force-push and delete branches. Never force-push a shared branch, and delete only branches on a list the owner approved.

## The project folder on the owner's PC

```text
OTSEC-Proj/          the only checkout of this repository; start `claude` here
├── reference/       files that records cite; ignored by Git, never committed
└── tools/           portable Go 1.27.3 for 64-bit Windows in `tools/go`, the Go caches, and the Python venv; ignored by Git
```

| In `reference/` | What it holds |
| --- | --- |
| `manuals-SEL/` | The SEL manuals (PDF) and their text in `text/` |
| `datasheets-SEL/` | The SEL datasheets |
| `rfc/` | The twelve RFC texts with `SHA256SUMS` (D4-58) |
| `carried/` | D1's log to #604 (`d1-open-items.md`), D6's queue of GT-PCAP cases (`d6-gt-pcap-next-plan-edits.md`, **live**), the branch-cleanup script, and the evidence files that records cite |
| `pc-logs/` | Logs from earlier runs on the owner's PC, including the 2026-10-27 run that `docs/verification.md` cites |

- **`reference/` and `tools/` are inside the checkout since 2026-11-10 (D4-80), and neither is ever committed.** The repository is public, and `reference/` holds vendor manuals and logs from the owner's PC. `.gitignore` lists both since #609 merged, and `.git/info/exclude` on the PC still lists them too. Stage by explicit path, as always.
- **Never run `git clean -x`, `git clean -X` or `git stash --all` in this checkout.** Each removes or moves ignored files, so each would take both folders, and `reference/carried/` holds files that are in use.
- **Go, `gofmt` and pytest do not read `.gitignore`,** so from the repository root they can walk into the two folders. The first run on 2026-11-11 showed it: `go list ./...` failed on a folder under `reference/` that the user cannot read, until `reference/` and `tools/` each got a one-line `go.mod` (local files, D4-83). Tests that walk the tree met the same folder, and brief P4-PC-1 fixed them (#617, D4-84). Before a run:
  - Check that `go list ./...` names only `otsec.local/otsec` packages. If it names anything under `tools/` or `reference/`, give each of the two folders a one-line `go.mod`, so that Go treats it as another module, and check again.
  - Run `gofmt` on tracked files only, as CI does, and not `gofmt -l .`: `gofmt -l $(git ls-files '*.go' | grep -v '^platform/experiments/')`.
  - Run `python -m pytest -q --ignore=tools --ignore=reference`.
  - CI is not affected, because neither folder is in the repository.
- `tools/go` ran on the PC on 2026-11-11 (Go 1.27.3, `windows/amd64`). Go is not on the PATH: call `tools\go\bin\go.exe`, or set `PATH` for the session only, with `GOCACHE`, `GOPATH` and `APPDATA` pointing into `tools/` and `GOTOOLCHAIN=local`.
- Claude Code keeps each subagent's worktree in `.claude/worktrees/` inside the checkout. `.git/info/exclude` on the PC lists it. Each worktree has the repository's own `go.mod`, so `go list ./...` skips it, and a test that walks the tree does not (P4-PC-1).
- The Python venv is `tools/venv`, created on 2026-11-12 with `pytest` 9.2.0 and `asyncssh` 2.24.1 (D4-89). Call `tools\venv\Scripts\python.exe -m pytest`; the system Python has no `pytest`.
- Eleven test files still carry paths into a shared folder that no longer exists (the eight SEL-751 register goldens, two files under `tests/integration/gt_mib/`, and `contracts/adapter/testdata/snmp/README.md`). The goldens are pinned by checksum, so the owner left them. The paths are citations only, and nothing opens them.

## First session in the CLI

1. In `OTSEC-Proj`, run `git status` and `git log -1`, and compare with `origin/main`.
2. Check the toolchain: `go version` must report 1.27.3 on `windows/amd64`. Use `$(go env GOROOT)/bin/gofmt`.
3. If `tools/venv` is missing, create it with `python -m venv tools/venv` and install `pytest` and `asyncssh==2.24.1` into it. Nothing else is installed.
4. The owner lifted D4-12 on 2026-11-11 (D4-83). Make the `go list` check above, then run `go vet ./...` and `gofmt` in the forms given above for the PC. Run `go test` by package or by name, never `./...`: the limits above keep `tests/security` and `tests/integration/syslogreceive` from running in full here (D4-84). State the skip count with the result.
5. Check the latest `ci` and `govulncheck` runs on `main`.
6. Follow the next action above. The owner answered the ADR-0009 question on 2026-11-10 (D4-78).
