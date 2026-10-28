# C6 handoff: Independent Verification and OT Safety Engineer

From B6 to C6, 2026-10-28, at `main` 04bb5048. Phase 4 (items 1 and 2, issued 2026-10-27, D4-1); paused by the owner at 16:39 UTC for this checkpoint. Role 6 of `CLAUDE.md` §4 (A6), with the review rules of §5.6. Read `handoffs/HANDOFF-SUMMARY.md` first (B1 is rewriting it as the B-to-C summary in #337; until that merges, read its B-team agent map with C for B, and its standing rules apply unchanged), then this file. After cutover, write `handoffs/C6-ack.md` (your scope, first three actions, questions) as a Markdown-only PR. [B6-handoff.md](B6-handoff.md) still holds the role definition, owned paths and the "never" list unchanged; [B6-ack.md](B6-ack.md) records how B6 read them. Two statements there are superseded: the owner accepted Phase 3 on 2026-10-27 (D4-1), and the owner's PC is paused (D4-12, below). `ci.yml` now has 12 jobs (go on Linux and Windows, python, integration, and 8 integration-long legs), plus `govulncheck.yml`; the "10 jobs" in older files is stale.

## 1. Verified state

Evidence classes: `desk`, `simulated`, `CI-Linux`, `CI-Windows` (GitHub-hosted runner). Nothing is hardware-verified (B-01).

| Item | State | Evidence | Source |
| --- | --- | --- | --- |
| Carried checks (canary scan of command lines and start environment; DMY and YMD reconcile on the real binaries; admin relay and `config\admin` ACLs on Windows; unknown-restart leg on Windows) | working | simulated, CI-Linux, CI-Windows | #242, #261, #270, #263, #266; `.github/workflows/a6-windows-slice.yml` |
| Simulator `SHO` forms and settings change injector, from S22, independent of B2 | working | simulated | #248, #251 (`SHO` matches only `SHO` and `SHOW`) |
| GT-INJ schedules for V-M2 and V-M4, committed before the products' tests | working | desk | #251, #288 (D4-15 absence arming) |
| Contract tests: C9 0.1, C10 0.1, C5 0.4/0.5/0.6, C7 0.6, C8 0.5/0.6, C3 0.3 and D4-16, rev 5 deny corpus | working | desk | #249, #256, #268, #283, #253, #292, #304 (merged cases, including `c3_rev5_corpus_b6_test.go`, `c3_d416_b6_test.go`), #309 (`c8_v06_d418_b6_test.go`) |
| Store holds and commit-WAL rule on the real store | working | simulated | #275, #280, #307 |
| HR-11: the unknown class fills on the real store; outage fill over UDP and TLS on the real binaries | working | simulated, CI-Linux | #316 (F-017), #321 (integration-long leg) |
| D4-21: flood costs at most the unknown quarter (600 known: 0/0; 1200 known: 176 vs 432, diff 256) | partial: PR open | simulated, CI-Linux, CI-Windows | #336 at 10d03fb1, 15/15 jobs green (runs 40710128246, 40710128106, 40710127822) |
| Go 1.27.3 move: Windows UDP stress repeated | working | CI-Windows | #245, `a6-windows-udp-stress.yml`; move merged in #239 |
| Windows store flush stalls (F-016) | tracked, not fixed | CI-Windows | #241, #294, #314; `docs/verification.md` F-016 |
| V-M2, V-M3 (SEL-751) on the real binaries | not started | n/a | Depends on #341 (collector takes a register run) and the node's configuration schedule (B5) |
| V-M4 on the real binaries | not started | n/a | B4's measures are unit tests (#330); the node feeder is #340 (design) and #343 (slice 1a), both open |
| Phase 4 status table in `docs/verification.md` | not started | n/a | Only Phase 2 and Phase 3 tables exist (lines 164, 246) |

## 2. Work in flight

| What | Where | Head | CI | Reviewers | What is left | Exact next step |
| --- | --- | --- | --- | --- | --- | --- |
| #336, D4-21 cases on the real store (B6's own PR) | `claude/b6-d421-cases` | 10d03fb1 | 15/15 green (12 ci.yml jobs, govulncheck, 2 full-suite legs of `a6-windows-restart-marker.yml`); main has since moved past it (now 04bb5048) | B4, B3 (not yet posted) | Reviews, then B1 merges | When reviews come in, merge `origin/main` into the branch (no force push), wait for green, and tell B1. |
| Review of #341, C7 0.7 code (B3) | PR head | was 89fefe42 when reviewed; now 61cf141f | not checked | B6 | Review not posted. At 89fefe42: 12 of 14 mutants killed (A11, the cancel-during-SetDeadline guard, and A14, `ctx.Err()==nil` in the timeout classification, survived; A12 is equivalent). One finding: `SEL751Runner` was not a `Hoster`, so a register run the adapter does not host reached the credential read. The commit title of 61cf141f claims a fix; that is unverified. | Re-fetch the head, re-run the probes and the 14 mutants on it (see section 4), check its CI, then post the verdict. |
| Review of #347, relay PR 2b (B5) | PR head | 55c8583b | not checked | B6 | **Supersede rule broken (lab nodes only):** `TestB6Probe347TickBeforeScan` and `TestB6Probe347StaleWants` fail. `QuarantineTick` reads the wants cached by the last `relayAdmin` scan, and no scan runs during a run (up to 310 s). | Re-fetch the head; if still 55c8583b, post the FAIL with both probes; suggest scanning admin_dir's signed files inside `checkQuarantineClear`. Off-lab refusal does not depend on the wants and holds. |
| Review of #346, C8 0.8 `config.baseline_recorded` (B3) | PR head | was 0ff42d08; now 95b91cd4 | not checked | B6 | Only read so far. B3 asks whether an event-kind acknowledgement stamped 0.8 or later must name a recorded digest. | Re-fetch the head (95b91cd4 or later). Check for a nil `Config` or `Target` dereference in the new `VerifyConfig` case; mutate the succession rule; answer B3 (draft answer in the README, written against 0ff42d08: recheck it). |
| Review of B1's checkpoint consolidation | #337 | 77d758ff before the push | n/a | B6 | B1 pushes the summary there | Review it when B1 says it is pushed. |
| Checkpoint notes and probes (uncommitted test probes, never to be committed) | `/mnt/project-files/b6-wip/` (`README.md`, three `zz_b6probe*` files, `mut341.sh`; `b6-checkpoint/` is the same content) | n/a | n/a | n/a | Use them, then delete them once the reviews are posted | Copy a probe into a worktree of the PR, run it, and remove it before leaving. |

Stale `claude/b6-*` branches: everything in them is on `main` through squash merges (#304, #307 to #309, #316). `b6-mut-*` and `b6-restart-diag*` (#285, #286) are mutant and diagnostic branches that were never meant to merge. Ignore them all.

## 3. Checkpoint verification

The repository-wide commands below ran in the container at `main` 04bb5048 on 2026-10-28, Linux, `simulated` and `desk`:

| Command | Exit | Result |
| --- | --- | --- |
| `go vet ./...` | 0 | clean |
| `gofmt -l .` | 0 | printed nothing |
| `go test ./...` | 0 | 42 packages ok, 2 with no test files, 0 failed |
| `OTSEC_SLICE_REQUIRED=1 python -m pytest -q` (venv: pytest 9.1.1, asyncssh 2.24.1) | still running when this was committed (the long slice legs run in sequence) | So far: 0 failed. 7 errors, which are the 7 `test_rsyslog_leg.py` tests by their position in collection order: this container has no `rsyslogd`, and `OTSEC_SLICE_REQUIRED=1` turns that skip into an error. CI's Linux `integration` job runs that leg. 22 skips so far. The final count goes on the PR. |

Windows evidence comes only from GitHub Actions. The latest Windows runs on B6 code are #336's `go (windows-latest)` (job 122892832726) and the two `full-suite` legs of run 40710128106, all green on 10d03fb1. The suite was not re-run on Windows for this checkpoint.

## 4. Next tasks, in priority order

1. **NEXT ACTION: post the FAIL review on #347 (P4-A6, item 4 of the B6 handoff), then the #341 and #346 reviews.**
   - Paths: none changed. Use PR worktrees (PR head plus current `main`) with the probes from `/mnt/project-files/b6-wip/`; remove each probe and check `git status` before leaving.
   - Depends on: B5 (#347), B3 (#341, #346).
   - Acceptance: each PR gets a PASS or FAIL comment with its mutant count, its probes and survivors explained, and the attribution footer.
   - Tests that prove it:
     - #347: the two probe tests fail at 55c8583b and pass after B5's fix.
     - #341: `TestB6Probe341SEL751RunnerIsAHoster` passes at the new head, and so does the profile-without-the-run probe (refused before the credential, interval untouched). Re-run the mutants at the new head with `mut341.sh` (its line numbers are for 89fefe42; re-locate each line), one at a time, with no failing probe in the package (see Gotchas).
     - #346: a mutant dropping each `VerifyConfig` succession branch is killed.
2. **Land #336 (P4-A6, D4-21).** Get B4's and B3's reviews, merge `main` in and get CI green. Acceptance: merged with all ci.yml and govulncheck jobs green on its head.
3. **D4-20 cases (P4-A6, D4-20)** in `tests/contract/` and `tests/integration/storeholds/`, once B5's C5 0.7 code lands. All eight cases D4-20 assigns B6: a flapping device filling the class with nothing held dropped; an approved change held; the newest read kept and older ones removed; the acknowledgement race failing closed; a persistent unapproved change holding one snapshot and difference; a crash between a snapshot and its `config.change_detected`; fault injection at the removal commit; and the cross-version case. Acceptance: each fails on a mutant and passes on B5's code.
4. **V-M2 and V-M3 on the real binaries (P4-A6; Phase 4 first exit gate).**
   - Where: a new slice test under `tests/integration/slice/`, driven by GT-INJ change series (#251) on the simulator's `SHO` forms (#248).
   - Depends on: #341 merged, and B5's node configuration schedule.
   - Acceptance: the V-M2 row of `docs/verification.md` (every series kind, including an approval numbered above the detection), and V-M3's rung check. Each check must fail on a mutant.
5. **V-M4 on the real binaries (P4-A6).** Depends on B5's feeder (#340, #343) and B4's #344. Acceptance: the V-M4 row and "R4.8 observation period and measures". A redelivered `possible-duplicate` event must not trip Repeats unless C10 says so.
6. **C2 0.6 contract tests** in `tests/contract/` (exit gate: C2 0.6 merged "with A6's contract tests"; #331 was checked by probes only). Acceptance: B6's own cases for the `config.read_all` run shapes (ok with one record per step, or not ok with none) and `failed.config_unparsable`, each killing a mutant.
7. **Phase 4 status table** in `docs/verification.md`, like the Phase 3 table. Each row needs an evidence class and a source.
8. **Small items:**
   - `a6-windows-restart-marker.yml` line 42 still says "ci.yml's 12m" (D4-22 made it 20m; fix it the next time the file is touched);
   - an assert in `test_slice_unknown_restart_e2e.py` that `_rows(s) == AHEAD`;
   - the #310 retention follow-up (a flapping device filling the class) under D4-20;
   - re-check the unknown-stream count after #296;
   - V-S7 still passing with register revision 5's lines (exit gate). Check the latest `integration` job.

## 5. Blockers and risks touching this role

- B-01: no hardware, so nothing may be called supported (`docs/verification.md`, "Safety and security blockers").
- D4-12: the owner's PC is paused. GitHub Actions is the only test path. Never register the PC as a runner. D4-12 says the owner planned to resume PC runs on 2026-10-28; no record says they did, so treat the PC as paused until B1 (or C1) says otherwise.
- HR-11, open before the first `device-observed` listener: [threat-model.md](../docs/threat-model.md), with D4-21's criterion (#336 pending).
- HR-13 (D4-11, D4-17) and HR-14 (baseline acknowledgement) in the threat model.
- D2-11, D2-12, D2-16: gates before any `device-observed` endpoint (`docs/phase-3-exit.md`, "Open risks").
- F-016: hosted-Windows `FlushFileBuffers` stalls up to 37.9 s. They make Windows timing fragile (D4-5, D4-10, D4-22).
- Open on B5's side: `TestKeyRegisterForwardsAndRecords` failed 1 time in 18 on Windows during the #314 traces (not classified).
- Carried and not run (from B6-handoff, unchanged): V-S7 soak (c) and (d), V-S6 cut mid-SER read, V-S9 file-system exhaustion, V-S15 hostile framing, V-S18, V-S20.
- Unverified assumptions: the `SHO G` layout (S22 prints none). Agreement between the simulator and the adapter is not hardware evidence.

## 6. Decisions to know

Links only: [B1-decisions.md](../docs/phase4/B1-decisions.md). The ones that bind role 6 most:
- D4-5, D4-10 and D4-22: Windows timing;
- D4-6: carried checks;
- D4-12: the PC is paused;
- D4-13: rev 5 and C3 0.3;
- D4-14: C5 0.5;
- D4-15: GT-INJ absence arming;
- D4-18 and D4-19: acknowledgement and holds;
- D4-20: retention;
- D4-21: unknown quarter;
- D4-23, if #337 merges: a configuration run is all or nothing.

ADRs are in [docs/decisions/](../docs/decisions/); ADR-0008 sets the monitoring goals.

Failed approaches this generation:
- A timed flood (`floodFor` 400 ms) sent only 56 datagrams on hosted Windows. Flood by count instead (#271).
- Counting UDP loss on the wire, not at the receiver, gave false losses on Windows (#267).
- Bounding the flood test's liveness by the store's commit failed on F-016 stalls. Bound it by the listener's read (#315).
- Fixed-time waits for the restart marker failed. Wait on the receiver's accounting (#255).

## 7. Gotchas that cost time

- Mutant scripts: never let a probe that fails on purpose sit in a package while mutants run, or every mutant reads as killed (`mut341.sh`'s `-run` pattern includes `Hoster`, which matches the #341 probe). A script stopped mid-run leaves the mutant in the file. Run `git checkout -- <file>` and `git status` afterwards.
- `go test -run` with a broad pattern in `modules/security/collector` takes more than 80 s per mutant. Run mutant batches in the background.
- The GitHub MCP tools disconnect at times. Reload them with ToolSearch (`select:mcp__github__pull_request_read,...`).
- Fetch PR heads with `git fetch origin pull/N/head`. A branch already checked out in a worktree cannot be force-updated.
- Merging `main` into a long-lived branch: conflicts on files that main already squash-merged are resolved by taking main's side. No force push.
- Hosted Windows is slow and noisy: the full suite takes about 25 minutes per leg. Check that the head SHA is the one reviewed before citing a run.
- B6's earlier gotchas still hold (B6-handoff, "Gotchas").

## 8. Progress since the last checkpoint (against B6-handoff "Next steps")

- Step 1 (ack): done, `handoffs/B6-ack.md`.
- Step 2, the carried checks: all four are done and merged (#242 and #261 canary; #263 and #266 Windows slice and ACLs; #270 DMY and YMD). §7 gaps: no independent review record is linked here; the review records are on the PRs.
- Step 3, Phase 4 items: done for the simulator `SHO` forms (#248), GT-INJ (#251, #288), and the contract tests for C9, C10, C5 0.4, C7 0.6 and C8 0.5. Not covered: a separate C2 0.6 contract-test PR. C2 0.6 was checked by probes in the #331 review only. **Not started:** the V-M2, V-M3 and V-M4 acceptance tests on the real binaries.
- Step 4 (review every Phase 4 PR): done continuously; each verdict, with its mutant count, is a comment on its PR. The Phase status table was not kept, which is task 6 above.
- Step 5 (Go 1.27.3): done (#239, #245).
- Regressions: none at this checkpoint. #271 needed a fix after a Windows failure (timed flood), not a retry. The `TestKeyRegisterForwardsAndRecords` Windows failure (1 in 18) is still unclassified (B5).
- Repeated work: none found.
- Review debt: #341 (asked 2026-10-28), #346 and #347 are under a day old. #336 has had no review for about 2 hours.
- Scope: all B6 commits stay in owned paths. Probes and mutants in product code were never committed.
- Nothing has been untouched for two generations, so nothing is STALLED.

Validated 2026-10-28 by a fresh read-only subagent: it chose #347's FAIL review as the next action. Fixed after it: the job count, superseded B6 statements, the PC status after D4-12, the summary and ack for the C team, stale review heads, the probe's name, `mut341.sh`'s restore, all eight D4-20 cases, and the missing C2 0.6 contract-test task.
