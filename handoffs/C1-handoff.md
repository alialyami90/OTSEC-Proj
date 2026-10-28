# C1 handoff: Principal Architect and team lead

From B1 to C1, 2026-10-28. `main` at `26d8e78` when this was written (checks below ran on `04bb504`; only Markdown merged since). The phase is Phase 4, first exit gate (items 1 and 2). The role is CLAUDE.md §4 "A1": you coordinate, review, integrate and rule. You are not the default implementer. Read [HANDOFF-SUMMARY.md](HANDOFF-SUMMARY.md) first. Its agent map lists your owned paths, which are unchanged from [B1-handoff.md](B1-handoff.md#role--scope).

## 1. Verified state

| Item | State | Evidence class | Source |
| --- | --- | --- | --- |
| Phase 3 accepted, Phase 4 issued | working | desk | D4-1, [phase-3-exit.md](../docs/phase-3-exit.md) |
| First-gate contracts merged: C9 0.2, C10 0.1, C2 0.6, C5 0.4 (now 0.6), C7 0.6, C8 0.5 (now 0.7) | working | CI-Linux, CI-Windows | #331 `6c33f14`, #247, #250, #281, #308, #324; [contracts/README.md](../contracts/README.md) |
| SEL-751 configuration read (`sel.config.read_all`, 24 `SHO` forms, all or nothing) | working in the adapter; not yet wired through the collector | simulated | #331, #338 `04bb504`; D4-23 |
| Collector run wiring (C7 0.7) | partial: draft #341, green | simulated | #341 `61cf141` |
| Signed quarantine clear and seq-reset ack through the relay (relay PR 2a) | working | simulated, CI-Linux, CI-Windows | #339 `ca524be`; D4-24 item 3 |
| Refusing unsigned clear files off-lab (relay PR 2b) | partial: #347 open | simulated | #347 |
| Event baseline learner and detector, V-M4 measures | working in the package | simulated | #303 `c268c0b`, #330 `d5bee69`; [B4-measures.md](../docs/phase4/B4-measures.md) |
| Event-baseline feeder in the node | not built: design #340, slice 1a #343 | desk | D4-26 |
| HR-11 absolute bound (unknown-sender quota, the quarter cap, the fill across an outage) | working; the HR-11 row is still to be closed in B3's doc | simulated, CI-Windows | #291, #296, #316, #317, #321; D4-21 |
| UDP `read_buffer_bytes` with a short-buffer alarm (Linux capped-then-doubled grant) | working | simulated, CI-Linux, CI-Windows | #297 `96fbbae`, #335 |
| Windows CI time budget (`-timeout 20m`, 35-minute job, a 12-minute `platform/node` budget) | working | CI-Windows | #327; D4-22 |
| Any hardware result | none exists | — | No device has been contacted (B-01) |

## 2. Work in flight

The owner paused all agents on 2026-10-28 at 16:39Z for this checkpoint and resumed them at 17:11Z (D4-28), so PRs merge again under D2-13. Reviewers below are given by role number: "roles 2, 5 and 6" means the agents C2, C5 and C6 now (B2, B5 and B6 before). This file writes "agent C5" for an agent and "contract C5" for a contract.

| PR | Branch | Head | CI at checkpoint | Reviewers, and what is left | Your next step |
| --- | --- | --- | --- | --- | --- |
| #337 (yours) | `claude/project-thread-uthkcb` | the branch tip carrying the commit "checkpoint: 2026-10-28 B1 to C1" | Markdown only | role 6 reviews D4-23 to D4-28 and the checkpoint files | Merge on role 6's acceptance (D3-13) |
| #341 C7 0.7 code | `claude/project-thread-ptcxmh-c7-07-code` | `61cf141` | 13/13 green | roles 2, 5 and 6 to accept; it is a draft | On their acceptance and green: merge, then also merge #334 (the design note) |
| #345 C9 0.3 | `claude/project-thread-0e41t5` | `c0a42f7` (adds `C2-handoff.md`, identical to the copy #337 carries) | 13/13 green; on the earlier head `2a72b4c`, `go (windows-latest)` failed in `platform/node` (see section 5) | role 5 confirms the record layout, role 6 reviews | Check that the fit is measured with `store.Record.Bytes` with 64 KiB headroom (D4-25 amendment), then approve |
| #346 C8 0.8 | `claude/project-thread-ptcxmh-c8-08` | `95b91cd` | 11 green, 1 running, `go (windows-latest)` failed in `tests/integration/syslogreceive` (see section 5); draft | roles 4, 5 and 6, against D4-26 item 4 | Approve when all three of D4-26 item 4's rules are in: kind `configuration` refused, a succeeded event acknowledgement names a recorded digest that has not been replaced (with both tests), and `correlation_id` is agreed. The "same commit step" rule is replaced: the baseline is stored first, the record is written after, and a missing record is repaired at start (D4-26 item 4). Also the window rule: the recorded-digest check applies only when the records hold the asset's version-1 recording (D4-26 amendment, B1 on #346) |
| #344 snapshots | `claude/b4-snapshot` | `7dbe6b0` | 13/13 green | role 5 (checkpoint contract) and role 6 (restore tests) | Merge on acceptance; then B4's F1 PR (D4-26 item 4) |
| #343 feeder 1a | `feeder1` | `d59d3b0` | 12 green, 1 running | roles 4 and 6 | Review against D4-26 and #340 |
| #342 | `relay-next` | `e752519` | 13/13 green | role 6, and role 3 for trust | Review: it pins `ConfigRecordBytes` to the cap that #345 derives |
| #347 relay 2b | `relay2b` | `55c8583` | 13/13 green | role 3 (trust), role 6 | Merge on acceptance; this closes relay PR 2 for the gate |
| #340 feeder design | `feeder-design` | `777030c` | Markdown only | role 4 | Merge on role 4's review; the rulings are on the PR |
| #336 D4-21 cases | `claude/b6-d421-cases` | `10d03fb` | 15/15 green (13 jobs plus B6's two Windows full-suite legs) | roles 3 and 4 | Merge on their acceptance |
| #334 C7 0.7 design | `claude/project-thread-ptcxmh-c7-07` | `aa008b5` | Markdown only; draft | merges with #341 | — |
| #181 signed-files design | `claude/project-thread-xni3ff-signedadmin` | `3d9d0f2` | Markdown only | It is the record behind #339 and #347. **STALLED**: open since generation A | Ask agent C5 to update it to the merged design and merge it, or close it as superseded |

## 3. Checkpoint verification (container, on `main` `04bb504`, Go 1.27.3)

- `go vet ./...`: exit 0.
- `$(go env GOROOT)/bin/gofmt -l .`: exit 0, no files listed.
- `go test ./...`: exit 0. 42 packages `ok`, 0 `FAIL`, 2 with no test files. Evidence class: CI-Linux equivalent, run in the container on Linux.
- Windows results come only from GitHub Actions. The `ci` push run on `main` `04bb504` passed 12 of 12 jobs, Windows included (CI-Windows): https://github.com/alialyami90/OTSEC-Proj/actions/runs/40725398231. `govulncheck` runs on pull requests and weekly.
- `python -m pytest -q`: not run. B1 owns no Python tests, and B6's checkpoint covers them.

## 4. Next tasks, in priority order

1. **NEXT ACTION: confirm the cutover.** Write `handoffs/C1-ack.md` as a Markdown-only PR. Then review and squash-merge the C2 to C6 ack PRs. Check each for overlaps or gaps against the summary's agent map, and get every question answered: by the B agent while its thread is open, otherwise from the records, otherwise by asking the owner. Fix each gap in the handoff file itself. Acceptance: six acks on `main` with no open question. Then tell the coordinator that cutover is done, so the B threads can be resolved (the owner chose a C team now, D4-28).
2. **Land the open contract work for the first gate.** Brief: P4-A2, A3, A4, A5. Paths: none of yours except `docs/phase4/` and `contracts/README.md`. Order: #345 (C9 0.3) and #342, then #341 with #334 (C7 0.7), then #346 (C8 0.8), #344, #347, #343 and #340. Acceptance: each has its reviewers' records and green CI on its head. Use the merged-result check (Gotchas) when `main` has moved. Then update the `contracts/README.md` rows for C7 0.7, C8 0.8 and C9 0.3.
3. **Drive the remaining gate pieces.** Role names follow the summary's map.
   - Agent C5: feeder slices 1b and 2 (merge reader, lifecycle, snapshots), then contract C5 0.7 (D4-20 rules 1 and 2).
   - Agent C4: the F1 cap PR, then `Params.Validate`.
   - Agent C3: close the HR-11 row.
   - Agent C2: nothing until H-13 captures exist.

   Acceptance: each item merged as in task 2.
4. **The independent gate runs (agent C6).** V-M2, V-M3 for the SEL-751, and V-M4 on the real binaries, `simulated`. These need #341 and the feeder. The node already schedules configuration reads: see `Collection.ReadsConfiguration` in `platform/node/layout.go`, and confirm with agent C5 that the scheduled read goes end to end once #341 lands. V-S7 must still pass with register revision 5 (B6's `tests/contract/c3_rev5_corpus_b6_test.go`).
5. **Write the Phase 4 first-gate report** in the §9 format, as `docs/phase-4a-exit.md`, against [the gate](../docs/agent-handoffs.md#phase-4-first-exit-gate-items-1-and-2-a1-decides). Check every SHA and count against its source.
6. **Brief item 3** (vulnerability applicability, R9, R1.8) only after the gate passes and the owner accepts it.

## 5. Blockers and risks

- **Owed by the owner:**
  - whether "Phase 4 done" means the first gate or all six items (asked 15:40Z, no answer yet);
  - authorization for a lab relay before any H-test or Q3;
  - the protocols at their sites, before IDS (item 4) is briefed;
  - resuming PC runs (D4-12);
  - deleting the mutant branches `claude/b6-mut-acl-1`, `claude/b6-mut-acl-2`, `claude/b6-mut-unknown-restart` and `claude/b6-diag-expired-links`, and noting #272's orphan push `e87191b`.
- **Open risks that gate a `device-observed` endpoint or listener:** HR-11 (row closure), HR-12, D2-11, D2-16, and the Windows state replace. See [phase-3-exit.md, Open risks](../docs/phase-3-exit.md).
- **Two Windows CI failures in packages the PRs do not change** (read 2026-10-28 about 16:55Z). Treat each as a finding, not a flake, and have its owner reproduce it against `main` before the PR merges:
  - #345 at `2a72b4c`, run 40727005166: `platform/node` `TestSlowCommitReachesStatusAndAlarms` (`commitslow_test.go:31`, "commits {Count:5 MaxMS:5323 ...}, alarms 1"); `platform/node` took 906 s. Agent C5's test: it assumed no commit exceeds 5 s, and one took 5.3 s. The test-only fix is #353 (B5, 17:15Z).
  - #346 at `95b91cd`, run 40728171729: `tests/integration/syslogreceive`, `restart_test.go:700` to `703` (unknown-budget flood during a restart). Agent C6's test, agent C4's code.
- **ADR-0007 is still `proposed`.**
- **Unverified assumptions:**
  - the `SHO` layouts (`documented-untested`);
  - a 300 s Level 1 session being tolerable on a real relay (H-13);
  - every false-positive figure, which is synthetic (V-M4).

## 6. Decisions to know

- D4-1 to D4-28 are in [docs/phase4/B1-decisions.md](../docs/phase4/B1-decisions.md). The ones written today:
  - D4-22: the Windows time budget;
  - D4-23: a run is all or nothing;
  - D4-24: the per-request deadline, and untrusted acceptances;
  - D4-25: the C9 snapshot bound;
  - D4-26: feeder state and `config.baseline_recorded`;
  - D4-27: run limits come from the signed register only;
  - D4-28: the owner's pause, the B-to-C checkpoint, and the resume.
- D4-23 to D4-28 reach `main` when #337 merges. Until then, read them on its branch.
- For older rulings, see D2-1, D2-4, D2-10, D2-13, D3-10 and D3-13 in the earlier decision files, and ADR-0006 and ADR-0008.
- Failed approaches this generation, each recorded where it happened:
  - my first acceptance of #297 missed Linux's doubled grant (#297, D4-22);
  - my "maximal case fits" claim was unmeasured (#338, D4-25);
  - checking `Restored` at apply time instead of at fold time (#339, D4-24).

## 7. Gotchas

- **The container's `gofmt` is older than Go 1.27.3.** `/usr/local/go/bin/gofmt` lists `relptest_test.go` falsely. Use `$(go env GOROOT)/bin/gofmt -l .`, which is what CI uses.
- **Force-push is denied.** After a squash merge, merge `origin/main` (or the remote branch) into your branch. Never reset and push.
- **Merged-result check before merging on stale CI:**

      MB=$(git merge-base origin/main prN)
      comm -12 <(git diff --name-only $MB origin/main|sort) <(git diff --name-only $MB prN|sort)

  Use it with `git merge-tree --write-tree`. If files overlap, the author merges `main` so that CI runs on the combined code.
- **GitHub access.**
  - `gh` REST works for reads (`gh api repos/.../commits/$sha/check-runs?filter=latest`). GraphQL is refused.
  - The GitHub MCP tools disconnect often. Reload them with ToolSearch.
  - Merge with the full `expectedHeadSha`.
- **Thread messages are capped at 40 an hour.** Never send a placeholder message to a resolved thread, because it reopens the thread. Get thread IDs from `list_threads`.
- **A reviewer's acceptance is on a head.** After a push, ask again. Withdraw your own acceptance in a comment when someone breaks a claim.

## 8. Progress since the last checkpoint (B1-handoff.md)

- **The B1-handoff NEXT list is all done:**
  - the handoff PRs were merged (#213, #214 and the rest), and the acks reviewed (#220);
  - the owner accepted Phase 3 and Phase 4 was issued (D4-1);
  - #176, #177 and #182 were merged (`dc27c33`, `7755176`, `c1da531`);
  - Go 1.27.3 was adopted (D4-7);
  - the gate item 1 checks were released to B6 (D4-6), and the admin relay on Windows was done in #266.
- **§7 gaps on done items:** V-M2, V-M3 and V-M4 are not yet run on the real binaries, so items 1 and 2 lack §7 point 4 (integration) and point 10 (independent review of the whole).
- **Regressions:** none on `main`. Retries: #271's Windows full-suite failed on timing and was fixed by count, not re-run (`8526f05`).
- **Repeated work:** relay PR 2 was believed done and was not. `agent-handoffs.md:60` still says "Not started", which was right. Fixed by tracking it in this handoff.
- **Review debt:**
  - #181 has been open since 2026-10-27 (see section 2);
  - #336 has waited about two hours.
- **Scope:** none outside the briefs or B1's paths.
- **STALLED:** #181 (open since generation A; the relay it designs was built in #339 and #347, but the document was never updated). Listed in the summary.

Validated 2026-10-28: fixed. The first reader found placeholder heads, stale decision references, C-name ambiguity, the unrecorded D4-25 headroom, #346's conditions, and the missing pause record. A second reader of the summary named each agent's next action and the order correctly. It found the pause wording left in the role handoffs, #347's FAIL missing from the summary, the merge authority not stated, an uneven pause time, and the orphan push left out. All of these are fixed here or in the summary.
