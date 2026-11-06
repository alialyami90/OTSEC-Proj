# D1 handoff: Principal Architect and team lead

From C1 to D1, 2026-11-06. `main` at `a69c416` (#479), with the checks below run on `961221b` (#475); only Markdown merged since. The phase is Phase 4, item 3 (vulnerability applicability with the asset module, R9 and R1.8). The role is CLAUDE.md §4 "A1": you coordinate, review, integrate and rule. You are not the default implementer. Read [HANDOFF-SUMMARY.md](HANDOFF-SUMMARY.md) first. Its [agent map](HANDOFF-SUMMARY.md#agent-map) lists your owned paths, which are unchanged from [C1-handoff.md](C1-handoff.md).

## 1. Verified state

| Item | State | Evidence class | Source |
| --- | --- | --- | --- |
| Phase 4 items 1 and 2 (configuration baselines, event-behaviour baseline) | accepted by the owner | simulated, CI-Linux, CI-Windows | D4-48; [phase-4a-exit.md](../docs/phase-4a-exit.md) |
| Item 3 contracts: C1 0.3, C2 0.8, C3 0.4, C5 0.8, C7 0.8, C8 0.11, C11 0.1, C12 0.1 | working; C6's contract tests for all eight | CI-Linux, CI-Windows | D4-53; #445, #446, #450, #453, #475 |
| V-M7 (R9 over GT-ADV, 128 cells, on the binaries) | working | simulated, CI-Linux | #467, #469; [verification.md, item 3 gate](../docs/verification.md#phase-4-item-3-exit-gate-status-c6-2026-11-06) |
| V-M8 (set refusals 18 of 18; paired runs 12 of 12, no probe) | working | simulated, CI-Linux | #470, #474, #480 (open) |
| V-S7 (egress corpus, SEL path, `check.py` over the V-M7 and V-M8 recordings) | working | desk, simulated | #449, #475 |
| F-025 (an audit citation read as passive evidence) | fixed | desk, CI-Linux, CI-Windows | D4-57; #476 `8b04003`, #477 `06effb5`, #478 |
| V-M1 (SNMPv3 over GT-MIB for the SEL-2731/2741) | not run; C6 is building GT-MIB's agent from the RFC texts | desk only so far | owner's choice 2026-11-06; `/mnt/project-files/rfc/` |
| Item 3 exit report | written; gate not yet decided | desk | [phase-4-item3-exit.md](../docs/phase-4-item3-exit.md), #479 `a69c416` |
| Windows node start sometimes over 12 s | open, cause unknown; tests survive it | CI-Windows | #471; exit report "Failed or incomplete" |
| Any hardware result | none exists | — | No device has been contacted (B-01) |

Step 1 commands, on `main` `961221b`, in the container (Linux, Go 1.27.3):

- `go vet ./...`: exit 0.
- `$(go env GOROOT)/bin/gofmt -l .`: exit 0, no files. The container's `/usr/local/go/bin/gofmt` still lists `relptest_test.go` falsely (gotcha below).
- `go test ./...`: exit 0. 52 packages `ok`, 3 with no test files, 0 `FAIL`. Evidence class: desk (Linux).
- `python -m pytest -q`: PYTEST_RESULT. The first run failed to collect 6 files because `asyncssh` was missing in the container. It was installed at 2.24.1, as CLAUDE.md says, and the run repeated.
- CI on `main` `961221b`: `ci` push run, 18 of 18 jobs green, Windows included (CI-Windows): https://github.com/alialyami90/OTSEC-Proj/actions/runs/42174011840. `govulncheck` last passed on #480's head `523ccce`: https://github.com/alialyami90/OTSEC-Proj/actions/runs/42212637436.
- `git status --short`: clean. `git stash list`: empty. Branch `claude/project-thread-jrno1y` holds only this checkpoint.

## 2. Work in flight

| PR or work | Branch | Head | CI | Reviewers, and what is left | Your next step |
| --- | --- | --- | --- | --- | --- |
| #480 (role 6): the D4-57 pair in c12_c6, `in_use_since` on the binaries, the gate table at `961221b` | `claude/project-thread-zypwj7` | `523ccce` | govulncheck green; `ci.yml` read again before merging | role 1 accepted (C1 comment on #480); role 4 for the C12 cases is optional | Merge when every job is green on its head |
| V-M1 (role 6) | role 6's branch | not yet a PR | — | role 2 for the SNMP reading, role 3 for security | Review the GT-MIB PR when it is up, then decide the gate |
| This checkpoint (role 1) | `claude/project-thread-jrno1y` | the branch tip | Markdown only | role 6 reviews | Merge on role 6's acceptance |
| The C2 to C6 checkpoint PRs | each role's branch | see the summary | Markdown only | role 1 | Merged before the summary was written |

## 3. Next tasks, in priority order

1. **NEXT ACTION: confirm the cutover.** Write `handoffs/D1-ack.md` as a Markdown-only PR. Then review and squash-merge the D2 to D6 ack PRs. Answer each question from the records, or ask the C agent while its thread is open, or ask the owner. Fix each gap in the handoff file itself. Acceptance: six acks on `main` with no open question. Then tell the coordinator that cutover is done.
2. **Close V-M1 and decide the item 3 gate.** Brief P4-3-C6 (V-M1), against [the item 3 gate](../docs/agent-handoffs.md#phase-4-item-3-exit-gate-c1-decides).
   - Role 6 builds GT-MIB's agent from `/mnt/project-files/rfc/` (RFC 3411, 3412, 3414, 3416, 3418, 3826, 6933 and 7860; `SHA256SUMS` beside them), checks the case table and the egress corpus against the texts, and runs V-M1 (a) to (c), (e) and (f), with (d) for the refusal alone.
   - Roles 2 and 3 review. A layout error the texts reveal is fixed in its owner's code (role 2 for `modules/ied/snmpv3`, role 3 for `snmpegress`).
   - Acceptance: V-M1 passes on `main` in CI. Then update `docs/phase-4-item3-exit.md` (status, the V-M1 rows, the gate decision) and put the acceptance to the owner on a decision card. Work stops for the owner's check (D4-34).
3. **After the owner accepts item 3: brief item 4 (IDS)**, only once the owner names the sites' protocols (D4-33). The next items follow [the Phase 4 briefs](../docs/agent-handoffs.md#phase-4-task-briefs-issued-2026-10-27) in order.
4. **Carry the item 3 limitations into the next contract round:** C12 0.2 (cite a mismatch on an operator identity, D4-55) and C1 0.4 (the SNMP profile's placeholders; the SEL-2731/2741 profile from measurement after H-17).

## 4. Blockers and risks

- **Owed by the owner** (also in the exit report, "Owner decisions needed"):
  - HR-18: who publishes the advisory set and holds its key (no real advisory until then);
  - severity scores in reports;
  - the v1/v2c approval key, if a v1/v2c path is ever added (HR-17);
  - which SEL switches the sites run;
  - model naming for set authors (`SEL-2731M`);
  - authorization for a lab device before any H-test or Q3;
  - the sites' protocols, before item 4;
  - resuming PC runs (D4-12);
  - deleting `claude/b6-mut-acl-1`, `claude/b6-mut-acl-2`, `claude/b6-mut-unknown-restart` and `claude/b6-diag-expired-links` (still present on 2026-11-06). **STALLED**: owed since generation B.
- **Open risks:** HR-16, HR-17 and HR-18 (SNMP and advisory keys), AP-28 and AP-29, and the carried HR-11, HR-12, D2-11 and D2-16. See the exit report's "Open risks".
- **ADR-0007 (Windows site node) is still `proposed`.** **STALLED**: unchanged since generation A.
- **Unverified assumptions:** the SEL-2731/2741's SNMPv3 behaviour (S29, `documented-untested`); the real FIDs and each real advisory's conditions (H-01); the SNMP wire layout until V-M1 runs against the RFC texts.

## 5. Decisions and lessons

- **Decisions.** D4-29 to D4-57 are in [docs/phase4/B1-decisions.md](../docs/phase4/B1-decisions.md). The ones that matter most now:
  - D4-48: the owner accepts items 1 and 2 and issues item 3;
  - D4-49 and D4-50: SNMP only in the collector, and applicability never probes;
  - D4-53: the item 3 contracts approved together;
  - D4-54 and D4-55: the rulings made while item 3 was built;
  - D4-56: network controls;
  - D4-57: F-025;
  - D4-58: this checkpoint and the owner's message routing rule.
- **Failed approaches this generation,** each recorded where it happened:
  - the "same commit step" rule for `config.baseline_recorded` (D4-26, replaced);
  - three rulings needed corrections (D4-41, D4-45 and D4-46; see phase-4a-exit.md, Lessons);
  - the first item 3 ceiling ended its crossing at the wrong moment (D4-54, corrected by D4-55);
  - "family token" `sel-27x1` as a product family (D4-54).
- **Gotchas that cost time:**
  - **The container's `gofmt` is older than Go 1.27.3.** Use `$(go env GOROOT)/bin/gofmt -l .`.
  - **pytest needs `asyncssh==2.24.1`,** which a fresh container may lack.
  - **Merged-result check before merging on stale CI:** `git merge-tree --write-tree origin/main prN`. Then extract the tree with `git archive` and run `go vet` and the affected tests.
  - **A reviewer's verdict names a head.** A later "merge main, no content change" commit keeps it. Check with `git diff --stat <reviewed> <head>`.
  - **Agent messages now go through the coordinator** (owner, 2026-11-06, D4-58). Direct thread messages are capped at 120 in 24 hours.
  - **GitHub:** `gh api` REST works; the MCP tools disconnect often. Merge with the full head SHA.
  - **Never `git checkout` in the main checkout to inspect a PR.** Use `git worktree add` under the scratchpad, or `git merge-tree` and `git archive`.

## 6. Progress since C1-handoff.md

- **The C1 NEXT list is all done:**
  1. Cutover: done (D4-31).
  2. The first-gate contracts landed: C9 0.3 and 0.4, C7 0.7, C8 0.8 to 0.10, C5 0.7, C10 0.2.
  3. The gate pieces were built.
  4. V-M2, V-M3 and V-M4 passed on the binaries.
  5. `phase-4a-exit.md` was written, and the owner accepted it (D4-48).
  6. Item 3 was briefed (#443) and built. Everything is merged except V-M1's run.
- **§7 gaps on done items:** item 3 lacks V-M1, so the SNMP path lacks §7 point 4 (integration against an agent) and point 8 (evidence of correct operation).
- **Regressions:** none on `main`.
- **Retries:** #466's Windows job was not re-run. The cause was found and fixed in #471.
- **Review debt over a day:** none.
- **Out of scope:** none.
- **Records fixed:**
  - #181 was closed unmerged on 2026-10-28 (no longer STALLED);
  - the V-M1 brief is in `/mnt/project-files/c1/vm1-unblocked.md`.
- **STALLED:** the owner's leftover branches, and ADR-0007 (above).

Validated: VALIDATION_RESULT
