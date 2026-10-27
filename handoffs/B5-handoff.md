# B5 handoff: Platform and Distributed Systems Engineer

From A5, 2026-10-27, at `main` `d4afc63`. Read `handoffs/HANDOFF-SUMMARY.md` first, then this file. The project brief is `CLAUDE.md` (A5's role is in §4, and the rules in §5 apply to every task). This file links to the docs instead of repeating them.

**Phase state.** Phase 3 passed its gate with conditions, but the owner has **not accepted it** ([docs/phase-3-exit.md](../docs/phase-3-exit.md)). **Phase 4 is held** until the owner accepts. The Phase 4 briefs are drafts and are not yet issued. A-team work is frozen for this handoff. Start nothing new until B1 says so.

## Role & scope

**B5 owns:**
- `platform/` (`node/`, `store/` and `store/protect/`, `winsvc/`; `experiments/` is the old Phase 0 module and is not built), `deploy/` and `ui/` ([README.md](../README.md), "Layout and ownership").
- `cmd/otsec`, the node binary and its CLI (`otsec health`, `otsec quarantine export`). A5 has maintained it since Phase 2.
- **C5** (`contracts/store/`), as its proposer. Every change needs A1's (now B1's) approval and a review by each consumer.
- Phase and handoff docs under `docs/phaseN/A5-*.md`, and `platform/node/README.md`.

**B5 does not touch:**
- `modules/` (A2, A3 and A4) or `cmd/otsec-collector` (A3).
- `tests/integration/`, `tests/security/`, `tests/safety/` and `docs/verification.md` (A6). Exception: the slice harness files A5 changed for service mode at A6's request (#179). Any further change there needs A6's agreement.
- Any other `contracts/` package.
- `docs/` outside A5's files (A1).

**UI.** `ui/` is empty. Any UI work goes through the `impeccable` skill, as `CLAUDE.md` says. Nothing in Phase 4's first items needs a UI.

**Review duties.** A6 reviews A5's work for reliability and A3 for trust boundaries (`CLAUDE.md` §5.6). A5 has reviewed A2's result size and storage, A4's listener wiring, and A6's slice checks.

## Current state

**Done and on `main`.** Everything in [docs/phase3/A5-handoff.md](../docs/phase3/A5-handoff.md) "Completed", plus two later PRs:
- #204, that handoff itself;
- #207, which fixed `TestRunRelaysBetweenRuns` on Windows; A6 and A3 passed it.

Gate item 1 (the slice against the installed services on the owner's PC, which #179's service mode runs) passed on 2026-10-27 with conditions (#208).

**Open A5 PRs.** Each is paused and fully committed. CI was green on every head, 7 of 7 jobs, against the base it was opened on. Every review so far is a comment; nobody has approved. B5 inherits all four.

| PR | Branch @ head | State | Review still needed |
| --- | --- | --- | --- |
| #176: the node resolves TLS references from the node key register (closes D2-12) | `claude/project-thread-xni3ff-nodekey` @ `af1bc8c` | 36 commits behind main and **conflicts** in `platform/node/status.go`. Needs a merge of main, then a fresh CI run. | A3 (trust boundary) and A6 (independent). Neither has reviewed. |
| #177: store crash children bounded, with their output kept | `claude/project-thread-xni3ff-crashchild` @ `6d7e468` | Merges with main cleanly. Changes test code only. | A6 and A3. Neither has reviewed. |
| #181: design for signed administrator files and the relay (docs only) | `claude/project-thread-xni3ff-signedadmin` @ `0e33a43` | Merges cleanly. PR 1 of this design was built as #189 (merged). | A3 re-review of blockers B1 and B2 (folded in at `21f56ab`). A6 review of the tests. See "Open questions" for A3's four "should fix" items. |
| #182: the refused-identity reason in `noDecisionDetail`; `ReceivedRecordBound` | `claude/project-thread-xni3ff-nodefix` @ `f82d347` | 34 behind main and **conflicts** in `platform/node/listenlimits_test.go`. | A3 has no objection to the first half. A6 has not reviewed the record-bound half (A6 measured it on #174). |

**Not started.**
- Relay PR 2 of #181: signed `clear-suspension`, `clear-quarantine` and `seq-reset-ack`; `node.quarantine_clear` and `node.seq_reset_ack`; A3's C8 0.4 fields; and the N items listed in the carry-over brief.
- P4-A5 and C5 0.4.
- `runtime.Version()` in `otsec health`.

**Blocked.** Phase 4 waits on the owner's acceptance of Phase 3. Nothing A5 owns is blocked on another agent today.

**Leftover branches**, not for merge, kept as evidence cited in PRs. Do not delete them without B1's say:
- `claude/project-thread-xni3ff-svcdry` and `-svcdry2` to `-svcdry8` (service-mode dry runs; svcdry8 also holds `tests/dryrun/readlive_check.py`, the rename race check);
- `-relaytickdry` and `-relaystartdry` (Windows timing runs for #202 and #207).

## Next steps

1. **First action:** read `handoffs/HANDOFF-SUMMARY.md`, this file, and the key files below. Then write `handoffs/B5-ack.md`. Do no code work until B1 lifts the freeze.
2. **Go 1.27.3: the first hygiene item.** B1 owns the move, with B3 and B6 reviewing, as its own PR under D3-10 ([agent-handoffs.md, "Carry-over and hygiene"](../docs/agent-handoffs.md#carry-over-and-hygiene-beside-items-1-and-2)). B5's part is to check the platform on that PR:
   - `go test ./platform/... ./cmd/otsec`, including the store crash tests;
   - the Windows job's `platform/node` and `platform/store` times.
   
   Do not rebase the carry-over PRs onto 1.27 before that PR merges.
3. **Bring #176 and #182 up to main.** Merge main into each branch; do not rebase, because force-push is blocked. Resolve the conflicts, run the checks in "Gotchas", push, and ask for the reviews in the table. #177 needs only its reviews.
4. **#181.** Update the design doc to record what #189 already implemented of A3's "should fix" items (see "Open questions"). Get A3's re-review and A6's review, then build relay PR 2 from it.
5. **When the owner accepts Phase 3 and B1 issues the briefs:** take [Task P4-A5](../docs/agent-handoffs.md#task-p4-a5-configuration-baselines-in-the-node-r32-r34-r36). Draft C5 0.4 as **one minor** carrying three changes:
   - the configuration stream class, with a per-snapshot byte cap well below the 1 MiB recovery reserve;
   - HR-11's unknown-sender class and quota (A4 reviews);
   - the faster unknown count, which must keep #196's rule (charge at read, count by received time).
   
   Follow the Phase 4 "Order" list: C9, C10, C7 0.6 and C8 0.5 are approved first. Then build the schedule, the baseline handling and `node.baseline_ack`, and relay `node.change_approval` and `node.baseline_ack` through the #189 relay.
6. **`runtime.Version()` in `otsec health`** (carry-over).
7. **Support B6** on the Windows checks gate item 1 still owes: the admin relay end to end and `admin_dir`'s ACLs, the unknown-restart leg, and a canary scan of process command lines. These are B6's deliverables (P4-A6), on the hosted runner. B5 helps where the harness needs platform changes.

## Key files

| Path | Why |
| --- | --- |
| [docs/phase3/A5-handoff.md](../docs/phase3/A5-handoff.md) | What A5 built in Phase 3, the evidence for it (run IDs), its limitations and risks. |
| [docs/phase-3-exit.md](../docs/phase-3-exit.md) | Gate state, the conditions, the open risks (HR-11, D2-12, the Windows state replace), and the lessons. |
| [docs/agent-handoffs.md](../docs/agent-handoffs.md), "Phase 4 task briefs" | P4-A5, the carry-over list and the Phase 4 order. A5's review points on #209 are already folded in. |
| [docs/phase3/A1-decisions.md](../docs/phase3/A1-decisions.md), [docs/phase2/A1-decisions.md](../docs/phase2/A1-decisions.md) | D2-* and D3-* rulings that A5's code follows, notably D2-11, D2-12, D2-13, D2-15, D3-1, D3-3, D3-8 and D3-10. |
| [docs/decisions/ADR-0004](../docs/decisions/ADR-0004-local-persistence-and-delivery.md), [ADR-0007](../docs/decisions/ADR-0007-windows-site-node.md), [ADR-0008](../docs/decisions/ADR-0008-monitoring-goals-and-collection-method-order.md) | Persistence and delivery, the Windows site node, and the monitoring goals. |
| [platform/node/README.md](../platform/node/README.md) | Node configuration fields, status, alarms, `admin_dir` files and the deploy order. Keep it in step with the code. |
| [docs/phase1/A5-store-semantics.md](../docs/phase1/A5-store-semantics.md), `contracts/store/` | C5's rules: commit groups, the audit-before-act receipt (`AuditBeforeAct`), modes, quotas and the recovery reserve. |
| `platform/node/schedule.go` (`Scheduler.Run`, `plan`, `RunOnce`) | The scheduling loop. The per-asset quiet interval is the `lastEnd` map in `plan`. |
| `platform/node/adminrelay.go` (`relayAdmin`, `readAdminFile`, `relayOne`, `RelayTimeout`, `relayKinds`) | The relay that P4-A5 and relay PR 2 widen. |
| `platform/node/seqreset.go` (`collectorHold`, `collectorHoldReason`) | Install-key and reset gating. It runs before every collector request. |
| `platform/node/unknownspent.go`, `listening.go`, `listenlimits.go` | The unknown-budget count at start (#198) and listener sizing (#169). |
| `platform/node/quarantine.go`, `assetclear.go`, `suspend.go` | The quarantine export and clear, and suspensions. |
| `platform/store/` (`db.go`, `commit.go`, `discard.go`, `protect/`) | SQLite (modernc) store, `Discarder`, and the protected-file rule. |
| `platform/winsvc/` | Installer and service layout; read it before any change to `%ProgramData%\OTSEC`. |
| `tests/integration/slice/slicerun.py` | The slice harness. Its service mode (`OTSEC_SLICE_SERVICE=1`) is A5's work in A6's directory. |
| [docs/phase3/A5-quarantine-export.md](../docs/phase3/A5-quarantine-export.md), [docs/phase2/A5-p3-failed-open-retry.md](../docs/phase2/A5-p3-failed-open-retry.md) | Agreed designs that the code implements. |

## Decisions made

These were settled with evidence; don't reopen them without new evidence.
- **The node verifies nothing in an admin request.** It carries the signed envelope unchanged, and the collector verifies and numbers each decision (C7 0.5, #181 and #189). The decided set is folded from the audit stream, so a file is sent once across restarts and a lost checkpoint.
- **At most one stall per tick.** Each relayed request has a `RelayTimeout` deadline, and after the first request with no answer the rest wait for the next tick (A3 on #197).
- **The first relay runs at `Run` start, not on a tick.** It commits `install_key` and the request's info record before it sends.
- **Every C5 change is one minor**, with a reader for the previous minor and A6's contract tests before merge. C5 0.4 carries all three stream-class changes (A1 accepted this on #209).
- **A baseline is acknowledged only by a signed `node.baseline_ack`**, never an unsigned `admin_dir` file. Approvals reach the collector only through the #189 relay (A1, on #209).
- **The unknown budget across restarts** is counted from the stream by received time inside the trailing window. If it cannot be counted, the budget starts empty with `syslog-unknown-budget-uncounted` (fail closed, #198).
- **Tests check properties, not fixed wall-clock times.** Fixed waits fail on loaded Windows runners (#202, #207, and A6's syslogreceive fixes).
- **The harness reads a running collector's `state.json` with `read_live`.** It shares delete and retries a refused open for up to 5 s (#179).
- **Windows state replace.** The product fix belongs to A3 (now B3) in Phase 4: `FileRenameInfoEx` with POSIX semantics, plus a bounded retry, keeping fail-closed as the fallback. B5 does not change `renameDurable`.
- **Go is at least 1.26.10** (D3-10, golang/go#78041). Toolchain bumps get their own PR, reviewed by A3 and A6.

## Open questions / risks

- **Phase 3 acceptance** belongs to the owner, and nothing in Phase 4 moves until then.
- **#181: A3's four "should fix" items.** These are: act on the bytes sent; take the kind from the payload; match the reply to the request; show an expired request as its own state. They are not written into the doc text. Two are already in #189's code:
  - `readAdminFile` refuses "signed kind is not the file's kind";
  - `collectorclient` refuses a reply whose `request_id` differs.
  
  Still to check or add, in relay PR 2:
  - "expired, re-sign" as a health state;
  - acting only from the payload decoded from the sent bytes;
  - a check that `collector_seq` rises.
- **D2-12 stays open until #176 merges.** The node's TLS key is still a file behind the lab flag. This must close before any `device-observed` endpoint.
- **HR-11 is open.** A forward clock step followed by a restart refills the unknown budget. The absolute bound is in C5 0.4, and it gates the first `device-observed` listener.
- **Windows state replace.** Any reader of `state.json` can stop collection until a restart. Race-check numbers are in `docs/phase3/A5-handoff.md` "Risks". This is a condition before the first site deployment.
- **No end-to-end Windows check** of the admin relay or of `admin_dir`'s ACLs. Only contract and unit tests run on Windows.
- **The unknown-budget start count** scans the whole window; its cost at quota is not measured.
- **The #172 hang.** It is not explained; #177 makes the next one diagnosable rather than fixing a cause.
- **Unsigned files.** `clear-suspension.json` and `clear-quarantine.json` remain unsigned until relay PR 2.

## Dependencies

- **B1** approves C5 changes, merges every PR (B5 never merges or approves), and issues Phase 4.
- **B2** gives C9 and C2 0.6 (`config.read`, snapshot size) for P4-A5. B5 reviews B2's result size and storage.
- **B3** gives C7 0.6 (`node.change_approval`, `node.baseline_ack`) and C8 0.5, reviews the trust boundary on every B5 PR, and owns the `replaceFile` POSIX-rename fix.
- **B4** drafts C10 alongside C9. B4's learner follows C5 0.4. B4 reviews the unknown-sender class and the faster count.
- **B6** reviews every B5 PR independently, owns the slice harness and `docs/verification.md`, and runs the owed Windows checks.

## Gotchas

**The repository and git**
- **The repo is public.** No secrets, real device data or internal hostnames go in commits, PRs or comments. Use test credentials only. No model names in commits or PRs.
- **Force-push is blocked.** Never rebase a pushed branch; merge main into it. If a branch must be rebuilt, push a new branch name.
- **Stage before you commit.** After `git revert --no-commit`, edits must be staged (`git add`) before the commit. A5 once committed only the revert and left the fix unstaged (`d146af7`, then repaired in `40e15b7`).

**Testing and CI**
- **Checks before every push:**
  - `gofmt -l .` (must print nothing);
  - `go vet ./...` and `GOOS=windows go vet ./...`;
  - `go test ./platform/... ./cmd/otsec`;
  - for slice changes, `python -m pytest -q tests/integration/slice -k <name>` (needs `pytest` and `asyncssh==2.24.1`).
  
  CI runs ten jobs; a PR merges only with all of them green.
- **GitHub Actions is the main test path** (D2-13). The owner's PC comes first only when it can do the job. Never register the PC as a self-hosted runner.
- **On Windows CI, `go test ./...` is slow.** `platform/node` took 374 s beside `platform/store` at 328 s. Any fixed timeout or context in a test will flake there, so wait on the property with a generous bound below the next schedule event. #207 shows the pattern, and its comment explains the bounds.
- **Windows dry runs** go on a separate branch with a workflow triggered by `on: push: branches: [<that branch>]`, never on main. Example: `relaystartdry`'s `.github/workflows/relay-start-dryrun.yml`.
- **CI logs.** Downloading a log zip directly with curl gets 403 from the proxy; use the GitHub tools' job-log call.

**Windows behaviour**
- **The store refuses a directory that inherits its DACL.** Create test store directories with `store.CreateDir`, as the node tests do.
- **Renaming over an open file.** `MoveFileEx` fails while another process holds the target open. Python's `open` and Go's `os.Open` do not share delete. A reader racing a rename gets `PermissionError`. See `read_live` in `slicerun.py`.
- **Service mode** needs an elevated shell and installs real services. Its teardown fails the run on anything left behind; never leave an install in place.

**Code rules**
- **`uintptr(unsafe.Pointer(...))`** is allowed only as a direct argument of a `Call` or `Syscall` (A6's AST rule, `tests/security/uintptr_args_test.go`). The CNG fix (#201) shows why.
- **The relay and the scheduler run on one goroutine.** `RunOnce` calls must not overlap, and `relayAdmin` runs only between runs.
- **Review comments.** Every GitHub comment ends with the Claude Code footer. Reviewers sign their verdicts in the body (A3, A6), because every comment is posted by one account.
