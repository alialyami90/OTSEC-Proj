# B6 handoff: Independent Verification and OT Safety Engineer

From A6, 2026-10-27, at `main` d4afc63. Read `handoffs/HANDOFF-SUMMARY.md` first, then this file. The role is defined in `CLAUDE.md` §4 (A6) and §5.6. Evidence and verdicts live in the project docs linked below; this file does not repeat them.

## Role & scope

You are the independent verifier. Your job is to try to disprove claims, not to approve them.

**What you do:**
- Write your own tests from the rule text, with an oracle that is not the product's code: the recording simulator's own log, a stock receiver, or a transcription from the manual.
- Mutate the code under test. Every verdict states how many mutants were killed.
- Post a PASS or FAIL (CHANGES NEEDED) comment on the PR. A critical safety or security failure blocks acceptance (`CLAUDE.md` §4, §6 Phase 3).

**What you own and may change:**
- `tests/integration/`, `tests/security/`, `tests/safety/` (including `tests/safety/recording_simulator/`), `tests/contract/`;
- `docs/verification.md`;
- your own handoffs under `docs/phase<N>/A6-*.md` (B6 from now on);
- `handoffs/B6-ack.md`.

**What you do not touch:**
- Product code: `modules/`, `platform/`, `cmd/`, `contracts/`, `deploy/`, `ui/`.
- Other agents' docs.
- `.github/workflows/ci.yml`, unless B1 authorizes the change in writing.

**What you never do:**
- Merge your own PRs or approve on GitHub. B1 merges.
- Skip, disable or quarantine a test.
- Touch a real device or production system. H-01 to H-15 stay prepared only until the owner authorizes a lab relay.

## Current state

**Nothing is in progress or uncommitted.**
- Branch `claude/project-thread-u7odvk` is level with main.
- Every A6 PR is merged:
  - #208, gate item 1;
  - #212, the harness log-read race that turned #209's `integration` job 122275033049 red.
- My last reviews were #211 (A2, PASS, 8 of 8 mutants killed) and #209, the exit report, which I accepted.

**Phase 3 passed its gate with conditions.** It is **not yet accepted by the owner** (`docs/phase-3-exit.md`, "Owner sign-off: Not yet given").
- **P4-A6 is held until the owner accepts.** That is your Phase 4 brief (`docs/agent-handoffs.md`, "Task P4-A6").
- The Phase 4 briefs are drafts, issued only on that acceptance.

**Gate item 1 (P3-W1, the slice on the owner's PC)** is met with conditions. The record is `docs/verification.md`, "Phase 3 status" and "P3-W1 on the owner's PC (2026-10-27)".
- **Result:** 159 passed, 27 skipped, 0 failed, at `main` 27fdea4, on Windows 11 Pro 10.0.26200.
- **The log copy:** `/mnt/project-files/phase3/P3-W1-pc-pytest.txt` is stored as UTF-8 with LF. The PC's `pc-out\pytest.txt` is UTF-16LE with a BOM and CRLF (Windows PowerShell `Tee-Object`), 49,796 bytes, with SHA-256 `DBEF499A332683F67D9895B6522F1A0849E8083F3A7E1B8692AC17FC77403D4B`. Re-encode the copy that way to reproduce the hash; the command is in `/mnt/project-files/phase3/P3-W1-pc-run-result.md`.
- **The SCM logs under `pc-out\slice` on the PC were not read.** They need an elevated read, which only the owner may do.

**Owed from P3-W1. None of these is done:**

| Owed item | Status |
| --- | --- |
| The admin relay end to end, and `admin_dir`'s (`config\admin`) ACLs, on Windows | Not covered. `test_slice_admin_relay_e2e.py` is skipped on Windows (it needs SIGSTOP and POSIX modes); only C7's contract tests run there. |
| The unknown-restart leg on Windows | Not covered. `test_slice_unknown_restart_e2e.py` is skipped on Windows. |
| The rsyslog leg | Linux only by design (`test_rsyslog_leg.py`). It runs in CI's Linux `integration` job. |
| A scan of the services' process command lines for the canary password | Not done. `Slice.cmdline()` exists in `tests/integration/slice/slicerun.py` but no test calls it. |

**Carried from earlier phases, not run** (`docs/phase-3-exit.md`, "Failed or incomplete"):
- V-S7's 24-hour soak, (c) and (d);
- V-S6's link cut in the middle of a SER read;
- V-S9's file-system exhaustion;
- V-S15's hostile framing on the SER path;
- V-S18 and V-S20.

The DMY and YMD reconcile passes from the adapter through the normalizer (#211). It has not been run on the real binaries.

**Evidence class.** Everything is `desk`, `simulated`, or from the GitHub-hosted Windows runner where stated. Nothing is hardware-verified (B-01).

## Next steps

1. **First action:** read `handoffs/HANDOFF-SUMMARY.md`, this file and the key files below, then write `handoffs/B6-ack.md`. Ask B1 whether the owner has accepted Phase 3. Until the owner has, start no P4-A6 work.
2. **When Phase 3 is accepted,** do the carried checks first. They are in the P4-A6 brief, and all of them can run on the hosted Windows runner, not the owner's PC:
   1. **The canary scan:**
      - call `Slice.cmdline()` for the node and the collector while they run, in service mode too, and assert that the canary never appears;
      - mutate by putting the password on a command line, and show that the test catches it.
   2. **The unknown-restart leg on Windows:** replace or justify the leg's POSIX-only parts.
   3. **The admin relay and `config\admin`'s ACLs on Windows:**
      - this needs a Windows stand-in for SIGSTOP (for example, suspending the node service's process) and an ACL check in place of POSIX modes;
      - agree the design with B5 (the harness's service mode is B5's) before writing it.
   4. **The DMY and YMD slice on the real binaries:** `test_slice_e2e.py` with the simulator's `--profile-date-f`.
3. **Phase 4 items 1 and 2, as P4-A6 lists them:**
   1. Write the simulator's `SHO` forms from S22 Table 7.67 and the Section 4 settings tables, independently of B2's parsers, with a change injector.
   2. Commit the GT-INJ series for configuration changes and event departures **before** any product test runs on them.
   3. Write the contract tests for C9, C10, C2 0.6, C5 0.4, C7 0.6 and C8 0.5.
   4. Write the acceptance tests for V-M2, V-M3 (SEL-751) and V-M4.
   - **V-M2, "prior":** an approval counts only if its `collector_seq` is below the number of the `config.read` decision that found the difference. Test an approval numbered above the detection.
   - **V-M4, redelivered events:** a redelivered event flagged `possible-duplicate` should not trip the Repeats rule, unless C10 states otherwise.
4. **Review every Phase 4 PR independently,** with mutants and a PASS or FAIL comment, and keep the Phase status table in `docs/verification.md` current.
5. **The move to Go 1.27.3** is A1's (now B1's) PR under D3-10. It needs your review and a repeat of the Windows UDP stress test on 1.27 (`docs/phase-3-exit.md`, D3-10).

## Key files

| Path | Why |
| --- | --- |
| `CLAUDE.md` | The brief: the role, the review rules (§5.6), Definition of Done (§7), and the scope update (all device classes, SEL first). |
| `docs/verification.md` | Your document: criteria (V-S, V-M), evidence classes, Phase 2 and 3 status tables, P3-W1 record, R4.8 and R9 semantics, findings F-001 to F-015, blockers. |
| `docs/phase-3-exit.md` | What passed, what is owed, open risks, lessons. |
| `docs/agent-handoffs.md` | "Phase 4 task briefs": P4-A6, and every brief whose acceptance tests are yours (P4-A2, P4-A3, P4-A5, P4-A4). |
| `docs/phase3/A6-handoff.md` | A6's Phase 3 handoff (2026-10-26): per-PR verdicts and mutant counts up to #183. Later verdicts are on the PRs (#184 to #211). |
| `docs/phase3/A1-decisions.md` | D3-1 to D3-11, especially D3-10 (Go 1.26.10) and D3-11 (`DATE_F` absent). |
| `tests/integration/slice/harness.py`, `slicerun.py` | The end-to-end harness: `Slice`, service mode, teardown with its leftovers check, `read_log(live=...)`. |
| `tests/safety/recording_simulator/sim.py`, `profile_sel751.py`, `check.py` | The recording simulator (GT-REC) and the read-only register check. The oracle for every slice test. |
| `tests/security/uintptr_args_test.go` | The AST rule for `uintptr` conversions in syscalls (#199). |
| `.github/workflows/ci.yml` | The 10 jobs (D2-13). Read it; change it only with B1's authorization. |
| `/mnt/project-files/a6/P3-W1-pc-run-sheet.md`, `/mnt/project-files/phase3/` | The PC run sheet, the result and the log copy. |

## Decisions made

- **D2-13: GitHub Actions is the main test path.** A PR merges when its reviewers accept it and all 10 jobs are green on its head. When the head's CI predates newer `main`, the Windows leg runs against the merged result before merge.
- **Independent oracles.** The simulator is built from the cited manual, not from B2's code or fixtures, so the two cannot share a misreading (`docs/verification.md`, "Device simulator plan"). Slice tests reconcile against the simulator's recording, never against the product's parser.
- **Every verdict carries mutants.** Survivors are explained: equivalent, or failing toward the safe side.
- **Waits check properties, not timings.** Wait for progress, use bounds from `ctx.Deadline()`, or wait for the event itself. Fixed sleeps failed on loaded runners several times (#188, #199, #207).
- **`harness.read_log(path, live=True)`** for a log whose writer still runs: it leaves a half-written last line for the next read. Strict reads after the writer stops still fail on truncation (#212).
- **P3-W1 verdict.** A6 accepted two checks met by other evidence:
  - the `teardown: nothing left behind` line goes to the SCM log, not `pytest.txt`, and teardown raises on any leftover;
  - there is no `go version` line, but `go.mod` says `go 1.26.10` and `GOTOOLCHAIN=local` refuses older toolchains.

  The reasoning is in `docs/verification.md`.
- **The `uintptr` rule.** A pointer converted to `uintptr` must be converted in the call's argument list, and the callee must carry `//go:uintptrescapes`. The AST test enforces this across the root module.
- **The Windows UDP crash (D3-10)** is inferred to be golang/go#78041, not proven: 2 of 42 runs crashed on 1.26.0 and 0 of 41 on 1.26.10. About 62 clean runs would be needed to exclude the old rate at 95 percent.

## Open questions / risks

- **No hardware (B-01).** No SEL family may be called supported.
  - The `SHO G` layout is assumed: S22 prints no `SHO G` reply.
  - Agreement between the simulator and the adapter is not hardware evidence.
- **HR-11.** A forward wall-clock step followed by a restart refills the unknown-sender budget. The absolute bound (a C5 class and quota) gates the first `device-observed` listener.
- **The collector-state replace on Windows.** `MoveFileEx` failed 1556 of 3000 times beside a reader that shares delete, and the collector then fails closed until a restart. B3's Phase 4 item fixes it; test both the POSIX path and the fallback.
- **The flood test catches a shared rate bucket only by its lag** (`docs/phase3/A6-handoff.md`, "Limitations").
- **The collector clears its failed-auth floor about 10 ms after `QUI`.** A kill in that gap leaves the floor in place, which fails safe.
- **The owner's PC.** The SCM logs from P3-W1 are unread. Nothing that needs elevation may run on the PC except by the owner personally (see Gotchas).

## Dependencies

- **B1:** owner acceptance of Phase 3, merges, and authorization for any `ci.yml` change.
- **B2:** C9, C2 0.6, the register revision 5 `SHO` lines, and the `config.read` operation. You test them; your simulator forms must not come from B2's code.
- **B3:** C7 0.6 and C8 0.5 (approvals, baseline acknowledgement), and the `replaceFile` fix. You write V-M2's tests and review security-sensitive behaviour.
- **B4:** C10 and the event-baseline learner. You test V-M4; B4 reviews your protocol interpretation.
- **B5:** C5 0.4, the configuration schedule, the harness's service mode, and #176, #177, #182 and relay PR 2. Agree with B5 on the Windows stand-in for SIGSTOP.
- **Everyone:** every implementation PR waits for your independent check before merge.

## Gotchas

**The owner's PC (standing rules):**
- Only the owner runs elevated steps, personally.
- Never register the PC as a self-hosted runner.
- No system-wide installs: portable Go and a Python venv inside the owner's OTSEC folder only.
- No machine keys, and no unverified binaries.

**The repository is public:**
- no secrets, no real device data, no internal hostnames;
- test credentials only (D2-5).

**Evidence hygiene:**
- Cite a run, job or comment ID only after a tool has returned it. Never build a URL from a guessed run ID.
- Before a verdict, check that the review worktree contains the PR head and current `main`. Two #189 items once ran on a stale tree.

**Local Python:** the system Python has no pytest. Use a venv with `pytest` and `asyncssh==2.24.1`, and set `OTSEC_SLICE_REQUIRED=1` so a missing tool fails rather than skips.

**Mutant scripts:**
- A mutant script killed mid-run leaves the mutant in the file. Always `git checkout -- <file>` afterwards, and check `git status`.
- `pkill -f` and `pgrep -f` can match your own shell.

**Editing `docs/verification.md`:** its tables are long single lines. A scripted edit that replaces a cell must keep the `| ` separators. Count the cells per row after editing.

**Windows:**
- The simulator and receiver logs are CRLF there (text mode).
- `ServiceMode.note()` writes to the SCM log, not stdout.
- The 27 Windows skips are expected: 7 rsyslog, 18 admin relay, 2 unknown restart.

**Git:**
- No force push. After a PR merges, merge `origin/main` into the branch to restart it.
- Use the GitHub MCP tools; there is no `gh` CLI.
- Commits and PR bodies carry the session attribution lines.

**Memory is off in this project.** Anything worth keeping goes in the repository or `/mnt/project-files/` (re-read a shared file about 10 seconds after writing it).
