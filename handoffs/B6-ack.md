# B6 acknowledgement

From B6 (Independent Verification and OT Safety Engineer), 2026-10-27, at `main` 8b4c9b2. I read `handoffs/HANDOFF-SUMMARY.md`, `handoffs/B6-handoff.md`, and the key files it lists: `CLAUDE.md`, `docs/verification.md` (Phase 3 status and P3-W1), `docs/phase-3-exit.md`, the P4-A6 brief and carry-over in `docs/agent-handoffs.md`, `.github/workflows/ci.yml` and `a6-windows-h14.yml`, and the slice harness (`slicerun.py`, `harness.py`) with the two Windows-skipped legs.

## My scope

I am the independent verifier. I try to disprove claims; I do not approve them by default.

- **I own:** `tests/integration/`, `tests/security/`, `tests/safety/` (including `recording_simulator/`), `tests/contract/`, `docs/verification.md`, `.github/workflows/a6-*.yml`, my own `docs/phase<N>/B6-*.md` files, and this file.
- **I do not touch:** product code (`modules/`, `platform/`, `cmd/`, `contracts/`, `deploy/`, `ui/`), other agents' docs, or `ci.yml` without B1's written authorization.
- **How I work:** every test has an oracle that is not the product's code (the simulator's recording, a stock receiver, or a transcription from the manual). Every verdict states its mutants killed and explains survivors. I post PASS or FAIL (CHANGES NEEDED) on the PR. A critical safety or security failure blocks acceptance. I never merge or approve my own PRs, and I never skip, disable or quarantine a test.
- **Standing rules I keep:** no device contact, simulator on loopback only, test credentials only (D2-5, D2-11), nothing on the owner's PC beyond what the owner approved, elevated steps there only by the owner in person, and D2-13 for every code PR. Evidence is labelled `desk`, `simulated` or hosted-runner; nothing is `hardware-verified` (B-01).

## Current state as I understand it

- Phase 3 passed its gate with conditions. The owner has not accepted it, so none of P4-A6's Phase 4 items start.
- Nothing from A6 is in progress or uncommitted. A6's last PRs (#208, #212) are merged.
- Owed from P3-W1, none done: the canary scan of process command lines, the unknown-restart leg on Windows, the admin relay and `config\admin`'s ACLs on Windows, and the DMY and YMD slice reconcile on the real binaries. They wait on B1's release, not on owner acceptance.

## My first three actions

1. **Ask B1 to release the carried checks**, and confirm Phase 3's acceptance state before anything from P4-A6 starts.
2. **When released, the canary scan first.** A slice test calls `Slice.cmdline()` for the node and the collector while they run (process mode and service mode) and asserts the canary password never appears. A mutant that puts the password on a command line must fail it. Then the DMY and YMD reconcile on the real binaries (`test_slice_e2e.py` with `--profile-date-f`), which needs no Windows-specific work.
3. **Agree the Windows admin-relay design with B5 before writing it:** a stand-in for SIGSTOP (suspending the collector service's process) and an ACL check on `config\admin` in place of POSIX modes. In parallel, work out what the unknown-restart leg needs on Windows (binding 127.0.0.2 and 127.0.0.3, killing the node mid-flood) and replace or justify each POSIX-only part.

## Questions and gaps

1. **How the Windows slice checks run on the hosted runner (A6, B1).** `ci.yml` runs the slice only on Linux, and the only A6 workflow on `main` is `a6-windows-h14.yml`. svcdry8 (run 40464065233) ran on a dry-run branch. Which workflow file ran it? Does my ownership of `.github/workflows/a6-*.yml` let me add an `a6-windows-slice.yml` without a separate B1 authorization, as A1 gave for H-14 on 2026-10-23? A `workflow_dispatch` workflow can be started only once the file is on `main`, so the first run would need either a merge or a `pull_request` trigger.
2. **The Windows Go job's 600 s timeout (A6, B1, B5).** On #214's CI (run 40549190723, attempt 1, job 122347974504), `platform/node` hit `go test`'s default 600 s timeout. The goroutine dump shows `TestBadSuspensionRecordHoldsEverything` blocked in `FlushFileBuffers`, inside a WAL commit during the store's open (`store.(*DB).load` → `tx`). In the same job, `platform/store` passed but took 515 s. The handoff does not mention this. The coordinator reports a second test hit the same timeout. Has anyone classified it as a hang (one flush that never returns) or a slow disk (many slow flushes adding up)? Under D2-13 it is not a flake until shown. I propose to measure it from the per-package times in recent Windows jobs and report to B1 and B5. Changing the package or the CI timeout stays with them.
3. **V-M4 and redelivered events (B4).** The handoff says a redelivered event flagged `possible-duplicate` should not trip the Repeats rule "unless C10 states otherwise". I will write the test to whatever C10 says, and ask B4 to state it explicitly in the C10 draft.
4. **Small handoff gap.** `B6-handoff.md` does not list `.github/workflows/a6-*.yml` under "What you own", while `HANDOFF-SUMMARY.md` does. I read the summary as correct. A6, please confirm.

None of these blocks the ack. Questions 1 and 2 must be answered before the Windows carried checks start.
