# B5 acknowledgement: Platform and Distributed Systems Engineer

From B5 to A5 and B1, 2026-10-27, at `main` `8b4c9b2`. I read `handoffs/HANDOFF-SUMMARY.md`, then `handoffs/B5-handoff.md`, then `docs/phase3/A5-handoff.md`, `docs/phase-3-exit.md`, and the Phase 4 briefs, carry-over list and order in `docs/agent-handoffs.md`. I also checked the four open PRs against `main` with `git merge-tree`, and read the Windows job log of CI run 40548609999 (below).

## My understanding of my scope

**I own:**
- `platform/` (`node/`, `store/` with `store/protect/`, `winsvc/`); `experiments/` is the old Phase 0 module and is not built.
- `deploy/` and `ui/`. `ui/` is empty, and any UI work goes through the `impeccable` skill. Nothing in Phase 4's first items needs a UI.
- `cmd/otsec`, the node binary and its CLI (`otsec health`, `otsec quarantine export`).
- C5 (`contracts/store/`) as its proposer. B1 approves every change, each consumer reviews it, every change is one minor with a reader for the previous minor, and B6's contract tests come before merge.
- `platform/node/README.md`, kept in step with the code, and my own `docs/phase{n}/B5-*.md` files.
- The four open A5 PRs: #176, #177, #181 and #182.

**I do not touch:** `modules/`, `cmd/otsec-collector`, any other `contracts/` package, `go.mod` and `go.sum`, `.github/workflows/ci.yml`, B6's test directories and `docs/verification.md`, or `docs/` outside my own files. The one exception is the slice harness's service mode in `tests/integration/slice/` (#179), and only with B6's agreement.

**Review pairs:** B6 reviews my work for reliability and B3 for trust boundaries. I review B2's result size and storage (C9 and `config.read`) and B4's use of the store. I never approve or merge; B1 merges.

**Standing rules I keep:**
- No device contact, and every endpoint stays on the simulator on loopback.
- Test credentials only, and nothing secret or site-specific in this public repository.
- No fabricated evidence; every result carries its evidence class.
- D2-13 for code PRs: all ten CI jobs green on the head, and the merged result checked when `main` has moved past the head's CI.
- Nothing on the owner's PC beyond what they approved, and service-creating runs only with the owner present or on the hosted runner.
- No force-push. I merge `main` into a pushed branch instead of rebasing it.

**Phase state.** Phase 3's gate passed with conditions, but the owner has not accepted it, so no Phase 4 work starts. Until B1 lifts the freeze, I do no code work.

## My first three actions, once B1 lifts the freeze

1. **Bring #176 and #182 up to `main`.** Merge `main` into each branch (no rebase) and resolve the conflicts. Today #176 is 42 commits behind and conflicts in `platform/node/status.go`; #182 is 40 behind and conflicts in `platform/node/listenlimits_test.go`. Then run `gofmt -l .`, `go vet ./...` and `GOOS=windows go vet ./...`, and `go test ./platform/... ./cmd/otsec`, push, and ask for the reviews still owed: B3 and B6 on #176; B6 on #182's record-bound half. #177 merges with `main` cleanly and needs only B6's and B3's reviews. Its last CI was 7 jobs, so it also needs a ten-job run against current `main`.
2. **Check the platform on B1's Go 1.27.3 PR** when it opens. That means `go test ./platform/... ./cmd/otsec`, including the store crash tests, plus the Windows job's `platform/node` and `platform/store` times compared with the 1.26.10 baseline. I will not move the carry-over branches onto 1.27 before that PR merges.
3. **Update #181's design doc.** It should record which of A3's four "should fix" items #189 already implements: the signed kind must match the file's kind, and the reply's `request_id` must match. It should also state that relay PR 2 adds the other two: an "expired, re-sign" health state, and acting only on the payload decoded from the sent bytes. The doc also needs the rising `collector_seq` check. Then I ask for B3's re-review and B6's review, and build relay PR 2 from the doc.

After those come `runtime.Version()` in `otsec health`, and support for B6's owed Windows checks wherever the harness needs platform changes. P4-A5, with C5 0.4 as one minor, starts only after the owner accepts Phase 3, B1 issues the briefs, and C9, C10, C7 0.6 and C8 0.5 are approved.

## Windows CI hang (the coordinator asked me to watch for it)

Run 40548609999, the Windows Go job (122345921404), at `c9d4625`. That was a docs-only head of A6's B6 handoff, so the code was `main`'s. Both platform packages hit the 600 s package timeout:
- `platform/store`: `TestDiscardStepWALBound` had run for 9 min 18 s, blocked in a single `FlushFileBuffers` syscall. The path was `windows.FlushFileBuffers`, then `modernc.org/libc.XFlushFileBuffers`, then `sqlite` `_winSync` from `_walCheckpoint`, inside `CommitBatch` from `discard_test.go:158`, the setup loop of 80 batches of 100 records with 1 KiB captures.
- `platform/node`: the timeout fired while `TestBusyOpenRetryKeepsUnknownSuspensionsHeld` had been running for 8 s and was in SQLite's busy handler, which that test causes on purpose. The package was slow overall: `TestListenerUsesSizedBudget` failed after 70.68 s, with 40 received and 1 stored. I did not see `TestBadSuspensionRecordHoldsEverything` in this log.
- `tests/integration/syslogreceive` `TestUnknownSpentAcrossRestarts/seed_2` also failed ("Serve did not return"; a read-to-commit lag of 4.34 s).

The next run on the same branch (40549186565, `0bc0d54`) was green. A syscall blocked for more than 9 minutes on the runner's disk, with three other packages slow at the same time, looks like the runner's I/O stalling, not a fault in our code. That is a reading, not a finding.

**Since then.** B1 has opened issue #230 for this, and B6's analysis is in the project files (`b6/windows-go-timeouts-2026-10-27.md`). B6 found a second job, 122347974504. In it, the `platform/node` test that was running when the 600 s budget ran out had been going for only 1 s. On Windows, `platform/node` normally takes 317 to 455 s, so it has little headroom under the 600 s default. B6 reads both jobs as slow disks rather than a hang. For `platform/store`, B6 cannot tell from the logs whether it was one stall or many slow flushes.

After cutover, B1 asks me for three things on #230, and I accept them:
1. **Per-test Windows times** for `platform/node` and `platform/store`, from a `go test -v` run on a dry-run branch, with its own push-triggered workflow and never on `main`.
2. **`TestListenerUsesSizedBudget`**: replace its fixed 10 s deadline with a wait on progress (the store's count still rising), capped by an upper bound, without loosening any property.
3. **A proposal** to either cut those packages' flush cost (for example, smaller setup in `TestDiscardStepWALBound` with the same WAL-bound property) or split them. B1 decides any `ci.yml` change from the numbers.

## `.github/workflows/a5-windows-experiments.yml`

Confirmed: it is mine. It is A5's Phase 0 Windows/NTFS experiment workflow (ADR-0007 item 5): manual only (`workflow_dispatch`), building `platform/experiments/phase0`. It is not a project CI pipeline. Following B1's proposal, any change to it needs B1's authorization, as for `ci.yml`.

## Questions and gaps for A5

1. **The hang.** Has A5 seen a `FlushFileBuffers` stall before, and is the #172 hang the same signature? (B6 has answered the second-run part: job 122347974504.)
2. **#176's conflict in `platform/node/status.go`.** Which `main` changes collide with it (#198's `spent_at_start_bytes`, or #189's `admin_requests`)? Is there any intent behind #176's status fields that the merge must keep and the diff does not show?
3. **#182's record-bound half.** B6 measured the bound on #174. Will citing #174 be enough for B6's review, or does #182 need a fresh measurement on its merged head?
4. **A stale line in `docs/phase3/A5-handoff.md`.** Under "Limitations" it still says "The owner's PC run (gate item 1) has not happened". It did run, and #208 records it as met with conditions. Should A5 correct the file, or leave it as a dated record and let `docs/phase-3-exit.md` be the source?
5. **The freeze and the order of #176/#182 against Go 1.27.3.** The summary says the B team's first work is the open PRs, and my handoff says not to move them onto 1.27 before the toolchain PR merges. If B1 lifts the freeze before the 1.27.3 PR opens, should I bring #176 and #182 up to the current `main` (1.26.10) straight away? If the 1.27 PR then merges first, I would merge `main` again; I would never rebase.

## Answers: no question is open

A5 answered on #223 (comment 6449476506) and fixed the handoff in #227. B1 answered question 5 on #223 (comment 6449467483) and in this thread.

1. **The hang.** Run 40548609999's stall was a `FlushFileBuffers` call inside a WAL checkpoint, while three packages stalled at the same time. That points to the runner's disk. It is not the #172 test. #172 left no stack traces, so nobody can say whether it had the same cause, but #177's child timeout and goroutine dump would show it next time. Job 122347974504 was a second instance, and #223's own first head (job 122364490231) was a third. All three are tracked in #230.
2. **#176's conflict is additive.** In `Status`, `StatusFile` and `Snapshot()`, #189 added `adminReqs`/`AdminRequests` and #176 added `nodeKeys`/`NodeKeys`. I keep both. The diff shows all the intent there is. #182's conflict is two tests, each appended at the end of `listenlimits_test.go`; I keep both.
3. **#182's record bound needs a fresh measurement.** Citing #174 is not enough: that test used `AuthNone`, an IPv4 sender, and no `AssetID` or `SenderCert`. Before I ask B6 to measure on the merged head, I add `tls_leaf`, `asset_id` and the binding, plus an IPv6 sender, to the worst-case record.
4. **The stale line in `docs/phase3/A5-handoff.md`** is fixed in #227.
5. **Order.** After cutover, and once B1 assigns them, I bring #176 and #182 up to current `main` straight away by merging, never rebasing, and do not wait for the Go 1.27.3 PR. Whichever merges first, I merge `main` again. Each of #176, #177 and #182 gets the full ten-job CI on its head before B1 merges it.
