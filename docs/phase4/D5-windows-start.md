# D5: Windows node start times (P4-H2, P4-H4)

D5, 2026-11-06. This note reports the measurements for P4-H2, deliverable 2 (`docs/agent-handoffs.md`). Every number below is `CI-Windows`, from GitHub-hosted `windows-latest` runners. Nothing ran on a device or on the owner's PC.

Sections 1 to 5 propose no fix (P4-H2, deliverable 3); D1 briefed the fix from them as P4-H4. Sections 6 and 7 are P4-H4's: the split of `store-reserve`, and the fix with its numbers before and after.

## 1. Where the numbers come from

All of them come from #515's code at head `8a6e5600dadcb3e4fd2778ca273aaf5b89c4d3e4`, after main `e205da6` was merged in. The commit that adds this note changes no code after that head.

| Source | Run | Job | Starts | Line |
| --- | --- | --- | --- | --- |
| `ci.yml`, `go (windows-latest)` | [42294811926](https://github.com/alialyami90/OTSEC-Proj/actions/runs/42294811926) | [128157168546](https://github.com/alialyami90/OTSEC-Proj/actions/runs/42294811926/job/128157168546), step "platform/node start times (P4-H2)" | 541 | `scope=runtime`: `node.Start`'s phases in a `platform/node` test |
| `a6-windows-slice.yml`, `service` (D6's dispatch) | [42294840346](https://github.com/alialyami90/OTSEC-Proj/actions/runs/42294840346) | [128157273410](https://github.com/alialyami90/OTSEC-Proj/actions/runs/42294840346/job/128157273410), Application-log step | 9 | `scope=node`: the installed `otsec-node` service started by the SCM, from the command's entry |

That is 550 starts in all. Both workflows (`ci`, `govulncheck`) and the dispatch are green at this head.

The two kinds of line measure different things:

- **`scope=node`** counts from `otsec node`'s entry. It covers every phase, `config` and `scm` included.
- **`scope=runtime`** is a test's `start()` helper. It covers only `Start`'s phases, so `config`, `scm` and `Run`'s phases are 0.
- **Test starts that bypass `start()` leave no line in the go job's log.** That covers tests that call `Start`, `Run` or `RunFrom` directly. Run's line goes to the test's own OS log function, which the test keeps or drops, not to `t.Log`. Such calls are in 9 `platform/node` test files (`forwarding`, `listencaps`, `eventbaselines_run`, `eventbaselines_run_c6`, `certperiod`'s `TestHeldRequiredTargetPastItsQuota`, `serbound`, `service`, `statusorder`, `results`), and in `cmd/otsec`, `tests/integration/quarantine` and `tests/security`. So the go job's 541 lines are the starts made through `start()`, not every node start in the job.
- **Neither** covers the time before the command's entry: process creation and the Go runtime's start.

The line ends before the scheduler's first collector exchange. That exchange waits for the first entry's due time, a minute after start (AP-13), so it is not part of starting.

The test starts ran during `go test -v ./...`, while other test packages ran on the same runner and disk. The 9 service starts ran in the slice harness: the first start after install, kills with `taskkill /F`, and stops. None was a recovery restart.

## 2. Totals

| Source | Starts | Min | Median | p90 | Max | Over 6 s | Over 12 s |
| --- | --- | --- | --- | --- | --- | --- | --- |
| go job (`runtime`) | 541 | 107 ms | 558 ms | 1462 ms | 67716 ms | 2 | 1 |
| service job (`node`) | 9 | 713 ms | 882 ms | 1244 ms | 1244 ms | 0 | 0 |

**Service starts:** none came near the 12.47 s of #471's late try.

**Starts over 6 s:** two of the 550 took more than 6 s, one of them 67.7 s. The brief asks for at least 3 such starts if any occur. One run at this head gave 2, so the third is still open. Another `go (windows-latest)` run on #515's code would add more starts, and D1 decides whether to spend that Windows time.

## 3. The slowest ten

All values are in ms. "All other phases" is the total less the four columns before it; it includes `other`, which was at most 1 ms on every line.

| # | Source, line in the step's list | Total | store-open | store-reserve | record-start | status | All other phases |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | go, 109 | 67716 | 18884 | 40626 | 6762 | 1428 | 16 |
| 2 | go, 7 | 6431 | 4 | 5221 | 1137 | 66 | 3 |
| 3 | go, 35 | 5873 | 1476 | 2750 | 1000 | 634 | 13 |
| 4 | go, 36 | 4031 | 2123 | 1292 | 499 | 102 | 15 |
| 5 | go, 33 | 3896 | 1246 | 1563 | 818 | 252 | 17 |
| 6 | go, 32 | 3368 | 1765 | 931 | 631 | 27 | 14 |
| 7 | go, 43 | 3350 | 983 | 1766 | 578 | 18 | 5 |
| 8 | go, 34 | 2765 | 1196 | 1163 | 366 | 29 | 11 |
| 9 | go, 77 | 2541 | 1115 | 752 | 611 | 47 | 16 |
| 10 | go, 99 | 2529 | 1144 | 1131 | 218 | 32 | 4 |

All ten are test starts. The slowest service start (1244 ms) is not among them.

**Which tests these were:** the line names no test, and the step prints the lines in log order. I matched positions against a local `go test -v ./platform/node` on Linux, which gave 543 lines to CI's 541, so a position may be off by up to two. On that basis:

- Line 109 falls in `TestC6LostFileKeepsAnOperatorMismatch`. Its start is the restart after `pruneThrough` and the deleted declared-identities file. The same job lists that test as its slowest, at 82.97 s.
- Line 7 falls in `TestSignedQuarantineClearResumesFromTheChain` (15.03 s in that list).
- Lines 32 to 43 fall in the signed-configuration and relay tests.

These test names are inferred from positions; the timings themselves are measured.

## 4. The dominant phase

**In the slow starts, the dominant phase is `store-reserve`, and the next is `store-open`.**

- In the go job, `store-reserve` was 49% of all start time (233.5 s of 475.9 s), `store-open` 26% and `record-start` 22%.
- `store-reserve` was the largest phase in 404 of the 541 starts.
- In the slowest ten, the largest phase was `store-reserve` in five and `store-open` in the other five. Across those ten, `store-reserve` was 56% of the time and `store-open` 29%.
- The 67.7 s start spent 40.6 s in `store-reserve` and 18.9 s in `store-open`.

`store-reserve` is the time inside C5 `StartupEnv.CreateReserve` and `ReleaseReserve`, summed over the node's databases. `store-open` is the time inside `StartupEnv.Open`. The line does not split them further, for example the file creation from the flush. #428's lead, recreating the recovery reserve with a flush at every start (F-013), is therefore consistent with these numbers but not shown by them.

**In the service starts, no phase is slow.** Every start took 713 to 1244 ms:

| Phase | Range | Note |
| --- | --- | --- |
| `record-start` | 522 to 836 ms | the largest phase every time |
| `node-keys` | 103 to 116 ms | |
| `store-reserve` | 54 to 263 ms | |
| `config` | 1 to 2 ms | |
| `scm` | 3 to 4 ms | |

## 5. Limits

- One go job and one service job at one head. Start times on hosted runners vary between runs and runners.
- The test starts share the runner with other test packages, which the service starts in the slice job do not do to the same extent. So a slow test start may come partly from load on the runner's disk.
- #471's 12.47 s was a late try of the certificate-period test in the go job (`docs/phase-4-item3-exit.md`). That test's tries start the node through `start()`, so a stall there would leave a line. This run had no such stall in it; its one start over 12 s (67.7 s) was in another test. These numbers do not show whether the two are the same stall.

## 6. P4-H4 step 1: what `store-reserve` is made of

D5, 2026-11-07. P4-H4 (`docs/agent-handoffs.md`) asks first for `store-reserve` split into its parts, with no fix, as the baseline. #520's commit `8fef498691a0fdf4a5dcb0fabeb4b40dda46b972` adds the parts to the start line, and these numbers come from it. Every number is `CI-Windows`, from the `go (windows-latest)` job's step "platform/node start times (P4-H2)", lines after "Every start line:".

| Attempt | Run | Job | Starts | `platform/node` budget step |
| --- | --- | --- | --- | --- |
| 1 | [42361544102](https://github.com/alialyami90/OTSEC-Proj/actions/runs/42361544102/attempts/1) | [128370804636](https://github.com/alialyami90/OTSEC-Proj/actions/runs/42361544102/job/128370804636) | 543 | 579.410 s |
| 2 | [42361544102](https://github.com/alialyami90/OTSEC-Proj/actions/runs/42361544102) | [128417906766](https://github.com/alialyami90/OTSEC-Proj/actions/runs/42361544102/job/128417906766) | 543 | 631.911 s |

The parts, in ms (median, p90 and max over each attempt's 543 starts):

| Part | Attempt 1 | Attempt 2 | Sum over both, ms |
| --- | --- | --- | --- |
| `total` | 325, 922, 17484 | 322, 954, 10639 | 543456 |
| `store-open` | 63, 327, 8354 | 66, 372, 8509 | 157567 |
| `store-reserve` | 151, 366, 8906 | 138, 383, 4195 | 234341 |
| `reserve-release` | 0, 3, 5 | 0, 3, 16 | 908 |
| `reserve-create` | 0, 1, 21 | 0, 2, 36 | 807 |
| `reserve-write` | 10, 13, 95 | 10, 13, 119 | 11629 |
| `reserve-sync` | 137, 348, 7527 | 123, 364, 4180 | 216250 |
| `reserve-dirsync` | 0, 0, 0 | 0, 0, 0 | 0 |
| `reserve-close` | 1, 3, 1330 | 1, 3, 30 | 3070 |

**The dominant part is `reserve-sync`, the flush of the reserve file.** It was 92.3% of `store-reserve` over both attempts (91.9% and 92.6%), and `store-reserve` was 43.1% of all start time. The zero writes themselves took a median of 10 ms; it is flushing them to disk that is slow. The slowest start of attempt 1 (17484 ms) spent 7527 ms in the flush and 1330 ms in `reserve-close`, the one close over 30 ms in either attempt. Three starts were over 6 s and one over 12 s.

How to read the parts:

- `store-reserve` stays on the line, and it is the sum of the `reserve-*` parts: the start-up code adds each part's time to both. Each value on the line is cut to whole milliseconds on its own, so on one line the printed parts can fall up to 4 ms short of the printed `store-reserve`; `TestReserveParts` checks the sum exactly, before rounding.
- `reserve-create` includes the `OpenFile` that creates the file. `reserve-close` is the rest of `CreateReserve`, chiefly the file's close (D3).
- `reserve-dirsync` is 0 on Windows by construction: `syncDir` does nothing there, and P4-H4 adds no Windows folder flush (D1).
- At a normal start the node releases and re-creates only the recovery reserve (F-013), at least 1 MiB: twice `store.WALBoundBytes` plus the largest commit's WAL bytes.

## 7. P4-H4 step 2: the fix

**The change.** `CreateReserve` (`platform/store/env.go`) now allocates the reserve's space in one call and writes no data:

- On Linux it uses `fallocate` in mode 0, which allocates blocks and never makes a sparse file.
- On Windows it extends the file with `SetEndOfFile` (Go's `Truncate`). On NTFS, extending a file that is not sparse allocates its clusters.
- Where there is no such call, it writes zeros as before. That covers `EOPNOTSUPP` from `fallocate`, for example on some network or overlay file systems, and every OS other than Linux and Windows.
- Any other allocation error fails the call and removes the file.

The file flush, then the folder flush, still run before the reserve counts. The flush now has only the size and the allocation to make durable, not a mebibyte of zeros. `RecoveryReserveBytes`, `LastResortReserveBytes`, `OpenHeadroomBytes` and the store's open are unchanged.

**Plain `Truncate` on `windows-latest` holds the space.** `TestReserveHoldsItsSpace` reads each reserve's `AllocationSize` back through `GetFileInformationByHandleEx` and logs it. In #520's `go (windows-latest)` job at `bce9619a0898780a860e725caf3f2b50633c3863` ([run 42378339919](https://github.com/alialyami90/OTSEC-Proj/actions/runs/42378339919), [job 128420487452](https://github.com/alialyami90/OTSEC-Proj/actions/runs/42378339919/job/128420487452)) it logged:

```text
reserve_test.go:33: recovery reserve: 4206649 bytes long, 4210688 allocated
reserve_test.go:33: last-resort reserve: 4206649 bytes long, 4210688 allocated
```

That is the file's length rounded up to whole 4 KiB clusters. This line is the `CI-Windows` evidence that `SetEndOfFile` holds real clusters on the runner's NTFS volume. `TestAllocatedBytesSeesASparseFile` shows the reader is not fooled by a sparse file: FSCTL_SET_SPARSE then a truncate on Windows, a truncate on Linux. On Linux, a `Truncate` in place of `fallocate` fails `TestReserveHoldsItsSpace` (desk).

**What pins each must-keep property:**

| Property | Tests |
| --- | --- |
| 1. F-013: the recovery reserve is released before the open | The existing order tests, `platform/store/startup_test.go` and `contracts/store/store_test.go`. CI pins this by order only. That the order keeps a full store openable has been shown only on a Windows Server VM with Python's SQLite, not with the product's driver or on Windows LTSC (C-22 and H-14 are still open). |
| 2. A reserve counts only once it holds real space and is flushed, and a node that can't re-create one alarms and does not collect (ADR-0004 item 8) | `TestReserveHoldsItsSpace`, `TestAllocatedBytesSeesASparseFile`, `TestReserveAllocationFallback`, `TestReserveFlushFaults` (`platform/store`), and `TestNodeWithAFailedReserveFlushDoesNotCollect` (the node). A fault in the file flush, then in the folder flush, fails `CreateReserve` and leaves no file. Startup ends drain-only with `reserve-recreate-failed`, and `Collecting()` is false. |
| 3. AP-13: the first collection waits 60 s | `TestFirstRunWaitsAMinute`, with the existing `TestRunWaitsBeforeTheFirstRun` and `TestPlanSpacesSessionsPerAsset`. |

Every existing V-S9 and storage-exhaustion test runs unchanged. `TestReserveParts`, added in step 1 of this PR, no longer requires `reserve-release` and `reserve-write` to be above zero: with no zero writes, both measured 0 s on `windows-latest` (D1). It still requires every part to be timed, `reserve-sync` to be above zero, and `store-reserve` to equal the parts' sum exactly.

**Known limit.** This sits next to H-14. On a compressed volume (NTFS, ZFS or btrfs compression) or a copy-on-write volume (ZFS, btrfs), a reserve may hold less real space than it reports. That is true on the allocation path and on the zero-write path alike: zeros compress to almost nothing, and copy-on-write reserves nothing for later writes. The gap predates this change. D1 ruled that failing the reserve on such volumes is an owner-level support decision, outside P4-H4 (D3 raised it, D6 the NTFS case).
