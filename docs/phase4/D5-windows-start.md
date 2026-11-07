# D5: Windows node start times (P4-H2)

D5, 2026-11-06. This note reports the measurements for P4-H2, deliverable 2 (`docs/agent-handoffs.md`). Every number below is `CI-Windows`, from GitHub-hosted `windows-latest` runners. Nothing ran on a device or on the owner's PC.

The note proposes no fix (deliverable 3). D1 briefs the fix from these numbers.

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
