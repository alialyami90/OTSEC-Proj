# Integration tests

Owner: A6. Independent end-to-end and cross-module verification of the criteria in [docs/verification.md](../../docs/verification.md). No integration tests exist yet; there is no product code.

## Experiments

Phase 0 experiments that challenge assumptions before contracts are approved. Each prints a JSON report; committed results are under `experiments/results/`.

| ID | Script | Question | Result |
| --- | --- | --- | --- |
| E-03 | [store_restart_while_full.py](experiments/store_restart_while_full.py) | After a crash at full disk, can a restarted process read and prune the SQLite store? | Reads and integrity OK, pruning fails without freed space, 6/6 trials (`simulated`). See F-004. |
| E-04 | [store_recovery_rounds.py](experiments/store_recovery_rounds.py) | Does A5's startup recovery (reserve, incremental prune, stepwise `incremental_vacuum`) regain capacity over repeated exhaustions, including when recovery is itself killed? | Holds with `auto_vacuum=INCREMENTAL` (5/5 rounds, both variants); fails capacity with `NONE`; interrupted recovery prunes twice (`simulated`). See F-006, R-A5-5. |
| E-02 | [fsync_before_ack.py](experiments/fsync_before_ack.py) | Does A5's writer fsync before each acknowledgement? | `NORMAL`: 1,011 of 1,016 acks unsynced; `FULL`: 0 of 680 (`simulated`). See F-004. |
| E-01 | [syslog_tls_delivery_gap.py](experiments/syslog_tls_delivery_gap.py) | Does an error-free write to an RFC 5425 collector mean the message was delivered? | No. 100 of 150 frames lost silently in 5 of 5 trials (`simulated`). See finding F-001. |

All experiments ran on Linux. The site platform node runs Windows 10/11 on dedicated hardware that may or may not be an SEL-3355-2 (ADR-0007), so storage and durability results (E-02 to E-04) are `simulated (Linux)` until H-14 re-runs them on Windows (C-22).

Run: `python3 -I tests/integration/experiments/<script>`. E-01 needs the `openssl` CLI; E-02 needs `strace` and A5's `p0` binary as its argument; E-03 and E-04 need root to mount tmpfs.

## H-14 on Windows

[h14/](h14/) is A6's Windows run of E-02, E-03 and E-04, plus R-A5-5. It is driven by [run_h14.ps1](h14/run_h14.ps1) and the manual workflow `a6-windows-h14`. The scripts under test run as a non-admin account.

- [flush_writer.py](h14/flush_writer.py) and [flush_analyse.py](h14/flush_analyse.py) use an ETW Kernel-File trace in place of strace. Marker files cut the trace into one interval per acknowledgement. Positive controls (`os.fsync` on a control file) make a trace that cannot see flushes come out INCONCLUSIVE instead of passing.
- [recovery_rounds.py](h14/recovery_rounds.py) is E-04, ported to run on Windows, with a cursor-bounded prune for R-A5-5. Since Phase 1 it recovers in ADR-0004 item 8's order: it releases the reserve before the first open, and stops if the release, the open or the prune fails. Each scenario runs on its own fresh volume, and every open of the store happens in a short-lived child process. This fixes F-013's WinError 32 and keeps a leaked handle from changing the next open. There are five scenarios:
  - `incremental-cursor`: the R-A5-5 case.
  - `incremental-half`: the double-prune contrast.
  - `none-half`: the capacity contrast.
  - `open-at-full`: F-013's order first, then the reserve-first recovery.
  - `no-reserve`: nothing to release.

  On a Linux tmpfs, [results/recovery-rounds-linux-tmpfs-2026-10-24.json](h14/results/recovery-rounds-linux-tmpfs-2026-10-24.json) gives these outcomes:
  - `incremental-cursor` passes, and its restart prunes 0.
  - `incremental-half` restarts prune 2,057 more.
  - `none-half` fails capacity.
  - `open-at-full` passes, because the open at full disk cannot fail on tmpfs.
  - `no-reserve` opens but cannot prune.

  The earlier version's Linux result is [results/recovery-rounds-linux-tmpfs-2026-10-23.json](h14/results/recovery-rounds-linux-tmpfs-2026-10-23.json).
- [test_flush_analyse.py](h14/test_flush_analyse.py) has 8 parser cases on synthetic traces. These cases are not Windows evidence.

Reviews of other agents' experiments live in `reviews/<agent>/`. They load the reviewed code by path, as the thing under test only; expected results are A6's (GT-HAND). A4 (PR #4 at `74ae579`): `ser_alignment_cases.py`, `relp_ack_variants.py` (needs `rsyslog` and `rsyslog-relp`), `goose_seq_cases.py`. See R-A4-1 to R-A4-4 in `docs/phase0/A6-cross-review.md`.
