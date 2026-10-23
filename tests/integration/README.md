# Integration tests

Owner: A6. Independent end-to-end and cross-module verification of the criteria in [docs/verification.md](../../docs/verification.md). No integration tests exist yet; there is no product code.

## Experiments

Phase 0 experiments that challenge assumptions before contracts are approved. Each prints a JSON report; committed results are under `experiments/results/`.

| ID | Script | Question | Result |
| --- | --- | --- | --- |
| E-03 | [store_restart_while_full.py](experiments/store_restart_while_full.py) | After a crash at full disk, can a restarted process read and prune the SQLite store? | Reads and integrity OK, pruning fails without freed space, 6/6 trials (`simulated`). See F-004. |
| E-02 | [fsync_before_ack.py](experiments/fsync_before_ack.py) | Does A5's writer fsync before each acknowledgement? | `NORMAL`: 1,011 of 1,016 acks unsynced; `FULL`: 0 of 680 (`simulated`). See F-004. |
| E-01 | [syslog_tls_delivery_gap.py](experiments/syslog_tls_delivery_gap.py) | Does an error-free write to an RFC 5425 collector mean the message was delivered? | No. 100 of 150 frames lost silently in 5 of 5 trials (`simulated`). See finding F-001. |

Run: `python3 -I tests/integration/experiments/<script>`. E-01 needs the `openssl` CLI; E-02 needs `strace` and A5's `p0` binary as its argument; E-03 needs root to mount tmpfs.
