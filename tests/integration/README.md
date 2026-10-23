# Integration tests

Owner: A6. Independent end-to-end and cross-module verification of the criteria in [docs/verification.md](../../docs/verification.md). No integration tests exist yet; there is no product code.

## Experiments

Phase 0 experiments that challenge assumptions before contracts are approved. Each prints a JSON report; committed results are under `experiments/results/`.

| ID | Script | Question | Result |
| --- | --- | --- | --- |
| E-01 | [syslog_tls_delivery_gap.py](experiments/syslog_tls_delivery_gap.py) | Does an error-free write to an RFC 5425 collector mean the message was delivered? | No. 100 of 150 frames lost silently in 5 of 5 trials (`simulated`). See finding F-001. |

Run: `python3 -I tests/integration/experiments/syslog_tls_delivery_gap.py` (standard library plus the `openssl` CLI).
