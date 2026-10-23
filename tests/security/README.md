# Security tests

Owner: A6. Independent security-boundary tests for the criteria in [docs/verification.md](../../docs/verification.md): V-S5 (monitoring cannot reach state-changing operations), V-S11 (credential canaries), V-S14 (identity mismatch fails closed), V-S15 (hostile device output), and R2.x for engineering access.

No tests exist yet. They depend on the authorization boundary and credential reference model from A3 (blockers B-04, B-05) and on the Phase 1 contracts.

## Reviews

- [reviews/A3-E1/](reviews/A3-E1/): independent reproduction of A3's experiment E1 (SSH gateway controls) with three extra probes: T9 (kill is not revocation), T10 (`ssh -W` to an unapproved device), T11 (sftp subsystem). Apply `a6-extra-probes.patch` to `modules/access/experiments/e1-ssh-forward-controls/run.sh` from A3's branch and run as root. Class `simulated`.
