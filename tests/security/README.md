# Security tests

Owner: A6. Independent security-boundary tests for the criteria in [docs/verification.md](../../docs/verification.md): V-S5 (monitoring cannot reach state-changing operations), V-S11 (credential canaries), V-S14 (identity mismatch fails closed), V-S15 (hostile device output), and R2.x for engineering access.

## Tests

- `lockdown_test.go`: the node loader's D2-10 lock (lock 1 of 2) and D2-4 on loopback. Ground truth is the rule text of D2-10 and D2-4, not the implementation. IP literals that are not loopback, or are loopback in a refused form (IPv4-mapped, zoned), must fail with `node.ErrNotLoopback`. Names, `localhost` included, shortened or numeric IPv4 forms, brackets, ports and spaces must not load at all. A device-observed endpoint is refused even on loopback. Mutation check: disabling the endpoint check, the listener check, the zone rule or the IPv4-mapped rule, or allowing device-observed, each fails at least one test. Class `simulated`. Nothing opens a connection.
- Lock 2 (the collector's own D2-10 check) gets its test when A3's check lands: a run request for an asset whose endpoint is not loopback must be refused before any dial, with a listener on a non-loopback address of the test host that records zero connections.

The V-S5, V-S11, V-S14 and V-S15 tests follow as the collector (A3) and the session adapter (A2) land.

## Reviews

- [reviews/A3-E1/](reviews/A3-E1/): independent reproduction of A3's experiment E1 (SSH gateway controls) with three extra probes: T9 (kill is not revocation), T10 (`ssh -W` to an unapproved device), T11 (sftp subsystem). Apply `a6-extra-probes.patch` to `modules/access/experiments/e1-ssh-forward-controls/run.sh` from A3's branch and run as root. Class `simulated`.
