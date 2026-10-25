# Security tests

Owner: A6. Independent security-boundary tests for the criteria in [docs/verification.md](../../docs/verification.md): V-S5 (monitoring cannot reach state-changing operations), V-S11 (credential canaries), V-S14 (identity mismatch fails closed), V-S15 (hostile device output), and R2.x for engineering access.

## Tests

- `lockdown_test.go`: the node loader's D2-10 lock (lock 1 of 2) and D2-4 on loopback. Ground truth is the rule text of D2-10 and D2-4, not the implementation. IP literals that are not loopback, or are loopback in a refused form (IPv4-mapped, zoned), must fail with `node.ErrNotLoopback`. Names, `localhost` included, shortened or numeric IPv4 forms, brackets, ports and spaces must not load at all. A device-observed endpoint is refused even on loopback. Mutation check: disabling the endpoint check, the listener check, the zone rule or the IPv4-mapped rule, or allowing device-observed, each fails at least one test. Class `simulated`. Nothing opens a connection.
- `collector_lock_test.go`: lock 2 of D2-10, the collector's own check (A3, #97), through `Pipeline.Handle` with a verified register active and a runner that dials. A run to these hosts must be refused `asset_not_enrolled` with a D2-10 detail, the runner must not be called, and listeners must record zero connections: this host's own non-loopback IPv4 address, `0.0.0.0`, `::`, `::ffff:127.0.0.1`, `10.0.0.5`, `192.168.1.10` and `2001:db8::1`. `localhost` and a zoned literal are refused earlier, by C1 at `NewPipeline`. A loopback control must be accepted and reach its listener. Mutation check: accepting any IPv4 in `loopbackLiteral`, or skipping the decision-time check, each fails it. Class `simulated`.

The V-S5, V-S11, V-S14 and V-S15 tests follow as the collector (A3) and the session adapter (A2) land.

## Reviews

- [reviews/A3-E1/](reviews/A3-E1/): independent reproduction of A3's experiment E1 (SSH gateway controls) with three extra probes: T9 (kill is not revocation), T10 (`ssh -W` to an unapproved device), T11 (sftp subsystem). Apply `a6-extra-probes.patch` to `modules/access/experiments/e1-ssh-forward-controls/run.sh` from A3's branch and run as root. Class `simulated`.
