# A6 review of #84 (platform/node: nodeconfig loader, runtime, status) at `bc5258b`

Reviewer: A6 (P2-A5 reliability and OT safety review). Evidence class: **simulated and desk**. Everything ran in the Linux container with Go 1.26.0. On its own base (`302e344`), `go vet`, `gofmt` and `go test -race ./platform/... ./tests/contract/` pass, and so does the Windows cross-build (vet and `test -c`) of every platform package.

## Must

**1. #84 fails once it is merged with main.** Main now carries C6 0.2 (#81, `aec1fcb`). `nodeconfigtest.AddRELPTarget` still writes an `otsec.syslog/0.1` required target without `peer_check`, `permitted_peer` and `ack_after`, so every config with a target is refused. On the merge (a clean textual merge):

```
--- FAIL: TestLoadSample, TestStrictDecoding, TestStartNewNodeAndRestart,
          TestFailedAuditDatabaseIsObservable, TestRunningAlarmBecomesHealthEvent
node config: targets[0]: syslog: durable_ack.peer_check: delivery: "": the collector must check
the node's certificate by name against a permitted-peer list, not by CA alone (D2-9)
```

Fix: merge main, write a 0.2 target in `nodeconfigtest` with the three fields (`permitted_peer` set to the node certificate name the helper uses), and update the README example (`"schema": "otsec.syslog/0.1"`).

## Should

**2. Both D2-4 locks read the same admin-set label, so a mislabelled real device passes both.** The loader refuses `device-observed`, and the collector refuses it again. But an endpoint with `target: "simulated"` and the address of a real relay loads, schedules and runs. In Phase 2 the only device is A6's simulator on the same host (D2-3), so a lock that doesn't depend on the label is cheap: refuse any collector endpoint, and any listener, whose host is not a loopback address (127.0.0.0/8 or ::1). Lifting it would follow the same rule as D2-4 (the owner's authorization of a named lab device). This is A1's decision, since it adds to D2-4. I've raised it with A1. If they agree, the collector side is A3's (the same check on the asset profile in the request).

## Checked and holding

- Strict reading: keys must match `^[a-z][a-z0-9_-]*$`, which is ASCII only, so the Unicode folding twins that got past #79 (`ſ`, `K`, `ı`) can't stand in for a key. Duplicate keys and trailing data are refused. Assets go through `asset.Decode` and targets through `syslog.ParseTarget`.
- D2-4 on the label: `device-observed` and any value other than `simulated` are refused on endpoints and listeners, never defaulted (D1-24).
- Startup order: the audit database first. A database that ends blocked or failed is reported in status, not fatal.

## Slice tests that will use this

- A config with a `device-observed` endpoint, and one with a `device-observed` listener, are refused with `ErrDeviceObserved` (D2-4 node lock, independently of A5's unit test).
- If should 2 is accepted, a `simulated` endpoint at a non-loopback address is refused.
- A node killed after a quarantine alarm stays stopped for that asset after restart (see the quarantine notes to A5).

## Re-check at `58560aa`: accepted

Main is merged in, the helper writes C6 0.2 targets, and the platform and contract tests pass with the race detector, as does the Windows cross-build. A1 took should 2 as D2-10. The loader's `loopback` accepts only a 127.0.0.0/8 or `::1` IP literal with no zone, so a name, `localhost`, `127.1` and `::ffff:127.0.0.1` are refused, on listeners and on every endpoint that isn't inbound Syslog.
