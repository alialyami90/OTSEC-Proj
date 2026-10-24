# A6 review of #89 (modules/telemetry/forward) at `8baa19d`

Reviewer: A6 (P2-A4 delivery-accuracy review). Evidence class: **simulated and desk**. Everything ran in the Linux container with Go 1.26.0, rsyslogd 8.2312.0 and librelp 1.11.0. The native Windows run is owed. Nothing here touches a device: the forwarder reads the node's own store and writes only to a collector.

Verdict: **accept**, with three shoulds. No must.

## What I ran

- #89 is up to date with main at `04c9525`. `go vet ./...` and `gofmt -l .` are clean (empty output). `go test -race -count=1 ./modules/telemetry/... ./tests/contract/ ./contracts/syslog/` passes. The three `TestRsyslog*` tests ran against the real rsyslog and were not skipped. The D2-1 import test passes: the package imports only `contracts/...` and the standard library.
- Windows cross-build: `GOOS=windows go vet ./...` and `go test -c` for the package pass.
- The `contracts/syslog/target.go` change is doc-only. It adds the #76 librelp finding to the `PermittedPeer` comment.
- I read `doc.go`, `tls.go`, `forward.go`, `relptest` and the test helpers. Then I ran probes of my own (below). They are not in the repo.

## Probes: the forwarder over the real store, against the A6 receiver oracle

The PR's tests use an in-memory store. I wired the forwarder to `platform/store` (SQLite, real C5 startup, required consumer `siem-a`) and sent to `tests/integration/slice/relp_receiver.py` over mutual TLS with `--permitted-peer site-a-node1`. The oracle refuses any TXNR that does not start at 1 and strictly increase, a second open, an open without `commands=syslog`, and any frame before open. Each case committed 60 copies of row 8 plus one record on a `quarantine/sel751-feeder1` stream, which the forwarder is not given.

| Case | Result |
| --- | --- |
| Clean | All 60 confirmed once, 0 duplicates. Store cursor = last seq. No oracle violations. |
| `--close-after 7` | No loss, 4 duplicates (what was in flight). Cursor = last. |
| `--serverclose-after 23` | No loss, 4 duplicates. Cursor = last. |
| `--reject-after 11` (one 500) | No loss, 7 duplicates. Session ends on the 500, as C6 says. Cursor = last. |
| Forwarder stopped at cursor 10, 30 more committed, new forwarder | Resumes from the store's cursor, no loss, 7 duplicates (confirmed but not yet saved when stopped). |
| `maxTXNR = 9` | 8 sessions. Each open is TXNR 1, no syslog frame above TXNR 9, 0 duplicates. |
| Quarantine stream | Never sent in any case. |

So the core rules hold against the real store and an independent receiver. The cursor is saved only after the window confirms, nothing is skipped, and TXNRs follow C6.

## Mutation check of the PR's own tests

I disabled one rule at a time in `forward.go` and ran the package's tests (not my probes).

| Rule disabled | Caught by |
| --- | --- |
| Report a skipped range | `TestSkippedRangeReported` |
| Confirm through TXNR, not one before | 11 tests |
| Response timeout ends the session | `TestSessionEndsAndResends`, `TestCursorOnlyOnAck` |
| Report text-omitted | `TestTextOmitted` |
| Wait for in-flight transactions before the last-TXNR close | `TestLastTXNRReopens` |
| Release a too-large hold only after `forward.too-large` is confirmed | **nothing** (should 2) |
| Check the open answer through the window | **nothing** (should 3) |
| `inFlight(i)` in `release` | nothing, but this mutant is equivalent: see note 2 |

## Should

**1. Each new session raises another `forward.too-large` for the same held event.** The hold, its release key and the `omitted` set live in `session`, so a reconnect renders the held event again and commits a new health event. I tested with a collector that drops the session whenever a `forward.too-large` arrives (RetryMin 5 ms). It made 83 sessions in 2 s and committed 83 `forward.too-large` events for one held event. At the default RetryMax of 60 s, a collector that flaps while the event is held adds up to about 1,440 health events a day, each held for confirmation. The same applies to `forward.text-omitted` for an event resent after a reconnect, and to the `forward.unreachable` skipped-range report, which is raised again each session until a later event is confirmed. Please keep, in the `Forwarder`, the release key per held stream and seq, the omitted keys, and the reported skipped ranges, so one process raises each one once. One raise per process restart is fine.

**2. No test checks that a too-large event stays held until its `forward.too-large` is confirmed.** If the `s.saved[j] < h.release.Seq` check is removed, the held event is passed at once and every test still passes. `TestTooLargeHeldThenPassed` checks only the order of what arrives, and with a collector that accepts everything both orders look the same. A test that fails on that mutant: refuse (`relptest.Refuse`) every message carrying `htype="forward.too-large"`, run for 500 ms, then check that the held stream's cursor is still 0 and the next event on that stream was never sent. I ran this against the mutant and it fails as expected.

**3. No test checks that the open answer must offer `commands=syslog`.** If `open()` skips `s.win.Answer(r)`, every test still passes. `relptest` always answers open with the offer. Please add a `relptest` option to answer open without `commands=syslog` (and one that answers 500), and check that the session ends before any syslog frame is sent.

## Nits

**4. A new best-effort target starts at the first retained event, not the first event in its window.** C6 `doc.go` says "a new best-effort target starts at the first event in its window". `peek` starts any target with no cursor at the first retained event. This only matters for the lab-only plain RELP target in Phase 2, so it can wait, but the doc and the code should agree.

## Notes for the record

1. Quarantine: the forwarder sends only the streams the node gives it, so A5's rule that `quarantine/<asset_id>` has no consumer is enforced in the node wiring, not here. My probe confirms that a quarantine stream in the same database is never read. Once the quarantine stream name is in a contract, `New` could refuse it as defence in depth. That is a follow-up, not a blocker.
2. The `inFlight(i)` check in `release` cannot change behaviour today. The `forward.too-large` event is committed after every earlier event of the held stream was sent in the same session, and `Window` confirms only a contiguous prefix. So when it is confirmed, those earlier events are confirmed too. Keep the check: it states the rule.
3. My probes also showed that a confirmed transaction whose cursor was not saved before shutdown is sent again (7 duplicates on a stop at cursor 10). That is the at-least-once rule working as C6 says. Receivers remove duplicates by `eid`.
4. Owed on Windows: `go test ./modules/telemetry/forward/... ./contracts/syslog ./tests/contract/` at `8baa19d`. The `TestRsyslog*` tests should skip there.
