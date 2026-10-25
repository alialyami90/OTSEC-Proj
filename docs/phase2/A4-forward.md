# A4: Syslog forwarder (P2-A4, part 2)

- **Package:** `modules/telemetry/forward`, with the test receiver in `modules/telemetry/forward/relptest`. The rules are in the package doc (`doc.go`); this note covers the seams and what was tested.
- **Evidence class:** `simulated`. No device and no production collector was contacted. The collector in the tests is either the Go test receiver or a local rsyslogd 8.2312.0 with librelp 1.11.0 running in the container, both on 127.0.0.1 with throwaway keys made by the test. The only device-shaped record is C4's documented example (Figure 10.16 row 8), read from `contracts/event/testdata`.

## What it does

`New(Config)` takes one C6 target (mode A: `relp-tls`, or lab-only plain `relp`), the C5 streams it carries, a dial function and a health sink. `Run` keeps one RELP session open. Each session does the following:

1. It loads the target's cursors, sends `open`, and requires the collector to offer `relp_version=0` and `commands=syslog`.
2. It reads each stream after its cursor, renders each record with C6 `Render` (or `RenderAudit` for the audit stream), and keeps up to `relp_window` transactions in flight.
3. It saves a stream's cursor with C5 `SaveCursor` only when C6 `Window` says every transaction up to it has a 200 OK.

Any failure ends the session, and the next session resends everything after the saved cursors.

`ClientTLS` builds the only TLS configuration used for `relp-tls`:

- TLS 1.2 or later;
- the target's own trust anchors, never the system roots;
- the collector's name checked against `tls.server_name`;
- SPKI pins when the target has them;
- the node's client certificate, which is always sent.

For a required target, the client certificate must carry `durable_ack.permitted_peer` as its CN or as one of its DNS names (A3 #81 S-2). The certificate must also be for client authentication and valid at load (A3 #89). `DialTLS` and `DialTCP` turn a target into a `Config.Dial`.

## Seams

| With | What | State |
| --- | --- | --- |
| A5 (node, `cmd/otsec`) | The node builds a `Forwarder` for each target, using `syslog.Consumers` for the C5 consumers. It hands over each stream's `Outbox` and `CursorStore` (the audit stream from its own database) and a `HealthSink`. The sink commits the pending C4 health event on the health stream and returns its key once the commit has returned. It resolves `trust_anchor_ref` and `client_credential_ref` and calls `ClientTLS` at load, so a target whose `permitted_peer` is not the node's name fails to load. It shows `Status` and raises `forward.unreachable` for a required target from `Status.LastConfirmed` and `Status.Open` (zero while no session is open, so a quiet target is told from a down one). | Built here; wiring is A5's. |
| A5 (C5) | The forwarder relies on four store behaviours: `SaveCursor` returns after a full commit; it refuses a regress and an ahead; `Read` past the prune point returns the first retained events; `LoadCursors` reads the database. A best-effort target also uses `CommitIndex.LastCommittedBy` for its window start. The unit tests use an in-memory store with these behaviours (`helpers_test.go`). | A6 ran the forwarder over the real `platform/store` in the #89 review (clean, close, serverclose, a 500, a restart, a TXNR rollover): no loss, and the cursor ended at the last seq. |
| A6 (slice) | A6's receiver (`tests/integration/slice/relp_receiver.py`, #76) is the oracle for the Windows leg, and rsyslog is the oracle for the Linux leg. The two differ on the client name: A6's receiver reads the SAN, or the CN when there is no SAN, while librelp also matches the CN when a SAN is present (A6's finding). The forwarder accepts `permitted_peer` as the CN or a SAN, so it works with both. | A6 accepted my review of the receiver at c00acce. |
| C6 | `PermittedPeer` now says what the name check rests on: the trust anchor must issue no certificate carrying the node's name, as CN or SAN, to anyone else (A6's librelp finding). The change is to the doc comment only; no rule changed. | In this PR. |

## Known limits

- **Repeats after a restart.** `forward.too-large`, `forward.text-omitted` and `forward.unreachable` are raised once per process for the event or range they name, however many sessions delivery takes (A6). A node restart before the target passes the event raises it once more: a duplicate alarm, never a lost one.
- **A hold without a release rule** stops its stream until someone acts. That covers an audit record `RenderAudit` refuses, a record that does not decode or render, a `forward.*` event that is itself too large, and a too-large event on the health stream. `Status.Streams[...].Blocked` says why.
- **Mode B** (RFC 5425, TCP, UDP) is not built. The Phase 2 slice uses `relp-tls` only.

## Tests (container, Linux, go1.26.0; Windows cross-build per D2-8)

| Test | Shows |
| --- | --- |
| `TestForwardsEveryEventOnce` | 100 events plus health: one connection, each eid once, oldest first, C6 0.2 rendering with `evc`. |
| `TestReceiverClosesMidBatch` | **P2-A4 acceptance.** The receiver drops the connection at frame 1, 5, 37 or 99, and again 40 frames later. Every event is acknowledged. Each new connection starts no later than the event after the highest one already acknowledged, and runs without a gap. Duplicates are at most one window per close. |
| `TestSessionEndsAndResends` | A 500, a serverclose, silence past the response timeout, and an answer given twice (a C6 violation) each end the session, and everything is delivered after reconnecting. A 500 names the refused event in `Status.LastErr`, so a collector that refuses the same event every session can be found (A2). |
| `TestRefusedReportDoesNotStall` | A HealthSink that refuses (a health stream at quota) does not stop forwarding: the events are sent, `Status.Unreported` counts the reports, and they are committed once the sink accepts. |
| `TestRefusedReportsSummarised` | Past the owed limit, refused reports are counted per type and committed as one summary event. |
| `TestTooLargeReportRefused` | A too-large event whose report is refused holds only its own stream; the others drain, and it is released once the report is committed and confirmed. |
| `TestStatusOpen` | `Status.Open` is set while an idle session is open and cleared when the collector goes away. |
| `TestOpenNeedsRELPVersion0` | An open answered without `relp_version=0` is refused (A2). |
| `TestSessionChecksOpenAnswer` | An open answered with a 500, or without `commands=syslog`, ends the session at the open, and no syslog frame reaches the collector (A6). |
| `TestTooLargeWaitsForConfirmation`, `TestTextOmittedOncePerProcess` | A collector that refuses every `forward.too-large` keeps the held stream at cursor 0 over four sessions, never receives the event after it, and the event is reported once. `forward.text-omitted` is raised once per event across sessions (A6). Both fail if the confirmation check or the once-per-process sets are removed. |
| `TestCursorOnlyOnAck` | A collector that acknowledges 5 and then goes silent leaves the cursor at 5 across three sessions. No save past 5 is ever made. |
| `TestResumesFromSavedCursor`, `TestSkippedRangeReported` | Resume at cursor+1. A pruned range is reported as `forward.unreachable` (11-20) and forwarded. |
| `TestTextOmitted`, `TestTooLargeHeldThenPassed`, `TestUnrenderableHolds` | The C6 size rules, and holds that never skip. |
| `TestLastTXNRReopens` | At the last TXNR the session drains, sends `close` and reopens, with no duplicates. |
| `TestBestEffortStartsAtWindow` | A new best-effort target (lab-only plain `relp`, one-hour window) starts at the first event committed in its window: of 15 events, the 10 committed two hours ago are not sent, and nothing is reported as skipped. Each event stream of a best-effort target needs a C5 `CommitIndex` (`Stream.Index`). (A6 #89 nit.) |
| `TestClientTLSChecksLeaf` | At load, the node's client certificate must be for client authentication (an EKU naming it, `any`, or none) and valid now; serverAuth-only, expired and not-yet-valid certificates are refused with the reason (A3 #89). |
| `TestNewRefuses`, `TestClientTLSRefuses`, `TestTLSPeerChecks`, `TestDialTCPOnlyForPlainRELP` | Configuration refusals. Against a TLS collector, the forwarder refuses: the wrong name; another CA; a certificate without serverAuth; TLS below 1.2; a pin mismatch. The collector refuses the node when it permits another name. |
| `TestRsyslogExactlyOnce` | **P2-A4 acceptance, local rsyslog.** 500 events through imrelp over TLS with `tls.authmode="name"`, one permitted peer, a Direct ruleset queue and omfile `sync="on"`: the file holds every eid exactly once, in order. |
| `TestRsyslogKilledMidStream` | rsyslogd is killed with SIGKILL once about 1,000 of 3,000 events are confirmed, then restarted. Every event confirmed before the kill is in the file, and every event arrives. Three runs gave 4 to 6 duplicates, within one window of 8. |
| `TestRsyslogRefusesAnotherNode` | A CA-signed certificate for `site-b-node1` is refused by rsyslog permitting `site-a-node1`. Nothing is written, and the cursor stays at 0. |
| `FuzzCollectorBytes` | A collector that sends arbitrary bytes after the open never moves a cursor further than the number of `200 OK` answers it sent, and the session always ends on its own. 60 s, about 40,000 runs, no failure. |
| `relptest`: `TestParseCommand`, `FuzzParseCommand` | The receiver's client-frame grammar, and that a parsed frame re-encodes to exactly its bytes. 60 s, about 4.7 million runs, no failure. |

The rsyslog tests skip when `rsyslogd` with `imrelp` is not installed. With `OTSEC_RSYSLOG_REQUIRED=1` they fail instead, which the integration job can set.
