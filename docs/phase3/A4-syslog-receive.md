# A4: Syslog receive (P3-A4)

- **Packages:** `modules/telemetry/receive` (the listener) and `modules/telemetry/normalize` (`Syslog`, the parser and event builder). The rules are in the two package docs; this note covers the seams, the acceptance mapping and what was tested.
- **Evidence class:** `simulated`. Every sender is a test process on 127.0.0.1 or 127.0.0.2. No device was contacted. The only device-shaped messages are A2's documented examples: RTAC (S23 p. 636), SEL-2488 (S26 p. D.2) and SEL-2730M (S43 p. 126). Each is `documented-example`, not device output.

## What it does

`New(Config)` checks one listener: one C1 Syslog transport, an IP-literal `ip:port`, the listener's target, its sender table, a C5 `Appender`, a health sink and a clock. `Listen` binds it. `Serve` receives until its context ends, then gives queued messages `Limits.Grace` to commit. `Close` releases a bound listener that will not be served (A5, for a node that cannot start all its listeners).

- **syslog-tls (RFC 5425).** `ServerTLS` builds the configuration from the listener certificate and an optional CA set for senders. A sender that presents a certificate must chain to that set, and a listener can require one. Events say `tls-mutual` or `tls-server-only`.
- **syslog-tcp (RFC 6587) and syslog-udp (RFC 5426).** These run only with `Config.Plaintext`, the lab-only flag, until the owner decides on plaintext Syslog. Their events say `none`.
- **One message, one record.** Its bytes are kept exactly: `native.bytes`, with `record_sha256` and `evidence.sha256` both equal to the SHA-256 of the bytes received. A message that does not parse is still stored, with `parse_status` `failed`.
- **Framing faults keep their bytes.** A frame is flagged `frame-truncated` when it is cut short, too long, or stalls. It is flagged `frame-invalid` when it is misframed.
- **Attribution.** The sender address is looked up in the C1 inbound endpoints (`SendersFor`).
  - A known sender is the subject, bound by `sender-address` with confidence `configured`.
  - An unknown sender's message is stored with `asset-unresolved`. The first message from each unknown address raises `syslog.unknown-source`.
- **Unknown senders cannot displace configured devices** (A3's F1 and F2). Together they hold at most 16 stream connections, and an idle one is closed after 30 s. Together they may store at most `UnknownBytes` of records per `UnknownWindow` (1 MiB per hour by default). Past that, their messages are dropped and counted as `unknown-budget`, and `syslog.unknown-budget` is raised at most once per window.
- **Rate limits per sender.** A stream over its rate is slowed. A datagram over its rate is dropped and counted.
- **Storage full.** A refused stream batch is held and retried (refuse-new). A refused datagram batch is dropped and counted (drop-and-count).

`normalize.Syslog` reads RFC 5424, RFC 3164, and the year-after-day header that all three SEL examples use. The RTAC dialect takes the event time from MSG, because the RTAC header time is the send time. The dialect comes from the asset's operator-declared `product_family` (`DialectOf`), never from the message.

## Seams

| With | What | State |
| --- | --- | --- |
| A5 (node) | For each configured listener, the node builds a `Config`: `ID`, `Transport`, `Address` and `Target` from the listener entry; `Stream` = `ListenerStream(id)`; `Senders` = `SendersFor(assets, transport, port)`; `Log` = a wrapper over the syslog database's `Log` that fails while that database is not open; `Health` = the forwarder's `healthSink` (same `Emit` signature); `Received` = the runtime's `received()`. `Plaintext` comes from a lab-only flag the node configuration does not have yet; the D2-10 loopback lock stays in the loader. `otsec health` shows `Status`: `Open`, `LastMessage`, `Received`/`Stored`, `Dropped`, `Refused`, `Held`, `UnknownSenders`, `LastErr`. | Not wired. A5's part of the brief. |
| A5 (configuration) | A TLS listener needs references the listener entry lacks: the listener's certificate and key, an optional CA set for senders, and whether a sender certificate is required. They should resolve through the same path as the target references: the D2-12 interim files under the lab flag, then A3's key store (P3-A3). | Proposal to A5 and A3. |
| A5 (C5) | The listener uses `AppendBatch` only. It expects `CodeQuotaReached` to mean nothing was written, and every other error to mean "not stored". It writes no captures: the message is in the event. | Matches C5 0.1. |
| A3 | The new inbound surface: TLS policy, the limits table below, the plaintext flag, and storage behaviour under flood. | F1 and F2 addressed; re-review requested. |
| A5 (sizing) | `UnknownBytes` bounds unattributed storage per window, not in all (see Known limits). The node should set it from the syslog class quota and the upstream outage it must ride out. | Proposal to A5. |
| A2 | The RFC 3164 year-after-day reading and the RTAC Logger split, against the three documented examples and A2's notes on #149 (the 2488 offset is not on the wire example; the 2730M sample contradicts its own table). | Review requested on the PR. |
| A6 (unknown senders) | An unknown sender's event keeps the listener's evidence class, as C4 says; it is not capped at `simulated`. A6 confirmed that `asset-unresolved` is enough, and will hold three invariants on every unresolved event: no asset is touched, it counts toward no per-asset or per-family claim, and it is kept whole and alarmed once per address. | Agreed with A6. |
| A6 | The acceptance tests in the brief (table below). For V-S8 on this origin, the oracle is the sender's own bytes: every stored `native.bytes` and `record_sha256` must equal what the test process sent, frame by frame. | A6's to write. |

### Limits (defaults)

| Limit | Default | What happens past it |
| --- | --- | --- |
| `MaxMessage` (stream frame) | 8192 | The first 8192 bytes are stored, flagged truncated. An octet count above the limit also closes the connection. Over-long line bytes are discarded and counted. |
| Datagram | 65507 (UDP) | Always kept whole. |
| `Rate`/`Burst` per sender | 100/s, 200 | A stream is slowed; a datagram is dropped as `rate-limit`. |
| `UnknownRate`/`UnknownBurst`, all unknown senders together | 400/s, 800 | The same, so many spoofed addresses cannot take a known sender's share. |
| `MaxConns` / `MaxConnsPerSource` | 64 / 4 | The connection is closed at accept (`Refused["limit"]`). |
| `MaxUnknownConns`, all unknown senders together | 16 (a quarter of `MaxConns` if less; always below it) | The connection is closed at accept (`Refused["unknown-limit"]`). The other connections stay free for configured devices. |
| `IdleTimeout` (`UnknownIdleTimeout` for an unknown sender) / `FrameTimeout` / `HandshakeTimeout` | 10 min (30 s) / 30 s / 10 s | The connection is closed. A partial frame is stored, flagged truncated. |
| `UnknownBytes` per `UnknownWindow`, all unknown senders together | 1 MiB per hour (at least 256 KiB) | The message is dropped as `unknown-budget`, on a stream too; `syslog.unknown-budget` at most once per window. A known sender's stream message is never dropped. |
| `Queue` (per connection / datagrams) | 64 / 1024 messages | A stream stops being read. A datagram is dropped as `queue-full`. |
| `MaxQueueBytes` (datagrams waiting) | 8 MiB | Dropped as `queue-full`. |
| `MaxSources` (rate-limiter table) | 4096 | A sender whose bucket has refilled is forgotten. |
| `MaxUnknown` (unknown-sender table) | 256 | One summary alarm is raised (`more_senders=true`); after that nothing more is remembered. |

## Acceptance (the brief's A6 tests) and where this PR covers them

| Brief | Covered here by |
| --- | --- |
| Raw bytes stored and hash-matching what the sender sent (V-S8) | `TestTLSMutual`, `TestHostileFraming`, `TestOctetCountLies`, `TestUDPKeepsWholeDatagram`; `checkKept` and `FuzzSyslog` (any bytes round-trip through the stored JSON) |
| Hostile framing never crashes or hangs, and never loses an earlier message | `TestHostileFraming` (over-long line, nested PRI, non-UTF-8, misframed count, empty lines), `TestOctetCountLies` (short and oversized counts), `TestFrameTimeout`, `TestFramerEdges`, `FuzzFramer`, `TestSyslogHostile` |
| A flood from one source is rate-limited without affecting another | `TestDatagramFloodIsolated`, `TestStreamFloodSlowed`, `TestDatagramUnknownShare`, `TestConnectionLimits` |
| Unknown senders cannot lock out or displace configured devices (A3 F1, F2) | `TestUnknownConnsReserved`, `TestUnknownIdleShort`, `TestUnknownBudgetDatagrams` (the store's quota is only 32 KiB above the budget, and a known sender's datagrams are still stored after the flood), `TestUnknownBudgetStream`, `TestUnknownBudgetAlarmRetried` |
| A TLS sender with the wrong anchor is refused | `TestTLSRefused` (client certificate from another CA; no certificate where one is required; sender trusting another CA), `TestTLSOptionalClient` |
| An unknown source is kept and alarmed | `TestUnknownSender`, `TestUnknownAlarmRetried`, `TestUnknownSendersBounded` |
| Duplicates from a retrying TCP sender are detectable by the raw hash and never dropped | `TestTLSMutual` (a repeated message is stored twice with equal `record_sha256`) |
| Storage full | `TestStreamQuotaHolds` (refuse-new, order kept), `TestDatagramQuotaDrops` (drop-and-count, reported), `TestDatagramQueueBytes`, `TestShutdownCommitsQueued` |
| End to end on the real binaries, `otsec health` per listener | Needs A5's wiring; not in this PR. |

Mutation check: 45 mutants, one for each check in the parser, the framer, the limiter, TLS, attribution, the unknown-sender table, the storage paths, and (after A3's review) the unknown connection limit, idle timeout, budget, budget alarm and their configuration checks. All 45 are killed. Three survived the first round; `TestSyslogRTACOtherMessage` and `TestTLSOptionalClient` were added for them.

## Known limits

- **No acknowledgement on RFC 5425 or RFC 6587.** Messages queued in memory are lost without the sender knowing if they are not committed within `Grace` of a stop. That is at most `Queue` messages per connection. RELP receive would close this; it is not built.
- **Duplicates are kept, not removed.** A device can send the same bytes on purpose, such as a repeating alarm (R4.8 will count those).
- **The unknown budget is per window, not in all.** Over an upstream outage of T, unknown senders can store up to `UnknownBytes` × (1 + T / `UnknownWindow`): 25 MiB in a day at the defaults. A separate C5 stream and quota for unknown senders would bound it absolutely. That needs a C5 class and a layout change, so it is not built.
- **A message whose record cannot be built** (a fault in this package) is dropped alone, counted as `store`; the rest of its batch is stored. No test can reach that path, because `normalize.Syslog` builds an event for any bytes.
- **Attribution is by address.** That is spoofable on UDP and TCP, and on TLS until C1 pinned keys exist. A relay's address names the relay.
- **The SEL-2488 UTC offset.** S26 says its time stamps carry one, but the only wire example has none (A2, #149). The parser reads the example as RFC 3164 with a year and states no offset. A message with an offset in an unexpected place keeps its bytes and its header text, and is partial if the header no longer parses.
- **The SEL-2730M sample** does not match the switch's own event table (A2). The golden pins only how the bytes are read, not what a real 2730M sends.
- **RTAC firmware time stamps.** RTAC firmware before R150-V8, R151-V6, R152-V2 and R153-V0 may send an incorrect time stamp (S23 Table A.1, noted in the C1 `sel-rtac-syslog` profile). Syslog does not carry the firmware, so an RTAC event's `device_time` cannot be qualified per message (A2's review).
- **An offset-looking token after the time** (`-07:00`, `+03`, `Z`) is not read as the host. The message is partial and its subject unset, because where the SEL-2488 puts its offset on the wire is unknown (D24). An offset glued to the time (`08:17:29-07`) also makes it partial.
- **The RTAC `message` field** holds the Log Message and, when one is set, the Logging Comment (S23 Table 8.16). They are not delimited safely, so they are not split. The example's tag carries a space as printed (`SystemTags. User_Logged_On`); a rule keyed on the tag should not depend on it until a capture exists.
- **A year-less RFC 3164 time** takes the year nearest the receive time and says so (`year-absent`, `year-assumed`).

## Files

- `modules/telemetry/receive/`: `doc.go`, `receive.go`, `stream.go`, `datagram.go`, `frame.go`, `limit.go`, `senders.go`, `tls.go`, and their tests.
- `modules/telemetry/normalize/`: `syslog.go`, `syslog_test.go`, `syslog_sel_test.go`, `testdata/syslog/` (three goldens), `doc.go`. In `time.go`, the wall-clock step is factored out as `setWall` and shared with the SER path, with no change to SER output (the SER goldens are unchanged).
- `docs/phase3/A4-syslog-receive.md` (this note).
