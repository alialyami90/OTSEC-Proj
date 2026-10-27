# A4: Syslog receive (P3-A4)

- **Packages:** `modules/telemetry/receive` (the listener) and `modules/telemetry/normalize` (`Syslog`, the parser and event builder). The rules are in the two package docs; this note covers the seams, the acceptance mapping and what was tested.
- **Evidence class:** `simulated`. Every sender is a test process on 127.0.0.1 or 127.0.0.2. No device was contacted. The only device-shaped messages are A2's documented examples: RTAC (S23 p. 636), SEL-2488 (S26 p. D.2) and SEL-2730M (S43 p. 126). Each is `documented-example`, not device output.

## What it does

`New(Config)` checks one listener: one C1 Syslog transport, an IP-literal `ip:port`, the listener's target, its sender table, a C5 `Appender`, a health sink and a clock. `Listen` binds it. `Serve` receives until its context ends, then gives queued messages `Limits.Grace` to commit. `Close` releases a bound listener that will not be served (A5, for a node that cannot start all its listeners).

- **syslog-tls (RFC 5425).** `ServerTLS` builds the configuration from the listener certificate and an optional CA set for senders. It refuses a listener certificate outside its validity period with `ErrCertificatePeriod`, wrapped with `ErrConfig` (HR-13). A sender that presents a certificate must chain to that set, and a listener can require one. Events say `tls-mutual` or `tls-server-only`. A `tls-mutual` event also names the verified sender certificate by its SHA-256 (C4 0.2, `source.sender.tls_leaf_sha256`), without raising the binding's confidence.
- **syslog-tcp (RFC 6587) and syslog-udp (RFC 5426).** These run only with `Config.Plaintext`: plaintext is enabled per listener by the operator, and TLS is the default (owner decision D3-5). Their events say `none`.
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
| A5 (node) | For each configured listener, the node builds a `Config`: `ID`, `Transport`, `Address` and `Target` from the listener entry; `Stream` = `ListenerStream(id)`; `Senders` = `SendersFor(assets, transport, port)`; `Log` = a wrapper over the syslog database's `Log` that fails while that database is not open; `Health` = the forwarder's `healthSink` (same `Emit` signature); `Received` = the runtime's `received()`. `Plaintext` comes from the listener's per-listener plaintext setting (D3-5), and health shows a plaintext listener. `otsec health` shows `Status`: `Open`, `LastMessage`, `Received`/`Stored`, `Dropped`, `Refused`, `Held`, `UnknownSenders`, `LastErr`. | Wired in #154 (A5), seam accepted. |
| A5 (configuration) | A TLS listener needs references the listener entry lacks: the listener's certificate and key, an optional CA set for senders, and whether a sender certificate is required. They resolve through the same path as the target references: the D2-12 interim files in `tls_dir`, then A3's key store (P3-A3). | Done in #154 (`credential_ref`, `sender_ca_ref`, `require_sender_cert`). |
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
| `ReadBuffer` (UDP `SO_RCVBUF`, 4 KiB to 256 MiB) | 0, the OS default | A datagram that arrives while the socket buffer is full is lost before the read, counted only by the OS (see Known limits). `Status.ReadBuffer` is the size granted. |
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
| End to end on the real binaries, `otsec health` per listener | A5 wired the listeners and the health line in #154 (`TestHealthShowsListeners`). The run on the real binaries is A6's and has not been done. |

Mutation check: 45 mutants, one for each check in the parser, the framer, the limiter, TLS, attribution, the unknown-sender table, the storage paths, and (after A3's review) the unknown connection limit, idle timeout, budget, budget alarm and their configuration checks. All 45 are killed. Three survived the first round; `TestSyslogRTACOtherMessage` and `TestTLSOptionalClient` were added for them.

## Known limits

- **No acknowledgement on RFC 5425 or RFC 6587.** Messages queued in memory are lost without the sender knowing if they are not committed within `Grace` of a stop. That is at most 2 × `Queue` + 1 messages per connection: the batch being committed (capped at `Queue`), the queue behind it, and the frame being read. A6 measured 130 with `Queue` 64 before the batch was capped; `TestStreamStopLoss` pins the bound. RELP receive would close this; it is not built.
- **Duplicates are kept, not removed.** A device can send the same bytes on purpose, such as a repeating alarm (R4.8 will count those).
- **The unknown budget is per window, not in all.** Over an upstream outage of T, unknown senders can store up to `UnknownBytes` × (1 + T / `UnknownWindow`): 25 MiB in a day at the defaults. Restarts add nothing once the node passes `Config.UnknownSpent`, the bytes unknown senders stored on the stream in the window before the start: the budget starts that much short (A3, D3-3). Each unknown message is charged as it is read, just after its received time is stamped, at its length with the widest seq the store can write, so the count by received time matches the charge and what is stored never exceeds it. When the charge was taken in the writer instead, a record read before the window and committed inside it fell out of the count, and on a slow store each restart over-granted by about one queue lag's worth (A6, `TestUnknownSpentAcrossRestarts` on Windows: 77 to 107 KB over a 512 KiB budget; fixed in the PR after #178). The node passes it since #198: at start, `unknownSpent` (`platform/node/unknownspent.go`) reads the listener's stream and sums the stored length of `asset-unresolved` records whose received time is inside the window, later, or does not parse, so neither a clock set back nor a damaged time hands out a fresh budget. The bound depends on that count. When the stream cannot be read, the budget starts empty and the node raises `syslog-unknown-budget-uncounted` (fail closed). A stream missing records under-counts, which fails open. A separate C5 stream and quota for unknown senders would bound it absolutely. That needs a C5 class and a layout change, so it is not built: A1 deferred it for Phase 3. A3 holds it as a condition before any device-observed listener: either unknown senders get their own C5 stream and quota, or the node refuses a syslog quota too small for listeners × `UnknownBytes` × the planned outage, and health shows the unknown share.
- **`Grace` bounds the writers, not `Serve`'s return.** After `Grace`, a writer stops trying, and its next `AppendBatch` fails at once on the cancelled context. A batch the store has already queued is still waited for: `c5.Log.AppendBatch` does not check the context once its group is queued, and groups of one stream commit in order. So `Serve` can return later than `Grace` by the commits queued on the stream when it ended, at most one per writer, which is one per connection (B4's review of #232). The syslogreceive rig reports when `Serve` actually returned (#232), and #241 times the store flushes behind it.
- **A message whose record cannot be built** (a fault in this package) is dropped alone, counted as `store`; the rest of its batch is stored. No test can reach that path, because `normalize.Syslog` builds an event for any bytes.
- **Attribution is by address.** That is spoofable on UDP and TCP, and on TLS until C1 pinned keys exist. A relay's address names the relay.
- **UDP loss before the read is not counted.** One socket serves every sender, and the listener leaves `SO_RCVBUF` at the OS default unless `Limits.ReadBuffer` asks for a size (4 KiB to 256 MiB). `Status.ReadBuffer` is the size the OS granted, read back after `Listen`: Linux doubles a request and caps it at `net.core.rmem_max`, so a larger request may be granted less, and `TestReadBufferGranted` checks only that a request changes the size. A larger buffer absorbs a longer stall; it does not remove the loss. A datagram the kernel drops because the buffer is full, when the read loop gets no CPU, never reaches `ReadFrom`, so no drop count sees it. Only the OS counters do (Linux `RcvbufErrors`, Windows `netstat -s`). The read loop itself never waits on the store: a full queue is a counted `queue-full` drop. Where loss matters, use TCP or TLS: UDP gives no delivery guarantee (RFC 5426). A6 saw this on a loaded Windows runner (job 121917868556, 14 of 15 from a well-behaved sender), and `TestDatagramFloodIsCountedAndIsolated` (#191) now requires every datagram read to be stored or counted, allowing a shortfall only by datagrams that were never read. That was the Phase 4 backlog item (A1). Setting it from the listener configuration and showing the granted size in health is the node half, B5's.
- **The SEL-2488 UTC offset.** S26 says its time stamps carry one, but the only wire example has none (A2, #149). The parser reads the example as RFC 3164 with a year and states no offset. A message with an offset in an unexpected place keeps its bytes and its header text, and is partial if the header no longer parses.
- **The SEL-2730M sample** does not match the switch's own event table (A2). The golden pins only how the bytes are read, not what a real 2730M sends.
- **RTAC firmware time stamps.** RTAC firmware before R150-V8, R151-V6, R152-V2 and R153-V0 may send an incorrect time stamp (S23 Table A.1, noted in the C1 `sel-rtac-syslog` profile). Syslog does not carry the firmware, so an RTAC event's `device_time` cannot be qualified per message (A2's review).
- **An offset-looking token after the time** (`-07:00`, `+03`, `Z`) is not read as the host. The message is partial and its subject unset, because where the SEL-2488 puts its offset on the wire is unknown (D24). An offset glued to the time (`08:17:29-07`) also makes it partial.
- **The RTAC `message` field** holds the Log Message and, when one is set, the Logging Comment (S23 Table 8.16). They are not delimited safely, so they are not split. The example's tag carries a space as printed (`SystemTags. User_Logged_On`); a rule keyed on the tag should not depend on it until a capture exists.
- **An RTAC message over 1024 bytes is not read as an RTAC Logger message.** The RTAC sends RFC 3164 with a 1024-byte packet limit (S23 Section 8, p. 635, A2's transcription; RFC 3164 section 4.1 counts PRI and HEADER in it). A longer one keeps its bytes and its whole MSG, its subject is the host, and it is partial. Without this bound, the RTAC reading copied one frame's text into four fields and two normalized values: an 8089-byte frame of `<` in the tag was stored as 156461 bytes, against the node's bound of 69632 bytes per record (`HeldBatchBytes`, #169). `TestSyslogSizeBounds` pins both of the node's bounds on hostile frames: at most 8 × 8192 + 4 KiB stored, and at most 22528 octets rendered whole.
- **A year-less RFC 3164 time** takes the year nearest the receive time and says so (`year-absent`, `year-assumed`).

## Files

- `modules/telemetry/receive/`: `doc.go`, `receive.go`, `stream.go`, `datagram.go`, `frame.go`, `limit.go`, `senders.go`, `tls.go`, and their tests.
- `modules/telemetry/normalize/`: `syslog.go`, `syslog_test.go`, `syslog_sel_test.go`, `testdata/syslog/` (three goldens), `doc.go`. In `time.go`, the wall-clock step is factored out as `setWall` and shared with the SER path, with no change to SER output (the SER goldens are unchanged).
- `docs/phase3/A4-syslog-receive.md` (this note).

## Handoff (P3-A4)

**Completed.**
- The listener and the parser: #150, merged. A5 wired them into the node and `otsec health` in #154.
- C4 0.2: a mutual-TLS event names the sender's certificate in `source.sender.tls_leaf_sha256`, the SHA-256 of the verified leaf (#167).
- C6 0.3: the forwarder carries that fingerprint upstream as `tlsleaf`, after `sender`.
- Parse goldens for the three documented SEL examples: RTAC, SEL-2488 and SEL-2730M.

**Evidence.** The evidence class is `simulated` throughout. Every sender is a test process on loopback, and no device was contacted.
- Go tests run in CI on Linux and Windows, with `-race`. The acceptance table above maps each brief item to its tests.
- 45 mutants of the receive checks are all killed.
- `TestStreamStopLoss` pins the stop-loss bound at 2 × `Queue` + 1.
- For C6 0.3, `TestTLSLeafSizeBoundary` finds the size threshold by trying every record length on a 2048-octet target:
  - at the threshold the message is exactly 2048 octets and keeps its text;
  - one octet more omits the text;
  - the threshold moves by exactly the 75 octets of `tlsleaf`;
  - `tlsleaf` survives the omission.

  Removing the parameter, or dropping it with the text, fails the tests.
- Reviews of #150: A3 accepted after F1 and F2; A6 passed it after the stop-loss fix. On #167, A3 accepted and A1 reviewed. A6's independent pass on C6 0.3 is pending; A1 made it a condition.

**Interfaces.**
- `receive`: `Config`, `Limits`, `Status`, `Listen`, `Serve` and `Close`, as A5 uses them in #154.
- `normalize.Syslog`: `SyslogInput.SenderCert` is the verified leaf's DER bytes. It is required with `tls-mutual` and refused without it.
- C4 0.2 adds `source.sender.tls_leaf_sha256`. It is required on a tls-mutual event from 0.2, forbidden otherwise, and forbidden before 0.2. Readers of 0.1 read 0.2 through `strictjson.Forward`.
- C6 0.3 adds `tlsleaf`. A target stamped 0.3 means the same as one stamped 0.2. `ParseMessage` keeps every parameter, so a 0.2 reader is unaffected.

**Limitations.**
- Everything under Known limits above still holds.
- The fingerprint says which certificate authenticated the sender. It does not bind the asset: attribution stays `sender-address`/`configured` until C1 has pinned keys.
- No end-to-end run of received Syslog on the real binaries yet.
- No RELP receive, so the stop-loss window remains.

**Risks.**
- The listener is an inbound surface on the site node (A3's review of #150).
- The unknown-sender budget is per window, not in all: HR-11 (D3-3). A3 holds a condition before any device-observed listener.
- Plaintext receive is per listener and operator-enabled: HR-12 (D3-5). Its events say `none`, and its attribution can be spoofed.
- A collector rule that reads `tlsleaf` as the device's identity would over-trust it.

**Dependencies.**
- A6: received Syslog end to end on the real binaries (V-S8 for this origin), and the independent pass on C6 0.3.
- A5: set `UnknownBytes` from the syslog class quota and the outage the node must ride out.
- Upgrade order: collectors upgrade before nodes, as C6 requires.
- Next for A4: the `DATE_F` read, after A2's adapter PR merges.

**Files.**
- `modules/telemetry/receive/` and `modules/telemetry/normalize/`, as listed under Files above.
- `contracts/event/`: C4 0.2, #167.
- `contracts/syslog/`: C6 0.3, this PR. That covers `render.go`, `target.go`, `doc.go`, `audit.go`, `schema/target.json`, `syslog_test.go`, `testdata/NOTES.md` and `testdata/rendered/`.
- `contracts/README.md` and this note.
