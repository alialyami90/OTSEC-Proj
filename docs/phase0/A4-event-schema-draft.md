# A4 draft: event schema, duplicate handling, and Syslog forwarding profile

- Task: P0-A4 deliverables (1), (2), (3). Findings and evidence for (4) and (5) are in [A4-telemetry-feasibility.md](A4-telemetry-feasibility.md).
- Author: A4 (Telemetry, Event Processing, and IDS Engineer). Date: 2026-10-23.
- Status: **draft, not a contract.** It becomes a contract only after Phase 1 review by A1, A2, A3, A5, and A6. Field names are proposals.
- Revised 2026-10-23 after the owner supplied SEL manuals and datasheets (SEL-751, SEL-400 series, SEL-311L, SEL-2488, others). Facts taken from them are `documented-untested`.
- Inputs used: A2 section 7 (SEL-751 SER, commit `9a84ef8`), A3 section 4.4 and AP-2/AP-9/AP-20, A5 outbox note, A6 C-04, C-05, C-06, C-08, C-13, V-S3, V-S4, V-S6, V-S8, V-S15, and A1's TB5 ruling.

## 1. Design rules the schema follows

| Rule | Source |
| --- | --- |
| The native record is kept byte-exact in the evidence store, persisted before parsing; events point to it by hash and byte span. Nothing is ever reconstructed from normalized fields. | R4.4, V-S8 |
| The device timestamp is kept as the native string or bytes, verbatim. Decoded values sit beside it, never in place of it. | C-05, V-S3 |
| No offset or precision is invented. A UTC value exists only when the offset is known and its basis is recorded. Decoded values carry no more digits than the declared resolution or accuracy. | C-05, V-S3 |
| Collector receive time is a separate field with the collector's own clock state. | C-05 |
| Time quality is carried with its scope (per record, per report, per stream), because formats differ: SEL gives a report-level "Time Source", IEC 61850 a per-value quality byte. | A2 section 7, section 3 below |
| Identity is not derived from content. `event_id` is assigned once, at first durable write, and never recomputed. | C-13 |
| `origin` (device or platform) is set by the collector and can never be parsed from device content. | AP-20 |
| Semantic normalization is optional and versioned. Unmapped means unmapped. | Q3 answer |
| Native-side loss indicators become platform events, never silent. | R4 "never silently discard", P5 |

## 2. Event record (draft v0.1)

```jsonc
{
  "schema": "otsec.event/0.1-draft",
  "event_id": "0192b7e0-…",            // UUIDv7, assigned at first durable write; stable for all re-forwarding
  "origin": "device",                   // "device" | "platform"; set by the collector, never from content
  "kind": "ser",                        // "ser" | "soe-log" | "device-log" | "syslog" | "host-event" | "device-status" | "protocol-event" | "telemetry-health" | "ids-alert"; open set (ADR-0006: all OT device classes)
  "source": {
    "asset_id": "…",                    // A1/A2 asset identity contract; the SUBJECT of the event
    "asset_binding": {"method": "adapter-target", "confidence": "configured"},   // R1.5; "asserted" when a relaying sender names the subject
    "sender": {"address": "…", "asset_id": "…"},   // who delivered the bytes; never copied into asset_id for relaying senders (A3 AP-22)
    "origin_auth": "session",           // A3 AP-22: "none" (UDP/TCP Syslog) | "tls-server-only" | "tls-mutual" | "session" (platform-initiated adapter read); unauthenticated events may alert but never drive automated actions
    "node_id": "site-a-node1",
    "stream_id": "…",                   // one native sequence space: asset + SER buffer, asset + log, syslog listener + sender
    "stream_seq": 18342                 // monotonic per (node, stream_id), assigned at durable write; A5's outbox position
  },
  "collection": {
    "method": "adapter",                // "adapter" | "syslog-receiver" | "passive-capture"
    "invocation_id": "…",               // A2 envelope; correlates audit (A3 4.4 correlation_id) and evidence
    "operation_id": "sel.ser.read_all",
    "parser": {"id": "sel-ascii-ser", "version": "0.1.0"},
    "native_position": 17,              // row index within the read, chronological order
    "alignment": "ok",                  // snapshot alignment result for the read (section 4)
    "parse_status": "ok"                // "ok" | "partial" | "failed" (failed still has raw evidence)
  },
  "received": {
    "utc": "2026-10-23T15:00:00.123456Z",
    "resolution_ns": 1000,
    "clock": {"sync": "synchronized", "source": "ntp", "scope": "node"}
  },
  "device_time": {
    "native": "02/28/2007 16:34:28.123",   // verbatim text, or hex of the wire bytes
    "native_encoding": "text",            // "text" | "hex"
    "format": "sel-ascii-ser-row",        // names the decoder, see section 3
    "wall_clock": "2007-02-28T16:34:28.123",  // decoded, no offset; null if undecodable
    "offset": "unknown",                  // "+00:00" | "-05:00" | "unknown"
    "offset_basis": "none",               // "format" | "device-config" | "site-config" | "none"
    "utc": null,                          // only when offset != "unknown"
    "resolution_ns": 1000000,             // resolution of the encoding or documented resolution
    "accuracy_ns": null,                  // declared accuracy if the format or time source gives one
    "quality": {"time_source": "Internal", "sync": "unknown", "scope": "report"},
    "flags": []                           // e.g. "dst-ambiguous", "two-digit-year:century-assumed-2000", "relative-to-cto"
  },
  "native": {
    "evidence": {"sha256": "…", "length": 4211, "store": "evidence://…"},   // whole transcript or datagram
    "span": {"offset": 1022, "length": 61},                                  // this record's bytes inside it
    "context": {"report_header_span": {"offset": 0, "length": 180}},          // header that applies to every row
    "alignment_key": "sha256:…",          // ring-buffer sources only: digest of the row bytes WITHOUT the row number (A6 R-A4-1); used only for snapshot alignment
    "fields": {"ELEMENT": "51P1P", "STATE": "Asserted"}   // verbatim strings, vendor names unchanged
  },
  "normalized": {
    "subject": "51P1P",
    "subject_type": "element",
    "value": {"native": "Asserted", "state": "asserted"},
    "category": "unmapped",              // only set from a versioned mapping table
    "mapping": null                       // {"id": "…", "version": "…"} when category is mapped
  },
  "flags": []                            // e.g. "gap-before", "alignment-ambiguous", "native-loss-indicated"
}
```

Field notes:

- `stream_seq` is what A5's outbox replays from and what a receiver can use to detect gaps between the platform and itself. It says nothing about gaps on the device side; those are separate `telemetry-health` events (section 4).
- `native.evidence` points at the whole transcript (A2's `transcript`) so the evidence store keeps one object per invocation, and each row is a span. A3 HR-3: the login phase appears in that transcript as a redaction marker (offset, length, reason, component). A4 accepts this: the login exchange is not an event record, so R4.4 is not affected. Two conditions: the marker must not contain a hash of the secret (SEL passwords are short enough to brute-force from a hash), and if the device echoes typed characters, the echoed bytes need the same treatment, which A2 should confirm for SEL Telnet.
- Bytes are bytes. A2 reports NUL and XON in SEL output (section 7). The evidence store keeps them; `native.fields` holds decoded strings with a recorded decoding; the forwarder base64-encodes anything non-printable (section 5).
- Audit records (A3 4.4) reuse `received`'s shape for their `time`: UTC value, `resolution_ns`, clock sync state. No conflict with A3's draft.

## 3. Timestamp models covered

The schema was checked against four native time encodings, three of them taken from wire bytes in public captures by `modules/telemetry/experiments/schema-mapping/map_examples.py` (output in `results/examples.json`, all invariant checks pass). This is the "more than one vendor" check from the brief: SEL ASCII text, DNP3 (multi-vendor), IEC 60870-5-104 (multi-vendor), and IEC 61850 (multi-vendor).

| Format | Native example (verbatim) | Resolution | Offset in the encoding | Quality the encoding carries | Scope | What the schema does | Evidence |
| --- | --- | --- | --- | --- | --- | --- | --- |
| SEL ASCII SER (SEL-751) | Row `8     02/28/2007   13:54:09.602   51P1P                    Asserted` under a header with relay id, `Date:`/`Time:` of the report, `Time Source: Internal`, `Serial No`, `FID`, `CID` | 1 ms. The manual's ±1 ms is relative to the relay's time source, so `accuracy_ns` stays null and the ±1 ms goes in `quality` as device-relative; with `Time Source: Internal` no time input is attached and accuracy to true time is unknown (A2 review) | None in the output. The relay keeps local time: `UTC_OFF` is applied only when SNTP sets the clock, "other time sources are defined as local time", and automatic DST switching (`DST_BEGM`…`DST_ENDH`) repeats an hour each autumn | `Time Source` (Internal or External); Relay Word bit `TSOK`; PTP `TQUAL` bits (not in the SER report) | Report | Row date and time kept verbatim; `wall_clock` decoded with the `DATE_F` setting (MDY, YMD, DMY), which the report does not print, so it is a recorded assumption until the adapter reads the setting with `SHO G` (A1-approved); a row whose date does not fit `DATE_F` is a parse error, never skipped; the relay's own `Relay Powered Up` and `Relay Settings Changed` messages are matched explicitly, their layout unconfirmed; `offset` "unknown" unless the site records the clock source and `UTC_OFF`/DST settings; report time source copied to each row with `scope: report`; `dst-ambiguous` applies | SEL-751 Instruction Manual 20260910 (owner-supplied): Figure 10.16, Table 7.63, Table 4.90 and the UTC offset text, section 1 SER specifications. `documented-untested`. All 8 rows of Figure 10.16 map losslessly (`map_examples.py`), including two pairs of rows that share a millisecond. `sel_ser.py` with `test_sel_ser.py` (12 tests) checks that every non-blank line after the label line becomes a row, a relay message, or a parse error |
| SEL-400 series SER (SEL-451, 411L) | `4    03/15/2001 00:30:00.021    GROUND O/C 1 LINE 1 51S1 PICKED UP` (Figure 9.16) | ms digits | Relay stores local time computed from an internal UTC clock plus `UTCOFF` and `BEG_DST`/`END_DST`; newer firmware saves the active `UTCOFF` with each report | as above | Report | Same as SEL-751, but ELEMENT is a multi-word alias, so the row parser cannot split on whitespace; offset derivable from settings when the adapter records `UTCOFF` and DST state | SEL-400 Series Instruction Manual 20260730, Figure 9.16, Global settings table, revision history. `documented-untested` |
| IEC 60870-5-104 CP56Time2a | hex `c75d170884070d` (`iec104.pcap` frame 25, M_SP_TB_1) | 1 ms | None. A summer-time bit (SU) and a two-digit year | IV (invalid), SU, substituted (GEN) | Record | `offset` "unknown"; year flagged `two-digit-year`; IV and SU kept | Wire bytes; lib60870 `CP56Time2a_isInvalid`/`isSummerTime`; tshark renders it "UTC", which the bytes do not say |
| DNP3 g51v1 CTO + g2v3 relative | hex `e2437d87ff00` + rel `0000` (`dnp3-digitalbond-part1.pcap` frame 40) | 1 ms | IEEE 1815 says UTC (recollection, not checked here), but see next column | IIN1.4 NEED_TIME, IIN2.3 event buffer overflow (stream level), point flags | Record (time), stream (IIN) | `offset` "unknown" unless site config states it; `relative-to-cto` flag | In this capture all 14 DNP3 absolute times are 4 h plus 0.06 to 5.1 s behind the capture clock (frame 7: payload 09:39:01.483, capture 13:39:01.548 UTC; the extra seconds fit event-to-report latency), consistent with US Eastern daylight time on the wire. Inference: the capture host clock could itself be wrong. tshark labels them UTC. The format's nominal UTC cannot be trusted per device |
| IEC 61850 UtcTime (GOOSE `t`, report timestamps) | hex `5cd3d9ac8395810a` (`goose-normal.pcapng` frame 1) | 2^-24 s (about 60 ns) encoding | UTC by definition | Quality byte: leapSecondsKnown, clockFailure, clockNotSynchronized, 5-bit accuracy. Here `0x0a`: synchronized, 10 bits (about 1 ms) | Record | `utc` set, `offset_basis: format`; `accuracy_ns` 976562; decoded to 3 digits, rounded | Wire bytes; libiec61850 `mms_value.h` bit definitions. tshark prints `.513999998`, nine digits of false precision; truncating would give `.513`, rounding gives the intended `.514` |
| Syslog RFC 3164 (device-originated) | `Oct 23 15:00:00` | 1 s | None, no year | None | Record | `offset` "unknown", flag `year-inferred` | RFC 3164 section 4.1.2 (from the RFC, not re-read here) |
| SEL-2488 satellite clock Syslog | Manual sample `<37>Jul 09 2009 08:17:29 myhostname Login: Login to web: failed from 192.168.1.1` | 1 s in the sample; the local report shows µs | Manual says RFC 3164 "with the enhancement that the SEL-2488 time stamps include the local time offset to UTC", but its own sample carries a year and no offset | Severity only | Record | Parser accepts both forms; offset taken only when present on the wire; year flagged when absent; transport is UDP port 514 only (fixed), so no confidentiality, integrity, or delivery | SEL-2488 Instruction Manual 20260918, section 18, Appendix D. `documented-untested`. The clock is the likeliest first device Syslog source, and its events (GNSS lock, holdover) are time-quality evidence for every relay it feeds |
| Syslog RFC 5424 (device-originated) | `2026-10-23T15:00:00.123+02:00` | As sent (up to 1 µs) | Mandatory in the format | None in header; may be in SD | Record | `offset_basis: format`, resolution from the digits sent | RFC 5424 section 6.2.3 (not re-read here) |

DST fall-back (V-S3 negative case): when a local wall-clock time falls inside a repeated hour and `offset_basis` is `site-config`, the decoder sets `flags: ["dst-ambiguous"]` and leaves `utc` null rather than picking one. Only a device-provided offset or a monotonic ordering argument may resolve it, and that resolution is recorded.

## 4. Duplicates and gaps (deliverable 2)

### SEL-style ring buffers: snapshot alignment, not a row key

A per-row key (device, timestamp, element, state) merges genuinely separate identical rows (A6 C-13, A2 section 7). The proposal is to align each read against the previous read of the same stream:

1. Each read is a chronological list of rows, compared by `alignment_key`: the digest of the row's native bytes from the DATE field to the end of the line, excluding the row number. The SEL-751 numbers row 1 as the newest (Table 7.63), so every new event renumbers every row; with the number in the key, 3 of A6's 6 consecutive-read cases reported false gaps and re-ingested the whole buffer (A6 R-A4-1, accepted by A1 for C5). The native bytes, number included, stay in evidence.
2. Find `d` such that `prev[d:]` is a prefix of `new` with at least one row of overlap. The rows after the overlap are new. Rows identical within one snapshot stay separate records.
3. If no `d` fits, the buffer wrapped past the previous read, was cleared (`SER C`), rows were removed (chatter deletion), or the relay restarted. Emit a `telemetry-health` gap event; store all rows of the new read with `flags: ["gap-before"]`.
4. If more than one `d` fits (periodic identical rows with no anchoring row), use the smallest overlap, so every row that may be new is kept; flag the extra rows `possible-duplicate` and emit an `alignment-ambiguous` event (A6 R-A4-2). Cost: a buffer of identical periodic rows re-emits flagged possible duplicates on every poll; that is visible noise, not loss.

Prototype: `modules/telemetry/experiments/schema-mapping/align.py` with keys from `sel_ser.alignment_key`, 13 unit tests passing (`results/test_align.txt`), including identical rows, wrap, clear, middle deletion, the ambiguous case, and SEL-751 renumbering. A6's independent harness (`tests/integration/reviews/A4/ser_alignment_cases.py`, PR #6) passes 6 of 6 against this `align.py` with the row number excluded (`results/a6-ser-alignment.txt`). A6's V-S4 should own the independent version of these tests.

Behaviour when the device re-sends its whole history: every row of the overlap is recognized by alignment and not stored again; nothing is forwarded twice from that read. If the device re-sends history after a restart with different row bytes (for example a changed date format), alignment fails and a gap event is raised; the history is stored again with `gap-before`, and duplicates downstream are then visible by content but not suppressed. That is the deliberate choice: a duplicate the analyst can see is better than an event silently dropped.

Model differences that change the collector (SEL manuals supplied by the owner):

- SEL-751 `SER` returns all rows (up to 1,024), row 1 newest, listed chronologically (Table 7.63). SEL-400 series `SER` returns only the 20 most recent rows by default (Table 9.3), so a collector must request `SER 1000` or alignment reports false gaps whenever more than 20 rows arrive between polls.
- SEL-400 series keeps a per-port "viewed" pointer: `SER CV`/`SER RV` clear already-viewed data for that port only, `SER C` clears the port, `SER CA` clears all ports (Access Levels P, A, O, 2). None of these may be in the approved register; a collector that cleared its own port would hide events from nobody else, but could still destroy evidence.
- **SEL-751 `SER C` (and `SER R`) clears the SER records at Access Level 1** (Table 7.63), the level the collector uses. Evidence destruction is therefore one mistyped line away under monitoring credentials. A2's register must deny it, and a cleared buffer must surface as a gap (it does: alignment finds no overlap).
- The SER itself records some of these conditions on the 400 series (power-up, settings changes, memory overflow, SER autoremoval and reinsertion, Figure 9.16 text), which the normalizer should map to `telemetry-health` categories once a mapping table exists.

Residual limit: SEL-751 exposes no sequence counter (A2), so a gap smaller than the read-to-read overlap cannot be distinguished from silence if rows are removed exactly at the overlap boundary. V-S4 should report this as a documented limitation for the family (C-06).

### Other sources

| Source | Native identity available | Duplicate handling | Gap signal |
| --- | --- | --- | --- |
| IEC 61850 buffered reports on SEL relays (scope is SEL only, ADR-0006) | EntryID per buffered report control block plus timeOfEntry | Resume after the last stored EntryID; an EntryID already stored is a duplicate | `BufOvfl`. The SEL-751 conformance statement lists 12 BRCB instances and **no IEC 61850 logging** (GetLCBValues, QueryLogByTime, QueryLogByEntry not supported) and no MMS journal services, so the "read the log" path does not exist on SEL-751. Taking a BRCB means writing `RptEna`, which A2 D14 classifies as a state change that can collide with SCADA. The read-only SEL alternative is the `SER.TXT` file (Reports directory, read-only, FTP or MMS file transfer, Access Level 1), the same rows as the `SER` command. MMS `fileDelete` is supported on the device, so any MMS file client needs A2's read-only facade. Source: SEL-751 IM 20260910, Appendix G conformance tables and Table 7 virtual file listing. `documented-untested` |
| DNP3 event polling (rejected for slice 1 by A2) | None per event; events leave the outstation buffer on confirm | Re-delivery after a lost confirm is possible; tuple match within one response window | IIN2.3 event buffer overflow |
| Device Syslog | None | No content dedup: identical messages repeat legitimately. Transport-level duplicates are rare on UDP and not suppressed | None from the sender; the receiver can only count |
| Platform events | `event_id` at creation | n/a | `stream_seq` |

### Forwarding duplicates

`event_id` is the receiver-side de-duplication key and travels in every forwarded message. Replay after reconnect (section 5) re-sends the same `event_id` and `stream_seq`.

## 5. Syslog forwarding profile (deliverable 3)

Draft profile `otsec-syslog/0.1`. Evidence: `modules/telemetry/experiments/syslog-framing/` (injection) and `modules/telemetry/experiments/relp-ack/` (acknowledgement semantics).

### Message format

- RFC 5424 syntax, always octet-counted framing (RFC 6587 section 3.4.1, which RFC 5425 mandates). Newline framing is never offered: with a stock rsyslog receiver, one device record containing an LF produced two parsed messages, the second a forgery with attacker-chosen hostname and MSGID (`results/framing.md`, cases `embedded-lf-forgery` and `embedded-crlf-forgery`).
- HEADER `TIMESTAMP` is the collector receive time (`received.utc`), never the device time. RFC 5424 requires an offset in TIMESTAMP, and device offsets are often unknown; putting local device time there would make every SIEM treat it as UTC.
- `HOSTNAME` is the node id, `APP-NAME` is `otsec`, `MSGID` is the event kind (`SER`, `SYSLOG`, `HEALTH`, `ALERT`).
- Structured data `[otsec@PEN …]` carries `eid` (event_id), `seq` (stream_seq), `stream`, `origin`, `asset`, `dts` (device_time.native verbatim), `dfmt`, `dutc` (only when known), `doff`, `dres`, `dacc`, `dsync`, `tsrc`, `subj`, `val`, `cat`. `PEN` must be an IANA Private Enterprise Number before production; experiments use 32473 (RFC 5612 documentation number).
- Device-originated text appears only inside SD-PARAM values, escaped per RFC 5424 section 6.3.3 (`"`, `\`, `]`). Any value that is not printable UTF-8 (control characters, ANSI escapes, NUL, invalid UTF-8) is sent as `dtext_b64` instead of `dtext`. MSG is a platform-written printable summary, never device bytes.
- Results with rsyslog 8.2312 as the independent receiver, 10 hostile cases: the naive encoder let 2 of 10 cases forge a message and the 10 KB case was split into 2 messages; the profile produced exactly one message per record in every case, 0 forged, the `origin` value intact, and the device bytes recovered exactly from SD in all 9 cases that fit.

### Size

- Default maximum message size 2048 octets, the size every RFC 5425 receiver must accept; configurable per collector up to what it is known to accept (8192 is the RFC's SHOULD).
- Over the limit, the device text parameter is replaced by `dtext_omitted="1" dlen="…" dsha256="…"`; event identity, time, and origin fields are never cut. The full record stays in the evidence store. A `telemetry-health` counter records each omission. Never split, never silently truncate.

### Delivery semantics (B-03, C-04, TB5)

The forwarder reads from A5's durable outbox in `stream_seq` order and keeps a cursor: the position up to which delivery is confirmed. Delivery is at-least-once; receivers de-duplicate by `eid`.

| Mode | Transport | What advances the cursor | Unconfirmed window | When to use |
| --- | --- | --- | --- | --- |
| A (preferred) | RELP over TLS | A RELP `rsp` with `200 OK` for that transaction number | Frames sent but not acknowledged (bounded by the RELP window, 128 in the experiment) | Collector is rsyslog, or a site or central relay we operate |
| B | RFC 5425 TLS, octet-counted | Nothing the receiver says. The cursor advances on successful write, and on every reconnect the forwarder re-sends the last W events or T seconds (configured) | Everything written since the collector last persisted, which the sender cannot know; A6 E-01 lost 100 of 150 | Collector supports only RFC 5425 (most SIEMs) |

Experiment E-A4-03 (`results/relp-ack-trial{1,2,3}.md`): 1,500 messages acknowledged by a stock rsyslog imrelp receiver, receiver crashed with SIGKILL. With rsyslog's default queues, only 29 to 31 of the 1,500 acknowledged messages had been stored (about 98% loss of acknowledged data, 3 of 3 trials). With Direct queues and an output that confirms each write, 0 acknowledged messages were lost (3 of 3). **A RELP acknowledgement is only as strong as the receiver's queue configuration.** Mode A therefore also requires a documented receiver configuration (Direct or disk-assisted queues with the ack issued after persistence) and a test against it. This is `simulated`, localhost, process crash only; host power loss and page-cache loss are not tested.

A1 ruling at the Phase 0 exit gate: mode A is the only mode allowed for a destination marked `required`; mode B is allowed only for `best-effort` destinations, with the replay window.

For the site-to-central hop, A5's own acknowledged channel is the better tool than Syslog; the profile above is for the platform-to-third-party-collector hop.

### Answer to A3 on TB5 and AP-9

Mode A needs exactly one inbound grammar: RELP server frames `TXNR SP COMMAND SP DATALEN [SP DATA] LF`, with COMMAND limited to `rsp` and `serverclose`, DATALEN bounded (4096 in the experiment), and `rsp` data required to start with `200 OK` for an outstanding transaction number. The experiment's parser (`AckParser` in `relp_ack_test.py`) is about 40 lines; its only output is the set of acknowledged transaction numbers, and anything else is counted as a violation (0 in all trials). That fits A3's option (1). The `open` handshake response carries an offer list that the parser must read once and ignore apart from the version. Note that even mode B parses inbound TLS records (handshake, alerts), so "accepts nothing back" was never literally true; TB5 can be stated as "accepts only TLS protocol records and, in mode A, RELP responses in the grammar above, whose only effect is advancing the cursor".

### Receiving device Syslog (R4.1)

- Listeners for UDP (RFC 5426), TCP (both framings, auto-detected), and TLS (RFC 5425), each a separate `stream_id` per sender address.
- Each datagram or frame is persisted byte-exact before parsing; RFC 3164 and RFC 5424 are parsed into `device_time` per section 3; unparseable messages are kept with `parse_status: failed`.
- Re-forwarded device Syslog is always wrapped (device bytes in `dtext`/`dtext_b64`), never relayed raw, so a device cannot forge platform messages upstream.

### SEL telemetry sources by device type (ADR-0006 scope)

ADR-0006 puts every OT device class in scope, so the schema does not assume an SER row. `kind` is an open set: a record from an RTAC SOE log, a clock's event log, a switch or gateway Syslog message, a Windows or Linux host event, or a clock status poll uses the same envelope. The byte-exact `native` evidence, the separate time fields, and `source.sender`/`origin_auth` apply unchanged. Only `collection.parser` and `native.fields` are kind-specific. Host events (Windows Event Log XML, journald JSON) are structured natively, so `native.span` points into the stored structured record instead of into a text line.

The owner set the scope to all SEL OT device types before other vendors. This table records, per SEL device type in the supplied manuals, where its events come from and what the receiver has to cope with. Every row is `documented-untested`: it comes from the SEL instruction manuals in the owner's folder, and no device has been observed. "Not found" means a text search of that manual found nothing, not that the product lacks the feature in every firmware.

| Device type | SEL product (manual) | Native event source | Syslog emitted | Transport, framing, TLS | Timestamp on the wire | Consequence for the schema and receiver |
| --- | --- | --- | --- | --- | --- | --- |
| Protective relay | SEL-751 (IM) | ASCII `SER` report (up to 1,024 rows, row 1 newest, no sequence counter, names changeable by ALIAS), SER.TXT over FTP/MMS, `CSE` at Level 1 (format not in this manual) | Not in the Port 1 protocol list (Table 7.5), per A2 | n/a | Local time per row, µs in the Figure 10.16 sample; offset from UTC_OFF only under SNTP; DST from Global settings with no per-row DST flag | Collected by A2's adapter; section 3 SEL-751 row and section 4 alignment |
| Protective relay | SEL-400 series (SEL-451 IM) | ASCII `SER` (20 rows by default, `SER 1000` for all) | Not found | n/a | Local time; UTCOFF and DST settings | Section 3 SEL-400 row; collector must request the full buffer |
| Protective relay | SEL-311L (IM) | ASCII `SER` | Manual: "does not support Syslog functionality" | n/a | Local time | Same as SEL-751 path |
| Time server | SEL-2488 (IM 20260918) | Local event log (60,000 entries, ID, µs local time with offset) and Syslog | Yes, RFC 3164 "with offset" per text; sample has a year and no offset | UDP 514 only, fixed; no TLS | 1 s in the Syslog sample | Parser accepts both forms; its GNSS lock and holdover events become `device_time.quality` evidence for every relay it feeds |
| Automation controller / RTU | SEL RTAC, ACSELERATOR RTAC SEL-5033 (IM 20260925) | SOE log (30,000 to 500,000 entries by platform) and Syslog; Tag Processor logging layout | Yes, RFC 3164 cited; facility fixed at 23; severity from a case-sensitive Logging Priority string, unknown strings become 6; 1024-byte limit; multiple destinations; local store of 10,000 messages | Transport for sending is not stated in that section; the Syslog Collector extension (R153+) listens on UDP or TCP | Two times: HEADER is send time at 1 s (`<190>Mar 21 2015 12:10:08`), MSG carries the event time at ms (`2015-03-21 12:09:58.593`), 9.4 s apart in the manual's own sample (12:10:08 versus 12:09:58.593); the HEADER carries a year | `device_time` comes from the MSG event time, not the HEADER; the HEADER time is kept in `native.fields`. The RTAC can also re-forward other devices' Syslog, so an RTAC message may describe a different asset (`asset_binding` must not assume sender = subject). Release notes list several fixed defects where RTAC Syslog had "an incorrect time", so firmware version belongs in `collection.parser` context |
| Network management | SEL-5056 SDN Flow Controller / NMS (IM 20261015) | Syslog for itself and for every managed SEL SDN switch | Yes, RFC 3164 or RFC 5424 selectable per destination; up to 3 destinations; severity threshold per destination | UDP or TCP/TLS; TLS needs the collector's X.509 certificate installed as trusted on the SEL-5056; port configurable (usually 514) | Sample `<131> Jul 19 10:15:54 ROBEMEINNB TopologyManager: ...`: no year, no offset, and a space after PRI that strict RFC 3164 parsers reject | First documented SEL source that can deliver over TLS, so it is the natural first test of the R4.1 TLS listener. Parser must tolerate the space after PRI. Switch events arrive from the SEL-5056's address, so the subject switch is in the MSG (OpenFlow datapath id) and binding again cannot assume sender = subject |
| Ethernet switch | SEL-2741, SEL-2731, control plane selectable | OT SDN mode: via SEL-5056 (above). RSTP managed mode: the switch's own Syslog, per A2 from the SEL RSTP Managed Ethernet Switch User's Guide 20260424 (Appendix C), which I have not read | SDN: via SEL-5056. RSTP: yes, RFC 3164, up to 3 destinations, 60,000 local messages (A2) | SDN: via SEL-5056. RSTP: UDP | Not checked | The source depends on the switch's mode, so the asset record must hold the control plane. SDN needs a datapath-id-to-asset mapping; RSTP needs a direct UDP listener. The hardware IMs for the 2731 and 2741 contain no Syslog text |
| Station computer | SEL-3355-2 (IM) | Host operating system logs | Not found in the hardware manual | Depends on the installed OS | Depends on the OS | Treated as a general host: Windows Event Log or Linux journal collection is a separate source type, not yet designed |

What this changes in the draft:

1. `source.sender` and `source.asset_id` are separate fields, and `source.asset_binding` must allow "subject differs from sender" (confidence `asserted`), because both the RTAC and the SEL-5056 relay events about other assets. The subject's identity comes from a mapping (OpenFlow datapath id, RTAC tag name) and its confidence is recorded.
2. A Syslog message can carry two device times (HEADER and an event time in MSG). The schema keeps both; `device_time` is the one closest to the event, and the choice is a per-source parser rule, not a guess at run time.
3. The receiver needs lenient RFC 3164 parsing (space after PRI, year present or absent, offset present or absent), with every deviation recorded in `flags` rather than silently normalized.
4. `source.origin_auth` (A3 AP-22) records how the sender was authenticated. The SEL-5056 manual documents only that the collector's certificate is installed as trusted on the SEL-5056, which authenticates the collector to the sender. It does not say the SEL-5056 presents a client certificate, so its TLS Syslog is `tls-server-only` (confidential and integrity-protected in transit, sender not authenticated) until mutual TLS is shown.
5. No SEL relay in the supplied manuals emits Syslog, so the vertical slice's SER path stays on A2's CLI adapter. The first device Syslog sources are the SEL-2488, the RTAC, the SEL-5056, and switches in RSTP mode.
6. `CSE` (Compressed ASCII SER) returns rows newest first, with fields mapped by its label line (A2). A2 found that 7 of 9 checksums in the SEL-400 Figure 9.17 sample are wrong (D25), so a parser fixture from that figure can verify only the label lines. The RTAC Syslog fixture is A2's `tests/fixtures/ied/sel/rtac/documented-example/syslog-user-logon.txt` on PR #2.

## 6. Platform events this schema implies

`origin: platform`, `kind: telemetry-health`. Each is observable, never silent (P5):

- `ser.gap` (alignment found no overlap), `ser.alignment_ambiguous`.
- `native.loss_indicated` (IEC 61850 BufOvfl, DNP3 IIN2.3, a cleared buffer).
- `time.unsynchronized` (IEC 61850 clockNotSynchronized, CP56Time2a IV, DNP3 NEED_TIME, SEL time source changing to Internal).
- `parse.failed` (raw kept).
- `forward.omitted_oversize`, `forward.window_replayed`, `forward.ack_violation`.

## 7. What this draft deliberately leaves out

- Asset identity fields beyond `asset_id` and `asset_binding` (A1/A2/A3 contract).
- Integrity chaining or signing of events (A3 proposes `prev_hash` for audit; whether events need the same is for A3 and A5).
- Semantic category tables. The first slice forwards `category: unmapped` unless a per-device mapping table exists (Q3 answer).
- IDS alert fields beyond `kind: ids-alert` (Phase 4).
