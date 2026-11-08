# C13 `otsec.netobs/0.1`: what the passive sensor hands the node (P4-4-A4)

D4, 2026-11-07. This is the draft for review. D1 approves it together with D5's C5 0.9 (#532) in D4-68. The reviewers are:

- D6, for testability against V-M6 and R6.1 to R6.5;
- D2, for protocol reading;
- D3, for the boundary (AP-33 to AP-36);
- D5, for the node's side and the store.

The design note beside it is [D4-network-baseline.md](D4-network-baseline.md). It holds the baseline, the rules and the platform's own traffic.

**Revised 2026-11-07, after D4-68, with D1's agreement** (§14). Coding C13 found four gaps, and D1 agreed the fixes before the code merges. The identifier stays `otsec.netobs/0.1`, because nothing has been written under it yet.

Everything here is `desk`. No sensor exists, no record has been produced, and no device was contacted. The Go package `contracts/netobs` follows approval, as C11 did (#437, then #446), so that review settles the text before code pins it.

**Written before ADR-0009 names an option, at D1's direction.** The brief's order puts C13 after the ADR (Order step 2). D1 asked for it now, because every option hands the node the same records. Nothing below depends on the option except the channel's transport:

- under (a) and (c), a local pipe or Unix socket bound to the sensor's account;
- under (b), mutual TLS on a connection the node opens.

D5's note covers both (§2). Where the option would change a field, the field is marked.

## 1. What C13 covers, and where each record goes

| Record | From, to | Stored as | Forwarded upstream |
| --- | --- | --- | --- |
| **Heartbeat** (§6) | sensor to node, every 10 s | health events made from it, not the heartbeat itself (D5 §1) | its health events, as any health event |
| **Observation** (§4) | sensor to node | a C4 platform event of a new kind, `network-observation`, carrying the observation in a new optional C4 field, `netobs` (C4 0.3, §9). Class `network-observation` (C5 0.9) | never (D5 §3: never a forward target's stream) |
| **Alert** (§7) | raised by the node's detector, never by the sensor | a C4 `telemetry-health` event, `netobs.alert`, in C10's departure-alarm form. Class `network-alert` | yes, as a health event, carrying hashes and frame numbers and never packet bytes (AP-33) |
| **Network baseline** (§8) | built by the node's learner, acknowledged by a person | a configuration-class document, series `baseline.network` (asks C5 0.9 for the series, §9) | no |

**The channel carries only heartbeats and observations.** The node refuses any other type from the sensor and counts it under `sensor-record-refused`. An alert-shaped record from the sensor is refused, so a compromised sensor cannot write alerts. It can only send observations, and the node judges those (AP-34).

**Strict.** C13 is strict, as C7 collector requests are: an unknown field, an unknown minor or an unknown closed-enum value refuses the one record (AP-34 (2)). The sensor parses hostile traffic, so whatever it sends is treated as hostile input in turn (D5 §2). A refused record never closes the channel (D5 §2).

**Framing.** Each record is one JSON document in UTF-8, preceded by its length as a 4-byte big-endian unsigned integer. A length above `MaxChannelFrame` (64 KiB) closes the channel and is counted, because the stream can't be resynchronized after it. Under option (b) the same framing runs inside TLS.

## 2. Identifiers and times

- **`sensor_id`:** a lowercase UUID. Every UUID in C13 takes the form C1's asset IDs and C2's invocation IDs take: version 1 to 8 and variant 8, 9, a or b (D5 on #549). It is set in the sensor's configuration at install, or at enrollment under (b). The node checks it against the `network_sensor` section's `sensor_id` (D5 §5). A record with another ID is refused.
- **`run_id`:** a lowercase UUID the sensor draws at each start.
- **`seq`:** a decimal from 1, per run, on every record the sensor sends. A gap in `seq` is a loss on the channel, and the node counts it as one, as D5 §2 counts channel drops. A heartbeat's own drop counters cover the losses before the channel.
- **Tokens.** Every sensor-supplied field written `<token>` matches `^[A-Za-z0-9][A-Za-z0-9._:+-]{0,63}$`. That covers `sensor_version`, `engine.name`, `engine.version`, `interfaces[].name`, `protocol`, `tls.version` and `login.why`. The node refuses a record that breaks it (D3). A token is never device text: a value read from the wire is a `Text` (§3.1).
- **Times** are RFC 3339 UTC with `Z`, at the precision the clock has, with `resolution_ns` stated once per record. They come from the capture timestamps on the sensor host's clock. The node adds its own received time through C4's `received`. An alert says which clock it ran on (§7).
- **`capture_id`** names the capture file the frame numbers count in. It takes one of two forms:
  - `ring:<run_id>:<n>` for the sensor's ring file `n` of that run (D5 §4);
  - `file:<sha256>` when the sensor reads a capture file offline, where `<sha256>` is the file's own hash. GT-PCAP's checker then asserts frame numbers as well as hashes (D6 plan §1).

  Frame numbers are 1-based within the capture, as tshark numbers them.

## 3. Common types

### 3.1 Device text

Every value the sensor reads from the wire as text is a `Text`. That covers a banner, an HTTP `Server` header, a Telnet `ID` reply field, an SNMP `sysDescr`, a TLS SNI and a user name. A `Text` is hostile input (#522, D3; C2's precedent in `contracts/adapter/doc.go`). Its rules are:

```
{ "value": "<escaped>", "length": <original bytes>, "truncated": <bool> }
```

- **What is kept.** The sensor keeps at most the first `MaxTextBytes` (256) bytes of the original. That holds the longest banner a relay allows, 254 characters (`TCBAN`, `FTPCBAN`, `HTTPBAN`; S22 Table 4.104, D6 plan §2C). `length` is the original length, and `truncated` is true when `length` exceeds 256.
- **How it is written.** `value` holds those bytes as printable ASCII. Each byte from 0x20 to 0x7E except `\` stands for itself. `\` is written as `\\`, and every other byte as `\xHH`, with the hex in lowercase. So `value` is at most 1,024 bytes, decodes back to exactly the kept bytes, and can't carry a control character, a newline or an escape sequence.
- **How it is used.** Nothing interprets `value`. Status, Syslog and any C6 rendering show it inside quotes, after their own escaping. It never reaches a forward or a status line raw (AP-34 (3)). The node refuses a record whose `value` is not in this form, or does not decode to `min(length, 256)` bytes.

### 3.2 The packet citation

Every observation and every alert cites its packets as a capture ID, frame numbers and one SHA-256 per frame (V-M6, R6.5, D4 on #527).

```
"citation": {
  "capture_id": "ring:<run_id>:<n>",
  "frames": [
    { "n": 17, "captured_len": 74, "wire_len": 74, "sha256": "<hex>", "lan": "a",
      "redactions": [ { "offset": 66, "length": 8, "reason": "credential" } ] }
  ],
  "frames_total": 3
}
```

- **What a frame's hash covers.** `sha256` is over the frame's link-layer bytes as stored: the Ethernet frame, with any 802.1Q tag and any PRP RCT, and with no pcap or pcapng record header and no timestamp. GT-PCAP hashes its frames the same way (D6 plan §1). `captured_len` is the stored length. `wire_len` is the length on the wire, which is larger only when the frame was cut at `MaxFrameBytes` (2,048). It is at most `MaxWireLen` (256 KiB), so the stored capture's 32-bit `orig_len` can't wrap; a larger one is refused as `range` (§14 item 11).
- **`lan`** is `a` or `b` when the frame carries a PRP RCT, from its LAN ID. It is absent otherwise.
- **How many frames.** At most `MaxCitedFrames` (8) are listed, the first frames that show the item. `frames_total` counts every frame that shows it, so the list holds the first `min(frames_total, 8)`. Where the same frame arrived on both LANs (the same source MAC and RCT sequence number), the sensor lists the copy it kept and counts the frame once (§4.4). The two copies' hashes differ, because their LAN IDs differ, so the checker accepts either copy's hash (D6).
- **Redactions (D4-67, AP-33 (4)).** Each redaction gives an offset into the stored frame and a length, with a closed reason:
  - **`credential`**: a credential slot placed after reassembly. The slots are a Telnet password after the password prompt up to the line end, FTP `PASS`, the community of every SNMPv1 or v2c message in either direction, plain HTTP's `Authorization: Basic` value, and a server's echo of any of those. D1 extended the list in D4-68, as an amendment to D4-67. It now also covers the value of every plain-HTTP `Cookie` and `Set-Cookie` header (the names stay), and the whole body of a plain-HTTP request whose `Content-Type` is `application/x-www-form-urlencoded` or `multipart/form-data`.
  - **`slot-not-placed`**: the TCP payload that would hold a slot that could not be placed. Examples: a login joined midstream, after a lost segment, at an unknown prompt, or with a password sent before its prompt; or a plain-HTTP header or body whose boundary can't be placed (D4-68). For a login or a request, the whole client payload of each such frame is covered, so none of that login's client bytes are stored (D4-67's fail-closed rule). Fail-closed covers whichever side carries the unplaced slot (D1, D4-68). So for a `Set-Cookie` whose boundary can't be placed, the whole server payload of the frame is covered.

- **At most `MaxRedactions` (16) per frame** (§14). A frame whose side of the exchange holds more slots than that is covered as one `slot-not-placed` redaction over that side's whole payload in the frame, as for any slot that can't be placed. That one entry replaces the per-slot `credential` entries for that payload, and doesn't sit beside them. A frame carries one side's payload, so a frame with a `slot-not-placed` entry has no other redaction, and the node refuses one that does (§14). So the bound fails closed, and a header with many cookies can't grow the record without limit. The node refuses a cited frame that lists more than `MaxRedactions`, and counts it under `sensor-record-refused`.

  Every redacted byte is replaced by `0x2A` (`*`). The node refuses a first-sight observation in which any byte inside a listed redaction is not `0x2A`, and counts the refusal under `sensor-record-refused` (D3). That catches a sensor that lists a redaction and forgets to apply it. A sensor that leaves a slot out of the list altogether can't be caught this way, and that remains AP-33's residual. The marker is a constant, never derived from the secret (HR-3's condition). Its length equals the slot's, on purpose, so a stolen node learns each secret's length and nothing more (D4-67, D6). The hash is over the stored, redacted bytes, so it checks against the ring and the alert's capture alike (D5 §4). Redactions in one frame are sorted and never overlap. A `credential` redaction covers exactly its slot, no wider and no narrower. A slot byte outside every redaction is a leak, and GT-PCAP fails it (D6). For a frame cut at `MaxFrameBytes`, the hash and the redactions cover the stored `captured_len` bytes only. A frame with a redaction is stored redacted everywhere: in the ring, on the channel and in the store.
- **The bytes themselves** travel only with a first-sight observation (§4.2), and are stored only as a record's C5 capture at the site. A forward, Syslog, status and health carry the citation without bytes (AP-33 (1)).

### 3.3 The coverage statement

Every observation carries the sensor's coverage statement, and every alert carries the one in force when it was raised (A4 §4, R6.1, the brief). It is small enough to embed whole, at most `MaxCoverageBytes` (2 KiB):

```
"coverage": {
  "sensor_version": "<token>", "engine": { "name": "<token>", "version": "<token>" },
  "interfaces": [ { "name": "<token>", "attachment": "span|tap|unknown", "lan": "a|b|single|unknown" } ],
  "prp": { "lans_seen": ["a", "b"], "duplicates_discarded": true },
  "hsr": "not-decoded",
  "vlans_seen": [10, 20], "vlans_overflow": false, "untagged_seen": true,
  "decodes": ["dnp3", "modbus", "telnet", "ftp", "http", "snmp", "tls"],
  "degraded": ["drops-driver"],
  "settings": { "sa_reply_timeout_ms": 5000, "max_pending_dnp3": 4096, "flow_idle_s": 60 },
  "since_utc": "..."
}
```

- **`attachment`** is what the sensor's configuration declares. The sensor can't tell a SPAN port from a TAP, so `unknown` is allowed and shown as such. C-11's reliance differs by attachment (D3), so the alert says which one applies.
- **`lans_seen`** is the LANs whose RCTs the sensor has seen since start. **`duplicates_discarded`** says whether the sensor discards PRP duplicates by source MAC and RCT sequence number before decoding. If a sensor sees both LANs and does not discard, every count is doubled. The node treats that as a coverage mismatch, not as data (§4.4).
- **`hsr`** is `not-decoded` in 0.1. HSR is a stated limit (ADR-0009 protocol point 5, R6.6).
- **`vlans_seen`** lists at most 64 VLAN IDs, ascending. `vlans_overflow` says there were more.
- **`decodes`** is the protocols the sensor decodes, from the protocol list (§4.1). A protocol absent here may still appear as `undecoded` (§4.3, kind `undecoded`), which is how R6.1's statement is checked against traffic.
- **`settings`** carries the sensor settings a checker needs to read its records. In 0.1 that is `sa_reply_timeout_ms`, `max_pending_dnp3` and `flow_idle_s` (§10), and all three are required. `flow_idle_s` is how long a flow can be silent before the sensor ends it, which bounds when a held flow's `end` must come (baseline note §5, §14 item 10). `sa_reply_timeout_ms` bounds how long a DNP3 `function` observation can wait, and so is part of R6.4's latency for the rules that judge DNP3 functions (D6, D1). A value outside its bound is refused by the node.
- **`degraded`** lists, closed, what has gone wrong since the previous heartbeat: `drops-driver`, `drops-decoder`, `drops-channel`, `decoder-errors`, `sessions-unparsed`, `table-evictions`, `dnp3-pending-overflow` and `interface-bound`. An empty list means none of these happened. It never means the sensor saw everything (AP-36 residual). The node's own checks stand beside it (§6, and the baseline note §5).

## 4. Observations

### 4.1 Common fields

```
{ "schema": "otsec.netobs/0.1", "type": "observation",
  "sensor_id": "...", "run_id": "...", "seq": "42",
  "kind": "flow|service|function|insecure|encrypted|identity|undecoded",
  "first_sight": true,
  "first_utc": "...", "last_utc": "...", "resolution_ns": 1000,
  "l2": { "src_mac": "..", "dst_mac": "..", "vlan": 10, "ethertype": "0x0800" },
  "ip": { "src": "192.0.2.10", "dst": "192.0.2.20", "l4": "tcp", "sport": 51234, "dport": 20000 },
  "direction": "client-server|midstream|none",
  "protocol": "<token>",
  "citation": { ... }, "coverage": { ... },
  "<kind>": { ... },
  "frames": [ { "n": 17, "ts": "...", "data": "<base64>" } ] }
```

- **Kinds** match GT-PCAP's label kinds one to one, so the checker compares field by field (D6 plan §1 and §7):

  | Kind | Label kind |
  | --- | --- |
  | `flow` | `flow` |
  | `service` | `service` |
  | `insecure` | `insecure` |
  | `encrypted` | `encrypted` |
  | `undecoded` | `seen-not-decoded` |
  | `function` | `case` rows that name a function code |
  | `identity` | the identity rows of §2B and §2C |

  `kind` is closed.
- **`ip`** is absent for a layer-2-only frame such as GOOSE, SV, LLDP or PRP supervision. `l4` is `tcp`, `udp` or `other`.
- **`direction`** is `client-server` when the sensor saw the TCP SYN without ACK, and then `src` is the client. It is `midstream` when it saw no handshake, and then `src` is the first frame's sender. It is `none` for UDP and layer 2. This is GT-PCAP's own rule (D6 plan §1).
- **`protocol`** is an open set of tokens: `dnp3`, `modbus`, `telnet`, `ftp`, `http`, `snmp`, `tls`, `ssh`, `iec104`, `mms`, `goose`, `sv`, `prp-supervision`, `lldp`, `c37.118`, `enip`, `opcua`, `unknown`. A later minor may add tokens. A reader that meets a token it doesn't know reads the observation as `undecoded` traffic of that token, never as a decoded protocol. That way a new decoder can't silently change V-M6's counts on an old node.
- **`first_sight`** is true the first time the sensor reports the observation's key since its start (§4.2).

### 4.2 First sight, and which observations carry bytes

The node's detector raises alerts as it reads observations. An alert must carry its packets (R6.5), and the node can't read the sensor's ring (D5 §4), which may rotate first under a flood. So:

- **A first-sight observation carries its cited frames' bytes** in `frames` (base64, redacted as cited, at most 8, each at most 2,048 bytes). The node checks every frame against its cited hash and refuses the record on any mismatch. It then strips `frames` from the stored body and stores the bytes as the record's C5 capture: a classic pcap of the cited frames in citation order, with the frames' own timestamps. The byte form is pinned, because `stored_capture` is the SHA-256 of these bytes and an alert capture that is one first-sight capture byte for byte shares its digest (§14 item 11):
  - **The file header**, 24 bytes, all little-endian: the nanosecond magic `0xa1b23c4d` (bytes `4d 3c b2 a1`), version 2.4, `thiszone` 0, `sigfigs` 0, `snaplen` 2048 (`MaxFrameBytes`), and link type 1 (`LINKTYPE_ETHERNET`).
  - **Each record**, 16 bytes of header, little-endian, then the frame's bytes as delivered, redactions applied. The header holds `ts_sec` and `ts_nsec` from the frame's `ts`, `ts_nsec` being its full nanoseconds (a `ts` with fewer than nine digits is read as zero-padded), `incl_len` equal to `captured_len`, and `orig_len` equal to `wire_len`.
  - **Nothing else.** The file has no trailing bytes, and no record carries the frame's `lan`, which stays in the citation.
  - **A frame's `ts` must fit the 32-bit seconds,** 1970-01-01T00:00:00Z to 2106-02-07T06:28:15Z. The node refuses a record whose frame falls outside, as `range`. The node's object gains `stored_capture`, the capture's SHA-256 (§5). The citation itself is unchanged (§14).
- **Every other observation carries its citation only.** Its bytes stay in the ring while the ring holds them (D5 §4).
- **An alert has its own capture,** built the same way from the frames it cites (up to 4 flows, 2 frames each, §7.1), taken from those first-sight captures. Where it is byte for byte one first-sight capture, it has the same SHA-256, and C5 keeps the bytes once. Otherwise it is a new capture. Either way it is charged to the alert class (#532 §2), and it lives as long as the alert does (EP-6), whatever happens to the observations.

**The key of a first sight,** by kind:

| Kind | Key |
| --- | --- |
| `flow` | `l4`, the sorted pair of (address, port), and `vlan`: one TCP connection or one UDP conversation |
| `service` | server address, `l4`, server port, `protocol` |
| `function` | the flow's key, the function code, `sub` where present, the sorted object set, `unit` for Modbus, and `sa` for DNP3 (§4.3) |
| `insecure` | the flow's key and `reason` |
| `encrypted` | the flow's key and `scheme` |
| `identity` | server address, `attribute` and the value's SHA-256 |
| `undecoded` | `l4` with server port, or `ethertype`; and the server address, or the source MAC for layer 2 |

**How often a repeat is emitted.** A `flow` gives its `start` and `end`. Every other kind is emitted at most once per key per flow, at the key's first occurrence in that flow, with its citation and no bytes unless it is a first sight. A DNP3 poll repeated in one connection therefore gives one `function` observation for that connection, not one per poll. Because `sa` is in the key, a different outcome for the same code and objects is a new key and is emitted again. So an unchallenged operate after a challenged one in the same connection, which is a downgrade, gives its own observation with `sa: none`, and a `failed` after a `challenged` gives its own with `sa: failed` (D2). Because `unit` is in the key, a write to a second unit behind a gateway, such as an RTAC, in the same connection is emitted too (D2). 0.1 carries no per-flow occurrence count (D6). **So a count of `function` observations, or of an alert's `hits`, is not a count of operations.** 100 operates in one connection give one observation and one hit. The R9 view and any report say "connections that carried the function", never "operations" (D6).

The sensor keeps its first-sight table in bounded memory. When an entry is evicted, the sensor counts a `table-evictions` (§3.3), and the key's next occurrence is a first sight again. So an eviction can repeat an observation, but it can never hide one. The detector judges repeats by the acknowledged baseline, not by `first_sight` (baseline note §3).

### 4.3 Per-kind fields

- **`flow`**: `{ "phase": "start|end", "packets": n, "bytes": n, "end": "fin|rst|idle|sensor-stop", "syn_only": true|false }`. `end` and `syn_only` are on the `end` phase only, and `syn_only` is there exactly when `l4` is `tcp`. It is `true` only when the flow holds at least one client SYN, and every frame of it is either a client SYN with no ACK and no payload, or a server RST with no SYN and no payload; ECN's ECE and CWR bits are ignored. That is `netobs.SynOnly`, the one definition the sensor and any checker use. Anything else is `false`: a SYN carrying data (TFO), a SYN-ACK, a client ACK, data either way, and a midstream flow. So `true` needs `direction: client-server`. With one-sided capture, a session that carried data still shows the client's ACKs or data, so it is never `syn_only`, and `false` fails closed, because only `true` lets a flow take the failed-dial tie (§14 item 10). `packets` is every frame of the flow after the PRP discard, TCP retransmissions included. `bytes` is the sum of `wire_len` over those frames: link-layer octets with any 802.1Q tag and RCT, without the FCS, which is tshark's `frame.len`. A flow cut by `idle`, or a 5-tuple reused after FIN, gives several `start` and `end` pairs with one key, and a checker sums the `end` records by key (D6). A flow gives two observations. `start` is its first sight, with the counts so far. `end` gives the totals over the flow, and `end` says why it closed, including `idle` after `flow_idle_s` (carried in `coverage.settings`), and `sensor-stop`. V-M6's packet counts and ADR-0009's PRP condition read the `end` record. The detector reads `start`.
- **`service`**: `{ "basis": "content|port", "version": Text? }`. The server is `ip.dst`. `basis` says whether the protocol was found by its content or only by its port, which ADR-0009 protocol point 2 needs. `version` is present only where the protocol shows one in clear: an SNMP message version, an HTTP `Server` header, a Telnet or FTP banner, an SSH identification string. For TLS it is the negotiated version from ServerHello's `supported_versions` when present, otherwise the ServerHello version (D2 on #527). A HelloRetryRequest has the ServerHello format and carries `supported_versions` too, so the sensor takes the version from the last ServerHello of the handshake (D2).
- **`function`**: `{ "code": n, "sub": n?, "objects": ["g50v1", ...], "unit": n?, "sa": "challenged|aggressive|failed|none"?, "sa_error_from": "master|outstation"? }`. It covers requests only, the frames the client sends to the server. A response's objects depend on which events the outstation has, so they are not a function (D6, D2). For DNP3 it is never emitted for 0 (confirm, sent by both ends), 129 or 130 (responses), or 131 (the authentication response) (S23 Table 2.30 pp. 82–83). Nor is it emitted for a 32 or 33 that carries group 120 objects and joins a pending exchange: that frame is part of the exchange's `sa`, not a request of its own (§14). A 32 or 33 with no pending exchange to join is emitted as any request is, class `other`.
  - `code` is the application function code as on the wire: DNP3's application-layer function code, or Modbus's function code.
  - `objects` are DNP3 object headers as `g<group>v<variation>`, sorted, with at most 16 kept. It is empty for Modbus.
  - `sub` is present only on Modbus 8 and 43, and holds what `fc-classes/1` needs to class them (§14). For 8 (Diagnostics) it is the sub-function, 0 to 65535 (S22 Tables E.18 and E.19, D2). For 43 (Encapsulated Interface Transport) it is the MEI type, 0 to 255. It is absent on every other code and on DNP3.
    - **Byte order.** The sensor reads the sub-function high byte first. That is the Modbus convention, and no held source states it, so it is `unknown` from the held set (D2). The order decides whether sub-functions 1 and 4 land in `control`.
    - **The MEI type** is the first byte after the function code. No held manual lists 2Bh, so that position and the value 14 for Read Device Identification are `unknown` from the held set, as the baseline note's row says (D2).
    - **A request too short to hold it** gives `sub` absent, and the record is still valid. The node classes it by the most restrictive row for its code: `control` for 8 and `write` for 43, never `other`. That fails closed against `authorized_writers` (D1 on #543, baseline note §4).
  - `unit` is the Modbus unit identifier.
  - `sa` is DNP3 only, and it is a **fact about the exchange**, not a verdict (D2). Which functions must be challenged is the outstation's configuration (S23 §12.3.1, p. 88), which the sensor can't see. So the sensor reports what happened on every DNP3 request, and the node decides `dnp3_no_sa` from `fc-classes/1` (§5). The values are:
    - `challenged`: the outstation sent a group 120 challenge before its response to the request;
    - `aggressive`: the request itself carries g120v3 with g120v9 (aggressive mode, S23 Table 2.30 pp. 82–83), so no challenge follows;
    - `failed`: a challenge or an aggressive-mode request was followed, in the same exchange, by an object g120v7 "Authentication -- Error" in function 33 from the master or function 131 from the outstation (S23 Table 2.30 p. 83). `sa_error_from` records which end sent it, and is present only with `failed`. The sensor reads 33 and 131 for this, though it never emits them as `function` observations (D2);
    - `none`: the request completed with none of these. A request completes at the outstation's response (function 129) with the same application sequence number. A request whose code has no reply (6, direct operate with no reply, S33 Table F.2 p. F.3, and the no-acknowledge freezes) completes when no challenge has come within `sa_reply_timeout_ms` (§10).
  - The pairing follows the (master, outstation, application sequence number) exchange, not a TCP flow, so it holds for DNP3 over UDP 20000 too (S22 Table D.7, p. D.11). **A reused sequence number completes the pending exchange first** (D2, D4-68). When a new request has the same (master, outstation, application sequence number) as a pending one, the pending one is emitted at once with what has been seen, before the new one becomes pending. The number wraps, and its width is in IEEE 1815, which the project doesn't hold. Without this rule, the new request's response would complete the old request and could give it a false `sa: none`, and so a false `dnp3_no_sa`. The heartbeat counts each exchange completed early this way under `dnp3_seq_reused`. It should sit near zero, so a rise makes visible an attacker who reuses the number before the g120v7 arrives to lose an `sa-failed` (D3, D4-68). A request with function 32 or 33 that carries group 120 objects belongs to the pending exchange, and never completes it early or counts under `dnp3_seq_reused` (D2).
  - **A DNP3 `function` observation is emitted once its `sa` is known,** not at the request: at the response, the challenge's outcome, the error, or `sa_reply_timeout_ms` (D2). **Every pending request completes at `sa_reply_timeout_ms`, whatever its code** (D3, D1). It is emitted then with what has been seen: `failed` if the error was seen, `challenged` or `aggressive` if that was seen with no error, `none` for a code with no reply and no challenge, and `sa` absent otherwise, for example when the sensor missed the 129. The class comes from the code, so `unauthorized-write` still fires on an operate whose response the sensor missed. No DNP3 request waits longer than `sa_reply_timeout_ms` to be emitted. It cites the request first, then the frames that decided `sa` and ended the exchange: the challenge, the master's reply to it, and the g120v7 error or the response (129) that completed it, as far as they exist (§14). That is at most 4 frames, within `MaxCitedFrames`.
  - **`sa` absent means not known.** The node never sets `dnp3_no_sa` from it (D1). A reply or challenge that arrives after the request was emitted is not paired again.
  - **The pending table is bounded** by `max_pending_dnp3` (§10). When it is full, the oldest pending request is emitted at once, in the same way, to make room, and the heartbeat counts it under `dnp3_pending_overflows`, with `dnp3-pending-overflow` in `degraded`, as a coverage loss (§3.3, §6). The counter is apart from first-sight evictions, so an overflow that can lose an `sa-failed` shows by name (D6, D4-68; AP-36 (b)). At `sensor-stop` every pending request is emitted the same way. So an overflow can leave a request's `sa` unknown, but it can never hide the request (D5, D3, D1).
  - **`failed` keys on the object's presence, never on its contents** (D2). The project holds neither IEEE 1815's SA clause nor IEC 62351-5. S23 confirms only the object's name, the functions that carry it, and its qualifier 5B. The error code's offset, the other fields and every code value are `unknown`, so the sensor decodes no reason and keeps no code.
  - The baseline's `functions` key is (code, `sub`, objects) per pair. The learner and `new-function` ignore `sa` and `unit`, so a new SA outcome or unit is not a new function. They don't ignore `sub`, so a new diagnostic sub-function is one.
  - The sensor does not classify codes as read or write. The node does, from one versioned table in the baseline note (§4 there), so the class table lives in one place.
- **`insecure`**: `{ "reason": "telnet|ftp|http-plain|snmp-v1|snmp-v2c|modbus-tcp", "login": { "user": Text?, "attempts": n, "slot": "placed|not-placed|none", "why": "<token>"? }?, "redirect_only": true? }`. This is V-M6's insecure list as R6 states it, except DNP3 without SA, which the node derives (§5).
  - `reason` is closed. A new entry on the list is a new minor.
  - `redirect_only` is present, and true, on `http-plain` when the server only redirected to HTTPS and no credential was seen. Plain HTTP stays insecure then, as D1 ruled, and the observation says why (D2).
  - `login` is present for Telnet, FTP and HTTP Basic. What is kept is what matters as evidence: that a secret was sent in clear, the user name, and the number of attempts (D4-67). The secret is never kept.
- **`encrypted`**: `{ "scheme": "tls|snmpv3|ssh", "tls": { "version": "<token>", "sni": Text? }?, "snmpv3": { "engine_id": "<hex>", "user": Text, "level": "noAuthNoPriv|authNoPriv|authPriv", "boots": n?, "time": n? }? }`.
  - Only what the handshake or header shows in clear is kept (V-M6).
  - The SNMPv3 level comes from `msgFlags` (D2, D6 plan §2B).
  - `engine_id` is lowercase hex, 5 to 32 octets (RFC 3411).
  - A `noAuthNoPriv` exchange is recorded as `encrypted` with that level. Its PDU is in clear, and D2 raised it for the owner (#528). It is not on the insecure list, so C13 doesn't flag it.
- **`identity`**: `{ "attribute": "fid|partno|devid|engine-id|banner|http-server|snmp-sysdescr|ssh-ident", "value": Text, "via": "<protocol>" }`. This is a value read in clear from the server end. `fid`, `partno` and `devid` come from the same SEL `ID` reply (S22 Table 7.43, Fig. 7.38, p. 7.64), and `partno` gives the model R6.7 compares (D2). DNP3 group 0 device attributes and Modbus Report Server ID are also in clear, but they are not read in 0.1, which is a stated limit (§12). R6.7's path to C12 is the baseline note's §6. C13 records the value and nothing else, and a passive identity never changes the asset's identity (AP-34 (4)).
- **`undecoded`**: `{ "basis": "port|ethertype|none", "packets": n }`. This is traffic the sensor saw and did not decode, which is how a `seen-not-decoded` label is met (D6 plan §2A).

### 4.4 PRP and HSR

A sensor that sees both LANs records each flow, service and function once. Its counts equal the LAN-A-only capture's (ADR-0009's PRP row, D6). The sensor discards a frame whose (source MAC, RCT sequence number) it has seen within `prp_window_ms`, before decoding, and counts the discards. The coverage statement says so (§3.3). The node raises `sensor-coverage-mismatch` for a sensor that reports both LANs and `duplicates_discarded: false`. Its observations are still stored, because dropping them would blind the node, but status shows the counts as unreliable. HSR is `not-decoded` in 0.1.

## 5. What the node adds before it stores an observation

The node validates the record, checks the frame hashes (§4.2), and then adds a `node` object. A record arriving with `node` already set is refused.

```
"node": {
  "src_asset": "<asset id>|asset-unresolved", "dst_asset": "<asset id>|asset-unresolved",
  "resolved_by": "ip|ip-ambiguous|none",
  "platform_session": { "invocation_id": "<uuid>", "tie": "connection|window" }?,
  "evidence_class": "device-observed|simulated",
  "stored_capture": "<sha256>"?,
  "function_class": "read|write|control|session-setup|time-sync|other"?,
  "function_table": "fc-classes/1"?,
  "dnp3_no_sa": true?
}
```

- **Assets.** Each end resolves by its IP address against the C1 endpoints of the assets enrolled on this node that count for resolution: the inbound endpoints, and the outbound endpoints whose `CheckPath` passes, which today means a known transport on a `direct` path (§14 item 9). A resolution is a label for detection and for `source.asset`, never identity evidence (§14 item 9). Every host is compared after `Unmap().WithZone("")`, as the sensor sees it. Each end resolves on its own (D1 in D4-70, D3 on #553). An address shared by two assets over that same set names neither, so that end is `asset-unresolved` (AP-35's enrollment flag), while the other end keeps its asset if it resolves. `resolved_by` is `ip-ambiguous` when at least one end's address is shared, `ip` when an end resolved and neither end is shared, and `none` when neither end matched anything. The C4 event's `source.asset` is the destination asset, or the flag `asset-unresolved` when it doesn't resolve. For `service`, `identity` and `function` the destination is the server.
- **`platform_session`** ties the observation to one of the node's own sessions (AP-35, baseline note §5). `tie` is `connection` when the collector's record is a connected C2 0.9 result: the flow has the session's exact 5-tuple from `local_addr`, and its time agrees with `connected_at` under the note's time rule. Otherwise it is `window`. That covers two cases. One is a 0.8 result, where the tie is the collector's address to the device's address and port, within the session's window plus a grace period for the TCP close (ADR-0009 Consequences, D2). The other is a failed dial's half-open flow, `syn_only: true`, to the run's endpoint inside the run's window (D1 on #547, baseline note §5).
- **`evidence_class`** comes from the node's configuration for this sensor, never from the record (D1-23): `simulated` for a GT-PCAP replay or a lab interface.
- **`stored_capture`** is present on a first-sight observation (§4.2).
- **`function_class`** is set on a `function` observation from `fc-classes/1` (baseline note §4). **`function_table`** names the table version the node used, and is present exactly when `function_class` is (§14).
- **`dnp3_no_sa`** is true on a DNP3 `function` observation whose class is `write`, `control` or `session-setup` and whose `sa` is `none`. This is how V-M6's "DNP3 without Secure Authentication" is flagged: by the node, from the one class table, never by the sensor (D2). `failed` never sets it: SA was in use and refused the request (g120v7), so flagging it would be a false V-M6 flag and would hide the one sign that SA works. A failure stays visible as `sa: failed`, and raises `sa-failed` (§7, D1, D4-68). Reads are not challenged by default (S23 pp. 73–74). The held sources give no other default (S23 §12.3.1, p. 88), so the critical set is `write`, `control` and `session-setup` by D4's choice, consistent with the sources but not confirmed by them. Time-sync is left out by the same choice (D2).

**Unresolved observations.** An observation counts against D5's unresolved budget only when neither end names an asset, whatever its `resolved_by` (#532 §4, D1 in D4-70). An observation with one end resolved is not budgeted, even when its other end is ambiguous. An unknown master polling an enrolled relay must reach the detector. Such traffic is bounded by the class quota and by the coalescing of its alerts (§7.3). D6's flood test decides whether this holds (D5 §9).

## 6. The heartbeat

```
{ "schema": "otsec.netobs/0.1", "type": "heartbeat", "sensor_id": "...", "run_id": "...", "seq": "43",
  "at_utc": "...", "coverage": { ... },
  "counters": { "packets": n, "bytes": n, "drops_driver": n, "drops_decoder": n, "drops_channel": n,
                "decoder_errors": n, "sessions_unparsed": n, "table_evictions": n, "dnp3_pending_overflows": n, "dnp3_seq_reused": n, "prp_discards": n,
                "redactions": n, "logins_not_placed": n },
  "ring_oldest_utc": "...", "interface_check": "ok|bound|unknown" }
```

- The counters are totals since `run_id` began, as decimals, and **never decrease within a run**. The node refuses a heartbeat whose counter is lower than the last one in the same run, and counts it under `sensor-record-refused`. A new `run_id` starts the differences from zero. The node writes the differences as a health event at most once a minute, and only when a counter other than `packets` or `bytes` changed. Status shows the live totals (D5).
- `drops_driver` is what the capture driver reports. Under (a′) and (c′), that is `pktmon`'s lost-event count. A driver that reports nothing leaves `drops_driver` out of `counters`, which means `unknown`, never zero. The monotonic check skips an absent counter.
- `interface_check` is D5 §7 step 4's binding read.
- A heartbeat carries no device text, and no frame bytes.

## 7. Alerts

### 7.1 The form

An alert is a C4 `telemetry-health` event of type `netobs.alert`, stored in `network-alert` with its cited frames as its capture. It reuses C10's departure alarm (`contracts/baseline/alarm.go`) where the two fit:

```
schema, rule, asset_id ("<id>"|"asset-unresolved"), baseline, baseline_version,
key_text, params (param.<name>), baseline_value, observation, clock ("capture"),
at_utc, window_start_utc, hits, sources, related (observation event IDs, ≤ 32, with related_total),
cite.1 .. cite.4 ("<capture_id> <n>=<sha256> ..."), capture (<sha256>), coverage.* (§3.3, flattened)
```

- **`rule`** is closed, from the baseline note's §4:
  - `unknown-pair`
  - `new-service`
  - `new-function`
  - `unauthorized-write`
  - `own-session-outside-record`
  - `node-address-spoofed`
  - `own-session-unseen`
  - `unresolved-address`
  - `sa-failed` (D1, D4-68)

  Each rule has exactly the parameters the note gives it, as C10's `ruleParams` does.
- **`baseline` and `baseline_version`** name the acknowledged network baseline the rule judged against (§8). `own-session-outside-record`, `node-address-spoofed`, `own-session-unseen` and `sa-failed` don't depend on it. They run before any baseline is acknowledged, and give the baseline in force, if there is one (D1).
- **`key_text`, `baseline_value` and `observation`** are the node's own words, at most 256 bytes each (C10's `ExplainMax`). Device text appears in them only as a quoted, escaped `Text` value.
- **Citations:** up to 4 flows, each `cite.<i>` giving its capture ID and up to 2 frames with their hashes. `capture` names the alert's own C5 capture: a classic pcap of those frames in citation order, built as in §4.2, at most 16,536 bytes.
- **`sa-failed` cites the challenged or aggressive-mode request and the g120v7 error** from its `function` observation (§4.3). Its `observation` text says "SA authentication failed, error sent by the master" or "by the outstation", and never "forged", because the sensor can't check the authentication codes (baseline note §8). It never states a number of failures. The outstation caps how many errors it sends (S23 §12.4.8, p. 89), and an observation is emitted once per key per flow, so `hits` counts connections with at least one seen failure. It is a lower bound, not a count of attempts (D2).
- **`own-session-unseen` cites nothing,** as C10's absence alarm cites no event. Its `observation` names the session record (invocation ID and window).

### 7.2 Where C10's form does not fit, and why

| C10 | C13 | Why |
| --- | --- | --- |
| Cites events only | Cites packets too (`cite.*`, `capture`) | R6.5: every alert links to packets that can be retrieved. |
| `clock` is `received` or `device` | `clock` is `capture`, the sensor host's clock | The triggering frame's time is what R6.4's latency measures. |
| No coverage | `coverage.*` on every alert | The brief and R6.1: an alert says what the sensor could see. |
| Key: the event type | Key: rule × destination asset, or the unresolved bucket (§7.3) | D1's ruling for D4-68. A port or address in the key would let an attacker mint new keys for free. |
| Hold per (asset, rule, key) per `alarm_hold_s`, then `alarms-held` | Coalesced per window, with `hits` and `sources` | Same purpose. The count and distinct sources are evidence an operator needs for a scan or a spoofing flood. |

Reused unchanged from C10: the health-event transport (no C4 or C6 change), `Param`, the baseline hash and version, `ExplainMax`, and lists of at most 32 event IDs with a total.

### 7.3 Coalescing (D1, for D4-68)

Within a window of `coalesce_window_s` (default 300, bounded 60 to 3600), the alerts of one rule against one destination asset make one key. So do the alerts of one rule whose destination is unresolved, which share one bucket. The detector:

1. **Commits the first alert of a key in a window at once,** with `hits` 1. A real write to an enrolled relay therefore alerts within the replay's latency. Under attack it is never queued behind decoys aimed at other assets, because those decoys have other keys.
2. **Counts the rest of the window's hits on that key.** At the window's end, if there were more, it commits one summary alert for the key, with `hits`, `sources` (the count of distinct source addresses, a number, not a list), and the first 4 flows' citations. Its `related` lists the observation of every hit in the window, the first alert's included, up to 32, with `related_total`, so every hit up to 32 can be attributed for R6.3 and R6.4 (D6). `sources` counts up to 32 distinct addresses and then stops, because the detector must hold the addresses to tell a new one from a repeat (baseline note §8).
3. **Holds at most `MaxDetectorWindows` (96) windows open** (D1 in D4-72). Each open window is in the detector's checkpoint (§8), which must fit one configuration record. When all 96 are open, a new key still alerts at once. To make room, the window that started earliest closes early, ties going by rule and then asset. If it had repeats, it gives its summary then, and otherwise it closes with no record. The key opens a new window the next time it is hit. So every hit is still counted once across the alerts, in a first alert or a summary. **The cost:** past 96 open keys, a key can give up to one record per hit instead of two per window, because each early close can be followed by a new first alert for the same key. A window gives at most its first alert and one summary, and the summary only after a repeat, so records never outnumber hits (D4 on #572, D1 in D4-72). The per-key drop count shows it if the alert class fills (#532 §4). Before that, the detector counts its early closes (`EarlyCloses`), and the node shows the count in status, so decoys rotated over more keys than the cap show before the class fills (D3's C1 on #569). In the checkpoint, a window's related observations are kept as seqs on the observation stream, which the checkpoint names once. The alert still carries full event IDs, and the cited capture still holds the bytes.

**Latency.** An alert's `at_utc` is the triggering frame's capture time. The time the node committed the alert is the C4 event's `received.utc`, on the node's clock. R6.4's latency is that minus the frame's send time, on one host clock under the timed replay (D6 plan §5). For a rule that judges a DNP3 `function` (`new-function`, `unauthorized-write`, `sa-failed`), the observation waits for its `sa`: until the response or the challenge's outcome, and at most `coverage.settings.sa_reply_timeout_ms`. The checker allows that wait for those rules (D6).

So a key writes at most two alert records per window, and the alert records per window are at most 2 × rules × (assets + 1), whatever the ports or addresses, while no more than 96 keys are open at once (item 3). This bounds the `network-alert` class's write rate and gives D5's alert floor its number (#532 §4). A drop at a full class is counted by the same key (D1; #532 §4, per rule).

**D1's ruling (D4-68).** Two records per key per window: the first at once, for R6.4, and the summary at the window's end only if the key had repeats. The cap is 2 × rules × (assets + 1) per window.

## 8. The network baseline document

The learner builds the network baseline from observations over a period the operator starts. A person acknowledges it by signed digest before the detector uses it (AP-36 (1), HR-14). Its contents are set out in the baseline note §2. C13 fixes its stored form:

- It is a configuration-class document, series `baseline.network`, on the stream `netbaseline/<sensor>` (#532 §8). Its first field is its schema, `otsec.netbaseline/0.1`, so readers that skip by schema prefix pass over it.
- Its hash is `sha256:` and the hex SHA-256 of its exact stored bytes, as C9 and C10 hash theirs (D4-4 item 5).
- **Its encoding is canonical:** the bytes `json.Marshal` gives for its Go type, with fields in declared order, no insignificant whitespace, and every list sorted and without duplicates. An empty list is `[]`, never `null`. A document is canonical when decoding it strictly (unknown fields refused) and encoding it again gives the same bytes. The learner writes only canonical bytes, and the node adopts only canonical bytes (baseline note §2.3).
- It holds the learned pairs, services and function codes, the learning period, and the **authorized writers**. That is a list a person fills in before acknowledging, and it is never learned (D6 plan §7, A4 §3).
- **Draft and accepted.** The learner records the frozen draft with an empty writer list. The accepted document is that draft with the person's writers filled in, and nothing else changed. The node adopts it only through D3's signed path: `node.network_baseline_ack` names both `baseline_digest` and `draft_digest`, and the node checks that the file differs from the latest recorded draft only in `authorized_writers` (baseline note §2.3, D3's §1). Both are stored in `baseline.network`. Only the draft has a `config.baseline_recorded`. The accepted document's record is the `config.baseline_acknowledged` that names its digest, so two `baseline.network` documents per learning run is normal.
- It is bounded by `MaxBaselineBytes`. The value is set in code at the configuration class's record cap, less headroom, as C10's `MaxBytes` is.

Each of the two local consumers of the observation stream checkpoints its state in its own working-state series (D1's ruling, D4-68). Both use schema `otsec.netcheckpoint/0.1`, and both are removable, as `eventcheckpoint.learner` and `eventcheckpoint.detector` are:

- **The learner's draft** is in `netcheckpoint.learner`. Without it, the learner's cursor couldn't move during the learning period, the observation class would fill, and new observations would be dropped (D5). The draft is bounded by `MaxBaselineBytes`. The document (`netobs.LearnerCheckpoint`) is `schema`, `half` (`learner`), `sensor_id`, `through` (the last observation-stream seq the learner took; it folds nothing at or below it, so a re-read after a restore folds each observation once), `frozen`, `draft`: the draft in this section's canonical encoding, with no writers, and with `end_utc` equal to `start_utc` until it is frozen, and `held`: the TCP starts held until their flow proves them (baseline note §2.2), each `{src, sport, dst, pair}`, sorted by flow, at most `MaxHeldStarts` (512), and none once frozen. The draft and the held starts are the learner's whole state, so a restore decodes them and folds on. The checkpoint is at most `MaxLearnerCheckpointBytes`: the draft's bound, 512 held starts at `MaxHeldStartBytes` (384) each, and 1 KiB (§14 item 15).
- **The detector's state** is in `netcheckpoint.detector`. The document (`netobs.DetectorCheckpoint`) holds these fields:
  - `schema`, `half` (`detector`) and `sensor_id`;
  - `node_id` and `stream`: the observation stream it reads;
  - `baseline` and `baseline_version`: the acknowledged baseline it judges against, or `""` and 0 before any;
  - `through`: the last observation seq it took;
  - `last_alert_seq`: the last seq on the sensor's alert stream it knew to be committed;
  - `clock_utc`: the capture clock, the latest `first_utc` taken;
  - `windows`: the open coalescing windows (§7.3), sorted by rule and then asset, at most `MaxDetectorWindows` (96);
  - `coverage`: the coverage statement of the last observation taken, or `null` before any. `own-session-unseen` judges against it and carries it;
  - `session_through`: the health-stream seq of the last session record taken, or 0. A session at or below it is a replay and is skipped (§14 item 17);
  - `sessions`: the connected sessions of the node's own taken and not yet judged, in the order taken, at most `MaxPendingSessions` (128), each `{invocation_id, asset_id, ip, l4, port, started_utc, ended_utc, after_seq}`;
  - `tied`: the invocation IDs observations were tied to before their session record was taken, in the order first tied, at most `MaxTiedSessions` (256), each `{invocation_id, clock_utc}`;
  - `taken`: the invocation IDs of sessions handed over and done with, oldest first, at most `MaxTakenSessions` (128), each `{invocation_id, clock_utc}`, so a later record tied to one, such as an SNMPv3 flow's idle `end` after the run, takes no room in `tied` (D6's F1 on #575);
  - `endpoints`: the enrolled run endpoints' addresses seen in observations that are neither tied nor degraded, sorted by address, at most `MaxDetectorEndpoints` (256), each `{ip, vlans, vlans_overflow, lans}`, with at most `MaxEndpointVLANs` (8) VLANs (0 for untagged). This is the coverage record before acknowledgement (baseline note §4);
  - `degraded` and `degraded_open`: the capture-time intervals of runs of observations whose `coverage.degraded` was not empty, oldest first, at most `MaxDegradedIntervals` (64), each `{start_utc, end_utc}`, and whether the last observation taken was degraded.

  Each window holds what its summary would carry so far: the texts, `at_utc`, `window_start_utc`, `hits`, the distinct `sources` (sorted addresses, at most 32), `related` (the seqs of the first 32 hits on `stream`), the first 4 `cites`, and the latest hit's `coverage`. The checkpoint holds the detector's whole state, so a restore decodes it and replays the observations after `through` against the alerts committed after `last_alert_seq` (baseline note §3). It is at most `MaxDetectorCheckpointBytes`, the sum of its parts at their worst and an envelope: 96 windows at `MaxDetectorWindowBytes` (12 KiB), 128 pending sessions at 512 bytes, 256 tied IDs and 128 taken IDs at 128, 256 endpoints at 192, 64 intervals at 128, the coverage statement at `MaxCoverageBytes` (2 KiB), and 1 KiB, which is 1,354,752 bytes. That is strictly under the configuration record cap less its headroom, 1,507,328 bytes, with 152,576 bytes (10.1%) to spare (§14 items 16 and 17). `TestWorstDetectorCheckpointFits` builds the checkpoint with every part at its bound.

Each consumer's cursor is confirmed only after its own checkpoint commits (D5 §3). Either one can be lost and restored on its own, as D4-40 item 6 provides for the event baseline.

**The learner consumer exists only while learning** (D1). It starts when learning starts. When learning ends, the draft is frozen: the learner folds nothing more, and its cursor follows the detector's until acknowledgement, so pruning isn't held while the draft waits. The person signs the accepted document's digest together with the frozen draft's, in `node.network_baseline_ack` (HR-14, baseline note §2.3). When the baseline is acknowledged, the node retires it with an audit record, and it never holds pruning again. Relearning starts a new learner consumer.

## 9. What C13 asks of other contracts

| Contract | Ask | Owner |
| --- | --- | --- |
| C4 `otsec.event/0.3` | the kind `network-observation` (Kind is open, so no reader breaks), and an optional field `netobs` holding the stored observation (§4, §5), set exactly on that kind and on a platform event. It is additive, and a 0.2 reader ignores it. | D4 |
| C5 `otsec.store/0.9` (#532, merged at `19a4eff5`) | a first-sight observation carries a capture of at most 16,536 bytes; an alert's capture is charged to the alert class; and the series `baseline.network`, `netcheckpoint.learner` and `netcheckpoint.detector` (#532 §8). | D5 |
| C7 0.10 (#534, merged at `924a6e0`) | a separate admin kind, `node.network_baseline_ack`, naming the sensor, `baseline_digest` and `draft_digest` (D1, D4-68) | D3 |
| C8 0.12 (#534) | records for the network baseline's recording and acknowledgement, `config.learner_retired` for retiring the learner consumer (§8), and `store.retention_moved` (#532) | D3 |
| C2 | `SessionFacts.local_addr` and `connected_at`, so that the tie becomes `connection` (already proposed by D2) | D2, opened by D1 |
| C12 | nothing (baseline note §6, D4-53) | |

The C7 and C8 asks are needed before the detector acts on a baseline, not before observations are stored. D1 may approve C13 and C5 0.9 in D4-68, and brief C7 and C8 with the implementation.

## 10. Bounds

| Name | Value | Basis |
| --- | --- | --- |
| `MaxChannelFrame` | 64 KiB | the largest observation (8 frames of 2,048 bytes in base64) plus its fields, with room |
| `MaxCitedFrames` | 8 | enough for a handshake plus the first application exchange |
| `MaxFrameBytes` | 2,048 | Ethernet with 802.1Q and RCT; a longer frame is cut, with `wire_len` kept |
| `MaxWireLen` | 262,144 (256 KiB) | D4's choice: above a jumbo frame and above a segment an offload has coalesced to 64 KiB, and far below the 32-bit `orig_len`. A larger `wire_len` is refused (D3 on #553) |
| `MaxTextBytes` | 256 original, 1,024 escaped | the 254-character banner (TCBAN), whole |
| `MaxCoverageBytes` | 2 KiB | 64 VLANs, 8 interfaces, the protocol list |
| `MaxObjects` | 16 | DNP3 object headers per function observation |
| `MaxRedactions` | 16 per cited frame | bounds the worst stored observation, so C4's `MaxNetobsBytes` can be pinned. A frame with more slots fails closed as one `slot-not-placed` (§3.2, §14) |
| Alert citations | 4 flows, 2 frames each | an alert's capture stays under the alert class's record cap |
| `coalesce_window_s` | 300, bounded 60 to 3600 | D1's ruling |
| `sa_reply_timeout_ms` | 5,000, bounded 1,000 to 30,000 | D4's choice; no held source gives an outstation's challenge or response time. It must exceed a normal response time, because a reply after it leaves `sa` unknown, and it is the most a DNP3 `function` observation adds to R6.4's latency. The checker reads it from `coverage.settings` |
| `flow_idle_s` | 60, bounded 10 to 600 | D4's choice. A flow silent this long is ended as `idle`. The bound caps how long the node holds a flow from its own address (baseline note §5). Carried in `coverage.settings`, required |
| `max_pending_dnp3` | 4,096, bounded 256 to 65,536 | D4's choice: at 5 s per request it holds about 800 requests a second before overflow, far above a station's polling. An overflow emits the oldest request with what has been seen and counts `dnp3_pending_overflows`. Carried in `coverage.settings` |

The worst cases are pinned by tests in `contracts/netobs`, as C10's `TestWorstAlarmFits` does. `TestWorstObservationFits` pins the channel record. `TestWorstStoredObservationFits` and `TestWorstAlertFits` pin what the store caps: the C4 event plus its capture (`Record.Bytes`), at most 64 KiB, the smallest record cap C5 allows. That is about 34 KiB today (D5). D5's record caps and floors use those numbers (#532 §4).

## 11. How each check in V-M6 and R6.1 to R6.5 reads these records

| Check | Field |
| --- | --- |
| Every labelled service, against its asset | `kind: service`, `ip.dst`, `dport`, `protocol`, `service.version`, `node.dst_asset` |
| Every observation cites its packets | `citation`, matched by per-frame hash, with redactions matched to `secret-slot` rows (D6 plan §1) |
| Every insecure use flagged | `kind: insecure`, `reason`; for DNP3 without SA, a `function` observation with `node.dnp3_no_sa` |
| A failed DNP3 SA authentication alerted | a `netobs.alert` with rule `sa-failed`, citing the request and the g120v7 error |
| Encrypted sessions record only the handshake | `kind: encrypted`. No field holds payload |
| Missed rows are recorded limits | `coverage.decodes`, `kind: undecoded`, `coverage.degraded` |
| PRP once | the `flow` `end` records whose key matches the label's, summed, with `packets` and `bytes` equal to the label's |
| Found by content, not port | on the moved-port rows, a `service` with `basis: port` fails: the sensor must find the protocol by content, or report it `undecoded` |
| Hostile text bounded | `Text` (§3.1). The node refuses any other form |
| Alerts link to retrievable packets | `cite.*`, `capture`, and the capture's bytes hashing to the cited SHA-256s |
| No packet bytes upstream | an alert carries `cite.*` and `capture` (hashes), never bytes. Observations are never forwarded |
| No ML field | none |

## 12. Not in C13

- The rules themselves, the learner and the detector: the baseline note.
- The sensor's decoders and its ring format, beyond the citation and redaction rules here.
- Identity from DNP3 group 0 device attributes and from Modbus Report Server ID. Both are in clear, but 0.1 doesn't read them, which is a stated limit (D2).
- The channel's transport under each option: D5's note §2 and ADR-0009.
- C5 classes, quotas and alarms: #532.

## 13. Open questions

None. D2 closed the last one, on the DNP3 `sa` values, the critical-function set and the TLS version rule.

## 14. Revision after D4-68: gaps found in coding (D1, 2026-11-07)

Coding `contracts/netobs` found places where the approved text could not be coded as written. D1 agreed items 1 to 4 on #543. Items 5 to 8 come with the `contracts/netobs` code, and D1 ruled item 9 on #549. D1 ruled items 10 and 11 in D4-70, with the baseline note's widened tie (§5), and items 13 and 15 in D4-71. D1 confirmed item 14, D4's answer to D6's A1 on #561, in D4-71, and ruled item 16 in D4-72. The identifier stays `otsec.netobs/0.1`, because no sensor or node has written a record under it.

1. **Modbus sub-function.** `fc-classes/1` classes Modbus 8 by its sub-function (0 is `other`, 1 and 4 are `control`) and 43 by its MEI type, but `function` had no field for either. So 8/1 could not be told from 8/0, and the class table could not be applied. `function.sub` now carries them (§4.3). It is in the first-sight key (§4.2) and in the baseline's `functions` entry (baseline note §2.1). D2 checked the readings on #543: the sub-function is read high byte first (Modbus convention, `unknown` from the held set), and a request too short for it gives `sub` absent. D1 ruled that the node classes such a request by the most restrictive row for its code, `control` for 8 and `write` for 43, never `other` (D1 on #543, after D2 and D3 differed).
2. **Redactions per frame were unbounded,** so the worst stored observation had no bound, and C4 0.3's `MaxNetobsBytes` could not be pinned. `MaxRedactions` is 16 per frame, and a frame with more slots is covered as one `slot-not-placed`. That is D4-67's fail-closed rule as amended by D4-68 ruling 13 (§3.2, §10). D3 confirmed it on #543.
   - The single `slot-not-placed` entry **replaces** the frame's per-slot `credential` entries for that side's payload. It does not sit beside them (D1 on #543).
   - The node refuses a cited frame that lists more than `MaxRedactions` redactions, and counts the refusal under `sensor-record-refused` (D1 on #543).
3. **`stored_capture` had two places.** §4.2 put it in the citation, while §5's schema put it in `node`. It is in `node` only (§4.2, §5).
4. **The table version had no field.** §5 said `function_class` names the table version, but no field held it. `node.function_table` holds it, exactly when `function_class` is present (§5).
5. **The channel decoder is strict about keys and about `node`** (D3 on #543). A record with a duplicate key, at the top level or nested, is refused as `decode`. So is a key in another case. A sensor record that carries `node` is refused: only the node writes it (§5).
6. **A `slot-not-placed` entry is its frame's only redaction** (item 2, D6 on #543). It covers that side's whole payload, and a frame carries one side's payload, so any other entry beside it would overlap it or sit outside the payload. The decoder refuses a frame that lists a `slot-not-placed` entry with any other (§3.2).
7. **A 32 or 33 inside a pending exchange is not a request of its own** (D4 on #548). §4.3 said such a frame "belongs to the pending exchange", but listed only 0, 129, 130 and 131 as never emitted. If a node emitted the master's 32 on its own, a challenged operate would raise `new-function` for a pair that never sent 32 in learning. So a 32 or 33 carrying group 120 objects that joins a pending exchange is never emitted as a `function`. One with no pending exchange is emitted as class `other`, so a stray authentication request stays visible (§4.3).
8. **A DNP3 function cites the response that completed it** (D4 on #548). §4.3 listed the frames that decided `sa` but left out the response (129) that completes an exchange with `sa` `none` or `challenged`. GT-PCAP's labels cite it, and the response is what shows the exchange completed. The worst case stays at 4 frames: the request, the challenge, the reply, and the error or the response (§4.3).
9. **Inbound endpoints count for resolution** (D1 on #549, from D5's question, with D2's points). Before this, an end resolved only against C1 endpoints whose path is `direct` (§5). A real DNP3 master enrolled only as a Syslog sender therefore stayed `asset-unresolved`, and its polling raised `unresolved-address` until learning put its address in `addresses`. Now:
   - **Resolution** counts, among the assets enrolled on this node, the inbound endpoints (`Transport.Inbound()`) and the outbound endpoints whose `CheckPath` passes, which today means a known transport on a `direct` path. An inbound endpoint is matched by address alone, because its port is optional and is the sender's.
   - **Not counted:** port-server endpoints, whose host is the port server and not the device; outbound endpoints with no path, whose host isn't known to be the device (D2-16); and transports from a later C1 minor, which C1 does not describe. Port-server resolution comes with the change that lifts H-13, under the same condition as the port-server tie (D1 on #547).
   - **Ambiguity** is computed over the same set. Two assets that share an address there resolve to neither at that address, as `ip-ambiguous`. Each end resolves on its own, so the observation's other end keeps its asset (§5, D1 in D4-70).
   - **Every host is compared after `Unmap().WithZone("")`,** as the sensor sees it, and not with `asset.CheckSenders`' key, which keeps the zone (D2).
   - **The session tie** (`platform_session`) counts only the endpoints the node connects to, so an inbound endpoint never ties.
   - **A label, not evidence (D3 on #549).** A resolution through an inbound endpoint names an asset for detection and for the C4 event's `source.asset`, and nothing more. It never raises the asset's identity confidence, never corroborates a C12 finding (a third party's traffic is unauthenticated, D4 on #528), and never counts as evidence for C1's inbound-sender check. So a spoofed source address can't turn itself into identity evidence.
   - **Spoofing (for D3).** A source address is only as trustworthy as the segment the sensor saw it on, as it is today. Resolution names an asset; it doesn't prove the sender. `unknown-pair` and `unauthorized-write` still judge the pair and the writer, and `node-address-spoofed` still guards the node's own address.
   - **The cost.** A Syslog sender recorded at a relay's or a NAT's address would name the wrong asset. C1 already asks for the device's own sending address, which the inbound-sender check relies on too.
   - **Two assets on one IP with different ports** resolve to neither at that address, as `ip-ambiguous`, and their traffic draws on the unresolved budget when its other end names no asset either (item 12). That fails closed and shows in status. A port-aware rule would be a later change, made on evidence (D5, D1 on #549).
   - **How an end resolved is not recorded (D3, D1 on #549).** The baseline doesn't say whether an asset end resolved through a direct or an inbound endpoint. The acknowledgement view derives it from `addresses` and the current C1, and it shows each pair end that is named only through an inbound (Syslog sender) address. A spoofed pair learned from a sender's address therefore doesn't look like one the node connects to.
   - **The limit (D2).** Resolution is per address. A device that sends Syslog from one address and polls from another stays `asset-unresolved` at the second address until learning adds it to `addresses`, or an operator enrolls it as another endpoint. That fails safe, since nothing is mis-named, but item 9 doesn't fix it.
10. **A TCP flow's `end` says whether it was only a dial attempt** (D1 in D4-70, after D3, D5 and D6 on #552). The `window` tie already counted only an "established" connection, and D6's AP-35 case includes a handshake that never completed (D6 plan §4). But no field said which flows completed. D1's failed-dial ruling on #547 needs the same fact: a retried dial's half-open flows take the `window` tie. A `start` can't carry it, because the sensor emits a `start` at the SYN. So the `end` carries `syn_only` (§4.3).
    - It is required on a TCP `end`, and absent on a `start` and on UDP. `true` needs `direction: client-server`.
    - **It is narrow (D3's H2).** A first draft said `established: false` for "SYN seen, handshake not completed". A sensor that sees one direction only, such as an asymmetric SPAN, a one-way TAP or PRP with a LAN degraded, never sees the SYN-ACK, so every session with a seen SYN would have read as a failed dial. `syn_only` is `true` only when every frame was a client SYN, or a server RST, with no payload. A client ACK or any data makes it `false`, so one-sided capture fails closed.
    - **A SYN carrying data is not syn-only** (D1). The tests pin data from client to server only, server to client only, and a SYN with payload, each `false` (`TestSynOnly`).
    - A sensor that can't track TCP flags writes `false` on every TCP `end`. The platform's own failed dials then alert as `own-session-outside-record`. That is a visible false alarm, not a hidden attack.
    - **`coverage.settings.flow_idle_s`** is added and required (D1), so the node knows how long a held flow's `end` can take (baseline note §5).
11. **The stored capture's byte form is pinned** (D1 in D4-70, from D5's question for intake). §4.2 said only "a classic pcap", but `stored_capture` is a SHA-256. Two writers of the same frames, such as the node's intake and its alert builder, or D6's checker, must give the same bytes, or C5 keeps two copies and a check against a recomputed digest fails. §4.2 now pins D5's choice: little-endian, the nanosecond magic (the frames' `ts` carries nine digits), `snaplen` 2048 to match `MaxFrameBytes`, and link type 1. The frames carry their 802.1Q tags and PRP RCT, as `wire_len` counts them. A frame's `ts` must fit classic pcap's unsigned 32-bit seconds, and the decoder refuses one outside them as `range`. So must `orig_len`: `wire_len` is bounded by `MaxWireLen`, and a larger one is refused as `range`, so no writer can wrap it (D3 on #553).
12. **Each end resolves on its own** (D1 in D4-70, from D3's S1 on #553). §5 said an ambiguous address left "both ends" `asset-unresolved`, and the decoder refused `ip-ambiguous` when either end had resolved. So a resolved relay polled by a master at an ambiguous address lost its asset, and intake would have budgeted the observation as unresolved. Now an ambiguous end is `asset-unresolved` and the other end keeps its asset. `resolved_by` is `ip-ambiguous` when at least one end is shared, and the budget applies only when neither end names an asset (§5). The decoder accepts `ip-ambiguous` with one end resolved, and refuses it with both ends resolved.
13. **The draft says when it overflowed** (D1 in D4-71, from D4's question with the learner). The draft is bounded by `MaxBaselineBytes`, about 3,000 entries, and the baseline had no field that said an entry was left out. A draft filled during learning, for instance by a flood of new pairs, would have looked complete to the person acknowledging it. Now `period.overflow` is required. It counts the folded observations that carried at least one entry (a pair, a service, a function, an address, or a new VLAN or LAN on a held address) that the full draft couldn't hold. An observation adds at most 1, and a repeat counts again. So it says the draft is incomplete, not how much is missing, which would take unbounded state to count. It is 0 when nothing overflowed, and it saturates at 2^53 − 1 (`MaxOverflow`), never wrapping. `Validate` refuses a value outside [0, 2^53 − 1]. Entries already in the draft are kept, and a refused entry is never merged into one. The learner reserves room for `period` at its largest, so counting never pushes a draft over the bound. A refused entry alerts as new once the baseline is acknowledged, which fails closed. D3's acknowledgement view shows a non-zero count before acknowledgement, and the acknowledgement record carries it (D4-71).
14. **A function's and a service's IP header are oriented by the request, not by the flow** (D4, from D6's A1 on #561; D1 confirmed it in D4-71). §4.1 says a midstream flow's `src` is its first frame's sender, which may be the server. §4.3 already orients the other two kinds by role: a service's server is `ip.dst`, and a function is a request, the frames the client sends to the server. This item says what that means for the header: on every `function` observation, `ip.src` and `sport` are the request's sender, the client, and `ip.dst` and `dport` the server, whatever the flow's `direction`, which stays the flow's. So the learner and the detector build a function's pair as `src` to `dst`'s port, and a service's server as `dst`, on a midstream flow too, and never key an entry on the client's ephemeral port. A sensor that can't tell request from response doesn't emit a `function` (§4.3), so it never guesses.
15. **The learner's checkpoint holds the starts it hasn't learned yet** (D1 in D4-71, from D6's A2 on #561). A TCP pair is learned only once its flow shows it was not only a dial (baseline note §2.2), so the learner holds each unproven TCP start. A UDP start is never held: a single datagram, decoded or not, learns its pair at once, from the first datagram's sender (§4.1), so a capture that begins on a reply learns the reversed pair, a stated limit. The learner holds the unproven TCP starts, and its checkpoint carries them as `held` (§8). They are bounded by `MaxHeldStarts` (512), and a start past it counts in `period.overflow`. So `MaxLearnerCheckpointBytes` grows from the draft's bound plus 1 KiB to that plus 512 × `MaxHeldStartBytes` (384), 705 KiB in all, still under the configuration class's record cap (`TestWorstHeldStartFits`). D5's configuration floor counts the larger figure.
16. **The detector's open windows are bounded** (D1 in D4-72, from D4 while coding the detector). §7.3 capped the alert records per window, but not the windows open at once, and every open window is in the detector's checkpoint. With nine rules and many assets, the checkpoint could outgrow the configuration record. The store would then refuse it, the detector's cursor would stop, and the observation class would fill. So a broad attack would have degraded detection. Now at most `MaxDetectorWindows` (96) windows are open, and the window that started earliest closes early to make room (§7.3 item 3). The checkpoint is bounded by `MaxDetectorCheckpointBytes`, 1,180,672 bytes, and keeps related observations as seqs (§8). D3 reviews this for AP-36 (c).
17. **The detector judges the node's own sessions, and its checkpoint carries their state** (D1 in D4-72 and D4-73, from D4 while coding 2b). The tie moved to the node's intake (baseline note §5), so `platform_session` is already set when the detector reads an observation. The detector judges `own-session-outside-record` and `node-address-spoofed` from each observation, and `own-session-unseen` from the session records the node hands over with `Session(record, after_seq)` once the record's flows and the record itself have committed. Judging a session needs state that §8 lacked: the sessions pending, the IDs tied before their record arrived, the coverage record before acknowledgement, the degraded intervals and the last coverage statement. Within 0.1, since no detector checkpoint was written outside tests, §8 gains those fields, each bounded, and `MaxDetectorCheckpointBytes` becomes their sum, 1,354,752 bytes. Every bound fails loud and is counted. A session past 128 pending, or one whose tied ID is dropped past 256, isn't judged, and the node raises the alarm. An interval past 64 is dropped, never merged, so a session in it may alert. An endpoint address past 256 is never recorded, so before acknowledgement its sessions are never judged; it shows as not yet seen, and `EndpointsNotTracked` counts it for status (D1's C1 on #575). A record tied to a session already handed over, such as an SNMPv3 flow's idle `end` after the run, refreshes that session's entry in `taken` (at most 128, the oldest dropped) and takes no room in `tied`, so `NotJudged` counts only a tie whose session never came (D6's F1 on #575). A tied ID whose session record never comes is dropped quietly after twice the longest run deadline and grace on the capture clock (2 × (600 s + 3,600 s)), because the session it would mark seen then alerts. A session handed over with `after_seq` below the detector's `through` is the node's ordering fault: it is refused, counted, and changes nothing else. The detector judges sessions in the order handed over, and the node hands them over in health-stream seq order, live and on restore. `own-session-unseen` alerts carry no `related` and no capture, and their window's `related_total` is 0 (§7.1).
