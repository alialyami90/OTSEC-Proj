# D6: GT-PCAP plan, and the item 4 checks (P4-4-A6)

D6, 2026-11-07. This note answers P4-4-A6 in `docs/agent-handoffs.md` (item 4, Stage A, D4-66). It covers three things:

- the plan for GT-PCAP, the labelled captures that V-M6 and R6.1 to R6.5 are checked against;
- the C-11 test design;
- what D6's testability review of ADR-0009, C13 and the baseline note will check.

Nothing here is built yet, and nothing in it is evidence. Every capture named below is either public, from `tests/fixtures/network/public-ot-captures/`, or recorded from this project's own simulators. No real network is captured, and nothing scans or probes (P1).

## 1. What GT-PCAP is

GT-PCAP is a capture plus a label file written before the product reads it (`docs/verification.md`, "Monitoring goals acceptance criteria"). The rules are:

- **Labels never come from the product.** They come from a decoder the product does not use. If ADR-0009 picks Zeek, that is tshark. Otherwise it is Zeek or tshark (P4-4-A6, D6 on #522). Until ADR-0009 names the engine, the plan assumes tshark, so no label has to be redone if Zeek is chosen. The labeller's version is pinned and recorded in each label file's header.
- **Every column is reproducible.** The label file's header names the pinned tshark version, its preferences, and the field or display filter behind each column. For example, the client in `direction` is the sender of the `tcp.flags.syn==1 && tcp.flags.ack==0` frame. A re-label with the same version gives the same file, and a reviewer can check a row without trusting whoever wrote it (D4 on #527).
- **Labels are fixed before the product test first runs**, as GT-INJ's schedules are. A capture and its labels are committed together and reviewed by D4 (labels) and D2 (protocol reading). A later change to a label is a reviewed change with its reason, and never follows a product result.
- **Every capture has a `SOURCE.md` row** giving its origin, date, nature, redistribution terms and evidence class. Public captures stay referenced, not vendored, because their sources state no redistribution terms (`public-ot-captures/SOURCE.md`). Captures this project records are ours to commit, and their row says so.
- **Evidence class.** Every result on GT-PCAP is `simulated`. The public captures are not from the target environment. The recorded ones come from simulators, and for SEL that is the documentation profile, not a device.

### Label fields

One row per labelled item, in a TSV beside the capture. The columns:

| Column | Meaning |
| --- | --- |
| `kind` | `service` (a server seen offering a protocol), `flow` (a talker pair), `insecure` (a use of a protocol on V-M6's list), `encrypted` (a session where only the handshake is readable), `seen-not-decoded` (traffic the first sensor is not expected to decode), `case` (a labelled R6.3 sample, see section 4), or `secret-slot` (a credential slot under D4-67, see section 2D) |
| `src`, `dst`, `sport`, `dport`, `l4` | as the labeller decodes them. MAC addresses too for layer-2 protocols (GOOSE, PRP) |
| `protocol` | the labeller's protocol name, mapped to a fixed list in the label file's header |
| `version` | only where it shows in clear (SNMP message version, TLS version from the handshake, an HTTP `Server` banner, a Telnet or FTP banner); empty otherwise |
| `direction` | client to server, as the labeller decides it from the handshake. `midstream` when the capture holds no handshake |
| `asset` | the GT asset ID the address belongs to, from the capture's asset table; `asset-unresolved` for an address in no table |
| `frames` | the frame numbers that show the item, as the labeller numbers them (1-based). Where the same bytes arrive twice, as the two copies of a PRP frame or a retransmitted segment, the row lists both, and either one satisfies it (D4 on #527) |
| `frame_sha256` | one SHA-256 per frame in `frames`, in the same order. Each hash covers that frame's link-layer bytes as captured: the Ethernet frame, including any 802.1Q tag and any PRP RCT, with no pcap or pcapng record header and no timestamp. C13's citation hashes each frame the same way (D4 on #527) |

**How a product citation is matched.** Under a timed live replay, the product cites frames from its own capture ring. The ring has its own capture ID and numbering, may hold extra frames, and may miss some. So the checker maps each frame the product cites to a GT frame by its per-frame hash, never by frame number. A frame the product stored redacted under D4-67 hashes differently. It is matched to the GT frame whose bytes are equal everywhere outside the labelled `secret-slot` ranges, and whose slot ranges are exactly the product's redaction markers. When the product reads a GT file offline, frame numbers match too, and the checker also asserts that.

The checker compares the product's records against these rows field by field. It reports recall and precision per protocol (V-M6), and it lists every missed row by kind. A missed row has to be a recorded visibility limit (R6.1). It is never left silently absent.

## 2. Sources

### A. Public captures, referenced by hash

These are the 21 files in `public-ot-captures/MANIFEST.tsv`, fetched by `modules/telemetry/experiments/ids-coverage/fetch_captures.sh`, which checks each SHA-256. That script and manifest are D4's, and GT-PCAP uses them as they stand.

| Files | Use in GT-PCAP |
| --- | --- |
| `dnp3-*.pcap` (6) | DNP3 services and flows. `dnp3-write` and `dnp3-select-operate` as write-class traffic. `dnp3-malformed` as hostile input. Its service rows are whatever tshark decodes, and "the sensor neither crashes nor hangs" is a separate check (D4 on #527). `dnp3-digitalbond-part2` has no TCP handshake, so it is the midstream case. DNP3 without SA is labelled `insecure` only where a critical function (a write, select/operate or direct operate) completes with no group 120 challenge. Under SA v5, reads are not challenged by default (S23 pp. 73–74, D2 on #527), so a window holding only reads is labelled `sa-not-observed`, and the checker accepts either answer from the product for it. |
| `modbus*.pcap` (3) | Modbus/TCP services and flows, with read and write function codes as the labeller shows them. `modbus-digitalbond-part2` is labelled with what tshark decodes. The engine disagreements recorded in A4 §3 are not taken as truth. |
| `iec104*`, `mms.pcap` | `seen-not-decoded`. The first sensor has no decoder for them (#522), so they test R6.1's statement of what it decodes. They become `service` rows only when the owner confirms them and a decoder is briefed. |
| `goose-*.pcapng` | `seen-not-decoded` for the first sensor. The dataset's own attack frame numbers stay in the manifest for the GOOSE decoder's brief. GOOSE also needs every precondition in R-A4-4 before any GOOSE rule is tested. |

The public captures carry no asset table, so their addresses are `asset-unresolved` unless a test supplies an inventory. V-M6's "recorded against its asset" is then checked on the recorded captures (B).

### B. Captures recorded from this project's simulators

These are recorded once, on Linux in CI, by a recording step that runs only when dispatched by hand. GT-PCAP's own workflow, `.github/workflows/a6-gt-pcap.yml`, runs on dispatch and on every pull request that touches GT-PCAP or the workflow, so no GT-PCAP change merges without tshark's verdict (D1 on #529). Each simulator pair runs in a network namespace with fixed addresses from 192.0.2.0/24 (TEST-NET-1), and `tcpdump` writes the capture. The captures and their labels are then reviewed and committed. Recording again is a reviewed change, never part of a product test run, so GT-PCAP stays fixed while the product changes.

| Source | What it produces | Label kinds |
| --- | --- | --- |
| The SEL-751 recording simulator (`tests/safety/recording_simulator`, `--transport tcp --telnet --profile sel-751-doc`) driven by the platform's own collector | The platform's own Telnet session as C2 runs it: `QUI` and `ID` at Level 0, then `ACC`, the in-band password at the `Password: ?` prompt (S22 p. 7.33), and the SER command. The `ID` reply puts FID, BFID, CID, DEVID, DEVCODE, PARTNO and CONFIG in clear (S22 Table 7.43), and these are labelled as identity rows (D2 on #527) | `service` (Telnet on the relay), `insecure` (Telnet, with the password in clear), plus a `flow` marked `platform-own` with its session window from the node's record. Under #522 this flow is both a known flow and an insecure use. |
| GT-MIB (`tests/integration/gt_mib/agent`) driven by its V-M1 client | SNMPv3 `authPriv` | `encrypted`: only the header in clear (message version, engine ID, user name, flags, boots and time) is labelled, never the scoped PDU |
| GT-MIB, sent one SNMPv2c `GetRequest` by a test client | A community string in clear | `insecure` (SNMPv2c). The request alone is the evidence, whether or not the agent's case answers it. |
| A DNP3 pair written by D6 in stdlib Python: TCP 20000, link-layer CRCs, an integrity poll, a time-sync write and a direct operate | DNP3 master and outstation traffic with known function codes | `service`, `flow`, `insecure` (no SA) |
| The same pair over UDP 20000, which the SEL relays allow (`DNPTR := UDP`, S22 Table D.7, D2 on #527) | DNP3 over UDP | `service`, `flow`, `insecure`. If the first sensor doesn't decode it, the miss is a recorded visibility limit. |
| The same pair with Secure Authentication objects (group 120): a reads-only segment, then critical functions each challenged | DNP3 that a passive sensor should not flag as lacking SA | The reads-only segment is `sa-not-observed`. The challenged segment is not `insecure`. A passive sensor can't check the MACs, so this case shows only that the flag follows the objects on the wire. |
| The SEL-751 simulator, the DNP3 pair and the Modbus/TCP pair with their ports moved off the defaults (`TPORT`, `DNPNUM`, `MODNUM1`; S22 Table 4.104, D2 on #527, D4 on #526) | Whether the sensor finds each protocol by its content, or only by its port | Labelled from the asset table's settings, not from the port. The moved ports are ones a relay accepts: a moved `TPORT` is in 1025 to 65534 (its default is 23), no two moved ports are the same, and none is one of the fixed ports 20, 21, 23, 102 or 502 (S22 pp. 4.250–4.251, D2 on #527) |
| A Modbus/TCP pair written by D6 in stdlib Python, port 502: function codes 3, 6 and 16 | Modbus/TCP reads and writes | `service`, `flow`, `insecure` (unauthenticated Modbus/TCP) |
| A TLS session on port 802 (Python `ssl`, test certificate). The port comes from the Modbus Organization's Modbus/TCP Security specification, which is not in the project files, so the row says it is from the standard (D2 on #527) | Modbus/TCP Security as a passive sensor sees it | `encrypted` and not `insecure`: the near-miss for the Modbus/TCP row (D6 on #522) |
| Python `http.server` and `ftplib` against a minimal stdlib FTP responder | Plain HTTP with a `Server` banner, and an FTP login | `service` with its banner as `version`, `insecure` |
| The same HTTP server with a login taken two ways: an `Authorization: Basic` header, and a form POST. Which one the SEL-751 and SEL-787-4 web servers use is `unknown` (S22, S34 p. 3.2; D2 on #528). | A web login in clear | `insecure`. The Basic value is a `secret-slot`. The form POST has no fixed slot, so the product must fail closed on its body (D4-67). |
| A port 80 server that only redirects to HTTPS, as the RTAC, SEL-2488, SEL-2730M and SEL-2731 offer | A redirect-only plain-HTTP service | `insecure`, with the detail "redirect to HTTPS only, no credential seen". Plain HTTP stays on the list whatever it serves, because the redirect is sent in clear and can be stripped (D1's ruling, 2026-11-07). A product that flags it is right, not a false positive. |
| GT-MIB with one user at `noAuthNoPriv` | SNMPv3 with its scoped PDU in clear, the default of a new SEL-2488 v3 profile (S26 Table 19.1, D2 on #528) | Not `encrypted`: the PDU is labelled as read. Not on the insecure list (the list is the owner's), and recorded with its flags. |
| A TLS session on 443, one with TLS 1.2 and one with TLS 1.3 | HTTPS | `encrypted`, with the TLS version and SNI from the handshake only. For TLS 1.3 the version is the one ServerHello's `supported_versions` names, not the record or legacy version field, which says 1.2 (D2 on #527) |

The DNP3 and Modbus sources are written by D6, and not taken from a library the product might link, so a shared bug can't make product and truth agree. Their correctness is whatever tshark's dissector shows when it decodes them, and that output is the label.

### C. Derived captures

These are made from A and B by a stdlib Python pcap rewriter in `tests/integration/gt_pcap/`. Each output's `SOURCE.md` row names its input and the transform.

| Case | Transform | What it tests |
| --- | --- | --- |
| PRP duplicates | Each frame is sent twice, each copy with an IEC 62439-3 Redundancy Control Trailer carrying the same sequence number, one with LAN ID A and one with LAN ID B. The RCT's LSDU size and its 0x88FB suffix are set as the standard gives them, so a PRP-aware sensor doesn't take the trailer for padding; tshark's PRP dissector checking the trailer is the rewriter's self-test (D2 on #527) | A sensor on both LANs records each service, flow and alert once, and its coverage statement says it sees both LANs (R6.1, R6.6) |
| One PRP LAN only | Only the LAN A copies | The coverage statement says one LAN. Nothing is lost for traffic that crossed that LAN. |
| PRP supervision | One synthesized PRP supervision frame per relay (EtherType 0x88FB), as a relay sends them (D2 on #527) | Labelled as one row. It is not an unknown talker. |
| HSR | The same frames carrying an HSR tag (EtherType 0x892F), which the SEL-751 (`NETMODE := HSR`) and the SEL-400 five-port card offer (S22 Table 4.104, S32 Table 15.4, D2 on #527) | Each service and flow is recorded once. Otherwise, HSR is a limit named in the coverage statement. |
| VLAN | 802.1Q tags on a subset, two VLAN IDs | The coverage statement lists the VLANs seen |
| Hostile device text | A Telnet banner and an HTTP `Server` header over 256 octets, and one with non-ASCII and control bytes | The recorded `version` is bounded printable ASCII, quoted, never interpreted, and never reaches a Syslog forward or a status line raw (#522, C2's record values) |
| A legitimate long banner | A printable Telnet banner of exactly 254 characters, the longest `TCBAN`, `FTPCBAN` or `HTTPBAN` a relay allows (S22 Table 4.104, D2 on #527) | The bound keeps the whole banner, so a normal relay's `version` row passes |
| A blind sensor (AP-36's residual, #523) | The SEL-751 Telnet capture with the node's own scheduled session removed, while the sensor reports full coverage | The node knows its own session ran. When no observation of it arrives, it alarms instead of reading the window as quiet. |
| Passive identity from the platform's own sessions | The SEL-751 Telnet capture, where the `ID` reply shows the FID in clear; and the GT-MIB SNMPv3 capture, where the engine ID shows in clear (D2 on #527) | Two rows. A passive FID or engine ID from the node's own session doesn't count twice in C12 (#522, D2): the asset's C12 corroboration is unchanged. |
| Whose session an identity read came from (D2's note, #528) | Three legs on one relay: a third-party Telnet client's `ID` at Level 0 with the relay's FID; the platform's own probe-phase `ID`; and a third-party `ID` reply with a different FID, as a host spoofing the relay's address would send | The first counts as independent passive evidence. The second doesn't count. The third is recorded as observed, and never outranks the collector's read: the asset's identity and C12 findings are unchanged (AP-34, D4 on #528). |
| The OT SDN discovery frame | The LLDP-structured OpenFlow announcement an uncommissioned SEL-2731 or SEL-2741 sends (S30 p. 5) | `seen-not-decoded` for the first sensor, or an identity row if C13 reads it |

### D. Credential slots and the key search (D4-67, AP-33)

D4-67 (#524) has the sensor redact every cleartext credential slot by position, for every session, and fail closed where it can't place one. GT-PCAP tests that independently:

- **Test secrets only.** Every credential in a recorded capture is a test value made for the recording (D2-5), never a real or product credential. Each value is unique to its capture, so a hit names the case.
- **The labeller places the slots, not the product.** A `secret-slot` row gives the TCP stream, direction, sequence range and frames of each slot, from tshark's own fields. These are: the Telnet bytes after the password prompt up to the end of the line, placed on the Telnet data stream after IAC unescaping and then mapped back to wire ranges (D2 on #527), FTP `PASS`, the SNMPv1 or v2c community, and the HTTP `Authorization: Basic` value. A server's echo of a slot is a row of its own.
- **The checker compares, by per-frame hash outside the slots** (section 1). The product's redacted ranges must equal the labelled slots. The stored bytes must equal the wire bytes everywhere outside them. A login the product marks `slot not located` must have none of its client-sent bytes stored.
- **The key search.** Each test secret, raw, as hex in either case and as base64 (the forms V-M1's M3 searches), must appear nowhere: not in the stored captures at the site, not in any record forwarded upstream, and not in Syslog, status or health.
- **The cases:**
  - a third party's Telnet, FTP and HTTP Basic logins, not only the platform's own;
  - a password sent one byte per frame (D3);
  - Telnet option bytes (IAC) in the same segment as the password, and an escaped 0xFF beside it (D2);
  - a retransmitted segment that carries the password (D4);
  - the password frames as PRP duplicates on LAN A and LAN B (D4);
  - a device that echoes the password, including a Telnet server that answers each character with its echo, so a fail-safe that ends at the first server reply would end after the password's first byte (D3);
  - an SNMPv2c community in a request, in the agent's response, and in a trap (D4-67's either-direction rule);
  - a login joined midstream, and a password sent before its prompt, where the product has to fail closed.

## 3. R6.2: the benign baseline and the held-out series

R6.2 needs a baseline built from benign traffic, replayed against held-out benign traffic **from the same network**, with zero alerts as the target (*to be revised with real data*). The plan:

- **Same network.** One generator, from section 2B, runs one simulated network: fixed addresses, fixed masters, and a fixed polling schedule per master (integrity polls, Modbus reads, the platform's own Telnet and SNMPv3 sessions at their scheduled times). It writes two series from two fixed seeds. Seeds vary only what varies on a real network: poll jitter, the order of reads within a cycle, TCP ports, and the session windows.
- **Train and held-out.** The baseline series is long enough to cover every pair and every function code the held-out series uses. The held-out series is at least as long, and is recorded after the baseline. Both are committed with their seeds.
- **Public captures** are not used for R6.2's pass. Their benignity is unknown (`unlabeled` in the manifest), and part1 and part2 of the Digital Bond sets aren't shown to be the same network. They may be replayed to report alert counts, labelled as such, and never as the zero-alert test.

## 4. R6.3: a malicious sample and a benign near-miss for each detection

Each detection gets at least one labelled malicious sample and one benign near-miss (R6.3). The detections themselves come from D4's baseline note and C13, so the final list waits for them. These are the pairs the brief's baseline already implies (#522). Each is a `case` row with the frames that make it.

| Detection (from the brief) | Malicious sample | Benign near-miss |
| --- | --- | --- |
| Unknown talker pair | A new master polls the outstation | The known master on a new TCP source port |
| Write-class function code from a master not authorized to write | A DNP3 direct operate, or Modbus function code 6 or 16, from a master that is only authorized to read | The same function from the authorized master. A DNP3 time-sync write (group 50) from the authorized master, the "write = bad" false positive A4 §3 records. |
| The platform's own session outside its record | A Telnet session to the relay from the node's address outside any scheduled or granted window (#522, D3) | The same session inside its window |
| A spoofed node address | A session from the node's IP with another MAC, or to an asset that has no session record | The node's real session |
| A new service on an asset | A port opened on the relay's address that the baseline never saw | A known service on a new client port |

These are committed before the product's detection code runs, and each one is checked against D4's final rule list. A detection with no pair is a gap that blocks the item 4 gate.

## 5. R6.4 and R6.5: how the numbers are measured

- **Detection rate and false-positive rate, per rule.** The detection rate is the malicious `case` rows the rule alerted on, divided by its malicious rows. The false-positive rate is its alerts on the held-out benign series, divided by the benign flows in that series. Both are reported per rule, with their counts.
- **Latency** is measured only under a timed replay onto a live interface, never from a file read offline (#522). The replayer sends each frame at its recorded offset onto one end of a veth pair. The sensor listens on the other end. Latency is the alert's time minus the triggering frame's send time, on one host clock. The report gives the median, the p90 and the maximum per rule.
- **R6.5 retrieval.** For every alert and observation, the checker reads the cited frames back at the site, as D5's note will say. It checks that their stored bytes hash to the cited per-frame SHA-256s, and that they map to the frames GT-PCAP labels (section 1). A redacted frame is matched by its bytes outside its labelled slots, and differs from the wire only inside them (section 2D). It also checks that no record forwarded upstream, and no Syslog line, carries the cited bytes, only the hash and the frame numbers (#522, D3).

- **The spoofed-address flood (D1 on #525, §3).** For 0.1, unresolved observations get a rate budget rather than a class of their own, and this test decides whether that holds. The rig replays observations from many spoofed, unresolved source addresses onto the live interface as fast as it can send, and the report states the rate it reached. Meanwhile it runs GT-INJ's SER and Syslog feed and, mid-flood, one labelled malicious `case`. **Pass:**
  - the case's alert is stored and forwarded;
  - the alert class still has its floor free;
  - SER and Syslog lose no record, and keep the throughput they reach without the flood;
  - every dropped observation is counted against the unresolved budget.

  If any of these fails, `network-unresolved` becomes a C5 class before the item 4 gate (D1).

## 6. C-11: the sensor transmits nothing

C-11's criterion is zero frames sourced from the sensor's monitoring interface. Its 24 h run stays with H-06 on hardware. In CI it runs over the whole GT-PCAP replay plus the sensor's start and stop, with the interface up throughout (#522).

**The Linux rig.** This covers option (b), and option (a) or (c) where they run on Linux:

1. Make a veth pair, `mon0` and `tap0`. `mon0` is the sensor's monitoring interface inside the sensor's network namespace. `tap0` is in the rig's namespace. `mon0` is configured as the product's installer configures it (ADR-0009). Unless the ADR says otherwise, that means no IPv4 address, IPv6 disabled, ARP off, and promiscuous mode on.
2. On `tap0`, start a capture of everything that arrives from `mon0`. Since `tap0` is a veth peer, every frame `mon0` transmits arrives there.
3. Bring both ends up. Start the sensor. Replay the whole GT-PCAP set onto `tap0` with timing. Stop the sensor. Bring the interfaces down only after the capture is stopped.
4. **Pass:** the capture on `tap0` holds zero frames sent from `mon0`. Every frame the replay sent is excluded by its own record, and nothing else is allowed: no ARP, IPv6 router solicitation or DAD, DHCP, LLDP, mDNS, or anything else.

**The test of the test.** The same rig is run once with `mon0` deliberately misconfigured: an IPv4 address, IPv6 on, and a DHCP client. That run must capture frames from `mon0`. Otherwise the rig couldn't see a transmitting sensor, and a pass would mean nothing.

**Windows.** It depends on ADR-0009. Hosted `windows-latest` runners offer no isolated second NIC, and on Windows C-11 rests on the installer's IP-stack unbinding and an HR-9-style firewall rule (#522, D5). So the CI half on Windows is the installer check: the binding and the rule are present after install and gone after uninstall. The zero-frames half on Windows stays with H-06, unless ADR-0009 names a rig that a hosted runner can run. A `windows-latest` result is labelled Windows Server, not the 10/11 LTSC floor (#522).

## 7. What the testability review of ADR-0009, C13 and the baseline note checks

When each draft arrives, D6 checks it against V-M6 and R6.1 to R6.5. The questions asked:

- **ADR-0009.** Does the chosen option accept a live interface fed by a timed replay, so that R6.4's latency and C-11 can both be tested? Can its monitoring interface be put in the rig in section 6? Is the engine's version pinned, so that labels and product run against known decoders? Is offline decoding of a file recorded apart from live capture?
- **C13.**
  - Does every observation carry the V-M6 fields (address, port, protocol, version where in clear, asset or `asset-unresolved`)?
  - Does every citation carry the capture ID, the frame numbers and one SHA-256 per frame over the link-layer bytes, so section 5's retrieval check is mechanical?
  - Is the coverage statement attached to every observation and alert, with protocols decoded, LANs and VLANs seen, and SPAN or TAP?
  - Does the record have no field the checker can't compare, and no ML field?
- **The baseline note.**
  - Is each detection named precisely enough that section 4 can give it a malicious and a near-miss pair?
  - Is the baseline's input fixed, so the same capture gives the same baseline (as V-M4 requires of event baselines)?
  - Is the authorized-master list an input, not something learned from the traffic it then judges?
  - Does R6.7's path to C12 avoid counting a passive read from the platform's own session twice?

## 8. Files and order

1. This note, and GT-PCAP's definition in `docs/verification.md` reworded to the independent-decoder rule (wording only; no threshold has run).
2. `tests/integration/gt_pcap/`. This holds:
   - the stdlib DNP3, Modbus/TCP and FTP sources;
   - the pcap rewriter (section 2C);
   - the labeller, which runs pinned tshark and writes the TSVs;
   - the checker, with self-tests on hand-made records, as `test_vm7_checker.py` does for V-M7.

   `.github/workflows/a6-gt-pcap.yml` runs on dispatch and on pull requests that touch GT-PCAP (D1 on #529). Recording new captures is a step that runs only on dispatch.
3. `tests/fixtures/network/gt-pcap/`, holding the recorded captures, their labels, the asset table and `SOURCE.md`. These are committed after D4 and D2 review the labels.
4. Section 4's pairs are finalized against D4's baseline note, and section 7's review is written against each draft as it arrives.

**What this waits on:**

- ADR-0009 names the engine. The labeller choice holds either way, and so does the C-11 rig, at least on Linux.
- D2's SEL service note gives the ports and banners that the SEL rows in section 2B are labelled against.
- D4's baseline note gives the detection list for section 4.
- D5's note says where the cited bytes are stored, for section 5's retrieval check.
- D4-67 (#524) is merged, for section 2D.
