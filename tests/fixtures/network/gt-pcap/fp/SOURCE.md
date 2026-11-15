# GT-PCAP: the false-positive set for HR-23 and HR-25 (D6, brief P4-4-HR2325S, deliverable 1)

One set, built once, serves both counted runs (D4-111 item 5.2): HR-23's bounds are `hr23-conditions.tsv`'s `fp-` rows, and HR-25's are `resync-conditions.tsv`'s. The classes are `docs/phase4/D4-hr23-design.md` section 4.3's UDP classes (1) to (5), and class (6), non-DNP3 TCP flows on tcp/20000, as HR-25's rows name it. Every result on these captures is `simulated`.

| Output | Origin | Nature | Terms |
| --- | --- | --- | --- |
| `<capture>.pcap` for each name in `fp.sha256`: one capture per class | Written by D6, 2026-11-16, with `tests/integration/gt_pcap/fp_set.py` (stdlib only: `dnp3.py`, `synth.py`, `pcapfile.py`) | Synthesized, never sent. Every item on its own 5-tuple, from 192.0.2.100 to 192.0.2.200 (LLMNR's queries to its group 224.0.0.252), its client port from 50000 + 1000 × class + item | This project's own. Not committed: `fp_set.py` rebuilds them byte for byte, and `fp.sha256` pins them |
| `<capture>.tsv`, one per class | The same run of `fp_set.py` | The builder's labels: one row per item with its 5-tuple, packets, datagram sizes or TCP segments, the offset of the one header it was built to hold, its code and side where it has one, its draws, and the class's facts | `desk` until D4 (labels) and D2 (protocol reading) review them |
| `tshark-beside-fp.tsv` | `hr23_tshark.py fp`, with the set's own UDP ports read as DNP3 | The items where tshark's DNP3 codes differ from the label: none. tshark reads each (3b-data) and (3c) item's built code and no other | Drafted with tshark 4.2.3 (`desk`); the `hr23` job checks it with the pinned 4.2.2 |

## The classes

| Capture | Class | Items | How each is built |
| --- | --- | --- | --- |
| `fp-udp-1` | (1) | 306 | `05 64` and 0 to 8 more octets, 34 of each length. Under 11 octets, so no header check runs (design 1 item 4) |
| `fp-udp-2` | (2) | 300 | `05 64`, six random header octets and a CRC that fails, in a datagram of 11 to 1,472 octets (both ends included) |
| `fp-udp-3a` | (3a) | 32 | A header whose CRC passes, then random octets in the same datagram whose every chunk CRC fails; the transport octet has FIR and FIN, so the first chunk's CRC is what fails |
| `fp-udp-3b-data` | (3b-data) | 42 | A whole frame from the originator, DIR set: each empty-arm code (0, 13, 14, 15, 19, 23, 24) three times with 2 application octets, and 21 default-arm codes (34 to 128, 132 to 255) with 2 to 22 (`arm-3bdata`); then a datagram of 11 to 200 octets with no `05` |
| `fp-udp-3b-link` | (3b-link) | 32 | A link-only frame (link status request, link status, reset link states, ACK or test link), then 1 to 40 octets, then 11 to 200, neither with a `05` |
| `fp-udp-3c` | (3c) | 54 | A whole frame from the originator whose code's request arm parses objects (1 to 12, 16 to 18, 20 to 22, 25 to 33), each twice, with exactly 1 object octet (`arm-3bdata`) |
| `fp-udp-4` | (4) | 304 | 76 each: DNS queries to 53, NetBIOS name queries to 137 and LLMNR queries to its group on 5355, each with ID 0564h; and RADIUS Accounting-Responses (code 5, identifier 64h) from 1813. DNS names are under `gt-pcap.example`, LLMNR's are `gtpcap<n>` and NetBIOS's `GTPCAP<nnn>`, and the RADIUS authenticator is random |
| `fp-udp-5` | (5) | 304 | 76 each: random payloads of 11 to 1,472 octets, NTPv4 client packets, RFC 5424 Syslog lines and SNMPv2c GetRequests (community `gtpcap-test`), each with its first two octets forced to `05 64` |
| `fp-tcp-6` | (6) | 104 | Non-DNP3 flows on tcp/20000 with the full handshake and the FIN exchange: HTTP/1.1 text, TLS-shaped records, an SSH banner then random octets, or random octets, 26 of each, 50 to 5,000 octets per end; an even flow at most 1,000 per end, so that about half stay under O |
| `fp-tcp-6-hole` | (6), one hole | 32 | The same, each with one end's stream in three segments, the middle one left out and the peer's ACK past it kept (`judge-r3`), the hole on the client's end for even flows and the server's for odd ones |

## The rules the builder keeps

- **The redraw rule** (`fp-redraw` in both conditions files). Every generator computes the header CRC at every offset of every datagram, and of each end's stream and each run of it between holes over TCP, where `05 64` occurs with 8 more octets, and draws the item again when one passes at an offset its class does not name. A class (4) item is drawn again with other flags (DNS, NetBIOS, LLMNR) or another authenticator (RADIUS). The `draws` column counts them; the test reads every offset again from the wire.
- **O for class (6).** HR-25's `fp-6` asks for the flows that reach O to be labelled by construction. Every octet of a class (6) stream is consumed by the scan, since no candidate passes, except at most 9 held octets of a partial candidate per run (D4-hr25-design.md section 2.1). So no flow's delivered total is drawn within 32 octets of O (2,048), and `reaches` is `O` when the total is at or above it. F cannot be reached: a flow has at most four failures (a scan run per end, a gap and the run after it).
- **Deterministic draws.** Every octet is SHA-256 in counter mode over the class, the item and the draw, so the set is the same on every run and every Python.

## Limits

- **What counts as named** under each configuration, and what each class is expected to show, are the conditions files', not these labels'.
- **Class (4) and (5)'s messages** are well formed for their protocols as far as their first octets go, and not checked against any real implementation; (5)'s are not valid in their protocols after their first two octets are forced.
- **Real traffic.** These say nothing about the UDP or TCP traffic at a site, where other near misses may start `05 64`.
