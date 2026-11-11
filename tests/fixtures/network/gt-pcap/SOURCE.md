# GT-PCAP sources (D6)

GT-PCAP is the labelled capture set for V-M6 and R6.1 to R6.5. The plan is `docs/phase4/D6-gt-pcap-plan.md`. Every result on it is `simulated`.

## PRP derived captures (plan section 2C)

| Output | Input | Transform | Terms |
| --- | --- | --- | --- |
| `<stem>-prp-ab.pcap` and `<stem>-prp-a.pcap`, for each stem in `prp-derived.sha256` | The public capture `<stem>.pcap` in `../public-ot-captures/MANIFEST.tsv`, fetched at its pinned SHA-256 | `tests/integration/gt_pcap/prp.py`: every frame twice, with an IEC 62439-3 RCT carrying one sequence number on LAN A and LAN B copies (`-ab`), and the LAN A copies alone (`-a`) | Not vendored, as their inputs state no redistribution terms. `prp.py` rebuilds them byte for byte, and `prp-derived.sha256` pins the result. |

**Limits** (D2 on #529):

- Every source becomes a doubly attached node (DANP). A real PRP LAN also has singly attached nodes that send no RCT. A mixed SAN and DANP case, and PRP supervision frames, come separately (plan section 2C).
- A frame under 54 octets is zero-padded to 54 before its RCT, as a PRP-1 sender pads, so the trailer stays last in a 60-octet frame. None of the nine inputs has one: their shortest frame is 54 octets. A frame that carries an 802.1ad (0x88A8) tag is refused.
- If an input frame ended with its FCS, the RCT would follow the FCS. `pcapfile` can't tell, and these inputs aren't known to carry one.

`.github/workflows/a6-gt-pcap.yml` rebuilds them, checks the hashes, has tshark's PRP dissector read every trailer, and writes flow labels as a job artifact. The labels are committed here only after D4 and D2 review them (plan section 1).

## DNP3 sources (plan sections 2B, 2C, 3 and 4)

| Output | Origin | Nature | Terms |
| --- | --- | --- | --- |
| `dnp3/<name>.pcap` for each name in `dnp3/dnp3.sha256`: 19 labelled cases, and the R6.2 series `dnp3-train` (seed 1) and `dnp3-heldout` (seed 2), each 3600 s | Written by D6, 2026-11-07, with `tests/integration/gt_pcap/dnp3_cases.py` (stdlib only: `synth.py`, `dnp3.py`, `pcapfile.py`). `dnp3-moved-port` and `dnp3-udp` were added on 2026-11-11 (P4-4-R1); the other 19 captures are byte for byte as before. | Synthesized frame by frame, never recorded through a kernel and never sent. The network is TEST-NET-1 (192.0.2.0/24) with locally administered MACs. O1 is the outstation of every capture but one, link address 10 on TCP 20000. Masters: M1 (.10, authorized to write and control), M2 (.11, reads), M3 (.12, reads and does the reconnect sequence), and M4 (.13, unenrolled). Group 120 objects are synthetic at header level, because no SA specification or SA capture is held (plan section 2B, D2 on #542). | This project's own. Not committed: `dnp3_cases.py` rebuilds them byte for byte, and `dnp3/dnp3.sha256` pins them and `dnp3-cases.json`. |
| `dnp3/<name>.tsv` | `tests/integration/gt_pcap/gtlabel.py` over the outputs above, with the pinned tshark 4.2.2 | Labels: `flow`, `service`, `function` (with `sa` as C13 §4 derives it), `counter` (`dnp3_seq_reused`), and `case` rows that list every rule expected to fire and their context. `gtlabel.py` first fails on any IP or TCP checksum, DNP3 CRC or malformed frame tshark reports, and on any case whose `sa` disagrees with tshark's reading. | `desk` until D4 (labels) and D2 (protocol reading) review them. Every result on them is `simulated`. |

**The C1 records the replay enrolls** (D1 on #548). C1 has no DNP3 transport, so a host resolves to its asset only through a direct endpoint on its IP that C1 does have. Each enrolled host therefore gets one, and no capture here holds a session on it. The records are in `dnp3-cases.json` under `net`, as `c1_endpoint`.

| Host | IP | Asset ID | C1 endpoint |
| --- | --- | --- | --- |
| O1 (outstation) | 192.0.2.20 | `6a1f3c2e-0d4b-4e8a-9c71-2b5d8e0f1a20` | Telnet 23, path `direct` |
| M1 (authorized writer) | 192.0.2.10 | `6a1f3c2e-0d4b-4e8a-9c71-2b5d8e0f1a10` | SSH 22, path `direct` |
| M2 (reads) | 192.0.2.11 | `6a1f3c2e-0d4b-4e8a-9c71-2b5d8e0f1a11` | SSH 22, path `direct` |
| M3 (reads, reconnect sequence) | 192.0.2.12 | `6a1f3c2e-0d4b-4e8a-9c71-2b5d8e0f1a12` | SSH 22, path `direct` |
| M4 | 192.0.2.13 | none: enrolled nowhere | none |
| M5 (O1's UDP session, authorized to control) | 192.0.2.14 | `6a1f3c2e-0d4b-4e8a-9c71-2b5d8e0f1a14` | SSH 22, path `direct` |
| O2 (outstation on a moved port) | 192.0.2.21 | `6a1f3c2e-0d4b-4e8a-9c71-2b5d8e0f1a21` | Telnet 23, path `direct` |

**The moved port and UDP** (plan section 2B, P4-4-R1). A relay has one DNP3 port for TCP and UDP, and a transport for each master's session (`DNPNUM`, 1 to 65534, default 20000; `DNPTRn`, UDP or TCP; S22 Table D.7, p. D.11). So each case adds a host that the R6.2 series never shows:

- **`dnp3-moved-port`:** M1 polls a second relay, O2, whose `DNPNUM` is 20001, and sends it one direct operate. No frame uses port 20000. The labeller is told the port from this table, with tshark's `-d tcp.port==20001,dnp3`, and the label's header says so. The product is not told: a `service` it finds there by port alone fails (C13 §11).
- **`dnp3-udp`:** a fifth master, M5, holds O1's UDP session and sends the same poll and operate, one link frame in each datagram. Both ends are on UDP 20000, as a relay with `DNPUDPn` at its default answers (S22 Table D.7). A UDP flow's `direction` is `none`, and its `src` is the first datagram's sender (C13 §4.1).
- **Rules.** The baseline has seen neither service nor pair, so each case's first row expects `new-service` and `unknown-pair`, once for the flow. `authorized_writers` gains (M1, O2, control) and (M5, O1, control), so the operate raises nothing more. Those two entries change no other case: no other capture holds O2 or M5.
- **The label files of these two cases were drafted without tshark,** on a machine that has none, by running `gtlabel.py` over a stand-in that parses only what `dnp3_cases.py` writes. The stand-in reproduces the 19 committed label files byte for byte. They count as labels only once the `dnp3` job of `a6-gt-pcap.yml` is green on them, because that job relabels every capture with the pinned tshark and fails on any difference.

**Counters.** A `counter` row is the difference between the heartbeats that bracket the capture's replay, not a value since the sensor started (D1 on #548).

**`dnp3-unauthorized-operate-no-response`** removes the response and its ACK, and renumbers every later frame: the outstation's sequence numbers and the master's acknowledgements come down by the 37 octets removed, and the TCP checksums are recomputed. So the request reads as unanswered, not as a capture gap (D1 on #548). A capture-gap case, if one is wanted, gets its own row and label.

`.github/workflows/a6-gt-pcap.yml`'s `dnp3` job rebuilds the captures, checks the hashes, relabels them with the pinned tshark, and fails on any difference from the committed labels. `test_dnp3_gt.py` checks the writer without tshark: determinism, checksums, a bitwise CRC, TEST-NET addresses, the case rows, the removed response, the g120 headers and the TCP sequence numbers.
