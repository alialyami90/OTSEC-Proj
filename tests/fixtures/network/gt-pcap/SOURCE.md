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
| `dnp3/<name>.pcap` for each name in `dnp3/dnp3.sha256`: 17 labelled cases, and the R6.2 series `dnp3-train` (seed 1) and `dnp3-heldout` (seed 2), each 3600 s | Written by D6, 2026-11-07, with `tests/integration/gt_pcap/dnp3_cases.py` (stdlib only: `synth.py`, `dnp3.py`, `pcapfile.py`) | Synthesized frame by frame, never recorded through a kernel and never sent. The network is TEST-NET-1 (192.0.2.0/24) with locally administered MACs. One outstation, link address 10 on TCP 20000. Masters: M1 (.10, authorized to write and control), M2 (.11, reads), M3 (.12, reads and does the reconnect sequence), and M4 (.13, unenrolled). Group 120 objects are synthetic at header level, because no SA specification or SA capture is held (plan section 2B, D2 on #542). | This project's own. Not committed: `dnp3_cases.py` rebuilds them byte for byte, and `dnp3/dnp3.sha256` pins them and `dnp3-cases.json`. |
| `dnp3/<name>.tsv` | `tests/integration/gt_pcap/gtlabel.py` over the outputs above, with the pinned tshark 4.2.2 | Labels: `flow`, `service`, `function` (with `sa` as C13 §4 derives it), `counter` (`dnp3_seq_reused`), and `case` rows that list every rule expected to fire and their context. `gtlabel.py` first fails on any IP or TCP checksum, DNP3 CRC or malformed frame tshark reports, and on any case whose `sa` disagrees with tshark's reading. | `desk` until D4 (labels) and D2 (protocol reading) review them. Every result on them is `simulated`. |

**The C1 records the replay enrolls** (D1 on #548). C1 has no DNP3 transport, so a host resolves to its asset only through a direct endpoint on its IP that C1 does have. Each enrolled host therefore gets one, and no capture here holds a session on it. The records are in `dnp3-cases.json` under `net`, as `c1_endpoint`.

| Host | IP | Asset ID | C1 endpoint |
| --- | --- | --- | --- |
| O1 (outstation) | 192.0.2.20 | `6a1f3c2e-0d4b-4e8a-9c71-2b5d8e0f1a20` | Telnet 23, path `direct` |
| M1 (authorized writer) | 192.0.2.10 | `6a1f3c2e-0d4b-4e8a-9c71-2b5d8e0f1a10` | SSH 22, path `direct` |
| M2 (reads) | 192.0.2.11 | `6a1f3c2e-0d4b-4e8a-9c71-2b5d8e0f1a11` | SSH 22, path `direct` |
| M3 (reads, reconnect sequence) | 192.0.2.12 | `6a1f3c2e-0d4b-4e8a-9c71-2b5d8e0f1a12` | SSH 22, path `direct` |
| M4 | 192.0.2.13 | none: enrolled nowhere | none |

**Counters.** A `counter` row is the difference between the heartbeats that bracket the capture's replay, not a value since the sensor started (D1 on #548).

**`dnp3-unauthorized-operate-no-response`** removes the response and its ACK, and renumbers every later frame: the outstation's sequence numbers and the master's acknowledgements come down by the 37 octets removed, and the TCP checksums are recomputed. So the request reads as unanswered, not as a capture gap (D1 on #548). A capture-gap case, if one is wanted, gets its own row and label.

`.github/workflows/a6-gt-pcap.yml`'s `dnp3` job rebuilds the captures, checks the hashes, relabels them with the pinned tshark, and fails on any difference from the committed labels. `test_dnp3_gt.py` checks the writer without tshark: determinism, checksums, a bitwise CRC, TEST-NET addresses, the case rows, the removed response, the g120 headers and the TCP sequence numbers.
