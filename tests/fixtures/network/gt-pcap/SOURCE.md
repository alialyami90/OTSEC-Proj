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
