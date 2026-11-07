# GT-PCAP sources (D6)

GT-PCAP is the labelled capture set for V-M6 and R6.1 to R6.5. The plan is `docs/phase4/D6-gt-pcap-plan.md`. Every result on it is `simulated`.

## PRP derived captures (plan section 2C)

| Output | Input | Transform | Terms |
| --- | --- | --- | --- |
| `<stem>-prp-ab.pcap` and `<stem>-prp-a.pcap`, for each stem in `prp-derived.sha256` | The public capture `<stem>.pcap` in `../public-ot-captures/MANIFEST.tsv`, fetched at its pinned SHA-256 | `tests/integration/gt_pcap/prp.py`: every frame twice, with an IEC 62439-3 RCT carrying one sequence number on LAN A and LAN B copies (`-ab`), and the LAN A copies alone (`-a`) | Not vendored, as their inputs state no redistribution terms. `prp.py` rebuilds them byte for byte, and `prp-derived.sha256` pins the result. |

`.github/workflows/a6-gt-pcap.yml` rebuilds them, checks the hashes, has tshark's PRP dissector read every trailer, and writes flow labels as a job artifact. The labels are committed here only after D4 and D2 review them (plan section 1).
