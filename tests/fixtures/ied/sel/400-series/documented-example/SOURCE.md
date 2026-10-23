# SEL-400 series documented example

- Fixture class: `documented-example`. This is not device output. It supports at most `documented-untested` or `simulated` claims.
- Source document: *SEL-400 Series Relays Instruction Manual*, date code 20260730. The copy is the one bundled with the owner-supplied SEL-451 manual (`451_400-Series_IM_20260730_20260730.pdf`).
- Transcribed by A2 on 2026-10-23 from a `pdftotext -layout` extraction. Left margin removed; the figure's side labels ("Report Header", "SER Data (six records)") were dropped.

| File | Manual location | Notes |
| --- | --- | --- |
| `cse-report-fig9-17.txt` | Section 9, Figure 9.17 "Sample Compressed ASCII SER Report", p. 9.30 | Response to `CSE`; records are newest first. The manual says each line ends with a four-digit hex checksum, and that "SEL sometimes changes the items and item order", so parse by label, not by position. A2 checked the checksum rule, a 4-hex sum of every byte before the checksum field, including the trailing comma. **The rule holds for the 2 label lines (lines 1 and 3) and fails for the other 7 lines.** Records 3 and 4 have identical byte sums but different printed checksums, so the example data were edited after the checksums were generated. Use it as a negative fixture for checksum validation, and as a positive fixture for layout only. |

The FID is an SEL-411L from 2001, so the example predates the manual revision.
