# SEL-751 documented examples

- Fixture class: `documented-example` (see `tests/fixtures/README.md`). These are not device output. The highest claim they support is `documented-untested` or `simulated`.
- Source document: *SEL-751 Feeder Protection Relay Instruction Manual*, date code 20260910, Schweitzer Engineering Laboratories. The project owner supplied the copy on 2026-10-23 (`OTSEC\Manuals\SEL\751_IM_20260910.pdf` on the owner's device).
- Transcribed by: A2, 2026-10-23, from `pdftotext -layout` output of that PDF, then checked against a second extraction without `-layout`. A6 transcribes the same figures independently, and any difference is logged in `docs/verification.md`.
- Redactions: none. The manual itself prints `Serial No = 2007XXXXXXXXXXX` with X placeholders.

| File | Manual location | Notes |
| --- | --- | --- |
| `id-response-fig7-38.txt` | Section 7, ID Command, Figure 7.38 "ID Command Response", p. 7.64 (also printed identically in the firmware upgrade instructions of the appendix) | All 10 per-line checksums are consistent with their line contents. Each checksum is the 4-digit hex of the sum of the characters of `"KEY=value",`. |
| `id-response-fig3-20.txt` | Section 3, Figure 3.20 "Device Response to the ID Command", p. 3.14 | Has the IEC 61850 fields `iedName`, `type` and `configVersion`, and no `SPECIAL` line. **6 of 12 checksums do not match their line contents in the manual itself.** For example, `"DEVID=SEL-751","0408"`: the same line in Figure 7.38 carries `03C7`, and 0x0408 − 0x03C7 = 0x41 = `A`, which suggests the figure was edited from an SEL-751A example without recomputing checksums. Use it as a negative fixture: a parser must report these checksum failures, not accept the values. |
| `ser-report-fig10-16.txt` | Section 10, Figure 10.16 "Example Sequential Events Recorder (SER) Event Report", p. 10.40 | The response to `SER 8`. Column spacing comes from the PDF layout and is not authoritative. Field order, values and line order are exact. The left margin was removed and trailing spaces trimmed. |

Line endings in these files are LF. The relay's actual line endings and any control bytes (NUL, XON/XOFF) are not shown in the manual and are unknown.
