# SOURCE: SEL-751 documented examples (class `documented-example`)

- **Document:** SEL-751 Feeder Protection Relay Instruction Manual, date code 20260910. The project owner supplied the file `751_IM_20260910.pdf` on 2026-10-23 (device folder `OTSEC/Manuals/SEL`).
- **Transcribed by:** A6, 2026-10-23, from `pdftotext -layout` output of the PDF, independently of A2. Not compared with A2's transcriptions; differences will be logged as findings when both exist.
- **This is not device output.** These are printed examples from a manual. They support `simulated` claims only (docs/verification.md, Rules).

| File | Source | Manual page | Notes |
| --- | --- | --- | --- |
| `id-fig-7-38.txt` | Figure 7.38 "ID Command Response" (also printed identically in Section 10 of the same manual) | 7.64 | Firmware R301, D20220607. All 10 line checksums are consistent with checksum = byte sum of `"FIELD",`. |
| `id-fig-3-20.txt` | Figure 3.20 "Device Response to the ID Command" | 3.14 | Firmware X397, D20170305. **6 of 12 checksums are inconsistent**; three differ by exactly 0x41 (`A`), consistent with an SEL-751A response edited to read SEL-751. Kept as a negative example: a parser that validates checksums must reject these lines. |
| `ser-fig-10-16.txt` | Figure 10.16 "Example Sequential Events Recorder (SER) Event Report", response to `SER 8` | 10.40 | Firmware R100 from 2007 in a 2026 manual. Column spacing comes from the PDF layout and is approximate; parsers must not depend on exact column positions until a real capture exists. The prompt line and command echo are omitted. |
| `port1-defaults-table-4-104.txt` | Table 4.104 "Ethernet Port Settings" (Sheets 1-3), factory defaults | 4.249-4.251 | Setting names and factory defaults only, one per line. **No figure in the manual shows `SHO P 1` output**, so the layout the profile renders is ASSUMED. It follows the `SHO` example on p. 7.78 and the SEL-400 Series IM 20260730 `SHO P 5` example (p. 15.49): section headings, `NAME := value` columns, quoted strings. A2 pointed to the SEL-400 example. Conditional settings that the table footnotes hide in some modes are all listed. |
| `command-summary-spanish-names.txt` | Command Summary, English and Spanish columns | last pages | Command names only, used for the `LANG := SPANISH` profile mode and the three-letter collision check. Argument letters also differ (`D` clears in Spanish); see the file header. |

Redactions: none (the manual already shows `Serial No = 2007XXXXXXXXXXX`).

Behaviour used by `../../profile_sel751.py` is cited there page by page. Anything the manual does not state is marked ASSUMED in that file.
