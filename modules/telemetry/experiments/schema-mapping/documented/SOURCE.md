# Documented examples (not device output)

| File | Source | Class |
| --- | --- | --- |
| `sel751-fig10.16.txt` | SEL-751 Instruction Manual, date code 20260910, Figure 10.16 "Example Sequential Events Recorder (SER) Event Report" (section 10, p. 10.40). It was transcribed from the PDF's text layer with `pdftotext -layout`, with the leading indentation removed. The owner supplied the manual on 2026-10-23. | `documented-untested` |

This is a manual example. It is not a capture from a relay. Column spacing, line endings, and control bytes in real Telnet output may differ (A2 section 7 notes NUL and XON bytes), so this file proves nothing about byte-exact parsing of real output. The serial number is shown as `2007XXXXXXXXXXX` in the manual itself.

A2 extracted the same figure with the same tool (`pdftotext -layout`) from the same manual, and the two files are byte-identical. They are two runs of one tool, not two independent transcriptions, so their agreement is not a cross-check of the PDF text layer against the printed figure.
