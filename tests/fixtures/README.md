# Test fixtures

Fixtures are evidence. Each fixture is one of the classes below, never synthesized to make a test pass.

| Fixture class | What it is | Highest claim it supports |
| --- | --- | --- |
| `device-capture` | Output captured from a real device, unmodified. | `hardware-verified` (with a dated hardware log) |
| `sanitized-capture` | A `device-capture` with identifying values redacted; `SOURCE.md` lists every redaction. | `hardware-verified` for the parsed structure; not for redacted values |
| `documented-example` | Sample output printed in an OEM manual or protocol document, transcribed exactly. `SOURCE.md` cites document title, revision, section, and page. Approved by A1, 2026-10-23 (A6 proposal). | `simulated` / `documented-untested` only |

A test may not mix classes silently: its fixture directory's `SOURCE.md` states the class. When A2 (parser tests) and A6 (simulator ground truth) each transcribe the same documented example, they transcribe independently, and any difference between the two transcriptions is logged as a finding in `docs/verification.md`.

- `ied/<vendor>/<model>/`: native device outputs (CLI transcripts, SER dumps, configuration files, Syslog samples). Owner: A2. Registered in `docs/device-capabilities.md`.
- `network/`: PCAP/PCAPNG captures and labeled traffic sets. Owner: A4.

Every fixture directory includes a `SOURCE.md` stating its fixture class, the originating device, network, or document, firmware or software version, capture date, who captured it, and what was redacted. A fixture without a `SOURCE.md` is treated as unknown provenance and must not be used as verification evidence.
