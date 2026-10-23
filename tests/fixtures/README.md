# Test fixtures

Fixtures are primary evidence. Each fixture must be real or sanitized real material, never synthesized to make a test pass.

- `ied/<vendor>/<model>/`: native device outputs (CLI transcripts, SER dumps, configuration files, Syslog samples). Owner: A2. Registered in `docs/device-capabilities.md`.
- `network/`: PCAP/PCAPNG captures and labeled traffic sets. Owner: A4.

Every fixture directory includes a `SOURCE.md` stating the originating device or network, firmware or software version, capture date, who captured it, and what was redacted. A fixture without a `SOURCE.md` is treated as unknown provenance and must not be used as verification evidence.
