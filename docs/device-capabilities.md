# Device Capabilities

Owner: A2. Reviewed by A6 (device safety and correctness) and A3 (security-sensitive behaviour). Status: **Phase 0 draft (2026-10-23). One family assessed from documentation only; nothing tested on hardware or a simulator.** Sources S1–S15 and risks D1–D14 are defined in [phase0/A2-device-feasibility.md](phase0/A2-device-feasibility.md).

Every capability claim in this document carries an evidence classification. A claim without a classification is invalid.

## Evidence classification

| Class | Meaning |
| --- | --- |
| `hardware-verified` | Demonstrated on physical equipment, with the firmware version, date, and reproducible procedure recorded. |
| `documented-untested` | Stated in OEM documentation but not exercised on hardware by this project. |
| `simulated` | Implemented and tested only against a simulator, emulator, or recorded fixture. |
| `unsupported` | Known not to work, or deliberately excluded. |
| `unknown` | Not yet investigated. |

A `simulated` result is never promoted to `hardware-verified` without a recorded hardware test.

## Candidate IED families

To be proposed in Phase 0 by A2. Selection criteria: availability of a lab unit or sanitized real outputs, representativeness, availability of primary documentation, and OT safety of the read-only collection mechanism.

| Rank | Family | Vendor | Candidate firmware | Lab availability | Rationale |
| --- | --- | --- | --- | --- | --- |
| 1 (primary, proposed) | SEL ASCII relays, reference model SEL-751 | Schweitzer Engineering Laboratories | unknown; FID gating per profile (D12) | none | Brief's own scenario (text command, parse output); manuals with ID response figure and example SER report (S2, S3); simple line protocol a simulator can reproduce; open-source reference client (S10). |
| 2 (contrast, proposed) | IEC 61850 MMS server keeping SOE in an IEC 61850 log | SIPROTEC 5 (Siemens) or Relion 615 (ABB), to be fixed | unknown | none | No CLI; structured reads and log queries (S12); different vendor exercises normalization (Q3). Nothing about either device verified yet. |
| 3 (deferred) | Modbus / proprietary-tool relays, e.g. GE Multilin UR | GE Vernova | unknown | none | Common, but SOE reached through proprietary tooling; not investigated. |

## Capability matrix template

One section per supported IED family and firmware line. Copy the template below.

### `<Vendor> <Model>` — firmware `<version range>`

| Capability | Mechanism | Transport / auth | Classification | Evidence | Limitations |
| --- | --- | --- | --- | --- | --- |
| Asset identification | | | `unknown` | | |
| Configuration retrieval | | | `unknown` | | |
| Event / SER retrieval | | | `unknown` | | |
| Syslog emission | | | `unknown` | | |
| Available CLI commands (approved, read-only) | | | `unknown` | | |
| Remote engineering compatibility | | | `unknown` | | |
| Known firmware differences | | | `unknown` | | |
| Operational limitations and safety notes | | | `unknown` | | |

Evidence column points to primary material: fixture files under `tests/fixtures/ied/`, OEM document name and section, or a dated hardware test log.

### SEL-751 (SEL ASCII) — firmware: unknown, not yet tied to any FID

All rows are from documents. "Located" means the defining manual section was found but its content could not be read from this environment (see A2 findings, section 1).

| Capability | Mechanism | Transport / auth | Classification | Evidence | Limitations |
| --- | --- | --- | --- | --- | --- |
| Asset identification | `ID` command; fields FID, BFID, CID, DEVID, DEVCODE, PARTNO, CONFIG, SPECIAL, each line with a checksum | Telnet or serial; access level unknown (0 or 1) | `documented-untested` | S2 Figure 3.5 p. 3.4 and S3 Table 7.24 (located); field list and checksum from S10 (open source) | Field list not yet confirmed from SEL text; IEC 61850 nameplate identity via MMS not assessed. |
| Configuration retrieval | `SHO` at Level 1 (text rendering); settings files over FTP | Telnet/serial Level 1; FTP with access-level credentials | `unknown` | S1 Table 5 (`SHO` Level 1); S5 (FTP "to and from the relay"); S3 Table 7.56 (located) | Out of slice 1. FTP also writes settings (D8). Q2 answer: not all configuration is retrievable safely. |
| Event / SER retrieval | `SER` (all rows) | Telnet or serial, Level 1 | `documented-untested` | S1 Table 5; S3 Table 7.39 excerpt; S4 (1,024 entries) | Ring buffer (D10); argument forms and row layout not read; no sequence counter found (A6 C-06: unknown). |
| Syslog emission | none found on the relay | — | `unknown` | not in S4 or S5; Syslog documented on SEL-3620 (S8) and RTAC (S9) | Relay-side security logging not found. |
| Available CLI commands (approved, read-only) | `ACC`, `ID`, `SER`, `QUI` | Telnet or serial | `documented-untested` | register below | Level 1 is not read-only (D1, D3); enforcement by full-line allowlist. |
| Remote engineering compatibility | Telnet ASCII; vendor tool (QuickSet) not assessed; SSH only through a gateway | Telnet cleartext; per-level shared passwords | `unknown` | S5, S7, S8 | Belongs to A3's Q1 comparison. |
| Known firmware differences | FID identifies model and firmware; output may differ by firmware | — | `unknown` | S10, S2 | Parse only for FIDs listed in a profile. |
| Operational limitations and safety notes | 3 bad passwords close ALARM contact 1 s (SEL-300G); session limits and idle timeout in Table 4.84; Fast Operate binary bytes share the port | — | `documented-untested` (ALARM, SEL-300G only); `unknown` (rest) | S1; S3 Table 4.84 (located); S10 | See risks D1–D14. |

### IEC 61850 MMS contrast family — reference device not fixed

| Capability | Mechanism | Transport / auth | Classification | Evidence | Limitations |
| --- | --- | --- | --- | --- | --- |
| Asset identification | MMS read of nameplate data (LPHD / LLN0) | MMS over TCP; optional authentication on some devices (S5 for SEL-451-6) | `unknown` | — | Device not chosen. |
| Event / SER retrieval | Log query (QueryLogAfter / QueryLogByTime) | MMS | `unknown` | S12 (logs hold SOE; multiple clients may query one log) | Report control blocks must not be enabled by the collector (D14). |
| Syslog emission | security event logging over Syslog (SIPROTEC 5) | — | `unknown` | S14 (marketing page) | Not verified against a manual. |

## Approved command register

Every command an adapter may issue is listed here before it is implemented. Commands are classified `read-only` or `state-changing`; `state-changing` commands are never reachable through monitoring permissions (R5.3, R5.7).

| Device family | Command | Parameters (validated) | Classification | Timeout / rate limit | Pagination / prompt handling | Classification evidence |
| --- | --- | --- | --- | --- | --- | --- |
| SEL-751 | `ACC` | none on the line; password sent separately on prompt | read-only (session level 0 to 1 only) | proposed: 10 s per step; one attempt per invocation | expects `Password:` prompt then `=>` (S10) | S1 Table 5 |
| SEL-751 | `ID` | none | read-only | proposed: 10 s; at most once per session | reads to prompt | S2 Fig. 3.5, S3 Table 7.24 (located) |
| SEL-751 | `SER` | none (range forms not yet read) | read-only | proposed: 30 s; byte cap 512 KiB; minimum 60 s between invocations per device | reads to prompt; paging behaviour unknown | S1 Table 5; S3 Table 7.39 |
| SEL-751 | `QUI` | none | read-only (session level to 0) | proposed: 5 s | reads to `=` | S1 Table 5 |

Denied lines (documented to exist, state-changing or not yet classified) and the full machine-readable register for A6's checker: [phase0/A2-command-register-draft.json](phase0/A2-command-register-draft.json). It denies, among others, `SER C`, every other `SER` argument form until classified, `HIS C`, `TRI`, `MET R*`, `TAR R`, `STA` with arguments, `OPE`, `CLO`, `PUL`, `CON`, `SET`, `PAS`, `COP`, `GRO n`, `R_S`, `L_D`, `FIL`, clock-setting `DAT`/`TIM`, all elevation commands (`2AC`, `BAC`, `PAC`, `AAC`, `OAC`, `CAL`), and any byte outside printable ASCII. Timeouts and rate limits above are proposals, not measured values.

## Fixture inventory

Sanitized real device outputs live under `tests/fixtures/ied/<vendor>/<model>/`. Each fixture records its source device, firmware, capture date, and what was redacted.

| Fixture path | Device | Firmware | Source | Redactions |
| --- | --- | --- | --- | --- |
| (none) | | | | |

No fixtures yet. No real device output exists, and I could not read the OEM manual examples verbatim, so nothing was transcribed.
