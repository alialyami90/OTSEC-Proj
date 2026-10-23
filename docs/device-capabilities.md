# Device Capabilities

Owner: A2. Reviewed by A6 (device safety and correctness) and A3 (security-sensitive behaviour). Status: **Phase 0 draft (2026-10-23). One family assessed from documentation only; nothing tested on hardware or a simulator.** Updated the same day from the owner-supplied SEL-751 instruction manual (S22). Sources S1–S22 and risks D1–D19 are defined in [phase0/A2-device-feasibility.md](phase0/A2-device-feasibility.md); S23–S34 and D20–D25 in [phase0/A2-sel-portfolio.md](phase0/A2-sel-portfolio.md).

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

## Candidate families (SEL only, ADR-0006)

Scope is SEL only until the owner declares the SEL product complete (ADR-0006). Families are listed by device class. The survey and its sources (S23–S34) are in [phase0/A2-sel-portfolio.md](phase0/A2-sel-portfolio.md). Selection criteria: a safe read-only mechanism, availability of primary documentation, representativeness, and lab availability.

| Rank | Device class | SEL family | Candidate firmware | Lab availability | Rationale |
| --- | --- | --- | --- | --- | --- |
| 1 (primary, slice 1) | Protective relay | SEL ASCII relays, reference model SEL-751 | unknown; FID gating per profile (D12) | none | Brief's own scenario (text command, parse output); full instruction manual supplied (S22); simple line protocol a simulator can reproduce. |
| 2 (Q5 contrast, proposed) | Automation controller | SEL RTAC (SEL-5033 firmware) | unknown | none | Push-based: Syslog security and SOE events, named users and roles, two time stamps per message. Tests whether the envelope fits a source with no command/response. Not chosen for SSH: the RTAC has no device shell for monitoring (portfolio §3). |
| 3 | Protective relay | SEL-400 series (SEL-451, SEL-411L, SEL-400G); SEL-787-4; SEL-311L | unknown | none | Same SEL ASCII adapter pattern with model-specific profiles; `CSE` documented for 400 series (S32). |
| 4 | Time server | SEL-2488 | unknown | none | Passive Syslog with UTC offset, SNMP v2c/v3 read, Monitor role (S26). |
| 5 | Ethernet switch | SEL-2730M; SEL-2731 / SEL-2741 with RSTP or OT SDN control plane | unknown | none | Passive Syslog, SNMP v2c/v3, Monitor role (S27–S29). SDN variant managed through SEL-5056 (S31, not read). |
| 6 | Server / computer | SEL-3355-2 | n/a (Windows or Linux) | none | Vendor-neutral host coverage plus SEL SysMon SNMP agent extension for hardware health (S25). |

The SIPROTEC 5 / Relion 615 contrast family from the first draft is dropped (ADR-0006).

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

All rows are from documents. S22 is the SEL-751 Instruction Manual, date code 20260910 (findings, section 15); page numbers are the manual's own.

| Capability | Mechanism | Transport / auth | Classification | Evidence | Limitations |
| --- | --- | --- | --- | --- | --- |
| Asset identification | `ID` command; fields FID, BFID, CID, DEVID, DEVCODE, PARTNO, CONFIG, SPECIAL and two display-package lines, each `"KEY=value","XXXX"` with a 4-hex checksum | Telnet or serial, **Level 0** | `documented-untested` | S22 Table 7.43 and Figure 7.38, p. 7.64; fixture `tests/fixtures/ied/sel/751/documented-example/id-response-fig7-38.txt` (checksums verified) | Figure 3.20 of the same manual has 6 bad checksums (negative fixture). IEC 61850 models add `iedName`, `type`, `configVersion`. |
| Configuration retrieval | `SHO` and its class forms at Level 1 (text rendering); settings files over FTP | Telnet/serial Level 1; FTP with access-level credentials (`FTPACC` default 2) | `documented-untested` for `SHO`; FTP out of scope | S22 Command Summary; S22 Section 4 port settings | Only `SHO G` and `SHO P 1` are proposed for the register, to read time-zone and port-security settings (findings 15.2, 15.4). Q2 answer unchanged: not all configuration is retrievable safely. |
| Event / SER retrieval | `SER` (all rows, up to 1,024, row 1 newest); range forms `SER r1 r2` and date forms exist; `CSE` Compressed ASCII at Level 1 | Telnet or serial, Level 1 | `documented-untested` | S22 Table 7.63, Table 7.16, Figure 10.16 p. 10.40, Table C.2; fixture `ser-report-fig10-16.txt` | No sequence counter (C-06 answered: row number is positional); relay local time, `UTC_OFF` only with SNTP, DST from Global settings; element and state names configurable via `ALIAS`; `CSE` format unknown; Spanish mode renames commands (D16). |
| Syslog emission | none found on the relay | — | `unsupported` per S22 Table 7.5 (no Syslog in the Port 1 protocol list) | S22 Table 7.5; S4, S5, S16; Syslog documented on SEL-3620 (S8) and RTAC (S9) | Relay-side security logging goes to the SER (SALARM, SER4) only. |
| Available CLI commands (approved, read-only) | `ACC`, `ID`, `SER`, `QUI`; proposed `SHO G`, `SHO P 1` | Telnet or serial | `documented-untested` | register below; S22 Command Summary | Level 1 is not read-only (D1, D3, findings 15.3); enforcement by full-line allowlist; English only. |
| Remote engineering compatibility | Telnet ASCII; vendor tool (QuickSet) not assessed; SSH only through a gateway | Telnet and HTTP cleartext; per-level shared passwords | `unsupported` for SSH/TLS on the relay (S22 Table 7.5); rest `unknown` | S5, S7, S8, S16, S22 | Belongs to A3's Q1 comparison. |
| Known firmware differences | FID and SPECIAL identify model, firmware and compatibility | — | `documented-untested` | S22 p. 7.63 | Parse only for FIDs listed in a profile. |
| Operational limitations and safety notes | 3 bad passwords and every Level 2/C access pulse SALARM 1 s, which by default closes OUT101 and is SER4; 2 concurrent Telnet sessions; `TIDLE` 15 min default and sessions stay elevated without `QUIT`; Fast Operate on Telnet gated by `FASTOP` (default N); `MAXACC` caps the port's access level; web server uploads firmware at Level 2 | — | `documented-untested` | S22 pp. 7.33, Table 7.5, Section 4 port and output settings; S16 | See risks D1–D19. Recommend owners set `MAXACC := 1` on the collection port. |

### SEL RTAC (Q5 contrast) — firmware: unknown

All rows from S23 (RTAC SEL-5033 instruction manual, 20260925) unless stated.

| Capability | Mechanism | Transport / auth | Classification | Evidence | Limitations |
| --- | --- | --- | --- | --- | --- |
| Asset identification | Syslog hostname; SNMP agent (v2c/v3) | UDP Syslog (unauthenticated); SNMP v3 user | `documented-untested` | S23 Syslog p. 636; SNMP agent section | Syslog hostname is operator-set, so it is a weak identity. |
| Event / SOE retrieval | Passive Syslog receipt of logged tags at or above a threshold; SOE log viewable in HTTPS web UI | RFC 3164, ≤1024 bytes, facility 23 | `documented-untested` | S23 pp. 636–637, 434; fixture `tests/fixtures/ied/sel/rtac/documented-example/syslog-user-logon.txt` | Only tags configured for logging are sent; UDP may drop; web UI also deletes logs (D21). |
| Security event emission | `User_Logged_On` and `User_Logged_Off` logged by default; 11 User Sessions tags | Syslog | `documented-untested` | S23 p. 633 | Which tags are logged is project-specific. |
| Available CLI commands | none on the device for monitoring; `AcRtacCmd` runs on the engineering PC | — | `unsupported` (device shell) | S24 Section 1 | No command register entries. |
| Operational limitations and safety notes | account lockout after 3 failed attempts; watchdog risk under traffic load; logins can drive OUT101 if so configured | — | `documented-untested` | S23 pp. 434, 602–603, 633–635 | See D20–D23. |

## Approved command register

Every command an adapter may issue is listed here before it is implemented. Commands are classified `read-only` or `state-changing`; `state-changing` commands are never reachable through monitoring permissions (R5.3, R5.7).

| Device family | Command | Parameters (validated) | Classification | Timeout / rate limit | Pagination / prompt handling | Classification evidence |
| --- | --- | --- | --- | --- | --- | --- |
| SEL-751 | `ACC` | none on the line; password sent separately on prompt | read-only (session level 0 to 1 only) | proposed: 10 s per step; one attempt per invocation | expects `Password: ?` then `=>`; on a re-prompt, close without sending (D19) | S22 Table 7.17, p. 7.33 |
| SEL-751 | `ID` | none | read-only (Level 0) | proposed: 10 s; at most once per session | reads to prompt; verify every line checksum | S22 Table 7.43, Figure 7.38 |
| SEL-751 | `SER` | none (range and date forms documented but not registered) | read-only | proposed: 30 s; byte cap 512 KiB; minimum 60 s between invocations per device | reads to prompt; `No Data Available` when empty; paging not documented | S22 Table 7.63 |
| SEL-751 | `SHO G` (**proposed**, needs A1/A6 approval) | none | read-only | proposed: 10 s | reads to prompt | S22 Command Summary |
| SEL-751 | `SHO P 1` (**proposed**, needs A1/A6 approval) | none | read-only | proposed: 10 s | reads to prompt | S22 Command Summary |
| SEL-751 | `QUI` | none | read-only (session level to 0) | proposed: 5 s | reads to `=`; never sent at a password prompt | S22 Table 7.59 |

Denied lines (documented to exist, state-changing or not yet classified) and the full machine-readable register for A6's checker: [phase0/A2-command-register-draft.json](phase0/A2-command-register-draft.json). It is English-only (D16). It denies, among others, `SER C`, `SUM C`, `COM C`, `GOOSE … C`, `PING`, `IRI`, and leaves `CSE` unregistered (so denied) until its format is known; it also denies every other `SER` argument form until classified, `HIS C`, `TRI`, `MET R*`, `TAR R`, `STA` with arguments, `OPE`, `CLO`, `PUL`, `CON`, `SET`, `PAS`, `COP`, `GRO n`, `R_S`, `L_D`, `FIL`, clock-setting `DAT`/`TIM`, all elevation commands (`2AC`, `BAC`, `PAC`, `AAC`, `OAC`, `CAL`), and any byte outside printable ASCII. Timeouts and rate limits above are proposals, not measured values.

## Fixture inventory

Sanitized real device outputs live under `tests/fixtures/ied/<vendor>/<model>/`. Each fixture records its source device, firmware, capture date, and what was redacted.

| Fixture path | Device | Firmware | Source | Redactions |
| --- | --- | --- | --- | --- |
| `sel/751/documented-example/id-response-fig7-38.txt` | SEL-751 (manual example) | not stated in figure | S22 Figure 7.38, p. 7.64 | none (manual uses X placeholders) |
| `sel/751/documented-example/id-response-fig3-20.txt` | SEL-751 (manual example), negative case | not stated | S22 Figure 3.20, p. 3.14 | none; 6 of 12 checksums wrong in the manual |
| `sel/751/documented-example/ser-report-fig10-16.txt` | SEL-751 (manual example) | not stated | S22 Figure 10.16, p. 10.40 | none; column spacing not authoritative |

| `sel/400-series/documented-example/cse-report-fig9-17.txt` | SEL-400 series (manual example, FID SEL-411L 2001) | as printed | S32 Figure 9.17, p. 9.30 | none; 7 of 9 checksums wrong in the manual (D25) |
| `sel/rtac/documented-example/syslog-user-logon.txt` | SEL RTAC (manual example) | not stated | S23 p. 636 | none; hostname placeholder is the manual's |

These are `documented-example` fixtures transcribed from the OEM manual (see their `SOURCE.md`). They are not device output and support at most `documented-untested` or `simulated` claims. No real device output exists yet.
