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

## Collection-method rungs (ADR-0008)

ADR-0008 makes the collection-method order a rule, recorded here per family. For each kind of data the rungs are tried in order, and an adapter for a lower rung is built only when the higher rungs are absent or unsafe for that family (decision 3):

- **Events:** rung 1 is device-generated Syslog; rung 2 is a file fetch (SFTP or SCP first, then HTTPS, FTP only where nothing better exists); rung 3 is command-line `SER` (Telnet, SSH or serial).
- **Configuration:** rung 1 is a secure file transfer; rung 2 is FTP; rung 3 is command-line `SHO`.
- **Identity:** rung 1 is SNMPv3; rung 2 is another read path (an `ID` command, a configuration file); rung 3 is passive observation.

Each cell gives the evidence class and the citation. A rung is `unsupported` when the device's own list of ports or protocols leaves it out, and `unknown` when the source has no such list and does not mention it. "Reached" is the highest rung that is both documented and safe for a monitoring credential, and says whether anything is built. Every cell is from documents: nothing here was tried on a device, and the Phase 2 adapter is `simulated`. No FTP or SNMP code is planned in Phase 3.

A finding that applies to several families: **on SEL ASCII relays a Level 1 login is not read-only.** `SER C` and `SER R` clear the SER at Level 1 (S22 Table 7.63; S34 Table 7.46 p. 7.62), which is why the register allows only exact lines (D1, D3).

### SEL-751 (S22)

| Data | Rung 1 | Rung 2 | Rung 3 | Reached |
| --- | --- | --- | --- | --- |
| Events | Syslog: `unsupported`. Not in the Port 1 protocol list (Table 7.5). | FTP `/REPORTS/SER.TXT`, marked read-only, the `SER` response as a file: `documented-untested` (Table 7.82 p. 7.89; p. 10.40). No SFTP or SCP (Table 7.5). Blocked: whether a Level 1 FTP login can write is `unknown` ([A2-sel751-ftp.md](phase3/A2-sel751-ftp.md)). | `SER` at Level 1 over Telnet: `documented-untested` (Table 7.63 p. 7.75); the Phase 2 adapter is `simulated`. | Rung 3, built. |
| Configuration | SFTP or SCP: `unsupported` (Table 7.5). | FTP `SET_ALL.TXT` and `CFG.TXT`, marked read-only: `documented-untested` (pp. 7.88–7.89). Same block as above, plus `FTPACC` defaults to 2 (Table 4.104 p. 4.250). | `SHO G`, `SHO P 1` at Level 1: `documented-untested` (Table 7.67 p. 7.77); in the register, `SHO G` reads `DATE_F` for `SER` from revision 4. | Rung 3, partly built (the two lines the collector needs). |
| Identity | SNMPv3: `unsupported`. No SNMP agent in Table 7.5. | `ID` at Level 0: `documented-untested` (Table 7.43, Figure 7.38 p. 7.64), built and `simulated`. `CFG.TXT` over FTP carries RELAYTYPE, FID, BFID and PARTNO (Figure 7.46), blocked as above. | Passive. | Rung 2, built. |

The Port 1 web server is excluded from every rung (A6 on #183). It is HTTP, not HTTPS. `EHTTP := Y`, `HTTPACC := 2` and `HTTPPORT := 80` are its defaults (Table 4.104 p. 4.251). Its Reports pages, the SER included, open at Level 1 or 2 (p. 3.2), so it would be a cleartext path for the same Level 1 password. Its Event Reports page also clears the event history and triggers an event (p. 3.4), and the manual does not say which access level those actions need. Class: `documented-untested`.

### SEL-787-4 (S34)

The same file and command model as the SEL-751.

| Data | Rung 1 | Rung 2 | Rung 3 | Reached |
| --- | --- | --- | --- | --- |
| Events | Syslog: `unsupported`. Port 1 lists Modbus TCP, FTP, EtherNet/IP, IEC 61850, DNP3, SNTP, PTP, Telnet, C37.118, PRP and RSTP (Table 7.4 p. 7.13). | FTP `/REPORTS/SER.TXT`, read-only: `documented-untested` (Table 7.63 p. 7.76). FTP logs in with the password of the `FTPACC` level (p. 7.16), `FTPACC` defaults to 2 (p. 4.138), and whether a Level 1 FTP login can write is `unknown`, as for the SEL-751. | `SER` at Level 1: `documented-untested` (Table 7.46 p. 7.62). | Rung 3 eligible, not built (needs its own profile and register). |
| Configuration | `unsupported` (Table 7.4). | FTP `SET_ALL.TXT` and `CFG.TXT`: `documented-untested` (Table 7.61 p. 7.74; p. 7.75). Same block. | `SHO G`, `SHO P k` and the other `SHO` forms at Level 1: `documented-untested` (Table 7.50 p. 7.64). `FIL READ` is Level 1 and `FIL WRITE` Level 2 (Table 7.24 p. 7.48). | Rung 3 eligible, not built. |
| Identity | SNMPv3: `unsupported` (Table 7.4). | `ID` at Level 0: `documented-untested` (Table 7.31 p. 7.53). `CFG.TXT` (Figure 7.36 p. 7.74) over FTP, blocked. | Passive. | Rung 2 eligible, not built. |

### SEL-400 series: SEL-451, SEL-411L, SEL-400G (S32)

| Data | Rung 1 | Rung 2 | Rung 3 | Reached |
| --- | --- | --- | --- | --- |
| Events | Syslog: `unsupported`. Not in the protocol list (Table 15.1 pp. 15.1–15.2); on Ethernet, IP means FTP, HTTP, Telnet, SNTP, MMS, DNP and C37.118 (Table 15.4 note a, p. 15.7). | FTP `REPORTS/SER.TXT` at Level 1: `documented-untested` (Table 15.8 p. 15.21; Table 15.10 p. 15.24). **Hazard:** "Report clears/resets when retrieved though use of a serial port" (Table 15.10 note b), and the SEL-451 R324 release (D20200229) "Modified firmware to retain stored data after successful reads of SER.TXT ... over Ethernet connections" (S32, SEL-451 part, p. A.9), so earlier firmware may clear the SER on an FTP read: `inferred`. A rung-2 collector needs a firmware floor and never the serial file interface. | `SER` at Level 1: `documented-untested` (Table 14.116 p. 14.55). | Rung 2 candidate, not built (Phase 4 decision). |
| Configuration | SFTP or SCP: `unsupported` (Table 15.4 note a). | FTP `SETTINGS/SET_ALL.TXT` and `CFG.TXT`: `documented-untested`. Unlike the SEL-751, the manual states per file that every settings file reads at Level 1 and that no file writes at Level 1 (writes need P, A, O or 2; Table 15.9 pp. 15.23–15.24). The FTP login is an access-level command and its password, one connection, three failures in a minute pulse SALARM and BADPASS (p. 15.16); the FTP server defaults off (Table 12.15 p. 12.12). Still cleartext (D7). | `SHO` at Level 1: `documented-untested` (Table 14.123 p. 14.59). | Rung 2 candidate: documented as read-only at Level 1, needs A3's acceptance of the cleartext login and a hardware check. |
| Identity | SNMPv3: `unsupported` (Table 15.4 note a). | `ID` at Level 0: `documented-untested` (Table 14.88 p. 14.42). `CFG.XML` carries the firmware identification (p. 15.22), at Level 1 over FTP. | Passive. | Rung 2 eligible, not built. |

### SEL-311L (S33)

| Data | Rung 1 | Rung 2 | Rung 3 | Reached |
| --- | --- | --- | --- | --- |
| Events | Syslog: `unsupported`. "The SEL-311L does not support Syslog functionality" (p. K.6). | `unknown`. Ethernet is an optional card, and S33 documents FTP only for that card's firmware upgrade (pp. B.17–B.18). The card's own manual is not in hand. | `SER` at Level 1: `documented-untested` (Table 10.8 p. 10.25). | Rung 3 eligible, not built. |
| Configuration | `unknown`, as above. | `unknown`, as above. | `SHO` at Level 1: `documented-untested` (Table 10.8; Table 10.10 p. 10.39). | Rung 3 eligible, not built. |
| Identity | SNMP: `unknown`. Not mentioned in S33. | `ID` at Level 0: `documented-untested` (p. 10.22). | Passive. | Rung 2 eligible, not built. |

### SEL RTAC: SEL-3505, SEL-3530, SEL-3555-2 with SEL-5033 software (S23; hardware S36–S38)

| Data | Rung 1 | Rung 2 | Rung 3 | Reached |
| --- | --- | --- | --- | --- |
| Events | Syslog of logged tags, RFC 3164, facility 23: `documented-untested` (S23 pp. 635–636; fixture `sel/rtac/documented-example/syslog-user-logon.txt`). | SFTP (or FTP, one mode per project) `Events` directory, readable by the Monitor role: `documented-untested` (S23 Table 2.40 pp. 116–117). It holds the event files of connected devices (CEV, COMTRADE), not the RTAC's own SOE or security log. | `unsupported`: no device shell for monitoring (S24 Section 1). | Rung 1; A4's receiver (Phase 3). |
| Configuration | SFTP: `documented-untested`, **not eligible**. The `Projects` directory is readable only by Administrator and Engineer accounts, which can also write it, and `Configuration` only by Administrator (S23 Table 2.40 pp. 116–117). No read-only account reads the configuration. | FTP: the same server and accounts, cleartext; not eligible. | `unsupported` (S24 Section 1). | None. |
| Identity | SNMPv3 agent, system and interface MIBs with firmware version and host name: `documented-untested` (S23 p. 355). Present only if the project adds the agent. | Syslog hostname, operator-set and weak (S23 p. 636). | Passive. | Rung 1 eligible, not built (Phase 4 item 3). |

### SEL-2488 (S26)

| Data | Rung 1 | Rung 2 | Rung 3 | Reached |
| --- | --- | --- | --- | --- |
| Events | Syslog: `documented-untested` (p. 18.4; Appendix D p. D.2; fixture `sel/2488/documented-example/syslog-login-failed.txt`, whose SOURCE.md records that p. 18.4 says time stamps carry a UTC offset and the wire example on p. D.2 has none). | `unsupported`. The device's IP ports are DHCP, NTP, SNMP, HTTPS and PTP (Table I.1 p. I.1); no file-transfer service. The local report in the web interface (Figure 18.1 p. 18.2) is not a file fetch. | `unsupported`: no command-line service in Table I.1. | Rung 1; A4's receiver (Phase 3). |
| Configuration | Not a protocol rung: settings export is a web-interface step that needs the Administrator role (Section 24, pp. 24.1–24.2). Not eligible for a monitoring credential. | `unsupported` (Table I.1). | `unsupported` (Table I.1). | None. The Monitor role has read-only access to settings in the web interface (p. 10.3), with no documented machine interface. |
| Identity | SNMPv3 `GET`, `GETNEXT` and `WALK` of the dashboard status: `documented-untested` (p. 18.6; v3 settings Table 19.1 p. 19.3). Which OIDs carry the model and firmware is `unknown` until the SEL MIBs (downloadable from the device, p. 19.6) are read. | HTTPS web interface, Monitor role. | Passive. | Rung 1 eligible, not built. |

### SEL-2730M (S43)

| Data | Rung 1 | Rung 2 | Rung 3 | Reached |
| --- | --- | --- | --- | --- |
| Events | Syslog to three destinations: `documented-untested` (p. 60; Appendix E pp. 126–128; fixture `sel/2730m/documented-example/syslog-invalid-login.txt`, whose sample on p. 126 contradicts Table E.3 p. 128). | `unsupported`. The logical ports are HTTP (redirect), HTTPS and SNMP read-only, and the switch "does not support any external file systems" (p. 156). | `unsupported` (p. 156). | Rung 1; A4's receiver (Phase 3). |
| Configuration | Not a protocol rung: settings export in the web interface "by using an active and authorized user" (p. 97; p. 156). Which role may export is not stated: `unknown`. | `unsupported` (p. 156). | `unsupported` (p. 156). | None. The Monitor role has read-only access to most settings (p. 31). |
| Identity | SNMPv3, read-only: `documented-untested` (pp. 83–84; port 161 "SNMP read-only", p. 156). The FID is in the Entity MIB (p. 155). SNMPv1 and v2c are also accepted (p. 83) and must not be used: the community string is plaintext. | HTTPS web interface, Monitor role. | Passive. | Rung 1 eligible, not built. |

### SEL-2731 and SEL-2741 (S27, S28; management from S29 in RSTP mode and S30 in OT SDN mode)

| Data | Rung 1 | Rung 2 | Rung 3 | Reached |
| --- | --- | --- | --- | --- |
| Events | RSTP mode: Syslog: `documented-untested` (S29 p. 28, p. 48, Appendix C pp. 67–69). OT SDN mode: Syslog event logs (S30 Appendix C p. 19). | `unsupported` in RSTP mode: HTTPS and SNMP read-only only, no external file systems (S29 p. 76). OT SDN: `unknown`. | `unsupported` in RSTP mode (S29 p. 76). OT SDN: `unknown`. | Rung 1; A4's receiver (Phase 3). |
| Configuration | RSTP mode: settings export in the web interface (S29 p. 57; p. 76), role not stated: `unknown`. OT SDN mode: flows are configured by the SEL-5056 controller (S31, not read): `unknown`. | `unsupported` in RSTP mode (S29 p. 76). | `unsupported` in RSTP mode (S29 p. 76). | None. |
| Identity | RSTP mode: SNMPv3 with a required cryptographic algorithm, no DES (S29 p. 43); FID in the Entity MIB (S29 p. 75): `documented-untested`. OT SDN mode: SNMP read-only status, v2c or v3, v3 configured through the SEL-5056 (S30 p. 7). | HTTPS web interface, Monitor role (S29 p. 11). | Passive. | Rung 1 eligible, not built. |

### SEL-3355-2 (S25)

A Windows or Linux computer. ADR-0006 gives it vendor-neutral coverage, plus the SEL SysMon hardware agent.

| Data | Rung 1 | Rung 2 | Rung 3 | Reached |
| --- | --- | --- | --- | --- |
| Events | Syslog: `unknown`; S25 documents none. The SEL Alarm Service writes Windows Event Log entries (p. 6.3); forwarding them is an operating-system matter. | `unknown`. | `unsupported`: no SEL command interface. | None. |
| Configuration | Operating-system configuration, vendor-neutral. The BIOS settings and SMBIOS event log are local (p. 4.5). | — | — | None. |
| Identity | SNMP through the standard Windows SNMP Service, extended by the SEL SysMon SNMP Agent Extension with hardware diagnostics (p. 7.7): `documented-untested`. The SNMP version is not stated: `unknown`. | — | Passive. | Rung 1 eligible if the operating system runs SNMPv3, not built. |

### Syslog dialects (D24, updated)

D24 recorded three dialects from the Phase 0 reading. The fixtures added for A4 correct two of them:

- **SEL-2488.** p. 18.4 says time stamps include the UTC offset, but the only wire example (p. D.2) is plain RFC 3164 with no offset. The offset appears only in the web report (Figure 18.1 p. 18.2), in hours, with trailing zeros of the fraction dropped. Whether the wire form carries it is `unknown` until a capture.
- **SEL-2730M.** The sample on p. 126 ("Invalid login attempt by: …") does not match the message text Table E.3 gives for the same event on p. 128 ("Login to {interface}: failed from {IP address}"). A parser keyed to either text alone is unproven.
- The RTAC's message has seven MSG components, adding Log Message and Logging Comment (S23 Table 8.16 p. 636).

## Approved command register

Every command an adapter may issue is listed here before it is implemented. Commands are classified `read-only` or `state-changing`; `state-changing` commands are never reachable through monitoring permissions (R5.3, R5.7).

| Device family | Command | Parameters (validated) | Classification | Timeout / rate limit | Pagination / prompt handling | Classification evidence |
| --- | --- | --- | --- | --- | --- | --- |
| SEL-751 | `ACC` | none on the line; password sent separately on prompt | read-only (session level 0 to 1 only) | proposed: 10 s per step; one attempt per invocation | expects `Password: ?` then `=>`; on a re-prompt, close without sending (D19) | S22 Table 7.17, p. 7.33 |
| SEL-751 | `ID` | none | read-only (Level 0) | proposed: 10 s; at most once per session | reads to prompt; verify every line checksum. A FID that differs from the declared one: `refused.identity_mismatch`, and the asset stays suspended until an administrator clears it. A reply that cannot be read (no STX and ETX, no FID line): `failed.identity_unreadable`, no suspension, retried at the next scheduled run (C2 0.3) | S22 Table 7.43, Figure 7.38 |
| SEL-751 | `SER` | none (range and date forms documented but not registered) | read-only | proposed: 30 s; byte cap 512 KiB; minimum 60 s between invocations per device | reads to prompt; `No Data Available` when empty; paging not documented | S22 Table 7.63 |
| SEL-751 | `SHO G` (**proposed**, needs A1/A6 approval) | none | read-only | proposed: 10 s | reads to prompt | S22 Command Summary |
| SEL-751 | `SHO P 1` (**proposed**, needs A1/A6 approval) | none | read-only | proposed: 10 s | reads to prompt | S22 Command Summary |
| SEL-751 | `QUI` | none | read-only (session level to 0) | proposed: 5 s | reads to `=`; never sent at a password prompt. As the language probe: a reply that ends in `=` but not the C2 grammar is `refused.language_probe_rejected`, and the asset stays suspended until an administrator clears it. No reply before the step timeout, or a close: `failed.timeout` or `failed.transport_closed`, no suspension (C2 0.4) | S22 Table 7.59 |

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
| `sel/2488/documented-example/syslog-login-failed.txt` | SEL-2488 (manual example) | not stated | S26 p. D.2 | none; the manual's host and address; no UTC offset in the example (D24) |
| `sel/2730m/documented-example/syslog-invalid-login.txt` | SEL-2730M (manual example) | not stated | S43 p. 126 | none; contradicts the manual's Table E.3 (D24) |

These are `documented-example` fixtures transcribed from the OEM manual (see their `SOURCE.md`). They are not device output and support at most `documented-untested` or `simulated` claims. No real device output exists yet.
