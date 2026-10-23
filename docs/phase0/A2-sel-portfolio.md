# A2 SEL portfolio survey by device class (ADR-0006)

Owner: A2. Date: 2026-10-23. Status: Phase 0 survey. Every finding is `documented-untested`: it comes from owner-supplied SEL manuals and was not tested on hardware or a simulator.

ADR-0006 limits vendor-specific work to SEL. It asks A2 to do two things: organize candidates by SEL product family and device class, and confirm or reject the RTAC as the Q5 contrast family. This document does both. Facts on the SEL-751 are in section 15 of `A2-device-feasibility.md`.

## 1. Sources (continuing S1–S22)

All sources below are owner-supplied PDFs in `/mnt/project-files/phase0/manuals-SEL/`. The quotations come from `pdftotext -layout` extractions, and page numbers are the manual's own.

| ID | Document | Date code |
| --- | --- | --- |
| S23 | ACSELERATOR RTAC SEL-5033 Software Instruction Manual | 20260925 |
| S24 | Programming Reference for ACSELERATOR RTAC SEL-5033 Software | 20260925 |
| S25 | SEL-3355-2 Automation Controller Instruction Manual (PM3355-04) | 20260521 |
| S26 | SEL-2488 Satellite-Synchronized Network Clock Instruction Manual (PM2488-01) | 20260918 |
| S27 | SEL-2731 Ethernet Switch Manual | 20251223 |
| S28 | SEL-2741 Ethernet Switch Manual | 20260724 |
| S29 | Rapid Spanning Tree Protocol for the SEL Managed Ethernet Switch, User's Guide | 20260424 |
| S30 | Software-Defined Networking for the SEL Managed Ethernet Switch, User's Guide | 20260601 |
| S31 | SEL-5056 Network Management System Instruction Manual | 20261015 |
| S32 | SEL-400 Series Relays Instruction Manual (bundled with SEL-451, SEL-411L, SEL-400G manuals) | 20260730 |
| S33 | SEL-311L-0, -6 Instruction Manual | 20260129 |
| S34 | SEL-787-4 Instruction Manual | 20251212 |

**Coverage limits.** Sections were read where this document cites them; everything else was located by keyword search only. Two families were surveyed only by keyword search: S30 and S31 (SDN) and S33 and S34 (relays). No document was supplied for the RTAC hardware itself (SEL-3530/3555/3350). S23 covers the RTAC software and firmware behaviour, and the SEL-3355-2 can be ordered as an RTAC platform or as a general computer.

## 2. Families by device class

"Mechanism" means the read-only way the platform could learn about the device. "Passive" means the device sends and the platform receives, with no query from the platform.

| Device class | SEL family | Management surface | Read-only mechanism for the platform | Device-native least privilege | Security event source | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Protective relay | SEL-751, SEL-787-4, SEL-311L (SEL ASCII relays) | Telnet/serial SEL ASCII, FTP, HTTP, MMS | SEL ASCII `ID`, `SER` (and `CSE`) at Level 1, allowlisted | Per-level shared passwords; `MAXACC` caps a port (751, 787-4) | SER rows from SALARM; no Syslog | S22; S33/S34 by search only |
| Protective relay | SEL-400 series (SEL-451, SEL-411L, SEL-400G) | Same, with seven access levels (1, B, P, A, O, 2, C) | SEL ASCII `ID`, `SER`, `CSE` at Level 1 | `MAXACC` (search: 15–26 hits per manual) | SER records password access (S18) | S32 Table 14.50; Figure 9.17 |
| Automation controller / communications processor | SEL RTAC (SEL-5033 firmware on SEL-3530/3555/3350 or SEL-3355-2) | HTTPS web UI with named user accounts and roles; LDAP and RADIUS; SSH and Telnet for engineering-access tunnels to downstream IEDs; SNMP v2c/v3 | **Passive Syslog receipt** (RFC 3164); SNMP read; SOE log via the HTTPS web UI | Named user accounts with roles | Security tags (`User_Logged_On`, `User_Logged_Off` by default) go to the SOE log and, at or above a threshold, to Syslog | S23 Section 8 pp. 602–603, 633–637; Section 5 p. 434 |
| Server / computer | SEL-3355-2 (Windows or Linux) | OS-native (Windows Remote Desktop and so on) | Windows SNMP Service with the SEL SysMon SNMP Agent Extension for hardware health; Windows event logs (vendor-neutral, ADR-0006 item 3) | OS accounts | OS event logs; SysMon alarms; alarm contact | S25 Section 7 "SNMP Agent Extension", Appendix B |
| Time server | SEL-2488 satellite clock | HTTPS web UI; front panel | **Passive Syslog** (RFC 3164 with a UTC offset in the time stamp; three destinations; port fixed at 514); SNMP v2c/v3 read; SNMP v2c traps | Four roles: Administrator, Engineer, User Manager, **Monitor** | Authentication success and failure, settings changes, link, time events (traps and Syslog); 60,000 local events | S26 Sections 10, 18, 19 |
| Ethernet switch | SEL-2731, SEL-2741 hardware with a selectable control plane: RSTP managed or OT SDN | RSTP: HTTPS web UI, SNMP v2c/v3, Syslog; SDN: managed by a flow controller (SEL-5056) | Passive Syslog (RFC 3164, UDP, up to three destinations, 60,000 local messages); SNMP read | Four roles including **Monitor** ("read-only access to most of the device"); LDAP and RADIUS role mapping | Syslog; SNMP | S27/S28 overview; S29 pp. 1–4, Section 3, Appendix C |
| Network management (SDN) | SEL-5056 | Software on a server | Syslog (73 hits); not read further | Not read | Not read | S31 by search only |

No SEL device in this set offers a device-side SSH command line for monitoring. The RTAC's SSH carries engineering-access tunnels, and its `AcRtacCmd` CLI runs on the Windows engineering PC (S24 Section 1, "the RTAC installation folder will be added to the user's %PATH%"), not on the device.

## 3. Q5 contrast family (ADR-0006 item 6): RTAC confirmed, with a corrected rationale

**Recommendation: keep the RTAC as the contrast, but for a different reason than ADR-0006 gives.** ADR-0006 expects the RTAC to differ "in transport (SSH)". The manual does not support that. The RTAC exposes no device shell for monitoring (section 2), so an SSH command adapter would have nothing to run. The RTAC is still the right contrast because it differs from an SEL ASCII relay in three ways the adapter envelope has to handle:

1. **Push instead of poll.** Security and SOE events arrive as Syslog the platform did not request. Each envelope must therefore cover a source with no invocation, no command register and no session. If the envelope only fits command/response, Q5 fails, so this is the right test.
2. **Named users and roles on the device.** The RTAC has named user accounts with roles, LDAP and RADIUS. The relay has only shared per-level passwords. The asset and credential model (C1, A3) must express both.
3. **Different timestamps.** The Syslog header carries the RTAC's send time, and the message body carries the event time to the millisecond. The SEL-751 SER carries local time with no zone. A4's schema must keep both RTAC times and must never use the header time as the event time (fixture below: 9.4 s apart in the manual's own example).

A second candidate is the SEL-2488 clock. It is smaller and also push-based, with an explicit UTC offset in its time stamps, and it is less critical than the RTAC. I recommend the RTAC because it is the device that collects relay SER in SEL's own architecture (S22 Table C.5), so it overlaps with the slice.

## 4. New device-side risks

These continue D1–D19 from `A2-device-feasibility.md`.

| ID | Risk | Evidence | Proposed control |
| --- | --- | --- | --- |
| D20 | **RTAC account lockout.** In the SOE log example, "the user is locked out" after three consecutive failed attempts. SSH engineering access disconnects after three failed attempts. A platform that authenticates to the RTAC with a shared account and fails could lock engineers out. | S23 p. 434, p. 602 | For the RTAC, prefer passive Syslog so the platform holds no RTAC credential. If an active read is ever approved, use a dedicated account with the lowest role and make one attempt only. |
| D21 | **The RTAC web UI can delete all logs.** "Delete Collected Events/Files and Logs … This operation cannot be undone." The same web session that reads SOE logs can also acknowledge or clear entries. | S23 p. 435 | Do not automate the RTAC web UI. If SOE retrieval is ever needed, use a role that cannot delete, and have A6 test that the role cannot delete. |
| D22 | **RTAC watchdog under traffic load.** Traffic that drives processing past 80 percent of the watchdog time-out lowers priorities. If it continues, "the watchdog timer will expire". | S23 pp. 602–603 | Prefer passive collection. Rate-limit any active polling, and have A6 add a load case. Polling an automation controller is not free. |
| D23 | **Logins can drive physical outputs on the RTAC too.** S23 Example 8.6 maps `User_Logged_On` to the alarm contact OUT101 as an example project. Whether a site has done this is unknown. | S23 pp. 633–635 | Same posture as D2: minimise logins. Passive Syslog avoids the issue. |
| D24 | **Syslog dialects differ.** RTAC: RFC 3164 with a year in the header and a fixed facility 23. SEL-2488: RFC 3164 with a UTC offset added to the time stamp, port fixed at 514. Switches: RFC 3164 over UDP. UDP Syslog is unauthenticated and can be lost or spoofed. | S23 p. 636; S26 Section 18; S29 Appendix C | A4's receiver keeps the raw bytes and parses each dialect with its own profile. It marks UDP Syslog as unauthenticated evidence, and receiving it is passive. A3 decides the network placement. |
| D25 | **OEM Compressed ASCII examples carry wrong checksums.** In the SEL-400 Figure 9.17 `CSE` sample, 7 of 9 line checksums do not match. Only the two label lines match. | S32 p. 9.30; fixture below | A parser rejects lines with bad checksums. A simulator built from this figure must recompute the checksums. |

## 5. Machine SER format: `CSE` (closes the SEL-751 open item in part)

S32 documents `CSE` for the SEL-400 series:

- Forms (Table 14.50, Level 1): `CSE`, `CSE k`, `CSE m n`, `CSE date1`, `CSE date1 date2`, and `TERSE` with any of these (Table 14.51).
- Records are newest first, the reverse of `SER`.
- The output is comma-delimited, and each line ends with a 4-hex checksum (Figure 9.17).
- "SEL sometimes changes the items and item order", so the parser must map fields by label line, not position.
- Example header: `"RID","SID","FID"`. Example fields: `"#","MONTH","DAY","YEAR","HOUR","MIN","SEC","MSEC","ELEMENT","STATE"`.

A2 verified the checksum rule on the label lines: the checksum is the sum of every byte before the checksum field, including the comma. The same rule is in S22 Appendix C. The data lines do not match.

For the SEL-751, `CSE` is a documented Level 1 command (S22 Table C.2), but its field list is still not in the 751 manual. Assuming the 400-series layout would be an inference. `CSE` stays unregistered until A1 approves it and a 751-specific source or capture exists.

## 6. Fixtures added

| Path | Source | Use |
| --- | --- | --- |
| `tests/fixtures/ied/sel/400-series/documented-example/cse-report-fig9-17.txt` | S32 Figure 9.17 | Layout positive, checksum negative (D25) |
| `tests/fixtures/ied/sel/rtac/documented-example/syslog-user-logon.txt` | S23 p. 636 | RTAC Syslog dialect for A4; header time is not the event time |

Each directory has a `SOURCE.md`.

## 7. What this changes for other agents

- **A1:**
  - Correct the rationale in ADR-0006 item 6. RTAC contrast is confirmed as push or passive, not SSH.
  - Decide whether `CSE` enters the register for the 400-series only.
- **A3:**
  - Passive Syslog from the RTAC, switches and clock needs no device credential. That is the safest collection mode found.
  - Switches and the clock have a device-native Monitor (read-only) role, which suits SNMPv3 reads if active reads are ever approved.
  - The RTAC is itself an engineering-access gateway (SSH or Telnet tunnels to IEDs), which bears on Q1 and Q7.
  - D20–D23.
- **A4:**
  - Three Syslog dialects (D24).
  - The RTAC event time is inside MSG.
  - The 2488 time stamp carries a UTC offset.
  - `CSE` is newest-first and its fields are mapped by label.
- **A6:**
  - D20–D22 test cases.
  - Two new negative and dialect fixtures.
  - Load on the RTAC (D22) is a hardware-only test.
