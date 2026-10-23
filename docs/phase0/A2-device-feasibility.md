# A2 Phase 0 findings: device feasibility for the first slice

- Task: P0-A2 (brief in `docs/agent-handoffs.md`, issued by A1 2026-10-23)
- Author: A2 (OT/IED Integration Engineer)
- Date: 2026-10-23
- Branch: `claude/project-thread-8k8qrr` (the session's fixed branch; the CLAUDE.md convention would be `agent/ied-phase0`)
- Status: draft for A1 consolidation and for cross-review by A6 (device safety, correctness) and A3 (security-sensitive behaviour)

Everything here is from documents and open-source code. No device was contacted. There is no lab IED and there are no real device outputs (owner confirmation relayed by A1, 2026-10-23), so no capability below can be better than `documented-untested`.

## 0. Answers in brief

> Update after reading the SEL-751 instruction manual (S22): see section 15. Every point below is now confirmed for the SEL-751 from the manual, with one correction. On the SEL-751, failed passwords pulse the SALARM Relay Word bit, which drives the alarm contact OUT101 by factory default and is recorded in the SER by factory default.

1. **Primary family: SEL relays that speak SEL ASCII, with the SEL-751 feeder relay as the reference model.** ~~Contrasting second family: an IEC 61850 MMS server IED (SIPROTEC 5 or Relion 615).~~ **Superseded by ADR-0006:** the contrast is the SEL RTAC (A1 accepted 2026-10-23; see `A2-sel-portfolio.md` section 3). Section 2.
2. **SSH is not a documented native transport for the SEL relay candidates.** The documents I could read list Telnet, FTP and HTTP on the relay Ethernet port. SSH appears only on SEL gateways and automation controllers (SEL-3620, SEL RTAC) that sit in front of relays. The brief's "SSH to an IED" example does not hold for this family; the realistic first-slice path is Telnet (cleartext) from a site-local collector, flagged as an insecure downstream connection. Section 5.
3. **Access Level 1 is not a read-only level.** On SEL relays it permits commands that trigger event reports, and on some models it permits clearing records or resetting meters, opening transparent connections to other ports, and starting elevation to breaker or settings levels. Read-only must be enforced by an allowlist of complete command lines, not by the device's access level. Section 6.
4. **Three bad passwords close the relay ALARM contact for one second** (SEL-300G, documented). A collector that retries authentication can raise alarms in SCADA. One attempt per invocation, then stop. Section 6.
5. **Q2 (can all desired configuration data be safely retrieved?): no, not all, and not with one mechanism.** Section 8.
6. **Q5 (can a common adapter framework represent vendor behaviour without excessive complexity?): plausibly yes, if the common part is the invocation and result envelope plus enforcement, and the session mechanics stay per family.** Section 9 has the draft interface.

## 1. Evidence base and its limits

The environment's egress policy denies direct download from `selinc.com` and from the third-party PDF mirrors I found (HTTP 403 at the proxy). The fetch tool that does reach them extracts only the first part of a long PDF, so for instruction manuals I could read the front matter (table of contents, list of tables and figures) but not the command tables themselves. Short documents (data sheets, quick-start guides, product pages) were read in full.

Consequence: for most commands I can cite the manual section that defines them, but I have not read that section's content. Those rows are marked "section located, content not read". Promoting them needs the manual text: either the owner uploads the SEL-751 instruction manual PDF to the project, or `selinc.com` is added to the environment's allowed domains.

| ID | Source | Revision / date | What was read | Class of source |
| --- | --- | --- | --- | --- |
| S1 | SEL-300G Relay Instruction Manual, Quick-Start section (mirror: bcsswitchgear.com `SEL_300G_QuickStart-CD_20060731.pdf`) | date code 20060731 | full text: Table 4 (commands that clear data), Table 5 (command summary by access level), password behaviour | OEM document |
| S2 | SEL-751A Feeder Protection Relay Instruction Manual, PM751A-01-NB (mirror: nepsi.com `SEL-751A-Instructions.pdf`) | date code 20130329 | front matter only: titles and page numbers of Figure 3.5 "Device Response to the ID Command" (p. 3.4), Tables 7.39 and 7.40 (SER, SER D), Table 7.34 (factory default passwords), Table 7.3 (protocols per port), Table 10.1 "Serial Port Commands That Clear Relay Data Buffers" (p. 10.5); command tables for R_S, L_D, PUL OUTnnn, CONTROL, TRIGGER | OEM document, section located |
| S3 | SEL-751 Feeder Protection Relay Instruction Manual (official: selinc.com/api/download/10737, unreadable from here; mirror: ManualsLib manual 1617093) | date code not visible in mirror | table of contents with mirror page numbers: Table 7.8 Access Commands (p. 470), Table 7.24 Identification Command (p. 489), Table 7.33 Password Command (p. 494), Table 7.39 SER Command (p. 497), Table 7.40 SER D (p. 497), Table 4.82 Time Synchronization Source (p. 314), Table 4.84 Ethernet Port Settings (p. 315), Table 7.56 FTP and MMS Virtual File Structure (p. 508), Figure 10.17 Example SER Event Report (p. 619). Two excerpts: Table 7.39 "SER displays a chronological progression of all available SER rows (as many as 1024 rows)"; Figure 10.17 header "Date: 02/28/2007 Time: 16:34:28 Time Source: Internal … ELEMENT STATE 51P1P Asserted …" | OEM document, section located, two excerpts read |
| S4 | SEL-751 Data Sheet (selinc.com/api/download/10734) | date code not shown in extracted text | full text | OEM document |
| S5 | SEL-451-6 Data Sheet (selinc.com/api/download/124252) | date code 20260217 | full text | OEM document |
| S6 | SEL-421 Instruction Manual, Table 4.3 Relay Access Levels (ManualsLib 1645670, p. 138) | not visible | page text | OEM document |
| S7 | SEL-2701 Ethernet Processor Instruction Manual, Tables 5.3 and 5.4 (ManualsLib 1584531, p. 72) | not visible | page text | OEM document |
| S8 | SEL-3620 Ethernet Security Gateway product page (selinc.com/products/3620) | retrieved 2026-10-23 | full text | OEM marketing |
| S9 | SEL white paper LWP0018-01, "Leveraging Security – Using the SEL RTAC's Built-In Security Features" (selinc.com/api/download/112760) | 20160111 | full text | OEM white paper |
| S10 | selprotopy 0.1.3 (PyPI sdist, MIT, Joe Stanley): `protocol/commands.py`, `protocol/parser/common.py`, `client/base.py` | 0.1.3 | source code read | open-source, not OEM |
| S11 | go-iec61850 v1.0.2 (pkg.go.dev/github.com/otfabric/go-iec61850) | published 2026-07-20 | package page | open-source |
| S12 | Triangle MicroWorks, 61850 Test Suite Pro "Log Services" page | retrieved 2026-10-23 | full text | vendor documentation |
| S13 | Digital Substation, "Magical case study #2: a report-control-block audit in IEDs" | 2026-05-15 | full text | trade article |
| S14 | Siemens, "Cybersecurity for energy automation" tutorial page | undated | full text | OEM marketing |
| S15 | SEL-751A ordering guide WI-7074 (selinc.com/api/download/3278) | 20180913 | full text | OEM document |
| S16 | SEL-751 Data Sheet, supplied by the owner (`/mnt/project-files/phase0/datasheets-SEL/751_DS_20260910.pdf`) | date code 20260910 | full text, extracted by A2 from the PDF | OEM document |
| S17 | SEL-311L Data Sheet, supplied by the owner (`311L_DS_20221103.pdf`) | date code 20221103 | full text | OEM document |
| S18 | SEL-400G Data Sheet, supplied by the owner (`400G_DS_20260331.pdf`) | date code 20260331 | full text | OEM document |
| S19 | SEL-451 Data Sheet, supplied by the owner (`451_DS_20250731.pdf`) | date code 20250731 | full text | OEM document |
| S20 | SEL-411L Data Sheet, supplied by the owner (`411L_DS_20250731.pdf`) | date code 20250731 | full text | OEM document |
| S21 | SEL-787-2/-3/-4 Data Sheet, supplied by the owner (`787-2-3-4_DS_20250501.pdf`) | date code 20250501 | full text | OEM document |
| S22 | **SEL-751 Feeder Protection Relay Instruction Manual**, supplied by the owner (`OTSEC\Manuals\SEL\751_IM_20260910.pdf`) | date code 20260910 | Section 7 (access levels, Telnet, command tables), Section 4 port and global settings, Section 10 SER, Appendix C, Command Summary; extracted by A2 with `pdftotext` | OEM document |

**S22 supersedes S2 and S3 for the SEL-751.** Section 15 records what it settles; where earlier sections say "section located, content not read", section 15 is authoritative.

S16–S21 were added on 2026-10-23 after the first draft. A1 had extracted and summarised them; A2 re-extracted each PDF with `pdftotext -layout` and checked every claim used here against its own extraction, not against A1's notes. They are data sheets: they have no command tables, access-level tables or example outputs, so they do not replace the instruction manuals.

Rules applied: an OEM document is `documented-untested` evidence for that model and firmware only. Open-source code (S10, S11) is a secondary source: it shows what someone implemented, not what SEL specifies. Where I state something from memory without a source, it is labelled "unverified recollection" and must not be relied on.

## 2. Candidate IED families, ranked

> Superseded in part by ADR-0006 (SEL only). The family 2 contrast below (SIPROTEC 5 / Relion 615) is dropped; the contrast is now the SEL RTAC. See `A2-sel-portfolio.md` for the SEL families by device class.

Selection criteria from `docs/device-capabilities.md`: lab availability, representativeness, primary documentation, OT safety of the read-only mechanism. Lab availability is "none" for every candidate, so documentation quality decides (A1, 2026-10-23).

| Rank | Family | Collection mechanism for ID and SER | Why | Against |
| --- | --- | --- | --- | --- |
| 1 (primary) | SEL relays using SEL ASCII, reference model SEL-751 | `ID` and `SER` commands over Telnet or serial at Access Level 1 | It is the brief's own scenario (text command, parse output). Published manuals with command tables, an ID response figure and an example SER report (S2, S3). Simple line protocol that a recording simulator can reproduce byte for byte. Widely deployed in substations. Open-source reference implementation exists (S10). SEL-751 has fewer access levels than the SEL-400 series (no Level 1 transparent connections documented, see section 6). | Cleartext Telnet. Shared per-level passwords. Level 1 is not read-only. Fast Operate binary messages share the port (section 6). |
| 2 (contrast) | IEC 61850 MMS server IED that keeps SOE in an IEC 61850 log; reference device SIPROTEC 5 or Relion 615, to be fixed after reading their manuals | MMS read of LPHD/LLN0 nameplate data for identity; log query (QueryLogAfter / QueryLogByTime) for SOE | Structured, standardized protocol with no CLI, so it tests whether the adapter envelope works without "commands". Log queries are a read service and several clients may query the same log (S12). Simulator available from open-source MMS stacks. Different vendor exercises SER normalization (Q3). | Nothing about either reference device verified yet (S14 only says SIPROTEC 5 has Syslog security logging, TLS and role-based access with LDAPS). Whether a given device configures a log control block at all is project-specific. Enabling report control blocks instead of reading logs would be a write (section 6). |
| 3 (deferred) | GE Multilin UR or similar Modbus/proprietary-engineering-tool relays | Modbus registers; vendor tool | Common in substations. | No text CLI, SOE access through proprietary tooling; least documentation reachable from here. Not investigated. |

Rejected as an SER mechanism for now: DNP3 event polling. Unverified recollection: in DNP3, events confirmed by a master are removed from that session's event buffer, so a second polling master could take events away from SCADA unless the outstation keeps separate buffers per session. This must be checked against the relay's DNP3 device profile (S3 lists one: "SEL-751 DNP3 Device Profile Information") before DNP3 is ever used for collection.

## 3. Capability matrix for the primary family

Recorded in `docs/device-capabilities.md`, section "SEL-751 (SEL ASCII)". Every row is `documented-untested` or `unknown`.

## 4. Draft approved command register

Recorded in `docs/device-capabilities.md`, section "Approved command register", and machine-readable in [`A2-command-register-draft.json`](A2-command-register-draft.json) in the `{id, pattern, classification}` shape A6's checker asked for. Principle (A6 C-01): entries classify complete command lines including parameters, never verbs. Only the exact canonical lines in the allow list may be sent; anything else is denied, whether or not it appears in the deny list. The deny list documents known dangerous lines so tests can probe them.

## 5. Transport: is SSH native?

| Device | Documented Ethernet services | SSH | Source |
| --- | --- | --- | --- |
| SEL-451-6 | Telnet ("access relay settings, metering, and event reports remotely by using the ASCII interface"), FTP ("transfer settings files to and from the relay"), HTTP read-only web pages, IEC 61850 MMS (up to 7 client sessions, optional MMS authentication), DNP3 LAN/WAN, C37.118 | not mentioned | S5 |
| SEL-751 | Specifications list "SEL, Modbus RTU and TCP/IP, DNP3 serial and LAN/WAN, FTP, Telnet, SNTP, PTP, IEC 61850 Edition 2.1, IEC 60870-5-103" among others; a password-protected web server that views settings, downloads reports and "upgrade[s] relay firmware" (firmware upload "available at Access Level 2"); FTP and MMS virtual file structure (S3 Table 7.56) | not listed; no TLS or HTTPS listed either | S16 (2026-09-10), S3, S4 |
| SEL-311L | "Telnet to Host: 1 server session (supports SEL ASCII, SEL Compressed ASCII, Fast Meter and Fast Operate)"; "Telnet to Card: 1 server session"; "FTP to Card: 1 server session"; "IEC 61850: 6 MMS sessions"; "Web Server: 3 simultaneous read-only server sessions" | not listed | S17 |
| SEL-400G | Telnet and FTP; MMS authentication "must be accompanied by the Access Level 2 password" when enabled | not listed | S18 |
| SEL-751A | SEL ASCII, Compressed ASCII, SEL Fast Meter/Operate/SER/Message, Ymodem file transfer, Modbus TCP, DNP3, IEC 61850 options | not mentioned | S15 |
| SEL-2701 Ethernet processor (older relays) | Telnet (no login to start, then relay access levels), FTP with access-level user names | not mentioned | S7 |
| SEL-3620 security gateway | SSH, user-based accounts, LDAP, RADIUS, Syslog, managed IED passwords, logging of all commands entered on IEDs | yes | S8 |
| SEL RTAC | SSH with username and password or keys, Syslog of its SOE log | yes | S9 |

Conclusion: absence from a data sheet is not proof, so the SSH row for the relays stays `unknown`, but nothing found supports SSH on the relay itself, and that now includes the SEL-751 data sheet dated 2026-09-10 (S16), whose full protocol list has no SSH, TLS or HTTPS. For the first slice:

- **Telnet from a site-local collector** on the same network zone as the relay is the realistic path. It is cleartext and must be presented as an insecure downstream connection (R2.3). The Telnet port number and the number of concurrent Telnet sessions are in S3 Table 4.84 (content not read).
- **Serial (EIA-232) from the site node** is equally documented and keeps credentials off the LAN, but needs a physical port and a hardware lab to test.
- **SSH to a gateway (SEL-3620) that then talks Telnet or serial to the relay** is the documented way to get encryption and per-user accounts. It changes the trust boundary (the gateway holds relay passwords) and belongs in A3's Q1 comparison, not in slice 1.

This matches A5's proposal that only site nodes talk to IEDs.

## 6. Device-side OT safety risks of the collection method

Each risk names its source. "Unknown" means the documents that would settle it are located but not read.

| ID | Risk | Evidence | Proposed control | Owner of control |
| --- | --- | --- | --- | --- |
| D1 | **Level 1 is not read-only.** On SEL-300G, Level 1 includes `TRI` (trigger an event report) as well as view commands, and Level 1 can issue `2AC` and `BAC` to request higher levels. | S1 Table 5 | Allowlist of full command lines; `TRI` denied; no elevation command other than `ACC` ever sent. | A2 adapter, A3 enforcement point, A6 test |
| D2 | **Bad password closes the ALARM contact.** "If the requested password is incorrectly entered three times, the relay closes the ALARM contact for one second and remains at Access Level 0." Alarm contacts are commonly wired to SCADA or annunciators. **SEL-751 (S22): confirmed and worse.** Three wrong passwords pulse SALARM for 1 s; so does every successful Level 2 or C access. By factory default SALARM drives OUT101 and is logged as SER4 (section 15.1). | S1, S22 | One authentication attempt per invocation. On failure, mark the device credential suspended until an operator clears it; never retry automatically; never probe default passwords. | A2, A3 |
| D3 | **Data-clearing and reset commands exist with short forms.** SEL-300G Table 4 lists `HIS C` (clears event report and history), `SER C` (clears the SER buffer), `PRO R`, `MET RD`, `MET RP`, `MET RE`, `MET RM` (reset demand, peak, energy, max/min). `HIS C` is Level 2 there; the levels of the others are not stated in the quick start. SEL-751A has an equivalent table (S2 Table 10.1, not read). `TAR R` (A6's recollection) is not in S1 and is unconfirmed. | S1, S2 | Deny by default; register only parameter forms read from the manual table. | A2 |
| D4 | **Control and settings commands live on the same session at higher levels.** `OPE`, `CLO`, `PUL` at Level B; `CON`, `SET`, `PAS` at Level 2 (SEL-300G). SEL-751A also has `R_S` (restore factory defaults) and `L_D` (load firmware). | S1, S2 | Collector never holds Level B or 2 passwords, so elevation fails at the password prompt even if an elevation line slipped through. Note: that failure itself counts toward D2. | A3 credential model |
| D5 | **Binary SEL Fast messages share the ASCII port.** The open-source client builds Fast Operate messages beginning `0xA5 0xE0` (remote bit) and `0xA5 0xE3` (breaker bit), plus `0xA5 0xB5` (acknowledge event report) and `0xA5 0xB9` (clear status bits). The SEL-751 data sheet confirms the shared channel: "Binary and ASCII protocols operate simultaneously over the same communications lines" (S16 Table 6), and the SEL-311L lists its single Telnet host session as supporting "SEL ASCII, SEL Compressed ASCII, Fast Meter and Fast Operate" (S17). So on at least one model a Telnet session accepts Fast Operate. S22 settles it for the SEL-751: Fast Operate is supported on Port 1 Telnet and gated by the port setting `FASTOP`, which defaults to `N` (blocked). | S16, S17, S22; S10 (secondary) | Transport-level byte filter: the adapter may send only printable ASCII (0x20–0x7E) plus CR and LF. A6 to test that any other byte aborts the session before transmission. | A2, A6 |
| D6 | **Transparent connections at Level 1 on SEL-400 series.** Level 1 permits "View data and settings and establish transparent connections", i.e. bridging the session to another port. This is a pivot path (Q7). Not documented for SEL-751 in what I read. | S7 Table 5.3 | Keep SEL-400 series out of slice 1; deny any port or transparent-connection command; A3 to track as a Q7 path. | A3 |
| D7 | **Cleartext transport and shared per-level passwords.** Telnet and FTP carry the Level 1 password in clear (S5, S7). Passwords are per access level, not per user ("Set unique passwords for each access level", S5), so the relay cannot attribute a login to a person. | S5, S6, S7 | Collector in the relay's zone; platform audit carries the user attribution; insecure-downstream flag shown to users. Per-user accounts need a gateway (S8). | A3 |
| D8 | **FTP and the web server are write paths.** FTP: FTP logins use the access-level user names (ACC, 2AC, …) and the SEL-451-6 FTP service transfers settings files "to and from the relay". Whether a Level 1 FTP login can write is unknown. The SEL-751 web server uploads relay firmware "(available at Access Level 2)" (S16). | S5, S7, S16 | FTP is out of slice 1. Before any FTP use, read S3 Table 7.56 and get A6 to test Level 1 write refusal on a simulator, then on hardware. | A2 |
| D9 | **Session and port contention.** SEL-311L allows exactly one Telnet host session, one Telnet-to-card session and one FTP session (S17), so a collector holding the Telnet session locks out an engineer on that path. SEL-751 Port 1 supports two concurrent Telnet sessions, and `TIDLE` defaults to 15 minutes (S22, section 15.2). MMS allows up to 7 client sessions on SEL-451-6 (S5) and 6 on SEL-311L (S17); a collector consumes one. An occupied session could block an engineer during an incident. | S17, S3 (located), S5 | Short sessions, always `QUI`, one session per device at a time, minimum interval between invocations, never hold a session open. | A2, A5 |
| D10 | **SER ring buffer overwrite.** SEL-751 keeps the latest 1,024 SER entries (S4, S16); SEL-451, SEL-411L and SEL-400G keep 1,000 (S5, S18–S20); SEL-311L keeps the last 512 (S17). Entries older than that are gone. A chattering-element auto-removal feature exists (S2/S3 Table 7.40 `SER D`, content not read). `SER C` empties the buffer. | S4, S5, S16–S20, S2, S3 | Poll interval sized to the expected event rate; overlap detection on every read; loss or a buffer reset must be reported as a telemetry gap, not hidden. | A2, A4 |
| D11 | **Processing load on the relay.** No CPU or communications-load guidance found in what I read. | none | Conservative rate limits until measured on hardware; listed as a hardware-only test. | A6 |
| D12 | **Firmware variance.** Output formats differ by model and firmware. The firmware identifier (FID) is returned by the ID command (S10; S2 Figure 3.5 located). | S10, S2 | Parse only on FIDs that a capability profile lists; otherwise run identification only and report "unsupported firmware". | A2 |
| D13 | **Default passwords are shipped.** "This device is shipped with default passwords" (S1); factory defaults are tabulated (S2 Table 7.34). | S1, S2 | Never test defaults (that is credential guessing and trips D2). Recommend operators change them; out of platform scope. | A3 |
| D14 | (Former non-SEL contrast family, superseded by ADR-0006; still relevant to MMS on SEL relays, which have 12 BRCBs and no IEC 61850 log per A4) **Enabling IEC 61850 reports is a write.** A client reserves a report control block and sets `RptEna` (S13); a collector doing so changes device state and can collide with the SCADA client that owns the block. Log queries are a read service and several clients can query one log (S12). The pure-Go MMS client S11 also exposes control operations and file delete. | S11, S12, S13 | For family 2 use log queries and nameplate reads only. Wrap any MMS library in a facade that exposes read services only, and have A6 test that control, write and file-delete services are unreachable. | A2, A6 |
| D15 | **The collector's own logins may appear in the SER.** SEL-400G SER records "setting changes, relay start-up, password access" (S18); SEL-311L SER may include "relay setting changes, and relay power-up" (S17). Each collection login could therefore create SER rows that the next read collects. **SEL-751 (S22): confirmed for alarms.** Denied access pulses SALARM, which is SER4 by default, so failed logins create SER rows. The manual does not say a successful Level 1 login is recorded. | S17, S18, S22 | Correlate SER rows with the platform's own session audit records and tag self-generated rows; never suppress them. A4 and A6 to include the case. | A2, A4 |
| D16 | **Port language is configurable.** SEL-751: "Choose English or Spanish for your serial ports" (S16). ASCII output, including SER and ID text, may be in Spanish. **S22 shows command names change too, and Spanish `SER D` clears the SER** (section 15.3). | S16, S22 | The parser accepts only the language a profile was built for and otherwise fails with `parse_error`; it never guesses. | A2 |
| D17 | (Contrast option on SEL) **MMS authentication uses the Level 2 password.** SEL-400G: when MMS authentication is enabled, "The client request must be accompanied by the Access Level 2 password" (S18). A collector using MMS on such a relay would have to hold a settings-level password, which A3's Level 1 credential ceiling forbids. | S18 | MMS collection from SEL relays with MMS authentication enabled is incompatible with the slice's credential model; do not use it. | A3 |
| D18 | **Elevated sessions persist.** SEL-751: without `QUIT`, "the relay remains at an elevated access level until TIDLE expires" (S22). Whether a new connection inherits that level is not stated. | S22 | Always `QUI` before closing. The auth phase reads the first prompt before sending anything: on `=>` or `=>>` it sends `QUI`, closes and alarms; it never collects on a session it did not elevate itself. | A2, A3, A6 |
| D19 | **After a wrong password, the next line is a password.** The relay re-prompts `Password: ?` up to three times (S22 p. 7.33), so any line sent then, including `QUI`, is consumed as another attempt and moves toward the SALARM pulse. A6 reached the same conclusion independently from its simulator. | S22 (inference from the documented re-prompt; A6 concurs) | On any `Password: ?` re-prompt, close the TCP connection without sending another byte. Never send `QUI` at a password prompt. | A2, A3, A6 |
| D26 | **Password disabled means the password becomes a command.** If the Level 1 password is disabled, `ACC` goes straight to `=>` with no prompt (S22 p. 7.33). A collector that sends its password regardless has it executed as a command line and possibly logged. Raised by A6. | S22 p. 7.33; A6 C-19 notes | Send the password only after seeing `Password: ?`. If `ACC` returns `=>` directly, send nothing further except `QUI`, and record "Level 1 password disabled" as a finding. | A2, A3, A6 |
| D27 | **Communications traffic has restarted SEL-751 relays on some firmware.** The S22 firmware history lists fixed defects where communications caused a "diagnostic restart" of the relay, which interrupts protection while it restarts. Fixes, by FID: "rare issue where Telnet traffic could cause a diagnostic restart" (fixed in R300-V3 and R202-V1, D20210104); "accessing the relay via communications ports … could cause a diagnostic restart" (fixed in R401-V1 and R400-V3, D20240930); "certain Ethernet traffic could cause diagnostic restarts" (R200-V3 and R112-V2, D20170814); "deliberately crafted Ethernet traffic" (R302-V0); invalid-size BPDU (R401-V0, R400-V2, R302-V3); web server denial of service (R500-V0). | S22 Appendix A firmware history | Collection is enabled only for FIDs that a capability profile lists, and a profile lists only FIDs at or after every applicable fix on its branch (strengthens D12). The FID is read with `ID` at Level 0 before `ACC`; an unlisted FID ends the session at Level 0. A6: these are fixed bugs only; unknown ones remain, so D11 (load) stays a hardware test. A3: owners on affected firmware need an upgrade before collection, which is outside the platform. |

## 7. Native SER record format (for A4)

Primary family, SEL-751. What is documented:

- Command: `SER` "displays a chronological progression of all available SER rows (as many as 1024 rows)" (S3 Table 7.39 excerpt). Argument forms (row ranges, date ranges) are in that table, not read.
- Capacity: latest 1,024 entries (S4, S16). SEL-451, SEL-451-6, SEL-411L, SEL-400G: 1,000 (S5, S18–S20). SEL-311L: last 512 (S17).
- Resolution: SEL-451-6 "0.5 ms for contact inputs" and "1/8 cycle for all elements" (S5). SEL-751 (data sheet 20260910, Specifications, Sequential Events Recorder): "Time-Stamp Resolution: 1 ms" and "Time-Stamp Accuracy (With Respect to Time Source): ±1 ms" (S16). SEL-311L: SER time stamps "within ±5 ms of the time-source input" with IRIG-B (S17). Precision therefore differs by model and must be carried per record, not assumed.
- Report header (S3 Figure 10.17 excerpt): `Date: 02/28/2007 Time: 16:34:28 Time Source: Internal`, followed by an identifier and a table with columns that include `ELEMENT` and `STATE`; first row in the excerpt `51P1P Asserted`.
- Time quality: the only time-quality field found is the report-level `Time Source` (example value `Internal`). Time synchronization sources: IRIG-B "within ±1 µs", SNTP "±1 ms (in an ideal network)", PTP ±1 ms firmware-based or ±250 ns hardware-based (S4, S16); "Unsynchronized Clock Drift, Relay Powered: 2 minutes per year typical" (S16), so an unsynchronized relay's SER times can be minutes off. Source selection is in S3 Table 4.82 (not read).
- Row identity: rows come from a ring buffer, so any row number is positional and changes as new entries arrive. Whether rows carry a monotonic sequence number, counter or overrun marker (A6 C-06) is not shown in anything I read: `unknown`.
- Time zone or UTC offset: `unknown`.
- Date format: unverified recollection that SEL relays have a date-format setting (MDY/YMD); `unknown`.
- Control bytes in relay output: the open-source SEL client patches Python's Telnet reader specifically so it does not drop NUL (0x00) and 0x11 (XON) bytes received from the relay, with the comment "Don't eat the Null Characters, They're Important!" (S10 `support/telnet.py`). Inbound control bytes are therefore expected and must survive into the byte-exact transcript; what they mean is `unknown` until the manual is read.

Implications for A4's schema: keep the full report (header and rows) byte-exact as the native record; carry report-level time source beside each row; do not use row numbers as identity; represent "time zone unknown" explicitly.

Duplicate handling (corrected after A6 cross-review, C-13): a per-row key of device identity, timestamp, element and state is wrong. `SER` returns the whole buffer on every read, and two genuinely separate rows can carry identical values, so such a key would merge them. New rows must instead be found by aligning snapshots: compare the new read with the previous one as ordered sequences, find where the previous read's newest rows reappear in the new read, and treat only the rows after that overlap as new. Rows that are identical within one snapshot are kept as separate records. If no overlap is found, the buffer has wrapped past the previous read, been cleared (`SER C`), or the relay restarted. That is a gap and must be reported as one, not resolved by guessing. The overlap can also match at more than one offset, for example when a chattering element produces a repeating tail A B A B, and each offset implies a different number of new rows. That result is reported as ambiguous in the same way as a gap, and is never resolved by picking one offset.

### 7.1 SEL Fast SER, Unsolicited SER and Compressed ASCII versus ASCII `SER`

The data sheets name machine-oriented SER paths besides the ASCII `SER` command: "SEL Fast SER: Provides SER events to an automated data collection system" (S16 Table 6; also S17, S18, S20); "Unsolicited SER protocol allows station-wide collection of binary SER messages" (S16); and Compressed ASCII, "Comma-delimited ASCII data reports … Data are checksum protected" (S16 Table 6).

| Path | For | Against | Slice 1 |
| --- | --- | --- | --- |
| ASCII `SER` (current proposal) | Printable ASCII both ways, fits the byte filter and A6's line checker; human-readable evidence; documented examples exist (S3 Figure 10.17). | Whole buffer on every read, so snapshot alignment and its ambiguity cases (section 7); no checksum on the text found; language and date format settings affect parsing (D16). | keep |
| Compressed ASCII SER | Still printable ASCII, so the same egress controls apply; checksum-protected lines (S16), which gives a transport integrity check; comma-delimited, less layout-dependent parsing. | Command name, fields and access level unknown until the manual is read. Still a whole-buffer read as far as known. | strongest candidate to replace plain `SER` once the manual confirms the command; add it to the register then |
| SEL Fast SER / Unsolicited SER (binary) | Built for automated collection; unsolicited delivery could remove whole-buffer re-reads and the alignment problem. | Binary framing on the same channel, so the client would have to send non-ASCII bytes, which the agreed egress filter forbids (D5); enabling it is very likely a relay port setting, i.e. a Level 2 change by the asset owner (unverified); protocol specification not available here; event delivery and acknowledgement semantics unknown (a risk of taking events from another consumer, as with DNP3, has not been ruled out). | no; revisit in Phase 4 with the protocol specification and an explicit A3 exception for a fixed, reviewed message set |

## 8. Q2: Can all desired IED configuration data be safely retrieved?

**No, not all, and not through one mechanism.** Evidence-based parts:

- SEL Level 1 permits viewing settings (`SHO`, S1; "From Access Level 1, you can view settings; you cannot change settings unless you are at a higher access level", S6). This is the lowest-risk path, but it returns a text rendering per settings class, not the native settings file. Whether every class (logic, port, global, report) is visible at Level 1 is in S3 and not read: `unknown`.
- SEL settings files exist on an FTP and MMS virtual file structure (S3 Table 7.56) and FTP transfers settings "to and from the relay" (S5). The same service writes, and its login is an access-level credential (S7), so FTP is not safe until a Level 1 write refusal is demonstrated (D8).
- Passwords and some security settings require Level 2 (`PAS`, S1) and must never be retrieved by the platform.
- For IEC 61850 devices, the SCL configuration may be retrievable through MMS file services, but vendor parameter sets edited in proprietary tools are not exposed by the standard (inferred from S14 and general knowledge; `unknown` per device).

Conclusion for A1: configuration monitoring (R3) needs per-family capability rows that say which settings classes are retrievable, by which mechanism, at which access level. "All configuration" is not a claim the platform should make. Configuration retrieval is out of the first slice.

## 9. Q5: Can a common adapter framework represent vendor-specific behaviour without excessive complexity?

> Superseded in part by ADR-0006. "Family 2" below was a non-SEL MMS device and is dropped. The Q5 contrast is now the SEL RTAC, a push-based Syslog source with no command register (`A2-sel-portfolio.md` section 3). The shared/per-family split below still holds; the RTAC adds a passive receiver as a second session-driver kind.

**Plausibly yes, with a narrow common layer.** Comparing family 1 (line-oriented CLI, prompt-driven, access levels by password) and family 2 (structured MMS client, typed reads, no commands), what they share is not the session mechanics but the envelope and the enforcement:

- Shared: invocation and result envelope, operation register as data, parameter validation, limits (timeouts, byte caps, rate), raw evidence capture, audit hooks, identity-mismatch handling, error taxonomy.
- Per family: session driver (Telnet/serial line driver with prompt detection; MMS client with read-only facade), parsers, capability profiles per model and firmware.

Trying to model MMS reads as "commands" or CLI output as typed reads is where complexity would grow. Status: inferred from documentation. Phase 1 test: implement the SEL ASCII profile against A6's simulator, write the MMS profile against the same envelope on paper (or against an open-source MMS server example), and count the special cases the envelope needs. More than a couple means the abstraction is wrong.

### Draft adapter interface (proposal for A1; not a contract)

Invocation (what an adapter receives):

| Field | Meaning |
| --- | --- |
| `invocation_id` | Unique id, used to correlate audit, raw evidence and results. |
| `principal_ref` | Who or what scheduled it (from A3's authorization model). |
| `adapter_id`, `adapter_version` | Which adapter build runs. |
| `profile_id` | Capability profile: family, model, firmware patterns it was tested with. |
| `target` | Asset id plus endpoint: transport (`telnet`, `serial`, `mms`), host and port or serial device, optional gateway. |
| `credential_ref` | Opaque reference resolved at connect time by A3's credential broker. The secret never appears in the invocation, logs, or results. |
| `operation_id` | Entry from the approved register, e.g. `sel.ser.read_all`. Only `read-only` operations are invocable under monitoring permission. |
| `params` | Validated against the operation's parameter grammar before connecting. |
| `limits` | Connect timeout, per-step timeout, overall deadline, max response bytes, max pages or rows, minimum delay between steps. |

Result (what an adapter returns):

| Field | Meaning |
| --- | --- |
| `invocation_id`, `status` | Status from a closed set: `ok`, `partial`, `device_error`, `timeout`, `auth_failed`, `refused_by_policy`, `transport_error`, `parse_error`, `identity_mismatch`, `aborted`. |
| `started_at`, `ended_at` | Collector clock. |
| `transcript` | Exact bytes sent and received, in order, with collector timestamps per chunk, and a SHA-256 over the whole. Secrets in sent bytes replaced by a marker before storage, with the replacement recorded. This is the R4.4/V-S8 evidence and lets A6 check V-S7 from the record. |
| `observed_identity` | Identity facts read in this session (for SEL: FID, CID, DEVID, PARTNO and others from `ID`), with a flag when they differ from the expected profile. |
| `session_facts` | Access level reached (from the prompt), whether `QUI` was confirmed. |
| `records` | Parsed records, each pointing to its byte span in the transcript. |
| `warnings`, `error` | Parse warnings and structured error detail. |

Enforcement points the envelope implies (for A3 and A6): the register lookup and parameter validation happen before connect; the transport refuses non-printable bytes for SEL ASCII; the session driver aborts and quits if the prompt shows an access level above the profile's ceiling; authentication is attempted once.

## 10. Simulator source material (for A6)

A6 builds the simulator independently from these locations. All are OEM manual examples, so anything built from them is `simulated`, and the examples themselves are `documented-untested`, not captures. Updated for S22 (SEL-751 Instruction Manual, date code 20260910, owner-supplied); page numbers are the manual's own.

| Behaviour | Document | Location |
| --- | --- | --- |
| ID command response | S22 | Figure 7.38 "ID Command Response", p. 7.64 (checksums consistent). Do **not** use Figure 3.20, p. 3.14: 6 of 12 checksums are wrong (section 15.5). |
| ID command definition and level | S22 | Table 7.43, p. 7.64 (Level 0) |
| Access commands, prompts, password exchange | S22 | Table 7.17, p. 7.32; access-level text and examples, pp. 7.29–7.33 |
| `QUIT` | S22 | Table 7.59, p. 7.73 |
| SER command forms | S22 | Table 7.63; `SER D` Table 7.64; `No Data Available` text, p. 7.75 |
| SER report header | S22 | Table 7.16 |
| SER report example | S22 | Figure 10.16, p. 10.40 |
| All commands with access levels (English and Spanish) | S22 | Command Summary at the back of the manual |
| Port 1 settings (`MAXACC`, `FASTOP`, `LANG`, `TIDLE`, `TCBAN`) | S22 | Section 4, Port 1 settings table; concurrency in Table 7.5 footnote |
| Compressed ASCII and checksum rule | S22 | Appendix C, Table C.2 |
| Bad-password behaviour on another model, for contrast | SEL-300G Quick-Start, 20060731 | password paragraph after Table 5 |

Fixtures already transcribed by A2 are in `tests/fixtures/ied/sel/751/documented-example/` with `SOURCE.md`. A6 should transcribe its own copies and compare.

## 11. Answers to A3's questions

1. Level for SER: Level 1 (`SER` is a Level 1 command on SEL-300G, S1; SEL-751 Table 7.8/7.39 not read). That level does not permit settings changes (S1, S6) but does permit triggering event reports, possibly clearing records, starting elevation, and on SEL-400 series transparent connections (D1, D3, D6). Read-only must be enforced by the platform.
2. Transports: Telnet, FTP, HTTP (read-only pages on SEL-451-6), IEC 61850 MMS, DNP3, Modbus TCP. None of the relay services found is encrypted; MMS has an optional authentication setting on SEL-451-6 (S5). SSH only via SEL-3620 or RTAC (section 5).
3. Accounts: shared per-access-level passwords, no per-user accounts on the relay (S5, S6, S7). Per-user accounts and LDAP/RADIUS exist on the SEL-3620 gateway (S8).
4. Lockout and alarms: three wrong passwords close the ALARM contact for one second and leave the session at Level 0 (S1, SEL-300G). No lockout duration found. SEL-751 behaviour unknown.
5. Device logging of logins and level changes: the SEL-400G SER records "password access" (S18); for SEL-751 not found (`unknown`). The SEL-3620 logs and time-stamps user access and all commands entered on IEDs and exports by Syslog (S8); the RTAC SOE log goes to Syslog (S9).

Commands that change access level: `ACC`, `BAC`, `2AC` (S1), and on SEL-400 series `PAC`, `AAC`, `OAC` (S7); `QUI` returns to Level 0. Only `ACC` and `QUI` are in the allow list.

## 12. Notes for A5 (toolchain)

No hard requirement for Python or C found. SEL ASCII is a line protocol over Telnet or serial with prompt detection and simple checksums; nothing needs a vendor library. For family 2, a pure-Go MMS client exists (S11, MIT, v1.0.2 July 2026, tested against libiec61850); it also exposes control and file-delete services, so it would need a read-only facade (D14). The main C option, libiec61850, is dual-licensed GPLv3/commercial (unverified recollection, check before relying on it). Telnet option negotiation and serial access are ordinary in Go.

## 13. Unsupported assumptions and open items

Updated after S22. Rows settled by the manual are listed in section 15.6 and removed here.

| Item | Status | What would settle it |
| --- | --- | --- |
| `CSE` (Compressed ASCII SER) output format | unknown; command and level documented (S22 Table C.2) | SEL Compressed ASCII documentation, or a capture |
| Whether a new Telnet connection inherits an unquit elevated level (D18) | unknown | SEL support or hardware test |
| Whether a successful Level 1 login is recorded in the SER (D15) | not documented in S22 | hardware test |
| Relay line endings and control bytes in ASCII output | unknown | capture |
| Relay CPU and communications load from polling | unknown | hardware only |
| ~~Identity and SOE on family 2 reference device~~ | superseded by ADR-0006 (SEL only) | n/a |
| DNP3 event-buffer behaviour with a second master | unverified recollection | SEL-751 DNP3 device profile (in S22) |
| Whether `SHO G` and `SHO P 1` output contains passwords or other secrets | believed not (passwords are set with `PAS`, not shown) but unverified | read the `SHO` examples in S22; A3 review |

Parsing experiments are now possible on the documented-example fixtures, but they show only that a parser matches the manual. They are not interoperability evidence.

## 14. Handoff P0-A2 — A2 — 2026-10-23

**Completed:**
- Candidate ranking (section 2; superseded by ADR-0006, SEL only).
- SEL-751 capability matrix and command register (`docs/device-capabilities.md`, `A2-command-register-draft.json`).
- SSH feasibility (section 5).
- Device-side safety risks D1–D27 (section 6; D20–D25 are in `A2-sel-portfolio.md`).
- Native SER format (sections 7 and 15.4).
- Q2 (section 8).
- Q5 and a draft adapter interface (section 9; contrast family is now the SEL RTAC).
- Simulator source list (section 10).
- SEL-751 manual results (section 15).
- SEL-751 firmware allowlist (section 15.7, `A2-sel751-firmware-allowlist.json`).
- SEL portfolio by device class (`A2-sel-portfolio.md`).

**Evidence:**
- Sources S1–S22 are in section 1, and S23–S43 are in `A2-sel-portfolio.md`. S16–S43 are owner-supplied SEL data sheets and manuals; S22 is the SEL-751 instruction manual, date code 20260910.
- This is documentation and open-source code only: no hardware and no captures. The simulator work is A6's.

**Interfaces:** the draft invocation and result envelope (section 9) is a proposal only. No contract was introduced or modified. The register moves to `contracts/` as C3 in Phase 1 (A1).

**Limitations:**
- Every capability is at best `documented-untested`.
- The allowlist's allowed branches are `inferred (owner-accepted)`.
- The `CSE` field list for the SEL-751 is not documented, so `CSE` and `CAS` are deferred.
- Fixtures are manual transcriptions. Figure 3.20, the Figure 9.17 data lines and several AG95-04 examples are internally inconsistent.

**Risks:**
- Level 1 is not read-only (D1, D3, section 15.3).
- Bad passwords pulse SALARM, which by default closes OUT101 and writes the SER (D2, D15).
- Unquit sessions stay elevated (D18).
- After a wrong password, the next line counts as another password (D19).
- If the password is disabled, the password line runs as a command (D26).
- In Spanish mode, `SER D` clears the SER (D16; ruled: refuse unless `LANG := ENGLISH`, with a Level 0 `QUI` probe).
- Communications traffic restarted relays on older firmware (D27; ruled: FID allowlist).
- Fast Operate bytes share the port (D5).
- Telnet is cleartext with shared passwords (D7).
- FTP can write settings (D8).
- The SER ring buffer can lose rows (D10).

**Dependencies:** none outstanding for Phase 0. A1's rulings are recorded in ADR-0005: `SHO G` and `SHO P 1` approved; `CSE` deferred; LANG fail-closed; the `QUI` probe; the allowlist with the `EHTTP` condition. Phase 1 waits on the owner.

**Files changed:**
- `docs/phase0/A2-device-feasibility.md`
- `docs/phase0/A2-command-register-draft.json`
- `docs/phase0/A2-sel-portfolio.md`
- `docs/phase0/A2-sel751-firmware-allowlist.json`
- `docs/device-capabilities.md`
- `tests/fixtures/ied/sel/` (`751/`, `400-series/`, `rtac/` documented-example fixtures, each with `SOURCE.md`)

Merged in PR #2 (85d8091) and PR #8.

**Reviewer(s) and outcome:**
- **A6 (device safety and correctness):** accepted for Phase 0. Record: `docs/phase0/A6-cross-review.md`, section "A2 findings" (commit 89745c6). R-A2-1 to R-A2-4 were dispositioned as follows:
  - R-A2-1 holds: deny-by-default, and every widening must pass A6's corpus.
  - R-A2-2 addressed: a `side_effects` field was added to every register entry.
  - R-A2-3 addressed: dedup by snapshot alignment, ambiguous offsets reported as gaps (section 7).
  - R-A2-4 accepted: Telnet only, so V-S14 does not apply and the cleartext credential is a recorded residual risk.
- **A6 later re-checks:**
  - Follow-up re-check: both corpora pass, snapshot dedup confirmed (`docs/agent-handoffs.md`).
  - The register at bb6f850 passes 112 deny and 6 allow lines, and its read-only set equals A6's allow corpus.
  - The firmware allowlist passed A6's independent `check_allowlist.py` at 27ed082, and again at 76e5940 after the evidence-class change (85d8091).
  - Figure 9.17 transcriptions match byte for byte across three manuals.
- **A3 (security-sensitive behaviour):** no review of P0-A2 recorded yet. A3's file records only A2's review of A3 (A3 §8.3) and A3's adoption of A2's facts for HR-2 and L5. Pending until A3 records it.
- **A1:** integration review accepted for Phase 0 (`docs/agent-handoffs.md`).

## 15. SEL-751 instruction manual results (S22, date code 20260910)

Read on 2026-10-23 from the owner-supplied manual. Everything here is `documented-untested` for the SEL-751 and that manual revision. Page numbers are the manual's own.

### 15.1 Session model

- Prompts: `=` (Level 0), `=>` (Level 1), `=>>` (Level 2), plus restricted Level C (p. 7.29–7.30). The SEL-751 has Levels 0, 1, 2 and C only (no B, P, A, O).
- `ACC` (Level 0) moves to Level 1, `2AC` (Level 1) to Level 2, and `CAL` (Level 2) to Level C (Table 7.17, p. 7.32). `QUIT` returns to Level 0 with no password check (Table 7.59, p. 7.73). `ID` works at Level 0 (Table 7.43, p. 7.64).
- Password exchange: `Password: ?` prompt. A correct password returns a header plus `Level 1` and `=>`. A wrong password re-prompts, up to three times; "If the requested password is incorrectly entered three times, the relay pulses the SALARM Relay Word bit for one second and remains at Access Level 0" (p. 7.33).
- Passwords can be disabled, in which case `ACC` goes straight to Level 1 with no prompt (p. 7.33). The adapter must therefore send its password only after seeing `Password: ?` (D26). A main-board jumper also bypasses passwords up to the port's `MAXACC` level. Even then, "the alarm contact still closes momentarily when accessing Level 2 and Level C" (Section 2, password jumper).
- "The relay pulses the SALARM Relay Word bit for one second after a successful Level 2 or Level C access, or if access is denied" (p. 7.33).
- Factory defaults: `OUT101 := HALARM OR SALARM` (Table 4.83), so SALARM closes the alarm output; `SER4 := SALARM` (Table 4.122), so SALARM pulses are written to the SER. Consequence: on a relay with factory defaults, each failed login burst (D2) both raises the alarm contact and creates SER rows (D15).
- Commands are case-insensitive and may be shortened to their first three letters (Command Summary, p. 1; p. 7.31). Responses: `Invalid Access Level` or `Invalid Command` (p. 7.31).
- Telnet: "Use the QUIT command prior to closing the Telnet-to-Host session to set the relay to Access Level 0. Otherwise, the relay remains at an elevated access level until TIDLE expires" (Telnet Server note, Section 7). `EXIT` terminates a Telnet session from any level.

New risk **D18, inherited elevation.** The manual says an unquit Telnet session stays elevated until `TIDLE` (default 15 min). Whether a new connection can inherit that level is not stated. The auth phase must therefore read the first prompt before sending anything: on `=>` or `=>>` send `QUI`, close and alarm, and never collect on an elevated session. On a `Password: ?` re-prompt, close without sending anything (D19). This matches A3's prompt check.

### 15.2 Port 1 (Ethernet) settings that govern collection

From the Port 1 settings table (Section 4, `SET P 1`; factory defaults shown):

| Setting | Range | Default | Collection relevance |
| --- | --- | --- | --- |
| `ETELNET` | Y, N | Y | Telnet on or off. |
| `MAXACC` | 1, 2, C | 2 | Highest access level reachable on this port. **Setting `MAXACC := 1` makes the relay itself refuse Level 2 on Port 1**: device-native L5 enforcement. Trade-off: engineers then need another port for settings work. |
| `LANG` | ENGLISH, SPANISH | ENGLISH | Also applies to the web server. Command names change in Spanish (D16). |
| `TPORT` | 23, 1025–65534 | 23 | Telnet TCP port. |
| `TCBAN` | 254 characters | `TERMINAL SERVER` | Connect banner sent before the prompt; the session driver must skip it. |
| `TIDLE` | 1–30 min | 15 | Telnet idle timeout (D18). |
| `FASTOP` | Y, N | N | "Set FASTOP := N to block binary Fast Operate messages". **The default blocks binary control on the port**, the device-native half of D5. |
| `EFTPSERV`, `FTPACC` | Y/N; 1, 2, C | Y; 2 | FTP is on by default with a Level 2 ceiling (D8). |

- Concurrency: "PORT 1 concurrently supports two Modbus, five DNP3 LAN/WAN, two FTP, two Telnet, one SNTP, one PTP, two C37.118 protocol (synchrophasor data), and seven IEC 61850 sessions" (Table 7.5 footnote). So a collector uses one of **two** Telnet sessions (D9).
- Protocols on Port 1: Modbus TCP, FTP, IEC 61850, DNP3, SNTP, EtherNet/IP, PTP, Telnet (SEL ASCII, Compressed ASCII, Fast Meter, Fast Operate, Fast SER, Fast Message), HTTP web server, C37.118, PRP, HSR, RSTP (Table 7.5). There is no SSH, TLS or HTTPS; the web server is reached at `http://IPADDR` "for unsecure HTTP communication" (Section 7).
- "Factory-default settings for the Ethernet ports disable all Ethernet protocols except Telnet, HTTP, and PING" (Section 7).
- Serial ports support XON/XOFF flow control (Section 4). XON, XOFF and CAN act on the ASCII stream only (Appendix C).

Recommended asset-owner settings for a relay the platform collects from (proposal for A3 and A1; the platform cannot change them and must not try): `MAXACC := 1` on the collection port, `FASTOP := N`, `LANG := ENGLISH`, and `EFTPSERV := N` or `FTPACC := 1`. With `SHO P 1` (approved by A1 on 2026-10-23), the collector reads these before every collection. Per A1's ruling, a `MAXACC` above 1 is recorded and warned, not refused. The owner has a decision open on whether that should become a refusal.

### 15.3 Level 1 is not read-only: the documented list

From the Command Summary, these SEL-751 **Level 1** commands change state or act outside the relay: `SER C`/`SER R` (clears SER, also Table 7.63), `HIS C`/`R`, `HIS HIF C`/`R`/`CA`/`RA`, `HIS IGF C`, `SUM C`/`R`, `TAR R` (resets latched targets), `LDP C`, `MET RD`/`RE`/`RM`/`RP`, `COM C` and `COM PTP C`/`R`, `GOOSE S … C`, `FGS S … C`, `DATE <date>` and `TIME <time>` (set the clock, which corrupts SER time stamps), `IRIG` (forces time synchronization), `TRI` and `TRI HIF` (trigger event capture), `PING` (relay emits ICMP), `FIL READ` (Ymodem binary transfer) and `2AC`. A6's recollections in C-01 are confirmed: `SER C`, `HIS C` and `TAR R` all clear or reset, and on the SEL-751 all three are Level 1.

Level 2 includes `STA C`/`R` ("Clears the self-test status and restarts the relay"), `OPE`, `CLO`, `PUL`, `CON`, `89C`/`89O`, `SET`, `PAS`, `COPY`, `GROUP n`, `FIL WRITE`, `L_D`, `R_S`, `LOO`, `ANA`, `BRE R`/`W`, `THE P`/`R`, `AFT`, `HSR C`, `INI HIF` and `PARTNO`.

**Language trap (D16, now documented).** With `LANG := SPANISH`, the Spanish column of the Command Summary shows `SER D o R` = "Borrar los datos SER" (clear the SER), while in English `SER D` only lists chattering elements (Table 7.64). Other renamings: `QUIT`→`SAL`, `SHO`→`MOS`, `STA`→`EST`, `TAR`→`BAN`, `DATE`→`FEC`, `TIME`→`HORA`, `SET`→`AJU`, `OPE`→`ABR`, `CLO`→`CER`. The register is valid for English only. SEL's own communications processors require the port language set to English (Appendix C note).

**Ruling (A1, ADR-0005, from A6 F-006):** the adapter reads `LANG` with `SHO P 1` before any `SER` command, and refuses to collect unless it reads `LANG := ENGLISH`, failing closed with an alarm. `FTPACC` or `HTTPACC` above 1 is warned like `MAXACC`. One gap remains: in Spanish `SHO` is `MOS` and `QUIT` is `SAL`. On a Spanish-mode relay, `SHO P 1` may therefore return an error, which correctly fails closed. But `QUI` may also fail to drop the session to Level 0 (D18). A1 accepted A2's proposal (ADR-0005, 4687c17): send `QUI` once at Level 0 before `ACC`, and if it is rejected, close without elevating and raise the LANG alarm. It is valid there in English (Table 7.59), so a rejection reveals a non-English port before any elevation. Whether a Spanish-mode relay accepts English command names is not documented (`unknown`).

### 15.4 SER (answers A6 C-06 and A4's questions for the SEL-751)

- Bare `SER` returns all rows, up to 1,024. "Row 1 is the most recently triggered row and row 1024 is the oldest" (Table 7.63). Forms: `SER row1`, `SER row1 row2`, `SER date1`, `SER date1 date2` (date format per `DATE_F`). A4's observation that a plain read returns only 20 records applies to the SEL-400 series, not the SEL-751.
- Empty buffer: the relay responds `No Data Available` (p. 7.75).
- Row content: "Each entry in the SER includes the SER row number, date, time, element name, and element state" (p. 10.40). **There is no sequence number, counter or overrun marker; the row number is positional** (C-06 answered).
- Element and state text are configurable: `ALIAS` settings rename up to 64 elements and their states, e.g. `ALIAS2:= PB02 FP_LOCK PICKUP DROPOUT` (p. 10.40). The parser must not assume a fixed vocabulary.
- System rows: the relay adds rows for "Relay Powered Up" and "Relay Settings Changed" (p. 10.39).
- Header (Table 7.16): `[RID]  Date: … Time: hh:mm:ss.sss` / `[TID]  Time Source: internal|external`. Time Source is "internal if no time-code input is attached and external if an input is attached", so it reports presence of an input, not lock quality. Date display order follows `DATE_F` (MDY, YMD or DMY). The SER example header also carries `Serial No`, `FID` and `CID`.
- Example (Figure 10.16, p. 10.40), transcribed as a `documented-example` fixture in `tests/fixtures/ied/sel/751/documented-example/ser-report-fig10-16.txt`. Rows are listed oldest first with descending row numbers, times to milliseconds, and two rows share the timestamp `13:54:09.602`.
- Time base: SER times are relay local time. `UTC_OFF` (−24 to +24 h, 0.25 h steps) is used only when SNTP sets the clock: "When a time source other than SNTP is updating the relay time, the UTC_OFF setting is not considered because the other time sources are defined as local time." Automatic DST follows `DST_BEGM` … `DST_ENDH` (Table 4.90, p. 4.230–4.231). Rows carry no DST flag, so local times in the repeated hour at the end of DST are ambiguous. Stating a UTC offset requires reading the Global settings, hence the proposed `SHO G` register entry.
- The SER is also available as a read-only file in `/REPORTS` over FTP or MMS (p. 10.40, Table 7.80). That path is out of slice 1 (D8).
- Machine paths (Appendix C): `CSE` is the Compressed ASCII SER command at Level 1 (Table C.2). SEL's own RTAC collects SER with `CSE` (Table C.5). Compressed ASCII lines carry a checksum computed "by numerically summing all of the bytes that precede the checksum field" (Appendix C). The `CSE` output format is not given in this manual (`unknown`). Fast SER is unsolicited binary that a communications processor enables and disables with binary commands, so it stays out (section 7.1).

### 15.5 Identification

- `ID` response, Figure 7.38 (p. 7.64): fields FID, BFID, CID, DEVID, DEVCODE, PARTNO, CONFIG, SPECIAL, SEL DISPLAY PACKAGE, CUSTOMER DISPLAY PACKAGE. Each line has the form `"KEY=value","XXXX"`. A2 verified that all 10 checksums equal the 4-digit hex sum of the characters of `"KEY=value",`, which confirms the checksum rule from an OEM source.
- Figure 3.20 (p. 3.14) shows a different field set: no SPECIAL, plus `"iedName =TEMPLATE"`, `"type =SEL_751"` and `"configVersion =…"` on IEC 61850 models. **6 of its 12 checksums do not match their lines in the manual itself.** For example, the same `"DEVID=SEL-751"` line carries `0408` there but `03C7` in Figure 7.38; the difference is 0x41, an `A`, suggesting the figure was edited from an SEL-751A example. Finding: OEM examples can be internally inconsistent. A simulator built from Figure 3.20 would emit bad checksums, and the parser must reject them. Both figures are fixtures; Figure 3.20 is a negative case.
- The SPECIAL field determines "hardware and firmware compatibility of the relay" (p. 7.63). `CFG.TXT` over FTP also carries RELAYTYPE, FID, BFID and PARTNO (Figure 7.46).

### 15.6 Status changes from this reading

| Item | Before | After |
| --- | --- | --- |
| SSH on SEL-751 | `unknown` | `unsupported` per Table 7.5 (Port 1 protocol list has no SSH) |
| Access level for `ID` | unknown | 0 |
| `SER C` level | unknown | 1 (clears) |
| `TAR R` | A6 recollection | documented, Level 1 |
| SER sequence counter (C-06) | unknown | none; row number is positional |
| Telnet sessions on SEL-751 | unknown | 2 |
| Bad-password effect on SEL-751 | SEL-300G only | SALARM 1 s; by default drives OUT101 and is logged in the SER |
| Fast Operate on Telnet | open-source inference | supported on Port 1 Telnet; blocked when `FASTOP := N` (default) |
| UTC offset | unknown | local time; `UTC_OFF` only with SNTP; DST rules in Global settings |

### 15.7 Firmware allowlist for collection (D27; A1 ruling ADR-0005, 6d82243)

The machine-readable list is `A2-sel751-firmware-allowlist.json`. Its source is S22 Appendix A. A6 checks it independently.

| Branch | Status | From | Basis |
| --- | --- | --- | --- |
| R501 | allow | V0 | Released after every listed fix |
| R500 | allow | V0 (V1 recommended) | Web-server DoS fix at V0 |
| R402 | allow with condition | V2 | Ethernet lock-up fix at V2. The web-server DoS fix is not listed for R402, so `EHTTP := N` is required, checked with `SHO P 1` |
| R401 | allow with condition | V5 | BPDU fix at V0, communications-port fix at V1, lock-up fix at V5. Same `EHTTP` condition |
| R400 | allow with condition | V7 | BPDU fix at V2, communications-port fix at V3, lock-up fix at V7. Same `EHTTP` condition |
| R302 | deny | – | The communications-port restart fix (collector traffic) is not listed. Ask SEL |
| R301, R300, R202 | deny | – | The crafted-Ethernet, BPDU and communications-port fixes are not listed |
| R201, R200, R100–R113 | deny | – | The Telnet restart fix is never listed |

**Caveat.** Appendix A records each fix only on the branches where SEL shipped it. A branch's V0 row has no "Includes" clause, so it never states whether an older defect existed on that branch. "Allow" therefore rests on an **inference**: a branch whose V0 is dated after a fix is assumed to contain that fix. SEL confirmation would make it documented. **The owner accepted this inference as an owner risk on 2026-10-23 (ADR-0005). The allowed entries carry the evidence class `inferred (owner-accepted)`, not `documented`.**

FIDs not in Appendix A fail closed: later releases, the SEL-751A, and special builds.

