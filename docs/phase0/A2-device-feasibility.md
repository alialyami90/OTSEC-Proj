# A2 Phase 0 findings: device feasibility for the first slice

- Task: P0-A2 (brief in `docs/agent-handoffs.md`, issued by A1 2026-10-23)
- Author: A2 (OT/IED Integration Engineer)
- Date: 2026-10-23
- Branch: `claude/project-thread-8k8qrr` (the session's fixed branch; the CLAUDE.md convention would be `agent/ied-phase0`)
- Status: draft for A1 consolidation and for cross-review by A6 (device safety, correctness) and A3 (security-sensitive behaviour)

Everything here is from documents and open-source code. No device was contacted. There is no lab IED and there are no real device outputs (owner confirmation relayed by A1, 2026-10-23), so no capability below can be better than `documented-untested`.

## 0. Answers in brief

1. **Primary family: SEL relays that speak SEL ASCII, with the SEL-751 feeder relay as the reference model.** Contrasting second family: an IEC 61850 MMS server IED that exposes its sequence of events as an IEC 61850 log (reference device to be fixed between Siemens SIPROTEC 5 and ABB Relion 615 once their manuals are read). Section 2.
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

S16–S21 were added on 2026-10-23 after the first draft. A1 had extracted and summarised them; A2 re-extracted each PDF with `pdftotext -layout` and checked every claim used here against its own extraction, not against A1's notes. They are data sheets: they have no command tables, access-level tables or example outputs, so they do not replace the instruction manuals.

Rules applied: an OEM document is `documented-untested` evidence for that model and firmware only. Open-source code (S10, S11) is a secondary source: it shows what someone implemented, not what SEL specifies. Where I state something from memory without a source, it is labelled "unverified recollection" and must not be relied on.

## 2. Candidate IED families, ranked

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
| D2 | **Bad password closes the ALARM contact.** "If the requested password is incorrectly entered three times, the relay closes the ALARM contact for one second and remains at Access Level 0." Alarm contacts are commonly wired to SCADA or annunciators. Behaviour on SEL-751 unknown. | S1 | One authentication attempt per invocation. On failure, mark the device credential suspended until an operator clears it; never retry automatically; never probe default passwords. | A2, A3 |
| D3 | **Data-clearing and reset commands exist with short forms.** SEL-300G Table 4 lists `HIS C` (clears event report and history), `SER C` (clears the SER buffer), `PRO R`, `MET RD`, `MET RP`, `MET RE`, `MET RM` (reset demand, peak, energy, max/min). `HIS C` is Level 2 there; the levels of the others are not stated in the quick start. SEL-751A has an equivalent table (S2 Table 10.1, not read). `TAR R` (A6's recollection) is not in S1 and is unconfirmed. | S1, S2 | Deny by default; register only parameter forms read from the manual table. | A2 |
| D4 | **Control and settings commands live on the same session at higher levels.** `OPE`, `CLO`, `PUL` at Level B; `CON`, `SET`, `PAS` at Level 2 (SEL-300G). SEL-751A also has `R_S` (restore factory defaults) and `L_D` (load firmware). | S1, S2 | Collector never holds Level B or 2 passwords, so elevation fails at the password prompt even if an elevation line slipped through. Note: that failure itself counts toward D2. | A3 credential model |
| D5 | **Binary SEL Fast messages share the ASCII port.** The open-source client builds Fast Operate messages beginning `0xA5 0xE0` (remote bit) and `0xA5 0xE3` (breaker bit), plus `0xA5 0xB5` (acknowledge event report) and `0xA5 0xB9` (clear status bits). The SEL-751 data sheet confirms the shared channel: "Binary and ASCII protocols operate simultaneously over the same communications lines" (S16 Table 6), and the SEL-311L lists its single Telnet host session as supporting "SEL ASCII, SEL Compressed ASCII, Fast Meter and Fast Operate" (S17). So on at least one model a Telnet session accepts Fast Operate. Whether this is gated by access level or a port setting is unknown. | S16, S17; S10 (secondary) | Transport-level byte filter: the adapter may send only printable ASCII (0x20–0x7E) plus CR and LF. A6 to test that any other byte aborts the session before transmission. | A2, A6 |
| D6 | **Transparent connections at Level 1 on SEL-400 series.** Level 1 permits "View data and settings and establish transparent connections", i.e. bridging the session to another port. This is a pivot path (Q7). Not documented for SEL-751 in what I read. | S7 Table 5.3 | Keep SEL-400 series out of slice 1; deny any port or transparent-connection command; A3 to track as a Q7 path. | A3 |
| D7 | **Cleartext transport and shared per-level passwords.** Telnet and FTP carry the Level 1 password in clear (S5, S7). Passwords are per access level, not per user ("Set unique passwords for each access level", S5), so the relay cannot attribute a login to a person. | S5, S6, S7 | Collector in the relay's zone; platform audit carries the user attribution; insecure-downstream flag shown to users. Per-user accounts need a gateway (S8). | A3 |
| D8 | **FTP and the web server are write paths.** FTP: FTP logins use the access-level user names (ACC, 2AC, …) and the SEL-451-6 FTP service transfers settings files "to and from the relay". Whether a Level 1 FTP login can write is unknown. The SEL-751 web server uploads relay firmware "(available at Access Level 2)" (S16). | S5, S7, S16 | FTP is out of slice 1. Before any FTP use, read S3 Table 7.56 and get A6 to test Level 1 write refusal on a simulator, then on hardware. | A2 |
| D9 | **Session and port contention.** SEL-311L allows exactly one Telnet host session, one Telnet-to-card session and one FTP session (S17), so a collector holding the Telnet session locks out an engineer on that path. The SEL-751 data sheet gives no session count (S16); its Telnet limit and idle timeout are in S3 Table 4.84 (not read). MMS allows up to 7 client sessions on SEL-451-6 (S5) and 6 on SEL-311L (S17); a collector consumes one. An occupied session could block an engineer during an incident. | S17, S3 (located), S5 | Short sessions, always `QUI`, one session per device at a time, minimum interval between invocations, never hold a session open. | A2, A5 |
| D10 | **SER ring buffer overwrite.** SEL-751 keeps the latest 1,024 SER entries (S4, S16); SEL-451, SEL-411L and SEL-400G keep 1,000 (S5, S18–S20); SEL-311L keeps the last 512 (S17). Entries older than that are gone. A chattering-element auto-removal feature exists (S2/S3 Table 7.40 `SER D`, content not read). `SER C` empties the buffer. | S4, S5, S16–S20, S2, S3 | Poll interval sized to the expected event rate; overlap detection on every read; loss or a buffer reset must be reported as a telemetry gap, not hidden. | A2, A4 |
| D11 | **Processing load on the relay.** No CPU or communications-load guidance found in what I read. | none | Conservative rate limits until measured on hardware; listed as a hardware-only test. | A6 |
| D12 | **Firmware variance.** Output formats differ by model and firmware. The firmware identifier (FID) is returned by the ID command (S10; S2 Figure 3.5 located). | S10, S2 | Parse only on FIDs that a capability profile lists; otherwise run identification only and report "unsupported firmware". | A2 |
| D13 | **Default passwords are shipped.** "This device is shipped with default passwords" (S1); factory defaults are tabulated (S2 Table 7.34). | S1, S2 | Never test defaults (that is credential guessing and trips D2). Recommend operators change them; out of platform scope. | A3 |
| D14 | (Contrast family) **Enabling IEC 61850 reports is a write.** A client reserves a report control block and sets `RptEna` (S13); a collector doing so changes device state and can collide with the SCADA client that owns the block. Log queries are a read service and several clients can query one log (S12). The pure-Go MMS client S11 also exposes control operations and file delete. | S11, S12, S13 | For family 2 use log queries and nameplate reads only. Wrap any MMS library in a facade that exposes read services only, and have A6 test that control, write and file-delete services are unreachable. | A2, A6 |
| D15 | **The collector's own logins may appear in the SER.** SEL-400G SER records "setting changes, relay start-up, password access" (S18); SEL-311L SER may include "relay setting changes, and relay power-up" (S17). Each collection login could therefore create SER rows that the next read collects. SEL-751 behaviour unknown. | S17, S18 | Correlate SER rows with the platform's own session audit records and tag self-generated rows; never suppress them. A4 and A6 to include the case. | A2, A4 |
| D16 | **Serial port language is configurable.** SEL-751: "Choose English or Spanish for your serial ports" (S16). ASCII output, including SER and ID text, may be in Spanish. | S16 | The parser accepts only the language a profile was built for and otherwise fails with `parse_error`; it never guesses. | A2 |
| D17 | (Contrast option on SEL) **MMS authentication uses the Level 2 password.** SEL-400G: when MMS authentication is enabled, "The client request must be accompanied by the Access Level 2 password" (S18). A collector using MMS on such a relay would have to hold a settings-level password, which A3's Level 1 credential ceiling forbids. | S18 | MMS collection from SEL relays with MMS authentication enabled is incompatible with the slice's credential model; do not use it. | A3 |

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

A6 builds the simulator independently from these locations. All are OEM manual examples, so anything built from them is `simulated`, and the examples themselves are `documented-untested`, not captures. The SEL-751 mirror copy's date code was not visible to me; record the date code from whichever copy you use.

| Behaviour | Document | Revision | Location |
| --- | --- | --- | --- |
| ID command response | SEL-751A Instruction Manual PM751A-01-NB | 20130329 | Figure 3.5 "Device Response to the ID Command", p. 3.4 |
| ID command definition | SEL-751 Instruction Manual | see above | Table 7.24 "Identification Command" (ManualsLib p. 489) |
| ID line format and checksum | selprotopy 0.1.3 `protocol/parser/common.py` | 0.1.3 | lines of the form `"FID=…","XXXX"` where XXXX is a hex checksum over the quoted field; fields FID, BFID, CID, DEVID, DEVCODE, PARTNO, CONFIG, SPECIAL (secondary source; confirm against Figure 3.5) |
| Access commands and prompts | SEL-751 Instruction Manual; SEL-421 Instruction Manual | see above | Table 7.8 "Access Commands" (p. 470); SEL-421 Table 4.3 prompts `=`, `=>`, `==>`, `=>>` |
| Bad-password behaviour | SEL-300G Quick-Start | 20060731 | password paragraph after Table 5 |
| SER command forms | SEL-751 Instruction Manual | see above | Table 7.39 (p. 497), Table 7.40 `SER D` (p. 497) |
| SER report example | SEL-751 Instruction Manual | see above | Figure 10.17 "Example Sequential Events Recorder (SER) Event Report" (p. 619) |
| Commands that clear data | SEL-751A Instruction Manual | 20130329 | Table 10.1 "Serial Port Commands That Clear Relay Data Buffers", p. 10.5; SEL-300G Quick-Start Table 4 |
| Command/level summary | SEL-300G Quick-Start | 20060731 | Table 5 |

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

| Item | Status | What would settle it |
| --- | --- | --- |
| Contents of SEL-751 Tables 7.8, 7.24, 7.39, 7.40, 4.84, 7.56, 10.x and Figures 3.5, 10.17 | section located, not read | SEL-751 manual text (owner upload or `selinc.com` allowed in network policy) |
| Access level required for `ID` | unknown (Level 0 or 1) | S3 Table 7.24 |
| Access level and exact forms of `SER C`, `TAR R`, `STA` variants | unknown | S3 command tables |
| SER row numbering, sequence counter, overrun marker | unknown | S3 Figure 10.17 and Table 7.39; then hardware |
| Telnet session limit, idle timeout, port number on SEL-751 | unknown (SEL-311L: 1 Telnet host session, S17) | S3 Table 4.84 |
| Behaviour of Fast Operate bytes on a Telnet session | unknown | SEL Fast Operate documentation; then hardware |
| Bad-password ALARM behaviour on SEL-751 | unknown (documented for SEL-300G) | S3 access-level section; then hardware |
| Compressed ASCII SER command, fields, access level | unknown | SEL-751 manual |
| Whether SEL-751 SER records password access (D15) | unknown (yes on SEL-400G, S18) | SEL-751 manual |
| Relay CPU and communications load from polling | unknown | hardware only |
| Identity and SOE on family 2 reference device | unknown | SIPROTEC 5 or Relion 615 manuals and PIXIT |
| DNP3 event-buffer behaviour with a second master | unverified recollection | SEL-751 DNP3 device profile |

No parsing experiment was run: I could not read the example outputs verbatim, and writing an output by hand would be fabricated evidence. No fixtures were added to `tests/fixtures/ied/`.

## 14. Handoff P0-A2 — A2 — 2026-10-23

**Completed:** candidate ranking (section 2); SEL-751 capability matrix and draft command register (`docs/device-capabilities.md`, `A2-command-register-draft.json`); SSH feasibility (section 5); device-side safety risks D1–D14 (section 6); native SER format as far as documented (section 7); Q2 (section 8); Q5 and a draft adapter interface (section 9); simulator source list (section 10).
**Evidence:** sources S1–S21 in section 1 (S16–S21 are owner-supplied data sheets added after the first draft). Documentation and open-source code only; no hardware, no simulator, no captures.
**Interfaces:** draft invocation and result envelope (section 9), proposal only. No contract introduced or modified.
**Limitations:** SEL-751 manual body text unreadable from this environment, so most command details are "section located, content not read". Every capability is at best `documented-untested`.
**Risks:** Level 1 is not read-only (D1, D3); bad passwords pulse ALARM (D2); Fast Operate bytes on the same port (D5); cleartext Telnet with shared passwords (D7); FTP writes settings (D8); SER ring-buffer loss (D10).
**Dependencies:** A3 decides the credential and enforcement points for D1, D2, D4, D5, D7. A4 consumes section 7 for the event schema. A6 builds the simulator from section 10 and verifies the register. A1 decides primary and contrast families and transfers the interface draft into Phase 1 contract work. The owner can unblock the manual reading.
**Files changed:** `docs/phase0/A2-device-feasibility.md`, `docs/phase0/A2-command-register-draft.json`, `docs/device-capabilities.md`.
**Reviewer(s) and outcome:** A6 and A3 per CLAUDE.md 5.6; pending.
