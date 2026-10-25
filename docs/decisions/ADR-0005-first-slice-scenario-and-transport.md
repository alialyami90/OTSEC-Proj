# ADR-0005: First vertical slice scenario and downstream transport

- Status: accepted
- Date: 2026-10-23
- Deciders: A1; transport decided by the project owner (decision card, 2026-10-23); A2 and A3 inputs
- Related: R1.2, R2.3, R4.1–R4.7, R5; Q7; A2 §2, §5, §6; A3 §4.5, HR-8; A6 B-01, B-05, C-07, V-S14; ADR-0002, ADR-0004

## Context

The brief's default first slice is "collect native SER records from a representative lab IED and securely forward them to an upstream Syslog collector, with local asset identification and evidence preservation". The owner confirmed there is no lab IED and no real device output (2026-10-23). A2 selected SEL ASCII relays (reference SEL-751) on documentation quality. Neither A2's sources nor the owner-supplied SEL-751 data sheet (date code 20260910) list SSH, TLS, or HTTPS; documented Ethernet access is Telnet and FTP with shared per-access-level passwords. A1's provisional encrypted-only rule therefore could not be met, and accepting cleartext credentials is a security-policy decision that belongs to the owner.

## Options considered

1. Telnet from a site node in the relay's zone, labelled insecure.
2. SSH to a gateway (SEL-3620 or RTAC) that talks to the relay.
3. Switch the primary family to an IEC 61850 MMS relay.
4. Serial (EIA-232) from the site node (A3's preferred production path; needs physical lab work).

## Evidence

A2 sources S1–S15; SEL data sheets supplied by the owner (`/mnt/project-files/phase0/datasheets-SEL/`); A3 E1 and threat model; A6 cross-review. All `documented-untested` or `simulated`.

## Decision

**Scenario.** A site node (ADR-0002) collects identity (`ID`) and SER (`SER`, no arguments) at Access Level 1 from a simulated SEL-751, stores native bytes and normalized events (ADR-0004), and forwards to an independent upstream syslog receiver. Only the four register lines `ACC`, `QUI`, `ID`, `SER` are sendable. SEL-400 series excluded (transparent connections, A2 D6). Configuration retrieval, FTP, the web server, DNP3, and Fast SER are out of the slice.

**Transport (owner decision).** Telnet from a site node in the relay's zone, with these controls:

- The device's `downstream_security` is `plaintext-unauthenticated`, shown wherever the device appears and carried in every `device.*` audit record.
- Plaintext collection requires a per-device admin acknowledgement recording the reason (A3 §4.5).
- Telnet never crosses the WAN; the node sits in the relay's zone.
- Credential ceiling Level 1; one authentication attempt per invocation; a failed login suspends the credential until an operator clears it (avoids the ALARM pulse, A2 D2).
- The credential slot opens only after the documented password prompt; sent authentication bytes are redacted in the transcript (HR-3 ruling).
- Transport egress check on the final socket bytes: exact register lines only, printable ASCII plus CR/LF (A2 D5).
- One session per device at a time (single Telnet session on some models, A2 D9). A successful session ends with `QUI`. *Amended 2026-10-23 (A6 C-19, SEL-751 IM 20260910 p. 7.33):* after a failed password the relay reads the next line as another attempt, so the adapter sends nothing more and closes the TCP connection; it never sends `QUI` after a failure.
- *Amended 2026-10-23 (A6, p. 7.33):* if `ACC` reaches Level 1 without a password prompt (Level 1 password disabled), the credential is not sent, the connection is closed, and a security alarm is raised for the asset (A3 AP-23: password-bypass jumper or disabled password).
- *Owner decision 2026-10-23 (MAXACC, raised by A3):* deployment guidance recommends `MAXACC := 1` on the collection port (with `FASTOP := N` and FTP disabled or `FTPACC` limited). Before collecting, the adapter reads `SHO P 1` and raises a visible warning when MAXACC on that port is above 1; it still collects. Relay settings are never changed by the platform.
- *A1 ruling 2026-10-23 (A6 F-006, IM Table 4.104 and Command Summary):* the same warning covers `FTPACC` and `HTTPACC` on Port 1 (both default 2), since a port that passes the MAXACC check still accepts Level 2 over FTP and HTTP.
- *A1 safety ruling 2026-10-23 (A6 F-006; A1 verified in the SEL-751 Command Summary, Spanish column: `SER D o R` clears SER data and `SER B` is the delete report):* command meaning depends on the port's `LANG` setting, so a register line that is read-only in English can be destructive in Spanish. The adapter reads `LANG` with `SHO P 1` before any `SER` command and **refuses to collect** (fails closed, raises an alarm) unless `LANG := ENGLISH`. The register is English-only; Spanish support would need its own register and deny corpus.
- *A1 ruling 2026-10-23 (A2 proposal, 9bdb98d; A1 checked the Command Summary, which says commands may be entered by their first three letters, and found no Spanish command beginning `QUI` or `SHO`):* before `ACC`, the adapter sends `QUI` once at Level 0 as a language probe. In English it is valid at Level 0 and changes nothing (Table 7.59: no password check to remain at Level 0); a rejection means a non-English port, and the adapter closes the connection without elevating and raises the LANG alarm. The `SHO P 1` LANG check stays as the second layer. The probe passes only when the reply matches a fixed grammar: an optional Table 7.16 header (RID/TID, date and time), an optional `Level 0` line, then the `=` prompt, and nothing else (A2, since the IM documents no QUIT reply; the exact grammar is defined in the Phase 1 C2 brief and must be confirmed against a real reply before collection from any real device, A6 hardware item); any other reply fails closed, because the Spanish error text is undocumented (A6 F-007). Whether a Spanish-mode port accepts English names is undocumented, so both cases are simulated, not proven (A6 V-S17, H-12). Session end is `QUI` then TCP close; the manual's Telnet `EXIT` is not added to the register (D18: if the relay keeps the session after disconnect, `TIDLE` bounds it). *Amended 2026-10-25 (D2-19, C2 0.4):* a probe with no prompt before the step timeout or a close is unanswered, not rejected. It ends the session with `failed.timeout` or `failed.transport_closed` and suspends nothing, and nothing more is sent. A reply that ends in a prompt is still judged by the grammar.
- *A1 safety ruling 2026-10-23 (A2 finding; A1 verified in SEL-751 IM 20260910 Appendix A firmware history):* several firmware revisions fixed diagnostic restarts caused by communications, for example "Telnet traffic could cause a diagnostic restart" (fixed in R300-V3 and R202-V1, D20210104), "certain Ethernet traffic could cause diagnostic restarts" (R200-V3 and R112-V2, D20170814), crafted Ethernet traffic (R302-V0, D20220826), invalid-size BPDU (R401-V0 D20240308, R302-V3 D20240122), and "accessing the relay via communications ports" (R401-V1, D20240930). A diagnostic restart interrupts protection, so: (a) collection is allowed only for firmware IDs (FID) on an allowlist per firmware branch, built by A2 from the firmware history with every known communications-restart fix present, and checked independently by A6; (b) the operator records the relay's FID at asset registration, and the collector **does not open a connection** unless that declared FID is on the allowlist, because the risk is in the Telnet traffic itself; (c) after connecting, the FID from `ID` (Level 0) must match the declared FID, or the collector closes before `ACC` and raises an alarm; (d) unknown, older, or unlisted FIDs fail closed; a unit whose FID is not known from records is never contacted to find out, and first contact with it needs separate owner authorization (A6 C-23). The allowlist (A2, `docs/phase0/A2-sel751-firmware-allowlist.json`) rests on the inference that a branch first released after a fix contains it; before collection from any real relay the owner obtains SEL confirmation or accepts that inference. *Owner decision 2026-10-23 (18:47Z): the inference is accepted;* branches R400–R402, R500 and R501 are treated as containing the earlier communications-restart fixes, recorded as an owner-accepted risk. The allowlist entries carry the evidence class `inferred (owner-accepted)`, never `documented`. Branches R400–R402 are allowed only with `EHTTP := N`. Residual risk: fixes not listed in the manual, and firmware branches the manual does not cover, remain unknown.
- *Fast Message (A2):* the slice sends no binary messages (egress check allows printable ASCII and CR/LF only; `FASTOP := N` recommended), so no Fast Message document is needed for this slice. Revisit only if a later family needs Fast SER or Fast Meter.
- In this milestone credentials are lab-only test values; collection from any real device needs separate owner authorization.

## Consequences

- **Residual risks accepted by the owner for this slice:** the Level 1 password is readable by anyone on the station LAN; the platform cannot cryptographically authenticate the relay, so identity rests on `ID` output plus network address, which is spoofable (V-S14 not applicable; A6 C-07 open for this family).
- A6's simulator needs a Telnet front end (built, per A6 cross-review).
- Serial collection and SSH gateways remain candidates for production and for Phase 4 engineering access.

## Open objections

A3 HR-8 recorded the conflict with B-05; resolved for this slice by the owner's decision with the residual risks above. Not resolved for production use.
