# Threat Model

Owner: A3. Reviewed by A6. Status: **v0 (Phase 0 draft, 2026-10-23).** Nothing in this document is verified on hardware. Every mitigation below is *proposed*; none is implemented. The one experiment run so far (E1) used loopback mocks and is `simulated` evidence only.

Supporting analysis (Q1 comparison, credential reference model, read-only enforcement layers, audit fields, evidence list) is in [phase0/A3-security-feasibility.md](phase0/A3-security-feasibility.md).

Evidence labels used here: `[doc]` stated in an OEM document or standard we read; `[exp-sim]` shown by a local experiment against mocks; `[inferred]` reasoning, not observed; `[peer]` agreed with another agent's draft, not yet an ADR.

## Scope and assumptions

Topologies in scope for v0:

- **T1 Single server.** One host runs UI, policy, storage, collection, and forwarding.
- **T2 Central plus site collectors.** A central management server and one or more site nodes; each site node collects from its own IEDs and keeps operating when the WAN is down.
- **T3 Distributed site-local services** is treated as T2 where the site node also exposes a local UI/API. Differences specific to T3 are noted inline.

Engineering access (R2) is modelled for its trust boundary and abuse paths, but it is not part of the first vertical slice and none of its mitigations are scheduled before Phase 4.

Assumptions (each must be confirmed or replaced before Phase 2):

| ID | Assumption | Basis | What would change if false |
| --- | --- | --- | --- |
| AS-1 | A site node sits in its own zone between the station LAN and the WAN, behind a firewall the asset owner controls. | `[inferred]` from IEC 62443 zone/conduit practice; no customer topology available. | If the node must sit directly on the station LAN with WAN reach, AP-16 (bridging) becomes the dominant risk. |
| AS-2 | At least some target IEDs offer only plaintext management transports (Telnet, FTP, serial) and shared per-access-level passwords. | `[doc]` ABB 615 series exposes FTP/FTPS and MMS, with plaintext possible when Secure Communication is off (1MRS758280 rev C, §3.3–3.4). Primary family not yet chosen by A2. | If the primary family has SSH with per-user accounts, AP-1 and AP-12 shrink considerably. |
| AS-3 | Upstream Syslog/SIEM collectors are *less* trusted than the platform for integrity: the platform sends to them and accepts nothing from them. | `[inferred]` | None expected; this is a design rule, not a fact. |
| AS-4 | The identity provider is out of scope; the platform consumes an external IdP or a local account store behind a stable interface. | A1 brief P0-A3 exclusion. | n/a |
| AS-5 | No lab IED is available. | A1 brief P0-A1. | With a lab IED, device-level layers (L5 below) and AP-4/AP-12/AP-13 become testable on hardware. |

## Assets to protect

Protection priority, highest first:

1. Protection and control functions of IEDs and controllers. The platform must never degrade them (P1, R8 constraint).
2. IED configurations and settings (integrity and confidentiality).
3. Engineering and monitoring credentials held by the platform.
4. Audit records and collected evidence (integrity and availability).
5. Collected telemetry (integrity, availability).
6. Platform control plane (enrollment, policy, upgrades).
7. The approved command register and signed policy bundles. Tampering with them widens what the platform will send to a device. *(added v0)*
8. Signing keys: release signing key and policy signing key. *(added v0)*
9. The platform's network position. A site node with an IED-facing interface and stored credentials is a ready-made pivot. *(added v0)*

The platform also *aggregates* reconnaissance value: asset inventory, firmware versions, configurations, and topology for many sites in one place (ATT&CK for ICS T0811 Data from Information Repositories, T0882 Theft of Operational Information). Central storage confidentiality is therefore a requirement, not a nice-to-have.

## Trust boundaries

```
 T2: central plus site collectors

  Users/IdP ──TB1──► [ Central management ]◄──TB2 (site-initiated mTLS, outbound only)──┐
  Admins ────TB7──►        │  no route to IEDs                                          │
                           │                                                            │
                     TB5 ──┴──► Upstream Syslog/SIEM ◄── TB5 ──┐                        │
                                                               │                        │
                                     ┌─────────────── Site zone (AS-1) ─────────────────┴──┐
                                     │  [ Site node ]  mgmt NIC: local UI/API (T3 only)     │
                                     │   monitoring plane │ TB4 │ collection/credential     │
                                     │                    │     │ plane                     │
                                     │  IED-facing NIC ───┼─────┘                           │
                                     └──────────┬────────────────────────────▲──────────────┘
                                          TB3 (node→IED, often plaintext)    │ TB10 (IED→node data:
                                                ▼                            │ SER replies, syslog)
                                     [ Station LAN: IEDs ]───────────────────┘
                                     [ TAP/SPAN ]──TB6 (receive-only)──► sensor NIC

 T1: single server = central and site node on one host. TB2 disappears; TB4 must still be
     a process and credential boundary; the host straddles the enterprise and station
     networks, which adds AP-16.
```

| ID | Boundary | What crosses | Initiator | Required properties | Enforced at |
| --- | --- | --- | --- | --- | --- |
| TB1 | User → platform UI/API | Human authentication, requests | User | Strong authentication; MFA for engineering, admin, and security roles; authorization per operation class; session expiry and revocation. | Platform API gateway (central, and site node in T3). |
| TB2 | Site node ↔ central | Telemetry, audit, asset data up; signed policy bundles and acks down | **Site node only** `[peer A5]` | mTLS with per-node certificates; no inbound listener on the node from the WAN; no generic exec channel; central can request replay of a sequence range from the node's *local store* only, never a device re-collect `[peer A5]`. | Site node transport and policy verifier. |
| TB3 | Site node → IED | Device sessions issuing register commands | Site node | Only register operations; least-privileged device access level; per-device rate limit and single session; host-key pinning where SSH exists; plaintext transports explicitly accepted per device and labelled. | Site node transport layer, plus site firewall and device-native access levels. |
| TB4 | Monitoring plane ↔ collection/credential plane (inside a node or server) | Collection schedules in, parsed results out | Scheduler (system identity) | Monitoring code cannot read credentials or reach the IED-facing interface; no API turns a user request into device I/O in slice 1. | OS process and user separation; credential store access control. |
| TB5 | Platform → upstream Syslog/SIEM | Normalized events and audit copies | Platform | Outbound only; TLS with pinned collector identity; nothing accepted back; never forwards secrets or full configurations. | Forwarder; site/central egress firewall. |
| TB6 | Sensor → platform | Mirrored traffic | Network | Receive-only interface with no IP address; capture process unprivileged after start. | Host network config (A4/A5). |
| TB7 | Administrator → platform | Policy, enrollment, credential *writes* | Admin | Credentials are write-only (set or replace, never read back); privileged role grants need a second approver; all changes audited. | Platform API; credential store. |
| TB8 | Engineering user → IED via access gateway (Phase 4) | Engineering sessions | User | Per-session destination pinning; time limit; recording; revocation; insecure downstream clearly flagged. | Access gateway (see Q1 in the findings file). |
| TB9 | Release pipeline → platform | Software updates | Admin | Signed with an offline release key not present on central; anti-rollback floor in signed metadata `[peer A5]`. | Node update verifier. |
| TB10 | IED → platform | SER replies, CLI output, syslog datagrams | IED or anything on the station LAN | Treated as hostile input: size limits, memory-safe parsing, no side effects in parsers, parser process holds no credentials. | Adapter parsers and syslog receiver. |

## Actors

| ID | Actor | Starting position | Main interest |
| --- | --- | --- | --- |
| AC-1 | External attacker | Enterprise network or internet-facing remote access | Reach OT through the platform. |
| AC-2 | Insider with monitoring role | Authenticated UI user | Escalate to device writes or credential access. |
| AC-3 | Insider with engineering role | Authenticated, privileged sessions (Phase 4) | Act outside approved device or time window; hide activity. |
| AC-4 | Malicious or compromised platform administrator | Policy, enrollment, credential write | Self-grant engineering access; widen policy; tamper with audit. |
| AC-5 | Compromised site node | Root on node: credentials at rest, IED-facing NIC | Use stored credentials and network position against IEDs. |
| AC-6 | Compromised central server | Root on central | Command many site nodes at once; harvest data across sites. |
| AC-7 | Compromised upstream collector | Receiving end of TB5 | Pivot back into the platform; read forwarded data. |
| AC-8 | Malicious, compromised, or spoofed IED | Station LAN | Attack parsers; harvest credentials the node sends. |
| AC-9 | Supply chain | Dependencies, build, update channel | Ship malicious code to every node. |
| AC-10 | Attacker already on station LAN | Station LAN | Sniff plaintext credentials; impersonate IEDs. |
| AC-11 | Vendor or contractor remote support (Phase 4) | Engineering access grant | Same as AC-3, with weaker accountability. |

## Attack paths through the platform (Q7)

**Answer to Q7, v0:** yes. The platform necessarily creates new paths into OT assets, because it holds device credentials and sits on the IED network. The design goal is that each path is closed by more than one independent control, and that each control has a falsifiable test. Status of every row is *proposed, not implemented, not verified* unless stated.

ATT&CK for ICS IDs are as listed at attack.mitre.org/techniques/ics on 2026-10-23 (note the 2026 renumbering: Default/Hardcoded Credentials are now T1694.001/.002, Unauthorized Command Message is T1692.001, Block Reporting Message is T1691.002).

| ID | Attack path | Actors | ATT&CK for ICS | Mitigation (enforcement point) | Falsifiable test |
| --- | --- | --- | --- | --- | --- |
| AP-1 | Stored IED credentials exfiltrated and reused directly against IEDs. | AC-5, AC-6, AC-1 | T0859, T1694 | Secrets only in the site-local credential store, encrypted under a node-bound key (TPM where available). Central holds references only; secrets travel admin→node encrypted to the node's public key, so central relays ciphertext. Unique per-device credentials where the device supports them. (Credential store; TB2; TB7.) | Seed a canary secret. After a full test run, search central DB dump, every API response, log, audit record, error message, and core dump: zero occurrences. Decrypt attempt on central with central's keys fails. Matches A6 V-S11 (canary credentials, zero occurrences). |
| AP-2 | Credentials leak into preserved raw evidence (login exchange captured in the device transcript kept for R4.4/R5). | AC-2, AC-7 | T0859 | Transport layer injects credentials *below* the transcript recorder; the login phase is recorded as a marker, not bytes. (Transport layer.) | Mock IED that echoes every input byte; run a collection; the canary secret appears nowhere in stored transcripts, normalized events, or forwarded Syslog. |
| AP-3 | Adapter command framework used to send non-approved commands (CR/LF or delimiter injection through parameters; free-form command field). | AC-2, AC-4, AC-6 | T1692.001, T0836 | Commands referenced by ID from a signed register; typed parameters with strict grammars (no control characters, bounded length); no API accepts a free-form command string; an independent egress check compares the rendered bytes against the register's exact pattern before the bytes leave the node. (Adapter + transport egress check.) | Fuzz every parameter with CR, LF, NUL, `;`, `\|`, ESC sequences, overlong input. A recording mock device (A6 harness) logs every received byte; pass only if every received line matches a register pattern. |
| AP-4 | Access-level escalation: the adapter holds (or can obtain) a device access level that also permits settings changes or control, so one bug becomes a write. | AC-2, AC-5, adapter bug | T0890, T0836 | Hold only the lowest device access level that supports the register operation; never store higher-level passwords in the collection plane; any access-elevation command is flagged in the register and blocked by the egress check. (Credential store policy; register; egress check; device-native levels.) Depends on A2's per-family access-level facts. | Config audit: collection-plane credential store contains no credential whose `access_level` is above the register's maximum for that family. Recording mock device: zero elevation commands observed across the full test suite. Same concern raised independently by A6 as C-12. |
| AP-5 | Read-only enforcement lives in one place and a single bug bypasses it. | Any | T0836, T0843 | Seven independent layers L1–L7 (findings file §4.3): role authorization, signed register classification, adapter rendering, transport egress allowlist, device-native least privilege, site firewall port allowlist, independent observation (IDS / recording simulator). | Mutation test: disable each layer in turn in a test build; a write attempt must still be blocked by the remaining layers, and observed by L7. |
| AP-6 | Engineering access gateway used to reach devices or services outside the authorized session (pivot). | AC-3, AC-11, AC-1 | T0884, T0886 | Per-session destination pinning to one device:port, no shell on the gateway, no reverse or dynamic (SOCKS) forwarding, time-limited grant, revocation. (Access gateway, Phase 4.) | E1 T2, T3, T4, T5 `[exp-sim]` passed: unapproved device and unapproved port refused with zero connections reaching the target; shell and reverse forward refused. Must be repeated on the chosen gateway implementation. |
| AP-7 | Compromised central instructs site nodes to touch devices (fleet-wide). | AC-6 | T0886, T1692.001 | No exec or shell channel from central `[peer A5]`. Central sends only signed policy bundles that reference register operation IDs. Each node enforces a site-local ceiling set at enrollment that central cannot raise. Policy signing key is separate from central's TLS identity and is not usable by central's online services alone. (Site node policy verifier.) | From a test "central" holding a valid mTLS cert: (a) bundle referencing an operation outside the site ceiling → rejected and alarmed; (b) bundle with bad signature → rejected; (c) any RPC outside the defined protocol → rejected. Zero bytes reach the recording mock device in all three. |
| AP-8 | Node enrollment spoofing: a rogue node enrolls, receives policy, or injects fabricated telemetry. | AC-1, AC-10 | T1692.002, T0849 | One-time enrollment token with short TTL; administrator confirms the node key fingerprint out of band; per-node certificate, revocable; central never sends IED secrets in usable form; a node may only report for assets assigned to it. (Central enrollment service.) | Reused token → rejected. Expired token → rejected. Enrolled node submits events for another node's asset → rejected and alarmed. Revoked node cert → connection refused on next connect. |
| AP-9 | Forwarding channel used inbound for lateral movement, or outbound for bulk exfiltration of OT data. | AC-7, AC-5 | T0882, T0869 | TB5 outbound only, no data accepted beyond the TLS handshake; egress firewall one direction; forwarded content excludes configurations and secrets. (Forwarder; firewall.) | From the collector side, attempt an inbound connection to the node → no listener. Send data on the established TLS session → ignored and alarmed. Inspect forwarded stream from a full run: no configuration payloads, no canary secret. |
| AP-10 | Update mechanism used to ship malicious or known-vulnerable code. | AC-9, AC-6 | T0862 | Releases signed with an offline key absent from central; signed metadata carries an anti-rollback floor `[peer A5]`; pinned dependencies and SBOM. (Node update verifier.) | Tampered package → rejected. Correctly signed package below the floor → rejected. Unsigned package → rejected. |
| AP-11 | Malicious or spoofed IED output exploits a parser, then pivots from the node. | AC-8, AC-10 | T0866 | Memory-safe implementation language; parsers are pure functions with size limits; parser process has no credential access and no write path to devices. (Adapter parsers; TB4 process separation.) | Coverage-guided fuzzing of every parser for a fixed budget with no crash or hang; oversized and malformed fixtures produce a structured error, not a partial write. |
| AP-12 | Attacker impersonates an IED on the station LAN and harvests the credentials the node sends at login. | AC-10, AC-8 | T0830, T0859 | SSH host keys pinned at commissioning with out-of-band verification (no trust-on-first-use); the node aborts before sending any credential on key mismatch. The asset identity record binds the device-reported identity (vendor, model, serial, firmware as A2 defines them) to the pinned key; a change in either, without an approved re-commissioning record, stops collection and alarms (A6 C-07). Telnet/FTP cannot authenticate the server: such devices are labelled `downstream: plaintext-unauthenticated`, use unique credentials, and the residual risk is recorded. (Transport layer; asset record.) | Mock IED presents a different host key → zero credential bytes sent, alarm raised. Telnet device appears in the asset list with its insecure label. Matches A6 V-S14 (host-key change: no credentials sent, collection stopped, event raised) and blocker B-05. |
| AP-13 | Platform itself degrades an IED (P1): over-polling, parallel sessions, failed-login lockout or alarm contacts. | Misconfiguration, AC-6 | T0814 | Per-device rate limit and a single concurrent session enforced at the node, bounded by the site-local ceiling; stop after the first authentication failure (no retry with the same credential) and alarm; hard and idle session timeouts. (Site node scheduler and transport.) | Mock IED counts sessions and login attempts. Wrong password → exactly one attempt, then alarm. Burst of scheduled jobs → never more than one concurrent session. |
| AP-14 | Administrator self-grants engineering rights, widens policy, or alters audit. | AC-4 | T0859, T0872 | Separation of duties: admin cannot hold engineering or security-auditor roles; grants of privileged roles need a second approver; audit is append-only, hash-chained, and forwarded off-host promptly. (Platform authorization; audit service.) | Admin attempts self-grant → denied and audited. Second-approver bypass attempts → denied. |
| AP-15 | Monitoring user reaches a state-changing device operation (R2.6, R5.7, V-S5). | AC-2 | T1692.001, T0836 | In slice 1 no human role can trigger device I/O at all; collection runs under a system identity from site-local schedules. Later, operation-class authorization at the API boundary; monitoring plane has no credential access. (API authorization; TB4.) | Enumerate every API operation with a monitoring token: any operation that could cause device I/O returns deny. Recording mock device shows zero writes (V-S5, V-S7). |
| AP-16 | Single-server host (T1) or misplaced node bridges the enterprise network and the station LAN. | AC-1 | T0886, T0883 | IP forwarding disabled; separate interfaces; UI/API bound only to the management interface, never the IED-facing one `[peer A5]`; host firewall default deny. Recommend T1 hosts sit in the site zone, not the enterprise network. (Host configuration; A5 deploy.) | From the management-side network, attempt to reach a station-LAN address via the host → fails. `net.ipv4.ip_forward=0` asserted at startup; startup fails closed otherwise. |
| AP-17 | Local audit deleted or edited on a compromised node to hide activity. | AC-5, AC-3 | T0872 | Per-node monotonic sequence numbers plus hash chain; prompt forwarding to central and Syslog; central alarms on gaps. (Audit service.) | Delete or edit one stored record → central detects the gap or chain break within one sync interval. |
| AP-18 | Stolen platform user credentials or session used remotely. | AC-1 | T0859, T0822 | MFA for engineering, admin, and security roles; short session lifetime; fresh re-authentication for privileged actions; revocation on logout. (TB1.) | Token replay after logout → rejected. Privileged action without fresh MFA → rejected. Expired session → rejected. |
| AP-19 | Storage exhaustion used to blind the platform (e.g. syslog flood stops SER collection). | AC-10, AC-8 | T1691.002, T0815 | Separate storage quotas for syslog and SER `[peer A5, A3 review]`; syslog drop-and-count with counters persisted and forwarded; SER polling stops with an alarm that records when collection stopped. (Site node storage manager.) | Flood syslog until its quota is full; SER collection continues; drop counter is visible centrally after a node restart. |
| AP-20 | Device output (attacker-controlled, TB10) forged into upstream events: embedded CR/LF, Syslog framing, or escape sequences split or spoof records at the SIEM. Raised independently by A6 as C-08. | AC-8, AC-10 | T1692.002, T0832 | Forward with RFC 5425 octet-counted framing (no newline framing); device-originated text placed only in escaped fields (RFC 5424 SD-PARAM escaping of `"`, `\`, `]`) with control characters encoded; the record's origin (device vs platform) is a field the device cannot set. (Forwarder, A4.) | A6 V-S15: device output containing CR/LF, a forged Syslog header, `]`, and ANSI escapes yields exactly one upstream record with the payload intact and inert. |

## Required security controls (minimum safe behaviour)

Controls for the first vertical slice. "Where" is the enforcement point; standards columns are **alignment, not certification**. IEC 62443-3-3 SR numbers are from the published SR list; we have not obtained the full normative text, so requirement-enhancement levels are not claimed. IEC 62351 part content is from public summaries and previews; the full texts have not been read.

| ID | Control | Where | IEC 62443-3-3 | IEC 62351 | Closes |
| --- | --- | --- | --- | --- | --- |
| SC-1 | Unique human identification; MFA for privileged roles; session expiry and revocation. | API gateway | SR 1.1, SR 1.13, SR 2.5, SR 2.6 | -8 (RBAC concept) | AP-18 |
| SC-2 | Role separation: monitoring, engineering, administration, security audit; plus a non-human collector identity. Privileged grants need a second approver. | Authorization service | SR 2.1 (permission mapping, dual approval) | -8 | AP-14, AP-15 |
| SC-3 | Device operations only by register ID; typed, validated parameters; no free-form command path. | Adapter framework | SR 3.5, SR 7.7 | — | AP-3 |
| SC-4 | Independent egress allowlist check on rendered bytes, fail closed. | Transport layer | SR 3.5, SR 3.6 | — | AP-3, AP-4, AP-5 |
| SC-5 | Credential store: site-local, encrypted at rest, write-only from admin, resolved only inside the transport at connect time. | Credential store | SR 1.5, SR 4.1, SR 4.3 | -9 (key management, alignment only) | AP-1, AP-2 |
| SC-6 | Least device access level per operation; no elevation commands reachable. | Register + credential policy | SR 2.1 | -8 | AP-4 |
| SC-7 | Downstream transport security label on every device (`encrypted-authenticated`, `encrypted-weak`, `plaintext-unauthenticated`), shown to users and recorded in audit; plaintext accepted only by explicit per-device admin acknowledgement. | Asset record; transport | SR 1.13, SR 3.1, SR 4.1 | -3, -4 | AP-12, R2.3 |
| SC-8 | SSH host-key and TLS certificate pinning at commissioning; no TOFU. | Transport | SR 1.2, SR 3.1 | -3 | AP-12 |
| SC-9 | Device-safety limits: one session per device, rate limit, stop on first auth failure, timeouts. | Scheduler + transport | SR 7.1, SR 7.2 | — | AP-13 |
| SC-10 | Site-initiated mTLS; no inbound WAN listener; no exec channel; signed policy bundles bounded by a site-local ceiling. | Site node | SR 1.2, SR 3.1, SR 5.1, SR 5.2 | -3 | AP-7, AP-8 |
| SC-11 | Enrollment with one-time token and out-of-band fingerprint; revocable node certificates. | Central enrollment | SR 1.2, SR 1.8, SR 1.9 | -9 | AP-8 |
| SC-12 | Audit: required fields (findings §4.4), append-only, hash chain, sequence numbers, prompt off-host forwarding. | Audit service | SR 2.8, SR 2.9, SR 2.10, SR 2.11, SR 3.9, SR 6.1 | -14 (security event logging, alignment only) | AP-14, AP-17 |
| SC-13 | Signed updates with offline key and anti-rollback floor. | Node updater | SR 3.4 | — | AP-10 |
| SC-14 | Memory-safe parsers; parser process without credentials; fuzzing in CI. | Adapter parsers | SR 3.5, SR 3.7 | — | AP-11 |
| SC-15 | Host hardening for any host with an IED-facing interface: no forwarding, separate NICs, UI bound to management NIC only. | Host / deploy | SR 5.1, SR 5.2, SR 7.6, SR 7.7 | — | AP-16 |
| SC-16 | Outbound-only forwarding with pinned collector identity; no secrets or configurations forwarded; octet-counted framing and escaping of device-originated text. | Forwarder | SR 5.2, SR 4.1, SR 3.5 | -3 | AP-9, AP-20 |
| SC-17 | Separate storage quotas per data class; observable drops; fail-observable telemetry. | Storage manager | SR 2.10, SR 7.2 | — | AP-19 |
| SC-18 | Privileged paths fail closed: unverifiable policy, locked credential store, or failed egress check → no device I/O, alarm. | Site node | SR 3.6, SR 3.7 | — | P5 |

NIST SP 800-82r3 alignment (general, section numbers not cited because not re-verified): defense-in-depth OT architecture with DMZs, controlled remote access through intermediate systems, least privilege, and monitoring of remote sessions, which SC-2, SC-7, SC-10, SC-15, and the Q1 recommendation follow.

## Standards mapping

The SR and IEC 62351 columns above are the mapping table for v0. ATT&CK for ICS technique IDs are in the attack-path table. A fuller mapping (requirement-enhancement levels, IEC 62443-4-2 component requirements for the site node) needs the normative texts and is deferred to Phase 1.

## Unresolved high-risk concerns

Tracked until resolved by an ADR or verified mitigation. Security and safety objections cannot be dismissed by majority agreement.

| ID | Concern | Raised by | Status |
| --- | --- | --- | --- |
| HR-1 | For plaintext, shared-password IEDs, compromise of one site node yields device access at that level for every device sharing the password. The platform cannot fix this; it can only label it (SC-7), use unique credentials where the device allows, and keep the node hardened. | A3; A6 blocker B-04 (credential storage on site node) | open; size depends on A2's primary family |
| HR-2 | If the device access level needed to read SER also permits settings changes or control, the device cannot enforce read-only for us and layers L1–L4, L6, L7 are the only barrier. | A3 | open; needs A2 access-level facts |
| HR-3 | Evidence preservation (R4.4, R5.6) and credential secrecy conflict inside raw transcripts. Proposed resolution AP-2 (inject below recorder) must be verified, and A4/A6 must accept that the login phase is not byte-exact evidence. | A3 | open; needs A4 and A6 agreement |
| HR-4 | Arbitrary vendor engineering tools cannot be shown safe by transparent proxying: TCP forwarding pins destinations but cannot constrain operations (E1 T6 `[exp-sim]`), and the IED sees only the gateway address (E1 T7), so per-user attribution at the device is lost. | A3 | open; Phase 4, see Q1 |
| HR-5 | Automated IED password rotation (as offered by commercial gateways such as SEL-3620 `[doc]`) is itself a state-changing device operation. R8.5 "credential rotation" must be read as platform credentials and certificates; IED credential rotation belongs to the engineering plane and is out of slice 1. | A3 | open; needs A1 to clarify R8.5 |
| HR-6 | Nothing in this model is hardware-verified. All device-side controls (L5, AP-4, AP-12, AP-13) are `[doc]` or `[inferred]`. | A3 | open until a lab IED exists |
| HR-7 | ABB 615 documents a relay-generated self-signed certificate with a 1024-bit RSA key and TLS 1.0–1.2 for its secure mode (1MRS758280 rev C, §3.4.1) `[doc]`. "Encrypted" downstream links may still be weak; SC-7 must distinguish `encrypted-weak`. | A3 | open; per-family classification by A2 |
