# Requirements

Source: the project brief in [CLAUDE.md](../CLAUDE.md), sections 1 and 2, as amended by the owner's scope change of 2026-10-23 (device classes and SEL-first vendor strategy, [ADR-0006](decisions/ADR-0006-device-coverage-and-vendor-strategy.md)) and the owner's clarification of 2026-10-26 (monitoring goals and the collection-method order, [ADR-0008](decisions/ADR-0008-monitoring-goals-and-collection-method-order.md)). This document restates the requirements in a form that can be traced to acceptance criteria in [verification.md](verification.md). Requirement IDs are stable; do not renumber.

Status legend for each requirement: `not started` | `investigating` | `contracted` | `implemented` | `verified`.

How to read the Status and Basis columns (D4-81). D1 brought them in line with the accepted gates on 2026-11-10, from the exit reports (`docs/phase-0-exit.md` to `docs/phase-4-item3-exit.md`), with `main` at `d507a62c`.

- **Status** is the furthest state the requirement has reached for at least one device family, at a gate the owner accepted. Phase 4 item 4 is not at a gate, so its work counts no higher than `contracted`.
- `investigating`: feasibility work or a design exists, beyond the acceptance criterion in [verification.md](verification.md).
- `contracted`: an approved contract covers it, and the product does not yet do it end to end.
- `implemented`: product code on `main` does it, in full or in the part Basis names, and D6's independent test of it ran at unit level only, passed for part of the criterion only, was not run, or is not recorded in an exit report.
- `verified`: D6's independent test of it passed end to end on the real binaries, and an accepted exit report records the pass. The test is the criterion that the verification matrix names for the requirement. A part that was not run may be an extension of that criterion (more fixtures, another transport, a soak, hardware), never its defining check, and Basis names it. The verification matrix gives such a row `e2e` in its own Status column, and a row that is not `e2e` there is not `verified` here (D4-82). In older records D6 is A6, B6 or C6.
- **`verified` never means hardware-verified.** No device has been contacted (B-01). Every result is `desk` or `simulated`, and no device family may be called supported. The HW column of the verification matrix says which criteria cannot close without equipment.
- **Basis** gives the evidence class, the scope, what is still owed, and the record.

## R1 — OT asset management and monitoring

| ID | Requirement | Status | Basis |
| --- | --- | --- | --- |
| R1.1 | Discover and inventory OT assets using passive observation and explicitly approved read-only methods. | contracted | Assets are entered by the operator under C1 0.3 (item 3 exit). No discovery exists, and passive observation waits for the sensor (item 4). Identity reads use register-approved read operations only (R1.2). R1.1's capture of a discovery run is not run. |
| R1.2 | Identify devices: manufacturer, model, firmware, communication interfaces, and other supported attributes. | implemented | V-M1 (e) compares model, firmware ID and version, hostname and engine ID with GT-MIB for the SEL-2731/2741 on the real binaries (`simulated`; item 3 exit), and some of GT-MIB's values are synthesized. No end-to-end run compares a serial number or a manufacturer for any family, and the criterion names both (D6's matrix, `e2e-part`). For the SEL-751, V-S1's end-to-end tests check the FID gate, not the reported attributes, and its field-by-field comparison with GT-HAND is not run (Phase 2 exit). V-M1 (f) reads the SEL-751's model as `SEL-751` over Telnet (item 3 exit). No comparison with a nameplate: H-01 and H-17 are not run. |
| R1.3 | Monitor connectivity, health, and communication behavior where observable. | implemented | An unreachable device, a failed login, a timeout and a hung read each show in `otsec health`, and six of the seven injected faults show within 60 s of the failing run (V-S12, `simulated` in part; Phase 2 exit and verification.md's Phase 2 slice status). Recovery timing is not recorded as run. Communication behaviour waits for item 4. |
| R1.4 | Correlate network activity, configurations, security events, and access sessions to assets. | implemented | Events, configuration snapshots, identity reads and findings carry their asset. An unknown Syslog sender is kept and alarmed, not attributed (Phase 3 exit). R1.4's two-device test is not recorded as run. Network activity (item 4) and access sessions (item 5) are not built. |
| R1.5 | Track identification confidence, evidence sources, and detection limitations. | implemented | C1 0.3 records each identity attribute with its source, a device read or an operator entry. V-M1 (e) checks the OID and the source of each attribute read on the real binaries (`simulated`), and D6's C1 0.3 contract tests are in the item 3 gate (item 3 exit). A plaintext Syslog listener never raises binding confidence (HR-12; Phase 3 exit). No exit report says that an attribute with no source is refused, which is R1.5's criterion. |
| R1.6 | Cover all OT device classes: protective relays and other IEDs; RTUs, automation controllers, and communications processors; Ethernet switches; routers, security gateways, and firewalls; time servers and satellite clocks; servers and computers; engineering workstations and HMIs; historians; meters; port servers and serial communications equipment. Each asset records its device class. (Added 2026-10-23, owner scope change, ADR-0006.) | implemented | Each asset records its device class (C1, a required attribute). Vendor-neutral coverage is received Syslog (Phase 3 exit) and operator-entered identity (item 3 exit). Device reads exist for the SEL-751 and the SEL-2731/2741 only. Windows host events and passive observation are not built. |
| R1.7 | Vendor-specific support is built for SEL products first, family by family, until the owner declares SEL coverage complete; other vendors follow. Non-SEL devices are covered by vendor-neutral mechanisms only (passive observation, received Syslog, Windows host events, operator-entered data) until then. "Supported" means an SEL family whose capabilities can meet the project requirements, assessed per family. (Added 2026-10-23, ADR-0006.) | implemented | A standing rule, and the work follows it: device-specific code exists for two SEL families only, the SEL-751 over Telnet and the SEL-2731/2741 over SNMPv3. No family is supported, because nothing is hardware-verified (B-01). |
| R1.8 | Asset monitoring and management is a separate module (`modules/asset/`), independently enabled and disabled. Its primary read path is SNMPv3 (authenticated and encrypted) wherever the device offers it; where it does not (for example SEL protective relays, which have no SNMP agent), identity and health come from another registered read-only path or from passive observation. SNMPv1 and v2c are read-only fallbacks only, each needing the owner's per-device approval because they are unauthenticated. (Added 2026-10-26, owner clarification, ADR-0008.) | verified | `simulated`, on Linux CI only. V-M1 (a) to (f) over GT-MIB on the real binaries: the asset module on and off, SNMPv3 `authPriv` only, and no v1 or v2c path (HR-17) (item 3 exit). No SNMPv3 device is contacted until H-17 runs with the owner's approval. |

Scope note (ADR-0006): R3, R4, and R5 apply to every device class in R1.6, not only IEDs, wherever a safe read-only mechanism exists (for example switch and gateway configurations, clock status, Windows event logs). "IED" in R3–R5 is read as "device" for those classes. Active queries to any class follow R5.3 and R5.7.

## R2 — Secure engineering and remote access

| ID | Requirement | Status | Basis |
| --- | --- | --- | --- |
| R2.1 | Controlled, proxied access to OT assets and engineering environments (SSH/terminal, RDP and remote workstations, vendor applications, native engineering protocols, controlled TCP forwarding or application gateways). | investigating | The Q1 comparison of proxying, remote workstations and gateways, and experiment E1 (Phase 0 exit). No decision for any access method. Phase 4 item 5 is not briefed. |
| R2.2 | Strong upstream authentication and authorization. | not started | Item 5 is not briefed. Admin-signed requests to the collector (C7 0.5; Phase 3 exit) are the only independently authenticated operator path so far. |
| R2.3 | Downstream security using IED-native capabilities when supported; clear identification of insecure downstream connections. | not started | Item 5 is not briefed. The slice's Telnet collection path is labelled insecure (ADR-0005), and that is collection, not an engineering session. |
| R2.4 | Per-user, per-device, and per-operation permissions. | implemented | In part. C7 gives roles and per-key allowed kinds for requests to the collector, with an approver role (D4-2): a non-approver's approval is refused on the real binaries (V-M2, F-022, `simulated`; Phase 4a exit), and the admin relay's end-to-end check passed 18 of 18 (Phase 3 exit). No user accounts exist, and no user, device and operation matrix. Item 5 is not briefed. |
| R2.5 | Session auditing, termination, expiration, and revocation. | investigating | Experiment E1 showed that ending a session does not revoke access (C-15 in verification.md; the Phase 0 exit records that termination was confused with revocation). No engineering session exists. Item 5 is not briefed. |
| R2.6 | Separation between monitoring privileges and privileged engineering operations. | implemented | The node holds no device transport and no credential code (D2-1, enforced by test), and V-S7's deny corpus finds no write form approved in a signed register. V-S5 passes in unit tests only (Phase 2 exit). No privileged engineering operation exists yet (item 5). |
| R2.7 | No unnecessary direct external access to IEDs. | implemented | Only the collector opens device sessions (D2-1; Phase 2 exit), and no service forwards traffic to a device. V-S18 is not run, because no central role exists. R2.7's port inventory is not recorded as run. |

Constraint: do not assume arbitrary engineering software can be transparently proxied. Protocol-level proxying must be compared with running engineering software on controlled remote workstations (see architecture-critical question Q1 in [architecture.md](architecture.md)).

## R3 — IED configuration and baseline monitoring

| ID | Requirement | Status | Basis |
| --- | --- | --- | --- |
| R3.1 | Retrieve supported IED configurations and settings. | implemented | The SEL-751's settings are read by the signed register's run `sel.config.read_all` over Telnet, end to end on the real binaries (`simulated`; V-M2, V-M3; Phase 4a exit). The simulator's replies are synthesized, and that retrieval sees a real change is an unverified assumption there. R3.1's comparison with the vendor tool needs a lab relay. |
| R3.2 | Maintain authenticated, versioned configuration baselines. | implemented | C9 snapshots are versioned, and a baseline is recorded and acknowledged in the audit chain (C7 0.6, C8 0.8; Phase 4a exit). R3.2's tamper test of a stored baseline is not recorded as run. On a pruned view the configuration fold trusts the store's holds (a limitation in the Phase 4a exit). |
| R3.3 | Detect meaningful operational differences; distinguish real changes from formatting, timestamps, and other non-semantic differences. | verified | `simulated`. V-M2's 21 labelled changes include three non-semantic ones, all of one kind, a `SHO` layout change, and they give no difference record (D4-46, F-022; Phase 4a exit). No reordering or timestamp case exists. The settings are synthesized, so R3.3's labelled set of real files is still owed. |
| R3.4 | Identify unexpected modifications and correlate detected changes with authorized maintenance. | verified | `simulated`, SEL-751 only. V-M2: an alarm for exactly the 15 changes with no valid prior approval, and none for the 3 approved changes, which link their approval (Phase 4a exit). |
| R3.5 | Preserve original configurations and evidence of changes. | implemented | Both snapshots of a read are stored, and the evidence an alarm cites is held from pruning (C5 0.4, D4-19, D4-46). `check.py` finds only read-only register lines in the V-M2 recordings (V-S7). `config.reads_removed` is contract only. That retrieval sees a real change is unverified (Phase 4a exit). |
| R3.6 | Prior approval. A change approval (device, time window, reason, approver) is recorded in the audit chain before the change is made. A retrieved configuration that differs from the baseline with no matching open approval raises an alarm; the difference is kept as evidence either way. An approval silences the alarm, never the record. (Added 2026-10-26, ADR-0008.) | verified | `simulated`, SEL-751 only. V-M2 on the real binaries: all 21 changes, 169 of 169 checks, and deleting or editing an approval fails audit-chain verification (F-022; Phase 4a exit). |
| R3.7 | Retrieval method order, chosen per device family from the capability matrix: (1) an authenticated, encrypted file transfer (SFTP, SCP, HTTPS download); (2) plain FTP only where the family offers nothing better, for read-only use, after A3's review of the credential exposure and the owner's acceptance for that family; (3) command-line parsing (Telnet, SSH or serial) only when no file path exists. (Added 2026-10-26, ADR-0008.) | verified | `desk` and `simulated`, for the SEL-751 only: V-M3 is met with conditions (Phase 4a exit). Rung 3, the command line, is its only built rung: rung 1 is absent, and rung 2 (FTP) waits for hardware test Q3. So the lower-rung refusal is vacuous (D4-40), and no test has exercised a choice between rungs. Each SEL family's rung is in the capability matrix (Phase 3 exit). |

Constraint: read-only by default. Never automatically restore or push settings.

## R4 — Syslog and Sequence of Events (SER) collection

| ID | Requirement | Status | Basis |
| --- | --- | --- | --- |
| R4.1 | Receive device-generated Syslog. | implemented | On the real binaries, the RFC 5425 TLS and RFC 5426 UDP listeners store each message byte for byte, a 3164-style message, invalid UTF-8 and NUL included, and an unknown sender is kept and alarmed (`simulated`; Phase 3 exit). A malformed message is stored raw and flagged in-process only, over the RFC 6587 TCP listener (`tests/integration/syslogreceive/`): no run on the real binaries sends a framing fault, and R4.1's criterion names that case (D6's matrix, `e2e-part`). No device has sent to the platform, and the per-family layouts rest on documented examples. |
| R4.2 | Retrieve IED SER records using supported interfaces. | verified | `simulated`. The SEL-751's `SER` over Telnet, end to end on the real binaries: V-S2 against one documented example and V-S6 (Phase 2 exit), and V-M4's SER half, 1,105 rows stored once and in order (Phase 4a exit). R4.2's reconciliation with a device's own SER display needs a lab relay. |
| R4.3 | Normalize events into a consistent internal schema. | verified | `simulated`. C4 events from SER (V-S2, against one documented example of the three it asks for; Phase 2 exit) and from received Syslog (Phase 3 exit). |
| R4.4 | Preserve native event records and timestamp precision. | verified | `simulated`. V-S3: native time text is kept and no offset is invented (Phase 2 exit). V-S8: every stored capture, record and forwarded message matches the bytes the simulator sent (Phase 3 exit). Timestamps across time-source loss and DST wait for H-10. |
| R4.5 | Correlate events with known assets. | implemented | SER events carry the asset they were read from, and a Syslog sender is correlated to a C1 asset or kept as unknown (Phase 3 exit). R1.4's two-device test is not recorded as run. |
| R4.6 | Forward events to upstream Syslog collectors. | implemented | RELP over TLS with a durable acknowledgement, end to end to D6's own test receiver, where D6's parser reads every forwarded message as RFC 5424 (V-S6, `simulated`; Phase 2 exit). R4.6's check needs a receiver that is not project code, and the real node has never forwarded to one: the forwarder meets a stock rsyslog in package tests only (D6's matrix, `e2e-part`). RELP is the only transport built. |
| R4.7 | Handle buffering, retransmission, duplication, reconnection, and storage limits. | implemented | V-S4 (duplicates and gaps) passes on the real binaries. V-S6 (100 seeded interruptions, all 240 rows delivered once) and V-S9 (a full store, then recovery with no operator) pass with D6's own receiver as the upstream (`simulated`; Phase 2 exit). Both name a receiver that is not project code as their ground truth, and no run used one (D6's matrix, `e2e-part`). Not run: a link cut in the middle of a SER read, and file-system exhaustion. Residual SER loss with repeated keys remains (D1-17). |
| R4.8 | Event-behaviour baseline. For each asset, after an observation period, the platform compares Syslog and SER events with the learnt baseline and raises an alarm on a departure: repeated alarms, an event type not in the baseline, events at an unexpected rate or time, or the absence of an expected periodic event. Rules are deterministic or explainable statistics; every alarm shows the baseline value and the observation that broke it. No machine learning until a measured benefit exists. (Added 2026-10-26, ADR-0008.) | verified | `simulated`. V-M4 on the real binaries, Syslog and SER halves: every departure kind has at least 3 detected departures, and the held-out series raises none (F-019 to F-024; Phase 4a exit). The real false-positive rate needs a device's history. |
| R4.9 | Event retrieval method order, per device family: (1) device-generated Syslog received by the platform; (2) a file fetch of the device's log or SER files, by the transfer order of R3.7; (3) command-line SER parsing. (Added 2026-10-26, ADR-0008.) | implemented | Each SEL family's event rung is in the capability matrix (12 of 12 checked cells match their citations; Phase 3 exit). The built event paths are received Syslog and command-line SER, and no file fetch exists. No exit report records V-M5 as run. |

Constraint: never silently discard important native event information.

## R5 — Custom IED command and integration framework

| ID | Requirement | Status | Basis |
| --- | --- | --- | --- |
| R5.1 | Extensible device adapter system for collection when standard interfaces are unavailable (e.g. SSH to an IED, run an approved command to retrieve SER records, parse and normalize). | implemented | The C2 adapter contract, the SEL-751 Telnet adapter, and the SNMPv3 client for the SEL-2731/2741. Adding SNMP took C2 0.7 and 0.8, both additive (item 3 exit). R5.1's review of the diff scope at the second family is not recorded. |
| R5.2 | Vendor- and firmware-specific implementations with versioned capability definitions. | implemented | The signed C3 register carries each family's content revision (SEL-751 revision 5) and is found by firmware allowlist (D4-55), and each adapter has an ID and a version (item 3 exit). R5.2's typed "unsupported" result is not recorded as tested in an exit report. |
| R5.3 | Approved commands with validated parameters; explicit read-only or state-changing classification. | implemented | The matrix's criterion is V-S10, and its hostile parameters reach the collector in unit tests only (`desk`; Phase 2 exit). On the real binaries, every line the simulator received in the slice, V-M2, V-M7 and V-M8 recordings is a read-only line of the signed register (V-S7, `simulated`). That shows what valid requests sent, not that an invalid parameter is refused. The deny corpus refuses 699 variants, and the egress corpus every SNMP write form (Phase 4a and item 3 exits). The classification on real firmware waits for H-16. |
| R5.4 | Safe timeouts, retry behavior, and rate limits. | verified | `simulated`. V-S13: one session per device, at most one password per session, `QUI` last, and the failed-auth floor kept after a kill; a timeout and a hung read show in health (V-S12) (Phase 2 exit). C3 0.3 limits and the 60 s SER read floor (D4-47; Phase 4a exit). Not run: the floor's full 31 minutes, and the device limits (H-03 to H-05). |
| R5.5 | Handling of prompts, pagination, errors, and connection failures. | implemented | A late device, a hung SER read and a malformed row each end with a named code (V-S12; Phase 2 exit), and a damaged row's bytes are kept (V-S8; Phase 3 exit). V-S15's hostile framing end to end on the SER path is carried, not run (item 3 exit). |
| R5.6 | Deterministic parser tests using real or sanitized device outputs. | implemented | Parser tests are deterministic and run on documented examples transcribed from the manuals. No real or sanitized device output exists, so R5.6's three outputs for each command are not met (B-01). |
| R5.7 | No unrestricted CLI execution through normal monitoring permissions. | implemented | V-S5 and V-S10 pass in unit tests only (`desk`), because the node builds only valid requests, so a hostile request reaches the collector only there (Phase 2 exit). V-S7's recordings show that only signed register lines reach the simulator (`simulated`). |

## R6 — Intrusion detection and network anomaly detection

| ID | Requirement | Status | Basis |
| --- | --- | --- | --- |
| R6.1 | Passive network traffic monitoring with OT protocol identification and analysis. | contracted | Item 4 is in progress and not at a gate. C13 `otsec.netobs/0.1`, C4 0.3, C5 0.9 and C2 0.9 are approved (D4-68, D4-69), and the node side is merged (D4-70 to D4-76). No sensor exists, and nothing captures traffic (ADR-0009 is `proposed`). Zeek and Suricata were evaluated for protocol coverage only (Phase 2 exit). |
| R6.2 | Network communication baselining. | contracted | As R6.1. The network baseline's acknowledgement is in C7 0.10 and C8 0.12. |
| R6.3 | Detection of unauthorized engineering communication and unusual device or protocol behavior. | contracted | As R6.1. The node's detector consumer and its own-session detector are merged (D4-73, D4-75). No labelled capture has been run. |
| R6.4 | Rule-based and behavioral anomaly detection. | contracted | As R6.1. Deterministic rules only. No detection rate, false-positive rate or latency is measured. |
| R6.5 | Explainable security alerts with supporting packet/event evidence. | contracted | As R6.1. Alert retention and the two network store classes are merged (D4-71). |
| R6.6 | Documented network visibility limitations (PRP topology, encrypted communication, unsupported protocols, sensor placement). | investigating | Phase 0's Q4 visibility limits, and ADR-0009's sensor options. The owner's answers on the sites' protocols, SPAN or TAP, and PRP are owed (D4-66). No measured visibility statement exists. |
| R6.7 | Passive identification, per asset, of exposed services, protocol versions and insecure protocols in use, recorded as evidence for R9. (Added 2026-10-26, ADR-0008.) | contracted | As R6.1. D6 runs V-M6 over GT-PCAP after the sensor is built. The additions to the insecure list wait for the owner (D4-68). |

Constraints: evaluate Zeek and Suricata before developing proprietary detection. Deterministic rules and explainable statistical baselines first; machine learning only after measured benefit.

## R7 — Modular and additive architecture

| ID | Requirement | Status | Basis |
| --- | --- | --- | --- |
| R7.1 | Modules independently developed, tested, enabled, disabled, upgraded, and maintained. | implemented | The asset and applicability modules each switch on and off, in the three supported combinations (V-M1 (a), `simulated`; D4-50; item 3 exit). The modules ship in one node binary, so upgrading one alone is not shown. R7.1's check of every module is not recorded in an exit report. |
| R7.2 | Stable interfaces for: assets and device identities; IED adapters; event collection and normalization; configuration monitoring; remote access; network sensors and IDS; authentication and authorization; audit records; inter-module messaging. | implemented | C1 to C12 are versioned, every change so far was additive with a reader for the previous minor, and each version has D6's contract tests (Phase 1 to item 3 exits). C13 follows in item 4 (D4-68). No remote-access contract exists. R7.2's static check is recorded for D2-1's import rule only. |

Constraint: no microservices by default. Compare a modular monolith with deployable edge components against alternatives.

## R8 — Centralized and distributed deployment

| ID | Requirement | Status | Basis |
| --- | --- | --- | --- |
| R8.1 | Single-server deployment. | verified | `simulated`. The installer puts both services under the SCM, and the slice passed against the installed services on the owner's PC (159 passed, with the 27 stated skips, on Windows 11 Pro). The same suite passed with the same counts on the hosted Windows runner, on the dry-run branch before #179 merged (Phase 3 exit, gate item 1). Not the site image, and not LTSC 2021. |
| R8.2 | Central management server with remote collection nodes. | investigating | The outline of site-to-central transport and enrollment (Phase 0 exit). No central role exists, and V-S18 is not run. Phase 4 item 6 is not briefed. |
| R8.3 | Distributed deployment with site-local services. | investigating | As R8.2. The single-site node is the only deployment built. |
| R8.4 | Intermittent WAN connectivity and independent site operation. | implemented | The node goes on collecting and storing with its upstream collector down, and delivers after the reconnection (V-S6, V-S9, `simulated`; Phase 2 exit). No central link exists, and R8.3's 72-hour partition is not run. |
| R8.5 | Secure node enrollment; certificates and credential rotation. | investigating | Parts only: the node key register and the non-exportable CNG key store (Software KSP, on the hosted Windows runner; Phase 3 exit), which the node reads its TLS keys from since #176 (Phase 4a exit). No enrollment, no central role, and no rotation shown. The TPM provider is untested (T-2). |
| R8.6 | Local storage and forwarding; reliable message handling. | implemented | V-S6: 100 seeded interruptions with the receiver and the node killed, and every row reaches D6's own receiver under one event ID (`simulated`; Phase 2 exit). V-S6's ground truth is a receiver that is not project code, and no run used one (D6's matrix, `e2e-part`). Power loss waits for H-11. |
| R8.7 | Service restarts and crash recovery; node upgrades and rollback; version compatibility. | implemented | Restart and crash recovery pass V-S6 and V-S9 under SIGKILL (`simulated`; Phase 2 exit), and every contract minor keeps a reader for the one before. Node upgrade and rollback are not built (D4-79), and some rollbacks fail closed (Phase 3 and Phase 4a exits). |
| R8.8 | Storage exhaustion and controlled failure behavior. | implemented | V-S9: a warning before runs stop, no session while the store is full, and recovery with no operator (`simulated`; Phase 2 exit). That nothing unforwarded was evicted is shown only at D6's own receiver: the test does not read the store, and no receiver that is not project code was used (D6's matrix, `e2e-part`). The limit tested is the quota, not the disk: file-system exhaustion is not run (F-013). |

Constraint: failure of the cybersecurity platform must not compromise protection or control functions.

Clarification of R8.5 (A1 ruling, 2026-10-23, on A3 HR-5): "credential rotation" means credentials and certificates the platform owns (node certificates, enrollment keys, platform service accounts, upstream collector credentials). Rotating a password or key stored on an IED is a state-changing device operation; it belongs to privileged engineering access (R2) and is outside the first slice.

## R9 — Vulnerability applicability (added 2026-10-26, owner clarification, ADR-0008)

| ID | Requirement | Status | Basis |
| --- | --- | --- | --- |
| R9.1 | Match each asset's collected identity (vendor, model, firmware, enabled services, settings posture where read) against a curated, versioned set of published advisories (vendor security advisories, CVE records) and report the applicable ones with the evidence that made each applicable. | verified | `simulated`. V-M7: all 128 GT-ADV cells on the real binaries, for the SEL-751 path (item 3 exit). Every advisory, set and key is a test one, and no real advisory is entered until HR-18 is decided. |
| R9.2 | Classify every finding as `applicable-by-version`, `confirmed` (only with evidence read from the device), `mitigated` (a documented setting or network control, with evidence) or `not-applicable`. Never state exploitability without evidence. | verified | `simulated`. V-M7: operator rows and denied-branch rows are never `confirmed` (F1), and the control cells pass with a recorded control (D4-56) (item 3 exit). |
| R9.3 | The advisory set is updated offline from a signed, versioned file; a site node never reaches the internet for it. Every report carries the set's version and date, and every entry cites its source. | verified | `simulated`. V-M8's set cases: the file passes 18 of 18, of which 17 are V-M8's and one is V-S7's. Ten bad files are refused and recorded, and the version floor and a revoked key hold (item 3 exit). A release build's refusal of a test set is shown at Go level only (`desk`). |
| R9.4 | No active vulnerability scanning of production devices (P1). Applicability comes from collected identity and passive observation only. | verified | `simulated`. V-M8's paired runs, 9 of 9, or 12 with V-S7's three checks in the same file: no run has a flow the baseline run lacks, and nothing is routed off the host (item 3 exit). |

Constraint: an advisory entry that cannot be traced to a published source is not entered (P10).

## Mandatory engineering principles

These apply to every requirement above and are restated here for traceability.

| ID | Principle |
| --- | --- |
| P1 | OT safety comes first. No unapproved active scanning or potentially disruptive operations on production equipment. |
| P2 | Read-only monitoring by default. Privileged engineering operations must be separately authorized. |
| P3 | Evidence before assumptions. Distinguish actual hardware verification from simulation, documentation, and inference. |
| P4 | Least privilege and defense in depth. Separate monitoring, engineering, administration, and security permissions. |
| P5 | Secure failure behavior. Privileged access fails closed. Telemetry failures remain observable. |
| P6 | Deterministic verification. Reproducible tests and known ground truth over subjective judgments. |
| P7 | Interoperability must be proven. No claims of universal vendor support. |
| P8 | Architecture must justify complexity. |
| P9 | Maintainability: readable, modular, testable, supportable code. |
| P10 | No fabricated validation. Never claim hardware testing, security verification, or protocol compatibility without evidence. |

Applicable standards for alignment (not certification claims): IEC 62443, IEC 62351, NIST SP 800-82, MITRE ATT&CK for ICS.

## Owner answers (2026-10-23)

- Site computer: SEL-3355-2 with Windows 10 Pro or Windows 11 Pro IoT LTSC (ADR-0007).
- WAN: outages are not tolerated; sites have N-1 redundancy. R8 store-and-forward stays as fault handling.
- Central access: the central HMI server may reach relays; central cybersecurity servers may not. The platform's central role never connects to devices.
- Upstream Syslog: assume any standards-compliant collector and support all types (ADR-0004 amendment).
- HMI and historian software: COPA-DATA zenon HMI Energy Edition on Windows (non-SEL; Windows events by host push, ADR-0006).
- SEL-3530 is discontinued; the SEL-3350 replaces it.

## Owner clarification (2026-10-26)

Recorded in [ADR-0008](decisions/ADR-0008-monitoring-goals-and-collection-method-order.md):

- Configuration monitoring means: unchanged unless approved in advance; an unknown change is an alarm (R3.6).
- Event monitoring means: a per-device behaviour baseline learnt over an observation period, with alarms on departures (R4.8).
- IDS keeps its network baseline, anomaly and vulnerability detection (R6), and feeds R9.
- Vulnerability applicability per device from every read path (R9).
- Collection-method order per device family: Syslog, then secure file fetch (FTP only where nothing better exists), then command-line parsing; the same order for configuration retrieval (R3.7, R4.9).
- Asset monitoring and management is a separate module, SNMPv3 first (R1.8).
