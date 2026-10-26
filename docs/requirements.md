# Requirements

Source: the project brief in [CLAUDE.md](../CLAUDE.md), sections 1 and 2, as amended by the owner's scope change of 2026-10-23 (device classes and SEL-first vendor strategy, [ADR-0006](decisions/ADR-0006-device-coverage-and-vendor-strategy.md)) and the owner's clarification of 2026-10-26 (monitoring goals and the collection-method order, [ADR-0008](decisions/ADR-0008-monitoring-goals-and-collection-method-order.md)). This document restates the requirements in a form that can be traced to acceptance criteria in [verification.md](verification.md). Requirement IDs are stable; do not renumber.

Status legend for each requirement: `not started` | `investigating` | `contracted` | `implemented` | `verified`.

## R1 — OT asset management and monitoring

| ID | Requirement | Status |
| --- | --- | --- |
| R1.1 | Discover and inventory OT assets using passive observation and explicitly approved read-only methods. | not started |
| R1.2 | Identify devices: manufacturer, model, firmware, communication interfaces, and other supported attributes. | not started |
| R1.3 | Monitor connectivity, health, and communication behavior where observable. | not started |
| R1.4 | Correlate network activity, configurations, security events, and access sessions to assets. | not started |
| R1.5 | Track identification confidence, evidence sources, and detection limitations. | not started |
| R1.6 | Cover all OT device classes: protective relays and other IEDs; RTUs, automation controllers, and communications processors; Ethernet switches; routers, security gateways, and firewalls; time servers and satellite clocks; servers and computers; engineering workstations and HMIs; historians; meters; port servers and serial communications equipment. Each asset records its device class. (Added 2026-10-23, owner scope change, ADR-0006.) | not started |
| R1.7 | Vendor-specific support is built for SEL products first, family by family, until the owner declares SEL coverage complete; other vendors follow. Non-SEL devices are covered by vendor-neutral mechanisms only (passive observation, received Syslog, Windows host events, operator-entered data) until then. "Supported" means an SEL family whose capabilities can meet the project requirements, assessed per family. (Added 2026-10-23, ADR-0006.) | not started |
| R1.8 | Asset monitoring and management is a separate module (`modules/asset/`), independently enabled and disabled. Its primary read path is SNMPv3 (authenticated and encrypted) wherever the device offers it; where it does not (for example SEL protective relays, which have no SNMP agent), identity and health come from another registered read-only path or from passive observation. SNMPv1 and v2c are read-only fallbacks only, each needing the owner's per-device approval because they are unauthenticated. (Added 2026-10-26, owner clarification, ADR-0008.) | not started |

Scope note (ADR-0006): R3, R4, and R5 apply to every device class in R1.6, not only IEDs, wherever a safe read-only mechanism exists (for example switch and gateway configurations, clock status, Windows event logs). "IED" in R3–R5 is read as "device" for those classes. Active queries to any class follow R5.3 and R5.7.

## R2 — Secure engineering and remote access

| ID | Requirement | Status |
| --- | --- | --- |
| R2.1 | Controlled, proxied access to OT assets and engineering environments (SSH/terminal, RDP and remote workstations, vendor applications, native engineering protocols, controlled TCP forwarding or application gateways). | not started |
| R2.2 | Strong upstream authentication and authorization. | not started |
| R2.3 | Downstream security using IED-native capabilities when supported; clear identification of insecure downstream connections. | not started |
| R2.4 | Per-user, per-device, and per-operation permissions. | not started |
| R2.5 | Session auditing, termination, expiration, and revocation. | not started |
| R2.6 | Separation between monitoring privileges and privileged engineering operations. | not started |
| R2.7 | No unnecessary direct external access to IEDs. | not started |

Constraint: do not assume arbitrary engineering software can be transparently proxied. Protocol-level proxying must be compared with running engineering software on controlled remote workstations (see architecture-critical question Q1 in [architecture.md](architecture.md)).

## R3 — IED configuration and baseline monitoring

| ID | Requirement | Status |
| --- | --- | --- |
| R3.1 | Retrieve supported IED configurations and settings. | not started |
| R3.2 | Maintain authenticated, versioned configuration baselines. | not started |
| R3.3 | Detect meaningful operational differences; distinguish real changes from formatting, timestamps, and other non-semantic differences. | not started |
| R3.4 | Identify unexpected modifications and correlate detected changes with authorized maintenance. | not started |
| R3.5 | Preserve original configurations and evidence of changes. | not started |
| R3.6 | Prior approval. A change approval (device, time window, reason, approver) is recorded in the audit chain before the change is made. A retrieved configuration that differs from the baseline with no matching open approval raises an alarm; the difference is kept as evidence either way. An approval silences the alarm, never the record. (Added 2026-10-26, ADR-0008.) | not started |
| R3.7 | Retrieval method order, chosen per device family from the capability matrix: (1) an authenticated, encrypted file transfer (SFTP, SCP, HTTPS download); (2) plain FTP only where the family offers nothing better, for read-only use, after A3's review of the credential exposure and the owner's acceptance for that family; (3) command-line parsing (Telnet, SSH or serial) only when no file path exists. (Added 2026-10-26, ADR-0008.) | not started |

Constraint: read-only by default. Never automatically restore or push settings.

## R4 — Syslog and Sequence of Events (SER) collection

| ID | Requirement | Status |
| --- | --- | --- |
| R4.1 | Receive device-generated Syslog. | not started |
| R4.2 | Retrieve IED SER records using supported interfaces. | not started |
| R4.3 | Normalize events into a consistent internal schema. | not started |
| R4.4 | Preserve native event records and timestamp precision. | not started |
| R4.5 | Correlate events with known assets. | not started |
| R4.6 | Forward events to upstream Syslog collectors. | not started |
| R4.7 | Handle buffering, retransmission, duplication, reconnection, and storage limits. | not started |
| R4.8 | Event-behaviour baseline. For each asset, after an observation period, the platform compares Syslog and SER events with the learnt baseline and raises an alarm on a departure: repeated alarms, an event type not in the baseline, events at an unexpected rate or time, or the absence of an expected periodic event. Rules are deterministic or explainable statistics; every alarm shows the baseline value and the observation that broke it. No machine learning until a measured benefit exists. (Added 2026-10-26, ADR-0008.) | not started |
| R4.9 | Event retrieval method order, per device family: (1) device-generated Syslog received by the platform; (2) a file fetch of the device's log or SER files, by the transfer order of R3.7; (3) command-line SER parsing. (Added 2026-10-26, ADR-0008.) | not started |

Constraint: never silently discard important native event information.

## R5 — Custom IED command and integration framework

| ID | Requirement | Status |
| --- | --- | --- |
| R5.1 | Extensible device adapter system for collection when standard interfaces are unavailable (e.g. SSH to an IED, run an approved command to retrieve SER records, parse and normalize). | not started |
| R5.2 | Vendor- and firmware-specific implementations with versioned capability definitions. | not started |
| R5.3 | Approved commands with validated parameters; explicit read-only or state-changing classification. | not started |
| R5.4 | Safe timeouts, retry behavior, and rate limits. | not started |
| R5.5 | Handling of prompts, pagination, errors, and connection failures. | not started |
| R5.6 | Deterministic parser tests using real or sanitized device outputs. | not started |
| R5.7 | No unrestricted CLI execution through normal monitoring permissions. | not started |

## R6 — Intrusion detection and network anomaly detection

| ID | Requirement | Status |
| --- | --- | --- |
| R6.1 | Passive network traffic monitoring with OT protocol identification and analysis. | not started |
| R6.2 | Network communication baselining. | not started |
| R6.3 | Detection of unauthorized engineering communication and unusual device or protocol behavior. | not started |
| R6.4 | Rule-based and behavioral anomaly detection. | not started |
| R6.5 | Explainable security alerts with supporting packet/event evidence. | not started |
| R6.6 | Documented network visibility limitations (PRP topology, encrypted communication, unsupported protocols, sensor placement). | not started |
| R6.7 | Passive identification, per asset, of exposed services, protocol versions and insecure protocols in use, recorded as evidence for R9. (Added 2026-10-26, ADR-0008.) | not started |

Constraints: evaluate Zeek and Suricata before developing proprietary detection. Deterministic rules and explainable statistical baselines first; machine learning only after measured benefit.

## R7 — Modular and additive architecture

| ID | Requirement | Status |
| --- | --- | --- |
| R7.1 | Modules independently developed, tested, enabled, disabled, upgraded, and maintained. | not started |
| R7.2 | Stable interfaces for: assets and device identities; IED adapters; event collection and normalization; configuration monitoring; remote access; network sensors and IDS; authentication and authorization; audit records; inter-module messaging. | not started |

Constraint: no microservices by default. Compare a modular monolith with deployable edge components against alternatives.

## R8 — Centralized and distributed deployment

| ID | Requirement | Status |
| --- | --- | --- |
| R8.1 | Single-server deployment. | not started |
| R8.2 | Central management server with remote collection nodes. | not started |
| R8.3 | Distributed deployment with site-local services. | not started |
| R8.4 | Intermittent WAN connectivity and independent site operation. | not started |
| R8.5 | Secure node enrollment; certificates and credential rotation. | not started |
| R8.6 | Local storage and forwarding; reliable message handling. | not started |
| R8.7 | Service restarts and crash recovery; node upgrades and rollback; version compatibility. | not started |
| R8.8 | Storage exhaustion and controlled failure behavior. | not started |

Constraint: failure of the cybersecurity platform must not compromise protection or control functions.

Clarification of R8.5 (A1 ruling, 2026-10-23, on A3 HR-5): "credential rotation" means credentials and certificates the platform owns (node certificates, enrollment keys, platform service accounts, upstream collector credentials). Rotating a password or key stored on an IED is a state-changing device operation; it belongs to privileged engineering access (R2) and is outside the first slice.

## R9 — Vulnerability applicability (added 2026-10-26, owner clarification, ADR-0008)

| ID | Requirement | Status |
| --- | --- | --- |
| R9.1 | Match each asset's collected identity (vendor, model, firmware, enabled services, settings posture where read) against a curated, versioned set of published advisories (vendor security advisories, CVE records) and report the applicable ones with the evidence that made each applicable. | not started |
| R9.2 | Classify every finding as `applicable-by-version`, `confirmed` (only with evidence read from the device), `mitigated` (a documented setting or network control, with evidence) or `not-applicable`. Never state exploitability without evidence. | not started |
| R9.3 | The advisory set is updated offline from a signed, versioned file; a site node never reaches the internet for it. Every report carries the set's version and date, and every entry cites its source. | not started |
| R9.4 | No active vulnerability scanning of production devices (P1). Applicability comes from collected identity and passive observation only. | not started |

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
