# Requirements

Source: the project brief in [CLAUDE.md](../CLAUDE.md), sections 1 and 2, as amended by the owner's scope change of 2026-10-23 (device classes and SEL-first vendor strategy, [ADR-0006](decisions/ADR-0006-device-coverage-and-vendor-strategy.md)). This document restates the requirements in a form that can be traced to acceptance criteria in [verification.md](verification.md). Requirement IDs are stable; do not renumber.

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
