# Product

<!-- impeccable:product-schema 1 -->

Provenance: written from the project brief in CLAUDE.md. The impeccable interview could not be completed in-session beyond one structured question (the UI stack), so every fact below is marked `[brief]` (stated in the brief), `[inferred]` (derived from the brief, not confirmed by the owner), or `[open]` (undecided). Confirm or correct inferred items before relying on them for design decisions.

## Platform

web

(`[inferred]` The brief calls for a "minimal user interface needed to verify end-to-end workflows" under `ui/`, owned by A5, with no native platform mentioned. Operators and engineers use workstations, not phones, in substations and control rooms.)

## Stack

delegated: the project owner chose (2026-10-23) to defer the UI stack to A5's Phase 0 technology evaluation, to be decided together with the platform runtime language and recorded in an ADR. Options offered and not chosen: plain static HTML/CSS/JS, React with Vite, SvelteKit. Until the ADR exists, no UI framework is to be added.

## Users

`[brief]` Primary users are the people responsible for the cybersecurity of electrical substations, SCADA environments, IEDs, and industrial control networks. The brief distinguishes four permission classes, which are also the user roles: monitoring, engineering, administration, and security.

`[inferred]` Concretely:

- **OT security analyst / SOC operator (monitoring role).** Watches asset inventory, events, configuration changes, and IDS alerts. Needs explainable alerts with evidence, and must never be able to trigger a write to a device.
- **Protection and control engineer (engineering role).** Uses the platform's proxied engineering access to reach IEDs and engineering workstations for authorized maintenance. Needs sessions that are auditable, time-limited, and revocable, and clear warning when a downstream connection is insecure.
- **Platform administrator (administration role).** Enrolls site nodes, manages certificates and credential rotation, upgrades and rolls back nodes, and watches storage and connectivity health across intermittently connected sites.
- **Security officer / auditor (security role).** Reviews audit records, correlates detected configuration changes with authorized maintenance windows, and needs evidence (raw device records, timestamps, session logs) preserved, not summarized away.

`[brief]` Operating situation: substations with intermittent WAN connectivity, sites that must keep operating independently, and equipment whose protection and control functions must never be put at risk by the platform.

## Product Purpose

`[brief]` A production-oriented, modular OT cybersecurity platform that provides: OT asset inventory and monitoring; secure, proxied engineering and remote access; IED configuration baseline monitoring; Syslog and Sequence-of-Events (SER) collection, normalization, and forwarding; an extensible IED adapter framework for devices without standard interfaces; passive intrusion and anomaly detection; and single-server, central-plus-collectors, and fully distributed deployment.

`[brief]` Success is "a small, secure, maintainable, extensible system whose behavior is independently demonstrated and whose architecture can support the remaining requirements without fundamental redesign." Engineering depth, security, reliability, interoperability, and verifiable implementation outrank feature count.

## Positioning

`[brief]` Read-only by default, evidence-first, and OT-safety-first: the platform observes passively, uses only explicitly approved read-only methods, never automatically pushes or restores device settings, and fails closed on privileged access. Every capability claim carries an evidence classification (hardware verified, documented but untested, simulated, unsupported, unknown), and no vendor compatibility is claimed without proof.

`[inferred]` The differentiating mechanism is the combination of native-evidence preservation (raw SER, Syslog, configurations, and packet evidence kept alongside normalized data) with a custom adapter framework that reaches IEDs lacking standard interfaces through approved, parameter-validated, read-only commands. The threat model explicitly treats the platform itself as a potential attack path and designs against it.

## Operating Context

`[brief]` Environments: electrical substations, SCADA networks, IEDs (protective relays and similar), industrial control networks, engineering workstations, and upstream Syslog/SIEM collectors. Network realities include PRP topologies, encrypted communication, unsupported protocols, and sensor placement limits.

`[brief]` Workflows: passive asset discovery; retrieval of IED configurations and SER records over supported interfaces (including SSH with approved commands); normalization and forwarding of events upstream; versioned configuration baselines with semantic diffing and correlation to authorized maintenance; proxied engineering sessions (SSH, RDP, vendor tools, native protocols, controlled TCP forwarding or application gateways); passive traffic monitoring and rule-based detection.

`[brief]` Materials and documents that are part of using and evaluating the product: native IED command outputs, OEM manuals and protocol documentation, PCAP/PCAPNG captures, original relay settings files, native SER and Syslog messages, IEC 61850 SCL files, network topology and firewall configuration, and records of authorized maintenance events.

`[brief]` Standards for alignment (not certification): IEC 62443, IEC 62351, NIST SP 800-82, MITRE ATT&CK for ICS.

## Capabilities and Constraints

`[brief]` Capabilities are the eight requirement groups R1–R8 in `docs/requirements.md`. None is implemented yet.

`[brief]` Hard constraints:

- No unapproved active scanning or disruptive operations on production equipment.
- Monitoring permissions can never invoke state-changing device operations. Privileged engineering operations are separately authorized.
- Configuration monitoring is read-only; no automatic restore or push.
- Native event information is never silently discarded; timestamp precision is preserved.
- Privileged access fails closed; telemetry failure stays observable.
- Platform failure must not compromise protection or control functions.
- Insecure downstream connections must be clearly identified to the user.
- No claim of hardware testing, security verification, or protocol compatibility without evidence.

`[brief]` Terminology: IED (intelligent electronic device), SER (sequence of events record), SCL (substation configuration language, IEC 61850), PRP (parallel redundancy protocol), SCADA, IDS. Evidence classes: hardware-verified, documented-untested, simulated, unsupported, unknown.

`[brief]` UI scope constraint: the interface is the minimum needed to verify end-to-end workflows. Elaborate UI is deferred until foundational workflows are proven.

`[open]` Runtime language, UI stack, persistence, IDS engine (Zeek, Suricata, or other), and deployment shape (modular monolith with edge components versus alternatives) are all undecided pending Phase 0 evidence.

## Brand Commitments

`[inferred]` Working name: OTSEC-Proj (repository name). No logo, voice guide, or identity constraints exist. Nothing visual is binding.

## Evidence on Hand

`[brief]` None. The repository holds no device outputs, captures, configuration files, screenshots, customer references, benchmarks, or testimonials. Future design and marketing work must not fabricate any of these. Fixtures will be registered in `docs/device-capabilities.md` and `tests/fixtures/` as they are collected, each with a `SOURCE.md` provenance record.

## Product Principles

`[brief]`, restated:

1. **OT safety over everything.** A feature that could disrupt protection or control is not a feature.
2. **Show the evidence.** Every alert, change, and asset attribute links to the raw record and its confidence.
3. **Read-only until explicitly authorized.** Privileged actions are separate, visible, audited, and revocable.
4. **Proven, not promised.** Capabilities and vendor support are labeled by evidence class, never implied.
5. **Keep working when disconnected.** Sites operate independently and reconcile later without losing data.

## Accessibility & Inclusion

`[inferred]` Operators work long shifts in control rooms and in the field; the interface must be scannable, keyboard-operable, and legible without relying on color alone to convey alert severity or device state. No formal standard has been mandated by the owner; WCAG 2.1 AA is the working target until stated otherwise.
