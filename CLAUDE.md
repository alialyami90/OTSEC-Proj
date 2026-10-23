# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

Modular OT cybersecurity platform for electrical substations, SCADA environments, IEDs, and industrial control networks. Success is measured by engineering depth, security, reliability, interoperability, and verifiable implementation, not feature count or code volume.

The repository currently contains no code. No language, toolchain, or test runner has been chosen yet. Once one is, record the build, lint, test, and single-test commands in this file.

## Non-negotiable engineering principles

1. **OT safety first.** No active scanning or potentially disruptive operations on production equipment without explicit authorization. Passive observation and approved read-only methods only.
2. **Read-only by default.** Configuration monitoring never pushes or restores settings automatically. Privileged engineering operations are separately authorized from monitoring.
3. **Evidence before assumptions.** Every capability is classified as one of: hardware verified / documented but untested / simulated or experimental / unsupported / unknown. Never claim hardware testing, security verification, or vendor compatibility without evidence.
4. **Least privilege and defense in depth.** Monitoring, engineering, administration, and security permissions are separate.
5. **Fail securely.** Privileged access fails closed. Telemetry failures stay observable. Platform failure must never compromise protection or control functions.
6. **Deterministic verification.** Reproducible tests and known ground truth over subjective judgement. Parser tests use real or sanitized device outputs.
7. **Justify complexity.** No microservices, frameworks, dependencies, or speculative abstractions without a documented reason. A modular monolith with deployable edge components is the default to compare against.
8. **Never silently discard native event information.** Preserve raw device records and timestamp precision alongside normalized data.
9. **No unrestricted CLI execution** through normal monitoring permissions. Device adapters expose only approved commands with validated parameters, each classified read-only or state-changing.

Reference IEC 62443, IEC 62351, NIST SP 800-82, and MITRE ATT&CK for ICS where applicable. Keep standards alignment distinct from certification claims.

## Product capabilities (scope)

1. OT asset management and monitoring (passive discovery, identification confidence, evidence sources).
2. Secure engineering and remote access (proxied SSH/RDP/vendor tools, per-user/device/operation permissions, session audit and revocation). Do not assume arbitrary engineering software can be transparently proxied; compare protocol proxying with controlled remote workstations.
3. IED configuration and baseline monitoring (versioned baselines, semantic diffing, correlation with authorized maintenance).
4. Syslog and Sequence-of-Events (SER) collection, normalization, and upstream forwarding with buffering and retransmission.
5. Custom IED command and integration framework (vendor/firmware-specific adapters with versioned capability definitions).
6. Passive intrusion and anomaly detection. Evaluate Zeek and Suricata before building proprietary detection. Deterministic rules and explainable baselines first; ML only after measured benefit.
7. Modular, additive architecture with stable interfaces per module.
8. Single-server, central-plus-collectors, and fully distributed deployment with intermittent WAN tolerance.

## Repository layout and ownership

Structure to adopt (create directories only when there is content for them):

```
docs/            requirements, architecture, threat-model, device-capabilities,
                 verification, agent-handoffs, decisions/ (ADRs)
contracts/       versioned shared schemas and typed interfaces, with contract tests
modules/ied/     IED adapters, device identification, parsers        (A2)
modules/security/ and modules/access/  auth, authz, sessions, audit  (A3)
modules/telemetry/ and modules/detection/  events, syslog, IDS       (A4)
platform/ deploy/ ui/  runtime, persistence, buffering, deployment    (A5)
tests/fixtures/{ied,network}/  sanitized real device outputs and captures
tests/integration/ tests/security/ tests/safety/                     (A6)
```

This project is run as a coordinated multi-agent engineering team. Preserve the roles even when work is executed sequentially, and never present work as independently reviewed when it was not.

| Agent | Role | Owns |
| --- | --- | --- |
| A1 | Principal Architect / coordinator. Owns architecture, shared contracts, integration, ADRs. Must not become the default implementer. | `docs/`, `contracts/` |
| A2 | OT/IED integration | `modules/ied/`, `tests/fixtures/ied/` |
| A3 | Security and engineering access | `modules/access/`, `modules/security/` |
| A4 | Telemetry, event processing, IDS | `modules/telemetry/`, `modules/detection/`, `tests/fixtures/network/` |
| A5 | Platform and distributed systems | `platform/`, `deploy/`, `ui/` |
| A6 | Independent verification and OT safety. Actively tries to disprove claims; a critical unresolved safety or security finding blocks acceptance. | `tests/integration/`, `tests/security/`, `tests/safety/`, `docs/verification.md` |

Rules:
- Agents modify only their owned paths unless explicitly authorized. Shared contracts change only through A1 with a documented proposal and review by affected owners.
- Cross-review is mandatory: A2 by A6 and A3; A3 by A6 and A2; A4 by A6 and A2; A5 by A6 and A3; contracts by A1 plus all affected owners; releases by A6 and A1.
- Branch convention: `agent/ied-*`, `agent/security-*`, `agent/telemetry-*`, `agent/platform-*`, `agent/verification-*`. A1 controls integration. Small, reviewable commits; merge only after checks pass.
- Disagreements are resolved by evidence (experiment where practical) and recorded as an ADR in `docs/decisions/`. Safety and security objections cannot be dismissed by majority.

## Development process

Phases are gated. Do not start broad implementation before the gate is met.

- **Phase 0, evidence.** Parallel investigation per agent. Exit when five architecture-critical risks are identified, an initial architecture is plausible, the first scenario is selected, required contracts are defined, acceptance criteria are objective, and unsupported assumptions are marked.
- **Phase 1, contracts.** Approve only the interfaces the current milestone needs (asset identity, device capability, event and timestamp schema, adapter invocation/result, error and timeout semantics, auth boundaries, inter-module messaging, audit format, versioning). Contract tests with deterministic fixtures or mocks must pass before parallel coding.
- **Phase 2, vertical slice.** First target: collect native SER records from a representative lab IED and securely forward them to an upstream Syslog collector, with local asset identification and evidence preservation. Integrate small increments continuously; do not wait for feature completeness.
- **Phase 3, independent verification** by A6 against predefined acceptance criteria. Simulator-only results are marked as such.
- **Phase 4, controlled expansion** (suggested order: config baselines, more vendors, secure access, passive IDS, advanced distributed operation), adjusted by measured risk.

Every significant task gets a brief: objective, owner, inputs and dependencies, files the owner may modify, expected interfaces, deliverable, acceptance tests, exclusions, and risks. Every completed task gets a handoff in `docs/agent-handoffs.md`: Completed, Evidence, Interfaces, Limitations, Risks, Dependencies, Files changed.

## Definition of done

A feature is done only with: working implementation, documented interface, unit tests, integration tests, negative and failure tests, security analysis, OT safety considerations, evidence of correct operation, known limitations, and an independent review. Compiling code or a working UI is not evidence of correctness; a simulator pass is not proof of IED compatibility.

Milestone reports (one consolidated report by A1, in `docs/`) use the sections: Milestone, Implemented, Independently verified, Failed or incomplete, Unverified assumptions, Architectural decisions, Open risks, Next coordinated tasks. Never present projected capability as completed.

## Authorization boundaries

Make routine technical decisions without asking. Require explicit authorization from the project owner before any action that could affect operational equipment, production networks, credentials, or security policies.
