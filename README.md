# OTSEC-Proj — Modular OT Cybersecurity Platform

A production-oriented, modular OT cybersecurity platform for electrical substations, SCADA environments, IEDs, and industrial control networks.

The full project brief, engineering principles, team structure, and operating procedure are in [CLAUDE.md](CLAUDE.md). Everything in this repository is governed by it.

## Status

Phase 0 (evidence and assumption challenge) passed its exit gate with conditions on 2026-10-23; see [docs/architecture.md](docs/architecture.md#phase-0-exit-gate). Runtime, toolchain (Go), persistence, and the first slice scenario are decided in ADR-0002 to ADR-0005. No product code exists yet; Phase 1 (contracts) is next. Everything so far is `documented-untested` or `simulated`.

## Layout and ownership

| Path | Purpose | Owner |
| --- | --- | --- |
| `docs/` | Requirements, architecture, threat model, device capabilities, verification, handoffs, decision records | A1 (shared); A6 owns `docs/verification.md` |
| `contracts/` | Versioned shared schemas and typed interfaces, with contract tests | A1 |
| `modules/ied/` | IED adapters, device identification, native output parsers | A2 |
| `modules/security/`, `modules/access/` | Authentication, authorization, sessions, audit, engineering access | A3 |
| `modules/telemetry/`, `modules/detection/` | Event normalization, Syslog, correlation, IDS | A4 |
| `platform/`, `deploy/`, `ui/` | Runtime, persistence, buffering, deployment, minimal UI | A5 |
| `tests/fixtures/ied/` | Sanitized real device outputs | A2 |
| `tests/fixtures/network/` | Sanitized captures and labeled traffic | A4 |
| `tests/integration/`, `tests/security/`, `tests/safety/` | Independent verification | A6 |

Agents modify only their owned paths unless explicitly authorized. Shared contracts change only through A1 with a documented proposal and review by affected owners.

## Documents

- [docs/requirements.md](docs/requirements.md): the eight product capabilities and mandatory principles.
- [docs/architecture.md](docs/architecture.md): system boundary, alternatives under evaluation, open questions.
- [docs/threat-model.md](docs/threat-model.md): trust boundaries, assets, attack paths, mitigations.
- [docs/device-capabilities.md](docs/device-capabilities.md): per-IED capability matrix with evidence classification.
- [docs/verification.md](docs/verification.md): verification matrix, acceptance criteria, and independent findings.
- [docs/agent-handoffs.md](docs/agent-handoffs.md): structured handoffs between agents.
- [docs/decisions/](docs/decisions/): Architecture Decision Records.
