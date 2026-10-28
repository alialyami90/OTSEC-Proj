# OTSEC-Proj — Modular OT Cybersecurity Platform

A production-oriented, modular OT cybersecurity platform for electrical substations, SCADA environments, IEDs, and industrial control networks.

The full project brief, engineering principles, team structure, and operating procedure are in [CLAUDE.md](CLAUDE.md). Everything in this repository is governed by it.

## Status

As of 2026-10-27 (details in [docs/phase-3-exit.md](docs/phase-3-exit.md)):

| Phase | State |
| --- | --- |
| Phase 0 (evidence) | Passed with conditions, 2026-10-23 |
| Phase 1 (contracts C1 to C8) | Passed with conditions, 2026-10-24 |
| Phase 2 (the simulated SEL-751 SER-to-Syslog slice) | Passed with conditions; the owner accepted it 2026-10-26 |
| Phase 3 (a hardened slice and the first monitoring rungs) | Passed with conditions; the owner accepted it 2026-10-27 |
| Phase 4 (configuration baselines, the event-behaviour baseline, carry-over) | Issued 2026-10-27; briefs in [docs/agent-handoffs.md](docs/agent-handoffs.md), decisions in [docs/phase4/B1-decisions.md](docs/phase4/B1-decisions.md) |

There are two Go binaries. `cmd/otsec` is the site node. `cmd/otsec-collector` is the privileged collector, which alone holds device credentials and opens device sessions.

Together they collect `ID` and `SER` from a simulated SEL-751 over Telnet, and they receive device Syslog. They store the raw bytes and the normalized events, and forward them upstream over Syslog.

Every result is `desk` or `simulated`. No device has been contacted, and no SEL family may be called supported. The scope covers all OT device classes, SEL first ([ADR-0006](docs/decisions/ADR-0006-device-coverage-and-vendor-strategy.md)). The order of monitoring goals is set in [ADR-0008](docs/decisions/ADR-0008-monitoring-goals-and-collection-method-order.md).

## Team

On 2026-10-27 the owner replaced agents A1 to A6 with B1 to B6. The roles and scope are unchanged; only the names changed. In older records, "A*n*" means the role that B*n* now holds. Start with [handoffs/HANDOFF-SUMMARY.md](handoffs/HANDOFF-SUMMARY.md), which has the agent map and the cross-agent dependencies. Each agent's own handoff is `handoffs/B{n}-handoff.md`.

## Layout and ownership

| Path | Purpose | Owner |
| --- | --- | --- |
| `docs/` | Requirements, architecture, threat model, device capabilities, verification, handoffs, decision records | A1 (shared); A6 owns `docs/verification.md`, A3 `docs/threat-model.md`, A2 `docs/device-capabilities.md` (A1 reviews both) |
| `handoffs/` | The A-to-B team handoff: the summary, one handoff and one acknowledgement per agent | A1 (summary); each agent its own files |
| `contracts/` | Versioned shared schemas and typed interfaces, with contract tests | A1 (each contract drafted by its owner) |
| `cmd/otsec/` | The site node binary (composition root) | A5 |
| `cmd/otsec-collector/` | The privileged collector binary | A3 |
| `modules/ied/` | IED adapters, device identification, native output parsers | A2 |
| `modules/asset/` | Asset monitoring and management: SNMPv3 and other device-facing identity and health reads, inventory logic (ADR-0008) | A2 |
| `modules/security/`, `modules/access/` | Authentication, authorization, sessions, audit, engineering access | A3 |
| `modules/telemetry/`, `modules/detection/` | Event normalization, Syslog, correlation, IDS | A4 |
| `platform/`, `deploy/`, `ui/` | Runtime, persistence, buffering, deployment, minimal UI | A5 |
| `tests/fixtures/ied/` | Sanitized real device outputs | A2 |
| `tests/fixtures/network/` | Sanitized captures and labeled traffic | A4 |
| `tests/contract/`, `tests/integration/`, `tests/security/`, `tests/safety/` | Independent verification | A6 |
| `go.mod`, `.github/workflows/ci.yml`, `.github/workflows/govulncheck.yml` | Dependencies and CI (`ci.yml`'s ten jobs and `govulncheck.yml`'s one job are the main test path, D2-13 and D4-3; Markdown-only PRs skip both, D3-13) | A1 (`a6-*.yml` workflows: A6; `a5-windows-experiments.yml`: A5, changes authorized by A1) |
| `contracts/internal/strictjson`, `contracts/node`, `.gitattributes`, `.gitignore` | Shared helpers and repository settings | A1 (`contracts/node` maintained by A4) |

The package-level table and the import rules are in [D2-1](docs/phase2/A1-decisions.md). Agents modify only their owned paths unless explicitly authorized. Shared contracts change only through A1 with a documented proposal and review by affected owners.

## Documents

- [docs/requirements.md](docs/requirements.md): the eight product capabilities and mandatory principles.
- [docs/architecture.md](docs/architecture.md): system boundary, runtime shape, what the platform may and must never do.
- [docs/phase-0-exit.md](docs/phase-0-exit.md) to [docs/phase-3-exit.md](docs/phase-3-exit.md): the milestone reports, with what is verified and what is open.
- `docs/phase1/` to `docs/phase3/`: each phase's decisions (`A1-decisions.md`) and the agents' findings and handoffs.
- [docs/threat-model.md](docs/threat-model.md): trust boundaries, assets, attack paths, mitigations.
- [docs/device-capabilities.md](docs/device-capabilities.md): per-IED capability matrix with evidence classification.
- [docs/verification.md](docs/verification.md): verification matrix, acceptance criteria, and independent findings.
- [docs/agent-handoffs.md](docs/agent-handoffs.md): task briefs for every phase (Phase 4 issued), handoffs, and the roadmap.
- [handoffs/](handoffs/): the A-to-B team handoff.
- [docs/decisions/](docs/decisions/): Architecture Decision Records.
