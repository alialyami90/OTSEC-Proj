# OTSEC-Proj — Modular OT Cybersecurity Platform

A production-oriented, modular OT cybersecurity platform for electrical substations, SCADA environments, IEDs, and industrial control networks.

The full project brief, engineering principles, team structure, and operating procedure are in [CLAUDE.md](CLAUDE.md). Everything in this repository is governed by it.

## Status

| Phase | State |
| --- | --- |
| Phases 0 to 3: evidence, contracts C1 to C8, the simulated SEL-751 SER-to-Syslog slice, and its hardening | Accepted by the owner. Reports: [docs/phase-0-exit.md](docs/phase-0-exit.md) to [docs/phase-3-exit.md](docs/phase-3-exit.md) |
| Phase 4, items 1 and 2: configuration monitoring and the event-behaviour baseline | Accepted. Report: [docs/phase-4a-exit.md](docs/phase-4a-exit.md) |
| Phase 4, item 3: vulnerability applicability with the asset module | Accepted. Report: [docs/phase-4-item3-exit.md](docs/phase-4-item3-exit.md) |
| Phase 4, item 4: network IDS | In progress. The node side is merged. The sensor waits on the owner's choice in [ADR-0009](docs/decisions/ADR-0009-passive-sensor.md) |
| Phase 4, items 5 and 6: secure engineering access and the central role | Not started |

There are two Go binaries. `cmd/otsec` is the site node. `cmd/otsec-collector` is the privileged collector, which alone holds device credentials and opens device sessions.

Together they collect identity, events and configuration from simulated SEL devices, receive device Syslog, store the raw bytes and the normalized events, and forward them upstream over Syslog.

Every result is `desk` or `simulated`. No device has been contacted, and no SEL family may be called supported. The scope covers all OT device classes, SEL first ([ADR-0006](docs/decisions/ADR-0006-device-coverage-and-vendor-strategy.md)). The order of monitoring goals is set in [ADR-0008](docs/decisions/ADR-0008-monitoring-goals-and-collection-method-order.md).

## Team

Seven roles, D1 to D7, each a subagent in [.claude/agents/](.claude/agents/), with two read-only helper agents beside them. [CLAUDE.md](CLAUDE.md) section 4 lists them. In older records, A*n*, B*n* and C*n* name the role that is now D*n*. [HANDOFF.md](HANDOFF.md) has the next action and the questions waiting on the owner.

## Layout and ownership

| Path | Purpose | Owner |
| --- | --- | --- |
| `docs/` | Requirements, architecture, threat model, device capabilities, verification, task briefs, decision records | D1 (shared); D6 owns `docs/verification.md`, D3 `docs/threat-model.md`, D2 `docs/device-capabilities.md` (D1 reviews both), D7 `docs/release.md` once its first brief creates it |
| `contracts/` | Versioned shared schemas and typed interfaces, with contract tests | D1 (each contract drafted by its owner) |
| `cmd/otsec/` | The site node binary (composition root) | D5 |
| `cmd/otsec-collector/` | The privileged collector binary | D3 |
| `modules/ied/` | IED adapters, device identification, native output parsers | D2 |
| `modules/asset/` | Asset identity (R1.8): turns collector observations into C1 0.3 attributes with their source; node-side, opens no connection, and is switched by the node's `asset` setting (D4-50, P4-3-C2) | D2 |
| `modules/security/`, `modules/access/` | Authentication, authorization, sessions, audit, engineering access | D3 |
| `modules/telemetry/`, `modules/detection/` | Event normalization, Syslog, correlation, IDS | D4 |
| `modules/applicability/` | Vulnerability applicability (R9): matching identities against the advisory set, producing C12 findings; a pure function that opens no connection (D4-52) | D4 |
| `platform/`, `deploy/`, `ui/` | Runtime, persistence, buffering, deployment, minimal UI | D5 |
| `tests/fixtures/ied/` | Sanitized real device outputs | D2 |
| `tests/fixtures/network/` | Sanitized captures and labeled traffic | D4 |
| `tests/contract/`, `tests/integration/`, `tests/security/`, `tests/safety/` | Independent verification | D6 |
| `go.mod`, `.github/workflows/ci.yml`, `.github/workflows/govulncheck.yml` | Dependencies and CI (`ci.yml`'s nineteen jobs and `govulncheck.yml`'s one job are the main test path; Markdown-only PRs skip both) | D1 (`a6-*.yml` workflows: D6; `a5-windows-experiments.yml`: D5, changes authorized by D1) |
| `contracts/internal/strictjson`, `contracts/node`, `.gitattributes`, `.gitignore` | Shared helpers and repository settings | D1 (`contracts/node` maintained by D4) |

The package-level table and the import rules are in [D2-1](docs/phase2/A1-decisions.md). A role modifies only its owned paths unless explicitly authorized. Shared contracts change only through D1, with a documented proposal and review by the affected owners.

## Documents

- [docs/requirements.md](docs/requirements.md): the product capabilities and the mandatory principles.
- [docs/architecture.md](docs/architecture.md): the system boundary, the runtime shape, and what the platform may and must never do.
- [docs/threat-model.md](docs/threat-model.md): trust boundaries, assets, attack paths and mitigations.
- [docs/device-capabilities.md](docs/device-capabilities.md): the per-family capability matrix with evidence classification.
- [docs/verification.md](docs/verification.md): the verification matrix, acceptance criteria and independent findings.
- [docs/agent-handoffs.md](docs/agent-handoffs.md): the task briefs for every phase.
- [docs/decisions/](docs/decisions/): Architecture Decision Records.
- `docs/phase-*-exit.md`: the milestone reports, with what is verified and what is open.
- `docs/phase0/` to `docs/phase4/`: each phase's decision log and the roles' findings.
