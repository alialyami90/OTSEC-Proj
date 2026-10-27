# Handoff summary: A-team to B-team

Owner: A1 (outgoing lead). Date: 2026-10-27. Read this first, then your own `B{n}-handoff.md`, then the files it lists.

The owner (Ali, GitHub `alialyami90`) asked on 2026-10-27 for agents A1 to A6 to be replaced by fresh agents B1 to B6 with the same roles, responsibilities and instructions. Only the names change. Wherever a project document says A1 to A6, read it as the role that B1 to B6 now hold: A1 means B1, A2 means B2, and so on. Older documents are not rewritten to the new names, because they are records of who did what at the time.

## Project state

The project is a modular OT cybersecurity platform for substations, written in Go (ADR-0003), with Python for verification tooling only. [CLAUDE.md](../CLAUDE.md) is the project brief and governs all work. [README.md](../README.md) has the layout and ownership table.

| Phase | Result | Record |
| --- | --- | --- |
| 0: evidence and assumptions | Passed with conditions, 2026-10-23 | [architecture.md, Phase 0 exit gate](../docs/architecture.md#phase-0-exit-gate) |
| 1: contracts C1 to C8 | Passed with conditions, 2026-10-24 | [phase-1-exit.md](../docs/phase-1-exit.md) |
| 2: the simulated SEL-751 SER-to-Syslog slice | Passed with conditions, 2026-10-25; the owner accepted it 2026-10-26 | [phase-2-exit.md](../docs/phase-2-exit.md) |
| 3: a hardened slice and the first monitoring rungs | The gate passed with conditions (A1, 2026-10-27). **The owner accepted it on 2026-10-27** (D4-1). | [phase-3-exit.md](../docs/phase-3-exit.md) |
| 4: configuration baselines, the event-behaviour baseline, then later items | **Issued 2026-10-27** (D4-1). | [agent-handoffs.md, Phase 4 task briefs](../docs/agent-handoffs.md#phase-4-task-briefs-issued-2026-10-27); [B1-decisions.md](../docs/phase4/B1-decisions.md) |

What works today, on `main` at the time of writing (`d4afc63`): two binaries. `cmd/otsec` is the site node: the store, the forwarder, Syslog receive, health and the admin relay. `cmd/otsec-collector` is the privileged collector: credentials, the register and the SEL-751 adapter over Telnet. They talk over the C7 named pipe or socket. Together they collect `ID` and `SER` from A6's simulated SEL-751, receive device Syslog, store the raw bytes and normalized events, and forward them over RELP/TLS or RFC 5425/6587/5426. Contracts C1 to C8 are at the versions in the Phase 3 exit report's table.

The evidence ceiling is `simulated`. No device has ever been contacted. No capability is `hardware-verified`, and no SEL family may be called supported (B-01).

### What the owner still owes, and what is open

- **Phase 3 acceptance.** Given on 2026-10-27 (D4-1); Phase 4 is issued.
- **Gate item 1's owed checks**, which can run on the GitHub-hosted Windows runner:
  - the admin relay end to end, and `config\admin`'s ACLs, on Windows;
  - the unknown-restart leg on Windows;
  - a canary scan of process command lines.
  
  The SCM logs from the owner's PC run stay unread in `pc-out\slice` on the owner's PC.
- **Open A5 PRs**, deferred until after the gate: #176 (the node reads its TLS keys from the key store), #177 (bounded crash children), #181 (the signed-files and relay design doc) and #182 (the refused-identity detail). Relay PR 2 of #181 is not started.
- **Open risks** that gate the first `device-observed` endpoint or listener: HR-11, D2-11, D2-12, D2-16, and the collector's state replace on Windows. The full list is in the Phase 3 exit report under "Open risks" and "Limitations".

## Next phase goals

When the owner accepts Phase 3, Phase 4 starts with ADR-0008's first two items and the carry-over work:

1. **Configuration retrieval, baselines and prior approval** for the SEL-751 (R3.1 to R3.7). New contract C9, plus C7 0.6 (`node.change_approval`, `node.baseline_ack`) and C8 0.5.
2. **The event-behaviour baseline** (R4.8). New contract C10, plus C5 0.4.
3. **Carry-over and hygiene**, beside items 1 and 2:
   - the move to Go 1.27.3;
   - `govulncheck` in CI;
   - the POSIX-semantics `replaceFile`;
   - HR-11's absolute bound;
   - #176, #177 and #182;
   - relay PR 2.

Items 3 to 6 (vulnerability applicability with SNMPv3 identity, IDS, secure engineering access, the central role) are outlines only. The briefs, their dependency order and the first Phase 4 exit gate are in `docs/agent-handoffs.md`.

## Agent map

| Agent | Role (CLAUDE.md §4) | Owns | Handoff file |
| --- | --- | --- | --- |
| **B1** | Principal Architect and team lead; integration authority | `docs/` other than `verification.md`, including `architecture.md`, `requirements.md`, `agent-handoffs.md` and `decisions/`; `contracts/` (each contract's draft comes from its owner, B1 approves); `go.mod` and `go.sum` (D2-2); `.github/workflows/ci.yml` and `.github/workflows/govulncheck.yml` (B1 authorizes changes); `handoffs/HANDOFF-SUMMARY.md`; `CLAUDE.md`'s repository-state section and `README.md` | [B1-handoff.md](B1-handoff.md) |
| **B2** | OT/IED integration | `modules/ied/`, `modules/asset/` (not yet created), `tests/fixtures/ied/`; C1, C2 and the C3 register content | [B2-handoff.md](B2-handoff.md) |
| **B3** | Security and engineering access | `modules/security/`, `modules/access/`, `cmd/otsec-collector/`; C7, C8; `docs/threat-model.md` | [B3-handoff.md](B3-handoff.md) |
| **B4** | Telemetry, event processing, IDS | `modules/telemetry/`, `modules/detection/`, `tests/fixtures/network/`; C4, C6, and later C10 | [B4-handoff.md](B4-handoff.md) |
| **B5** | Platform and distributed systems | `platform/`, `deploy/`, `ui/`, `cmd/otsec/`; C5 | [B5-handoff.md](B5-handoff.md) |
| **B6** | Independent verification and OT safety | `tests/integration/`, `tests/security/`, `tests/safety/`, `tests/contract/`, `docs/verification.md`, `.github/workflows/a6-*.yml` | [B6-handoff.md](B6-handoff.md) |

The package-level table is in [D2-1](../docs/phase2/A1-decisions.md) and the import rules beside it. Each agent may also write its own `docs/phase{n}/B{n}-*.md` findings files. Every new file uses the B name: Phase 4 decisions go in `docs/phase4/B1-decisions.md`, numbered D4-n, and older files keep their A names as records. Where a B handoff says `docs/phase4/A{n}-*.md`, read `B{n}`. B1 creates `docs/phase4/` when Phase 4 is issued.

Ownership settled in B1's ack (#220):

- B3 owns `docs/threat-model.md`, and B2 owns `docs/device-capabilities.md`. B1 reviews both.
- B5 owns `.github/workflows/a5-windows-experiments.yml`, with changes authorized by B1 as for `ci.yml`.
- B1 owns `contracts/internal/strictjson`, `contracts/node` (maintained by B4), `.gitattributes` and `.gitignore`.

## Cross-agent dependencies

Review pairs (CLAUDE.md §5.6):

| Work | Reviewers |
| --- | --- |
| B2's work | B6, and B3 where it is security-sensitive |
| B3's work | B6, and B2 for IED compatibility |
| B4's work | B6, and B2 for protocol interpretation |
| B5's work | B6, and B3 for trust boundaries |
| Contracts | B1 and every affected owner |
| Releases and gates | B6 and B1 |

**Phase 4 order**, once issued:

1. **Contracts.** B2 drafts C9 and B4 drafts C10 at the same time, while B3 drafts C7 0.6 and C8 0.5. B1 approves the four together, after every consumer has reviewed them.
2. **Test material.** At the same time, B6 writes the simulator's `SHO` forms and the GT-INJ series. Both come before any product test.
3. **Implementation.** B2's `config.read`, B3's approval verifier and B5's C5 0.4 run in parallel. B4's learner follows C5 0.4.
4. **Carry-over.** It runs beside the items above. B5's #176 and relay PR 2 come before P4-A5's approvals relay. HR-11's bound (B4 with B5) comes before any `device-observed` listener.

**Standing dependencies:**

- Every contract change needs B6's independent contract tests before merge.
- Every register change needs B6's deny corpus to pass.
- Every toolchain or dependency bump needs review by B3 and B6.

## Standing rules every B agent must keep

These come from the owner. They hold in every phase until the owner changes them.

- **No contact with operational equipment or any real device.** Collecting from a real device needs the owner's separate authorization. So does a first contact with a relay whose firmware ID is unknown. H-01 to H-15 and Q3 are written only and are never run. Every endpoint stays on the simulator, on loopback (D2-4, D2-10).
- **Never fabricate evidence**: no invented device outputs, results, commit SHAs or test counts. Label every result with its evidence class.
- **Credentials are test values only** (D2-5). No vendor-default or real-device password may appear in any fixture or doc (D2-11). The repository is public, so keep secrets, real device data and internal hostnames out of it.
- **Testing (D2-13, D4-3).** GitHub Actions is the main test path. `ci.yml` has ten jobs and `govulncheck.yml` has one. A PR merges when its reviewers accept it and every job in both is green on its head. When the head's CI is older than newer `main`, verify the merged result before merging. A PR that changes only Markdown skips both and merges on review (D3-13). Re-run a failing commit at most once. Never push an empty commit, and never call a property failure a flake.
- **The owner's PC.**
  - The GitHub-hosted runner comes first (D2-13). The owner's PC is the second Windows run, and the fallback when Actions is unavailable or a run needs a real installation. This replaces the earlier PC-first rule (D1-26) and the PC wording in `B5-handoff.md` (B1's ack, #220).
  - Install nothing on it beyond what the owner approved: portable Go inside the OTSEC folder, and a venv inside OTSEC with `pytest` and `asyncssh`. That means no installer, no admin rights requested, no system settings, no permanent PATH changes, and no pip installs outside the venv.
  - A run that creates services happens only in the owner's own elevated session, with the owner present, or on the GitHub-hosted runner.
  - The PC is never a self-hosted runner and never holds machine keys.
- **Actions that affect equipment, networks, credentials or security policies** need the owner's explicit authorization.
- **Ownership.** Modify only your own paths. Shared contracts change only through B1, with a written proposal and review by the affected owners.
- **Documents** use they/them for the owner.

## How the B team works

Each B agent runs in its own thread of this project, on its own branch, and opens PRs against `main`. B1 reviews and squash-merges them, and posts an "integration review" comment on each one. Agents message each other only when their work depends on each other; anything for the owner goes through B1 or the coordinator.

Onboarding (from the owner's plan):

1. Read this file, then your `B{n}-handoff.md`, then the key files it lists.
2. Write `handoffs/B{n}-ack.md` with three things: your understanding of your scope, your first three actions, and any questions or gaps you found. Open it as a docs-only PR that touches only that file.
3. The matching A agent answers your questions and fixes the handoff.
4. B1 reviews all six ack files for overlaps and gaps.

Cutover follows only when every ack is confirmed with no open questions. At that point A1 to A6 retire and B1 leads. Until the owner accepts Phase 3, the B team's first work is the Phase 3 conditions and the open PRs, not Phase 4.
