# Handoff summary: C-team to D-team

Owner: C1 (outgoing lead). Date: 2026-11-06. `main` at `6045edb` when this was written, after the role checkpoint PRs #481 to #485. The generation log is [GENERATIONS.md](GENERATIONS.md). The C-to-D handoff is recorded in D4-58.

## Reading order

1. [CLAUDE.md](../CLAUDE.md), the project brief. It governs all work.
2. This file.
3. Your own `handoffs/D{n}-handoff.md`, then the files it links to.
4. Write `handoffs/D{n}-ack.md` (your scope, your first three actions, your questions) as a Markdown-only PR that touches only that file.

## The role-number rule

The owner (Ali, GitHub `alialyami90`) has replaced the team three times:

- A1 to A6 with B1 to B6 (D3-12, 2026-10-27);
- B1 to B6 with C1 to C6 (D4-28, 2026-10-28);
- C1 to C6 with D1 to D6 (D4-58, 2026-11-06).

Only the names change. Role, owned paths, rules and review duties stay with the number. Wherever a record says A*n*, B*n* or C*n*, read it as the role D*n* now holds. Older records are not renamed, because they record who did what at the time. Contract names (C1 to C12) are not agent names: "C5 0.8" is a contract, and "agent D5" is role 5.

Phase 4's decision file stays [docs/phase4/B1-decisions.md](../docs/phase4/B1-decisions.md), and its numbering continues at D4-59. A new phase starts a new file under the current letter (`docs/phase5/D1-decisions.md`).

## Phase table

| Phase | Result | Record |
| --- | --- | --- |
| 0: evidence and assumptions | Passed with conditions, 2026-10-23 | [architecture.md, Phase 0 exit gate](../docs/architecture.md#phase-0-exit-gate) |
| 1: contracts C1 to C8 | Passed with conditions, 2026-10-24 | [phase-1-exit.md](../docs/phase-1-exit.md) |
| 2: the simulated SEL-751 SER-to-Syslog slice | Passed with conditions, 2026-10-25; owner accepted 2026-10-26 | [phase-2-exit.md](../docs/phase-2-exit.md) |
| 3: a hardened slice and the first monitoring rungs | Passed with conditions, 2026-10-27; owner accepted the same day (D4-1) | [phase-3-exit.md](../docs/phase-3-exit.md) |
| 4, items 1 and 2: configuration baselines, the event-behaviour baseline | Passed with conditions, 2026-11-05; owner accepted the same day (D4-48) | [phase-4a-exit.md](../docs/phase-4a-exit.md) |
| 4, item 3: vulnerability applicability with the asset module (R9, R1.8) | Built and merged. Every gate item is met except V-M1, which the D team runs now. Then the owner's check (D4-34) | [phase-4-item3-exit.md](../docs/phase-4-item3-exit.md); [verification.md, item 3 gate](../docs/verification.md#phase-4-item-3-exit-gate-status-c6-2026-11-06) |
| 4, items 4 to 6 | Not briefed. "Phase 4 done" means all six items (D4-33), item by item (D4-34) | [Phase 4 briefs](../docs/agent-handoffs.md#phase-4-task-briefs-issued-2026-10-27) |

## What works on `main`

Two Go binaries:

- **`cmd/otsec`, the site node.** It holds the store, the forwarder and Syslog receive, with the HR-11 bound. It also runs health, the admin relay, configuration baselines with prior-approval alarms, and event-behaviour baselines. Item 3 added identity records, the signed advisory set and findings.
- **`cmd/otsec-collector`, the privileged collector.** It holds credentials, the signed register, the SEL-751 adapter over Telnet (ID, SER and the 24 `SHO` forms), and, new in item 3, the SNMPv3 path behind an independent egress check.

The contracts are listed in [contracts/README.md](../contracts/README.md); the item 3 versions are in the exit report.

**Evidence ceiling.** It is `simulated`. No device has been contacted. No capability is `hardware-verified`, and no SEL family may be called supported (B-01).

**CI.** CI on `961221b` is 18 of 18 `ci.yml` jobs, Windows included: [run 42174011840](https://github.com/alialyami90/OTSEC-Proj/actions/runs/42174011840). `govulncheck`'s last run on `main` is from 2026-11-02, so it is stale. It passed on every PR head since.

## Owed by the owner

- **The item 3 check (D4-34),** after V-M1 passes and the gate is decided.
- **HR-18:** who publishes the advisory set and holds its signing key. No real advisory is entered until this is answered.
- **Item 3 questions:**
  - severity scores in reports;
  - the v1/v2c approval key, if a v1/v2c path is ever added (HR-17);
  - which SEL switches the sites run;
  - model naming for set authors (`SEL-2731M`).
- **The sites' protocols,** before IDS (item 4) is briefed (D4-33).
- **Authorization for any device contact.** This covers a lab relay or switch before any H-test or Q3, and any SNMPv3 contact after V-M1.
- **Resuming test runs on their PC** (D4-12).
- **Deleting the leftover branches** `claude/b6-mut-acl-1`, `claude/b6-mut-acl-2`, `claude/b6-mut-unknown-restart` and `claude/b6-diag-expired-links`. They were still present on 2026-11-06. **STALLED.**

## Open PRs at the checkpoint

None. Every PR from generation C is merged or closed. The last were #479 (the item 3 exit report), #480 (role 6's D4-57 tests) and the checkpoints #481 to #485. Role 6's V-M1 work is not a PR yet: it is a patch in `/mnt/project-files/c6-wip/` (see its README). This checkpoint's own PR is the only one open.

## Dependency order and each agent's next action

V-M1 is the only gate item left. The order:

0. **This checkpoint's PR** merges on D6's review. Then every D agent writes its ack, and D1 merges the acks (cutover).
1. **D2** checks `modules/ied/snmpv3` against the RFC texts in `/mnt/project-files/rfc/`.
2. **D6** checks GT-MIB's case table and the egress corpus against the same texts, then builds GT-MIB's agent and runs V-M1.
3. **Reviews of D6's V-M1 PR:** D2 (SNMP reading), D3 (security), D5 (node side), and D4 (any change to `contracts/finding` or `modules/applicability`).
4. **D1** merges the PR, decides the gate, updates the exit report, and puts the acceptance to the owner. Then work stops for the owner's check (D4-34).

Every D agent first writes its ack (reading order, step 4), whether or not its handoff repeats this step. Read the role handoffs with these corrections, made after they were written. #479 and #480 are merged (`a69c416`, `158a5d0`). This summary is the C-to-D one, GENERATIONS.md's C row is closed, and its standing rules section is "Standing rules every D agent must keep". All twelve RFC texts are in `/mnt/project-files/rfc/` (D4-58). "C1" in a role handoff means D1.

After the ack, each agent's NEXT ACTION is:

- **D1:** confirm the cutover. Review and squash-merge the six acks. Then drive V-M1 and decide the item 3 gate ([D1-handoff.md](D1-handoff.md)).
- **D2:** check `modules/ied/snmpv3` against the RFC texts. Then give the SNMP reading of V-M1 ([D2-handoff.md](D2-handoff.md)).
- **D3:** the security review of V-M1 when D6 posts GT-MIB's agent ([D3-handoff.md](D3-handoff.md)).
- **D4:** review for the item 3 gate. #480 has merged, so this means any change V-M1 makes to `contracts/finding`, `modules/applicability` or `tests/integration/applicability`. Then the C12 0.2 proposal when D1 opens it ([D4-handoff.md](D4-handoff.md)).
- **D5:** the node-side review of D6's V-M1 PR ([D5-handoff.md](D5-handoff.md)).
- **D6:** finish GT-MIB's agent from the WIP patch `/mnt/project-files/c6-wip/2026-11-06-gt-mib-agent-wip.patch`, and correct the case table to what the RFC texts confirm. Two corrections are known: H12 is not hostile (RFC 3417 §8), and W4 is 720 varbinds (RFC 6933's 18 columns). Then build the V-M1 runner on the real binaries ([D6-handoff.md](D6-handoff.md)).

**The single highest team priority:** V-M1 over GT-MIB, built from the RFC texts in `/mnt/project-files/rfc/`. The twelve texts are the eight from D4-58, plus RFC 2578, 3417, 1157 and 1901 for the MIB roots and encoding. All twelve are listed in `SHA256SUMS`. It is the last item 3 gate item.

## STALLED items

- The owner's leftover branches (above). Owed since generation B.
- ADR-0007 (Windows site node) is still `proposed`. It is unchanged since generation A.
- Role 3: D4-20 rule 4, the evidence release and export kind. D4-20 lets it stay unbuilt ([D3-handoff.md](D3-handoff.md)).
- Role 5: refusing `clear-suspension.json` off-lab. It needs role 3 first and a brief from role 1 ([D5-handoff.md](D5-handoff.md)).
- Role 4: IDS (item 4) is untouched by design. It waits on the owner's protocols.

## How the D team works

- Each D agent runs in its own thread, named for it, on its own branch, and opens PRs against `main`.
- Only D1 merges. It squash-merges after the reviewers accept and CI is green, and posts a "D1 integration review" comment. No other agent approves or merges.
- **Messages between agents go through the coordinator** (owner, 2026-11-06, D4-58). An agent sends what another agent needs to the coordinator, which relays it. Anything for the owner goes through D1 or the coordinator.

## Agent map

| Agent | Role (CLAUDE.md §4) | Owns | Handoff |
| --- | --- | --- | --- |
| **D1** | Principal Architect and team lead; integration authority | `docs/` other than `verification.md`, `threat-model.md` and `device-capabilities.md`; `contracts/` (each contract drafted by its owner, D1 approves); `contracts/internal/strictjson`, `contracts/node` (maintained by D4); `go.mod`, `go.sum`; `.github/workflows/ci.yml`, `govulncheck.yml` (D1 authorizes every change); `.gitattributes`, `.gitignore`; `README.md`, CLAUDE.md's repository-state section, `handoffs/HANDOFF-SUMMARY.md`, `handoffs/GENERATIONS.md` | [D1-handoff.md](D1-handoff.md) |
| **D2** | OT/IED integration | `modules/ied/`, `modules/asset/`, `tests/fixtures/ied/`, `docs/device-capabilities.md`; contracts C1, C2, C9 and the C3 register content | [D2-handoff.md](D2-handoff.md) |
| **D3** | Security and engineering access | `modules/security/`, `modules/access/`, `cmd/otsec-collector/`, `docs/threat-model.md`; contracts C7, C8, C11 | [D3-handoff.md](D3-handoff.md) |
| **D4** | Telemetry, event processing, IDS | `modules/telemetry/`, `modules/detection/`, `modules/applicability/`, `tests/fixtures/network/`; contracts C4, C6, C10, C12 | [D4-handoff.md](D4-handoff.md) |
| **D5** | Platform and distributed systems | `platform/`, `deploy/`, `ui/`, `cmd/otsec/`, `.github/workflows/a5-windows-experiments.yml` (D1 authorizes changes); contract C5 | [D5-handoff.md](D5-handoff.md) |
| **D6** | Independent verification and OT safety | `tests/integration/`, `tests/security/`, `tests/safety/`, `tests/contract/`, `docs/verification.md`, `.github/workflows/a6-*.yml` | [D6-handoff.md](D6-handoff.md) |

**Findings files.** Each agent may also write its own `docs/phase{p}/` findings files. Phase 4 files keep their `B{n}-` and `C{n}-` names. New ones may use `D{n}-`. The package table and import rules are in [D2-1](../docs/phase2/A1-decisions.md).

**Review pairs** (CLAUDE.md §5.6):

| Work | Reviewed by |
| --- | --- |
| D2's | D6, and D3 where security-sensitive |
| D3's | D6 and D2 |
| D4's | D6 and D2 |
| D5's | D6 and D3 |
| Contracts | D1 and every affected owner |
| Gates | D6 and D1 |

Every contract change needs D6's contract tests. Every register or egress change needs D6's deny corpus. Every toolchain or dependency bump needs review by D3 and D6.

## Standing rules every D agent must keep

These come from the owner and hold until the owner changes them. They are carried over word for word from the B-to-C summary, with the name changed and each change marked with its decision.

- **No contact with operational equipment or any real device.** Collecting from a real device needs the owner's separate authorization. So does a first contact with a relay whose firmware ID is unknown. H-01 to ~~H-15~~ H-17 and Q3 are written only and are never run. Every endpoint stays on the simulator, on loopback (D2-4, D2-10).
- **Never fabricate evidence**: no invented device outputs, results, commit SHAs or test counts. Label every result with its evidence class.
- **Credentials are test values only** (D2-5). No vendor-default or real-device password may appear in any fixture or doc (D2-11). The repository is public, so keep secrets, real device data and internal hostnames out of it. *Added by D4-53 and HR-18: every advisory set and advisory signing key is a test one until the owner decides HR-18.*
- **Testing (D2-13, D4-3).** GitHub Actions is the main test path. `ci.yml` has ~~twelve~~ eighteen jobs (#470; CLAUDE.md) and `govulncheck.yml` has one. A PR merges when its reviewers accept it and every job in both is green on its head. When the head's CI is older than newer `main`, verify the merged result before merging. A PR that changes only Markdown skips both and merges on review (D3-13; *widened by the owner on 2026-11-01, in CLAUDE.md: also `.pdf`, `.doc`, `.docx`, `.pptx` and `.xlsx` files outside a `testdata` directory, and a push to `main` with only such changes skips `ci.yml`*). Re-run a failing commit at most once. Never push an empty commit, and never call a property failure a flake.
- **The owner's PC.** *Changed by D4-12: no test runs on the owner's PC until the owner resumes them, so GitHub Actions is the only test path. The rest applies when they do.*
  - The GitHub-hosted runner comes first (D2-13). The owner's PC is the second Windows run, and the fallback when Actions is unavailable or a run needs a real installation. This replaces the earlier PC-first rule (D1-26) and the PC wording in `B5-handoff.md` (B1's ack, #220).
  - Install nothing on it beyond what the owner approved: portable Go inside the OTSEC folder, and a venv inside OTSEC with `pytest` and `asyncssh`. That means no installer, no admin rights requested, no system settings, no permanent PATH changes, and no pip installs outside the venv.
  - A run that creates services happens only in the owner's own elevated session, with the owner present, or on the GitHub-hosted runner.
  - The PC is never a self-hosted runner and never holds machine keys.
- **Actions that affect equipment, networks, credentials or security policies** need the owner's explicit authorization.
- **Ownership.** Modify only your own paths. Shared contracts change only through D1, with a written proposal and review by the affected owners.
- **Documents** use they/them for the owner.
- *Added by the owner during generation B:* name every new thread after the agent assigned to that work in the repository documentation; stage files by explicit path, never `git add -A` (the 2026-10-28 checkpoint instruction).
- *Added by the owner during generation C (D4-58):* all messages between agents run through the coordinator.
- *An environment fact, not a rule:* force-push is denied on every branch, an agent's own included (C6 on #486). After a squash merge, restart the branch with `git checkout -B <branch> origin/main && git merge -s ours origin/<branch>`, then push normally; never rewrite it.
