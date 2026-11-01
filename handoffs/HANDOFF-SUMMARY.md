# Handoff summary: B-team to C-team

Owner: B1 (outgoing lead). Date: 2026-10-28. `main` at `26d8e78` when this was written (after the checkpoint PRs #348 to #351 and #354). The generation log is [GENERATIONS.md](GENERATIONS.md).

## Reading order

1. [CLAUDE.md](../CLAUDE.md), the project brief. It governs all work.
2. This file.
3. Your own `handoffs/C{n}-handoff.md`, then the files it links to.
4. Write `handoffs/C{n}-ack.md` (your scope, your first three actions, your questions) as a Markdown-only PR that touches only that file.

## The role-number rule

The owner (Ali, GitHub `alialyami90`) replaced agents A1 to A6 with B1 to B6 on 2026-10-27 (D3-12), and B1 to B6 with C1 to C6 on 2026-10-28 (D4-28). Only the names change: role, owned paths, rules and review duties stay with the number. Wherever a record says A*n* or B*n*, read it as the role C*n* now holds. Older records are not renamed, because they record who did what at the time. Phase 4's decision file stays `docs/phase4/B1-decisions.md` and its numbering continues at D4-29. A new phase starts a new file under the current letter (`docs/phase5/C1-decisions.md`).

## Phase table

| Phase | Result | Record |
| --- | --- | --- |
| 0: evidence and assumptions | Passed with conditions, 2026-10-23 | [architecture.md, Phase 0 exit gate](../docs/architecture.md#phase-0-exit-gate) |
| 1: contracts C1 to C8 | Passed with conditions, 2026-10-24 | [phase-1-exit.md](../docs/phase-1-exit.md) |
| 2: the simulated SEL-751 SER-to-Syslog slice | Passed with conditions, 2026-10-25; owner accepted 2026-10-26 | [phase-2-exit.md](../docs/phase-2-exit.md) |
| 3: a hardened slice and the first monitoring rungs | Passed with conditions, 2026-10-27; owner accepted the same day (D4-1) | [phase-3-exit.md](../docs/phase-3-exit.md) |
| 4: configuration baselines (item 1), the event-behaviour baseline (item 2), carry-over | Issued 2026-10-27. Working toward the first exit gate (items 1 and 2). Paused by the owner 2026-10-28 16:39Z for this checkpoint and resumed 17:11Z (D4-28). | [Phase 4 briefs and gate](../docs/agent-handoffs.md#phase-4-task-briefs-issued-2026-10-27); [B1-decisions.md](../docs/phase4/B1-decisions.md) |

## What works on `main`

Two Go binaries. `cmd/otsec` is the site node: the store, the forwarder, Syslog receive with the HR-11 unknown-sender bound, health, the admin relay with signed quarantine clears and seq-reset acknowledgements, and the configuration database. `cmd/otsec-collector` is the privileged collector: credentials, the signed register and the SEL-751 adapter over Telnet. They talk over the C7 named pipe or socket. Together they collect `ID` and `SER` from B6's simulated SEL-751, receive Syslog, store raw bytes and normalized events, and forward over RELP/TLS or RFC 5425/6587/5426.

New in Phase 4 and merged: contracts C9 0.2, C10 0.1, C2 0.6, C5 0.6, C7 0.6 and C8 0.7 ([contracts/README.md](../contracts/README.md)); the SEL-751 adapter reads all 24 `SHO` forms all or nothing (D4-23), but the collector does not run it yet (#341); the event-baseline learner and detector meet V-M4 in their package (#330), but the node does not feed them yet (#340, #343); Go 1.27.3 (D4-7) and `govulncheck` (D4-3).

The evidence ceiling is `simulated`. No device has been contacted. No capability is `hardware-verified`, and no SEL family may be called supported (B-01). Every false-positive figure is synthetic.

## Owed by the owner

- ~~Whether "Phase 4 done" means the first gate or all six items (asked 2026-10-28 15:40Z).~~ Answered 18:10Z: all six items (D4-33).
- Authorization for an out-of-service lab relay before any H-test or Q3.
- The protocols at their sites, before IDS (item 4) is briefed.
- Resuming test runs on their PC (D4-12).
- Deleting the leftover branches `claude/b6-mut-acl-1`, `claude/b6-mut-acl-2`, `claude/b6-mut-unknown-restart` and `claude/b6-diag-expired-links`, and noting #272's orphan push `e87191b`.

## Open PRs at the checkpoint

CI is "green" only when all 12 `ci.yml` jobs and `govulncheck` pass on the head. Read each PR again before acting: these heads are from 2026-10-28 about 17:00Z.

| PR | Owner | What | Head | CI | Waiting on |
| --- | --- | --- | --- | --- | --- |
| #345 | C2 | C9 0.3: the snapshot bound (D4-25) | `c0a42f7` | green (13); Windows had failed on the earlier head `2a72b4c` in `platform/node` `TestSlowCommitReachesStatusAndAlarms` | C6 review (C5 accepted at 17:15Z; C5's node-side fit test is on branch `fit345-node`, to follow #345) |
| #353 | C5 | Test-only fix: `TestSlowCommitReachesStatusAndAlarms` assumed no commit over 5 s (the #345 Windows failure) | see PR | see PR | C6 review |
| #341 | C3 | C7 0.7 code: the collector runs a register run (D4-24, D4-27) | `61cf141` | green | C2, C5, C6 review; draft |
| #334 | C3 | C7 0.7 design note | `aa008b5` | Markdown | merges with #341 |
| #346 | C3 | C8 0.8: `config.baseline_recorded` (D4-26 item 4) | `95b91cd` | Windows failed in `tests/integration/syslogreceive` (`restart_test.go`), a package #346 does not touch | C4, C5, C6 review; `correlation_id`; the acknowledgement window rule (D4-26 amendment); draft |
| #344 | C4 | Learner and detector `Snapshot`/`Restore` (D4-26) | `7dbe6b0` | green | C5, C6 review |
| #343 | C5 | Feeder slice 1a: the `event_baselines` section | `d59d3b0` | running | C4, C6 review |
| #342 | C5 | Pin `ConfigRecordBytes` to #345's cap | `e752519` | green | C6, C3 review |
| #347 | C5 | Relay PR 2b: refuse unsigned clears off-lab | `55c8583` | green | C6 holds a FAIL (the supersede rule on lab nodes, C6-handoff section 2); C3 review |
| #340 | C5 | Feeder design (rulings on the PR, D4-26) | `777030c` | Markdown | C4 review; update to rulings |
| #181 | C5 | Signed-files and relay design | `3d9d0f2` | Markdown | update to the merged design, or close; **STALLED** (open since generation A) |
| #336 | C6 | D4-21 criterion on the real store | `10d03fb` | green (15) | C3, C4 review |
| #337 | C1 | D4-23 to D4-28 and this checkpoint | the branch tip | Markdown | C6 review |

Two Windows failures above are in packages the PRs do not change. The `platform/node` one is C5's test, explained and fixed in #353. The `syslogreceive` one on #346 is still unexplained: treat it as a finding to reproduce against `main`, not a flake.

## Dependency order and each agent's next action

The order to land work:

1. **Contracts:** #345 (C9 0.3) and #342, then #341 with #334 (C7 0.7), then #346 (C8 0.8).
2. **Detection state:** #344, then C4's F1 pair-cap PR.
3. **Node feeder:** #340, #343, then slices 1b (merge reader), 1c (snapshots, needs #344), 1d (lifecycle and `node.baseline_ack`, needs #346).
4. **Relay:** #347, then #181 updated or closed.
5. **Gate runs:** C6 runs V-M2, V-M3 and V-M4 on the real binaries (needs #341 and the feeder), then C1 writes `docs/phase-4a-exit.md`.

The role handoffs were written during the pause. Where one says to wait for the owner to resume, that wait is over (D4-28), and its PR heads may have moved, so read every PR again before acting. Every C agent first writes its ack (reading order, step 4). After that, each agent's NEXT ACTION is:

- **C1:** confirm the cutover by reviewing and merging the six ack PRs. Then land the step 1 contracts in order, and update the `contracts/README.md` rows for C7 0.7, C8 0.8 and C9 0.3 ([C1-handoff.md](C1-handoff.md)).
- **C2:** read #345's checks on its current head, fix anything red in its own code, get C5 and C6 to review ([C2-handoff.md](C2-handoff.md)).
- **C3:** read #341's and #346's reviews and checks, fix what is real, ask C1 to merge #341 first, #346 second ([C3-handoff.md](C3-handoff.md)).
- **C4:** land #344 ([C4-handoff.md](C4-handoff.md)).
- **C5:** land #342, #343 and #347 ([C5-handoff.md](C5-handoff.md)).
- **C6:** review #346 (C3's question is answered by D4-26's window amendment), #345, #353 and #352, and classify `TestUnknownSpentAcrossRestarts/seed_1` (D4-31). Then land #336. The #341 PASS is posted, and #347's is on `714203e`; `fc31c79` is under C6's review ([C6-handoff.md](C6-handoff.md)). *Updated by C1 after cutover, D4-31.*

**The single highest team priority:** land the step 1 contracts (#345, #342, #341 with #334, #346). Every other piece of the first gate waits on them.

## How the C team works

Each C agent runs in its own thread, named for it, on its own branch, and opens PRs against `main`. Only C1 merges: it squash-merges after the reviewers accept and CI is green, and posts a "C1 integration review" comment. No other agent approves or merges. Agents message each other only when their work depends on each other's. Anything for the owner goes through C1 or the coordinator.

## Agent map

| Agent | Role (CLAUDE.md §4) | Owns | Handoff |
| --- | --- | --- | --- |
| **C1** | Principal Architect and team lead; integration authority | `docs/` other than `verification.md`, `threat-model.md` and `device-capabilities.md`; `contracts/` (each contract drafted by its owner, C1 approves); `contracts/internal/strictjson`, `contracts/node` (maintained by C4); `go.mod`, `go.sum`; `.github/workflows/ci.yml`, `govulncheck.yml` (C1 authorizes every change); `.gitattributes`, `.gitignore`; `README.md`, CLAUDE.md's repository-state section, `handoffs/HANDOFF-SUMMARY.md`, `handoffs/GENERATIONS.md` | [C1-handoff.md](C1-handoff.md) |
| **C2** | OT/IED integration | `modules/ied/`, `modules/asset/` (not yet created), `tests/fixtures/ied/`, `docs/device-capabilities.md`; C1, C2, C9 and the C3 register content | [C2-handoff.md](C2-handoff.md) |
| **C3** | Security and engineering access | `modules/security/`, `modules/access/`, `cmd/otsec-collector/`, `docs/threat-model.md`; C7, C8 | [C3-handoff.md](C3-handoff.md) |
| **C4** | Telemetry, event processing, IDS | `modules/telemetry/`, `modules/detection/`, `tests/fixtures/network/`; C4, C6, C10 | [C4-handoff.md](C4-handoff.md) |
| **C5** | Platform and distributed systems | `platform/`, `deploy/`, `ui/`, `cmd/otsec/`, `.github/workflows/a5-windows-experiments.yml` (C1 authorizes changes); C5 | [C5-handoff.md](C5-handoff.md) |
| **C6** | Independent verification and OT safety | `tests/integration/`, `tests/security/`, `tests/safety/`, `tests/contract/`, `docs/verification.md`, `.github/workflows/a6-*.yml` | [C6-handoff.md](C6-handoff.md) |

Each agent may also write its own `docs/phase{p}/` findings files. Phase 4 files written so far keep their `B{n}-` names; new ones may use `C{n}-`. The package table and import rules are in [D2-1](../docs/phase2/A1-decisions.md). Review pairs (CLAUDE.md §5.6): C2's work by C6 (and C3 where security-sensitive); C3's by C6 and C2; C4's by C6 and C2; C5's by C6 and C3; contracts by C1 and every affected owner; gates by C6 and C1. Every contract change needs C6's contract tests, every register change C6's deny corpus, and every toolchain or dependency bump review by C3 and C6.

## Standing rules every C agent must keep

These come from the owner and hold until the owner changes them. They are carried over word for word from the A-to-B summary, with the name changed and each change marked with its decision.

- **No contact with operational equipment or any real device.** Collecting from a real device needs the owner's separate authorization. So does a first contact with a relay whose firmware ID is unknown. H-01 to H-15 and Q3 are written only and are never run. Every endpoint stays on the simulator, on loopback (D2-4, D2-10).
- **Never fabricate evidence**: no invented device outputs, results, commit SHAs or test counts. Label every result with its evidence class.
- **Credentials are test values only** (D2-5). No vendor-default or real-device password may appear in any fixture or doc (D2-11). The repository is public, so keep secrets, real device data and internal hostnames out of it.
- **Testing (D2-13, D4-3).** GitHub Actions is the main test path. `ci.yml` has ~~ten~~ twelve jobs (#321) and `govulncheck.yml` has one. A PR merges when its reviewers accept it and every job in both is green on its head. When the head's CI is older than newer `main`, verify the merged result before merging. A PR that changes only Markdown skips both and merges on review (D3-13). Re-run a failing commit at most once. Never push an empty commit, and never call a property failure a flake.
- **The owner's PC.** *Changed by D4-12: no test runs on the owner's PC until the owner resumes them, so GitHub Actions is the only test path. The rest applies when they do.*
  - The GitHub-hosted runner comes first (D2-13). The owner's PC is the second Windows run, and the fallback when Actions is unavailable or a run needs a real installation. This replaces the earlier PC-first rule (D1-26) and the PC wording in `B5-handoff.md` (B1's ack, #220).
  - Install nothing on it beyond what the owner approved: portable Go inside the OTSEC folder, and a venv inside OTSEC with `pytest` and `asyncssh`. That means no installer, no admin rights requested, no system settings, no permanent PATH changes, and no pip installs outside the venv.
  - A run that creates services happens only in the owner's own elevated session, with the owner present, or on the GitHub-hosted runner.
  - The PC is never a self-hosted runner and never holds machine keys.
- **Actions that affect equipment, networks, credentials or security policies** need the owner's explicit authorization.
- **Ownership.** Modify only your own paths. Shared contracts change only through C1, with a written proposal and review by the affected owners.
- **Documents** use they/them for the owner.
- *Added by the owner during generation B:* name every new thread after the agent assigned to that work in the repository documentation; stage files by explicit path, never `git add -A` (the 2026-10-28 checkpoint instruction).
- *An environment fact, not a rule:* force-push is denied, so after a squash merge merge `origin/main` into your branch instead of rewriting it.
