# Handoff: the move to Claude Code CLI

Owner of this file: D1. Written 2026-11-10, with `main` at `82daa04` (#604). The project owner is moving the work from Claude project threads to Claude Code CLI on their own PC. This file is what a fresh CLI session needs to continue. Everything in it is `desk` evidence read from the repository, the decision log, GitHub and the role threads on 2026-11-10.

## Reading order

1. [CLAUDE.md](CLAUDE.md), the project brief. It governs all work.
2. This file.
3. [handoffs/HANDOFF-SUMMARY.md](handoffs/HANDOFF-SUMMARY.md): the agent map, the review pairs and the owner's standing rules. It was written on 2026-11-06 for the C-to-D handoff, so its "next action" lines are done. Where it differs from this file, this file wins.
4. Your role's file in [.claude/agents/](.claude/agents/), then `handoffs/D{n}-handoff.md` for that role's lessons.
5. [docs/phase4/B1-decisions.md](docs/phase4/B1-decisions.md) from D4-58 to D4-76.

## Where the work stands

| Phase | Result |
| --- | --- |
| 0 to 3 | Passed with conditions and accepted by the owner (2026-10-23 to 2026-10-27) |
| 4, items 1 and 2: configuration baselines, the event-behaviour baseline | Accepted 2026-11-05 (D4-48) |
| 4, item 3: vulnerability applicability with the asset module | Accepted 2026-11-06 (D4-62); report in `docs/phase-4-item3-exit.md` |
| Hardening P4-H1 to P4-H4 | Merged by 2026-11-07 (D4-63, D4-65) |
| 4, item 4: network IDS | **In progress.** Contracts approved (D4-68). The node side is built and merged (D4-70 to D4-76, #545 to #604). The sensor is not briefed |
| 4, items 5 and 6: secure engineering access, the central role | Not briefed |

**What is on `main`.** Two Go binaries: `cmd/otsec` (the site node) and `cmd/otsec-collector` (the privileged collector). For item 4 the node now has the sensor intake with its hold for the node's own sessions, the two network store classes, the detector consumer and its checkpoints, alert retention, alert drop counts by rule and asset, `sensor-unreachable`, the network baseline acknowledgement (C7 0.10, C8 0.12), and one full alarm per fill. C13 `otsec.netobs/0.1`, C4 0.3, C5 0.9 and C2 0.9 are coded. No sensor process exists yet, and nothing captures traffic.

**Evidence ceiling.** Every result is `desk`, `simulated`, `CI-Linux` or `CI-Windows`. No device has been contacted, nothing is `hardware-verified`, and no SEL family may be called supported.

**CI on `main` at `82daa04`.** `ci` passed on the push ([run 42506206650](https://github.com/alialyami90/OTSEC-Proj/actions/runs/42506206650)). The weekly `govulncheck` passed on 2026-11-09 ([run 42629797940](https://github.com/alialyami90/OTSEC-Proj/actions/runs/42629797940)).

## The one blocker, and the next action

**The owner has not yet chosen where the passive sensor runs** ([ADR-0009](docs/decisions/ADR-0009-passive-sensor.md), still `proposed`). The options are (a) Zeek or Suricata on the Windows site node with a capture driver, (b) a separate Linux sensor at each site that feeds the node, and (c) the project's own Go decoders in a separate process on the node. D1 recommended (b). The ADR's table gives the evidence for each.

**NEXT ACTION (D1):** get the owner's choice. Then mark ADR-0009 accepted with D4, record the choice and this move as D4-77, and write the sensor's implementation brief in `docs/agent-handoffs.md`. The points that brief must carry are listed in `.claude/agents/d1-principal-architect.md`. After the sensor is built, D6 runs V-M6 over GT-PCAP, and D1 opens item 4's exit gate. Nothing on items 5 or 6 starts before the owner says so (D4-34).

## Open PRs, branches and work in progress

- **Open PRs: none** besides the one that adds this file. Every PR from #487 to #604 is merged or closed.
- **Each role reports nothing in flight** (role threads, 2026-11-08). The per-role open items are in `.claude/agents/`.
- **Branches.** The remote still has 248 branches. The owner approved deleting 150 merged ones on 2026-11-06 (D4-62), and the script for it, `d1/delete-merged-branches-2026-11-06.ps1` in the shared folder, has not been run. Each delete in it is leased to a recorded SHA. Re-check the list before running it, because branches merged after 2026-11-06 are not on it. Four unmerged mutant branches are kept on purpose: `claude/b6-mut-acl-1`, `claude/b6-mut-acl-2`, `claude/b6-mut-unknown-restart` and `claude/b6-diag-expired-links`.
- **Work-in-progress files in the shared folder.** They were the safety copies agents saved before a session ended. No PR is open, so none of them is known to hold unmerged work, but they were not checked one by one against `main`. Treat each as history unless its role's notes say otherwise.

| Shared-folder path | What it is | Status on 2026-11-10 |
| --- | --- | --- |
| `d1/open-items.md` | D1's running log, 2026-11-06 to 2026-11-08 | Current to #604. Its last line names this blocker |
| `d6-wip/gt-pcap-next-plan-edits.md` | D6's queue of 24 GT-PCAP edits and cases | **Live.** Check each against `main` before V-M6 |
| `d6-wip/*.patch`, `d6-wip/*_test.go.txt` | D6's probes and test patches for #564 to #601 | Their PRs merged; history |
| `d5-wip/b5-intake-step2-plan.md` | D5's plan for the intake hold | Built in #576 and #584; history |
| `d4-wip/2026-11-06-c12-0.2.patch`, `d3-wip/c7-0.9.patch`, `d2/c1-engine-id-70b01ec.patch` | Contract patches | Merged (#507 to #513, #497, #498); history |
| `d4-c13-draft/`, `d3-c7-c8-draft/`, `d2-reviews/` | Drafts and reviews of item 4's contracts | Approved texts are in `docs/phase4/`; history |
| `d3/snmpv3-multi-credential-notes.md`, `d6/vm1-runner-notes.md`, `d2/gt-mib-points-2026-11-06.md` | Notes for V-M1 | V-M1 passed (#496, #501); reference |
| `rfc/` | The twelve RFC texts with `SHA256SUMS` (D4-58) | Reference; GT-MIB was built from them |
| `phase0/manuals-SEL/`, `phase0/datasheets-SEL/` | SEL manuals and datasheets, as PDF and as text | Reference. Not in the repository, because they are large and not ours to publish |
| `a*/`, `b*/`, `c*/`, `phase1/` to `phase4/` | Earlier generations' notes, probes and patches | History |

## Waiting on the owner

1. **Where the sensor runs** (ADR-0009). This blocks item 4.
2. **The sites' networks:** which protocols run on them, whether a site can give a SPAN port or a TAP, and whether the station network is PRP (D4-66).
3. **R6.7's insecure list:** should it add IEC 104, MMS and GOOSE, C37.118, EtherNet/IP, Fast Operate inside Telnet, SNMPv3 noAuthNoPriv, AMT's redirection ports, and raw TCP serial tunnels (D4-68)?
4. **May the DNP3 Secure Authentication text** (IEEE 1815's SA clause or IEC 62351-5) be placed in the shared folder (D4-68)?
5. **HR-18:** who publishes the advisory set and holds its signing key. No real advisory is entered until then.
6. **Item 3's questions:** severity scores in reports; the v1/v2c approval key if such a path is ever added (HR-17); which SEL switches the sites run; model naming for set authors (`SEL-2731M`).
7. **From D4-65:** should the reserve fail on volumes that can't hold real space (compressed or copy-on-write)? Should the store get a Windows folder flush? Should the rare starts over 6 s be briefed?
8. **Authorization for any device contact:** a lab relay or switch before any H-test or Q3, and any SNMPv3 contact.
9. **Test runs on the owner's PC** are paused since 2026-10-27 (D4-12). See the first process question below.
10. **Running the branch-cleanup script** (above).
11. **STALLED:** ADR-0007 (Windows site node) is still `proposed`, unchanged since generation A.

## Test policy

In priority order (D2-13, D4-3, and the owner's project instructions):

1. **GitHub Actions first.** `ci.yml` (nineteen jobs) and `govulncheck.yml` (one job) are the gate. A PR merges when its reviewers accept it and every job in both is green on its head. A PR that touches GT-PCAP also needs `a6-gt-pcap` green. A PR that changes only Markdown or other document files outside a `testdata` directory skips both and merges on review. When a head's CI is older than `main`, verify the merged result before merging.
2. **The owner's PC second.** It is the second Windows run, and the fallback when GitHub Actions is unavailable or a run needs a real installation. A local run never replaces a green CI run for a merge. Label a PC result `simulated`, with the Windows version and the commit SHA.
3. **Never register the PC as a GitHub self-hosted runner,** and never put machine keys on it. The repository is public, so any outside PR could run code on a self-hosted runner.

Limits on the PC, from the owner's standing rules:

- Install nothing beyond what the owner approved: a portable Go inside the project folder, and a Python venv inside it with `pytest` and `asyncssh==2.24.1`. No installer, no admin rights requested, no system settings, no permanent PATH change, no pip install outside the venv.
- A run that creates Windows services happens only in the owner's own elevated session, with the owner present, or on the GitHub-hosted runner.
- Every endpoint is the simulator on loopback. No device, and no site network.

Other rules that hold: re-run a failing job at most once; never push an empty commit to retrigger CI; never call a timeout or a property failure a flake; a failure in code the PR doesn't touch is a finding to reproduce against `main`; before opening a code PR, check the latest scheduled run on `main`.

Commands are in CLAUDE.md's repository-state section. The toolchain is Go 1.27.3 (`go.mod`), 64-bit; a 32-bit build is not a declared target (D4-72).

## How the team maps onto Claude Code CLI

- **The six roles are subagents** in `.claude/agents/`: `d1-principal-architect`, `d2-ied-integration`, `d3-security-access`, `d4-telemetry-ids`, `d5-platform`, `d6-verification-safety`. Each file holds the role's scope, owned paths, reviewers, standing rules and open items.
- **The main session acts as D1,** as CLAUDE.md §10 already says, and calls D2 to D6 as subagents with a bounded brief (§5.2). A subagent starts with no memory of earlier work, so the brief names the files to read.
- **The coordinator's job moves into the main session.** Subagents report only to the session that called them, so every message between roles still passes through one place (D4-58).
- **Independent review still means a separate agent.** D6 reviews in its own subagent, from the requirement and the contract text. Never report a review that one context did of its own work as independent (§5.3).
- **Branches.** Use the brief's convention (`agent/ied-*`, `agent/security-*`, `agent/telemetry-*`, `agent/platform-*`, `agent/verification-*`), one `git worktree` per agent working at the same time, and one PR per branch. Stage by explicit path.
- **The shared folder.** Records cite `/mnt/project-files/...`. That path exists only in the Claude project. On the owner's PC the same tree is the `project-files` folder beside this checkout, so read `/mnt/project-files/X` as `../project-files/X`.
- **GitHub.** The cloud sessions could not force-push or delete a branch. A CLI session uses the owner's own credentials and can, so the rules now carry the weight the tooling used to: never force-push a shared branch, and delete only branches on a list the owner approved.

## Two process questions for the owner

These are the owner's rules, so D1 asks and does not assume.

1. **PC test runs (D4-12).** They have been paused since 2026-10-27. Working in the CLI on the PC makes local `go vet`, `gofmt` and `go test` the natural first check. Recommended: lift the pause for ordinary local runs under the limits above, and keep service-creating runs for the owner's elevated session.
2. **The coordinator rule (D4-58).** Recommended: the main session takes the coordinator's part, as described above.

D1 records both answers, with the move itself, as D4-77.

## The project folder on the owner's PC

The layout below is the one proposed to the owner on 2026-11-10. It is in force only once they confirm it.

```text
OTSEC/
├── OTSEC-Proj/      the only checkout of this repository; start `claude` here
├── project-files/   a copy of the Claude project's shared folder (history, RFC texts, work-in-progress notes)
├── reference/       SEL datasheets and manuals (PDF), outside the repository
└── tools/           portable Go 1.27.3 (64-bit), the Go caches, and the Python venv
```

The tool folders stay outside the checkout so that `go vet ./...` and `gofmt -l .` never walk into a Go distribution or a module cache.

## First session in the CLI

1. In `OTSEC-Proj`, run `git status` and `git log -1`, and compare with `origin/main`.
2. Check the toolchain: `go version` must report 1.27.3 on `windows/amd64`. Use `$(go env GOROOT)/bin/gofmt`.
3. If `tools/venv` is missing, create it with `python -m venv ../tools/venv` and install `pytest` and `asyncssh==2.24.1` into it. Nothing else is installed.
4. If the owner has lifted D4-12, run `go vet ./...`, `gofmt -l .` and `go test ./...`, and say plainly which packages need a longer timeout on Windows (`platform/node`, D4-44).
5. Check the latest `ci` and `govulncheck` runs on `main`.
6. Ask the owner the ADR-0009 question as one decision with D1's recommendation, then follow the next action above.
