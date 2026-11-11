# Handoff: continuing in Claude Code CLI

Written by D1 on 2026-11-10, with `main` at `82daa04` (#604). The work moved from Claude project threads to Claude Code CLI on the owner's PC. This file is what a CLI session needs to continue. Everything in it is `desk` evidence, read from the repository, the decision log and GitHub on that day.

Read [CLAUDE.md](CLAUDE.md) first, then this file, then your role's file in [.claude/agents/](.claude/agents/). For the reasons behind recent work, read [docs/phase4/B1-decisions.md](docs/phase4/B1-decisions.md) from D4-58 to its last entry.

## Where the work stands

| Phase | Result |
| --- | --- |
| 0 to 3 | Accepted by the owner |
| 4, items 1 and 2: configuration baselines, the event-behaviour baseline | Accepted (D4-48) |
| 4, item 3: vulnerability applicability with the asset module | Accepted (D4-62); report in `docs/phase-4-item3-exit.md` |
| 4, item 4: network IDS | **In progress.** Contracts approved (D4-68). The node side is merged (D4-70 to D4-76). The sensor is not briefed |
| 4, items 5 and 6: secure engineering access, the central role | Not briefed |

**What is on `main`.** Two Go binaries: `cmd/otsec` (the site node) and `cmd/otsec-collector` (the privileged collector). For item 4 the node has the sensor intake with its hold for the node's own sessions, the two network store classes, the detector consumer and its checkpoints, alert retention, alert drop counts by rule and asset, `sensor-unreachable`, the network baseline acknowledgement (C7 0.10, C8 0.12), and one full alarm per fill. C13 `otsec.netobs/0.1`, C4 0.3, C5 0.9 and C2 0.9 are coded. No sensor process exists yet, and nothing captures traffic.

**Evidence ceiling.** Every result is `desk`, `simulated`, `CI-Linux` or `CI-Windows`. No device has been contacted, nothing is `hardware-verified`, and no SEL family may be called supported.

**CI on `main` at `82daa04`.** `ci` passed on the push ([run 42506206650](https://github.com/alialyami90/OTSEC-Proj/actions/runs/42506206650)). The weekly `govulncheck` passed on 2026-11-09 ([run 42629797940](https://github.com/alialyami90/OTSEC-Proj/actions/runs/42629797940)).

## The one blocker, and the next action

**The owner chose option (a) for the passive sensor on 2026-11-10** (D4-78), **and on 2026-11-11 wrote "i want to continue progress on project phases or gates"**. D1 reads that as the word to start the evidence work, and the owner's confirmation is owed (D4-83). D4 is gathering the evidence for the engine choice under brief P4-4-S1. No sensor is briefed. [ADR-0009](docs/decisions/ADR-0009-passive-sensor.md) is still `proposed`. The options are (a) Zeek or Suricata on the Windows site node with a capture driver, (b) a separate Linux sensor at each site that feeds the node, and (c) the project's own Go decoders in a separate process on the node. D1 recommended (b). The ADR's table gives the evidence for each.

**NEXT ACTION (D1):** review D4's findings under P4-4-S1, put the Npcap OEM licence question to the owner with the real terms, choose the engine with D4 (D4-78), mark ADR-0009 accepted with D4, and write the sensor's implementation brief in `docs/agent-handoffs.md`. The points that brief must carry are listed in `.claude/agents/d1-principal-architect.md`. After the sensor is built, D6 runs V-M6 over GT-PCAP, and D1 opens item 4's exit gate. Nothing on items 5 or 6 starts before the owner says so (D4-34).

## Open PRs and branches

- **Open PRs:** list them with `gh pr list`. #609, which adds `reference/` and `tools/` to `.gitignore` (D4-80), merged on 2026-11-10 as `cdbf61e8`. A PR that D1 wrote merges on D6's acceptance and the owner's word (D4-82). On 2026-11-11 at 15:10Z (D4-84): #615 (D7), #616 (D5) and #617 (D6) are merged. Open: #612, #613 and #614, reviewed, waiting for the owner's words; #618 (D4, the sensor's evidence), passed by D3, waiting for the owner's confirmation and choice; #619 (D6, the closing legs), four legs green, waiting for #620; #620 (D4, the forwarder's rsyslog tests), blocked by the hosted runners' failure to reach Ubuntu's package archive. Each role's open items are in its file in `.claude/agents/`.
- **Branches.** The remote had 248 branches when this file was written, and 253 on 2026-11-10 at about 21:45Z (D4-81). The owner approved deleting 150 merged ones (D4-62), with the script `reference/carried/delete-merged-branches-2026-11-06.ps1`, in which each delete is leased to a recorded SHA. Four unmerged mutant branches are kept on purpose: `claude/b6-mut-acl-1`, `claude/b6-mut-acl-2`, `claude/b6-mut-unknown-restart` and `claude/b6-diag-expired-links`. D1 sorted the 102 branches that are not on the script into three groups, in `reference/carried/branch-cleanup-2026-11-10.md` (D4-81): 49 meet the owner's rule, 6 hold a tree that equals a commit on `main`, and 47 are kept. The owner approved the first two groups on 2026-11-11, and both scripts ran that day: 207 branches deleted, 49 left (D4-83). The third group stays.

## Waiting on the owner

1. **The sensor under option (a)** (ADR-0009, D4-78): whether an Npcap OEM licence is acceptable. D1 asks with D4's findings (D4-83). This blocks item 4.
2. **The sites' networks:** which protocols run on them, whether a site can give a SPAN port or a TAP, and whether the station network is PRP (D4-66).
3. **R6.7's insecure list:** should it add IEC 104, MMS and GOOSE, C37.118, EtherNet/IP, Fast Operate inside Telnet, SNMPv3 noAuthNoPriv, AMT's redirection ports, and raw TCP serial tunnels (D4-68)?
4. **May the DNP3 Secure Authentication text** (IEEE 1815's SA clause or IEC 62351-5) be given to the project, in `reference/` (D4-68)?
5. **HR-18:** who publishes the advisory set and holds its signing key. No real advisory is entered until then.
6. **Item 3's questions:** severity scores in reports; the v1/v2c approval key if such a path is ever added (HR-17); which SEL switches the sites run; model naming for set authors (`SEL-2731M`).
7. **From D4-65:** should the reserve fail on volumes that can't hold real space (compressed or copy-on-write)? Should the store get a Windows folder flush? Should the rare starts over 6 s be briefed?
8. **Authorization for any device contact:** a lab relay or switch before any H-test or Q3, and any SNMPv3 contact.
9. **Test runs on the owner's PC** are resumed for ordinary local runs (D4-83, 2026-11-11). Runs that create Windows services stay in the owner's elevated session. Nothing is owed here.
10. **The branch cleanup is done** (D4-83). Nothing is owed here.
11. **ADR-0007** (Windows site node) is still `proposed`.
12. **D7 and D8** (D4-79): D7's first brief is in flight (D4-83). Still owed: the word to start D8's first brief, and who holds the release key and where it is kept (TB9).
13. **The words to merge a PR that D1 wrote** (D4-82). On 2026-11-11 these are #612 and #613, which merge together, and then #614.
14. **The sensor: the choice among (a), (b) and (c′)** with D4's findings and Npcap's prices in front of them, and whether the platform serves their own sites only or is delivered to others (D4-84).
15. **Whether scratch mutant branches may be pushed** (D4-84). Until then D6's mutants for the closing legs are owed.
16. **A `LICENSE` and a `SECURITY.md`** for the public repository (D4-84).
17. **Optional, on the PC:** removing the fourteen `Allow` firewall rules that the approved prompts left for temporary test programs. It needs an elevated shell (D4-84).

## Test policy

1. **GitHub Actions first.** `ci.yml` (nineteen jobs) and `govulncheck.yml` (one job) are the gate. The merge rules are in CLAUDE.md, "Testing and merging". When a head's CI is older than `main`, verify the merged result before merging.
2. **The owner's PC second.** It is the second Windows run, and the fallback when GitHub Actions is unavailable or a run needs a real installation. A local run never replaces a green CI run for a merge. Label a PC result with its class (`desk` for Go and Python tests, `simulated` for the real binaries against the simulator), the Windows version and the commit SHA.
3. **Never register the PC as a GitHub self-hosted runner,** and never put machine keys on it. The repository is public, so any outside PR could run code on a self-hosted runner.

Limits on the PC:

- **Run no package in full that holds a listener on an address other than loopback** (`tests/security`, `tests/integration/syslogreceive`). Each run raises a Windows Firewall prompt for the owner, and one test listens on the PC's own LAN address. Run tests by name with `-run`; GitHub Actions runs the full set (D4-84).
- A run that is not elevated skips 162 of `platform/node`'s tests. State the skip count with any result from the PC (D4-84).
- Install nothing beyond what the owner approved: a portable Go inside the project folder, and a Python venv inside it with `pytest` and `asyncssh==2.24.1`. No installer, no admin rights requested, no system settings, no permanent PATH change, no pip install outside the venv.
- A run that creates Windows services happens only in the owner's own elevated session, with the owner present, or on the GitHub-hosted runner.
- Every endpoint is the simulator on loopback. No device, and no site network.

Other rules that hold: re-run a failing job at most once; never push an empty commit to retrigger CI; never call a timeout or a property failure a flake; a failure in code the PR doesn't touch is a finding to reproduce against `main`; before opening a code PR, check the latest scheduled run on `main`.

The toolchain is Go 1.27.3 (`go.mod`), 64-bit. A 32-bit build is not a declared target (D4-72).

## Working in the CLI

- **Start `claude` inside `OTSEC-Proj`.** The agent files are found from the working directory up to the repository root, so a session started in the folder above the checkout loads none of them. Check with `/agents`.
- **The main session acts as D1** and calls D2 to D8 as subagents with a bounded brief (CLAUDE.md section 5.2). `records-auditor` and `ci-triage` are helper agents that own no path. The first checks a documentation PR before its review, and is read-only by instruction: its Bash tool is not restricted. The second reads a failed CI run from files D1 saves for it, and has no tool that can change anything.
- **Independent review means a separate subagent.** D6 reviews in its own subagent, from the requirement and the contract text. Never report a review that one context did of its own work as independent.
- **Branches.** One branch and one PR per task, and one `git worktree` per role working at the same time. Stage by explicit path.
- **Working files** go in the repository, or in a scratch folder outside it that no record cites. A file that a record must cite goes in the repository or in `reference/`.
- **GitHub.** A CLI session uses the owner's own credentials and can force-push and delete branches. Never force-push a shared branch, and delete only branches on a list the owner approved.

## The project folder on the owner's PC

```text
OTSEC-Proj/          the only checkout of this repository; start `claude` here
├── reference/       files that records cite; ignored by Git, never committed
└── tools/           portable Go 1.27.3 for 64-bit Windows in `tools/go`, the Go caches, and the Python venv; ignored by Git
```

| In `reference/` | What it holds |
| --- | --- |
| `manuals-SEL/` | The SEL manuals (PDF) and their text in `text/` |
| `datasheets-SEL/` | The SEL datasheets |
| `rfc/` | The twelve RFC texts with `SHA256SUMS` (D4-58) |
| `carried/` | D1's log to #604 (`d1-open-items.md`), D6's queue of GT-PCAP cases (`d6-gt-pcap-next-plan-edits.md`, **live**), the branch-cleanup script, and the evidence files that records cite |
| `pc-logs/` | Logs from earlier runs on the owner's PC, including the 2026-10-27 run that `docs/verification.md` cites |

- **`reference/` and `tools/` are inside the checkout since 2026-11-10 (D4-80), and neither is ever committed.** The repository is public, and `reference/` holds vendor manuals and logs from the owner's PC. `.gitignore` lists both since #609 merged, and `.git/info/exclude` on the PC still lists them too. Stage by explicit path, as always.
- **Never run `git clean -x`, `git clean -X` or `git stash --all` in this checkout.** Each removes or moves ignored files, so each would take both folders, and `reference/carried/` holds files that are in use.
- **Go, `gofmt` and pytest do not read `.gitignore`,** so from the repository root they can walk into the two folders. The first run on 2026-11-11 showed it: `go list ./...` failed on a folder under `reference/` that the user cannot read, until `reference/` and `tools/` each got a one-line `go.mod` (local files, D4-83). Tests that walk the tree met the same folder, and brief P4-PC-1 fixes them. Before a run:
  - Check that `go list ./...` names only `otsec.local/otsec` packages. If it names anything under `tools/` or `reference/`, give each of the two folders a one-line `go.mod`, so that Go treats it as another module, and check again.
  - Run `gofmt` on tracked files only, as CI does, and not `gofmt -l .`: `gofmt -l $(git ls-files '*.go' | grep -v '^platform/experiments/')`.
  - Run `python -m pytest -q --ignore=tools --ignore=reference`.
  - CI is not affected, because neither folder is in the repository.
- `tools/go` ran on the PC on 2026-11-11 (Go 1.27.3, `windows/amd64`). Go is not on the PATH: call `tools\go\bin\go.exe`, or set `PATH` for the session only, with `GOCACHE`, `GOPATH` and `APPDATA` pointing into `tools/` and `GOTOOLCHAIN=local`.
- Claude Code keeps each subagent's worktree in `.claude/worktrees/` inside the checkout. `.git/info/exclude` on the PC lists it. Each worktree has the repository's own `go.mod`, so `go list ./...` skips it, and a test that walks the tree does not (P4-PC-1).
- The Python venv does not exist yet. Create it as `tools/venv` (step 3 below).
- Eleven test files still carry paths into a shared folder that no longer exists (the eight SEL-751 register goldens, two files under `tests/integration/gt_mib/`, and `contracts/adapter/testdata/snmp/README.md`). The goldens are pinned by checksum, so the owner left them. The paths are citations only, and nothing opens them.

## First session in the CLI

1. In `OTSEC-Proj`, run `git status` and `git log -1`, and compare with `origin/main`.
2. Check the toolchain: `go version` must report 1.27.3 on `windows/amd64`. Use `$(go env GOROOT)/bin/gofmt`.
3. If `tools/venv` is missing, create it with `python -m venv tools/venv` and install `pytest` and `asyncssh==2.24.1` into it. Nothing else is installed.
4. The owner lifted D4-12 on 2026-11-11 (D4-83). Make the `go list` check above, then run `go vet ./...`, `gofmt` and `go test ./...` in the forms given above for the PC, and say plainly which packages need a longer timeout on Windows (`platform/node`, D4-44).
5. Check the latest `ci` and `govulncheck` runs on `main`.
6. Follow the next action above. The owner answered the ADR-0009 question on 2026-11-10 (D4-78).
