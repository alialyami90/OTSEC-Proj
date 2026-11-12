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

**The owner chose option (b) for the passive sensor on 2026-11-11** (D4-85): a separate Linux machine at each site that feeds the node. It supersedes their choice of option (a) on 2026-11-10 (D4-78), after D4's evidence in PR #618 showed that under (a) Suricata's Windows build needs Npcap even to start, Zeek has no Windows binary, Npcap needs a paid licence, and its safe install mode is unknown (D4-84). The link's contracts, the engine run and the test rig are briefed (D4-86), and no sensor is built. [ADR-0009](docs/decisions/ADR-0009-passive-sensor.md) is accepted for option (b) on `main` (#618). D3's trust design for the link is merged (#624): `docs/phase4/D3-sensor-link.md`. The options are (a) Zeek or Suricata on the Windows site node with a capture driver, (b) a separate Linux sensor at each site that feeds the node, and (c) the project's own Go decoders in a separate process on the node. D1 recommended (b). The ADR's table gives the evidence for each.

**NEXT ACTION (D1):** carry the five briefs of "Phase 4 item 4, second part" to their results (D4-86): P4-4-S2, P4-4-L1, P4-4-L2, P4-4-L3 and P4-4-R1, in `docs/agent-handoffs.md`. On 2026-11-13 (D4-90): L1 to L5 are merged as documents, R1 is merged, and S2 is done. **The engine is approved: Zeek 9.0.1 with the project's script** (D1's ruling on #637, merged as `d6c2a7f6`), and Modbus on a moved port is a high risk that is not closed (HR-22, which D3 writes under P4-4-L6). **No contract is approved:** the cross-reviews that P4-4-L5 asked for failed C13 0.2 (D5, 6 findings, on #634) and the node's design (D4, 5 findings, on #633). **Next:** brief P4-4-L6 (D4, D5 and D3) amends them, and D1 then approves C13 0.2, the node's design, C7 0.11, C8 0.13 and C4 0.4 together. P4-4-E2 (the Modbus signature measured) and P4-D6-GT2 (the owed GT-PCAP cases) start too; P4-D6-RR, P4-D6-I100, P4-D6-MUT and P4-D7-2 are briefed (D4-88). Then bring the owner a recommendation on the sensor's host (O-1 to O-12), and issue the implementation briefs as the third part. **Until F-027's couplings F1 to F11 (`docs/verification.md`; `docs/phase4/D5-sensor-node.md` §1.0) are closed and tested, no configuration outside the tests carries a `network_sensor` section, no release ships, no caller of `ServeSensor` outside the tests merges, and no caller of `sensorlink.Link.Serve` other than `ServeSensor` (D4-87, D4-88).** After the sensor is built, D6 runs V-M6 over GT-PCAP, and D1 opens item 4's exit gate. Nothing on items 5 or 6 starts before the owner says so (D4-34).

## Open PRs and branches

- **Open PRs:** list them with `gh pr list`. #609, which adds `reference/` and `tools/` to `.gitignore` (D4-80), merged on 2026-11-10 as `cdbf61e8`. A PR that D1 wrote merges on D6's acceptance, and D1 merges it (D4-85). On 2026-11-11 at 15:10Z (D4-84): #615 (D7), #616 (D5) and #617 (D6) are merged. #612, #613 and #614 merged that day too (D4-85). #621 (D4-85) merged as `afc5a802`, and #622 (D4-86) as `1f5b307f`. Later that day (D4-87): #624 (D3's design of the sensor link) merged as `551b03dd`, #618 (D4, the sensor's evidence and ADR-0009's decision for option (b)) as `c9222b35`, and #623 (D6, GT-PCAP's new cases and the engine run's pass conditions) as `96c35ef8`. #620 (D4, the forwarder's rsyslog tests) merged as `8e29891e`, green after the hosted runners recovered; #627 (D4, C13 0.2, proposed) as `624beb58`; and #628 (D5, the node's side of the link) as `d06fdb86`. Later on 2026-11-11 (D4-88): #629 merged as `8ecdecc6`, #619 as `1f7ed8b5`, #625 as `17f746dc`, #626 as `4d0c7154`, #632 as `f771fec9`, #631 as `3176c60f` and #630 as `8f23629d`. #634 merged as `cdd7eebc`, #633 as `f93557b2` and #635 as `8cd5628e` (brief P4-4-L5). On 2026-11-12: #638 (D4-89, the rule on subagents) merged as `8a67c79d`, and #637 (D4's write-up of the counted engine run) as `d6c2a7f6`. #636 (D4-88) merged as `72f09c81` on 2026-11-12. D4-90 is the next PR of D1's. Each role's open items are in its file in `.claude/agents/`.
- **Branches.** The remote had 248 branches when this file was written, and 253 on 2026-11-10 at about 21:45Z (D4-81). The owner approved deleting 150 merged ones (D4-62), with the script `reference/carried/delete-merged-branches-2026-11-06.ps1`, in which each delete is leased to a recorded SHA. Four unmerged mutant branches are kept on purpose: `claude/b6-mut-acl-1`, `claude/b6-mut-acl-2`, `claude/b6-mut-unknown-restart` and `claude/b6-diag-expired-links`. D1 sorted the 102 branches that are not on the script into three groups, in `reference/carried/branch-cleanup-2026-11-10.md` (D4-81): 49 meet the owner's rule, 6 hold a tree that equals a commit on `main`, and 47 are kept. The owner approved the first two groups on 2026-11-11, and both scripts ran that day: 207 branches deleted, 49 left (D4-83). The third group stays.

## Waiting on the owner

1. **The sensor's host under option (b)** (D4-85): the hardware and the operating system of the Linux machine at each site, and who ships its image. D1 brings a recommendation. The choice of option (b) itself is made.
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
12. **D7 and D8** (D4-79): D7's first brief is done (#615, D4-84). Still owed: the word to start D8's first brief, and who holds the release key and where it is kept (TB9).
13. **Nothing: D1 merges its own reviewed PRs** (D4-85, which supersedes D4-82).
14. **Nothing: the owner chose option (b)** (D4-85).
15. **Nothing: D1 decided that mutants are committed as patch files with a dispatch-only workflow,** and no scratch branch is pushed (D4-85). D6's mutants for the closing legs are brief P4-D6-MUT (D4-88, D4-90).
16. **Switching on GitHub's private vulnerability reporting,** which `SECURITY.md` relies on (D4-85). `LICENSE.md` and `SECURITY.md` are added.
17. **Nothing: the owner leaves the fourteen firewall rules** that the approved prompts left for temporary test programs (D4-85).

## Test policy

1. **GitHub Actions first.** `ci.yml` (twenty-four jobs) and `govulncheck.yml` (one job) are the gate. The merge rules are in CLAUDE.md, "Testing and merging". When a head's CI is older than `main`, verify the merged result before merging.
2. **The owner's PC second.** It is the second Windows run, and the fallback when GitHub Actions is unavailable or a run needs a real installation. A local run never replaces a green CI run for a merge. Label a PC result with its class (`desk` for Go and Python tests, `simulated` for the real binaries against the simulator), the Windows version and the commit SHA.
3. **Never register the PC as a GitHub self-hosted runner,** and never put machine keys on it. The repository is public, so any outside PR could run code on a self-hosted runner.

Limits on the PC:

- **Run no package in full that holds a listener on an address other than loopback** (`tests/security`, `tests/integration/syslogreceive`). Each run raises a Windows Firewall prompt for the owner, and one test listens on the PC's own LAN address. Run tests by name with `-run`, and never with a pattern that matches `TestD210CollectorRefusesNonLoopback` (`tests/security/collector_lock_test.go`) or `TestDualStackKeysByIPv4` (`tests/integration/syslogreceive/receive_test.go`); GitHub Actions runs the full set (D4-84). D6 owes a change so that those tests bind off loopback only on CI, and fail there if skipped, before the next local run of either package.
- A run that is not elevated skips 162 of `platform/node`'s tests. State the skip count with any result from the PC (D4-84).
- Install nothing beyond what the owner approved: a portable Go inside the project folder, and a Python venv inside it with `pytest` and `asyncssh==2.24.1`. No installer, no admin rights requested, no system settings, no permanent PATH change, no pip install outside the venv.
- A run that creates Windows services happens only in the owner's own elevated session, with the owner present, or on the GitHub-hosted runner.
- Every endpoint is the simulator on loopback. No device, and no site network.

Other rules that hold: re-run a failing job at most once (one exception, for D1 alone: a job that failed in a set-up step before any project code ran, with its failing line quoted on the PR, may be re-run again once the same step has passed in another run in this repository, or 60 minutes after it last failed, at most three times by the clock for one head; each such re-run is recorded on the PR, D4-85; and a job in which project code ran counts as a set-up failure under that exception when all of these hold: a set-up step of that job failed, and its failing line is quoted on the PR; every test that failed in the job failed on its own required-and-missing check for what that step installs, and the message that names the missing thing is quoted on the PR; and nothing else in the job failed: no assertion, timeout, panic, build error or connection error. A test that fails in any other way is a first result and gets the ordinary single re-run, and D6 confirms the three points from the job's log when it reviews the green run (D6 on #629, D4-88)); never push an empty commit to retrigger CI; never call a timeout or a property failure a flake; a failure in code the PR doesn't touch is a finding to reproduce against `main`; before opening a code PR, check the latest scheduled run on `main`.

The toolchain is Go 1.27.3 (`go.mod`), 64-bit. A 32-bit build is not a declared target (D4-72).

## Working in the CLI

- **Start `claude` inside `OTSEC-Proj`.** The agent files are found from the working directory up to the repository root, so a session started in the folder above the checkout loads none of them. Check with `/agents`.
- **The main session acts as D1** and calls D2 to D8 as subagents with a bounded brief (CLAUDE.md section 5.2). `records-auditor` and `ci-triage` are helper agents that own no path. The first checks a documentation PR before its review, and is read-only by instruction: its Bash tool is not restricted. The second reads a failed CI run from files D1 saves for it, and has no tool that can change anything.
- **Independent review means a separate subagent.** D6 reviews in its own subagent, from the requirement and the contract text. Never report a review that one context did of its own work as independent.
- **Only the agents in `.claude/agents/` run, and one instance of each role at a time** (the owner's rule, D4-89; CLAUDE.md, "Subagents"). `.claude/settings.json` wires `.claude/hooks/agent_guard.py`, which refuses any other agent type and a second instance of a role that is running, and it denies the `Workflow` tool. Two tasks for one role run one after the other. The helpers `ci-triage` and `records-auditor` are the exception: each may run several instances at once. The hook's tests run by name, with the venv's Python on the PC: `tools\venv\Scripts\python.exe -m pytest -q .claude/hooks/test_agent_guard.py`.
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
- **Go, `gofmt` and pytest do not read `.gitignore`,** so from the repository root they can walk into the two folders. The first run on 2026-11-11 showed it: `go list ./...` failed on a folder under `reference/` that the user cannot read, until `reference/` and `tools/` each got a one-line `go.mod` (local files, D4-83). Tests that walk the tree met the same folder, and brief P4-PC-1 fixed them (#617, D4-84). Before a run:
  - Check that `go list ./...` names only `otsec.local/otsec` packages. If it names anything under `tools/` or `reference/`, give each of the two folders a one-line `go.mod`, so that Go treats it as another module, and check again.
  - Run `gofmt` on tracked files only, as CI does, and not `gofmt -l .`: `gofmt -l $(git ls-files '*.go' | grep -v '^platform/experiments/')`.
  - Run `python -m pytest -q --ignore=tools --ignore=reference`.
  - CI is not affected, because neither folder is in the repository.
- `tools/go` ran on the PC on 2026-11-11 (Go 1.27.3, `windows/amd64`). Go is not on the PATH: call `tools\go\bin\go.exe`, or set `PATH` for the session only, with `GOCACHE`, `GOPATH` and `APPDATA` pointing into `tools/` and `GOTOOLCHAIN=local`.
- Claude Code keeps each subagent's worktree in `.claude/worktrees/` inside the checkout. `.git/info/exclude` on the PC lists it. Each worktree has the repository's own `go.mod`, so `go list ./...` skips it, and a test that walks the tree does not (P4-PC-1).
- The Python venv is `tools/venv`, created on 2026-11-12 with `pytest` 9.2.0 and `asyncssh` 2.24.1 (D4-89). Call `tools\venv\Scripts\python.exe -m pytest`; the system Python has no `pytest`.
- Eleven test files still carry paths into a shared folder that no longer exists (the eight SEL-751 register goldens, two files under `tests/integration/gt_mib/`, and `contracts/adapter/testdata/snmp/README.md`). The goldens are pinned by checksum, so the owner left them. The paths are citations only, and nothing opens them.

## First session in the CLI

1. In `OTSEC-Proj`, run `git status` and `git log -1`, and compare with `origin/main`.
2. Check the toolchain: `go version` must report 1.27.3 on `windows/amd64`. Use `$(go env GOROOT)/bin/gofmt`.
3. If `tools/venv` is missing, create it with `python -m venv tools/venv` and install `pytest` and `asyncssh==2.24.1` into it. Nothing else is installed.
4. The owner lifted D4-12 on 2026-11-11 (D4-83). Make the `go list` check above, then run `go vet ./...` and `gofmt` in the forms given above for the PC. Run `go test` by package or by name, never `./...`: the limits above keep `tests/security` and `tests/integration/syslogreceive` from running in full here (D4-84). State the skip count with the result.
5. Check the latest `ci` and `govulncheck` runs on `main`.
6. Follow the next action above. The owner answered the ADR-0009 question on 2026-11-10 (D4-78).
