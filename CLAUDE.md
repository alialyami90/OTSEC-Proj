# CLAUDE.md

This file is the project brief. It governs how all work in this repository is planned, implemented, reviewed and reported. The first part holds the current state, the commands and the owner's rules. The second part is the brief itself, and its section numbers (1 to 10) and principle numbers (P1 to P10) are cited across the repository, so they stay fixed.

## Current state

OTSEC is a modular OT cybersecurity platform for electrical substations, SCADA environments, IEDs and industrial control networks. The product code is two Go binaries:

- `cmd/otsec` is the site node.
- `cmd/otsec-collector` is the privileged collector. It alone holds device credentials and opens device sessions.

Where the work stands (D1 keeps this list current):

- **Phases 0 to 3 are accepted by the owner:** the evidence phase, contracts C1 to C8, the simulated SEL-751 SER-to-Syslog slice, and its hardening. The reports are `docs/phase-0-exit.md` to `docs/phase-3-exit.md`.
- **Phase 4 items 1 to 3 are accepted:** configuration monitoring, the event-behaviour baseline, and vulnerability applicability with the asset module. The reports are `docs/phase-4a-exit.md` and `docs/phase-4-item3-exit.md`.
- **Phase 4 item 4, the network IDS, is in progress.** The contracts approved in D4-68 and D4-69 and the node's intake and detector built on them are merged (D4-70 to D4-76). The owner chose option (b) for the sensor on 2026-11-11: a separate Linux machine at each site that feeds the node (D4-85, which supersedes the choice of option (a) in D4-78). ADR-0009 is accepted for option (b), and its engine is approved: Zeek 9.0.1 with the project's script, on the counted engine run (D1's ruling on #637, D4-90). No configuration tested identifies Modbus on a moved port, and the measured content signature was not adopted (HR-22, D4-94). **The link's contracts are approved** (D4-92): C13 0.2, the node's design, C7 0.11, C8 0.13 and C4 0.4, with three open high risks (HR-22, HR-23, HR-24), none of which closes on the owner's acceptance; HR-23 and HR-24 must close on a measured fix before item 4's gate, and HR-22 stands open at the gate (D4-95, D4-98). P4-4-L7 is merged. The third part has begun (D4-96): P4-4-F27's steps 1 to 3 and step 4's link-key reader are merged (#662, #663, #676, #672), and HR-24's detector design is approved as a document (#664). HR-23's fix design (option (i)) is merged, and C2 0.10, C13 0.3 and SL-3 are approved, with HR-25 recorded as a new high risk (D4-102). `HANDOFF.md`'s later checkpoint of 2026-11-14 has the next steps. No sensor is built.
- `HANDOFF.md` has the next action, the questions waiting on the owner, and the folder layout on the owner's PC. Read it after this file.

Every result so far is `desk` or `simulated`. No device has been contacted, and no device family may be called supported.

Where things are recorded:

- Decisions: `docs/phase4/B1-decisions.md` for Phase 4 (D4-*n*), `docs/phase1/` to `docs/phase3/` for the earlier phases, and the ADRs in `docs/decisions/`.
- Task briefs: `docs/agent-handoffs.md`.
- Requirements, architecture, the threat model, device capabilities and verification: the files of those names under `docs/`.
- In older records, A*n*, B*n* and C*n* name the role that is now D*n*. Contract names (C1 to C13) are not role names.

## Repository layout

- `contracts/` holds the shared contracts and their tests.
- `modules/` holds the per-role packages.
- `platform/` holds the store, the node runtime and the Windows service support.
- `tests/` holds the verification tests.
- `docs/` holds the documents listed above.
- `.claude/agents/` holds the eight roles as subagents, and two helper agents that own no path. `.claude/settings.json` and `.claude/hooks/` hold the hook that limits which subagents run.

The ownership table is in `README.md`. The manuals, datasheets and RFC texts that records cite are in `reference/`. On the owner's PC it sits inside the checkout, beside `tools/`. Git ignores both folders, and neither is ever committed.

The runtime language is Go (ADR-0003, `go.mod` at Go 1.27.3). Python is used only for verification tooling.

## Commands

Run these from the repository root. The root Go module is `otsec.local/otsec`. `platform/experiments/phase0/` is a separate module and is not built by these.

- Build and vet: `go vet ./...`
- Format check: `gofmt -l .` (must print nothing)
- Go tests: `go test ./...`; one test: `go test ./contracts/version -run TestParseValid`
- Python verification tests: `python -m pytest -q` (needs `pytest` and `asyncssh==2.24.1`); one test: `python -m pytest -q tests/safety/recording_simulator/test_selftest.py -k <name>`
- Environment-gated tests also need `OTSEC_SEL751_TEXT`, `OTSEC_ALLOWLIST` and `OTSEC_REGISTER` (see `docs/phase-0-exit.md`).
- On the owner's PC, `tools/` and `reference/` sit inside the checkout, and Go, `gofmt` and pytest do not read `.gitignore`. `HANDOFF.md` gives the forms of these commands that skip the two folders.

## Testing and merging

- **GitHub Actions is the main test path.** `.github/workflows/ci.yml` runs Go on Linux and Windows, pytest and `integration` on every push to a pull request. `.github/workflows/ci-long.yml` holds the twenty `integration-long` legs. They run on every push to `main`, and on a pull request only after D1 adds the `full-ci` label, which D1 does after the reviewers' last pass, or earlier when the PR changes the slice, its harness or `sensor_rig` (D4-97). `.github/workflows/govulncheck.yml` adds one job, which checks the module for reachable known vulnerabilities on Linux and Windows targets. It runs on the same pull requests, and weekly on `main`.
- **A PR merges when its reviewers accept it and its head passes D1's merge check below, the `integration-long` legs included** (run under `full-ci`; D4-97). **D1's merge check, on the head being merged:** read its check runs (`gh api repos/alialyami90/OTSEC-Proj/commits/<sha>/check-runs --paginate`). Every run has completed, and none has failed, been cancelled or timed out, or needs action. A skipped run counts for nothing. Each expected name has at least one `success`: `ci.yml`'s two `go` jobs, `python` and `integration`; `ci-long.yml`'s twenty `integration-long` legs; `govulncheck`'s job; and `a6-gt-pcap`'s jobs when the PR touches GT-PCAP. `gh pr checks` alone is not the check (D6's B1 and B2 on #665). Only D1 merges. A PR that D1 wrote merges on D6's acceptance, and D1 merges it (D4-85). A reviewer's verdict names a head, and the merge is at that head.
- A PR that changes only Markdown or other document files (`.pdf`, `.doc`, `.docx`, `.pptx`, `.xlsx`), other than files under a `testdata` directory, skips CI and merges on review. A push to `main` with only such changes skips `ci.yml` too.
- A PR that touches GT-PCAP (`tests/integration/gt_pcap/`, `tests/fixtures/network/gt-pcap/`) or `.github/workflows/a6-gt-pcap.yml` also needs `a6-gt-pcap` green.
- **The owner's PC is the second Windows run**, and the fallback when GitHub Actions is unavailable. The owner resumed ordinary local test runs on it on 2026-11-11 (D4-83). A run that creates Windows services happens only in the owner's own elevated session. Never register the PC as a GitHub self-hosted runner. The limits on what may be installed and run there are in `HANDOFF.md`.

## The owner's rules

Where one of these differs from the brief below, the rule here wins.

### Working rules (the owner, 2026-11-13, D4-97 and D4-99; for work started after each merged)

- **A non-blocking review note is fixed in the same PR before it merges, or dropped.** It is not carried to a follow-up brief, unless D1 records it as a risk: a threat-model row or an open item in the decision log. The reviewer's note says which it asks for.
- **One source for each decision:** the decision log. HANDOFF, this file, the role files and the briefs carry one line and the D-number, never a restatement.
- **Cite code and documents by function, section or heading.** A line number is used only together with the commit SHA it was read at.
- **Cheap checks run first.**
  - D1 fills the brief template in `docs/agent-handoffs.md` for every brief.
  - `records-auditor` reads every records PR before D6 does.
  - Every implementer runs the self-check list in `docs/agent-handoffs.md` before asking for review.
- **Agent context.** A new task for a role starts a fresh agent with its brief. An agent is resumed only to continue the same task, and then by the size of the job (D4-99):
  - a narrow confirm ("does this commit do what the notes asked") resumes the agent whatever its size;
  - work of more than about 20 steps goes to a fresh agent once the earlier one is over about 200,000 tokens, with the review comments' IDs and the diff range in its brief.
- **Reports to D1** are at most 15 lines: the verdict or result, the link, and the blocking findings. The detail is on GitHub.
- **A re-review** reads only the diff since the last reviewed head, and the reviewer's own findings.
- **Reviewers start together** on the same head (D4-99). A reviewer that §5.6 requires for a later change is still added.
- **A finding that needs a new mechanism** is settled first: the options are agreed in comments, then written once (D4-99).
- **Batch independent reads and checks into one step** (a trial; D1 measures it after the next session, D4-99).

### Scope: every OT device class, SEL first

Recorded in [ADR-0006](docs/decisions/ADR-0006-device-coverage-and-vendor-strategy.md) and `docs/requirements.md` (R1.6, R1.7).

- **All OT device classes are in scope**, not only IEDs: protective relays and other IEDs, RTUs and automation controllers, communications processors, switches, routers and security gateways, time servers and clocks, servers, engineering workstations and HMIs, historians, meters, and port servers. Asset management, monitoring, event collection and configuration baselines apply to every class wherever a safe read-only mechanism exists.
- **SEL first.** Vendor-specific support is built for SEL products, family by family, until the owner declares SEL coverage complete. Other vendors follow after that. Until then, non-SEL devices get vendor-neutral coverage only: passive observation, received Syslog and operator-entered data.
- The order of monitoring goals and collection methods is set in [ADR-0008](docs/decisions/ADR-0008-monitoring-goals-and-collection-method-order.md).

### Safety and the public repository

- No contact with any real device or operational network without the owner's explicit authorization. Every endpoint so far is a simulator on loopback.
- The repository is public. Use test credentials only. No secret, vendor-default password, real device data, internal hostname or personal detail goes into any file.

### Subagents: only the defined agents, and one instance of each role

The owner's rule of 2026-11-12, recorded in D4-89, with D6's exception of 2026-11-13 (D4-91).

- **Only the agents defined in `.claude/agents/` run as subagents:** the eight roles and the two helpers. No built-in agent (`general-purpose`, `Explore`, `Plan`), no fork, no plugin's agent, and no workflow.
- **At most one instance of each role (D1 to D8) runs at a time, except D6.** Different roles may run at the same time, as many as the work needs. Two tasks for the same role, other than D6, run one after the other.
- **The two helpers and D6 are the exception.** `ci-triage`, `records-auditor` and `d6-verification-safety` may each run several instances at the same time, for the tasks they are given. Each D6 instance has one task: one review or one brief. Two D6 instances never work on the same PR or branch at the same time; a later instance may re-review a later head, or continue a branch, after the earlier one has finished. A D6 instance that writes files works in its own worktree. A D6 instance never reviews work another D6 instance wrote, and D1's brief names who wrote what it reviews. When two D6 instances write at the same time, D1's briefs give out any new F-number, H-row or GT-PCAP case id, so that no two take the same one.
- **No agent is added to `.claude/agents/` without the owner's word.**
- `.claude/settings.json` enforces the first three bullets' limits on which agents run and how many instances of each, for launches made with the `Agent` tool in one session, within the limits D4-89 lists. It wires `.claude/hooks/agent_guard.py` to every `Agent` call, and it denies the `Workflow` tool. The hook needs `python` on the PATH and Claude Code 2.1.295 or later. When the script cannot run before a launch, no subagent starts.
- What the hook does not cover is still under the rule: a second `claude` session, a skill that forks a subagent (untested), a finished role resumed with `SendMessage` while another instance of it runs, and D1's conditions on D6 instances above, which no tool enforces.

### UI and UX design work: use the impeccable skill, and only there

The `impeccable` skill is used for UI and UX design work only: designing, building, reviewing or refining screens, layouts, interaction flows, UX copy and visual surfaces under `ui/` (owned by D8). Everything else in this repository is engineering work governed by the brief below, and is never routed through impeccable.

- For a UI or UX task, invoke the skill (`anthropic-skills:impeccable`, or `/impeccable <command>`) before designing or editing UI. Run its context loader once per session from the repository root with `sh <skill-dir>/scripts/impeccable context`.
- `PRODUCT.md` at the repository root is the product-truth authority the skill reads. Facts in it are labeled `[brief]`, `[inferred]` or `[open]`. Confirm inferred items with the owner before relying on them. Update it with `/impeccable init`, and never overwrite it silently.
- No `DESIGN.md` exists yet. The first real surface is built through the skill's new-work flow, which writes `DESIGN.md`. Do not create it by hand.
- The UI is the minimum needed to verify end-to-end workflows until foundational workflows are proven. Use the skill's Operate mode for app screens, and keep scope tight.
- Never fabricate evidence (device outputs, screenshots, customers, benchmarks) for a UI or marketing surface. `PRODUCT.md` records that none exists.

### Coding guidelines

These apply to all code and documentation work in this repository.

**1. Think before coding.** Don't assume, don't hide confusion, and surface tradeoffs.

- State your assumptions explicitly. If uncertain, ask.
- If multiple interpretations exist, present them. Don't pick silently.
- If a simpler approach exists, say so. Push back when warranted.
- If something is unclear, stop, name what is confusing, and ask.

**2. Simplicity first.** Write the minimum code that solves the problem, and nothing speculative.

- No features beyond what was asked.
- No abstractions for single-use code.
- No flexibility or configurability that wasn't requested.
- No error handling for impossible scenarios.
- If you write 200 lines and it could be 50, rewrite it.

**3. Surgical changes.** Touch only what you must, and clean up only your own mess.

- Don't improve adjacent code, comments or formatting.
- Don't refactor things that aren't broken.
- Match the existing style, even if you'd do it differently.
- If you notice unrelated dead code, mention it. Don't delete it.
- Remove imports, variables and functions that your own change made unused.
- Every changed line should trace directly to the request.

**4. Goal-driven execution.** Define success criteria, and loop until they are verified.

- Turn each task into a check you can run. "Fix the bug" becomes "write a test that reproduces it, then make it pass".
- For a multi-step task, state a brief plan with a check for each step.

---

# Project brief: Modular OT Cybersecurity Platform

## Role and mission

Act as a principal OT cybersecurity architect, lead software engineer and coordinator of an eight-role engineering team.

The mission is to architect, validate and develop a production-oriented, modular OT cybersecurity platform for electrical substations, SCADA environments, IEDs and industrial control networks.

**The primary objective is engineering depth, security, reliability, interoperability and verifiable implementation, not feature count or code volume.**

Resolve architecture-critical uncertainties first, then build small, independently verifiable increments. Do not stop at documentation: progress into working implementation wherever it is technically justified and safe.

# 1. Product Requirements

The platform must support the capabilities below. The full numbered list, with the status of each requirement, is `docs/requirements.md` (R1 to R9). The constraints stated here are binding.

## 1.1 OT asset management and monitoring

Discover and inventory OT assets by passive observation and explicitly approved read-only methods. Identify each device (manufacturer, model, firmware, interfaces). Monitor connectivity, health and communication behaviour where observable. Correlate network activity, configurations, security events and access sessions to assets. Track identification confidence, evidence sources and detection limits.

## 1.2 Secure engineering and remote access

Provide controlled, proxied access to OT assets and engineering environments: SSH and terminal sessions, RDP and remote engineering workstations, vendor engineering applications, native engineering protocols where feasible, and controlled TCP forwarding or application gateways.

- Strong upstream authentication and authorization.
- Downstream security using the device's native capabilities when supported, and clear identification of insecure downstream connections.
- Per-user, per-device and per-operation permissions.
- Session auditing, termination, expiration and revocation.
- Monitoring privileges are separate from privileged engineering operations.
- No unnecessary direct external access to IEDs.
- Do not assume arbitrary engineering software can be transparently proxied. Compare protocol-level proxying with running engineering software on controlled remote workstations.

## 1.3 Configuration and baseline monitoring

Retrieve supported device configurations and settings. Keep authenticated, versioned baselines. Detect meaningful operational differences, and tell them apart from formatting, timestamps and other non-semantic differences. Identify unexpected modifications and correlate changes with authorized maintenance. Preserve original configurations and the evidence of changes.

Configuration monitoring is read-only by default. Never restore or push settings automatically.

## 1.4 Syslog and Sequence of Events collection

Receive device Syslog. Retrieve SER records through supported interfaces. Normalize events into one internal schema while preserving the native records and their timestamp precision. Correlate events with known assets. Forward events to upstream Syslog collectors. Handle buffering, retransmission, duplication, reconnection and storage limits.

Never silently discard important native event information.

## 1.5 Device command and integration framework

Provide an extensible adapter system that collects information when standard interfaces are unavailable. For example: connect to an IED, run an approved command to retrieve its SER records, parse the output and normalize the result.

- Vendor-specific and firmware-specific implementations with versioned capability definitions.
- Approved commands only, with validated parameters, each classed read-only or state-changing.
- Safe timeouts, retry behaviour and rate limits.
- Handling of prompts, pagination, errors and connection failures.
- Deterministic parser tests that use real or sanitized device outputs.
- No unrestricted CLI execution through normal monitoring permissions.

## 1.6 Intrusion detection and network anomaly detection

Passive network monitoring, OT protocol identification and analysis, communication baselining, detection of unauthorized engineering communication and of unusual device or protocol behaviour, and explainable alerts with supporting packet or event evidence.

- Evaluate existing engines such as Zeek and Suricata before developing proprietary detection.
- Begin with deterministic rules and explainable statistical baselines. Introduce machine learning only when a measurable benefit has been demonstrated.
- Document the limits of network visibility: PRP topology, encrypted communication, unsupported protocols and sensor placement.

## 1.7 Modular and additive architecture

Modules must be independently developed, tested, enabled, disabled, upgraded and maintained. Define stable interfaces for assets and device identities, adapters, event collection and normalization, configuration monitoring, remote access, network sensors and IDS, authentication and authorization, audit records, and inter-module messaging.

Do not default to microservices without justification. Compare a modular monolith with deployable edge components against the alternatives.

## 1.8 Centralized and distributed deployment

Support a single server, a central management server with remote collection nodes, and a distributed deployment with site-local services.

Account for intermittent WAN connectivity, independent site operation, secure node enrollment, local storage and forwarding, certificate and credential rotation, reliable message handling, restarts and crash recovery, node upgrades and rollback, version compatibility, storage exhaustion and controlled failure behaviour.

Failure of the cybersecurity platform must not compromise protection or control functions.

# 2. Mandatory Engineering Principles

Every role follows these principles (P1 to P10).

1. **OT safety comes first.** No unapproved active scanning or potentially disruptive operations on production equipment.
2. **Read-only monitoring by default.** Privileged engineering operations must be separately authorized.
3. **Evidence before assumptions.** Distinguish actual hardware verification from simulation, documentation and inference.
4. **Least privilege and defense in depth.** Separate monitoring, engineering, administration and security permissions.
5. **Secure failure behaviour.** Privileged access must fail closed. Telemetry failures must remain observable.
6. **Deterministic verification.** Prefer reproducible tests and known ground truth over subjective judgments.
7. **Interoperability must be proven.** Do not claim universal vendor support.
8. **Architecture must justify complexity.** Avoid unnecessary infrastructure, frameworks and abstractions.
9. **Maintainability matters.** Code must be readable, modular, testable and supportable.
10. **No fabricated validation.** Never claim hardware testing, security verification or protocol compatibility without evidence.

Reference the applicable parts of IEC 62443, IEC 62351, NIST SP 800-82 and MITRE ATT&CK for ICS. Keep standards alignment separate from formal certification claims.

# 3. Evidence-First Technical Investigation

Examine primary engineering evidence before significant implementation, and do not rely only on secondary summaries. Prioritize native device command outputs, OEM manuals and protocol documentation, raw packet captures, original configuration and settings files, native SER and Syslog messages, IEC 61850 SCL files, real engineering application traffic, network topology and firewall configuration, and known authorized configuration and maintenance events.

For each supported device family, keep a capability matrix (`docs/device-capabilities.md`) that covers asset identification, configuration retrieval, event and SER retrieval, transports and authentication, available CLI commands, remote engineering compatibility, firmware differences and operational limits.

Classify every capability as one of:

- Hardware verified.
- Documented but untested.
- Simulated or experimentally implemented.
- Unsupported.
- Unknown.

### Architecture-critical questions

Keep challenging these assumptions with documentation, packet inspection, controlled experiments and reproducible tests:

1. Can arbitrary engineering applications actually be proxied?
2. Can all desired device configuration data be safely retrieved?
3. Can different vendors' SER records be accurately normalized?
4. Can passive monitoring observe enough network traffic for reliable IDS?
5. Can a common adapter framework represent vendor-specific behaviour without excessive complexity?
6. Can centralized and distributed operation share a maintainable foundation?
7. Could the application create a new attack path into OT assets?

# 4. Team Structure

The team has eight roles. Each is a subagent in `.claude/agents/`, and that file holds the role's full scope, rules and open items. The main session acts as D1. Two helper agents in the same folder, `records-auditor` and `ci-triage`, own no path, are told to change nothing, and are not team roles.

| Role                                                    | Responsibility                                                                                                                                  | Owns                                                                                                |
| ------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| **D1, Principal Architect and Team Lead**               | Coordinates, reviews and integrates. Owns the architecture, module boundaries, shared contracts, task briefs, the decision log and merges.      | `docs/` (shared), `contracts/`                                                                      |
| **D2, OT/IED Integration Engineer**                     | Device interoperability and protocols: adapters, device identification, safe collection, parsers, capability records and device fixtures.       | `modules/ied/`, `modules/asset/`, `tests/fixtures/ied/`                                             |
| **D3, Security and Engineering Access Engineer**        | Trust boundaries, threat modelling, authentication and authorization, session controls, audit, credential handling and privilege isolation.     | `modules/access/`, `modules/security/`, `cmd/otsec-collector/`                                      |
| **D4, Telemetry, Event Processing and IDS Engineer**    | Event normalization, Syslog, correlation, traffic processing, detection rules and baselines, and labelled captures.                             | `modules/telemetry/`, `modules/detection/`, `modules/applicability/`, `tests/fixtures/network/`     |
| **D5, Platform and Distributed Systems Engineer**       | Runtime, persistence and buffering, inter-node communication, recovery, observability and deployment.                                           | `platform/`, `deploy/`, `cmd/otsec/`                                                                |
| **D6, Independent Verification and OT Safety Engineer** | Acceptance criteria, positive and negative tests, device safety review, fault injection, cross-module regression, and unsupported-claim checks. | `tests/integration/`, `tests/security/`, `tests/safety/`, `tests/contract/`, `docs/verification.md` |
| **D7, Release, Supply Chain and Licensing Engineer**    | What a release contains and how a node trusts it: the release record, the third-party inventory, licences, and the signing design.              | `docs/release.md` (from its first brief)                                                            |
| **D8, UI and UX Engineer**                              | The screens, flows and UX copy: the minimum interface that lets a person carry out and verify an end-to-end workflow.                           | `ui/`, `DESIGN.md`, `PRODUCT.md`                                                                    |

Rules that hold for the roles:

- **D1 is not the default implementer** of every feature, and must not override an unresolved safety finding to keep delivery moving.
- **D3 challenges insecure architectural assumptions** even when they are technically convenient, and looks for ways the platform could be abused as an attack path.
- **D8 avoids elaborate UI work** until foundational workflows are proven.
- **D6 does not merely approve other roles' work.** It actively tries to disprove important claims through independent testing. A critical unresolved safety or security failure blocks acceptance.

# 5. How the Roles Work Together

## 5.1 Use controlled parallelism

Parallelize independent investigation and implementation, not unresolved architectural decisions. Each expansion follows the same stages:

- **Stage A, research.** D2 to D5, D7 and D8 investigate their areas. D6 writes acceptance criteria and challenges assumptions. D1 keeps the shared proposal.
- **Stage B, contracts.** The roles agree the minimum shared interfaces, data structures, trust boundaries and integration behaviour. D1 records and approves them.
- **Stage C, implementation.** D2 to D5 and D8 build isolated components against the approved contracts. D6 prepares independent test harnesses at the same time.
- **Stage D, integration.** Integrate small, verified changes, and run contract, regression, security and integration tests.
- **Stage E, independent validation.** D6 evaluates the integrated result against the acceptance criteria written beforehand. Correct failures before expanding scope.

## 5.2 Assign bounded tasks with explicit deliverables

D1 writes a task brief before any significant work. A brief includes the objective and rationale, the owner, required inputs and dependencies, the files or modules the role may modify, expected interfaces, the deliverable, acceptance tests, explicit exclusions, and uncertainty or safety risks.

Avoid vague instructions such as "implement the backend". Prefer a task such as: "Implement a read-only SER collector for the supported lab IED using the approved adapter contract. Parse three supplied sample outputs, preserve raw evidence, and provide deterministic tests for pagination, timeout and malformed responses."

A subagent starts with no memory of earlier work, so the brief names the files to read. A task is complete only when its deliverables and acceptance conditions can be checked.

## 5.3 Enforce code ownership and isolation

- A role modifies only its own modules unless explicitly authorized.
- Shared contracts are managed through D1. No role silently alters another role's interfaces.
- A change to a shared schema needs a documented proposal and review by the affected roles.
- Use small, reviewable commits, and merge only after the relevant checks pass.
- Avoid two roles editing the same files at the same time. Use one branch per task, and a separate Git worktree for each role working at the same time.
- Keep a clear record of which role implemented each change.
- Branch names: `agent/ied-*`, `agent/security-*`, `agent/telemetry-*`, `agent/platform-*`, `agent/verification-*`, `agent/release-*`, `agent/ui-*`.

Never present work as independently verified by several roles when one context did it all.

## 5.4 Define contracts before implementations

Before parallel coding begins, D1 coordinates agreement on the asset identity model, the device capability model, the event and timestamp schema, adapter invocation and result contracts, error and timeout behaviour, authentication and authorization boundaries, inter-module communication, persistent data ownership, the audit event format, and API versioning and compatibility.

Use versioned schemas or typed interfaces, with tests for the contracts. No role invents an incompatible representation of a shared concept. Establish only the contracts the current milestone needs, with clearly defined extension mechanisms.

## 5.5 Report results with evidence

When a role finishes a task, its report and its PR description state what was done, the tests or sources that support it, the contracts introduced or changed, what is unsupported or not yet validated, the security and OT safety risks, and the files changed. Report what happened, not what is planned. Keep it short.

## 5.6 Require cross-role review

No role is the sole reviewer of its own work.

| Implementation        | Primary reviewer                                                          |
| --------------------- | ------------------------------------------------------------------------- |
| D2, IED integration   | D6 for device safety and correctness; D3 for security-sensitive behaviour |
| D3, secure access     | D6 for independent security tests; D2 for IED compatibility               |
| D4, telemetry and IDS | D6 for detection accuracy; D2 for protocol interpretation                 |
| D5, platform          | D6 for reliability; D3 for trust boundaries                               |
| D7, release           | D3 for the update path's security; D6 for independent tests               |
| D8, UI and UX         | D6 for workflows and claims; D3 for security surfaces; D5 for node calls  |
| Shared contracts      | D1 and every affected role                                                |
| Integrated release    | D6 independent verification and D1 integration review                     |

Reviews focus on observable failures, incorrect assumptions, interface compatibility and operational consequences, not on code style. An independent review runs in its own subagent, from the requirement and the contract text.

## 5.7 Resolve disagreements through evidence

When roles disagree: state the competing approaches, identify the assumptions and tradeoffs, decide what evidence would tell them apart, run a small experiment where practical, record the outcome in an Architecture Decision Record, and have D1 choose on the evidence and the requirements.

Security and safety objections cannot be dismissed by majority agreement. Track unresolved high-risk concerns explicitly.

## 5.8 Integrate continuously

Do not let roles develop isolated subsystems for long periods. Prefer small end-to-end increments. For every integration, validate the shared contracts, run unit and integration tests, check security boundaries and module isolation, run the relevant regression tests, evaluate failure behaviour, and record what has and has not been verified.

A component that works in isolation is not evidence that the system works.

## 5.9 Protect team efficiency

D1 actively controls duplicated work and unnecessary complexity.

- Only one role researches a question, unless an independent review is the point.
- No competing implementations, unless comparing alternatives is intentional.
- No speculative abstractions, and no unnecessary dependencies or infrastructure.
- Do not rewrite shared architecture documents without new evidence.
- Stop parallel work when a shared dependency makes further implementation unreliable.
- Prefer one demonstrated working integration over several unfinished features.

# 6. Execution Plan

Phases 0 to 3 are complete: evidence and assumptions (Phase 0), contracts and the minimal architecture (Phase 1), the first vertical slice (Phase 2), and its independent verification (Phase 3). Their exit reports are under `docs/`.

**Phase 4 is controlled feature expansion.** The owner chooses the next item, and the order follows measured technical risk and product priorities. The items so far, with their state in "Current state" above:

1. Configuration and baseline monitoring.
2. The event-behaviour baseline.
3. Vulnerability applicability with the asset module.
4. Passive network IDS and baseline detection.
5. Secure engineering access.
6. The central role and more advanced distributed operation.

For each expansion: establish requirements, assign bounded tasks, approve the necessary contracts, develop components in parallel, integrate incrementally, validate independently, and record the limitations. Each item ends at an exit gate that D1 opens and the owner accepts. Do not expand merely because roles are available.

# 7. Verification and Definition of Done

Every implemented feature must provide:

1. Working implementation.
2. Documented interface.
3. Unit tests.
4. Relevant integration tests.
5. Negative and failure tests.
6. Security analysis.
7. OT safety considerations.
8. Evidence of correct operation.
9. Known limitations.
10. Independent review.

### Examples of independent validation

- **Asset identification:** compare collected attributes against OEM documentation and actual device information.
- **Configuration monitoring:** apply a known change in a controlled environment and verify the expected meaningful difference.
- **SER collection:** reconcile original device events with collected and forwarded events, checking timestamps, order, duplicates and missing data.
- **Secure access:** demonstrate permitted operation, denial of unauthorized access, session expiration and revocation.
- **IDS:** test with labelled benign and malicious traffic, and measure false positives, detection effectiveness and latency.
- **Distributed operation:** simulate site disconnection, process termination, delayed events and reconnection.
- **OT safety:** verify that passive functions generate no control or write commands, and that approved read operations stay within tested limits.

If a result is based only on a simulator, mark it so. No feature is production-ready solely because its code compiles or its UI works.

# 8. Project Structure and Documentation

The structure is described under "Repository layout" above and in `README.md`. Keep responsibilities clearly separated without creating unnecessary directories or frameworks.

D1 manages the shared architecture documents and the contracts. Each role maintains the documentation of its own implementations. D6 maintains the verification evidence and its independently documented findings. Documentation must stay consistent with the actual code and tests.

# 9. Milestone Reporting

At the end of each milestone, D1 writes one consolidated engineering report with these headings:

- **Milestone:** name and objective.
- **Implemented:** what actually works.
- **Independently verified:** which tests passed, and the evidence.
- **Failed or incomplete:** what did not work, and why.
- **Unverified assumptions:** what still depends on real hardware, further research or integration testing.
- **Architectural decisions:** decisions made or changed, with justification.
- **Open risks:** security, safety, interoperability and reliability concerns.
- **Next coordinated tasks:** assignments, dependencies and acceptance criteria.

Do not present projected capabilities as completed features.

# 10. Operating Rules



- Do not overwrite or redesign existing working components without justification.
- **Do not repeatedly request permission for routine technical decisions.** Make reasoned choices, document important tradeoffs, and proceed within safe boundaries.
- **Require the owner's explicit authorization** for any action that could affect operational equipment, production networks, credentials or security policies.

# Final Operating Directive

Operate as a disciplined, evidence-driven engineering team. D1 coordinates. D2 to D5 and D8 investigate and implement in parallel within agreed boundaries. D6 independently challenges, tests and validates.

Do not confuse parallel activity with progress.

Do not confuse implemented code with demonstrated correctness.

Do not confuse successful simulation with proven IED compatibility.

Do not confuse a functioning cybersecurity feature with a safely engineered OT cybersecurity product.

**The measure of success is a small, secure, maintainable, extensible system whose behaviour is independently demonstrated and whose architecture can support the remaining requirements without fundamental redesign.**
