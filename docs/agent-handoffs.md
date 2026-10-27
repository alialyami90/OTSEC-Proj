# Agent Handoffs

Maintained by A1. Each agent appends a handoff when it completes an assigned task. Keep entries actionable; this is not a progress diary.

## Task brief template

A1 issues a brief before assigning significant work.

```
### Task <ID>: <short title>
- Objective and rationale:
- Owner agent:
- Required inputs and dependencies:
- Files or modules the agent may modify:
- Expected interfaces:
- Deliverable:
- Acceptance tests:
- Explicit exclusions:
- Uncertainty or safety risks:
```

## Handoff template

```
### Handoff <Task ID> — <agent> — <date>
**Completed:** what was implemented or investigated.
**Evidence:** tests, source material, or experiments supporting the result. Include paths.
**Interfaces:** contracts introduced, used, or modified.
**Limitations:** what is unsupported or not yet validated.
**Risks:** what might fail, including security and OT safety concerns.
**Dependencies:** what another agent must do next.
**Files changed:** source, tests, documentation.
**Reviewer(s) and outcome:** per the cross-review table in CLAUDE.md section 5.6.
```

## Cross-review assignments

| Implementation | Primary reviewer |
| --- | --- |
| A2 — IED integration | A6 (device safety, correctness); A3 (security-sensitive behaviour) |
| A3 — Secure access | A6 (independent security tests); A2 (IED compatibility) |
| A4 — Telemetry and IDS | A6 (detection accuracy); A2 (protocol interpretation) |
| A5 — Platform | A6 (reliability); A3 (trust boundaries) |
| Shared contracts | A1 and all affected agent owners |
| Integrated release | A6 independent verification and A1 integration review |

## Open task briefs

Issued by A1 on 2026-10-23 for Phase 0. Common rules for every Phase 0 brief:

- **No contact with operational equipment.** No scanning, no connections to any real IED, network, or credential. Research uses public OEM documentation, standards, open-source code, and local experiments in the container only. Anything that would touch equipment, networks, credentials, or security policy needs the owner's explicit authorization through A1.
- **No fabricated evidence.** A sample output copied from an OEM manual is a `documented-untested` example, not a device capture. Never write a fixture by hand and present it as device output. Every fixture needs a `SOURCE.md` (see `tests/fixtures/README.md`).
- **Write only to owned paths.** Each agent may additionally create one findings file, `docs/phase0/<agent>-<topic>.md`, which it owns. `docs/architecture.md`, `docs/requirements.md`, `docs/agent-handoffs.md`, `docs/decisions/`, and `contracts/` are edited by A1 only. Proposals for those go in your findings file and A1 transfers them.
- **No contracts in Phase 0.** Schema and interface proposals are drafts in findings files. They become contracts in Phase 1 after review by affected owners.
- **No toolchain choice by stealth.** Experiments may use any language available in the container, but nothing outside a findings experiment directory commits the project to a language until the toolchain ADR exists.
- **Branch.** Work on your own branch (`agent/<area>-phase0` per CLAUDE.md 5.3, or your session's assigned branch if the environment fixes one) and tell A1 the branch name. Open a PR against `main`; A1 reviews and integrates.
- **Finish with a handoff** to A1 in the template below. Mark every factual claim with its evidence class or source.

### Task P0-A1: Architecture boundary, alternatives, and exit gate
- Objective and rationale: define the system boundary and candidate architectures so Phase 0 findings land in one place, and decide whether the Phase 0 exit gate is met.
- Owner agent: A1.
- Required inputs and dependencies: handoffs P0-A2 to P0-A6.
- Files or modules the agent may modify: `docs/architecture.md`, `docs/requirements.md`, `docs/agent-handoffs.md`, `docs/decisions/`, `contracts/README.md`, `README.md`.
- Expected interfaces: list of contracts required for the first slice, with owners and reviewers.
- Deliverable: system boundary, architecture alternatives with a provisional choice, critical dependency map, five architecture-critical risks, selected slice scenario, required contract list, list of unsupported assumptions, exit gate decision.
- Acceptance tests: every exit gate item in `docs/architecture.md` is either checked with a pointer to evidence or explicitly left open with a reason.
- Explicit exclusions: no implementation code; no contract text beyond scope and ownership.
- Uncertainty or safety risks: no lab hardware is known to exist, so every device claim in Phase 0 is at best `documented-untested`.

### Task P0-A2: Device feasibility for the first slice
- Objective and rationale: pick the IED family the first slice targets and establish, from primary documentation, how to identify it and retrieve SER read-only. Answers Q2 and Q5.
- Owner agent: A2.
- Required inputs and dependencies: public OEM manuals and protocol documentation. Owner confirmation of any lab hardware (A1 is asking).
- Files or modules the agent may modify: `docs/device-capabilities.md`, `docs/phase0/A2-*.md`, `tests/fixtures/ied/` (only with provenance).
- Expected interfaces: a draft of what an adapter needs to receive (target, credential reference, command id, parameters, limits) and return (raw transcript, parsed records, errors). Draft only.
- Deliverable: (1) two or three candidate IED families ranked against the selection criteria in `docs/device-capabilities.md`, one recommended primary and one contrasting second family to keep the adapter model honest; (2) a capability matrix for the primary family with every row classified; (3) a draft approved command register for identification and SER retrieval, each command classified read-only or state-changing with the documentary evidence, the access level it needs, and its pagination and prompt behavior; (4) whether SSH is actually a native transport for the primary family or whether Telnet, serial, or a gateway is the realistic path (the brief's SSH example is an assumption to test); (5) device-specific OT safety risks of the collection method (session limits, CPU impact, access-level escalation, lockout); (6) the native SER record format with timestamp precision and time-quality fields.
- Acceptance tests: each capability row cites a document and section or is marked `unknown`; each command in the register has a classification source; no hand-written fixture is presented as device output.
- Explicit exclusions: no connection to any device; no state-changing commands in the register except to document that they exist and must be blocked; no adapter code beyond a parsing experiment against documented examples.
- Uncertainty or safety risks: documented examples may differ from real firmware output. Access-level commands on some relays can elevate to settings-change levels; flag any such path.

### Task P0-A3: Threat model v0 and engineering access feasibility
- Objective and rationale: establish trust boundaries and minimum safe behavior before any collection path exists. Answers Q1 and Q7.
- Owner agent: A3.
- Required inputs and dependencies: P0-A2 transports and access levels (to judge insecure downstream links); P0-A5 runtime shape (to place boundaries).
- Files or modules the agent may modify: `docs/threat-model.md`, `docs/phase0/A3-*.md`.
- Expected interfaces: draft authorization boundary for collection (who may invoke which adapter operation class), draft credential reference model (how an adapter obtains a device credential without it being visible to monitoring users or logs), draft audit event minimum fields.
- Deliverable: (1) threat model v0 with trust boundaries for single-server and central-plus-collector deployments, actors, and the Q7 attack-path table with a proposed mitigation and a test idea for each; (2) Q1 comparison of protocol-level proxying vs controlled remote engineering workstations vs per-application gateways, with what evidence would settle it; (3) minimum safe behavior for the first slice (credentials, read-only enforcement point, audit, handling of insecure downstream transports such as Telnet or serial); (4) the standards anchors (IEC 62443-3-3 SRs, IEC 62351 parts, NIST SP 800-82r3, ATT&CK for ICS technique IDs) that each control aligns to, labeled alignment not certification.
- Acceptance tests: every Q7 attack path has a mitigation and a falsifiable test; every control states where it is enforced.
- Explicit exclusions: no implementation of authentication; no choice of identity provider.
- Uncertainty or safety risks: read-only enforcement that lives only in the adapter is one bug away from a write. Say where defense in depth is needed.

### Task P0-A4: Telemetry feasibility and draft event schema
- Objective and rationale: decide what the event schema must carry so normalization loses nothing, and evaluate detection engines before any detection work. Answers Q3 and Q4.
- Owner agent: A4.
- Required inputs and dependencies: P0-A2 native SER formats (A4 should also survey at least two vendors' SER and Syslog formats independently from documentation).
- Files or modules the agent may modify: `docs/phase0/A4-*.md`, `tests/fixtures/network/` (only with provenance), throwaway experiments under `modules/telemetry/experiments/`.
- Expected interfaces: draft event schema; draft Syslog forwarding profile.
- Deliverable: (1) draft event schema that keeps the native record byte-exact beside normalized fields, and models device timestamp, its precision, time source and quality, time zone or offset (including "unknown"), and collector receive time separately; (2) a duplicate-detection key proposal and how it behaves when a device re-sends SER history; (3) Syslog forwarding profile: RFC 5424 over TLS (RFC 5425) vs alternatives, framing, structured data, size limits, what happens to records larger than the collector accepts; (4) Zeek vs Suricata vs protocol libraries for OT protocol coverage relevant to substations (DNP3, Modbus, IEC 61850 MMS and GOOSE, IEC 60870-5-104, vendor engineering protocols), with sources; (5) Q4 visibility limits (PRP duplicates, encryption, SPAN vs TAP, process bus).
- Acceptance tests: the schema draft can represent every field of the A2 SER example without loss (show the mapping); every engine claim cites a source.
- Explicit exclusions: no IDS implementation; no ML; no Syslog code beyond a throwaway experiment.
- Uncertainty or safety risks: normalization that rounds timestamps or drops vendor fields violates R4.4.

### Task P0-A5: Runtime shape, toolchain, and persistence
- Objective and rationale: propose the minimal deployable runtime that serves single-server and central-plus-collector deployments from one codebase. Answers Q6.
- Owner agent: A5.
- Required inputs and dependencies: none blocking. Coordinate with A3 on node trust and with A4 on event buffering.
- Files or modules the agent may modify: `docs/phase0/A5-*.md`, throwaway experiments under `platform/experiments/`.
- Expected interfaces: draft local store and forward (outbox) semantics: at-least-once delivery, ordering, idempotency key, behavior when storage is full.
- Deliverable: (1) comparison of modular monolith plus edge collector vs service-per-module vs hybrid against R7 and R8, with a recommendation; (2) toolchain recommendation (language, build, test runner, lint) with reasons tied to requirements: deployability on site hardware, SSH and Telnet client libraries, parser testability, memory safety, supportability; also the UI stack decision deferred to you in `PRODUCT.md`; (3) persistence and buffering recommendation with crash-recovery semantics, backed by one small experiment (for example kill -9 during writes to the candidate store, then check for loss or duplication); (4) site-to-central transport and enrollment outline (mTLS, who initiates, what the central side can and cannot instruct a site node to do).
- Acceptance tests: the recommendation states which R7/R8 rows it satisfies and which it defers; the experiment is reproducible from committed scripts with recorded output.
- Explicit exclusions: no production runtime code; no UI; no orchestration platform unless justified against P8.
- Uncertainty or safety risks: a central server able to instruct site nodes is a Q7 attack path; coordinate the command surface with A3.

### Task P0-A6: Verification matrix and assumption challenge
- Objective and rationale: make acceptance objective before implementation and attack the plan's weakest assumptions.
- Owner agent: A6.
- Required inputs and dependencies: requirements; drafts from A2 to A5 as they appear.
- Files or modules the agent may modify: `docs/verification.md`, `docs/phase0/A6-*.md`, `tests/integration/`, `tests/security/`, `tests/safety/`.
- Expected interfaces: none; A6 consumes contracts and tests them.
- Deliverable: (1) measurable acceptance criteria for V-S1 to V-S8, each stating the test, the pass threshold, the ground truth, and whether it needs hardware, simulator, or fixtures; (2) the R-level verification matrix filled for R4, R5, and R8 at minimum; (3) a method to prove "no write operations" independent of the adapter's own claims (for example a recording device simulator that logs every byte received and checks it against the approved register); (4) a challenge list of at least five assumptions in the brief or in other agents' drafts that you think are wrong or unproven, with what would disprove each; (5) safety and security blockers, if any.
- Acceptance tests: every V-S criterion has a numeric or binary pass condition and named ground truth.
- Explicit exclusions: do not review your own work; do not accept implementing agents' claims as evidence.
- Uncertainty or safety risks: with no lab IED, the strongest available evidence is simulator plus documentation; criteria must say what remains unverified.


## Handoffs

### Handoff P0-A6 — A6 — 2026-10-23
Full text: `docs/phase0/A6-handoff.md` on branch `claude/project-thread-u7odvk`. Summary:
**Completed:** V-S1 to V-S15 with binary or numeric pass conditions, named ground truth, and separate simulator-proves and hardware-dependent columns; R1–R8 and P1–P10 verification matrix; recording SSH simulator plus register checker for V-S7; challenges C-01 to C-12; hardware-only tests H-01 to H-10; blockers B-01 to B-06; experiment E-01.
**Evidence:** E-01 (TLS syslog writes succeed while 100 of 150 frames are lost, 5/5 trials) and the recording simulator self-test (8/8), both `simulated`.
**Interfaces:** none; proposes that A2's command register be machine-readable and map onto the checker's register format.
**Limitations:** no implementation to test yet; vendor facts in C-01/C-02 are recalled, pending A2 confirmation.
**Risks:** parser and simulator both derive from OEM documents, so a documentation error passes every simulated test.
**Dependencies:** A2 (C-01, C-02, C-06, C-12, B-02), A3 (B-04, B-05, C-07, C-08), A4 (C-04, C-05, C-08, B-03), A5 (C-04, V-S9, R8.7).
**Reviewer(s) and outcome:** A1 integration review, 2026-10-23: accepted for Phase 0. A1 independently re-ran E-01 (5/5 trials, 100 of 150 frames lost, `ConnectionResetError` on a later write) and the self-test (8/8 pass, asyncssh 2.24.1 in a clean venv); both reproduce. Decisions below.

#### A1 decisions on P0-A6 (2026-10-23)
- **Criteria.** V-S1 to V-S15 and the R/P matrix are the Phase 0 baseline. Thresholds marked *(proposed)* stay proposed until the owning agent confirms or replaces them in Phase 1 (A5 for the 72 h partition and 100-iteration crash loop, A4 and A5 for the 60 s health-event latency, A3 for the 5 s revocation).
- **B-06.** Approved. Verification tooling under `tests/` may use Python 3 with pinned dependencies (currently asyncssh 2.24.1) regardless of the implementation toolchain. Oracle independence comes from the no-import rule, not the language; a different language is welcome where it helps.
- **`documented-example` fixture class.** Approved; `tests/fixtures/README.md` updated by A1. Such fixtures support `simulated` or `documented-untested` claims only.
- **B-03 and B-05** are entry conditions for Phase 1 contract approval: the forwarding contract must define the confirmed position, replay, de-duplication key, and unconfirmed window; the asset identity contract must bind reported attributes to a transport identity and fail closed on change, with no trust-on-first-use.

### Handoff P0-A3 — A3 — 2026-10-23
Full text: section 8 of `docs/phase0/A3-security-feasibility.md` on branch `claude/project-thread-qj1j9d` (PR #1). Summary:
**Completed:** threat model v0 (10 trust boundaries, 11 actors, 20 Q7 attack paths each with mitigation, enforcement point, falsifiable test, and ATT&CK for ICS IDs; 18 controls aligned to IEC 62443-3-3 and IEC 62351; HR-1 to HR-7). Q1 comparison (P-tcp, P-aware, W, G) with settling experiments X1–X4. Drafts: role and operation matrix, `CredentialRef`, read-only layers L1–L7, audit minimum fields, `downstream_security` label, failure behaviour. Experiment E1.
**Evidence:** ABB 1MRS758280 rev C; Siemens SSA-899560; SEL-3620 documentation; ATT&CK for ICS (retrieved 2026-10-23); E1 (`simulated`, 9/9).
**Answers:** Q7 yes, by construction. Q1: transparent proxying of arbitrary tools rejected; hybrid proposed for Phase 4, unsettled until X1–X4.
**Dependencies:** A2 access-level and transport facts (HR-2, L5); A4 forwarding rules (AP-20) and HR-3; A5 site-to-central rules; A6 cross-review.
**Reviewer(s) and outcome:** A1 integration review, 2026-10-23: accepted for Phase 0. A1 re-ran E1 (OpenSSH 9.6p1, loopback): 9 pass, 0 fail, reproducing the recorded result. Review note: T4's refusal comes from the account's `nologin` shell, not from an sshd restriction, so a production gateway must not rely on the shell alone (add `ForceCommand`/`PermitTTY no` or equivalent and test with a real shell). A6 (security) and A2 (IED compatibility) reviews pending.

#### A1 rulings on P0-A3 (2026-10-23)
- **R8.5 (HR-5).** Rotation means platform-owned credentials only; IED credential rotation is a device write outside slice 1. Recorded in `docs/requirements.md`.
- **HR-3 (evidence vs secrecy).** The session transcript keeps every byte *received* from the device, including banners and prompts during login. Bytes the platform *sends* during authentication are replaced by a redaction marker recording position, length, and that a secret was sent. After login, every sent byte is preserved. Evidence hashes (V-S8) cover the redacted transcript as stored, and the redaction rule is part of the evidence format so it is reproducible.
- **Plaintext-only devices and B-05.** Provisional: slice 1 collects only over `encrypted-authenticated` transports with a host key pinned out of band. If A2 shows the primary family cannot be collected that way, A1 will not accept plaintext credentials on the station LAN on the team's authority; it goes to the project owner as a security-policy decision, with A3's per-device acknowledgement model as the proposed control.
- **No human-triggered device I/O in slice 1** (A3 4.1, collector identity only): accepted as a slice constraint.
- **Section 7 proposals** transferred to `docs/architecture.md` (Q1, Q7 status; ADR candidates) at consolidation.

### Handoff P0-A2 — A2 — 2026-10-23
Full text: section 14 of `docs/phase0/A2-device-feasibility.md` on branch `claude/project-thread-8k8qrr` (PR #2), with `docs/phase0/A2-command-register-draft.json` and `docs/device-capabilities.md`. Summary:
**Completed:** candidate ranking (primary: SEL ASCII relays, reference SEL-751; contrast: an IEC 61850 MMS server keeping SOE in a log, SIPROTEC 5 or Relion 615 to be fixed); SEL-751 capability matrix; machine-readable draft command register (4 allowed exact lines `ACC`, `QUI`, `ID`, `SER`; 29 documented deny patterns; deny by default); SSH feasibility; device risks D1–D14; native SER format; Q2; Q5 with a draft adapter envelope; simulator source list for A6.
**Evidence:** sources S1–S15 (OEM documents and open-source code). The SEL-751 manual body is blocked by the egress policy, so most command tables are "section located, content not read". Every row is at best `documented-untested`. No fixtures added (correctly: nothing could be transcribed verbatim).
**Answers:** Q2 no, not all configuration, and not with one mechanism. Q5 plausibly yes, if the common layer is the envelope plus enforcement and session drivers stay per family.
**Key findings:** SSH is not a documented native transport for SEL relays (only on SEL-3620/RTAC gateways); Access Level 1 is not read-only (`TRI`, elevation, possibly clears); three bad passwords pulse the ALARM contact (SEL-300G); SER is a 1,024-entry ring buffer with no sequence counter found; binary Fast Operate messages may share the ASCII port.
**Reviewer(s) and outcome:** A1 integration review, 2026-10-23: accepted for Phase 0. Integration check: A1 loaded A2's register into A6's `check.py` (branch `claude/project-thread-u7odvk`) without changes. Exact `ACC`, `QUI`, `ID`, `SER` classify read-only; `SER C`, `SER 1 10`, `TRI`, `2AC`, `OPE`, and a 0xA5-prefixed line classify state-changing; lower-case, abbreviated, space-padded, and unregistered lines (`ser`, `SE C`, `ACC `, `SHO`) are violations; a NUL is caught as control bytes. The two drafts are compatible. Gap carried to A6: non-ASCII detection currently depends on the register pattern and on latin-1 decoding; the checker should flag any byte outside 0x20–0x7E plus CR/LF itself. A6 (safety, correctness) and A3 (security) reviews pending.

#### A1 decisions on P0-A2 (2026-10-23)
- **Primary family accepted:** SEL ASCII relays, reference SEL-751, `ID` and `SER` at Level 1. SEL-400 series excluded from slice 1 (D6 transparent connections).
- **Contrast family:** kept as a paper exercise for the Q5 envelope test in Phase 1; reference device fixed when its manual is readable. Not in slice 1.
- **Transport:** SEL relays offer no documented SSH, which triggers the ruling recorded under P0-A3. Put to the project owner as a security-policy decision on 2026-10-23; pending.
- **Register file location:** keep the JSON under `docs/phase0/` for Phase 0. In Phase 1 the approved register moves to `contracts/` (A1-owned format, A2-owned content) so the adapter and A6's checker read the same file.
- **Manual access:** reading SEL-751 Tables 7.8, 7.24, 7.39, 7.40, 4.84, 10.1 and Figures 3.5, 10.17 is the single largest evidence gap. Needs the owner to upload the manual or allow `selinc.com`.
- **DNP3 event polling** stays rejected as a collection mechanism until the DNP3 device profile is read (a second master may consume SCADA's events).

### Cross-review P0-A2 and P0-A3 — A6 — 2026-10-23
Full record: `docs/phase0/A6-cross-review.md` on branch `claude/project-thread-u7odvk` (commit 89745c6). Both drafts accepted for Phase 0 by A6. Findings: read-only layers L2–L4 and the checker all derive from the register, L5 fails for SEL Level 1, L6 is the same port, so the only non-derived check is A6's independent deny corpus; kill is not revocation (T9: the same key reconnects); SEL in-band `ACC`/password breaks "inject credentials below the recorder"; TB5 "accept nothing back" conflicts with acknowledged delivery (B-03); AP-17 detection window equals WAN outage; ATT&CK IDs verified. A2's register passes A6's 61-line deny corpus (0 classified read-only) and 4/4 allow corpus. Per-row SER dedup would drop legitimate identical rows (C-13). V-S14 is not applicable to Telnet families. Checker now flags 0x80–0xFF itself; simulator has a Telnet front end; self-test 13/13 over 3 runs. New blocker B-07: SEL manual bodies unreadable (proxy 403 on selinc.com).

#### A1 rulings on the A6 cross-review (2026-10-23)
- **Register independence.** Accepted. A6's deny corpus is an independent gate: no register change merges unless the corpus still classifies 0 deny lines as read-only, and the corpus is owned by A6, not A2. L4 checks the final bytes handed to the socket, after Telnet encoding.
- **Credential injection.** The credential slot opens only when the session driver has matched the documented password prompt, and only once per session. The transcript redaction rule (HR-3 ruling) applies to that slot.
- **Revocation.** Revocation means the credential or key is invalidated, not only the process killed. A6's tightened R2.5 criterion stands; it applies from Phase 4.
- **TB5 vs acknowledged delivery.** Provisional, to be fixed in the Phase 1 forwarding contract with A3, A4, A5: TB5 becomes "accept no instructions or data from upstream; accept only transport acknowledgements in a fixed grammar, parsed by a minimal parser that drops the connection on anything else". Where the upstream collector supports an acknowledging transport, use it; otherwise the contract states the unconfirmed window and the replay rule.
- **AP-17.** Recorded as a known limitation: tampering with a disconnected node's audit chain is detectable only after reconnection.
- **C-13.** Routed to A4: dedup by aligning overlapping SER snapshots, not by per-row keys.
- **V-S14 for Telnet.** Marked not applicable for plaintext families; device identity for them rests on `ID` output plus address, which is spoofable. Recorded as residual risk in the transport decision.
- **B-07.** Folded into the single owner request in the Phase 0 exit report.

### Handoff P0-A5 — A5 — 2026-10-23
Full text: last section of `docs/phase0/A5-platform-feasibility.md` on branch `claude/project-thread-xni3ff` (PR #3); experiments in `platform/experiments/phase0/`. Summary:
**Completed:** runtime shape (modular monolith, one Go binary, roles by configuration; collector and IDS engines out of process); toolchain and UI stack (Go 1.26 pinned, server-rendered HTML); persistence and delivery semantics (SQLite WAL, `(node_id, stream, seq)`, storage-full policy); site-to-central transport and central instruction allowlist (aligned with A3); node runtime, upgrades, observability; experiments E-A5-1 to E-A5-5.
**Answers:** Q6 yes, under four invariants (only sites talk to IEDs; sites are system of record; site-initiated connections; central loss never stops a site).
**Reviewer(s) and outcome:** A1 integration review, 2026-10-23: accepted for Phase 0. A1 rebuilt the experiment binary and re-ran E-A5-1 (25 kills per mode, 4 modes, 0 failures), E-A5-3 (default WAL wedges; bounded WAL with reserve and 50-event pruning recovers: 4,160 pruned, 5,440 more accepted, integrity ok), and E-A5-4 (3 runs per scenario, loss in 3/3; acked transport 0 missing, 1 duplicate). All reproduce the recorded results. Proposals transferred to ADR-0002, ADR-0003, ADR-0004 (status proposed). A6 (reliability) and A3 (trust boundaries) reviews pending.

#### A1 decisions on P0-A5 (2026-10-23)
- **R7.1 deviation accepted** in ADR-0002: modules are released together as one signed artifact; the owner may override.
- **Privilege-separated collector process** adopted in ADR-0002, consistent with A3's credential model.
- **Owner questions** (site hardware/OS, WAN outage durations, central direct IED access) go into the exit report; until answered, the design assumes Linux amd64/arm64, a 72 h outage floor, and never.

### Owner-supplied evidence — 2026-10-23
The project owner supplied six SEL data sheets (SEL-751 date code 20260910, SEL-311L, SEL-400G, SEL-411L, SEL-451, SEL-787-2/-3/-4). Copies, text extractions, and A1's reading notes: `/mnt/project-files/phase0/datasheets-SEL/` (`README-A1.md`). Class: OEM document, `documented-untested`. They are data sheets, not instruction manuals, so B-07 (command tables and example outputs) stays open. A2 and A6 read the PDFs themselves rather than relying on A1's notes. Items for A6: SEL-751 SER time-stamp resolution 1 ms, accuracy ±1 ms to the time source (event reports ±5 ms) for V-S3; SEL-311L single Telnet host session for V-S13; possible Spanish-language serial output for V-S2/V-S15.

### Cross-review P0-A5 — A6 — 2026-10-23
Record: section "A5 findings" of `docs/phase0/A6-cross-review.md` (commit 827fffc). Accepted for Phase 0. E-02 (strace): NORMAL left 1,011 of 1,016 acks unsynced, FULL 0 of 680, so E-A5-1 is R8.7 evidence for FULL only; new hardware test H-11 (power cut). E-03: after a crash at full disk, reads and draining work (6/6) but pruning fails (6/6) until space is freed. C-18: "prune only confirmed" plus "RFC 5425 never confirms" stops SER polling permanently. A6 also re-checked A3's follow-up (E1 14/14 over 3 runs, revocation proven; R-A3-1, 2, 3, 5 closed) and A2's follow-up (both corpora pass; snapshot dedup including ambiguous offset).
**A1 rulings:** folded into ADR-0004 (still proposed): required vs best-effort targets with a replay-window retirement rule (C-18); FULL for every cursor- or delivery-advancing stream; reserve release and pruning at startup.

### Handoff P0-A4 — A4 — 2026-10-23
Full text: `/mnt/project-files/phase0/A4-handoff.md`; findings in `docs/phase0/A4-telemetry-feasibility.md` and `docs/phase0/A4-event-schema-draft.md` on branch `claude/project-thread-ix2tu3` (PR #4). Summary:
**Completed:** telemetry feasibility and engine evaluation; draft event schema `otsec.event/0.1-draft`, snapshot-alignment duplicate handling, forwarding profile `otsec-syslog/0.1` (mode A RELP/TLS, mode B RFC 5425 with replay window), evidence-preservation rules EP-1 to EP-9; experiments E-A4-01 (engine coverage, GOOSE checks), E-A4-02 (syslog framing), E-A4-03 (RELP ack vs storage), schema mapping and alignment tests.
**Answers:** Q3 structurally yes, semantically no without per-device mapping tables. Q4 only per site with stated placement; stock Zeek 8.0.4 and Suricata 7.0.3 decode none of IEC 61850 MMS, GOOSE, or IEC 104.
**Reviewer(s) and outcome:** A1 integration review, 2026-10-23: accepted for Phase 0. A1 re-ran with rsyslog 8.2312.0: E-A4-02 reproduces (naive newline framing forges 1 message in each of the LF and CRLF cases; the profile forges 0 in all 10 cases and recovers device bytes); E-A4-03 reproduces (default queues: 1,476 of 1,500 acknowledged messages not stored; Direct queues: 0); alignment tests 10/10. E-A4-01 not re-run (needs Zeek container and capture downloads). A6 (detection accuracy) and A2 (protocol interpretation) reviews requested.

#### A1 rulings on P0-A4 (2026-10-23)
- **Forwarding mode policy.** Mode A (RELP over TLS, receiver configuration documented and tested, ack-only parser that can only advance the forwarding cursor) is the only mode that may be a `required` target. Mode B (RFC 5425 with replay window W and `event_id` dedup) is allowed only as a `best-effort` target (ADR-0004). A3 and A4 agree.
- **TB5 wording:** as in the A6 cross-review ruling; A4's schema draft §5 wording is accepted.
- **HR-3 amendment (A4 conditions):** the redaction marker carries no derivative of the secret (no hash); if the device echoes password characters, those received bytes are redacted too, with a marker. Every other received byte is preserved.
- **SD-ID:** the slice uses the documentation PEN 32473 (RFC 5612) in structured-data IDs; registering a real IANA PEN is an owner action before any production use.
- **Licences:** recorded in ADR-0003 (libiec61850 and lib60870 not linked without a licence decision).
- **IDS engine:** Zeek as a separate process is the provisional direction for Phase 4; no ADR until R6 work starts.

### Owner scope change — 2026-10-23
The owner widened scope to all OT device classes with SEL as the only vendor for vendor-specific support until the SEL product is complete. Recorded in ADR-0006, `docs/requirements.md` R1.6/R1.7, the scope update section of `CLAUDE.md`, `PRODUCT.md`, and `docs/architecture.md` "Device coverage and vendor strategy". Effects on Phase 1 briefs: A2 organizes candidates and capability matrices by SEL product family and device class and confirms A1's SEL product list; the Q5 contrast exercise uses an SEL RTAC instead of SIPROTEC/Relion; A3 adds network-device and host credentials and any host agent to the threat model; A4 makes the schema accept non-SER native records (switch/gateway Syslog, Windows events, clock status); A6 states support per SEL family and device class. The first slice (ADR-0005) is unchanged.

### Owner-supplied SEL manuals — 2026-10-23
The owner supplied 15 SEL instruction manuals and user's guides (SEL-751 IM date code 20260910, SEL-787-2/-3/-4, SEL-311L/-6, SEL-400G, SEL-411L, SEL-451-5, SEL-2488, SEL-2731, SEL-2741, SEL-3355-2, acSELerator RTAC SEL-5033, SEL-5056, Programming Reference, RSTP User's Guide, SDN User's Guide) and two more data sheets (SEL-2488, SEL-3355-2). PDFs and text extractions: `/mnt/project-files/phase0/manuals-SEL/`. Class: OEM document, `documented-untested`. **B-07 is unblocked for SEL-751.**

A1 spot-read of the SEL-751 IM (A2 and A6 must read and cite the source themselves):
- Table 7.43: `ID` is Access Level 0; Figure 7.38 prints an example ID response (candidate `documented-example` fixture).
- Table 7.63: `SER` is Level 1 ("as many as 1024 rows", row 1 most recent); **`SER C` or `SER R` clears the SER records at Level 1**; argument forms `row1`, `row1 row2`, `date1`, `date1 date2` (dates follow `DATE_F`). `SER D` lists automatically removed chattering elements (Table 7.64).
- Table 7.17 and following text: `ACC` (0→1), `2AC` (1→2), `CAL` (2→C); three incorrect passwords pulse `SALARM` for one second; `SALARM` also pulses after successful Level 2 or C access or a denied access. Factory example logic includes `OUT101 := HALARM OR SALARM` and `SER4 := SALARM`, so failed logins can drive the alarm output and appear in the SER.
- Port settings: `ETELNET`, `TPORT`, `TIDLE` (1–30 min, default 15), Telnet `LANG` English or Spanish; factory default Ethernet enables only Telnet, HTTP, and PING. No SSH, Syslog, or TLS in the manual.
- Consequence for risk 1: the collector's own access level can destroy the evidence it collects. The exact-line register and egress check are the only platform-side barriers; this is now `documented-untested`, not inferred.

Missing for the ADR-0006 table: SEL-3620/-3622 gateway, RTAC hardware (SEL-3530/-3555/-3505), SEL-735, SEL-3610, SEL-ICON, SEL-2401/-2407, and the SEL Fast Message protocol documentation (for A2 D5).

### Open owner items — 2026-10-23
**Decision posted to the owner (A3 raised):** whether deployment guidance should recommend, require, or omit `MAXACC := 1` on the SEL-751 port the collector uses (factory default on the Ethernet port is 2; `FASTOP := N` default; FTP has its own `FTPACC`, default 2). **Owner chose "Recommend and check" (2026-10-23), recorded in ADR-0005.** The deployment guide recommends it and the platform reads port settings at Level 1 and warns when the collection port allows Level 2. It does not stop `SER C`/`SER R` (Level 1); the register and egress check remain the platform barrier. A3 also notes the relay's password-bypass jumper as a physical-access risk for the threat model.

**Consolidated document and fact request to the owner (A2, A3, A5):**
1. SEL Fast Message protocol documentation (A2, register and D5).
1a. SEL Compressed ASCII documentation, including the CSE command format (A2, parser design for machine-readable SER).
2. SEL-3620 / SEL-3622 security gateway and SEL-2730M switch manuals (A3, engineering-access path and network-device credentials).
3. RTAC hardware manual: SEL-3530, SEL-3555, or SEL-3505 (A2 Q5 contrast; A5 site computer option).
4. SEL application note on SSD lifetime / write endurance for SEL-3355 class computers (A5, SQLite WAL sizing).
5. SEL-735 meter, SEL-3610 port server, SEL-2401/2407 clocks manuals (A2, device classes in ADR-0006).
6. Facts: site computer model and OS (A5 proposes SEL-3355-2: TPM, mirrored SSD, AMT disabled or kept off the WAN, ~17 s/day drift without a time source); expected WAN outage duration; whether central may reach IEDs directly; the upstream Syslog collector product; the HMI and historian software in use on Windows hosts.

**Integration note (A1):** non-SEL second-family references in A2, A4 and A6 Phase 0 documents (SIPROTEC/Relion contrast, second-vendor fixture requests) are out of scope per ADR-0006; A1 removes or marks them superseded when merging those branches.

#### A1 rulings on A2 manual findings (PR #2 fe0fd7b, 9278a2d) — 2026-10-23
Checked against SEL-751 IM Table 7.67 (SHOW command, all forms Access Level 1) and SEL-400 series IM Table 14.50 (CSE, Levels 1, B, P, A, O, 2).
1. **`SHO G` and `SHO P 1`: approved** for the C3 register as exact lines with no `s` setting-name argument, classified read-only, Level 1. Conditions: (a) A2 cites the table showing Port 1 is the Ethernet port on the SEL-751 (A1 named Table 2.5 in error; the correct source is Table 7.1, verified by A1); (b) the output is stored as configuration evidence and treated as sensitive (it contains addresses and `FTPUSER`), and A2 confirms from the manual that no password value is printed; (c) A6 adds the `s`-argument and other-port variants to the deny corpus. What the collector does when MAXACC on the collection port is above 1 waits for the owner's MAXACC decision; per the owner's decision it records and warns, it does not refuse.
2. **`CSE` (400 series): deferred.** The first slice is SEL-751 only and 400-series register entries belong to that family's Phase 4 expansion. Keep `CSE` as a candidate, `documented-untested`, with D25 (Figure 9.17 checksums) recorded. The Compressed ASCII documentation is on the owner request list.
3. **RTAC as the Q5 contrast: accepted** with A2's corrected reason; ADR-0006 item 6 and `docs/architecture.md` Q5 updated.
4. **D18–D25:** accepted into A2's risk list; A1 will fold the ones that affect the slice into `docs/architecture.md` at integration.

#### A1 rulings on A6 SEL-751 notes (b354d01) and A5 follow-up (9f14154, 5465af5) — 2026-10-23
- **C-19 accepted** into ADR-0005: after a failed password the adapter closes the connection without sending `QUI`; if `ACC` reaches Level 1 with no prompt, the credential is not sent. A2 implements this in the session driver; A6's simulator profile is the test.
- **C-20 accepted:** manual figures are `documented-example`, not byte-level ground truth; parsers must not depend on figure checksums being self-consistent, and each fixture records which checksums verify.
- **`TAR R` (Level 1, p. 7.82)** is state-changing (target reset) and must stay out of the register; A6 confirms it is in the deny corpus.
- **B-03 / C-18 (delivery and retirement):** already ruled in ADR-0004 item 6 (required vs best-effort targets, replay-window retirement, audited admin retirement); A5's per-consumer `required` flag implements it. B-03 closes when C5/C6 contract text carries these semantics in Phase 1.
- **R-A3-4 (ack channel):** already ruled: mode A only for `required` targets, with an ack-only parser that can advance only the forwarding cursor (TB5 wording per A6/A4). Closes with C6 contract text.
- **A5 durability changes:** ADR-0004 item 8 amended with `auto_vacuum=INCREMENTAL` at creation and the startup recovery order; items 6 and 7 already match A5's (1) and (3).
- **A5 §12:** SEL-3355-2 as candidate site node noted (`documented-untested`); AMT isolation and RTC drift recorded; site computer choice is on the owner request list.
- **Support gate** in docs/verification.md (per SEL family and device class) accepted for Phase 1.
- **A3 follow-up (bd29be1, PR #1):** AC-12 physical access and AP-23 password-bypass jumper accepted; ADR-0005 now says an `ACC` that reaches Level 1 without a prompt closes the connection and raises a security alarm (test: bypass-enabled simulator, zero credential bytes). AP-22 (spoofed or relayed UDP Syslog from SEL-2488, RTAC, switches) accepted: the C4 event contract in Phase 1 must carry an `origin_auth` field and separate sender (transport peer) from subject (asset the event is about). Recorded for the A4 Phase 1 brief.
- **A4 follow-up (74ae579, PR #4):** rulings recorded in the schema draft; `kind` is an open set (adds `soe-log`, `device-log`, `host-event`, `device-status`); `source.sender` and `source.origin_auth` added per AP-22. Proposal to split `tls-pinned` into `tls-server-only` and `tls-mutual` (SEL-5056 documents server-side trust only) is accepted as input to the Phase 1 C4/C6 briefs, with A3 as required reviewer. C4–C6 text held until Phase 1 briefs.
- **Decision posted to the owner (A3 raised), 2026-10-23:** how to collect Windows server, historian and HMI events: host push (sites configure forwarding, platform holds no Windows credentials and installs no agent; silent-host alerting), platform pull with a read-only event-reader account, or a platform-installed agent. A1 and A3 recommend host push.
- **PR status:** A3 accepted PR #3; all Phase 0 PRs wait only on the owner's merge approval.
- **A2 follow-up (bb6f850, PR #2):** conditions met. A1 checked IM Table 7.1 (Port 1 is the rear Ethernet port, ordering options 1–4). A2 reports no `:=` setting carries a password (passwords only via `PAS`, Table 7.52) and the manual prints no example `SHO G`/`SHO P` output, so the simulator has no documented example for these lines. `CSE` is a denied deferred candidate; non-SEL contrast references are marked superseded; D26 (password disabled: the secret would be executed as a command) is covered by ADR-0005's no-prompt rule.
- **A6 follow-up (PR #6), 2026-10-23:** TAR R and SER D are in the deny corpus; 27 SHO variants denied, A2 bb6f850 passes, read-only set equals A6's 6-line allow corpus; V-S16 (MAXACC warning) written, simulator serves `SHO P 1`. D25 independently confirmed (7 of 9 checksums fail). Rulings: (1) FTPACC/HTTPACC warning added to ADR-0005; (2) **LANG ≠ ENGLISH refuses collection** (ADR-0005; A1 verified the Spanish column of the Command Summary: `SER D o R` clears SER); (3) R-A5-5 added to ADR-0004 item 8 (prune boundary from persisted consumer cursors). The adapter result needs a `warnings` field and a refusal reason for posture checks: input to the Phase 1 C2 brief.
- **A2 language probe (9bdb98d):** accepted into ADR-0005: `QUI` at Level 0 before `ACC`; rejection closes without elevating. A1 verified the three-letter rule and that no Spanish command starts `QUI` or `SHO` (`QUIT`→`SAL`, `SHO`→`MOS`). A6 to simulate both an English-names-accepted and an English-names-rejected Spanish port.
- **A6 language tests (32322dd, PR #6):** V-S17, H-12, F-007 added; 7/7 pass against A6's reference reading of ADR-0005 (not yet against the adapter). Probe must positively match the Level 0 prompt (ADR-0005 amended). Spanish `D` as a clear argument extends to `HIS D o R` and `HIS HIF DT o RT`; 23 Spanish forms added, deny corpus 135 lines; A2 register 986238b passes. H-12 (real Spanish-mode behaviour) needs hardware.
- **Probe reply grammar (A2, 2026-10-23):** the IM documents no QUIT reply, so "exactly the Level 0 prompt" is replaced by a fixed grammar (optional Table 7.16 header, optional `Level 0` line, `=` prompt, nothing else); defined in the C2 brief; the real reply is a hardware/capture verification item for A6.
- **A6 grammar tests (0d9cd85, PR #6):** V-S17 has 3 accepted forms and 7 near misses (all stop after `QUI`, zero credential bytes). Blank line after the header is A6's assumption from p. 7.32, to be pinned in the C2 brief. H-13 added: real Level 0 QUIT reply under each `DATE_F` value plus a `SHO P 1` capture before any real collection.
- **A6 review of A4 (0a20f69, PR #4):** R-A4-1 accepted for C5: the SER alignment key excludes the row number, because SEL-751 row 1 is always the newest (IM Table 7.63) and every new event renumbers the buffer; with the row number, 3 of 6 cases report false gaps and re-ingest. Snapshot alignment (C-13) still handles identical rows by multiplicity. V-S4 covers it. RELP Direct queues 12/12 no loss (process crash only; power loss is H-11). GOOSE rules fail 8/8 adversarial cases: Phase 4 input, not blocking.
- **A4 follow-up (74a64eb, PR #4):** alignment key now covers row bytes from DATE to end of line, no row number; A6 harness 6/6. R-A4-2 adopted (ambiguous overlap keeps most rows and flags possible duplicates). All Phase 0 agent follow-ups are in; agents hold until Phase 1 briefs.
- **Owner decision 2026-10-23:** Windows host events by host push (no Windows credentials held, no agent; silent-host alert). Recorded in ADR-0006 owner clarifications. Inputs: A3 threat model (receive-only boundary, AP-22 origin authentication applies), A4 C4 (`host-event` kind, sender/subject split), A6 (silent-host alert test).
- **A3 follow-up (127f8bd, PR #1):** TB11 Windows hosts → platform, receive-only; host `origin_auth` is `tls-mutual` only with a pinned host certificate, otherwise `none`; AP-25 closed by design (credential-store audit checks zero Windows credentials); AP-26 (agents) kept as excluded by owner decision.

### Owner answers and second manual set — 2026-10-23 (17:21Z)
**Manuals added** to `/mnt/project-files/phase0/manuals-SEL/` (PDF + `text/`, `documented-untested`): SEL-2401, SEL-2404, SEL-2407 clocks; SEL-3350-1 (RTAC, replaces discontinued SEL-3530); SEL-3505, SEL-3530, SEL-3555-2 RTAC hardware; SEL-3610/3620/3622 shared IM; SEL-735; AG95-04 Compressed ASCII Commands (format, checksum rule, configuration message at any level). Not supplied: SEL Fast Message standalone document (the SEL-751 IM covers Fast Message in its own appendix; A2 to check if it suffices), SEL-2730M, SSD-lifetime note (owner: not available).
**A1 grep only (A2 to read and cite):** SEL-3620/3622/3610 IM documents Syslog, SSH, SNMP, HTTPS; SEL-735 has Telnet and SER, no Syslog or SSH; SEL-2401/2404/2407 show no Syslog, SSH, Telnet, SNMP, or NTP; SEL-3555-2 has Syslog, SSH, SNMP, PTP.
**Owner answers:** recorded in `docs/requirements.md` "Owner answers". Consequences: ADR-0007 (proposed) Windows site node on SEL-3355-2; ADR-0002/0003/0004 amended; `docs/architecture.md` device table and assumptions updated.
**Follow-ups:** A5 owns ADR-0007 (Windows durability re-test, SCM supervision, service-account isolation, SSD write estimate); A3 credential-at-rest on Windows/TPM and AMT precondition; A6 Windows runs of E-02/E-03/E-04 and per-transport forwarding interoperability; A2 reads the new manuals and classifies; A4 forwarder transport set (RELP/TLS, 5425, 6587, 5426).
- **A3 follow-up on owner answers (d3d2da3+, PR #1):** (1) SEL-3620 IM §7: its proxy is not a command allowlist (unmatched input passes through, binary mode passes everything, a user who knows the relay password gets through), so it gives authentication, attribution and password secrecy but not per-operation control; HR-4 confirmed (Q1 §3.2). (2) HR-9 Windows node hardening: service-SID firewall rules so only the collector reaches the IED NIC, WDAC or AppLocker, BitLocker with TPM, no domain join, LTSC only. Folded into ADR-0007 as A3's requirements, pending A5 review. Owner asked to confirm no node runs plain Windows 10 Pro. (3) HR-10: plaintext Syslog targets carry a `forwarding_security` label and an admin acknowledgement, never `required`. (4) AS-6: the zenon central HMI reaches relays outside the platform; monitored only as a TB11 host.
- **Firmware allowlist safety ruling (A2 finding, A1 verified), 2026-10-23:** recorded in ADR-0005. Collection only from allowlisted FIDs with all communications-restart fixes; operator-declared FID checked before any connection; `ID` FID must match before `ACC`; otherwise fail closed with an alarm. A2 builds the allowlist per firmware branch from IM Appendix A; A6 checks it independently and adds tests (unlisted FID → zero bytes sent; FID mismatch → close before `ACC`); A3 adds the attack/hazard path (platform traffic restarting a relay) to the threat model. Fast Message doc not needed for the slice.
- **A6 (via coordinator, 17:30Z):** PR #6 verification plan adds Windows LTSC re-runs of the durability tests, a central-never-connects-to-devices test, and the SEL-751 firmware gate test. A6 firmware-gate item considered delivered; A1 still sends the allowlist assignment to A2 and the hazard path to A3.
- **A4 forwarder modes (4b4ccd0, b61c3d0, PR #4), A1 ruling 2026-10-23:** A4's reading is confirmed: modes B (RFC 5425), C (TCP, octet or LF framing) and D (UDP), and the RFC 3164 rendering, are `best-effort`; a `required` target must be mode A **over TLS** (plain RELP acks could be forged on the path and would advance pruning, so plain RELP is best-effort too). Treating a non-RELP collector as `required` would be an owner decision to accept undetectable loss; not raised unless a site needs it. 80/80 hostile sends against stock rsyslog arrived as one message each, none forged.
- **A6 F-008/F-009 (782aa2f, 34262db, PR #6):** accepted. C-21: N-1 redundancy does not remove partition tests. C-22/H-14: Linux storage evidence re-run on Windows LTSC. V-S6/V-S15 per Syslog transport; unacknowledged transports must make loss detectable (sequence numbers in structured data). V-S18 central never connects. C-23/V-S19: the `ID` probe is itself Telnet traffic, so the FID must be known before first connection; unknown-FID first contact needs owner authorization (added to ADR-0005). 7/7 simulator cases pass.
- **A2 D27 (ff8f605, PR #2):** superseded by the stronger ADR-0005 ruling (declared FID checked before connecting, `ID` confirms). CAS (AG95-04) deferred with `CSE`; no Fast Message document needed; SEL-2730M still missing.
- **A3 (ea8f58a, a10550b, PR #1):** AP-27 relay-restart hazard (T0816, T0837): FID allowlist ships in the signed register so central cannot widen it; checked before connect (FID recorded at commissioning by other means) and on `ID` before `ACC`. HR-10 matches the RELP-over-TLS ruling. SEL-3620 audit Syslog is UDP-only (`origin_auth` none). Windows credentials: no machine-scope DPAPI; key scoped to the collector service SID; admin/SYSTEM is a residual. ADR-0007 item 4 corrected to match.
- **A5 review of ADR-0007 (§14 of A5-platform-feasibility.md, PR #3):** items 2, 7, 8 agreed; amendments to 3, 4, 5, 6, 9 folded into ADR-0007 (durable session record and `TIDLE` before reconnect; user-scope DPAPI or TPM CNG key ACL'd to the collector SID; E-A5-6 and W-1..W-4, group commit for SSD wear; time-sync alarm threshold proposal; BitLocker TPM-only with owner-held recovery keys, WDAC signing in the release process, local accounts without a domain). Dedicated host and the Windows test runner are being confirmed with the owner in A5's thread.
- **A2 firmware allowlist (2585fd9, PR #2; `docs/phase0/A2-sel751-firmware-allowlist.json`, findings §15.7), A1 ruling 2026-10-23:** accepted for the simulated slice. Allowed: R501 ≥ V0, R500 ≥ V0 (V1 recommended). Conditional: R402 ≥ V2, R401 ≥ V5, R400 ≥ V7, collection only if `SHO P 1` reads `EHTTP := N` (web-server DoS fix not listed on those branches), otherwise refuse. Denied: R100–R113, R200–R202, R300–R302. Not covered: FIDs after 20260910, SEL-751A, special builds (fail closed). The "a branch first released after a fix contains it" inference is classed `inferred`; it does not block the simulated slice, but **before any collection from a real relay** the owner must either obtain SEL confirmation of fix inheritance or accept the inference in writing. Added to the owner's pre-production list; A6 checks the list independently against Appendix A.
- **A6 independent check of the allowlist (27ed082, PR #6, tests/safety/firmware_review/):** accurate; all 7 restart/lock-up fixes on exactly A2's rows. Every allowed branch relies on inherited fixes for F1 (Ethernet) and F2 (Telnet), and R402/R500/R501 also for F5 (comms access): on documented evidence alone the allowlist is empty. Owner asked to obtain SEL confirmation early (pre-production item).
- **Owner decision 2026-10-23 (18:47Z):** plain Windows 10 Pro allowed on platform nodes as an accepted risk, labelled "OS out of support" (ADR-0007 item 9). Inputs: A3 (residual in threat model), A5 (installer warns, does not refuse), A6 (label test).
- **Owner decision 2026-10-23 (18:47Z):** firmware fix inheritance accepted as an owner risk; allowlist entries classed `inferred (owner-accepted)` (ADR-0005). A2 marks the JSON; A6 checks the class; A3 records the residual under AP-27.
- **A6 (76e5940, PR #6):** check_allowlist.py fails allowed branches relying on unlisted F1/F2/F5 fixes unless classed `inferred (owner-accepted)` (A2 954fd86 currently fails until A2 adds the class). V-S20: OS label derived from each edition's lifecycle end date against the clock, so nodes relabel as dates pass; unknown edition → "OS support unknown". Accepted; A5 must cite Microsoft lifecycle dates before the test data is fixed (A6's dates are from memory).
- **A3 (e3b8e4e, 09783c7, PR #1):** both owner-accepted risks recorded (AP-27 [inferred], HR-9). A3 proposal accepted for the Phase 1 platform brief: an "OS out of support" node raises a standing low-severity condition (not a recurring alert) and records a migration date set by the operator; collection is unaffected.
- **A5 (findings §15, PR #3):** Windows lifecycle dates cited for V-S20 and sent to A6. Edition naming point added to ADR-0007 consequences. Windows test runs blocked: GitHub Actions runner never assigned (3 tries); A5 asked the owner to check Actions billing/settings.
- **Owner decision 2026-10-23 (18:53Z):** dedicated platform machine at each site, not shared with zenon; hardware may be a server other than the SEL-3355-2 (ADR-0007 item 1). A5: per-model commissioning checks; A6: no test assumes co-hosting.

### Phase 0 branches merged — 2026-10-23 (18:5xZ)
With the owner's approval, PRs #1–#6 were merged to `main` (heads: A3 09783c7, A2 85d8091, A5 830a0f4, A4 27a8182, A6 3b666e9, A1 f500e94). Trial merge had no conflicts. On merged `main`: 67 tests pass, 5 skipped; the 5 environment-gated tests pass with the SEL-751 manual text, A2 allowlist and A2 register (5 passed, 141 subtests). Further work goes on branches cut from `main`. SEL-2730M IM (20260408) supplied and added to `manuals-SEL/` (grep: Syslog, SNMP, RADIUS, HTTPS); A2 to classify. The repository default branch is still `claude/project-thread-03n4bh` (same commit as the old `main`); changing it is a repository setting the owner makes.
- **A6 F-010 / C-24 (PR #10):** no A6 test assumes co-hosting or 3355-2-only features. C-24 accepted: H-11 per hardware and drive model; node reports models and labels "storage durability unverified" without an H-11 result (ADR-0007). A3 PR #9: AS-7 and AP-24 widened to any out-of-band controller (ADR-0007 item 8). A2 PR #8: SEL-2730M classified.

## Phase 1 task briefs (issued 2026-10-24)

The owner accepted Phase 0 and authorized Phase 1 on 2026-10-24 at 11:16Z ("Continue phase 1"; see `docs/phase-0-exit.md`, "Owner sign-off"). Phase 1 approves contracts C1 to C8 and nothing else. Phase 2 code waits for the Phase 1 exit gate below.

### Common rules for every Phase 1 brief

- **Still no contact with operational equipment.** The Phase 0 rules on equipment, networks, credentials and fabricated evidence apply unchanged. Hardware checks (H-01 to H-14) are prepared, not run, unless the owner authorizes a lab device or site machine through A1.
- **Write only to owned paths.** Each contract owner writes its own package under `contracts/<pkg>/` (layout and rules in [contracts/README.md](../contracts/README.md)), plus `docs/phase1/<agent>-<topic>.md`. Reviewers write `docs/phase1/reviews/<contract>-<reviewer>.md`. `docs/architecture.md`, `docs/requirements.md`, `docs/agent-handoffs.md`, `docs/decisions/`, `contracts/README.md` and `contracts/version/` stay A1's. Proposals for them go in your findings file.
- **Contracts only.** A contract package holds types, validation, JSON Schemas, golden examples and tests. It does no I/O and has no device, storage or network logic. Standard library only.
- **One definition per concept.** The owning contract defines a concept and the others import it:
  - C1: asset ID and device identity;
  - C3: operation ID;
  - C4: event ID `(node_id, stream, seq)`, node ID and the timestamp model;
  - C7: principal, role and `CredentialRef`.
  Until the owner's package is merged, use the name and shape agreed in its draft PR and leave a `TODO(C<n>)` where you will import it.
- **Merge order** (later PRs rebase onto earlier ones; nobody waits to start): C4, C1, C3, C7, C2, C8, C5, C6.
- **Branch and CI.** Branch from `main` (`agent/<area>-phase1`, or your session's assigned branch). Open a PR against `main`. CI (`.github/workflows/ci.yml`) must be green on Linux and Windows.
- **Finish with a handoff** in the template above, listing every reviewer's outcome.

### Task P1-A1: Contract conventions, C3 format, integration and the Phase 1 gate
- Objective and rationale: give every owner one set of conventions and one tree to build against. Own the C3 format. Integrate contracts in order and decide the Phase 1 exit gate.
- Owner agent: A1.
- Required inputs and dependencies: `docs/phase-0-exit.md` ("Carried into Phase 1"), A2's register JSON, A6's register checker, `A3-review-A2.md`.
- Files or modules the agent may modify: `go.mod`, `contracts/README.md`, `contracts/version/`, `contracts/register/` (format only), `.github/workflows/ci.yml`, `CLAUDE.md` "Repository state", A1-owned docs.
- Expected interfaces: the `otsec.<name>/<major>.<minor>` identifier and compatibility rule (done, `contracts/version`). C3 register format `otsec.register/0.1`. It must cover:
  - exact lines;
  - parameters with validation patterns;
  - access level;
  - classification `read-only`, `state-changing` or `session-control` (C-A2-1: `session-control` entries are never invocable as operations);
  - citation;
  - per-family firmware allowlist inside the same package (C-A2-2);
  - a detached signature envelope with release key ID and anti-rollback floor, whose verification rules A3 defines in C7.
- Deliverable: skeleton, conventions and CI on `main`; C3 format package with schema and tests; integration of each contract PR; Phase 1 exit report in `docs/phase-1-exit.md`.
- Acceptance tests:
  - `go test ./...` is green on Linux and Windows.
  - A2's current register JSON converts to `otsec.register/0.1` with no information lost.
  - A6's deny corpus still passes against it.
  - `ACC` and `QUI` cannot be named as an invocable operation.
- Explicit exclusions: no register content changes (A2), no signing implementation (Phase 2).
- Uncertainty or safety risks: a register format that can express an unrestricted line would defeat risk 1. The schema must make free-form lines unrepresentable.

### Task P1-A2: C1 asset identity and capability profile; C2 adapter envelope; C3 content
- Objective and rationale: fix how a device is identified and how the collector is asked to do one approved thing and reports what happened. Closes B-02 and B-05 and tests Q5.
- Owner agent: A2.
- Required inputs and dependencies: A2 §9 draft interface, §15 manual results, the firmware allowlist, `A3-review-A2.md` C-A2-1 to C-A2-3, A3 §4.5 and §8.3, A4 EP-1 to EP-9, ADR-0005 rulings, and the C3 format from P1-A1.
- Files or modules the agent may modify: `contracts/asset/`, `contracts/adapter/`, register content (`docs/phase0/A2-command-register-draft.json` moving into the C3 package once the format lands), `docs/device-capabilities.md`, `docs/phase1/A2-*.md`, `tests/fixtures/ied/`.
- Expected interfaces:
  - **C1 `otsec.asset/0.1`:**
    - asset ID, device class and vendor/product family (ADR-0006);
    - each attribute with value, evidence source, evidence class and confidence;
    - `downstream_security` (plaintext labelled insecure);
    - the FID from `ID`, plus the serial number read after authentication, as the identity binding for a transport without cryptographic identity (B-05: state what is and is not proven by it, and what a mismatch does). *Amended 2026-10-24 on A2's finding:* the SEL-751 `ID` response (Figure 7.38) carries no serial number. The serial appears only at Level 1 (SER header, `STA`). Only the FID can be checked before the password is sent; the serial can only detect a substitution after the password has been sent;
    - the site platform node itself as an asset of class "server", carrying A5's posture labels.
  - **C2 `otsec.adapter/0.1`:**
    - **Invocation:** asset ID, operation ID from C3, validated parameters, `CredentialRef` from C7, and limits (timeout, retries, rate).
    - **Result:** the raw transcript as bytes, with byte spans for every send and receive, redaction markers (echo redaction mandatory until a capture shows no echo, C-A2-3), parsed records, and the closed error taxonomy with a failure fallback.
    - **Posture and refusals:** posture warnings and refusal reasons, including the FID gate, `LANG`, MAXACC, FTPACC and HTTPACC warnings, no password prompt (AP-23), and a failed password with no `QUI` (C-19).
    - **Language probe:** the reply grammar for the language probe.
- Deliverable:
  - **Packages:** the two contract packages with schemas, golden examples built from `documented-example` figures, and tests.
  - **Register:** the register, re-expressed in the C3 format with citations read from the manual. Closes B-02.
  - **Q5 test:** a paper exercise in `docs/phase1/A2-q5-rtac.md`, expressing RTAC collection against C1 and C2 and counting every special case the envelope cannot carry.
- Acceptance tests:
  - every C2 error code has a negative example;
  - a result whose transcript spans do not cover the bytes exactly is rejected;
  - an invocation naming a `session-control` or unknown operation is rejected;
  - an asset attribute with no evidence class is rejected;
  - the RTAC exercise needs no change to the envelope's shape, or the changes are listed and reviewed.
- Explicit exclusions: no Telnet driver, no parser implementation beyond the contract's record types, no new device families in the register.
- Uncertainty or safety risks:
  - FID and serial can be spoofed by anything on the station LAN. C1 must say so rather than imply authentication.
  - Manual figures are not byte-level ground truth (C-20).

### Task P1-A3: C7 authorization and credentials; C8 audit; security review of every contract
- Objective and rationale: fix who may ask for what, how device credentials are held on a Windows site node, and what is recorded. Closes B-04 and checks that no contract opens a path into OT (Q7).
- Owner agent: A3.
- Required inputs and dependencies: A3 §4.1, §4.2, §4.4, §4.6, the threat model (TB1 to TB11, AP-1 to AP-27, HR-1 to HR-10), ADR-0007 items 4 and 9, C-A2-2, A4's timestamp model (C4).
- Files or modules the agent may modify: `contracts/authz/`, `contracts/audit/`, `docs/threat-model.md`, `docs/phase1/A3-*.md`.
- Expected interfaces:
  - **C7 `otsec.authz/0.1`:**
    - **Roles and operations:** a role and operation matrix that separates monitoring, engineering, administration and security.
    - **`CredentialRef`:** an opaque handle. The main process never holds a secret.
    - **Collector IPC:** strict and allowlisted. The main process may ask the collector only to run a C3 operation ID against an enrolled asset. It can never send raw lines, change the register or read a secret.
    - **Credential storage on Windows:** a key scoped to the collector's service SID, no machine-scope DPAPI, plus rotation and revocation.
    - **Register package verification:** release key, anti-rollback floor, and failing closed when anything is missing, unsigned or unparseable (C-A2-2).
  - **C8 `otsec.audit/0.1`:**
    - records every collector request, refusal, posture warning, credential use and session;
    - shares the C4 timestamp model;
    - is append-only, with integrity chaining.
- Deliverable:
  - the two packages with schemas and tests;
  - `docs/phase1/A3-credential-design.md`, which closes B-04 after A6's review;
  - a security review record for each of C1, C2, C3, C4, C5 and C6 in `docs/phase1/reviews/`.
- Acceptance tests:
  - an IPC request with an unknown field, a raw command line or a `session-control` operation is rejected;
  - every C2 refusal maps to an audit record;
  - an audit chain with one record removed or altered fails verification;
  - an unsigned or rolled-back register package is rejected.
- Explicit exclusions: no engineering-access contracts (Phase 4), no central enrollment protocol (deferred).
- Uncertainty or safety risks: Telnet credentials cross the station LAN in cleartext (owner-accepted for the simulated slice only). C7 must keep that label visible and must not allow the same credential on a non-slice device.

### Task P1-A4: C4 event and timestamp schema; C6 Syslog forwarding profile
- Objective and rationale: fix the event every module produces and how it leaves the node, preserving native evidence. Closes B-03 together with C5.
- Owner agent: A4.
- Required inputs and dependencies: `A4-event-schema-draft.md` (§2 to §5), EP-1 to EP-9, A2 §7 and §15.4 (SEL-751 SER), ADR-0004 (required vs best-effort), owner answers (any standards-compliant collector; all transports offered).
- Files or modules the agent may modify: `contracts/event/`, `contracts/syslog/`, `docs/phase1/A4-*.md`, `tests/fixtures/network/`.
- Expected interfaces:
  - **C4 `otsec.event/0.1`:**
    - event ID `(node_id, stream, seq)` and node ID format;
    - native bytes verbatim, with native time verbatim;
    - resolution kept separate from accuracy, offset allowed to be "unknown", and time quality scoped;
    - asset reference (C1);
    - snapshot alignment for SEL ring buffers, with gaps reported as health events;
    - platform event types.
  - **C6 `otsec.syslog/0.1`:**
    - message format and size rules;
    - modes A and B;
    - transports: RELP over TLS, which is the only one allowed as `required`; RFC 5425, RFC 6587 TCP, RFC 5426 UDP and plain RELP as `best-effort`; plain TCP and UDP labelled insecure;
    - the TB5 ack-only grammar.
- Deliverable: the two packages with schemas, golden examples (SEL-751 SER rows from `documented-example` figures, mapped field by field) and tests.
- Acceptance tests:
  - every native SER example round-trips to C4 and back to identical native bytes;
  - an event whose rendered time claims more precision than its resolution is rejected;
  - a `required` target with any transport other than RELP over TLS is rejected;
  - a rendered message over the size limit is split or truncated only as the profile says, never silently.
- Explicit exclusions: no forwarder implementation, no IDS event types (Phase 4).
- Uncertainty or safety risks: semantic mapping is per device (Q3). C4 must not imply meaning it cannot carry.

### Task P1-A5: C5 local store, outbox and delivery semantics; node posture labels
- Objective and rationale: fix how events are kept, acknowledged, recovered and pruned on a Windows site node. This is where the Windows evidence (F-012, F-013) lands. Closes B-03 together with C6.
- Owner agent: A5.
- Required inputs and dependencies:
  - A5 §5 and §13;
  - ADR-0004 (item 8 and its F-013 note) and ADR-0007;
  - W-1 results;
  - A6 E-02 to E-04 and F-011 to F-013;
  - R-A5-5;
  - the event ID from C4.
- Files or modules the agent may modify: `contracts/store/`, `docs/phase1/A5-*.md`.
- Expected interfaces: C5 `otsec.store/0.1`, as Go interfaces with documented semantics, covering:
  - **Store shape:** per-module data ownership, with one writer per database.
  - **Commit before acknowledgement:** with **group commit required**. An acknowledgement is released only after its batch's commit returns at `synchronous=FULL` (W-1: 92/s one at a time vs 676/s in batches of 100).
  - **Outbox and cursors:** at-least-once delivery with consumer cursors, and the prune boundary taken from persisted cursors on every run (R-A5-5).
  - **Startup recovery order:**
    - the reserve is released before the store is first opened, and **a failed release is an error that stops startup, not a silent continue**;
    - **no other process opens the store before recovery completes**;
    - **what startup does when there is no reserve to release** (F-013's condition; propose and justify).
  - **Storage-full alarms.**
  - **Node posture labels:** "storage durability unverified" until H-11 passes for that hardware model (C-24), "OS out of support" or "OS support unknown" (V-S20), and the standing condition and migration date for an unsupported OS. Defined in `docs/phase1/A5-node-posture.md` and carried into C1 by A2.
- Deliverable: the package with interface tests against an in-memory fake, and `docs/phase1/A5-store-semantics.md`.
- Acceptance tests:
  - the interface makes it impossible to release an acknowledgement before its commit returns;
  - a prune call cannot take a boundary that is not a persisted cursor;
  - the startup sequence is expressed so that A6 can test each step's failure, including reserve release failing and reserve absent.
- Explicit exclusions: no SQLite implementation (Phase 2); no site-to-central protocol.
- Uncertainty or safety risks: F-013's failure mode is shown only on a Windows Server VM with Python's SQLite. The product driver and LTSC are untested (H-14 rest, A6).

### Task P1-A6: Independent contract tests, the integration chain, H-14 part 2 and hardware procedures
- Objective and rationale: prove the contracts fit together before any implementation exists, and close what can be closed without hardware.
- Owner agent: A6.
- Required inputs and dependencies: every contract PR as it opens, `docs/verification.md`, the recording simulator, A6's own SEL-751 transcription, and the H-14 harness.
- Files or modules the agent may modify: `tests/contract/` (new), `tests/integration/`, `tests/security/`, `tests/safety/`, `docs/verification.md`, `.github/workflows/a6-*.yml`.
- Expected interfaces: none of its own. A6 consumes every contract.
- Deliverable:
  - **Independent contract tests:** under `tests/contract/` for each contract, with positive and negative cases built from A6's own transcription, not the owner's fixtures.
  - **Chain test:** `tests/contract/chain_test.go`, which builds one SEL-751 `ID` plus `SER` collection end to end out of contract types only and checks the whole path with no gaps and nothing lost. The path is: C3 lookup, C7 IPC request, C2 invocation, C2 result with transcript, C1 identity check, C4 events, C5 commit and acknowledgement, C6 rendering, and C8 audit records. Run it on Linux and Windows in CI.
  - **H-14 part 2:** fix the harness setup (WinError 32), then run the reserve-first order, `INCREMENTAL` and R-A5-5 on NTFS as a non-admin account. A1 dispatches it. Record the result as F-014.
  - **Hardware procedures:** step-by-step, read-only procedures with stop conditions for H-01 to H-13 and the hardware half of H-14, ready for when the owner authorizes a lab relay or site machine.
  - **Thresholds:** confirm, or ask the owning agents to confirm, every V-S threshold marked *(proposed)*.
  - **Reviews:** review each contract per the table in `docs/architecture.md`.
- Acceptance tests:
  - the chain test fails if any contract changes a shared concept's shape;
  - each contract has at least one negative test that its owner did not write;
  - the H-14 part 2 report says whether the reserve-first order keeps a full store openable on NTFS.
- Explicit exclusions: no product implementation, no hardware runs without the owner's authorization.
- Uncertainty or safety risks: tests derived from the same manuals as the contracts share their errors (risk 3). Mark which tests have independent ground truth.

### Phase 1 exit gate (A1 decides)

- C1 to C8 merged at 0.x, each with every listed reviewer's record.
- The chain test passes in CI on Linux and Windows.
- B-02, B-03, B-04 and B-05 are closed, or carried with the owner's explicit agreement.
- A3's security review is recorded for every contract, with no open safety or security objection.
- `docs/phase-1-exit.md` gives the integration path for Phase 2: the order of components, who builds which, and the first end-to-end test.

## Phase 1 handoffs (2026-10-24)

Each agent's full handoff is linked below; these entries are the summary A1 accepted. Every item is `desk` or `simulated`; nothing ran against a device.

### Handoff P1-A2 — A2 — 2026-10-24
Full text: `docs/phase1/A2-contracts.md`, `docs/phase1/A2-q5-rtac.md`.
**Completed:** C1 `otsec.asset/0.1` (#32, endpoint `target` #65), C2 `otsec.adapter/0.1` (#51, D1-25 follow-up), C3 SEL-751 register content rev 2 (#32), Q5 RTAC paper exercise (passes, D1-21).
**Reviewers and outcome:** C1 accepted by A3, A4, A6; C2 accepted by A1, A3, A4, A6 after two rounds (dialogue rules checked against the bytes).
**Open:** C3 content change naming `SHO G` as the read for `DATE_F`; capture-dependent assumptions H-12, H-13, H-15.

### Handoff P1-A3 — A3 — 2026-10-24
Full text: `docs/phase1/A3-credential-design.md` and the A3 review records in `docs/phase1/reviews/`.
**Completed:** C7 `otsec.authz/0.1` and C8 `otsec.audit/0.1` (#38; D1-20 amendment wording and `transcript_sha256`, #64); security review of C1 to C6; credential design closing B-04 as a design.
**Reviewers and outcome:** C7 accepted by A2, A5, A6; C8 accepted by A4, A6.
**Open:** Windows credential mechanisms T-1 to T-5 on the site image (H-14); pinned-key enrollment before any SSH family.

### Handoff P1-A4 — A4 — 2026-10-24
Full text: `docs/phase1/A4-handoff-phase1.md`, `docs/phase1/A4-contracts.md`.
**Completed:** C4 `otsec.event/0.1` (#29, #42, `evidence_class` #59, D1-24 amendment rule #63) and C6 `otsec.syslog/0.1` (#42, `evc` #59, `RenderAudit`/`ParseAudit` #63).
**Reviewers and outcome:** C4 accepted by A2, A3, A5, A6; C6 accepted by A1, A2, A3, A5, A6.
**Open:** render `evc` through `Source.Simulated()` (A1 note on #59); PEN 32473 replacement before production.

### Handoff P1-A5 — A5 — 2026-10-24
Full text: `docs/phase1/A5-handoff-phase1.md`, `docs/phase1/A5-store-semantics.md`, `docs/phase1/A5-node-posture.md`.
**Completed:** C5 `otsec.store/0.1` (#33): ownership, group commit, outbox and cursors, audit sealing, startup recovery order, storage-full actions; node posture labels.
**Reviewers and outcome:** accepted by A3, A4, A6.
**Open:** `OpenHeadroomBytes` untested against F-013; listener `target` and the `device-observed` interlock go into the Phase 2 node configuration (D1-24 and its amendment).

### Handoff P1-A6 — A6 — 2026-10-24
Full text: `tests/contract/README.md`, `docs/phase1/A6-chain.md`, and the A6 review records in `docs/phase1/reviews/`.
**Completed:** independent contract tests for C1 to C8; C2 probes as contract tests; the chain test across all nine links on Linux and Windows (run 40115458123; final run in `docs/phase-1-exit.md`); H-14 third run (F-014); hardware procedures prepared, not run.
**Findings that changed contracts:** C2 dialogue rules (round 1), C1 endpoint `target` (D1-24), the floor starting at `ACC` (D1-20 amendment), the C2 faults in D1-25.
**Open:** H-14 remaining cases; every H-item awaits the owner's authorization of a lab device.

## Phase 2 task briefs (issued 2026-10-24)

On 2026-10-24 at 19:15Z the owner accepted the Phase 1 exit and started Phase 2 ("Start Phase 2 now"; see [phase-1-exit.md](phase-1-exit.md)). Phase 2 builds one working slice: **a simulated SEL-751, then the collector, the node store, the forwarder and an upstream Syslog collector, with local asset identification and evidence preservation.** The decisions every brief relies on are D2-1 to D2-7 in [phase2/A1-decisions.md](phase2/A1-decisions.md).

### Common rules for every Phase 2 brief

- **No device.** Every endpoint is `target: simulated`, and the only device is A6's recording simulator. Lab devices, site machines and real credentials all need the owner's authorization through A1 (D1-24, D2-4, D2-5).
- **Write only to owned paths** (D2-1). Contract changes are proposals to the contract's owner and A1. Each change bumps the contract's minor version and has its own PR with its reviewers.
- **Dependencies:** standard library, plus `modernc.org/sqlite` and `golang.org/x/sys`. Anything else needs A1's approval first (D2-2).
- **Tests:** unit tests next to the code, a fuzz target for every parser of device or network input (ADR-0003), and negative and failure tests. They run on the owner's PC first, then on Linux (D1-26, D2-7). Every evidence statement carries its class. Nothing in Phase 2 is `hardware-verified`.
- **Small PRs.** Each PR is one step a reviewer can check. Branch from `main` and use your session's branch. Reviewers follow `CLAUDE.md` §5.6.
- **Finish with a handoff** in the template at the top of this file.

### Task P2-A1: Integration, CI and the Phase 2 gate
- Objective and rationale: keep the slice integrable from the first PR, run the integration job, and decide the gate.
- Owner agent: A1.
- Required inputs and dependencies: D2-1 to D2-7 and `docs/phase-1-exit.md`.
- Files or modules the agent may modify: `go.mod`, `go.sum`, `.github/workflows/ci.yml`, `contracts/README.md`, `contracts/version/`, `CLAUDE.md` "Repository state", and A1-owned docs.
- Expected interfaces: none new. A1 reviews every module's seam with its neighbours.
- Deliverable:
  - the CI `integration` job (D2-3);
  - a review of every PR that adds a dependency or crosses a module seam;
  - the Phase 2 exit report in `docs/phase-2-exit.md`.
- Acceptance tests: the integration job runs A6's end-to-end suite on Linux, against rsyslog with RELP.
- Explicit exclusions: no module implementation.
- Uncertainty or safety risks: A1 must not become the implementer of last resort (`CLAUDE.md` §4).

### Task P2-A2: Telnet transport and the SEL-751 adapter
- Objective and rationale: the first adapter that really talks to a device, implementing C2 exactly as ADR-0005 and D1-20 require.
- Owner agent: A2.
- Required inputs and dependencies: C1, C2 and C3 on `main`; ADR-0005; D1-16, D1-20 and D1-25; A6's recording simulator; the C6-A2 notes (no STX, ETX or CR LF in record bytes, and `DATE_F` from `SHO G`).
- Files or modules the agent may modify: `modules/ied/telnet/`, `modules/ied/sel751/`, `tests/fixtures/ied/`, `docs/device-capabilities.md`, and `docs/phase2/A2-*.md`.
- Expected interfaces:
  - a function from a C2 `Invocation`, a resolved credential handle and a C1 profile to a C2 `Result`, which `Result.Validate` and `CheckAgainst` accept;
  - a hook the collector calls before `ACC` is sent and when `=>` is seen, so A3 can keep the failed-auth floor durable;
  - no other exported surface.
- Deliverable:
  - **Telnet client:** RFC 854 with every option refused (`WONT`/`DONT`), and bounded reads.
  - **Session dialogue:** the D16 wake and language probe, the FID gate before `ACC`, `ACC` with the single-use credential slot and echo redaction, `SHO P 1` for the LANG, MAXACC, FTPACC and HTTPACC warnings, `ID`, `SER`, then `QUI`.
  - **No QUI after a failed password:** close the connection instead (C-19).
  - **No password prompt:** close and raise an alarm (AP-23).
  - **Every line:** the C3 egress check on the final socket bytes.
  - **Framing:** STX/ETX handling.
  - **Parsers:** for `ID`, `SER` and `SHO P 1`, each with golden tests and a fuzz target.
- Acceptance tests:
  - every C2 golden transcript replays to its expected `Result`;
  - against the simulator, A6's tests for the language probe, the FID gate, the session state and the firmware gate pass;
  - fuzzing the parsers for 60 seconds per target finds no panic;
  - no line outside the C3 register can reach the socket, shown by a test that tries.
- Explicit exclusions: no SSH, no serial, no `SER` arguments, no families other than the SEL-751, no credential storage.
- Uncertainty or safety risks:
  - the language probe reply grammar and the pending-password behaviour are unconfirmed on hardware (H-12, H-15);
  - mark them `simulated` wherever they appear.

### Task P2-A3: The collector service and the security boundary
- Objective and rationale: the only process that holds credentials and reaches devices. It must fail closed.
- Owner agent: A3.
- Required inputs and dependencies: C7 and C8; `docs/phase1/A3-credential-design.md` (host rules W-1 to W-4, tests T-1 to T-12); ADR-0007 items 4 and 9; D1-11, D1-20 and D1-24; D2-4 and D2-5.
- Files or modules the agent may modify: `cmd/otsec-collector/`, `modules/security/`, `modules/access/` (unchanged in this phase), and `docs/phase2/A3-*.md`.
- Expected interfaces:
  - **IPC:** C7 over a named pipe on Windows and a Unix socket on Linux. Only the node service's identity may connect.
  - **Client:** `collectorclient` for A5.
  - **Results:** each run returns the C2 `Result` and the collector-reported audit facts.
  - **Audit:** the node writes the audit records (C8, D1-11). The session-close record carries `transcript_sha256`.
- Deliverable:
  - the collector binary and service;
  - the credential store: sealed install with the pinned fingerprint, then revoke and clear;
  - durable collector state, written before `ACC` and cleared only after QUI (cleared on `=>` until D2-20);
  - checks in order before any connection: the role check, the `device-observed` refusal, the register signature, then the floor;
  - one session per device;
  - no `TIDLE` reconnect after an unclean exit (ADR-0007 item 3);
  - the collector excluded from crash dumps (T-5).
- Acceptance tests:
  - T-1 to T-12 from the A3 design pass as automated tests, T-9b included in all three cases;
  - a `monitor` principal cannot cause a run;
  - a request with any field outside C7 is refused before any I/O;
  - no secret is found in any byte the collector writes (T-5).
- Explicit exclusions: no remote engineering access, no SSH proxying, and no central node.
- Uncertainty or safety risks:
  - an administrator or SYSTEM compromise of the node remains a residual risk (ADR-0007 item 4);
  - the service-SID scoping is `[doc]` until it is tested on the owner's PC.

### Task P2-A4: Normalization and the Syslog forwarder
- Objective and rationale: native SER rows become C4 events without losing anything, and leave the node only with confirmation.
- Owner agent: A4.
- Required inputs and dependencies: C4, C5 and C6; D1-12, D1-14, D1-15, D1-21, D1-22 and D1-23; A4's RELP experiment from Phase 0; the A4 note on rendering `evc` through `Source.Simulated()`.
- Files or modules the agent may modify: `modules/telemetry/`, `modules/detection/` (unchanged in this phase), `tests/fixtures/network/`, and `docs/phase2/A4-*.md`.
- Expected interfaces:
  - **Normalizer:** C2 parsed records plus the stored native bytes go to C4 events, with `native.fields` exactly as printed and `device_time` with native precision. Overlapping reads are aligned, so a row that was already seen is never emitted again.
  - **Forwarder:** a C5 outbox consumer that renders C6 and sends over RELP/TLS. It advances its cursor only on a confirmed `durable_ack`.
- Deliverable:
  - both packages;
  - a fuzz target for every parser;
  - the receiving half of a RELP test server in Go for unit tests;
  - `evc` rendered through `Source.Simulated()`.
- Acceptance tests:
  - for every SER golden, the events reconcile 1:1 with the native rows;
  - re-reading with 0, 50 and 100 percent overlap emits no duplicate;
  - the forwarder survives the receiver closing mid-batch, resumes from the cursor, and loses nothing;
  - against rsyslog in the integration job, every event arrives exactly once, counting by `event_id`.
- Explicit exclusions: no Syslog receiver (the `lab-only` UDP listener waits for the owner's plaintext Syslog decision), no IDS, and no Zeek or Suricata.
- Uncertainty or safety risks: `durable_ack` depends on how the collector is configured (V-S6). The integration job's rsyslog configuration is the only evidence for it.

### Task P2-A5: Node runtime, store, configuration and the minimal interface
- Objective and rationale: the node keeps everything durably, recovers on its own and tells the operator what it is doing.
- Owner agent: A5.
- Required inputs and dependencies:
  - C5 and its three lock conditions from A3;
  - the alarm channel outside the store (C5-A3-5);
  - ADR-0004 (item 8 order) and ADR-0007;
  - W-1;
  - D2-1, D2-4 and D2-6;
  - the `Usage` and `CompactStep` conformance notes (V-S9).
- Files or modules the agent may modify: `cmd/otsec/`, `platform/`, `deploy/`, `ui/`, and `docs/phase2/A5-*.md`.
- Expected interfaces:
  - the C5 implementation, which passes the C5 contract tests;
  - the `otsec.nodeconfig/0.1` loader and a test helper (D2-6);
  - the scheduler that sends runs through `collectorclient`, commits through C5 and hands results to A4's normalizer;
  - an alarm sink.
- Deliverable:
  - the SQLite store: group commit, `synchronous=FULL`, `auto_vacuum=INCREMENTAL`, the reserve released before the first open, recovery that resumes, and quotas;
  - the node binary, and both services under the SCM;
  - the configuration with both `target` checks (D2-4);
  - a read-only CLI: `otsec assets`, `otsec events` and `otsec health`.
  - A minimal HTML view follows only after the slice passes end to end. It goes through the impeccable skill's new-work flow, which writes `DESIGN.md`.
- Acceptance tests:
  - the C5 contract tests and A6's D1-11 test pass against the real store;
  - killing the process at every commit point loses no acknowledged event;
  - startup is tested with the reserve present, with no reserve, and with the release failing;
  - a `device-observed` configuration refuses to load.
- Explicit exclusions: no central node, no site-to-central link, no upgrades or rollback, and no UI before the slice passes.
- Uncertainty or safety risks: the four open H-14 cases (no reserve, failed release, Windows 10/11 client edition, the product binary) are what this work must close or carry.

### Task P2-A6: End-to-end verification of the slice
- Objective and rationale: an independent check that the slice does what it claims, and nothing it must not.
- Owner agent: A6.
- Required inputs and dependencies: the recording simulator, the D1-26 setup on the owner's PC, `docs/verification.md`, and every Phase 2 PR as it opens.
- Files or modules the agent may modify: `tests/integration/`, `tests/security/`, `tests/safety/`, `tests/contract/`, `docs/verification.md`, and `.github/workflows/a6-*.yml`.
- Expected interfaces: none. A6 drives the built binaries from outside.
- Deliverable:
  - **The slice suite** (`tests/integration/slice/`):
    - forwarded events reconcile 1:1 with the simulator's native rows (timestamps, order, no duplicates, no loss), with `evc="simulated"` on every event;
    - the stored transcript's SHA-256 equals `transcript_sha256` in the audit chain.
  - **Safety:** the simulator's recording shows only register lines (V-S7). No write command is ever sent.
  - **Security:** negative tests for D2-4, D1-20 and the role checks.
  - **Failure:** interruption and restart, covering the forwarder target down, the node killed, the collector killed between `ACC` and `=>`, and the store at quota (V-S6, V-S9).
  - **Imports:** the D2-1 import-rule test.
- Acceptance tests: each check fails on a deliberately broken build, as a mutation check.
- Explicit exclusions: no hardware runs without the owner's authorization.
- Uncertainty or safety risks: the simulator and the adapter both come from the same manuals, so agreement between them is not hardware evidence (risk 3).

### Order

1. A5's store and node configuration, and A3's collector and IPC, start at once and in parallel. A1 adds the integration job.
2. A2 starts at once on the transport and parsers against replays. The adapter joins A3's collector once the IPC stub exists.
3. A4 starts at once on the normalizer against goldens. The forwarder joins once A5 exposes the outbox.
4. A6 writes the slice suite now against the simulator, and runs it at every integration step.

### Phase 2 exit gate (A1 decides)

- The slice suite passes on the owner's PC (Windows) and on Linux, rsyslog included, from one commit on `main`.
- Every component above is merged, with its reviewers' records.
- No safety or security objection is open.
- The V-S checks in scope pass: V-S6, V-S7 and V-S9.
- `docs/phase-2-exit.md` records what is `simulated`, and what needs a lab relay before it can be called supported.

## Owner clarification and Phase 2 acceptance — 2026-10-26

On 2026-10-26 the owner clarified the monitoring goals and the collection-method order (recorded in [ADR-0008](decisions/ADR-0008-monitoring-goals-and-collection-method-order.md) and `docs/requirements.md` R1.8, R3.6, R3.7, R4.8, R4.9, R6.7 and R9), asked that they be in the Phase 3 and Phase 4 plan, and then said: "After you finish with the update I gave you, start on phase 3." A1 records that as the owner's acceptance of the Phase 2 exit with its conditions ([phase-2-exit.md](phase-2-exit.md)).

## Phase 3 task briefs (issued 2026-10-26)

Phase 3 hardens the slice so that a `device-observed` endpoint can later be allowed, closes the Phase 2 conditions in [phase-2-exit.md](phase-2-exit.md), and starts the owner's monitoring goals at their first rung: received Syslog (R4.1, R4.9) and the capability-matrix record of which rung each SEL family reaches (R3.7, R4.9, R1.8). Nothing in it contacts a device. The decisions every brief relies on are D2-11, D2-12, D2-16, D2-20 and D2-21 in [phase2/A1-decisions.md](phase2/A1-decisions.md) and ADR-0008.

### Common rules for every Phase 3 brief

- The Phase 2 common rules stand: no device, write only to owned paths (D2-1), the dependency list (D2-2), tests with their evidence class, small PRs, a handoff at the end.
- **Testing (D2-13, extended):** GitHub Actions is the main test path. A PR merges when its reviewers accept it and all seven CI jobs are green on its head. The owner's PC is the second Windows run, used only through the owner's own elevated session; nothing is installed there beyond what the owner approved.
- **Contract changes** bump the minor version, carry a reader for the previous version where a stored artefact may still exist, and record the rollback note in the release notes (`level_open`, C2 0.3 and `unanswered`, and now any field below).
- **Evidence class** stays `simulated`. H-01 to H-15 remain prepared only.

### Task P3-A5/A6: The slice against the installed Windows services (gate condition 1)
- Objective and rationale: the end-to-end suite has run on Linux only. The shipped configuration is two Windows services under the SCM with the installer's WER exclusion and the admin folder's SIDs (D2-21). Running the slice against them closes the one gate item carried as a condition.
- Owner agents: A5 (the harness path to installed services) and A6 (the run and its record). A1 coordinates the owner's session.
- Required inputs and dependencies: the installer and `OTSEC_REQUIRE_ELEVATED=1` run at `c486e42`; `tests/integration/slice/`; the owner's PC and the owner's UAC approval for each elevated step.
- Files or modules the agent may modify: A5: `platform/`, `deploy/`, `tests/integration/slice/slicerun.py` and `slicehelper/` only for a Windows service mode; A6: `tests/integration/slice/`, `docs/verification.md`.
- Expected interfaces: a slice mode that drives the installed `otsec-node` and `otsec-collector` services instead of spawning processes: start and stop through the SCM, the collector's named-pipe or socket path as installed, the administrator's file through the installed `config\admin`. The simulator and the RELP receiver stay user processes on 127.0.0.1.
- Deliverable: `test_slice_e2e.py`, `identity` and `failures` passing against the installed services on the owner's PC, with the run's log and commit recorded in `docs/verification.md`; the Windows row of V-S6 and V-S9 stated as run or not run.
- Acceptance tests: every row arrives once (reconcile), the recording check passes, the password is nowhere, and the services are left as the installer left them (the uninstall row still passes).
- Explicit exclusions: no change to the installer's privileges or ACLs to make a test pass; no self-hosted runner on the owner's PC; no run while the owner is away.
- Uncertainty or safety risks: a kill test against installed services needs SCM stop semantics, which differ from SIGKILL; state that difference rather than hiding it.

### Task P3-A3: Admin-signed C7 requests (C7 0.4) and the §9 node key store
- Objective and rationale: D2-11 found that a compromised node can use the install path as an equality oracle for passwords; the interim install budget bounds but does not stop it. Independently authenticated requests remove the oracle. D2-12's file resolver for TLS references is lab-only and must be replaced before any `device-observed` endpoint.
- Owner agent: A3. A5 implements the node side of the key store. A2 reviews for IED compatibility of the request fields.
- Required inputs and dependencies: D2-11's ruling (the signed fields, the fixed domain-separation prefix, the single-use nonce spent durably, the maximum lifetime); `docs/phase1/A3-credential-design.md` §9; C7 0.3 and C8 0.2 on `main`.
- Files or modules the agent may modify: `contracts/authz/` (C7, with A1's approval), `contracts/audit/` only if a new record type is needed, `modules/security/`, `modules/access/`, `docs/phase1/A3-credential-design.md`, `docs/phase3/A3-*.md`.
- Expected interfaces: a signed request envelope for install, revoke and clear-suspension with the fields D2-11 lists; a verifier in the collector that spends the nonce before any decision and refuses an expiry past the maximum; a key register and a non-exportable node key behind the C6 reference resolver, with the file resolver kept only behind an explicit lab flag.
- Deliverable: C7 0.4 with its contract tests; the collector refusing every unsigned or mis-bound request with one refusal code and no equality leak; the install budget retained as defence in depth; the node resolving `trust_anchor_ref` and `client_credential_ref` from the key store on Windows, files only with the lab flag.
- Acceptance tests (A6 independent): a replayed nonce is refused after a restart; a signature for one operation is refused for another; a request bound to another node ID is refused; a swapped sealed secret under a genuine signature is refused; no reply or log differs between a wrong guess and a right one; mutation of the verifier's checks is caught.
- Explicit exclusions: no real administrator key; no vendor-default or real-device password in any fixture (D2-11); no change to the collector's run path.
- Uncertainty or safety risks: the admin key's distribution and rotation are an operational procedure, to be written down and reviewed by A6, not solved in code here.

### Task P3-A2: The C1 endpoint path field, the port-server rule, and `DATE_F` from `SHO G`
- Objective and rationale: D2-16 requires an endpoint to say whether it is a direct Ethernet path or a port server before any `device-observed` endpoint, because only the direct path's `TIDLE` bounds the floor. The SER date order follows `DATE_F`, which the report does not print; the normalizer assumes MDY and flags it, so a DMY relay would misread days of 12 or less.
- Owner agent: A2. A3 reviews the floor rule; A4 reviews the `DATE_F` hand-off into C4.
- Required inputs and dependencies: D2-16 and D2-20; C1 and C3 on `main`; the SEL-751 manual's `SHO G` and `DATE_F` references (Table 4.90, Table 7.67); A6's simulator profile for the `SHO G` reply.
- Files or modules the agent may modify: `contracts/asset/` (C1, with A1's approval), `contracts/register/` content for `SHO G` (C3, signed), `modules/ied/sel751/`, `modules/ied/telnet/`, `tests/fixtures/ied/`, `docs/device-capabilities.md`, `docs/phase3/A2-*.md`.
- Expected interfaces: C1 gains `path` with the values `direct` and `port-server`; an endpoint with no path or an unknown one is refused like a port server; `SHO G` as a Level 1 read-only register entry; `sel751` reports `DATE_F` in the C2 result's device settings so that A4's normalizer takes the order from it rather than assuming MDY, with a parse error (never a skip) for a row that does not fit.
- Deliverable: C1 0.x with a reader for the previous version; the register entry and its deny-corpus check; the parser and its fuzz target; the goldens for MDY, YMD and DMY; the port-server refusal as a C2 refusal code.
- **Second deliverable (ADR-0008): the collection-method rungs in the capability matrix.** For every SEL family in `docs/device-capabilities.md`, three columns with their evidence class and citation: the event rung (received Syslog; file fetch over SFTP, SCP, HTTPS or FTP; command-line SER), the configuration rung (secure file transfer; FTP; command-line `SHO`), and the identity rung (SNMPv3; another read path; passive). For the SEL-751, the FTP assessment ADR-0008 decision 4 asks for: what `FTPACC := 1` permits, whether `/REPORTS` and the settings files are readable at that level, and what the manual says about writes at Level 1, each `documented-untested`. No FTP code in Phase 3.
- Acceptance tests (A6 independent): the three date orders reconcile against the simulator's rows; a DMY profile no longer produces the MDY assumption flag; a `port-server` endpoint gets zero sessions; the reported `TIDLE` shortens a floor only on `direct` and only after an `ok` or `partial` run. The matrix columns carry a citation on every cell (A6 spot-checks ten).
- Explicit exclusions: the port-server floor rule itself stays refused until `T_OUT` evidence exists (H-13); no checksum enforcement (V-S19 (d) stays a recorded gap until H-01 or H-13); no SNMP or FTP adapter yet.
- Uncertainty or safety risks: the `SHO G` layout is documented but untested; mark the parser `documented-untested` and keep every assumption in the goldens. A3's FTP objection (D7, D8) stands until the assessment is read.

### Task P3-A4: Syslog receive (R4.1, the first rung of R4.9)
- Objective and rationale: the owner's first rung for events is device-generated Syslog. SEL switches, the RTAC, the SEL-2488 and the SEL-3620 emit it; the contracts already carry it (C1 listener endpoints, C4 `origin: syslog`, C5 `syslog-stream` and `syslog-datagram` classes) and nothing is built. This is also the vendor-neutral path of ADR-0006.
- Owner agent: A4. A5 wires the listener into the node and the C5 classes; A3 reviews the listener as a new inbound surface; A2 reviews the per-family message layouts.
- Required inputs and dependencies: C1, C4, C5 and C6 on `main`; the documented examples in `tests/fixtures/ied/` (RTAC user logon, SEL-2730M, SEL-2488) and A2's per-family notes; the owner's open decision on plaintext Syslog outside the lab (carried from Phase 1).
- Files or modules the agent may modify: `modules/telemetry/receive/` (new), `modules/telemetry/normalize/` for `origin: syslog`, `tests/fixtures/network/`, `docs/phase3/A4-*.md`; A5: `platform/node/` and `platform/store/` for the listener wiring and the classes.
- Expected interfaces: a listener per C1 listener endpoint for RFC 5425 (TLS, mutual where the sender supports it) and, under the lab-only flag until the owner decides, RFC 6587 TCP and RFC 5426 UDP; parsing of RFC 3164 and RFC 5424 with the raw datagram or frame stored before parsing (R4.4); correlation of the source address to a C1 asset, or a `syslog.unknown-source` record kept and alarmed, never dropped; per-source rate limiting and the C5 quota rules; the existing outbox and forwarder unchanged.
- Deliverable: received Syslog from a sender on 127.0.0.1 stored, normalized, correlated and forwarded end to end on the real binaries; `otsec health` showing each listener and its last message; the per-family parse goldens for the three documented examples.
- Acceptance tests (A6 independent): every received frame's raw bytes are stored and hash-match what the sender sent (V-S8 for this origin); hostile framing (oversized, truncated, non-UTF-8, octet-count lies, nested priority) never crashes or hangs the node and never loses an earlier message; a flood from one source is rate-limited without affecting another source; a TLS sender with the wrong anchor is refused; an unknown source is kept and alarmed; duplicates from a retrying TCP sender are detectable through the raw hash and are never silently dropped.
- Explicit exclusions: no device sends to the platform in Phase 3 (every sender is a test process); no plaintext listener outside the lab flag until the owner decides; no event-behaviour baseline (R4.8) yet.
- Uncertainty or safety risks: a listener is an inbound surface on the site node; A3 reviews its exposure, its parsing under hostile input, and its storage behaviour under flood before the PR merges.

### Task P3-A5: Audited quarantine export, a clear for a halted asset, and the failed-open retry
- Objective and rationale: quarantine streams have no consumer and are never pruned, so a device whose outcomes are quarantined run after run fills adapter-evidence for good and halts with `collection-no-quarantine-room` until an operator acts; today there is nothing an operator can do except reinstall. The failed-open retry is the approved brief in `docs/phase2/A5-p3-failed-open-retry.md`.
- Owner agent: A5. A3 reviews the export's trust boundary and the clear's authorization; A6 writes the contract tests.
- Required inputs and dependencies: C5 0.x and C8 0.2 on `main`; #135's pruning and the quarantine-room alarms; D2-15's administrator file pattern; the approved failed-open brief.
- Files or modules the agent may modify: `contracts/store/` (C5, with A1's approval), `platform/store/`, `platform/node/`, `cmd/otsec/`, `docs/phase3/A5-*.md`.
- Expected interfaces: `otsec quarantine export <asset> <dir>` as a read-only CLI that writes each quarantined outcome with its raw bytes and hash and a manifest, then leaves a hashes-only manifest in `config/admin`, which the node verifies against its own stream and records as `quarantine.exported` (the CLI opens the store read-only and never writes the chain; D3-1); an administrator's `clear-quarantine.json` in `config/admin`, modelled on `clear-suspension.json`, that removes only outcomes named in a completed export and records `quarantine.cleared` with the manifest hash; the `Resume` from `ModeFailed` exactly as the failed-open brief states.
- Deliverable: the export and clear with their audit records; the retry with its typed cause; `otsec health` showing an exported-but-not-cleared quarantine.
- Acceptance tests (A6 independent): nothing is removed without a matching export manifest; a tampered manifest is refused; the export never runs while the node holds the exclusive lock in a way that breaks it (busy_timeout evidence); the failed-open brief's four cases; mutation of the clear's checks is caught.
- Explicit exclusions: no automatic deletion of quarantined evidence; no clear through the node's own IPC; no change to the pruning of confirmed events.
- Uncertainty or safety risks: an operator clearing evidence is a state-changing operation; it must be administrator-authorized the way D2-15's clear is, and A3 must agree before the PR opens.

### Task P3-A6: V-S8 end to end, the Phase 3 contract tests, and the installed-services run
- Objective and rationale: V-S8 (raw evidence preserved) passes in units only; end to end, every stored event's raw hash must equal the bytes the recording shows the simulator sent, including after a forced parser failure. A6 also writes the independent tests for every task above.
- Owner agent: A6.
- Required inputs and dependencies: the recording simulator and its `--profile` switches; `tests/integration/slice/`; the PRs of P3-A2, P3-A3 and P3-A5 as they open.
- Files or modules the agent may modify: `tests/integration/`, `tests/security/`, `tests/safety/`, `tests/contract/`, `docs/verification.md`.
- Deliverable: `test_slice_evidence_e2e.py` (V-S8), the acceptance tests named in each brief above, the Windows record of P3-A5/A6, and the Phase 3 status table.
- **Second deliverable (ADR-0008):** measurable acceptance criteria in `docs/verification.md` for R1.8, R3.6, R3.7, R4.8, R4.9, R6.7 and R9, written before any of them is implemented, each with its ground truth named and what needs hardware marked. The R4.8 criteria must fix the observation-period semantics and the false-positive measure; the R9 criteria must fix what evidence makes a finding `confirmed`.
- Acceptance tests: each check fails on a deliberately broken build (mutation), as in Phase 2.
- Explicit exclusions: no hardware runs without the owner's authorization.
- Uncertainty or safety risks: as in Phase 2, the simulator and the adapter come from the same manuals; agreement between them is not hardware evidence.

### Order

1. P3-A2 (C1 path, `SHO G`, then the matrix rungs), P3-A3 (C7 0.4), P3-A4 (Syslog receive) and P3-A5 (failed-open retry first, then the export) start at once and in parallel; each contract change is its own PR with A1's approval.
2. P3-A6 writes the new acceptance criteria and V-S8 end to end now, and the acceptance tests as each PR opens.
3. P3-A5/A6 on the owner's PC runs when the owner has a session free; it does not block the others.
4. Phase 4 is briefed after the Phase 3 gate, in the order ADR-0008 sets: (1) configuration retrieval, baseline and prior approval (R3, with the SEL-751 rung decided on A2's FTP assessment); (2) the event-behaviour baseline (R4.8); (3) vulnerability applicability (R9) with the asset module's SNMPv3 identity (R1.8); (4) IDS (R6); (5) secure engineering access (R2); (6) the central role (R8). The owner may reorder.

### Phase 3 exit gate (A1 decides)

- The slice passes against the installed Windows services on the owner's PC from one commit on `main`.
- C7 0.4, the C1 path field, the `DATE_F` read and the key store are merged with their reviewers' records, and A6's negative tests for each pass in CI.
- The quarantine export and clear, and the failed-open retry, are merged and tested.
- V-S8 passes end to end, and received Syslog passes A6's tests end to end on the real binaries.
- The capability matrix states the rung each SEL family reaches, with citations, and `docs/verification.md` has criteria for every requirement ADR-0008 added.
- No safety or security objection is open, and `docs/phase-3-exit.md` records what remains `simulated`.

## Phase 4 task briefs (draft, 2026-10-27; issued when the owner accepts the Phase 3 exit)

Phase 4 starts the owner's monitoring goals in ADR-0008's order. Only the first two expansions are briefed in full here, because they share the store and the audit chain and their contracts must be agreed together (CLAUDE.md §5.4). Items 3 to 6 are outlined with their dependencies; each gets a full brief, contracts first, when the one before it passes its gate. The carry-over and hygiene tasks run beside them. Nothing in Phase 4 contacts a device: every endpoint stays on the simulator (D2-4, D2-10), and H-01 to H-15 and Q3 stay prepared only until the owner authorizes a lab relay.

### Common rules for every Phase 4 brief

- The Phase 3 common rules stand: no device, owned paths only, the dependency list, evidence class on every test, small PRs, a handoff at the end.
- **Testing (D2-13):** a PR merges when its reviewers accept it and every CI job is green on its head. When the head's CI predates newer `main`, the Windows leg runs against the merged result before merge (Phase 3 lesson).
- **Toolchain (D3-10):** the latest patch of a supported Go minor; bumps are their own PR, reviewed by A3 and A6, never auto-merged.
- **Contracts:** each change bumps the minor, keeps a reader for the previous version, and has A6's contract tests before merge. A new contract is proposed by its owner and approved by A1 after every consumer reviews it.
- **A6's criteria are fixed first.** V-M1 to V-M8 in `docs/verification.md` are the bar. A brief may not lower a threshold after its test has run.

### Decision for the SEL-751 configuration rung (ADR-0008 decision 4)

Taken here, as ADR-0008 requires, on A2's FTP assessment (#183): **the SEL-751 stays on rung 3, command-line `SHO` over the Telnet path, for configuration as for events.** Rung 2 (FTP) needs hardware test Q3 to show that a Level 1 FTP login cannot write, and A3's D7 and D8 objection stands until then. Q3 needs the owner's authorization and an out-of-service lab relay. If Q3 shows a read-only Level 1 login, a later brief adds the FTP rung for the SEL-751 under V-M3's read-only bound, and the `SHO` path becomes its fallback. A family the matrix marks rung 2 with a documented read-only Level 1 (the SEL-400 series, whose manual states that no settings file writes at Level 1) is not built in Phase 4: it has no simulator profile and no register yet.

### Task P4-A2: Configuration retrieval for the SEL-751 (R3.1, R3.3, R3.5, R3.7)
- Objective and rationale: a configuration baseline needs a complete, repeatable read of the settings an engineer can change, with the native bytes kept, and a difference that ignores what is not a setting.
- Owner agent: A2. A6 reviews device safety and correctness; A3 reviews the register additions; A5 reviews the result's size and storage.
- Required inputs and dependencies: S22 (the `SHO` forms and their access levels, Table 7.67 and the settings tables in Section 4); C2 0.5, C3 0.2 and register revision 4; the `SHO G` and `SHO P 1` parsers; the deny corpus.
- Files or modules the agent may modify: `contracts/adapter/` (C2, with A1's approval), `contracts/register/` content (C3, signed), a new `contracts/config/` (C9, with A1's approval), `modules/ied/sel751/`, `tests/fixtures/ied/`, `docs/device-capabilities.md`, `docs/phase4/A2-*.md`.
- Expected interfaces:
  - **C9 `otsec.config/0.1`** (new, A2 drafts, A1 approves after A5, A3 and A6 review): a configuration snapshot (asset, retrieval time, the session's evidence ID, one section per settings class with its native bytes and SHA-256, and the parsed settings as name and value exactly as printed); a semantic difference between two snapshots (each changed, added or removed setting with both values); and the per-family rule that decides what is not a setting (headers, the relay's date and time, checksums, paging), stated in the contract and tested.
  - **C2 0.6**: a `config.read` operation whose result is a C9 snapshot. It reuses the session rules of `ser.read` (one session, at most one password, Level 1 only, `QUI` last, the failed-auth floor).
  - **Register revision 5**: each `SHO` form needed, at Level 1, each with its timeout and byte cap. No `SET`, `FIL WRITE` or Level 2 entry.
- Deliverable: the operation, the parsers with a fuzz target each, goldens transcribed from the manual's settings figures and tables, and the C9 difference with its non-semantic rules.
- Acceptance tests (A6 independent): every `SHO` line the collector sends is in the register and passes the deny corpus (V-S7); the same configuration read twice, with a different time and page break, gives an empty difference; each single-setting change A6 injects in the simulator gives a difference naming exactly that setting; a reply that cannot be parsed is kept with its bytes and fails the read (never a partial snapshot presented as complete); mutation of the non-semantic rule is caught.
- Explicit exclusions: no FTP code; no write or restore of settings (brief §1.3); no family other than the SEL-751.
- Uncertainty or safety risks: the `SHO` layouts are `documented-untested`; every assumption stays in the goldens. Each extra `SHO` line adds session time at Level 1, so the read's total time and the poll interval are stated in the register and checked against H-04 when hardware exists.

### Task P4-A3: Change approvals (R3.4, R3.6)
- Objective and rationale: the owner's rule is that a configuration stays unchanged unless a change was approved in advance. "In advance" must be provable from the audit chain, and an approval must come from a person, not from a compromised node.
- Owner agent: A3. A5 implements the node side; A6 writes the tests to V-M2.
- Required inputs and dependencies: C7 0.5's admin-signed node kinds and C8 0.4; D2-11 and D2-15; V-M2.
- Files or modules the agent may modify: `contracts/authz/` (C7), `contracts/audit/` (C8), `modules/security/`, `docs/phase4/A3-*.md`.
- Expected interfaces: **C7 0.6** adds the admin-signed node kind `node.change_approval` (asset, window start and end, reason, approver, nonce); **C8 0.5** adds `config.change_approved`, `config.change_detected` (with the C9 difference's hash and whether an approval matched) and `config.baseline_acknowledged`. Order in the chain decides "prior", never a time written in the approval (V-M2).
- Deliverable: the two contract changes with their tests; the verifier rules for an approval (signature, approver role, window not already ended, asset known).
- Acceptance tests (A6 independent): V-M2's seven cases, each binary; a replayed or re-signed approval for another asset is refused; editing or deleting an approval is caught by chain verification.
- Explicit exclusions: no approval through the node's own IPC; no approval entered in a UI; no link to an external ticketing system.
- Uncertainty or safety risks: an approval that is too broad (a long window, every asset) would silence real changes. The verifier caps the window (A3 proposes the cap) and the alarm text shows which approval silenced it.

### Task P4-A5: Configuration baselines in the node (R3.2, R3.4, R3.6)
- Objective and rationale: the node schedules configuration reads, keeps every snapshot, holds one acknowledged baseline per asset, and alarms on an unapproved difference.
- Owner agent: A5. A3 reviews the trust boundary; A6 reviews reliability.
- Required inputs and dependencies: C9 and C2 0.6 (P4-A2), C7 0.6 and C8 0.5 (P4-A3), C5 0.3.
- Files or modules the agent may modify: `contracts/store/` (C5, with A1's approval), `platform/`, `cmd/otsec/`, `docs/phase4/A5-*.md`.
- Expected interfaces: **C5 0.4**: a configuration stream class for snapshots with its own quota (never pruned while it holds the baseline or an unacknowledged difference); the schedule (a configuration read at most once per hour per asset by default, never in the same session as a SER read unless the register allows both); the first snapshot becomes the baseline only when an administrator acknowledges it (the same rule A1 set for R4.8); `otsec health` and `otsec config <asset>` show the baseline, the last read and any open difference.
- Deliverable: the schedule, the store class, the baseline and approval handling, the alarm, and their tests.
- Acceptance tests (A6 independent): V-M2 end to end on the real binaries with A6's GT-INJ change series; a snapshot is never lost across a SIGKILL at each commit point; the configuration class at quota stops configuration reads with a warning first and never displaces events.
- Explicit exclusions: no restore, no push, no automatic re-baseline.
- Uncertainty or safety risks: a configuration read holds Level 1 longer than a SER read; the failed-auth floor and the one-session rule apply unchanged.

### Task P4-A4: The event-behaviour baseline (R4.8)
- Objective and rationale: the owner's second goal. A per-asset baseline of Syslog and SER events, learnt over an observation period, with explainable alarms on departures.
- Owner agent: A4. A5 stores the baseline; A6 tests to V-M4; A2 reviews the event-type key for SER.
- Required inputs and dependencies: C4 0.2, the received Syslog and SER paths, V-M4 and "R4.8 observation period and measures" in `docs/verification.md`, which fix the event-type key, the clock, the period, the five departure rules and the measures.
- Files or modules the agent may modify: `modules/detection/` (new package for event baselines), a new `contracts/baseline/` (C10, with A1's approval), `tests/fixtures/network/`, `docs/phase4/A4-*.md`.
- Expected interfaces: **C10 `otsec.baseline/0.1`**: the baseline record (asset, period, coverage, each event type with its counts, hours and any period found), and the departure alarm (rule, parameters, baseline value, observation, the IDs of the events that broke it). Deterministic rules only; no machine learning.
- Deliverable: the learner, the five rules, the alarm, and the measures report.
- Acceptance tests (A6 independent): V-M4 in full, on GT-INJ series with a held-out benign series.
- Explicit exclusions: no machine learning; no network baseline (that is IDS, item 4).
- Uncertainty or safety risks: a synthetic false-positive rate says nothing about a real device; the real rate needs site data.
- **Timing.** C10 is drafted beside C9 so the two share their store design; A4's implementation follows P4-A5's C5 0.4.

### Task P4-A6: Verification for items 1 and 2, and the carried checks
- Owner agent: A6.
- Deliverable: the `SHO` forms in the simulator, from the manual and independently of A2, with a change injector; GT-INJ series for configuration changes and event departures, committed before the products' tests first run; the acceptance tests in each brief above; and the carried checks: the full DMY and YMD slice reconcile, and a Windows end-to-end check of the admin relay and `config\admin`'s ACLs on the hosted runner.
- Acceptance tests: each check fails on a deliberately broken build (mutation).
- Explicit exclusions: no hardware without the owner's authorization.

### Carry-over and hygiene (beside items 1 and 2)

- **A5:** #176 (the node reads its TLS keys from the key store; D2-12 closes), #177, and relay PR 2 of #181 (signed `clear-*`; N1/N3, N18, N21, N24, N27, N9; a deadline in `collectorclient.Do`). `runtime.Version()` in `otsec health`.
- **A4 with A5: HR-11's absolute bound.** A separate C5 stream and quota for unknown senders, with a health alarm when it is reached, and A6's test that fills it across an outage while a known device still stores. It gates the first `device-observed` listener. Also a configurable UDP receive buffer that logs the size granted, and a sound faster unknown count (the store keeps the stream's latest received time, or a running total saved with commits).
- **A1 with A3 and A6: move to Go 1.27.3** (the owner asked, 2026-10-27), as its own PR under D3-10's rule: full CI, A3 and A6 review, and the Windows UDP stress test repeated on 1.27. Kept off the Phase 3 gate so the gate's evidence stays on the toolchain it was gathered on.
- **A3:** a pinned `govulncheck` job in CI on every PR and weekly (A1 authorizes the `ci.yml` change); the C8 asset-ID-pattern test case; a POSIX-semantics rename (`FileRenameInfoEx`) plus a bounded retry in `replaceFile`, which the collector's state and the credential store share, keeping the fail-closed break as the fallback, because `MoveFileEx` failed 1556 of 3000 replaces beside a reader that shared delete, and both renames failed beside one that did not (2085 and 1652; A5's race check), with the floor written from the session's end when a write fails after `ACC`.

### Items 3 to 6 (outlines; full briefs later)

3. **Vulnerability applicability with the asset module (R9, R1.8).** A2 owns `modules/asset/` with an SNMPv3 read-only adapter under the register rules; A3 owns the signed offline advisory-set format; A6 builds GT-MIB and GT-ADV. Depends on item 1's identity and settings reads. The first SNMPv3 family needs its own simulator profile.
4. **IDS (R6).** A4, starting from the Phase 0 Zeek and Suricata evaluation and GT-PCAP. Neither stock engine decodes IEC 61850 MMS, GOOSE, SV or IEC 60870-5-104, so the brief starts by choosing the protocols the first sensor must decode, from the owner's sites.
5. **Secure engineering access (R2).** A3, from the Phase 0 Q1 comparison (protocol proxying against controlled remote workstations).
6. **The central role (R8).** A5, with V-S18.

### Order

1. A2 drafts C9 and A4 drafts C10 at once; A3 drafts C7 0.6 and C8 0.5. A1 approves the four together after every consumer reviews them.
2. A6 writes the simulator's `SHO` forms and the GT-INJ series at the same time, before any product test runs.
3. A2's `config.read`, A3's verifier and A5's C5 0.4 follow in parallel; A4's learner follows C5 0.4.
4. The carry-over tasks run beside them; HR-11's bound before any `device-observed` listener, D2-11's and D2-12's closures before any `device-observed` endpoint.

### Phase 4 first exit gate (items 1 and 2; A1 decides)

- V-M2, V-M3 (for the SEL-751) and V-M4 pass on the real binaries, `simulated`.
- C9, C10, C2 0.6, C5 0.4, C7 0.6 and C8 0.5 are merged with their reviewers' records and A6's contract tests.
- V-S7 still passes with the new register lines, and the deny corpus covers every `SHO` form added.
- #176 and relay PR 2 are merged; HR-11's absolute bound is merged or recorded as the open condition before any `device-observed` listener.
- No safety or security objection is open.
