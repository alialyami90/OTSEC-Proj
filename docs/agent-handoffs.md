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
