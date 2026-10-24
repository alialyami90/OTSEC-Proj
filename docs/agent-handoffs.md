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
    - FID and serial from `ID`, as the identity binding for a transport without cryptographic identity (B-05: state what is and is not proven by it, and what a mismatch does);
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
