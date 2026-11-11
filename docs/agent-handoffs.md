# Task Briefs

Maintained by D1. This file holds the task brief for every bounded piece of work, by phase, with the newest at the end. Where the work stands now is in [CLAUDE.md](../CLAUDE.md), "Current state". Older briefs keep the role names of their time: read A*n*, B*n* and C*n* as the role D*n* holds now.

## Task brief template

D1 issues a brief before assigning significant work.

```
### Task <ID>: <short title>
- Objective and rationale:
- Owner:
- Required inputs and dependencies:
- Files or modules the role may modify:
- Expected interfaces:
- Deliverable:
- Acceptance tests:
- Explicit exclusions:
- Uncertainty or safety risks:
```

The review pairs are in CLAUDE.md section 5.6.

## Phase 0 task briefs (issued 2026-10-23)

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
The project owner supplied six SEL data sheets (SEL-751 date code 20260910, SEL-311L, SEL-400G, SEL-411L, SEL-451, SEL-787-2/-3/-4). Copies, text extractions, and A1's reading notes: `reference/datasheets-SEL/` (`README-A1.md`). Class: OEM document, `documented-untested`. They are data sheets, not instruction manuals, so B-07 (command tables and example outputs) stays open. A2 and A6 read the PDFs themselves rather than relying on A1's notes. Items for A6: SEL-751 SER time-stamp resolution 1 ms, accuracy ±1 ms to the time source (event reports ±5 ms) for V-S3; SEL-311L single Telnet host session for V-S13; possible Spanish-language serial output for V-S2/V-S15.

### Cross-review P0-A5 — A6 — 2026-10-23
Record: section "A5 findings" of `docs/phase0/A6-cross-review.md` (commit 827fffc). Accepted for Phase 0. E-02 (strace): NORMAL left 1,011 of 1,016 acks unsynced, FULL 0 of 680, so E-A5-1 is R8.7 evidence for FULL only; new hardware test H-11 (power cut). E-03: after a crash at full disk, reads and draining work (6/6) but pruning fails (6/6) until space is freed. C-18: "prune only confirmed" plus "RFC 5425 never confirms" stops SER polling permanently. A6 also re-checked A3's follow-up (E1 14/14 over 3 runs, revocation proven; R-A3-1, 2, 3, 5 closed) and A2's follow-up (both corpora pass; snapshot dedup including ambiguous offset).
**A1 rulings:** folded into ADR-0004 (still proposed): required vs best-effort targets with a replay-window retirement rule (C-18); FULL for every cursor- or delivery-advancing stream; reserve release and pruning at startup.

### Handoff P0-A4 — A4 — 2026-10-23
Full text: in a working file that was not kept; findings in `docs/phase0/A4-telemetry-feasibility.md` and `docs/phase0/A4-event-schema-draft.md` on branch `claude/project-thread-ix2tu3` (PR #4). Summary:
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
The owner supplied 15 SEL instruction manuals and user's guides (SEL-751 IM date code 20260910, SEL-787-2/-3/-4, SEL-311L/-6, SEL-400G, SEL-411L, SEL-451-5, SEL-2488, SEL-2731, SEL-2741, SEL-3355-2, acSELerator RTAC SEL-5033, SEL-5056, Programming Reference, RSTP User's Guide, SDN User's Guide) and two more data sheets (SEL-2488, SEL-3355-2). PDFs and text extractions: `reference/manuals-SEL/`. Class: OEM document, `documented-untested`. **B-07 is unblocked for SEL-751.**

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
**Manuals added** to `reference/manuals-SEL/` (PDF + `text/`, `documented-untested`): SEL-2401, SEL-2404, SEL-2407 clocks; SEL-3350-1 (RTAC, replaces discontinued SEL-3530); SEL-3505, SEL-3530, SEL-3555-2 RTAC hardware; SEL-3610/3620/3622 shared IM; SEL-735; AG95-04 Compressed ASCII Commands (format, checksum rule, configuration message at any level). Not supplied: SEL Fast Message standalone document (the SEL-751 IM covers Fast Message in its own appendix; A2 to check if it suffices), SEL-2730M, SSD-lifetime note (owner: not available).
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

## Phase 4 task briefs (issued 2026-10-27)

Drafted by A1. B1 issued them on 2026-10-27, when the owner accepted the Phase 3 exit (D4-1 in `docs/phase4/B1-decisions.md`). In these briefs, A*n* means the role that B*n* now holds, and new files use the B name (`docs/phase4/B{n}-*.md`). D4-2 to D4-8 refine the briefs below; where they differ, the decision wins.

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
  - From A2's review of S22 (Table 7.67, p. 7.77; the `SHO` example on p. 7.78):
    - the register holds only exact `SHO` forms, with no trailing `s` (setting-name) form and an explicit port where the form takes one;
    - C9 states a continuation-line rule for SELOGIC values that wrap;
    - the parsers follow the documented three-settings-per-line layout;
    - `SHO P 1` is classed sensitive, although no settings class prints a password;
    - configuration and SER reads are scheduled back to back against `TIDLE` and the relay's two-session limit (with P4-A5's quiet interval).
- Deliverable: the operation, the parsers with a fuzz target each, goldens transcribed from the manual's settings figures and tables, and the C9 difference with its non-semantic rules.
- Acceptance tests (A6 independent): every `SHO` line the collector sends is in the register and passes the deny corpus (V-S7); the same configuration read twice, with a different time and any documented non-semantic difference, gives an empty difference (D4-9); each single-setting change A6 injects in the simulator gives a difference naming exactly that setting; a reply that cannot be parsed is kept with its bytes and fails the read (never a partial snapshot presented as complete); mutation of the non-semantic rule is caught.
- Explicit exclusions: no FTP code; no write or restore of settings (brief §1.3); no family other than the SEL-751.
- Uncertainty or safety risks: the `SHO` layouts are `documented-untested`; every assumption stays in the goldens. Each extra `SHO` line adds session time at Level 1, so the read's total time and the poll interval are stated in the register and checked against H-04 when hardware exists.

### Task P4-A3: Change approvals (R3.4, R3.6)
- Objective and rationale: the owner's rule is that a configuration stays unchanged unless a change was approved in advance. "In advance" must be provable from the audit chain, and an approval must come from a person, not from a compromised node.
- Owner agent: A3. A5 implements the node side; A6 writes the tests to V-M2.
- Required inputs and dependencies: C7 0.5's admin-signed node kinds and C8 0.4; D2-11 and D2-15; V-M2.
- Files or modules the agent may modify: `contracts/authz/` (C7), `contracts/audit/` (C8), `modules/security/`, `docs/phase4/A3-*.md`.
- Expected interfaces: **C7 0.6** adds two admin-signed node kinds: `node.change_approval` (asset, the hash of the baseline it approves a change against, window start and end, reason; the nonce, the expiry and the approver come from the C7 0.4 signed envelope, D4-2) and `node.baseline_ack` (asset, baseline kind, configuration or event, and the hash of the baseline acknowledged), so acknowledging a baseline is never an unsigned `admin_dir` file (D2-15's gap; A5, A1 decision); **C8 0.5** adds `config.change_approved`, `config.change_detected` (with the C9 difference's hash and whether an approval matched) and `config.baseline_acknowledged`. Order decides "prior", never a time written in the approval (V-M2): the collector accepts the approval and gives it a `collector_seq`, and a difference counts as approved only if that number is below the number of the `config.read` decision that found it, so a node cannot reorder them (A3). The approval window is capped (A3 proposes 24 hours, with a shorter default).
- Deliverable: the two contract changes with their tests; the verifier rules for an approval (signature, approver role from a per-key allowed-kinds list (D4-2), window not already ended, asset known).
- Acceptance tests (A6 independent): V-M2's seven cases, each binary; a replayed or re-signed approval for another asset is refused; editing or deleting an approval is caught by chain verification.
- Explicit exclusions: no approval through the node's own IPC; no approval entered in a UI; no link to an external ticketing system.
- Uncertainty or safety risks: an approval that is too broad (a long window, every asset) would silence real changes. The verifier caps the window (A3 proposes the cap) and the alarm text shows which approval silenced it.

### Task P4-A5: Configuration baselines in the node (R3.2, R3.4, R3.6)
- Objective and rationale: the node schedules configuration reads, keeps every snapshot, holds one acknowledged baseline per asset, and alarms on an unapproved difference.
- Owner agent: A5. A3 reviews the trust boundary; A6 reviews reliability.
- Required inputs and dependencies: C9 and C2 0.6 (P4-A2), C7 0.6 and C8 0.5 (P4-A3), C5 0.3, and relay PR 2 of #181. Approvals and baseline acknowledgements reach the collector only through the node's relay of signed requests (#189), which today carries credential kinds only; relay PR 2 widens it.
- Files or modules the agent may modify: `contracts/store/` (C5, with A1's approval), `platform/`, `cmd/otsec/`, `docs/phase4/A5-*.md`.
- Expected interfaces: the relay of signed requests (#189, widened by relay PR 2) for `node.change_approval` and `node.baseline_ack`. **C5 0.4**, one minor carrying three changes so two C5 minors are never open at once: a configuration stream class for snapshots with its own quota (never pruned while it holds the baseline or an unacknowledged difference) and a per-record byte cap, with the recovery reserve derived per database from its commit cap (D4-9, D4-13); HR-11's separate class and quota for unknown senders; and the faster unknown count (A5); the schedule (a configuration read at most once per hour per asset by default, never in the same session as a SER read unless the register allows both); the per-asset quiet interval applies across SER and configuration sessions, as a rule, not only as the schedule's effect (A5); the first snapshot becomes the baseline only when an administrator acknowledges it with a signed `node.baseline_ack` (the same rule A1 set for R4.8); `otsec health` and `otsec config <asset>` show the baseline, the last read and any open difference.
- Deliverable: the schedule, the store class, the baseline and approval handling, the alarm, and their tests.
- Acceptance tests (A6 independent): V-M2 end to end on the real binaries with A6's GT-INJ change series; a snapshot is never lost across a SIGKILL at each commit point; the configuration class at quota stops configuration reads with a warning first and never displaces events.
- Explicit exclusions: no restore, no push, no automatic re-baseline.
- Uncertainty or safety risks: a configuration read holds Level 1 longer than a SER read; the failed-auth floor and the one-session rule apply unchanged.

### Task P4-A4: The event-behaviour baseline (R4.8)
- Objective and rationale: the owner's second goal. A per-asset baseline of Syslog and SER events, learnt over an observation period, with explainable alarms on departures.
- Owner agent: A4. A5 stores the baseline; A6 tests to V-M4; A2 reviews the event-type key for SER.
- Required inputs and dependencies: C4 0.2, the received Syslog and SER paths, V-M4 and "R4.8 observation period and measures" in `docs/verification.md`, which fix the event-type key, the clock, the period, the five departure rules and the measures.
- Files or modules the agent may modify: `modules/detection/` (new package for event baselines), a new `contracts/baseline/` (C10, with A1's approval), `tests/fixtures/network/`, `docs/phase4/A4-*.md`.
- Expected interfaces: **C10 `otsec.baseline/0.1`**: the baseline record (asset, period, coverage, each event type with its counts, hours and any period found), and the departure alarm (rule, parameters, baseline value, observation, the IDs of the events that broke it). Deterministic rules only; no machine learning. C10 also states (A4): events flagged `asset-unresolved` belong to no asset's baseline (A6's invariant), and C10 says whether they are ignored or counted in a site-level total only; a repeat (the same `record_sha256` within a window) counts as an occurrence, not a duplicate to drop, because R4.8's repeated-alarm rule needs it; rate and time-of-day rules run on `received.utc`, with device time only as evidence in the alarm, since Syslog device time is often absent or year-assumed and SER time is the relay's own clock. This is within the Clock rule under "R4.8 observation period and measures" in `docs/verification.md`, which allows device time for time-of-day only when the offset is known; the alarm says which clock it used. C10 also says how a `possible-duplicate` event counts toward the repeats rule (A6). D4-4 records the drafting rulings from B4's ack (#229).
- Deliverable: the learner, the five rules, the alarm, and the measures report.
- Acceptance tests (A6 independent): V-M4 in full, on GT-INJ series with a held-out benign series.
- Explicit exclusions: no machine learning; no network baseline (that is IDS, item 4).
- Uncertainty or safety risks: a synthetic false-positive rate says nothing about a real device; the real rate needs site data.
- **Timing.** C10 is drafted beside C9 so the two share their store design; A4's implementation follows P4-A5's C5 0.4.

### Task P4-A6: Verification for items 1 and 2, and the carried checks
- Owner agent: A6.
- Deliverable: the `SHO` forms in the simulator, from the manual and independently of A2, with a change injector; GT-INJ series for configuration changes and event departures, committed before the products' tests first run; the acceptance tests in each brief above; and the carried checks: the DMY and YMD slice reconcile on the real binaries (the adapter-through-normalizer step passes since #211), a Windows end-to-end check of the admin relay and `config\admin`'s ACLs on the hosted runner; the unknown-restart leg on Windows; and a scan of the services' process command lines for the canary password.
- Acceptance tests: each check fails on a deliberately broken build (mutation).
- Explicit exclusions: no hardware without the owner's authorization.

### Carry-over and hygiene (beside items 1 and 2)

- **A5:** #176 (the node reads its TLS keys from the key store; D2-12 closes), #177, #182 (the refused-identity detail and the record-bound comment), and relay PR 2 of #181 (signed `clear-*`; N1/N3, N18, N21, N24, N27, N9; a deadline in `collectorclient.Do`). `runtime.Version()` in `otsec health`.
- **A4 with A5: HR-11's absolute bound.** A separate C5 stream and quota for unknown senders (in P4-A5's C5 0.4), with a health alarm when it is reached, and A6's test that fills it across an outage while a known device still stores. It gates the first `device-observed` listener. Also a configurable UDP receive buffer that logs the size granted, and a sound faster unknown count (the store keeps the stream's latest received time, or a running total saved with commits). It must keep #196's rule, charging at read and counting by received time: a running total keyed by commit time would bring back #178's edge (A4).
- **A1 with A3 and A6: move to Go 1.27.3** (the owner asked, 2026-10-27), as its own PR under D3-10's rule: full CI, A3 and A6 review, and the Windows UDP stress test repeated on 1.27. Kept off the Phase 3 gate so the gate's evidence stays on the toolchain it was gathered on.
- **A3:** a pinned `govulncheck` job in CI on every PR and weekly (A1 authorizes the `ci.yml` change); and a POSIX-semantics rename (`SetFileInformationByHandle` with `FileRenameInfoEx`, `FILE_RENAME_FLAG_POSIX_SEMANTICS | REPLACE_IF_EXISTS`) in `replaceFile`, which the collector's state and the credential store share. `MoveFileEx` failed 1556 of 3000 replaces beside a reader that shared delete, and both renames failed beside one that did not (2085 and 1652; A5's race check). The item: fall back to `MoveFileEx` when the call itself fails as unsupported (`ERROR_INVALID_PARAMETER`, `ERROR_NOT_SUPPORTED`, `ERROR_INVALID_FUNCTION`: FAT, exFAT, SMB shares, some filter drivers), logged once per process, rather than by Windows version, since ADR-0007's site floor is above every build that lacks the API (A3 and B3, #221); retry briefly (about 500 ms) on `ERROR_SHARING_VIOLATION` and `ERROR_ACCESS_DENIED`, logging each retry episode, then keep the fail-closed break; wrap the OS error with `%w` in `State.write` and the credential store; show durability with a crash test, since `FileRenameInfoEx` has no write-through flag; and write the floor from the session's end when a write fails after `ACC` and the session ends without `QUI`. (The C8 asset-ID-pattern test is already done in #187, `TestSchemaPatterns`.)

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


### Phase 4 item 3: Stage A briefs (issued 2026-11-05, D4-48)

Items 1 and 2 passed their gate with conditions, and the owner accepted them (`docs/phase-4a-exit.md`, D4-48). Item 3 is **vulnerability applicability with the asset module** (R9, R1.8). This stage is investigation and contract drafts only (CLAUDE.md §5.1, stages A and B). No product code merges until C1 approves the contracts. The common rules for every Phase 4 brief apply. Nothing contacts a device, and no advisory feed is fetched from a site node (R9.3).

**What item 3 must show at its gate**, to be fixed in the implementation briefs once the contracts are approved:

- **R9 on the SEL-751,** from the identity it already reads (`ID` at Level 0). It needs no SNMP and is the first end-to-end path. On allowlisted FIDs (R400 to R501) the identity is device-read, so V-M7 can reach every class. A denied branch (R302 and older) gets no session at all, not even for `ID`, so its identity is `operator` only and it can never be `confirmed` (D4-49, F1).
- **R1.8 on one SNMPv3 SEL family,** read only, at `authPriv` only, on a new simulator profile (V-M1).
- **V-M7 and V-M8** over GT-ADV, and **V-M1** over GT-MIB, on the real binaries, `simulated`. These criteria are fixed (#144). A brief may not lower them. D4-49 answers C6's testability questions on them (#436), and V-M1 (d) is shown for the refusal alone.

**The first SNMPv3 family: the SEL-2731 and SEL-2741 in RSTP mode (D4-51, on C2's evidence; it replaces the SEL-2730M first proposed here).** Its matrix row has SNMPv3 read-only with the FID in the Entity MIB (`documented-untested`, pp. 83 to 84, 155 and 156). The alternatives are the SEL-2731 and SEL-2741 in RSTP mode (S29) and the SEL-2488 (S26, whose model and firmware OIDs are `unknown`). SNMPv1 and v2c are never used without the owner's per-device approval (R1.8).

#### P4-3-A2 (C2): the asset module, the SNMPv3 family and identity attributes

- **Objective.** Define how an asset's identity attributes are read and recorded with their source, and choose the first SNMPv3 family on evidence.
- **Deliverables.**
  - A desk note `docs/phase4/C2-snmp-family.md` that confirms or replaces SEL-2730M. It lists, with citations, each identity attribute the device offers over SNMPv3 (vendor, model, firmware and FID), the OIDs, the USM levels and algorithms the device supports, and whether the SEL MIB text the simulator needs is available to the project. If it is not available, say so: GT-MIB cannot be built from an assumption.
  - **Contract drafts:** C1 0.3, identity attributes each with a source (`device-read` with its read path and evidence ID, `passive`, or `operator`; V-M1 (e), R9 classes); and C3 0.4, an SNMP read operation in the register: `GET`, `GETNEXT` and `GETBULK` on named OIDs only, never `SET` (V-M1 (b)).
  - The boundary of `modules/asset/`, independently enabled and disabled (R1.8, V-M1 (a)).
- **May change:** `modules/asset/` (new), `contracts/asset`, `contracts/register` (drafts only, in a PR for review), `docs/device-capabilities.md`, `docs/phase4/C2-*.md`.
- **Exclusions:** no SNMP code merged in this stage, and no v1 or v2c path.
- **Reviewers:** C6 and C3; C1 approves the contracts.

#### P4-3-A3 (C3): the signed offline advisory set, and SNMP's threat model

- **Objective.** Define the advisory set's format and its update path (R9.3, V-M8), and the trust boundary for SNMPv3 credentials.
- **Deliverables.**
  - **Contract draft C11 `otsec.advisory/0.1`:** a signed, versioned, offline set. Each entry has its source citation, the affected products and version ranges, and its named preconditions and mitigations, in a form V-M7's classes can evaluate. Refusal of an unsigned, wrongly signed, truncated or older set keeps the set in use, and the refusal is audited (C8 addition). Test advisories are marked `test-only` and refused in a shipped set.
  - **The approval record for a v1 or v2c device** (V-M1 (d)), as a C7 and C8 addition, refused without the owner's approval.
  - **Threat-model rows:** SNMPv3 USM keys held by the privileged collector with the other device credentials (ADR-0002, D4-50), no downgrade, and the asset module as a new path to devices. Also the signing key's custody, and who may publish a set.
- **May change:** `contracts/authz`, `contracts/audit`, a new `contracts/advisory` (drafts only, in a PR), `docs/threat-model.md`, `modules/security/`.
- **Reviewers:** C6 and C2, with C4 for the fields the matcher reads; C1 approves.

#### P4-3-A4 (C4): the applicability finding and the matcher's design

- **Objective.** Define the finding that R9.1 and R9.2 report, and how identity is matched against C11.
- **Deliverables.**
  - **Contract draft C12 `otsec.finding/0.1`:** one finding per asset and advisory. It holds the class (`applicable-by-version`, `confirmed`, `mitigated`, `not-applicable`, or `not-applicable (operator)`), the evidence IDs, each unread precondition by name, and the set's version and date. A reclassification is recorded as a change, not an overwrite (V-M7). No field states exploitability.
  - **A design note** for a deterministic matcher, `docs/phase4/C4-matcher.md`: the version-range comparison per SEL firmware string form (cite the FID formats the project already reads), and what makes evidence current under "R9 classes and what `confirmed` needs" (point 3). It also covers how R6.7's passive evidence will plug in later without a contract change.
- **May change:** `modules/detection/` or a new `modules/applicability/` (C4 chooses and says why), and `contracts/` drafts only.
- **Reviewers:** C6 and C2; C1 approves.

#### P4-3-A5 (C5): the node's side

- **Objective.** A design note, `docs/phase4/C5-asset-node.md`, covering the following.
  - Enabling and disabling the asset module and R9 independently. With either disabled, nothing it owns runs and nothing else changes (V-M1 (a), V-M8's paired runs).
  - Where the advisory set, identity records and findings are stored (C5 class and quota), and how the set is replaced atomically, with the old one kept in use on refusal.
  - SNMP poll scheduling under the register's limits.
  - Health and status lines for each.
- **Exclusions:** no store contract change without its own proposal.
- **Reviewers:** C6 and C3; C1 approves.

#### P4-3-A6 (C6): ground truth before the product

- **Objective.** Fix the ground truth before any product test runs.
- **Deliverables.**
  - **GT-ADV:** a truth table of identities, with their sources and a SEL-751 FID set from the fixtures already held, crossed with `test-only` advisories, each cell the class it must get. It is committed before the matcher exists.
  - **A GT-MIB plan** for the chosen family, built from the vendor MIB and manual only, with what it serves and how it records every PDU. If C2 finds the MIB is not available, the plan says what can still be shown.
  - A check that V-M1, V-M7 and V-M8 are testable as written, with any ambiguity raised to C1 before the contracts are approved. The thresholds are not changed.
- **May change:** `tests/`, `docs/verification.md`.
- **Reviewers:** C1, and the owners of what each item covers.

#### Order

1. C2's family note comes first. C6's GT-MIB plan depends on it.
2. C2, C3 and C4 draft their contracts at once. Each consumer reviews them, then C1 approves them together (§5.4).
3. C5's note and C6's GT-ADV run beside the drafts.
4. The implementation briefs and the item 3 gate follow the approval.

### Phase 4 item 3: implementation briefs (issued 2026-11-05, D4-53)

C1 approved the item 3 contracts together in D4-53 (#442), at the heads named there. The approved texts are `docs/phase4/C2-c1-0.3-c3-0.4.md` (C1 0.3, C3 0.4, C2 0.7), `docs/phase4/C3-c11-advisory.md` (C11 0.1, C7 0.8, C8 0.11), C12 in `contracts/finding` with `docs/phase4/C4-matcher.md`, and `docs/phase4/C5-asset-node.md`. D4-49 to D4-53 refine them, and where they differ, the decision wins. The common rules for every Phase 4 brief apply. Nothing contacts a device, every advisory is `test_only`, and no real advisory is entered until the owner answers who publishes the set and holds its key (HR-18).

**A contract that was approved as text is coded exactly as approved.** If code shows that the text is wrong or incomplete, the owner raises it with C1 before merging, and the change goes to the same reviewers.

#### P4-3-C2 (C2): the contract code, the SEL-751 identity observations, `modules/asset/` and the SNMPv3 client

- **Objective.** Code C1 0.3, C3 0.4 and C2 0.7. Give the SEL-751's identity its model and firmware as device-read observations. Build the node-side asset module and the collector-side SNMPv3 client for the SEL-2731/2741 in RSTP mode.
- **Deliverables, in this order:**
  1. **Contract code:** `contracts/asset` (C1 0.3, keeping a reader for 0.2), `contracts/register` (C3 0.4, `get`, `getnext` and `getbulk` only, and refusal of `set` at load), and `contracts/adapter` (C2 0.7 codes). Each has C6's contract tests before it merges.
  2. **The SEL-751's model and firmware**, as their own observations with sub-spans of the FID's bytes (#438 question 5). This needs no new read and no register revision.
  3. **`modules/asset/`**, as §3 of the approved text describes. It includes the import test that fails on any network, `syscall`, `os/exec` or `modules/ied/...` import.
  4. **`modules/ied/snmpv3/`**, linked only into `otsec-collector`. It has the USM session at `authPriv` with the pinned engine ID, the BER decoder with a fuzz target, each family's identity parse, and the transcript that stores every full message (GT-MIB plan §4). Algorithms are `hmac-sha-256`, `hmac-sha-512` and `aes-128` only, with no fallback. The rules for Reports and Responses follow D4-53. A new module dependency (an SNMP or crypto library) is named in the PR with its reason, and C3 and C6 review it.
- **May change:** `contracts/asset`, `contracts/register`, `contracts/adapter`, `modules/asset/`, `modules/ied/`, `tests/fixtures/ied/`, `docs/device-capabilities.md`, `docs/phase4/C2-*.md`.
- **Acceptance (C6, independent):** V-M1 (b), (c), (e) and (f) over GT-MIB on the real binaries, and V-M1 (a) with C5. The SEL-751 FID goldens still parse. Each family parse is mutation-tested.
- **Exclusions:** no v1 or v2c path, no `set`, and no SDN-mode SEL-2731/2741.
- **Reviewers:** C6 for correctness and device safety. C3 for the USM session, the decoder and the egress check's placement. C5 for what the node calls.

#### P4-3-C3 (C3): the advisory set, the SNMP credentials and the egress check

- **Objective.** Code C11 0.1, C7 0.8 and C8 0.11, and the collector's egress check for SNMP messages.
- **Deliverables:**
  1. **`contracts/advisory`:** the envelope, the set and its entries, the limits (including the `MaxEnvelopeBytes` test against the node's record cap), the verifier, and the advisory anchors. A shipped set refuses a `test_only` entry.
  2. **C7 0.8**, with the `snmpv3` credential and its pinned engine ID held by the collector, and **C8 0.11**, with its records. The v1/v2c approval stays a design and is not built (D4-49 Q3).
  3. **The egress check**, a separate package from the encoder. It takes one encoded message and returns the rule that refused it (GT-MIB plan §4), and it refuses `SetRequest` and any OID outside the operation.
  4. **A test-only signing tool** under `tests/`, with a key held by the tests only (V-M8), so that C6 can build sets. It is not linked into either binary.
- **May change:** `contracts/advisory`, `contracts/authz`, `contracts/audit`, `modules/security/`, `docs/threat-model.md`, `docs/phase4/C3-*.md`, and the signing tool's directory under `tests/` (agreed with C6).
- **Acceptance (C6, independent):** V-M8's set cases (unsigned, wrongly signed, truncated, older and same-version sets, an entry with no source, a shipped set holding a `test_only` entry), each refused with the set in use unchanged, the refusal in health and the chain. GT-MIB §2.7's egress deny corpus, case by case.
- **Reviewers:** C6, C2 for the egress check's place in the client, and C5 for the verifier's use at the node.

#### P4-3-C4 (C4): the matcher

- **Objective.** Build the deterministic matcher in `modules/applicability/` as `docs/phase4/C4-matcher.md` describes, as a pure function of identity records and the set, producing C12 findings.
- **Deliverables:** the `sel-fid` parse and comparison (within one branch, never across), preconditions and mitigations, classification in the note's §5 order (with Q5 first, D4-53), evidence currency, and the revision rule (a finding is written on any C12 §7 change, D4-53). A fuzz target on the FID parse. An import test that fails on any network, `os/exec`, store or `modules/ied/...` import.
- **May change:** `modules/applicability/`, `contracts/finding` (only through C1, as above), `docs/phase4/C4-*.md`.
- **Acceptance (C6, independent):** GT-ADV, all 128 cells, first as a unit run on the matcher and then on the real binaries (V-M7). Mutation of each classification step is caught.
- **Reviewers:** C6, C2 for the FID forms, and C5 for the call from the node.

#### P4-3-C5 (C5): C5 0.8 and the node's side

- **Objective.** Store identity records, the set and findings. Replace the set atomically. Run the matcher once per collection run. Schedule SNMP reads through the collector, with the module switches and health.
- **Deliverables:**
  1. **A C5 0.8 proposal first**, from the note's "What C5 0.8 would need". It covers the four series, the holds, the `advisory` stream and the quota floor terms. C4 and C6 review it, C1 approves it, and C6 adds its contract tests.
  2. **The node**, as the approved note describes. The `asset` and `applicability` switches, with `applicability` without `asset` refused at load (D4-50). The set taken under C11 §1.5 and D4-53 (a bounded read, re-verification at start and on an anchor change, and never an older set). Evaluation once per collection run (D4-53). SNMP schedule entries under the register's limits. Health and `otsec` status lines.
  3. **For C6's runner:** a way to start the collector with a schedule that has one SNMP entry, on the test clock (GT-MIB plan §4).
- **May change:** `contracts/store` (after approval), `platform/`, `cmd/otsec/`, `docs/phase4/C5-*.md`.
- **Acceptance (C6, independent):** V-M1 (a) for all three supported combinations. V-M8's paired runs (D4-49 Q12, D4-50). No identity record, set or finding is lost across a SIGKILL at each commit point. A set refused at start leaves no set in use, and the floor holds.
- **Reviewers:** C6 for reliability, and C3 for the trust boundary (R9 code holds no `Collector` and no network handle).

#### P4-3-C6 (C6): GT-MIB, and the item 3 runs

- **Objective.** Build the ground truth's remaining parts before the products' tests first run, then verify V-M1, V-M7 and V-M8 on the real binaries.
- **Deliverables:**
  1. **GT-MIB's `cases.json`**, committed before the agent. Its codes are final now that C3 0.4 and C2 0.7 are approved.
  2. **The GT-MIB agent**, built from S29 and the RFC texts, as the plan says. **It waits for the RFC texts** (the owner question). Until they are in the project, the agent is not built, and no V-M1 run counts. The egress deny corpus and the import checks can run as soon as C3's egress check exists.
  3. **R9 on the SEL-751 end to end** over GT-ADV, which needs no SNMP and is the first path to run (V-M7, including the denied-branch rows under F1).
  4. **V-M8's paired runs**, with the A/A pair first (D4-49 Q12).
  5. **A new H item for the SEL-2731/2741**, prepared only: its OIDs, its engine-ID behaviour and its load at the poll rate (V-M1's hardware column).
  6. **The root cause of the Windows `TestUnknownSendersAreKeptAndAlarmedOnce` failure** (#441's CI note): done in #447. A fixed wait read a slow store as a lost datagram, and the same work found the SER leg's scheduler race, which C5 fixed in #448.
- **May change:** `tests/`, `docs/verification.md`, and `.github/workflows/ci.yml` for a new leg, with C1 reviewing that line. The same change fixes the `gtinj_ser` leg's comment, which says about 30 minutes where the run takes about 33 since #448.
- **Reviewers:** C1, and the owner of what each case covers. C2 reviews GT-MIB's values against S29.

#### Order

1. The contract code (C2's three, C3's, and C5's C5 0.8 proposal) comes first, each with C6's contract tests. #440 (C12) and #441 (GT-ADV and the GT-MIB plan) are merged.
2. Then, in parallel: C4's matcher, C5's node, C2's SEL-751 observations and `modules/asset/`, and C3's egress check and signing tool.
3. R9 on the SEL-751 runs end to end as soon as the matcher and the node are in. It does not wait for SNMP.
4. C2's SNMPv3 client may start beside step 2. GT-MIB's agent and every V-M1 run wait for the RFC texts.

#### Phase 4 item 3 exit gate (C1 decides)

- **V-M7** passes per cell over GT-ADV on the real binaries, `simulated`, for the SEL-751 path. That covers the allowlisted FIDs and the denied-branch rows, where the identity is `operator` only and never `confirmed` (F1).
- **V-M8** passes: every set refusal case, and the paired runs with no flow in the R9 run that the other lacks.
- **V-M1** (a) to (c), (e) and (f) pass over GT-MIB for the SEL-2731/2741 in RSTP mode, and (d) is shown for the refusal alone (D4-49 Q3). If the RFC texts are still missing when everything else has passed, C1 puts the choice to the owner. The gate never counts a GT-MIB built from memory.
- C1 0.3, C3 0.4, C2 0.7, C5 0.8, C7 0.8, C8 0.11, C11 0.1 and C12 0.1 are merged, with their reviewers' records and C6's contract tests.
- V-S7 still passes, and the egress deny corpus refuses every SNMP write form.
- No real advisory is in any set, and the gate says which owner questions are still open.
- No safety or security objection is open.

Work then stops for the owner's check (D4-34).

## After item 3: hardening briefs (issued 2026-11-06, D4-62)

The owner accepted item 3 on 2026-11-06 and chose to have the two hardening items D4-59 queued done before the next item. D1 issues them here, with C12 0.2's code (D4-61) after them. The common rules for every Phase 4 brief apply. Nothing contacts a device. The configuration loader refuses a `device-observed` target in this phase (D2-4), so a test of an off-lab path sets the target after loading, as `platform/node/unsigned_test.go` does, and the binaries can only be run lab-only. When all three are merged, D1 reports to the owner and asks for the next item.

#### P4-H1 (D3, then D5): refuse `clear-suspension.json` off-lab

- **Objective.** An asset suspension on a node with any endpoint that is not `simulated` can be lifted only by an administrator's signed `asset.clear_suspension`, never by the unsigned `clear-suspension.json`. This closes the last unsigned administrator file (`platform/node/unsigned.go`; C7 0.4 `doc.go`, "Admin-signed requests").
- **Deliverables, in this order:**
  1. **D3, the collector.** It accepts `asset.clear_suspension` as an admin-signed request relayed by the node, with the checks every admin-signed request has: signature, key, nonce spent before any decision, and expiry. The signed body and the collector's own record must name the same asset and invocation, or it is `suspension_mismatch`. For an asset with any endpoint that is not `simulated` in the collector's configuration, the collector refuses the unsigned path, and the file alone lifts nothing. A lab-only asset keeps the file path. If this needs a new refusal code or a C8 field, D3 proposes the C7 or C8 minor first, and D1 approves it after its consumers have reviewed it and D6's contract tests pass.
  2. **D5, the node.** It relays the signed request through the admin relay and records `asset.suspension_clear` from it, naming the person and that the request was signed. It refuses `clear-suspension.json` on a node that is not lab-only, through `unsigned.go`'s alarms. Those are `unsigned-admin-file-refused` once per file content, `-accepted` on a lab-only node, and `-ignored` when a signed request names the same clear. The `otsec health` line that names the file changes to match.
- **May change:** D3: `modules/security/`, `cmd/otsec-collector/`, and `docs/phase4/D3-*.md`, plus a contract proposal if one is needed. D5: `platform/node/`, `cmd/otsec/`, and `docs/phase4/D5-*.md`.
- **Acceptance (D6, independent):**
  - On the binaries, on a lab-only node, the file still clears a suspension and raises `unsigned-admin-file-accepted`, and a signed request clears it too.
  - In Go tests at the node and the collector, with an endpoint that is not `simulated`:
    - the file alone clears nothing at the node or the collector, and raises `unsigned-admin-file-refused` once;
    - a signed request clears both, with one record each;
    - a replayed, expired or wrongly signed request, or one naming another invocation, is refused, and nothing changes.
  - A mutant that drops the off-lab check fails a test.
  - The credential suspension path does not change.
- **Reviewers:** D3's part by D6 and D2. D5's part by D6 and D3.
- **Exclusions:** no change to `credential.clear_suspension`, no change to `clear-quarantine.json` or `seq-reset-ack.json` (#347 covers them), and no UI.

#### P4-H2 (D5): find the Windows node start stall

- **Objective.** Find which step of the node's start takes more than 12 s on the hosted Windows runner (#471, D4-58), before anyone tries a fix. #428's lead, recreating the recovery reserve with a flush at every start (F-013), is unverified until the numbers show it.
- **Deliverables:**
  1. The node logs one line at the end of its start with the time each start phase took (for example: configuration, store open and recovery, the reserve, the key register, listeners, and the first collector connection). The line holds no path to a secret, no key and no device text. A test pins its format.
  2. The Windows CI jobs that start a node keep that line in their output. D5 then collects at least 20 Windows starts from CI runs, and at least 3 that take over 6 s if any occur. D5 writes `docs/phase4/D5-windows-start.md` with the numbers, the run links and the phase that dominates.
  3. **No fix in this PR.** D1 briefs the fix from the numbers. Its proving test is the platform budget step's numbers before and after.
- **May change:** `platform/node/`, `cmd/otsec/`, `docs/phase4/D5-*.md`, and, with D1's authorization of the line, `.github/workflows/ci.yml` if a job must keep more output.
- **Acceptance:** both workflows green on Linux and Windows. The timing line appears for each node start in the Windows `go` job and the `service` job. The note's numbers link to the runs they came from.
- **Reviewers:** D6 and D3.

#### P4-H3 (D5, D4, D6): C12 0.2, as D4-61 approved it

In the order of `docs/phase4/D4-c12-0.2.md` §8 and §10:

1. **D5's fail-closed `fold`.** The node refuses any `otsec.finding/` minor that `finding.Known` does not name. The refusal is per asset, through the not-evaluated alarm. The alarm names the schema, bounded to 64 bytes of printable ASCII and quoted. This PR carries D5's tests (ii), the refusal half of (iii), and the 0.1 regression.
2. **D4's PR:** `contracts/finding` 0.2 with rules 1 to 5 and `Known`, and `modules/applicability`, with the §7 tests. D6's `c12_v02_d6_test.go` must pass before it merges. D5's reader for both minors ships in the same release.
3. **D6:** V-M7's checker resolves `identity.mismatch.id` to its stored `identity.read`, and an operator-only mismatch scenario joins the V-M7 leg, checked across a restart.

- **Reviewers:** a contract by D1 and every consumer, with D6's contract tests. D4's code by D6 and D2. D5's code by D6 and D3.

#### Order

P4-H1's D3 part, P4-H2 and P4-H3's step 1 may run in parallel, because they touch different paths. P4-H1's D5 part follows D3's part, and P4-H3's step 2 follows its step 1. P4-H2 uses Windows CI time, so a V-M1-length leg is not added while it runs.

## After the hardening briefs: P4-H4 (issued 2026-11-07, D4-64)

#### P4-H4 (D5): make the store's start-up reserve step faster on Windows

- **Objective.** P4-H2's numbers show where slow node starts spend their time (`docs/phase4/D5-windows-start.md`). In the Windows `go` job, `store-reserve` was 49% of all start time and the largest phase in 404 of 541 starts, with `store-open` second. P4-H4 makes `store-reserve` faster without weakening anything it protects. Real service starts already took 0.7 to 1.2 s, so the goal is the loaded case, not a new feature.
- **What the step does today.** At every start, C5's startup releases the recovery reserve before the store is first opened (F-013). After recovery, `platform/store.Env.CreateReserve` re-creates the reserve by writing `RecoveryReserveBytes` of zeros in 64 KiB writes, then flushes the file and its folder. This happens for each of the node's databases.
- **Step 1, measure before changing (desk and CI-Windows).** Split `store-reserve` into the release, the zero writes, the file flush and the folder flush, as new phases in the P4-H2 line (for example `reserve-release`, `reserve-write`, `reserve-sync` and `reserve-dirsync`), so that the service job's real SCM starts show it too, and `TestStartLine` pins the names. The line keeps its rule: phase names and milliseconds only, with no path, key or device text. This step-1 commit, with no fix, is the baseline for the acceptance numbers. Report which part dominates on `windows-latest`, with the run link. The fix targets that part, not a guess.
- **Step 2, the fix.** D5 picks the smallest change that removes the dominant part. Candidates to weigh with numbers:
  - larger writes;
  - one preallocation call in place of the writes, if the space is really allocated (no sparse file), still followed by the same flushes as today: the file flush, and the folder flush where the store has one. On Windows `syncDir` is a no-op today (`platform/store/os_windows.go`), so there the reserve has the file flush only. Adding a Windows folder flush is a separate question and is not part of P4-H4 (D5 on #519).

  Skipping the release at a clean start is out of scope, because it breaks must-keep 1 (D3 on #519).

  Any change to C5's startup order, or to what the startup report or its alarms say, is a C5 minor bump. It needs a proposal reviewed by D6 and D3, and D1's approval, before any code.
- **Must keep** (D3 on #515, D4-63):
  1. F-013's rule. The recovery reserve is released before the store is first opened, and nothing opens the store before that.
  2. A reserve counts only once it holds real space and is flushed. A start never reports a reserve that a full disk could take away. ADR-0004 item 8 still holds: a node whose reserve cannot be re-created alarms and does not collect.
  3. AP-13's 60 s first wait before the first collector exchange.
- **Deliverables.**
  1. The step 1 split, in `docs/phase4/D5-windows-start.md` as a new section.
  2. The change, with tests. Every existing V-S9 and storage-exhaustion test passes unchanged, and a test pins that the reserve holds its full size on disk. The test reads the space allocated, not the file's length: `Stat_t.Blocks` times 512 on Linux, and the allocation size from `GetFileInformationByHandleEx` on Windows. `Stat().Size()` passes for a sparse file and does not count. It runs on both OS legs. On Linux, a mutant that replaces the writes with `Truncate(n)` fails it. On Windows, extending a non-sparse file may allocate its clusters (a desk reading, untested), so there the mutant marks the file sparse (`FSCTL_SET_SPARSE`) and then truncates, and fails it. D5 reports in the note what a plain `Truncate(n)` allocates on `windows-latest` (D3 on #519). A second test pins the flush: a fault hook makes the file flush fail, and on Linux the folder flush too, and the test checks that `CreateReserve` returns an error and removes the file, and that the node raises the ADR-0004 item 8 alarm and does not collect.
  3. Before and after numbers from the platform budget step and the P4-H2 line on `windows-latest`. "Before" is the step-1 commit and "after" is the fix head, both on the PR's own code, with two `go (windows-latest)` runs on each side. They go in the same note, with run links.
  4. The note states that CI pins must-keep 1 by order only, not by reproducing F-013 on a full NTFS volume (C-22, H-14 still open). Next to H-14, it records a known limit that P4-H4 does not open: with no folder flush on Windows, a crash can lose the reserve's directory entry, and the next start then takes the existing "reserve missing" path (D6 on #519).
- **May change:** `platform/store/`, `platform/node/`, `docs/phase4/D5-*.md`. A change in `contracts/store/` only through the C5 proposal above.
- **Acceptance.**
  - Both workflows are green on Linux and Windows.
  - In the Windows `go` job, the median and the p90 of `store-reserve` both fall from the step-1 baseline to the fix head, and so do the median and the p90 of `total`.
  - The three properties above are each pinned by a test that fails if the property is broken.
- **Exclusions.** No change to `RecoveryReserveBytes`, `LastResortReserveBytes` or `OpenHeadroomBytes`. No change to `store-open` in this PR; if it remains the next cost, D5 says so in the note and D1 decides. No skipped or loosened test.
- **Reviewers:** D6 for reliability, D3 for the trust boundary and the three properties.

## Phase 4 item 4: Stage A briefs (issued 2026-11-07, D4-66)

The owner chose IDS (R6) as the next item (D4-66). This stage covers investigation and contract drafts only (CLAUDE.md §5.1, stages A and B). No product code merges until D1 approves the contracts and the sensor ADR. The common rules for every Phase 4 brief apply.

Nothing captures traffic on a real network. Every capture is either a public one listed in `tests/fixtures/network/public-ot-captures/` or one recorded from the project's own simulators. The sensor never transmits on its monitoring interface (C-11), and nothing scans or probes, actively or otherwise (P1).

**Starting point.** The Phase 0 evaluation (`docs/phase0/A4-telemetry-feasibility.md` §3 and §4, E-A4-01) found the following:

- Zeek 8.0.4 decoded all 6 DNP3 captures, including midstream, and Modbus on 2 of 3.
- Suricata 7.0.3 decoded 4 of 6 DNP3 captures by default. The 2 captured without the handshake needed `stream.midstream=true`. It decoded Modbus on 1 of 3 by default and 2 of 3 with midstream.
- Neither engine decodes IEC 61850 MMS, GOOSE, SV or IEC 60870-5-104.
- A6 broke the throwaway GOOSE sequence check: all 8 of its 8 adversarial cases failed (R-A4-4).

The provisional direction is Zeek as a separate supervised process (ADR-0002 item 2b, A4 §3). It has no ADR yet.

**The open question that comes first: where the sensor runs.** The site node is a dedicated Windows 10/11 machine (ADR-0007, C-22). Every engine and decoder evaluated so far ran on Linux. A packet capture on Windows needs a capture driver, and that driver's licence and privileges are part of the choice. Stage A settles this in an ADR before any contract depends on it.

**Protocols for the first sensor.** These come from the owner's answer about their sites, which was asked for on 2026-11-07. Until the answer arrives, the first set is the following:

- DNP3 and Modbus/TCP, which Zeek decodes.
- R6.7's insecure list from V-M6: Telnet, FTP, plain HTTP, SNMPv1 and v2c, unauthenticated Modbus/TCP, and DNP3 without Secure Authentication.
- SNMPv3 and the SEL Telnet sessions that the platform itself runs. These are a known flow for the baseline and the unknown-flow alerts, but they are still recorded as an insecure service under R6.7, because the SEL-751's only path is Telnet (D4, D2).
- The customer HMI server's relay traffic, an existing authorized path that the baseline models as a known flow (ADR-0007 item 7).

IEC 61850 (MMS, GOOSE, SV) and IEC 60870-5-104 are added once the owner confirms they are in use. Each of them needs its own decoder, and GOOSE needs every precondition R-A4-4 lists.

**What item 4 must show at its gate**, to be fixed in the implementation briefs once the contracts are approved. V-M6 and R6.1 to R6.6 apply as `docs/verification.md` states them, and the bullets below are only a summary (D6):

- **V-M6** over GT-PCAP on the real binaries, `simulated`. The sensor sends zero packets. Every labelled service is recorded against its asset with the packets that show it. Every protocol on the insecure list is flagged.
- **R6.1 to R6.5** as `docs/verification.md` sets them:
  - a visibility statement per sensor placement;
  - zero alerts when a baseline built from benign traffic is replayed against held-out benign traffic;
  - one malicious sample and one benign near-miss for each detection;
  - detection rate, false-positive rate and latency for each rule;
  - every alert linked to packets that can be retrieved.
- **R6.6:** the PRP, encryption and unsupported-protocol limits, listed per deployment.
- **C-11 in CI** runs for the full GT-PCAP replay plus the sensor's start and stop, with the interface up throughout. The interface is a virtual one in a network namespace of its own, as in V-M8's paired runs, and never the runner's real NIC (D3). The 24 h run stays with H-06 on hardware (D6).
- These criteria are fixed (#144), and a brief may not lower them.

#### P4-4-A4 (D4): the sensor, its first protocols, and its contracts

- **Objective.** Choose the engine and where it runs on evidence, and define what the sensor hands the node.
- **Deliverables.**
  1. **A draft ADR-0009, the passive sensor**, written with D5 and D3. It compares these options:
     - (a) Zeek or Suricata running on the Windows site node, with a capture driver;
     - (b) a separate Linux sensor at the site that feeds the node;
     - (c) the project's own Go decoders in a separate process on the node.

     For each option it records the following, with sources and a re-check of upstream (ICSNPP and the Zeek packages change):
     - whether it runs on Windows, shown by a run on `windows-latest` in a dispatched workflow, or else marked `unknown`. Offline decoding of a capture file (no driver) is recorded apart from live capture. A `windows-latest` result is labelled Windows Server, not ADR-0007's 10/11 LTSC floor (D5);
     - the capture driver and its licence for a product that ships it, and the engine's own licence (Zeek BSD, Suricata GPLv2) (D4);
     - which of the protocols above it decodes, shown on the public captures;
     - midstream handling;
     - PRP duplicate handling;
     - the process and privilege it needs;
     - whether it accepts a live interface fed by a timed replay, which R6.4's latency and the C-11 test both need (D6);
     - the channel to the node and how it is authenticated. For (a) and (c) this is a local channel with an OS ACL bound to the sensor's account. For (b) it is a network link that needs enrollment and a revocable credential like a node's (SC-11), and the comparison counts the new device's own management interface and update path as attack surface (D3);
     - what C-11 relies on: a TAP is receive-only by construction, while a SPAN port with a host NIC relies on software settings (D3).

     The ADR names the supervised process and the boundary it enforces (ADR-0002 item 2).
  2. **Contract draft C13 `otsec.netobs/0.1`.**
     - **Observations:** a flow or service seen. Each holds the addresses, ports, protocol and the version where it shows in clear, and the asset it resolves to, or `asset-unresolved`.
     - **Packet citation:** each observation cites its packets as the capture's ID and the frame numbers, plus the SHA-256 of the cited bytes.
     - **Device text is hostile input.** A version or banner read in clear is bounded printable ASCII, kept quoted and never interpreted, as C2's record values are (`contracts/adapter/doc.go`). It never reaches a Syslog forward or a status line raw (D3).
     - **Coverage statement:** the sensor states which protocols it decodes, which LANs and VLANs it sees, and whether it uses SPAN or a TAP. The statement is attached to every observation and alert (A4 §4, R6.1).
     - **Alerts:** the alert form reuses C10's departure alarm form where it fits. D4 says where it doesn't fit and why. It has no ML field.
  3. **A design note, `docs/phase4/D4-network-baseline.md`,** with the following content:
     - **The baseline:** who talks to whom, and which function codes are used per pair, against a baseline of authorized masters (A4 §3: "write = bad" alerts on routine time sync).
     - **The insecure-list rule.**
     - **The platform's own traffic.** A known flow is tied to the node's own session record: the asset, the time window of a scheduled or granted session, and the destination. Traffic outside that record is alerted, even when it comes from the node's address, so that spoofing the node's address does not hide a session (D3).
     - **How R6.7's observations reach C12's matcher** without a C12 change (D4-53). A FID or an SNMPv3 engine ID read passively from the platform's own sessions doesn't corroborate the identity those sessions already read, and doesn't count twice in C12 (D2).
- **May change:** `contracts/` (drafts only, in a PR for review), `modules/detection/`, `modules/telemetry/experiments/`, a dispatch-only `.github/workflows/d4-sensor-eval.yml`, `docs/decisions/` (the ADR draft), and `docs/phase4/D4-*.md`.
- **Exclusions.**
  - No sensor code is merged in this stage.
  - No ML.
  - No GPL library (libiec61850 or lib60870) is linked into the Go binaries.
  - No capture file is committed unless its source states redistribution terms.
- **Reviewers:** D6 for detection accuracy, D2 for protocol interpretation, D3 for the trust boundary, and D5 for the process. D1 approves.

#### P4-4-A2 (D2): what the SEL families put on the wire

- **Objective.** Give GT-PCAP and R6.7 the protocols and ports the SEL families in scope speak, from documents, with citations.
- **Deliverables:** `docs/phase4/D2-sel-network-services.md`. It covers each SEL family the matrix holds (SEL-751, SEL-2731/2741 and the others it lists), with the following for each:
  - the network services it can offer, with protocol, port, default state and the setting that turns each one on;
  - which services are on the insecure list;
  - what a passive sensor can read in clear for identity (R1.1, R6.7).

  The sources are the manuals already in `reference/manuals-SEL/` (S22 to S43). Nothing is taken from the web without the owner's leave (D4-58). Mark a service `unknown` where the document is silent. Nothing is guessed.
- **May change:** `docs/device-capabilities.md` and `docs/phase4/D2-*.md`.
- **Reviewers:** D4 and D6.

#### P4-4-A3 (D3): the sensor's trust boundary

- **Objective.** Bring the sensor into the threat model before any code is written.
- **Deliverables:** threat-model rows covering the following:
  - **Hostile input:** packet parsing is a hostile-input surface, so a decoder crash or exploit must not reach the node's store or keys.
  - **The capture driver:** its privilege on Windows.
  - **The monitoring interface:** it transmits nothing, which is C-11, and the ADR states how that is enforced and how it is tested.
  - **Stored captures:** cited packets may hold credentials in clear, including the platform's own SEL Telnet logins and SNMPv1 or v2c community strings. The rows say three things:
    - cited bytes stay at the site and are never forwarded upstream, only their hash and frame numbers;
    - how long they are kept;
    - who may read them (the security role, not monitoring).
  - **Spoofed alerts:** the sensor as a path to forge alerts or observations into the node.

  D3 also reviews ADR-0009 and C13 for the boundary.
- **May change:** `docs/threat-model.md` and `modules/security/` (notes only).
- **Reviewers:** D6 and D4.

#### P4-4-A5 (D5): the node's side

- **Objective.** A design note, `docs/phase4/D5-sensor-node.md`, covering the following:
  - how the sensor process is supervised (start, restart and health) on Windows and on Linux. The note compares its own SCM service, like the collector, with a child of the node (ADR-0002 item 5: no orchestrator). For option (b) the node supervises nothing, so the note covers the network link's health and its inbound boundary instead (D5);
  - how C13 records reach the store, and in which stream and quota (C5), so that a flood of observations cannot starve SER or Syslog (the lesson from HR-11);
  - where the cited capture bytes live, with their quota and retention, so that R6.5's packets can be retrieved. This sits next to D3's protection row (D5);
  - C-11 on Windows: unbinding the IP stack from the monitoring NIC, plus an HR-9-style firewall rule. This is installer work under `deploy/` (D5);
  - enabling and disabling the sensor on its own: with it disabled, nothing it owns runs and nothing else changes;
  - what status shows.
- **May change:** `docs/phase4/D5-*.md`, and `contracts/store` (a C5 draft of the new stream class, in a PR for review, approved together with C13).
- **Note:** the sensor's supervision tests go in their own package, because `platform/node`'s Windows test step already runs 530 to 648 s against a 720 s budget (D5).
- **Reviewers:** D3 and D6.

#### P4-4-A6 (D6): GT-PCAP and the item 4 checks

- **Objective.** Build the ground truth before any product test runs.
- **Deliverables.**
  1. **The GT-PCAP plan** (`docs/verification.md` definition), using two sources:
     - the public captures already listed;
     - captures recorded in CI from the project's own simulators (the SEL-751 Telnet profile, GT-MIB's SNMPv3 agents, and a DNP3 and a Modbus/TCP source D6 picks or writes).

     Labels come from a decoder the product does not use: tshark if ADR-0009 picks Zeek, and Zeek or tshark otherwise. They never come from the product (D6). The plan includes held-out benign series for R6.2, and labelled malicious samples with benign near-misses for R6.3. A PRP duplicate case is built from a capture by sending each frame twice, each copy with an IEC 62439-3 Redundancy Control Trailer carrying the same sequence number, one with LAN ID A and one with LAN ID B. That is what a sensor on both LANs sees.
  2. **Testability review** of ADR-0009, C13 and the baseline note against V-M6 and R6.1 to R6.5.
  3. **The C-11 test design:** zero frames from the monitoring interface, for whichever option ADR-0009 picks.
- **May change:** `tests/integration/`, `tests/fixtures/network/`, and `docs/verification.md` (plans and criteria wording only, never a threshold that has run).
- **Reviewers:** D4 for the labels and D2 for protocol interpretation.

### Order

1. D4 drafts ADR-0009 first, with D5 and D3. D2's note and D6's GT-PCAP plan run at the same time.
2. D4 drafts C13 and the baseline note once ADR-0009 names the option, and D5 drafts the C5 stream class beside them. Every consumer reviews them, and D1 approves them together.
3. The implementation briefs follow approval. They include the owner's protocols, or record that the owner hasn't answered and the first set above stands.

### Phase 4 item 4: implementation briefs, first part (issued 2026-11-07, D4-68)

D1 approved item 4's contracts together in D4-68. The approved texts are:

- `docs/phase4/D4-c13-netobs.md`: C13 `otsec.netobs/0.1`, with its follow-up #538;
- `docs/phase4/D4-network-baseline.md`: the baseline, the detector and its nine rules;
- `docs/phase4/D4-c4-0.3.md`: C4 0.3;
- `docs/phase4/D5-c5-0.9.md`: C5 0.9;
- `docs/phase4/D3-c7-0.10-c8-0.12.md`: C7 0.10 and C8 0.12.

D4-68's rulings refine these texts, and where they differ, the decision wins. The common rules for every Phase 4 brief apply. A contract that was approved as text is coded exactly as approved. If code shows that the text is wrong, the owner of the text raises it with D1 before merging, and the change goes to the same reviewers.

Nothing captures traffic on a real network. Nothing scans, probes or transmits on a monitoring interface (P1, C-11).

**This is the first part, and it does not include the sensor.** ADR-0009 is still proposed: the owner hasn't chosen where the sensor runs. Everything below is the same under all three options:

- the contract code;
- the node's intake, store, learner and detector;
- the admin path for the acknowledgement;
- GT-PCAP.

**Where the options differ.** The sensor process itself and the channel's transport depend on the option. Under (a) and (c) the transport is a local pipe or socket bound to the sensor's account. Under (b) it is mutual TLS on a link the node opens. These are briefed once the owner chooses. Until then, the node's intake is written over a byte stream with C13's framing, and its tests drive it in-process.

**Protocols.** The owner hasn't yet said which protocols their sites run (asked 2026-11-07). The first set from the Stage A brief stands: DNP3, Modbus/TCP, R6.7's insecure list, and the platform's own Telnet and SNMPv3 sessions.

**Where code lives (D1, from the review of these briefs).** Each path keeps one owner (§5.3):

- **Shared document types go in `contracts/netobs`.** The baseline document `otsec.netbaseline/0.1` (C13 §8) and the two checkpoint documents `otsec.netcheckpoint/0.1` live there, with their canonical encoding, `Validate` and digest. `modules/security/` and `platform/` import them from the contract, never from `modules/detection/`.
- **`fc-classes/1` exists once, in `modules/detection/`, and D4 owns it.** B4 exports one pure classification function (protocol, code, objects, sub-function → class, with the row's status). The node imports it to set `node.function_class` and `dnp3_no_sa`, as it already imports `modules/detection/eventbaseline`. Nobody copies the table.
- **The trust decision is D3's, and its wiring is D5's.** D3 writes the acknowledgement checks as pure functions in `modules/security/`. D5 wires them into `platform/node` under B5, and D3 reviews that boundary.
- **`platform_session` is set by the node (D5).** Until C2 0.9 lands, the node ties by address and time window. After it, the node ties by connection, using B2's fields. D2 and D4 review the tie.

#### P4-4-B4 (D4): the C13 and C4 code, and the detector

- **Objective.** Code C13 and C4 0.3, and build the learner and the detector as the baseline note describes.
- **Deliverables, in this order:**
  1. **`contracts/netobs`**, covering C13 0.1 and #538:
     - the records, the framing, and strict decoding with every bound in §10;
     - `coverage.settings` checked against its bounds in the decoder, so the node refuses values outside them;
     - the token grammar and the device-text rules;
     - the citation, including the redaction markers (D4-67 as amended by D4-68 ruling 13);
     - the coverage statement with `coverage.settings`;
     - the baseline document and the two checkpoint documents, as above;
     - `TestWorstObservationFits`, `TestWorstStoredObservationFits` and `TestWorstAlertFits` (C13 §10). The last two pin a C4 event plus its capture at 64 KiB or less;
     - a fuzz target on the decoder.
  2. **`contracts/event` 0.3**: the `network-observation` kind and the `netobs` field, keeping a reader for 0.2.

     Both packages have D6's contract tests before they merge.
  3. **`modules/detection/`**: the learner and the detector, as pure functions over C13 observations, the node's session records and a baseline document. They cover:
     - the exported `fc-classes/1` classification function;
     - the nine rules, with `sa-failed` and the three other baseline-free rules running before acknowledgement (D4-68 ruling 10);
     - coalescing by (rule, destination asset), two records per window (ruling 5);
     - the drop-count key (ruling 4);
     - `own-session-unseen` as #538 defines it before acknowledgement;
     - the frozen draft at the end of learning (ruling 7).

     An import test fails on any network, `syscall`, `os/exec`, store or `modules/ied/...` import.
- **May change:** `contracts/netobs`, `contracts/event`, `modules/detection/`, `docs/phase4/D4-*.md`.
- **Acceptance.** B4 merges on its own unit tests:
  - **Determinism.** The same observations give the same baseline bytes, including across different fold batch splits.
  - **Restore equals uninterrupted.** The run is cut at every checkpoint on a recorded stream on the test clock, and the alert records are compared byte for byte. This covers a crash between an alert's commit and the next checkpoint, with and without a backward clock step, seeding from the last alert seq.
  - **Mutation.** Each rule's condition is mutated by hand-written mutants run in CI, and each mutant is caught. No new dependency.
- **Acceptance (D6, independent), run as GT-PCAP's labelled cases land and before the item gate:**
  - every rule's malicious sample alerts and its near-miss doesn't (R6.3);
  - the benign held-out series raises zero alerts against a baseline learned from the benign training series (R6.2).
- **Exclusions:** no sensor and no capture code. No ML.
- **Reviewers:** D6 for detection accuracy, D2 for protocol reading, D5 for what the node calls, and D3 for the boundary.

#### P4-4-B5 (D5): C5 0.9 and the node's side

- **Objective.** Code C5 0.9, and give the node its sensor intake, store classes, checkpoints, retention consumer, status, the `network_sensor` section and the node's half of the acknowledgement.
- **Deliverables:**
  1. **`contracts/store` 0.9 and its store half in `platform/store`**, with D6's contract tests:
     - two classes;
     - three series;
     - `network-full`;
     - the record-cap and database rules;
     - per-class capture charging (#532 §2). A capture is charged once to each class that cites it. The "still cited by this class?" query is indexed by stream and bounded per step.
  2. **Intake.** The node reads C13 records from a byte stream:
     - strict decoding, `sensor_id`, `seq` gaps, and record types (the channel carries only heartbeats and observations);
     - the `node` object (C13 §5):
       - asset resolution with `ip-ambiguous`;
       - the `platform_session` tie, as above;
       - `evidence_class` from configuration (D1-23);
       - `function_class` and `dnp3_no_sa` from B4's function, where an absent `sa` never sets `dnp3_no_sa`;
     - the heartbeat (C13 §6): counters monotonic within a run, a decrease refused, and a difference event at most once a minute;
     - refusal of `coverage.settings` values outside their bounds;
     - the unresolved budget (D4-68 ruling 1);
     - the first-sight capture stored once and reused by SHA-256 (#532).

     The transport waits for ADR-0009, as above.
  3. **The learner and detector consumers**, with their checkpoint series. The learner is retired at acknowledgement, with its C8 record written first (ruling 7). The node builds each alert's capture from the first-sight captures it holds (C13 §7.1), in the same form, so a byte-identical one is stored once, and charges it to the alert class.
  4. **The retention consumer** when there is no alert forward target (ruling 6), writing its C8 records as #534 §2.2 sets out: the `created` record at creation and again on re-creation, a move only when the cutoff advances past an alert, and nothing written while stalled. It takes separate seams for the wall clock and the monotonic clock, so that D6's clock-step test can drive them apart.
  5. **`network-full`, with per-key drop counts**, in status and in `intake.drop-counted` (ruling 4), and with the top-streams detail (#532 §7 step 4).
  6. **The `network_sensor` section.** With it absent, nothing item 4 owns runs, and nothing else changes. It carries:
     - the load-time floors: the alert floor, the observation floor, and the configuration class's 9 MiB of network terms;
     - `network-baseline-no-room` at item 3's ceiling (#532 §4, §8).
  7. **The node's half of the acknowledgement**, calling D3's functions from B3:
     - the accepted file read once;
     - the adoption checks (#534 §1);
     - `policy.apply` written before any decision under a new key-kind digest, failing closed (ruling 9);
     - `config.baseline_recorded` and `config.baseline_acknowledged` with kind `network` (#534 §2.1);
     - admin replies serialized where the node applies an acknowledgement (D5's note on #534).
- **May change:** `contracts/store` (as approved), `platform/`, `cmd/otsec/`, `docs/phase4/D5-*.md`.
- **Note:** the sensor's supervision tests go in their own package, because `platform/node`'s Windows test step is near its budget.
- **Acceptance (D6, independent):**
  - No committed observation, alert or checkpoint is lost across a SIGKILL at each commit point, and a record in flight shows as a counted `seq` gap.
  - **The flood.** No SER or Syslog record is lost. Their throughput during the flood is at least 90% of the same job's run without it; the margin is D6's, revised with real data. Every refused observation is counted under its reason, and the flood's legs give ruling 1's outcomes.
  - The refused-learner-checkpoint path goes from `network-baseline-no-room` to `network-full`, with the drops counted (#535).
  - D3's decoy case (AP-36 (3)), and the retention clock-step case.
  - The "not yet seen" status for an enrolled asset commits no alert record.
- **Reviewers:** D6 for reliability, D3 for the trust boundary (deliverable 7 above all), and D4 for the detector's calls.

#### P4-4-B3 (D3): C7 0.10, C8 0.12 and the acknowledgement path

- **Objective.** Code C7 0.10 and C8 0.12, and let a person acknowledge a network baseline and its authorized writers.
- **Deliverables:**
  1. **`contracts/authz` 0.10 and `contracts/audit` 0.12**, with their schemas and goldens.
  2. **The collector accepts `node.network_baseline_ack`**, a separate admin kind that no existing key gains silently (ruling 8). It sets `keys_digest` and `keys` on every accepted 0.10 reply (#534 §1.1).
  3. **The adoption checks as pure functions in `modules/security/`** (for example `modules/security/netack`), which D5 calls from the node:
     - `Adopt(fileBytes, draft, reply)`: the canonical check, both digests, the draft's sequence, and byte-for-byte equality apart from `authorized_writers` (#534 §1);
     - `NeedsGrantRecord(lastDigest, reply)`, for `policy.apply` at first use (ruling 9).

     An import test refuses any store or network import.
  4. **A library function that builds the accepted document**, since the product has no admin client yet. It builds the document from the frozen draft and the writers, in C13's canonical encoding. It returns the bytes to show, with `baseline_digest` and `draft_digest` computed over those same bytes (HR-14). The test helpers use it. A client binary or UI that shows the bytes is a later brief. Until then, HR-14 holds only in tests, and D3 records that under AP-36 (1).
- **May change:** `contracts/authz`, `contracts/audit`, `modules/security/`, `docs/threat-model.md`, `docs/phase4/D3-*.md`.
- **Acceptance (D6, independent):** every test in #534 §3, including T1 to T5. Among them:
  - A key holding only `node.baseline_ack` is refused for kind `network`, and the reverse case is refused too.
  - A document that differs from the draft in anything but `authorized_writers` is refused.
  - The chain shows `policy.apply` before the first network acknowledgement under it, and a forced write failure blocks adoption. This runs once D5's deliverable 7 is in.
- **Reviewers:** D6, D5 for the node's side, and D4 for the baseline document.

#### P4-4-B6 (D6): GT-PCAP, the contract tests and the node-side runs

- **Objective.** Finish GT-PCAP's labelled cases, and verify everything above before the sensor exists.
- **Deliverables:**
  1. **Contract tests** for C13, C4 0.3, C5 0.9, C7 0.10 and C8 0.12, ready before each package merges.
  2. **GT-PCAP's labelled cases**, with their label files:
     - the R6.3 malicious samples and near-misses for all nine rules;
     - the `sa-failed` case;
     - an aggressive-mode operate (g120v3 with g120v9), which gives no `dnp3_no_sa` and no alert;
     - an operate with its response removed;
     - a Modbus 7Dh from a master authorized only to read, which alerts `unauthorized-write`;
     - the cookie and form-login cases, including a server-side value that can't be placed;
     - the off-default ports;
     - the R6.2 held-out benign series.

     Labels come from tshark, never from the product.
  3. **A test-only C13 source** under `tests/` that turns GT-PCAP labels into C13 records. It drives the node's intake through a real byte stream, so the node-side checks run before any sensor exists. It is never linked into either binary.
  4. **The agreed cases beyond the R6.3 pairs**, run at intake level through the test source until the sensor exists:
     - the spoofing-flood test, with its unresolved legs and the leg that mimics a known pair. It decides ruling 1's outcome before the gate;
     - AP-33's checks: the key search for every test secret, and redaction matched to the `secret-slot` rows, with the either-side fail-closed cases;
     - the end-to-end kill and restart on the offline path, comparing the alert set (note §3);
     - the DNP3 pending cases: a reused sequence number (`dnp3_seq_reused`), the challenged exchange whose function 32 reply shares the sequence number (#538), and an overflow at `max_pending_dnp3` = 256 (`dnp3_pending_overflows`);
     - AP-35: a second connection inside the window alerts, and an attacker's connection made first makes the platform's own connection alert;
     - the canary before acknowledgement, including "not yet seen" (#538).
  5. **The C-11 rig**, prepared: the namespaced veth pair, with its negative control. It runs once the sensor exists.
- **May change:** `tests/`, `docs/verification.md` (plans and wording only), `docs/phase4/D6-*.md`, `handoffs/D6-*`, `.github/workflows/a6-gt-pcap.yml`.
- **Evidence class.** Every result from the test source is `simulated` and marked as running without a sensor. R6.2 and R6.3 results from it count toward the gate only once rerun on the real sensor. They are not V-M6 evidence.
- **Acceptance:**
  - D4 and D2 accept each label file.
  - `a6-gt-pcap` is green, with the pinned tshark and every derived capture's hash checked.
  - The C-11 rig's negative control captures frames, which shows the rig can see a transmitting interface.
- **Exclusions:** no product code. No capture from a real network. No credential except the test values made for the recording (D2-5). The test source is never linked into either binary.
- **Reviewers:** D4 for the labels, D2 for protocol reading, D5 for the node runs.

#### P4-4-B2 (D2): the C2 revision for AP-35

- **Objective.** Tie the platform's known flows to one connection (D4-68, carried to C2).
- **Deliverables:**
  1. **A C2 0.9 proposal**, with D5's and D3's review:
     - `local_addr` and `connected_at` in `SessionFacts`;
     - the GetNext code;
     - `ended_at` bounded to 9 fractional digits;
     - the collector refusing to load when two enrolled assets share one host:port.
  2. After D1 approves it, the code in `contracts/adapter`, the adapters and the collector, with D6's tests. The collector fills in `local_addr` for SNMPv3 sessions, or passes it through the `snmpv3` connection interface, because the socket is the collector's. The host:port refusal goes where the collector loads its configuration.
  3. **If the owner places the DNP3 SA specification in `reference/`,** confirm `sa-failed`'s codes and the g120v7 layout in a C13 note.
- **May change:** `contracts/adapter`, `modules/ied/`, `modules/security/collector/` (for the two collector changes in deliverable 2 only), `docs/phase4/D2-*.md`.
- **Reviewers:** D6, D3 for the collector, D5 for the node, and D4 for the known-flow tie.

#### Order

1. Contract code comes first, each package with D6's contract tests: `contracts/netobs`, `contracts/event` 0.3, `contracts/store` 0.9, `contracts/authz` 0.10 and `contracts/audit` 0.12. The C2 0.9 proposal goes beside it.
2. Then, in parallel:
   - D4's detector;
   - D5's node side;
   - D3's acknowledgement functions, then D5's wiring of them;
   - D6's labelled cases and test source.
3. The node-side runs go over the test source as soon as D5's intake and D4's detector are in.
4. The sensor brief follows the owner's choice on ADR-0009. V-M6, R6.4's latency and C-11 run only on the real sensor.

The item 4 exit gate is set in the sensor brief. It holds every criterion the Stage A brief listed, and a brief may not lower them.

## After #611: the verification matrix's status (issued 2026-11-11, D4-82)

### P4-D6-M1 (D6): the Status column of the verification matrix

- **Objective.** The matrix in `docs/verification.md` says `defined` on all 57 rows, and it has no row for R1.6 or R1.7. `docs/requirements.md` now states a status for each requirement (D4-81), which D1 read from D6's status tables. Give each matrix row D6's own status, so that the two files agree and the requirement statuses rest on D6's record.
- **Inputs.** D6's status tables in `docs/verification.md` ("Phase 2 slice status", "Phase 3 status", and the two Phase 4 gate tables), its findings log, the tests themselves, the six exit reports, and the legend of `docs/requirements.md`.
- **Deliverables:**
  1. **A short legend for the matrix's Status column.** Each value says what ran and at which evidence class. No value reads as hardware evidence.
  2. **A status for each of the 57 rows,** naming the table row, finding or test it rests on.
  3. **Rows for R1.6 and R1.7,** each with a criterion. R1.7 is a standing rule: say how it is checked (the unsupported-claim check), and do not name a test that does not exist.
  4. **The line that reconciles V-M8's "9 of 9"** with the item 3 exit's "12 of 12" (D6 on #611).
  5. **In the report to D1:** every row where D6's status and the status in `docs/requirements.md` disagree under D4-81's legend, with the reason. D6 does not edit `docs/requirements.md`.
- **May change:** `docs/verification.md` only.
- **Acceptance:**
  - Every status names its source, and none claims more than the source records.
  - No criterion, threshold, HW value or Slice value changes.
  - `records-auditor` finds no reference that fails.
  - For each `verified` row of `docs/requirements.md`, either a matrix row supports it or D6 has named it as a disagreement.
- **Exclusions.** No test is run, and none is written. No criterion is reworded or lowered. No status for an item 4 row goes above what its tables hold: V-M6 has not run.
- **Risk.** A status copied from an exit report, or from `docs/requirements.md`, would make the two files circular. Work from the tests and the status tables.
- **Branch:** `agent/verification-matrix-status`.
- **Reviewers:** D1. `records-auditor` checks the PR first.
- **Extended on 2026-11-11 (D4-82).** D6 also corrects two lines of the same file to what is true: the opening "Status" paragraph, and the P3 row of the Principles table. No criterion changes.
- **Ruling on 2026-11-11 (D4-82).** A row is `e2e` only when its run used the ground truth that its criterion names. Where a criterion's HW value is `P` or `Y`, the ground truth for this purpose is the criterion's form against a simulator, a documented example or a synthetic series, as the matrix's legend says: the device itself stays owed at any status.

## After the owner's go-ahead of 2026-11-11 (D4-83)

Each brief below is worked in its own worktree. Each role reads CLAUDE.md, `HANDOFF.md`, its own agent file and the files its brief names before it starts. Where a brief lets a role change a path that it does not own, D1 authorizes that change by the brief, for what the brief names and no more. Common rules: the repository is public; stage by explicit path; never force-push; no contact with any device or network; nothing is installed on the owner's PC; a failing job is re-run at most once and a failure is a finding, not a flake.

### P4-4-S1 (D4): the engine and the capture path under option (a), from evidence

- **Objective.** Fill the `unknown` cells of ADR-0009 that a GitHub-hosted Windows runner and primary documents can fill, so that D1 and D4 can choose the engine and the owner can answer the Npcap question with the real terms in front of them. It builds no sensor.
- **Deliverables:**
  1. **E-D4-01, second part,** in `modules/telemetry/experiments/sensor-windows/` and the dispatch-only `.github/workflows/d4-sensor-eval.yml`, on `windows-2025`: Suricata's official Windows build decoding the public captures and GT-PCAP offline, pinned by URL and SHA-256 from the vendor's page, and whether it starts with no Npcap installed; whether an official Zeek binary for Windows exists, from primary sources; the (a′) pipeline, `pktmon` to pcapng to the engine, with packets counted at each stage. A row that did not run is `unknown`.
  2. **Npcap's terms and prices** from the vendor's own pages, each with its URL and the date read. An unreachable page stays `unknown`.
  3. **ADR-0009's evidence updated,** each new cell with its evidence class and run URL, and D4's provisional view rewritten for option (a). The Status line and the decision are D1's.
  4. **A findings note,** `docs/phase4/D4-sensor-engine-eval.md`, naming what still needs a lab machine.
- **Inputs.** `docs/decisions/ADR-0009-passive-sensor.md`, D4-66 to D4-68 and D4-78, and the experiment's own folder and workflow.
- **May change:** `modules/telemetry/experiments/sensor-windows/`, `docs/phase4/D4-*.md`, and, authorized by D1 here, `.github/workflows/d4-sensor-eval.yml` and `docs/decisions/ADR-0009-passive-sensor.md` (evidence and D4's view only).
- **Acceptance.** Every new claim has a run URL or a cited source with its date. The workflow stays dispatch-only, pins every download by SHA-256 and checks the hash before it runs anything it downloaded.
- **Exclusions.** No sensor and no product code. No Npcap install anywhere, the runner included. No capture of a real network: `pktmon` captures only the runner's own traffic, and the workflow reports counts, not the capture. No binary and no installer is committed or uploaded as an artifact. Where the vendor publishes no hash for a download, the SHA-256 of the first download is recorded with its URL and date and pinned from then on, and the record says that it is a first-use pin. No change to `ci.yml`.
- **Branch:** `agent/telemetry-sensor-engine-eval`. **Reviewers:** D6 (testability), D3 (the boundary and the downloads), D7 (the licence rows).
- After this brief's evidence the owner chose option (b), and D4-78's choice of option (a) is superseded (D4-85). The same branch then carries ADR-0009's decision.

### P4-D7-1 (D7): `docs/release.md`, the first inventory

- **Objective.** State what `cmd/otsec` and `cmd/otsec-collector` contain today and under which licences, from primary sources, so that every later toolchain or dependency change has a record to update, and the licence duties of option (a) are known before anything is shipped.
- **Deliverables, all in `docs/release.md`:**
  1. The modules linked into each binary, with version and `go.sum` hash, and the Go toolchain and standard library, derived by commands the file states.
  2. Each component's licence, read from the component's own files, with the file's SHA-256.
  3. What each licence asks of a distributor, and whether the repository does it today. An unmet duty is listed, not fixed.
  4. The third-party programs of option (a), not shipped today (Suricata, Zeek and the ICSNPP packages, Npcap): what shipping each would require, from its licence text.
  5. A list of what does not exist yet: signing and the key's holder, the SBOM's format, the update package's contract, the anti-rollback floor, and the record of which versions upgrade and roll back together. No design.
  6. The one check that shows the file and `go.sum` disagree, described for D6 to turn into a test later.
- **Inputs.** `go.mod`, `go.sum`, the module cache, the Go distribution's own files, the threat model's TB9, AC-9, AP-10, SC-13 and AP-30, and ADR-0009's licence rows.
- **May change:** `docs/release.md`, `docs/phase4/D7-*.md`.
- **Acceptance.** Every licence statement names the file it was read from and that file's SHA-256. The inventory can be regenerated by the stated commands, and D7 ran them. The file is labelled `desk`.
- **Exclusions.** No change to `go.mod`, `go.sum`, a workflow, `deploy/` or code. No key is made. No SBOM file is generated into the repository. Nothing is called compliant or release-ready.
- **Branch:** `agent/release-inventory`. **Reviewers:** D3 and D6.

### P4-D6-H5 (D6): the closing legs for R4.1, R4.6, R4.7, R8.6 and R8.8

- **Objective.** Run each of the five criteria on the real binaries against the ground truth it names (D4-82's ruling), and find out whether the product passes.
- **Deliverables:**
  1. The node forwards to a stock rsyslog over RELP with mutual TLS and the durable acknowledgement, and rsyslog's own output is reconciled against the simulator's rows (R4.6).
  2. V-S6's interruption run, with its kills, against that rsyslog (R4.7, R8.6).
  3. V-S9 on its named ground truths: rsyslog as the upstream, and a direct read of the store showing that nothing unforwarded was evicted (R8.8). If no read-only way to read the store exists, D6 reports it and adds no product code.
  4. A framing fault and a malformed message sent to the real binaries, each stored raw and flagged, with no message lost (R4.1).
  5. One mutant for each new test, never committed.
  6. New `integration-long` matrix entries in `ci.yml`, with the packages they install and their versions printed.
- **May change:** `tests/integration/`, `tests/security/`, `docs/phase4/D6-closing-legs.md`, and, authorized by D1 here, `ci.yml` for those entries. Not `docs/verification.md`: the status cells follow in a later PR, after the legs pass on `main`.
- **Inputs.** The matrix's legend and the five rows' cells in #613, V-S6's and V-S9's criteria with their ground truths, and D4-82.
- **Acceptance.** Each leg is green on the PR's head, or red for a reason reported as a finding. A product failure is a result: the test is not loosened, and no product code changes. **A failing leg is never removed, skipped or marked as an expected failure.** If the product fails, the PR stays open with the leg red, D6 writes the finding in `docs/phase4/D6-closing-legs.md` and reports it to D1, and the owner of the code fixes the product in its own PR. The oracles are rsyslog's own output and the store's contents, never the product's code or D6's own receiver.
- **Exclusions.** No product code. No lowering of any criterion. Loopback only. No new CI job outside `integration-long`'s matrix.
- **Branch:** `agent/verification-closing-legs`. **Reviewers:** D4, D5 and D1.

### P4-PC-1 (D5 and D6): the six tests that pass only on a CI runner

- **Objective.** `go test ./...` passes on a Windows machine that is not elevated, not on UTC, and holds `reference/`, `tools/` and `.claude/worktrees/` inside the checkout, with nothing left behind, and each test still fails when it should (D4-83's first local run).
- **D5's half** (`agent/platform-pc-run-fixes`): the test that formats a C7 time from a local time, after checking that no product path does the same; the `nodeconfigtest` helper, so that a test which needs elevation and skips leaves no folder its cleanup cannot remove. The tests already skip when not elevated, and already fail instead when `GITHUB_ACTIONS` is `true` or `OTSEC_REQUIRE_ELEVATED` is set; both conditions stay. **May change:** tests and test helpers under `platform/` and `cmd/otsec/`. **Reviewers:** D6 and D3.
- **D6's half** (`agent/verification-pc-run-fixes`): every test that walks the repository tree, with one stated rule for what a walker skips and a test of that rule. The rule is anchored at the repository root, and an unreadable folder anywhere else still fails the test. **May change:** `tests/` (not `tests/integration/slice/`), and, authorized by D1 here, the walk's skip rule in `contracts/advisory/testkeys_test.go`, a C11 test that D3 drafted. **Reviewers:** D3, D5 and D1.
- **Inputs.** D4-83's account of the first local run, and `HANDOFF.md`'s section on the project folder.
- **Acceptance.** On the owner's PC, not elevated, the affected packages pass, or skip the elevation-only tests with their message, and no folder is left in the temp directory. Each fixed test fails again when its fix is reverted or its rule is broken. All nineteen `ci` jobs and `govulncheck` are green, and on CI the elevation tests still run.
- **Exclusions.** No weakening of what any test asserts. No elevated run.

### P4-D4-F26 (D4): the forwarder's rsyslog tests run in CI and cannot skip there (issued 2026-11-11, D4-84)

- **Objective.** The three tests of `modules/telemetry/forward/rsyslog_test.go` run on every pull request in the Linux `go` job, against the `rsyslogd` that Ubuntu's packages install, and fail if rsyslog is missing. Then find out whether the forwarder passes them (F-026).
- **Inputs.** D6's diagnosis on #619 (`4776b0da` and `1a9439f3`), and how `tests/integration/slice` starts a stock rsyslogd.
- **Deliverables:**
  1. The set-up fixed, so the installed `rsyslogd` starts under the runner's AppArmor profile, or a copy of it does, with the test saying which and checking the copy against the installed binary.
  2. In the Linux leg of the `go` job: `rsyslog` and `rsyslog-relp` installed with their versions printed, and `OTSEC_RSYSLOG_REQUIRED=1` for the `go test` step. `fail-fast: false` on the matrix.
  3. The result. If the forwarder fails a test, that is a product finding: D4 stops, loosens nothing, and reports to D1.
- **May change:** `modules/telemetry/forward/rsyslog_test.go`, and, authorized by D1 here for those lines only, `.github/workflows/ci.yml`.
- **Acceptance.** Every check green on the PR's head, with the Linux `go` log showing each of the three tests' `--- PASS`. With rsyslog absent and the variable set, the tests fail.
- **Exclusions.** No change under `tests/`. No weakening of what the tests assert. A failing test is never skipped, removed or marked as an expected failure.
- **Risk.** A copy of the binary runs outside the vendor's AppArmor profile, and the Linux `go` job's rsyslog is a newer build than the one the closing legs use. Both are stated with the result.
- **Branch:** `agent/telemetry-rsyslog-tests-run`. **Reviewers:** D6 and D5.
- This brief was given to D4 at about 13:30Z on 2026-11-11 and written here afterwards, in D4-84's PR.

## Phase 4 item 4, second part: the sensor under option (b) (issued 2026-11-11, D4-86)

The owner chose option (b) on 2026-11-11 (D4-85): a separate Linux machine at each site runs the engine and feeds the node. ADR-0009 records the decision and what it commits the project to. This part covers the evidence for the engine, the contracts for the link between sensor and node, and the test rig (CLAUDE.md §5.1, stages A and B). **No sensor code, no dialer and no enrolment code merges until D1 approves the link's contracts.** The implementation briefs follow that approval, as the third part.

Common rules, beside those of every Phase 4 brief:

- Nothing captures traffic on a real network. Every capture is a public one, a GT-PCAP one, or one recorded from the project's own simulators. Every interface is a virtual one in a network namespace on a CI runner.
- The sensor never transmits on its monitoring interface (C-11), and nothing scans or probes (P1).
- No contact with any device, and no lab machine. What needs a lab machine becomes an H-row that D6 writes and nobody runs without the owner's authorization.
- On the owner's PC: no test package in full that holds a listener off loopback, tests by name only, and nothing installed (`HANDOFF.md`). These briefs need no local run: their test path is GitHub Actions.
- Each role reads CLAUDE.md, `HANDOFF.md`, its own agent file, ADR-0009 and D4-82 to D4-86 before it starts. Where a brief lets a role change a path it does not own, D1 authorizes that change by the brief, for what the brief names and no more.

**What already exists** (read on `main` on 2026-11-11, `desk`): the node's intake `ServeSensor` reads any byte stream with C13's framing and assumes that its caller authenticated the peer; `sensor-unreachable`; the hold for the node's own sessions; the two network store classes; the detector, which runs on the node. **What does not exist:** a sensor program, an engine on a sensor host, enrolment or a credential for a sensor, a TLS dialer or listener for C13, sensor fields in the node's configuration, more than one sensor for a node, an update path for the sensor, and every test rig in D6's GT-PCAP plan §5 and §6.

### P4-4-S2 (D4): E-D4-03, the engine on Linux over GT-PCAP

- **Objective.** ADR-0009 names Zeek as the provisional engine. Produce the run that lets D1 approve it or turn the choice: Zeek on Linux, with and without the ICSNPP-DNP3 and ICSNPP-Modbus packages, over the labelled captures.
- **Inputs.** E-A4-01 and E-D4-02 (`modules/telemetry/experiments/`), GT-PCAP and its labels (`tests/fixtures/network/gt-pcap/`, `tests/integration/gt_pcap/`), D6's plan, D2's review of #618 (what each SEL family puts on the wire), D7's `docs/release.md` §4 (written under option (a); its readings of Zeek's and ICSNPP's licences still apply).
- **Deliverables:**
  1. **A dispatch-only workflow and experiment folder** under `modules/telemetry/experiments/`, offline, on a Linux runner. It runs a pinned Zeek, once stock and once with the two ICSNPP packages, over: GT-PCAP's 19 DNP3 captures (17 labelled cases, and the training and held-out series), of which the five `dnp3-sa` cases hold group 120 objects (`dnp3-sa`, `dnp3-sa-failed-outstation`, `dnp3-sa-failed-before-ack`, `dnp3-sa-failed-unauthorized` and `dnp3-sa-failed-master`); the two cases that D6 adds first under P4-4-R1, DNP3 on a moved outstation port and DNP3 over UDP, which GT-PCAP does not hold yet; the 9 PRP pairs; and the public captures. Suricata runs over the same set, with and without `stream.midstream=true`, as the comparison.
  2. **A table per engine and configuration,** against GT-PCAP's labels, which come from tshark and not from an engine: per case, whether the protocol, the function and the service are recorded; whether DNP3 group 120 is visible per session; whether DNP3 and Modbus are found on a moved port; DNP3 over UDP; what the engine logs of SNMPv3's header fields and of Telnet, FTP and HTTP. A row that did not run is `unknown`.
  3. **Pins:** the engine images or packages and each ICSNPP package by version and hash, with the upstream signature checked where one is published, and a first-use pin called a first-use pin. `zkg` may fetch in the experiment; say in the note that a sensor may not fetch at run time (AP-31), so the packages must be carried.
  4. **A findings note** `docs/phase4/D4-engine-linux-eval.md`, and ADR-0009's evidence updated with the run. D4 states its recommendation; the ADR's engine line changes only on D1's approval in review.
- **May change:** `modules/telemetry/experiments/`, a new dispatch-only workflow under `.github/workflows/` (authorized here), `docs/decisions/ADR-0009-passive-sensor.md` (evidence and D4's view), `docs/phase4/D4-*.md`.
- **Acceptance.** Every claim has a run URL and its evidence class (`CI-Linux`). The workflow is dispatch-only, has `permissions: contents: read`, uploads no binary and no capture, and checks every pin before it runs what it fetched. The table's pass conditions are D6's, from the labels, and D6 commits them before the counted run, with the two new cases. **The result is evidence for the engine choice. It is not V-M6 evidence:** V-M6 runs on the real sensor.
- **Exclusions.** No sensor and no product code. No change to `ci.yml`. No capture of a real network.
- **Risk.** Offline decoding of files is not live capture on a SPAN or TAP port, and a hosted runner is not the sensor host. Both stay `unknown` and are named.
- **Branch:** `agent/telemetry-engine-linux-eval`. **Reviewers:** D6 (the pass conditions), D2 (the protocol reading), D7 (the pins and licences).

### P4-4-L1 (D3): the trust design of the link, and the sensor host in the threat model

- **Objective.** Fix, before any code, how a sensor on another machine is trusted by the node and what it may hold, and bring the threat model in line with option (b).
- **Inputs.** ADR-0009, TB6, AP-30 to AP-36, SC-11, SC-14, SC-19, HR-19, HR-20, D5's note `docs/phase4/D5-sensor-node.md` (§1(b), §2), C13's note, C7 and C8 as they stand, and D3's and D5's reviews of #618.
- **Deliverables:**
  1. **A design note** `docs/phase4/D3-sensor-link.md` that fixes:
     - **the credential:** one key per sensor, made on the sensor and never exported, and what the node holds;
     - **enrolment with no trust on first use:** both ends pinned out of band by an admin-signed, audited request, with the C7 kind and the C8 actions it needs;
     - **binding:** the node's configuration names the sensor's address, key and `sensor_id`, and a record under any other `sensor_id` is refused with an alarm; one compromised sensor cannot speak as another;
     - **revocation:** it closes the link at once; records already stored are kept and marked, later ones are refused, and the network baseline is acknowledged again;
     - **replay and resume:** what C13's channel must carry so that a replayed, re-ordered or cloned stream is refused, and so that sequence and resume survive a re-image of the sensor;
     - **direction:** the node opens the link and gains no inbound port; the link carries the sensor's C13 records and the node's acknowledgements, and no command and no configuration to the sensor;
     - **secrets on the sensor:** the sensor holds no platform credential, and no unredacted secret is at rest or sent: the ring, the engine's own logs, temporary files, swap and core dumps. A slot that cannot be placed fails closed and is counted (D4-67, D4-68 ruling 13);
     - **the management side of the sensor host:** who may log in and how, physical custody, and the update path with AP-10's three refusals, each stated as a requirement on the host and marked as not built. AP-31 is proposed and was written for the node: say whether it covers the sensor host, including its rule that nothing is fetched at run time (D7 on #618).
  2. **The threat model updated** (`docs/threat-model.md`): TB6 and AP-30 to AP-34 read for a sensor on another host; HR-20 closed by D4-85, to reopen if option (a) or (c) does; a new **HR-21** for the sensor host (its image and patching, management access, custody, TAP or SPAN); and AP-32 (1) stated plainly: against a compromised sensor host, only a TAP, or the switch refusing ingress on the mirror port, keeps it from sending.
  3. **Proposals, not code,** for the C7 and C8 additions, for D1's approval with D4, D5 and D6.
- **May change:** `docs/threat-model.md`, `docs/phase4/D3-*.md`. No file under `contracts/` in this brief.
- **Acceptance.** Each rule names the attack path it answers and the test that would show it (for D6's rig). Nothing is written as built. D5 confirms that the node can do what the note asks of it, and D4 that the sensor can.
- **Exclusions.** No code. No change to a contract's text or version. No decision on the sensor host's hardware or operating system, which D1 brings to the owner.
- **Branch:** `agent/security-sensor-link`. **Reviewers:** D5, D4 and D6.

### P4-4-L2 (D4): C13 0.2, the channel over a network link

- **Objective.** Revise C13's channel for a link between two machines, as ADR-0009 says, without changing what an observation is.
- **Inputs.** `docs/phase4/D4-c13-netobs.md` and `contracts/netobs/`, D3's note from P4-4-L1 (its rules are the requirements), D5's review of #618 and its note, and the lesson of C-04 and E-01 on acknowledged delivery.
- **Deliverables:** a written proposal for `otsec.netobs/0.2`, with its reader for 0.1, that covers:
  1. the transport under (b): C13's framing inside mutual TLS on a connection that the node opens;
  2. acknowledgement of the committed sequence number, resume after a break, and a bound on how late a record may arrive, with what the node does past it;
  3. what binds a stream to one sensor and one run, so that replay and a cloned sensor are refused (from P4-4-L1);
  4. the sensor's buffer while the link is down: how much, for how long, and what is counted when it overflows (D5's note leaves this to D4);
  5. time: the sensor host's clock in each record and heartbeat, so that the node can check the skew. The proposal may add clock fields. It does not define R6.4's latency: that measure is D6's, the alert's time minus the triggering frame's send time (GT-PCAP plan §5);
  6. the wording left over from an on-node sensor: the local pipe, `drops_driver` in `pktmon` terms, and the Windows binding read in `interface_check`, each replaced by its Linux `AF_PACKET` meaning;
  7. the PRP stage's missing pieces: `prp_window_ms` in the coverage settings and the bounds table, and a counter for a "duplicate" that is not byte-identical apart from the LAN ID (D4-69);
  8. a signal for a sensor that heartbeats but is blind (flat packet counters, D4-74), so the node can raise `sensor-blind`.
- **May change:** `docs/phase4/D4-c13-netobs.md` and a proposal file `docs/phase4/D4-c13-0.2-proposal.md`. The code in `contracts/netobs` changes only after D1 approves the proposal, under the third part's brief.
- **Acceptance.** Every change bumps the minor and keeps a 0.1 reader. Each clause says which of D3's rules it meets. D6 can write a contract test for each clause from the text alone.
- **Exclusions.** No change to what an observation, a citation or a coverage statement means. No change to how any criterion in `docs/verification.md` is measured. No code.
- **Order.** After P4-4-S2, and with P4-4-L1's note in hand.
- **Branch:** `agent/telemetry-c13-link`. **Reviewers:** D3, D5, D6 and D2.

### P4-4-L3 (D5): the node's side of the link

- **Objective.** Say what the node must become to dial a sensor on another machine, and mark what was written for a sensor on the node as history.
- **Inputs.** `docs/phase4/D5-sensor-node.md`, `platform/node` and `platform/sensorlink` on `main`, D5's review of #618, D3's note from P4-4-L1 (`docs/phase4/D3-sensor-link.md`), and the reviews on #624. Added by D4-87, from D6's review of `f9d3a1d1`: a bound on `sensor.coverage-gap` events and on stalled handshakes, so that a sensor cannot fill the platform class, with the test named; and the node's read of the audit chain at start is conditional today (it is skipped when there is no event baseline), so an unreadable or future-dated time must hold the cap on `sensor.link_refused` and never fail the start.
- **Deliverables:** `docs/phase4/D5-sensor-node.md` revised for option (b), as a design for D1's approval:
  1. the mutual-TLS dialer with backoff, and the node's outbound firewall rule to the sensor's one address;
  2. the `network_sensor` configuration: address, trust anchor, credential and permitted peer, and whether a node has one sensor or several (a PRP network may need one for each LAN), with what each choice costs in the intake, the store classes and the baseline;
  3. enrolment and revocation records, and an expiry alarm for the sensor's certificate;
  4. the clock-skew check on each heartbeat, with its bound and its alarm;
  5. records that arrive late after an outage: how the hold for the node's own sessions waits for the sensor's backlog, so that `own-session-unseen` does not fire falsely;
  6. retiring and replacing a sensor, so that its streams keep a consumer and are pruned;
  7. `sensor-blind`, beside `sensor-unreachable`;
  8. the rule that a sensor failure, or a flood from it, must never affect SER or Syslog collection, with the test that would show it. The separate store classes exist; no flood over a network link has run (D3 on #618);
  9. the sections written for a pipe and a service SID, marked as history.
- **May change:** `docs/phase4/D5-*.md`.
- **Acceptance.** Each item names the code on `main` that it changes and the test that would show it. Nothing is written as built.
- **Exclusions.** No code. No change to C5's classes or quotas in this brief: a need for one is reported to D1.
- **Branch:** `agent/platform-sensor-link`. **Reviewers:** D3, D4 and D6.

### P4-4-R1 (D6): the rig for the sensor's tests

- **Objective.** Build, before the sensor exists, the rigs that V-M6, R6.4 and C-11 need, so that the sensor is tested by something that was written first.
- **Inputs.** `docs/phase4/D6-gt-pcap-plan.md` §2, §5 and §6, `docs/verification.md` (V-M6, C-09, C-11, H-06, R6.1 to R6.7), GT-PCAP, D6's review of #618, and the rules in P4-4-L1 as they land.
- **Deliverables:**
  0. **First, because P4-4-S2 waits for them: two GT-PCAP cases with their labels,** DNP3 on an outstation port other than TCP 20000, and DNP3 over UDP (the plan's §2B). Today the outstation listens only on TCP 20000, and `dnp3-known-master-new-port` moves the master's source port (D2 and D6 on #618).
  1. **The veth rig:** a pair of virtual interfaces across two network namespaces on a Linux runner, with a timed replayer on one end, for R6.4's latency.
  2. **The C-11 rig:** zero frames from the monitoring interface over the whole GT-PCAP replay and the sensor's start and stop, with its negative control, a deliberately misconfigured interface that must show frames. It includes a sender that uses `PACKET_QDISC_BYPASS`, so that an nftables egress rule is tested against a path that may skip it.
  3. **The test-only C13 source,** which turns GT-PCAP's labels into C13 records over a real byte stream. It is never linked into either binary.
  4. **The checker** that compares a product's records with the labels: the pass conditions for V-M6, written from `docs/verification.md` and not from an engine's output.
  5. **Cases with no plan yet, planned here and built where the rig allows:** `CAP_NET_RAW` dropped after the socket opens; a link cut and resumed; a revoked sensor credential refused and alarmed; no inbound port on the node; the spoofing flood; AP-33's key search over the sensor's disk and the link's bytes.
  6. **H-rows, written and not run,** for what only a lab machine can show: a real NIC on a SPAN or TAP port, VLAN tags under NIC offload, PRP live on both LANs, HSR, and the 24 h run (H-06).
- **May change:** `tests/`, `docs/verification.md` (plans and H-rows), `docs/phase4/D6-*.md`, `.github/workflows/a6-*.yml` and, authorized here, new `integration-long` entries in `ci.yml` for the rigs' own self-tests. `tests/fixtures/network/` is D4's path: D1 authorizes the two new GT-PCAP cases and their labels there, and D4 accepts each label file. A PR that touches GT-PCAP also needs `a6-gt-pcap` green.
- **Acceptance.** Each rig has a self-test that fails when the rig is broken: the negative control shows frames, the replayer's timing is checked against its own clock, and the checker fails on a planted wrong record. Evidence class `CI-Linux`.
- **Exclusions.** No product code and no sensor. No real NIC of a runner as a monitoring interface. No lowering of any criterion.
- **Branch:** `agent/verification-sensor-rig`. **Reviewers:** D4, D5, D3 and D1.

### Order

1. **Now, in parallel:** P4-4-S2 (D4), P4-4-L1 (D3) and P4-4-R1 (D6). P4-4-R1's two new GT-PCAP cases come first, and P4-4-S2's counted run waits for them.
2. **Then, with L1's note:** P4-4-L3 (D5) and P4-4-L2 (D4). Both started on 2026-11-11 (D4-87). L2 was to wait for S2's result. D1 started it first, because the channel does not depend on which engine is chosen and the engine run was waiting on the hosted runners. L2 marks each clause that the engine's result could change.
3. **D1 approves** the engine (from S2) and the link's contracts (from L1, L2 and L3), and brings the owner a recommendation on the sensor's host: its hardware, its operating system, and whether the project ships an image or the site installs the engine (D7's review of #618 gives what each costs in licence duties).
4. **The third part:** the implementation briefs for the sensor, the node's dialer and enrolment, each against the approved contracts, with D6's contract tests.

### Phase 4 item 4 exit gate (D1 decides)

It holds every criterion that the Stage A brief listed under "What item 4 must show at its gate", unchanged, and these, which option (b) adds:

- V-M6 over GT-PCAP runs on **the real sensor and the real node, over the real link**, `simulated`, on the rig of P4-4-R1.
- C-11 as the Stage A bullet states it, on the sensor's monitoring interface: the full GT-PCAP replay and the sensor's start and stop, the interface up throughout, a virtual interface in a network namespace of its own, with its negative control. The 24 h run stays with H-06 on hardware.
- R6.4's latency from the timed replay, reported with the clock it was measured against.
- The link refuses a sensor without the enrolled credential and a revoked one, and the node has no inbound port.
- A sensor that is cut, blind or flooding never stops SER or Syslog collection.
- AP-33's key search finds no test secret on the sensor's disk, in the link's bytes, in the node's store, or in anything forwarded.
- On the real link: a record under another `sensor_id` is refused and alarmed, and a replayed stream is refused.
- A sensor that heartbeats but is blind raises its alarm, and a sensor clock outside the bound raises the skew alarm.
- The sensor holds no capability after its capture socket is open (`CAP_NET_RAW` dropped), shown by a test.
- C13 0.2 and the C7 and C8 additions are merged, with their reviewers' records and D6's contract tests.
- No safety or security objection is open, and the report says what remains `simulated` and which H-rows wait for a lab machine.
- The engine and its packages are pinned, and D7's inventory covers the sensor.
