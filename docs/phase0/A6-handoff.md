# Handoff P0-A6 — A6 — 2026-10-23

**Completed:** Verification matrix and assumption challenge for Phase 0, in [docs/verification.md](../verification.md):
- Measurable acceptance criteria for V-S1 to V-S8, plus V-S9 to V-S15 that the slice also needs (storage exhaustion, command and parameter validation, credential leakage, telemetry failure observability, device session safety, identity mismatch, hostile device output). Each has a binary or numeric pass condition, named ground truth, what a simulator run proves, and what stays hardware-dependent.
- R-level matrix filled for all of R1 to R8 and P1 to P10 (the brief asked for R4, R5, R8 at minimum).
- An independent "no write operations" method (V-S7): static register check, a recording SSH simulator that logs every received byte, and transcript agreement. The recording layer is built and self-tested.
- Twelve challenged assumptions (C-01 to C-12), ten hardware-only tests (H-01 to H-10), six blockers (B-01 to B-06), five proposed architecture-critical risks.
- Experiment E-01 disproving that RFC 5425 write success implies delivery.

**Evidence:**
- E-01: [tests/integration/experiments/results/E-01-2026-10-23.json](../../tests/integration/experiments/results/E-01-2026-10-23.json). 5 of 5 trials, 100 of 150 frames lost with no write error. `simulated`.
- Recording simulator self-test: [tests/safety/recording_simulator/results/selftest-2026-10-23.txt](../../tests/safety/recording_simulator/results/selftest-2026-10-23.txt). 8 of 8 pass. `simulated`.
- Vendor facts in C-01 and C-02 (SEL `SER C`, `HIS C`, `TAR R`, ALARM pulse on access-level entry) are recalled, not checked against a manual. A2 must confirm or refute them from OEM documentation.

**Interfaces:** None introduced. The checker's register input (`{"commands": [{"id", "pattern", "classification"}]}`, full-line regex match) is a test-side format; A6 proposes that A2's approved command register be machine-readable in a form that maps onto it, so V-S7 (a) and (b) use the same source.

**Limitations:** No product code exists, so no criterion has been run against an implementation. No lab IED exists (owner, via A1), so no slice result can exceed `simulated`. The documented-behaviour layer of the simulator waits on A2's cited register. Cross-review of A2's command register and A3's threat model is pending: neither draft was on a pushed branch or in the project files when this handoff was written.

**Risks:** Parser and simulator both derive from OEM documentation, so a documentation error passes every simulated test (Device simulator plan, item 4). Thresholds marked *(proposed)* are A6 starting values, not evidence-based.

**Dependencies:**
- A1: approve or amend the criteria and thresholds; decide B-06 (test-harness language) and the `documented-example` fixture class (needs a change to `tests/fixtures/README.md`); carry B-03 and B-05 into Phase 1 contract approval.
- A2: classify full command lines including parameters, with citations (C-01, B-02); per family, session limits, lockout threshold, alarm side effects, lowest access level for SER and what else it permits (C-02, C-12); whether SER records carry a sequence number or counter (C-06).
- A3: credential storage design for site nodes (B-04); device identity trust model, no trust-on-first-use (B-05, C-07); treat device output as untrusted input (C-08).
- A4: event schema per C-05 (native timestamp verbatim, precision, offset "unknown", time quality, receive time); forwarding delivery semantics given E-01 (C-04, B-03); hostile output reaching the SIEM (C-08).
- A5: durable store with confirmed position and replay (C-04); storage exhaustion behaviour (V-S9); crash-consistency target for R8.7.

**Files changed:** `docs/verification.md`, `docs/phase0/A6-handoff.md`, `tests/integration/README.md`, `tests/integration/experiments/`, `tests/safety/README.md`, `tests/safety/recording_simulator/`, `tests/security/README.md`.

**Reviewer(s) and outcome:** A1 integration review pending. A6 does not review its own work.
