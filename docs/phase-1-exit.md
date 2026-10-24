# Phase 1 exit report

Owner: A1. Date: 2026-10-24. Status: **gate passed with conditions, pending owner sign-off.**

This report closes Phase 1 (contracts and minimal architecture). It follows the milestone format in `CLAUDE.md` §9. Phase 1 wrote contracts, not product code, and nothing was run against a device. Every result here is either `desk` (code and tests on a CI runner) or `simulated` (synthetic transcripts and A6's recording simulator). No result is `hardware-verified` (B-01).

## Milestone

**Phase 1: contracts and minimal architecture.** The objectives were:

- approve the eight contracts the first slice needs (C1 to C8);
- show they fit together, using deterministic fixtures;
- review the major security assumptions;
- give a clear integration path for the first workflow: collect native SER from a simulated SEL-751, keep the evidence, and forward it to an upstream Syslog collector.

## Implemented (on `main`)

| ID | Contract | Package | Owner | PRs | Reviewers, all accepted |
| --- | --- | --- | --- | --- | --- |
| C1 | `otsec.asset/0.1`: asset identity, identity binding, capability profile, endpoint `target` | `contracts/asset` | A2 | #32, #65 | A3, A4, A6 |
| C2 | `otsec.adapter/0.1`: invocation, result, transcript, session dialogue rules | `contracts/adapter` | A2 | #51, #65, D1-25 PR | A1, A3, A4, A6 |
| C3 | `otsec.register/0.1`: signed command register format; SEL-751 content rev 2 | `contracts/register` | A1 (format), A2 (content) | #27, #32 | A2, A3, A6 |
| C4 | `otsec.event/0.1`: event, native evidence, time, alignment, `evidence_class` | `contracts/event` | A4 | #29, #42, #59, #63 | A2, A3, A5, A6 |
| C5 | `otsec.store/0.1`: store, outbox, cursors, startup recovery | `contracts/store` | A5 | #33 | A3, A4, A6 |
| C6 | `otsec.syslog/0.1`: forwarding targets, rendering, RELP grammar, `evc`, audit rendering | `contracts/syslog` | A4 | #42, #59, #63 | A1, A2, A3, A5, A6 |
| C7 | `otsec.authz/0.1`: roles, credentials, collector IPC, failed-auth floor | `contracts/authz` | A3 | #38, #64 | A2, A5, A6 |
| C8 | `otsec.audit/0.1`: audit record and hash chain, `transcript_sha256` | `contracts/audit` | A3 | #38, #64 | A4, A6 |
| — | `contracts/version`, `contracts/node`, `contracts/internal/strictjson` | | A1 | #26, #29, #27 | A6 (via contract tests) |

- Review records are in `docs/phase1/reviews/<contract>-<reviewer>.md`.
- Decisions D1-1 to D1-25 are in `docs/phase1/A1-decisions.md`.
- Contract status is in `contracts/README.md`.

Supporting design, all merged:

- **A3 credential design** (`docs/phase1/A3-credential-design.md`), which closes B-04 as a design.
- **A5 store semantics and node posture** (`docs/phase1/A5-store-semantics.md`, `A5-node-posture.md`, `deploy/README.md`).
- **A2 contract notes and the Q5 RTAC paper exercise** (`docs/phase1/A2-contracts.md`, `A2-q5-rtac.md`).
- **A4 contract notes** (`docs/phase1/A4-contracts.md`).
- **A6 chain notes** (`docs/phase1/A6-chain.md`).
- **Threat model:** AP-20 and SC-16 updated for C6.

## Independently verified

### A6 contract tests (`tests/contract/`)

- A6 built them from its own transcription, never from the owners' test data.
- Every contract has at least one negative test that its owner did not write.
- Each test states its ground truth (see `README.md` there).

### A6 C2 probes

A6 wrote its own synthetic sessions and ran them against the exported API: 13 probes in round 1, and more at each re-check.

All of them are now refused, including:
- a password with no `Password: ?` before it (C-17);
- `QUI` after an unconfirmed password (C-19);
- lines sent before a prompt;
- a credential sent with no language probe or identity check;
- `QUI` after an unanswered `ACC`;
- `QUI` after a rejected probe.

The probes are committed as contract tests.

### Negative tests on A1 decisions

- **D1-11:** with the audit store full, the act never runs, so no `ACC` is sent, while received Syslog still commits.
- **D1-15:** audit is refused over UDP, on a best-effort target, without `durable_ack`, and without mutual TLS.
- **D1-20:** the failed-auth floor holds across a crash, now from `ACC` (amendment).
- **D1-23 and D1-24:** `evidence_class` and endpoint `target` are refused when missing, empty, mis-cased or of another class. A later-minor class reads as `simulated`.

### Chain test (`tests/contract/chain_test.go`)

- The chain is one SEL-751 `ID` plus `SER` collection, built end to end from contract types only: C3 lookup → C7 IPC → C2 invocation and result → C1 identity → C4 events → C5 commit → C6 rendering → C8 audit.
- All nine links run, and each fails rather than skips.
- Passing run before the final fixes: [40115458123](https://github.com/alialyami90/OTSEC-Proj/actions/runs/40115458123), on Linux and Windows.
- The chain test found two C2 faults, which were fixed under D1-25:
  - the transcript digest was not in the audit chain;
  - SER field names differed from C4's.
- Final run from `main`, with the end-to-end transcript-digest check and `CheckAgainst`: *(run ID)*.

### A1 integration checks

- Before each merge, A1 ran `go vet`, `gofmt` and `go test ./...` on the merge with `main`.
- For C3 and C6, A1 also probed the code directly, for example with 13 hostile RELP responses against `ParseRELPResponse`.

### CI

CI runs Go on Linux and Windows, plus pytest, on every PR.

## Exit-gate items

| Gate item (P1 briefs) | State |
| --- | --- |
| C1 to C8 merged at 0.x, each with every listed reviewer's record | Met. Reviewer table above. |
| Chain test passes in CI on Linux and Windows | Met (run IDs above). |
| B-02, B-03, B-04, B-05 closed, or carried with the owner's agreement | **B-02** is closed for the SEL-751 slice from documented evidence; H-09 confirms levels on hardware. **B-03** is closed as a contract. **B-04** is closed as a design. **B-05** is closed for the slice as a stated limit: the binding is device-reported and spoofable, the FID is checked before the credential, and `CredentialAllowed` gates it. |
| A3's security review recorded for every contract, with no open safety or security objection | Met. A3 reviewed C1 to C6. C7 and C8 are A3's own and were reviewed by A6 for security. No objection is open. |
| Integration path for Phase 2 | Below. |

**Conditions carried into Phase 2:**
- the pinned-key enrollment rule (before any SSH family);
- replacing PEN 32473 (before production);
- the owner decision below on plaintext Syslog.

## Owner decisions needed

1. **Plaintext Syslog outside the lab.** In 0.1, two things are `lab-only` (D1-21, D1-22): receiving plaintext UDP Syslog (RTAC, SEL-2730M, SEL-2488), and forwarding to `tcp`, `udp` or plain `relp` targets. A production scope, such as `same-segment`, needs your decision. This does not block Phase 2, which is simulated.
2. **Phase 2 start.** Phase 2 builds product code against these contracts. It contacts no device: the slice runs against A6's simulator, and the node refuses any endpoint marked `device-observed` until you authorize a lab relay (D1-24).

## Failed or incomplete

- No contract has met a device. Every device fact comes from manuals.
- **H-14 part 2** ran on a hosted Windows Server 2025 runner (run 40090170881, F-014). With the reserve released before the first open, a full store opened and recovered in every round. `INCREMENTAL` with cursor pruning passed, and R-A5-5 held. Four cases are still open:
  - startup with no reserve to release;
  - a failed release;
  - a Windows 10/11 client edition (LTSC 2021);
  - the product binary as the thing under test.
- **`OpenHeadroomBytes`** (A5, *proposed*): whether it actually prevents F-013 is untested.
- The hardware procedures for H-01 to H-14 are written but not run, as the owner directed.

## Unverified assumptions

- **Manual-derived facts.** Every device fact comes from the SEL-751 manual (S22, date code 20260910) or other SEL manuals. Tests built from the same manual share its errors (risk 3).
- **Prompt position.** The SEL-751 prompt is assumed to follow `ETX` directly, and the password is assumed not to be echoed. No capture shows either (H-12, H-13).
- **Pending password across connections.** Whether a relay keeps a pending `Password: ?` across connections is unknown (H-15). The D1-20 amendment covers it by starting the floor at `ACC`.
- **Windows credential mechanisms.** The TPM key ACL for a virtual account and the DPAPI scope in the credential design are `[doc]` or `[inferred]` until T-1 to T-5 pass on the site image (H-14).
- **RELP `durable_ack`.** It depends on the collector's configuration, so commissioning has to test it (V-S6).
- **SER row length.** The 80-byte SER row length behind the 1 MiB response ceiling is inferred from Figure 10.16 and has not been measured.

## Architectural decisions

D1-1 to D1-25 are in `docs/phase1/A1-decisions.md`. These shape Phase 2 most:

- **D1-10:** one strict decoder for every contract.
- **D1-11:** audit comes before the act. A full audit store stops credentialed collection, and Syslog continues.
- **D1-15:** audit is forwarded only over RELP/TLS.
- **D1-18, D1-19:** family limits and the secret policy live on the C1 profile.
- **D1-20 and its amendment:** the failed-auth floor starts when `ACC` is sent and clears only on `=>`.
- **D1-21:** C2 stays command/response only. Push sources go through C1, C6 and C4.
- **D1-22:** insecure forwarding needs an acknowledgement and sends no device content by default.
- **D1-23, D1-24:** every device event says whether its source was a real device or a simulator. The label comes from configuration (the endpoint and listener `target`), never from a default and never from the far end.
- **D1-25:** the C8 session-close record carries the C2 transcript digest, so stored evidence can be checked against the audit chain.

## Open risks

- **No hardware (B-01).** No family may be called supported, and the slice can be accepted only as `simulated`.
- **Residual SER loss with repeated keys (D1-17).** It cannot be detected from the reads alone. Only a device run shows how often it happens.
- **Pinned-key enrollment.** C1 does not yet say how a pinned key is obtained (out of band, never trust on first use). This must be settled before any SSH family is enrolled. It does not affect the Telnet slice.
- **PEN 32473** in C6 is the RFC 5612 documentation number and must be replaced before production.
- **Plaintext Telnet to the relay** is accepted for the lab only (ADR-0005).
- **The 31-minute floor.** It now also follows an `ACC` that times out. On a flaky link this delays collection. That is a deliberate trade against the relay's alarm contact.

## Phase 2 integration path

The first workflow is: simulated SEL-751 → collector → node store → forwarder → rsyslog.

1. **A5: node runtime and store.**
   - SQLite implementation of C5, with group commit, startup recovery, quotas and the C8 audit chain.
   - Windows service skeleton.
   - Node configuration, including the listener and endpoint `target` and the `device-observed` interlock (D1-24).
   - First test: the C5 contract tests and A6's D1-11 test against the real store.
2. **A3: collector service.**
   - C7 IPC over a named pipe.
   - The credential store: sealed install, and the failed-auth floor in durable state, written before `ACC`.
   - Audit before act, and `transcript_sha256` at session close.
3. **A2: SEL-751 adapter.** A Telnet transport that implements C2 against A6's recording simulator:
   - language probe, FID check, and `ACC` with a single-use slot;
   - `SER` read and `QUI`;
   - STX/ETX framing, and the C3 egress check on every line.
4. **A4: normalization and forwarding.**
   - SER → C4 with alignment (D1-12, D1-14).
   - A C6 forwarder over RELP/TLS with `durable_ack` to a local rsyslog.
5. **A6: end-to-end test of the first workflow.**
   - The forwarded events must reconcile 1:1 with the native rows: timestamps, order, no duplicates, no loss.
   - Every event carries `evc="simulated"`.
   - The recording simulator must show no write command (V-S7).
   - Then interruption and restart (V-S6, V-S9).

Order:
- Steps 1 and 2 start first, in parallel.
- Step 3 starts against the simulator once step 2's IPC is stubbed.
- Step 4 starts once step 1 exposes the outbox.
- Step 5 runs at each integration step.

## Owner sign-off

*(pending)*
