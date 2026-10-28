# Contracts

Owner: A1. Changes require a documented proposal and review by every affected module owner (CLAUDE.md sections 5.3 and 5.4).

Phase 1 approves the contracts C1 to C8 listed in [docs/architecture.md](../docs/architecture.md#contracts-required-for-phase-1). They are limited to what the first vertical slice needs. The briefs are P1-A1 to P1-A6 in [docs/agent-handoffs.md](../docs/agent-handoffs.md).

## Layout

One Go package per contract, in the root module `otsec.local/otsec`:

| ID | Package | Identifier | Owner | Status (2026-10-27) |
| --- | --- | --- | --- | --- |
| C1 | `contracts/asset` | `otsec.asset/0.2` | A2 | Merged (#32). 0.2: `Endpoint.path` (`direct`, `port-server`); only `direct` gets a session, and a 0.1 record's endpoints are refused until an administrator sets the path (D2-16, `docs/phase3/A2-c1-path.md`). |
| C2 | `contracts/adapter` | `otsec.adapter/0.5` | A2 | Merged (#51). 0.2: `failed.unexpected_password_prompt` and the probe QUI exemption (D2-14). 0.3: `failed.identity_unreadable`, which suspends nothing (A6 on #118, D2-17). 0.4: the unanswered language probe, reported as `failed.timeout` or `failed.transport_closed` (A6, V-S12). 0.5: `refused.endpoint_path` and `settings` (`DATE_F`), P3-A2. |
| C3 | `contracts/register` | `otsec.register/0.2` | A1 (format), A2 (content) | Merged (#27, #32); 0.2 adds context reads (D3-2); SEL-751 content rev 4. |
| C4 | `contracts/event` | `otsec.event/0.2` | A4 | Merged (#29, #42, #59: `evidence_class`, D1-23). 0.2: `source.sender.tls_leaf_sha256`, the certificate a `tls-mutual` sender presented; binding confidence unchanged (A3 on #150, A1). |
| C5 | `contracts/store` | `otsec.store/0.4` | A5 | Merged (#33). 0.2: `open-busy`, the one open failure `Resume` retries without a restart (P3-A5). 0.3: `Discarder`, bounded removal of named events from a quarantine stream (D3-1). 0.4 approved (D4-9, #246; store in #273): the configuration class with its record cap and document validator, held records that pruning skips, HR-11's `syslog-unknown` class, and the per-database commit cap and recovery reserve (`docs/phase4/B5-c5-0.4-proposal.md`). |
| C6 | `contracts/syslog` | `otsec.syslog/0.3` | A4 | Merged (#42, #59: `evc`; #81: D2-9 peer check by name and durable-write acknowledgement). 0.3 adds `tlsleaf`, the C4 0.2 sender fingerprint (Phase 3, A1). |
| C7 | `contracts/authz` | `otsec.authz/0.6` | A3 | 0.1 merged (#38). 0.2 adds `asset.clear_suspension` and `suspension_mismatch` (D2-15, A1). 0.3 adds `asset_suspended` and the held suspension it names, which the node adopts (A6 on #120). 0.4 adds admin-signed requests (`admin_signed`, `VerifyAdminRequest`) and the `admin_unverified` refusal (D2-11, P3-A3). 0.5 adds the admin-signed node kinds `node.quarantine_clear` and `node.seq_reset_ack`, and on an accepted admin-signed request `repeat_of` and `admin` (P3-A3, A5's #181). 0.6 adds `node.change_approval`, `node.baseline_ack`, the per-key allowed kinds and the `authority` check (P4-A3, D4-2); 0.6 approved (D4-9, #250). |
| C8 | `contracts/audit` | `otsec.audit/0.6` | A3 | 0.1 merged (#38); 0.2 adds the node-state actions (D2-15); 0.3 adds quarantine.exported and quarantine.cleared (P3-A5, D3-1); 0.4 adds the claimed and verified admin groups and repeat_of on collector.request (C7 0.5). 0.5 adds config.change_approved, config.change_detected and config.baseline_acknowledged, Admin.kind, ApprovalCovers and VerifyConfig (P4-A3, C7 0.6); 0.5 approved (D4-9, #250). 0.6 changes VerifyConfig only: a succeeded configuration-kind config.baseline_acknowledged ends every open configuration alarm of its asset raised before it (D4-18). |
| C9 | `contracts/config` | `otsec.config/0.1` | B2 | Approved (D4-9, #247; P4-A2, 2026-10-27): the configuration snapshot (every class of its rule, each section a transcript span and SHA-256, D4-8), the semantic difference, the `sel-751-sho/1` rule and `Digest` (`docs/phase4/B2-c9-config.md`). The record cap becomes 1.5 MiB with register revision 5 (D4-13). |
| C10 | `contracts/baseline` | `otsec.baseline/0.1` | B4 | Approved (D4-9, #254; P4-A4, 2026-10-27): the R4.8 event-behaviour baseline of one asset (the event-type key, which events count, the record and its hash, D4-4 and D4-9), and the departure alarm as a C4 platform health event (`docs/phase4/B4-c10.md`). |
| — | `contracts/version` | identifier parsing and the compatibility rule | A1 | Merged (#26). |
| — | `contracts/node` | node ID and stream token, shared by C1 and C4 (D1-1) | A1 (maintained by A4) | Merged (#29). |

Every status is `desk` evidence: code and tests on a CI runner. No contract has been exercised against a device.

Each package contains:

- `doc.go`: what the contract covers, what it deliberately leaves out, and the requirements, threat-model entries and V-S criteria it serves.
- Go types for the contract, and a `Validate` function for every type that crosses a process or network boundary.
- `schema/*.json` (JSON Schema 2020-12) for every message that crosses a process or network boundary: collector IPC (C2, C7), events (C4), the Syslog payload (C6), audit records (C8), configuration snapshots and differences (C9), and event baselines and departure alarms (C10). In-process interfaces (C5) are Go interfaces only.
- `testdata/`: valid and invalid golden examples, each with a one-line note on what it shows. Device-derived examples carry provenance per [tests/fixtures/README.md](../tests/fixtures/README.md) and are never presented as device captures.
- `*_test.go`: the owner's tests. A6 writes independent contract tests under `tests/contract/`, which may import these packages but not the owner's test helpers.

A contract package imports only the standard library and other contract packages. It contains no I/O, no device logic and no storage.

## Identifiers and compatibility

- Every message and every contract carries an identifier of the form `otsec.<name>/<major>.<minor>`, parsed by `contracts/version`.
- **Within a major version, changes are additive only.** A new minor may add optional fields or, where the contract declares an enum open, new enum values. It never removes a field, renames it, changes its type or changes its meaning.
- **Readers accept every minor of their own major** and ignore fields they do not know. A contract may declare itself **strict**, in which case unknown fields are rejected. C7 collector requests are strict, because anything the main process can ask the collector to do is a path to a device (AP-7, HR-1).
- **Closed enums** (for example the C2 error taxonomy) list every value. A reader that meets a value it does not know treats it as the contract's declared fallback, which is always a failure, never a success.
- **Different majors are incompatible.** A major change needs a migration note and A1's approval after review by every consumer.
- **Phase 1 contracts are 0.x.** Breaking changes are allowed in 0.x with A1's approval and review by every affected owner. 1.0 is cut when the first slice passes Phase 3.

## Common conventions

- JSON in UTF-8 on every boundary. Bytes that must survive exactly (native device output, transcripts) are base64 in JSON and never re-encoded as text.
- Platform times are RFC 3339 in UTC with a `Z` suffix and the precision the clock actually has. Device-native times are kept verbatim, as C4 defines.
- Identifiers that appear in more than one contract (asset ID, node ID, event ID, operation ID, credential reference) are defined once, in the contract that owns the concept, and imported by the others.
- Errors are values from a closed list, not free text. Free text may accompany a code but never replaces it.

## Review and approval

1. The owner drafts the contract on its own branch, in its package only, and opens a PR against `main`.
2. Each listed reviewer records an outcome in `docs/phase1/reviews/<contract>-<reviewer>.md`: accepted, accepted with changes (each change numbered), or rejected with the reason. Security or safety objections cannot be outvoted (CLAUDE.md 5.7).
3. A1 merges when every reviewer has accepted, the owner's tests and A6's contract tests pass, and no other contract defines the same concept differently.
   - **Where tests run (D2-13, which replaced D1-26):** GitHub Actions is the main test path. A PR merges when every job in `.github/workflows/ci.yml` and `.github/workflows/govulncheck.yml` is green on its head (D4-3). A PR that changes only Markdown skips CI (D3-13).
   - The owner's PC is the second Windows run, and the fallback when Actions is unavailable or a run needs a real installation. A PC result names the commit and is posted on the PR.
