# Contracts

Owner: A1. Changes require a documented proposal and review by every affected module owner (CLAUDE.md sections 5.3 and 5.4).

Phase 1 approves the contracts C1 to C8 listed in [docs/architecture.md](../docs/architecture.md#contracts-required-for-phase-1). They are limited to what the first vertical slice needs. The briefs are P1-A1 to P1-A6 in [docs/agent-handoffs.md](../docs/agent-handoffs.md).

## Layout

One Go package per contract, in the root module `otsec.local/otsec`:

| ID | Package | Identifier | Owner | Status (2026-10-24) |
| --- | --- | --- | --- | --- |
| C1 | `contracts/asset` | `otsec.asset/0.1` | A2 | Merged (#32). D1-24 `Endpoint.target` pending (A2). |
| C2 | `contracts/adapter` | `otsec.adapter/0.4` | A2 | Merged (#51). 0.2: `failed.unexpected_password_prompt` and the probe QUI exemption (D2-14). 0.3: `failed.identity_unreadable`, which suspends nothing (A6 on #118, D2-17). 0.4: the unanswered language probe, reported as `failed.timeout` or `failed.transport_closed` (A6, V-S12). |
| C3 | `contracts/register` | `otsec.register/0.1` | A1 (format), A2 (content) | Merged (#27, #32); SEL-751 content rev 3. |
| C4 | `contracts/event` | `otsec.event/0.1` | A4 | Merged (#29, #42, #59: `evidence_class`, D1-23). |
| C5 | `contracts/store` | `otsec.store/0.2` | A5 | Merged (#33). 0.2: `open-busy`, the one open failure `Resume` retries without a restart (P3-A5). |
| C6 | `contracts/syslog` | `otsec.syslog/0.2` | A4 | Merged (#42, #59: `evc`; #81: D2-9 peer check by name and durable-write acknowledgement). |
| C7 | `contracts/authz` | `otsec.authz/0.4` | A3 | 0.1 merged (#38). 0.2 adds `asset.clear_suspension` and `suspension_mismatch` (D2-15, A1). 0.3 adds `asset_suspended` and the held suspension it names, which the node adopts (A6 on #120). 0.4 adds admin-signed requests (`admin_signed`, `VerifyAdminRequest`) and the `admin_unverified` refusal (D2-11, P3-A3). |
| C8 | `contracts/audit` | `otsec.audit/0.2` | A3 | 0.1 merged (#38); 0.2 adds the node-state actions (D2-15). |
| — | `contracts/version` | identifier parsing and the compatibility rule | A1 | Merged (#26). |
| — | `contracts/node` | node ID and stream token, shared by C1 and C4 (D1-1) | A1 (maintained by A4) | Merged (#29). |

Every status is `desk` evidence: code and tests on a CI runner. No contract has been exercised against a device.

Each package contains:

- `doc.go`: what the contract covers, what it deliberately leaves out, and the requirements, threat-model entries and V-S criteria it serves.
- Go types for the contract, and a `Validate` function for every type that crosses a process or network boundary.
- `schema/*.json` (JSON Schema 2020-12) for every message that crosses a process or network boundary: collector IPC (C2, C7), events (C4), the Syslog payload (C6) and audit records (C8). In-process interfaces (C5) are Go interfaces only.
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
   - **Where tests run (owner rule, 2026-10-24; D1-26):** the project owner's local PC first, through Remote Control, using the same steps as `.github/workflows/ci.yml`. GitHub Actions is used only when the PC is offline or a step cannot run there.
   - The owner's PC runs Windows. The Linux leg comes from a Linux container run of the same steps, or from Actions when that is available.
   - Each result is posted on the PR with where it ran (owner PC, container, or Actions) and the commit it tested.
