# Quarantine export and clear: design (P3-A5)

Status: proposal for agreement. A3 must agree to the authorization and A1 to the two contract additions before the PR opens. A3 agreed to the authorization model on 2026-10-26 with five conditions, numbered A3-1 to A3-5 below.

## Problem

`quarantine/<asset>` streams have no consumer, so pruning never removes them (#135). An asset whose outcomes are quarantined run after run fills `adapter-evidence` until runs stop with `collection-no-quarantine-room`. An asset halted for an unauthorized line stays halted for good. Today the operator's only remedy is to reinstall.

## Flow

1. **Export: the CLI reads.** An administrator runs `otsec quarantine export -config <file> <asset> <dir>`.
   - The CLI opens the evidence database read-only (`store.OpenReadOnly`, `busy_timeout` first, as in #138). It never takes the node's lock and never writes the store.
   - `<dir>` must not exist. The CLI creates it with the store directory's rule, which on Windows is the protected DACL with Administrators and SYSTEM only (`store.CreateDir`). It refuses a directory that already exists, whatever its ACL (A3-5). An export can hold an unredacted password, since a failed redaction is one reason an outcome is quarantined.
   - For each record of `quarantine/<asset>`, the CLI writes the stored event (`<seq>.event.json`) and its capture (`<seq>.capture`) byte for byte, as committed.
   - It then writes `manifest.json`. The manifest lists hashes, never content (A3-5): `schema`, `node_id`, `asset_id`, `stream`, `exported_at`, and `items` with `seq`, `event_sha256` and `capture_sha256` for each record. A quarantine is two records, the frame and its reason, and both are listed.
   - Last, the CLI copies `manifest.json` into the admin folder as `quarantine-export-<asset>.json`. The CLI runs as an administrator, so it can write there, and the node reads that folder under D2-12's protected-file rule.
2. **Record: the node verifies and audits.** Before each run, the node reads `quarantine-export-*.json` from `admin_dir` under the protected-file rule and checks each manifest against its own stream:
   - every listed seq exists in `quarantine/<asset>`, and its stored event hash and capture hash equal the manifest's;
   - the node ID and asset match.

   If the manifest passes and the chain holds no `quarantine.exported` record with this manifest's hash, the node writes one (C8, new). Its detail holds the manifest's SHA-256, the asset, the seq range and the count. If the manifest fails, the node writes nothing and raises `quarantine-export-refused` once. `otsec health` shows `EXPORTED, NOT CLEARED` for each recorded export whose clear has not been applied.
3. **Clear: an administrator's file.** The administrator writes `clear-quarantine.json` in `admin_dir`, modelled on `clear-suspension.json`, with `asset_id`, `manifest_sha256` and `principal`. It moves to a signed file together with the node's checks of `clear-suspension.json` and the reset acknowledgement under C7 0.4 (A3). The node applies it under the protected-file rule, in this order:
   1. **A3-1.** The chain must hold a `quarantine.exported` record with that manifest hash for that asset. A manifest file is never trusted on its own.
   2. **A3-4.** If the chain already holds `quarantine.cleared` for that hash, the file changes nothing. The node records it as stale: `quarantine.cleared` with outcome `info`, reason `already_cleared`. A stale file never removes anything new.
   3. **A3-2.** The node re-reads every item from the stream. If any listed seq is gone, or its event or capture hash differs, nothing is removed. Only the listed seqs are ever removed, never the whole stream and never a record added after the export.
   4. **A3-3.** The node writes `quarantine.cleared` (outcome `succeeded`) with the clear file's SHA-256, the manifest hash and the named principal, and gets its C5 receipt before removing anything (audit before act, D1-11). With no receipt, nothing is removed.
   5. The node removes exactly those events through C5's new `Discard`, in one transaction.
   6. If the asset was halted for an unauthorized line, the node reads its quarantine stream again (`durableHalt`). The halt ends only if no unauthorized-line quarantine is left, which is the clear for a halted asset the brief asks for. A removal that fails after the record raises `quarantine-clear-failed`. The record then shows an intent whose effect did not happen, and the next run retries it.

## Contract additions (A1 approval)

- **C5 0.3, `Discarder.Discard(ctx, stream, seqs)`.**
  - Removes the named events of a stream that has no consumer, and any capture no remaining event refers to, in one transaction. It updates the class bytes.
  - Refuses a stream that has a consumer, a seq that is not stored, and an empty list.
  - The contract text says it is called only after an audited administrator clear and never automatically. It never prunes confirmed events, and #135's pruning is unchanged.
- **C8 (A3's contract): two actions.**
  - `quarantine.exported`: actor type `node`, detail as above.
  - `quarantine.cleared`: actor type `admin` carrying the file's `principal`, with outcomes `succeeded`, or `info` for a stale file.

  Both are written only by the node.

## Tests (A6 independent; mine in the PR)

- **No matching export record, no removal.** A clear file whose manifest hash has no `quarantine.exported` record removes nothing, even with a matching manifest file in the admin folder.
- **A tampered manifest is refused.** One changed item hash, a missing seq or another asset means no `quarantine.exported` is recorded, and a clear naming it removes nothing.
- **A changed stored record means no removal.** If a stored event or capture hash differs from the manifest at clear time, nothing is removed.
- **A stale file changes nothing.** A second application of the same file is recorded as stale. Records added after the export survive.
- **Audit before removal.** With the audit Log stopped, the clear removes nothing.
- **Export directory.** An existing directory is refused, and the new directory has the protected DACL on Windows (`OTSEC_REQUIRE_ELEVATED`).
- **Export beside a running node.** The export runs while the node commits, without either side failing (#138's `busy_timeout`, `TestOpenBesideReaderAfterKill` pattern).
- **The halt ends only when no unauthorized-line quarantine remains.**
- **Mutants:** each check of the clear (A3-1 to A3-4) removed fails a test.

## Exclusions

- No automatic deletion.
- No clear through the node's IPC.
- No change to the pruning of confirmed events.
- The node writes nothing outside its store and status. The export directory is written by the administrator's CLI only.
