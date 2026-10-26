# Quarantine export and clear: design (P3-A5)

Status: agreed (2026-10-26). A3 agreed to the authorization model with conditions A3-1 to A3-5, then to the hand-off and the resume rule with further conditions, all marked below. A1 approved C5's `Discard` in its bounded form (D3-1, #151) and the resume conditions (a) to (c). A3 adds the two C8 actions. The node and CLI code follows in its own PR.

## Problem

`quarantine/<asset>` streams have no consumer, so pruning never removes them (#135). An asset whose outcomes are quarantined run after run fills `adapter-evidence` until runs stop with `collection-no-quarantine-room`. An asset halted for an unauthorized line stays halted for good. Today the operator's only remedy is to reinstall.

## Flow

### 1. Export: the CLI reads

An administrator runs `otsec quarantine export -config <file> <asset> <dir>`.

- The CLI opens the evidence database read-only (`store.OpenReadOnly`, `busy_timeout` first, as in #138). It never takes the node's lock and never writes the store.
- `<dir>` must not exist. The CLI creates it with the store directory's rule, which on Windows is the protected DACL with Administrators and SYSTEM only (`store.CreateDir`). It refuses a directory that already exists, whatever its ACL (A3-5). An export can hold an unredacted password, since a failed redaction is one reason an outcome is quarantined.
- For each record of `quarantine/<asset>`, the CLI writes the stored event (`<seq>.event.json`) and its capture (`<seq>.capture`) byte for byte, as committed.
- It then writes `manifest.json`. The manifest lists hashes, never content (A3-5): `schema`, `node_id`, `asset_id`, `stream`, `exported_at`, and `items` with `seq`, `event_sha256` and `capture_sha256` for each record. A quarantine is two records, the frame and its reason, and both are listed. The items are every seq the stream stores, in order, so the range `first..last` holds no stored seq that is not listed.
- Last, the CLI copies `manifest.json` into the admin folder as `quarantine-export-<asset>.json`. The CLI runs as an administrator, so it can write there, and the node reads that folder under D2-12's protected-file rule.

### 2. Record: the node verifies and audits

Before each run, the node reads the manifest copies from `admin_dir` under the protected-file rule, with A3's limits:

- It reads at most a bounded number of `quarantine-export-*.json` files, each one size-capped and strictly decoded (unknown fields and trailing data are refused).
- The asset in the file name must equal the manifest's `asset_id`, and `node_id` must be this node's.
- The manifest hash is SHA-256 over the file's bytes as read.
- The items have unique seqs in ascending order, and there is at least one.

It then checks the manifest against its own stream, both ways (A3):

- Every listed seq is stored in `quarantine/<asset>`, and its stored event hash and capture hash equal the manifest's.
- Every seq the stream stores in `first..last` is listed.

So the set the record names is exactly the set stored in that range at record time. A gap in the list is allowed only where the stream stores nothing, which can only be the range of an earlier completed clear, since `Discard` is the only other remover.

If the manifest passes and the chain holds no `quarantine.exported` record with this manifest's hash, the node writes one (C8, new). The record carries:

- the manifest's SHA-256;
- the asset and stream;
- `first`, `last` and the count;
- the wording "manifest verified against the stream" (A3). It never claims the evidence was preserved off the node, which the node cannot see.

If the manifest fails, the node writes nothing and raises `quarantine-export-refused` once. `otsec health` shows `EXPORTED, NOT CLEARED` for each recorded export whose clear has not been applied.

### 3. Clear: an administrator's file

The administrator writes `clear-quarantine.json` in `admin_dir`, modelled on `clear-suspension.json`, with `asset_id`, `manifest_sha256` and `principal`. It moves to a signed file together with the node's checks of `clear-suspension.json` and the reset acknowledgement under C7 0.4 (A3). The node applies it under the protected-file rule, in this order:

1. **A3-1.** The chain must hold a `quarantine.exported` record with that manifest hash for that asset. The node takes the stream, range and seq list from the record and the manifest copy it verified, and never trusts a manifest file on its own.
2. **A3-4.** If the chain already holds a succeeded `quarantine.cleared` for that hash, the file changes nothing. The node records it as stale: `quarantine.cleared` with outcome `info`, reason `already_cleared`. A stale file never removes anything new.
3. **A3-2, all or nothing.** The node re-reads every listed item from the stream. If any listed seq is gone, or its event or capture hash differs, nothing is removed and the clear is refused. Only the listed seqs are ever removed, never the whole stream and never a record added after the export.
4. **A3-3.** The node writes `quarantine.cleared` (outcome `succeeded`) with the clear file's SHA-256, the manifest hash, the stream, the range `first..last`, the count, and the named principal as `requested_by`. It gets that record's C5 receipt before removing anything (audit before act, D1-11). With no receipt, nothing is removed.
5. **Removal in bounded steps.** The node removes the listed seqs through C5's `Discard`, at most `DiscardStepEvents` (16) per call and one step per tick (A1 (c)). The steps run before any run of that asset. Until the range is empty, `quarantine-clear-incomplete` is raised and `otsec health` shows it.
6. **The halt.** If the asset was halted for an unauthorized line, the halt ends only after the whole range is gone and `durableHalt` finds no unauthorized-line quarantine left. It never ends mid-removal (A3).

### 4. Resume from the record (A1 (a) to (c), A3)

A clear stopped partway, by a kill, a restart or a failed step, is finished from the node's own verified chain, never from a file:

- **(a) The chain drives it.** At start, and at each tick, the node finds every succeeded `quarantine.cleared` record whose range still has stored seqs, and resumes it before any run of that asset. It never re-reads `clear-quarantine.json` or the manifest copy to decide what to remove.
- **(b) Only the range.** The resume removes only seqs inside the record's stream and `first..last`, never beyond `last`. Because the export check proved that every stored seq in that range was listed, removing what is stored there removes only listed seqs. A seq added to the stream later has a seq above `last`, since seqs only grow.
- **(c) Bounded and visible.** One `Discard` step per tick. `quarantine-clear-incomplete` stays raised until the range is empty.

A missing seq counts as progress only once the succeeded `quarantine.cleared` record exists. Before it, A3-2 holds whole: a listed seq that is gone refuses the clear (A3).

A file applied again after the clear finished is stale under A3-4 and changes nothing.

## Contract additions

- **C5 0.3, `Discarder.Discard(ctx, consumers, stream, seqs)` (#151, A1 D3-1).**
  - Removes named seqs of a stream under `quarantine/`, with their captures when no retained record of any stream still refers to them, in one transaction at `FULL`. It updates the class bytes.
  - At most 16 seqs per call. 50 seqs spread across a long stream wrote 997 KB of WAL, nearly the 1 MiB recovery reserve. 16 wrote 387 KB, inside `WALBoundBytes` (simulated).
  - A seq no longer stored is skipped, so a resume can call it with seqs a killed step already removed.
  - Refuses a stream outside the prefix, a stream a consumer reads or that has a persisted cursor, an empty list, a repeated seq and seq 0.
  - The contract text says it is called only after an audited administrator clear and never automatically. #135's pruning is unchanged.
- **C8 0.3 (A3's contract, #155): two actions.** Both have actor type `node` and a `quarantine` object holding `manifest_sha256`, `first_seq`, `last_seq` and `items`.
  - `quarantine.exported`: outcome `info`.
  - `quarantine.cleared`: outcome `succeeded`, or `info` with reason `already_cleared` for a stale file. It also carries `clear_sha256` and `requested_by`, the principal the file names. The actor is the node, not the administrator: as with `asset.suspension_clear`, an unsigned file cannot prove who wrote it (A3; A1 to rule).

  Both are written only by the node.

## Tests (A6 independent; mine in the PR)

- **No matching export record, no removal.** A clear file whose manifest hash has no `quarantine.exported` record removes nothing, even with a matching manifest file in the admin folder.
- **A tampered manifest is refused.** One changed item hash, a missing seq, an unlisted stored seq inside the range, another asset or node, a file-name mismatch, an oversized file or unknown fields means no `quarantine.exported` is recorded, and a clear naming it removes nothing.
- **A changed stored record means no removal.** If a stored event or capture hash differs from the manifest at clear time, nothing is removed.
- **A stale file changes nothing.** A second application of the same file is recorded as stale. Records added after the export survive.
- **Audit before removal.** With the audit Log stopped, the clear removes nothing.
- **Kill between the record and the first step** (A3). At the next start the remainder goes before any run of the asset, and nothing outside the range is touched.
- **Kill between steps** (A3, A6). The same, with `quarantine-clear-incomplete` shown until the range is empty and a re-applied file recorded as stale.
- **A large clear.** More than 16 seqs takes several ticks, one step each.
- **Export directory.** An existing directory is refused, and the new directory has the protected DACL on Windows (`OTSEC_REQUIRE_ELEVATED`).
- **Export beside a running node.** The export runs while the node commits, without either side failing (#138's `busy_timeout`, `TestOpenBesideReaderAfterKill` pattern).
- **The halt ends only when the whole range is gone** and no unauthorized-line quarantine remains.
- **Mutants:** each check of the clear (A3-1 to A3-4), the both-ways list check, and the range bound on resume, when removed, fails a test.

## Exclusions

- No automatic deletion.
- No clear through the node's IPC.
- No change to the pruning of confirmed events.
- The node writes nothing outside its store and status. The export directory is written by the administrator's CLI only.
