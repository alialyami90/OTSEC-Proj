# C5 `otsec.store/0.1`: store, outbox and delivery semantics

Owner: A5. Reviewers: A4, A6, A3. Brief: P1-A5 in [../agent-handoffs.md](../agent-handoffs.md). Code: [contracts/store](../../contracts/store/). Status: draft for review, 2026-10-24.

C5 fixes how a site node keeps, acknowledges, recovers and prunes events. It is an in-process contract, so it consists of Go interfaces plus two pieces of contract-owned logic: the group-commit coordinator `Log` and the startup sequence `RunStartup`. Those two are in the contract because they are what make an early acknowledgement or an out-of-order startup impossible. Phase 2 writes the SQLite implementation behind the interfaces. The implementation does not reorder the steps.

Evidence classes: every number below is `simulated` (Linux container, Windows Server 2025 VM) unless marked otherwise. *(proposed)* marks a value A5 chose that no measurement fixes yet.

## 1. Store shape: one writer per database

- `Layout` lists the node's databases. Each has exactly one writer module, the streams it holds, the stream classes it holds, and one quota per class. `Layout.Validate` rejects a stream in two databases, a database with no writer, a class with no quota, and audit mixed with any other class.
- Other modules never open another module's database file. They read through the `Outbox` and `CursorStore` the owning module hands out. On Windows the files' ACL names only the node's service SID (ADR-0007 item 4, A3 AP-1).
- Audit has its own database. A full audit store then fails privileged operations closed without stopping evidence collection, and an evidence flood cannot block audit (ADR-0004 item 9).

## 2. Commit before acknowledgement, with group commit

| Rule | How the contract enforces it | Evidence |
| --- | --- | --- |
| An acknowledgement to a source (a RELP ack, a "stored" status, a device-cursor advance outside the store) is released only after the record's commit has returned at `synchronous=FULL`. | `Receipt` is sealed (it has an unexported method). Only `Log` creates one, and only after `Committer.CommitBatch` has returned. Code outside the package cannot implement `Receipt`, and a struct that embeds a nil `Receipt` panics on use (`TestForgedReceiptIsUnusable`). `TestNoReceiptBeforeCommitReturns` holds a commit open and checks that no receipt appears until it returns. | A6 E-02 and H-14 part 1: at `NORMAL`, 280 of 300 acknowledgements had no flush before them; at `FULL`, none. |
| A commit reported below `FULL` releases nothing. | `Commit.Sync` must be `SyncFull`. Otherwise the waiting callers get `commit-not-durable` and the Log stops. | ADR-0004 item 7 |
| Group commit is required. | `GroupOptions` rejects `MaxEvents` below 2. Records of one stream wait at most `MaxWait` for each other. *(proposed)* default: 100 events or 100 ms. | W-1: 92 events/s with one event per commit, 676/s with 100 per commit. E-A5-6: 10.6 KB written per event against 1.05 KB. |
| Producers that already hold a batch, such as one SER read, commit the whole batch, its capture and its device cursor in one transaction. | `Log.AppendBatch`. It first flushes any group of the stream that is already waiting, so seqs follow arrival order. | ADR-0004 item 2 |
| Seqs start at 1, rise by exactly 1 per stream, and follow append order. | The Log checks that each `Commit` starts at the stream's previous last seq plus 1. Groups of one stream commit strictly one after another, in the order they were opened. | C4 `EventID` |
| After a failed commit, nothing more is accepted until a restart. | `commit-failed`, `commit-not-durable` and `commit-mismatch` all stop the Log. Every later `Append` returns `log-stopped`. | After a failed flush the state of the file is unknown. Retrying could acknowledge data the disk lost (the PostgreSQL fsync lesson), so the restart path runs startup recovery instead. |
| A cancelled `Append` returns no receipt. | The record may still commit, but the source is not acknowledged, so it re-sends (at-least-once). Content-level duplicates are handled by C4 alignment. | ADR-0004 item 3 |

Native evidence: a `Record` may point at a `Capture` (a whole SER report, a datagram, a pushed file). The store keeps each capture once, keyed by its SHA-256, and C4 carries the reference as `native.evidence.ref = "sha256:<hex>"`. The prune step that deletes the last record referring to a capture also deletes the capture, in the same transaction, so raw evidence and the normalized form go together (EP-6).

## 3. Outbox, cursors and pruning

- **At-least-once.** `Outbox.Read` returns committed events in seq order, never one whose commit has not returned. Receivers de-duplicate by C4's event ID.
- **Consumers** are declared `required` or `best-effort` (ADR-0004 item 6). A required consumer holds back pruning until it has confirmed delivery. A best-effort consumer, such as plain RFC 5425, has a replay window. Events older than the window are prunable as far as it is concerned. `Consumer.Validate` rejects a required consumer that has a window, and a best-effort consumer that has none.
- **Cursors** are saved at `FULL` in the stream's own database. `SaveCursor` refuses to move a cursor backwards (`cursor-regress`) or past the last committed seq (`cursor-ahead`).
- **The prune boundary comes only from persisted cursors (R-A5-5).** `Boundary` is sealed, and the only way to get one is `ComputeBoundary`. It reads `LoadCursors` from the database at the time of the call and takes the lowest of:
  - each required consumer's persisted cursor (0 if it has none);
  - for each best-effort consumer, the higher of its cursor and the last seq committed before its replay window.

  `Pruner.PruneStep` accepts nothing but a `Boundary`, so a prune can never take an in-memory position, a step counter, or "the oldest half". `TestBoundaryIgnoresUnpersistedCursor` shows that a confirmed but unsaved cursor moves nothing. `TestInterruptedPruneNeverPassesCursor` kills a recovery part-way and restarts it, and it still prunes exactly up to the cursor.
- **A stream with no consumer is never pruned** (`no-consumers`). The site is the system of record (Q6), and V-S9 allows no un-forwarded native record to be evicted. A node with no upstream configured fills its quota and then applies the storage-full policy.
- **Pruning happens in small transactions** (*(proposed)* 50 events), because one large delete can need more WAL than a full disk has (E-A5-3).

## 4. Startup recovery order

`RunStartup(ctx, env, policy)` runs the steps below. Each one is a separate `StartupEnv` or `RecoveryStore` call, so a test can make any one of them fail. Steps 1 to 4 never open the database, its WAL or its `-shm`.

| # | Step | On failure |
| --- | --- | --- |
| 1 | `Lock`: exclusive use of the store's files for the life of the node. The lock fails if another process holds it. | `failed`. The store is not opened. Alarm `store-lock-failed`. |
| 2 | Inspect without opening: does the store exist, and which reserves exist. | `failed`. Alarm `store-open-blocked`. |
| 3 | Release the recovery reserve. `ReleaseReserve` returns success only once the file is gone. **A failed release stops startup.** | `failed`. Alarm `reserve-release-failed`. The store is not opened. |
| 3' | If the store exists and the recovery reserve does not, release the last-resort reserve instead (section 5). | As step 3. |
| 4 | Check the free space against `OpenHeadroomBytes`. | `blocked`. The store is not opened. Alarm `store-open-blocked`. The lock is kept. |
| 5 | `Open`, then `CheckSettings` (WAL, `FULL`, bounded WAL, created with `auto_vacuum=INCREMENTAL`; a store without it is refused, never altered), then `QuickCheck`. | `failed`, and the store is closed. Alarms `store-open-failed`, `store-settings-invalid` and `store-integrity-failed`. Nothing is pruned or repaired automatically, so evidence is preserved. |
| 6 | While usage is above `PruneTarget` *(proposed 0.8)*, run one prune step per stream per pass. The boundary is recomputed before every step. | `drain-only`. Alarm `store-prune-failed`. |
| 7 | `CompactStep` *(proposed 32 pages)* returns free pages to the filesystem with a checkpoint between steps. | `drain-only`. Alarm `store-compact-failed`. |
| 8 | Re-create any released or missing reserve, the last-resort reserve first. `CreateReserve` is all or nothing. | `drain-only`. Alarm `reserve-recreate-failed`. |

The node collects (`collecting`) only if every step passed and both reserves are back in place. In `drain-only`, the store is open and forwarding runs, so cursors can advance, but collectors do not start. The node retries steps 6 to 8 while draining and may start collectors once both reserves exist. Alarm `store-drain-only`.

**Nothing else opens the store before recovery completes, or after.** The lock from step 1 is held for the life of the node. Support tools and the UI read through the node, never the files. Phase 2 has to choose the OS mechanism for this. *(proposed)* There are two layers:

- **ACL.** The files' ACL admits only the node's service SID, so no other account can open them at all.
- **Lock file.** The node opens a lock file in the store directory with share mode 0 and keeps it for its lifetime. A second instance under the same SID, such as a support command run as the service, fails at step 1.

The database files themselves cannot be held with share mode 0, because SQLite in the same process has to open them. A6 should test both layers.

**Why this order.** On NTFS, a fresh open of a full store can rebuild the `-shm`. If the space freed by truncating it is not enough to grow it again, every later open fails, read-only opens included (F-013). W-1, which releases the reserve before its first open, recovered on every round (F-011, A1's reconciliation in `docs/phase-0-exit.md`). That is why steps 3 and 4 come before step 5.

## 5. No reserve left to release (F-013's condition): proposal

ADR-0004 item 8 says a node whose reserve cannot be re-created alarms and does not collect. The next startup then has no reserve to release, which is the case F-013 shows can wedge a store. The proposal has three parts.

1. **Two reserve files.**
   - The *recovery reserve*, at least twice the WAL bound, is released at every startup.
   - The *last-resort reserve* is released only when the recovery reserve is missing on an existing store. It is at least `OpenHeadroomBytes`.

   Step 8 re-creates the last-resort reserve first. So after a failed recovery, the next startup still has something to release, and enough space to open the store and drain it.
2. **Never open below the headroom.** If both reserves are gone and free space is below `OpenHeadroomBytes`, startup stops in `blocked` without opening the store. The node keeps the lock, raises `store-open-blocked` with the free and needed byte counts, and retries startup when free space changes.
   - The recovery from `blocked` is space freed outside the store, by an operator or by another file being removed. It is never an open attempt.
   - *(proposed)* `OpenHeadroomBytes` is the WAL bound plus 64 KiB, and the contract floor is 64 KiB. F-013 failed with 28,672 bytes free against a 32 KiB `-shm` region, and two regions leave margin. Whether this headroom actually prevents F-013 is untested. It is an H-14 part 2 item for A6.
3. **Drain before collecting.** A startup that needed the last-resort reserve, or could not re-create a reserve, opens the store only for forwarding. Draining advances the required cursors, which is the only thing that makes confirmed events prunable. Pruning and compaction then free space, and the reserves come back.

Alternatives considered:

- *Open read-only first* fails on NTFS in F-013.
- *Delete the `-shm` before opening* is unsafe while any other connection could exist, and depends on SQLite internals.
- *One larger reserve* only moves the problem one exhaustion later, because a failed re-creation still leaves nothing for the next startup.
- *Refuse to start* would stop forwarding too, which loses the only way to drain.

Sizing rule for deployment: the sum of the class quotas, plus both reserves, plus the open headroom, must fit on the store's volume, with margin for the WAL bound. A store within its quotas then always has room to re-create its reserves. A re-creation failure means something outside the store has used the volume, and the node says so.

## 6. Storage-full behaviour and alarms

`ActionFor(class)` is fixed by the contract, not configurable, because no class may evict unconfirmed records to make room (ADR-0004 item 9, A3's additions).

| Class | At quota |
| --- | --- |
| `adapter-evidence` | `stop-collecting`. Raises `collection-stopped` with the stop time and the device-buffer overwrite estimate. |
| `syslog-stream` (TCP, TLS, RELP) | `refuse-new`. Nothing is acknowledged without a `Receipt`. |
| `syslog-datagram` (UDP) | `drop-and-count`. The count is persisted and forwarded (`syslog-dropped`; C4 `intake.drop-counted`). |
| `audit` | `fail-closed`. Privileged operations are refused (`audit-store-full`). |
| `platform` | `refuse-new`. The alarm stays in node status. |

Alarm codes form a closed list in `class.go`:

- quota warning and reached;
- collection stopped and Syslog dropped;
- audit full;
- required consumer stalled;
- commit failed;
- one alarm per startup step.

They become C4 platform events on the node's `platform/health` stream. The mapping to C4 `Health.Type` values is agreed with A4 (`TODO(C4)`; see the C4 review).

## 7. What A6 can make fail

Every `StartupEnv` and `RecoveryStore` method is a failure point:

- `Lock`, `StoreExists`, `ReserveExists` (each reserve), `ReleaseReserve` (each reserve) and `FreeBytes`;
- `Open`, `CheckSettings`, `QuickCheck`, `Usage`, `LoadCursors`, `LastCommitted`, `LastCommittedBy`, `PruneStep`, `CompactStep` and `CreateReserve` (each reserve).

The Log's failure points are:

- a `CommitBatch` error;
- a commit below `FULL`;
- a wrong stream, count or node;
- a seq gap.

The owner's tests (`contracts/store/*_test.go`) cover each one against an in-memory fake. The table-driven tests also check that a failure before step 5 never calls `Open`, and that the reserve is never re-created before the store has been opened. A6's independent tests may import the package but not `fake_test.go`.

## 8. Not covered, and dependencies

- **C4 (`TODO(C4)`).** `NodeID`, `StreamID`, `Seq` and `Key` mirror C4's draft (PR #29) and become aliases once it merges. Two C4 changes are requested in [reviews/C4-A5.md](reviews/C4-A5.md):
  - a pre-commit event form, because the seq exists only after commit;
  - the format of `evidence.ref`.
- **Phase 2:**
  - the SQLite implementation and the OS lock mechanism;
  - measuring `OpenHeadroomBytes` against F-013 on NTFS;
  - measuring the group-commit window on the real drive. A fast flush is not proof of durability (A6's note on C-24), so the window may be tuned from flush latency for throughput, but never treated as a health signal.
- **Power loss** is H-11, per hardware model (C-24). See [A5-node-posture.md](A5-node-posture.md).
- Site-to-central delivery reuses `Consumer`, `Cursor` and `Boundary` (central is a required consumer), but the protocol itself is not in C5.
