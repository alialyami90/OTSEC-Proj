# C5 `otsec.store/0.1`: store, outbox and delivery semantics

Owner: A5. Reviewers: A4, A6, A3. Brief: P1-A5 in [../agent-handoffs.md](../agent-handoffs.md). Code: [contracts/store](../../contracts/store/). Status: draft for review, 2026-10-24; revised for A4's review ([reviews/C5-A4.md](reviews/C5-A4.md)), A3's review (`reviews/C5-A3.md`, PR #37) and A1's decisions D1-3 to D1-5 and D1-11.

C5 fixes how a site node keeps, acknowledges, recovers and prunes events. It is an in-process contract, so it consists of Go interfaces plus two pieces of contract-owned logic: the group-commit coordinator `Log` and the startup sequence `RunStartup`. Those two are in the contract because they are what make an early acknowledgement or an out-of-order startup impossible. Phase 2 writes the SQLite implementation behind the interfaces. The implementation does not reorder the steps.

Evidence classes: every number below is `simulated` (Linux container, Windows Server 2025 VM) unless marked otherwise. *(proposed)* marks a value A5 chose that no measurement fixes yet.

## 1. Store shape: one writer per database

- `Layout` lists the node's databases. Each has exactly one writer module, the streams it holds, the stream classes it holds, and one quota per class. `Layout.Validate` rejects a stream in two databases, a database with no writer, a class with no quota, and audit mixed with any other class.
- Other modules never open another module's database file. They read through the `Outbox` and `CursorStore` the owning module hands out. On Windows the files' ACL names only the node's service SID (ADR-0007 item 4, A3 AP-1).
- Audit has its own database, with **exactly one audit stream per node**, because the C8 hash chain is one per node (`Layout.Validate`, C5-A3-1). An evidence flood cannot fill the audit quota (ADR-0004 item 9). A full audit store fails privileged operations closed and also stops collection that uses a device credential (section 6, D1-11). Passive intake, such as received Syslog, continues.

### 1a. Audit records (C5-A3-1, C5-A3-2)

- **Sealed in the commit.** An audit `Record.Event` is a pending C8 record. Each record carries its seq and the SHA-256 of the exact stored bytes of its predecessor, and neither value exists before commit. So the Committer calls `SealAudit(chain, head, recs)` inside the `CommitBatch` transaction. `SealAudit` validates every pending record before it seals any, then calls C8's `Seal(pending, seq, prevHash)` in order. The Committer stores the sealed bytes exactly and stores the new chain head in the same transaction. The head starts at `ChainLink{0, Genesis}` on a new node.
- **Never re-encoded.** `Outbox.Read` and every forwarder return the sealed bytes unchanged (`TestAuditSealedInCommit`).
- **A bad pending record** refuses its whole batch with `invalid`, and nothing is written (`TestAuditBadPendingRefusesBatch`).
- **Pruning keeps a chain anchor.** The prune step that deletes audit records also writes the `ChainLink` of the last record it deleted, in the same transaction. `Outbox.ChainAnchor` exposes it read-only, so the retained chain always verifies from it, even after a prune that was interrupted and resumed (`TestAuditPruneKeepsAnchor`).
- **Only required consumers make audit prunable.** A best-effort replay window would delete audit records with no confirmed delivery (AP-17), so `ComputeBoundary` ignores best-effort consumers for class audit. A node whose audit stream has no required consumer keeps audit until its quota is reached, and then fails closed (`TestAuditBoundaryIgnoresBestEffort`).
- `AuditChain` and `ChainLink` mirror C8 (`TODO(C8)`). They become adapters over `audit.ValidatePending`, `audit.Seal`, `audit.GenesisPrevHash` and `audit.Checkpoint` when C8 merges, and the tests then verify with `audit.VerifyChain`.

## 2. Commit before acknowledgement, with group commit

| Rule | How the contract enforces it | Evidence |
| --- | --- | --- |
| An acknowledgement to a source (a RELP ack, a "stored" status, a device-cursor advance outside the store) is released only after the record's commit has returned at `synchronous=FULL`. | `Receipt` is sealed (it has an unexported method). Only `Log` creates one, and only after `Committer.CommitBatch` has returned. Code outside the package cannot implement `Receipt`, and a struct that embeds a nil `Receipt` panics on use (`TestForgedReceiptIsUnusable`). `TestNoReceiptBeforeCommitReturns` holds a commit open and checks that no receipt appears until it returns. | A6 E-02 and H-14 part 1: at `NORMAL`, 280 of 300 acknowledgements had no flush before them; at `FULL`, none. |
| A commit reported below `FULL` releases nothing. | `Commit.Sync` must be `SyncFull`. Otherwise the waiting callers get `commit-not-durable` and the Log stops. | ADR-0004 item 7 |
| Group commit is required. | `GroupOptions` rejects `MaxEvents` below 2. Records of one stream wait at most `MaxWait` for each other. *(proposed)* default: 100 events or 100 ms. | W-1: 92 events/s with one event per commit, 676/s with 100 per commit. E-A5-6: 10.6 KB written per event against 1.05 KB. |
| Producers that already hold a batch, such as one SER read, commit the whole batch, its capture and its device cursor in one transaction. | `Log.AppendBatch`. It first flushes any group of the stream that is already waiting, so seqs follow arrival order. | ADR-0004 item 2 |
| Seqs start at 1, rise by exactly 1 per stream, and follow append order. | The Log checks that each `Commit` starts at the stream's previous last seq plus 1. Groups of one stream commit strictly one after another, in the order they were opened. | C4 `EventID` |
| After a failed commit, nothing more is accepted until a restart. | `commit-failed`, `commit-not-durable` and `commit-mismatch` all stop the Log. Every later `Append` returns `log-stopped`. | After a failed flush the state of the file is unknown. Retrying could acknowledge data the disk lost (the PostgreSQL fsync lesson), so the restart path runs startup recovery instead. |
| A refusal does not stop the Log. | A Committer may refuse a batch it has not written, with `quota-reached` (the class is at quota and its action refuses) or `invalid`. The Log fails that batch's appends with the error and keeps running for every other stream (`TestQuotaRefusalDoesNotStopTheLog`). Any other error leaves the batch's durability unknown, and the Log stops. | A full Syslog quota must not stop evidence collection. |
| A cancelled `Append` returns no receipt. | The record may still commit, but the source is not acknowledged, so it re-sends (at-least-once). Content-level duplicates are handled by C4 alignment. | ADR-0004 item 3 |

Native evidence: a `Record` may point at a `Capture` (a whole SER report, a datagram, a pushed file). The store keeps each capture once, keyed by its SHA-256, and C4 carries the reference as `native.evidence.ref = "sha256:<hex>"`. The prune step that deletes the last record referring to a capture also deletes the capture, in the same transaction, so raw evidence and the normalized form go together (EP-6).

## 3. Outbox, cursors and pruning

- **At-least-once.** `Outbox.Read` returns committed events in seq order, never one whose commit has not returned. Receivers de-duplicate by C4's event ID.
- **Reading across a pruned range.** If `Read(after)` asks for seqs that have been pruned, it returns the first retained events with no error. The forwarder sees the jump in seq and reports the skipped range as C4 `forward.unreachable` (A4 review, change 3). This only happens to a best-effort consumer that was away longer than its window, because nothing a required consumer has not confirmed is ever pruned.
- **Consumers** are declared `required` or `best-effort` (ADR-0004 item 6). A required consumer holds back pruning until it has confirmed delivery. A best-effort consumer, such as plain RFC 5425, has a replay window. Events older than the window are prunable as far as it is concerned. `Consumer.Validate` rejects a required consumer that has a window, and a best-effort consumer that has none.
  - **Only an acknowledgement that cannot be forged makes a consumer required.** For Syslog that is a C6 target with transport `relp-tls`. Plain RELP acknowledgements can be forged by anyone on the path, so a plain RELP target is best-effort (A4 review, change 2).
  - `ConsumerID` is the C6 target name for Syslog, and the central server for site-to-central. `Delivery` uses the same strings as C6's target class, `required` and `best-effort`.
- **Cursors** are saved at `FULL` in the stream's own database. `SaveCursor` refuses to move a cursor backwards (`cursor-regress`) or past the last committed seq (`cursor-ahead`).
- **The prune boundary comes only from persisted cursors (R-A5-5).** `Boundary` is sealed, and the only way to get one is `ComputeBoundary`. It reads `LoadCursors` from the database at the time of the call and takes the lowest of:
  - each required consumer's persisted cursor (0 if it has none);
  - for each best-effort consumer, the last seq committed before now minus its replay window, `LastCommittedBy(now − window)`, **whatever its cursor says**.

  A best-effort cursor records what was sent, not what was delivered. It tells the forwarder where to resume, and it never makes an event prunable. So an open replay window is never pruned, which is A1's D1-5 and R-A5-5 (A4 review, change 1; `TestComputeBoundary`).

  The window is measured on the node's clock against commit time. A forward clock step therefore shortens it, and a backward step lengthens it. C6's replay window is by time only (ADR-0004 item 6), so this is accepted rather than corrected; a clock step is already a C4 timing event (A4 review, note 4).

  `Pruner.PruneStep` accepts nothing but a `Boundary`, so a prune can never take an in-memory position, a step counter, or "the oldest half". `TestBoundaryIgnoresUnpersistedCursor` shows that a confirmed but unsaved cursor moves nothing. `TestInterruptedPruneNeverPassesCursor` kills a recovery part-way and restarts it, and it still prunes exactly up to the cursor.
- **No forced prune.** C5 0.1 has no path that prunes past the boundary, under storage pressure or otherwise. A full store stops intake (section 6) and drains (section 4a). D1-5 requires any future forced prune to be an explicit loss with a gap marker and an audit record; it would need a C5 version change and A1's approval.
- **A stream with no consumer is never pruned** (`no-consumers`). The site is the system of record (Q6), and V-S9 allows no un-forwarded native record to be evicted. A node with no upstream configured fills its quota and then applies the storage-full policy.
- **Pruning happens in small transactions** (*(proposed)* 50 events), because one large delete can need more WAL than a full disk has (E-A5-3).

## 4. Startup recovery order

`RunStartup(ctx, env, policy)` runs the steps below. Each one is a separate `StartupEnv` or `RecoveryStore` call, so a test can make any one of them fail. Steps 1 to 4 never open the database, its WAL or its `-shm`.

| # | Step | On failure |
| --- | --- | --- |
| 1 | `Lock`: exclusive use of the store's files for the life of the node. The lock fails if another process holds it. | `failed`. The store is not opened. Alarm `store-lock-failed`. |
| 2 | Inspect without opening: does the store exist, and which reserves exist. | `failed`. Alarm `store-open-blocked`. |
| 3 | Release the recovery reserve. `ReleaseReserve` returns success only once the file is gone. **A failed release stops startup.** | `failed`. Alarm `reserve-release-failed`. The store is not opened. |
| 3' | If the store exists and the recovery reserve does not, release the last-resort reserve instead (section 5). | As step 3: a failed release of either reserve stops startup (D1-4; `TestReleaseOfLastResortFailingStopsStartup`). |
| 4 | Check the free space against `OpenHeadroomBytes`. | `blocked`. The store is not opened. Alarm `store-open-blocked`. The lock is kept. |
| 5 | `Open`, then `CheckSettings` (WAL, `FULL`, bounded WAL, created with `auto_vacuum=INCREMENTAL`; a store without it is refused, never altered), then `QuickCheck`. | `failed`, and the store is closed. Alarms `store-open-failed`, `store-settings-invalid` and `store-integrity-failed`. Nothing is pruned or repaired automatically, so evidence is preserved. |
| 6 | While usage is above `PruneTarget` *(proposed 0.8)*, run one prune step per stream per pass. The boundary is recomputed before every step. | `drain-only`. Alarm `store-prune-failed`. |
| 7 | `CompactStep` *(proposed 32 pages)* returns free pages to the filesystem with a checkpoint between steps. | `drain-only`. Alarm `store-compact-failed`. |
| 8 | Re-create any released or missing reserve, the last-resort reserve first. `CreateReserve` is all or nothing. | `drain-only`. Alarm `reserve-recreate-failed`. |

The node collects (`collecting`) only if every step passed and both reserves are back in place. Otherwise it ends in one of the states of section 4a.

## 4a. Blocked and drain-only (A1 D1-4)

| | `blocked` | `drain-only` |
| --- | --- | --- |
| Entered when | Step 4 finds free space below `OpenHeadroomBytes`. | The store opened, but step 6, 7 or 8 failed, or startup needed the last-resort reserve and could not put both reserves back. |
| Store | Not opened. The lock from step 1 is held. | Open. Forwarding reads the outbox and saves cursors; pruning and compaction run. |
| New events | None. | None. |
| Exit | `Resume` re-runs steps 2 to 8 when free space changes, *(proposed)* checked every 60 s. It opens the store only once free space reaches the headroom, then goes to `collecting` or `drain-only` like a fresh startup. Free space comes from outside the store, from an operator or a removed file; an open attempt is never the way out. | `Resume` re-runs steps 6 to 8 on the open store after forwarding saves a cursor, *(proposed)* at most every 60 s. It goes to `collecting` only when pruning and compaction succeed and both reserves exist again. |
| Tests | `TestStartupBlockedWithoutHeadroom`, `TestResumeFromBlocked` | `TestStartupDegradesToDrainOnly`, `TestResumeFromDrainOnly` |

Common to both, and to `failed`:

- **Collection stops at the device.** `Mode.AcceptsEvents` is true only in `collecting`. In every other mode the collector stops pulling SER, so records stay in the relay's own buffer. If that buffer wraps before collection resumes, the next collection reports the loss as a C4 `ser.gap` event, never as silence. Syslog stream listeners refuse new data, and datagram listeners drop and count it (section 6).
- **Every mode change is reported** on the node's health surface, as a C4 platform event on `platform/health`, and as an audit record. `ModeChangeOf(prev, next, at)` gives the change with the alarms that caused it. The health type is `store.mode-changed` (to be confirmed with A4 as part of C4's open `store.*` set). The audit record is C8's action `store.mode_change`, with the new mode as `reason_code` and the alarms in `detail` (A3).
- `failed` has no exit except a restart. `Resume` leaves `failed` and `collecting` unchanged (`TestResumeLeavesOtherModesAlone`).

**Nothing else opens the store before recovery completes, or after.** The lock from step 1 is held for the life of the node. Support tools and the UI read through the node, never the files. Phase 2 has to choose the OS mechanism for this. *(proposed)* There are two layers:

- **ACL.** The files' ACL admits only the node's service SID, so no other account can open them at all.
- **Lock file.** The node opens a lock file in the store directory with share mode 0 and keeps it for its lifetime. A second instance under the same SID, such as a support command run as the service, fails at step 1.

The database files themselves cannot be held with share mode 0, because SQLite in the same process has to open them. A6 should test both layers.

A3 accepted the two layers for 0.1 (C5-A3 review, section 4), and A1 confirmed it on three conditions. They are Phase 2 implementation rules:

1. The ACL is a **protected DACL on the store directory**, with inheritance off, and not only on the files. SQLite creates `-wal`, `-shm` and journal files while it runs, and they take the directory's ACL. The default ACL on `C:\ProgramData` lets Users read and create files. The DACL names the node's service SID, SYSTEM and Administrators only.
2. **SQLite temporary files stay in memory or in the store directory** (`temp_store=MEMORY`, or the temp directory set to the store directory). Otherwise a large sort writes record content to the service profile's `Temp` folder, under another ACL.
3. **The service SIDs are separate.** The collector's SID is not in the store's ACL, and the node's SID is not in the credential store's ACL. The collector hands results to the node over IPC and never writes the store.

Residual risk, accepted and recorded: a local administrator or SYSTEM can take ownership or use backup privilege, and C5 cannot prevent that. Tampering with audit is detected by the C8 chain, and for the newest records only by a checkpoint held off the node (AP-17). On Linux the barrier is a `0700` directory owned by the service user with `0600` files; `flock` is advisory and only stops cooperating instances.

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

Sizing rule for deployment: the sum of the class quotas, plus both reserves, plus the open headroom, must fit on the store's volume, with margin for the WAL bound. The audit quota must hold the audit records of the longest expected outage of its required consumer, because nothing else makes audit prunable (C5-A3-8). A store within its quotas then always has room to re-create its reserves. A re-creation failure means something outside the store has used the volume, and the node says so.

## 6. Storage-full behaviour and alarms

`ActionFor(class)` is fixed by the contract, not configurable, because no class may evict unconfirmed records to make room (ADR-0004 item 9, A3's additions).

| Class | At quota |
| --- | --- |
| `adapter-evidence` | `stop-collecting`. Raises `collection-stopped` with the stop time and the device-buffer overwrite estimate. |
| `syslog-stream` (TCP, TLS, RELP) | `refuse-new`. Nothing is acknowledged without a `Receipt`. |
| `syslog-datagram` (UDP) | `drop-and-count`. The count is persisted and forwarded (`syslog-dropped`; C4 `intake.drop-counted`). |
| `audit` | `fail-closed`. Privileged operations and credential-bearing collection are refused (`audit-store-full`; see "audit before act" below). |
| `platform` | `refuse-new`. The alarm stays in node status. |

**Audit before act (C5-A3-3, A1 D1-11).** A privileged operation, and every collector request that uses a device credential, runs only after its audit record holds a `Receipt`. `AuditBeforeAct(ctx, log, rec, act)` is the contract's form of the rule. If there is no receipt, for any reason, `act` does not run, and the caller gets `audit-unavailable`. The reasons covered are a stopped Log, a full audit quota, an audit database that is not open, and a cancelled append (`TestAuditBeforeAct`).

- The refusal is reported through node status, because the audit store may be what failed.
- So a full or failed audit store **stops collection that uses a credential**, while passive intake (received Syslog, evidence already received) continues. SER rows stay in the relay's buffer, and a wrap shows up as `ser.gap` (D1-4).
- A6's V-S9 case: with the audit store full, no `ACC` is sent and Syslog is still received.

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

- **C8 (`TODO(C8)`).** `AuditChain` and `ChainLink` mirror the parts of C8 the store uses (section 1a). C8 merges before C5 in the merge order.
- **Captures and redaction (C5-A3-6).** A capture is raw device output and may contain the echo of what the transport sent. HR-3 redaction happens before the capture is built (C2, C6), never in the store.
- **C4 (`TODO(C4)`).** `NodeID`, `StreamID`, `Seq` and `Key` mirror C4's draft (PR #29) and become aliases once it merges. Two C4 changes are requested in [reviews/C4-A5.md](reviews/C4-A5.md):
  - a pre-commit event form, because the seq exists only after commit;
  - the format of `evidence.ref`.

  A4 made both changes (PR #29 at `de3476e`). A producer's event passes `ValidatePending`, which requires seq 0. The store writes the assigned seq into `id` in the commit transaction, so a stored event always passes `Validate`. `evidence.ref` must be `"sha256:" + evidence.sha256`.
- **Phase 2:**
  - the SQLite implementation and the OS lock mechanism, with A3's three conditions (section 4);
  - **a channel for alarms outside the store** (C5-A3-5). If the database that holds `platform/health` or audit is the one that failed, `RunStartup`'s alarms cannot be stored. They go to node status and the Windows Event Log, so a storage failure stays observable (principle 5);
  - measuring `OpenHeadroomBytes` against F-013 on NTFS;
  - measuring the group-commit window on the real drive. A fast flush is not proof of durability (A6's note on C-24), so the window may be tuned from flush latency for throughput, but never treated as a health signal.
- **Power loss** is H-11, per hardware model (C-24). See [A5-node-posture.md](A5-node-posture.md).
- Site-to-central delivery reuses `Consumer`, `Cursor` and `Boundary` (central is a required consumer), but the protocol itself is not in C5.
