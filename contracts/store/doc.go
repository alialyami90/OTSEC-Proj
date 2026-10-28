// Package store is contract C5, otsec.store/0.4: how a site node keeps,
// acknowledges, recovers and prunes events. It is owned by A5 (now B5). Reviewers are
// A4, A6 and A3. The full semantics, with the evidence behind each rule, are
// in docs/phase1/A5-store-semantics.md.
//
// The contract covers:
//
//   - Store shape: one database per data-owning module, written by exactly
//     one module (Layout).
//   - Commit before acknowledgement, with group commit required: a Receipt,
//     the only thing that may release an acknowledgement or count as
//     "stored", exists only after the batch holding the record has committed
//     at synchronous=FULL (Log, Committer, Receipt).
//   - The outbox and consumer cursors: at-least-once delivery, required and
//     best-effort consumers, and a prune boundary derived from persisted
//     cursors on every call, never from memory (Outbox, CursorStore,
//     Boundary, ComputeBoundary, Pruner). Since 0.3, the named events of a
//     quarantine stream, which no consumer reads, can be removed in bounded
//     steps to carry out an administrator's audited clear (Discarder,
//     QuarantinePrefix, DiscardStepEvents, D3-1).
//   - The startup recovery order on a store that may be full: the reserve is
//     released before the store is first opened, a failed release stops
//     startup, nothing else opens the store before recovery completes, and a
//     store with no reserve left is opened only with enough free space, and
//     then only to drain (StartupEnv, RunStartup). Since 0.2, an open that
//     failed only because the database was busy or locked (CodeOpenBusy) is
//     retried by Resume without a restart; every other failure still needs
//     one (Report.OpenBusy, P3-A5, docs/phase2/A5-p3-failed-open-retry.md).
//   - Storage-full behaviour per stream class and the alarms the store
//     raises (StreamClass, FullAction, Quota, Alarm).
//   - Since 0.4 (P4-A5, docs/phase4/B5-c5-0.4-proposal.md): the
//     configuration class, alone in its database, for C9 and C10 documents
//     with a per-record cap and an injected DocumentValidator; held records,
//     which pruning skips (Holder, Record.Holds, HoldReason); the
//     syslog-unknown class, HR-11's absolute bound on what unknown senders
//     store; and a commit cap, so the recovery reserve covers the largest
//     commit (GroupOptions.MaxCommitBytes, LargestCommit,
//     RecoveryReserveFor, D4-9).
//   - Since 0.5 (D4-14, docs/phase4/B5-c5-0.5-proposal.md): the WAL a
//     commit may write counts its rows, not only its bytes
//     (GroupOptions.MaxCommitRecords, LargestCommitRecords, RowWALBytes,
//     CommitWALBytes and RecoveryReserveFor take the record count), and the
//     file's size against the quota is bounded (DiskBytesPerQuotaByte), after
//     B6's event-size sweep showed that events near half a page and small
//     rows write more WAL and disk than their bytes.
//   - Since 0.6 (D4-18, D4-19): the hold codes HoldAcknowledgedDifference and
//     HoldRestoredDifference. A
//     configuration acknowledgement, or a return to the baseline, ends a
//     change's alarm and not the hold on its snapshot and difference, which
//     stay held as evidence. A
//     reconcile that meets a hold code it does not know keeps that hold
//     unchanged (no release, no new reason) and raises an alarm.
//   - Startup measures a quota in class bytes (a defect fix in 0.6, B6's
//     finding on #299). RecoveryStore.Usage is the payload the class quotas
//     count, as the runtime refusal counts it, not the pages, which run well
//     over it: a class at 75% of its quota raised store-quota-reached at
//     every start. Pages are the store's PageBytes and stay bounded by
//     DiskBytesPerQuotaByte.
//   - Audit records: one audit stream per node, sealed into the C8 hash
//     chain inside the commit and never re-encoded, a chain anchor kept
//     across pruning, and audit before act, so that a privileged operation
//     or credential-bearing collection runs only after its audit record
//     holds a Receipt (SealAudit, ChainLink, GenesisLink, AuditBeforeAct, over contracts/audit).
//
// It deliberately leaves out the SQLite implementation (Phase 2), the
// site-to-central protocol, how events are encoded (C4) and how they are
// rendered for Syslog (C6). Store implementations live outside contracts/.
//
// C5 is an in-process contract: Go interfaces only, no JSON Schema. The
// package does no I/O. The group-commit coordinator (Log) and the startup
// sequence (RunStartup) are in the contract on purpose: they are the rules
// that make an early acknowledgement or an out-of-order startup impossible,
// and keeping them here means every implementation runs the same order.
//
// Serves: R4.4, R4.6, R4.7, R8.4, R8.6, R8.7, R8.8; ADR-0004 items 1, 2, 6 to
// 9; ADR-0007; V-S6, V-S9; A6 E-02 to E-04, F-011 to F-013; R-A5-5; A3 AP-1
// (store file ACL) and the storage-full additions in ADR-0004 item 9.
package store

// Identifier is this contract's identifier, parsed by contracts/version.
const Identifier = "otsec.store/0.6"
