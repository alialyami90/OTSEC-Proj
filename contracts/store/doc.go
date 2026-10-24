// Package store is contract C5, otsec.store/0.1: how a site node keeps,
// acknowledges, recovers and prunes events. It is owned by A5. Reviewers are
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
//     Boundary, ComputeBoundary, Pruner).
//   - The startup recovery order on a store that may be full: the reserve is
//     released before the store is first opened, a failed release stops
//     startup, nothing else opens the store before recovery completes, and a
//     store with no reserve left is opened only with enough free space, and
//     then only to drain (StartupEnv, RunStartup).
//   - Storage-full behaviour per stream class and the alarms the store
//     raises (StreamClass, FullAction, Quota, Alarm).
//   - Audit records: one audit stream per node, sealed into the C8 hash
//     chain inside the commit and never re-encoded, a chain anchor kept
//     across pruning, and audit before act, so that a privileged operation
//     or credential-bearing collection runs only after its audit record
//     holds a Receipt (AuditChain, SealAudit, ChainLink, AuditBeforeAct).
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
const Identifier = "otsec.store/0.1"
