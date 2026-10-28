// Package store is the SQLite implementation of C5 otsec.store/0.3
// (contracts/store). It is owned by A5 (A1 D2-1). One DB is one database of
// a node's Layout: one file, one writer module, one OS lock. The node runs
// contracts/store.RunStartup over an Env for each database and then appends
// only through a contracts/store.Log over the returned DB, so the contract's
// commit, receipt and startup rules apply unchanged.
//
// What this package adds to the contract, and why:
//
//   - The file settings ADR-0004 item 1 and E-A5-3 require: WAL,
//     synchronous=FULL, a bounded WAL (wal_autocheckpoint and
//     journal_size_limit), auto_vacuum=INCREMENTAL set before the first
//     table, and temp_store=MEMORY so that no record content reaches a
//     temporary file outside the store directory (A3 lock condition 2).
//     CheckSettings refuses a store whose persistent settings differ; it
//     never changes them.
//   - One connection, used under a mutex. SQLite allows one writer per
//     file, so a second connection would add SQLITE_BUSY handling and no
//     throughput. Readers wait for at most one transaction.
//   - The store writes the assigned seq into each C4 event's id in the
//     commit transaction. Every other member's value keeps the producer's
//     bytes. Audit records are sealed with contracts/store.SealAudit.
//   - Per-class quotas are counted in bytes of stored payload (event bytes,
//     source cursors and captures), not pages, so that a class at quota is
//     refused before the database as a whole is full. Usage, which startup
//     uses to prune, counts live pages as C5 requires.
//   - Close checkpoints the WAL (wal_checkpoint(TRUNCATE)) on a background
//     context. That work is bounded in bytes, by the WAL bound above, and not
//     in time: on a slow disk each flush can take seconds (F-016), so a
//     caller that must stop by a deadline does not wait on Close.
//   - Options.BusyTimeout is SQLite's busy_timeout, 5 s unless a test that
//     holds a database busy on purpose shortens it.
//   - Alarms go to Options.Alarms, a sink outside the store (C5-A3-5): the
//     database that raises an alarm may be the one that cannot store it.
//
// Evidence: every test runs against real SQLite files. Durability across a
// killed process is tested; durability across power loss is not (H-11).
package store
