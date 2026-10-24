// Package audit is contract C8, otsec.audit/0.1: the audit record every module
// writes for security-relevant actions, and the per-node hash chain that makes
// removal or alteration of a record detectable.
//
// # What it covers
//
//   - Record: who (Actor, built on the C7 principal), did what (a closed set of
//     Actions), to what (Target), with which outcome and reason code, when (the
//     C4 platform timestamp model), and how it correlates with a collector
//     request, a C2 invocation and the events it produced.
//   - What must be recorded: every collector request, accepted or refused,
//     with the C7 refusal code; every C2 refusal and posture warning; every
//     credential use, install, suspension, clearing and revocation; every
//     device session open and close; register package verification and
//     activation; sign-in, role and policy changes; audit export; clock steps;
//     storage alarms and store mode changes; node posture changes and the OS
//     migration date (HR-9); moving an asset's collection to another node
//     (D1-3); service start and stop.
//   - The chain. Records are stored as the exact bytes that were written.
//     Record N carries prev_hash, the SHA-256 of record N-1's bytes, and seq
//     increases by one per record on a node. Removing, inserting, reordering or
//     altering a record breaks the chain at the next record. Altering or
//     truncating the newest records is detected only against a Checkpoint held
//     outside the node (forwarded upstream or to central); between checkpoints
//     that window is the residual risk recorded under AP-17.
//   - Audit before act (A1 D1-11, C5-A3-3). A privileged operation, and every
//     C7 collector request, proceeds only after its record holds a C5
//     receipt. When audit cannot be written (quota, a stopped log, a store
//     that is not open), the operation is refused and the refusal goes to node
//     status. Credentialed collection therefore stops; passive Syslog intake
//     continues.
//
// # What it leaves out
//
//   - Secrets, full configurations and raw device output. Values that need
//     reconciling (parameters, bytes sent) appear only as SHA-256 digests. The
//     raw transcript belongs to the C2 evidence, not to audit. ParseRecord
//     rejects a record that carries a field named like a secret.
//   - Storage, forwarding and retention (C5, C6). A producer hands C5 a
//     pending record (ValidatePending: no seq, no prev_hash). C5 seals it with
//     Seal inside the commit transaction, in commit order, and stores the
//     result byte for byte, because the chain is over the stored bytes. A
//     prune of audit records persists the (seq, hash) of the last record it
//     removes, so the rest of the chain still verifies from that Checkpoint.
//   - Signing checkpoints. 0.1 relies on getting checkpoints off the node; a
//     node-held signing key would not survive a node compromise anyway.
//
// # Concepts imported from other contracts
//
// Principal and the C7 refusal codes come from contracts/authz. The timestamp
// model (C4), node ID (C4), asset ID (C1) and the C2 refusal and posture codes
// are provisional here, marked TODO(C1), TODO(C2) and TODO(C4).
//
// # Requirements and threat-model entries served
//
// R2.4 (session auditing), R4.4, AP-2, AP-14, AP-15, AP-17, HR-3, SC-12, V-S8
// and V-S11.
package audit
