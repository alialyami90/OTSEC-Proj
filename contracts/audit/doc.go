// Package audit is contract C8, otsec.audit/0.3: the audit record every module
// writes for security-relevant actions, and the per-node hash chain that makes
// removal or alteration of a record detectable.
//
// # What it covers
//
//   - Record: who (Actor, built on the C7 principal), did what (a closed set of
//     Actions), to what (Target), with which outcome and reason code, when,
//     and how it correlates with a collector request, a C2 invocation and the
//     events it produced.
//   - Time is C4's event.Received: a UTC value, its resolution, and the node
//     clock's state, with C4's closed sync values. It is always the node's
//     clock (C8-A4-3): the host clock that the node and its collector share.
//     A collector stamps the records it relays as it acts; the node stamps
//     its own records when it builds them. Chain order is commit order, not
//     time order: a run's relayed records are committed after the node's
//     decision record, so they follow it in seq and read earlier by the
//     run's duration. Per collector request (its info and decision records
//     carry the request ID, its relayed records the invocation ID), the info
//     record's time is at or before every relayed record's, and those are
//     at or before the decision's (D3-8).
//   - Correlation. A collector.request record carries the C7 request ID as
//     correlation_id. Every device.* and credential.use record carries the C2
//     invocation ID, which C4 events carry as collection.invocation_id, so
//     "which events did this privileged read produce?" is a lookup by ID
//     (C8-A4-4). A collector-reported record also carries collector_seq
//     (C7-A5-2, VerifyCollectorSeq).
//   - Session close. After a successful ACC, the session-close record has
//     outcome failed with reason qui_not_sent when the collector could not
//     send QUI before closing (C7-A6-2). Every session-close record carries
//     transcript_sha256, the C2 result's transcript.sha256: the SHA-256 of
//     the transcript exactly as stored, redactions included (A1 D1-25). The
//     chain therefore covers the evidence: a verifier hashes the stored C2
//     transcript and compares it with the record whose correlation_id is the
//     invocation ID. The digest is known only when the session ends, so it
//     is not on device.session.open, which audit before act requires first.
//     It was added inside 0.1 by D1-25; no 0.1 reader was deployed without
//     it. An open with no matching close means the collector stopped during
//     the session (a crash or a lost node), so no close, and no digest, could
//     be written. That session's outcome is unknown and its transcript, if
//     any was stored, cannot be checked against the chain. A reader reports
//     it as such and never treats it as succeeded. Events that carry its
//     invocation ID are kept, but they are not shown as reconciled with the
//     chain. The C7 failed-auth floor stays in force for the asset, because
//     the collector cleared nothing (D1-20).
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
// # Node state (0.2)
//
// Five node-written actions, all outcome info with actor type node
// (docs/phase2/A3-c8-seq-reset.md, A1 D2-15):
//
//   - collector.install_key: the collector install key the node trusts,
//     written at its first start, so a reset can be checked against it.
//   - collector.seq_reset: the collector's numbering restarted, which only a
//     reinstall with a new install key does. It carries previous_high, the
//     new install_key_id, and first_seen when a reply showed it (absent when
//     the node found the new key before sending). The node holds collection
//     from it until collector.seq_reset_ack.
//   - collector.seq_reset_ack: an admin acknowledged the reset on the key
//     they confirmed (T-12); that key becomes the trusted one. The Phase 2
//     acknowledgement is an admin-written file, so the record cannot name
//     the admin; an admin-signed C7 0.2 request will replace it before any
//     device-observed endpoint.
//   - asset.suspend and asset.suspension_clear: the node's C1 asset
//     suspensions, with the reason, the C2 code that set it, and the ref
//     (the invocation ID, or the operator) as correlation_id. A node can
//     rebuild its suspensions from them (VerifySuspensions).
//
// VerifyCollectorSeq reads each reset as an epoch boundary, and
// VerifySuspensions checks that each clear names an open suspension. A node
// that verifies window by window carries the state between windows:
// VerifyCollectorSeqFrom takes and returns a SeqState, and VerifySuspensions
// the open set. A record stamped 0.1 cannot carry any of these actions or
// their fields.
//
// # Quarantine export and clear (0.3)
//
// Two node-written actions for the administrator's export and clear of an
// asset's quarantine stream (P3-A5, A1 D3-1). Both have actor type node, a
// target asset, and a quarantine object: the SHA-256 of the manifest the
// node read, and first_seq..last_seq with the number of items it lists.
// Every stored seq in that range is listed and nothing else, so the range
// names exactly the verified set, and a clear removes only seqs in it.
//
//   - quarantine.exported (info): the node checked every listed item's
//     event and capture hashes against its own stream. It records what the
//     node checked, not that the export was kept anywhere, which the node
//     cannot see.
//   - quarantine.cleared: an administrator's clear-quarantine.json named a
//     manifest the chain holds a quarantine.exported record for. Outcome
//     succeeded means every item was re-checked and the clear is recorded
//     before anything is removed (audit before act); the removal is resumed
//     from this record, never from the file. Outcome info with reason
//     already_cleared means the chain already held a clear of that manifest
//     and the file changed nothing. It carries clear_sha256, the hash of the
//     file applied, and requested_by, the principal the file names. The
//     file is not signed, so requested_by is what it says, not who wrote
//     it, and the actor stays the node, as on asset.suspension_clear, until
//     a signed admin request (C7 0.4) replaces the file.
//
// A record stamped 0.2 or earlier cannot carry these actions or the
// quarantine object.
//
// # What it leaves out
//
//   - Secrets, full configurations and raw device output. Values that need
//     reconciling (parameters, bytes sent, the session transcript) appear only
//     as SHA-256 digests. The raw transcript belongs to the C2 evidence, not
//     to audit. ParseRecord rejects a record that carries a field named like
//     a secret, raw output, or any field whose name starts with "transcript"
//     other than transcript_sha256.
//   - Storage and retention (C5). A producer hands C5 a
//     pending record (ValidatePending: no seq, no prev_hash). C5 seals it with
//     Seal inside the commit transaction, in commit order, and stores the
//     result byte for byte, because the chain is over the stored bytes. A
//     prune of audit records persists the (seq, hash) of the last record it
//     removes, so the rest of the chain still verifies from that Checkpoint.
//   - Signing checkpoints. 0.1 relies on getting checkpoints off the node; a
//     node-held signing key would not survive a node compromise anyway.
//
// # Properties a forwarder relies on
//
// These hold for every 0.x minor (C8-A4-6). MaxRecordBytes (16 KiB) bounds a
// sealed record and is never raised. Sealed bytes are compact JSON in valid
// UTF-8 with no raw CR, LF or NUL byte: Seal writes them with json.Marshal,
// which escapes control characters, and ParseRecord rejects a record that
// has one. A receiver verifies the chain over exactly the bytes it received.
// C6 carries them unchanged in the Syslog MSG part, never truncated, split or
// re-encoded, on octet-counted or RELP framing only.
//
// # Checkpoints leave the node with the audit stream
//
// Every forwarded record is a checkpoint: a receiver that holds record N
// holds (node, N, Hash(record N)). A Checkpoint counts against AP-17 only
// when the receiver confirmed it: central's acknowledgement on the
// node-to-central link (C5 outbox), or a RELP target. A best-effort Syslog
// target confirms nothing, so it narrows nothing. An audit.checkpoint record
// states the newest (seq, hash) a confirming receiver acknowledged. A3
// recommends that the audit stream always goes to a confirming receiver;
// whether a RELP target is required is A1's call under ADR-0004 item 6
// (C8-A4-7).
//
// # Audit actions and C4 health types
//
// Where an audit record and a C4 health event state one fact, one detection
// writes both, so they cannot disagree (C8-A4-5):
//
//	C8 action            C4 health type                   Source
//	store.mode_change    store.mode-changed               C5 (reason_code is the new mode)
//	storage.alarm        store.* (names final in C5)      C5
//	clock.change         time.node-stepped (proposed)     node runtime; moves every event's received.utc
//
// C4 time.unsynchronized is about a source's clock and has no audit record.
// A forwarding fault (C4 forward.*) is telemetry, not an audited action. A
// refusal because audit cannot be written cannot itself be audited; it goes
// to node status and to C4 store.mode-changed (blocked) (D1-11).
//
// # Concepts imported from other contracts
//
// Principal and the C7 refusal codes come from contracts/authz, the timestamp
// (event.Received) from C4, and the node ID pattern from contracts/node
// (D1-1). The asset ID (C1, a lowercase UUID) and the C2 refusal and posture
// codes are copies here, marked TODO(C1) and TODO(C2). TestSchemaPatterns
// keeps the schema's patterns equal to the code's.
//
// # Requirements and threat-model entries served
//
// R2.4 (session auditing), R4.4, AP-2, AP-14, AP-15, AP-17, HR-3, SC-12, V-S8
// and V-S11.
package audit
