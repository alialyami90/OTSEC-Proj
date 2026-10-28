// Package audit is contract C8, otsec.audit/0.7: the audit record every module
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
// # Admin-signed requests: claimed, verified and the repeat (0.4)
//
// A collector.request record about an admin-signed request (C7 0.4 and
// later) names the request by an Admin group: the signing key ID, the
// human principal, the nonce, and the SHA-256 of the signed payload bytes.
// Never the payload, the sealed secret or the signature.
//
//   - claimed is on the node's info record, written before it sends. It is
//     what the envelope and payload say, and nothing has checked it yet: a
//     forged file claims whatever it likes.
//   - verified is on the allowed record: C7 CollectorReply.Admin, what the
//     collector checked against its pinned keys. The record's actor is the
//     verified person (type human, the same ID), so it names one person. A reader that wants to
//     know who authorised an action reads verified, never claimed. A
//     claimed group whose request was then refused stays in the chain as
//     evidence of the attempt.
//   - repeat_of is on an allowed record whose reply was the C7 0.5 repeat
//     answer, with verified. The repeat has its own collector_seq, and
//     repeat_of names the first decision on the same signed bytes, which
//     did nothing again. VerifyCollectorSeq counts repeat_of as accounting
//     for that first decision: when the first reply was lost, the repeat
//     is the record of it. A window report can therefore show a gap younger
//     than the admin request window (15 minutes) that a later repeat
//     covers; see VerifyCollectorSeqFrom.
//
// A record stamped 0.3 or earlier cannot carry these fields, and they are
// on collector.request only: claimed with outcome info, verified and
// repeat_of with outcome allowed, repeat_of below the record's own
// collector_seq. A 0.3 reader ignores the fields (readers are not strict),
// but its VerifyCollectorSeq reports a first decision that only a repeat
// accounts for as a gap: the safe side.
//
// # Configuration approvals, acknowledgements and differences (0.5)
//
// Four actions record configuration monitoring (P4-A3, V-M2). The node
// writes all four, each with a target asset, a correlation_id and a Config
// group holding exactly that action's fields (config.go):
//
//   - config.change_approved follows the collector's acceptance of a C7 0.6
//     node.change_approval. Its actor is the verified person. It copies the
//     body (baseline_digest, the window and the reason, checked by C7's own
//     rule) and names the acceptance by decision_seq and payload_sha256. It
//     is succeeded, or denied when the node refuses to act on it.
//   - config.baseline_acknowledged follows a node.baseline_ack in the same
//     way, with the baseline's kind (configuration or event) and
//     previous_digest, the baseline it replaces. It is denied when the node
//     holds no baseline of that asset and kind whose stored bytes hash to
//     baseline_digest, or (B4 on #250) when that record is of the other
//     kind, of another asset or node, or not the next in the asset's chain.
//   - config.change_detected is the node's own record of a read whose
//     snapshot differs from the baseline: the snapshot, the C9 difference,
//     the decision on the read that found it (read_seq), and the asset's
//     last run of that operation before it (unchanged_read_seq, and
//     unchanged_at, that run's record time; or the epoch's collector reset
//     when it has no earlier run). It is warning unapproved_change,
//     which is the alarm, or info approved_change with approval_seq naming
//     the approval that covers it.
//   - config.baseline_restored is the node's record of the first read
//     equal to the baseline after a recorded difference from it.
//
// The digests are C9's and C10's "sha256:<hex>" over a document's stored
// bytes. Admin gains kind in 0.5: the request's C7 kind, which the node
// fills on claimed and verified.
//
// "In advance" is decided by order, never by a time the approval states. An
// approval covers a difference only if the collector numbered its acceptance
// below its decision on the read that first found the difference, in the
// same collector epoch (ApprovalCovers). The window must also overlap the
// time the change happened in, between unchanged_at and the detection. The
// node writes config.change_detected when a read finds a configuration
// state it has not recorded against the baseline, not on every read. Once a
// difference was recorded unapproved, no later detection against the same
// baseline may be approved until a config.baseline_restored for it follows
// the alarm, so an approval accepted after a change was found never
// silences it. Ending that alarm takes a signed baseline acknowledgement or
// a recorded return to the baseline. From 0.6 (D4-18) a succeeded
// configuration-kind acknowledgement ends every open alarm of its asset
// raised before it, whatever baseline it was against, so acknowledging A
// again starts A afresh; an alarm raised after the latest acknowledgement
// still blocks a later approval, and an event-kind or denied acknowledgement
// ends none. VerifyConfig checks all of this over the chain:
//   - each approval and acknowledgement follows a real acceptance of its kind
//     by its actor for the same signed bytes;
//   - each detection and restore names a real read of its asset;
//   - each detection's unchanged_at is the time of the asset's last run
//     before that read, a record already in the chain, so the node cannot
//     choose how early the change happened;
//   - each detection, restore and succeeded approval names the asset's
//     configuration baseline that the last succeeded acknowledgement set;
//   - every approval_seq names an approval that covers the detection;
//   - no approved detection follows an unapproved one against the same
//     baseline without a restore, or a configuration acknowledgement of
//     its asset, in between;
//   - each succeeded acknowledgement names, as previous_digest, the
//     baseline of its asset and kind the last one set.
//
// A node that forges records can still forge all of them, as for any
// collector event (VerifyCollectorSeq). What it cannot do is silence an
// alarm by citing an acceptance the collector numbered later, or one of
// another kind or person, without VerifyConfig failing.
//
// # Compared reads and their removal (0.7)
//
// A configuration read that shows no difference from the baseline, or only
// the change the asset's newest recorded change already is, would otherwise
// fill the store with copies that say nothing new (D4-20). Two node actions
// let such copies be removed without losing the evidence of why:
//
//   - config.read_compared is the node's record of one such read, info, with
//     reason no_difference (baseline_digest, snapshot_digest, snapshot_seq,
//     the snapshot's seq in the asset's configuration stream, and read_seq) or
//     same_change (also change_seq, the config.change_detected record the
//     read repeats, and changes_digest, the digest of that change's ordered
//     changes, which C9 supplies and which config.change_detected carries
//     from 0.7). It is the only result a read can have besides a detection
//     or a restore: a second result for the same read breaks the chain.
//   - config.reads_removed is the node's record, written and receipted
//     before any copy is removed, of the oldest compared reads of one asset
//     that the chain shows and no earlier removal took: removed_count, the
//     stream seqs removed_first_seq and removed_last_seq, removed_digest
//     (RemovedReadsDigest over their snapshot digests in order) and
//     kept_digest, the snapshot digest of the newest compared read. The two
//     newest compared reads of an asset always stay (D4-20), so a removal can
//     only take what other recorded reads already show, and a person who
//     views a read has at least one schedule interval before it goes.
//
// VerifyConfig adds to its checks:
//   - a config.read_compared names a real read of its asset, compares
//     against the asset's acknowledged configuration baseline, and gives
//     the read its only result;
//   - a no_difference read follows no recorded change against that
//     baseline that a restore or a configuration acknowledgement has not
//     ended;
//   - a same_change read names the newest recorded change against the
//     baseline, by its seq and its changes_digest;
//   - results come in the order the reads were taken: per asset and
//     collector epoch, each config.change_detected, config.baseline_restored
//     or config.read_compared names a later read decision than the asset's
//     previous result, and each compared read's snapshot_seq is greater than
//     the previous one's. So a read cannot repeat a change that a later read
//     found, and the baseline's own read cannot be given a result after a
//     change;
//   - an asset's results name runs of one operation, until a configuration
//     acknowledgement sets a new baseline. Which operations are
//     configuration reads is the register's, so this contract checks only
//     the consistency;
//   - a config.reads_removed takes the oldest recorded reads that no earlier
//     removal took, leaving at least the two newest, with a removed_digest
//     that matches them, a removed_first_seq and removed_last_seq that are
//     the snapshot_seq of the first and last of them, and a kept_digest that
//     is the newest's.
//
// Removal by seq range, never by time or space, is the store's rule (C5).
// The range bounds the stream; the set removed is the compared reads the
// chain names inside it (removed_count of them), never every record in the
// range, since the stream also holds held differences and baselines. After a
// crash between the record and the removal, the node completes the removal
// the chain names, re-deriving that set from the chain; the chain may name
// more than was removed, never less. A node whose audit stream has lost its
// first records cannot derive the set and removes nothing.
//

// Not covered: the approver and the person who changed the relay may be
// the same. Nothing observes who changed a relay until engineering access
// (R2) exists, so this stays a limitation that R2 can close (D4-2). An
// approval covers any change from its baseline in its window, not named
// settings. The reason says what was meant, and the alarm text shows which
// approval silenced a difference.
//
// A record stamped 0.4 or earlier cannot carry these actions, Config or
// Admin.kind.
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
// R2.4 (session auditing), R3.4 and R3.6 (approved changes, 0.5), R4.4,
// AP-2, AP-14, AP-15, AP-17, HR-3, SC-12, V-S8, V-S11 and V-M2.
package audit
