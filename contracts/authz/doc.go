// Package authz is contract C7, otsec.authz/0.5: who may ask for what, how
// device credentials are referenced without being held, what the main process
// may ask the collector to do, and how the collector verifies a register
// package before using it.
//
// # What it covers
//
//   - Principals and roles (monitor, engineer, admin, security-auditor, and the
//     non-human collector role), operation classes, the role and operation
//     matrix, and separation of duties. Monitoring, engineering, administration
//     and security are separate: admin cannot hold engineer or
//     security-auditor, engineer cannot hold security-auditor, and the
//     collector role is never combined with a human role.
//   - CredentialRef, an opaque handle to one device credential held by one
//     node's collector. No type in this package has a field for a secret. The
//     main process can install a credential only as ciphertext sealed to the
//     collector's key (SealedSecret), and nothing can read a credential back.
//   - The collector IPC (CollectorRequest, CollectorReply). This contract is
//     strict: unknown fields, duplicate keys, trailing data and oversize
//     messages are rejected (contracts/README.md). The only request that can
//     lead to device I/O is "run", which names a C3 operation ID and an
//     enrolled asset. It cannot carry a command line, a register change, limits
//     or a secret. Credential install, revoke and clear-suspension, and
//     (since 0.2) asset.clear_suspension, are the only other kinds, and none
//     of them causes device I/O. From 0.4 an administrator signs them
//     (AdminSigned); see "Admin-signed requests". From 0.5 two node kinds,
//     node.quarantine_clear and node.seq_reset_ack, exist only signed: the
//     collector verifies them and changes nothing of its own, and the node
//     acts only once the collector has accepted.
//   - Register package verification (VerifyRegisterPackage): Ed25519 only,
//     release keys from the node's trust anchors, a signed statement that binds
//     the payload digest and package version, and an anti-rollback floor. Any
//     missing, unsigned, unknown-key, revoked-key, digest-mismatched or
//     rolled-back package is rejected, and the caller must then do no device
//     I/O (C-A2-2, SC-18).
//
// # Collector rules this contract fixes
//
//   - A credential is bound to one node, asset, C1 endpoint, transport and
//     access level (CredentialRef.Binds). A run whose node, asset, endpoint,
//     transport or needed access level differs from its reference, or whose
//     plaintext scope differs from the scope of the C1 endpoint's
//     acknowledgement, is refused with credential_mismatch (C1-A3-3,
//     C7-A2-4, C7-A2-6). A run of a level 0 operation, sent before ACC,
//     carries no credential_ref, and any other run carries one (C7-A2-5).
//   - The access level is checkable (CheckAccessLevel, C7-A6-1). It is the
//     register's level token, and an auth-phase session line of the verified
//     register must reach it from level 0, with a read-only operation that
//     needs it. For SEL-751 0.1 that is "1" only. The collector checks it at
//     install and at every run. It cannot tell what a password opens: a
//     Level 2 password installed for level 1 is caught only if the relay
//     rejects it at ACC (H-15).
//   - A secret is checked against the verified register at install
//     (ValidateSecret, C7-A6-3): it may not match any register line in any
//     case, nor start with a command mnemonic (three characters for SEL).
//   - The credential slot opens at most once per session, right after the
//     documented password prompt that follows ACC (C7-A6-2). A second
//     password prompt is auth-failed: the slot sends nothing, the session
//     ends and the credential is suspended. No password prompt at all is
//     password-prompt-absent, and nothing is sent.
//   - After a successful ACC, every way out of the session sends QUI before
//     the connection closes: the normal end, an identity mismatch, a parse
//     failure, a timeout and any other error (S22 p. 7.16: a Telnet session
//     closed without QUIT keeps its level until TIDLE expires). A QUI that
//     could not be sent is recorded on the session-close audit record
//     (outcome failed, reason qui_not_sent).
//   - Identity is checked in every authenticated session, not only in SER
//     runs (C7-A6-6). The family's register names the operation whose output
//     carries the serial number; for SEL-751 0.1 that is the SER report
//     header, since the ID output has no serial-number field. A session that
//     runs another level 1 operation also reads that identity source before
//     its output is released, and a mismatch suspends the credential with
//     identity-mismatch.
//   - At most one unconfirmed authentication per asset within FailureFloor
//     of the last one (C7-A2-1, A1 D1-20 and its amendment). An
//     authentication is unconfirmed from the moment ACC is sent until the
//     Level 1 prompt (=>) confirms it, so a wrong password, a timeout, a
//     closed connection or a crash in between starts the floor, and so does
//     an ACC that is never answered. The relay may then sit at a pending
//     "Password: ?", and whether it keeps that prompt across connections is
//     unknown (A6 H-15 (a)). The floor is TIDLE plus one minute, where TIDLE
//     is the port's idle timeout last read with SHO P 1, or 31 minutes when
//     it is unknown. A new session inside TIDLE could otherwise land on the
//     previous session's pending password prompt, so its first line, even
//     the wake line end, would be a wrong password. A request inside the
//     floor is refused with rate_limited before any connection, so a
//     compromised main process cannot cycle install, clear and run fast
//     enough to drive the relay's alarm contact (SALARM after three wrong
//     passwords).
//   - Durable collector state (C7-A5-3). The collector keeps the time of the
//     last unconfirmed authentication per asset, and its collector sequence
//     counter, in its own store. It flushes the attempt time before the
//     transport sends ACC, and the counter before it replies. A restart
//     therefore does not reopen the floor. A failure time later than the
//     clock counts as inside the floor, so a clock stepped backwards does
//     not reopen it either. If the state cannot be read or flushed, the
//     collector refuses every run with collector_state_unavailable.
//   - Trust anchors (C7-A6-7). When the node's trust anchors change, the
//     collector re-verifies every active register package. A package that no
//     longer verifies, for example because its release key was revoked, is
//     dropped: collection for that family stops and an alarm is raised
//     (SC-18).
//   - Suspend reasons are C1's names (SuspendReason). identity-mismatch means
//     the password went to another device: it cannot be cleared on the same
//     version (ClearableInPlace), only by rotation or re-commissioning.
//   - Asset suspensions (0.2, D2-15). A run whose outcome code suspends the
//     asset (C2 Code.Suspends) is recorded by the collector with the
//     invocation that set it, and every later run to the asset is refused.
//     Only asset.clear_suspension lifts it. The node sends it on its own
//     behalf, after recording its own asset.suspension_clear from the
//     administrator's clear-suspension.json. The collector reads that file
//     itself, from the administrators' folder the node and the collector
//     both read, after checking the folder and the file are writable by
//     neither service. It clears only when the request, the file and its
//     own record all name the same asset and invocation. A refused folder,
//     a missing or malformed file, or a file, request or record naming
//     another invocation is suspension_mismatch, and nothing changes. A
//     matching clear of an asset the collector does not hold suspended is
//     accepted and changes nothing, so a retry after a lost reply, or a
//     clear sent to a reinstalled collector, settles. So a compromised node cannot lift the collector's
//     suspension without the administrator's file, and a file planted
//     without the node's request lifts nothing. The two clears are
//     separate: asset.clear_suspension never touches a credential's
//     suspension, and credential.clear_suspension never touches an asset's.
//   - Held suspensions (0.3, A6 on #120). A run refused because the
//     collector holds the asset suspended is refused with asset_suspended,
//     and the refusal's suspension names the C1 reason, the invocation that
//     set it and its C2 outcome code. A clear refused with suspension_mismatch names the
//     suspension the collector holds, if it holds one. The node adopts a
//     named suspension it does not hold: it records its own asset.suspend
//     with that reason and ref, so the administrator's clear works as for
//     any other. Otherwise a suspension whose run reply was lost, or which
//     the node never recorded, could be lifted only by reinstalling the
//     collector. Adopting only adds a restriction the collector already
//     enforces, so a collector that names a false suspension stops nothing
//     it could not already refuse. CollectorReply.HeldSuspension checks
//     the named suspension's shape, and the node checks its code is a known
//     C2 code whose Suspends is the reason (C2 imports this package). One
//     that fails either check, or has no code because the collector
//     recorded it before it kept codes, is not adopted, and the node
//     alarms. The collector never holds an operator suspension, so that
//     reason is not accepted.
//   - Audit before act (A1 D1-11). The main process sends a request only after
//     its C8 collector.request record holds a C5 receipt. With a full or
//     failed audit store, no request is sent, so collection that uses a
//     credential stops; passive Syslog intake does not.
//
// # Admin-signed requests
//
// From 0.4 (D2-11) the collector accepts credential.install,
// credential.revoke and credential.clear_suspension only as admin-signed
// requests, and asset.clear_suspension as one once the node relays the
// administrator's signed file (A1, Phase 3). Up to 0.3 the node built these
// requests and asserted the person itself, so a compromised node could seal
// any guess and install it, and the reuse rule's secret_rejected told it
// whether the guess equalled a stored secret: an equality oracle, however
// the refusal was worded.
//
// The request carries AdminSigned in place of its body. The payload
// (AdminRequest) holds the body and binds the person, the admin key, the
// node, the collector's install key, a single-use nonce and a validity
// window of at most MaxAdminLifetime. The signature is Ed25519 over
// AdminSigningInput: a prefix naming the contract and the operation,
// then the payload's exact bytes, so a signature for one operation never
// verifies for another, nor as a register package, and no canonical JSON
// is needed. The signature covers the sealed secret, so a node cannot put
// its own guess under a genuine signature.
//
// VerifyAdminRequest runs the checks in a fixed order (envelope, key,
// signature, payload, binding, window) and decodes the payload only after
// the signature verifies. The collector then spends the nonce durably
// before any other decision, so a signed request is good for one decision,
// even across a restart, and only then applies the install budget, the
// store and the reuse rule. Every failure, the collector's replay and
// capacity checks included, is refused with admin_unverified, the check's
// name (Refusal.Check) and a fixed detail naming only the check
// (AdminRefusal): no reply to an unsigned or mis-bound request depends on
// any stored secret. The node's C8 record of the reply names the check
// (A1). Admin keys are pinned in the
// collector's own configuration out of band; one key speaks for one
// person, and its ID is derived from it (AdminKeyID).
//
// What stays possible: the node can drop or delay a request, and an
// administrator can still learn equality through the reuse rule, at the
// install budget's rate; the administrator could install any secret anyway.
//
// # The node kinds and the repeat answer
//
// The node holds no admin key and verifies no signature: it relays an
// administrator's signed file to the collector unchanged and acts on its own
// part (the node kinds, and its side of an asset clear) only after the
// collector accepts (A5's design, docs/phase3/A5-signed-admin-files.md). From
// 0.5 every accepted reply to an admin-signed request names what the
// collector verified (CollectorReply.Admin): the key, the person, the nonce
// and the SHA-256 of the payload bytes. CollectorReply.AdminAcceptance is the
// node's check that a reply accepts exactly the bytes it sent.
//
// A reply can be lost after the collector has accepted and spent the nonce,
// and the node sends the same file again. Up to 0.4 that resend is refused
// as a replay, so a node part never ran. From 0.5 the collector keeps, for
// each nonce it spent on an accepted request and until that nonce expires,
// the payload's SHA-256 and the decision's collector_seq, in the same store
// as the nonce, under the same bound (MaxAdminNonces), and for exactly as
// long. The same nonce with byte-identical payload bytes, which must still
// pass every check in VerifyAdminRequest, is accepted again with RepeatOf
// naming the first decision's collector_seq, and the collector does
// nothing again. The repeat reply takes its own collector_seq like any
// other, so the node keeps one rule, that each reply is numbered above the
// last one it saw (A1 on #184), and its C8 record of the repeat names
// repeat_of. Any other payload with a spent nonce is
// refused as a replay, as before, so the answer tells a sender nothing it
// did not already hold: only a sender with the exact signed bytes gets it.
// A request refused after its nonce was spent is not repeated: its resend
// is refused as a replay. Only requests stamped 0.5 or later get the
// repeat answer or Admin (AnswersRepeat); an older reader decodes replies
// strictly and gets what a 0.4 collector replied. After the request
// expires, a resend is refused with window, and the administrator signs it
// again: each node kind, and the collector's side of an asset clear, is
// idempotent.
//
// # Collector sequence
//
// The collector numbers every event it reports to the node: each reply to a
// request, and each session, credential and register event of a run. The
// number (collector_seq) starts at 1, rises by one per event, and is kept in
// the durable collector state. The node writes the C8 record of each such
// event with the same number (C7-A5-2). The node writes these records, not
// the collector, so a node that left one out would otherwise go unseen;
// audit.VerifyCollectorSeq turns that omission into a gap. A reply without a
// collector_seq is not accepted (CollectorReply.Accepted).
//
// The residual is stated plainly. A compromised main process can install,
// replace, revoke, suspend and clear credentials, and ask for runs. Whether
// those actions are audited depends on the node writing the records, because
// the node holds the audit store; collector_seq exposes a record the node
// leaves out once the collector reports a later number, but cannot restore
// it. The compromised process cannot read a stored secret, send a raw line,
// or use a credential outside its binding.
//
// # Versions
//
// A reader accepts every minor of major 0 (AcceptsContract,
// contracts/README.md), and requests stay strict. A request stamped with
// a minor older than its kind is refused as invalid: asset.clear_suspension
// needs 0.2. Replies are decoded strictly too, so the collector answers a
// request in its own minor (Refusal.ForRequest): a request stamped before
// 0.3 gets asset_not_enrolled for a suspended asset, as 0.2 collectors
// replied, and no suspension field. A request stamped before 0.4 gets
// principal_not_permitted in place of admin_unverified. AdminSigned needs
// 0.4. The node kinds need 0.5, and so do the repeat answer and
// CollectorReply.Admin, and a reply stamped before 0.5 that carries either
// is invalid (CollectorReply.Validate). The admin payload's format stays
// otsec.authz.admin-request/0.4, and the signing prefix names
// otsec.authz/0.4, so a 0.4 request verifies unchanged; a 0.4 reader
// refuses a node body in the payload as a payload error. The labels bound into the sealing (the seal AAD and the HKDF
// info, both "otsec.authz/0.1 ...") are fixed byte strings, not the
// contract version, and do not change with it.
//
// # What it leaves out
//
//   - Engineering access and device-write operations (Phase 4). No operation
//     class for device writes exists in 0.1.
//   - The central enrollment protocol and how admins authenticate to the main
//     process (deferred).
//   - The sealing algorithm's implementation and the Windows key storage
//     implementation (Phase 2). docs/phase1/A3-credential-design.md specifies
//     them: a key scoped to the collector's service SID, never machine-scope
//     DPAPI (ADR-0007 item 4).
//
// # Concepts imported from other contracts
//
// The node ID pattern comes from contracts/node (D1-1) and the register
// envelope from C3. Asset ID and endpoint ID (C1) and the operation ID rule
// (C3) are copies of their owners' patterns, marked TODO(C1) and TODO(C3):
// asset IDs are C1 lowercase UUIDs.
//
// # Requirements and threat-model entries served
//
// R2 (separation of monitoring and engineering privilege), R5.7 (no
// unrestricted CLI), TB3, TB4, AP-1, AP-3, AP-4, AP-7, AP-13, AP-14, AP-15,
// AP-23, AP-27, HR-1, HR-5, HR-8, SC-2, SC-5, SC-6, SC-18, and V-S11.
package authz
