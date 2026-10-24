// Package authz is contract C7, otsec.authz/0.1: who may ask for what, how
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
//     or a secret. Credential install, revoke and clear-suspension are the only
//     other kinds, and none of them causes device I/O.
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
//     rejects it at ACC (H-12).
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
//   - At most one failed authentication per asset within FailureFloor of
//     the last one (C7-A2-1): TIDLE plus one minute, where TIDLE is the
//     port's idle timeout last read with SHO P 1, or 31 minutes when it is
//     unknown. A new session inside TIDLE could otherwise land on the
//     previous session's pending password prompt, so its first line would be
//     a second attempt. A request inside the floor is refused with
//     rate_limited before any connection, so a compromised main process
//     cannot cycle install, clear and run fast enough to drive the relay's
//     alarm contact (SALARM after three wrong passwords).
//   - Durable collector state (C7-A5-3). The collector keeps the time of the
//     last failed authentication per asset, and its collector sequence
//     counter, in its own store, and flushes both before it replies. A
//     restart therefore does not reopen the floor. A failure time later than
//     the clock counts as inside the floor, so a clock stepped backwards does
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
//   - Audit before act (A1 D1-11). The main process sends a request only after
//     its C8 collector.request record holds a C5 receipt. With a full or
//     failed audit store, no request is sent, so collection that uses a
//     credential stops; passive Syslog intake does not.
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
