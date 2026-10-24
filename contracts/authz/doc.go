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
//   - A credential is bound to one asset, node, transport and access level. A
//     run whose asset, node or transport differs from its reference, or whose
//     plaintext scope differs from the scope of the C1 endpoint's
//     acknowledgement, is refused with credential_mismatch (C1-A3-3).
//   - At most one failed authentication per asset per 15 minutes (proposed),
//     whatever the requests say. A request inside that floor is refused with
//     rate_limited before any connection, so a compromised main process cannot
//     cycle install, clear and run fast enough to drive the relay's alarm
//     contact (SALARM after three wrong passwords).
//   - Suspend reasons are C1's names (SuspendReason). identity-mismatch means
//     the password went to another device: it cannot be cleared on the same
//     version (ClearableInPlace), only by rotation or re-commissioning.
//   - Audit before act (A1 D1-11). The main process sends a request only after
//     its C8 collector.request record holds a C5 receipt. With a full or
//     failed audit store, no request is sent, so collection that uses a
//     credential stops; passive Syslog intake does not.
//
// The residual is stated plainly. A compromised main process can install,
// replace, revoke, suspend and clear credentials, and ask for runs, all of
// them audited. It cannot read a stored secret, send a raw line, or use a
// credential outside its binding.
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
// Asset ID (C1), node ID (C4), operation ID and the register envelope (C3) are
// not defined here. Until those packages merge, this package checks them
// against the provisional patterns marked TODO(C1), TODO(C3) and TODO(C4).
//
// # Requirements and threat-model entries served
//
// R2 (separation of monitoring and engineering privilege), R5.7 (no
// unrestricted CLI), TB3, TB4, AP-1, AP-3, AP-4, AP-7, AP-13, AP-14, AP-15,
// AP-23, AP-27, HR-1, HR-5, HR-8, SC-2, SC-5, SC-6, SC-18, and V-S11.
package authz
