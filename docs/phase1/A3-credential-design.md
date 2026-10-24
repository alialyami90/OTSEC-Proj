# Device credential design for a site node

Owner: A3. Reviewers: A6 (closes B-04), A5 (Windows runtime), A2 (device behaviour). Brief: P1-A3 in [../agent-handoffs.md](../agent-handoffs.md). Contract: C7 `otsec.authz/0.1` in [contracts/authz](../../contracts/authz/). Status: design for review, 2026-10-24.

This document says how a site node holds the device passwords it needs to collect SER, who can put them there, how they are used, rotated, suspended and revoked, and what remains exposed. It closes B-04 once A6 has reviewed it. It serves AP-1, AP-2, AP-25, C-12, C-17, HR-1 and V-S11.

**Evidence.** Everything here is design. The C7 types and checks are implemented and tested (`go test ./contracts/authz`). Nothing has run on a Windows site image. The Windows mechanisms in section 3 are `[doc]` from Microsoft documentation or `[inferred]`, and each one has a test in section 10 that has to pass on the real image before the claim stands.

## 1. What the node holds, and why it is a risk

For the slice, the node holds one Level 1 password per SEL-751, sent over Telnet. On SEL relays, Level 1 is the lowest level that permits `SER` and `SHO`, and a password is often shared by many relays (AS-2, HR-1). Anyone who gets that password can read every relay that shares it at Level 1, and can try to elevate. So the store is a direct path into IEDs (Q7, C-12). The design aims for four things:

- the process that talks to users and the network never holds a secret;
- a secret can be used only for the asset, node, transport and access level it was installed for;
- a secret never appears in evidence, events, audit, logs or crash output;
- every install, use, suspension and revocation is audited.

## 2. Two processes, two accounts

| | Node service | Collector service |
| --- | --- | --- |
| Windows account | Virtual service account `NT SERVICE\otsec-node` | Virtual service account `NT SERVICE\otsec-collector` |
| Holds | The store (C5), the API and UI, policy, schedules, audit | The credential store, the device transport, the register package (C3) |
| Talks to devices | No | Yes, only through register operations |
| Can read a secret | Never | Yes, inside the transport's auth phase |

The node asks the collector to do things only through the C7 IPC (`DecodeRequest`): `run`, `credential.install`, `credential.revoke` and `credential.clear_suspension`. No request kind carries a raw line, a register change or a plaintext secret, and unknown fields are rejected. The collector checks every `run` against its own verified register (`RunBody.ValidateAgainst`): the operation must be invocable, read-only and in the operate phase, and its parameters must render through `Matcher.Render`. The collector's SID is not in the store's ACL, and the node's SID is not in the credential store's ACL (C5-A3 section 4).

## 3. Storage on Windows

**The key.** The credential store is encrypted with a key only the collector account can use. Two options are allowed, in this order:

1. **A TPM-backed key** in the Microsoft Platform Crypto Provider, non-exportable, whose ACL names only `NT SERVICE\otsec-collector`. `[doc]` for the provider. Whether a virtual account's SID can be set on a Platform Crypto Provider key ACL is `[inferred]`, and is test T-2.
2. **User-scope DPAPI** under the collector's virtual account (`CryptProtectData` without `CRYPTPROTECT_LOCAL_MACHINE`). `[doc]`. A virtual account has no password, so its DPAPI master key is protected by the machine's system DPAPI secret. That means SYSTEM and administrators can recover it, which is the residual in section 9. Other non-admin accounts cannot. `[inferred]`, test T-1.

**Never machine-scope DPAPI** (`CRYPTPROTECT_LOCAL_MACHINE`), because any process on the node can decrypt it (AP-1).

**The file.** The store is one file under `%ProgramData%\OTSEC\collector\credentials\`. That directory has a protected DACL with inheritance turned off. It grants full control to `NT SERVICE\otsec-collector`, plus SYSTEM and Administrators, which Windows always allows anyway. `%ProgramData%` grants Users read and create by default, so the DACL must be protected (test T-3).

**The record.** Each entry holds:

- the C7 `CredentialRef`: id, asset, node, transport, purpose, access level, downstream security label, plaintext scope, version, created by, created at;
- the state (`CredentialStatus`);
- the secret encrypted with AES-256-GCM under the store key, with `SealAAD(ref)` as additional data.

The AAD binds the ciphertext to its reference. A ciphertext copied onto another reference, another asset, another version or another access level does not decrypt.

## 4. Installing a credential

Only a human with the `admin` role installs a credential (`credential-write`, `ValidateRoleSet`). The secret is sealed on the admin's own machine to the collector, so the node service relays ciphertext it cannot open.

1. **The collector's install key.** At first start, the collector creates an X25519 key pair. The private key is kept under the store key. The node publishes the public key and its key ID. The collector also writes the key's fingerprint to the Windows Event Log, under its own event source, and to the local console of the install tool.
2. **Sealing.** The admin's client checks that fingerprint against the one recorded at commissioning, then seals the secret with `x25519-hkdf-sha256-aes256gcm` (`SealedSecret`). The AAD is `SealAAD(ref)`. The client can be a small CLI or a browser page using WebCrypto X25519; Phase 2 chooses which. Either way, the node's API never receives the plaintext.
3. **The request.** The node sends `credential.install` with the `CredentialRef` and the `SealedSecret`. `created_by` must be the requesting human (`CollectorRequest.Validate`). The node writes the C8 `collector.request` record first (audit before act, C5-A3-3).
4. **Checks in the collector,** in this order. Any failure refuses the install and keeps nothing:
   - The reference is consistent (`CredentialRef.Validate`). A plaintext transport requires the `plaintext-unauthenticated` label and the `lab-only` scope, and any other transport must have no scope.
   - The asset is enrolled on this node, and its C1 endpoint for that transport has the same downstream security label and, for plaintext, an acknowledgement with the same scope. Otherwise the result is `credential_mismatch`.
   - The secret decrypts.
   - The secret passes `ValidateSecret` against the family's policy:
     - printable ASCII only;
     - within the family's length bounds;
     - only characters in the family's allowed set;
     - not a line that any register entry or the deny corpus would match (C-17).
     Errors never include the secret (`secret_rejected`).
   - **The reuse rule** (section 6).
5. The collector stores the entry, wipes the buffers it controls, and writes `credential.install` (C8) with the reference and version, never the secret.

**Residual at first install.** A node service that is already compromised when the collector key is first published could substitute its own public key and read the next secret sealed to it. Checking the fingerprint against the commissioning record closes this only if the admin really compares it. Phase 2 makes the client refuse to seal without a pinned fingerprint.

## 5. Using a credential

The collector resolves a secret only for a `run` it accepted, and only inside the transport:

- **Bound use.** The run's asset, node and transport, and the access level the register operation needs, must equal the reference's. Otherwise the run is refused with `credential_mismatch`. For SEL, the reference's level is 1, the lowest level that permits the approved operations (C-12). No credential for Level 2 or above can be installed with purpose `collect-readonly`.
- **The prompt-gated slot** (AP-2, C-17). The transport opens the credential slot only right after the documented `Password: ?` prompt that follows `ACC`. If `ACC` reaches `=>` without a prompt, no secret is sent, the session is closed, and the credential is suspended with `password-prompt-absent` (AP-23).
- **Redaction** (HR-3). Bytes the platform sends during authentication are replaced in the transcript by a marker with position, length and "secret sent". The marker holds no hash or other derivative of the secret. Any echoed password characters are redacted the same way.
- **One attempt.** There is one `ACC` and one password per session. A wrong password suspends the credential with `auth-failed`, and the transport disconnects without `QUI`. Three wrong passwords would pulse `SALARM` on the relay.
- **The failed-auth floor.** There is at most one failed authentication per asset per 15 minutes *(proposed)*, whatever the requests say. A request inside the floor is refused with `rate_limited`. This keeps a compromised node service from cycling install, clear and run fast enough to drive the relay's alarm contact.
- **Identity after login** (C1-A3-5). If the serial number in the SER header differs from the declared one, the password has gone to a device that is not the bound one. The credential is suspended with `identity-mismatch`, no event is created from that session, and the transcript is kept as evidence.
- Each use is recorded as C8 `credential.use`, with the reference, version, transport and downstream security label.

## 6. Reuse of one secret across assets

SEL sites often share one Level 1 password across relays (HR-1). The platform cannot change that, but it can make it visible and keep it from spreading.

- At install, the collector compares the new secret with every stored secret. It uses HMAC-SHA-256 under a key derived from the store key, so no comparison value ever leaves the collector.
- **Refused:** a secret whose `plaintext_scope` is `lab-only` that equals a stored secret without that scope, or the reverse. A lab Telnet password can never become a production one by being typed in again. This is the brief's rule that the slice credential must not be accepted for a device outside the slice.
- **Allowed but labelled:** the same secret on several assets with the same scope. The collector reports the number of assets that share it. The asset view shows "credential shared with N assets", and the label is recorded in audit at install.

## 7. Rotation, revocation and suspension

The platform never changes a password on a device. That is an engineering action done outside the platform. **Rotation** means that, after the relay's password has been changed, an admin installs a new version for the same reference. The old version is revoked with reason `rotated` and its ciphertext is destroyed when the new version is stored. A run already under way finishes with the version it started with.

**Revocation** (`credential.revoke`) is terminal. Its reasons are `rotated`, `compromised`, `asset-decommissioned` and `operator`. The ciphertext is destroyed, and the reference stays for audit.

**Suspension** stops use until it is cleared. The reasons are C1's names, limited to cases where the password was sent or may have been:

| Reason | Raised when | Cleared by |
| --- | --- | --- |
| `auth-failed` | The device rejected the password. | An admin, with `credential.clear_suspension`, after checking the relay. |
| `password-prompt-absent` | `ACC` reached a prompt without asking for a password (D26, AP-23). | An admin, after the jumper or password setting has been checked. |
| `unexpected-access-level` | The first prompt was already elevated (D18). | An admin. |
| `identity-mismatch` | The serial number differed after login (C1-A3-5). | **Not clearable on the same version.** Only a new version (rotation), or re-commissioning the asset with a declared serial recorded after the suspension. Otherwise the result is `credential_unusable`. |
| `operator` | An admin suspended it. | An admin. |

`language-not-english` and `firmware-not-allowlisted` are found in the probe phase, before `ACC`. They suspend the asset (C1), not the credential, because no password was sent. Every suspension, clearing and revocation is a C8 record. Clearing and revoking need a human `admin`.

## 8. Central and distributed deployment

0.1 has no central enrollment (an exclusion in the brief). The design keeps the route open without changing the store. Central would hold `CredentialRef`s and relay `SealedSecret`s sealed by the admin's client to the target node's collector key, so it would never be able to open them (AP-1). One collecting node per asset (A1 D1-3) means a credential lives on exactly one node. Moving collection is a re-install on the new node plus a revocation on the old one, recorded as `asset.collector_assign`.

## 9. What remains exposed

| Residual | Why it remains | Where it is recorded |
| --- | --- | --- |
| A local administrator, or SYSTEM, can act as the collector and read every secret. | Windows cannot keep secrets from the node's own administrators. Compromise of a node by an admin equals compromise of its credentials. | AP-1. The hardening of ADR-0007 item 9 applies, and AS-7 gives a dedicated machine. |
| Telnet sends the password in clear text to anyone reading the station LAN. | SEL ASCII over Telnet has no encryption. Accepted by the owner for the lab slice only, and the label is visible on every endpoint, credential and audit record. | ADR-0005, C1 `doc.go`, `PlaintextLabOnly`. |
| A compromised node service can install, replace, revoke, suspend or clear credentials, and request runs. | It holds the admin's session. It still cannot read a stored secret, send a raw line, or use a credential outside its binding. Each such action is audited, and the failed-auth floor limits alarm-cycling. | AP-14, AP-17. |
| First-install key substitution by a node service that is already compromised. | Section 4. | This document; Phase 2 client pinning. |
| Go cannot guarantee that every copy of a secret is wiped from memory. The garbage collector can copy buffers. | A language limit. The collector keeps secrets in byte slices it wipes, never in strings, and holds them for as short a time as it can. | V-S11 crash-output check. |
| Crash dumps of the collector could contain a secret. | Windows Error Reporting writes dumps by default. | Phase 2: exclude the collector from WER dumps and disable local dumps for it (test T-5). |

## 10. Tests for A6

C7 unit tests that already pass:

- `TestNoSecretFields`: no C7 type has a field that can hold a plaintext secret;
- `TestGoldenRequests`: unknown fields, raw lines, a secret inside a reference, wrong principals, malformed and oversize requests are each refused with their own code;
- `TestRunAgainstRegister`: session-control lines, deny rules and probe-only operations are refused;
- `TestSecretPolicy`;
- `TestSealAADBindsReference`;
- `TestCredentialStatus`;
- `TestRegisterPackageVerification`.

Tests that need the Windows site image (H-14 style) or the slice:

| ID | Test | Pass |
| --- | --- | --- |
| T-1 | Seed a canary secret. From another service account, and from an interactive non-admin user, try to read the store file and decrypt it. | Both fail. |
| T-2 | Create the TPM key with an ACL naming the collector's virtual account, then use it from another account. | Creation works, and use from the other account fails. If creation fails, use the DPAPI option and record the result. |
| T-3 | List the effective ACLs of the credential and store directories, including files created at runtime. | Only the listed principals appear. Nothing is inherited from `%ProgramData%`. |
| T-4 | Copy a ciphertext onto another reference, asset, version or access level, then run. | Decryption fails, and the run is refused with `credential_unusable`. |
| T-5 | Crash the collector during authentication. | No dump is written, or the dump scan finds no canary. |
| T-6 | Install a `lab-only` secret, then install the same secret without that scope. | The second install is refused. |
| T-7 | Run against a simulator with the bypass jumper set, then with a wrong password, then with an identity mismatch. | No secret is sent in the first case. The credential is suspended with the matching reason in each case. `clear_suspension` on `identity-mismatch` is refused. |
| T-8 | V-S11: run the full slice with canary credentials. | Zero occurrences anywhere outside the store. |
| T-9 | Two failed authentications on one asset inside 15 minutes. | The second request is refused with `rate_limited`, before any connection. |
