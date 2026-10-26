# Device credential design for a site node

Owner: A3. Reviewers: A6 (closes B-04), A5 (Windows runtime), A2 (device behaviour). Brief: P1-A3 in [../agent-handoffs.md](../agent-handoffs.md). Contract: C7 `otsec.authz/0.1` in [contracts/authz](../../contracts/authz/). Status: design for review, 2026-10-24; revised the same day for the A2, A5 and A6 reviews (`docs/phase1/reviews/C7-A2.md`, `C7-A5.md`, `C7-A6.md`).

This document says how a site node holds the device passwords it needs to collect SER, who can put them there, how they are used, rotated, suspended and revoked, and what remains exposed. It closes B-04 once A6 has reviewed it. It serves AP-1, AP-2, AP-25, C-12, C-17, HR-1 and V-S11.

**Evidence.** Everything here is design. The C7 types and checks are implemented and tested (`go test ./contracts/authz`). Nothing has run on a Windows site image. The Windows mechanisms in section 3 are `[doc]` from Microsoft documentation or `[inferred]`, and each one has a test in section 11 that has to pass on the real image before the claim stands.

## 1. What the node holds, and why it is a risk

For the slice, the node holds one Level 1 password per SEL-751, sent over Telnet. On SEL relays, Level 1 is the lowest level that permits `SER` and `SHO`, and a password is often shared by many relays (AS-2, HR-1). Anyone who gets that password can read every relay that shares it at Level 1, and can try to elevate. So the store is a direct path into IEDs (Q7, C-12). The design aims for four things:

- the process that talks to users and the network never holds a secret;
- a secret can be used only for the node, asset, endpoint, transport and access level it was installed for;
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

**Host rules for Phase 2** (A5's W-1 to W-4, `[doc]` unless marked; they do not change the contract):

- **W-1. The IPC is a local named pipe, and each end checks the other.** The collector creates the pipe with `FILE_FLAG_FIRST_PIPE_INSTANCE` and `PIPE_REJECT_REMOTE_CLIENTS`, and an explicit DACL that grants read and write to `NT SERVICE\otsec-node` only, plus SYSTEM. The default pipe DACL gives Everyone read access, so it is never used. The collector checks the client's token at identification level (`ImpersonateNamedPipeClient` at `SecurityIdentification`, then `RevertToSelf`) and refuses any SID but the node's. The node checks the server: it gets the server process with `GetNamedPipeServerProcessId`, checks that its token holds `NT SERVICE\otsec-collector`, and otherwise sends nothing. Without that check, a local process that created the pipe name while the collector was stopped could not get a secret (installs are sealed to the collector's key), but it could answer `run` requests with forged results that the node would commit as evidence.
- **W-2. Neither service keeps `SeImpersonatePrivilege`.** Windows grants it to every service by default, and it is a known route to SYSTEM, which can read every credential. Both services set a required-privileges list (`SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO`) without it, so the service control manager removes it from the token. That this still allows the identification-level check in W-1 is `[inferred]` and is tested.
- **W-3. Only the collector can reach devices.** Windows Firewall rules matched by service SID allow outbound traffic to the device subnets and ports (Telnet 23 for the slice) for `otsec-collector` only, and block it for `otsec-node` and every other program. A compromised node service then cannot open a Telnet session to a relay itself. Inbound Syslog to the node is unaffected.
- **W-4. The installer creates the directory tree.** It creates `%ProgramData%\OTSEC`, `…\store` and `…\collector\credentials` itself, with protected DACLs and owner Administrators. If any of them already exists with another owner or an unexpected ACE, the installer stops: a non-admin user who pre-created the folder would own it and could rewrite its DACL (`[inferred]` from the default `%ProgramData%` ACL). Service binaries live under `%ProgramFiles%`, never under `%ProgramData%`.

## 3. Storage on Windows

**The key.** The credential store is encrypted with a key only the collector account can use. Two options are allowed, in this order:

1. **A TPM-backed key** in the Microsoft Platform Crypto Provider, non-exportable, whose ACL names only `NT SERVICE\otsec-collector`. `[doc]` for the provider. Whether a virtual account's SID can be set on a Platform Crypto Provider key ACL is `[inferred]`, and is test T-2.
2. **User-scope DPAPI** under the collector's virtual account (`CryptProtectData` without `CRYPTPROTECT_LOCAL_MACHINE`). `[doc]`. A virtual account has no password, so its DPAPI master key is protected by the machine's system DPAPI secret. That means SYSTEM and administrators can recover it, which is the residual in section 10. Other non-admin accounts cannot. `[inferred]`, test T-1.

**Never machine-scope DPAPI** (`CRYPTPROTECT_LOCAL_MACHINE`), because any process on the node can decrypt it (AP-1).

**The file.** The store is one file under `%ProgramData%\OTSEC\collector\credentials\`. That directory has a protected DACL with inheritance turned off. It grants full control to `NT SERVICE\otsec-collector`, plus SYSTEM and Administrators, which Windows always allows anyway. `%ProgramData%` grants Users read and create by default, so the DACL must be protected (test T-3).

**The record.** Each entry holds:

- the C7 `CredentialRef`: id, asset, node, C1 endpoint, transport, purpose, access level (the register's level token, `1` for SEL Level 1), downstream security label, plaintext scope, version, created by, created at;
- the state (`CredentialStatus`);
- the secret encrypted with AES-256-GCM under the store key, with `SealAAD(ref)` as additional data.

The AAD binds the ciphertext to its reference. A ciphertext copied onto another reference, asset, node, endpoint, version or access level does not decrypt.

**Durable collector state** (C7-A5-3). Beside the credentials, the collector keeps the time of the last unconfirmed authentication per asset and its collector sequence counter (section 5). It flushes both before it replies to the run they belong to. If it cannot read or flush them, it refuses every run with `collector_state_unavailable`, so a restart or a lost write cannot reopen the failed-auth floor or reuse a sequence number.

## 4. Installing a credential

Only a human with the `admin` role installs a credential (`credential-write`, `ValidateRoleSet`). The secret is sealed on the admin's own machine to the collector, so the node service relays ciphertext it cannot open.

1. **The collector's install key.** At first start, the collector creates an X25519 key pair. The private key is kept under the store key. The node publishes the public key and its key ID. The collector also writes the key's fingerprint to the Windows Event Log, under its own event source, and to the local console of the install tool.
2. **Sealing.** The admin's client checks that fingerprint against the one recorded at commissioning, then seals the secret with `x25519-hkdf-sha256-aes256gcm` (`SealedSecret`). The AAD is `SealAAD(ref)`. The client can be a small CLI or a browser page using WebCrypto X25519; Phase 2 chooses which. Either way, the node's API never receives the plaintext.
3. **The request.** The node sends `credential.install` with the `CredentialRef` and the `SealedSecret`. `created_by` must be the requesting human (`CollectorRequest.Validate`). The node writes the C8 `collector.request` record first (audit before act, C5-A3-3).
4. **Checks in the collector,** in this order. Any failure refuses the install and keeps nothing:
   - The reference is consistent (`CredentialRef.Validate`). A plaintext transport requires the `plaintext-unauthenticated` label and the `lab-only` scope, and any other transport must have no scope. Serial is refused in 0.1: a serial port keeps its session state and nothing closes it, so serial waits for a lab capture of the port's behaviour (A2's C7 review).
   - The access level is one the verified register reaches (`CheckAccessLevel`, C7-A6-1): an auth-phase session line must take level 0 to it, and a read-only operation must need it. For the SEL-751 that is `1` only; `2`, `2AC` and `0` are refused with `credential_mismatch`.
   - The asset is enrolled on this node, and the named C1 endpoint belongs to it, uses that transport, and has the same downstream security label and, for plaintext, an acknowledgement with the same scope. Otherwise the result is `credential_mismatch`.
   - The secret decrypts.
   - The secret passes `ValidateSecret` against the family's policy and its verified register package:
     - printable ASCII only;
     - within the family's length bounds;
     - only characters in the family's allowed set, matched against the whole secret; for the SEL-751, 1 to 12 characters in `[!-~]`, so no space (S22 Table 7.54, A2's C7 review item 7). The policy is `authz.SecretPolicies["sel-751"]` until A2's C1 capability profile carries it (D1-18); it never comes from a request;
     - not a line the register would match in any case, allowed or denied, and not starting with the mnemonic of any operation, session line or deny rule (the first three characters for SEL, which reads `QUIT` as `QUI`). A6's probe found `quiet123`, `accent12`, `serial99` and `close!` passing the earlier check; all are refused now (C7-A6-3, C-17).
     Errors never include the secret (`secret_rejected`).
   - **The reuse rule** (section 6).
5. The collector stores the entry, wipes the buffers it controls, and writes `credential.install` (C8) with the reference and version, never the secret.

**Residual at first install.** A node service that is already compromised when the collector key is first published could substitute its own public key and read the next secret sealed to it. Checking the fingerprint against the commissioning record closes this only if the admin really compares it. Phase 2 makes the client refuse to seal without a pinned fingerprint.

## 5. Using a credential

The collector resolves a secret only for a `run` it accepted, and only inside the transport:

- **Bound use** (`CredentialRef.Binds`). The run's node, asset, C1 endpoint and transport, and the access level the register operation needs, must equal the reference's, and a plaintext credential needs the endpoint's acknowledgement with the same scope. Otherwise the run is refused with `credential_mismatch`. For SEL, the reference's level is `1`, the lowest level that permits the approved operations (C-12). A run of a level 0 operation (`sel.id`, sent before `ACC`) carries no credential reference, and a run of any other operation must carry one (C7-A2-5).
- **What the platform cannot see.** It cannot tell what a password opens. If an admin types the Level 2 password into a level `1` credential, it is caught only if the relay rejects it at `ACC`, which suspends the credential with `auth-failed`. How the relay answers that is a lab question (H-15). The egress gate still never sends `2AC`, so the session cannot rise above Level 1 whatever the password.
- **The prompt-gated slot** (AP-2, C-17). The transport opens the credential slot only right after the documented `Password: ?` prompt that follows `ACC`, and **at most once per session** (C7-A6-2). After a wrong password the relay asks `Password: ?` again, up to three times (S22 p. 7.33). That second prompt is `auth-failed`: the slot sends nothing, the session ends and the credential is suspended. If `ACC` reaches `=>` without a prompt, no secret is sent, the session ends, and the credential is suspended with `password-prompt-absent` (AP-23).
- **Redaction** (HR-3). Bytes the platform sends during authentication are replaced in the transcript by a marker with position, length and "secret sent". The marker holds no hash or other derivative of the secret. Any echoed password characters are redacted the same way.
- **One attempt.** There is one `ACC` and one password per session. A wrong password suspends the credential with `auth-failed`. Three wrong passwords would pulse `SALARM` on the relay.
- **`QUI` on every exit after `ACC`** (C7-A6-2). A Telnet session closed without `QUIT` keeps its level until `TIDLE` expires (S22 p. 7.16), and a new connection might inherit it. So once `ACC` has succeeded, every way out sends `QUI` before the TCP close: the normal end, an identity mismatch, a parse failure, a timeout and any other error. If `QUI` cannot be sent, the session-close audit record has outcome `failed` and reason `qui_not_sent`. After a failed `ACC` the session is not elevated and `QUI` is not needed.
- **An elevated first prompt** (D18) is not a credential fault. No password was sent, and the state clears when `TIDLE` expires. C2 refuses the session (`refused.session_elevated`) and the credential stays usable (C7-A2-2).
- **The failed-auth floor** (`FailureFloor`, C7-A2-1). A session closed without `QUI` after a wrong password stays at its pending password prompt until `TIDLE` expires, so a new session inside `TIDLE` could land on that prompt, and its first line would be the second attempt. The floor is therefore longer than `TIDLE`: `TIDLE` plus one minute, where `TIDLE` is the port's value last read with `SHO P 1`, or 31 minutes (the largest `TIDLE`, 30, plus one) when it is unknown. The floor starts whenever `ACC` was sent and no Level 1 prompt (`=>`) confirmed the login: a wrong password, but also an `ACC` that is never answered, and a timeout, a closed connection or a collector crash anywhere between `ACC` and the prompt, since the relay may still be at `Password: ?` (A2's re-check). Whether the relay keeps a pending `Password: ?` across connections is unknown (A6 H-15 (a)). If it does, the next session's first byte, even the wake line end, would be a wrong password. That is why the floor starts at `ACC`, not at the password (D1-20 as amended for A6 C2 change 14). The cost is a 31-minute wait after any `ACC` that times out. The collector writes the attempt time to its durable state before the transport sends `ACC`, and clears it only when `=>` is received. A request inside the floor is refused with `rate_limited` before any connection. Because the state is durable, a restart does not reopen the floor, and a time later than the clock counts as inside it. When A2's C1 capability profile merges (D1-18), the maximum `TIDLE` comes from its `session_limits`; a `TIDLE` read from the relay only ever shortens the floor, never below that value plus one minute. This keeps a compromised node service from cycling install, clear and run fast enough to drive the relay's alarm contact.
- **Identity after login** (C1-A3-5, C7-A6-6). If the serial number differs from the declared one, the password has gone to a device that is not the bound one. The credential is suspended with `identity-mismatch`, no event is created from that session, and the transcript is kept as evidence. The check runs in every authenticated session, not only in SER runs. For the SEL-751, the only documented source of the serial number is the SER report header: the `ID` output lists FID, BFID, CID, DEVID, DEVCODE, PARTNO, CONFIG and SPECIAL, but no serial number (the C3 register's `sel.id` notes). A session that runs another level 1 operation therefore also reads the identity source before its output is released. If A2 finds a cheaper source in S22, the register names it and this rule uses it.
- **Collector sequence** (C7-A5-2). The collector numbers every event it reports: each reply, and each session, credential and register event. The node writes the C8 record of each with the same `collector_seq`, and `audit.VerifyCollectorSeq` finds a number with no record. The node holds the audit store, so this detects a record it leaves out; it cannot restore one.
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
| `unexpected-access-level` | `ACC` and the password reached a prompt other than the credential's level. An elevated first prompt is not this reason (section 5). | An admin. |
| `identity-mismatch` | The serial number differed after login (C1-A3-5). | **Not clearable on the same version.** Only a new version (rotation), or re-commissioning the asset with a declared serial recorded after the suspension. Otherwise the result is `credential_unusable`. |
| `operator` | An admin suspended it. | An admin. |

`password-prompt-absent` sends no password, but the relay's password setting has changed, so the credential stays suspended until an admin has checked it. `language-not-english` and `firmware-not-allowlisted` are found in the probe phase, before `ACC`. They suspend the asset (C1), not the credential, because no password was sent. Every suspension, clearing and revocation is a C8 record. Clearing and revoking need a human `admin`.

## 8. Central and distributed deployment

0.1 has no central enrollment (an exclusion in the brief). The design keeps the route open without changing the store. Central would hold `CredentialRef`s and relay `SealedSecret`s sealed by the admin's client to the target node's collector key, so it would never be able to open them (AP-1). One collecting node per asset (A1 D1-3) means a credential lives on exactly one node. Moving collection is a re-install on the new node plus a revocation on the old one, recorded as `asset.collector_assign`.

## 9. Node keys for forwarding (C6 TLS references)

C6 targets name two TLS references, `trust_anchor_ref` and `client_credential_ref` (`TODO(A3 node key ref)`). Neither is a C7 `CredentialRef`. A `CredentialRef` is a device password held by the collector, bound to an asset, an endpoint and an access level. Forwarding runs in the node service, and W-3 keeps the collector off every network except the device networks. A node key reference is therefore its own kind:

- **Syntax.** `nodekey_` followed by 8 to 40 lowercase letters or digits, opaque like a credential reference. It names one entry in the node's key register. The register is kept by the node service and lists, for each entry: kind (`tls-client` or `trust-anchors`), the node it is for, the certificate or CA set's SHA-256 fingerprint, a version, who installed it, and when.
- **`tls-client`** (kind `tls-key` in the register, `modules/security/nodekey`, Phase 3).
  - **Where the key lives.** A CNG machine key with its export policy off. It is in the Microsoft Software Key Storage Provider, or the Platform Crypto Provider (TPM) where T-2 shows it works.
  - **Who may use it.** After its certificate request is signed, the key's DACL is set once (D3-7). SYSTEM and Administrators get full control, and `NT SERVICE\otsec-node` gets generic read, which lets it sign. No other account has any right, and the collector service can neither read nor use the key.
  - **Why Administrators are not excluded.** The Software KSP needs read and write on a key to change its DACL or delete it, and it refuses a second DACL change through any handle. This is CI evidence on #157 (`TestCNGRightsProbe`). An administrator can act as SYSTEM in any case. The boundary is that nobody, an administrator included, can export the private key, and that no other account has any right.
  - **How the key is made.** An administrator's elevated tool generates it on the node and publishes a certificate request, never the key, and the central CA signs that request.
- **`trust-anchors`.** A CA set used only for this platform's collectors, or a single collector certificate, optionally with SPKI pins on the target (C6-A3-3). It is public data whose integrity matters: whoever changes it decides which collector's acknowledgements can advance pruning.
- **Who changes them.** Only a human `admin` installs, rotates or removes a node key or a trust-anchor set. The node writes a C8 `policy.apply` record naming the reference, its kind and the fingerprint, and the same applies to every target change (C6-A3-7). Removing the client key of a required or audit target makes that target invalid at load, which raises an alarm. It does not silently fall back to anything.
- **Rotation.** A new version is installed next to the old one, the target is switched to it, and the old version is removed. Certificate expiry is reported as node health 30 days ahead (Phase 2).
- **Contract.** This needs no change to C7 0.1, because C6 holds the references as strings. The `nodekey_` syntax and the key register's record become part of C7 0.2 when Phase 2 implements forwarding. Until then, C6 checks only that the string is present.

## 10. What remains exposed

| Residual | Why it remains | Where it is recorded |
| --- | --- | --- |
| A local administrator can use the node's TLS client key (section 9), though not export it. | The Software KSP needs Administrators' read and write to manage a key, and an administrator can act as SYSTEM in any case (D3-7). Compromise of a node by an admin equals use of its forwarding identity until the certificate is revoked. | Section 9; `TestCNGRightsProbe`. |
| A local administrator, or SYSTEM, can act as the collector and read every secret. | Windows cannot keep secrets from the node's own administrators. Compromise of a node by an admin equals compromise of its credentials. | AP-1. The hardening of ADR-0007 item 9 applies, and AS-7 gives a dedicated machine. |
| Telnet sends the password in clear text to anyone reading the station LAN. | SEL ASCII over Telnet has no encryption. Accepted by the owner for the lab slice only, and the label is visible on every endpoint, credential and audit record. | ADR-0005, C1 `doc.go`, `PlaintextLabOnly`. |
| A compromised node service can install, replace, revoke, suspend or clear credentials, and request runs. | It holds the admin's session. It still cannot read a stored secret, send a raw line, or use a credential outside its binding. Auditing these actions depends on the node writing the records, because it holds the audit store; `collector_seq` exposes a collector-reported event it leaves out, once the collector reports a later one. The failed-auth floor limits alarm-cycling. | AP-14, AP-17. |
| A Level 2 password typed into a level `1` credential. | The platform cannot see what a password opens. | Section 5; H-15. |
| A release key revoked while a package it signed is active. | On any change to the trust anchors, the collector re-verifies every active register package and drops any that no longer verifies. Collection for that family stops and an alarm is raised (SC-18, C7-A6-7). | `contracts/authz` doc. |
| First-install key substitution by a node service that is already compromised. | Section 4. | This document; Phase 2 client pinning. |
| Go cannot guarantee that every copy of a secret is wiped from memory. The garbage collector can copy buffers. | A language limit. The collector keeps secrets in byte slices it wipes, never in strings, and holds them for as short a time as it can. | V-S11 crash-output check. |
| Crash dumps of the collector could contain a secret. | Windows Error Reporting writes dumps by default. | Phase 2: exclude the collector from WER dumps and disable local dumps for it (test T-5). |

## 11. Tests for A6

C7 unit tests that already pass:

- `TestNoSecretFields`: no C7 type has a field that can hold a plaintext secret;
- `TestGoldenRequests`: unknown fields, raw lines, a secret inside a reference, wrong principals, malformed and oversize requests are each refused with their own code;
- `TestRunAgainstRegister`: session-control lines, deny rules and probe-only operations are refused;
- `TestSecretPolicy` and `TestMnemonicsFromRegister`: secrets checked against the real SEL-751 register, including A6's probe list;
- `TestCheckAccessLevel`: `1` passes, and `0`, `2`, `2AC` and `ACC` are refused;
- `TestBinds` and `TestCredentialRefFields`: node, asset, endpoint, transport, level and acknowledgement scope, the DNS-label node ID, and serial refused;
- `TestFailedAuthFloor`: `TIDLE` plus one minute, 31 minutes when unknown, and a failure time in the future counts as inside;
- `TestReplyFailsClosed`: a reply without `collector_seq` is not accepted;
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
| T-9 | Two failed authentications on one asset inside the floor (`TIDLE` plus one minute). | The second request is refused with `rate_limited`, before any connection. |
| T-9b | Fail once, restart the collector, then ask again inside the floor. Separately, kill the collector after the password is sent and before the prompt, restart it, and ask again. Also kill it after `ACC` is sent and before any reply, restart it, and ask again. | `rate_limited` in all three cases. With the state file unreadable, `collector_state_unavailable`. |
| T-10 | A simulator that answers the password with a second `Password: ?`. | No second secret is sent; the credential is suspended with `auth-failed`. |
| T-11 | After a successful `ACC`, end the session by each path: normal end, identity mismatch, parse failure, timeout. | `QUI` is sent before the TCP close on every path. A forced failure to send it gives a session-close record with `qui_not_sent`. |
| T-12 | Install with a collector key whose fingerprint does not match the commissioning record. | The Phase 2 client refuses to seal. |
| T-13 | W-1: a second process creates the pipe name first. W-2: read each service's token. W-3: TCP connect to a simulator's port 23 from each service. W-4: pre-create `%ProgramData%\OTSEC\store` as a non-admin user, then install. | The node refuses the impostor and commits nothing; no token holds `SeImpersonatePrivilege`; only the collector connects; the installer stops. |
