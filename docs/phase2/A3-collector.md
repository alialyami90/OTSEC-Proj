# A3: the collector and its IPC (P2-A3)

Owner: A3. Reviewers: A6, A2. Status: PR 1 (IPC) merged in #79; its follow-up (strict names, quarantine) in #82. PR 2 adds the durable collector state and the credential store. Later sections are added as their PRs land.

This note records how the collector side of C7 is built. C7 (`contracts/authz`) defines the messages; this is the implementation around them. The design it follows is [../phase1/A3-credential-design.md](../phase1/A3-credential-design.md) (W-1 to W-4, T-1 to T-12).

## Packages

| Package | What it holds | Who imports it |
| --- | --- | --- |
| `modules/security/collectorwire` | Framing, strict decoding, the run outcome, the two transports and their peer checks, `ServiceSID`. No credential code, no device transport. | `collector`, `collectorclient` |
| `modules/security/collector` | The IPC server, the durable collector state, the credential store; later the run pipeline. Hosts the SEL-751 adapter. | `cmd/otsec-collector` only |
| `modules/security/seal` | Sealing a secret to a collector's install key (`Seal`, which refuses without a pinned fingerprint) and opening it (`Open`). No store, no transport. | `collector`; the admin's sealing client |
| `modules/security/collectorclient` | The node's side: send one request, check the reply and the outcome. | `cmd/otsec`, `platform/node` |

The wire package is separate so the client never imports `collector`: D2-1 forbids the node binary from reaching `modules/security/collector`, and A6's import test checks that transitively.

## Exchange

One connection carries one request. Each frame is a 4-byte big-endian length followed by JSON.

1. The node sends a `CollectorRequest` frame, at most `authz.MaxRequestBytes` (8 KiB).
2. The collector sends a `CollectorReply` frame, at most 4 KiB.
3. Only after an accepted run, the collector sends a `RunOutcome` frame, at most 8 MiB, when the run is over.

Both ends then close. The collector waits up to 5 s for the node to close first, because a pipe server that closes first can discard data the client has not read.

`RunOutcome` is `{wire, invocation_id, result, audit}`:

- `wire` is `otsec.collectorwire/0.1`.
- `result` is the C2 result exactly as the adapter produced it, after the collector ran `Validate`, `CheckLines` and `CheckAgainst` on it.
- `audit` is the list of pending C8 records for the events the collector reports for the run, each with its `collector_seq`. The node writes these records (C7-A5-2), and the collector writes none itself.

A length over the reader's limit is refused before any of the body is read.

## What the server guarantees

- **Strict decoding before any decision.** A request is decoded with `authz.DecodeRequest` before the handler sees it. A field C7 does not define, at any depth, is refused with `unknown_field`. A duplicate key, trailing data or invalid UTF-8 is refused with `malformed`. An oversize frame is refused with `oversize` without its body being read. The server then drains at most 64 KiB, for at most 5 s, so the client can read the refusal. A run asked for by anyone but a schedule is refused with `principal_not_permitted`. All of these refusals go through `Handler.Refuse`, never `Handler.Handle`, so they cannot reach the run pipeline or the device. Tests: `TestFieldOutsideC7RefusedBeforeHandler`, `TestMalformedRequestsRefused`.
- **Every decision is numbered.** Each reply, including a refusal of an undecodable request, carries the handler's next `collector_seq`. A connection that ends before a whole request arrives is not a decision and takes no number (`TestIncompleteRequestTakesNoNumber`).
- **The reply comes before the run, and the run starts only after the reply has been written.** "Written" means the whole frame was accepted by the socket or pipe; it does not prove the node read it. If the reply cannot be written, the work is not started. A node that has no reply cannot record the run, so the run must not happen.
- **Handler bugs fail closed.** The server drops the connection without a reply in two cases: an accepted reply without work, and work with anything other than an accepted run that carries an invocation ID. It also drops the outcome if its invocation ID differs from the reply's (`TestHandlerContractBreachDropsConnection`, `TestOutcomeForAnotherInvocationDropped`).
- **Logs** carry the request ID, status, refusal code and collector_seq only. They never carry a request body, a secret or a device line.

## What the client checks

`collectorclient.Do` validates the request (`req.Validate`) before it dials, so an invalid request is never sent. It then checks the reply against C7:

- the contract;
- the request ID: an empty ID is allowed only on a refusal, meaning the collector could not decode the request;
- the status;
- refusal and invocation ID consistency;
- that an accepted reply has a `collector_seq`.

A failure here is `ErrProtocol`, with no decision. An unknown refusal code is normalised to `refused_unknown`.

For an accepted run, the client checks the outcome:

- The invocation ID matches the reply.
- The result decodes strictly as C2, passes `Validate`, and names the run's invocation, operation and register version.
- Every audit record passes `audit.ValidatePending`, which refuses secret-named and unknown fields, and is an event the collector reports.
- `collector_seq` rises through the records, starting above the reply's own number. Runs on other assets may take numbers in between, so contiguity is checked over the whole chain by `audit.VerifyCollectorSeq`, not here.
- Invocation-scoped records carry the invocation ID as `correlation_id`.
- There is at most one session, with its open and close paired.
- The close record's `transcript_sha256` equals the result's transcript digest.
- A result with any transcript bytes has a session.

`Result.CheckLines`, the "no unauthorized line" oracle (C2 EP-4), runs in the collector before the outcome is sent (PR 3). It also runs on the node whenever the node sets `Client.Register` to return its own verified copy of the register package. If the node sets the hook but holds no package at the run's version, the outcome is `ErrOutcomeUnknown`. Test: `TestCheckLinesOnTheNode`.

A connection that ends before the outcome arrives is `ErrOutcomeUnknown`. It comes with the accepted reply, so the node still audits the decision and records the run as outcome unknown, never as succeeded. It must not treat the run as "nothing happened" either: ACC may have been sent. A retry is safe because the failed-auth floor is written before ACC (D1-20), so a retry is refused with `rate_limited` until the floor has passed.

### An outcome that fails a check is quarantined, never dropped

If an outcome frame arrived but failed any check above, `Do` returns `ErrOutcomeUnknown` together with `ErrOutcomeQuarantined`, and the `Response` carries a `Quarantine` instead of an `Outcome`. Evidence is never silently discarded (brief section 1.4, EP-1; A6 and A1 on #79). The `Quarantine` holds:

- `Raw`: the frame exactly as received;
- `ResultJSON`: the C2 result, when the envelope decoded;
- `Audit`: every record that passes `audit.ValidatePending` on its own, kept even when the failed check was about the records as a set (order, correlation, pairing or digest);
- `Reason`: the check that failed.

A `CheckLines` failure on the node also returns `ErrUnauthorizedLine` and sets `UnauthorizedLine`. By the node's own register, the session put a line on the wire that this run was not allowed to send. This is the safety case.

What the node does with a quarantine is A5's to implement. A3's requirement is:

- Store `Raw` as quarantined evidence. It is never normalized, never forwarded as events, and never treated as a result.
- Write the session records it holds, so the transcript digest reaches the chain.
- Record the run as outcome unknown.
- On `UnauthorizedLine`, raise a safety alarm.

`Reason` can quote the refused line, so it belongs with the evidence, not in an operational log.

**Residual.** A quarantine keeps whatever the collector sent. If the collector were faulty enough to put a secret in a frame, for example in a record field that `ValidatePending` refuses, the quarantined bytes would hold it. Keeping evidence takes priority here, so the collector's own tests carry the burden: T-5 scans every byte the collector writes for the test secret (PR 2 and PR 4).

Tests:
- `TestCheckLinesOnTheNode`: a forbidden line leaves the frame, the transcript and the four session records reachable.
- `TestBadOutcomeIsOutcomeUnknown`: every case keeps the frame.
- `TestLostOutcomeKeepsReply`: when no frame arrives, there is no quarantine.

Tests: `TestReplyBreakingC7Refused` (9 cases), `TestBadOutcomeIsOutcomeUnknown` (13 cases), `TestLostOutcomeKeepsReply`, `TestInvalidRequestNotSent`.

## Transports and peer checks (W-1)

Each end checks the other's operating-system identity before it sends a byte. `Endpoint.Peer` names the identity required of the far end, and there is no "accept anyone": an empty peer is refused.

**Windows** is the production boundary. Evidence class: it compiles (`GOOS=windows go vet`) but has not run, so everything in this paragraph is documented but untested until the PC run (D1-26).

- The pipe is created as `FILE_FLAG_FIRST_PIPE_INSTANCE`, so the collector refuses to start if another process holds the name. It also uses `PIPE_REJECT_REMOTE_CLIENTS`.
- One instance is always kept open, so the name is never free for another process to take.
- The DACL is protected and grants:
  - SYSTEM and the collector's own account full access, which the collector needs to create further instances;
  - the node only read data, write data, read attributes and synchronize. It does not grant `GENERIC_WRITE`, because on a pipe `FILE_APPEND_DATA` is `FILE_CREATE_PIPE_INSTANCE`, which would let the node create a competing instance.
- The collector impersonates the client at identification level (the node opens with `SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION`). It reads the thread token, reverts, and accepts only a token whose user is the node's SID or which holds it as an enabled, non-deny-only group. If `RevertToSelf` fails, the collector panics rather than run on with the client's token.
- The node calls `GetNamedPipeServerProcessId`, opens the process with `PROCESS_QUERY_LIMITED_INFORMATION`, and applies the same token rule for the collector's SID.
- Service SIDs are computed by `ServiceSID`, which is checked against the published SID of `NT SERVICE\TrustedInstaller`, rather than looked up. This way neither side depends on the other service being installed first.

**Linux** is the development and CI platform.

- It uses a Unix socket with `SO_PEERCRED` uid checks on both ends.
- The socket's directory must not be writable by group or others.
- The socket is bound under a private name, set to mode 0660, then hard-linked into place, so it never appears at its address with the umask's mode. The link fails if the address appeared in the meantime.
- A stale socket file is replaced. A socket that still answers is refused, so two collectors never serve one path. A path that is not a socket is refused. `Close` removes the socket.

Other operating systems return `ErrUnsupported`.

Transport tests (`collectorwire/transport_test.go`) run on both Linux and Windows. They cover:

- a round trip;
- a client with another identity refused before it can read;
- a server with another identity refused before the client sends anything;
- an empty or malformed peer refused;
- a second listener on the same address refused;
- `Close` unblocking `Accept`.

## Durable collector state (PR 2)

`collector.State` is one file, `otsec.collector-state/0.1`, that holds `collector_seq` and, per asset, the time of the last unconfirmed authentication and the `TIDLE` last read (design section 3, C7-A5-3, D1-20 as amended).

- **Every change is durable before the method returns.** The new state is written to a temporary file, flushed, renamed over the old one (`MoveFileEx` with `MOVEFILE_WRITE_THROUGH` on Windows) and the directory is flushed. After a crash the file holds the old or the new state, never a mix.
- **A failed write breaks the state.** Every later call returns `ErrStateUnavailable`, which the run pipeline turns into `collector_state_unavailable`, until the collector restarts and reads the file again.
- **The file is created once, at install** (`InitState`). `OpenState` never creates it. A missing, unreadable, oversize or unknown file is `ErrStateUnavailable`, never a fresh state, because a fresh one would reopen every floor and restart `collector_seq` at 1.
- **`NextSeq`** writes the new number before handing it out, so a number is never used twice. A crash after it leaves a gap, which `audit.VerifyCollectorSeq` shows.
- **The floor.** `BeginAuth` records the attempt before `ACC` is sent, and `ConfirmAuth` clears it only on `=>`. `CheckFloor` refuses with `rate_limited` inside `authz.FailureFloor` (`TIDLE` plus one minute, 31 minutes when unknown), and a time later than the clock counts as inside. `SetTIDLE` keeps only 1 to 30 minutes and records anything else as unknown.
- **`FloorGate`** binds the state to one asset for one run, with the seam's `BeforeACC` and `Confirmed`. A failure to clear leaves the floor set and calls `Alarm`. A compile-time assertion checks it against `sel751.FloorGate`.

Tests (`state_test.go`): fail-closed open for ten bad files; `collector_seq` durable across a reopen; the floor with and without `TIDLE` and with the clock set back; `TestFloorSurvivesKill`, where a child process records `BeginAuth` and kills itself, then the parent refuses inside the floor; a failed write breaks the state; the gate and its alarm.

## Credential store (PR 2)

`collector.CredStore` is one file, `otsec.collector-credentials/0.1` (design sections 3 to 7). It holds:

- **The store key**, 32 random bytes, protected for the collector's account. On Windows that is user-scope DPAPI (`CryptProtectData` without `CRYPTPROTECT_LOCAL_MACHINE`, with fixed entropy). On Linux, the development platform, the key is stored as it is (`none-development`), so the file mode is its only protection; Phase 2 credentials there are test values only (D2-5). A store written with the other protection is refused. The TPM option waits on T-2.
- **The install key**, an X25519 key pair. Its private half is encrypted under the store key. Its key ID is derived from the public key (`x25519-` and 16 hex digits of its SHA-256). `Fingerprint` is `sha256:` and the full hex digest, for the Event Log and the install tool's console (PR 4).
- **One entry per credential version:** the `CredentialRef`, its `CredentialStatus`, the secret under AES-256-GCM with `SealAAD(ref)` as additional data, and the reuse tag.

Three keys are derived from the store key with HKDF-SHA256, one each for the records, the install key and the reuse tags. Writes follow the same rules as the durable state: flushed and renamed before returning, a failed write breaks the store, and the file is created once (`InitCredStore`) and never recreated. A missing store would mean a new install key that no admin has pinned.

### Sealing (`modules/security/seal`)

C7 names the algorithm, `x25519-hkdf-sha256-aes256gcm`, but not its parameters. `seal` fixes them for 0.1:

- an ephemeral X25519 key pair; an all-zero shared secret is refused;
- HKDF-SHA256 with an empty salt, and info `otsec.authz/0.1 x25519-hkdf-sha256-aes256gcm\n` followed by the ephemeral and the recipient public keys;
- AES-256-GCM with a random 12-byte nonce and `SealAAD(ref)` as additional data.

`Seal` refuses to run without a pinned fingerprint, or with one that differs from the published key's (T-12, D2-5). It also refuses a key ID that is not derived from the key. A fingerprint copied with spaces, colons or capitals is accepted. `Open` gives one error for every failure and never says why.

### Install

`Install` runs the checks in this order, and any failure keeps nothing:

1. `CredentialRef.Validate`;
2. the reference names this node, and its asset is enrolled here;
3. a verified register package is active for the asset's family, and `CheckAccessLevel` passes. This comes after enrollment, not before as in the design note, because the package is chosen by the asset's family;
4. the C1 endpoint belongs to the asset, with the same transport, downstream security label and acknowledgement scope;
5. the version is 1 for a new reference, or the stored version plus one. A new version keeps the node, asset, endpoint, transport and access level; anything else needs a new reference. A revoked reference takes no new version;
6. the secret is sealed to this collector's install key and opens for this exact reference;
7. `ValidateSecret` with the family's policy and the register package. This is where `SER C`, `ACC`, `QUIT`, `2AC` and anything starting with a command mnemonic are refused (A6's re-check of #75);
8. the reuse rule.

The refusal codes are `invalid`, `credential_mismatch`, `asset_not_enrolled`, `register_unverified`, `credential_unusable` and `secret_rejected`. A refusal detail never contains the secret: C7 promises this for `ValidateSecret`, and the store also replaces any detail that contains it.

A new version revokes the previous one with reason `rotated` and removes its ciphertext, nonce and reuse tag in the same write. `InstallResult` gives the new status, the replaced one and `SharedWith`.

### Reuse rule (design section 6)

The reuse tag is HMAC-SHA-256 of the secret under its own key derived from the store key, so no comparison value leaves the collector. A secret equal to a stored one under a different plaintext scope is refused with `secret_rejected`, in both directions. A secret equal to one on other assets under the same scope is accepted, and `SharedWith` counts those assets. A revoked version keeps no tag, so it no longer counts.

### Revoke, suspend, clear

- **`Revoke`** marks every version revoked with the reason and removes their secret material. It is terminal. Revoking a revoked or unknown reference is `credential_unusable`.
- **`Suspend`** is called by the run pipeline (PR 3). It changes only the current version. An existing suspension keeps its reason, except that `identity-mismatch` replaces any other, because it is the one that cannot be cleared in place.
- **`ClearSuspension`** needs the exact current version (`invalid` otherwise), refuses a version that is not suspended, and refuses `identity-mismatch` with `credential_unusable`. Only a new version clears that.

### Use at run time

`Acquire` resolves the current version for one accepted run:

- it refuses with `credential_unusable` a credential that is missing, suspended or revoked, or whose stored ciphertext does not decrypt for its reference (T-4);
- it refuses with `credential_mismatch` a use the reference does not bind (`Binds`);
- it applies `CheckAccessLevel` again.

It returns a `SecretHandle`, the seam's `sel751.Secret`:

- `Use` calls its function once with a copy of the secret and wipes the copy afterwards. A second `Use` is `ErrSecretUsed`, so the slot opens at most once per session.
- `EchoSpans` gives the non-overlapping half-open ranges of received bytes that equal the secret.
- `Close` wipes the secret. After it, `Use` fails and `EchoSpans` finds nothing.

Tests (`credstore_test.go`, `seal_test.go`):

- init and reopen;
- fail-closed open for 16 bad files;
- 25 install refusals in order, each leaving the file byte-for-byte unchanged;
- refusal details never echo the secret;
- rotation destroys the old ciphertext;
- the reuse rule in both directions (T-6);
- revoke, suspend and clear, including `identity-mismatch` (the store's part of T-7);
- binding checks on `Acquire`;
- a ciphertext copied onto another entry refused (T-4);
- a scan of every file the store wrote and every value it returned for the test secrets (the store's part of T-5 and T-8);
- a failed write breaking the store;
- T-12, seal and open binding to every field of the reference.

Fuzz targets: `FuzzOpenCredStore` and `seal.FuzzOpen`.

## Open items

- **PC run of the Windows transport.** One risk to check there: a service's process token may not grant another service `TOKEN_QUERY`. If it does not, `Dial` fails closed, and the collector must grant the node's SID `TOKEN_QUERY` on its own token at startup. A5's service accounts (`platform/winsvc`) decide which case applies.
- **The install path is a guessing oracle for a compromised node service (A3 finding, for A1 and A6).** The node service holds the install key's public half, so it can seal any guess. It installs the guess under a new reference whose plaintext scope differs from the target's. The reply is `secret_rejected` for the reuse rule exactly when the guess equals a stored secret, and nothing is destroyed. SEL default passwords are well known, so a short list could confirm that a site still uses one. The secret still cannot leave through the collector, but the node service could carry it to another host on the station LAN. Every attempt is a collector-numbered decision, so a node that hides them leaves `collector_seq` gaps. In Phase 2 every device credential is lab-only Telnet, so no target of another scope exists yet. Proposed fix for PR 3: a durable install budget in the collector state, for example 10 installs per hour per node, refused with `rate_limited`. The shared count must then not go into the reply either, because it would be the same oracle within one scope.
- **The shared-secret count has no field in the C7 reply.** `InstallResult.SharedWith` exists, but `CollectorReply` cannot carry it. Given the oracle above, it belongs in a collector-reported C8 install record, not in the reply. That is a C7 or C8 0.2 candidate.
- **The sealing parameters** (HKDF salt and info) are fixed by `modules/security/seal`, not by C7. They are a C7 0.2 candidate, so that a browser client using WebCrypto can be checked against the contract.
- **A revoked secret can remain on disk.** Revocation removes the ciphertext from the store file, but the blocks of an earlier file may survive on the disk until they are reused. Recovering them needs the store key, so only the collector's account, SYSTEM or an administrator could read them, and design section 10 already lists those as able to read every secret.
- **C7 0.2 candidate.** C7 has no `DecodeReply`. `collectorwire.DecodeStrict` is therefore a copy of the contracts' internal strict decoder: a struct key must be exactly a field name, so `STATUS` and `ſtatus` are refused (A6's review of #79). A contract-level `DecodeReply` would let the copy go. Until then the two must be kept in step.
