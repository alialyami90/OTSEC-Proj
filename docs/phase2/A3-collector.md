# A3: the collector and its IPC (P2-A3)

Owner: A3. Reviewers: A6, A2. Status: PR 1 (IPC) merged in #79; its follow-up (strict names, quarantine) in #82. PR 2 adds the durable collector state and the credential store; PR 3 adds the run pipeline. Later sections are added as their PRs land.

This note records how the collector side of C7 is built. C7 (`contracts/authz`) defines the messages; this is the implementation around them. The design it follows is [../phase1/A3-credential-design.md](../phase1/A3-credential-design.md) (W-1 to W-4, T-1 to T-12).

## Packages

| Package | What it holds | Who imports it |
| --- | --- | --- |
| `modules/security/collectorwire` | Framing, strict decoding, the run outcome, the two transports and their peer checks, `ServiceSID`. No credential code, no device transport. | `collector`, `collectorclient` |
| `modules/security/collector` | The IPC server, the durable collector state, the credential store, verified register packages and the run pipeline. Hosts the SEL-751 adapter. | `cmd/otsec-collector` only |
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
- **The reply comes before the run, and the run starts only after the reply has been written.** "Written" means the whole frame was accepted by the socket or pipe; it does not prove the node read it. If the reply cannot be written, the work is not started. A node that has no reply cannot record the run, so the run must not happen. The server then calls `Work.Discard`, which wipes the decrypted secret and frees the device without any device I/O; it does the same when a handler breaks the reply contract (A6 on #97: before this, the asset stayed `busy` and the secret stayed decrypted until a restart). Whichever of `Run` and `Discard` comes first wins. A later call does nothing: it never runs a device session without the claim, and it never frees a claim that a later run on the same asset holds (D9). Tests: `TestUnwrittenReplyDiscardsWork`, `TestContractBreachDiscardsWork`, `TestDiscardReleasesRun`, `TestRunWorkFinishesOnce`.
- **Handler bugs fail closed.** Work comes exactly with an accepted run, and an accepted run carries an invocation ID. An accepted credential request has neither. The server drops the connection without a reply when a handler breaks this: an accepted run without work or without an invocation ID, work with anything other than an accepted run, or an invocation ID on anything other than an accepted run. It also drops the outcome if its invocation ID differs from the reply's (`TestHandlerContractBreachDropsConnection`, `TestAcceptedCredentialRequest`, `TestOutcomeForAnotherInvocationDropped`). Before PR 3 the rule dropped an accepted credential request as "accepted without work"; the collector binary's end-to-end test found it.
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
- **The file is created once, at the first start** (`InitState`). `OpenState` never creates it. A missing, unreadable, oversize or unknown file is `ErrStateUnavailable`, never a fresh state, because a fresh one would reopen every floor and restart `collector_seq` at 1.
- **A fresh state starts a floor on every asset (PR 4, A1 on the `collector_seq` reset).** `InitState` records `created_utc`, which is required. `CheckFloor` treats it as an unconfirmed authentication on every asset, so after a reinstall the collector authenticates to nothing for the longest floor (31 minutes, `TIDLE` unknown), and a clock set back before it counts as inside. The previous state may have held an `ACC` left unconfirmed, and a fresh state cannot know, so a reinstall never shortens a floor. A creation time set ahead by a wrong clock holds every asset until real time passes it, and only a reinstall clears that. This is the safe direction, but an operator who sees every run refused with `rate_limited` after a reinstall should check the clock (A6 on #106).
- **Asset suspensions (PR 4).** `SuspendAsset` records the C1 reason an outcome code set (`adapter.Code.Suspends`) with the invocation, durably, and `CheckSuspended` refuses runs to the asset. A later reason does not replace the first, except `identity-mismatch`, as for credentials. Nothing in C7 0.1 clears one, and a fresh state does not hold them (see Open items).
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
  - **A cut echo (A3 on #99, A6 on #106).** For the first reply after `Use` only, which is the reply to the password line, it also returns a trailing run of at least 3 bytes that equals the start of the secret. That reply may have been cut by the response budget, a timeout or a close in the middle of an echo, and the cut part is redacted too.
  - **Later replies get whole matches only.** A partial match on device data, such as the cut tail of a SER reply, would redact it, and the redaction would show the secret's first bytes.
  - **A reply that ends in a prompt was not cut.** No partial match is returned when the reply, without trailing spaces, NUL, XON and XOFF, ends in `=`, `>` or `?`, the last byte of every SEL prompt. So a redaction never covers `=>>` or `Password: ? `.
  - **What this leaves.** A cut echo shorter than 3 bytes, or one that ends in one of those three bytes, is not redacted.
  - "First reply after `Use`" is the first call after `Use`. That is how #99 calls it: on every non-empty reply after the secret, in order.
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

## Run pipeline (PR 3)

`collector.Pipeline` is the server's `Handler`. Each decision is numbered first, so every reply has a `collector_seq`, including a refusal whose own state write then fails. If the number itself cannot be written durably, the reply is `collector_state_unavailable` with no number. The policy version is checked next, for every kind of request (`policy_version`).

### Run checks, in order

Nothing before the accepted reply opens a connection.

1. **The principal is a schedule.** A person, whatever their role, never causes device I/O directly; `authz.DecodeRequest` already refuses it, and the pipeline refuses it again (`principal_not_permitted`). That is how a monitor principal is kept from causing a run.
2. **The asset is enrolled on this node** (`asset_not_enrolled`). Enrolled assets and their profiles come from the collector's own configuration; `NewPipeline` refuses an asset that fails C1 validation, is on another node, does not match its profile, or appears twice.
3. **D2-4.** No endpoint of the asset is labelled `device-observed`, and the run's endpoint is labelled `simulated`.
4. **D2-10.** Every outbound endpoint (Telnet, SSH) of the asset has as its host an IPv4 literal in 127.0.0.0/8 or the literal `::1`. Host names, `localhost` included, zones and IPv4-mapped forms are refused, and nothing is resolved. A5's node loader applies the same rule with the same result.
   Both locks refuse with `asset_not_enrolled` and name the decision in the detail, because C7 0.1 has no closer code. C7 0.1 runs name no endpoint, so an asset with more than one outbound endpoint is refused with `invalid` rather than guessed at.
5. **The register.** The family's package is active, which means its signature verified in this collector (`Registers.Activate`, below), and the run names its revision (`register_unverified`, `register_version`).
6. **The operation** (`RunBody.ValidateAgainst`): known, read-only, in the operate phase, with parameters that render, and a credential exactly when its level is above 0.
7. **The invocation, and no suspension.** The collector builds the C2 invocation itself. It takes the endpoint, profile, expected identity (the binding attributes' declared values) and limits from its configuration, and the minimum interval from the profile. It then runs C2's `ValidateWith` and `CheckAgainst`, so an asset that is suspended, a binding that compares nothing, or a credential C1 does not allow is refused before any secret is decrypted. C2 codes map to C7 codes, with the C2 code kept in the detail. A suspension an earlier run's outcome set (`State.CheckSuspended`) is refused with `asset_not_enrolled` (PR 4).
8. **The failed-auth floor, then the profile's minimum interval** (`rate_limited`). Both are durable. The floor applies to every run, level 0 included, because a session landing on a pending `Password: ?` would send its first line as a password.
9. **One session per device** (`busy`).
10. **The credential.** `CredStore.Acquire` decrypts the secret only here, after every other check.
11. **The run's start is recorded durably** (for the interval). Only then is the reply sent.

### After the reply

The accepted run's work calls the `Runner`, with a deadline of the invocation's deadline plus 10 s. The SEL-751 runner wraps A2's `sel751.Run` and follows when it lands. The `RunPlan` carries:

- the invocation, asset, profile, endpoint and register;
- the credential and `SecretHandle`;
- the asset's `FloorGate`;
- a dialer that connects only to the endpoint's own host and port over TCP and checks D2-10 again;
- the reply's number and `NextSeq` for the events the run reports.

When the runner returns, the pipeline:

- records the `TIDLE` the session read;
- suspends the asset for the outcome code (`Code.Suspends`), and the credential for the fault the session reported or, when it reported none, for the outcome code (`Code.SuspendsCredential`) (PR 4). The code is read from the result's `error.code` alone, without `Result.Validate`, so a result that fails Validate or the checks below still suspends what its code suspends. Suspending is the cautious direction (A6 on #106: before this, a result inconsistent with its own bytes suspended nothing; `TestOutcomeCodeSuspendsInvalidResult` covers every suspending C2 golden with three Validate-breaking changes). A result that does not decode suspends nothing, and the floor rule below still applies;
- **sets the floor again when the login was confirmed (`=>`) and the report does not say QUI was sent.** The relay may keep Level 1 until `TIDLE` expires, so no new session may land on it. A zero report counts as "QUI not sent";
- runs `Validate`, `CheckLines` and `CheckAgainst` on the result. A `CheckLines` failure is a `SAFETY` alarm. The outcome is still sent, because the node quarantines it and evidence is never dropped;
- wipes the secret and frees the device, whatever happened, including when the runner panics. A panic is an alarm, and the node receives an outcome with no result, which it records as outcome unknown.

### Credential requests

Install, revoke and clear are refused unless a person asked (`principal_not_permitted`). An install first spends one from the **install budget**: 10 per hour per node by default, durable in the state file, and refused with `rate_limited`. The budget is spent before any check, so a request a later check refuses still counts. An install dated after the clock stays in the window, so after a clock that ran far ahead is corrected, installs are refused until real time catches up. That fails closed, and it is why an admin may see `rate_limited` with no recent installs. This bounds guessing through the reuse rule (see Open items).

### Register packages

`Registers.Activate` takes a signed envelope and runs `authz.VerifyRegisterPackage` against the collector's own trust anchors and the per-family floors in the state file. It persists the new floor before activating the package. On any failure, the previous package stays active. The trust anchors are fixed at start, so a change to them restarts the collector, which then verifies every package again.

Tests (`pipeline_test.go`, with the C1 simulated SEL-751 asset moved to 127.0.0.1, its profile, the C3 register signed in the test, and result-ok.json):

- an accepted level 1 run: the secret reaches the runner, no alarm, then the handle is wiped, the device freed and the floor cleared;
- a level 0 run carries no secret;
- a person or service principal cannot run;
- 20 refusals, each before the runner, each numbered, none leaving the device busy;
- the locks without C1 validation;
- T-9: after a failed authentication the next request is `rate_limited`, and after the floor the suspended credential is `credential_unusable`;
- an exit without QUI sets a floor of `TIDLE` plus one minute;
- a zero report is cautious;
- a runner panic;
- the SAFETY alarm when the result's lines are not the operation's;
- credential requests and the install budget;
- the dialer reaches only its endpoint;
- register activation: unknown key, wrong key, tampered payload, revoked key, and rollback after a restart are all refused;
- PR 4, `TestOutcomeCodeSuspends`: an outcome of `failed.unexpected_access_level` with no suspension in the report suspends the asset and the credential, and the next run to the asset is refused before the runner. `state_test.go` adds `TestFreshStateFloor`, `TestStateWithoutCreationRefused` and `TestAssetSuspension`.

## Collector binary and service (PR 4)

`cmd/otsec-collector run -data <dir>` is the whole command. On Windows, `-data` defaults to `%ProgramData%\OTSEC` and the binary runs as the service `otsec-collector` when the service manager starts it (A5's command line: `"<exe>" run -data %ProgramData%\OTSEC`), or in the foreground otherwise. On Linux, the development platform, `-data` is required and the binary runs in the foreground until SIGINT or SIGTERM.

### Start, in order

1. **Hardening, before anything else (T-5).** A failure stops the start.
   - All platforms: `GOTRACEBACK` containing `crash` or `wer` is refused, because the runtime would then write or hand off a dump. A lower level set from code is ignored by the runtime, so the setting is refused rather than overridden.
   - Linux: `PR_SET_DUMPABLE` 0 (no core file, and no ptrace by other processes of the same user) and `RLIMIT_CORE` 0.
   - Windows: no fault dialog (`SetErrorMode`), `WerAddExcludedApplication` for the collector's own account (best effort, because under the SCM the virtual account's hive may not be loaded), and a required machine-wide WER exclusion: `HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\ExcludedApplications`, value `otsec-collector.exe` = 1, set by the installer. That the exclusion also stops WER `LocalDumps` is [inferred] from the WER documentation. It is T-5 on the Windows site image and has not been run.
   - Other platforms refuse to start.
2. **Configuration.** `collector\collector.json` (`otsec.collector-config/0.1`) is decoded strictly with `collectorwire.DecodeStrict`: node ID, policy version, IPC endpoint, the enrolled assets with their C1 profiles (matched by ID and version), the register trust anchors, the signed register packages, and the install budget. Any error stops the start. The file is written by the installer and is readable by the collector account only.
3. **First start.** The stores are created only when both are missing and the installer's marker `collector\state\provision` is present. They are created by the collector's own account, because DPAPI user scope protects the store key for that account. The marker is then removed. One store present without the other, or both missing without the marker, is **lost state** and stops the start: creating new stores would reopen every failure floor, restart `collector_seq`, and make an install key no admin has pinned. A crash between creating the two stores leaves one of them, so the next start stops and the site reinstalls. A marker left by a crash after both stores were created is removed at the next start, so a later loss of both stores is refused as lost state, not taken as a first start (A6 on #106).
4. **Stores.** `OpenState` and `OpenCredStore`. The install key's fingerprint is logged, so the admin can compare it with the one they pin.
5. **Public install key.** At every start, before it serves, the collector writes `collector\public\install-key.json`. The node reads it before every request to find a reinstall (D2-15), and publishes it for T-12. The shape is `{"schema": "otsec.collector.install_key/0.1", "key_id", "public_key", "fingerprint"}`, where `public_key` is standard base64 of the 32-byte X25519 key, as in `seal.InstallKey`. A reader refuses a file with any other schema. The collector writes a temporary file, syncs it and renames it over the old one, so a reader sees the old file or the new one, never part of one. On Windows the rename fails while a reader has the file open without `FILE_SHARE_DELETE`, which Go's `os.Open` does not set, so the collector retries the rename for up to a second. A reader that can, such as A5's node, should open it with `FILE_SHARE_DELETE` as well (A6 on #106). Both the failure and the retry are inferred from Win32 semantics: the retry has not run on Windows, and no test exercises it, because the failure cannot happen on Linux. If the public directory is missing or the write fails, the collector does not start (`TestStartNeedsPublicDir`). Nothing in the file is secret: its integrity is what the admin's pinned fingerprint checks (T-12).
6. **Register packages.** Every package is verified against the trust anchors and the floors; a rejected package raises an alarm and stays inactive, so its operations are refused.
7. **Serve.** `collectorwire.Listen` on the configured endpoint: on Windows the default pipe and the node service's SID as the only peer; on Linux the socket path and peer UID from the configuration.

### The hosted adapter

`hostedRunner()` returns nil until A2's `sel751.Run` is on main. Until then, every run that passes the checks is refused with `not_invocable`, and only credential requests do work.

The SEL-751 runner will follow these rules, which came from the reviews of #97 and #99:

- **Never pass a nil `*SecretHandle` as `sel751.Config.Secret`** (A2 on #97). A nil pointer stored in the interface is not a nil interface, so `Run` would refuse every Level 0 run as `failed.internal`. `cfg.Secret` and `cfg.Floor` are set only when `plan.Secret != nil`.
- **A wake answered by `Password: ?` counts as an unconfirmed attempt** (A3 on #99). The bare line end probably landed as a blank password. A Level 0 run has no floor gate, so nothing else records it. When a result is `failed.internal` with `wake_sent` true and its last received bytes end in the password prompt, the runner sets the floor for the asset. A2 is adding a golden for this path.
- **`RunReport.TIDLE` stays 0 until `sel751` reports the TIDLE it parsed** (A2 on #97, A2's follow-up). Until then, the floor after an exit without QUI is the 31-minute fallback, which is the safe side.

### Logs

On Windows a service logs to the Event Log under the source `otsec-collector`, which the installer registers. Error level goes to Error, Warn to Warning, and the rest to Information. In the foreground the log goes to standard error. What is logged is the same as the server's: request ID, status, refusal code and collector_seq.

### Tests (`main_test.go`)

- `TestParseConfig`: a good configuration, and 12 refusals: an unknown field, a case variant of a field name, another format, a bad node ID, policy version 0, a bad asset, a missing profile, a profile of another version, a bad anchor key or status, trailing data, and (on Linux) no IPC endpoint.
- `TestProvision`: both stores missing without the marker is refused; with it, the first start creates both and removes the marker; a second start leaves them; one store missing is refused even with a marker, and the missing store is not recreated; a leftover marker with both stores present is removed, and losing both stores afterwards is refused.
- `TestCheckTraceback` and `TestHarden`: hardening runs in a child process, and on Linux the child is shown non-dumpable with a zero core limit.
- `TestServe`, end to end over a Unix socket: first start, an install sealed by the client against the published key and its pinned fingerprint, a run refused with `not_invocable`, a stop, a restart without the marker, and a scan of every log line and every file the collector wrote for the test secret (the binary's part of T-5 and T-8). It found the server rule that PR 3 fixed.
- `FuzzParseConfig`.

## Open items

- **PC run of the Windows transport.** One risk to check there: a service's process token may not grant another service `TOKEN_QUERY`. If it does not, `Dial` fails closed, and the collector must grant the node's SID `TOKEN_QUERY` on its own token at startup. A5's service accounts (`platform/winsvc`) decide which case applies.
- **The install path is a guessing oracle for a compromised node service (A3 finding, for A1 and A6).** The node service holds the install key's public half, so it can seal any guess. It installs the guess under a new reference whose plaintext scope differs from the target's. The reply is `secret_rejected` for the reuse rule exactly when the guess equals a stored secret, and nothing is destroyed. SEL default passwords are well known, so a short list could confirm that a site still uses one. The secret still cannot leave through the collector, but the node service could carry it to another host on the station LAN. Every attempt is a collector-numbered decision, so a node that hides them leaves `collector_seq` gaps. In Phase 2 every device credential is lab-only Telnet, so no target of another scope exists yet. PR 3 adds a durable install budget (10 per hour per node by default, `rate_limited`). It bounds the rate, but it does not remove the oracle: a few known default passwords fit in one hour. The shared count must not go into the reply either, because it would be the same oracle within one scope. **Ruled in D2-11 (#91):** the budget is accepted for Phase 2 only. Before any `device-observed` endpoint, every credential request must be signed by an administrator whose key is pinned in the collector. The design, a C7 0.2 candidate, is in [A3-signed-credential-requests.md](A3-signed-credential-requests.md). Until it merges this is an open high risk.
- **The shared-secret count has no field in the C7 reply.** `InstallResult.SharedWith` exists, but `CollectorReply` cannot carry it. Given the oracle above, it belongs in a collector-reported C8 install record, not in the reply. That is a C7 or C8 0.2 candidate.
- **The sealing parameters** (HKDF salt and info) are fixed by `modules/security/seal`, not by C7. They are a C7 0.2 candidate, so that a browser client using WebCrypto can be checked against the contract.
- **Removal is logical, not physical (A6 on #90).** Revocation removes the ciphertext from the current store file. But an earlier copy can still hold it: the blocks of an earlier file, a backup, a volume shadow copy, or a crash-left `credentials.json.tmp`. Reading such a copy needs the store key, so only the collector's account, SYSTEM or an administrator could read it, and design section 10 already lists those as able to read every secret. **So revoking a compromised secret must always be paired with changing it on the device.** **Putting such a copy back is refused.** The store carries a generation, which is 1 at creation and goes up by one at every write. The State records the highest generation written or opened (`cred_generation`), and `OpenCredStore` refuses a store older than the record. The store file is written first and the record second, so a crash between them leaves the store ahead, and the next open accepts it and catches the record up (`TestRestoredStoreRefused`, `TestStoreAheadOfRecord`). **The collector alone refuses a store restored by itself, not one restored together with its state (A6 on #97).** Restoring both files from one backup or volume shadow copy, the realistic case, passes this check. It brings back a revoked secret and rolls back the install budget, the failed-auth floors and the register family floors (register rollback). The backstop is the node: the restored `collector_seq` goes back while the install key is unchanged, which D2-15 and the C8 0.2 `collector.seq_reset` rules treat as a restore. The node holds collection, and an unchanged key is never acknowledged.
- **Owed from A5's installer:** the `collector\public` directory (written by the collector, readable by the node), the Event Log source `otsec-collector`, and the WER value above. Without the WER value the collector refuses to start, which is the intended failure.
- **Clearing an asset suspension.** C7 0.1 has no request for it, so in Phase 2 only a reinstall clears one, and a reinstall clears every one, behind the fresh state's 31-minute floor. A clear request belongs with the admin-signed requests (C7 0.2). Until then, the node should hold the suspension too (C1 `Suspension` from the outcome code), so a reinstalled collector is not the only record.
- **C7 0.2 candidates from the pipeline:** `endpoint_id` in `RunBody`, so an asset with two outbound endpoints can be collected; and refusal codes for the Phase 2 locks and for a suspended asset, which use `asset_not_enrolled` today.
- **C7 0.2 candidate.** C7 has no `DecodeReply`. `collectorwire.DecodeStrict` is therefore a copy of the contracts' internal strict decoder: a struct key must be exactly a field name, so `STATUS` and `ſtatus` are refused (A6's review of #79). A contract-level `DecodeReply` would let the copy go. Until then the two must be kept in step.
