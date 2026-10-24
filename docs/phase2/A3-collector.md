# A3: the collector and its IPC (P2-A3)

Owner: A3. Reviewers: A6, A2. Status: PR 1 (IPC) in review; later sections are added as their PRs land.

This note records how the collector side of C7 is built. C7 (`contracts/authz`) defines the messages; this is the implementation around them. The design it follows is [../phase1/A3-credential-design.md](../phase1/A3-credential-design.md) (W-1 to W-4, T-1 to T-12).

## Packages

| Package | What it holds | Who imports it |
| --- | --- | --- |
| `modules/security/collectorwire` | Framing, strict decoding, the run outcome, the two transports and their peer checks, `ServiceSID`. No credential code, no device transport. | `collector`, `collectorclient` |
| `modules/security/collector` | The IPC server (this PR); later the credential store, durable collector state and the run pipeline. Hosts the SEL-751 adapter. | `cmd/otsec-collector` only |
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

- **Strict decoding before any decision.** A request is decoded with `authz.DecodeRequest` before the handler sees it. A field C7 does not define, at any depth, is refused with `unknown_field`. A duplicate key, trailing data or invalid UTF-8 is refused with `malformed`. An oversize frame is refused with `oversize`, and so is a run asked for by anyone but a schedule. All of these refusals go through `Handler.Refuse`, never `Handler.Handle`, so they cannot reach the run pipeline or the device. Tests: `TestFieldOutsideC7RefusedBeforeHandler`, `TestMalformedRequestsRefused`.
- **Every decision is numbered.** Each reply, including a refusal of an undecodable request, carries the handler's next `collector_seq`. A connection that ends before a whole request arrives is not a decision and takes no number (`TestIncompleteRequestTakesNoNumber`).
- **The reply comes before the run, and the run starts only after the reply is delivered.** If the reply cannot be written, the work is not started. A node that has no reply cannot record the run, so the run must not happen.
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

A failure, or a connection that ends before the outcome, is `ErrOutcomeUnknown`. It comes with the accepted reply, so the node still audits the decision and records the run as outcome unknown, never as succeeded. It must not treat the run as "nothing happened" either: ACC may have been sent. A retry is safe because the failed-auth floor is written before ACC (D1-20), so a retry is refused with `rate_limited` until the floor has passed.

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
- A stale socket file is replaced. A socket that still answers is refused, so two collectors never serve one path. A path that is not a socket is refused.

Other operating systems return `ErrUnsupported`.

Transport tests (`collectorwire/transport_test.go`) run on both Linux and Windows. They cover:

- a round trip;
- a client with another identity refused before it can read;
- a server with another identity refused before the client sends anything;
- an empty or malformed peer refused;
- a second listener on the same address refused;
- `Close` unblocking `Accept`.

## Open items

- **PC run of the Windows transport.** One risk to check there: a service's process token may not grant another service `TOKEN_QUERY`. If it does not, `Dial` fails closed, and the collector must grant the node's SID `TOKEN_QUERY` on its own token at startup. A5's service accounts (`platform/winsvc`) decide which case applies.
- **Credential secrets that the register recognises (from A6's #75 re-check).** The credential store will refuse at install any secret that the register `Matcher` classifies as anything other than unlisted: an operation, a session line or a deny rule. That covers values such as `SER C` and `ACC`, because `telnet.SendSecret` deliberately bypasses the egress check. This lands with the credential store (PR 2).
- **C7 0.2 candidate.** C7 has no `DecodeReply`, so `collectorwire.DecodeReply` applies the D1-10 strictness rules itself. A contract-level decoder would let other readers share it.
