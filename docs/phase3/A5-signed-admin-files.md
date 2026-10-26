# Signed administrator files and the node's relay: design (P3-A5)

Status: agreed (2026-10-26). A1 approved the relay design and adopted A3's review on #181. A3's two blockers are folded in below: B1, the principal on the request, and B2, the repeat answer. The two new C7 kinds are approved in principle for 0.5 and A3 drafts them. The transition is (a) with A1's conditions. A2 accepted the fields. Owner: A5. Reviewers: A3 (trust boundaries, C7), A1 (contract approval), A2 (request fields), A6 (tests). It covers the two items A1 assigned to A5's signed clear-* task:

1. **The node's relay of signed admin requests,** `credential.install` included. Today no node path relays one on either platform (A3 on #179). On Windows, an administrator can install a credential on an installed collector only by temporarily pointing `ipc.node_peer` at their own account.
2. **The administrator's files become signed requests,** so the audit actor is the person, not the node (D3-3). The files are `clear-suspension.json`, `clear-quarantine.json` and `seq-reset-ack.json`.

Nothing here changes how the collector verifies a signed request (`authz.VerifyAdminRequest`, the nonce spent durably, the admin clock).

## Principle: the collector verifies, the node only carries

The node holds no admin key and verifies no signature. Every signed request goes to the collector, which already pins the admin keys, binds the request to its node ID and install key, spends the nonce durably before any decision, and numbers the decision. The node acts on a signed request only after the collector has accepted it, and then only on the body the payload carries. This has three consequences:

- **A compromised node cannot originate, alter or replay a request.** It has no key, the signature covers the body, and the collector spends each nonce once.
- **A forged clear leaves a trace outside the node.** The node's own actions (quarantine clear, reset acknowledgement) need a numbered `collector_seq` acceptance that the node cannot produce itself. A node that skips the check is a compromised node, which could discard its own store anyway. What the design adds is the collector-side record of every admin decision.
- **One key set, one nonce store and one clock rule.** A node-side verifier would need its own pinned keys, nonce store and admin clock, two of each to keep consistent.

## The drop point: one file kind in `config\admin`

An administrator's signing client writes each request as its own file, `admin-request-<name>.json`, in `admin_dir`:

```json
{"schema": "otsec.admin-request-file/0.1", "kind": "<C7 kind>", "signed": <authz.AdminSigned>}
```

- `<name>` matches `[a-z0-9-]{1,64}`. The client uses the nonce, so names do not collide.
- The node reads the files under the protected-file rule (`protect.ReadFileFor`, `AdminReaders`), so only an administrator's file is read. Each file is capped at `MaxAdminPayload` base64-encoded (the envelope's form) plus 1 KiB for the rest, decoded strictly, and read in name order. At most 16 are read per tick.
- The node cannot delete or rename a file, because `admin_dir` is read-only to it. It records each file it has relayed by the SHA-256 of the file's bytes (below), and an administrator removes files when convenient. A file that has been relayed is never sent again, so an old file left in place changes nothing.
- The existing names (`clear-suspension.json` and the others) keep their 0.1 unsigned form during the transition (see "Transition"). Signed requests use only the new file kind.

## Relay

For each unrelayed file, before any run of the tick:

1. **Record (audit-before-act).** The node writes a C8 `collector.request` info record, then sends. The record carries the kind, the file's SHA-256, and the envelope's `key_id`. It also carries the payload's `nonce`, `admin_key_id`, `principal` and `expires_at` in a field group named as unverified, because the collector has not decided yet. A3's limits (#181) apply:
   - each value is checked against its pattern before it is recorded;
   - no body is decoded or recorded, and above all no sealed secret;
   - the reply record repeats the values as verified only when the collector accepted.

   A3's admin-keys procedure asks for the key ID and nonce on the record.
2. **Send** a `CollectorRequest`: `{contract, kind, request_id: "admin-" + first 16 hex digits of the file hash, on_behalf_of: the payload's principal, policy_version, admin_signed: the envelope as read}`. `VerifyAdminRequest` refuses any other `on_behalf_of` with check `binding` (A3, B1). The node does not set the body: under 0.4 the body is only in the payload.
3. **Record the reply** as for a run. An acceptance names `collector_seq`. A refusal names `admin_unverified` and its check.
4. **Mark it relayed.** The suspension checkpoint in the store directory (`suspensions.json`, field `admin_relayed`) holds the request IDs that got a decision (accepted or refused). It is folded from the audit stream with the suspensions, so one `through_seq` covers both, and written atomically after the reply record commits. On a restart the chain is the authority: a file whose hash has a reply record is relayed. So a crash between the reply record and the checkpoint resends nothing.

A transport failure or a lost reply leaves the file unrelayed, and the next tick sends it again. The request expires after at most 15 minutes, so retries end on their own.

The collector may already have spent the nonce of a request whose reply was lost. Under 0.4 it then answers `replay`, so the node would never learn of the acceptance and never do its own part (A3, B2). For the credential kinds that loses nothing, because the collector's part is the whole operation. For the kinds where the node acts after acceptance, C7 0.5 adds an idempotent repeat answer: the same signed bytes, sent again inside their window, get the original decision and its `collector_seq`. The node relays those kinds only once 0.5 is in.

## What the node does on an accepted request

| Kind | Collector | Node, after acceptance |
| --- | --- | --- |
| `credential.install`, `credential.revoke`, `credential.clear_suspension` | Acts, as today. | Nothing further: the reply record is the node's whole part. |
| `asset.clear_suspension` (exists, 0.2; signed since 0.4) | Clears its own suspension of the asset. | Clears its own suspension of the same asset and ref, from the payload's body. The C8 `asset.suspension_clear` record's actor is the payload's principal, and its detail names the `collector_seq`. The collector no longer reads `clear-suspension.json` for a signed clear. For an unsigned clear during the transition it keeps checking the file as today (A3, A1). |
| `node.quarantine_clear` (**new, C7**) | Verifies, spends the nonce, numbers the decision, and does nothing else. | Runs the existing clear (D3-1) for the payload's `asset_id` and `manifest_sha256`. The `quarantine.cleared` actor is the principal, and `requested_by` keeps its meaning (D3-3). |
| `node.seq_reset_ack` (**new, C7**) | Same as above: verifies only. The binding to the current install key is the check that matters, because it is the new collector's key. | Applies the acknowledgement for the payload's `install_key_id`. |

**The two new kinds** are A3's to add to C7, with A1's approval, as a 0.5 minor. Each is admin-signed only and has a body with no secret:

- `node.quarantine_clear`: `{asset_id, manifest_sha256}`.
- `node.seq_reset_ack`: an empty body. The signed binding to the install key ID already names the key (A3).

The collector's decision is accept-and-record, with no state of its own beyond the nonce and the repeat answer. A2 accepted the fields: neither body names a device field or carries a secret, and the relay adds no command path to a device.

**A clear releases nothing early (A2).** Clearing a suspension resets neither the endpoint's session floor nor the minimum interval. A suspension usually follows a run that did not end cleanly, and the SEL-751 port may still hold that session until `TIDLE`, so the next run waits for both as it would have anyway. A test pins this in the PR that relays the signed asset clear.

## Health and alarms

- `admin-request-refused` (per file hash): the collector refused the request, naming its check.
- `admin-request-unread`: a file was refused by the protected-file rule or the decoder. The alarm says why, never the file's content.
- `otsec health` lists unrelayed files and the last decision on each.

## Transition

A1 chose option (a) on 2026-10-26, subject to A3's agreement on #181. The 0.1 unsigned files stay accepted, with the node as actor as today (D3-3), until the first `device-observed` endpoint. Option (b), refusing them at once, would break the slice for no safety gain while every endpoint is simulated. A1's conditions:

- **It is enforced in code, not by convention.** The node refuses an unsigned file whenever its configuration holds any endpoint that is not marked lab or simulated, and a test pins that.
- **Every unsigned file the node accepts is visible.** Each one raises an alarm and writes an audit record that names it as unsigned.
- **The exit report lists it** as a known limitation.

When a node sees both an unsigned file and a signed request for the same clear, it acts on the signed one only.

## Plan

1. **PR 1 (node only, no contract change):**
   - the drop point and the relay for the three credential kinds only (A1);
   - the checkpoint, the alarms and health;
   - slicehelper `install-credential` writing a file instead of dialling the pipe, which lets #179 drop its temporary `node_peer`.
2. **C7 0.5 (A3):** the two node kinds and the repeat answer.
3. **PR 2 (node):**
   - the signed asset clear and the node's own clear after it;
   - the signed quarantine clear and reset acknowledgement;
   - the refusal of unsigned files on a configuration with any endpoint that is not lab or simulated.

Tests in PR 1 include:
- a relayed file is sent once, including across a restart and after a crash before the checkpoint;
- an altered payload byte is refused by the collector, and the node does not act;
- a file a non-administrator wrote is never read;
- the relay record names the key ID and nonce, unverified until accepted;
- `on_behalf_of` is the payload's principal.

PR 2 adds:
- the actor on the node's clear is the signed principal;
- a clear does not release a run before the floor and the interval;
- a lost reply's resend gets the repeat answer, and the node does its part once.

## Answers from review

- **A3:** the node's unverified decode for the record is acceptable within the limits above.
- **A3, A1:** the collector keeps checking `clear-suspension.json` for an unsigned clear during the transition. Its refusal goes on the device-observed gate's list.
