# Signed administrator files and the node's relay: design (P3-A5)

Status: relay design approved by A1 (2026-10-26). The two new C7 kinds are approved in principle for 0.5 and A3 drafts them. The transition is (a) with conditions, which A3 has still to agree. Owner: A5. Reviewers: A3 (trust boundaries, C7), A1 (contract approval), A2 (request fields), A6 (tests). It covers the two items A1 assigned to A5's signed clear-* task:

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
- The node reads the files under the protected-file rule (`protect.ReadFileFor`, `AdminReaders`), so only an administrator's file is read. Each file is capped at `MaxAdminPayload` plus 1 KiB of envelope, decoded strictly, and read in name order. At most 16 are read per tick.
- The node cannot delete or rename a file, because `admin_dir` is read-only to it. It records each file it has relayed by the SHA-256 of the file's bytes (below), and an administrator removes files when convenient. A file that has been relayed is never sent again, so an old file left in place changes nothing.
- The existing names (`clear-suspension.json` and the others) keep their 0.1 unsigned form during the transition (see "Transition"). Signed requests use only the new file kind.

## Relay

For each unrelayed file, before any run of the tick:

1. **Record (audit-before-act).** The node writes a C8 `collector.request` info record, then sends. The record carries the kind, the file's SHA-256, and the envelope's `key_id`. It also carries the payload's `nonce`, `admin_key_id`, `principal` and `expires_at`, decoded from the payload but labelled unverified, because the collector has not decided yet. A3's admin-keys procedure asks for the key ID and nonce on the record.
2. **Send** a `CollectorRequest`: `{contract, kind, request_id: "admin-" + first 16 hex digits of the file hash, on_behalf_of: the node, policy_version, admin_signed: the envelope as read}`. The node does not set the body: under 0.4 the body is only in the payload.
3. **Record the reply** as for a run. An acceptance names `collector_seq`. A refusal names `admin_unverified` and its check.
4. **Mark it relayed.** `adminrelay.json` in the store directory holds the file hashes that got a decision (accepted or refused). It is written atomically after the reply record commits. On a restart the chain is the authority: a file whose hash has a reply record is relayed. So a crash between the reply record and the checkpoint resends nothing.

A transport failure or a lost reply leaves the file unrelayed, and the next tick sends it again. The collector then answers `replay` if it had spent the nonce, and the node records that refusal like any other. The request expires after at most 15 minutes, so retries end on their own.

## What the node does on an accepted request

| Kind | Collector | Node, after acceptance |
| --- | --- | --- |
| `credential.install`, `credential.revoke`, `credential.clear_suspension` | Acts, as today. | Nothing further: the reply record is the node's whole part. |
| `asset.clear_suspension` (exists, 0.2; signed since 0.4) | Clears its own suspension of the asset. | Clears its own suspension of the same asset and ref, from the payload's body. The C8 `asset.suspension_clear` record's actor is the payload's principal, and its detail names the `collector_seq`. The collector no longer reads `clear-suspension.json` for a signed clear. |
| `node.quarantine_clear` (**new, C7**) | Verifies, spends the nonce, numbers the decision, and does nothing else. | Runs the existing clear (D3-1) for the payload's `asset_id` and `manifest_sha256`. The `quarantine.cleared` actor is the principal, and `requested_by` keeps its meaning (D3-3). |
| `node.seq_reset_ack` (**new, C7**) | Same as above: verifies only. The binding to the current install key is the check that matters, because it is the new collector's key. | Applies the acknowledgement for the payload's `install_key_id`. |

**The two new kinds** are A3's to add to C7, with A1's approval, as a 0.5 minor. Each is admin-signed only and has a body with no secret:

- `node.quarantine_clear`: `{asset_id, manifest_sha256}`.
- `node.seq_reset_ack`: `{install_key_id}`.

The collector's decision is accept-and-record, with no state of its own beyond the nonce. A2: neither body names a device field.

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

1. **PR 1 (node only, no contract change):** the drop point, the relay for the existing admin kinds (the three credential kinds and the signed `asset.clear_suspension`), the node's own clear on a signed asset clear, the checkpoint, the alarms and health, and A6's slicehelper `install-credential` writing a file instead of dialling the pipe. That last step removes the temporary `node_peer` from service mode.
2. **C7 0.5 (A3):** the two node kinds.
3. **PR 2 (node):** signed quarantine clear and reset acknowledgement.

Tests in PR 1 include:
- a relayed file is sent once, including across a restart and after a crash before the checkpoint;
- an altered payload byte is refused by the collector, and the node does not act;
- the same signed clear with a different asset in an unsigned file clears nothing;
- a file a non-administrator wrote is never read;
- the relay record names the key ID and nonce;
- the actor on the node's clear is the signed principal.

## Questions for reviewers

- **A3:** is the node's unverified decode of the payload, for the record only, acceptable? Its values appear in the record before the collector decides, labelled unverified.
- **A3:** should the collector still check `clear-suspension.json` for an unsigned asset clear during the transition, as it does today? The proposal says yes, unchanged.
