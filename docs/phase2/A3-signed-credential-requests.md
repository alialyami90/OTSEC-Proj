# Admin-signed credential requests (C7 0.2 candidate, D2-11)

Owner: A3. Status: the C7 0.2 candidate named by D2-11 (merged in #91), aligned with it. Nothing here is implemented. D2-11 requires this control to be merged before any `device-observed` endpoint, that is before D2-4 or D2-10 is lifted. Until then it is an open high risk.

**Phase 2 condition (D2-11).** Until this control is merged, no credential installed in Phase 2 may be a vendor default password or a password used on any real device. At 10 installs an hour, a compromised node can test every published SEL factory password within the first hour, so the budget alone does not protect such a secret.

## Problem

In C7 0.1 the node service builds every credential request and asserts the human principal itself. A compromised node service can therefore originate a request in the name of any person:

- **Install.** The node holds the collector's public install key, so it can seal any guess and install it under a new reference whose plaintext scope differs from the target's. The reuse rule replies `secret_rejected` exactly when the guess equals a stored secret. Any refusal that depends on equality leaks equality, however it is worded (D2-11).
- **Revoke.** It stops collection from a device.
- **Clear suspension.** It lifts a failure floor that the collector set for safety.

The Phase 2 install budget (10 per hour per node) only bounds the rate.

## Rule

From C7 0.2, the collector accepts a credential request only if an administrator signed it, with a key whose public half is pinned in the collector's own configuration. The node can relay a request but cannot originate one, and it cannot change one.

## The envelope

A credential request carries `admin_signed` in place of the three 0.1 bodies:

```json
{
  "contract": "otsec.authz/0.2",
  "kind": "credential.install",
  "request_id": "...",
  "on_behalf_of": {"type": "human", "id": "admin@site-a"},
  "policy_version": 3,
  "admin_signed": {
    "key_id": "ed25519-0123456789abcdef",
    "algorithm": "ed25519",
    "payload": "<base64 of the exact signed bytes>",
    "signature": "<base64, 64 bytes>"
  }
}
```

The signature is Ed25519 over a fixed domain-separation prefix followed by the payload bytes. The prefix names the contract version and the operation:

```
otsec.authz/0.2 admin-request credential.install\n
otsec.authz/0.2 admin-request credential.revoke\n
otsec.authz/0.2 admin-request credential.clear_suspension\n
```

The collector builds the prefix from the outer `kind` and its own contract version, never from the payload. A signature for one operation is therefore never valid for another, a signature for another contract version is never valid for this one, and neither is ever valid as a register signature. This is the same construction as register packages: the signed bytes are carried as they are, so no canonical JSON is needed.

The payload is strict JSON, decoded only after the signature verifies:

| Field | Meaning |
| --- | --- |
| `format` | `otsec.authz.admin-request/0.2` |
| `kind` | Must equal the outer `kind`. |
| `principal` | The admin. Must equal `on_behalf_of` and the principal the key is pinned for. |
| `admin_key_id` | Must equal the outer `key_id`. The outer copy only selects the key; this one is signed, so key rotation and revocation can be audited from the signed record alone. |
| `node_id` | Must equal the collector's node ID. |
| `install_key_id` | Must equal the collector's current install key ID. Together with `node_id`, this stops a signed request from being replayed to another collector, or to this one after its install key changes. |
| `nonce` | 16 random bytes, base64url. Single use. |
| `issued_at`, `expires_at` | RFC 3339 UTC. The maximum lifetime is fixed at 15 minutes: the collector refuses an `expires_at` more than 15 minutes after `issued_at`, or more than 15 minutes after its own clock. |
| `credential_install`, `credential_revoke` or `credential_clear_suspension` | Exactly one, matching `kind`. These are the 0.1 bodies unchanged. An install body includes the whole `SealedSecret` (ephemeral key, nonce, ciphertext, recipient key ID). |

**The signature covers the sealed secret.** Otherwise a compromised node could take one genuine signed install and replace the sealed secret with its own guess under the same signature. It would learn one equality result per genuine install, and the admin's real secret would never be stored.

The body exists only inside the signed payload. The outer request has no copy, so there is no class of "outer and inner disagree" to get wrong.

## Collector checks, in order

These run before any check of the 0.1 install, revoke or clear order. Each failure is refused with `admin_unverified` and a detail that never contains the payload.

1. `admin_signed` is present for a credential kind, and absent for a run.
2. `key_id` names a pinned admin key whose status is `active`, and `algorithm` is `ed25519`.
3. The signature verifies over the prefix for the outer `kind` and the payload. The payload is at most 64 KiB.
4. The payload decodes strictly. `kind`, `principal`, `admin_key_id`, `node_id` and `install_key_id` match as in the table.
5. The time window: `issued_at` is not more than 2 minutes ahead of the collector's clock, `expires_at` has not passed, and `expires_at` is no more than the fixed 15-minute maximum ahead of either `issued_at` or the collector's clock.
6. **The nonce is spent durably before anything else is decided.** It is written to the state file, with its expiry, before the request reaches the install budget or the store. A request that a later check refuses has still spent its nonce, so a signed request is good for exactly one decision. A nonce already in the file is refused with `admin_replay`.

The state file keeps a nonce until its `expires_at` has passed. Nothing older than 15 minutes is ever kept, and the file holds at most 256 unexpired nonces; beyond that, requests are refused with `rate_limited`. A collector clock set back keeps nonces longer, which is safe. A clock set forward drops them early, but step 5 then refuses the same requests as expired.

The install budget stays. It now bounds how fast a real admin can be pressed into signing.

## Admin keys

- **Pinned in `collector.json`** as `admin_keys`: key ID, Ed25519 public key, the principal it speaks for, and status (`active` or `revoked`). The key ID is `"ed25519-"` followed by the first 16 hex digits of SHA-256 over the public key, and the collector checks that it is derived from the key.
- **Set out of band.** A local administrator on the collector host sets it through A5's installer `-collector-config`. A change takes effect at restart, as the register trust anchors do. The node cannot add, change or revoke an admin key. Anyone who can write `collector.json` can already read every secret (design section 10), so this adds no new holder of power.
- **The private key stays with the admin.** It lives in the admin's client: a CLI on the admin workstation, or a browser holding a non-extractable key. Whether WebCrypto Ed25519 is available in the browsers the sites use is [open]. If it is not, the CLI is the Phase 3 path. Phase 2 uses test keys only (D2-5).
- **One key per person.** A key speaks for exactly one principal, so the audit trail names a person, not a shared role.

## What this fixes, and what it does not

**Fixed.**
- A compromised node can no longer originate or alter an install, revoke or clear, so the guessing oracle is closed against the node.
- It cannot swap the sealed secret under a genuine signature.
- It cannot replay a request, to this collector or to another.

**Still possible.**
- A compromised node can drop or delay requests. That is a denial of service, and the admin sees no reply.
- An admin can still learn equality through the reuse rule. That is accepted: the admin can already install any secret, and the budget bounds the rate.
- A compromised admin workstation is a compromised admin. Hardware-backed keys reduce that risk, and are a site decision.

**Audit.** The collector's numbered decision for every credential request (C8, collector-reported) carries the admin key ID and the nonce. A request the node never relayed leaves no record, which is the drop case above. A request the node invents is refused and numbered.

## Tests the implementation owes

- A good install, revoke and clear are each accepted.
- A missing envelope, an unknown key, a revoked key, a key ID not derived from its key, another algorithm, a bad signature, a register-domain signature, an oversize payload and an unknown payload field are each refused with `admin_unverified`, before the budget or the store is touched.
- Each signed-field mismatch is refused: kind, principal, admin key ID, node, install key ID, and the sealed secret replaced after signing.
- A signature made for one operation, presented with another `kind`, is refused, and so is a signature made under another contract version's prefix.
- Replay of the same request, including after a restart, is refused with `admin_replay`.
- A request a later check refuses still spends its nonce.
- Expired, not yet valid and over-long windows are refused, including an `expires_at` that is within 15 minutes of `issued_at` but more than 15 minutes ahead of the collector's clock.
- The 257th unexpired nonce is refused, and expiry frees space.
- A byte scan shows that no payload, secret or signature appears in logs or in the C8 record beyond the key ID and the nonce.

## Contract changes for C7 0.2

- `CollectorRequest.AdminSigned` replaces `CredentialInstall`, `CredentialRevoke` and `CredentialClearSusp` on the wire. The body types stay, inside the payload.
- New refusal codes: `admin_unverified` and `admin_replay`.
- `AdminRequestSigningInput(kind, payload)` sits beside `RegisterSigningInput` and builds the per-operation prefix, plus a verifier like `VerifyRegisterPackage`, so that A6 can test the client and the collector against one definition.
- The collector configuration gains `admin_keys`. That is A3's format, not a contract.
