# Admin keys: distribution, rotation and revocation (P3-A3)

Owner: A3. Reviewer: A6. Status: procedure for review. It applies to the `admin_keys` the collector pins in `collector.json` (C7 0.4, D2-11; design in `docs/phase2/A3-signed-credential-requests.md`). **Phase 3 uses test keys only (D2-5).** No real admin key exists, and none may be committed, pasted into an issue or pull request, or used on a real device.

## What an admin key does

An admin key signs every credential request (install, revoke, clear suspension) and the signed asset clear. The collector accepts a request only when it is signed by a key pinned in its own `collector.json`, has status `active`, and is bound to that key's person. The node relays signed requests. It cannot originate, alter or replay one, and it cannot add, change or revoke a key.

| Property | Rule |
| --- | --- |
| Algorithm | Ed25519. |
| Key ID | `ed25519-` followed by the first 16 hex digits of SHA-256 over the 32-byte public key (`authz.AdminKeyID`). The collector refuses a pinned ID that is not derived from its key, and a key ID pinned twice. |
| Fingerprint | The full SHA-256 of the public key, in hex. People compare **the fingerprint**, never only the key ID. The ID is 64 bits: it selects the key, but it is too short to be the thing a person checks by eye. |
| One key per person | Each pinned key names exactly one human principal. A shared or role key is not allowed, because the audit trail must name a person. |
| Where the private key lives | With the person, in their signing client on the admin workstation. It stays in a hardware token or a non-exportable OS key store where the site has one. It is never on the node or collector host, and never in a file the node can read. |
| Lifetime of a signed request | At most 15 minutes, with 2 minutes of clock skew allowed. The client issues 10 minutes (A1 on #146). |

The signing client (a CLI on the admin workstation, or a browser holding a non-extractable key) is not built. Whether WebCrypto Ed25519 is available in the sites' browsers is [open]. Until the client exists, only the test helpers sign: `modules/security/collector/adminsig_test.go`, `cmd/otsec-collector/main_test.go`, and A6's `slicehelper`, which makes a fresh key for each run.

## Who can do what

| Role | Can | Cannot |
| --- | --- | --- |
| Administrator (a person) | Hold their own private key; sign requests; ask for their key to be pinned, rotated or revoked. | Pin their own key on a collector without the collector host's local administrator. |
| Collector host's local administrator | Edit `collector.json` (owner Administrators, collector reads, node nothing; design W-4), through A5's installer `-collector-config`, and restart the collector. | Sign for another person. Anyone who can write `collector.json` can already read every secret (design section 10), so this role adds no new holder of power. |
| Node service | Relay signed requests. | Read or write `collector.json`; add, change or revoke a key; sign. |

## Procedures

### 1. Enrol a new administrator

1. The administrator generates an Ed25519 key pair in their signing client. The private key never leaves the client.
2. The client prints the public key (standard base64), its key ID and its fingerprint.
3. The administrator sends the public key and key ID to the collector host's local administrator, through the site's normal change channel.
4. **Fingerprint check, on a second channel.** The local administrator computes the fingerprint from the public key they received. The administrator reads theirs from the client, by phone or in person, never over the channel that carried the key. The two must match in full. If they do not, stop: the key was altered in transit.
5. The local administrator adds an entry to `admin_keys`:
   ```json
   {"key_id": "ed25519-…", "public_key": "<base64>", "principal": "<person>@<site>", "status": "active"}
   ```
   `principal` is the C7 human principal ID the person signs as.
6. Restart the collector. A config error stops the start, so a mistyped key never runs: wrong length, a key ID not derived from the key, a duplicate, or an unknown status.
7. Check the start log. Each pinned key is listed (`admin key pinned`, with key ID, principal and status). If no key is active, the collector raises `no active admin key pinned: every credential request will be refused`.
8. Record the enrolment in the site's change record: the person, the key ID, the fingerprint, the date and both people's names.

### 2. Rotate a key (planned)

1. Enrol the new key as in 1, with status `active`, beside the old one. Restart.
2. Make the next real signed request with the new key and confirm it is accepted.
3. Set the old entry's status to `revoked`. **Keep the entry**: it maps the old key ID to its person for anyone reading earlier audit records. Restart.
4. The old private key may then be destroyed in the client.

At no point is the collector left with no active key for that person.

### 3. Revoke a key (lost, compromised, or the person leaves)

1. Set the entry's status to `revoked` and restart the collector **at once**. Until the restart, the old key still works: the pinned set is read only at start, as the register trust anchors are.
2. A request that key signed before the revocation can be replayed for at most its remaining lifetime (15 minutes at most). After the restart, every such request is refused with check `key`, and a replayed nonce with check `replay`.
3. If the key may have been used by someone else, review every credential request since the suspected time. The collector's replies are numbered (`collector_seq`), and the node's C8 `collector.request` records name the key ID. Revoke or replace any credential installed or cleared in that window.
4. If the person had no other key and was the only administrator, a new key is enrolled as in 1. That needs the collector host's local administrator, which is the intended recovery path.

### 4. Retire a collector or reinstall it

A reinstalled collector has a new install key. Every signed request is bound to the install key ID, so requests signed for the old install are refused with check `binding`. The `admin_keys` entries must be carried into the new `collector.json`, and checked by fingerprint again if they were re-typed.

## What the audit shows

- **Collector side.** Every decision is numbered. A refusal is `admin_unverified` with a fixed detail naming the check (`envelope`, `key`, `signature`, `payload`, `binding`, `window`, `replay`, `capacity`), and the collector raises an alarm with the reason. Neither ever holds the payload, the sealed secret or the signature.
- **Node side.** The node's C8 `collector.request` record carries the reply's check in its detail (A5, agreed). The design also calls for the record to name the admin key ID and the nonce from the envelope. The node can read both without trusting them, because the collector has decided. That is A5's part of the node wiring.

## Tests A6 can run against this procedure

| Step | Check |
| --- | --- |
| Enrol | A key whose ID is not derived from it, a duplicate ID, a 31-byte key, an empty principal or an unknown status stops the start (`cmd/otsec-collector` `TestParseConfig`). |
| Enrol | A collector with no active key raises the start alarm, and refuses an install with check `key`. |
| Rotate | With both keys pinned, both are accepted. With the old one revoked, only the new one is. |
| Revoke | A request signed before the revocation is refused after the restart (check `key`). |
| Reinstall | A request signed for the old install key is refused (check `binding`). |
| Replay | The same signed request, after a restart, is refused (check `replay`) (`TestAdminReplayRefused`). |

## Not covered

- The signing client, and how its key is held (hardware token or OS key store), is the site's choice and is not built.
- Distribution of the collector host's local administrator rights is site policy (IEC 62443-2-1 account management), not the platform's.
- Central management of many collectors' `admin_keys` (R1.8, distributed deployment) is not designed. Each collector is enrolled by hand.
