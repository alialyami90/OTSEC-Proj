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
| Repeat (0.5) | For every admin kind, the same signed request stamped 0.5, sent again in the same process and after a restart, is accepted with a new `collector_seq`, `repeat_of` naming the first, and the same `admin` block. Where the action could run again (a credential or asset clear), the test suspends again first, and the repeat leaves it suspended. Nothing but `collector_seq` changes in `state.json` or the credential store (`TestAdminRepeat`). |
| Not a repeat | The same nonce on other signed bytes, a refused request, and a request first accepted at 0.4 are refused when resent (check `replay`) (`TestAdminRepeatOnlyTheSameBytes`). |
| Repeat expiry | Past the request's window the resend is refused (check `window`), and the decision goes with its nonce (`TestAdminRepeatExpires`). |
| Clock put back | Spend a request, move the clock past its expiry, spend another (which drops the first nonce), then put the clock back inside the first request's window: it is refused (check `window`), after a restart too, and the collector raises the "clock is behind" alarm (`TestAdminClockBack`, A6 on #153). |

## Replay protection and the collector's clock

Replay protection rests on the collector's clock. A spent nonce is kept until its request expires, and a request is judged at the **admin clock**. That is the collector's clock, or `admin_clock_utc` in `state.json` when the clock is behind it. `admin_clock_utc` is the latest time a nonce was spent, and it never goes back.

- **A clock put back,** for example by an unauthenticated time source, cannot reopen the window of a request whose nonce was dropped. That request had expired by the admin clock, and the admin clock still says so.
- **While the clock is more than the 2-minute skew behind the admin clock,** every admin request raises an alarm that names how far behind it is.
- **A clock set wrongly forward carries the admin clock with it.** Admin requests are then refused as expired until real time catches up, which fails closed. If that wait is unacceptable, the recovery is a reinstall of the collector state, with its own rules (A1, collector_seq reset). Keep the collector host on an authenticated time source where the site has one.

## The repeat answer at the collector (C7 0.5)

A node that loses a reply sends the same signed request again. Before 0.5 it was refused as a replay, so the node could not tell an accepted request from one never decided. From 0.5 the collector answers it with the first decision (A1 on #184).

- **What is kept.** For each accepted admin request stamped 0.5 or later, `state.json` keeps `admin_decisions`: by nonce, the SHA-256 of the signed payload bytes and the decision's `collector_seq`. An entry exists only while its nonce is in `admin_nonces`, and it is dropped in the same write that drops the nonce, so it is bounded by `MaxAdminNonces` and lives exactly as long. On open, an entry for a nonce not held, a malformed hash, or a number not yet handed out makes the state unavailable.
- **When it is a repeat.** The request passes every check first: key, signature, binding and window. It is a repeat only when it is stamped 0.5 or later and its payload hash equals the kept one. Only accepted decisions are kept, so a refused request resent is a replay. The reply is accepted, takes a fresh `collector_seq` (so the node's rule that each reply is numbered above the last still holds), names the first decision in `repeat_of`, and carries the same `admin` block. **A repeat runs nothing**, and the collector logs `repeat_of` with the decision.
- **Recorded after the action.** The decision is kept after its action has run. If the collector dies between the two, or the write fails (which raises an alarm and leaves the state unavailable), a resend is refused as a replay, as before 0.5. It is never answered as a repeat of an action that did not happen.
- **The node kinds** (`node.quarantine_clear`, `node.seq_reset_ack`) change nothing at the collector. It checks them, spends the nonce and numbers the decision. The node acts on its own part only on `CollectorReply.AdminAcceptance`.
- **Rollback.** A collector built before this change decodes `state.json` strictly and refuses a file holding `admin_decisions`, so it does not start until the site deals with the state: the safe side, as with `level_open`. The field is held only while an accepted 0.5 request's nonce is unexpired (at most 15 minutes, `MaxAdminLifetime`), and it is emptied by the next nonce spent once those have expired, unless that request is itself an accepted 0.5 one. Removing `admin_decisions` from the file by hand, and leaving `admin_nonces`, is also safe: it loses only the repeat answers, and the resends are then refused as replays. A node that sends 0.4 requests gets no repeat and no `admin` block, and its resends are refused as before.

## Not covered

- The signing client, and how its key is held (hardware token or OS key store), is the site's choice and is not built.
- Distribution of the collector host's local administrator rights is site policy (IEC 62443-2-1 account management), not the platform's.
- Central management of many collectors' `admin_keys` (R1.8, distributed deployment) is not designed. Each collector is enrolled by hand.
