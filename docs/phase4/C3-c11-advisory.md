# C11 `otsec.advisory/0.1`, the legacy SNMP approval (C7 0.8, C8 0.11), and SNMP's threat model (P4-3-A3)

Owner: C3. Date: 2026-11-05. Status: **draft, for review** (Stage A, D4-48). Reviewers:
- C6, independently, for V-M1 (d), V-M7 and V-M8;
- C2, for the asset module and IED compatibility;
- C4, for the fields the matcher reads (C12 and `docs/phase4/C4-matcher.md`);
- C5, for where the node stores and loads the set.

C1 approves the contracts together with C1 0.3, C3 0.4 and C12 (§5.4). The Go package follows this note's review, as #334 led to #341. Where the two differ, the code is what runs and this note is updated to match.

Every statement here is `desk`. No device, advisory feed or SNMP agent is behind any of it. The threat-model rows this note adds are in `docs/threat-model.md` (AP-28, AP-29, HR-16 to HR-18).

## Why

R9.3 and V-M8 need an advisory set that a site node can trust without reaching the internet. The set must be signed and versioned, and every entry must cite its source. A refused set must leave the set in use in place, with the refusal in health and in the audit chain. V-M7 needs each entry in a form the matcher can evaluate: affected versions, and named preconditions and mitigations, each of which is either read or reported as unread.

R1.8 and V-M1 (d) need a record that lets a device be read over SNMPv1 or v2c only with the owner's approval for that device, and refuse it without one. Those versions carry their community string in clear and authenticate nothing.

## 1. C11 `otsec.advisory/0.1`: the signed set

### 1.1 The envelope

It is the register's pattern (C3 and C7's `VerifyRegisterPackage`), so there is one kind of signed file to review, not two.

```json
{
  "contract": "otsec.advisory/0.1",
  "algorithm": "ed25519",
  "key_id": "ed25519-<16 hex>",
  "payload": "<base64 of the set's JSON bytes>",
  "signature": "<base64 Ed25519 signature over AdvisorySigningInput(payload)>"
}
```

- **The signing input** is `"otsec.advisory/0 set\n"` followed by the payload bytes. The prefix names the contract and the artifact. So a signature over a register package, an admin request or a release can never verify as an advisory set, and the reverse holds too (C3-A3-1's rule).
- **Decoding is strict**, as for the register: unknown fields, duplicate keys and trailing data are refused. The envelope is bounded to twice `MaxSetPayload` before anything parses it. The payload is parsed only after the signature verifies.
- **The key ID** is the admin key rule, `AdminKeyID`: `ed25519-` and the first 16 hex digits of SHA-256 over the public key.

### 1.2 The set (the payload)

```json
{
  "contract": "otsec.advisory/0.1",
  "set_id": "otsec-sel",
  "version": 7,
  "issued_at": "2026-11-05T00:00:00Z",
  "purpose": "release",
  "publisher": "<who curated it>",
  "entries": [ ... ]
}
```

| Field | Rule |
| --- | --- |
| `set_id` | A token, `^[a-z0-9][a-z0-9-]{0,63}$`. A node holds one set per `set_id`. A set with another `set_id` is a different set, never a replacement (see 1.5). |
| `version` | An unsigned integer of 1 or more, strictly increasing per `set_id`. It is the anti-rollback key. |
| `issued_at` | RFC 3339 UTC with `Z`. Every report carries it with `version` (R9.3). It is never used for ordering. Only `version` orders sets, so a wrong clock cannot roll a set back. |
| `purpose` | `release` or `test`. A node built for release refuses a `test` set (1.5, rule 7). |
| `publisher` | Free text, at most 128 bytes, for people. It confers nothing: what the node trusts is the key. |
| `entries` | From 0 to `MaxEntries` entries, each with a distinct `id`. |

### 1.3 An entry

```json
{
  "id": "adv-sel-2025-0001",
  "test_only": false,
  "title": "<short text>",
  "sources": [
    { "kind": "vendor-advisory", "ref": "<the publisher's ID>", "url": "https://...",
      "published": "2025-03-01", "retrieved": "2026-11-01", "sha256": "<hex of the retrieved document>" }
  ],
  "affected": [
    { "vendor": "SEL", "product": "SEL-751", "scheme": "sel-fid",
      "ranges": [ { "introduced": "<version>", "fixed": "<version>" } ],
      "versions": [] }
  ],
  "preconditions": [
    { "name": "telnet-enabled", "kind": "setting", "key": "ETELNET", "op": "in", "values": ["Y"] }
  ],
  "mitigations": [
    { "name": "telnet-disabled", "kind": "setting", "key": "ETELNET", "op": "in", "values": ["N"] }
  ]
}
```

- **`sources`** must hold at least one citation. A set with an entry that cites nothing is refused whole (V-M8: "an entry with no published source is refused"). `kind` is a closed enum: `vendor-advisory`, `cve`, `national-advisory` (for example a CISA ICS advisory), `other`. `ref` is required. `published` is required, as a date. `url`, `retrieved` and `sha256` are optional. `sha256` lets a reviewer show that the entry was written from the document cited.
- **`affected`** must hold at least one product.
  - `vendor` and `product` are compared exactly with the identity attributes C1 0.3 defines (C2's draft). C4's matcher note says how a device's model string maps to `product`.
  - `scheme` is a closed enum that names how versions compare. 0.1 has `sel-fid` (the SEL firmware ID string forms the project already reads) and `exact` (string equality only). The comparison rules are C4's (`docs/phase4/C4-matcher.md`), and C11 only names them. A reader that meets an unknown scheme refuses the set, because a set the node cannot evaluate is not one it can claim to use.
  - `ranges` are half-open: `introduced` is inclusive and may be absent ("from the first version"), and `fixed` is exclusive and may be absent ("no fix"). `versions` lists exact affected versions. At least one range or one version is required.
- **`preconditions`** name what must hold for the advisory to apply beyond the version. **`mitigations`** name what, when read, makes it `mitigated`. Each one has:
  - a `name`, unique within the entry, which the finding repeats when the item was not read (V-M7: "that precondition named as unread");
  - a `kind`, a closed enum: `setting` (a C9 setting name), `service` (a service seen on the asset, for R6.7's passive evidence later) or `attribute` (a C1 0.3 identity attribute);
  - a `key`;
  - an `op`, a closed enum: `in`, `not-in`, `present` or `absent`;
  - `values`, required for `in` and `not-in`.

  C11 defines only the shape. Whether a read is current enough to count is C12's and C4's ("R9 classes and what `confirmed` needs", point 3).
- **`test_only`** marks an entry written for tests (GT-ADV). A set whose `purpose` is `release` must not hold one, and is refused whole if it does. This is checked in `Validate`, so it holds whatever build reads it.
- **What an entry deliberately leaves out.** It has no severity, no CVSS and no exploitability field. R9.2 forbids stating exploitability without evidence, and a copied score reads as one. A reader who wants the publisher's score follows the citation. If the owner wants scores shown, it is a 0.2 field labelled as the publisher's, never as the platform's finding.

### 1.4 Limits

| Limit | Value | Why |
| --- | --- | --- |
| `MaxSetPayload` | 1 MiB | It fits one C5 configuration record (1.5 MiB) with headroom, if C5 stores the set there (C5's note). The SEL advisories number in the tens, not thousands. |
| `MaxEntries` | 2048 | |
| Per entry | 16 sources, 64 products, 64 ranges and 256 versions per product, 32 preconditions, 32 mitigations, 64 values per item | Bounds the matcher's work and the hostile-input surface (TB10's rule applies to a file from a USB stick too). |
| Strings | `title` at most 256 bytes; `ref`, `key` and each value at most 128 bytes; `url` at most 512 bytes and `https` only | |

These are proposals. C4 and C5 may ask for others, with a reason.

### 1.5 How a node takes a set (the rule V-M8 tests)

The node checks a candidate file in this order and stops at the first failure:

1. **Size and envelope.** The file is at most twice `MaxSetPayload`, decodes strictly, names `otsec.advisory/0.x` and `ed25519`. Otherwise: `malformed`.
2. **Key.** `key_id` names an active advisory anchor pinned on this node (1.6). Otherwise: `unknown_key`. An anchor marked revoked gives `revoked_key`.
3. **Signature.** It verifies over `AdvisorySigningInput(payload)`. Otherwise: `bad_signature`. A truncated or altered file fails here or at step 1. An unsigned file (no `signature`) fails at step 1.
4. **Payload.** It decodes strictly, its `contract` equals the envelope's, and `Validate` passes. Validation covers every rule in 1.2 to 1.4: a cited source on every entry, no `test_only` entry in a `release` set, known schemes, and the limits. Otherwise: `invalid`. The detail names the first entry that failed, by `id`, and nothing else from the file.
5. **Set.** If the node holds a set, the candidate's `set_id` equals it. Otherwise: `wrong_set`. A node holds one `set_id` in 0.1. A second publisher is a 0.2 question.
6. **Order.** The candidate's `version` is greater than the floor's. If it is equal and the payload's SHA-256 equals the floor's, the set is already in use: nothing is recorded and the file is ignored. If it is equal with other bytes, the result is `same_version_differs`. If it is lower, the result is `older_version`.
7. **Purpose.** A node built for release refuses a `test` set (`test_set`). A build tag lets a test build accept one. It is the same pattern as `otsec_testclock`, and a release-build test pins the refusal, as `tests/security/testclock_c6_test.go` does for the clock.

On success, the node replaces the set atomically (C5's note says how). It moves the floor to (`version`, payload SHA-256) and writes `advisory.set_installed`. On any refusal, the set in use stays in use, untouched, and the node:
- raises the health alarm `advisory-set-refused`, which names the file and the reason code;
- writes `advisory.set_refused` (section 3).

The floor is kept with the set. It survives a restart, so a restart cannot reopen an older set.

### 1.6 Advisory anchors

- **A separate trust root.** An advisory anchor is an Ed25519 public key in its own list. It is never an admin key (C7 `AdminKey`), a register release key (`TrustAnchor`) or a node TLS key. So no other key's compromise lets someone publish a set, and the signing key's compromise lets someone do nothing else.
- **How anchors arrive.** They are installed as register anchors are: at enrollment or by a signed release of the node software, and never by central policy (AP-7, C-A5-2). A change is audited.
- **The test key is public.** V-M8's signing key is "held by the test only". This repository is public, so any private key committed for tests is known to everyone. A release build therefore refuses to load an advisory anchor whose key ID is in a list compiled into it, `advisory.TestKeyIDs`. That list holds every key ID used under `testdata` or `tests/`. A contract test checks that every key in those trees is listed. Without this, a misconfigured site that pinned the test key would accept a set anyone could sign.

## 2. C7 0.8: SNMP credentials and the legacy SNMP approval

### 2.1 Credentials

C7 0.8 adds three transports: `snmpv3`, `snmpv2c` and `snmpv1`. `Transport.Plaintext()` is true for `snmpv2c` and `snmpv1`. A community string authenticates nothing and travels in clear, so it is a plaintext credential, like a Telnet password.

- **An SNMPv3 credential** is a USM user, held by the collector like any other device credential (SC-5). It is never in the node's key register (C3's review of #435). Its fields:
  - the user name;
  - the authentication protocol and the privacy protocol, each a closed enum whose values C2's evidence fixes for the chosen family;
  - **the localized keys** (RFC 3414 §2.6), not the passwords. A localized key works only for the one engine ID it was localized to. So a key stolen from one site's collector does not open a device elsewhere that shares the password. The cost is that a replaced device, with a new engine ID, needs a new install. Section 4 needs that anyway.
  - the authoritative engine ID it was localized to, pinned (HR-16).

  The level is always `authPriv`, and the record has no field for another level. So there is no lower level to configure, and none to fall back to.
- **`DownstreamSecurity`** is `encrypted-authenticated` for `snmpv3` when both protocols are on the strong list in HR-16, `encrypted-weak` when either is on the weak list, and `plaintext-unauthenticated` for v1 and v2c.
- **Purpose.** It stays `collect-readonly`. An SNMP credential reaches only C3 0.4's SNMP read operations (`GET`, `GETNEXT` and `GETBULK` on named OIDs). The collector refuses to resolve it for anything else.

### 2.2 The approval: `asset.legacy_snmp_approval`

V-M1 (d) needs v1 or v2c to be refused for a device with no approval record naming it in the audit chain. C7 0.8 adds one admin-signed kind, verified by the collector as every admin-signed request is (`VerifyAdminRequest`).

```json
{
  "kind": "asset.legacy_snmp_approval",
  "legacy_snmp_approval": {
    "asset_id": "<C1 asset ID>",
    "endpoint_id": "<the C1 endpoint>",
    "snmp_version": "v2c",
    "credential_ref": "cred_...",
    "reason": "<at most 512 bytes, for the audit record>",
    "not_after": "2027-11-05T00:00:00Z"
  }
}
```

- **Who may sign it.** It is not in `DefaultAdminKinds`, so only a key whose pinned list names it may sign it (the authority check, D4-2). A collector with no such key refuses every v1 and v2c use, which fails closed.
- **What it binds.** It names one asset, one endpoint, one version and one credential reference. It covers nothing else. Replacing the community credential (a new `CredentialRef` version) does not carry the approval over: a new credential needs a new approval.
- **How long.** `not_after` is required, and at most 366 days after the request's `issued_at`. An approval that lapses refuses the next run (`legacy_snmp_unapproved`), and a health alarm is raised 14 days before it lapses (C5's note says which process raises it). A cleartext credential approved once should not stay approved forever without someone looking at it again.
- **Revocation.** `credential.revoke` of the named credential ends it. A later approval for the same asset and endpoint replaces the earlier one.
- **What the collector checks for a v1 or v2c run.** A live approval names this asset, endpoint, version and credential, and has not lapsed. Otherwise it refuses with `legacy_snmp_unapproved` before the credential is resolved, so the refusal spends nothing and sends nothing. An SNMPv3 run never needs or uses an approval.
- **The plaintext scope.** C7 0.1's `PlaintextScope` has one value, `lab-only`, and says production plaintext needs an owner decision and a contract change. This approval is that decision, made per device. C7 0.8 adds the scope `owner-approved`, valid only for `snmpv1` and `snmpv2c`, and only with a live approval. Telnet keeps `lab-only` (HR-8 and ADR-0005 are unchanged).

## 3. C8 0.11: the records

| Action | Actor | Outcome | Fields |
| --- | --- | --- | --- |
| `advisory.set_installed` | node | `succeeded` | `set_id`, `version`, `issued_at`, `payload_sha256`, `key_id`, and `previous_version` (absent on the first set) |
| `advisory.set_refused` | node | `denied` | `reason_code` (the 1.5 codes: `malformed`, `unknown_key`, `revoked_key`, `bad_signature`, `invalid`, `wrong_set`, `same_version_differs`, `older_version`, `test_set`); the file's SHA-256; and `set_id`, `version` and `key_id` when they were read before the refusal |
| `asset.legacy_snmp_approved` | collector, with the verified admin group (C8 0.4) | `succeeded` | the approval's six fields and the admin key ID |
| `collector.request` | collector | `denied` | the new refusal code `legacy_snmp_unapproved` |

- **No silent refusal.** A refused set always writes `advisory.set_refused`, even when the in-use set is unchanged. An identical file that is already in use writes nothing, so a node that re-reads its drop directory every minute does not flood the chain.
- **`VerifyConfig`'s rules are unchanged.** These actions are outside the configuration chain's rules. But a 0.10 reader's `Record.Validate` refuses an action it does not know (`audit.go`, "unknown action"), and `VerifyConfig` reads only records that pass `Validate`. So, as for 0.10, readers are upgraded before a node or collector writes one. The collector and the node ship together, so this is an upgrade-order rule, not a migration.

## 4. SNMPv3: no downgrade, and the engine ID

These are rules for C2's SNMP client and C3 0.4's operation. They are written here because they are trust-boundary rules. V-M1 (c) tests them.

1. **`authPriv` only.** Every request is sent with `msgFlags` auth and priv set. A Report PDU of `usmStatsUnsupportedSecLevels`, `usmStatsUnknownUserNames`, `usmStatsWrongDigests` or `usmStatsDecryptionErrors` ends the session as a failure, with a health line. Nothing is retried at a lower level, as another user, or over v1 or v2c. A device that answers v2c but not v3 stays unread until someone installs a v2c credential and approves it (2.2).
2. **The engine ID is pinned at commissioning (SC-8's rule, no trust on first use).** Discovery is the one unauthenticated exchange RFC 3414 needs. The collector compares the discovered `msgAuthoritativeEngineID` with the pinned one and stops on a mismatch, before it sends any authenticated request. A changed engine ID means a replaced, reset or impersonated device, and an administrator must decide which (a new credential install).
3. **Time window.** `engineBoots` and `engineTime` follow RFC 3414's window. A response outside it is discarded, and repeated failures raise a health line. The collector never resets its idea of the engine's boots to accept an older value.
4. **No SET can be built.** The egress check (SC-4's equivalent for BER) decodes the final encoded message before it is sent. It refuses any PDU type other than `GetRequest`, `GetNextRequest` or `GetBulkRequest`, any v3 message without auth and priv, and any OID not named by the operation. This check is separate from the code that built the message, as SC-4's is (AP-5).

## 5. Open questions

**For the owner** (decision cards via C1, not assumed here):

1. **Who may sign a legacy SNMP approval.** My recommendation is the owner's own key only, as a separate pinned key that lists only this kind. An approver role is the alternative.
2. **Who publishes the advisory set, and who holds its key** (HR-18). My recommendation:
   - one curator signs on the owner's behalf, with an offline key on a dedicated device that is not on central, any node or CI;
   - a second person checks every new set's citations against the sources before it is signed;
   - the key is never the release key (TB9).
3. **Whether reports show the publisher's severity scores** (a 0.2 field, 1.3).

**For C4.** Are `scheme`, `ranges` and `versions` enough for the SEL FID forms in your matcher note? Do `kind`, `key`, `op` and `values` cover the preconditions GT-ADV needs?

**For C5.**
- Where does the set live? One configuration-class record fits under 1.4.
- How is the atomic replacement done, and where is the floor kept?
- What is the drop path the node reads? The relay files' directory is the model.

**For C2.**
- What are the authentication and privacy protocols the chosen family supports? HR-16's strong and weak lists depend on them.
- Does the device's engine ID survive a firmware upgrade? If not, every upgrade needs a credential reinstall (4.2).

## 6. What this note does not cover

- The matcher and the finding (C4, C12).
- The asset module's boundary and SNMP operation format (C2, C1 0.3, C3 0.4).
- Storage (C5).
- GT-ADV and GT-MIB (C6).
- Any real advisory's content. Every entry in tests is `test_only`, and no real advisory is entered until the owner answers question 2.
