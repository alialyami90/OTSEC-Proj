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
- **Decoding is strict**, as for the register: unknown fields, duplicate keys and trailing data are refused. The file is bounded to `MaxEnvelopeBytes` (1.4) before anything parses it. The payload is parsed only after the signature verifies.
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
  - **`sel-fid` ranges are per branch (C6 on #437).** SEL firmware branches are parallel lines, not one order: R302-V9 (D20260831) is newer than R400-V0 (D20230315), and fixes are listed per branch. So for `sel-fid`, a version is the token `R<branch digits>-V<digits>` (C4's note confirms the form against the FIDs the project reads), and `Validate` requires:
    - `introduced` and `fixed`, when both are present, name the same branch (the same `R` part);
    - at least one of the two is present, so a range always names its branch;
    - an absent `introduced` means V0 of the `fixed` branch, and an absent `fixed` means every V of the `introduced` branch from that one on, and nothing on another branch.

    An advisory that affects several branches has one range per branch. Versions on a branch the entry does not name are not affected by that entry. C4's matcher note states the same rule, and GT-ADV states its ranges per branch.
- **`preconditions`** name what must hold for the advisory to apply beyond the version. **`mitigations`** name what, when read, makes it `mitigated`. Each one has:
  - a `name`, unique within the entry, which the finding repeats when the item was not read (V-M7: "that precondition named as unread");
  - a `kind`, a closed enum: `setting` (a C9 setting name), `service` (a service seen on the asset, for R6.7's passive evidence later), `attribute` (a C1 0.3 identity attribute) or `control` (a recorded network control, mitigations only);
  - a `key`;
  - an `op`, a closed enum: `in`, `not-in`, `present` or `absent`;
  - `values`, required for `in` and `not-in`.

  **`control` (C6 on #437).** "R9 classes and what `confirmed` needs" allows `mitigated` on a recorded network control, labelled `operator-attested` when an operator entered it. A `control` item names what the control blocks. Its `key` is `<protocol>/<port>` in 0.1 (`^(tcp|udp)/[1-9][0-9]{0,4}$`, port 65535 or less), its `op` is `present`, and it has no `values`. For example, `tcp/80` for a rule that blocks the device's web server. `Validate` refuses a `control` item among the preconditions, or with another `op` or with values. C11 fixes only how an entry names a control. Where a control is recorded, and by whom, is C1 0.3's or C12's: C2 and C4 settle it, and C11 needs no change either way.

  C11 defines only the shape. Whether a read is current enough to count is C12's and C4's ("R9 classes and what `confirmed` needs", point 3).
- **`test_only`** marks an entry written for tests (GT-ADV). A set whose `purpose` is `release` must not hold one, and is refused whole if it does. This is checked in `Validate`, so it holds whatever build reads it.
- **What an entry deliberately leaves out.** It has no severity, no CVSS and no exploitability field. R9.2 forbids stating exploitability without evidence, and a copied score reads as one. A reader who wants the publisher's score follows the citation. If the owner wants scores shown, it is a 0.2 field labelled as the publisher's, never as the platform's finding.

### 1.4 Limits

| Limit | Value | Why |
| --- | --- | --- |
| `MaxSetPayload` | 1 MiB (1,048,576 B) | The node stores the whole signed file as one configuration-class record on a node-level `advisory` stream (C5, #438), so the bound below must fit that record. |
| `MaxEnvelopeBytes` | 1,399,128 B: the base64 length of `MaxSetPayload` (1,398,104 B) plus 1,024 B for the envelope's other fields and any whitespace | A file over it is `malformed` at step 1, whatever it holds. It is under the node's record cap `ConfigRecordBytes` (1,572,864 B, `platform/node/layout.go`, equal to C9's `RecordCap`) less C9's `RecordHeadroom` (65,536 B), which is 1,507,328 B. So **a set that passes step 1 always fits one record**, with 108,200 B to spare for C5's record framing. A contract test pins `MaxEnvelopeBytes` ≤ `config.RecordCap` − `config.RecordHeadroom`, as D4-25 pinned C9's `RecordsFit`. A contract imports only other contracts, and `TestConfigRecordBytesIsTheDerivedCap` already pins the node's cap to `RecordCap`. `MaxSetPayload` stays at 1 MiB or less while the set is one record (C5). |
| `MaxEntries` | 2048 | |
| Per entry | 16 sources, 64 products, 64 ranges and 256 versions per product, 32 preconditions, 32 mitigations, 64 values per item | Bounds the matcher's work and the hostile-input surface (TB10's rule applies to a file from a USB stick too). |
| Strings | `title` at most 256 bytes; `ref`, `key` and each value at most 128 bytes; `url` at most 512 bytes and `https` only | |

These are proposals. C4 and C5 may ask for others, with a reason.

**Is 1 MiB enough for a realistic SEL set?** I have no measured set: no real advisory has been entered (§6), and none will be before the owner decides question 2. As an estimate only, an entry like the example in 1.3, with two sources, one product, a few ranges and two preconditions, is about 1 to 2 KiB of JSON. At 4 KiB per entry, 1 MiB holds 256 entries. SEL's published security advisories number in the tens, so the bound has a wide margin for SEL alone. It would bind first for a multi-vendor set (after the owner declares SEL coverage complete, ADR-0006). That is the point to measure a real set and, if needed, split the set over records, a C5 change. `Validate` checks the payload's byte length as well as the counts, so `MaxEntries` cannot be reached at the per-entry maximums.

### 1.5 How a node takes a set (the rule V-M8 tests)

The node checks a candidate file in this order and stops at the first failure:

1. **Size and envelope.** The file is at most `MaxEnvelopeBytes`, decodes strictly, names `otsec.advisory/0.x` and `ed25519`. Otherwise: `malformed`.
2. **Key.** `key_id` names an active advisory anchor pinned on this node (1.6). Otherwise: `unknown_key`. An anchor marked revoked gives `revoked_key`.
3. **Signature.** It verifies over `AdvisorySigningInput(payload)`. Otherwise: `bad_signature`. A truncated or altered file fails here or at step 1. An unsigned file (no `signature`) fails at step 1, and its refusal detail is "no signature", so V-M8's unsigned case is told apart from other malformed files without reading the file again (C6).
4. **Payload.** It decodes strictly, its `contract` equals the envelope's, and `Validate` passes. Validation covers every rule in 1.2 to 1.4: a cited source on every entry, no `test_only` entry in a `release` set, known schemes, and the limits. Otherwise: `invalid`. The detail names the first entry that failed, by `id`, and nothing else from the file.
5. **Set.** If the node holds a set, the candidate's `set_id` equals it. Otherwise: `wrong_set`. A node holds one `set_id` in 0.1. A second publisher is a 0.2 question.
6. **Order.** The candidate's `version` is greater than the floor's. If it is equal and the payload's SHA-256 equals the floor's, the set is already in use: nothing is recorded and the file is ignored. If it is equal with other bytes, the result is `same_version_differs`. If it is lower, the result is `older_version`. (D4-49, Q8 to Q11: a same-version set is refused unless byte-identical, a byte-identical one is a no-op, and an entry with no published source refuses the whole set, at step 4.)
7. **Purpose.** A node built for release refuses a `test` set (`test_set`). The existing test-build tag `otsec_testclock` also lets a build accept one. V-M7 and V-M8 on the real binaries need both the test clock and a test set, so one tagged build serves both, and one release refusal pins both: `TestC6ReleaseBuildsRefuseTheTestClock` grows a test-set case (C6 on #437). Whether the tag keeps its name is C5's call. It is a build-time switch, so no configuration can turn it on in a release build.

On success, the node replaces the set atomically (C5's note says how). It moves the floor to (`version`, payload SHA-256) and writes `advisory.set_installed`. On any refusal, the set in use stays in use, untouched, and the node:
- raises the health alarm `advisory-set-refused`, which names the file and the reason code;
- writes `advisory.set_refused` (section 3).

The floor is the in-use set's (`version`, payload SHA-256), derived at start from the store and the audit chain (C5, #438). It survives a restart, so a restart cannot reopen an older set.

- **A frozen set is not silent (C6 on #437, AP-29).** A withheld update leaves a node on an old set. Every finding carries the set's version and date, but nobody may read them. So the node raises `advisory-set-stale` when the set in use was issued more than a configured age ago. The age is the owner's to set, with a proposed default of 90 days. The node judges the age by its own clock, so a clock set back can delay the line. That is the same trust HR-13 records.
- **Residual: a store reset resets the floor (C6 on #437).** Re-enrolling a node or rebuilding its store loses the set and the floor together. The next signed set is then accepted whatever its version, so an older set signed by a valid key can be installed once. The record shows it: that `advisory.set_installed` has no `previous_version`, and the chain is forwarded upstream, where it can be compared with the newest version issued. Pinning the floor somewhere a store reset does not reach would mean a second store with its own failure modes. I do not propose one in 0.1. AP-29 lists this as a residual.

### 1.6 Advisory anchors

- **A separate trust root.** An advisory anchor is an Ed25519 public key in its own list. It is never an admin key (C7 `AdminKey`), a register release key (`TrustAnchor`) or a node TLS key. So no other key's compromise lets someone publish a set, and the signing key's compromise lets someone do nothing else.
- **How anchors arrive.** They are installed as register anchors are: at enrollment or by a signed release of the node software, and never by central policy (AP-7, C-A5-2). A change is audited.
- **The test key is public.** V-M8's signing key is "held by the test only". This repository is public, so any private key committed for tests is known to everyone. A release build therefore refuses to load an advisory anchor whose key ID is in a list compiled into it, `advisory.TestKeyIDs`. Without this, a misconfigured site that pinned the test key would accept a set anyone could sign.
  - **One source of test keys (C6 on #437).** A scan of key files would miss a key built from a fixed seed in code (`ed25519.NewKeyFromSeed` over a constant, or a Python generator with a fixed seed), and that key is just as public. So every advisory test key comes from one helper, `advisorytest.Key(n)`, over a published list of seeds, and `TestKeyIDs` is generated from that list. GT-ADV's signer uses the same seeds.
  - **The contract test** checks that `TestKeyIDs` equals the helper's key IDs. It fails on any `NewKeyFromSeed`, `ed25519.GenerateKey` with a fixed reader, or private-key literal in a Go or Python file under the repository that also signs an advisory set (it names `AdvisorySigningInput` or the signer), other than the helper.
  - **What this cannot catch:** a key generated and committed outside the repository's conventions by someone set on it. That is the anchor's custody, HR-18: anchors arrive only at enrollment or by signed release, never by a configuration file edited at a site.

## 2. C7 0.8: SNMP credentials and the legacy SNMP approval

### 2.1 Credentials

C7 0.8 adds three transports: `snmpv3`, `snmpv2c` and `snmpv1`. `Transport.Plaintext()` is true for `snmpv2c` and `snmpv1`. A community string authenticates nothing and travels in clear, so it is a plaintext credential, like a Telnet password.

- **An SNMPv3 credential** is a USM user, held by the collector like any other device credential (SC-5). It is never in the node's key register (C3's review of #435). Its fields:
  - the user name;
  - the authentication protocol and the privacy protocol, each a closed enum whose values C2's evidence fixes for the chosen family;
  - **the localized keys** (RFC 3414 §2.6), not the passwords. A localized key works only for the one engine ID it was localized to. So a key stolen from one site's collector does not open a device elsewhere that shares the password. The cost is that a replaced device, with a new engine ID, needs a new install. Section 4 needs that anyway.
  - the authoritative engine ID it was localized to, pinned (HR-16).

  The level is always `authPriv`, and the record has no field for another level. So there is no lower level to configure, and none to fall back to.
- **Algorithms (D4-49 Q2).** The client uses only the authentication and privacy protocols configured in the credential. SNMP negotiates nothing, and the client tries no other protocol on failure. C3 rules which protocols may be configured at all:
  - **refused:** `usmHMACMD5AuthProtocol` and `usmDESPrivProtocol`. A credential naming either is refused at install. MD5's collision weakness does not directly break HMAC-MD5, but its 96-bit truncated tag and a 56-bit DES key give no margin, and every agent that offers them is expected to offer SHA and AES as well. If C2's evidence shows the chosen family offers only MD5 or DES, that is a finding for the owner, not a quiet exception. GT-MIB offers both as negative cases.
  - **`encrypted-weak` (SC-7's label), allowed:** `usmHMACSHAAuthProtocol` (HMAC-SHA-1-96). HMAC-SHA-1 has no practical break, but it is the RFC 3414 baseline that RFC 7860 supersedes.
  - **`encrypted-authenticated`:** the HMAC-SHA-2 protocols of RFC 7860, with `usmAesCfb128Protocol` (RFC 3826) or stronger for privacy.
  - **`DownstreamSecurity`** follows the weaker of the two configured protocols. v1 and v2c are `plaintext-unauthenticated`.
- **Purpose.** It stays `collect-readonly`. An SNMP credential reaches only C3 0.4's SNMP read operations (`GET`, `GETNEXT` and `GETBULK` on named OIDs). The collector refuses to resolve it for anything else.

### 2.2 The approval: `asset.legacy_snmp_approval`

**Item 3 builds no v1 or v2c path (D4-49 Q3).** In item 3, C7 0.8 knows `snmpv2c` and `snmpv1` only to refuse them: the collector refuses to install a credential with either transport, and refuses any run that would use one, with `legacy_snmp_unapproved`. V-M1 (d) is shown for that refusal alone, and the item 3 gate says so. The approval below is the design for the later item that adds a v1 or v2c path. It is here so that the refusal code and the threat-model row (HR-17) have one meaning across both, and it is not built in item 3.

V-M1 (d) needs v1 or v2c to be refused for a device with no approval record naming it in the audit chain. C7 adds one admin-signed kind, verified by the collector as every admin-signed request is (`VerifyAdminRequest`).

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
- **How long.** `not_after` is required, and at most 366 days after the request's `issued_at`. An approval that lapses refuses the next run (`legacy_snmp_unapproved`), and the node raises `legacy-snmp-approval-lapsing` 14 days before, once per approval, and `legacy-snmp-approval-lapsed` at the lapse (C5, #438). The node folds the chain and owns health; the collector only refuses. A cleartext credential approved once should not stay approved forever without someone looking at it again.
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

1. **`authPriv` only, with one exemption: discovery (C6 on #437).** RFC 3414 §4 discovery is unauthenticated by design. The one message exempted has exactly this shape: SNMPv3, `msgFlags` reportable with neither auth nor priv, an empty user name, an empty context engine ID, a `GetRequest` and no varbinds. It is sent only before the engine ID is known for this session. Its answer is a Report of `usmStatsUnknownEngineIDs`, which yields the engine ID, boots and time, and is checked against the pin (rule 2). The answer is not otherwise trusted. Every other request is sent with `msgFlags` auth and priv set. An authenticated Report of `usmStatsNotInTimeWindows` updates the engine's boots and time once (RFC 3414 §3.2 step 7), and the request is resent once, at `authPriv`. Any other Report: a Report PDU of `usmStatsUnsupportedSecLevels`, `usmStatsUnknownUserNames`, `usmStatsWrongDigests` or `usmStatsDecryptionErrors` ends the session as a failure, with a health line. Nothing is retried at a lower level, as another user, or over v1 or v2c. A device that answers v2c but not v3 stays unread. In item 3 it has no v1 or v2c path at all (2.2).
2. **The engine ID is pinned at commissioning, as part of the credential (SC-8's rule, no trust on first use; D4-49 Q1).** Discovery is the one unauthenticated exchange RFC 3414 needs. The collector compares the discovered `msgAuthoritativeEngineID` with the credential's pinned one and stops on a mismatch, before it sends any authenticated request. The mismatch has its own failure code and health line (`snmp-engine-id-mismatch`; the C2 failure code is C2's to name in C3 0.4). The client never re-localizes keys to a discovered engine ID: it holds localized keys only (2.1), so it cannot. A changed engine ID means a replaced, reset or impersonated device, and an administrator must decide which (a new credential install).
3. **Time window.** `engineBoots` and `engineTime` follow RFC 3414's window. A response outside it is discarded, and repeated failures raise a health line. The collector never resets its idea of the engine's boots to accept an older value.
4. **No SET can be built.** The egress check (SC-4's equivalent for BER) decodes the final encoded message before it is sent. It refuses any PDU type other than `GetRequest`, `GetNextRequest` or `GetBulkRequest`, any v3 message without auth and priv except the exact discovery shape in rule 1 (matched field by field, and only before the session's engine ID is known), and any OID outside the operation. This check is separate from the code that built the message, as SC-4's is (AP-5).
5. **A walk stays in its subtree (C6 on #437, AP-28).** For `GET`, each OID must be one the operation names. A `GETNEXT` or `GETBULK` continuation carries the last OID the agent returned, which the operation never named. So the rule is that a continuation OID must lie inside a subtree the operation names, and the egress check refuses one outside. On the receiving side, a returned OID outside the named subtree ends that walk: it is the normal end of a subtree walk, and it is never followed. An agent cannot steer the client outside the register this way, and `max-repetitions` stays the register's value. The falsifiable test: GT-MIB returns an out-of-subtree OID, and the client sends no request carrying it.

## 5. Open questions

**For the owner** (decision cards via C1, not assumed here):

1. **Who may sign a legacy SNMP approval.** My recommendation is the owner's own key only, as a separate pinned key that lists only this kind. An approver role is the alternative.
2. **Who publishes the advisory set, and who holds its key** (HR-18). My recommendation:
   - one curator signs on the owner's behalf, with an offline key on a dedicated device that is not on central, any node or CI;
   - a second person checks every new set's citations against the sources before it is signed;
   - the key is never the release key (TB9).
3. **Whether reports show the publisher's severity scores** (a 0.2 field, 1.3).

**For C4.** Are `scheme`, `ranges` and `versions` enough for the SEL FID forms in your matcher note? Do `kind`, `key`, `op` and `values` cover the preconditions GT-ADV needs?

**For C5:** answered on #438 at `7d5c42c`. The set is one configuration-class record on a node-level `advisory` stream, holding the whole signed file. The record is stored first, then `advisory.set_installed`; a set is in use only once its record is in the chain, and a crash between the two is repaired at start. The floor is the in-use set's (version, payload SHA-256), derived at start from the store and the chain. The drop path is `admin_dir/advisory-set.json` under the relay files' lock rules. The lapse alarms are the node's.

**For C2.**
- What are the authentication and privacy protocols the chosen family supports? If it offers only MD5 or DES, that goes to the owner (2.1).
- Does the device's engine ID survive a firmware upgrade? If not, every upgrade needs a credential reinstall (4.2).

## 6. What this note does not cover

- The matcher and the finding (C4, C12).
- The asset module's boundary and SNMP operation format (C2, C1 0.3, C3 0.4).
- Storage (C5).
- GT-ADV and GT-MIB (C6).
- Any real advisory's content. Every entry in tests is `test_only`, and no real advisory is entered until the owner answers question 2.
