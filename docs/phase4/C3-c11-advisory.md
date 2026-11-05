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

- **`id`** matches `^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$` and is unique in the set (C4, because C12 repeats it).
- **`sources`** must hold at least one citation. A set with an entry that cites nothing is refused whole (V-M8: "an entry with no published source is refused"). `kind` is a closed enum: `vendor-advisory`, `cve`, `national-advisory` (for example a CISA ICS advisory), `other`. `ref` is required. `published` is required, as a date. `url`, `retrieved` and `sha256` are optional. `sha256` lets a reviewer show that the entry was written from the document cited.
- **`affected`** must hold at least one product.
  - `vendor` and `product` are compared exactly with the identity attributes C1 0.3 defines (C2's draft). C4's matcher note says how a device's model string maps to `product`.
  - `scheme` is a closed enum that names how versions compare. 0.1 has `sel-fid` (the SEL firmware ID string forms the project already reads) and `exact` (string equality only). The comparison rules are C4's (`docs/phase4/C4-matcher.md`), and C11 only names them. A reader that meets an unknown scheme refuses the set, because a set the node cannot evaluate is not one it can claim to use.
  - `ranges` are half-open: `introduced` is inclusive and may be absent ("from the first version"), and `fixed` is exclusive and may be absent ("no fix"). `versions` lists exact affected versions. At least one range or one version is required.
  - **`sel-fid` ranges are per branch (C6 and C4 on #437).** SEL firmware branches are parallel lines, not one order. R302-V9 (D20260831) is newer than R400-V0 (D20230315), and Appendix A lists fix F1 on both R112-V2 and R200-V3, dated the same day. So the matcher compares only within one branch, on V, and never orders two branches. For `scheme: sel-fid`, `Validate` requires:
    - each endpoint is `R<branch>-V<n>` (`^R[0-9]{3}-V[0-9]+$`), never a full FID, because Z and D are not compared;
    - a range with both endpoints has them on the same branch, with `introduced`'s V below `fixed`'s V;
    - a range with one endpoint covers that branch only: an absent `introduced` means V0 of the `fixed` branch, and an absent `fixed` means every V of the `introduced` branch from that one on, so "no fix" never reaches a later branch;
    - a range with no endpoint covers every version of the product, on every branch (for example, an advisory about the hardware);
    - each `versions` item is a full FID, compared as a whole string.

    **An entry must list every affected branch.** An advisory published as "R302 and earlier" is written as one range per branch, each citing the publisher. A FID on a branch the entry has no range for is outside the entry (`outside-range` in C12). C4's matcher note (#440, §3 and §4) states the same rule, and GT-ADV states its ranges per branch. A FID the matcher cannot place at all gives `applicable-by-version`, with the reserved precondition `firmware-version` named as unread (below).
- **`preconditions`** name what must hold for the advisory to apply beyond the version. **`mitigations`** name what, when read, makes it `mitigated`. Each one has:
  - a `name`, unique within the entry, matching `^[a-z][a-z0-9._-]{0,63}$`, which the finding repeats when the item was not read (V-M7: "that precondition named as unread"). The name `firmware-version` is reserved for the matcher's unplaced-FID case (C4), and `Validate` refuses an entry that uses it;
  - a `kind`, a closed enum: `setting` (a C9 setting name), `service` (a service seen on the asset, for R6.7's passive evidence later), `attribute` (a C1 0.3 identity attribute) or `control` (a recorded network control, mitigations only);
  - a `key`;
  - an `op`, a closed enum: `in`, `not-in`, `present` or `absent`;
  - `values`, required for `in` and `not-in`.

  **`control` (C6 on #437).** "R9 classes and what `confirmed` needs" allows `mitigated` on a recorded network control, labelled `operator-attested` when an operator entered it. A `control` item names what the control blocks. Its `key` is `<protocol>/<port>` in 0.1 (`^(tcp|udp)/[1-9][0-9]{0,4}$`, port 65535 or less), its `op` is `present`, and it has no `values`. For example, `tcp/80` for a rule that blocks the device's web server. `Validate` refuses a `control` item among the preconditions, or with another `op` or with values. C11 fixes only how an entry names a control. Where a control is recorded, and by whom, is C1 0.3's or C12's: C2 and C4 settle it, and C11 needs no change either way.

  C11 defines only the shape. Whether a read is current enough to count is C12's and C4's ("R9 classes and what `confirmed` needs", point 3). Three further rules (C4 on #437):
  - **Comparison is byte for byte.** `in` and `not-in` compare the value as stored, with no case folding. So a condition on one position of a value (for example one character of `PARTNO`) cannot be written in 0.1. That is fine for GT-ADV, and a 0.2 question for real advisories.
  - **Passive evidence never shows absence.** Under `kind: service`, a passive observation (R6.7, later) can show `present` or `in`, but never `absent` or `not-in`, because traffic that was not seen proves nothing. Those ops on a service stay unread unless a device read shows them.
  - **Attributes the matcher cannot compare are refused.** The matcher reads `BFID` and `configVersion` but compares neither in 0.1. So `Validate` refuses a `kind: attribute` item keyed on either, rather than let an entry the matcher cannot evaluate sit in the set and match nothing.
- **`test_only`** marks an entry written for tests (GT-ADV). A set whose `purpose` is `release` must not hold one, and is refused whole if it does. This is checked in `Validate`, so it holds whatever build reads it.
- **What an entry deliberately leaves out.** It has no severity, no CVSS and no exploitability field. R9.2 forbids stating exploitability without evidence, and a copied score reads as one. A reader who wants the publisher's score follows the citation. If the owner wants scores shown, it is a 0.2 field labelled as the publisher's, never as the platform's finding.

### 1.4 Limits

| Limit | Value | Why |
| --- | --- | --- |
| `MaxSetPayload` | 1 MiB (1,048,576 B) | The node stores the whole signed file as one configuration-class record on a node-level `advisory` stream (C5, #438), so the bound below must fit that record. |
| `MaxEnvelopeBytes` | 1,399,128 B: the base64 length of `MaxSetPayload` (1,398,104 B) plus 1,024 B for the envelope's other fields and any whitespace | A file over it is `malformed` at step 1, whatever it holds. It is under the node's record cap `ConfigRecordBytes` (1,572,864 B, `platform/node/layout.go`, equal to C9's `RecordCap`) less C9's `RecordHeadroom` (65,536 B), which is 1,507,328 B. So **a set that passes step 1 always fits one record**, with 108,200 B to spare for C5's record framing. A contract test pins `MaxEnvelopeBytes` ≤ `config.RecordCap` − `config.RecordHeadroom`, as D4-25 pinned C9's `RecordsFit`. A contract imports only other contracts, and `TestConfigRecordBytesIsTheDerivedCap` already pins the node's cap to `RecordCap`. `MaxSetPayload` stays at 1 MiB or less while the set is one record (C5). |
| `MaxEntries` | 2048 | |
| Per entry | 16 sources, 64 products, 64 ranges and 256 versions per product, 32 preconditions, 16 mitigations, 64 values per item | Bounds the matcher's work and the hostile-input surface (TB10's rule applies to a file from a USB stick too). |
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

- **A set whose key is later revoked stops being used (C3 on #438).** At every start, and whenever the advisory anchors change, the node verifies the stored set in use again against the anchors pinned now, steps 2 and 3 above. If its key is now revoked or no longer pinned, the set is no longer in use: the matcher does not run, the node raises `advisory-set-refused` with `revoked_key` or `unknown_key`, and `applicability-no-set` stands until a valid set arrives. The floor stays where it was, so the next accepted set must still be newer. Findings already stored are not rewritten, and each still names the set it was made under. A start that repairs a missing `advisory.set_installed` (C5's fold) verifies the set the same way before it writes the record.
- **One refusal record per file (C3 on #438).** A refused file left in `admin_dir` is reported once: `advisory.set_refused` and the alarm are keyed by the file's SHA-256, and the same bytes found again at a later tick or after a restart write nothing new.

- **A frozen set is not silent (C6 on #437, AP-29).** A withheld update leaves a node on an old set. Every finding carries the set's version and date, but nobody may read them. So the node raises `advisory-set-stale` when the set in use was issued more than a configured age ago. The age is the owner's to set, with a proposed default of 90 days. The node judges the age by its own clock, so a clock set back can delay the line. That is the same trust HR-13 records.
- **Residual: a store reset resets the floor (C6 on #437).** Re-enrolling a node or rebuilding its store loses the set and the floor together. The next signed set is then accepted whatever its version, so an older set signed by a valid key can be installed once. The record shows it: that `advisory.set_installed` has no `previous_version`, and the chain is forwarded upstream, where it can be compared with the newest version issued. Pinning the floor somewhere a store reset does not reach would mean a second store with its own failure modes. I do not propose one in 0.1. AP-29 lists this as a residual.

### 1.6 Advisory anchors

- **A separate trust root.** An advisory anchor is an Ed25519 public key in its own list. It is never an admin key (C7 `AdminKey`), a register release key (`TrustAnchor`) or a node TLS key. So no other key's compromise lets someone publish a set, and the signing key's compromise lets someone do nothing else.
- **How anchors arrive.** They are installed as register anchors are: at enrollment or by a signed release of the node software, and never by central policy (AP-7, C-A5-2). A change is audited.
- **The test key is public.** V-M8's signing key is "held by the test only". This repository is public, so any private key committed for tests is known to everyone. A release build therefore refuses to load an advisory anchor whose key ID is in a list compiled into it, `advisory.TestKeyIDs`. Without this, a misconfigured site that pinned the test key would accept a set anyone could sign.
  - **One source of test keys (C6 on #437).** A scan of key files would miss a key built from a fixed seed in code (`ed25519.NewKeyFromSeed` over a constant, or a Python generator with a fixed seed), and that key is just as public. So every advisory test key comes from one helper, `advisorytest.Key(n)`, over a published list of seeds, and `TestKeyIDs` is generated from that list. GT-ADV's signer uses the same seeds.
  - **The contract test** checks that `TestKeyIDs` equals the helper's key IDs. It fails on any `NewKeyFromSeed`, `ed25519.GenerateKey` with a fixed reader, or private-key literal in a Go or Python file under the repository that also signs an advisory set (it names `AdvisorySigningInput` or the signer), other than the helper.
  - **What this cannot catch:** a key generated and committed outside the repository's conventions by someone set on it. That is the anchor's custody, HR-18: anchors arrive only at enrollment or by signed release, never by a configuration file edited at a site.

### 1.7 Where the text was silent, and what the code does (P4-3-C3)

The code follows 1.1 to 1.6 and 2.1. These points were not settled by the text, and the code settles them as follows, for C1 and the reviewers to confirm on the contract PR:

- **`exact` ranges.** `exact` compares strings and has no order, so a range under it may only be the empty one, which covers every version. A range with an endpoint under `exact` makes the set `invalid`.
- **`present` and `absent` take no `values`.** An item with those ops and values makes the set `invalid`, as for `control`.
- **A `sel-fid` `versions` item is a full FID** in the form `SEL-<model>-R<nnn>-V<n>-Z<nnnnnn>-D<yyyymmdd>`, which every FID in the project's sources has.
- **`vendor`, `product` and an `exact` version** are required and non-empty. An `exact` version is at most 128 bytes, the bound for a value.
- **The refusal's fields.** `Refusal` carries `key_id` only once it is in its form, and `set_id` and `version` only after step 4, so `advisory.set_refused` never holds unchecked bytes from the file.
- **An `snmpv3` credential has no access level** (`access_level` is empty). SNMP has none: the register names the OIDs, and the device's view bounds the user.
- **The localized keys are the sealed secret**: the authentication key, then the 16-byte AES-128 key, 48 or 80 bytes. `MaxSealedLen` is 80, while a password stays at most `MaxSecretLen` (64). The seal's AAD also names the user, both protocols and the engine ID, so keys cannot be moved to another engine ID. Telnet and SSH keep their AAD unchanged.
- **The sole-password attestation** is the field `usm.sole_device_attested`, which must be `true`.
- **An `snmpv3` install needs a request stamped `otsec.authz/0.8` or later**, in the clear or admin-signed (D4-16's rule).

## 2. C7 0.8: SNMP credentials and the legacy SNMP approval

### 2.1 Credentials

C7 0.8 adds one transport, `snmpv3`. It does not add `snmpv2c` or `snmpv1`, because C1 0.3 does not either (C2's draft on #439, D4-49 Q3): an endpoint or a credential naming them is refused as an unknown transport. The later minor that adds them makes `Transport.Plaintext()` true for both, because a community string authenticates nothing and travels in clear, like a Telnet password (2.2).

- **An SNMPv3 credential** is a USM user, held by the collector like any other device credential (SC-5). It is never in the node's key register (C3's review of #435). Its fields:
  - the user name;
  - the authentication protocol and the privacy protocol, each a closed enum whose values C2's evidence fixes for the chosen family;
  - **the localized keys** (RFC 3414 §2.6), not the passwords. A localized key works only for the one engine ID it was localized to. So a key stolen from one site's collector does not open a device elsewhere that shares the password. The cost is that a replaced device, with a new engine ID, needs a new install. Section 4 needs that anyway.
  - the authoritative engine ID it was localized to, pinned (HR-16).

  The level is always `authPriv`, and the record has no field for another level. So there is no lower level to configure, and none to fall back to.
- **Algorithms (D4-49 Q2, C2 on #437).** The client uses only the authentication and privacy protocols configured in the credential. SNMP negotiates nothing, and the client tries no other protocol on failure. The credential's two fields are closed enums that hold **only the strong values**, so a weaker protocol cannot even be named:
  - authentication: `hmac-sha-256` and `hmac-sha-512` (RFC 7860, `usmHMAC192SHA256AuthProtocol` and `usmHMAC384SHA512AuthProtocol`);
  - privacy: `aes-128` (RFC 3826, `usmAesCfb128Protocol`).

  MD5, SHA-1 and DES are not in the enums. HMAC-MD5 and DES give no margin (D4-49 Q2). HMAC-SHA-1 has no practical break, but it is the RFC 3414 baseline that RFC 7860 supersedes, and C2's recommended family (SEL-2731 and SEL-2741 in RSTP mode, S29 Table 4.13, p. 45) offers SHA-256 and SHA-512, so nothing needs it. AES-256 is left out too: USM AES-256 has no RFC, two key-extension methods are in use, and S29 does not say which one the device uses. It is added only after hardware shows which (C2). GT-MIB offers MD5, SHA-1, DES and AES-256 as negative cases.
  - **The family is chosen (D4-51):** the SEL-2731 and SEL-2741 in RSTP mode, so SHA-1 stays out. If the SEL-2730M (S43) follows later, SHA-1 is its best authentication (Table 5.14, p. 84), and SHA-1 then gets its own ruling.
  - **`DownstreamSecurity`** is `encrypted-authenticated` for every `snmpv3` credential these enums allow, and `plaintext-unauthenticated` for v1 and v2c. C1 0.3 treats SNMPv3 `authPriv` with a pinned engine ID and a localized key as a `pinned-key` binding (C2's draft on #439), which keeps the label consistent with C1 0.2's rule.
- **One USM password per device (C2 on #437).** Localized keys protect the collector's store, but the device holds its own key or the password. If two devices share a password and one is compromised, the attacker can localize keys to every other pinned engine ID and impersonate those devices to the collector. So commissioning gives each device a distinct USM password. The platform cannot see this from outside. It is a commissioning rule beside C2's read-only, no-Trap profile rule, and the credential install records the operator's attestation of it.
- **Purpose.** It stays `collect-readonly`. An SNMP credential reaches only C3 0.4's SNMP read operations (`GET`, `GETNEXT` and `GETBULK` on named OIDs). The collector refuses to resolve it for anything else.

### 2.2 The approval: `asset.legacy_snmp_approval`

**Item 3 builds no v1 or v2c path (D4-49 Q3).** Neither C1 0.3 nor C7 0.8 names `snmpv2c` or `snmpv1`. An asset record with such an endpoint fails C1's `Validate` (unknown transport), so the asset is refused whole, and a credential install naming either fails C7's. V-M1 (d) is shown for that refusal alone, with zero PDUs at GT-MIB, and the item 3 gate says so. The approval below is the design for the later item that adds a v1 or v2c path, which needs a C1 minor and the owner's decision (HR-17). It is here so that HR-17 has a design to point to. Nothing in it is built in item 3, and neither is its refusal code `legacy_snmp_unapproved`.

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
| `asset.legacy_snmp_approved` (later item, not 0.11) | collector, with the verified admin group (C8 0.4) | `succeeded` | the approval's six fields and the admin key ID |
| `collector.request` (later item, not 0.11) | collector | `denied` | the new refusal code `legacy_snmp_unapproved` |

- **No silent refusal.** A refused set always writes `advisory.set_refused`, even when the in-use set is unchanged. An identical file that is already in use writes nothing, so a node that re-reads its drop directory every minute does not flood the chain.
- **`VerifyConfig`'s rules are unchanged.** These actions are outside the configuration chain's rules. But a 0.10 reader's `Record.Validate` refuses an action it does not know (`audit.go`, "unknown action"), and `VerifyConfig` reads only records that pass `Validate`. So, as for 0.10, readers are upgraded before a node or collector writes one. The collector and the node ship together, so this is an upgrade-order rule, not a migration.

## 4. SNMPv3: no downgrade, and the engine ID

These are rules for C2's SNMP client and C3 0.4's operation. They are written here because they are trust-boundary rules. V-M1 (c) tests them.

1. **`authPriv` only, with one exemption: discovery (C6 on #437).** RFC 3414 §4 discovery is unauthenticated by design. The one message exempted has exactly this shape, every field fixed (C6's list on #437):
   - `msgVersion` 3 and `msgSecurityModel` 3 (USM);
   - `msgFlags` reportable, with neither auth nor priv;
   - in the USM security parameters: `msgAuthoritativeEngineID` empty, `msgAuthoritativeEngineBoots` 0, `msgAuthoritativeEngineTime` 0, `msgUserName` empty, `msgAuthenticationParameters` empty and `msgPrivacyParameters` empty;
   - in the scoped PDU: `contextEngineID` empty and `contextName` empty;
   - a `GetRequest` with an empty varbind list.

   It is sent only before the engine ID is known for this session. A noAuthNoPriv message that carries a known or guessed authoritative engine ID is not discovery, and is refused like any other unauthenticated message. Its answer is a Report of `usmStatsUnknownEngineIDs`, which yields the engine ID, boots and time, and is checked against the pin (rule 2). The answer is not otherwise trusted. Every other request is sent with `msgFlags` auth and priv set, and any other response at a level below authPriv (a noAuthNoPriv or authNoPriv Response, even one with a valid digest) is discarded unparsed. **Two Reports are expected, each at most once per session and in this order (C2 on #437):** discovery's `usmStatsUnknownEngineIDs`, and then an authenticated Report of `usmStatsNotInTimeWindows` answering the first authenticated request. That Report carries the engine's boots and time (RFC 3414 §4), which the client adopts, and the request is resent once, at `authPriv`. The time-window Report must authenticate. A second occurrence of either Report, or any other Report, ends the session: a Report PDU of `usmStatsUnsupportedSecLevels`, `usmStatsUnknownUserNames`, `usmStatsWrongDigests` or `usmStatsDecryptionErrors` ends the session as a failure, with a health line. Nothing is retried at a lower level, as another user, or over v1 or v2c. A device that answers v2c but not v3 stays unread. In item 3 it has no v1 or v2c path at all (2.2).
2. **The engine ID is pinned at commissioning, as part of the credential (SC-8's rule, no trust on first use; D4-49 Q1).** Discovery is the one unauthenticated exchange RFC 3414 needs. The collector compares the discovered `msgAuthoritativeEngineID` with the credential's pinned one and stops on a mismatch, before it sends any authenticated request. Every later response must carry the pinned `msgAuthoritativeEngineID`, and one that does not is discarded before its digest is checked. The mismatch has its own failure code and health line (health `snmp-engine-id-mismatch`; C2 0.7's code `refused.engine_id_mismatch`, #439). The client never re-localizes keys to a discovered engine ID: it holds localized keys only (2.1), so it cannot. A changed engine ID means a replaced, reset or impersonated device, and an administrator must decide which (a new credential install).
3. **Time window.** After the one adoption in rule 1, `engineBoots` and `engineTime` follow RFC 3414's window. A response outside it is discarded, and repeated failures raise a health line. The collector never resets its idea of the engine's boots to accept an older value.
4. **No SET can be built.** The egress check (SC-4's equivalent for BER) decodes the final encoded message before it is sent. It refuses any PDU type other than `GetRequest`, `GetNextRequest` or `GetBulkRequest`, any v3 message without auth and priv except the exact discovery shape in rule 1 (matched field by field, and only before the session's engine ID is known; GT-MIB's deny corpus holds one near miss per field, each refused: `msgVersion` 1 (a v2c message), a `msgSecurityModel` other than 3, the reportable flag clear, a nonempty authoritative engine ID, nonzero boots, nonzero time, a user name, nonempty authentication parameters, nonempty privacy parameters, a nonempty `contextEngineID`, a context name, a `GetNextRequest`, and one varbind (C2, C6), and any OID outside the operation: for a `get`, an OID not in its `oids` list; for a `getnext` or `getbulk`, an OID outside its `subtree` (rule 5, C3 0.4's operation shape on #439). This check is separate from the code that built the message, as SC-4's is (AP-5).
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

**For C2:** answered in C2's review of #437.
- The protocols are in 2.1.
- The engine ID is `80 00 7C 4F 03` followed by the unit's MAC (S29 p. 42, S43 p. 80). So it should survive a firmware upgrade and change only with the hardware, but that is `inferred` from the format, not documented. A factory-default reset clears SNMP and, by inference, the USM users. So a firmware upgrade should need no credential reinstall, and a replaced unit always will. The new V-M1 H item checks both.

## 6. What this note does not cover

- The matcher and the finding (C4, C12).
- The asset module's boundary and SNMP operation format (C2, C1 0.3, C3 0.4).
- Storage (C5).
- GT-ADV and GT-MIB (C6).
- Any real advisory's content. Every entry in tests is `test_only`, and no real advisory is entered until the owner answers question 2.
