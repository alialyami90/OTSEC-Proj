# The applicability matcher: design note (P4-3-A4)

Owner: C4. Date: 2026-11-05. Status: **draft for review** under Phase 4 item 3 Stage A (D4-48). Reviewers: C6 and C2. C1 approves it together with C12, C11 and C1 0.3. Evidence class: `desk`. No matcher code exists, and none is written in this stage.

This note covers how an asset's identity is matched against an entry of the signed advisory set to give a finding:
- the set is C11, `otsec.advisory/0.1` (C3's draft, `docs/phase4/C3-c11-advisory.md`, #437);
- the finding is C12, `otsec.finding/0.1` (`contracts/finding`, drafted beside this note).

The classes are fixed by `docs/verification.md` ("R9 classes and what `confirmed` needs", V-M7 and V-M8) and by C1's answers in D4-49. This note does not change them. C1 settled the one question it raised in D4-52, subject to C6 (section 8).

## 1. Where the matcher lives: a new `modules/applicability/`

The matcher goes in a new package, `modules/applicability/`, owned by C4, not in `modules/detection/`. The reasons:

- **R9 has its own switch.** V-M8 compares two runs, one with R9 on and one with it off. D4-50 makes R9 depend on the asset module, and nothing else. `modules/detection/` holds the event baseline (R4.8) and, later, the IDS (R6), and each of those has its own switch. A package of its own puts R9 behind one switch with nothing else behind it.
- **It reads from three owners and belongs to none.** It reads:
  - identity, from C2's asset module and the SEL adapter;
  - settings, from C9 snapshots;
  - later, passive observations, from R6.7 in detection.

  Inside `modules/detection/`, it would make detection the module that imports the asset module. As its own package, it depends only on `contracts/`, and no producer knows it exists.
- **It is a pure function.** It takes stored records and the set, and returns findings, with no I/O, clock or network. So V-M8's no-probe rule holds by construction: the package has no way to send a packet. The node (C5) feeds it and stores what it returns.

The ownership table in `README.md` is C1's, so the new row is C1's to add on approval.

## 2. Inputs and output

`Evaluate(identity, evidence, set, previous) → []finding.Finding`, one finding per entry. The inputs are:
- the asset's identity attributes under C1 0.3, each with its kind (`device-read`, `passive` or `operator`), its read path and its evidence ID (D4-49 Q4);
- the asset's evidence records: its C9 snapshots and, later, its R6.7 observations;
- the set in use;
- the asset's latest finding per entry, so that a change becomes a new revision.

The same inputs always give the same bytes. Every finding names the matcher and its version. The matcher's tests run every GT-ADV cell twice.

## 3. Versions under C11's `sel-fid` scheme

### The FID form the project reads

The SEL-751 `ID` reply carries the FID as `"FID=<value>","<checksum>"` (S22 Table 7.43, Figure 7.38, p. 7.64). The SER header carries it too, as `FID = <value> CID = <value>` (`serFIDCID` in `modules/ied/sel751/parse_ser.go`). The adapter reads it into the attribute `firmware_id` (`attrFID` in `modules/ied/sel751/run.go`).

A2's allowlist gives the form, from S22 Appendix A (`docs/phase0/A2-sel751-firmware-allowlist.json`, `fid_match`):

```
<product>-R<branch>-V<n>-Z<six digits>-D<yyyymmdd>
SEL-751-R301-V2-Z009005-D20220607      (S22 Figure 7.38, fixture id-response-fig7-38.txt)
```

The project's fixtures hold two other forms, and the matcher must not misread either:

- `SEL-751-X397-V0-Z007003-D20170305` (S22 Figure 3.20, fixture `id-response-fig3-20.txt`). Its branch letter is `X`, not `R`, and it is not in Appendix A. No source in the project says what `X` means.
- The SEL-400 series CSE example names its FID only as "SEL-411L 2001" (`tests/fixtures/ied/sel/400-series/documented-example/SOURCE.md`). The project holds no 400-series FID string to define a form from.

### Parsing

A FID is parsed with one anchored expression:

```
^(SEL-[0-9A-Z]+)-R([0-9]{3})-V([0-9]+)-Z([0-9]{6})-D([0-9]{8})$
```

It gives the product (`SEL-751`), the branch (`301`) and the version number (`2`). The Z and D fields are kept as read and take no part in the comparison.

- **Product.** The device's `product` is the FID's product part. It is matched exactly against C11's `affected[].product`. For the SEL-751, `DEVID` in the same reply must agree. `SEL-751A` is a different product, with its own manual and FIDs (the allowlist's `not_covered`).
- **SNMPv3 families.** Their product and FID come from the Entity MIB. The project has not yet read that string form (section 3.1).

### Comparison: within one branch, never across

Branches are parallel lines, not one sequence. Appendix A lists fix F1 on both R112-V2 and R200-V3, and both are dated D20170814 (allowlist, `fixes.F1`). So "R200 is later than R112" says nothing about which fixes R200 carries, and the matcher never orders two branches.

C11 ranges are half-open: `introduced` is inclusive, `fixed` is exclusive, and either may be absent. Under `sel-fid`, I ask C11 to fix their form as follows:

- **Endpoints.** Each endpoint is `R<branch>-V<n>`, for example `R301-V3`, and never a full FID, since Z and D are not compared.
- **One branch per range.** A range with both endpoints present has them on the same branch, with `introduced` V below `fixed` V.
- **One endpoint.** A range with one endpoint covers that branch only. "No fix" means every later V on that branch, and never a later branch.
- **No endpoint.** A range with neither endpoint covers every version of the product, including FIDs the matcher cannot parse (below).
- **Exact versions.** `versions` lists full FIDs, compared as whole strings.

C11's `Validate` should refuse any other shape. An advisory published as "R302 and earlier" is then written by the set's author as one range per branch, citing the publisher, and the matcher never guesses the order.

**Inside or outside.** A parsed FID is inside when either of these holds:
- it is listed exactly;
- a range on its branch contains its V;
- a range with no endpoint covers the product.

It is outside when the product is named and none of these holds. That includes the case where the entry has no range on the FID's branch: an entry that names a product but not a branch does not affect that branch. So C11 entries must list every affected branch. C3 and C6 should check that this reading suits the advisories they cite.

### A FID that cannot be placed

These FIDs can be neither inside nor outside:
- a FID that does not parse, including the `X` branch;
- a FID whose product differs from the `DEVID` in the same reply;
- a FID of a family whose form the project has not read.

Such a FID is never `not-applicable`. If the entry names the product, the finding is `applicable-by-version` with the precondition `firmware-version` listed as unread. That name is reserved in C11. A range with no endpoint still places such a FID inside. So an unplaceable FID can only keep an advisory visible, never hide it.

### 3.1 SNMPv3 families

The FID is in the Entity MIB on these families (`docs/device-capabilities.md`):
- the SEL-2730M (S43 p. 155);
- the SEL-2731 and SEL-2741 in RSTP mode (S29 p. 75).

The project has not read the string form they use, and it may not follow the SEL-751's. Until C2's family note cites the form, their FIDs cannot be placed, as above. Once it is cited, it becomes one more parse expression with its own fixture under the same rules. It needs no change to C11's shape or to C12.

### Not covered in 0.1

The matcher reads but never compares:
- the boot firmware ID (`BFID`);
- the IEC 61850 `configVersion`.

An entry about either cannot be matched in 0.1. C11 should refuse one until a later version adds the form.

**SEL-751 firmware that is denied (D4-49 F1).** On branch R302 and older, no session runs, not even one for `ID`. Such a relay's identity is `operator`, and its findings can never be `confirmed`. GT-ADV pins this with rows on denied branches.

## 4. Preconditions and mitigations under C11's shape

Every C11 precondition and mitigation has a `name`, a `kind`, a `key`, an `op` (`in`, `not-in`, `present` or `absent`) and, for `in` and `not-in`, `values`. The matcher reads each one from current evidence only (section 5) and gives it one of three results:
- **holds:** the matching evidence is cited;
- **does not hold:** the matching evidence is cited;
- **unread:** no current evidence shows it either way.

What it reads depends on the kind:

- **`setting`:** the setting `key` in the asset's latest C9 snapshot. `present` and `absent` test whether the key is in the snapshot. `in` and `not-in` compare the value as stored, byte for byte, with no case folding or trimming. If the snapshot does not hold the key's section, the result is unread.
- **`attribute`:** the C1 0.3 identity attribute `key`, compared the same way. Values are compared whole, so a condition on one position of `PARTNO` (an option fitted) cannot be expressed in 0.1. That is enough for GT-ADV. For real advisories, it is a question for C11 0.2.
- **`service`:**
  - **Before R6.7,** only a device-read value counts.
  - **With R6.7,** a passive observation of the service in the device's own traffic, citing its packets, also shows `present` or `in`. Traffic that was not seen never shows `absent` or `not-in`, so those stay unread unless a device read shows them.

## 5. Classification, step by step

For one asset and one entry:

1. **Product not named:** the class is set by the identity's kind, with reason `product-not-named`:
   - device-read: `not-applicable`;
   - operator: `not-applicable-operator`;
   - passive: `not-applicable-passive` (D4-49 Q6 (iii)).
2. **FID not placeable:** `applicable-by-version`, with `firmware-version` listed as unread (section 3).
3. **Outside every range:** the class by kind as in step 1, with reason `outside-range`.
4. **Inside a range.** The preconditions and mitigations are read as in section 4. Then the first rule that applies sets the class:
   - **a.** If any mitigation holds, the class is `mitigated` (D4-49 Q6 (i)), and the precondition results are kept. This covers D4-49 Q5's case where the advisory names a setting both as a precondition and as its mitigation: the precondition does not hold and the mitigation holds. A mitigation whose only evidence is an operator's entry is marked `operator_attested`.
   - **b.** If any precondition does not hold, the class depends on the identity (D4-49 Q5):
     - with a device-read identity, `not-applicable` with reason `precondition-not-met`, citing the settings read;
     - otherwise, `applicable-by-version`, with that precondition shown as `not-met`.
   - **c.** The class is `confirmed` when all of these are true:
     - the identity is device-read and current;
     - every precondition holds on current device-read or passive evidence.

     An entry with no preconditions is `confirmed` on a current device-read FID alone (D4-49 Q6 (iv)).
   - **d.** Otherwise the class is `applicable-by-version`. Each unread precondition is named. Any evidence that would have made the finding `confirmed` but is stale is kept and marked `stale` (D4-49 Q6 (ii)).

`contracts/finding` checks every rule above that holds on one record. It cannot check currency, because currency depends on records stored after the evidence. Currency is the matcher's rule, and GT-ADV tests it.

## 6. Evidence currency

Point 3 of "what `confirmed` needs" says evidence is current when no later read contradicts it and no configuration change has been retrieved since. D4-49 Q6 (iv) makes the second half asset-wide. For each record the matcher cites:

- **Identity.** The identity is current only while both hold:
  - it is the asset's latest successful identity read;
  - no configuration change has been retrieved for the asset since that read.

  The SEL-751 reads `ID` at Level 0 on every run (the FID gate), so the next run makes it current again. A later read with another value contradicts it, and the matcher evaluates on the new value. That includes a `refused.identity_mismatch`, whose observed FID is a device read.
- **Settings.** A C9 snapshot is current while it is the asset's latest snapshot and no change has been retrieved after it.
- **Passive observations (R6.7).** An observation is current until one of two things happens: a configuration change is retrieved after it, or a device-read setting contradicts it.
- **Operator entries.** An operator entry is current until it is replaced. It never supports `confirmed`, and it never makes a precondition `not-met` on a device-read identity.

A failed read contradicts nothing and leaves the evidence as it was. Only a successful read with another value contradicts it.

## 7. When it runs, and how a change is recorded

D4-49 Q7 sets when evaluation runs. The node runs it after each commit of an identity, settings or configuration record for the asset, and after each set replacement. The finding's change is stored before the asset's next scheduled read starts. With R6.7, the commit of a passive observation for the asset is one more trigger. V-M7's "at the next evaluation" is therefore the first of these after the read that contradicted the evidence.

A finding is never edited. An evaluation may differ from the asset's latest finding for that entry in any of these:
- the class or reason;
- the identity;
- a precondition, a mitigation, or any evidence or its `stale` mark;
- the set.

Then it records a new finding with `revision` + 1, with `previous` set to the hash of the bytes it replaces, and with `from` set to that finding's class. A finding carries no "why" text: the difference between two revisions records the change. An evaluation that changes nothing records nothing.

Which findings the node stores, and in which C5 class, is for C5's note (P4-3-A5). My suggestion is to store every finding whose entry names the asset's product. A `product-not-named` finding follows from the product and the set, so storing one for every asset and every entry adds nothing.

## 8. Unread preconditions on a mitigated finding (D4-52)

**Unread preconditions on a mitigated finding.** V-M7 says an unread precondition "leaves the finding `applicable-by-version`". D4-49 Q6 (i) covers the case where every precondition holds. Read strictly, V-M7 would hide an evidenced mitigation whenever another precondition is unread.

**C1's ruling (D4-52, subject to C6, since V-M7 is C6's):** a `mitigated` finding may list unread preconditions, by the same precedence as D4-49 Q6 (i), and it still names each one. The draft does this.

**The tokens.** The class tokens `not-applicable-operator` and `not-applicable-passive` stand for "not-applicable (operator)" and "not-applicable (passive)". GT-ADV (C6) should use the same tokens.

## 9. What this asks of C11 (C3) and C1 0.3 (C2)

**Of C11:**
- the `sel-fid` range shape of section 3, checked in `Validate`;
- `firmware-version` reserved as a precondition name;
- precondition and mitigation names of the form `^[a-z][a-z0-9._-]{0,63}$`, which C12 repeats;
- entry IDs of the form `^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`;
- refusal of an entry about `BFID` or `configVersion`.

The rest of C11's §1.3 is enough for the matcher and for GT-ADV's cells. C12 carries no severity or CVSS, matching C11.

**Of C1 0.3:**
- one evidence ID on every attribute. The draft takes an evidence ID as either the `event.EventID` of a stored record or `audit:<node_id>:<seq>` for an operator entry in the C8 chain;
- if C1 0.3 stores operator entries some other way, C12 follows it.

**How R6.7 plugs in later.** A passive observation becomes a stored record, and a finding cites it as evidence with source `passive`. C12 does not change. C11's `service` kind already exists. What remains is R6.7's own observation record and the matcher reading it. V-M7's rule that passive evidence never confirms an identity is already in `Validate`, because `confirmed` needs a device-read identity.

## 10. What a simulated run will and will not show

Over GT-ADV, a run shows:
- the classification rules;
- the evidence links;
- the revision chain;
- that the matcher sends nothing.

It shows nothing about the real FIDs on site, or about what a real advisory's conditions are. Those belong to V-M7's hardware-dependent column: H-01, and a desk check of each advisory against its publisher.
