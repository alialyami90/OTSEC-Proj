# GT-ADV: advisory applicability ground truth (C6, P4-3-A6)

`gt_adv.json` gives the class each identity must get for each test advisory. It was written by hand before the matcher existed, as the brief for P4-3-A6 requires. The matcher's acceptance test (C4, `modules/applicability/`) reads this file, and the matcher must produce every cell.

**Nothing here is real advisory data.** All eight advisories are invented, marked `test_only`, and named `TEST-ADV-*`. None may go into a release set (C11, R9). The FIDs are real. Fourteen come from S22 Appendix A, as register revision 5 lists them (`contracts/register/testdata/sel-751.json`). The fifteenth, O5, is the example in S22 Figure 3.20 (`tests/fixtures/ied/sel/751/documented-example/id-response-fig3-20.txt`). No device was contacted.

## The rules it follows

The rules are in `docs/verification.md`, "R9 classes and what `confirmed` needs". They are read together with D4-49 (Q5, Q6 and F1 in `docs/phase4/C6-item3-testability.md`) and D4-52. The class and reason tokens are C12's (#440). For one identity and one advisory, the first step that applies decides the cell:

1. **The advisory does not name the product:** `not-applicable`, `not-applicable-operator` or `not-applicable-passive`, according to the identity's source. The reason is `product-not-named`.
2. **The FID cannot be placed on a branch** (O5's `X397`): `applicable-by-version`, with `firmware-version` named as unread. Such a FID is never not-applicable.
3. **The FID is outside every range:** the source's not-applicable class, with reason `outside-range`. Ranges are per branch: a FID on a branch the advisory does not list is outside, whatever its date.
4. **A precondition was read false** (D4-49 Q5, ahead of any other mitigation): on a device-read identity, `not-applicable` with reason `precondition-not-met`; on any other identity, `applicable-by-version`. The one exception is a mitigation that holds on that same setting, which gives `mitigated`. Any other mitigation, such as a recorded control, does not outrank the device's own setting (D10).
5. **A mitigation holds:** `mitigated` (D4-49 Q6 (i)). The cell keeps any unread preconditions (D4-52). A recorded network control marks it `attested`, which means operator-attested.
6. **The identity is device-read and current, and every precondition holds:** `confirmed`. An advisory with no preconditions needs the current FID alone (D4-49 Q6 (iv)).
7. **Otherwise:** `applicable-by-version`, naming each unread precondition. A device-read identity made stale by a later configuration change is marked `stale`, and the change is cited (D4-49 Q6 (ii)).

## Rows

| Row | FID branch and version | Source | EHTTP | Also |
| --- | --- | --- | --- | --- |
| D1 | R501-V0 | device-read | Y | |
| D2 | R501-V0 | device-read | N | |
| D3 | R501-V0 | device-read | unread | no configuration read yet |
| D4 | R500-V1 | device-read | N | |
| D5 | R402-V2 | device-read | N | gate condition met |
| D6 | R400-V7 | device-read | N | gate condition met, lowest allowed V |
| D7 | R501-V0 | device-read | Y | stale: a configuration change was retrieved after the ID read |
| D8 | R500-V0 | device-read | Y | a recorded control blocks tcp/80 |
| D9 | R501-V0 | device-read | unread | a recorded control blocks tcp/80 |
| D10 | R501-V0 | device-read | N | a recorded control blocks tcp/80 |
| O1 | R302-V9 | operator | | denied branch (D4-49 F1) |
| O2 | R301-V2 | operator | | denied branch |
| O3 | R400-V3 | operator | | below the branch's minimum V |
| O4 | R501-V0 | operator | | allowed, before the first read |
| O5 | X397-V0 | operator | | not in Appendix A, so the scheme cannot place it |

**Why the sources fall this way.** The firmware gate decides which identity can be device-read. Each device-read row passes it, and of the operator rows only O4 would pass. `test_firmware_gate_matches_the_sources` checks this against the register.

**What the rows exercise.** The advisories cover these cases:
- ranges with both ends, open-ended ranges, and a range with neither end;
- a branch the advisory does not list (R302 against R301 and R302's V9 fix);
- a setting precondition, and a setting mitigation on the same key (Q5);
- a control mitigation;
- a `service` precondition, which no read path shows before R6.7, so it is always unread;
- a product the rows do not have (SEL-2730M).

## How the file is checked

`test_gt_adv.py` derives every cell again from the rules above and compares the result with the hand-written table, which has 120 cells. It also checks four other things:
- Every FID is real.
- The gate agrees with the sources.
- Every class and reason is reached, except `not-applicable-passive`.
- Each rule is pinned. Eight mutants each break one rule, and every one of them changes at least one cell:
  1. ordering branches as one line;
  2. ignoring staleness;
  3. confirmed beating mitigated;
  4. reading D4-52 strictly;
  5. reversing Q5;
  6. letting any mitigation outrank a precondition read false;
  7. confirming an operator identity;
  8. hiding an unplaceable FID.

The test was also checked against the table itself. A one-field edit to five different cells (a class, a stale mark, evidence and a reason) made the test fail each time.

## Limitations

- **No passive rows.** R6.7 is not built, so `not-applicable-passive` and V-M7's passive clause cannot occur in item 3. They are vacuous here, and a passive row is added when R6.7 is built.
- **No row where a precondition is read false on an operator identity.** An operator identity carries no settings in item 3.
- **Layout.** The JSON layout of the advisories is GT-ADV's own, not C11's set format. Ranges are `[introduced, fixed)` with `null` for an absent end, as in C11's `sel-fid` rules (#437). The set the matcher's test signs is built from these entries in C11's form, with `purpose: test`, using the `advisorytest.Key(n)` helper, on a build tagged `otsec_testclock`.
- **Reaching each row on the real binaries is the acceptance test's job:**
  - The simulator serves the FID.
  - EHTTP comes from SHO P 1, in `sel.config.read_all`.
  - D7 needs a configuration change retrieved after the ID read.
  - D8 and D9 need a control record, which C1 0.3 or C12 will define.
  - The operator rows need an asset entered with a declared FID and no session. For O1 to O3 the gate guarantees that. O4 is evaluated before its first scheduled run.
