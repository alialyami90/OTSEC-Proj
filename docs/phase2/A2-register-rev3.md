# A2: SEL-751 register revision 3

Owner: A2 (C3 content). Brief approved by A1, 2026-10-25. Evidence class: **documented-untested**, from S22 (the SEL-751 instruction manual, date code 20260910). No device has been contacted.

## Why

`authz.ValidateSecret` refuses a password that starts with a command mnemonic: the first three characters of the first word of every operation, session line and deny rule (C7-A6-3). This keeps a password the slot sends at the wrong moment from reading as a command. Revision 2 left 36 documented words out, so a password such as `Help2026` or `sal#1` passed. Revision 2 also matched no Spanish form that changes state, unless it was spelled like the English one. The worst case was `89A`, the Spanish 89OPEN, which opens a disconnect. D16 already sends nothing on a non-English port, and egress permits only exact approved lines, so revision 3 adds a third barrier rather than closing an open path.

## What changed

- **Spanish forms added to existing rules.** Each rule gains its Command Summary page as a citation:
  - `sel.disconnect`: 89A.
  - `sel.breaker.ope`: ABR.
  - `sel.settings.set`: AJU.
  - `sel.clock.set`: FEC and HORA with arguments.
  - `sel.tar.reset`: BAN R.
  - `sel.sta.args`: EST with arguments.
  - `sel.breaker.data`: INT R and INT W.
  - `sel.his.clear`: D, DT and RT.
  - `sel.ldp.clear`: D.
- **`sel.ser.clear` now matches R.** Its notes always said it covers C and R, but the pattern had only C, so `SER R` fell to `sel.ser.other_args` (unknown). The line was refused either way; the classification is now right.
- **Three Spanish rules of their own:**
  - `sel.breaker.clo.es` (CER);
  - `sel.settings.group.es` (GRUPO n);
  - `sel.met.reset.es` (MED RD/RE/RM/RP).

  They are separate rules because Go's regexp parser factors a shared prefix out of neighbouring alternatives. `(CLO|CER)` would become `C(?:LO|ER)`, and `ValidateSecret` would derive the mnemonic `C`.
- **`sel.unapproved.command`, last, classified unknown.** It covers every documented word with no approved line, whole and with any arguments. These are the English and Spanish words of the Command Summary and the Compressed ASCII words of Table C.2. Earlier rules decide first. Its alternation is ordered so that no two neighbours share a first character (`build_sel751.py` `interleave`), and must not be sorted.
- **Unchanged:** operations, session lines, preconditions, warnings, firmware and every revision 2 rule's classification, access level, evidence and citations.

## How it is checked

- **`build_sel751.py`** finds every word on its Command Summary page, or in Table C.2, in the S22 text before it writes anything.
- **`contracts/register` `TestContentCommandForms`** covers 196 documented forms, English and Spanish, with sample arguments:
  - only the approved lines are permitted;
  - every form that changes state is denied by a state-changing rule;
  - every other form is denied, except the other forms of ACC, ID, QUI, SHO and SER, which stay unlisted;
  - lower case decides the same way.
- **`TestContentDenyRulesOnlyGrow`:** every revision 2 rule is kept in order, and every line revision 2 denies, revision 3 denies.
- **`TestContentApprovedLinesPermitted`:** the wake, the QUI probe, ID, ACC, SHO P 1, SHO G, SER and the closing QUI are permitted in their phases and match no deny rule.
- **`contracts/authz` `TestSEL751MnemonicsExact`** pins the derived set of 86 mnemonics. `89` comes from `sel.disconnect` and was already in revision 2.
- **`TestSEL751SecretsThatReadAsCommands`:** every word refuses, in either case, and secrets such as `CZ9!` and `ME!x` are still accepted.
- **`TestSEL751Rev3SupersedesRev2`:** revision 3 activates over the revision 2 floor, and revision 2 is then a rollback. It is signed with the test release key only. `sel-751-rev2.json` is revision 2 as built, pinned for this test.

## Ripple

- The C2 goldens are regenerated with `REGISTER_REVISION = 3`; only `register_version` changes.
- A3's two copies of the register are re-copied byte for byte.
- `register_version` goes from 2 to 3 in A3's collector and client tests and fixtures, and in A5's `nodeconfigtest`.
- `tests/safety/windows_installer/node.template.json` still names revision 2. Its collector is a stand-in that is never started, so I left A6's file alone.

## Limits

- The Spanish column comes from a two-column PDF layout, read through `pdftotext -layout`. A6 re-checks the word table against S22 pp. 1 to 9 and Table C.2 independently.
- Whether a Spanish-mode relay also accepts the English words is not documented (unknown, as in revision 2).
- Words from other SEL manuals already in the register stay: BAC, PAC, AAC, OAC, PRO and POR.
