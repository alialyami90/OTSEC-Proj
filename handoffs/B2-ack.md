# B2 acknowledgement: OT/IED Integration Engineer (2026-10-27)

B2 read `handoffs/HANDOFF-SUMMARY.md`, then `handoffs/B2-handoff.md`, then the key files it lists: `CLAUDE.md`, P4-A2 and the Phase 4 common rules in `docs/agent-handoffs.md`, `docs/phase3/A2-handoff.md`, `docs/device-capabilities.md`, the `DATE_F` and FTP notes, `modules/ied/sel751/`, `contracts/adapter/doc.go`, the register content and its tests, and V-S7, V-S16, V-M3 and H-13 in `docs/verification.md`.

## What B2 checked on `main` (`8b4c9b2`)

These checks were run in B2's cloud container. No device and no network endpoint was contacted.

- `go test ./modules/ied/... ./contracts/adapter/... ./contracts/register/... ./contracts/asset/...` passes. With `OTSEC_SEL751_TEXT` set, the register tests pass too. `TestSimulator` skips, because `OTSEC_SEL751_SIM` is not set.
- Register content is at revision 4. Its approved lines are `ACC`, `ID`, `QUI`, `SER`, `SHO G` and `SHO P 1`. `content_sel751_test.go` still classes `SHO 1`, `SHO P 2` and `SHO R` as not approved.
- `build_sel751.py` reproduces the committed `sel-751.json` byte for byte. It was run with `python3 -I` against the S22 text in the project's shared folder (`phase0/manuals-SEL/text/751_IM_20260910.txt`). So register work does not need the owner's PC.
- No A2 PR is open. The open PRs are #176, #177, #181, #182 (A5) and #219 (CI).
- `docs/phase-3-exit.md` lists no condition that B2 owns.

## Scope as B2 understands it

**B2 owns:**

- SEL-only IED interoperability, until the owner declares SEL coverage complete (ADR-0006);
- `modules/ied/`, meaning `sel751/` and also `telnet/` (see question 4);
- `tests/fixtures/ied/`;
- `docs/device-capabilities.md`;
- B2's own design notes;
- in Phase 4 item 3, a new `modules/asset/`.

**B2 drafts and B1 approves:**

- C1 (`contracts/asset/`);
- C2 (`contracts/adapter/`), whose goldens come only from `generate.py`;
- C3 register content (`contracts/register/testdata/`, built by `build_sel751.py`);
- in Phase 4, C9 (`contracts/config/`).

Each change bumps the minor, keeps a reader for the previous minor, and needs the consumers' review and B6's contract tests.

**B2 does not touch** B3's, B4's, B5's or B6's paths. When a change of B2's forces an edit in another owner's file, the edit is named in the PR body and confirmed by that owner before merge, as in #175.

**B2 never:**

- contacts a device;
- sends anything but exact register lines;
- adds a write, a Level 2 entry, FTP code or SNMP code without a brief that calls for it;
- puts a credential that is not a test value in the repository.

## First three actions

1. **Ask B1 whether the owner has accepted Phase 3.** Until they have, B2 starts no Phase 4 work: no C9, no register revision 5 and no `config.read`. Meanwhile B2 answers review requests that need IED compatibility or protocol interpretation, for example on B3's and B4's PRs.
2. **Once Phase 4 is issued, draft C9 `otsec.config/0.1`.** It comes as `contracts/config/` (schema, Go types, contract tests) plus a design note, opened as one PR for B1, B3, B5 and B6 to review. It settles three things:
   - the continuation-line rule for wrapped SELOGIC values;
   - the non-semantic rule (headers, the relay's date and time, paging);
   - how a snapshot points at transcript bytes (question 7).
3. **Write register revision 5 and C2 0.6 `config.read`.**
   - Revision 5 has exact `SHO` forms only, each at Level 1 with a timeout and a byte cap. Every `s` form and every bare `SHO P` goes into the deny corpus.
   - Then `config.read` in `sel751`, under the `ser.read` session rules, with a parser and a fuzz target for each settings class, and goldens transcribed from S22.
   - B6 writes the simulator's `SHO` forms independently, and B2 does not read them before its own goldens are fixed.

## Questions and gaps for A2

1. **The `SHO` forms for revision 5 do not cover all of Table 7.67.** Table 7.67 (S22 p. 7.77) also lists:
   - `SHO I` (IEC 60870-5-103);
   - `SHO E m` (EtherNet/IP map, m = 1 to 3);
   - `SHO DNP m` (DNP map, m = 1 to 3);
   - `SHO P n` for ports 2, 3, 4 and F.

   The handoff lists only `SHO 1` to `4`, `SHO L 1` to `4`, `SHO G`, `SHO P 1`, `SHO R`, `SHO F` and `SHO M`. Were the others left out on purpose, for example because they depend on the ordering option? If so, R3.1's "settings an engineer can change" leaves out the other ports' settings, which matter for security. And if they belong in, what should C9 do when a relay without the option rejects the form?
2. **Where should B2's notes go?** The summary says `docs/phase{n}/B{n}-*.md`, and B2's handoff says `docs/phase4/A2-*.md`. B2 will use `docs/phase4/B2-*.md` unless told otherwise.
3. **H-13 does not say what the handoff says it does.** The handoff says the `SHO G` layout and the port-server `T_OUT` rule wait on H-13. But H-13 in `docs/verification.md` names only the Level 0 `QUI` reply, a `SHO P 1` reply and the STX/ETX framing. Should H-13 also capture `SHO G`, each revision 5 form and `T_OUT`? Or is there another hardware item for them? This is B6's file, so the fix would be B6's.
4. **`modules/ied/telnet/` is missing from the handoff.** D2-1 gives it to A2, but the handoff's scope and key files leave it out. B2 takes it as owned unless A2 says otherwise.
5. **Manual text.** The Gotchas say to extract S22 from the owner's PDF. The text in the shared folder already reproduces revision 4, so B2 will use it. Was any A2 artifact built from a different extraction, with different `pdftotext` flags?
6. **Page citation.** P4-A2 in `docs/agent-handoffs.md` cites "Table 7.67, p. 7.78". The table is on p. 7.77, and p. 7.78 has the `SHO` example. This is a one-line fix for B1.
7. **Snapshot bytes.** P4-A2 asks for "one section per settings class with its native bytes and SHA-256". The handoff says the snapshot should "reference C2 transcript spans, not copy bytes twice". B2 reads the two as compatible: the snapshot holds each section's span and SHA-256 over the transcript bytes, and it holds no second copy. Is that A2's intent, and has B5 agreed to it for C5 0.4's size cap?

## Other notes

- **Planned confirmations with other owners.** Revision 5 changes three files that other agents own, and each needs that owner's confirmation:
  - B6's deny corpus, `tests/safety/register_review/test_register.py`;
  - B3's collector tests, where revision 5 is activated through `Registers.Activate`;
  - possibly B4's `ser_test.go`, whose receive times shift.
- **Spanish forms stay denied.** The Spanish `MOS` forms in `content_sel751_test.go` stay denied under revision 5. The `LANG := ENGLISH` precondition is unchanged.
