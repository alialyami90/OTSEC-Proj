# B2 handoff: OT/IED Integration Engineer (from A2, 2026-10-27)

You replace A2. You remember nothing of A2's work, so this file states the current state and links to the rest. Read `handoffs/HANDOFF-SUMMARY.md` first (A1 writes it), then this file, then the key files below in order.

## Role & scope

**You own:**
- IED interoperability and adapters, as the brief describes (`CLAUDE.md` §4, A2), for SEL devices only until the owner declares SEL coverage complete (ADR-0006).
- `modules/ied/`: the SEL-751 adapter `modules/ied/sel751/`, and `modules/ied/telnet/`, the minimal RFC 854 client that refuses every option (D2-1).
- `tests/fixtures/ied/`.
- `docs/device-capabilities.md`.
- Your own design notes: A2's are `docs/phase3/A2-*.md`; yours go in `docs/phase4/B2-*.md`, the summary's convention.

**Shared contracts you draft but A1 approves:**
- C1 asset (`contracts/asset/`);
- C2 adapter (`contracts/adapter/`);
- C3 register content (`contracts/register/`, signed);
- in Phase 4, the new C9 configuration contract (`contracts/config/`).

Each change bumps the minor, keeps a reader for the previous minor, and needs every consumer's review.

**You do not touch:**
- `modules/security/` or `modules/access/` (A3);
- `modules/telemetry/` or `modules/detection/` (A4);
- `platform/`, `deploy/` or `ui/` (A5);
- `tests/integration/`, `tests/security/`, `tests/safety/` or `docs/verification.md` (A6).

When a change of yours forces an edit in another owner's file (a fixture literal, a test helper), make it in your PR. Name it in the PR body, and get that owner's confirmation on the PR before merge. #175's "Fixture changes in other owners' files" table is the model.

**Never:**
- contact a device;
- send anything but exact register lines;
- add a write, a Level 2 entry, or any FTP or SNMP code without a brief that says so.

## Current state

Phase 3 is complete for A2, with nothing in progress and nothing uncommitted. Every A2 PR is merged, the last one being #211 (`e16ee25`). A1's exit report is `docs/phase-3-exit.md`. Phase 4 has not started: its briefs are in `docs/agent-handoffs.md` ("Phase 4 task briefs"), issued only when the owner accepts Phase 3.

| Item | State | Where |
| --- | --- | --- |
| C1 0.2: `Endpoint.Path` (`direct` or `port-server`) and `CheckPath` | merged | #149, `docs/phase3/A2-c1-path.md` |
| C3 0.2 context reads; SEL-751 register revision 4 (`ctx.date_f`: `SHO G` read for `sel.ser.read_all`) | merged | #156, `docs/phase3/A2-c3-context.md` |
| C2 0.5: `refused.endpoint_path` and `Result.Settings` | merged | #164 |
| SEL-751 adapter 0.2.0: the path rule, `DATE_F` from `SHO G`, `TIDLE` reported only from `SHO P 1` and only after `ok` or `partial` | merged; A6 PASS | #175, `docs/phase3/A2-sel751-datef.md` (15 acceptance cases) |
| Collection-method rungs for every SEL family, and the SEL-751 FTP assessment | merged; A6 checked 12 cells | #183, `docs/device-capabilities.md` ("Collection-method rungs"), `docs/phase3/A2-sel751-ftp.md` |
| `DATE_F` orders through the normalizer | merged; A6 PASS, 8 of 8 mutants | #211, `tests/integration/slice/test_sel751_date_orders.py` |
| P3-A2 handoff (section 5.5 format) | merged | `docs/phase3/A2-handoff.md` |
| Full DMY and YMD slice reconcile on the real binaries (store, forwarder, receiver) | **not run**; carried to P4-A6 (A6 owns it) | `docs/phase-3-exit.md` |

Evidence class for everything above: `simulated` or `documented-untested`. Nothing is hardware-verified, and no SEL family may be called supported (B-01).

## Next steps

1. **First action:** ask B1 whether the owner has accepted the Phase 3 exit. On 2026-10-27 it was **not owner-accepted**, so P4-A2 is held. Until it is accepted, start no Phase 4 work.
2. Once accepted, read task **P4-A2** in `docs/agent-handoffs.md`. It carries A2's five points from S22 Table 7.67 (p. 7.77) and the `SHO` example on p. 7.78:
   1. **Exact forms only.** The register holds only exact `SHO` forms, with no trailing `s` and an explicit port. Every form takes an optional `s` that jumps to a named setting, and `SHO P n` defaults to the active port when `n` is left out.
   2. **Wrapped values.** C9 states a continuation-line rule for SELOGIC values that wrap. A rewrap at another column must give an empty difference.
   3. **Layout.** The parsers follow the three-settings-per-line layout, where a name can sit one space from `:=` (`SINGLEV := N`).
   4. **Sensitivity.** `SHO P 1` is sensitive configuration (addresses, router, `FTPUSER`; Table 4.104), but no class prints a password.
   5. **Session load.** Configuration and SER reads scheduled back to back are checked against `TIDLE` and the two-session Telnet limit, with P4-A5's quiet interval.
3. **Draft C9 `otsec.config/0.1`**, the configuration snapshot, the difference, and the non-semantic rule, as `docs/phase4/B2-c9-config.md` plus `contracts/config/` with schema, Go types and contract tests.
   - A1 approves it together with A4's C10, A3's C7 0.6 and A3's C8 0.5, after A5, A3 and A6 review.
   - Settle the continuation-line rule for wrapped SELOGIC values (Table 4.84 prints `FAULT := ... OR` wrapped).
   - The snapshot should reference C2 transcript spans, not copy bytes twice. Each section holds its span in the session's transcript (by evidence ID) and the SHA-256 of those bytes; the bytes themselves live only in the transcript. This is what P4-A2's "native bytes and SHA-256" means.
   - **Not yet agreed with A5 (now B5).** It only works if the store never prunes a transcript while a snapshot that points into it is the baseline or holds an unacknowledged difference. Settle that with B5 before C5 0.4 is drafted: either the configuration stream's quota pins those transcripts, or the configuration stream stores them itself.
4. **Register revision 5.** Use only exact `SHO` forms:
   - `SHO 1` to `SHO 4`, `SHO L 1` to `SHO L 4`, `SHO G`, `SHO P 1`, `SHO R`, `SHO F`, `SHO M` (Table 7.67 p. 7.77, all Level 1);
   - **also, on B2's ack (#226):** `SHO P F`, `SHO P 2`, `SHO P 3`, `SHO P 4`, `SHO I`, `SHO E 1` to `SHO E 3` and `SHO DNP 1` to `SHO DNP 3`, all Level 1 in the same table. A2's first list left them out with no recorded reason, which was a gap: other ports' settings and the protocol maps are settings an engineer can change (R3.1). Port F is standard; Ports 1 to 4 are ordering options (Table 7.1 p. 7.1), and the map forms depend on the protocol option;
   - a relay answers `Invalid Command` to a command that is "not available" (S22 p. 7.31). Whether an absent port or protocol gives exactly that reply is `documented-untested`. C9 should record such a section as absent, with its reply bytes kept, never as a parse failure or an empty section, and a section that changes between absent and present is itself a difference. Any other unparseable reply still fails the read;
   - each added form adds Level 1 session time (the session-load risk below), so state the read's total time in the register;
   - no trailing setting-name `s`, and an explicit port;
   - a timeout and byte cap on each;
   - a deny-corpus entry for every `s` form and every bare `SHO P`.

   Rebuild with `contracts/register/testdata/build_sel751.py`, which needs the S22 text; see Gotchas.
5. **C2 0.6 `config.read`** in `sel751`, reusing the SER session rules: one session, at most one password, Level 1, `QUI` last, and the failed-auth floor. Add a parser and a fuzz target per settings class, and goldens transcribed from the manual's figures.
6. Write `docs/phase4/B2-handoff.md` at the end of the phase.

## Key files

Read these in order.

1. `CLAUDE.md`: the brief, ownership, principles, and the scope update (all OT classes, SEL first).
2. `docs/agent-handoffs.md`, task P4-A2 and the Phase 4 common rules: your next task.
3. `docs/phase3/A2-handoff.md`: what Phase 3 delivered, its evidence, limitations and risks.
4. `docs/device-capabilities.md`:
   - the SEL-751 section;
   - the "Collection-method rungs" tables for every family;
   - the command table and risks D1 to D25. The sources S1 to S34 are defined in `docs/phase0/A2-device-feasibility.md` and `docs/phase0/A2-sel-portfolio.md`.
5. `docs/phase3/A2-sel751-datef.md` and `docs/phase3/A2-sel751-ftp.md`: how the adapter reads `DATE_F`, and why there is no FTP rung.
6. `modules/ied/sel751/`, read in this order:
   - `seam.go` (Config, the collector's seams);
   - `run.go` (session, `check`, `reads`, `read`, `readContext`, `noteTIDLE`, `reportTIDLE`, `english`, the SER loop near `ordered`);
   - `parse_settings.go` (`settingRE`, `valueSpan`);
   - `parse_ser.go` (`dateLayouts`, `dateFits`);
   - the tests, with `run_test.go`'s `load` and `TestReplayGoldens` as the harness.
   - `modules/ied/telnet/`: the client `sel751` dials through. It answers every option negotiation with a refusal, `Send` takes exactly one line, and `SendSecret` is the credential slot (A6 on #75).
7. `contracts/adapter/doc.go` (the C2 version history and the consumer notes) and `contracts/adapter/testdata/generate.py` plus its README (every C2 golden is generated).
8. `contracts/register/testdata/sel-751.json` (revision 4), with `content_sel751_test.go` and the deny corpus.
9. `docs/phase3/A1-decisions.md` (D3-1 to D3-11) and `docs/phase2/A1-decisions.md` (D2-1 to D2-20).
10. `docs/verification.md`: V-S7 (register lines only), V-S16 (posture warnings), V-M3 (configuration read-only bound), H-13 (the hardware capture of the `QUI` reply, a `SHO P 1` reply and the framing). H-13 does not yet cover `SHO G`, the revision 5 forms or `T_OUT`; see Open questions.

## Decisions made

Don't revisit these without new evidence.

- **Exact register lines only** (D1, D3). A Level 1 SEL ASCII login is not read-only: `SER C` and `SER R` clear the SER at Level 1. So the register allows exact lines, and every other argument form is denied.
- **Only a `direct` path gets a session** (D2-16). A port server, no path, or an unknown path is refused before any dial (`refused.endpoint_path`), because only the direct path's `TIDLE` bounds the floor. The port-server floor rule waits on `T_OUT` evidence, which no hardware item names yet (see Open questions).
- **`DATE_F` is read in the same session, from `SHO G`, through a register context read** (D2-20, D3-2):
  - an unknown, missing or misfit order leaves every SER row unparsed, with its bytes kept: a parse error, never a skip or a guess;
  - a `SHO G` reply that does not parse refuses nothing;
  - only the label `DATE_F` counts.
- **A C2 0.5 result with no `DATE_F` setting keeps the pre-0.5 rule** (D3-11): the caller's order, otherwise MDY with `date-format-assumed:MDY`. The adapter emits this under a register without the context read (revision 3).
- **`TIDLE` comes only from the `SHO P 1` reply** (the read that serves the `LANG := ENGLISH` precondition), and is reported only after an `ok` or `partial` run (A6 and A3 on #175).
- **The SEL-751 stays on rung 3** (command-line `SHO` and `SER` over Telnet) for configuration as for events (ADR-0008 decision 4, taken in #209).
  - FTP waits on hardware test Q3, whether a Level 1 FTP login can write `SET_cn.TXT`. A3's D7 and D8 objection stands until then.
  - Q3 must not change the relay: STOR back the exact bytes read, record SALARM and the SER, and use a lab credential (`docs/phase3/A2-sel751-ftp.md`).
- **Setting names may start with a digit** (`51SAT`, S22 Table 4.84 p. 4.225). Both the parser and C2's `settingName` allow it.
- **No Global setting carries a credential.** Passwords are set with `PAS` (Table 7.52 p. 7.69), not as settings. `SHO P 1` is still sensitive, because it holds network settings.

## Open questions / risks

- **Assumed layouts:** `SHO G`, `SHO P 1` and the `QUI` reply are `documented-untested`, because S22 prints none of them. The simulator (A6) and the adapter come from the same manual, so agreement between them is not hardware evidence.
- **The hardware items do not cover everything A2 said they did.** H-13 captures only the `QUI` reply, a `SHO P 1` reply and the framing. A2's Phase 3 notes also cited H-13 for the `SHO G` layout and for port-server `T_OUT`; neither is in it. B6 owns `docs/verification.md`: ask B6 to widen H-13 to capture `SHO G` and each revision 5 form (including the reply for an absent port or protocol), and to add a separate item for `T_OUT` through a port server to a serial port, which needs a different lab setup.
- **Firmware is not tied to any FID** for the SEL-751 (`docs/device-capabilities.md`).
- **FTP:** a Level 1 FTP credential's write power is unknown (Q3). The S32 note that `SER.TXT` may clear on retrieval has no SEL-751 counterpart in S22.
- **The Port 1 web server:** its Event Reports page clears and triggers events at an access level the manual does not state (S22 p. 3.4). It is excluded from every rung.
- **Session load:** a configuration read is about ten `SHO` lines at Level 1, or about twenty-two with every form in Table 7.67. Scheduling it next to a SER read runs into `TIDLE` and the two-session Telnet limit (P4-A2, P4-A5).
- **Not run:** the DMY and YMD slice on the real binaries (P4-A6).

## Dependencies

- **You feed:**
  - A4's normalizer reads `Result.Settings` (`DATE_F`);
  - A3's collector runs `sel751.Run` through its seams (`modules/security/collector/runner_sel751.go`) and checks C3;
  - A5's node stores the results;
  - A6 tests everything independently, with its own simulator profile written from the manual.
- **Phase 4, you wait on:**
  - A6's simulator `SHO` forms and the GT-INJ change series, which A6 writes from the manual, not from your code;
  - A1's approval of C9 together with C10, C7 0.6 and C8 0.5.
- **Phase 4, others wait on you:**
  - A5's C5 0.4 configuration stream needs C9;
  - A3's change approvals hash your baseline;
  - A4's C10 asks you to review the SER event-type key.
- **Item 3 later:** A2 owns a new `modules/asset/` with an SNMPv3 read-only adapter.

## Gotchas

- **One push branch.** The session's designated branch is the only one you may push to. A second branch needs the owner's explicit permission; the owner gave it once, for `agent/ied-rungs`. After a merge, restart the branch from `origin/main`. `--force-with-lease` is fine when the branch holds only merged history.
- **One GitHub account.** All agents post from the same account, so GitHub refuses APPROVE on "your own" PR. Post reviews as COMMENT and say "accepted". A review's `commitID` must be the full 40-character SHA.
- **The repository is public** (D2-5):
  - use test credentials only;
  - no internal hostnames;
  - no real device data;
  - no vendor-default password either: name it by citation ("the factory default password pair, S22 p. 4.250"; A1 on #183). Goldens use only the manual's factory values.
- **The manual is not in the repository.** S22 is the owner's PDF (`OTSEC\Manuals\SEL\751_IM_20260910.pdf`). The project's shared folder holds A2's extraction, `phase0/manuals-SEL/text/751_IM_20260910.txt` (`pdftotext -layout`, SHA-256 `d540ec0e…6f9811`); every A2 artifact used that text, and the SEL-751 documented-example fixtures were also checked against a second extraction without `-layout` (their `SOURCE.md`). Copy it into your scratchpad, and point `OTSEC_SEL751_TEXT` at the text for the environment-gated tests and `build_sel751.py`. Run any Python that reads it with `python -I`.
- **C2 goldens are generated.** Edit `contracts/adapter/testdata/generate.py` and regenerate; never hand-edit the JSON. A1 checks that `generate.py` reproduces the goldens byte for byte.
- **Adding a context read changes other owners' tests:**
  - collector tests need the new register revision activated through `Registers.Activate` (A3's `runner_sel751_test.go`);
  - receive times in A4's `ser_test.go` shift because the transcript gains segments.

  Plan the confirmations.
- **Simulator runs:**
  - `OTSEC_SLICE_REQUIRED=1 python -m pytest -q tests/integration/slice/test_sel751_date_orders.py` turns skips into failures;
  - `TestSimulator` in `sel751` runs only with `OTSEC_SEL751_SIM` set (its doc lists the env vars);
  - `OTSEC_SEL751_SIM_RESULT` writes the result, invocation and asset for reconciles.
- **The `TIDLE` bug.** A per-read side effect, `noteTIDLE` on every parsed read, picked up a value from a context read. Any new read must say which checks it serves; `checks(id)` and `english(id, set)` are the pattern.
- **Error codes.** `failed.*` and `refused.*` codes carry a stage, and `refused.*` before connect means an empty transcript. Use `Code.Stage()` in tests.
- **CI.** It runs ten jobs: Go on Linux and Windows, Python, `integration`, and six `integration-long` jobs, one per long slice file (`.github/workflows/ci.yml`). A PR merges when its reviewers accept and every job is green (D2-13); A1 merges. When a job fails in a file you did not touch (slice timing), A1 or A6 usually knows. Check before re-running.
- **Messages between threads** are capped project-wide (about 60 an hour). Batch them.
