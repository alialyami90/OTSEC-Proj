# Handoff P3-A2 — A2 — 2026-10-26

The brief is "Task P3-A2" in `docs/agent-handoffs.md`. Every result below is `simulated` (replays of invented C2 goldens, A6's recording simulator, the hosted collector runner on loopback, fuzzing) or `documented-untested` (manuals only). No relay was contacted, and nothing ran on the owner's PC.

## Completed

- **C1 0.2, the endpoint path** (#149). `Endpoint.Path` is `direct` or `port-server`, and `CheckPath` refuses a missing or unknown path the same way it refuses a port server. A C1 0.1 record still reads, and its endpoints have no path. The SEL-2488 and SEL-2730M Syslog documented examples were added as fixtures for P3-A4.
- **C3 0.2 context reads and SEL-751 register revision 4** (#156, D3-2). A package can declare a read made only for its value. Revision 4 declares `ctx.date_f`: `DATE_F`, read by `SHO G` (Level 1, read-only), for `sel.ser.read_all`, with the values MDY, YMD and DMY. `SHO G` was already a Level 1 read-only entry; revision 4 adds the context read and corrects its `DATE_F` citation, and `SET G` stays denied.
- **C2 0.5** (#164). It adds:
  - `refused.endpoint_path`, given before any connection;
  - `Result.Settings`, a context read's settings as printed, each with a span on the relay's bytes. `CheckLines` places each setting in the reply to the read that served it.

  A setting name may start with a digit (`51SAT`, S22 Table 4.84).
- **The SEL-751 adapter, 0.2.0** (#175):
  - a non-direct path is refused before any dial;
  - `SHO G` is read after `SHO P 1` and before `SER`;
  - a row parses only if its DATE is a calendar date in the order `DATE_F` gives, and an unknown, missing or misfit order leaves every row unparsed with its bytes kept (`partial.parse_errors`), never skipped;
  - `Config.TIDLE` is called once, after an ok or partial run only, and only from the `SHO P 1` reply. That last rule was A6's finding on #175.

  The design note lists 15 acceptance cases: `docs/phase3/A2-sel751-datef.md`.
- **Collection-method rungs and the SEL-751 FTP assessment** (#183, ADR-0008, open):
  - every SEL family in `docs/device-capabilities.md` has its event, configuration and identity rungs, each cell with an evidence class and a citation;
  - `docs/phase3/A2-sel751-ftp.md` answers ADR-0008 decision 4 from S22. It concludes there is no FTP rung for the SEL-751 until one authorized hardware test settles whether a Level 1 FTP session can write `SET_cn.TXT`. The `SHO` rung stays.
- **Reviews**, each recorded on its PR:
  - #160: the collector's path check;
  - #166: A6's simulator `SHO G` reply, which is how the `51SAT` parser bug was found;
  - #174: the RTAC 1024-byte packet bound (S23 p. 635);
  - #181: A5's signed admin files, checked for IED compatibility;
  - A4's Syslog receive: the per-family layouts and the RTAC firmware time-stamp note.

## Evidence

- **Unit and replay tests** in `modules/ied/sel751`:
  - `TestEndpointPathRefused` and `TestDateFReadBeforeSER`;
  - `TestUnknownDateFLeavesRowsUnread`, `TestSHOGUnreadable` and `TestDateFOnlyFromItsLabel` (A6's label-only case);
  - `TestContextReadCountsAgainstTheBudget`, `TestContextReadWithoutReader` and `TestEgressContextReadOnlyFromTheRegister`;
  - `TestTIDLEOnlyAfterOKOrPartial` and `TestTIDLEOnlyFromSHOP1`, the latter failing without the fix;
  - `FuzzDateFits`, and the replay of every C2 golden.
- **Goldens:** `ok` (MDY), `ok-date-ymd`, `ok-date-dmy` and the three `partial.parse_errors-date-*` cases. They are reproduced byte for byte by `contracts/adapter/testdata/generate.py`, as checked by A1.
- **Against A6's simulator in each order:** `tests/integration/slice/test_sel751_date_orders.py` (integration job, 6 passed). Rows reconcile with S22 Figure 10.16, and `check.py` finds only read-only lines.
- **In the collector:** `TestContextReadRefusedUnderRev3` (A3's file, A3 confirmed) shows that `SHO G` checked against revision 3 raises the SAFETY alarm.
- **Independent checks:** A6 passed #175 at 581c38a with its own relay tests and 10 of 10 mutants killed. A3 and A4 accepted their parts.

## Interfaces

- C1 0.2 (`Endpoint.Path`, `CheckPath`), C3 0.2 (`Package.Context`, `ContextFor`) and C2 0.5 (`RefusedEndpointPath`, `Result.Settings`, `Result.Setting`). Each has a reader for the previous minor.
- `sel751.Config.TIDLE` now fires after the run, not during it. Its doc changed, and its signature did not.

## Limitations

- **The `SHO G` layout is documented-untested.** S22 prints no `SHO G` reply, and p. 7.31 states the date order for command responses, not for SER rows. The adapter and A6's simulator both come from the same manual, so agreement between them is not hardware evidence.
- **The full slice reconcile in YMD and DMY on the real binaries is not run.** A4's normalizer reads `DATE_F` since #203 (with D3-11 for a result without it). `test_sel751_date_orders.py` now carries each order's adapter result through `normalize.Normalize`: 8 events per order, dated 2007-02-28, with no `date-format-assumed` flag. So the brief's "a DMY profile no longer produces the MDY assumption flag" is met at that level. The store, the forwarder and the real binaries in YMD and DMY are not covered.
- **The port-server floor rule stays refused** until `T_OUT` evidence exists (H-13). There is no checksum enforcement (V-S19 (d)), and no FTP or SNMP code.
- **Firmware is not tied to any FID** for the SEL-751 (`docs/device-capabilities.md`).

## Risks

- **A Level 1 FTP credential's write power is unknown.** If FTP is ever chosen for the SEL-751, the platform would hold a credential that may change settings. The FTP assessment blocks that on one hardware test, and A3's D7 and D8 objection stands until then.
- **`SHO G` capture content.** Every SER capture now keeps the whole `SHO G` reply. No Global setting carries a credential (S22 Tables 4.84 to 4.102). The Event Messenger text `MPTX01` to `MPTX32` is free text an engineer types, and the capture keeps it.
- **The S32 note that `SER.TXT` may clear on retrieval** has no SEL-751 counterpart in S22. Any future file-based SER rung must read twice and compare on a lab relay first.

## Dependencies

- **A4:** done in #203 (D3-11).
- **A6:** if the exit report needs it, the real-binaries slice run in YMD and DMY (`test_slice_e2e.py` with the simulator's `--profile-date-f`).
- **A6:** spot-check ten cells of #183. Record the P3-A2 acceptance results in `docs/verification.md`.
- **A3:** read the FTP assessment against D7 and D8 (#183).
- **A1:** the Phase 4 configuration rung for the SEL-751 is decided on the FTP assessment (ADR-0008 order, item 1). The hardware test it names needs the owner's authorization and an out-of-service lab relay.

## Files changed

- `contracts/asset/` (C1 0.2), `contracts/register/` and `contracts/register/testdata/sel-751.json` (C3 0.2, revision 4), and `contracts/adapter/` with its `testdata/` (C2 0.5, goldens, `generate.py`).
- `modules/ied/sel751/`: `run.go`, `parse_ser.go`, `parse_settings.go`, `seam.go` and their tests.
- Changes in other owners' files, each confirmed on its PR:
  - `modules/security/collector/runner_sel751_test.go` (A3);
  - `modules/telemetry/normalize/ser_test.go`, one literal (A4);
  - `tests/integration/slice/test_sel751_date_orders.py`, new (A6).
- Docs:
  - `docs/device-capabilities.md`;
  - `docs/phase3/A2-c1-path.md`, `A2-c3-context.md`, `A2-sel751-datef.md`, `A2-sel751-ftp.md` and this handoff.
