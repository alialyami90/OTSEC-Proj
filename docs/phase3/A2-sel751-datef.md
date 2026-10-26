# SEL-751 adapter: the path rule, DATE_F from SHO G, and TIDLE after the run (A2, P3-A2)

**Status:** adapter change on C1 0.2, C3 0.2 (register revision 4) and C2 0.5. Evidence class: **simulated**: replays of invented C2 goldens, the hosted collector runner on loopback (hosted runner, simulated), A6's recording simulator, and fuzzing. The `SHO G` layout and the claim that SER rows follow `DATE_F` are **documented-untested**: S22 prints no `SHO G` reply, and p. 7.31 states the order for command-response dates, not for SER rows. No relay was contacted.

## Behaviour, as acceptance cases

Each case names the test that shows it. A6 is asked to test each one independently.

| # | Behaviour | Test |
| --- | --- | --- |
| 1 | An endpoint whose C1 path is not `direct` (port server, no path, a path this build does not know) is refused with `refused.endpoint_path` before any dial: empty transcript, not connected, nothing suspended. | `TestEndpointPathRefused`, `TestBeforeConnect/refused.endpoint_path` |
| 2 | In a SER run, the context read comes after the language precondition's read and before the operation: `SHO P 1`, `SHO G`, `SER`. | `TestDateFReadBeforeSER` |
| 3 | `DATE_F` is reported in `settings` as printed, with a span that selects exactly the value in the relay's bytes. | `TestDateFReadBeforeSER`, the replays of `ok`, `ok-date-ymd`, `ok-date-dmy` |
| 4 | With `DATE_F` one of `MDY`, `YMD`, `DMY`, a row parses only if its DATE is a calendar date in that order. | goldens `ok`, `ok-date-ymd`, `ok-date-dmy`; `FuzzDateFits` |
| 5 | A `DATE_F` outside the register's values leaves the SER output unreadable: every row `parse_ok` false with its bytes kept, `partial.parse_errors`, and the value still reported as printed. | `TestUnknownDateFLeavesRowsUnread` (`partial.parse_errors-date-f-unknown`) |
| 6 | No `DATE_F` in `SHO G`: nothing reported, every row unparsed. | as 5 (`-date-f-missing`) |
| 7 | Rows that do not fit the reported order (a DMY relay printing `10/24/2026`) are unparsed, each one, never skipped. | as 5 (`-date-misfit`) |
| 8 | A `SHO G` reply that does not parse (`Invalid Command`, a half-read line, no framing, `DATE_F` twice) refuses nothing: `SER` is still read and every row is left unparsed. Only a read that serves a check (precondition, warning, firmware condition) fails the run on a bad reply. | `TestSHOGUnreadable` |
| 9 | The context line is a line like any other (D3-2): it passes egress, its reply counts against `max_response_bytes`, the step timeout and the deadline, and it is kept in the transcript. | `TestContextReadCountsAgainstTheBudget`, `TestEgressRefusesUnregistered` |
| 10 | `SHO G` is sent only because the package declares it: with the context removed, egress refuses the line; in the collector, a SER result with `SHO G` checked against revision 3 raises the SAFETY alarm. | `TestEgressContextReadOnlyFromTheRegister`, `TestContextReadRefusedUnderRev3` |
| 11 | A context read this build has no reader for (another setting, or a value with no date layout) stops the run before it connects (`failed.internal`). | `TestContextReadWithoutReader` |
| 12 | `Config.TIDLE` is called once, after the run, and only when it ended ok or partial; never after a failed or refused run, though `SHO P 1` showed `TIDLE`. With 1, only a direct path's `TIDLE` is ever reported. | `TestTIDLEOnlyAfterOKOrPartial`, `reportsTIDLE` in `TestReplayGoldens` |
| 13 | A setting name may start with a digit (S22 Table 4.84 p. 4.225: `51SAT`), and is read whole, so `1LANG` is never `LANG`. Found by running against A6's independent `SHO G` reply (#166): before the fix the line holding `51SAT` did not parse, and every row was left unparsed. | `TestParseSettings` |
| 14 | Only the `DATE_F` label counts (A6): an order printed as another setting's value, or under a name that merely contains `DATE_F` (`DATE_FX`, `XDATE_F`), is never taken for it; with the real `DATE_F` present, another setting's value does not change the order. | `TestDateFOnlyFromItsLabel` |
| 15 | Against A6's recording simulator (#166) in each order, the adapter's rows reconcile with S22 Figure 10.16: each row once, its bytes the figure's with the date in that order, its DATE reading as 2007-02-28 in that order and in no other, the other fields the figure's; `SHO P 1`, `SHO G`, `SER` sent; every line the simulator received read-only (`check.py`). | `tests/integration/slice/test_sel751_date_orders.py` (integration job) |

Case 15 stops at the adapter's result. The normalizer and the forwarder are not in it: A4's normalizer takes the order from `DATE_F` in its follow-up to C2 0.5 (A4 on #164), and the full slice reconcile in YMD and DMY follows that. Simulated evidence only.

Every SER capture now keeps the whole `SHO G` reply (case 9). No Global setting carries a credential (A3): the Global settings section of S22 (pp. 4.225 to 4.248, Tables 4.84 to 4.102) defines no password, key or user setting. Passwords are set with the `PAS` command (Table 7.52, p. 7.69) and are not settings; `MAXACC` and the network settings are Port settings (`SET P`, from Table 4.103), which `SHO G` does not print. The one free-text Global setting is the Event Messenger text `MPTX01` to `MPTX32` (Table 4.85, 148 characters), a message an engineer types, so the capture keeps whatever was typed there. This is documented-untested: it comes from the manual's tables, not from a relay's `SHO G` reply.

A run under a register without a context read (revision 3) sends no `SHO G`, reports no settings and parses rows as before; its consumer keeps the MDY assumption and its flag (C2 0.5 doc).

## Fixture changes in other owners' files

| File | Owner | Change |
| --- | --- | --- |
| `modules/security/collector/runner_sel751_test.go` | A3 | hosted runs activate revision 4 through `Registers.Activate` (signature and floor checked) and carry `register_version` 4; new `TestContextReadRefusedUnderRev3`. Evidence class: hosted runner, simulated. |
| `tests/integration/slice/test_sel751_date_orders.py` (new) | A6 | case 15; uses `harness`, `reconcile.native_rows` and `check.py` unchanged. `modules/ied/sel751` `TestSimulator` gains `OTSEC_SEL751_SIM_RESULT` to hand it the result. |
| `modules/telemetry/normalize/ser_test.go` | A4 | the SER reply's received time in `TestNormalizeC2Read` moves from 09:15:01.3Z to 09:15:01.5Z, because `ok.json` gains the two `SHO G` segments. |

A6's `SHO G` reply landed first (#166). The `parse_test.go` case "digit prefix" (A6 on #85) becomes a positive check (case 13): `1LANG` parses as its own setting and `LANG` stays absent.
