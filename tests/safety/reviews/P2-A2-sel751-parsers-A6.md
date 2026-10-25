# A6 review of #85 (modules/ied/sel751 parsers, C2 example row order) at `28c7f54`

Reviewer: A6 (P2-A2 device-safety and correctness review). Evidence class: **simulated and desk**. The parsers read bytes that were already received; they send nothing to a device. Everything ran in the Linux container with Go 1.26.0. Nothing here is hardware-verified, and the SHO and SER layouts beyond the manual's figures stay open until H-13.

Verdict: **changes requested**, one must.

## What I ran

- #85 merged with main at `04c9525`, no conflicts. `go vet ./...` and `gofmt -l .` are clean (empty output), and `go test -count=1 ./...` passes. `python -m pytest -q` gives 140 passed, 5 skipped, so my slice suite and reconciliation oracle agree with the new C2 row order (row 8 first, as Figure 10.16 prints it).
- Windows cross-build: `GOOS=windows go vet ./modules/ied/...` and `go test -c ./modules/ied/sel751` pass.
- Each of the four fuzz targets ran 15 s more on my side, with no failure.
- I read `frame.go`, `parse_id.go`, `parse_ser.go`, `parse_settings.go` and the tests, and probed each parser with inputs of my own. The probes are not in the repo.

## Must

**1. `parseSettings` accepts lines it has only half read, which defeats the LANG gate it exists for.** The doc says "a check such as LANG := ENGLISH must never pass on a line the parser half read", and C2 has `refused.language_not_english` for exactly this. But the parser only checks that the number of `settingRE` matches equals the number of `:=` on the line. Text outside the matches is ignored, and a match can start in the middle of a word. What I saw (each input is one line of a framed SHO reply):

| Line | Parsed as | Error |
| --- | --- | --- |
| `LANG := ENGLISH  trailing words` | LANG = ENGLISH | none |
| `xLANG := ENGLISH` | LANG = ENGLISH | none |
| `EN-LANG := ENGLISH` | LANG = ENGLISH | none |
| `1LANG := ENGLISH` | LANG = ENGLISH | none |
| `TID := FEEDER  1` | TID = FEEDER | none (wrong value) |
| `LANG := ENGLISH FOO := BAR` | refused | correct |
| `lang := english` | refused | correct |

So a line that names another setting, or a value cut short at a double space, is read as a clean `LANG := ENGLISH` or as a shorter value. Real SHO output puts several settings on one line separated by runs of spaces. If a text setting's value holds two spaces, the parser silently returns the part before them.

A fix: require the matches to tile the line. Each match must start at the beginning of the line or after a space. Between matches, and before the first and after the last, there may be only spaces. Anything else refuses the line, as an unaccounted `:=` does today. Please add each row of the table above as a test case. The first five must be refused.

## Nits

**2. SER date grammar.** `contracts/adapter/probe.go` gives the date as `1*2DIGIT "/" 1*2DIGIT "/" 4DIGIT` (or the YMD form), but `serRowRE` needs exactly two digits. An unpadded date such as `2/28/2007` makes the row unparsed. Its bytes are kept (EP-1), so nothing is lost, but the parser and the C2 grammar should say the same thing. Either accept 1 or 2 digits, or narrow the C2 grammar, and note it under H-13.

**3. Leading spaces are not accepted.** A row with leading spaces (` 8   02/28/2007 ...`) is kept but unparsed. A headings line with leading spaces refuses the whole report as "without the column headings". Figure 10.16 prints both flush left, so this is right for the documented layout. Whether a relay right-aligns row numbers of 10 and over is unknown until H-13. Please list it there so the first hardware capture checks it.

## Notes for the record

- `frame` refuses a reply with no STX ... ETX, an unterminated one, or two, and spans never cover STX, ETX or a line end. My probes agree.
- `parseID` checks the checksum over `"KEY=value",` and refuses a key printed twice. A line that is not an ID field goes to `other` rather than being dropped.
- `parseSER` keeps an unmatched row with its bytes and `ok = false`, so a row outside the grammar is never guessed at (EP-1). An element name with a space (`Relay Enabled`) is unparsed today, and that falls under the H-13 layout question too.
- The C2 example change (rows oldest first) only reorders the existing goldens, and the C2 contract tests pass. I made no change to `tests/contract` for it.
- Native Windows run on ALI's PC at `28c7f54` (Windows 11, portable Go 1.26.0, Python 3.13.6). vet and gofmt are clean. `go test ./modules/ied/... ./contracts/adapter/ ./tests/contract/` passes, with sel751 at 13 tests. `python -m pytest -q` gives 85 passed, 5 skipped (the environment-gated ones). That is the PR head unmerged, so the slice suite is not in it.

## Re-check at `20a87b3`: must closed, accepted

`parseSettings` now refuses any line with `:=` whose settings do not fill it, with only spaces before, between and after them. The five cases from must 1 are refusals in `TestParseSettings`, and `FuzzParseSettings` checks that every non-space byte of such a line is in a setting span. My own probe of 15 lines agrees with the new parser on every line: the five half-read lines are refused, a tab inside a line is refused, an empty value is refused, `LANG := ENGLISH  DATE_F := MDY` and leading or trailing spaces are accepted, and a line without `:=` is ignored. After merging with main, vet, gofmt and `go test ./modules/ied/... ./contracts/adapter/ ./tests/contract/` pass, and `FuzzParseSettings` ran 20 s more with no failure. Nits 2 and 3 are left for later, as A2 said. The native Windows run at `20a87b3` is running on ALI's PC.
