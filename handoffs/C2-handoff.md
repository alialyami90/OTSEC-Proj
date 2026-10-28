# C2 handoff: OT/IED Integration Engineer (from B2, 2026-10-28)

B2 to C2. Date 2026-10-28. `origin/main` at `04bb504` (#338); a local `main` ref in a container may be stale, so always fetch. Phase 4, task P4-A2. Role, owned paths and standing rules are unchanged: see `handoffs/HANDOFF-SUMMARY.md` (it still says "A-team to B-team" until B1 rewrites it for the C team; the role-number rule is the same) and `handoffs/B2-handoff.md` ("Role & scope", "Decisions made", "Key files", which still hold). Where a record says A2 or B2, it means this role. Owned: `modules/ied/` (`sel751`, `telnet`), `tests/fixtures/ied/`, `docs/device-capabilities.md`, `docs/phase4/B2-*.md`, and drafts of C1, C2, C3 content and C9 that B1 approves. Counterparts B1, B3, B5 and B6 keep their names until their own handoffs say otherwise. Evidence class of everything below: `simulated`, `desk` or `documented-untested`; nothing is hardware-verified and no SEL family is supported (B-01).

## 1. Verified state

| Item | State | Evidence class | Source |
| --- | --- | --- | --- |
| C3 0.3 (`limits`, `runs[]`) and D4-16 (a `runs` or `limits` key before 0.3 is refused) | working | CI-Linux, CI-Windows | #279, #293 |
| SEL-751 register revision 5: 24 `SHO` forms, run `sel.config.read_all` (512 KiB, 300 s, 10 s a step); rev 4 kept as `sel-751-rev4.json` | working | CI-Linux, CI-Windows | #301 |
| C2 0.6: runs invoked by their ID, `Limits.ForRun`, `sel.config.section` and `sel.config.absent`, `failed.config_unparsable`; a run is ok with one parsed record per step or reports no record, and `partial` is not a run outcome | working | CI-Linux, CI-Windows | #331 (`6c33f14`) |
| C9 0.2 (`sel-751-sho/2`, `FromResult`, `Compare`, `ChangesDigest`, `SameChanges`) | working | CI-Linux, CI-Windows | #331 |
| SEL-751 configuration read in `modules/ied/sel751` (one session, one `ACC`, gate forms first, device error before the language check) | working | simulated | #331, `run_config_test.go` |
| `sel751.Hosts`; maximal-result and record-size measurements | working | simulated | #338 (`04bb504`) |
| C9 0.3: snapshot bound (10,918 settings, 960 KiB encoded, record headroom 64 KiB), over-bound read is `failed.config_unparsable`; adapter 0.3.1 | **in review** (C5 accepted; C6 owed) | CI-Linux, CI-Windows (13/13 green on `c0a42f7`) | #345, head `c0a42f7`, run 40730154598 |
| Touchscreen (`/HMI`) settings | not read, not baselined (owner, 2026-10-28) | n/a | `docs/device-capabilities.md`, `contracts/config/doc.go` |
| SER system rows ("Relay Powered Up", "Relay Settings Changed") | deferred until an H-13 capture | desk | `docs/phase4/B2-handoff.md` |
| Any real relay capture (H-13) | not done, owner-gated | none | `docs/verification.md` |

## 2. Work in flight

- **PR #345**, branch `claude/project-thread-0e41t5`, head `c0a42f7` (*corrected by C2, 2026-10-28: this file first gave `aa3ebf3`, the head before this file was committed*), base `main` `04bb504`, not merged. It changes code (`contracts/config`, `modules/ied/sel751`, goldens, two Markdown docs), so it needs every CI job green.
  - CI at the time of writing (run 40727695256 and govulncheck 40727695124): green for `go (ubuntu-latest)`, `python`, govulncheck and four `integration-long` legs; `go (windows-latest)`, `integration` and the other `integration-long` legs were still running. Re-read them on the head before anything else. `ci.yml` has 12 jobs plus govulncheck (13 check runs).
  - B1 asked for the record headroom (done in `aa3ebf3`) and said everything else was accepted. B5 accepted at 17:15Z and answered: a configuration record has no source cursor, so the 64 KiB headroom is all spare. B5's `TestLargestConfigRecordIsStored` (`fit345-node`, `a6f7594`) follows #345 as C5's own PR (C1 on #360). C6's review is owed.
  - This handoff file is committed on that branch, because the branch is occupied by #345 and a second PR cannot share it. B1: say if you want it as its own Markdown-only PR.
- No uncommitted code, no stash, no patch files. The container has stale local branches (`local-c2-06`, `wip-b2-all`, `pr279`, `pr292`, `pr337`); ignore them, they are not records.
- **#337** (B1's D4-23 and README rows) is B1's. B2 checked the C2 and C9 rows on it: the C2 row names the kinds `config_section` and `config_absent`, the code has `sel.config.section` and `sel.config.absent`, and the C3 row still says rev 4.
- **#334 and #341** (B3's C7 0.7 design and code): B3 uses `sel751.Hosts` and the measured result size. The largest ok result is now 1,428,686 bytes of result JSON (B3 was told).

## 3. Checkpoint verification

Run in B2's container on `aa3ebf3` (2026-10-28), `CI` marks what only GitHub can say.

| Command | Result |
| --- | --- |
| `go vet ./...` | exit 0 |
| `$(go env GOROOT)/bin/gofmt -l .` | prints nothing, exit 0 |
| `go test ./...` | exit 0, 42 packages `ok`, none failing |
| `python -m pytest -q --ignore=tests/integration/slice` | 145 passed, 5 skipped |
| Windows, `integration`, `integration-long` | not run locally; CI only (see section 2) |

`/usr/local/go/bin/gofmt` in the container is older than the module's Go and lists `modules/telemetry/forward/relptest/relptest_test.go`; that is not a defect. Use the GOROOT one.

## 4. Next tasks

1. **NEXT ACTION: land #345: get C6's review and answer its findings** (the owner resumed the agents, D4-28; C5 has accepted). Objective: merge C9 0.3 (D4-25). Paths: `contracts/config/`, `modules/ied/sel751/`, `docs/phase4/B2-*.md`. Dependencies: B5 (cursor question, and a node-side check), B6 (independent review of the bounds). Acceptance: all 12 `ci.yml` jobs and govulncheck green on the head, reviews accepted. Tests that prove it: `TestBoundsFitTheCap`, `TestLargestAcceptedSnapshotFitsTheCap`, `TestRecordCapIsTheNodes`, `TestRecordsFitImpliesValidate`, `TestConfigOverBoundRunFails`, `TestConfigMaximalRecordFitsTheCap`. Merge is B1's. After it merges, restart your branch from `main` (see Gotchas).
2. **Hand B3 the number once #345 is on `main`.** B3 owes the collector wiring for `sel.config.read_all` (C7 0.7): the run deadline is 300 s, above the collector default of 120 s, and its test profile copy lacks the run. Answer B3's review questions on the limits.
3. ~~Ask B6 to widen H-13~~ *Dropped by C2, 2026-10-28: H-16 in `docs/verification.md` (D4-8) already covers each revision 5 form including `SHO G`, an absent option's `Invalid Command` reply, and one 24-form run. Nothing is owed to C6.* Until H-16 runs, every layout in `contracts/adapter/testdata/config` is invented.
4. **Parked, owner-gated:** SER system rows, any real capture, SEL-family expansion beyond the SEL-751. Do not start any without a brief.
5. **After that:** the P4-A2 brief is complete; the next brief for this role comes from B1 (`docs/agent-handoffs.md`).

## 5. Blockers and risks

- **H-13** (hardware capture of `QUI`, `SHO P 1`, `SHO G`, the new forms and the framing) is owed by the owner; no real device may be contacted until then. The assumed 25% margin on the settings count, the reply sizes and the 300 s run time are bounds, not measurements.
- A real relay may print a section in a way the parser cannot read. The run then fails closed with `failed.config_unparsable`, bytes kept, and that relay has no baseline until the parser is fixed from a capture.
- Open risks that gate the first `device-observed` endpoint: HR-11, D2-11, D2-12, D2-16, B-01 (full list in `docs/phase-3-exit.md`). D4-12: test runs on the owner's PC are paused, so GitHub Actions is the only test path.
- Unverified: nothing about #345 beyond C6's pending review (Windows is green on `c0a42f7`; B5 answered the cursor question).

## 6. Decisions to know

Link only: D4-13 (the configuration read and run), D4-16 (new-key rule), D4-20 (retention), D4-23 (C2 0.6 and C9 0.2 approved; in #337), D4-25 (the snapshot bound, B1's ruling on #338) in `docs/phase4/B1-decisions.md`. On `main` at `04bb504` that file ends at D4-22, so D4-23 and D4-25 are not recorded there yet. Design notes: `docs/phase4/B2-register-rev5.md`, `B2-c9-config.md`, `B2-handoff.md`.

Failed approaches, one line each: C2 allowed failed or partial runs with records (fixed in #331, B6's review); an unbounded setting count let a record pass the 1.5 MiB cap (fixed in #345); a 1 MiB snapshot bound left no headroom under Record.Bytes (fixed in #345).

## 7. Gotchas

- GitHub Actions is the test path. `go test ./platform/node` takes about 130 s; the Windows `go` leg is slow. Do not poll: subscribe to the PR.
- Regenerate goldens with `python3 -I` in their directory: `contracts/adapter/testdata/generate_config.py`, `contracts/config/testdata/generate.py`. Output must be byte-stable.
- After a PR of yours merges, restart the branch from `main` with the same name and `git merge -s ours origin/<old branch>`, never a force push. Interactive git flags (`checkout -p`) hang.
- The GitHub MCP tools disconnect and must be reloaded with ToolSearch. Every GitHub comment ends with the Claude Code footer; commits carry the two attribution trailers.
- Docs call the owner "they". Test credentials only; no real or vendor-default passwords anywhere in the public repo.
- `sel751` imports `contracts/config` for `RecordsFit` only; it keeps its own tokenizer and form table (`TestCfgFormsAreTheRule` makes them agree). Keep it that way.
- `contracts/README.md` rows and `docs/verification.md` are B1's and B6's. Also not yours: `platform/`, `cmd/`, `modules/security`, `modules/telemetry`, `tests/integration|security|safety|contract`, `ci.yml`, `go.mod`, `PRODUCT.md`, `DESIGN.md`. Never contact a device, run an H item or Q3, or run anything on the owner's PC; asking B6 to widen H-13 is writing only.

## 8. Progress since the last checkpoint

`handoffs/B2-handoff.md` was the previous file for this role. Its NEXT list: ask B1 about acceptance (done; Phase 4 issued 2026-10-27); C9 0.1 (merged, #247); register revision 5 (merged, #301); C2 0.6 `config.read` (merged, #331); write `docs/phase4/B2-handoff.md` (merged in #338 as a file, updated on #345).
- Not met from CLAUDE.md §7 for the configuration read: point 8 (evidence of correct operation) beyond simulation, and point 10 only partly (reviews by B3, B5, B6 and B1 are recorded on #331; #345 has none yet).
- No regressions seen; `TestConfigDenseRecordExceedsTheCap` was added in #338 and removed in #345 on purpose.
- Review debt: #345 awaits B5 and B6. Nothing is STALLED.
- Scope: all work was inside owned paths, except `contracts/config` and register content, which are drafted by this role and approved by B1.

Validated 2026-10-28 by a fresh read-only subagent: matched on state, next action and prohibitions. Fixed after it: the stale-branch claim, the "when Ali resumes" wording, a pointer that the summary still names the old teams, the owned and forbidden paths (it had not read B2-handoff.md), and the note that D4-23 and D4-25 are not on `main` yet.
