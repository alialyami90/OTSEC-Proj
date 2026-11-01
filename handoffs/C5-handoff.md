# C5 handoff: Platform and Distributed Systems Engineer

From B5 to C5, 2026-10-28, `main` `04bb504`. Phase 4 (issued 2026-10-27). Role 5: `platform/`, `deploy/`, `ui/`, `cmd/otsec/` and the contract C5 (`contracts/store/`). Read [HANDOFF-SUMMARY.md](HANDOFF-SUMMARY.md) first (its agent map, standing rules and "B5" mean role 5), then the previous file [B5-handoff.md](B5-handoff.md), whose scope, key files and gotchas still hold. This file adds what changed since. Evidence classes: everything here is `simulated` or `desk`; CI is the only test path (D4-12).

## Verified state

| Item | State | Class | Source |
| --- | --- | --- | --- |
| Config database, 1.5 MiB record cap, document check (C5 0.4) | working | CI-Linux, CI-Windows | #299, #246, #273 |
| Unknown-sender class and quota (HR-11 absolute bound) | working | CI-Linux, CI-Windows | #296, #291, #317 |
| C5 0.5 (commit-WAL rule, events as rowid table), 0.6 (hold code `acknowledged-difference`) | working | CI | #281, #282, #308 |
| Holds rebuilt from C8 at start (D4-18, D4-19) | working | CI | #305 |
| Signed `node.quarantine_clear` and `node.seq_reset_ack` acted on (relay 2a), with taint and key-binding gates (D4-24) | working | CI-Linux, CI-Windows | #339 |
| TLS references from the key register (closes D2-12); #177, #182 | working | CI | #176, #177, #182 |
| HR-13 certificate period, per-link expiry; `read_buffer_bytes`; store-commit-slow alarm; Go version in health | working | CI | #290, #298, #302, #313, #297, #311, #244 |
| Unsigned clear files refused on a non-lab node (relay 2b) | in review, CI running at write time | simulated | #347 |
| `event_baselines` section, checks, quota floor (feeder 1a) | in review, CI running | simulated | #343 |
| Event-baseline feeder (reader, lifecycle, snapshots, alarms) | **not built**; no V-M4 claim | none | proposal #340 |
| C5 0.7 (hold codes `approved-difference`, `superseded-baseline`; remover) | not started | none | D4-20 |
| Admin relay and `config\admin` ACLs end to end on Windows | working (B1's statement; I did not re-read the run) | CI-Windows | #266 (B6, merged) |

## Work in flight

| PR | Branch @ head | CI at write time | Reviewers | What is left |
| --- | --- | --- | --- | --- |
| #347 relay 2b | `relay2b` @ `55c8583` | run 40727785420: 13 of 13 green (read 16:54 UTC) | B3 (supersede rule), B6 (tests) asked | Wait for B3 and B6. `clear-suspension.json` is deliberately not covered. |
| #343 feeder 1a | `feeder1` @ `d59d3b0` | run 40728121619, 13 jobs: 6 green (ubuntu, python, govulncheck, 3 long legs), 7 running (windows, integration, 4 long legs) | B4 reviewed `e317d93` and I pushed the fixes (checkpoint quota, SER-read predicate); B6 asked | Wait for CI. B4 to re-check the floor. I asked B4 to make `Snapshot`'s byte bound a parameter. |
| #342 pin test and README | `relay-next` @ `e752519` | run 40725906839: 13 of 13 green | B6 | Nothing. B1 merges. |
| #340 feeder proposal (docs) | `feeder-design` @ `777030c` | none (Markdown only) | B1, B4 | B1 ruled on it in a comment on #340 (D4-26): option A, the snapshot carries per-stream positions, `config.baseline_recorded` yes. Update the doc to the rulings (slices 3 and 4 below) before it merges. |
| #181 design doc | `claude/project-thread-xni3ff-signedadmin` | none | none open | 2a (#339) built its "should fix" items. Update the doc or close it. |

**Reviews owed, in this order** (do task 1 first, it is cheap; #344 and #346 must be read before slice 1c): #346 (C8 0.8): I commented that "both or neither in one commit step" cannot be built, because the baseline (configuration database) and the audit record (audit database) are separate C5 databases. B3 has reworded it: the baseline is stored first, the record after, and a missing record is repaired at the next start. #344 (snapshots) and #345 (C9 0.3 bounds) await my read; the feeder needs #344.

No uncommitted work and no stash. The clone is `/home/claude/OTSEC-Proj` (remote `origin`); the branches above are all pushed. Heads and CI states are as of 2026-10-28 16:50 UTC: re-read each PR before acting. You own these four branches and #181's, as B5 did; push to them to fix their own PRs only, and use any new branch name (B5 used short names) off `origin/main` for new work. #340 is a docs PR under my own `docs/phase4/B5-*` name, so it is yours to update. Review by comment signed in the body; "never approve or merge" means do not submit an approving GitHub review or merge, B1 does.

## Checkpoint verification

On a clone of `main` `04bb504` (branch `checkpoint-b5-c5`), Linux container:
- `go vet ./...`: exit 0.
- `gofmt -l .` with the container's `/usr/local/go/bin/gofmt` (old) prints `modules/telemetry/forward/relptest/relptest_test.go`. With `$(go env GOROOT)/bin/gofmt -l .` (1.27.3, the one CI uses): prints nothing, exit 0. Always use the GOROOT one.
- `go test ./...`: exit 0, 42 packages `ok`, 2 with no test files.
- Not run: `python -m pytest` (the slice harness is B6's; CI runs it), Windows (use the Actions runs above; none of my PRs has a finished Windows result yet).

## Next tasks, in priority order

1. **NEXT ACTION: land #342, #343 and #347.** Read each PR's reviews and CI when they finish (GitHub MCP `pull_request_read`, `get_check_runs`; reload the tools with ToolSearch). Fix any red job in the PR's own code. A job red on `main` too is not mine: check the latest `ci.yml` run on `main` (`actions_list`) for the same job, and comment once on the PR if so. Pushing needs `go test ./platform/node ./cmd/...` and `$(go env GOROOT)/bin/gofmt -l platform cmd` first. B1 merges; never approve or merge yourself.
2. **Feeder slice 1b (P4-A5, R4.8).** The merge reader over `ser/<asset>` and `syslog/<listener>`, in received order, with a low watermark and `AfterFailure` and `NotCounted` inputs. Paths: `platform/node/eventbaselines*.go`. Needs #343 merged. Accept when a test delays an `Observe` past a tick and the output is unchanged (#303's rule) and a test shows two streams interleaved by received time.
3. **Slice 1c: snapshots (D4-26).** Needs #344 merged and B4's bounded `Snapshot`. The checkpoint carries the per-stream positions it reflects; on restore resume each stream from the later of the snapshot's position and the consumer's cursor. A snapshot that will not restore (corrupt, unknown version, other `Params`) is never a silent restart: raise an alarm, start a re-learn and audit it naming the replaced baseline. Store the checkpoint as a record of `config/<asset>` (cap `ConfigRecordBytes`; the floor already counts it), commit a required C5 consumer after it is durable (as `node-suspensions`). Needs a new `ConfigDocuments` kind. Accept with restart-at-every-step equivalence on GT-INJ, a crash test before and after the cursor commit, and V-M4 on the real binaries with B6.
4. **Slice 1d: lifecycle and `node.baseline_ack` (event kind).** Needs #346 merged and #339's gates. The node stores the baseline, then writes `config.baseline_recorded`; at start it folds the chain and repairs a missing record (a repeat digest breaks the chain). **A baseline whose `config.baseline_recorded` is not yet in the chain is not awaiting acknowledgement and cannot be acknowledged** (B1, D4-26 item 4): the repair at start comes first. Accept with a crash test at both points (baseline stored without its record; record without baseline cannot occur), a refused ack whose digest is not stored, and a refused ack of a baseline not yet recorded.
5. **C5 0.7 and D4-20 rules 1 and 2** ([D4-20](../docs/phase4/B1-decisions.md)): hold codes `approved-difference`, `superseded-baseline` (priority order in D4-20), then the bounded remover (rule 3) as a follow-up PR. Needs B3's C8 0.7 on `main` (merged: #322). Rules 1, 2, 3 and 5 gate the first `device-observed` asset.
6. **Signed `asset.clear_suspension`** relayed and acted on by the node (needs B3 for the collector's refusal of the unsigned file). Then refuse `clear-suspension.json` off-lab the way #347 does for the other two.
7. **C7 0.7 node side** once #341 merges: the node stamps `authz.ContractID`, so upgrade the node before the collector. Nothing in the node waits less than a run plus 10 s (checked on #342).
8. Smaller: `BeginStats.Waiting` monotonic; a stale-status flag in `otsec health`; `TypesOverflow` at acknowledgement; a departure-alarm cap; C8 0.5 `unchanged_read_seq`; `VerifyConfig` naming the last acknowledged baseline; B6's register test of which operations are configuration reads.

## Blockers and risks

- **HR-11**: the absolute bound is in (#296, #317), B6's fill-across-outage test is merged (#321) and B6's #336 is open. The threat-model row stays open until B3 rewrites it ([threat-model.md](../docs/threat-model.md)).
- **D4-19 stop at the quota** stands until rule 4 (release with export) exists or the owner accepts it. **D2-11, D2-16**, the Windows state replace (B3), HR-13: see [phase-3-exit.md](../docs/phase-3-exit.md).
- D2-12 closed by #176.
- Unexplained Windows failure of `TestKeyRegisterForwardsAndRecords`, once; #314 added a trace. The Windows stalls of #230 (disk flush) are tracked there.
- The CI job count is 13: twelve in `ci.yml` and one in `govulncheck.yml` (CLAUDE.md is right; `HANDOFF-SUMMARY.md` still says ten and lists #176, #177 and #182 as open; B1 owns it).
- Unverified: quota sizes for real nodes; a learner at the type ceiling cannot be checkpointed in 1.5 MiB (the node keeps the last checkpoint and raises a health event); the start-time unknown-budget scan cost at quota.
- Asked and unanswered: B4 on exporting `baseline.Params.Validate()` (then delete the repeated check and its pin test); B4 on a bounded `Snapshot`.

## Decisions to know

[D4-18 to D4-26](../docs/phase4/B1-decisions.md) (D4-23 is on #337; D4-24 trust rules for node kinds, D4-25 and D4-26 are cited in #341, #345, #344 and #340 and may not be on `main` yet; D4-26 is B1's comment on #340, with item 4 the store-first order for #346). Mine from this generation: the unsigned-file gate is `Config.LabOnly()` (every endpoint simulated), signed wins, the actor of `quarantine.cleared` stays the node. Failed approaches: a window refusal as its own `expired` state (dropped; it stays `refused` with a suffix, #339); a snapshot checkpoint in its own class (dropped for the configuration stream, #343); one commit step over two databases (cannot be built, #346).

## Gotchas

- GitHub MCP tools disconnect; reload with ToolSearch. Every turn must end with a hearthbot call.
- Stack branches on fresh `origin/main`; never rebase pushed branches. Commit trailers and PR footers are in the session's attribution reminder.
- `relayAdmin` calls `collectorHold` only when a file is undecided, so a test of a reinstall needs a `RunOnce` first.
- The config loader refuses `device_observed` (D2-4); tests reach the non-lab node by changing the loaded config's `assets[].Endpoints[].Target`. That is a test-only device: never in product code or a config, and no endpoint is ever `device-observed` in this phase.
- New files use the C name: write `handoffs/C5-ack.md` first (scope, first three actions, questions), as a Markdown-only PR. The README in #342 is `platform/node/README.md`, yours.
- A subagent or tool that cannot end with a hearthbot call does not change the rule for your own turns.
- `go test ./platform/node` takes about 100 s locally. A `pgrep -f` monitor matches itself; wait on a PID.

## Progress since the last checkpoint

Of `B5-handoff.md`'s list: 1 (ack) done, #223, #236. 2 (Go 1.27.3): `go.mod` is at 1.27.3 (D4-7); my platform check is not recorded, so unverified. 3 done: #176, #177, #182 merged. 4 partly: relay PR 1 and 2a (#189, #339) merged, 2b in review, the #181 doc not updated. 5 partly: C5 0.4 to 0.6 and the config database merged; schedule, baselines, `node.baseline_ack`, approvals relay not started. 6 done (#244). 7 done by B6 (#266, the Windows admin relay). Regressions: none seen; one unexplained Windows failure (above). Repeated work: the unsigned-file scope was re-derived because the 2b plan was only in my head; now in task 6 and #347. Review debt: #340 and #181 have waited over a day. Outside brief or paths: none. §7 gaps on merged work: real-device evidence only (none, by rule). Stalled: none.

Validated 2026-10-28 by a fresh read-only subagent: it matched on state, next action and paths; it found the ambiguities fixed above (CI counts, clone and branch authority, review scope, naming), the stale parts of `HANDOFF-SUMMARY.md` and CLAUDE.md (B1's), and that it could not see GitHub, so heads and CI must be re-read.
