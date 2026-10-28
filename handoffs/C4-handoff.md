# C4 handoff: Telemetry, Event Processing and IDS

From B4 to C4, 2026-10-28, at `main` `04bb504` (#338), Phase 4, role 4. Read [HANDOFF-SUMMARY.md](HANDOFF-SUMMARY.md) first (agent map, standing rules), then this file. Your scope, owned paths and rules are the same as [B4-handoff.md](B4-handoff.md) "Role & scope"; only the name changed. Where a document says B4 or A4, it means you.

## Verified state

Evidence classes: `desk`, `simulated`, `CI-Linux`, `CI-Windows`. Nothing is hardware-verified, and no device has been contacted.

| Item | State | Class | Source |
| --- | --- | --- | --- |
| C10 `otsec.baseline/0.1` (event baseline, alarm, hash) | working, merged | simulated | #254 `7823047`; [B4-c10.md](../docs/phase4/B4-c10.md) |
| Learner and detector, five rules (new-type, repeats, rate, time, absence) | working, merged | simulated | #287 `126147b`; `modules/detection/eventbaseline`; [B4-learner.md](../docs/phase4/B4-learner.md) |
| V-M4 measures (100% recall per kind, 0 false alarms on the held-out series, latency) | working, merged, with B6's review fixes (`ae1f9d5` was #330's head when B1 squash-merged it) | simulated | #330 `d5bee69`; [B4-measures.md](../docs/phase4/B4-measures.md) |
| Detector `Tick` is a watermark; alarm identity under replay | working, merged | simulated | #303 `c268c0b`; `doc.go` "Replay and alarm identity" |
| Unknown senders in their own stream, dropped and counted at the class quota (HR-11) | working, merged | simulated, CI-Linux | #291 `5f5ad27`, node #296 `dcf3c1a` |
| Unknown senders hold at most a quarter of a datagram queue (D4-21) | working, merged | simulated, CI-Linux | #317 `7495eff`; [B4-unknown-stream.md](../docs/phase4/B4-unknown-stream.md) |
| Configurable UDP receive buffer; `ErrCertificatePeriod` | working, merged | simulated | #274 `7fec85c`, node #297 `96fbbae`, doc fix #335 |
| Learner and detector Snapshot and Restore (D4-26) | working, **PR #344 open** | simulated, CI-Linux (see below) | `claude/b4-snapshot` `7dbe6b0`; `docs/phase4/B4-snapshot.md` (in #344, not on `main` yet) |
| F1: bound the detector's pairs | **WIP, no PR**, tests pass locally | simulated (local) | `claude/b4-pair-cap` `3f75825` |
| IDS (Zeek, Suricata, protocol rules) | not started, by design | none | needs the owner to name the sites' protocols |

## Work in flight

1. **PR #344**, branch `claude/b4-snapshot`, head `7dbe6b0`, branched from `d5bee69` (#330); `main` is now `04bb504`, two commits ahead (#339 node, #338 sel751; neither touches `eventbaseline`), so the head was not tested on `04bb504` itself. Update the branch from `main` before B1 merges if GitHub asks. Review: B5 (checkpoint contract), B6 (restore tests), B1 merges when both accept and it is green. CI run [40726548965](https://github.com/alialyami90/OTSEC-Proj/actions/runs/40726548965): all 13 checks succeeded by 16:48Z (12 jobs plus govulncheck, Windows included). No review comment yet. Next step: read any review, fix findings with a validated push. I am subscribed to it.
2. **Branch `claude/b4-pair-cap`**, head `3f75825`, stacked on #344 (not a PR). B1 ruled on F1: (1) drop a pair whose hold ended and that lists nothing, with a test that output is identical with and without; (2) cap the rest, as a constant documented beside the 16,384 new-type cap; (3) past the cap, no break is silent or re-alarms without bound, and the alarm that follows states "N more beyond the cap"; (4) a flood of 114,688 distinct new types keeps memory and the snapshot under a stated bound and the counts exact. Built: `MaxNewTypePairs` = 4096, `sweepNewPairs` (new-type pairs only, because an absence alarm is stamped with its deadline and a sweep of those is not output-neutral), `Detector.BeyondNow`, the note in the next alarm's `Observation`. Tests in `paircap_test.go` pass: sweep changes no output, the flood is bounded (553 KB snapshot at 114,688 types), a ledger over three floods balances (154,690 breaks), pass 2 counts what it drops. **Left:** update `doc.go` "Limits" and F1 in `B4-snapshot.md` (both still say the pairs are unbounded); one mutant survives (the clip of the note in `raise`); add `Observation` to the list of fields that can differ in a replay; then rebase onto `main` once #344 merges, open the PR (B5 and B6 review, B1 records it with D4-26).
3. **Branch `claude/b4-measures`** (`ae1f9d5`): nothing to do. It was #330's head when B1 squash-merged it (`d5bee69`); `git diff origin/main origin/claude/b4-measures -- modules/detection docs/phase4/B4-measures.md` is empty.
4. **Review debt (mine to answer):**
   - B3's draft PR #346 (C8 0.8 `config.baseline_recorded`): they asked what `correlation_id` should hold for a baseline. My leaning, not yet sent: the baseline's own digest on the recording, since a learner run has no ID in C10; B1 and I decide.
   - B6's PR #336 (D4-21's criterion on the real store): review owed, receiver side.
   - B5's #343 (event_baselines config): my review is posted; B5 owes a decision on where checkpoints live and their quota (the floor of 4 x 512 KiB does not cover an 8 MiB snapshot; the config class record cap is 1.5 MiB).
   - B5 asked me to export `baseline.Params.Validate()` (additive C10 change, no wire change; B1 agreed). Not started. Today it is the unexported `Params.check` at `contracts/baseline/baseline.go:341`.

## Checkpoint verification

Run on branch `claude/b4-checkpoint` at `04bb504`, Go 1.27.3, Linux container (`desk`/`simulated`; Windows results only from Actions).

| Command | Result |
| --- | --- |
| `go vet ./...` | exit 0 |
| `gofmt -l .` | clean with the 1.27.3 toolchain gofmt (`$(go env GOROOT)/bin/gofmt -l .`, what CI uses). The container's old `/usr/local/go/bin/gofmt` (2025) lists `modules/telemetry/forward/relptest/relptest_test.go`; ignore that. |
| `go test ./...` | exit 0, 42 packages `ok`, none failed (Linux, about 3 minutes in the longest packages) |
| `go test ./modules/detection/...` on `claude/b4-pair-cap` | ok, 9 s; `-race` ok, 50 s |
| `python -m pytest -q` | **not run**: `pytest` is not installed in this container. CI runs it ([run 40726548965](https://github.com/alialyami90/OTSEC-Proj/actions/runs/40726548965), job `python`, success on #344's head). GT-INJ's Python checks are B6's. |

## Next tasks

1. **NEXT ACTION: land #344.** Check CI and reviews (above). Acceptance: all 12 jobs green on the head, B5 and B6 accept, B1 merges. Proof: `go test ./modules/detection/eventbaseline -run TestSnapshot -count=1`.
2. **F1 PR** (P4-A4, D4-26 follow-up). Paths: `modules/detection/eventbaseline/` (`detector.go`, `common.go`, `snapshot.go`, `doc.go`, `*_test.go`), `docs/phase4/B4-snapshot.md`. Depends on #344 merged. Acceptance: B1's four rules above. Tests: `TestPairSweepChangesNoOutput`, `TestPairCapFloodStaysBoundedAndCountsStayExact`, `TestPairSweepDropsListedPairsLast`; kill the note-clip mutant.
3. **`baseline.Params.Validate()`** (B5's ask). Path `contracts/baseline/`. Contract README notes it; B1 and B5 review. Acceptance: node #343 can drop its copy and `TestEventBaselineParamsMatchC10`; a test that `Validate` and `Baseline.Validate` agree on every field.
4. **Review** #346, #336 and B5's feeder PRs as they come (proposal #340, `docs/phase4/B5-event-baseline-feeder.md`, not merged yet): the feeder must tick with a watermark, checkpoint the position and the previous read's alignment keys with the snapshot, and keep the V-S12 state (list in `B4-snapshot.md`, "What the feeder must do").
5. **IDS** (brief item 4): wait for the owner to name the sites' protocols. Do not start it.

## Blockers and risks

- **HR-11:** mitigated in code, open until the real-binary fill test and D4-21's criterion are accepted (B6, #316, #321, #336). Gates the first `device-observed` listener. [threat-model.md](../docs/threat-model.md).
- **D3-10:** the Windows UDP corruption cause is inferred (Go 1.26.2 fix); reopen if a `receive` panic returns.
- **F1 (detector pairs unbounded)** is open until item 2 lands; `ErrSnapshotTooLarge` is the backstop.
- **V-M4's real false-positive rate** needs a real device's event history (14 days, 200 events). All figures are on B6's synthetic series.
- Unverified: whether 8 MiB (`MaxSnapshotBytes`) suits B5's checkpoint layout; the worst detector snapshot with every cap full and 128-byte names is about 8.3 MB by estimate (not measured).
- Windows results for #344 and the pair-cap tests are CI-only.

## Decisions to know

[B1-decisions.md](../docs/phase4/B1-decisions.md): D4-15 (absence arming, type working set), D4-21 (unknown queue share), D4-9 (first contract batch). D4-23 to D4-26 are B1's rulings in flight; D4-26 (snapshots, a required C5 consumer) is B1's, to be recorded. Failed approaches: charging unknown senders in the writer instead of at read (#178, fixed #196, [A4-syslog-receive.md](../docs/phase3/A4-syslog-receive.md)); a wall-clock `Tick` loses alarms (#303); an absence latency read from the alarm itself (B6 on #330).

## Gotchas

- `Tick(now)` must be a watermark, never the wall clock; `Observe` of an earlier event is `ErrOrder` and loses its alarm.
- A pair sweep is output-neutral only for the new-type rule; absence alarms carry their deadline as `at`.
- Never run the mutation scripts without restoring the file; keep copies under `/tmp` and check `git status` after.
- `ser()` in the tests uses a global `nextSeq`; reset it when comparing two runs.
- The token limit on `message_thread` is 2000 characters.
- Run `$(go env GOROOT)/bin/gofmt -l .`, not the bare `gofmt`: this container's `/usr/local/go/bin/gofmt` is old and lists `relptest_test.go` wrongly.
- `HANDOFF-SUMMARY.md` still says ten CI jobs and `main` at `d4afc63`; `CLAUDE.md` says twelve. B1's text.
- Keep scratch scripts (mutation runs) in your session scratchpad, not `/tmp`, where your session rules say so; they must not enter the repo.

## Progress since the last checkpoint

The last checkpoint is [B4-handoff.md](B4-handoff.md) (A4 to B4, 2026-10-27, `d4afc63`).
- Item 1 (C10): done, #254 `7823047`. Item 2 (C5 0.4 scope): done, #246 `c3c07cf`, #291. Item 3 (learner, detector): done, #287, #303, #330 (B6's follow-up `ae1f9d5` was its head, merged). Item 4 (receive hygiene): UDP buffer #274, #335; HR-11 receiver side #291, #317; B6's tests #316, #321. First action (stale `UnknownSpent` line): done.
- §7 gaps for the detector: independent review of V-M4 on the real binaries (B6); documented limits are in `doc.go`; no real-device evidence.
- Regressions: none seen. Retries: none. Repeated work: the mutation scripts were rewritten twice because they were not kept (now outside the repo).
- Review debt: #346 (C8 0.8), #336 owed by me; #344 waits on B5 and B6. Out-of-brief work: none; F1 is B1's ruling. STALLED: none.

Validated 2026-10-28: fixed. A fresh read-only agent, given only the repo and this file, named #344 as the next action and the right files, paths and limits. It found three errors, now fixed here: the base of #344 and `claude/b4-pair-cap` is `d5bee69`, not `04bb504`; the `go test ./...` cell was unfilled; the gofmt note was an unverified guess (B1 then found the cause: the container's old gofmt); B1 also corrected the claim that `ae1f9d5` was unmerged. It could not check GitHub (PRs, CI, reviews); those I checked myself: CI on `7dbe6b0` all 13 checks success.
