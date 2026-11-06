# D5 handoff: Platform and Distributed Systems Engineer

From C5 to D5, 2026-11-06, `main` `961221b` (#475). Phase 4, item 3 (vulnerability applicability with the asset module) built and awaiting its gate, which waits only on V-M1 ([item 3 exit report, #479](https://github.com/alialyami90/OTSEC-Proj/pull/479)). Role 5: `platform/`, `deploy/`, `ui/`, `cmd/otsec/`, `.github/workflows/a5-windows-experiments.yml` (changes authorized by role 1), `docs/phase4/C5-*` and the contract C5 (`contracts/store/`, changes approved by role 1). Names: after cutover, role 1 is D1 and role 6 is D6; older records say C1, C6. Read [HANDOFF-SUMMARY.md](HANDOFF-SUMMARY.md) first (its [agent map](HANDOFF-SUMMARY.md#agent-map) and standing rules; A5, B5 and C5 all mean role 5), then this file. [C5-handoff.md](C5-handoff.md) and [B5-handoff.md](B5-handoff.md) still hold for scope and older gotchas. Evidence classes: desk, simulated, CI-Linux, CI-Windows. Nothing here is hardware-verified; no device has been contacted.

## Verified state

| Item | State | Class | Source |
| --- | --- | --- | --- |
| C5 0.7 and 0.8 in the SQLite store (hold codes, document series, bounded remover; item 3 series and ceiling, `identity.read` `mismatch`) | working | CI-Linux, CI-Windows | #382, #450; C6 contract tests #450 |
| Configuration-read writer, reconcile, `HoldsConsumer`, `node.change_approval` and `node.baseline_ack` (event kind) | working | CI-Linux, CI-Windows | #390, #400, #406, #408 |
| Event-baseline feeder slices 1a to 1d: section, merge reader, checkpoint, lifecycle; restart and open gap (D4-45) | working | CI-Linux, CI-Windows; V-M4 simulated on the binaries (`integration-long` legs `test_slice_gtinj_feed_e2e.py`, `test_slice_gtinj_ser_e2e.py`) | #343, #365, #376, #405, #384, #413, #415, #431 |
| Stepped test clock behind `otsec_testclock` | working | CI-Linux, CI-Windows (`TestTestClock` step) | #391, #401, #407 |
| Item 3 node, part 1: `asset`/`applicability` switches, advisory set intake (C11 §1.5), item 3 ceiling | working | CI-Linux, CI-Windows | #452 |
| Item 3 node, part 2: identity records, latest reads, SNMP schedule entries | working | CI-Linux, CI-Windows | #454 |
| Item 3 node, part 3: findings and the matcher's evaluation | working | CI-Linux, CI-Windows; V-M7 128/128 simulated (`test_slice_vm7_e2e.py`) | #458, C6's #467 |
| One-SNMP-entry node for GT-MIB's runner | working at Go level against a fake agent; no V-M1 run | CI-Linux, CI-Windows (`snmpstart_test.go`) | #463 |
| Recorded network controls (D4-56) | working | CI-Linux, CI-Windows (`controls_test.go`); V-M7 D8/D9 simulated | #469 (`0e87cfa`) |
| Register revision per profile (`register_versions`) | working | CI-Linux, CI-Windows (`registerversions_test.go`); mixed node simulated (`test_slice_mixed_register_e2e.py`, `integration` job) | #466 (`05af5a0`) |
| `in_use_since` stable across a restart | working | CI-Linux, CI-Windows (`TestAdvisoryInUseSinceSurvivesRestart`) | #474 (`356bc24`) |
| V-M8 set cases and paired runs (C6's, node side reviewed by me) | working | CI-Linux | #470 (`5011589`) |
| Certificate-period release waits (Windows `not_yet_valid`) | fixed in the test; node start stall unexplained | CI-Windows | #471 (`673f018`) |
| Older carried items (C5-handoff task 8: `BeginStats.Waiting`, stale-status flag, departure cap, etc.) | **unverified**: not re-checked this checkpoint | none | [C5-handoff.md](C5-handoff.md) task 8 |

**Step 1 results** (worktree of `origin/main` `961221b`, branch `c5/checkpoint-2026-11-06`, Linux container, desk):

- `git status --short`: empty. `git stash list`: empty. Every C5 branch is pushed and its PR merged (squash merges, so `rev-list origin/main..branch` still counts their commits). No WIP.
- `go vet ./...`: exit 0. `$(go env GOROOT)/bin/gofmt -l .` (go1.27.3): prints nothing, exit 0.
- `go test ./...` (every package of the root module, run beside the slice files below): exit 1. 51 packages `ok`, 3 with no test files, 1 FAIL: `tests/security` `TestB6HeldLinksDialAndBindNothing`, "the held-back listener's address 127.0.0.1:44015 could not be bound 184 times: bind: address already in use". Re-run alone: `go test ./tests/security -count=1` exit 0. Classified as load from my own concurrent slice run taking that port as an ephemeral port (the test frees a port and expects nothing else to take it); role 6's test, reported to C6 through the coordinator. `platform/node` `ok` in 152 s.
- `python -m pytest -q --ignore=tests/integration/slice` (CI's `python` job; pytest 9.2.0 locally, CI pins 9.1.1): exit 0, 493 passed, 5 skipped (the three `OTSEC_SEL751_TEXT`/`OTSEC_ALLOWLIST` and two `OTSEC_REGISTER` env-gated tests).
- Slice e2e, two files only (`test_slice_mixed_register_e2e.py`, `test_slice_vm7_e2e.py`): exit 0, 51 passed in 352 s. The other slice legs were not run here; CI ran all of them green on `main` `961221b`.
- CI on `main` `961221b`: `ci.yml` run [42174011840](https://github.com/alialyami90/OTSEC-Proj/actions/runs/42174011840), success (Go on Linux and Windows, pytest, integration, every `integration-long` leg). `govulncheck.yml` on `main` runs weekly; its last `main` run is [41453799611](https://github.com/alialyami90/OTSEC-Proj/actions/runs/41453799611) at `fd64a14` (2026-11-02), success, so **stale** for `961221b`; it ran green on each of my PR heads.

## Work in flight

None. No open PR, branch or patch of role 5. Open PRs that touch my area, owned by others: C6's #480 (C12 contract pair, the set's in-use time across a restart, the gate at `961221b`) and C1's #479 (item 3 exit report). Neither has asked me to review at this checkpoint; read them before acting.

## Next tasks, in priority order

D4-34 holds: work stops at the end of item 3 until the owner's check. Do not start item 4, 5 or 6 work (briefs, contracts or code) until role 1 relays the owner's go.

1. **NEXT ACTION: write `handoffs/D5-ack.md`** (scope, first three actions, questions) as a Markdown-only PR, then **review role 6's V-M1 PR from the node side when it is up**. Role 5's share: P4-3-C5's acceptance is "V-M1 (a) for all three supported combinations", and P4-3-C2's is "V-M1 (a) with C5" ([agent-handoffs.md](../docs/agent-handoffs.md), item 3 implementation briefs). No V-M1 PR number exists at this checkpoint; ask the coordinator. Paths to read: `platform/node/snmp.go`, `identity.go`, `item3*.go`, `schedule.go`, `snmpstart_test.go`, and the item 3 sections of `platform/node/README.md`. Dependency: role 6's GT-MIB agent. The owner allowed `www.rfc-editor.org` on 2026-11-06 and the RFC texts are in `/mnt/project-files/rfc/` (3411, 3412, 3414, 3416, 3418, 3826, 6933, 7860, with `SHA256SUMS`), per #479; `docs/verification.md` and `B1-decisions.md` still list them as owed until role 1 updates them. Accept when the node's SNMP entry, identity records and status lines in C6's run match what the node writes, as I did for #470. Review by COMMENT only; role 1 merges.
2. **Fix any node defect V-M1 finds** (P4-3-C5). Branch off fresh `origin/main`; a test that reproduces it first; `go test ./platform/node ./cmd/...` and GOROOT `gofmt` before push; C6 and C3 review.
3. **The Windows node start stall** (open item in #479; needs role 1's go, it is not briefed). Hosted Windows sometimes takes over 12 s to start a node (#471's run: a 6 s try took 12.47 s). The CI log has no per-step timing. The best lead is #428's profile (closed, unmerged; D4-44 in [phase-4a-exit.md](../docs/phase-4a-exit.md)): recreating the ~20 MB recovery reserve with a flush at every start (F-013). Unverified. Proving test: per-phase start timings logged on Windows CI, then a fix with the budget step's numbers before and after.
4. **Item 6, the central role (R8, V-S18)**, only after the owner's go and role 1's brief.
5. **STALLED: refuse `clear-suspension.json` off-lab** (C5-handoff task 6, from B5's relay plan, #181 closed). Untouched for two generations. `platform/node/unsigned.go` says this file is not covered; the node already sends `asset.suspension_clear` from it (`assetclear.go`). Needs C3 for the collector's refusal of the unsigned file first, and role 1's brief. Then re-check the carried small items (C5-handoff task 8) and drop or brief each with role 1.

## Blockers and risks

- **D4-34**: stopped at item 3's end apart from reviews ([B1-decisions.md](../docs/phase4/B1-decisions.md)).
- **Owner-owed**: HR-18 (who publishes the advisory set and holds its key; no real advisory until then); approval of any device contact for the SNMPv3 path after V-M1; D4-12 (owner's PC paused, CI only).
- **HR-11** threat-model row and **D4-19** stop at the quota (no export release yet), **D2-11**, **D2-16**: see [phase-3-exit.md](../docs/phase-3-exit.md) and [threat-model.md](../docs/threat-model.md).
- **Windows `platform/node` budget** (D4-44): 720 s is a warning (706 to 743 s on item 3 runs); hard guard is the 30-minute package timeout.
- **Unverified**: quota sizes for real nodes; the node start stall's cause; the C5-handoff task 8 items; V-M1 on any agent.

## Decisions and lessons

- Decisions this generation that shape the node: D4-26 to D4-57 in [B1-decisions.md](../docs/phase4/B1-decisions.md), in particular D4-34 (item by item), D4-39 (C5 0.7), D4-40 to D4-46 (writer, feeder, test clock, non-semantic change), D4-44 (Windows budget), D4-50 and D4-53 (item 3 switches and set intake), D4-54 and D4-55 (identity mismatch, cleared by hash), D4-56 (recorded controls), D4-57 (an audit citation is never passive evidence). The item 3 design is [C5-asset-node.md](../docs/phase4/C5-asset-node.md), C5 0.8 is [C5-c5-0.8.md](../docs/phase4/C5-c5-0.8.md), the per-family register note is [C5-register-per-family.md](../docs/phase4/C5-register-per-family.md).
- Failed approaches (one line each): parallel node tests on Windows saved nothing (#427); a configuration batch append is refused (one record per commit), so tests fill with checkpoints (findings_test.go `fillConfig`); `in_use_since` from the commit time moved on restart (#474); a release wait counted from the end of the checks (#471).
- Gotchas:
  - `main` moves fast: #466 needed three merges of `main` for `slicehelper` flag conflicts. Merge with a merge commit, keep every side's flags, re-run the affected slice files.
  - Waits counted from the wrong instant pass on desk and fail only on slow runners (#471).
  - The GitHub MCP tools disconnect; reload with ToolSearch. A full job log cannot be downloaded through the proxy; `get_job_logs` gives only the tail.
  - Reviews need the full 40-character SHA as `commitID`.
  - All cross-agent messages go through the coordinator (owner's message in the project chat, 2026-11-06 11:43Z; no D-number yet, proposed to X1). `HANDOFF-SUMMARY.md` still describes direct messages until role 1 rewrites it.
  - Local slice runs share the working tree: do not switch branches while one builds; use `git worktree`.

## Progress against C5-handoff.md

1 (land #342, #343, #347): done (#342, #343, #347 merged). 2 (feeder 1b): done, #365. 3 (slice 1c snapshots): done, #376, #405. 4 (slice 1d lifecycle, ack): done, #384, #406. 5 (C5 0.7, D4-20 rules 1 and 2, remover): done, #375, #382, #390. 6 (signed suspension clear, then refuse `clear-suspension.json` off-lab): not started, STALLED (task 5 above). 7 (C7 0.7 node side): done with #341. 8 (small items): not re-checked, unverified. Item 3 (P4-3-C5, not in the old list): deliverables 1 to 3 done (#444, #450, #452, #454, #458, #463), plus #466, #469, #471, #474. Regressions: two Windows `not_yet_valid` failures, root-caused and fixed (#471). Retried runs: none by me. Review debt over a day: none known. Out-of-scope work: none. §7 gaps on merged work: hardware evidence only (none, by rule). STALLED: task 5 above (the off-lab refusal of `clear-suspension.json`).

Proposed to X1: give the coordinator-routing rule a D-number; record the Windows start stall as an open reliability item with #428's reserve recreation as the lead (unverified), and the failed approaches above.

Validated 2026-11-06 by a fresh read-only subagent (CLAUDE.md, the summary, this file): it matched on state, next action and paths. fixed: the RFC texts' source, the brief quote for V-M1 (a), role names after cutover, the workflow file in scope, CI evidence classes and test sources, the coordinator rule's source. Not fixable here: `HANDOFF-SUMMARY.md`, CLAUDE.md's "Team handoff" paragraph and `GENERATIONS.md` are role 1's, and the subagent had no GitHub access, so PR states must be re-read.
