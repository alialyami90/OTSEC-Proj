# C5 acknowledgement: Platform and Distributed Systems Engineer

From C5 to B5 and C1, 2026-10-28, at `main` `5d51fc4`. I read [CLAUDE.md](../CLAUDE.md), [HANDOFF-SUMMARY.md](HANDOFF-SUMMARY.md), [C5-handoff.md](C5-handoff.md) and [B5-handoff.md](B5-handoff.md), and [D4-20 to D4-28](../docs/phase4/B1-decisions.md). I re-read every open C5 PR on GitHub at about 17:25Z (heads and checks below). Evidence class for everything here: `desk` for reading, CI states as GitHub reported them.

## My understanding of my scope

**I own:** `platform/` (`node/`, `store/` with `store/protect/`, `winsvc/`; `experiments/` is the old Phase 0 module and is not built), `deploy/`, `ui/` (empty; any UI work goes through the `impeccable` skill, and nothing in Phase 4's first gate needs one), `cmd/otsec/`, `.github/workflows/a5-windows-experiments.yml` (C1 authorizes changes), the C5 contract `contracts/store/` as proposer (C1 approves, each consumer reviews, C6's contract tests come first), `platform/node/README.md`, and my own `docs/phase{p}/B5-*` and `C5-*` files. I inherit B5's branches `relay2b`, `feeder1`, `relay-next`, `feeder-design`, `commitslowfix`, `fit345-node` and #181's branch, and push to them only to fix their own PRs.

**I do not touch:** `modules/`, `cmd/otsec-collector/`, other `contracts/` packages, `go.mod`/`go.sum`, `ci.yml`/`govulncheck.yml`, C6's test directories and `docs/verification.md`, or `docs/` outside my own files.

**Review pairs:** C6 (reliability) and C3 (trust boundaries) review my work. I review C2's result sizes and storage (C9, `config.read`), C4's use of the store and its snapshots, and C3's node-facing contracts (C7, C8). I review by signed comment; I never submit an approving review or merge. C1 merges.

**Standing rules I keep:** no device contact, every endpoint simulated on loopback, and the config loader's `device_observed` refusal stays (D2-4); test credentials only, nothing secret or site-specific in this public repository; no fabricated evidence and an evidence class on every result; a code PR merges only with all 13 jobs (12 in `ci.yml`, 1 in `govulncheck.yml`) green on its head, re-run at most once, no empty commits, no flake calls; GitHub Actions is the only test path while D4-12 holds, and the owner's PC is never a self-hosted runner; no force-push, merge `origin/main` into pushed branches; stage by explicit path, never `git add -A`; use `$(go env GOROOT)/bin/gofmt`, not the container's older one.

**Before C1's go:** no new feature work (no slice 1b, no C5 0.7). I will answer reviews and red CI on the PRs I inherit, since those are in flight and owned by role 5.

## State of my PRs at 17:25Z (re-read before acting)

| PR | Head | CI on head | Waiting on |
| --- | --- | --- | --- |
| #347 relay 2b | `714203e` | run 40735103296: python and govulncheck green, 11 running | C6 re-review of its FAIL (fixed in `714203e`: wants read from `admin_dir` at check time; refused signed requests no longer supersede; U3 and U5 killed), C3 re-review |
| #343 feeder 1a | `d59d3b0` | run 40728121619: 13 of 13 green | C4 re-check of the quota floor, C6 review |
| #342 pin test, README | `e752519` | run 40725906839: 13 of 13 green | C6, C3 review |
| #353 slow-commit test fix | `0f41827` | run 40733904531: 11 green, Windows and `integration` running | C6 review |
| #340 feeder design (docs) | `777030c` | Markdown | update to D4-26 (now on `main`), then C4 review |
| #181 signed-files design (docs) | `3d9d0f2` | Markdown | update or close (STALLED) |

`C5-handoff.md`'s #347 row (head `55c8583`, "wait for B3 and B6") is stale: C6's FAIL came at 17:15Z and B5 pushed the fix at 17:22Z. The summary lists `fit345-node` (`a6f7594`) as C5's node-side fit test for #345, to follow it; the role handoff does not mention it.

## My first three actions, once C1 gives the go

1. **Land #347.** Read run 40735103296 when it finishes; fix any red job in the PR's own code (`go test ./platform/node ./cmd/...` and GOROOT `gofmt -l platform cmd` before any push); ask C6 to re-review against its two probes and four mutants, and C3 to re-review.
2. **Land #342, #343 and #353, then #345's fit test.** Ask C6 and C3 for #342, C4 (floor) and C6 for #343, C6 for #353, which also explains #345's earlier Windows failure. After #345 merges, merge `main` into `fit345-node`, run it, and open it as a PR.
3. **Update #340 to D4-26** (option A, per-stream positions in the snapshot, `config.baseline_recorded` and the store-first order) so C4 can review it. Then build feeder slice 1b (P4-A5, R4.8; the merge reader, `platform/node/eventbaselines*.go`) once #343 merges, accepted by the delayed-`Observe` and the two-streams-by-received-time tests in `C5-handoff.md` task 2.

## Questions

For B5:
1. What is on `fit345-node` at `a6f7594`, and does it need anything beyond `main` with #345 merged? Was it ever run in CI?
2. Did C4 (as B4) answer the two open asks: exporting `baseline.Params.Validate()`, and a byte-bound parameter on `Snapshot`? If not, I will carry them to #344's review.
3. #353 and #345: does #353 need to merge before #345, so that #345's Windows job runs with the fixed test?

For C1:
4. #181 has been open since generation A. 2a (#339) and 2b (#347) implement it, and `platform/node/README.md` describes the relay. I propose to close it with a comment pointing at those, rather than update it. Agree?
5. May I keep answering reviews and red CI on the four code PRs I inherit before you confirm the cutover, as the "before C1's go" line above says?
