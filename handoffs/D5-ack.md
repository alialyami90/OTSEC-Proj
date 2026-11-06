# D5 acknowledgement: Platform and Distributed Systems Engineer

From D5 to C5 and D1, 2026-11-06, at `main` `a774a97` (#486). I read [CLAUDE.md](../CLAUDE.md), [HANDOFF-SUMMARY.md](HANDOFF-SUMMARY.md) (C-team to D-team), [D5-handoff.md](D5-handoff.md), and the files they point me to for V-M1: `docs/verification.md` row V-M1, the item 3 briefs in [agent-handoffs.md](../docs/agent-handoffs.md) (P4-3-C5) and [D4-50](../docs/phase4/B1-decisions.md). Evidence class for everything here: `desk` (reading, `git` and the GitHub PR list at about 13:00Z). Nothing here is hardware-verified, and no device has been contacted.

## State I checked

- `main` is `a774a97`. Since `961221b`, where D5-handoff.md was written, `main` gained #479, #480 and the checkpoints #481 to #486. None of them touches my paths: `git diff --stat 961221b origin/main -- platform deploy ui cmd/otsec contracts/store .github` is empty. So the node-side state in D5-handoff.md's table still holds.
- Open PRs on GitHub: none (before this one). There is no V-M1 PR yet. D6's GT-MIB agent is still the uncommitted patch `/mnt/project-files/c6-wip/2026-11-06-gt-mib-agent-wip.patch` (no tests yet, per its README).
- Role 5 has no open PR, branch or patch.
- Corrections to D5-handoff.md, already made in the summary: #479 and #480 are merged (`a69c416`, `158a5d0`), not open. `/mnt/project-files/rfc/` holds twelve RFC texts with `SHA256SUMS`, not eight. The summary now states the coordinator rule.
- I did not run `go vet`, `gofmt` or the tests. This PR changes only this file, and my paths are unchanged since C5's run on `961221b` (D5-handoff.md, step 1 results).

## My scope

**I own** (agent map): `platform/` (`node/`, `store/` with `store/protect/`, `winsvc/`; `experiments/` is the separate Phase 0 module and is not built), `deploy/`, `ui/` (empty; any UI work goes through the `impeccable` skill, and none is planned), `cmd/otsec/`, `.github/workflows/a5-windows-experiments.yml` (D1 authorizes changes), the C5 contract `contracts/store/` as proposer (D1 approves, consumers review, D6's contract tests first), `platform/node/README.md`, and my own `docs/phase4/C5-*` and new `D5-*` findings files.

**I do not touch:** `modules/`, `cmd/otsec-collector/`, other `contracts/` packages, `go.mod` and `go.sum`, `ci.yml` and `govulncheck.yml`, D6's test directories and `docs/verification.md`, or any other `docs/` file.

**Review pairs:** D6 (reliability) and D3 (trust boundaries) review my work. I review the node side of D6's V-M1 PR, and anything that uses the store or the node. I review by COMMENT only, with the full 40-character head SHA. I never approve or merge; D1 merges.

**Standing rules I keep:** the summary's list word for word. In short: no device contact, every endpoint on the simulator over loopback; test credentials only, nothing secret or site-specific in this public repository; no fabricated evidence, and an evidence class on every result; GitHub Actions is the only test path while D4-12 holds, all 18 `ci.yml` jobs and the `govulncheck.yml` job green on the head before a code PR merges, re-run at most once, no empty commits, no flake calls; the owner's PC is never a self-hosted runner; merge `origin/main` into my branches instead of force-pushing; stage by explicit path, never `git add -A`; use `$(go env GOROOT)/bin/gofmt`; all messages to other agents go through the coordinator (D4-58).

**D4-34 holds.** Apart from reviews and fixing node defects V-M1 finds, I start no work until the owner's item 3 check: no item 4, 5 or 6 briefs, contracts or code.

## My first three actions

1. **Review D6's V-M1 PR from the node side when it is up** (D5-handoff.md task 1; P4-3-C5 acceptance "V-M1 (a) for all three supported combinations"). Before it lands I re-read `platform/node/snmp.go`, `identity.go`, `item3*.go`, `schedule.go`, `snmpstart_test.go` and the item 3 sections of `platform/node/README.md`, so the review starts at once. I check that:
   - V-M1 (a) runs the three combinations D4-50 allows: both off, `asset` alone, and both on. GT-MIB must receive zero PDUs with `asset` off. The node must refuse `applicability` without `asset` at load.
   - The node's SNMP schedule entry, identity records and `otsec` status lines in D6's run match what the node writes, as C5 did for #470.
   - The run starts the node with #463's one-SNMP-entry start on the test clock, not a second path.
2. **Fix any node defect V-M1 finds** (D5-handoff.md task 2). Branch off fresh `origin/main`, write a test that reproduces it first, run `go test ./platform/node ./cmd/...` and GOROOT `gofmt -l platform cmd` before pushing, then ask for review by D6 and D3 through the coordinator.
3. **Ask D1 whether the Windows node start stall should be briefed** (D5-handoff.md task 3), and when. It is an open item in the item 3 exit report, and it is not briefed. My proposal: hold it until the item 3 gate is decided, so it does not compete with V-M1 for CI time. Then a first PR only logs per-phase start timings on Windows CI, and no fix is made until those numbers show the cause. #428's recovery-reserve lead stays unverified until then.

## Questions

For D1:

1. Should the Windows node start stall wait until the item 3 gate is decided (action 3)? If you want it sooner, I need a brief ID.
2. `govulncheck.yml`'s last run on `main` is from 2026-11-02 (`fd64a14`), so it is stale for `a774a97`. It is your workflow. Will the weekly run cover the gate, or should it be dispatched before you decide it?
3. The STALLED item, refusing `clear-suspension.json` off-lab (D5-handoff.md task 5), needs D3's collector refusal first and then your brief. Should it be dropped with a decision, or kept on the list for after item 3?

For D6, through the coordinator:

4. Will V-M1 (a)'s three runs use the real `otsec` and `otsec-collector` binaries started through #463's one-SNMP-entry path? Please send its PR number to the coordinator when it is up, so it reaches me for the node-side review.

For C5: none. D5-handoff.md answered what I needed, and the only stale parts are the PR states and the RFC count noted above.
