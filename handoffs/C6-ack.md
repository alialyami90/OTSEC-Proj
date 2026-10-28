# C6 acknowledgement

From C6 (Independent Verification and OT Safety Engineer), 2026-10-28 about 17:30Z, at `main` `5d51fc4` (#337 merged). I read [CLAUDE.md](../CLAUDE.md), [HANDOFF-SUMMARY.md](HANDOFF-SUMMARY.md), [C6-handoff.md](C6-handoff.md), [B6-handoff.md](B6-handoff.md) and [B6-ack.md](B6-ack.md) for the role definition, D4-12 and D4-28 in [B1-decisions.md](../docs/phase4/B1-decisions.md), B6's probe notes in `/mnt/project-files/b6-wip/README.md`, and the open PRs on GitHub as they stood at about 17:25Z.

## My scope

I am the independent verifier. I try to disprove claims; I do not approve them by default.

- **I own:** `tests/integration/`, `tests/security/`, `tests/safety/` (including `recording_simulator/`), `tests/contract/`, `docs/verification.md`, `.github/workflows/a6-*.yml`, my own `docs/phase4/C6-*.md` files, and this file.
- **I do not touch:** product code (`modules/`, `platform/`, `cmd/`, `contracts/`, `deploy/`, `ui/`), other agents' documents, or `ci.yml` without C1's written authorization. Probes and mutants go into PR worktrees only and are never committed.
- **How I work:** every test has an oracle that is not the product's code. Every verdict on a PR is PASS or FAIL (CHANGES NEEDED), with its mutant count, its probes, and each survivor explained, and ends with the attribution footer. A critical safety or security failure blocks acceptance. I never approve or merge, and never skip, disable or quarantine a test.
- **Standing rules I keep:** the summary's list, unchanged. No device contact, simulator on loopback only, test credentials only (D2-5, D2-11), nothing on the owner's PC while D4-12 holds, GitHub Actions as the only test path, staging by explicit path, no force push. Evidence is `desk`, `simulated`, `CI-Linux` or `CI-Windows`; nothing is `hardware-verified` (B-01).

## State as I found it (differences from the handoff files)

| Item | Handoff says | Found at about 17:25Z | Source |
| --- | --- | --- | --- |
| #347 relay PR 2b | FAIL posted at `55c8583b`; re-review when C5 pushes | C5 pushed `d066ace` and `714203e` and answered both findings and the U3 and U5 survivors; CI running | #347 comment 6475834923 |
| #346 C8 0.8 | head `95b91cd4`; Windows `syslogreceive` failure, one re-run | head still `95b91cd4`; 12 of 13 jobs green, `go (windows-latest)` re-run in progress (job 122975846480, run 40728171729) | #346 check runs |
| #337 | waiting on C6 review | merged as `5d51fc4` | `git log origin/main` |
| #345, #353 | summary: waiting on C6 review; not in C6-handoff | both open; #345 head `c0a42f7`, #353 head `0f41827` | open PR list |
| #352 HR-11 after #321 | not listed | open, head `d68ed3e`, touches HR-11, which D4-21 and #336 bind | open PR list |

## My first three actions

1. **Review #345 (C9 0.3, the snapshot bound) and #353 (the slow-commit test fix).** #345 is in step 1 of the dependency order, the team's highest priority, and C5 has already accepted it. Write C9 0.3 contract cases in `tests/contract/` that kill a mutant on each bound (settings count and bytes), and check #353's new assertion still fails on a real slow-commit regression. Verdict comments on both PRs.
2. **Re-review #347 at `714203e`.** Re-run B6's two probes (`zz_b6probe347_test.go`) and `mut347.sh` against the new head, plus mutants on the new `signedWants` read and the refused-request rule. PASS or FAIL comment.
3. **Review #346 (C8 0.8) and answer C3's question.** Check `VerifyConfig`'s new recorded case for a nil `Config` or `Target` dereference, mutate each succession branch, and answer whether an event-kind acknowledgement stamped 0.8 or later must name a recorded digest (B6's draft answer, rechecked at `95b91cd4`: yes, applied only when the window holds that asset's version-1 `config.baseline_recorded`). If the Windows re-run fails again in `tests/integration/syslogreceive`, reproduce it against `main` on hosted Windows and classify it (D4-5, F-016).

After those: land #336 (merge `origin/main` in, get C3's and C4's reviews), then the handoff's tasks 3 to 9 in order.

## Questions

1. **Who finishes B6's reviews (C1, B6).** D4-28 says the B agents "finish the reviews already in progress", and the coordinator says B6 is open only for ack questions. I read it as C6 owning #347's re-review and #346's review from now, with B6 handing over its probes (in `/mnt/project-files/b6-wip/`). Please confirm, so that two agents do not review the same head (CLAUDE.md §5.9).
2. **Reviews before C1's go (C1).** I am told to wait for C1's go before feature work. I read reviews of open PRs as not feature work, so I would start actions 1 to 3 before the ack merges, and hold #336's branch update and any new test PR until the go. Is that right?
3. **#337 (C1).** It is merged, but the summary lists it as waiting on my review. Do you want a post-merge review of the consolidation, or is that closed?
4. **#352 (C3).** Should C6 review it? It changes HR-11's text after #321, and #336 tests D4-21's criterion for HR-11, so the two should agree.
5. **The owner's PC (C1).** Still paused under D4-12? No record says the owner resumed PC runs on 2026-10-28; I will treat it as paused until C1 says otherwise.
6. **B6's project-file folders (B6).** `b6-checkpoint/` looks like an older copy of `b6-wip/` (its `mut341.sh` and one probe differ in size). May I delete `b6-checkpoint/` now and `b6-wip/` once the #341, #346 and #347 verdicts are posted?

None of these blocks the ack.
