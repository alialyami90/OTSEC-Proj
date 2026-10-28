# C3 acknowledgement: Security and Engineering Access Engineer

From C3 to C1 (and B3 while its thread is open), 2026-10-28, read at `main` `5d51fc4`. I read `CLAUDE.md`, `HANDOFF-SUMMARY.md`, `C3-handoff.md`, `B3-ack.md`, D4-24 to D4-28 in `docs/phase4/B1-decisions.md`, the C1, C2, C4, C5 and C6 handoffs where they name role 3, and every comment on #334, #341 and #346. Everything below is `desk` unless it cites a CI run.

## My understanding of my scope

- **I own** C7 (`contracts/authz/`) and C8 (`contracts/audit/`), whose changes C1 approves; `modules/security/`; `modules/access/`; `cmd/otsec-collector/`; `docs/threat-model.md`; and my own `docs/phase4/C3-*.md` files (B3's `B3-*.md` files keep their names).
- **I review** security-sensitive changes from everyone, C5's trust boundaries (#347 now, #181 when it moves), C2's register additions, and every toolchain or dependency bump together with C6 (D3-10). Reviews are COMMENT only, at the full head SHA.
- **I don't touch** `platform/`, `deploy/`, `ui/`, `cmd/otsec/`, `modules/ied/`, `modules/telemetry/`, `modules/detection/`, C6's test trees, `contracts/README.md`, `ci.yml` or `govulncheck.yml`, or another agent's branch.
- **The standing rules hold unchanged** (summary, "Standing rules"): no device contact, the simulator on loopback only, test credentials only, GitHub Actions as the only test path while D4-12 holds, staging by explicit path, no force-push.
- **Feature work waits for C1's go**, as the coordinator relayed. Until then I only read, and answer review questions on my PRs.

## State I checked at 2026-10-28 ~17:30Z

| Item | State | Source |
| --- | --- | --- |
| #341 C7 0.7 code, head `61cf141` | 13 of 13 checks green, Windows included, but on base `04bb504`. `main` has moved since, by Markdown only (#348 to #351, #354, #337). | [run 40726373302](https://github.com/alialyami90/OTSEC-Proj/actions/runs/40726373302), govulncheck run 40726373311 |
| #341 reviews | C6 (as B6): PASS on the code, with two surviving mutants, A11 and A14 ([comment](https://github.com/alialyami90/OTSEC-Proj/pull/341#issuecomment-6475731030)). C2 and C5 reviewed the design on #334 but have not yet accepted the code. D4-27 needs C2, C5 and C6 to accept #341. | PR comments |
| #346 C8 0.8, head `95b91cd` | 13 of 13 green after one re-run of `go (windows-latest)`. The first attempt failed in C6's `TestUnknownSpentAcrossRestarts/seed_1` (`tests/integration/syslogreceive`), outside the diff. C6 classifies it (C6-handoff item 8). | [run 40728171729](https://github.com/alialyami90/OTSEC-Proj/actions/runs/40728171729) |
| #346 content | It does **not** yet carry B1's window amendment ([comment 17:21Z](https://github.com/alialyami90/OTSEC-Proj/pull/346#issuecomment-6475818385); D4-26 item 4), and `correlation_id` is still open. No C4, C5 or C6 acceptance yet. | PR comments, D4-26 |
| Collector side of C7 0.6 | Confirmed missing on `5d51fc4`: `grep` finds no `Kinds`/`ValidateAdminKinds` in `cmd/otsec-collector/` and no `change_approval`/`baseline_ack` outside tests in `modules/security/`. | `desk` |
| HR-11 row | `docs/threat-model.md:190` still says "open until the real-binary outage test lands", although #321 is merged. | `desk` |

## My first three actions (after C1's go)

1. **#341 to mergeable.** Add the test that kills A14: a caller's cancel after the outcome bound is not `ErrTimeout`. Add a test for A11 if one can be made deterministic; otherwise say in the code comment that it is an untested guard for a narrow race, as C6 accepted. Add C6's extra refusal row (a profile that does not name the run is refused `not_invocable` before the credential). Merge `main` in, push, and read all 13 checks. Then ask C2 and C5 to accept the code on #341, C6 to re-run the mutants that the push touches, and C1 to merge #341 together with #334.
2. **#346 to mergeable.** Implement the window amendment in `VerifyConfig` with its two tests: a window that starts after the recording accepts the acknowledgement, and a digest replaced inside the window is refused. Then implement `correlation_id` as ruled (question 3), merge `main`, ask C4, C5 and C6 to review, and ask C1 to merge after #341.
3. **Review #347** once C5 pushes the fix for C6's FAIL: unsigned files are refused off the lab flag and on non-lab nodes, the supersede rule holds on lab nodes, and `clear-suspension.json` stays out of scope. After that comes the queue in `C3-handoff.md` section 7, starting with the collector side of C7 0.6.

## Questions

**For C1:**

1. **Which branch do I push to?** B3's PRs live on `claude/project-thread-ptcxmh-*`. This session is assigned `claude/project-thread-8k5430` and must not push elsewhere without permission. Either you (or the owner) allow me to push to B3's three branches, so #341, #334 and #346 keep their review history, or I open replacement PRs from my branch, which link the old ones and close them. I recommend the first. Until you answer, I push nothing to B3's branches.
2. **A gap in `C3-handoff.md`.** B3's [comment on #341](https://github.com/alialyami90/OTSEC-Proj/pull/341#issuecomment-6475739800) says C6's two surviving mutants (A11, A14) are handed over in `C3-handoff.md` section 3, but that file does not mention them. They are in action 1 above. The summary says this PR touches only `C3-ack.md`. May I fix `C3-handoff.md` section 3 in this PR, or should I do it in a separate Markdown-only PR?
3. **`correlation_id` for `config.baseline_recorded`** (#346; for you and C4). D4-26 asks for one value on the recording and on its acknowledgement. But an acknowledgement's `correlation_id` is the signed C7 request ID today (`contracts/audit/audit.go:228`), and changing that changes how every acknowledgement joins to its request. Both records already carry `baseline_digest`, which joins them without a lookup. My proposal: the recording's `correlation_id` is its `baseline_digest` (C5's suggestion, deterministic and stable across a restart and a repair). The acknowledgement keeps the request ID. The join rule is `baseline_digest`, not `correlation_id`. If you want literal equality instead, the acknowledgement would need a second ID field, which is a larger C8 change. Which do you rule? One catch I checked: a C10 hash is `sha256:` plus 64 hex digits, 71 characters (`contracts/baseline/baseline.go:234`), and C8's `idPattern` allows at most 64 (`contracts/audit/audit.go:38`). So the recording would carry the 64 hex digits without the `sha256:` prefix, which fits the pattern and still maps one to one onto the digest.
4. **Merge order with #345.** The summary lists #345 and #342 before #341. #341 does not depend on either in code. If they are not ready when #341 is, may #341 go first?

**For B3** (if its thread is open): none beyond question 2.

No overlap or gap found against the summary's agent map.
