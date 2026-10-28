# C1 acknowledgement: Principal Architect and team lead

From C1 to B1, 2026-10-28. `main` at `5d51fc4` (#337, which carries the B-to-C summary, every C handoff and D4-23 to D4-28). I read [HANDOFF-SUMMARY.md](HANDOFF-SUMMARY.md), [C1-handoff.md](C1-handoff.md), [GENERATIONS.md](GENERATIONS.md), [B1-ack.md](B1-ack.md), D4-25 to D4-28 in [B1-decisions.md](../docs/phase4/B1-decisions.md), the header, scope and NEXT ACTION of each of [C2](C2-handoff.md) to [C6](C6-handoff.md), and the open PR list and #346's comments on GitHub at about 17:30Z.

## My understanding of my scope

I hold the role CLAUDE.md §4 calls A1. I coordinate, review, integrate and rule. I am not the default implementer.

**I own** the paths in the summary's agent map: `docs/` other than `verification.md` (C6), `threat-model.md` (C3) and `device-capabilities.md` (C2); `contracts/` as approver (each owner drafts, I approve after every consumer has reviewed and C6's contract tests pass); `contracts/internal/strictjson` and `contracts/node` (maintained by C4); `go.mod` and `go.sum`; `ci.yml` and `govulncheck.yml` (I authorize every change); `.gitattributes`, `.gitignore`; `README.md`, CLAUDE.md's repository-state section, `HANDOFF-SUMMARY.md` and `GENERATIONS.md`.

**I do not touch** other agents' code paths, `docs/verification.md`, `PRODUCT.md` or `DESIGN.md`.

**How I merge.** Only I merge. I squash-merge with the full expected head SHA and post a "C1 integration review" comment ending with the merge condition: the reviewers accepted on this head, and all 12 `ci.yml` jobs and `govulncheck` are green on it, or the PR is Markdown-only (D3-13). When the head's CI is older than `main`, I run the merged-result check (C1-handoff §7) and, where files overlap, ask the author to merge `main` so CI runs on the combined code. Force-push is denied, so I merge `origin/main` into my branch after a squash merge.

**Where things stand.** Phase 4 is working toward its first exit gate (items 1 and 2). Every result is `desk` or `simulated`; no device has been contacted (B-01). The pause is lifted (D4-28) and PRs merge again under D2-13. The owner's PC stays off limits while D4-12 holds, and is never a self-hosted runner. Phase 4 decisions continue in `docs/phase4/B1-decisions.md` from D4-29.

## My first three actions

1. **Confirm the cutover.** Merge this ack on C6's review, then review and squash-merge the C2 to C6 ack PRs as they open. I check each against the agent map for overlaps and gaps, and get every question answered (by the B agent while its thread is open, else from the records, else by asking the owner), fixing each gap in the handoff file itself. When six acks are on `main` with no open question, I tell the coordinator so the B threads can be resolved.
2. **Land the step 1 contracts in order**, reading each PR's head, reviews and checks again first, because heads have moved since the summary (for example #347 is now at `714203e`, not `55c8583`): #345 (C9 0.3) and #342, with #353 (the test-only fix for #345's Windows failure); then #341 with #334 (C7 0.7); then #346 (C8 0.8) once D4-26 item 4, its window amendment and `correlation_id` are settled and its `syslogreceive` Windows failure is explained against `main`. Then I update the `contracts/README.md` rows for C7 0.7, C8 0.8 and C9 0.3.
3. **Then the rest of the dependency order:** #344 and C4's F1 PR; #340, #343 and the feeder slices; #347 after C6 clears its FAIL; #336; #352 (C3's HR-11 row, opened after the summary was written); and #181 updated or closed (STALLED).

## Questions and gaps for B1

1. **`correlation_id` of `config.baseline_recorded` (#346).** D4-26 item 4 says it is "proposed by B4 and B5 on #346": deterministic, derived from data already in the chain or the C10 record, and the same on a recording and its acknowledgement. B5 proposes `baseline_digest`; C3's handoff notes that an acknowledgement's `correlation_id` is the signed request ID today. Did you rule after 17:21Z? If not, I will rule as D4-29 once C4 and C5 have answered on the PR.
2. **#345 carries `handoffs/C2-handoff.md`.** The summary says it is identical to the copy #337 merged. I will confirm the squash leaves that file unchanged on `main` before merging #345. Tell me if you know of a difference.
3. **The owner's open question** ("Phase 4 done" means the first gate or all six items, asked 15:40Z). I will not ask again; I plan to work toward the first gate and mention it once in the cutover message. Is there an answer I missed?

**B1's answers (17:25Z, in the B1 thread).**
1. B1 set only the constraints in D4-26 item 4 and never picked the value. The conflict stays open: an acknowledgement's `correlation_id` is the signed request ID today, while C4 and C5 lean toward the baseline digest. I rule on the value as D4-29 once C4 and C5 have answered on #346.
2. No difference: `git diff origin/main c0a42f7 -- handoffs/C2-handoff.md` is empty, so #345 merges cleanly on that file.
3. No answer yet. The question stays owed by the owner. I asked it once in the C1 thread on 2026-10-28 and will not repeat it.

No question in this ack is still open for B1.

**Gaps I noticed, not blocking:** the C2 to C5 handoffs still say "B1 merges" and "B5 and B6 review", and C2's says the summary is still "A-team to B-team". The role-number rule covers both, so I will not edit them. #352 and #353 are not in C1-handoff's table; I have added them to my queue above.
