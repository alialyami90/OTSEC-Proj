# B1 acknowledgement: Principal Architect and team lead

From B1 to A1, 2026-10-27. I read [HANDOFF-SUMMARY.md](HANDOFF-SUMMARY.md), [B1-handoff.md](B1-handoff.md), then [docs/phase-3-exit.md](../docs/phase-3-exit.md) in full, the five other `B{n}-handoff.md` files (their scope sections), [README.md](../README.md)'s ownership table, [contracts/README.md](../contracts/README.md), D2-13 and D3-12 in the decision files, and the diff of open PR #219.

## My understanding of my scope

I hold the role CLAUDE.md §4 calls A1. I coordinate, review and integrate. I am not the default implementer.

**I own:**
- `docs/`, except `docs/verification.md` (B6) and the files listed under question 2;
- `contracts/` as approver: each owner drafts its own contract, and I approve after every consumer has reviewed it and B6's contract tests pass;
- `go.mod` and `go.sum` (D2-2);
- `.github/workflows/ci.yml`: I authorize every change, whoever writes it;
- `README.md`, `CLAUDE.md`'s "Repository state" section, and `handoffs/HANDOFF-SUMMARY.md`.

**I do not touch:**
- other agents' code paths;
- `docs/verification.md`;
- `PRODUCT.md` (changed only through `/impeccable init`, with the owner);
- `DESIGN.md`.

**How I merge.** I squash-merge. I post a "B1 integration review" comment that ends with the merge-condition line: the reviewers accepted, and every CI job is green on the head SHA, or the PR is Markdown-only under D3-13 once #219 merges. When a head's CI is older than newer `main`, I check the merged result first:
- `go vet ./...`, also with `GOOS=windows`;
- `gofmt -l .`;
- the affected packages with `-race`;
- the affected end-to-end suites;
- the Windows leg on the merged result when it matters.

**Where things stand.**
- Phase 3's gate passed with conditions, and the owner said "Not yet". I ask the owner once, after cutover, what they want checked or changed. No Phase 4 brief is issued and `docs/phase4/` is not created until they accept.
- Every result stays `desk` or `simulated`.
- The standing safety rules apply unchanged:
  - no device contact;
  - the simulator on loopback only;
  - test credentials only;
  - nothing on the owner's PC beyond what they approved;
  - never a self-hosted runner.

## My first three actions

1. **Review and merge the B2 to B6 ack PRs** as they open. The handoff PRs my handoff names as the first action (#213 to #218) are already on `main` (`8b4c9b2`), so that step is done. I check each ack against the agent map for overlaps and gaps (see questions 2 to 4), and I make sure every question is answered by the matching A agent before cutover.
2. **After cutover, post one message to the owner.** It says the B team is in place and asks once what they want checked or changed before they accept Phase 3.
3. **After cutover, start the work that does not wait for acceptance:**
   - Release gate item 1's owed checks to B5 and B6 on the hosted Windows runner: the admin relay end to end with `config\admin`'s ACLs, the unknown-restart leg, and the canary scan of process command lines.
   - Start the integration review of #176, #177, #181 and #182. Each needs current CI and its reviewers' records, and a check on the merged result if `main` has moved.
   - Coordinate the Go 1.27.3 PR under D3-10.
   - Track the Windows CI hang in SQLite `FlushFileBuffers` (`TestDiscardStepWALBound` and `TestBadSuspensionRecordHoldsEverything` hit the 600 s timeout). B5 opens an item if it happens again; I do not count it as a flake.

## Questions and gaps for A1

1. **The owner's PC order in HANDOFF-SUMMARY.md contradicts D2-13 and the owner's standing rule.** The summary's "Standing rules" say to use the PC "first when a run needs Windows and the owner is available". D2-13 makes the PC the backup. The owner's project instruction makes GitHub Actions the main path, and the PC the second Windows run and the fallback when Actions is unavailable. B5's handoff repeats the summary's wording ("The owner's PC comes first only when it can do the job"). I propose the summary say: "the hosted runner first; the owner's PC as the second Windows run, and as the fallback when Actions is unavailable or a run needs a real installation". Do you agree, and will you fix it before cutover, or should I?
2. **Two files have two owners on record.**
   - `docs/threat-model.md`: the summary and B3's handoff give it to B3. The README table puts all of `docs/` under A1 and does not name it.
   - `docs/device-capabilities.md`: my handoff says I own it and B2 supplies the content. B2's handoff says B2 owns it.
   
   I propose B3 owns the threat model and B2 owns the capability matrix, with B1 reviewing each, and the README table naming both. Is that right?
3. **Paths with no named owner.**
   - `.github/workflows/a5-windows-experiments.yml`. I propose B5, with changes authorized by me as for `ci.yml`.
   - `contracts/internal/strictjson`. I propose B1, as for `contracts/version`.
   - `contracts/node`, which is listed as "A1 (maintained by A4)". I propose B1 owns it and B4 maintains it.
   - The root files `.gitattributes` and `.gitignore`. I propose B1.
4. **Names for new files.** My handoff says Phase 4 decisions go in `docs/phase4/A1-decisions.md`, numbered D4-1 onwards. The summary says agents write `docs/phase{n}/B{n}-*.md`. B2, B3 and B5's handoffs say `docs/phase4/A{n}-*.md`. I propose that every new file uses the B name (`docs/phase4/B1-decisions.md`, D4-n numbering), and that older files keep their A names as records. Do you see a reason to keep the A names?
5. **`contracts/README.md` is stale on where tests run.** Its merge rule still describes D1-26 (the owner's PC first, Actions only when the PC is offline), which D2-13 replaced. I own that file and will fix it after cutover, unless you want it in the handoff.
6. **#219 (Markdown-only PRs skip CI, D3-13).** I read the diff. The path filter (`'**'`, `'!**.md'`, `'**/testdata/**'`) is correct for this repository. The only Markdown files that any Go or Python test reads are the two `testdata/README.md` files the PR names (`contracts/asset/asset_test.go:131` and `contracts/adapter/adapter_test.go:621`). Pushes to `main` still run in full. Since it changes `ci.yml`, I take it that you merge it on green CI before cutover. If you would rather I merge it, say so.
7. **Who writes the Go 1.27.3 PR?** `go.mod` is mine under D2-2, and D3-10 says I coordinate the move. Do you expect me to write it, or one of B3 or B5 under my authorization? The Windows UDP stress test must also be repeated, and I need to know who runs that.
