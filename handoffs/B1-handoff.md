# B1 handoff: Principal Architect and team lead

From A1 to B1, 2026-10-27. Read [HANDOFF-SUMMARY.md](HANDOFF-SUMMARY.md) first. This file does not repeat it.

## Role & scope

You are the role CLAUDE.md §4 calls A1: you coordinate, review and integrate. You are not the default implementer (§4, A1).

You own:

- `docs/` other than `docs/verification.md` (B6 owns that). This covers `architecture.md`, `requirements.md`, `agent-handoffs.md`, `device-capabilities.md` (B2 supplies the content), the phase exit reports, `docs/phase{n}/A1-decisions.md`, and the ADRs in `docs/decisions/`.
- `contracts/`. Each owner drafts its own contract; you approve it after every consumer reviews it. `contracts/README.md` holds the conventions.
- `go.mod` and `go.sum` (D2-2). Every new module needs your approval in review.
- `.github/workflows/ci.yml`. You authorize every change to it, even when another agent writes the change.
- `README.md`, `CLAUDE.md`'s "Repository state" section, and `handoffs/HANDOFF-SUMMARY.md`.

You do not touch:

- Another agent's code paths. Ask the owner of the path to change it instead.
- `docs/verification.md`.
- `PRODUCT.md` without the owner. It is the product-truth file for UI work and changes only through `/impeccable init`.
- `DESIGN.md`, which must not be written by hand.

You merge PRs:

- Squash-merge.
- Post an "A1 integration review" comment on each PR (from now on, "B1 integration review"). It ends with the merge-condition line, stating that the reviewers accepted and every CI job is green on the head SHA.
- End every GitHub comment with the Claude Code footer.

## Current state

- **Phase 3:** the gate passed with conditions; the owner chose "Not yet" on acceptance. **Done:** the exit report (#209), A6's gate-item-1 record (#208), and the harness live-read fix (#212). **Status: waiting on the owner.** The question still open is what the owner wants checked or changed before accepting. Ask it once; don't repeat it.
- **Phase 4:** briefs drafted, not issued. **Held** until acceptance.
- **The handoff itself:** these files plus the doc updates in the same PR. B2's handoff is #213 and B3's is #214. B4, B5 and B6 open their own docs-only PRs. Each needs your review and merge.
- **Open PRs you will review:** A5's #176, #177, #181 and #182, deferred until after the gate. Each needs current CI and its reviewers' records before merge, and the Windows leg checked against the merged result if `main` has moved.
- **Blocked:** nothing on your side, other than the owner's acceptance.
- **The decision log** runs to D3-11 in `docs/phase3/A1-decisions.md`, with the handoff recorded as D3-12. Phase 4 decisions start a new file, `docs/phase4/A1-decisions.md`, numbered D4-1 onwards.

## Next steps

1. **First action:** review and merge the B2 to B6 handoff PRs (#213, #214, and the B4, B5 and B6 ones when they open). Check that each has the owner's eight sections and links rather than copies. Then tell the coordinator that the handoff files and the summary are on `main`.
2. Review the six `B{n}-ack.md` files. Check them for overlaps or gaps in ownership against the agent map. Get every question answered (by the matching A agent before cutover, by you after it).
3. After cutover, post one short message to the owner. Say the B team is in place, and ask what they want checked or changed before accepting Phase 3.
4. While waiting, run the work that does not need acceptance:
   - gate item 1's owed checks on the hosted Windows runner (B5 and B6);
   - review of #176, #177 and #182;
   - the Go 1.27.3 PR, which is yours to coordinate under D3-10: its own PR, full CI, B3 and B6 review, the Windows UDP stress test repeated, and never auto-merged.
5. When the owner accepts:
   - mark the Phase 3 exit report as owner-accepted;
   - issue the Phase 4 briefs by changing their heading from "draft" to "issued";
   - create `docs/phase4/`;
   - follow the Order section of the briefs: C9, C10, C7 0.6 and C8 0.5 are drafted at once and approved together.

## Key files

| File | Why |
| --- | --- |
| [CLAUDE.md](../CLAUDE.md) | The brief: roles, the review table, the milestone report format (§9), and the owner's scope update (ADR-0006). |
| [docs/phase-3-exit.md](../docs/phase-3-exit.md) | The current state, open risks, limitations and next tasks. Read it in full. |
| [docs/agent-handoffs.md](../docs/agent-handoffs.md) | The brief template, the review assignments, and the Phase 4 briefs, order and gate (end of the file). |
| [docs/phase3/A1-decisions.md](../docs/phase3/A1-decisions.md), [docs/phase2/A1-decisions.md](../docs/phase2/A1-decisions.md), [docs/phase1/A1-decisions.md](../docs/phase1/A1-decisions.md) | Every ruling in force. Start with D2-1 (owners and import rules), D2-4 and D2-10 (the locks), D2-11 and D2-12 (credential gates), D2-13 (testing), D3-10 (toolchain). |
| [docs/decisions/](../docs/decisions/) | ADR-0002 to ADR-0008. ADR-0008 sets the monitoring goals and the Phase 4 order. ADR-0007 (the Windows site node) is still `proposed`. |
| [docs/architecture.md](../docs/architecture.md) | The system boundary, what the platform may and must never do, and the runtime shape. |
| [docs/verification.md](../docs/verification.md) | B6's criteria. V-M1 to V-M8 are the Phase 4 bar, and a brief may not lower them. |
| [contracts/README.md](../contracts/README.md) | Contract versioning and compatibility rules. |
| `.github/workflows/ci.yml` | The ten jobs every merge depends on. |
| `/mnt/project-files/phase3/` (project files, not the repo) | `A1-exit-notes.md` is A1's running log of gate events. `P3-W1-pc-run-result.md` and `P3-W1-pc-pytest.txt` are the owner's PC run. |

## Decisions made

These are recorded in the decision files. Don't reopen them without new evidence:

- **D2-13: GitHub Actions is the main test path.** The owner asked for it. The PC is used for owner-present Windows runs only.
- **D3-10: build with the latest patch of a supported Go minor.** `govulncheck` is pinned in CI. Bumps are reviewed by A3 and A6 and never auto-merged. The Go 1.27.3 move was kept off the Phase 3 gate, so the gate's evidence stays on the toolchain it was gathered with (1.26.10).
- **The Phase 3 gate passed with conditions, not clean.** The conditions are the untested Windows items listed under gate item 1. A clean pass would overstate what the PC run covered.
- **D3-11: a SER result with no `DATE_F` keeps the pre-0.5 date rule.** Refusing it would stop collection while the relay's finite SER buffer overwrites records.
- **Phase 4 briefs only items 1 and 2 in full**, because they share the store and the audit chain and their contracts must be agreed together (§5.4). Items 3 to 6 get briefs one at a time, each after the previous item passes its gate.
- **The window cap for prior approval is proposed at 24 h.** "Prior" means the approval's `collector_seq` is lower than the `config.read` decision's. P4-A3 and P4-A5 carry this.
- **D3-12 (handoff):** the B agents take over the A roles unchanged. Older records keep the A names.

## Open questions / risks

- **The owner's acceptance of Phase 3**, and what they want checked first. This is the only thing between now and Phase 4.
- **ADR-0007 is still `proposed`.** The Windows site-node consequences have hosted-runner and desktop evidence only, nothing on the SEL-3355-2 image or LTSC 2021.
- **Open risks that gate the first `device-observed` endpoint or listener:** HR-11, HR-12, D2-11, D2-12 (until #176), D2-16, and the Windows state replace. See the exit report.
- **ADR-0008's FTP rung for the SEL-751** waits on hardware test Q3, which needs the owner's authorization and an out-of-service lab relay. Don't promise it.
- **Fragile area: timing assumptions in tests on loaded runners.** Phase 3 fixed several (see the exit report's "Lessons"). Insist on property checks rather than fixed sleeps when you review.

## Dependencies

- **You feed everyone** the approved contracts, the briefs, the decisions and the merges.
- **You wait on:**
  - the owner, for acceptance and for any device or PC authorization;
  - B6, for the independent PASS on contract and gate work;
  - each owner, for its handoff and ack.
- **The coordinator** starts and stops threads and relays the owner's messages. If the inter-thread limit blocks a direct message to a B agent, ask the coordinator to pass it on.

## Gotchas

- **Stale CI.** CI on a PR's head can predate newer `main`. #197 merged on old CI and turned `main`'s Windows job red. Before merging such a PR, run `go vet ./...` (also with `GOOS=windows`), `gofmt -l .`, the affected packages with `-race`, and the affected end-to-end suites on the PR merged locally with `main`. If the Windows leg matters, get it run on the merged result.
- **One re-run per failing commit.** Never push an empty commit to kick CI. A property-test failure is a finding, not a flake: #178 and the CNG pointer bug both looked like flakes at first.
- **The owner's PC log was UTF-16LE with a BOM and CRLF.** That is how Windows PowerShell's `Tee-Object` writes. The copy in project files is UTF-8 with LF. To check it against the PC's hash, re-encode it the same way: `(printf '\xff\xfe'; sed 's/$/\r/' P3-W1-pc-pytest.txt | iconv -f UTF-8 -t UTF-16LE) | sha256sum`.
- **Service teardown lines go to the SCM log, not to pytest's output.** Don't expect them in `pytest.txt`.
- **Use the GitHub MCP tools for GitHub work.** There is no `gh` CLI in the session.
- **Every GitHub comment ends with the Claude Code footer.** Commit messages and PR bodies end with the attribution lines the session gives you. No model names in anything pushed.
- **The owner sees one Claude.** Never quote or forward another session's report verbatim; say what it found in your own words. A Remote Control session on the owner's PC is started only for an owner-present run and stopped after it.
- **Exit reports have been corrected after review four times in Phase 3.** The errors were a wrong SHA, "byte-exact" where only the content matched, a missing condition, and "his" instead of "their". Check every SHA and count against its source before writing it.
