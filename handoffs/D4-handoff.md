# D4 handoff: Telemetry, Event Processing and IDS

From C4 to D4, 2026-11-06, at `main` `961221b` (#475). Phase 4, item 3 (vulnerability applicability), at its exit gate. Role 4. Start with [HANDOFF-SUMMARY.md](HANDOFF-SUMMARY.md), which has the agent map and the standing rules, then read this file. Your scope and rules are C4's, given in [C4-ack.md](C4-ack.md) "My scope" and [B4-handoff.md](B4-handoff.md) "Role & scope". Since then, two things have been added: `modules/applicability/` (the R9 matcher, D4-52) and contract C12 `otsec.finding` in `contracts/finding`. You author C12, but any change to it goes through C1. Where a document says A4, B4 or C4, it means you.

## Verified state

Evidence classes: `desk`, `simulated`, `CI-Linux`, `CI-Windows`. Nothing is hardware-verified, and no device has been contacted.

| Item | State | Class | Source |
| --- | --- | --- | --- |
| C12 `otsec.finding/0.1`: classes, reasons, evidence by source, revisions | working, merged, approved (D4-53) | simulated, CI-Linux, CI-Windows | #440 `b6a753d`, #446; [C4-matcher.md](../docs/phase4/C4-matcher.md) |
| C12 tightening: passive evidence is never an `audit:` reference, and a device-read ID is a v1 to v8 RFC-variant UUID (D4-57, F-025) | working, merged | simulated, CI-Linux, CI-Windows | #476 `8b04003`; all 19 checks green on the PR's branch head `46bd3c2` (not on `main`) ([run 42168477739](https://github.com/alialyami90/OTSEC-Proj/actions/runs/42168477739)) |
| The matcher, `modules/applicability`: pure function, §5 order, currency, revisions, FID fuzz target, import test | working, merged | simulated, CI-Linux, CI-Windows | #451 `b9c361d`; `TestGTADV` (128 of 128 cells), `TestImportsArePure`, `FuzzFID` |
| A mismatch under an operator identity (D4-55) | working, merged | simulated, CI-Linux, CI-Windows | #459 `89206d4`; `TestOperatorMismatch` |
| V-M7 over GT-ADV on the real binaries (C6's run, my matcher) | pass, 128 of 128 cells after D4-56 | simulated, CI-Linux | #467, #469; C6's gate table in `docs/verification.md` |
| C12's contract tests by C6 (`tests/contract/c12_c6_test.go`) | merged; I reviewed them as owner and accepted | desk (my review), CI | #475 `961221b`; my review on #475 at its branch head `fa7fb37` |
| Event-behaviour learner and detector, snapshots with the caller's bound, F1 pair cap (512), C10 0.2, lifecycle, period (D4-45) | working, merged (item 2, accepted by the owner, D4-48) | simulated, CI-Linux, CI-Windows | #364, #369, #384, #405, #413, #414, #415; [phase-4a-exit.md](../docs/phase-4a-exit.md) |
| Syslog receive: unknown-sender stream and queue share (HR-11), UDP buffer | working, merged | simulated, CI-Linux | #291, #317, #274, #335; HR-11 row in [threat-model.md](../docs/threat-model.md) |
| IDS (brief item 4) | not started, by design (D4-34) | none | the owner has not named the sites' protocols |

**Step 1 commands**, run in this container (Linux, Go 1.27.3, on branch `c4-checkpoint` at `961221b`):

| Command | Result |
| --- | --- |
| `git status --short`, `git stash list` | both empty; no uncommitted work, no stash |
| commits ahead of `main` | none of content. `claude/project-thread-5bkbi1` (`46bd3c2`) holds only history already squash-merged (#459, #476) |
| `go vet ./...` | exit 0 |
| `$(go env GOROOT)/bin/gofmt -l .` | exit 0, prints nothing. The container's bare `gofmt` (`/usr/local/go/bin`, older) still lists `relptest_test.go` wrongly |
| `go test ./...` | exit 0: 52 packages `ok`, 3 with no test files, none failed (all packages of the root module; `platform/experiments/phase0` is a separate module and not run) |
| `python -m pytest -q` | **did not finish**: stopped by my 25-minute local timeout (exit 124) before it reported, so no counts and unverified here. It collects the long slice e2e tests, which CI splits into `integration-long` legs. CI's `python` job and every leg passed on run 42168477739 |

Windows results come only from Actions; the last Windows run on my code is `go (windows-latest)` in run 42168477739 (#476), success.

## Work in flight

- **No open PR of mine and no WIP.** Every C4 branch, local or remote (`claude/b4-*`, `claude/project-thread-5bkbi1`), is the head of a merged or superseded PR. `claude/b4-snapshot` (#344) was superseded by #364, and `claude/b4-pair-cap` by #369. Do not reopen them.
- **#480 (C6, open)** adds D4-57's pair to `tests/contract/c12_c6_test.go`. As C12's owner, check that it asserts passive `audit:...` evidence as refused, and that the skip comment I flagged on #475 is gone.
- **#479 (C1, open)** is the item 3 exit report. Every gate item is met except V-M1 (C6, GT-MIB's agent). It says the owner allowed `www.rfc-editor.org` and the RFC texts are in the project; `docs/verification.md` at `961221b` may still say V-M1 waits on the owner for them, so trust the newer record. It lists my one carried item: C12 0.2.
- **`HANDOFF-SUMMARY.md`** is rewritten by C1 last. If it still reads "B-team to C-team" (where C4's next action is "land #344", long done), this file is the current state for role 4.

## Next tasks, in priority order

1. **NEXT ACTION: review for the item 3 gate (D4-34: an agent with nothing queued does reviews and verification for the current item).** First #480's C12 part, if it is still open: it must assert passive `audit:...` evidence as refused for D4-57 and drop the skip comment. Then any change C6's V-M1 work makes to `contracts/finding`, `modules/applicability` or `tests/integration/applicability`. Acceptance: a posted review that says what was checked against C12's text, with its evidence class. Proof: `go test ./contracts/finding ./modules/applicability -count=1 && go test ./tests/contract -run C12 -count=1`, and both workflows green on the PR's head.
2. **Then, once C1 opens it: draft C12 0.2, citing a device-read mismatch on an operator or passive identity** (D4-55's accepted limitation; the exit report's next task 2). The draft is a written proposal first (`docs/phase4/D4-c12-0.2.md`), with no code until C1 approves it. **Dependency:** start once C1 says item 3's next tasks are open. Ask through the coordinator, since all cross-agent messages now go through them (owner, 2026-11-06). The proposal covers:
   - Today's rule, "identity evidence has the identity's source", refuses the citation. The draft must say how a device-read mismatch piece is allowed beside an operator or passive identity without letting an operator's entry be cited as a device read. #440's C6 probe "operator evidence citing a device read" must still fail.
   - The matcher then cites `Input.LatestMismatch` in `markStale` for non-device-read identities (`modules/applicability/applicability.go`).
   - C5's node already stores the mismatch run (`identity.read` `mismatch`, D4-54).
   - A reader for 0.1 is kept.

   Reviewers: C5 (the node), C6 (contract tests), C3. C1 approves. Acceptance: GT-ADV still 128 of 128 (`TestGTADV`), `TestOperatorMismatch` and `TestRevisions` still pass; a new case in which an operator identity under a mismatch cites the mismatch read; C6's c12 tests extended.
3. **IDS, item 4 (R6).** Do not start it before the owner's check of item 3 and their go (D4-34), and before the owner names the sites' protocols. Start from the Phase 0 Zeek and Suricata evaluation and GT-PCAP ([agent-handoffs.md](../docs/agent-handoffs.md), "Items 3 to 6").

## Blockers and risks

- **HR-11** (unknown senders) is mitigated in `simulated` only. It gates the first `device-observed` listener. The byte share has no real-store test (C4 on #379 and #434). Owner: C6, receiver mine. See [threat-model.md](../docs/threat-model.md).
- **D3-10:** the Windows UDP corruption cause is inferred (the Go 1.26.2 fix). Reopen it if a `receive` panic returns.
- **HR-18 (owner):** who publishes the advisory set and holds its key. Until it is answered, every advisory is `test_only` and the matcher has never seen a real one.
- **V-M4's real false-positive rate** needs a real device's event history. Every figure comes from C6's synthetic GT-INJ.
- **Unverified:**
  - the matcher on any real FID beyond the SEL-751 goldens;
  - C11's `exact` scheme on any real product;
  - whether real advisories fit the `sel-fid` branch model (one branch, never ordered across branches).

## Decisions and lessons

- **Decisions:** D4-49 to D4-57 in [B1-decisions.md](../docs/phase4/B1-decisions.md); D4-52 is my module, D4-55 the operator mismatch, D4-56 recorded controls, D4-57 C12's ID forms. Also ADR-0008, and the matcher note's §11 for what the code settles.
- **Failed approaches**, each recorded where it was fixed:
  - Only the device-read identity counted a mismatch, so an operator-only asset under a mismatch stayed `not-applicable` (C5 on #458, fixed #459).
  - A mismatch hid outside-range and Q5 cells, where it should only leave firmware-version unread (C6 on #451, fixed by branch commit `b0522d4`, squashed into #451).
  - Two ID forms could collide, `audit:<node>:<seq>` against `<node>:<stream>:<seq>` (F-025, fixed #476 and #477).
- **Gotchas:**
  - Equal times count as stale: identity currency is "`LatestRead` strictly before neither `LatestChange` nor `LatestMismatch`".
  - A stale mark alone is a revision (D4-53), so `TestRevisions` counts four, not three.
  - Push with `git push origin <local>:claude/project-thread-5bkbi1`. When the remote holds squashed history, first run `git merge -s ours origin/claude/project-thread-5bkbi1`. Force-push is denied.
  - Use the toolchain's gofmt (above).
  - `message_thread` text is capped at 2000 characters, and it is no longer used: send through the coordinator.

## Progress since [C4-handoff.md](C4-handoff.md) (B4 to C4, 2026-10-28)

- **Item 1, land #344:** dropped and superseded by #364 `f9e7234`, with the caller's byte bound (D4-26, D4-30).
- **Item 2, F1 pair cap:** done in #369 `53f9b1a` (`MaxNewTypePairs` 512, D4-30).
- **Item 3, `Params.Validate()`:** done in #369.
- **Item 4, reviews:** #346 merged `151c17a` (D4-29); #336 carried by #379; the feeder in #340, #405, #413 and #415.
- **Item 5, IDS:** not started, by design.
- **Item 3's brief, P4-3-C4:** done in #440, #451, #459 and #476, with C6's V-M7 on the binaries in #467 and #469.
- **§7 gaps:** no real advisory, no real device, and V-M7 is `simulated`.
- **Regressions:** none. **Re-runs:** none on my PRs this generation. **Review debt over a day:** none. **Out-of-brief work:** none.
- **Repeated work:** none recorded this generation.
- **STALLED:** IDS (item 4) has been untouched for two generations. That is by design: it is gated on the owner, not stalled by the role.

Validated 2026-11-06: fixed. A fresh read-only agent was given only `CLAUDE.md`, the summary, this file, and the files they link to. It named the right state, files, checks and limits. Fixes made:

- the proof command matched too few tests;
- NEXT ACTION was blocked, so it moved to the review that can start now;
- three SHAs were branch heads, not on `main`;
- V-M1's RFC-text state differed between records;
- the summary is stale until C1 rewrites it.
