# C4 acknowledgement: Telemetry, Event Processing and IDS

From C4, 2026-10-28, at `main` `5d51fc4` (#337). I read [HANDOFF-SUMMARY.md](HANDOFF-SUMMARY.md), then [C4-handoff.md](C4-handoff.md), then the files it links to: [B4-handoff.md](B4-handoff.md) "Role & scope", D4-26 to D4-28 in [B1-decisions.md](../docs/phase4/B1-decisions.md), and the PR threads of #344, #343 and #346. I checked the handoff's PR and branch state against GitHub at about 17:30Z. Everything below is `desk` unless it says otherwise.

## My scope

- **I own** `modules/telemetry/` (receive, normalize, forward), `modules/detection/` (the event-baseline learner and detector), `tests/fixtures/network/`, and my design notes (`docs/phase4/B4-*.md`, earlier `A4-*.md`; new notes may be `C4-*.md`).
- **As author I own the contracts** C4 (`contracts/event`), C6 (`contracts/syslog`) and C10 (`contracts/baseline`), and I maintain `contracts/internal/strictjson` and `contracts/node` for C1. Any change to them is a shared-contract change: a written proposal, review by every consumer, C6's contract tests, and C1's approval.
- **I do not touch** `platform/` or `cmd/otsec/` (C5), `modules/ied/` (C2), `modules/access/`, `modules/security/` or `cmd/otsec-collector/` (C3), C6's test directories, or any other contract.
- **I review** C2's protocol-adjacent work, C5's listener wiring and the event-baseline feeder, store changes that affect telemetry, and C6's tests on the receive, normalize and detection paths. C6 and C2 review my work. Only C1 merges.
- **Rules I keep**: no contact with any device; every endpoint on the simulator or loopback; test credentials only; every result labelled with its evidence class (today `desk`, `simulated`, `CI-Linux` or `CI-Windows`); GitHub Actions is the only test path while D4-12 holds; a failing commit gets at most one re-run; no empty commits; no force-push; stage by explicit path. IDS (brief item 4) does not start until the owner names the sites' protocols.

## What I checked

| Item | What I found | Class | Source |
| --- | --- | --- | --- |
| #344 snapshots | open, head `7dbe6b0`, mergeable (clean), 13 of 13 checks green; no review and no comment yet | CI-Linux, CI-Windows | [run 40726548965](https://github.com/alialyami90/OTSEC-Proj/actions/runs/40726548965) |
| `claude/b4-pair-cap` (F1) | head is now `cb370ac`, not `3f75825` as the handoff says. `cb370ac` already does the three "Left" items: `doc.go` "Limits" and F1 in `B4-snapshot.md` describe the cap, `Observation` is listed as a field that can differ in a replay, and the note-clip mutant is gone (the clip was unreachable and was removed, with a test that the observation stays under 120 bytes). Still left: rebase onto `main` after #344 merges and open the PR | simulated | `git show cb370ac` |
| F1 tests on `cb370ac` | `go vet ./modules/detection/...` exit 0; Go 1.27.3 `gofmt -l modules/detection` clean; `go test -count=1 ./modules/detection/... ./contracts/baseline/...` both `ok` (11.6 s, 0.04 s). It merges into `main` without conflicts (`git merge-tree`) | simulated, Linux container | this session |
| `Params.check` | unexported, at `contracts/baseline/baseline.go:341`, as the handoff says | desk | `main` `5d51fc4` |

## My first three actions

1. **Land #344 (NEXT ACTION).** Ask C5 and C6 for their reviews, answer findings with validated pushes, and update the branch from `main` if C1 asks (`main` has moved six commits past the PR's base `04bb504`, all Markdown only, so none touches `eventbaseline`). Proof: `go test ./modules/detection/eventbaseline -run TestSnapshot -count=1` and all 13 checks green on the head. If C1 rules on question 1 below before #344 merges, the bound parameter goes into #344 rather than a follow-up.
2. **Post the review debt that only needs reading, not feature work**: my review of #346 against D4-26 item 4 and D4-29 (question 2 is settled), and the review of #336 (D4-21's criterion on the real store, receiver side). Then re-check #343's checkpoint floor, which C5 asked me to do after their push.
3. **Open the F1 PR** from `claude/b4-pair-cap` once #344 merges: merge `origin/main` into the branch, wait for green, and ask C5 and C6 to review against D4-26 item 4's four rules. After that, `baseline.Params.Validate()` (C5's ask, an additive C10 change) as its own small PR.

I start none of these feature steps until C1 confirms the cutover. Reviews and comments I can post now.

## Questions

For C1 unless marked.

1. **Gap: C5's ask for a parameterized snapshot bound is not in my handoff.** On #343 ([comment](https://github.com/alialyami90/OTSEC-Proj/pull/343#issuecomment-6474873717)) B5 chose to store the checkpoint as one configuration record (cap `ConfigRecordBytes`, 1.5 MiB) and asked B4 to make the byte bound a parameter (`Snapshot(maxBytes)` or a config field, refusing above it with `ErrSnapshotTooLarge`), and to say whether an oversize snapshot can be detected before it is built in full. [C5-handoff.md](C5-handoff.md) lists this as unanswered. It has a consequence: the learner at the 4096-type ceiling with 128-byte names measures about 1.9 MB, so under that layout it cannot be checkpointed at all, and the detector with every cap full is about 1.3 MB, close to the cap. **My proposal:** add the parameter to #344 before it merges (keep `MaxSnapshotBytes` as the hard ceiling), and answer C5 that the size is known only after encoding, though a cheap upper estimate from the type count can refuse early. **For C1:** is a learner that cannot be checkpointed near the ceiling acceptable under D4-26, or should C5's layout split a checkpoint over records? I will fix my handoff file with this gap after this ack merges.
2. **`correlation_id` on #346.** B5 proposes the baseline's own digest (`baseline_digest`), and B4 leaned the same way, so I would propose that. But C3's handoff notes that an acknowledgement's `correlation_id` is today the signed request ID, which conflicts with D4-26 item 4's "the same on a recording and on its acknowledgement". **For C1 and C3:** may the acknowledgement keep its request ID and join on `baseline_digest` instead, which it already carries? If yes, I will post that on #346 as the proposal. **Answered by C1 as D4-29 (2026-10-28, comment on #361):** the recording's `correlation_id` is the 64 hex digits of `baseline_digest` without `sha256:` (C8's `idPattern` caps it at 64), the acknowledgement keeps the signed C7 request ID, and the two join on `baseline_digest`. I agree; it matches my leaning, so nothing more is owed from me on #346 for this point.
3. **A receive-path property failure, for C6.** #346's first Windows run failed `tests/integration/syslogreceive` `TestUnknownSpentAcrossRestarts/seed_1` ("UDP marker lost without a count", `restart_test.go:662`), then passed on the one re-run (the same check on [run 40728171729](https://github.com/alialyami90/OTSEC-Proj/actions/runs/40728171729)). #346 does not touch the receiver. A lost, uncounted datagram is the HR-11 property itself, so I do not treat it as a flake. The receiver is my code and the test is C6's. I propose C6 and I reproduce it against `main` before HR-11 is closed. **For C1:** shall I own that as a task, with C6?
4. **My handoff's stale lines.** Besides question 1, [C4-handoff.md](C4-handoff.md) gives the F1 head as `3f75825` with three items left, which `cb370ac` finished. I will correct both in one Markdown-only PR after this ack merges, since this PR touches only this file.

No overlap found with C2, C3, C5 or C6. C5's handoff names me as the reviewer of #343 and #340, and C6's names me as a reviewer of #336. Both match my handoff.
