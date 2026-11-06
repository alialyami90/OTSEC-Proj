# D4 acknowledgement: Telemetry, Event Processing and IDS

From D4, 2026-11-06, at `main` `a774a97` (#486, the C1 to D1 checkpoint). I read [HANDOFF-SUMMARY.md](HANDOFF-SUMMARY.md), then [D4-handoff.md](D4-handoff.md), then the files it links to: [C4-ack.md](C4-ack.md) "My scope", D4-49 to D4-58 in [B1-decisions.md](../docs/phase4/B1-decisions.md), the item 3 exit report [phase-4-item3-exit.md](../docs/phase-4-item3-exit.md), the HR-11 row in [threat-model.md](../docs/threat-model.md), and role 6's WIP note in `/mnt/project-files/c6-wip/README.md`. I checked the PR and branch state against GitHub at about 13:00Z. Everything below is `desk` unless it says otherwise.

## My scope

- **I own** `modules/telemetry/` (receive, normalize, forward), `modules/detection/` (the event-baseline learner and detector), `modules/applicability/` (the R9 matcher, D4-52), `tests/fixtures/network/`, and my design notes (`docs/phase4/C4-*.md` and earlier; new notes may be `D4-*.md`).
- **As author I own the contracts** C4 (`contracts/event`), C6 (`contracts/syslog`), C10 (`contracts/baseline`) and C12 (`contracts/finding`), and I maintain `contracts/internal/strictjson` and `contracts/node` for D1. Any change to them is a shared-contract change: a written proposal, review by every consumer, D6's contract tests, and D1's approval.
- **I do not touch** `platform/` or `cmd/otsec/` (D5), `modules/ied/` or `modules/asset/` (D2), `modules/access/`, `modules/security/` or `cmd/otsec-collector/` (D3), role 6's test directories, or any other contract.
- **I review** changes to `contracts/finding`, `modules/applicability` and `tests/integration/applicability` (item 3), D2's protocol-adjacent work, D5's listener wiring and the event-baseline feeder, store changes that affect telemetry, and D6's tests on the receive, normalize, detection and applicability paths. D6 and D2 review my work. Only D1 merges.
- **Rules I keep:** the standing rules in the summary, word for word. In short: no contact with any device; every endpoint on the simulator or loopback; test credentials and test advisory keys only (HR-18); every result labelled with its evidence class; GitHub Actions is the only test path while D4-12 holds; at most one re-run of a failing commit; no empty commits; no force-push; stage by explicit path; every message to another agent goes through the coordinator. IDS (item 4) does not start until the owner has checked item 3, given their go, and named the sites' protocols (D4-33, D4-34).

## What I checked

| Item | What I found | Class | Source |
| --- | --- | --- | --- |
| Open PRs | none open on the repository | desk | GitHub, 13:00Z |
| `main` since my handoff (`961221b`) | 8 commits: #479 (exit report), #480 (C6 tests), and the checkpoints #481 to #486. Only #480 touches my area, in `tests/contract/c12_c6_test.go` | desk | `git log 961221b..a774a97` |
| #480's C12 part (my handoff's first review item) | merged as `158a5d0` before I could review it on the PR, so I checked it on `main`. `TestC12EvidenceIsItsSourcesForm` refuses every cross-source citation (the full source-by-form matrix) and the named case "an audit ref cited as passive, on node audit"; `TestC12NodeAuditIsReserved` covers D4-57's reserved node. No `t.Skip` and no skip comment remain in the file. It meets what my handoff asked | desk, simulated | `main` `a774a97`, `tests/contract/c12_c6_test.go` lines 87 to 125 |
| My proof command | `go test ./contracts/finding ./modules/applicability -count=1`: both `ok`. `go test ./tests/contract -run C12 -count=1 -v`: 5 tests pass (`TestC12SourcesAreC1s`, `TestC12NamesAC11SetExactly`, `TestC12EvidenceIsItsSourcesForm`, `TestC12AFindingAtEveryBoundFitsOneRecord`, `TestC12NodeAuditIsReserved`) | simulated, Linux container, Go 1.27.3 | this session, at `a774a97` |
| Role 6's V-M1 WIP patch | it creates files under `tests/integration/gt_mib/agent/` only (6 files). Nothing in `contracts/finding`, `modules/applicability` or `tests/integration/applicability`, so as it stands it needs no review from me | desk | `/mnt/project-files/c6-wip/2026-11-06-gt-mib-agent-wip.patch` |
| RFC texts for V-M1 | all twelve are in `/mnt/project-files/rfc/` with `SHA256SUMS`, as the summary says | desk | directory listing |
| HR-11 | mitigated in `simulated` only; still a gate before the first `device-observed` listener. The byte share of D4-21 still has no real-store test (C4 on #379 and #434) | desk | HR-11 row, `docs/threat-model.md` |

I ran no full `go test ./...` or pytest for this ack: it changes only this file, and nothing in my area moved apart from #480's test, which I ran.

## My first three actions

1. **Review for the item 3 gate (NEXT ACTION, D4-34).** #480 is done (above). What remains is any change D6's V-M1 PR makes to `contracts/finding`, `modules/applicability` or `tests/integration/applicability`. When the coordinator relays that D6's PR is up, I check its file list. If it touches my paths, I post a review that says what I checked against C12's text, with its evidence class, and run `go test ./contracts/finding ./modules/applicability -count=1 && go test ./tests/contract -run C12 -count=1` on its head, with both workflows green there. If it does not, I tell the coordinator that no review from role 4 is needed.
2. **Draft C12 0.2 as a written proposal** (`docs/phase4/D4-c12-0.2.md`, no code): citing a device-read mismatch on an operator or passive identity (D4-55's accepted limitation; the exit report's next task 2). It must keep #440's probe "operator evidence citing a device read" failing, have the matcher cite `Input.LatestMismatch` in `markStale` for non-device-read identities, use the mismatch run D5's node already stores (`identity.read` `mismatch`, D4-54), and keep a 0.1 reader. Acceptance: `TestGTADV` 128 of 128, `TestOperatorMismatch` and `TestRevisions` still pass, a new case where an operator identity under a mismatch cites the mismatch read, and D6's c12 tests extended. Reviewers D5, D6, D3; D1 approves. I start it when D1 answers question 1.
3. **Keep IDS (item 4) closed** until the owner's item 3 check, their go and the sites' protocols arrive. When they do, start from the Phase 0 Zeek and Suricata evaluation and GT-PCAP ([agent-handoffs.md](../docs/agent-handoffs.md), "Items 3 to 6").

I start no feature work until D1 confirms the cutover. Reviews I can post now.

## Questions

For D1 unless marked, through the coordinator.

1. **May I write the C12 0.2 proposal now, before item 3's next tasks open?** My handoff says to wait for D1 to open it. My only other queued item, the V-M1 review, waits on D6, and the WIP patch suggests it may not touch my paths at all. The proposal is a document with no code, so drafting it now costs nothing if D1 later reorders it. I propose to draft it now and not open a code PR until D1 approves the proposal.
2. **#480 merged without the C12 owner's review on the PR.** I checked it on `main` (above) and found nothing to fix. I propose to record that here only and not comment on the merged PR, to avoid a notification that asks for nothing. Tell me if D1 wants it on #480.
3. **For D6:** does the V-M1 runner plan to change `contracts/finding`, `modules/applicability` or `tests/integration/applicability`? If not, I am not on the reviewer list for it, and the summary's step 3 can drop role 4 for that PR. **Answered by D6 through the coordinator (2026-11-06, 12:52Z):** no. The runner lives under `tests/integration/gt_mib/` only, and D6 does not plan to change `tests/integration/applicability`. If V-M1 (a)'s both-on run needs a change there, D6 will say so in the PR description and ask for my review through the coordinator.
4. **HR-11's byte share.** The real-store test for D4-21's byte share is still owed (role 6's test, my receiver). It is a gate before the first `device-observed` listener, not before item 3. Is it on D6's list, or should it be carried as an open item in the next summary so it is not lost?

## Corrections to my handoff

- #480 is merged (`158a5d0`), and its C12 part is checked (above). The handoff's first review item is done.
- "C1" in my handoff means D1, and C12 0.2 waits on D1, not C1.
- The handoff's main SHA `961221b` is now `a774a97`; nothing in my paths changed between them except the test file above.

No overlap found with D2, D3, D5 or D6. The summary's dependency order names me as a reviewer of D6's V-M1 PR only for changes in my paths, which matches my handoff.
