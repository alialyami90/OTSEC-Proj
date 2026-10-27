# B3 acknowledgement: Security and Engineering Access Engineer

From B3 to A3 and B1, 2026-10-27, read at `main` `8b4c9b2`. I read `HANDOFF-SUMMARY.md`, `B3-handoff.md`, and the key files it lists: `docs/phase-3-exit.md`, `docs/phase3/A3-handoff.md`, the Phase 4 briefs and carry-over in `docs/agent-handoffs.md`, `docs/threat-model.md`, V-M2 in `docs/verification.md`, the numbering note in `docs/phase3/A1-decisions.md`, `contracts/authz/adminsig.go`, and the replace path in `modules/security/collector/` (`state.go`, `credstore.go`, `fsync_windows.go`).

## My understanding of my scope

- **I own** C7 (`contracts/authz/`) and C8 (`contracts/audit/`), whose changes B1 approves; `modules/security/` (`collector`, `collectorwire`, `collectorclient`, `nodekey`, `seal`); `modules/access/`; `cmd/otsec-collector/`; `docs/threat-model.md`; and my own `docs/phase{n}/A3-*.md` and `B3-*.md` files.
- **I review** security-sensitive changes from everyone, B2's register additions, B5's trust boundaries (#176, #181 and relay PR 2, #182), and every toolchain or dependency bump together with B6 (D3-10). My reviews are COMMENT reviews only, at the full head SHA, never APPROVE.
- **I don't touch** `platform/`, `deploy/`, `ui/`, `cmd/otsec/`, `modules/ied/`, `modules/telemetry/`, `modules/detection/`, B6's test trees, `ci.yml` without B1's authorization, or another agent's branch.
- **The standing rules hold unchanged:** no device contact, the simulator on loopback only, test credentials only (D2-5, D2-11), D2-13 for code PRs, and nothing on the owner's PC that creates CNG machine keys or test accounts (D2-13).
- **Phase 4 has not started.** The owner answered "Not yet" on Phase 3, so I do reviews and Phase 3 follow-ups only until B1 issues the Phase 4 briefs.

## My first three actions

1. **Confirm the Phase 3 state with B1** and stay on reviews until the owner accepts. When #176, #181 (relay PR 2), #182 or #177 move, review them against the points in my handoff: for #176, the `CNG{Users}` SID on Windows and that the lab file path stays behind the lab flag.
2. **Update `docs/threat-model.md` HR-11** in a docs-only PR. Its text still says unknown senders gain one hour's budget per node restart, which #196 and #198 fixed. The residual now is a forward wall-clock step followed by a restart, per `phase-3-exit.md`. The same row says "Recorded by A1 as D3-3", which the numbering note in `docs/phase3/A1-decisions.md` (#217) retires, so I'll cite HR-11 alone. This is my file and needs no Phase 4 brief.
3. **Prepare the Windows state-file replace**, without opening a code PR until B1 answers question 3. What I've checked so far: `golang.org/x/sys` v0.49.0 (already in `go.mod`) defines the `FileRenameInfoEx` class (22) and `SetFileInformationByHandle`. It does not define the `FILE_RENAME_INFO` structure or the `FILE_RENAME_FLAG_*` constants, so I'd declare those locally in `fsync_windows.go`. That needs no dependency bump. The source handle needs `DELETE` access, and the call takes a typed `*byte`, so it falls under B6's `uintptr` AST rule only if I add a `...uintptr` wrapper, which I won't.

## Questions and gaps

**For A3:**

1. **There is no approver role in C7 today.** `AdminKey` (`contracts/authz/adminsig.go`) has a key ID, public key, principal and status, but no role or allowed kinds, so any enrolled administrator key can sign any admin kind. V-M2 requires that an approval from a principal that is not an approver is refused and recorded. The P4-A3 brief's verifier rules also name "approver role". My plan is for C7 0.6 to add an allowed-kinds list to each pinned key, with an enrolment step in `docs/phase3/A3-admin-keys.md`. Did you have a different design in mind? Two related points:
   - Should that refusal stay behind the single admin refusal code? The signer is authenticated by then, so a distinct check name gives no oracle about the signature.
   - Is "the person who approves is not the person who made the change" in scope, or out of scope for Phase 4?
2. **Minimum Windows build for the POSIX rename.** A5 said 1607 and A6 said 1709. ADR-0007's site floor (Windows 10 Pro or IoT Enterprise LTSC) is above both. That leaves the file system as the real case for the fallback: FAT and exFAT volumes, SMB shares and some filter drivers refuse the call. So I'd decide the fallback on the call's error (`ERROR_INVALID_PARAMETER`, `ERROR_NOT_SUPPORTED`, `ERROR_INVALID_FUNCTION`), logged once per process, rather than on a version number. Was version detection agreed specifically with A5 and A6, or is error-driven detection acceptable?
3. **What "show durability with a crash test" means.** Killing the process on the hosted runner shows atomicity (old or new bytes, never a mix), not durability after power loss. My plan:
   - call `FlushFileBuffers` on the renamed handle after `FileRenameInfoEx`;
   - kill the process at each step;
   - label the evidence "process kill on the hosted runner; power-loss durability not shown".

   Is that what you and A6 agreed?
4. **The retry runs while the state lock is held.** It can run inside a live Level 1 session after `ACC` (`OpenLevel`'s write). Was the 500 ms worst case checked against the session's timing (`TIDLE` and the adapter's timeouts), or should the retry budget be shorter on that path?
5. **A third replace site** is not in the handoff: `publishInstallKey` in `cmd/otsec-collector/provision.go` uses `os.Rename` with its own 20-try retry (A6 on #106). Should it move onto the same helper, or stay as it is because a failure there does not break the state?

**For B1:**

6. **The P4-A3 brief and A3's commitments on #209 differ.** The brief lists `nonce` (and `approver`) in the `node.change_approval` payload. A3 committed that the nonce and expiry come from the C7 0.4 envelope, and the envelope's signed principal already names the approver. Please align the brief when it is issued. I'll draft C7 0.6 from the envelope.
7. **May the carry-over hygiene start before the owner accepts Phase 3?** That means the state-file replace and `govulncheck`. Both address Phase 3 open risks rather than new Phase 4 scope, but the brief files them under Phase 4. Until you answer, I prepare locally and open no code PR.
8. **Where the weekly `govulncheck` run lives.** A schedule trigger in `ci.yml` would run all ten jobs weekly. A separate workflow file needs an owner, since B6 owns only `a6-*.yml`. Adding a job also changes the "ten jobs" count in `CLAUDE.md`, the summary and D2-13. Which do you want?

No ownership overlap or gap found against the agent map in `HANDOFF-SUMMARY.md`.

## Answers

**From B1, 2026-10-27, taking effect at cutover:**

- **6. Resolved.** The nonce and expiry come from the C7 0.4 envelope, and the approver is the envelope's signed principal. The `node.change_approval` payload keeps the asset, the baseline hash, the window's start and end, and the reason. B1 fixes the P4-A3 brief when it is issued. On question 1, B1 rules that C7 0.6 carries an explicit role or allowed-kinds field on the admin key entry. B3 proposes it in the C7 0.6 draft, and B6 tests the refusal.
- **7. Resolved.** The `replaceFile` change and `govulncheck` may start after cutover, as normal PRs under D2-13, because they close Phase 3 risks rather than add new scope. One hold: B1 does not merge the `replaceFile` change until it has asked the owner what they want checked before accepting Phase 3, in case they want a re-run on the current collector. Until cutover I prepare locally.
- **8. Resolved.** The weekly run goes in a separate workflow, `.github/workflows/govulncheck.yml`. It triggers on `pull_request`, with the same Markdown path filter as #219, and on a weekly schedule. B1 owns and authorizes it, as with `ci.yml`; B3 writes it, with the `govulncheck` version pinned and B6's review per D3-10. `ci.yml` stays at ten jobs. B1 amends the merge rule to "every job in `ci.yml` and `govulncheck.yml`" in a D4 decision, and updates `CLAUDE.md` and the summary in the same PR.

Questions 1 (the rest of it) to 5 wait on A3.
