# B3 handoff: Security and Engineering Access Engineer

From A3 to B3, written 2026-10-27 at `main` `d4afc63`. It is a map: details live in the linked docs, which stay authoritative where this file and they differ. The project brief is `CLAUDE.md`, §4 "A3".

## Role & scope

**You own:**
- `contracts/authz/` (C7, the collector IPC and admin-signed requests). Changes need A1's (now B1's) approval.
- `contracts/audit/` (C8, audit records and `VerifyCollectorSeq`).
- `modules/security/`:
  - `collector/`: the collector's pipeline, durable state, credential store and admin verifier;
  - `collectorwire/`: the named pipe and peer identity;
  - `collectorclient/`;
  - `nodekey/`: the node key register and the non-exportable CNG key store;
  - `seal/`.
- `modules/access/`. Only `experiments/e1-ssh-forward-controls` exists, from Phase 0.
- `cmd/otsec-collector/`: the collector binary and service.
- `docs/threat-model.md`, `docs/phase1/A3-credential-design.md`, `docs/phase2/A3-*.md`, `docs/phase3/A3-*.md`, and from Phase 4 `docs/phase4/A3-*.md`.

**You review:**
- everyone's security-sensitive changes;
- A2's register additions;
- A5's trust boundaries (node, relay, key wiring);
- every toolchain and dependency bump, with A6 (D3-10).

**You don't touch:**
- `platform/`, `deploy/`, `ui/` (A5's, B5's from now);
- `modules/ied/` (A2);
- `modules/telemetry/` and `modules/detection/` (A4);
- `tests/integration/`, `tests/security/` and `tests/safety/` (A6). You may read A6's tests and review them, but A6 changes them.
- Another agent's branch, or the branch of a merged PR.

## Current state

- **Phase 3:** exit gate passed with conditions (`docs/phase-3-exit.md`, #209). **Owner sign-off has not been given yet.** The Phase 4 briefs are drafts and are issued only when the owner accepts Phase 3 (`docs/agent-handoffs.md`, "Phase 4 task briefs").
- **A3 PRs:** none open, and none in progress. Everything is merged. The last ones were #201 (CNG pointer fix), #205 (held `state.json` test) and #210 (handoff update). No uncommitted or half-applied work exists. The old local branches under `claude/project-thread-qj1j9d-*` are all merged; ignore them.
- **What A3 built, with evidence:** see `docs/phase3/A3-handoff.md` (both sections, 2026-10-26 and the 2026-10-27 update), plus `docs/phase2/A3-collector.md` and `docs/phase1/A3-credential-design.md`.
- **Open PRs by others that need A3/B3 review when they move:**
  - #176 (A5): the node resolves TLS references from `nodekey`. This closes D2-12; check the Windows `CNG{Users}` SID and that the lab file path stays behind the lab flag.
  - #181 (A5): the signed admin files design. Relay PR 2 widens the relay to the `clear-*` kinds, and in Phase 4 to `node.change_approval` and `node.baseline_ack`.
  - #182 (A5): the refused-identity detail.
  - #177 (A5): crash-child bounds.
- **Blocked:** nothing on A3's side. Phase 4 work waits for the owner's Phase 3 acceptance.

## Next steps

1. **First action:** read `docs/phase-3-exit.md` ("Open risks", "Limitations recorded in Phase 3") and the "Phase 4 task briefs" section of `docs/agent-handoffs.md` (P4-A3 and "carry-over"). Then confirm with B1 whether the owner has accepted Phase 3. Until then, do reviews only.
2. **When Phase 4 is issued, draft C7 0.6 and C8 0.5 together (P4-A3).** A1 approves them alongside A2's C9 and A4's C10.
   - C7 0.6 adds two admin-signed node kinds: `node.change_approval` and `node.baseline_ack`. Both follow the C7 0.5 node-kind pattern in `contracts/authz/` (see `node.quarantine_clear` and `node.seq_reset_ack`): the collector verifies, spends the nonce and numbers the decision, but changes nothing of its own. The node acts only after acceptance.
   - C8 0.5 adds `config.change_approved`, `config.change_detected` and `config.baseline_acknowledged`.
   - Every contract change bumps the minor, adds a reader for the previous minor, and carries a rollback note in the PR. Use `contracts/authz` and `contracts/audit` at 0.5 and 0.4 as the model.
   - Points A3 already committed to on #209, which go into the draft:
     - **"Prior" is decided by `collector_seq`.** The collector accepts the approval and numbers it. A difference counts as approved only if the approval's number is below the number of the `config.read` decision that found it. Never use a time written in the approval.
     - **The approval binds the baseline hash** it approves a change against. Optionally it also names the settings classes expected to change.
     - **Window cap:** propose 24 hours, refused above, with a shorter default.
     - **Approver role (B3's ack, question 1):** C7 has no role today; `AdminKey` has no allowed kinds. Add a per-key allowed-kinds list to the pinned keys in C7 0.6, with an enrolment step in `docs/phase3/A3-admin-keys.md`.
       - A key pinned without the list keeps exactly the 0.5 kinds and never gets the new ones, so it fails closed.
       - The refusal stays `admin_unverified`, with a new `Check` value. Run it after the signature and binding checks and before the replay check, so the nonce is not spent. The decision is still numbered, so V-M2's "refused and recorded" holds.
       - "The approver is not the person who made the change" is out of scope: nothing observes who changed a relay until engineering access (R2) exists. Record it as a limitation.
     - **Nonce and expiry come from the C7 0.4 envelope**, not repeated in the payloads.
     - **The node refuses an accepted `node.baseline_ack` whose hash it does not hold** for that asset and kind, and audits the refusal. The hash is over the stored canonical bytes, so A6 can recompute it.
     - **An approved change never moves the baseline by itself.** The new snapshot needs its own `node.baseline_ack`.
   - A6 tests to V-M2 (`docs/verification.md`).
3. **Hygiene item: harden the state-file replace.** It is a condition before the first site deployment (`docs/agent-handoffs.md`, carry-over "A3"; `docs/phase3/A3-handoff.md`, "Phase 4 item").
   - In `modules/security/collector/state.go`, `replaceFile` and `renameDurable` (`fsync_windows.go`), which the credential store shares, replace with `SetFileInformationByHandle(FileRenameInfoEx)` and `FILE_RENAME_FLAG_POSIX_SEMANTICS | REPLACE_IF_EXISTS`.
   - Fall back to `MoveFileEx` when the call itself says the class is unsupported (`ERROR_INVALID_PARAMETER`, `ERROR_NOT_SUPPORTED`, `ERROR_INVALID_FUNCTION`), and log that once per process. Don't use a Windows version check: ADR-0007's site OS is above both candidate floors, and the real cases are the file system (FAT, exFAT, SMB) and filter drivers. Never fall back on a sharing or access error.
   - Retry for at most about 500 ms on `ERROR_SHARING_VIOLATION` and `ERROR_ACCESS_DENIED`, logging each episode, then keep today's fail-closed break.
     - The retry holds `State.mu`, which can be inside a Level 1 session. That's acceptable: the SEL-751 adapter calls `FloorGate.Confirmed` between a reply and its next send, and `run.go` arms the step deadline at each send, so no read timer is running.
     - The cost is up to 500 ms of the run's wall-clock deadline, plus a 500 ms stall for other assets' `NextSeq`. TIDLE is at least a minute.
     - Add a test that a retry at `OpenLevel` still leaves the run inside its deadline.
   - Wrap the OS error with `%w` in `State.write` and in `credstore.go`.
   - Durability: after `FileRenameInfoEx`, call `FlushFileBuffers` on the renamed file's handle and, where NTFS allows it, on the directory handle (`FILE_FLAG_BACKUP_SEMANTICS`). Kill the process at each step to show atomicity (old or new bytes, never a mix). Label the evidence "process kill on the hosted runner; power-loss durability not shown". Power loss needs a VM power cut or hardware, and stays `documented-untested`.
   - Move `publishInstallKey` (`cmd/otsec-collector/provision.go`) onto the same helper. Its own `os.Rename` loop (20 tries, 50 ms apart, A6 on #106) is the same `MoveFileEx` replace, with the same race. Keep its failure behaviour: a start that cannot publish the key stops.
   - Write the floor from the session's end when `OpenLevel`'s write fails and the session ends without `QUI`.
   - `state_windows_test.go` (#205) must stay green.
4. **Hygiene item: a pinned `govulncheck` job in `ci.yml`** on every PR and weekly. B1 authorizes the `ci.yml` change.
5. **Review the Go 1.27.3 move** (owner's request; A1 with A3 and A6) under D3-10: its own PR, full CI, the Windows UDP stress test repeated, never auto-merged.
6. **Update `docs/threat-model.md` HR-11.** Its text still says unknown senders gain "one hour's budget per node restart", but #196 and #198 fixed that. The residual now is a forward wall-clock step plus a restart (see `phase-3-exit.md`, "Open risks").
7. **Later Phase 4 items:**
   - the signed offline advisory-set format (item 3, R9);
   - secure engineering access (item 5, R2), from the Phase 0 Q1 comparison in `docs/architecture.md` and `modules/access/experiments/`.

## Key files

Read these first, in this order:
1. `CLAUDE.md`: the brief, roles, principles and repository commands.
2. `docs/phase-3-exit.md`: the true current state, risks and limitations.
3. `docs/phase3/A3-handoff.md`: what A3 built in Phase 3, the evidence, and the Phase 4 item.
4. `docs/agent-handoffs.md`, "Phase 4 task briefs": P4-A3 and the carry-over items.
5. `docs/phase1/A3-credential-design.md`: the credential and key design. §9 is the node key store, and §10 is the residual risks.
6. `docs/threat-model.md`: SC-1 to SC-18 and HR-1 to HR-12.
7. `docs/phase3/A1-decisions.md` and `docs/phase2/A1-decisions.md`: D2-x and D3-x rulings.
8. `docs/phase3/A3-admin-keys.md`: the admin key procedure.
9. `modules/security/collector/state.go`: durable state, the floor (`CheckFloor`, `BeginAuth`, `OpenLevel`, `EndAuth`, `FloorGate`), `NextSeq`, `write` and `replaceFile`.
10. `modules/security/collector/pipeline.go`: `Handle`, `verifyAdmin` and the admin decisions, `asRefusal`, and the post-run floor handling.
11. `contracts/authz/`: C7. Read `ipc.go` for refusal codes, and the admin-signed request and verifier files.
12. `contracts/audit/`: C8 and `VerifyCollectorSeq`.
13. `modules/security/nodekey/cng_windows.go`: the CNG wrapper. Read it before touching any Windows syscall.
14. `docs/verification.md`: A6's criteria (V-M2 for P4-A3) and the Phase 3 status table.

## Decisions made

They're recorded in the linked docs. Don't reopen them without new evidence.
- **D2-11:** credential requests are admin-signed (C7 0.4). No vendor default or real-device password is ever installed. Test credentials only.
- **D2-13:** CI is the main test path. No CNG machine keys or test accounts are created on the owner's PC, so Windows CNG tests run only on the hosted runner.
- **D2-15:** the `config\admin` folder rule. Clear files stay unsigned until relay PR 2.
- **D2-16 and D2-20:** the failed-auth floor runs from ACC and is held until `QUI`. A port-server path is refused.
- **HR-11** (`docs/threat-model.md`): the bound on unknown-sender storage. The absolute bound is still open. Cite it as HR-11, not D3-3: in `docs/phase3/A1-decisions.md`, D3-3 is `quarantine.cleared` (see the numbering note in #217).
- **D3-5:** plaintext Syslog receive is allowed per listener (HR-12).
- **D3-7:** a node key is non-exportable; SYSTEM, Administrators and the node service may use it.
- **D3-9:** the collector grants its node two query rights (#180), and Dial still checks the server token.
- **D3-10:** the latest patch of a supported Go minor. `govulncheck` in CI. Bumps are reviewed by A3 and A6, never auto-merged.
- **A collector state write failure is a sticky break.** It refuses everything with `collector_state_unavailable` until a restart, deliberately: memory and disk may disagree after a failed write. Keep that as the fallback behind any retry.
- **The admin verifier answers every unsigned or mis-bound request with one refusal code,** so there's no oracle. The nonce is spent durably before anything else is decided. Judgement uses the later of the clock and the high-water mark (`admin_clock_utc`).

## Open questions / risks

- **Windows state-file replace:** an availability risk. Any reader of `state.json` or the credential store can stop collection until a restart. See step 3.
- **HR-11:** there's no absolute bound on unknown-sender storage. It gates the first device-observed listener (A4 and A5 build it, A3 reviews).
- **HR-12:** a spoofed known address on a plaintext listener.
- **D2-12** until #176: the node's TLS key is still a lab file.
- **A local administrator can use the node's TLS client key** (D3-7, design §10).
- **The TPM provider is untested** (T-2). There's no certificate renewal, and the `register.json` admin tool isn't built.
- **No end-to-end Windows check of the admin relay or of `admin_dir`'s ACLs** (A6 owes it).
- **A3's objection to the SEL-751 FTP rung** (D7 cleartext credentials, D8 write path) stands until hardware test Q3. Q3 needs the owner's authorization and an out-of-service lab relay.
- **No hardware anywhere.** Everything is `simulated` or from the hosted runner.

## Dependencies

- **B1 (lead):** approves C7 and C8 changes, merges every PR, authorizes `ci.yml` changes, and issues the Phase 4 briefs.
- **B2 (IED):** C9 and the `config.read` operation that P4-A3's ordering depends on. B3 reviews B2's register additions.
- **B4 (telemetry):** C10, whose baseline hash `node.baseline_ack` names, and HR-11's bound.
- **B5 (platform):** the node side of approvals and baseline acknowledgements, relay PR 2 of #181, and #176. B3 reviews their trust boundaries.
- **B6 (verification):** independent tests (V-M2) and the AST rule `tests/security/uintptr_args_test.go`. B3's changes need B6's PASS before merge.

## Gotchas

- **The repository is public.** No secrets, real device data, internal hostnames or real credentials in commits, PRs or comments. Never commit the SEL manuals. No secret may appear in any transcript, log, event, audit record or crash dump.
- **Windows syscalls.**
  - Any wrapper taking `...uintptr` needs `//go:uintptrescapes`, with `uintptr(unsafe.Pointer(x))` written inside the call expression. A hoisted `uintptr` is not kept alive.
  - `TestCNGPointersEscape` (`nodekey`) checks the escape report deterministically. A stack-growth stress test did NOT reproduce the bug on the Windows runner, so don't rely on one.
  - A6's AST rule fails any violation.
- **Test the Windows build locally without Windows:** `GOOS=windows go vet ./...` and `GOOS=windows go test -c -o /dev/null ./<pkg>`. Windows-only tests run only in CI's `go (windows-latest)` job, plus the named CNG steps in `ci.yml`.
- **Forcing a state-write failure in tests:** `os.Mkdir(path+".tmp", 0o700)` (see `TestFailedWriteBreaksState`). On Windows, holding the file with `os.Open` makes the rename itself fail (`state_windows_test.go`).
- **Timing assumptions fail on loaded runners** (#197, #202, #207). Wait for the property (the request, progress, `ctx.Deadline()`), not a fixed sleep.
- **Merging and pushing.**
  - Force-push is denied, so use new commits or merge `main` in; never rebase a pushed branch.
  - Branches are `claude/project-thread-<id>-<topic>`.
  - B1 squash-merges each PR through GitHub, so it shows as merged, and `main` gets one commit with a `(#N)` suffix.
  - When a PR's CI predates newer `main`, merge `main` in and let the Windows job run again before asking for the merge.
- **Reviews:** COMMENT reviews only, never APPROVE, at the full 40-character head SHA, ending with the Claude Code attribution footer. Prove a finding with a mutant where you can. Every review A3 did is recorded on its PR.
- **Evidence:** never claim hardware or production compatibility. Label `simulated` or "hosted runner". If a check passed on a different tree from the one under review, say so.
- **Messages to other threads** are capped at 2000 characters. Long findings go on the PR.
