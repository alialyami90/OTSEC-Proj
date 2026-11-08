# Phase 4 decisions (B1)

Decisions B1 made during Phase 4, numbered D4-n. Phase 3's are in `docs/phase3/A1-decisions.md`, which ends with D3-13. The Phase 4 briefs are in `docs/agent-handoffs.md`, "Phase 4 task briefs". Where a decision here differs from a brief, the decision wins.

## D4-1: the owner accepts Phase 3, and Phase 4 is issued (owner)

Date: 2026-10-27.

**What happened.**
- After the A-to-B handoff, B1 asked the owner once what they wanted checked or changed before accepting Phase 3.
- At 18:26Z the owner answered: "Start phase 4 and all work."
- B1 reads that as acceptance of the Phase 3 exit with the conditions it states, and with no further check requested.

**Recorded:**
- `docs/phase-3-exit.md` is marked owner-accepted.
- The Phase 4 briefs are issued: ADR-0008's items 1 and 2, the carry-over and hygiene list, and the order and first exit gate.
- Items 3 to 6 stay outlines. Each gets a full brief only after the item before it passes its gate.

**The Phase 3 conditions carry into Phase 4:**
- gate item 1's owed checks, released to B6 (D4-6);
- #176, #177, #181 and #182, plus relay PR 2 (B5);
- the collector's state replace (B3, D4-3);
- HR-11's absolute bound (B4 with B5).

**What does not change.**
- Every endpoint stays on the simulator, on loopback.
- H-01 to H-15 and Q3 are not run.
- No result is `hardware-verified`.

## D4-2: change approvals take their signer and nonce from the C7 envelope, and an approver is a per-key allowed kind (P4-A3)

Date: 2026-10-27. Sources: B3's ack (#221, #228), A3's answers on #221, and A1's concurrence on #221.

**The rulings:**
1. **The `node.change_approval` payload** carries:
   - the asset;
   - the hash of the baseline it approves a change against;
   - the window's start and end;
   - the reason.

   The nonce, the expiry and the approver come from the C7 0.4 signed envelope, which is already signed and replay-checked. They are not repeated in the payload. The P4-A3 brief is corrected to match.
2. **C7 0.6 adds an allowed-kinds list to each pinned admin key.**
   - A key pinned without the list keeps exactly the C7 0.5 kinds. It never gets `node.change_approval` or `node.baseline_ack`, so existing installs fail closed.
   - B3 documents the enrolment step in its admin-key design note.
3. **Refusing a key that may not sign a kind.**
   - The refusal stays `admin_unverified`, with a new `Check` value.
   - The check runs after `signature` and `binding` and before `replay`, so a refused approval does not spend its nonce.
   - The decision still takes a `collector_seq`, and the node writes the denied record. That is V-M2's "refused and recorded".
4. **"The approver is not the person who made the change" is out of scope for Phase 4.** Nothing observes who changed a relay until engineering access (R2) exists. C7 0.6 records it as a limitation that R2 can close.

## D4-3: carry-over hygiene starts now, and `govulncheck` gets its own workflow

Date: 2026-10-27.

1. **The collector's state replace (B3).** The POSIX-semantics rename in `replaceFile` falls back to `MoveFileEx` only when the call fails as unsupported (`ERROR_INVALID_PARAMETER`, `ERROR_NOT_SUPPORTED`, `ERROR_INVALID_FUNCTION`), never by Windows version. The fallback is logged once per process. A sharing or access error is never a reason to fall back: it goes to the bounded retry (about 500 ms) and then the fail-closed break.
   - `publishInstallKey` moves onto the same helper and keeps its rule: no published key, no start.
   - Evidence for the crash test is labelled "process kill on the hosted runner; power-loss durability not shown".
   - B1 had held this merge until the owner said what they wanted checked before accepting Phase 3. The owner asked for nothing further (D4-1), so the hold is lifted. The PR merges under D2-13 with B6's and B5's reviews.
2. **`govulncheck`.** It goes in its own workflow, `.github/workflows/govulncheck.yml`.
   - Triggers: `pull_request` with D3-13's Markdown filter, and a weekly schedule.
   - B3 writes it, with `govulncheck` pinned. B6 reviews it (D3-10).
   - B1 owns and authorizes it, as with `ci.yml`.
   - `ci.yml` stays at ten jobs.
   - When the workflow merges, D2-13's merge rule becomes "every job in `ci.yml` and `govulncheck.yml` is green on the head". B1 updates `CLAUDE.md`, `README.md` and `handoffs/HANDOFF-SUMMARY.md` in the same PR, so the documents never state a rule CI does not run.

## D4-4: rulings for the C10 draft (P4-A4)

Date: 2026-10-27. Sources: B4's ack (#229), A4's answers on #229, and B6's ack (#222).

1. **Clock.** C10 follows the clock rule in `docs/verification.md`, "R4.8 observation period and measures": received time by default, and device time for the time-of-day rule only when the offset is known. The alarm names the clock it used. The brief's wording stays, because it defers to that text.
2. **SER catch-up.** Rows of the first successful read after a recorded V-S12 failure, and rows aligned `gap-before`, count toward the type set but not toward rate and hour learning. Rate and time rules skip them; the new-type and repeats rules still apply. Every row of one read shares one `received.utc`, so the SER rate bucket is at least the collection interval, or the rate rule counts per read.
3. **`possible-duplicate`.** A row flagged `possible-duplicate` is checked against the previous read only, matched one to one: k identical rows in the previous read suppress at most k rows. Rows are never compared within the current read. B6 tests whatever C10 states.
4. **The Syslog event-type key.**
   - Facility and severity come from `pri`. A message whose PRI cannot be parsed gets the fixed key `pri-absent`.
   - The template is `msg` with every digit run replaced.
   - `app_name` and the tag are not part of the key.
   - The digit rule merges RTAC tags that differ only by a number. C10 states this as a limit. A dialect rule may follow in a later C10 minor if B6's tests or a real capture show that the merge hides a distinction that matters.
5. **The baseline hash** that `node.baseline_ack` names is SHA-256 over the stored record's exact bytes, with no canonical JSON. This follows C7's exact-bytes precedent. B3 reviews it beside C7 0.6.

## D4-5: the Windows Go timeouts are tracked, not waved through (#230)

Date: 2026-10-27.

**What failed.** At least three Windows `go` jobs on docs-only heads hit `go test`'s 600 s package timeout in `platform/node`:
- 122345921404;
- 122347974504;
- 122364514991.

B5's ack also names job 122364490231.

**B6's reading.** B6's analysis is in the project files, `b6/windows-go-timeouts-2026-10-27.md`. It reads these as slow disks across every disk-bound package, not one hung flush.
- `platform/node` normally uses 53 to 76 percent of the 600 s budget.
- This reading is an inference, and `platform/store`'s 9-minute case is unclassified.

**Rulings.**
- None of these is a flake.
- No `ci.yml` change (`-timeout`, `-p`, a split, or the job's 15-minute limit) until B5 reports per-test Windows times for `platform/node` and `platform/store` and proposes a fix.
- B6 runs an ETW-timed `FlushFileBuffers` check in an `a6-*` workflow.
- Fixed wall-clock bounds become waits on progress:
  - `TestListenerUsesSizedBudget` and `flood` (B5);
  - the syslogreceive rig (B6, #232). The rig keeps its 15 s close bound because, after Grace, there is no further progress to wait on, but on a late return it now reports when `Serve` actually returned.

## D4-6: the Phase 3 carried checks are released to B6

Date: 2026-10-27.

**The checks**, which run on the GitHub-hosted runner, not the owner's PC:
- the canary scan of process command lines;
- the DMY and YMD slice reconcile on the real binaries;
- the unknown-restart leg on Windows;
- the admin relay with `config\admin`'s ACLs on Windows.

**`a6-windows-slice.yml`.** B6 may add it under B6's own `a6-*.yml` ownership, on two conditions:
- its `pull_request` trigger is limited to the slice and harness paths;
- B1 is told when it lands.

A run that installs services stays on the hosted runner. B5 reviews it, because it drives B5's service-mode harness.

## D4-7: order of the open A5 PRs and Go 1.27.3

Date: 2026-10-27.

**The open PRs.**
- B5 brings #176 and #182 up to current `main` now, by merging and never by rebasing. They do not wait for the toolchain PR.
- Whichever lands first, the other merges `main` again.
- #176, #177 and #182 each need all ten CI jobs green on their own head before merge, and #182 needs B6's fresh measurement of the record bound on a worst-case record. Per B5's ack, that record adds:
  - a TLS leaf;
  - `asset_id` and its binding;
  - an IPv6 sender.

**Go 1.27.3** is one PR under D3-10.
- B1 writes it, because it owns `go.mod`.
- B3 and B6 review it.
- B6 repeats the Windows UDP stress test on 1.27.
- B5 compares `platform/node` and `platform/store` times against the 1.26.10 baseline.
- It is never auto-merged.

## D4-8: items carried, not open

Date: 2026-10-27.

- **H-13.** B6 widens H-13, or adds a separate hardware item, to cover `SHO G`, each register revision 5 form and absent-option replies, and port-server `T_OUT` (B2's ack, #226 and #231). It stays prepared only and is not run.
- **Snapshot bytes.** A C9 snapshot holds each settings section's transcript span and SHA-256, with no second copy of the bytes. B2 and B5 agree how long transcripts are retained before C5 0.4 is drafted.
- **SEL-751 rung.** The SEL-751 stays on rung 3 (`SHO` over Telnet), as the brief's ADR-0008 decision 4 states. Q3 needs the owner's authorization and an out-of-service lab relay.

## D4-9: rulings for the first Phase 4 contract batch (C5 0.4, C9 0.1, C7 0.6, C8 0.5, C10 0.1)

Date: 2026-10-27. Sources: the review threads on #246, #247, #250 and #254; B6's contract tests (#249, #253, #256); B6's GT-INJ series (#251).

**C5 0.4 (#246, B5).**
1. `GroupOptions.MaxCommitBytes` caps one commit, at 1 MiB for event databases. A single record larger than the cap commits alone.
2. The recovery reserve is per database, not per volume: `2 × WALBoundBytes + 1.1 × C + 64 KiB`, where C is the database's commit cap. This replaces P4-A5's "a per-snapshot byte cap well below the 1 MiB recovery reserve".
3. B4's receive path splits a stream or datagram batch at the cap. The parts commit in order, and a connection is held until every part has committed. A crash between parts leaves the earlier parts stored. C6 is unchanged, and the receivers acknowledge nobody. When RELP receive is built, it acknowledges only after commit.
4. One SER read commits atomically (capture, events and outcome together), so the adapter-evidence database's cap is the derived bound of one read, not a measured size. The bound follows from C2's 1 MiB `MaxResponseBytes`, the row ceiling the code enforces (`MaxReadRowsCeiling`, 2048) and the largest legal C4 event. A store test computes it and fails if a change to C2, C4 or the register raises it above the cap. The reserve follows from the formula, a few MiB more than the cap for that database. A row-length cap in the SER grammar was rejected, because it would turn a long legitimate row into a failed read. A commit over a cap is refused whole: nothing is stored, the read fails with an alarm, and the whole outcome frame goes to quarantine as received. That frame is up to C2's 8 MiB `MaxOutcomeBytes` plus a reason of at most 16 KiB, so the quarantine room fits under the cap, and #278 pins this (B5 on #277). The bound holds only for rows the SEL-751 adapter marks parsed (`serRowRE`: elements in `[A-Za-z0-9_]`). It is the adapter's guarantee, not C2's, because C2 does not check field characters. A parsed row with JSON-escapable characters can exceed it, and that read fails closed as above. A new adapter or a change to the row grammar must recompute the bound.

   B5's figures (`desk`), with a 512 KiB `WALBoundBytes`. **They are withdrawn by item 6 until the commit rule holds for a SER read.**

   | Database | Commit cap | Recovery reserve |
   | --- | --- | --- |
   | evidence | 11 MiB (the SER bound, 10.4 MiB, rounded up) | 13,801,881 bytes |
   | configuration (D4-13) | 1.5 MiB | 2,844,262 bytes |
   | syslog and audit | 1 MiB | 2,267,545 bytes |
5. B6 owes two tests, with these pass conditions (B6 on #277). Until the storekill leg passes, the reserve formula is `desk`.
   - **Small-cap test.** On the real store, one commit at each cap from `MinRecordBytes` up to the largest cap any database uses (the evidence database's 11 MiB) writes no more WAL than `CommitWALBytes(payload)`. A second connection pins the WAL while it is measured, so no checkpoint can hide frames.
   - **Storekill leg at a full reserve.** Set up a database at quota whose WAL holds un-checkpointed frames up to `WALBoundBytes`, plus one commit at its cap. Kill it at each commit point, then restart it on a volume whose free space is exactly what `RecoveryReserveFor` gives. It passes when it reaches collecting mode with every committed record intact, and it must fail when the reserve is one commit's WAL smaller. The leg needs a size-limited filesystem, so it runs in an `a6-*.yml` workflow on a hosted runner, with no secrets and `contents: read`. It is not a D2-13 required job, but the formula moves to `simulated` only on a green run of it.
6. **B6's finding (#280): the commit rule does not hold for a SER read.** `CommitWALBytes(p) = p + p/10 + 64 KiB` holds for one large record, up to 11 MiB (#275). It does not hold for a batch of many events. `events` is a `WITHOUT ROWID` table, so every event over about 1 KB spills to an overflow page of its own. One read of 2048 events at the 11 MiB cap wrote 19.3 MB of WAL against the rule's 12.7 MB. Once checkpointed, the file grew 4.29 × the bytes the quota counts. Until this is fixed:
   - the reserve figures in item 4 are withdrawn, and #278 does not merge;
   - no volume may be sized from quota sums.

   **Ruling.** B5 chooses the fix from #280's three options, or a combination, and B6 reviews it. The fix is accepted when all of the following hold:
   - #280 passes, unchanged, at all six shapes, and also on a sweep of event sizes from 100 B to 64 KiB that includes each overflow step.
   - The ratio of file growth to the bytes a quota counts is stated and bounded, and a test pins it, so that a quota still means a bound on disk.
   - A database written by the current code opens with every record intact, or is refused with a clear error, and B6's cross-version check covers this.
   - If the rule changes (a per-row term, or a new signature for `CommitWALBytes` or `RecoveryReserveFor`), that is a C5 change and comes to B1 as a contract PR.

   B1's preference is to fix the layout first: a rowid `events` table, or a page size that keeps a legal event local. A per-row term alone would make the reserve honest but leave the quota counting a quarter of the disk.

**C9 0.1 (#247, B2).**
1. The configuration record cap is a provisional 1 MiB, replaced by register revision 5's counted caps when they exist.
2. Three fail-open paths found in review are closed, and none is recorded as a limitation:
   - each section is bound to the command that read it;
   - a section's span must be the whole reply, from STX through ETX and the prompt;
   - a `:=` line is never a header, and a header after a setting line fails the read.
3. Read 2's repeated header is marked ASSUMED. H-13 adds "does `SHO` repeat its header".
4. `difference_digest` is an identity. Late approval is keyed on the asset and the baseline, not on the difference digest. There is no settings-only digest in 0.1.

**C10 0.1 (#254, B4).** These amend D4-4 where they differ.
1. The Syslog event-type key is facility, severity and the digit-replaced template, with `pri-absent` for an unparsable PRI. MSGID, `app_name` and the tag are not part of the key. This drops MSGID from `docs/verification.md`'s earlier key. It is a new ruling, made for security: a sender chooses its MSGID, so a compromised sender could hide a new kind of message under a known MSGID (#254, `contracts/baseline/key.go`). Two messages that share a MSGID stay two types.
2. There is one rate bound per type: a factor times the most events in any one clock-hour bucket of the observation period.
3. A refused approval approves nothing, so the change it named alarms.
4. The parameters stay proposed in GT-INJ until C10 fixes them. B6 regenerates the schedules before any product test runs against them. The regeneration adds three cases: a Syslog message with an unparsable PRI (`pri-absent`), a SER row with no bytes keyed by its record hash, and the rows of the first read after a recorded V-S12 failure.
5. Every stored SER row is keyed: a row that was read, by its template; a row with no bytes, by its record hash.
6. The detector's clock can be injected.
7. **Catch-up rows (amends D4-4 item 2).** Every type-only row C10 defines (first-read rows, rows of the first read after a recorded V-S12 failure, and rows aligned `gap-before`) counts toward the type set and the new-type rule only. MaxPerWindow learning and the repeats, rate and time rules skip it. The repeats rule uses received time. **Limit:** repeats that happen while the node cannot read the device are not detected by the repeats rule. The outage itself stays observable (V-S12, `gap-before`), and a new type inside the catch-up still alarms. A device-time repeats rule may come in a later C10 minor, once a device's offset is known.

**C7 0.6 and C8 0.5 (#250, B3).**
1. `AdminChecks` runs binding, then authority, then window, then replay. A refused approval does not spend its nonce (D4-2).
2. HR-14: for a baseline acknowledgement or a change approval, an admin client computes the digest itself, over the record's stored bytes that it decodes for display and never over a C5 frame, and never takes the digest from the node (C7 0.6 `doc.go`).

**Brief amendments.**
- P4-A2's acceptance reads "the same configuration read twice, with a different time and any documented non-semantic difference, gives an empty difference".
- P4-A5's per-snapshot cap is item 1 of C9 and item 2 of C5 above.

## D4-10: Windows CI time and the `govulncheck` red-run policy (#230, #258)

Date: 2026-10-27. This follows D4-5, now that B5 has posted per-test times (#230, 19:13Z).

1. **Store fixture (#252).** `TestDiscardStepWALBound`'s fixture is built in 16 commits with autocheckpoint off. The measured WAL step is unchanged (370832 bytes). On Windows, `platform/store` took 61 s on #252's job, against 328 to 511 s before.
2. **Package timeout.** The Windows `go test ./...` step runs with `-timeout 12m`. The `go` job's limit is 30 minutes on Windows and stays 15 on Linux. `-timeout` starts per test binary, so the job limit has to come late enough that a slow package's goroutine dump is kept (B6 on #252). A green run takes exactly as long as before.
3. **Node fixtures (#264)** are required, not optional. There is no package split, `-p` change or further limit change without a new decision.
4. **`govulncheck.yml`** is a required check. A red run caused by a newly published advisory is handled as follows:
   - B3 triages it the same day, with an issue.
   - B1 writes the `go.mod` or toolchain bump, and B3 and B6 review it.
   - Nothing is suppressed.
   - When no fixed version exists, accepting the risk is a security-policy decision for the owner.

   GitHub notifies only the last committer about a red scheduled run, so whoever opens a code PR after a Monday checks that week's scheduled run on `main`.

## D4-11: an expired TLS certificate stops only its own link (HR-13, #265)

Date: 2026-10-27. Source: B5's brief on #265.

1. A certificate that is otherwise good, but outside its validity period, stops only its own listener or forwarding target, with an alarm. The node and its other links keep running.
2. Every other TLS file fault still stops the node at start, and nothing falls back to another credential, plain TLS or the system roots.
3. Targets get the same 30-day expiry warning as listeners.
4. At each 10 s check, the node re-checks the period of every link it held back, using the certificate it already loaded, and starts the link once the period is valid. A running link is never stopped at expiry.
5. An expired trust anchor is never trusted. The link it would verify stays held back or refuses the peer, and it never accepts a peer unverified. B5 states this and pins it with a test.
6. Alarm names and status fields stay out of C6 and C8 enumerations. Any change to those enumerations comes to B1 first.
7. A test shows a required target held back past its quota, with every alarm in order and no silent prune.
8. B4 provides the `ErrCertificatePeriod` sentinel in `receive` and `forward`. B3, B6 and B4 review.
9. When a running link's certificate passes its end, the node raises an alarm that names the link, and it keeps raising it while the link runs (B3 on #277).
10. A test shows that a held-back link opens no socket and sends no byte until its period is valid. This covers item 2's rule that a held-back link falls back to nothing.
11. The node judges a period by the same clock it uses at start. A clock that is set back can start a held link, just as it can at start. B3 records this in HR-13 when the node side lands.

## D4-12: the owner's PC runs are paused (owner, 2026-10-27)

Date: 2026-10-27. Source: the owner's answer on the B1 thread, choosing "Pause PC runs for now" over two other options, swapping the portable Go for 1.27.3 and `GOTOOLCHAIN=auto`.

1. Nothing runs on the owner's PC, neither the second Windows run nor the fallback. Its portable Go is 1.26.x, so it can no longer build `main`, which needs 1.27.3 (D4-7).
2. GitHub Actions is the only test path. D2-13 as amended by D4-3 is unchanged, and the `go (windows-latest)` job is the Windows evidence.
3. If GitHub Actions is unavailable, PRs wait. Nothing moves to the PC and nothing merges on local runs alone.
4. Only the owner resumes PC runs, and they plan to on 2026-10-28, while they are present. They choose how the PC gets Go 1.27.3, and B1 asks before using it again. The PC is never a self-hosted runner.

## D4-13: register revision 5, C3 0.3 and the configuration record cap (#276)

Date: 2026-10-27. Source: B2's design note, `docs/phase4/B2-register-rev5.md` (#276), and B1's rulings on #276.

1. **C3 0.3** adds an optional `operations[].limits` (`max_reply_bytes`, `timeout_ms`) and `runs[]`, an ordered, named list of read-only, literal, Level 1 steps sent in one session.
   - A run fails as a whole: on a failed step the adapter sends `QUI`, keeps every byte read, and reports the read failed. No partial snapshot is presented as complete.
   - `max_total_bytes` is at most C2's 1 MiB session ceiling, and `deadline_ms` at most its 600 s. A step's `max_reply_bytes` is at most its run's total. A package that breaks any of these fails validation.
   - `Matcher.Permit` still checks each line, and `CheckLines` requires exactly the run's lines.
   - A state-changing or Level 2 step in a run is invalid in 0.3.
   - One authentication per session (B3 on #277). If a step meets an unexpected prompt, or the session drops to Level 0, the run stops: it sends `QUI`, keeps what it read, fails as a whole, and never sends `ACC` a second time. A test drops the relay to Level 0 mid-run.
   - A failed run sets the failed-auth floor and the suspension exactly as a failed single operation does, with the same codes. A confirmed login with no `QUI` sets the floor from the session's end.
   - `runs[]` are covered by the register's signature, and a run is read only from a verified register. One invalid step fails validation of the whole package.
   - The adapter does not assume that Level 1 outlasts `deadline_ms`. The relay's own timeouts can end the session first, and the first rule above covers that case.
2. **Caps.** The read's total cap T is 512 KiB. The configuration record cap is 1.5 MiB, which replaces C9's provisional 1 MiB (D4-9, C9 item 1).
   - The cap is a derived bound (`2 × T + 363,442` bytes), and a test enforces it, as for the SER cap. B2 owns that test, which ships in the register revision 5 PR, because it reads the run's `max_total_bytes` and C9's constants.
   - The configuration database's commit cap is 1.5 MiB, and its reserve follows the C5 0.4 formula. The 64- and 384-byte value assumptions are `documented-untested`.
3. **Touchscreen HMI settings** (`SET_HMI.zds`, `CDP.zds`) are files, and P4-A2 excludes file transfer. They are not baselined, and this is recorded as an exception in the capabilities and in C9's limitations. The owner settled this on 2026-10-28: touchscreen settings are not required. A touchscreen model is in scope, but its touchscreen settings are not, so they are not read or baselined, and no document may claim that a snapshot covers them.

## D4-14: the store's commit rule gets a per-record term, and `events` becomes a rowid table (C5 0.5, #280)

Date: 2026-10-27. Sources: B6's finding (#280) and B5's measured proposal on B6's harness. All figures are `simulated` and come from a prototype, not built code.

1. **Layout.** `events` becomes a rowid table (`id INTEGER PRIMARY KEY`) with a unique index on `(stream, seq)`. Events up to about 4 KB stay in their leaf page. On the prototype, the read that fills the 11 MiB cap wrote 12.51 MB of WAL, 1.09 × its payload.
2. **Rule (C5 0.5).** Index entries, cell headers and per-row references cost 275 to 470 B per record, whatever the layout. The rule becomes `W(C, R) = 1.1 × C + 64 KiB + 1 KiB × R`, where R is the most records in one commit.
   - `GroupOptions.MaxCommitRecords` sets R, with a default of `MaxEvents`. An `AppendBatch` over R is refused, the same way as one over `MaxCommitBytes`.
   - `RecoveryReserveFor` takes R.
   - The 1 KiB per record is provisional. B6 measured 0.7 to 1 KB of overhead per small row on a rowid table. B6 also measured about 2 × the payload for events just over half a page, because two such cells do not fit one page. The C5 0.5 PR sets the per-record term, and if needed a size-dependent term, from the worst case of #280's sweep, 100 B to 64 KiB at 1 and 2048 rows, with margin. No value is fixed before that sweep runs on the built layout.
   - B5's proposed reserves at 1 KiB (`desk`, to be recomputed): evidence (C = 11 MiB, R = 2048) 15.16 MiB; configuration (R = 1) 2.71 MiB; syslog and audit (R = 100) 2.26 MiB.
3. **Quota against disk.** C5 0.5 names a constant for disk bytes per quota byte. It is set from the built numbers, with margin; the prototype measured 1.07 to 1.70, against 4.07 before. Volume sizing is quota × that factor, plus the reserves. A test fails if the measured ratio exceeds the constant. No volume figure in the docs comes from raw quota sums.
4. **Old layout.** A database with the old `events` table is refused at open, with a clear error and an alarm. It is never deleted or rewritten automatically. The error and `platform/store`'s README name the export-and-rebuild path. There is no migration: all data so far is simulated, and a migration would need free space equal to the database.
5. **No page-size change.** A legal event can be 1 MiB, and small pages add frame overhead to every table.
6. **Order of work.**
   1. B5 writes the C5 0.5 contract PR, B6 writes its contract tests, and B1 approves it.
   2. B5's implementation PR follows: the layout, the open-time refusal and `MaxCommitRecords`.
   3. #280 keeps its property (measured WAL ≤ the rule) against the new rule, and gains a sweep from 100 B to 64 KiB at 1 and 2048 rows.
   4. #278 merges after that, with its reserves recomputed.

## D4-15: absence arming, the type working set, and the receiver split's caps (#287, #288, #284)

Date: 2026-10-28. Sources: B4's two readings on #287, B6's GT-INJ regeneration (#288), and B6's cap finding on #284.

1. **Absence is re-anchored at activation (C10).** This replaces B6's earlier reading, under which a type was armed only by an occurrence after activation or by a deadline still ahead at activation.
   - Every periodic type is armed at activation. A deadline (`last + IntervalS + ToleranceS`) still ahead at activation stands. A deadline that has already passed becomes `activation + IntervalS + ToleranceS`. Nothing alarms before activation.
   - Why: the earlier reading never alarmed for a periodic source that stopped while the baseline waited for its acknowledgement and did not return. A lost heartbeat is what the absence rule is for, and P5 says telemetry failures must stay observable. Re-anchoring delays that alarm by at most one interval and tolerance.
   - The held-out benign series' 16.5-hour start gap was an artifact of the schedule. B6 regenerated it to start at the acknowledgement (#288). It still raises 0. A new case silences the heartbeat from the wait onwards: it alarms once, at the acknowledgement + 5,402 s, and the old arming fails it.
2. **Max types keeps the highest Count, with a bounded working set (C10 0.1 clarification).** Keeping the first `max_types` types met would contradict `Counts.TypesOverflow`. It would also let a sender that floods new templates early in the observation period crowd out legitimate types.
   - While learning, the learner holds at most `MaxTypesCeiling` (4096) types per asset. A type first met while that many are held is counted in `TypesOverflow` and never held.
   - At `Finish` it keeps the `max_types` types with the highest Count. It then fits `MaxBytes`, or the node's lower cap, by leaving out the lowest Count. Wherever Count ties, in both steps, the lower key in byte order is kept.
   - `TypesOverflow` counts types, never events, because events in no type can be derived from `Full + TypeOnly − Σ Type.Count`. It is the exact number of types dropped at `Finish`, plus the distinct keys met while the working set was full. Those keys are tracked in a second set of at most 4096 keys, and past that the count saturates and is a lower bound (B6 on #289).
   - The result is exact for an asset with up to 4096 types in its observation period. The overflow count is shown to the operator at acknowledgement (B5).
   - C10's doc gains these sentences on the working set and replaces `baseline.go`'s "a learner stops at max_types or at MaxBytes". The encoding and `Validate` are unchanged.
3. **The receiver splits at both commit caps (C5 0.4 item 3, C5 0.5; #284).**
   - Stream and datagram batches commit in parts, in order. Each part stays within `MaxCommitBytes` and `MaxCommitRecords`. The node sets both from each Log's `GroupOptions`.
   - A committed part is never sent again. A stream part refused for any reason other than size is held and retried, as before. A datagram part refused that way is dropped and counted as store.
   - The refusal does not say which cap a part exceeded, so a part refused as too large halves only the record cap, never below one. The byte cap is never lowered. The caps only fall during the receiver's life.
   - A lone record the Log refuses as too large is dropped and counted as store, with `LastErr` set. This path is defensive: the frame limit keeps a message well under the record cap.
4. **D4-14 as built (#281, #282, #283; B5).** These are the values on `main` at 49b9454. The provisional figures in D4-14 item 2 are replaced.
   - `RowWALBytes` is 3 KiB per record. B6's sweep on the built layout found a worst case of 2,051 B, and the worst WAL was 0.905 of the rule.
   - `DiskBytesPerQuotaByte` is 2.5. B6 measured a worst file growth of 2.24.
   - `MaxHoldsPerRecord` is 16.
   - Recovery reserves at a 512 KiB WAL bound:

     | Database | Cap | Records | Reserve |
     | --- | --- | --- | --- |
     | evidence | 11 MiB | 2048 | 20,093,337 B |
     | syslog | 1 MiB | 1024 | 5,413,273 B |
     | audit | 1 MiB | 128 | 2,660,761 B |
     | configuration | 1.5 MiB | 1 | 2,847,334 B |

     The configuration database arrives with the next node PR.
   - All figures are `simulated` and measured on Linux. The reserve formula stays `desk` until B6's storekill leg runs (D4-9, C5 item 5).

## D4-16: a pre-0.3 register package with `runs` or `limits` is refused even when they are empty (#279)

- **Decision.** Under C3 0.3, a package with a version below 0.3 that carries a `runs` key or a `limits` key is refused. This holds when the value is empty (`[]`) or `null`. The key's presence decides, not its content.
- **Why.**
  - A 0.2 reader already refuses these keys as unknown fields (strictjson). With this rule, the same signed bytes get the same verdict on an old node and an upgraded one.
  - It reads the C3 text ("with limits or runs is invalid") literally, and it fails closed.
  - Found by B6 in the independent C3 0.3 review. At #279's merge the reader accepted all three cases. They carry nothing, so nothing unsafe got through.
- **Follow-up.**
  - B2: a small C3 0.3 change ahead of register revision 5. The reader checks for the raw key, `contracts/register/doc.go` says so in one sentence, and there is one test for each of `"runs": []`, `"runs": null` and `"limits": null` in a 0.2 package.
  - B6: pins the same three cases in the independent tests (#292 or a follow-up to it).
- **Extension (B6 on #293).** The rule is general: a key introduced at a C3 version is refused by its presence in a package below that version, whatever its value. So a 0.1 package with `"context": []` or `"context": null` is refused too, as a 0.1 reader already does. This case predates #279. B2 adds it to #293 with one test each, and the `doc.go` sentence states the general rule rather than listing keys.

## D4-17: D4-11 covers keys from the key register too (#290)

- **Decision.** D4-11 is about posture, not about where a key comes from. An expired or not-yet-valid certificate stops only its own link whether the node reads it from lab TLS files or from the key register (#176). B3 confirmed this reading.
- **State at #290.** The lab-file path narrows to one link. The register path still stops the whole node, because `nodekey` refuses an out-of-period certificate with an error that cannot be narrowed to a link. This is fail closed with no fallback (B3 read the loaders at 778c3c7), so #290 merges as it is. B3's HR-13 threat-model row states the gap until the follow-up lands.
- **Follow-up, in two PRs.**
  - B3 (`modules/security/nodekey`): loaders that return the certificate and the anchor set without judging the period. The strict loaders stay.
  - B5 (node): `ServerTLS` and `ClientTLS` decide the period for register keys exactly as they do for files. B3 reviews it.

## D4-18: a configuration baseline acknowledgement ends the asset's open configuration alarms (C8 0.6, #305)

- **Question (B3, from B6's probe on #305).** C8's `VerifyConfig` keys an open unapproved-change alarm by asset and baseline digest, and only a `config.baseline_restored` clears it. So after acknowledging B and then A again (A to B to A), an alarm raised against A before the acknowledgement of B is open again, and an approved detection against A is refused. C8's own text says that ending the alarm "takes a baseline acknowledgement (which moves the baseline) or a return to the baseline, recorded", and B5's hold fold follows the text.
- **Decision: the text stands, and `VerifyConfig` changes (C8 0.6).**
  - A succeeded configuration-kind `config.baseline_acknowledged` ends every open configuration alarm of its asset raised before it, whatever baseline they were raised against.
  - An event-kind acknowledgement (a C10 baseline) or a denied acknowledgement ends no configuration alarm.
  - Re-acknowledging A starts A again from that acknowledgement. Alarms from before it do not come back.
  - Only an alarm raised after the latest acknowledgement blocks a later approval, until a restore or another acknowledgement.
  - Detection compares each read against the latest acknowledged baseline. So re-acknowledging A while the device is still at S does not go quiet: the next read of S differs from A and raises a new alarm, unless an approval covers it.
- **Why.**
  - An acknowledgement is a signed decision by a person, verified against its acceptance. It is the act that accepts the device's configuration as the baseline. Letting an alarm from before it come back depending on which digest is acknowledged makes an alarm's state depend on history the person already decided on.
  - The alarm's C8 records stay in the chain. Only their open state ends.
  - Keeping alarms open until a restore would mean an alarm against a baseline the device never returns to stays open forever, which C8's text already rules out.
- **Evidence bytes (B6 on #306).** The acknowledgement does not release the snapshot and difference an ended alarm names. They stay held, with the reason `acknowledged-difference` in place of `unapproved-difference`, so the bytes that showed an unexpected change are kept and not only its digest. R3.5 and R3.6 require this: "the difference is kept as evidence either way". Nothing ends that hold yet. Releasing it needs a retention rule for configuration evidence, which B1 rules with the retention rule #299 left open. Until then the node never releases it to make room, the same as every hold.
- **C5 0.6 for the new hold code (B6 on #306).** `acknowledged-difference` is outside C5 0.5's closed `HoldCode` set, and `HoldReason.Validate` refuses it, so it needs a C5 minor.
  - B5 owns C5 0.6. It adds `HoldAcknowledgedDifference`, whose `Ref` stays the `config.change_detected` C8 record, the same as `unapproved-difference`. B3 and B6 review it.
  - C5 0.6 merges before #305, so no binary that reconciles holds ever lacks the code.
  - Older binaries. On main, pruning skips every row in the holds table whatever its code, and `Held` returns the stored code without validating it. So a 0.5 binary that opens a 0.6 store prunes nothing held. B6 pins this with a cross-version test: a store holding an `acknowledged-difference` record, opened, pruned and listed by the 0.5 code, keeps the record.
  - From 0.6 on, a reconcile that meets a hold code it does not know keeps the hold as it is, never releases it or changes its reason, and raises an alarm. This is fail closed (P5), and it covers any later code.
- **Missing baseline (B6 condition 2 on #305).** If the newly acknowledged baseline cannot be found at reconcile, the node does not release the holds of the old one. It keeps what it held and raises an alarm, so nothing becomes unheld because a lookup failed. This is fail closed (P5).
- **Owners.**
  - B3 writes C8 0.6: the `VerifyConfig` change plus one sentence in `doc.go`.
  - B6 tests it independently, with the A to B to A case and an alarm raised after the latest acknowledgement still blocking.
  - B5 keeps #305's fold consistent with it, including the `acknowledged-difference` reason.

## D4-19: a return to baseline keeps the alarm's evidence held too (C5 0.6, #305, #308)

- **Question (B5 on #305).** D4-18 keeps the snapshot and difference of an alarm that an acknowledgement ends. It says nothing about an alarm that a `config.baseline_restored` ends, so #305 releases them on a return to baseline.
- **Decision: they stay held.** A recorded return to baseline ends the alarm's open state, as before. The snapshot and difference it names are re-reasoned to `restored-difference` and are not released.
- **Why.** R3.6 keeps the difference as evidence either way. A change that was made and then reverted with no approval is still an unexpected modification, and its bytes are the only evidence of what was on the device in between. A change and revert within one collection gap is also what someone covering their tracks would do.
- **The code.**
  - C5 0.6 (#308) gets a second code, `HoldRestoredDifference` = `restored-difference`, beside `acknowledged-difference`. Its `Ref` is the `config.change_detected` record, the same as the other two difference codes.
  - The two codes stay separate, so a reviewer can read from the holds table how each alarm ended without walking the chain.
  - D4-18's other rules apply unchanged: nothing ends the hold until the retention rule for configuration evidence, and a reconcile keeps a hold whose code it does not know.
- **Ref for `acknowledged-difference`.** It is the `config.change_detected` record, as D4-18 already says. B5's #305 and #308 are right.
- **What a flapping device does (B5 and B6 on #310).** Held evidence now grows by one snapshot and one difference for every alarm that ends. A device that keeps changing and reverting fills the configuration class. At its quota the class stops taking new reads, with the class warning raised first, and the node never releases a hold to make room. So configuration monitoring of that node stops and says so, and nothing already held is dropped. That is the intended failure (P5), but it stops monitoring, so the retention rule for configuration evidence is ruled before any device-observed asset is configured. It is tracked as an open risk until then.
- **Owners.** B5 adds the code to #308 and the re-reasoning to #305's fold, with a fold case and a test at start. B6 adds the new code to #307's cross-version test. B3 reviews #308.

## D4-20: retention of configuration evidence (C5 0.7, #299, #305)

- **Question (B5 on #299, B3, B5 and B6 on #310).** The configuration class has no consumers, so nothing in it is ever pruned. D4-18 and D4-19 keep every ended alarm's snapshot and difference held with no rule that ends the hold. So a node fills its configuration class and stops reading, with the warning first. This must be ruled before any `device-observed` asset is configured.
- **Decision.** The node keeps every configuration record that is evidence of a change or of a baseline, and it never releases one to make room. It removes only reads that showed no difference, and of those it keeps the two newest per asset. The rules:
  1. **An approved change is held too.** R3.6 keeps the difference "either way", and today #305 holds nothing for a change that an approval covered. Its snapshot and difference are held as `approved-difference`, with `Ref` the `config.change_detected` record. This replaces #305's case "an approved change holds nothing more".
  2. **A superseded baseline stays held.** When a new baseline of the same kind is acknowledged, the previous baseline record is re-reasoned to `superseded-baseline`, with `Ref` the `config.baseline_acknowledged` record that made it the baseline. It is not released. It is the original configuration that R3.5 preserves. Its growth is bounded by signed acknowledgements, which only people make.
  3. **A read with no difference is removable once a newer read of the asset is stored.** After rules 1 and 2, the only configuration records left unheld are reads whose snapshot showed no difference from the baseline, together with their captures. The node keeps the two newest such reads per asset and kind. It removes older ones in bounded steps, as the quarantine clear does (D3-1, `Discarder`), and counts each removal in node status and a platform health event. Their `config.read` C8 records stay in the audit chain with their digests. B3 decides in review whether a removal also needs a C8 record of its own.
  4. **Held evidence is released only by a person, and only after it has been exported.** No rule releases a held record automatically. A release is a signed, audited administrator command per asset, in the pattern of `quarantine.cleared`. It is refused for an open alarm (`unapproved-difference`) and for the current baseline. The configuration documents have no forwarding path, so a release would destroy the only copy. The release is therefore built only together with an export, where the admin client fetches the bytes and the release's C8 record carries their digests. It is not owed by Phase 4. Until it exists, D4-19's stop at the quota stands.
  5. **A load-time floor on the quota.** A node with configuration collection refuses a `configuration` quota below 16 × `ConfigRecordBytes` (24 MiB) for each asset it reads. That covers the baseline, the two newest reads and one read in flight, with room for 12 held differences before the class stops. This is a floor that catches a quota too small to work, not a sizing recommendation. Real nodes are sized by the owner.
- **Why.**
  - R3.5 and R3.6 make change evidence and original configurations the thing this module exists to keep. A rule that ages them out by time or by space would let someone who changes a device and waits remove the proof.
  - A read that matched the baseline proves only "unchanged at T". Its `config.read` record already says that, and the baseline holds the bytes. Keeping only the two newest bounds steady-state growth to two reads per asset.
  - What grows after this is bounded by events that each raise an alarm or need a signature: changes, approvals and acknowledgements. A device that flaps fills the class and stops configuration reads with the warning first (D4-19). That is now the only path to a full class, and it is an attack or fault someone has to look at. Event collection and Syslog are in other classes and are not affected.
- **Races, failing closed.** A person can view read N and acknowledge it after read N+1 has been stored and N removed. The acknowledgement then names a digest the store does not have, so the reconcile keeps the old holds and raises an alarm (D4-18, missing baseline), and the person acknowledges again against the read they now see. Nothing becomes unheld. Keeping the two newest reads (B6 on #319) gives a person at least one schedule interval, and up to two, between a read landing and its removal. That makes the race rare in practice, without the node having to know about an acknowledgement that has not arrived yet.
- **The contract (C5 0.7, B5).**
  - Two hold codes, `approved-difference` and `superseded-baseline`.
  - A bounded remover for unheld configuration records, which refuses a held record, the newest read of an asset, or any record of another class.
  - A 0.6 binary that opens a 0.7 store prunes nothing held (the prune skips every row in the holds table, whatever its code), and its reconcile keeps the codes it does not know and raises an alarm (D4-18). B6's cross-version test pins both.
- **Amendments from review (B2, B3 and B5 on #319).**
  - **What "no difference" means (B2).** `Compare(baseline, read)` against the asset's current acknowledged baseline of the same kind returned a nil error and an empty `Changes`. These are not no-difference reads and are never removed:
    - `ErrNotComparable`, for example a `/1` baseline after C9 0.2 retires that rule, or a `simulated` baseline against a `device-observed` read. The node raises "baseline not comparable" and keeps the reads.
    - A read made before any baseline was acknowledged, since it may become the baseline.
    - A failed read, which produces no snapshot.
  - **What C9 ignores (B3's condition 2, answered by B2).** C9 compares every setting it parses, by name. Only formatting, order, wrapping, heading lines and the command-response header are outside a `Difference`, and none of those is configuration. So removal does not need byte-identical transcripts. A removed read takes its own header lines with it, and only the baseline's transcript keeps those. Settings that C9 does not retrieve, such as the touchscreen gap (S22 Table 7.80), are a coverage gap recorded in the capability matrix, not a reason to keep reads.
  - **The same change again (B2's question to B5).** A change that persists would otherwise hold a new snapshot and difference on every read, and fill the class in about 13 cycles. So a read whose `Changes` equal those of the asset's newest held change, while that change's alarm is still open or an approval covers it, is the same change. It holds nothing new and raises no new alarm, and the audit chain records it as a read with the same change, naming that change's `config.change_detected`. Under rule 3 it is removable as the no-difference reads are, and the two newest are kept. This also covers every read after an approved change that is never re-baselined (B6 on #319): without it, a 300 s schedule at 150 to 250 KB a read stores 43 to 72 MB a day per asset. Equal `Changes` slices are the test, since C9 orders them (rule class order, then name). B2 adds `SameChanges` to C9 0.2. A change whose alarm has ended (acknowledged or restored) is not open, so the same `Changes` seen again afterwards is a new change and a new alarm. That keeps D4-18 and D4-19 as they are.
  - **What the remover may take (B5's point 1, B3's conditions 1, 3 and 4).**
    - The remover takes only a record that the audit chain shows as a read with no difference, or as the same change, whose result is already recorded. Having no hold is not enough. So a crash between a change's snapshot and its `config.change_detected` cannot later lose that snapshot.
    - It removes by seq range of one asset and kind, never by time or space pressure, and never the two newest such reads.
    - Each step writes a node-written C8 `config.reads_removed` record (B3 writes it in C8 0.7, with the shape in B3's review), and that record is receipted before the removal commits. A refusal to audit refuses the removal.
    - A fault injected at the removal commit leaves the records and the audit consistent: either both are done, or the record still exists and the audit names more than was removed. Nothing is ever removed without a receipt.
  - **Rule 2's `Ref` (B5's point 2).** It is the new acknowledgement that superseded the record, so the hold says why it stopped being the baseline.
  - **Priority when one record is wanted for two reasons** (A to B to A, for example). The order is `baseline`, then `unapproved-difference`, then `approved-difference`, `acknowledged-difference`, `restored-difference` and `superseded-baseline`, in that order.
  - **Rule 5 counts the assets with configuration collection (B5's point 3).** An asset that only sends Syslog needs no configuration room, and counting every asset would ask a node with many such assets for gigabytes it never uses. A reload that adds collection is checked again and fails visibly. The load error states the quota needed and the number of assets behind it (B3).
- **Gate.** Rules 1, 2, 3 and 5 are merged and independently tested before the first `device-observed` asset is configured. Rule 4 may stay unbuilt. The open risk from D4-19 is narrowed to "a flapping or repeatedly changed device fills the class and stops configuration reads until an operator acts", and it stays open until rule 4 is built or the owner accepts it.
- **Owners.**
  - B5: C5 0.7 and the node changes. Rule 5 goes in #299. Rules 1 and 2 and the priority order go in #305's fold after #299 is on main. C5 0.7, the remover (rule 3) and the same-change rule are a follow-up PR after #305.
  - B3: reviews C5 0.7, writes C8 0.7 (`config.reads_removed`, and the same-change read result), and owns the release and export design (rule 4) when it is scheduled.
  - B2: adds `SameChanges` to C9 0.2.
  - B6: tests independently. The cases are a flapping device filling the class with nothing held dropped; an approved change held; the newest read kept and older ones removed; the acknowledgement race failing closed; a persistent unapproved change holding one snapshot and difference, not one per read; a crash between a change's snapshot and its `config.change_detected` leaving that snapshot unremovable; fault injection at the removal commit; and the cross-version case.

## D4-21: unknown senders get at most a quarter of a listener's queue (F-017, HR-11)

- **Question (B6, F-017 on #316).** Does HR-11 need the known senders' room in the receiver's queue reserved, so that a lifted or misconfigured rate limit cannot take it? With the default limits, no case shows a known loss from a flood. With the rate limits lifted, a held commit drops known datagrams as `queue-full`, all of them counted.
- **Decision: yes, by capping the unknown share.** The receiver admits an unknown sender's message only while unknown messages hold less than a quarter of the listener's queue, by count (`Queue`) and by bytes (`MaxQueueBytes`). A message past that share is dropped and counted as `unknown-queue-full`, a new drop reason. The cap is fixed and is not a configurable limit, so no configuration can give unknown senders the known senders' three quarters.
- **Why this and not a queue per class.** It is one check before the existing queue-room checks, and it adds no second consumer or ordering question. A quarter matches the share the node already gives unknown senders elsewhere: the connection limit (a quarter of `MaxConns`) and the unknown storage sizing (#169). The rate limits and the budget stay as they are. This is a floor under them, not a replacement.
- **At the smallest queue (B4 on #317).** `MaxQueueBytes` validates at 64 KiB or more. At that minimum the unknown share is 16 KiB, so an unknown datagram larger than that is always dropped as `unknown-queue-full`. The default of 8 MiB gives the unknown share 2 MiB. This matters only for a deliberately tiny setting, and it fails toward the known senders.
- **What it does not fix.** A store stall long enough to overflow the known senders' three quarters still drops datagrams, whoever sends. That is F-016's disk, and it is tracked there.
- **Owners.**
  - B4 builds it in `modules/telemetry/receive`, with the drop reason in the status counters (#317).
  - B6 re-runs F-017's lifted-limits case.
- **What the cap guarantees (B6 on #317).**
  - If the known senders' datagrams during the stall fit in three quarters of the queue, by places and by bytes (768 datagrams and 6 MiB at the defaults), a flood costs them nothing. B6's run of 600 known datagrams lost 0 with and without the flood, and 88 on main.
  - If a stall is long enough to overflow the queue anyway, the flood costs the known senders at most the unknown quarter. With 1200 known datagrams, the run lost 176 without the flood and 432 with it, a difference of 256 = `Queue`/4. On main the flood cost 512.
  - So the pass criterion is: known loss with the flood ≤ known loss without it + the unknown quarter, and no loss at all when the known datagrams fit in three quarters of the queue. The unknown quarter is `Queue`/4 datagrams (256 at the defaults) or `MaxQueueBytes`/4 bytes, whichever binds first, so with large datagrams it is fewer than 256 (B6 on #323).
  - Equal loss in a long stall would need known datagrams to evict queued unknown ones. That adds an eviction path to the receiver for a case that is already F-016's disk stall, so it is not built.
  - B3 adds it to the HR-11 row's "still open before the first `device-observed` listener".
  - It is a gate before the first `device-observed` listener, and not before #316 merges.

## D4-22: the Windows package timeout is 20 minutes, and `platform/node` gets a time budget (#324)

- **What failed.** On #324 at 9a0b0a8 (job 122721753701), `platform/node` hit the Windows `-timeout 12m`. The goroutine that was running sat in `store.(*DB).Close`, inside a WAL checkpoint, in `FlushFileBuffers` (F-016).
- **B5's evidence.** The table gives Windows times in seconds for three runs: #320, #324's first run, and this run.

  | Package | #320 | #324, first run | This run |
  | --- | --- | --- | --- |
  | `platform/node` | 416 | 552 | over 720 |
  | `platform/store` | 95 | 105 | 152 |
  | `storeholds` | 286 | 370 | 501 |
  | `quarantine` | 46 | 64 | 97 |
  | `security` | 107 | 174 | 215 |
  | `syslogreceive` | 136 | 230 | 278 |

  Packages that #324 does not touch slowed by the same 1.3× to 2×. The Linux time for `platform/node` is flat (165 to 170 s). So the cause is the runner's disk, not #324. A normal Windows run of `platform/node` used 58 to 77 percent of 12 minutes, which is the same headroom D4-5 recorded against 600 s. One slow disk uses it up.
- **Decision.**
  1. The Windows `go test ./...` step runs with `-timeout 20m`, and the Windows job limit goes from 30 to 35 minutes. In the failed job, `go test` began 3.4 minutes in and the last packages started 3.7 minutes into the step, so a hang there dumps at about 27 minutes, and another 1.5× slowdown takes it to about 29. At 30 the job could be killed before the dump prints (B6 on #327). Linux is unchanged. This replaces D4-10 item 2's 12 minutes and 30-minute limit.
  2. **A budget, so the new limit is not slack.** `platform/node` on a green Windows run must stay under 12 minutes, the old limit. A green run over 12 minutes is a finding for B5 under F-016, not a pass that nobody notices. B5 reports the ten slowest `platform/node` tests on Windows and cuts what is fixture time, as #252 and #264 did. B6 suggested a Windows step that emits a `::warning::` when `platform/node` goes over 720 s, so the budget is seen without reading the times; B5 builds it with this item. First cut, #328: tests that hold a database busy on purpose set a 400 ms `busy_timeout`, and production keeps 5 s. On Linux `platform/node` went from 170 s to 83 s. One Windows run gave 449 s, which is inside the range above, so it shows no Windows saving either way. B6 delayed every fsync and ran the six held-database tests: 92 s on main and 9 s on #328 with no delay, 8 m 33 s and 7 m 09 s at 1 s, and at 2 s main ran past B6's time limit while #328 took 14 m 20 s. All finished runs passed. So the cut saves least on exactly the slow disks the budget is for, and the budget still depends on further fixture cuts and the 720 s warning.
  3. **Close's checkpoint is bounded in bytes but not in time.** `wal_checkpoint(TRUNCATE)` on `context.Background()` parks in `FlushFileBuffers`, which no context can cancel. That is acceptable at shutdown, where the service manager's stop timeout is the bound. B5 records it in the store's README under F-016.
  4. A run that times out at 20 minutes is real, never a flake, and it is handled under D4-5.
- **Owners.** B1 makes the `ci.yml` change in this PR. B5 and B6 review it. B5 owns items 2 and 3.

## D4-23: a configuration run is all or nothing, and "Invalid Command" is never a language refusal (C2 0.6, C9 0.2, #331)

Date: 2026-10-28. B6 raised two items in the review of #331 at 4be058c. B2 fixed both at 5a10fb8, and B6 re-reviewed and accepted 8e57949.

1. **The device-error check comes before the language check.** On `SHO P 1`, the language gate's form, a reply of "Invalid Command" was refused as `refused.language_not_english` with an empty detail. That code suspends the asset for language. "Invalid Command" is an English reply from the device. So on every form that serves a check, the gate form included, the adapter tests for it before the parse and the language check, and it reports `failed.device_error`. The gate form is not carved out of rule 4, because a carve-out would leave the wrong order in place for the next form.
2. **A run's result has exactly two shapes, and C2 holds it, not only the adapter.** `checkRun` accepts:
   - `ok`, with every step sent once and in order, and one parsed configuration record per step, in step order;
   - not `ok` (failed or refused), with a prefix of the steps sent and no record.

   `partial` is not a run outcome, and a configuration record that did not parse is invalid. A reply the rule cannot read ends the run with `failed.config_unparsable` and no record. A partial snapshot would give C9 false differences against the baseline, and a snapshot is whole or absent. The two invalid examples are a failed run with 24 records and a `partial.parse_errors` run.
- **Not blocking (B6).** `failed.config_unparsable` is still accepted on a single SER read. B2 may close that in a follow-up.
- **Approved.** C2 0.6 and C9 0.2 merged as #331 (6c33f14). The next steps belong to others. B2 adds `sel751.Hosts` and a measured maximal result frame. B3 builds the collector run wiring under C7 0.7 (#334), including B5's `checkReply` fix: it accepts any contract the node accepts (`AcceptsContract`), so a mixed 0.6/0.7 node and collector do not reply `ErrProtocol`.

## D4-24: the collector client's deadline, the clear's actor, and acceptances from an untrusted collector (#339, relay PR 2a)

Date: 2026-10-28.

1. **`collectorclient.Do` gets a deadline for each request, not a fixed constant.** The deadline is the collector's own bound for that request plus 10 s. For an invocation, that bound is the operation's or run's total limit from the signed register (`Limits.ForRun` for a run), which gives the 310 s or more that C7 0.7 (#334) expects. For the credential and admin-relay kinds, it is their existing reply bound. When the deadline passes, the request fails closed with `ErrTimeout` and is not retried in the same session. B3 builds it in the C7 0.7 collector PR, together with `AcceptsContract` in `checkReply`.
2. **On `quarantine.cleared` the actor stays the node, so C8 does not change.** The node performs the clear. The person who signed the request is recorded in `requested_by`, and the record links to the collector's accepted admin-signed request by the hash of the payload the collector verified, not by a later read of the file. Relay PR 2b only adds the refusal of unsigned clear files when any endpoint is not lab or simulated.
3. **An acceptance from a collector the node did not trust is never acted on (B6's high finding on #339, A3's item 3 on #181).** Before this fix, a clear that a restored collector accepted was applied once the collector was reinstalled and the reset acknowledged. Two rules close this, and both are required:
   - **(a) Taint at fold time.** A relay entry is tainted if the restored hold was in force when its acceptance was folded, that is, if `Restored` was non-nil after that record (B3's refinement), or if its `collector_seq` is at or below the high mark. The taint is derived from the chain, so a restart keeps it.
   - **(b) Bind to the install key.** An acceptance is acted on only while its `install_key_id` is the trusted key. A reinstall retires every acceptance from the old key, and going back to an earlier key does not revive them.

   A tainted or retired entry is refused, not left pending. Its status and the health line tell the administrator to sign the request again. Tests: B6's probe (a restored acceptance, then a reinstall, then an acknowledged reset, and nothing is cleared), (b) on its own, and the node's own `applySeqAck` key check reached through the relay. B3 confirmed the rule.

## D4-25: a configuration snapshot is bounded in C9, so a valid run always fits the record cap (#338)

Date: 2026-10-28.

- **What B2 measured (simulated, `config.FromResult`).** With S22's 8,734 settings and values that fill the 512 KiB run limit, the stored record (snapshot plus transcript) is 1,210,476 bytes, which is 77% of the 1.5 MiB cap. But nothing bounds the number of settings. A transcript at the byte limit packed with one-character settings gives 65,822 settings and a record of 2,295,738 bytes. C5 would refuse that commit, and the run would store nothing.
- **Decision: C9 0.3 bounds a snapshot.** The bound is set by setting count, starting from S22's count plus a margin that B2 proposes (25% to start), with a byte bound on the snapshot as encoded as the backstop. Both are chosen so that a record at both bounds, with a full 512 KiB transcript, fits the 1.5 MiB cap with room to spare, and tests pin this. A run over either bound fails as `failed.config_unparsable`. The detail names the bound, the transcript is kept, and no snapshot is made.
- **Why not accept a run that stores nothing, or raise the cap.** A run that passes every check and is then refused at commit drops evidence silently (brief §1.4). A larger cap only moves the edge, because the transcript limit does not bound the setting count. A relay that prints far more settings than S22 lists is outside our evidence, so it should fail visibly, with its bytes kept.
- **Owners.** B2 drafts C9 0.3 as its own contract PR, which deletes `TestConfigDenseRecordExceedsTheCap`. B5 and B6 review it, and B1 approves. #338 merges with the gap pinned and stated.
- **Amendment (B1 on #345).** The fit is measured on the record the node actually commits, with `store.Record.Bytes` (event, capture and source cursor). It is not measured as snapshot plus transcript. It leaves at least 64 KiB of headroom under the cap. #345 derives `MaxSnapshotBytes` as the record cap, less the run's `max_total_bytes`, less 64 KiB (960 KiB), and a test fails if the register or the node's `ConfigRecordBytes` drifts from it.

## D4-26: the event-baseline feeder keeps its state across a restart, and the recording is in the audit chain (#340)

Date: 2026-10-28.

1. **Learner and detector state: snapshots plus a required C5 consumer (B5's option A).**
   - **The snapshot API.** B4 adds `Snapshot` and `Restore` to the learner and the detector. The format is deterministic, versioned and bounded, and B4 states the largest snapshot at the 4096-type ceiling. Restoring at any point gives byte-identical output to a run that never stopped.
   - **How the node uses it.** The node writes the snapshot atomically, together with the per-stream positions that the snapshot reflects. After the snapshot is durable, it commits the required `node-eventbaseline` consumer. On restore, each stream resumes from the later of the snapshot's position and the consumer's cursor, so a crash between the two steps counts nothing twice.
   - **A snapshot that does not restore** (corrupt, an unknown version, or other `Params`) raises an alarm and starts an audited re-learn that names the replaced baseline. It is never a silent restart.
   - **Rejected:** keeping 14 days of events (an unbounded replay, and a flood fills the quota), and restarting the period (a node that is updated weekly never learns).
2. **C8 0.8 adds `config.baseline_recorded`.** Its fields are asset, kind (event, or configuration where that applies), digest, version, and previous (the replaced digest on a re-learn). It is written in the same commit step as the baseline record. verification.md requires the baseline to be "recorded once, versioned and hashed in the audit chain", and the C5 record alone does not show a baseline that was recorded but never acknowledged. B3 drafts it, B4, B5 and B6 review it, and B1 approves.
3. **Order.** B5 builds the configuration and layout, then the merge reader with its watermarks, then the lifecycle with learner state in memory only. That stage is not shippable, and V-M4 is not claimed on it. The snapshot and the restart tests follow once B4's API lands. B4's snapshot PR and C8 0.8 run alongside.
4. **Amendments after review (B3's #346, B4's F1 on #344).**
   - **C8 0.8 is event-only.** `config.baseline_recorded` with `kind: configuration` is refused until a writer for it exists. A succeeded event-kind `config.baseline_acknowledged` must name a `baseline_digest` that an earlier `config.baseline_recorded` for the same asset and kind recorded and no later one replaced. `VerifyConfig` refuses any other, and tests cover a digest that was never recorded and one that was replaced. `correlation_id` is proposed by B4 and B5 on #346. It is deterministic, derived only from data already in the chain or in the C10 record, and the same on a recording and on its acknowledgement. *(The last clause is superseded by D4-29.)*
   - **Ordering across two databases, which replaces "the same commit step" in item 2 (B5 and B3 on #346).** The baseline lives in the configuration database and the audit record in the audit database, so one commit step cannot cover both. The node stores the baseline first, then writes `config.baseline_recorded`. At start it folds the chain and writes any missing record for a stored baseline. A baseline whose record is not yet in the chain is never shown as awaiting acknowledgement, and it cannot be acknowledged. A crash test covers each of the two points.
   - **The acknowledgement window (B1 on #346, from B6's review of #337).** `VerifyConfig` may receive records that start partway through the chain. It applies "a succeeded event acknowledgement names a recorded digest" only when the records hold that asset's version-1 `config.baseline_recorded`. Otherwise it refuses only a digest that a recording inside the records has replaced. A test covers each side.
   - **The detector's per-(rule, type) hold records are bounded (B4's F1).** Before this, a flood of distinct new types grew `Detector.pairs` and the snapshot without bound: 4.8 MB at 114,688 types, and refused at 245,760. A pair whose hold has ended and that holds no events is dropped, which changes no output, and a test shows it. What remains is capped, with the cap stated in the package doc. Past the cap, every departure still counts toward an alarm or the held notice. That alarm or notice states how many it does not list, and it never re-alarms without bound or drops an alarm. B4 builds it as a small PR, and B5 and B6 review it.

## D4-27: a run's limits come from the signed register only (C7 0.7, #334, #341)

Date: 2026-10-28. This is a ruling. Approval of C7 0.7 is pending on #341.

- **What C7 0.7 does.** A run request names a register run in `operation_id`, with no new field. Every run check comes before any credential, failed-auth floor or interval check (B6's `TestConfigRunRefusalsComeBeforeTheCredential`). The run's access level comes from `RunBody.AccessLevel`.
- **Limits.** A run's limits are `Limits.ForRun` from the signed register. The collector configuration cannot change them, not even to tighten them. A local override would make a run behave in a way that was never verified, and a tighter deadline only turns a valid read into `failed.timeout` on every poll. A site that needs a lower bound ships a new register revision, which is signed and reviewed.
- **Deadlines (D4-24 item 1).** `run_deadline_ms` goes on every run-kind request stamped 0.7 or later, operations included (120 s by default). The node waits `run_deadline_ms` plus 10 s, and `ErrTimeout` wraps `ErrOutcomeUnknown`.
- **Mixed versions.** `collectorclient.checkReply` accepts any contract the node accepts (`AcceptsContract`). Before this, a reply with a different minor was `ErrProtocol` (B5 on #334). The upgrade order is the node first, then the collector.
- **Hosting.** The collector holds each shipped profile to `sel751.Hosts` (#338), so a profile cannot name an operation no adapter hosts. A run of only Level 0 steps is already refused (`refused.not_invocable`).
- **Approval.** C7 0.7 is approved when B2, B5 and B6 accept #341 and CI is green on its head.

## D4-28: the owner pauses all agents, and the B team hands off to the C team (owner, 2026-10-28)

- **The pause.** At 16:39Z the owner asked every agent to pause at a safe checkpoint. Agents start no new work, commit or save what is in progress, and merge nothing until the owner resumes.
- **The checkpoint.** At 16:46Z the owner issued the restart-safe generation checkpoint: B1 to B6 hand off to C1 to C6, with the same roles, paths and rules. Each B agent writes `handoffs/C{n}-handoff.md`. B1 rewrites `handoffs/HANDOFF-SUMMARY.md`, creates `handoffs/GENERATIONS.md`, and updates the names in `CLAUDE.md` and `README.md`.
- **What may merge during the pause.** Only checkpoint PRs, which change Markdown files under `handoffs/` (plus this file and the name updates). They merge on review (D3-13). Feature and contract PRs stay open as they are.
- **Where a handoff file rides.** Where an agent's only branch is the head of an open code PR, B1 carries that agent's handoff file unchanged in B1's checkpoint PR, so that it does not wait on the code PR.
- **Numbering.** Phase 4's decisions continue in this file and numbering under the C team (D4-29 onwards), as the checkpoint instruction says.
- **The pause is lifted.** At 17:11Z the owner said "Resume". The B agents resume from their handoffs' next actions, and feature and contract PRs merge again under D2-13. The checkpoint is still finished first. At 17:13Z the owner chose to open the C threads now. From then on the B agents start no new feature work. They push what they have, finish the reviews already in progress, and answer the C agents' ack questions. The C team takes over when every ack is confirmed.

## D4-29: the `correlation_id` of `config.baseline_recorded` (C8 0.8, #346)

Date: 2026-10-28. C1, on C3's proposal in #361 (comment 6475983773), which matches B5's proposal and B4's leaning on #346.

- **The recording.** The `correlation_id` of a `config.baseline_recorded` record is the 64 hexadecimal digits of its `baseline_digest`, without the `sha256:` prefix. A C10 digest is 71 characters, and C8's `idPattern` allows at most 64 (`contracts/audit/audit.go:38`). The value is deterministic, and it stays the same across a restart and across the repair at start.
- **The acknowledgement.** A `config.baseline_acknowledged` record keeps the signed C7 request ID as its `correlation_id`, as today (`contracts/audit/audit.go:228`).
- **The join.** A recording and its acknowledgement join on `baseline_digest`, which both already carry.
- **Superseded:** D4-26 item 4's "the same on a recording and on its acknowledgement". The join that clause wanted already exists through `baseline_digest`. Making the acknowledgement's ID equal would change how every acknowledgement joins to its request, or would need a second ID field in C8.

## D4-30: the learner and the detector checkpoint at every configured ceiling (D4-26, #344, #343)

Date: 2026-10-28. C1, on C4's ack question 1 (#357, comment 6476181758).

- **The finding (C4, desk measurement).** C5 stores a checkpoint as one configuration record, capped at `ConfigRecordBytes` (1.5 MiB). The learner at the 4096-type ceiling with 128-byte names measures about 1.9 MB, so it could not be checkpointed. The detector with every cap full measures about 1.3 MB, close to the cap.
- **The rule.** At every ceiling the configuration allows, the learner and the detector must checkpoint. A test that builds the maximal case and measures it against the cap the node uses proves it, as D4-25 did for C9.
- **The means** are C4's and C5's to choose on #344 and #343, with measurements. Either a C10 ceiling (for example the name length or the type count) is lowered until the worst case fits `ConfigRecordBytes` with headroom, or C5 splits a checkpoint over several records. C1 approves the choice.
- **Until then** an oversize snapshot is refused with `ErrSnapshotTooLarge` and raises an alarm. It never fails silently. A byte-bound parameter on `Snapshot` may go into #344, with `MaxSnapshotBytes` kept as the hard ceiling.

## D4-31: the C team takes over (owner and C1, 2026-10-28)

- **Branches.** At 17:37Z the owner chose, on a decision card in the C1 thread, to let C3 push to B3's existing branches for #341, #334 and #346, so that their review history stays in place. Force-push is still denied, so a branch is updated by merging `origin/main` into it.
- **Reviews.** B6 re-reviewed #347 at `714203e` (PASS on the code, comment 6475908745, recorded in `C6-handoff.md` by #359). C5 has since pushed `fc31c79` for C3, so that commit needs a role 6 review. Every role 6 review from here, #346 and `fc31c79` included, is C6's.
- **HR-11.** HR-11's row (#352) closes only when both conditions hold:
  - C6 has classified `TestUnknownSpentAcrossRestarts/seed_1`, which failed once on hosted Windows, on #346's head `95b91cd`, with a UDP marker reported lost without a count, and passed on the re-run. C6's first reading of the log: the counts reconcile (180 = 74 stored + 106 dropped) and the marker is in the store, so the test's loss detector may have raised a false alarm. *(Classified in D4-36.)* C6 owns the classification. C4 supports it as the receiver's owner and fixes any product fault.
  - The row names D4-21's pass criterion as a gate before the first `device-observed` listener, with #336 as its evidence (C6, comment 6476212811 on #352).
- **Cutover.** All six acks are on `main`: C1 #355, C2 #360, C3 #361, C4 #357, C5 #358 and C6 #356. Each question is answered on its PR. The C team holds the six roles from here, and the B threads can be resolved.

## D4-32: the event-baseline checkpoint in the configuration class, and its remover rule (#340, slice 1c)

Date: 2026-10-28. C1, on C5's two questions on #340 at `438062e` (comment 6476619232).

1. **A C5 minor, folded into C5 0.7.** The configuration class holds C9 snapshots and differences and C10 baselines (`contracts/store/class.go:32`, `commit.go:50`). Retention is decided by class, and D4-20's remover refuses any record of another class. So adding the node's checkpoint document, `otsec.eventcheckpoint/0.1`, changes what the class means, even though no wire field changes. C5 0.7, which already carries D4-20 rules 1 and 2, adds three things: the class text names the checkpoint as a node document of the class; the validator tells the three kinds apart; and the remover rule in item 2. Reviewers: C2 and C4 as consumers, C6's contract tests, and C3 for the retention rule.
2. **Superseded checkpoints are removable (a D4-20 amendment).** A checkpoint is working state, not evidence.
   - **When it may be removed.** A checkpoint of one half and asset may be removed once three things hold: a newer checkpoint of the same half and asset has committed; the `node-eventbaseline` cursor has been saved after that commit; and the newer one is the checkpoint the node would restore. *(Defined in D4-36.)* After the cursor moves, the older checkpoint's restart point may already be pruned, so the older checkpoint cannot serve as a fallback.
   - **What is kept.** The newest checkpoint of each half and asset is kept while that half is running. The remover refuses it, any C9 or C10 record, and any held record.
   - **A finished learner (C5 on #367).** When a learner finishes, its last checkpoint is never superseded. It becomes removable once the `config.baseline_recorded` of the baseline that learner produced is in the audit chain. From then on the node does not restore it. The baseline record, stored before the C8 record (D4-26 item 4), is what the node keeps.
   - **How removal runs.** Removal runs in bounded steps with the `Discarder` pattern of rule 3, and each removal is counted in node status and a platform health event.
   - **No C8 record.** A checkpoint is not in the audit chain, so its removal needs no C8 record. C3 confirms this in review.
   - **When the newest checkpoint does not restore.** The node raises an alarm and writes an audit record. A learner half starts the audited re-learn of D4-26. A detector half is rebuilt from the acknowledged baseline, which is stored and hashed, so only the open windows and holds are lost, and the alarm says so (C5 on #367). The node never falls back to an older checkpoint.
3. **Where D4-30 stands.** C4's option (a) is approved in direction (#364, comment 6476462128), with C5's layout of one self-contained record per half and a floor of about 8 MiB per asset. Six conditions apply. The C10 0.2 ceilings and the measured maximal-case figures are recorded when that PR merges. *(Recorded in D4-38.)*

## D4-33: "Phase 4 done" means all six items (owner, 2026-10-28)

- **The answer.** At 18:10Z the owner answered the question asked at 15:40Z: "means all phase 4 items". Phase 4 is done only when all six items in [the Phase 4 briefs](../agent-handoffs.md#phase-4-task-briefs-issued-2026-10-27) are done, not at the first exit gate.
- **What stays the same.** The first exit gate (items 1 and 2) is still a checkpoint, and C1 still writes `docs/phase-4a-exit.md` for it. Passing it does not close Phase 4.
- **The rest of the order.** Items 3 to 6 follow in the order of the briefs. Each is briefed only after the previous gate passes, and IDS (item 4) waits until the owner names the sites' protocols.

## D4-34: Phase 4 goes item by item, with the owner's check at the end of each (owner, 2026-10-28)

- **What the owner said.** At 18:11Z: "work on them item by item". At 18:12Z: "stop at the end of each item to check with me".
- **The rule.** Each Phase 4 item is finished, gated and reported before the next one starts. At the end of each item, C1 reports to the owner and waits for their go before any agent starts the next item's briefing, contracts or code. An agent with nothing queued for the current item does reviews, verification or preparation for it, and does not start work on a later item.
- **Items 1 and 2 finish together.** These two were briefed together, under one gate, because they share the store and the audit chain. At 18:14Z the owner chose "Finish 1 and 2 together" on C1's decision card. They pass the first exit gate as one unit, and C1 checks with the owner at that gate. From item 3 on, each item is briefed, built, gated and checked with the owner before the next starts.

## D4-35: the acknowledgement window, tightened (C8 0.8, #346)

Date: 2026-10-28. C1, on C3's push `f8c615d` to #346, confirming C3's tightening of the D4-26 amendment (the acknowledgement window).

- **The rule.** When `recs` holds a `config.baseline_recorded` of the asset before a succeeded event acknowledgement stamped 0.8 or later, that acknowledgement must name the digest of the asset's latest such recording before it. When `recs` holds no recording of the asset before it, the acknowledgement is refused only if `recs` holds the asset's version-1 recording, as the amendment says.
- **What it replaces.** The amendment's "otherwise refuse only a digest that a recording inside `recs` has replaced". A recording inside the window replaced whatever was current then, so no other digest can be the current baseline, whether or not `recs` names it.
- **The race.** A person who acknowledges a baseline that a re-learn has just replaced is refused, and acknowledges again against the baseline they now see. This fails closed, as D4-20's race does.

## D4-36: follow-ups to D4-31 and D4-32 (C6's reviews of #367)

Date: 2026-11-01. C1, on C6's reviews of #367 (at `8b6c9d7` and `ccf3a8d`).

1. **`seed_1` is classified (D4-31, HR-11).** The `TestUnknownSpentAcrossRestarts/seed_1` failure on #346's `95b91cd` was a defect in role 6's test, not a product fault. The loss detector read the counts before the goroutine stacks, so a commit that ended between the two reads looked like a held message, and its idle counter never reset on an unheld poll. #366 fixes the test (merged as `cf856e1`, accepted by C4 as the receiver's owner), and F-018 in `docs/verification.md` records it. HR-11's row (#352) now waits only on D4-21's criterion.
2. **"The checkpoint the node would restore" (D4-32 item 2) means the newest committed checkpoint of that half and asset, chosen by commit order and without decoding it.** This is C6's reading (a). When the newest committed checkpoint does not restore, the older one is still removable once the cursor has been saved after the newer commit. The node raises the alarm and rebuilds or re-learns as D4-32 says, and never falls back. C6's C5 0.7 contract tests pin this with a case in which the newest checkpoint is committed and corrupt.
3. **What a detector rebuild repeats (D4-32 item 2).** A detector rebuilt from the acknowledged baseline loses `newSeen`, the pair holds and the per-hold counts. So a new type that alarmed before the rebuild alarms again when next seen, and a (rule, type) pair can alarm again inside its `alarm_hold_s` and pass `max_alarms_per_hold` across the rebuild. This is the stated failure behaviour. The rebuild alarm names both effects, and V-M4's accounting does not count those repeats as detector faults.
4. **The record.** The owner merged #367 at `643f444` on 2026-11-01. C6 had reviewed it up to `ccf3a8d`, so C6 reviews D4-34's completion (`f0a93eb`) and D4-35 (`643f444`) after the merge. Any finding is fixed by a later entry.

## D4-37: a missed series that cannot be written holds its entry's runs (#372)

Date: 2026-11-01. C1, on C6's review of #372 at `4345404` (comment 6557514234) and C3's trust-boundary review (comment 6557260079).

- **The finding.** The SER stream is class `adapter-evidence` and `platform/health` is class `platform`, each with its own quota. `cannotKeep` checks only `adapter-evidence`. So while `platform` is full and `adapter-evidence` has room, runs are still sent. The next read's SER rows commit, and that ends the missed series before its `collection.missed` was stored. The feeder then learns the catch-up backlog as on time, which is the case #372 exists to close. Because the two classes fill at different rates, this is a configuration-dependent steady state, not a race inside one run.
- **The ruling: fail closed (C6's recommendation).** While an entry's missed series is unwritten, the node sends no run of that entry. Each held slot joins the series, so `first_at` stays the first slot's time. The node retries the write, and runs resume once the record is stored. Keeping the series past a stored read is refused, because the record would then reach the feeder after the rows.
- **Why.** A run sent while `platform` is full also loses its own `collection.run`, so the node would contact the device without recording what it did. Holding the run is the same behaviour as `AlarmNoQuarantineRoom` when `adapter-evidence` is full. The device keeps its records in its own buffer during the hold.
- **Observable (P5).** The hold raises one status alarm per series, naming the schedule entry. Once the record is stored, a later hold raises it again. Status alarms are a list of recent events, so this is not a current-state field like `runs_held`. A refused `collection.missed` is never silent.
- **Tests C6 asked for.** The probe's scenario is a test: `platform` full, a missed slot, then a held run, then room and the record stored before any row. Assertions cover `first_at`, the first slot's request ID (`request_id`) and the alarm on a series of two slots, a run whose own `collection.*` append is refused counting as missed, and the hold alarm (C6's X1, X10 and X14 to X16). Under the hold no later slot sends a request, so the record carries one request ID, and C6's X8 and X9 no longer apply (C5 on #374).
- **Limitation.** A long hold can let the device's SER buffer wrap before collection resumes. That buffer's depth is `documented-untested`, and the same limit already applies under `AlarmNoQuarantineRoom`. This is recorded in the Phase 4a exit report.

## D4-38: C10 0.2 merged, and D4-30's figures (#369)

Date: 2026-11-01. C1, at the merge of #369 (`53f9b1a`), recording what D4-30 item 3 left for that merge.

- **The amendment.** D4-30 option (a) is in force. C10's `MaxTypesCeiling` is 512, down from 4096. A record stamped 0.1 is still read under 0.1's 4096 (`MaxTypesCeiling01`), and `Params.Validate` checks parameters as 0.2 states them. The learner refuses `repeats_n` above 31. Its distinct gap lengths are capped at 16,384 across all types and 4096 for any one type, and its gaps at 256. The detector holds digests as 16-byte SHA-256 prefixes, with 2048 new-type keys, 512 new-type pairs, 2048 held IDs and 16 streams. `MaxSnapshotBytes` is 1.25 MiB (1,310,720 B).
- **The measured figures** (`TestSnapshotMaximalCase`, `simulated`, CI green on `cc7db85`). The widest learner state is 1,167,117 B and the widest detector state is 910,592 B. Both are within `MaxSnapshotBytes`. That limit is within the 1,323,008 B one checkpoint record leaves: `ConfigRecordBytes` less 64 KiB of headroom, a 16 KiB envelope allowance and the feeder's own state. The envelope allowance holds only if slice 1c carries the snapshot raw as the record's capture, not as base64 (C5's condition).
- **The six conditions** from C1's approval on #364 are met: C5 agrees, the contract process was followed, there is a maximal-case test, the coverage limit is stated, C3 reviewed the digests, and a `repeats_n` above 31 is refused.
- **Open item.** An SEL-400 series relay can have as many as 250 SER points, so about 507 types, at the ceiling (400-Series IM p. 9.31, `documented-untested`; C2 on #369). Revisit 512 before a 400-series adapter is briefed. Until then, `counts.types_overflow` above zero shows an asset that is only partly baselined, and C5 reports it in slice 1d.

## D4-39: C5 0.7 approved; the validator's signature, and the order of rule 3 (#375)

Date: 2026-11-04. C1, approving C5's proposal `docs/phase4/C5-c5-0.7.md` at `243c4f8` (merged as `b7ca5ea`). The answers were given on 2026-11-01 (comment 6557751838). Reviewers: C2 and C4 as consumers, C3 for retention, C6 for the contract tests (D4-32 item 1).

1. **Changing `DocumentValidator`'s signature is acceptable in 0.7.** The compatibility rule in `contracts/README.md` protects what one binary reads from another: identified messages and stored records. `DocumentValidator` is an in-process hook, and the store and the node that inject it are built into one binary. Its only implementation is the node's `ConfigDocuments`. What crosses versions is the stored data, and that change is additive: two new columns, empty on a pre-0.7 record, which the remover refuses. The conditions are that the 0.7 doc comment states the change, so it is not read as a precedent for messages, and that C6's cross-version test pins section 4 of the proposal, including the rollback note.
2. **D4-20 rule 3 goes into C5 0.7 with the checkpoint, and both land before the Phase 4a gate.** Without them, every scheduled read and every checkpoint stays in the configuration class until its quota fills (R1.8). The PRs follow the order in section 6 of the proposal. Slice 1c's node work does not wait for rule 3. If rule 3 is slower, the checkpoint writer, restore and removal go first.
3. **What the reviews narrowed.** `RemoveConfig` takes one series and accepts only `RemovableSeries`: `config.snapshot`, `eventcheckpoint.learner` and `eventcheckpoint.detector`. So no difference and no baseline of either kind can be removed through it (C3, C4). Kind and series form a closed table that `DocumentInfo.Validate` enforces (C3). A configuration baseline is a C9 snapshot held by its `baseline` hold, so `baseline.configuration` is never written (C2). A finished learner's last checkpoint is the newest of its series and stays until the next re-learn (C4). At start, the node replays each asset's last `config.reads_removed` (C3).

## D4-40: what the first gate still needs, who builds it, and the V-M3 and V-M4 rulings

Date: 2026-11-04. C1, on C6's gate-run needs (`/mnt/project-files/c6/gate-run-needs.md`, checked against `main` at `68e3d57`).

1. **The finding.** The contracts for items 1 and 2 are merged, but the binaries do not yet do what V-M2 and V-M4 test:
   - no scheduled configuration read stores a C9 snapshot or difference;
   - the node writes none of C8's configuration records;
   - no code outside `contracts/` handles the signed kinds `node.change_approval` and `node.baseline_ack`;
   - no learner ends in a recorded baseline that is acknowledged and then activated;
   - no detector runs in the node.

   The gate waits for these. Nothing here changes the gate's criteria.
2. **Who builds what.** C5 holds most of this path, so part of the node work moves, by C1's explicit authorization under brief 5.3. C5 stays the reviewer of every change under `platform/`.
   - **C5 (P4-A5).** C5 0.7, store and node (D4-39). The configuration-read writer: a scheduled `sel.config.read_all` stores its C9 snapshot with the transcript as capture, compares it with the acknowledged baseline, and stores the difference. The node's C8 configuration records, the `unapproved_change` alarm and the hold fold. The node side of the two signed kinds. Feeder slice 1c.
   - **C3 (P4-A3).** The collector side of the two signed kinds: verify, cap the window, assign `collector_seq`, and refuse a non-approver. C3 agrees the node interface with C5 before either side is built. The relay's widening for those kinds (`relayKinds` and `nodeActKinds` in `platform/node/adminrelay.go`) is C5's, with the node side (C3 on #380).
   - **C4 (P4-A4), authorized for `platform/node`.** The event-baseline lifecycle and the detector in the node: the learner's end in a C10 baseline and its `config.baseline_recorded`, activation once its `node.baseline_ack` is recorded, and the detector's alarms to the health stream with rule, baseline value, parameters, observation and event IDs. This goes in new files beside `eventbaselines_feed.go`. C5 reviews as owner of `platform/`, C6 for reliability and C3 for the trust boundary. Slice 1d's status and health counts are C4's here too.
   - **C2.** Reviews the configuration-read writer as C9's owner.
   - **C6.** The V-M3 desk half now, the test clock below, and the gate runs.
3. **V-M3 for the SEL-751.** Rung 3 (`SHO` over Telnet) is the SEL-751's only built rung. Rung 1 is absent, and rung 2 waits for hardware test Q3 (ADR-0008 decision 4). So no lower rung exists to name, and no rung-selection code is built now. That code is built with the second rung, not before (simplicity). The "refused at start" case is recorded as vacuous for the SEL-751, with one test that is not vacuous: a node configuration that tries to choose a configuration method, for example FTP, is refused at start, because the node configuration has no such field and refuses fields it does not know. C6's desk check of every SEL-751 matrix cell against its citation stands as the other half.
4. **V-M4's clock: C6's option (a), with a short untagged case.**
   - **The test clock.** It is test-only and lives behind a build tag (`otsec_testclock`), so a build without the tag has no code path to it. The harness drives it, the simulator stamps on it, and the whole GT-INJ series runs with every rule.
   - **A check on the release build.** CI checks that a build without the tag refuses the clock's control (the flag or variable is unknown), so a production binary cannot be driven.
   - **The untagged binary.** A short-period case on the untagged binary covers the lifecycle and the event-driven rules, so the untagged binary is shown too.
   - **The record.** The exit report says which runs used the tagged build.
   - **Who builds it.** C6, by C1's authorization. It is limited to one tagged file and its hook in `cmd/otsec` and `platform/node`, with C5 reviewing as owner, and one tagged file and its hook in `cmd/otsec-collector`, with C3 reviewing as owner. The collector needs it because SER received time is stamped there (`modules/security/collector/runner_sel751.go`, the runner's `Now`). No `modules/` change is authorized. The clock is stepped, not scaled, so the D4-24 and `run_deadline_ms` deadlines do not fire falsely. The release-build check covers both binaries.
5. **On C5's review of #380.**
   - **The seam.** C4 owns the per-asset learner and detector state. Slice 1c snapshots and restores through C4's interface and holds no copy of its own. C4 and C5 agree that seam before either side builds it.
   - **The clock.** The test clock drives everything that waits, not only `Now`: the scheduler's timer, the service tickers and any deadline the GT-INJ series crosses.
   - **C5's order.** First the C5 0.7 store, then the configuration-read writer with the C8 records, alarm and fold. Slice 1c follows, then the node side of the signed kinds, and rule 3 last.
6. **The audit record D4-32 names for a checkpoint that does not restore: C8 0.9 adds `config.checkpoint_not_restored`** (C5 and C4, 2026-11-04). It is node-written, its Target is the asset, and its kind is `event`. It carries:
   - the half (`learner` or `detector`);
   - an error class from a closed set (`corrupt`, `version`, `mismatch`, `refused`);
   - the checkpoint's seq;
   - for a learner, the version and previous digest of the re-learn it starts.

   C3 drafts it as C8's owner. C5 and C4 review as writers, and C6 writes the contract tests. Until it merges, slice 1c raises the alarm and the health event only, and does not claim D4-32's audit. The first gate needs the record.

   In C3's draft, the error class is the `reason_code`, with outcome `warning`. The detector half also carries `baseline_digest`, which names the acknowledged event baseline the detector is rebuilt from. It is not read from the failed checkpoint, which may not decode. `VerifyConfig` checks it against the asset's latest succeeded event acknowledgement, and a checkpoint that decodes but names another baseline gets the reason code `mismatch` (C3). C1 accepts both.
7. **How the node gets the register that `config.FromResult` renders from: option (a) of #383.** The node loads and verifies the signed register envelope it was commissioned with, against anchors in its own configuration. Option (b), lines taken from the rule's classes, is refused. It needs a C9 change, and it drops the check that the run is the register's: the rule would restate the register's order. A reordered run would still fail closed, not mislabel, because `CheckAgainst` requires each section's command before its span (C2 on #383, correcting C1). Option (c), the snapshot built in the collector, is refused because it adds parsing to the privileged process. C3 passes (a) on the trust boundary. Its conditions:
   1. The node refuses at start an envelope that fails verification, and a register whose version is not the commissioned `register_version`.
   2. The node pins the payload's SHA-256 in its configuration and refuses any other bytes, because a revision number does not identify the bytes (C3's A2; C1 chose the pin over a status display, because the pin fails closed).
   3. The node uses its copy only to build snapshots. One direction only: the package and its anchors come from the node's own configuration, never from the collector, and nothing derived from them goes to the collector (C3's A1).
   4. A read whose record count, or any line, does not match the rendered run fails the read, with no partial snapshot. A node test pins this.
   5. On a version mismatch between node and collector, the collector refuses the run, and a test pins that too.
   6. The node refuses a result whose `register_version` is not the revision it loaded (C2).
8. **`VerifyConfig` on a pruned audit stream (C3's B1 on #384): option (a).** The node prunes its audit stream once records are forwarded upstream. So at start it holds only a retained view, and `VerifyConfig` on that view fails, which would stop every observed asset after the first prune. C8 0.9 adds `VerifyConfigFrom`, which treats a reference to a record before the view as unknown, not broken. This is the same reading the D4-26 amendment gives recordings. The conditions:
   1. The view starts at the node's recorded prune point, not at whichever record happens to be first. Inside the view the hash chain is checked in full, so a record deleted or edited inside the view is still caught.
   2. Only a reference to a seq before the prune point is unknown. A reference into the view that does not resolve is broken.
   3. The full chain stays verifiable upstream, where the records were forwarded before the prune.
   4. Status shows that start-up verification ran from the prune point.

   Option (b), skipping the check on a pruned stream and raising an alarm, is refused as weaker. C3 adds it to the C8 0.9 draft, and C6 tests it. C3's B2, a version-1 recording repeated after recordings are pruned, is C4's to fix in #384.

## D4-41: the active event baseline after its acknowledgement is pruned (C4 on #387)

Date: 2026-11-04. C1, on C4's question on #387.

- **The fact.** The node prunes its audit stream (`Runtime.Prune` passes over every open database, the audit database included). It prunes only a class above its target, and only records its consumers have confirmed upstream (`platform/node/prune.go`). So a prune can remove an asset's last succeeded event acknowledgement while its later `config.baseline_recorded` stays. The node then cannot tell from the audit view which baseline is active, and the asset would restart awaiting acknowledgement with its detector off.
- **The ruling.** The node finds the active baseline of each kind from the configuration store's `baseline` hold (C5 0.7, D4-39: the fold holds each kind's acknowledged baseline with `baseline`, and `Ref` is its `config.baseline_acknowledged`). The configuration class is never pruned of a held record, so the hold outlives the audit prune.
  - When that `Ref` lies before the audit view's prune point, it is unknown, not broken, under D4-40 item 8.
  - When it lies inside the view, the record it names must be a succeeded acknowledgement of that asset, kind and digest, or start-up verification fails.
- **Refused.** C4's option (a), an audit prune that keeps the latest acknowledgements: it would leave records before the prune point, outside D4-40 item 8's contiguous view. C4's option (b), a record restating the active baselines at each prune: it would add a node-written claim of what a person acknowledged, which the hold already carries.
- **Who.** C4 reads the hold in #384's start-up fold. C5 confirms that the 0.7 fold sets `baseline` on the event baseline with that `Ref`. C6 tests a prune that removes the acknowledgement while the detector stays active after a restart.
- **C4's two points on #389.**
  1. **Two event `baseline` holds after a prune.** On a pruned view, reconcile adds holds and never releases them, so an asset can hold two. If the view holds a succeeded acknowledgement, that one wins. Otherwise the hold with the highest `Ref.Seq` wins, because commit order is the chain's order.
  2. **The detector's `ActiveFrom` when the acknowledgement was pruned.** A hold does not carry the acknowledgement's time. When the node has no acknowledgement time, the restore takes `ActiveFrom` from the checkpoint, provided it is not before the end of the baseline's own period and not after the restart's watermark. Otherwise the detector is rebuilt and `config.checkpoint_not_restored` is written with `mismatch`. Without this, every restart after the prune would rebuild the detector.

  C4 builds both in #384.
- **C5's points on #389.** C5 confirms that the 0.7 fold holds the event baseline as `baseline`, with `Ref` its `config.baseline_acknowledged` (`TestHoldsAreRebuiltFromAuditAtStart`). The kind is read from the held record's document kind, not from the hold. One gap remains: today the hold is taken only at start, so an acknowledgement and an audit prune in the same run can leave no hold. The rule is that a prune never passes an acknowledgement whose hold is not taken:
  - the node side of `node.baseline_ack` takes the hold right after the acknowledgement's Receipt;
  - at start that order does not hold on `main`: `New` opens the audit database, whose start-up step 6 prunes, before `reconcileHolds` runs (`runtime.go`, C5). So a crash between the Receipt and the hold, followed by a start-up prune, loses the hold;
  - **the fix (C5's): a node-local required consumer on the audit stream, `HoldsConsumer`,** on the `SuspensionConsumer` precedent (`pruneConsumers`). Its cursor is the last audit seq through which every hold the fold wants is taken. The live path advances it after each hold, and reconcile advances it once nothing is missing. Neither the start-up prune nor the runtime prune passes it, and no C5 contract change is needed. A hold that cannot be taken, for example because its baseline document is missing, stops audit pruning and raises an alarm, as `AlarmSuspensionNotDurable` does;
  - C5 builds it with the node side of `node.baseline_ack`. C6 tests both cases: an acknowledgement followed by a prune within one run, and a crash between the Receipt and the hold followed by a start-up prune.

- **C6's G2 on #390: the same rule holds for the configuration baseline.** A prune can remove the acknowledgement of configuration baseline X and keep a later unapproved `config.change_detected` against X. The writer's chain fold then has no baseline, drops the change, and after a restart its `config-unapproved-change` alarm is not raised again. The ruling:
  - In a fold whose view starts after the acknowledgement, the configuration baseline is the one the store holds as `baseline` for that asset. The kind is read from the held record's document kind, and when two are held, the highest `Ref.Seq` wins, as in C4's point 1 above.
  - A `config.change_detected` in the view against that baseline's digest stays open until a record in the view ends it: a restore or a configuration acknowledgement, as in the full fold. An approval never ends an open change, because an approval covers only reads after it in the chain (`approval_seq` < `read_seq`). *(Corrected on C6's review: the first text also named a covering approval, which would make the pruned fold differ from the full one and let a later approval silence an unapproved change.)*
  - A change in the view against any other digest is not open. Its baseline was replaced by an acknowledgement that the prune removed.
  - C5 builds this in #390's chain fold, using the same baseline lookup as `compareConfig`'s pruned check. C6's G2 probe becomes its test: `open` must be the same for the full fold and the pruned fold.

- **How `HoldsConsumer` advances (C5 on #408, accepted by C1).** C5 does not advance the cursor after each hold on the live path. #408 advances it in one check instead, which runs at start after the reconcile and again before each runtime prune of the audit database. The cursor is the last audit seq through which every hold the fold wants is taken. The start-up prune runs before the reconcile, so it uses the cursor persisted by the last check. A crash between an acknowledgement's Receipt and its hold therefore leaves the cursor behind that acknowledgement, and the prune does not pass it. The guarantee is the one stated above. It covers every path that takes a hold: an acknowledgement, the writer's differences and a restore. The check also cannot let an acknowledgement at seq N carry the cursor past a writer record at N-1 whose hold is still being taken. C6's probe P1 releases the writer's hold through the store, because no seam stops it. *(Corrected on C6's and C3's reviews of #408 at 64ac534: on a pruned view the check as first built covered neither the writer's differences (C6's F1, probe P5) nor a restore (C3's B1). The two rules below make the claim hold. #408 does not merge without them.)*
  - **On a pruned view, the fold's configuration baseline is the held one (G2, applied to the holds fold).** Once an asset's configuration acknowledgement has been pruned, `foldHolds` takes that asset's baseline from the store's `baseline` hold, using the same lookup as `compareConfig`'s pruned check and G2: the kind comes from the held record's document kind, and the highest `Ref.Seq` wins. A `config.change_detected` in the view whose `BaselineDigest` is that baseline is then wanted. Its difference holds are counted by `advanceHolds` and taken by the reconcile. Without this rule the fold skips the change (`holds.go:133-136`), the cursor passes it, and the change's evidence can be pruned from both streams, against §1.3 and §1.4.
  - **On a pruned view, the reconcile corrects the codes a restore changed.** A hold coded `approved-difference` or `unapproved-difference` is wanted as `restored-difference` when its `Ref` lies after the held baseline's acknowledgement and before an in-view `config.baseline_restored` of the same asset. `advanceHolds` counts it as a replace and the reconcile applies it. This is justified by a record the node still holds: a prune removes a prefix, so the restore and every record after it are in the view. That is C5's argument for `prunedReplace` on the baseline. Without this rule, a failed re-code is never corrected. A stale `approved-difference` would then put an approved change back in force after its return, and a later repeat of that change outside any window would be read as an approved same-change read, not as a new unapproved detection. That is the outcome D4-43 exists to prevent.
  - **Tests (C5, in #408).**
    - C6's P5, plus C6's variant, in which the restart's reconcile takes the hold and only then does the cursor pass the change record.
    - C3's test: the restore re-code fails once on a pruned stream, the cursor does not pass the `config.baseline_restored` record, and the next start's reconcile corrects the code.
    - C3's three non-blocking mutants are wanted too: `missing` not counted, `through` read after the fold, and a wrong baseline reason on a pruned view. H14 (`through` read after the check) is accepted as untestable without a concurrency seam, because C3 and C6 both read the order as correct.
  - **The permanently missing record (C6 and C3, not blocking).** When a record the fold wants is gone from the configuration store, no reconcile can take its hold, so audit pruning stops for good and the audit class fills to D4-19's stop rule. That is the evidence-preserving failure, and it stands. `AlarmHoldsNotTaken` must say so for that case, and point to `AlarmBaselineNotStored`, rather than say the next start's reconcile takes it. The exit report lists it, and C3 records it as a threat-model residual at the gate.

## D4-42: an oversize configuration difference is recorded without a stored difference (C2 on #392)

Date: 2026-11-04. C1, on section 4 of `docs/phase4/C2-c9-0.4.md` (C9 0.4, #392).

- **The fact.** C2 measured the SEL-751's settings sheets (`contracts/config/testdata/difference_max.py`). A read in which every setting of every form changes makes a difference of 1,615,535 to 1,738,065 bytes, 7.2% to 15.3% over the bound (C2's table, six rows; C1 re-ran `difference_max.py` on `pdftotext -layout` of the manual and got the same six rows). Both snapshots fit, but the difference does not fit `MaxDifferenceBytes` (1,507,328 bytes). A realistic large change fits: 8,500 settings of 30 characters encode to about 1.22 MB. Evidence class: `desk` for the measurement, `simulated` for the tests. C9 0.4 makes the case visible: `Validate` refuses with `ErrTooLarge`, and `Compare` still returns the difference with that error.
- **The ruling: C2's option (a).** Only `Compare`'s own size refusal of the difference takes this path. `ErrTooLarge` alone does not say which document was too large, because a snapshot's size refusal wraps it too (C5 on #392), so the path keys on `ErrDifferenceTooLarge` (#392), which wraps `ErrTooLarge` and comes only with the difference itself. Any other `Compare` error stays `config-not-compared`, because `Compare` returns a zero `Difference` for those. On `ErrDifferenceTooLarge`, the node:
  - records the change as `config.change_detected` with `changes_digest` from the returned difference and no `difference_digest`, plus a field that says the difference was too large to store;
  - raises `config-unapproved-change` as for any change not covered by an approval, with "difference not stored: too large" in its text (my ask to C5 on #390). An approved oversize change raises nothing, the same as any approved change. `collection-evidence-not-stored` would say that evidence was lost, and none is lost, because both snapshots are held and the chain's `difference_too_large` shows the case (C6 on #390, C1);
  - holds the read's snapshot with the same hold the normal path takes (`unapproved-difference`, or `approved-difference` under C5 0.7), only without a difference beside it, so reconcile and rule 3 are unchanged. The baseline is held `baseline`, and `Compare` is a pure function of the two stored snapshots, so the difference can be recomputed whenever it is needed. No evidence is lost.
- **Refused.** Options (b), a difference without values, and (c), one with only the new values. Each changes C9's stored format to cover a case that needs a whole relay reloaded at once. And `changes_digest` would no longer be computable from the stored difference alone.
- **What stays unchanged.** Approval (`node.change_approval`) names a baseline and a window, not a difference, and acknowledging the read as the new baseline names its snapshot digest. So an oversize change can be approved and acknowledged like any other. `config.read_compared` with `same_change` already names a change by `changes_digest`.
- **Who.**
  - C3 builds the C8 change as C8 0.10 (#393): `difference_too_large`, a boolean on `config.change_detected` only. From 0.10 a detection carries `difference_digest` exactly when that field is absent. `VerifyConfig` reads audit records only, and no chain rule names `difference_digest`, so a too-large detection verifies as any other (C3). The check that the change is the one recorded is a store check: `Compare(baseline, snapshot).ChangesDigest()` equals `changes_digest`. It belongs to C6's tests and to an auditor, not to `VerifyConfig`.
  - **Upgrade order.** A 0.9 reader refuses a 0.10 record with `difference_too_large`, because it still requires `difference_digest`. That fails closed. So every reader of a chain must be at 0.10 before a node writes the field. Both binaries ship in one release, so a forward upgrade meets this. A rollback below 0.10 after such a record is written fails start-up verification closed. This goes in the rollback note with C5 0.7's, and in the exit report's open items.
  - C5 builds the node side in #390, switching `encodeDifference` to `Difference.Encode` once #392 merges. The fold's `wants()` (`platform/node/holds.go`) skips an empty difference digest, so a too-large detection asks for no difference hold (C3). #390 merges only after C8 0.10 and #392, so `main` never writes a `difference_digest` that names a difference that was not stored (C5's interim 0.9 record at fbbcbf5).
  - C6 tests: an every-setting change that is alarmed and recorded with no stored difference; the store check, a `changes_digest` that equals `Compare` re-run on the two held snapshots; a realistic large change that is still stored as a difference; and C3's restart case, in which reconcile does not report the unstored difference as `config-baseline-not-stored`.
  - C9 0.4 (#392) needs nothing more.

## D4-43: a restore after a pruned approved change (C3 and C5 on #390)

Date: 2026-11-04. C1, on the residual C3 found and C5 sized on #390. This amends D4-19.

- **The case.** An approved change is recorded, the audit stream is pruned past it, and the device is then reverted to the baseline. The writer's pruned fold does not know the approved change as the asset's last change, so it records the revert as `config.read_compared` `no_difference` instead of `config.baseline_restored`. No alarm is silenced and no evidence is released. But the full chain refuses a `no_difference` where a restore is due. So every approved maintenance change that is later reverted after a prune would give the auditor a chain-verification failure that is not an attack.
- **The ruling: fix it in #390, not with HoldsConsumer.** A verification failure in normal operation teaches people to ignore verification failures. The fix costs about what C3's B3 did.
  - In a pruned fold, when no later change is in the view, the writer takes the last change from the asset's held differences in B3's window: after the held baseline's acknowledgement and before the fold's first record. The last change is the newest such hold of either code, `approved-difference` or `unapproved-difference`, taken by `Ref` (C3 on #397).
  - A restore re-codes the `approved-difference` holds of the changes approved since the baseline's acknowledgement as `restored-difference` (C5 on #397). An approved change against an earlier baseline keeps its code, even when that baseline had the same digest (acknowledge X, then Y, then X again). The re-coding happens in the writer and in the start-up reconcile's `returned`. This extends D4-19, which re-codes only unapproved ones. The evidence stays held, as D4-19 requires. The holds table then shows that the change ended in a restore, and the chain still shows that it was approved.
- **Who.** C5 builds it in #390, with a test that prunes past an approved change, reverts, and checks that the result is `config.baseline_restored` and that `VerifyConfig` accepts the full chain. C6 adds the case to the re-check. C3 reviews it.

## D4-44: the Windows package timeout is 30 minutes, and the 12-minute budget is breached (C5 on #406)

Date: 2026-11-04. C1, on C5's report from #406 at 7df03de (CI-Windows runs 41866643125 and 41865420446).

- **What failed.** `go (windows-latest)` failed because `platform/node` reached the step's `-timeout 20m` at 1200 s. No test failed. The goroutine that was running sat in SQLite's `FlushFileBuffers`, the same place as F-016 and D4-22. On that runner, packages the PR does not touch slowed by about 2×: `platform/store` took 333 s, against 150 s on the previous head, and the collector took 447 s, against 236 s. So the cause is the runner's disk, as in D4-22.
- **The budget was already breached.** D4-22 set 12 minutes (720 s) as the budget for `platform/node` on a green Windows run. A normal run at f4ae324 took 815 s, already over that budget, and the gate PRs (#405, #406, #408) add tests on top. D4-22's 720 s warning step was never built.
- **Decision.**
  1. The Windows `go test ./...` step runs with `-timeout 30m`, and the Windows job limit goes from 35 to 45 minutes. As in D4-22, `go test` starts about 3.5 minutes into the job, so a hang dumps its stacks at about 34 minutes, with room for a late start. Linux is unchanged. This replaces D4-22 item 1's 20 minutes and 35-minute job limit.
  2. **The 12-minute budget stands, and the breach is a finding for C5 under F-016.** After the three gate pieces, C5 reports the ten slowest `platform/node` tests on Windows and cuts their fixture time until a green run is back under 720 s. C5 also builds D4-22's warning step. The exit report lists the breach as open until then.
  3. D4-22 item 4 still holds. A run that reaches 30 minutes is real, never a flake.
- **Owners.** C1 makes the `ci.yml` change in this PR, and C5 and C6 review it. C5 owns item 2.

## D4-45: an event baseline's period ends at a point fixed by its input (C6's F-020 on #411)

Date: 2026-11-04. C1, on C6's F-020 (`docs/verification.md`, #411).

- **The fact.** Two V-M4 runs fed the same `gt-inj-syslog` series and learnt different baselines. One period ended at 00:58:12Z with 774 events, the other at 04:03:10Z with 780. The cause is in `eventLife.Tick`: the learner finishes at the watermark of the first feeder step that finds both minima met (`Learner.Finish(at)`). When that step runs depends on the scheduler, not only on the events.
  - On the test clock, the step can come hours late.
  - On a real clock, C6 reads the drift as about one step plus `FeedLateness` (15 s + 2 min). That is a reading of the code, not a measurement.
  - No alarm changed in this series. The record states the period and counts it actually learnt, so an acknowledgement still names exactly what it accepts.
- **The ruling.** The same input, meaning the same events and the same gaps in the same order, gives the same baseline bytes. The period's end is a function of that input, never of when the scheduler runs (principle 6). It is a gate item for Phase 4 items 1 and 2, because V-M4 measures this detector.
  - **The shape (C4 and C5 choose the code).** The period ends at the first instant at which both minima hold, given the events and gaps fed so far. Nothing fed after that instant is counted in the baseline. The feeder already releases events and gaps in order up to its watermark, so the instant can be found when the first event past it is released, or when the watermark passes it with no such event.
  - **The two edges (C6 on #412).**
    1. **An event at exactly T is counted.** Every event whose time is at or before T (≤ T) is in the baseline, and every event after T (> T) is not. T can be the time of the event that meets the event minimum, and that event must count. Events at the same whole second are all taken, whichever order the feeder releases them in.
    2. **T is not final while a gap that began at or before it is open.** The feeder releases a gap only when it closes, so a watermark past T does not finish the period while a collection gap that began at or before T is still open. Once that gap is fed, T is computed again, and a gap moves it later. A gap that begins after T does not change it. The mechanism is C5's wording: a gap still open counts as not collected from its start, so the feeder passes the open gap's start to the learner on `Observe` and `Tick`. That is C4's condition (the watermark never passes the start of a gap not yet fed), stated as a rule on the end.
  - **Order.** C5's plumbing PR goes first. C4's learner change and the version bump follow.
  - **Tests.** C4: `Tick` at three cadences over the same input gives the same `Finish` bytes, plus an event at exactly T and a gap open across T. C5: a restart between T and the record gives the same bytes.
  - **The learner's version.** It changes what a learnt baseline covers, so `LearnerVersion` goes up and C10's learner field carries it. No other C10 change is expected. If one is needed, C4 brings it to C1 first.
- **Who.**
  - C4 changes `modules/detection/eventbaseline`.
  - C5 changes the feeder's call in `platform/node`.
  - C6 extends the repeat run in `test_slice_gtinj_feed_e2e.py` to compare the two baselines byte for byte, as well as the alarms, and closes F-020 on that.
  - If C4 and C5 cost the change at more than one small PR each, they say so before building, and C1 decides again.
- **Two limitations, accepted (C5 on #414, C6's F-021).** Both arise only from a fault (a restart, or a late collection record), and through that fault the end can depend on timing. Without such a fault the end is fixed by the input. The record still states the period it learnt. *(Worded on C5's review of #416.)*
  - **A restart's gap.** It starts at the checkpoint's watermark (`restarted`, #372). When T is set by the duration minimum, a restart after T whose last checkpoint lies before T moves the end later, so the bytes depend on where the last checkpoint fell. The learner really did not durably see that interval, so the gap is part of the input. `restarted` stays as it is.
  - **A late `collection.missed` (F-021).** A record committed more than `FeedLateness` after its series' `first_at` has its gap start clamped to the watermark. Its start then depends on the cadence, and events after the old T may be refused before the gap would have moved T later. Neither `Late` nor `Refused` counts it. The sign is the `evidence.not_stored` alarm raised while the record was not stored (D4-37). *(Corrected on C6's review of #416.)* It stays a limitation unless a measurement shows it happens outside a fault.

## D4-46: a non-semantic configuration change stores both snapshots and no difference (C6 on V-M2)

Date: 2026-11-04. C1, on C6's first V-M2 run on the real binaries.

- **The fact.** For the three non-semantic changes in V-M2's series (a SHO layout change only), the node writes `config.read_compared` with `no_difference`. It stores both snapshots, and it writes no difference record. `tests/integration/gt_inj/config.json` lists "difference R0 to R1" under `expect.stored` for those three, and V-M2's pass condition says the difference is stored in every case.
- **The ruling: the product is right, and the test reads the oracle that way.**
  - Under R3.3, a change of layout alone is no difference. C9's `Compare` returns none, so there is no difference to store. Storing an empty difference would record that a change happened when none did.
  - Both snapshots are stored, and they differ byte for byte, so the layout change can be recovered from them while the read is retained. Under D4-20 rule 3, a no-difference read is removable once two newer ones are stored, and the baseline's transcript is then the only layout kept. D4-20's amendment already accepts that. The removal (`config.reads_removed`) is not built in the node yet, which is why both snapshots are still present today. V-M2 checks the second snapshot while the read is retained and must not treat its presence as permanent. *(Worded on C5's review of #419.)*
  - **When `no_difference` applies.** The node compares a read with the acknowledged baseline, never with the previous read. It writes `no_difference` only when no change is held for the asset. When a change is open or approved, a layout-only read gives `config.baseline_restored` if its settings equal the baseline's, or `same_change` if its `Changes` equal the held change's (`configread.go:187`, `:195`). This ruling covers a non-semantic read against the baseline with no change held. C6 confirms that each of V-M2's three non-semantic reads comes at such a point in the series.
  - For a non-semantic change, the V-M2 test therefore requires all of the following: both snapshots stored, the two snapshots' bytes different, `no_difference` in `config.read_compared`, and no difference record. That is how C1 reads "the difference is stored" when there is none.
- **`config.json` is not edited.** The GT-INJ README says a series changed after a product run is a new series. Changing an `expect` field to match the product's output would be fitting the oracle to the product. This ruling is therefore an interpretation, recorded here and not in the file, and the exit report lists it as made after a product run.
- **Who.** C6 builds the test this way and cites D4-46. C6 may add the V-M2 leg to the `integration-long` matrix in `ci.yml`, a one-line edit in C1's file that this ruling authorizes. C1 reviews it as the owner.

## D4-47: V-M4's SER half runs on a new GT-INJ SER series whose reads respect the 60 s floor (C6)

Date: 2026-11-04. C1, on C6's finding while building V-M4's SER half.

- **The fact.** `gt-inj-ser` gives each SER row a received time, and for SER the received time is the read time. 387 of its 1,025 gaps between distinct received times are under 60 s, and the smallest is 1 s. The node and the collector each keep SER sessions at least 60 s apart: the node through `MinIntervalSeconds` = 60 and the schedule's quiet time, and the collector through `min_interval_ms` = 60000 and `State.CheckInterval`. So no harness can give those reads their own received times. C4's in-process `gtinj_test` feeds rows straight to the detector, so it never met the floor. The series describes reads that a correctly configured node can never make.
- **The ruling: C6's option (a).**
  - C6 regenerates the SER series with `generate.py`, so that every received time is a read time the node's schedule can produce, at least 60 s after the previous one. The next read is at max(t, previous read + 60 s), and it takes every row up to that time. The event types and the injected departures stay as the generator defines them. The series carries received times only, so no SER event time is changed. The README states each asset's expected D4-45 end and event count. *(Worded on C6's and C4's reviews of #424.)*
  - The new series goes in its own file, under its own asset name. `events.json`, `events-heldout.json` and `config.json` stay byte-identical.
  - The generator re-derives `expected_alarms` from the new rows by its own reading, before any product test runs against the new series.
  - A product test (`gtinj_test`) has already run against `gt-inj-ser`, so under the README's rule this is a new GT-INJ series. It gets a new name, and the README records why: the 60 s read floor. The old series stays in the repository, marked as superseded for the SER path, so the history of what ran is kept.
  - C4 reviews the new series and its expected alarms, and re-runs `gtinj_test` on it. Any difference between the generator's alarms and the detector's goes to C1 before the harness is built on top.
- **Refused.** Option (b), a test-build-only lower minimum interval in the node and the collector, would put a test switch on the OT safety floor of how often a device is read. The floor is the safety property here, not an obstacle. Option (c), leaving the SER half open, would leave recall for `new`, `time` and `rate` unshown on the slice's main device path.
- **Order.** Two PRs, both C6's: first the new series with its README entry, reviewed by C4; then the SER harness (a file-driven SER buffer in the simulator, a `slicehelper` flag for the slice asset's event baseline, the collector on the test clock, and signed requests stamped `-issued` at clock time), reviewed by C4 and C5. The SER leg goes into `ci.yml` under this ruling, and C1 reviews that line.

## D4-48: the owner accepts Phase 4 items 1 and 2, and item 3 is issued (owner, 2026-11-05)

Date: 2026-11-05. The owner, on C1's decision card after `docs/phase-4a-exit.md` merged (#429).

- **The acceptance.** The owner chose "Accept, start item 3" at 04:01Z. Items 1 and 2 are accepted with the conditions in `docs/phase-4a-exit.md`, which carry into item 3 as recorded there.
- **Item 3 is issued** as Stage A (investigation and contract drafts), in `docs/agent-handoffs.md` ("Phase 4 item 3: Stage A briefs"). Its implementation briefs and its exit gate follow C1's approval of the contracts, under §5.4 and the common rules for every Phase 4 brief.
- **D4-34 stands.** Work stops at the end of item 3 for the owner's check.

## D4-49: answers to C6's item 3 testability questions, and F1 (C6, #436)

Date: 2026-11-05. C1, on `docs/phase4/C6-item3-testability.md` (#436), before any item 3 contract is approved. The thresholds of V-M1, V-M7 and V-M8 are not changed. Every answer below is C6's proposed reading, accepted unless stated otherwise. The contract drafts (C1 0.3, C3 0.4, C11, C12) carry them.

- **Q1. The engine ID is pinned.** It is part of a device's SNMPv3 credential. A discovered engine ID that differs is refused with its own health code, and the client never re-localizes keys to it (C2 in C3 0.4, C3 in the key register row).
- **Q2. No algorithm fallback.** The client uses only the algorithms configured for the device. C3 rules which algorithms may be configured at all. Unless C3 shows a reason otherwise, DES and MD5 are refused. GT-MIB offers the refused algorithms as negative cases.
- **Q3. No v1 or v2c path in item 3.** V-M1 (d) is shown for the refusal alone, and the item 3 gate says so, as D4-40 point 3 did for V-M3.
- **Q4. One source vocabulary.** C1 0.3 stores a kind (`device-read`, `passive` or `operator`) and, for `device-read`, the read path (`snmpv3`, `sel.id`, ...) and an evidence ID. V-M1 (e) checks the path, and V-M7 checks the kind.
- **Q5. A precondition read as false:**
  - with a device-read identity, `not-applicable`, citing the settings read;
  - `mitigated` only when the advisory itself names that setting as a mitigation;
  - with an operator or passive identity, `applicable-by-version`, with the precondition shown as evidenced false.
- **Q6. Precedence and staleness:**
  - (i) All preconditions hold and a mitigation is evidenced: `mitigated`.
  - (ii) A `confirmed` finding whose evidence is no longer current falls to `applicable-by-version` and names the stale evidence.
  - (iii) A passive identity out of range gives `not-applicable (passive)`, a label C12 allows.
  - (iv) An advisory with no preconditions is `confirmed` on a current device-read version. Any configuration change retrieved for the asset makes every `confirmed` finding on it stale until the next identity read.
- **Q7. When evaluation runs.** Evaluation runs after each commit of an identity, settings or configuration record for the asset, and after each set replacement. The finding's change is stored before the asset's next scheduled read starts.
- **Q8 to Q11** as proposed. A same-version set is refused unless byte-identical, and a byte-identical one is a no-op. An entry with no published source refuses the whole set.
- **Q12** as proposed: the ports are fixed for the paired runs, and the comparison covers every destination. C6 runs an A/A pair first. If packet counts differ between identical runs, C6 brings C1 the measured difference before anything changes.
- **F1. No `ID` session on a denied SEL-751 branch.** The firmware gate (ADR-0005, F-009) refuses every session on a firmware line not on the allowlist, because communications access is where the restart defect lies. A session that only reads `ID` is still a session. So R302 and older stay `operator` identity only, and can never be `confirmed`. This is recorded as an item 3 limitation, and GT-ADV pins it with denied-branch rows. The item 3 brief is corrected: V-M7 reaches every class on the SEL-751 only for allowlisted FIDs.

## D4-50: SNMPv3 runs in the collector; the module combinations; V-M8's upstream flow (C3 on #435, C5 on #438)

Date: 2026-11-05. C1.

- **USM keys and the SNMP session belong to the privileged collector** (C3), as every device credential and device session does (ADR-0002). The node's asset module schedules reads and records identities, and opens no SNMP socket. The collector executes the read under the register's limits. D4-49 Q1's pinned engine ID is held with the collector's credential. The P4-3-A3 brief is corrected to match.
- **Applicability needs the asset module** (C5's proposal on #438). A node configuration that enables applicability without the asset module is refused at load. "Independently enabled" (R1.8) therefore means three supported combinations: both off, asset alone, and both on. V-M1 (a) is tested with the asset module off, which turns applicability off too.
- **V-M8's flows** (C5 and C6). The upstream forwarder's flow exists in both paired runs. Its volume may differ, because the R9 run forwards its own health and finding events. The comparison is the one D4-49 Q12 states: same flows and packet counts per collection session to every device address, and no flow in the R9 run that the other lacks, over every destination.

## D4-51: the first SNMPv3 family is the SEL-2731 and SEL-2741 in RSTP mode (C2, #439)

Date: 2026-11-05. C1, on C2's family note (`docs/phase4/C2-snmp-family.md`, #439).

- **The ruling: C2's recommendation, which replaces the SEL-2730M proposed in the brief.** The evidence is all `documented-untested`, from S29:
  - the device cannot be set below `authPriv` (p. 43);
  - it offers SHA-256 and SHA-512 authentication (Table 4.13, p. 45), where the SEL-2730M's best is SHA-1;
  - S29 lists every OID the agent serves (pp. 46 to 47), so GT-MIB can serve exactly that set;
  - the FID's letter shows the mode.

  Only RSTP mode is in scope. OT SDN mode, configured through the SEL-5056, is not.
- **Against it, recorded:** the firmware line is young, and which switches the owner's sites run is open. Both go to the owner with item 3's questions. If the sites run the SEL-2730M, it follows as the second SNMPv3 family.
- **MIB text.** No SEL MIB is in the project, and identity needs only the standard modules (RFC 3418, 6933 and 3411), which this container cannot fetch. GT-MIB labels as SYNTHESIZED every value the manual does not print: the FID's column, `sysDescr`, `sysObjectID` and the row count. V-M1 (e) then shows the client's attribution and parse, not the real agent's values, which stay hardware-dependent.
- **The brief is corrected** to name this family.

## D4-52: the matcher's module, and a mitigation with unread preconditions (C4, #440)

Date: 2026-11-05. C1, on C4's C12 draft and matcher note (#440).

- **The matcher lives in a new `modules/applicability/`, owned by C4.** It has its own switch (R9, D4-50), it reads from three owners, and as a pure function it has no way to send a packet, which V-M8 relies on. The ownership row is added to `README.md`.
- **A `mitigated` finding may also list unread preconditions** (C4's question). An evidenced mitigation is the stronger statement, and it is the same precedence as D4-49 Q6 (i). The finding still names every unread precondition, so nothing is hidden. V-M7's "an unread precondition leaves the finding `applicable-by-version`" is read as applying when no mitigation is evidenced. This reading is subject to C6, who owns V-M7. If C6 objects that it lowers the criterion, C1 decides again before C12 is approved.

## D4-53: the item 3 contracts are approved together, with the rulings made in review (C1, 2026-11-05)

Date: 2026-11-05. C1, under §5.4, after every draft had its reviewers' acceptance at the head named below. Evidence class: desk. No device was read.

- **Approved together:**
  - C1 0.3 (identity attributes with their source), C3 0.4 (SNMP reads) and C2 0.7 (codes), in C2's drafts on #439 at `92026c9`. C3 and C4 accepted them, and C6 passed them.
  - C11 `otsec.advisory/0.1`, C7 0.8 and C8 0.11, in C3's drafts on #437 at `1c9e479`. C2, C4 and C5 reviewed them, and C6 passed them.
  - C12 `otsec.finding/0.1` (`contracts/finding`) and the matcher note, on #440 at `1730ee1`. C3 accepted them, and C6 passed them.
  - The node's side of item 3, C5's note on #438 at `23c2e7c`. C3 accepted it, and C6 passed it.

  GT-ADV and the GT-MIB plan (#441, C6) are test material, not contracts. They carry C4's pass on GT-ADV and C2's and C3's acceptances of the plan, at `cf23cea`, and merge when CI is green.
- **D4-49 Q7, as it now reads.** The finding is evaluated once per collection run, at the end of the run: after the run's last commit, or after the run if it commits nothing. An identity read that confirms an unchanged identity therefore still re-evaluates. A commit made outside a collection run (a set replacement, an operator entry) triggers its own evaluation. If a restart cuts a run off, the evaluation at start covers it, and the latest confirming read survives the restart. This replaces "after each commit", which on an SEL-751 run (identity, then settings) would record a transient `confirmed` against the old snapshot (C6 on #438).
- **A finding is written on any C12 §7 change,** including a new stale mark or changed evidence under the same class, and not only when the class changes (C6 on #438). Without this, V-M7's evidence is lost. A change to `identity.latest_read` alone is not a revision, as C12 says.
- **The product match uses the device-read `model`, never a declared `product_family`** (C6 on #439, §1.5; GT-ADV D11). A disagreement shows as `identity.family_conflict` in health and is never an input to the match, so an operator entry cannot lower a finding on a device-read identity.
- **D4-49 Q5 comes before every other mitigation** (C6 on #440, matcher note §5 step 4a; GT-ADV D10). A precondition read false on a device-read identity gives `not-applicable`, unless the mitigation that holds is that same setting. C12 refuses a `mitigated` or `precondition-not-met` that rests on stale evidence, and ties each evidence ID's form to its source.
- **Algorithms.** SHA-1 stays out for the SEL-2731/2741 (D4-51). The credential can name only `hmac-sha-256`, `hmac-sha-512` and `aes-128`, so MD5, SHA-1, DES and AES-256 are refused, and GT-MIB offers them as negative cases (C3 on #437, after C2).
- **What an unauthenticated message can do** (C6 on #439, GT-MIB U15 and U16):
  - A Report or a Response counts only when it matches the outstanding `msgID` and comes from the endpoint's address and port. Anything else is discarded.
  - Nothing an unauthenticated message can cause suspends the asset or its credential. The four Report failure codes and `refused.engine_id_mismatch` fail the run and show in health, and suspend nothing.
  - C11 §4 rule 1 (a Response below `authPriv` is discarded unparsed, even with a valid digest) and HR-16 are read with this ruling (C6's cross-reference on #437).
- **Advisory set loading** (C3 on #438). The node reads at most `MaxEnvelopeBytes` (1,399,128 B) + 1 and refuses a larger file before parsing. It verifies the newest installed set again against the current anchors at start and on every anchor change. If that fails, no set is in use, and an older set never takes its place. `advisory.set_refused` is written once per file hash, as the alarm is.
- **Still with the owner** (`docs/agent-handoffs.md`, item 3): who publishes the advisory set and holds its key (HR-18), the severity scores, which SEL switches the sites run, the RFC texts (RFC 3411, 3418 and 6933), and the approval key for a later v1 or v2c path. No real advisory goes into a set until the publisher and key are answered. The implementation can be built and verified on GT-ADV's test sets without them.

## D4-54: rulings made while item 3 was built (C1, 2026-11-05 and 2026-11-06)

Date: 2026-11-06. C1, on the item 3 implementation PRs (#444 to #453). Evidence class: desk. No device was read. Each ruling was given on its PR when it was made, and is recorded here so that the contracts and briefs can be read with it.

- **C5 0.8, the node's store for item 3** (#444, merged as `f5b3205`; the store code in #450):
  - No hold codes. An installed set's records are never removable, which is stronger than a hold.
  - Advisory sets are kept for good (D4-20), to be revisited with the publisher's cadence (HR-18). C3's condition is met as C5 0.8 §5 states it: a set install that would take the class past the item 3 ceiling is refused with `advisory-set-no-room`, and at start the floor is compared with every stored set (`advisory-sets-over-floor`). There is no separate "one record free" check.
  - **The item 3 ceiling** (C6's FAIL: item 3 evidence could fill the configuration class). Every item 3 series write is refused above the quota less the configuration floor. `asset-store-full` is raised once per crossing, the matcher pauses while it holds, and refusals are counted. Configuration reads still commit up to the full quota.
  - **When the crossing ends** (C6 on #455). C5 0.8 §5 stands: the crossing ends when the class falls back to the ceiling or below it, whatever freed the room. #452 ends it only at the next item 3 write that fits, which is not the rule. If the matcher paused on that flag, and only its own writes could clear it, the pause would never lift. So in part 3 the node tests the class against the ceiling, both to clear `asset-store-full` and to lift the matcher's pause, and C6's test covers room freed by a configuration removal.
- **C2 0.7, C1 0.3 and C3 0.4 in code** (#445, merged as `8ecbe61`):
  - The SNMP result rules join C2 0.7: `session.snmp`; the engine ID as the first identity item, under AP-27; and `observations[].read`.
  - **An authenticated SNMPv3 FID mismatch suspends the asset only, not the credential.** The SEL-751 rule is unchanged. C3 confirmed.
  - `max_reply_bytes` is capped at 65,507, the largest UDP payload.
  - `CapabilityProfile.models` is optional in C1 0.3. When it is absent, no `family_conflict` check is made.
  - **`failed.snmp_fid_unreadable`** is a new code. It is raised after authentication, on SNMP only. It suspends nothing, keeps the transcript, reports only the engine-ID identity item, and is not a confirming read.
  - **Apply never adopts a mismatched identity.** A mismatch (SEL `refused.identity_mismatch`, or SNMP authenticated `failed.identity_mismatch`) writes no new identity record and marks the device-read evidence stale (D4-49 Q6 (ii)).
- **C2 0.8** (in #453, with the SNMPv3 client). Two more codes, both SNMP-only, both suspending nothing, both keeping the bytes:
  - `failed.snmp_unexpected_report`, at any stage after connecting;
  - `failed.snmp_scoped_pdu_unreadable`, after authentication.

  #445 merged without them so that C3 and C5 were not held up.
- **The family token** (C5 and C2, #453). `product_family` stays per product: `sel-2731` and `sel-2741`. `Models(sel-2731)` is `[SEL-2731M]` and `Models(sel-2741)` is `[SEL-2741M]`. `sel-27x1` (and `sel-27x1-rstp`) names only the profile, the register entry and the adapter family. A family with no model list makes no conflict check. This corrects C1's first answer, which used `sel-27x1` as the product family.
- **C11, C7 0.8 and C8 0.11 in code** (#446, merged as `cf37940`):
  - §1.7's eight points are confirmed.
  - `MaxMitigations` is 16, to match C12.
  - A `sel-fid` product must match `^SEL-[0-9A-Z]+$`, and each FID in `versions` must begin with that product (C6). C2 confirms the read forms.
  - An `attribute` key must be a C1 attribute name.
- **The matcher** (#451, C4):
  - After a mismatch, the version is treated as unread: the finding is `applicable-by-version`, stale, and cites the mismatch (C6's fix). A mismatch contradicts the FID on record, not only its age.
  - `product-not-named` holds under a mismatch only if neither the stored model nor the model the mismatch read reported is named.
  - Only SEL `refused.identity_mismatch` and SNMP authenticated `failed.identity_mismatch` feed `LatestMismatch`. `refused.engine_id_mismatch` (unauthenticated) and `failed.snmp_fid_unreadable` never do (C2).
  - C4's three conservative points in the note's §11 are confirmed.
- **Which findings the node stores** (C5 for part 3, after the C4 note's §7). The node does not store a `product-not-named` finding for an entry that has no earlier stored finding for the asset. A `product-not-named` finding follows from the product and the set alone, and storing one for every asset and entry would use up the findings allowance on nothing. Two conditions apply:
  - Once an entry has a stored finding for the asset, every later change is stored as a revision, including a change to `product-not-named`. So no history is lost.
  - A missing finding must not be confused with an evaluation that never ran, for example under the item 3 ceiling's pause, with no set, or before the first read. So status shows, for each asset, the set version and the time of its last completed evaluation. A `product-not-named` result is shown as "no stored finding, and the asset's last completed evaluation ran under that set". V-M7 checks those cells that way on the binaries, and a cell with no completed evaluation under the set fails. Two more conditions apply (C6 on #455):
    - The last completed evaluation must be later than the asset's newest identity record. Otherwise "evaluated under set v" could describe an earlier model.
    - An evaluation counts as completed only if every finding it returned was stored. A finding refused at the item 3 ceiling must never read as "not named".
- **Operator identity evidence** (C5 for part 3). Operator-only assets are evaluated, because the exit gate needs GT-ADV's operator rows and the denied-branch rows (F1). C12 cites operator evidence as `audit:<node_id>:<seq>`, and a declaration in the node's configuration has no record of its own. So at start, the node writes one `policy.apply` record for each asset whose declared identity is new or changed, as `nodekeys.go` does for register entries. It has a node reason code, and its detail carries the asset ID and the SHA-256 of the declared identity attributes. It is idempotent, and the operator evidence cites it. Pruning the chain must not cause it to be written again (C6 on #455). Otherwise every prune followed by a restart would write a new record and revise every operator finding. So the node either holds the record from removal or keeps and reuses the cited reference while the declared identity's hash is unchanged. C5 chooses which. No new C8 action is needed. The evidence stays `operator` and is never `confirmed`. C3 reviews it for the trust boundary.
- **The mismatch read's FID is stored** (C5 for part 3). If it were kept only in memory, a restart would turn an `applicable-by-version` finding into a stored `product-not-named` revision, which is a false downgrade. So the `identity.read` document gets an optional field for that FID text. It is bounded to C1's FID length and marked as device text that is never adopted. It is set only from a mismatch read and cleared on the next confirming read. The mismatch fields are kept apart from the latest-read part. An `identity.read` that carries a mismatch FID keeps the last confirming read's invocation ID and time as its latest-read part (C6 on #455). Otherwise removing older reads would delete the confirming read, and a mismatch could look like a confirmation. This is an additive C5 0.8 amendment, in part 3's PR. C4 and C6 review it, C1 approves it, and C6 adds the restart case.
- **Set authors name models as the device reports them** (C2 on #451): `SEL-2731M` and `SEL-2741M`, with the mode letter. A bare `SEL-2731` gives a false `not-applicable`. This joins the publisher question (HR-18), and GT-ADV's test sets follow it.
- **P4-3-C3 deliverable 5** (a gap in the brief). C3 also builds the SNMP path in `modules/security/collector/pipeline.go`: the register lookup for SNMP runs, the credential acquired with the engine ID pinned, C2's client called through the egress check, `SuspendsCredential` returning nothing for SNMP, and asset-only suspension on an authenticated FID mismatch.
- **Still with the owner,** in addition to D4-53's list: the five remaining RFC texts (RFC 3412, 3414, 3416, 3826 and 7860) or access to `www.rfc-editor.org`, and the model naming rule above, which goes to whoever publishes the set.

## D4-55: rulings made while the node's part 3 and the SNMP path were built (C1, 2026-11-06)

Date: 2026-11-06. C1, on #456 to #459 and C3's deliverable 5. Evidence class: desk. No device was read. Each ruling was given on its PR or to its owner at the time it was made.

- **The C5 0.8 amendment, `identity.read`'s optional `mismatch` object, is approved** (C5 on #458, at b9276a2, merged as b78d215). C4 and C6 passed it. It carries the run that refused the identity, when that run ended, the FID the device reported, and, for an operator-only asset, the hash of the declaration it contradicted. The FID is bounded at `MaxValueBytes` and is never adopted. The latest-read part stays the last confirming read. For an asset that no read has confirmed, the latest-read part is absent, and only then. A node built from part 2 alone refuses the new field, so parts 2 and 3 ship in the same release.
- **The declared-identity record** (D4-54). The node keeps the cited `policy.apply` reference in `declared-identities.json` and reuses it while the declaration's hash is unchanged. It does not hold the record from pruning, because that would stop audit pruning altogether. The file is written atomically, with mode 0600. An entry is trusted only for a sequence number below the chain's first retained record. If the file is lost, the cost is at most one new record and one revision for each operator finding (C3 on #458). It must not change a class, so a standing mismatch is never cleared by the record's time (C6 on #460; see the next ruling but one).
- **When the item 3 ceiling's crossing ends** (D4-54, as built). A refusal happens when the write would pass the ceiling, so the class can sit below the ceiling during a crossing. The crossing therefore ends when the class has room for the smallest write it refused, whatever freed the room, or at the next item 3 write that fits. The matcher's pause lifts at the same moment. That still tests the class, not a flag.
- **A mismatch on an operator-only asset counts** (C5's question on #458, C4's #459). Under a mismatch, an operator identity is treated as a device-read one is: the version is read as unread, every entry naming either model is `applicable-by-version`, the declaration is marked stale, and nothing is `confirmed`. The node stores the mismatch for such an asset. A confirming read clears it, and so does a change to the declaration. That change is judged by the declaration's hash, never by time. For an operator-only asset, the `mismatch` object carries the SHA-256 of the declared identity it contradicted, and the mismatch stands until that hash changes (C6 on #460). A lost `declared-identities.json`, which rewrites the record with a new time, therefore cannot drop a mismatch.
  - **Limitation, accepted for item 3.** C12 0.1 refuses identity evidence of a different source from the identity, so the finding cannot cite the device-read mismatch on an operator identity. The mismatch shows in `identity.read`, in status and in the chain's `asset.suspend` record. Citing it in the finding is a C12 0.2 item, and goes in the item 3 exit report.
- **Operator rows in status** (C6's alternative on #457). For an operator asset, `last_evaluation.identity_evidence_id` is the declared identity's audit reference. V-M7 matches it by ID, as for device-read rows, rather than by comparing times.
- **A mismatch whose `identity.read` does not commit** (C6 on #458). If the mismatch's `identity.read` fails to commit, at the ceiling or for any other reason, the run's evaluation does not set `last_evaluation` as current. Otherwise an entry naming the reported model would read as `product-not-named`.
- **The register lookup for SNMP runs** (C3, deliverable 5). The collector finds an asset's register package by `profile.firmware.allowlist`, not by `product_family`. The register ships each family's allowlist in that family's own package, so the allowlist's name is the package's family: `sel-27x1-rstp` for the SEL-2731 and SEL-2741, and `sel-751` for the SEL-751, so nothing changes there. An allowlist of `none` finds no package, and the run is refused as register-unverified, with no fallback. The package found must be of that family. No C1 change is needed.
- **The engine-ID pin at run time** (C1 on #456). The credential store checks the credential's engine ID against the asset's declared `snmp_engine_id` at install. The SNMP path checks it again before each run, against the declaration as it is then, and refuses the run as a credential mismatch if they differ. It suspends nothing, because this is an operator-side change.
- **V-M7's checker parses times** (C1 on #457). Times in the observed record are parsed before they are compared, never compared as strings.

## D4-56: where a recorded network control lives, and V-M7's two control cells (C1, 2026-11-06)

C6's V-M7 run on the binaries (#467) passes 126 of GT-ADV's 128 cells. The two that fail, TEST-ADV-03 × D8 and × D9, need a recorded network control, and no control is recorded anywhere yet. C11 (`docs/phase4/C3-c11-advisory.md`, `control`) and the matcher note (`docs/phase4/C4-matcher.md` §5) left where a control is recorded to C1 0.3, settled with C2. That was never settled. The item 3 gate needs V-M7 to pass per cell, so it is settled now.

- **A control is part of the node's asset configuration, not of C1 0.3.** A control is not an identity attribute, so C1 0.3 is unchanged. The node's configuration may give an asset `controls` in a list keyed by `asset_id`, beside the C1 records, for example `"asset_controls": [{"asset_id": "…", "controls": ["tcp/80"]}]`. A key inside a C1 record is refused by `asset.Decode`, so nothing in `modules/asset` ever sees a control (C2 on #468). Each control is a C11 control key (`^(tcp|udp)/[1-9][0-9]{0,4}$`, port 65535 or less) and names what a network control in front of the asset blocks. The node refuses a configuration with a malformed or duplicate key, an `asset_id` that matches no asset, the same asset listed twice, or more than 16 keys for one asset. Controls come from this file only, and never from a device, the collector or a result.
- **It is recorded the way a declared identity is (D4-54, D4-55).** With `applicability` on, the node writes a `policy.apply` record at start with reason `asset_controls_declared` for each asset whose list is new or changed. Its detail is `asset <asset_id> controls sha256:<hex> keys <k1>,<k2>,…`, with the keys in the hashed order, or `keys none` for an empty list, so the attested keys can be read from the chain without the old configuration (C3 on #468). Sixteen keys fit the 512-byte detail bound. The hash is the SHA-256 of the keys sorted in byte order, each followed by one LF (`tcp/80\nudp/161\n`), so an empty list hashes the empty string (C6 on #468). The record is reused while that hash is unchanged, in the same atomic, mode-0600 file as the declared identities. The matcher's `Controls` take each key with that record's `audit:<node_id>:<seq>` as evidence. The finding cites it with source `operator` and that ID, so the mitigation is `operator_attested` (C6 on #468). A list emptied or changed writes a new record, and the findings that cited the old one are re-evaluated.
- **It fails toward fewer mitigations.** A record that cannot be written raises `asset-controls-not-recorded`, and the asset is evaluated with no controls. An unrecorded control is never cited.
- **The device outranks the control.** That is unchanged from C4's note §5 step 4a: a precondition read false on a device-read identity gives `not-applicable`, whatever control is recorded (GT-ADV TEST-ADV-03 × D10).
- **Owners.** C5 builds it in `platform/node`. C2 confirms that C1 0.3 needs no change. C3 reviews the trust boundary, because this is operator-entered data that turns a finding `mitigated`. C6 adds a case to the per-cell test and removes the pin below in the same change.
- **#467's pin is accepted for now** (C6's question). `test_the_control_cells_fail_only_for_want_of_a_control` pins that D8 and D9 fail for that reason alone, so V-M7 stays a FAIL on those cells while CI is green. The pin is a tripwire, not a waiver. It must fail when controls land, and the item 3 gate does not pass while it exists.
- **A configuration-read asset is `confirmed` from its second read** (C6 on #467). The matcher counts the first stored snapshot as a change, and the run that stores it is the run that reads the identity, so that read is not later than the change. The node cannot tell a baseline from a change it did not see, so this errs toward the weaker class for one read interval. It stands, and the exit report lists it as a known behaviour.

## D4-57: an audit citation never reads as passive evidence (C6's F-025, C1, 2026-11-06)

C6 found at the desk (F-025) that an operator audit citation, `audit:<node_id>:<seq>`, also has the form of a passive event ID, `<node_id>:<stream>:<seq>`, when the node is named `audit`. A finding could then cite an operator entry as `passive` evidence, and passive evidence can back `confirmed`. No configuration in the repository names a node `audit`, so this was never seen in a run. It is closed at both ends, and the item 3 gate waits for both changes.

- **C12 (C4, #476).** `finding.Validate` refuses passive evidence whose ID starts with `audit:`. A device read's ID must now be a lowercase UUID of version 1 to 8 with the RFC variant, the same form as `contracts/adapter`'s invocation ID, so a finding can cite only an ID that C2 would issue. The DRAFT note in `contracts/finding/doc.go` is removed, because C12 0.1 was approved under D4-53. The C12 version does not change: the change only refuses findings that no conforming node writes.
- **Node IDs (C3, #477).** `node.ID.Valid` refuses `audit`, so the node configuration, the collector configuration, enrollment and the credential store all refuse it. Names that only contain the word, such as `audit1`, stay valid. `contracts/authz` and `contracts/audit` still match `node.IDPattern` directly. They are left as they are, because no configuration can produce a node named `audit`.
- **Verification (C6).** C6 reviews both changes and adds the pair to `tests/contract/c12_c6_test.go`.

## D4-58: the RFC texts, message routing through the coordinator, and the C-to-D handoff (owner and C1, 2026-11-06)

- **The RFC texts (owner, 11:41Z).**
  - The owner chose "Allow www.rfc-editor.org" on C1's V-M1 decision card.
  - C1 added that one host to the cloud environment's allowed hosts. C1 then fetched RFC 3411, 3412, 3414, 3416, 3418, 3826, 6933 and 7860 into the project files (`/mnt/project-files/rfc/`, with `SHA256SUMS`).
  - Role 6 also needed RFC 2578 (the MIB roots), 3417 (the transport and BER rules), 1157 and 1901. C1 fetched them from the same host. Each matches role 6's own copy byte for byte, and `SHA256SUMS` covers all twelve.
  - V-M1 is unblocked. GT-MIB may be built only from these texts. The item 3 gate still never counts a GT-MIB built from memory.
- **Messages between agents go through the coordinator (owner, 11:43Z).** "New rule. All messages run through you the coordinator."
  - An agent sends a message meant for another agent to the coordinator, which relays it. This replaces direct thread-to-thread messages.
  - What an agent posts in its own thread, and on its own PRs, is unchanged.
- **The C team hands off to the D team (owner, 11:55Z).** The owner asked every agent to run a generation checkpoint.
  - C2 to C6 wrote `handoffs/D{n}-handoff.md` (#481 to #485). C1 wrote `D1-handoff.md` and the C-to-D `HANDOFF-SUMMARY.md`.
  - Roles, owned paths and rules stay with the number. Wherever a record says A*n*, B*n* or C*n*, read it as the role D*n* now holds.
  - Phase 4's decision file stays `docs/phase4/B1-decisions.md`, and its numbering continues at D4-59.
  - Cutover happens once D1 has confirmed all six acks.
- **Socket waits use the wall clock under a test clock** (C1's ruling on #461, recorded here at C3's request).
  - The collector's SNMP socket deadlines are taken from the wall clock. The transcript's times come from the session clock.
  - With the session clock held an hour behind, deadlines taken from it expired at once (fixed by `163a9f9`; `TestSNMPRunDiscoveryTimeout` pins it).
  - The rule holds for any socket wait in a build with the test clock.
- **The Windows node start can stall for more than 12 s, and this is an open reliability item** (C5, #471).
  - The cause is unknown. The CI logs do not show which step of the start stalls.
  - The lead is #428's profile: recreating the recovery reserve with a flush at every start (F-013). It is unverified.
  - Investigating it needs role 1's brief. It is not briefed yet.

## D4-59: the carried items after the C-to-D handoff (D1, 2026-11-06)

D1, on the D3 (#488) and D5 (#487) acknowledgements.

- **D3's check of `modules/security/snmpegress` against the RFC texts goes ahead now.** It is item 3 verification under D4-34, not new feature work. A layout error the texts reveal is fixed in its owner's code (D1-handoff task 2), with a failing test first.
- **The same holds for D2's check of `modules/ied/snmpv3`.** A client or egress fix the texts call for merges before D6's V-M1 run, so the run that counts for the gate is on the corrected code on `main`. A run on the old code may still help D6 debug, but it does not count. New findings notes use the `D{n}-` prefix (`docs/phase4/D2-snmpv3-rfc-check.md`, `docs/phase4/D3-snmpegress-rfc-check.md`).
- **D4-20 rule 4 (the evidence release and export kind) is deferred past Phase 4.** D4-20 already says it is not owed by Phase 4, and D4-19's stop at the quota stands until it exists. It leaves the STALLED list and is no longer carried as a role 3 task. It is briefed only when the owner asks for it or a later item needs it.
- **Two items are queued for right after the item 3 gate, not STALLED:**
  - the off-lab refusal of `clear-suspension.json` (role 3's collector refusal of the unsigned file first, then role 5's node side);
  - the Windows node start over 12 s (D4-58, #471). Role 5's first PR only logs per-phase start timings on Windows CI; no fix is made until those numbers show the cause.

  Both harden what is already built, so neither is a later Phase 4 item. Under D4-34 they still wait for the owner's go at the item 3 check, where D1 puts them beside the choice of the next item. D1 writes their briefs then.
- **D4 may draft C12 0.2 now, as a proposal document only** (`docs/phase4/D4-c12-0.2.md`). It fixes item 3's accepted limitation (D4-55), so it is not a later item. No code until D1 approves the proposal, and D1 reviews it after V-M1, so it does not compete with the gate.
- **D6 writes GT-MIB's agent, the case-table corrections and the V-M1 runner now,** and opens the PR once its ack merges. D6 proposes the new `integration-long` leg's `ci.yml` line in that PR, with a time limit of about twice the measured run, and D1 authorizes it there.
- **The real-store test of D4-21's byte share (HR-11)** is role 6's test against role 4's receiver. It gates the first `device-observed` listener, not item 3. It is carried as an open item in the summary until it is briefed.
- **#486 needs no post-merge review.** Role 6 (C6) passed it at `c81b9e3`, the head that merged. #480's C12 part, checked by D4 on `main`, is recorded in D4's ack only.
- **`govulncheck` on `main`.** D1 dispatches the workflow on `main` before deciding the item 3 gate, so the decision cites a run on the code it accepts. The weekly run stays as it is (D4-3).

## D4-60: rulings made while V-M1 ran (D1, 2026-11-06)

D1, on #495, #496, #497 and #498, with each owner's and reviewer's word through the coordinator (D4-58).

- **An empty `noError` GetNext Response** (D2's #495, the one point left open). RFC 3416 §4.2.2 never allows a Response to a GetNext with fewer varbinds than the request, but the client still ends such a walk as complete, because no C2 0.8 code names that violation.
  - The next C2 revision adds a `failed.*` code for it. It does not suspend anything, like the other SNMP protocol codes (D4-54).
  - Until that revision merges, no signed register may declare a `GETNEXT` walk. Every SNMP operation in a register is a `GET` or a `GETBULK` walk. C2's test package already is, and D6's runner walks with GetBulk only.
  - This is a recorded item 3 limitation, not a gate item.
- **The C1 engine-ID rule ships within `otsec.asset/0.3`, with no version bump** (D2's #498, merged as `aae3eb6`). RFC 3411 §5 says an SnmpEngineID may not be all zeros or all `ff`. `Asset.Validate` now refuses such an `snmp_engine_id`. No minor bump, because no valid record changes meaning. Such an asset could never get a credential, since the collector requires the credential's engine ID to equal the asset's. A stored record that already holds such an ID fails closed. None exists in the repository.
- **C7 0.9 is a minor bump** (D3's #497). It refuses the same engine-ID form in a `snmpv3` credential at install. It was opened under D4-59 and merges after V-M1's counted run, with D2's review and D6's contract tests at its head.
- **The V-M1 leg** (D6's #496, merged as `73ab7b6`). D1 authorized a new `integration-long` leg for `test_slice_vm1_e2e.py`, with the matrix's 20-minute limit, about twice the measured 9.4 minutes. The step pipes the run's output to `vm1_keysearch.py`, so the CI log itself is searched for the test keys. `ci.yml` now has nineteen jobs, fifteen of them `integration-long` legs.
- **V-M1 (f) needs its own check on the V-M1 run.** V-M7's runs show the SEL-751's identity read over telnet, but they are other runs and do not show that the SEL-751 receives no SNMP. D6 adds a check to the asset-alone run: a UDP socket on the SEL-751's address and port gets no datagram, its configuration has no SNMP entry, and its identity is device-read over telnet. The gate counts (f) only from that check, green in CI.
- **F6 was a product defect, not a test error** (D6 on #496). GT-MIB plan §2.2 says a case whose read model belongs to another family shows `identity.family_conflict` in health. `modules/asset.FamilyConflict` existed, but nothing on the node called it. D5 fixed it in #499, and #496's F6 check passed on the binaries only after that.

## D4-61: C12 0.2's proposal is approved (D1, 2026-11-06)

D1, on D4's #504 (`docs/phase4/D4-c12-0.2.md`), with D2, D3, D5 and D6 reviewing. The full rulings are in the proposal's §10.

- **Option A.** A new `identity.mismatch` field, a `Read` holding only the C2 invocation ID and the stored `ended_at`, cites the device read that refused an operator or passive identity. No device text ever goes into a finding. `identity.evidence` keeps its 0.1 meaning. Rules 1 to 5 apply, and rule 3 matches the matcher: `applicable-by-version` with `firmware-version` unread.
- **Rollback fails closed.** Before 0.2 merges, D5 makes the node refuse any `otsec.finding/` minor that `finding.Known` does not name. The refusal is per asset and for applicability only, through the existing not-evaluated alarm in health. The alarm names the schema, bounded to 64 bytes of printable ASCII and quoted. Collection, SER forwarding and configuration monitoring go on. The release record states that this change must be in every build a node can roll back to before any node writes 0.2.
- **Proof.** Role 6's V-M7 checker resolves `identity.mismatch.id` to its stored `identity.read`. An operator-only mismatch scenario joins the V-M7 leg on the binaries, checked across a restart. Role 6's contract tests for 0.2 are in a new `c12_v02_d6_test.go`.
- **The next C2 revision** bounds `ended_at`'s fraction at nine digits, beside D4-60's GetNext code.
- **No code before the owner's go** (D4-34). C12 0.2's code is queued with D4-59's two hardening items.

## D4-62: the owner accepts item 3, the hardening briefs, and the branch cleanup (owner and D1, 2026-11-06)

- **The owner accepted Phase 4 item 3 with its conditions** (16:48Z, on D1's decision card) and chose "Accept, do two hardening fixes first". The conditions are the limits in `docs/phase-4-item3-exit.md`. D1 issues the hardening briefs in `docs/agent-handoffs.md` ("After item 3: hardening briefs"):
  - P4-H1, refusing `clear-suspension.json` off-lab;
  - P4-H2, finding the Windows node start stall;
  - P4-H3, C12 0.2's code as D4-61 approved it, which closes item 3's last limitation.

  D1 told the owner that C12 0.2 follows the two fixes unless they say otherwise. When all three are merged, D1 reports to the owner and asks for the next item. The owner's other open questions (HR-18, severity scores, HR-17, which SEL switches, model naming) stay open.
- **The branch cleanup (16:48Z).** The owner chose "Delete the 150 merged ones". D1 re-checked that each of the 150 branches is still at the tip recorded on 2026-10-31 and is the head of no open PR. `claude/project-thread-8k5430` has moved and stays. This session's GitHub access refuses a branch delete, as it refuses a force push. So D1 wrote `/mnt/project-files/d1/delete-merged-branches-2026-11-06.ps1` for the owner to run from a clone. Each delete is leased to the recorded SHA. The four unmerged mutant branches are kept.

## D4-63: the hardening briefs are done, and two rulings on P4-H2 (D1, 2026-11-07)

- **All three briefs are merged.**
  - **P4-H1:** D3's #508, D5's #514, and D6's acceptance tests in #516 (`e205da6`).
  - **P4-H2:** D5's #515 (`ad42d4a`), with the note `docs/phase4/D5-windows-start.md`.
  - **P4-H3:** #507, #509, #510, #511, #512 and #513.
- **P4-H2's result** (`CI-Windows`, from 550 starts at #515's head `8a6e5600`).
  - In slow starts, the dominant phase is `store-reserve`, followed by `store-open`. `store-reserve` is 49% of all start time in the Windows `go` job, and the largest phase in 404 of 541 starts.
  - The 9 service starts took 0.7 to 1.2 s.
  - #428's F-013 lead (recreating the reserve with a flush at every start) is consistent with these numbers but not shown by them.
  - D6 recomputed every figure from the raw log.
- **Ruling 1: two starts over 6 s are accepted, not three.** The brief asks for three "if any occur". One run gave two, and the dominant phase is already clear, so more Windows time would not change what a fix targets.
- **Ruling 2: the go job's coverage is accepted as limited to starts made through the tests' `start()` helper.** Direct `Start`, `Run` and `RunFrom` calls in tests leave no line there. The production path, `Run` and `RunFrom`, always logs the line, and the service job shows one line per SCM start. The note states the limit.
- **For any fix brief** (D3 on #515):
  - The fix keeps F-013's recovery reserve, flushed before it counts, when the disk is full.
  - The fix keeps AP-13's 60 s first wait.
  - Its proving test is the platform budget numbers before and after.

  The fix is not briefed yet. It goes to the owner beside the next item (D4-34).
- **A timing-sensitive test, and its fix at the cause (open).** `TestHostileCorpus/H11/outer` failed once on Windows, on #515's docs-only head, because GT-MIB's test manager read a fixed window before the agent had finished answering. D6's #517, open when this was written, waits for the agent's own handled count, and loosens no count. D2 passed it. It merges on green CI.

## D4-64: the owner chooses the slow-start fix before the next item (owner and D1, 2026-11-07)

- **The owner's choice.** At 09:36Z, on D1's card "Which Phase 4 item should come next?", the owner chose "Fix the slow start first". D1 had recommended IDS (item 4). The fix comes before items 4 to 6, and D1 checks with the owner again once it is merged (D4-34).
- **The brief.** D1 issues P4-H4 to D5 in `docs/agent-handoffs.md`.
  - Measure which part of `store-reserve` dominates on Windows first, then make the smallest change that removes it.
  - Keep F-013's release-before-open rule, a reserve that only counts once it holds real space and is flushed, and AP-13's 60 s first wait.
  - Any change to C5's startup order or its report is a C5 minor bump, through a reviewed proposal first.
  - Proof is before and after Windows numbers from the PR's own code.

## D4-65: the slow-start fix is merged, with two rulings (D1, 2026-11-07)

- **The result.** P4-H4 merged as #520 (`28e94ae`), with D5 implementing and D6 and D3 reviewing. Evidence class: CI-Windows, with 543 starts per run.
  - The step-1 split showed that the file flush of about 1 MiB of written zeros was about 92% of `store-reserve`.
  - `CreateReserve` now reserves the space in one call: `fallocate` on Linux, and a non-sparse extend on Windows. It falls back to zero writes only on `ErrUnsupported`, and it keeps both flushes before a reserve counts.
  - `store-reserve` median/p90 went from 151/366 and 138/383 ms to 9/19 and 8/14 ms.
  - `total` median/p90 went from 325/922 and 322/954 ms to 196/736 and 179/672 ms.
  - The three must-keeps are pinned by tests. Must-keep 1 is pinned by order only, because C-22 and H-14 are open.
- **Ruling 1: no allocation read-back.** D3 asked for a read-back that falls back to zero writes when the allocation is short. On compressed or copy-on-write volumes, the zero writes hold no real space either, so a fallback cannot fix it. The only real fix is to fail the reserve on such volumes, which would change which file systems the node supports. The PR's note therefore records this as a known limit next to H-14. D1 takes the question to the owner in the next report: should the reserve fail (drain-only) where it can't hold real space? D3's Windows folder-flush item goes with it.
- **Ruling 2: the Windows clock.** `TestReserveParts` dropped its `> 0` checks on the release and the allocation, because under the Windows clock tick both read 0. The exact sum and `reserve-sync > 0` stay. If `reserve-sync` ever reads 0, that check is dropped, not retried.
- **Not fixed, and carried.** There are still starts over 6 s: 5 after the fix against 3 before. All of them sit in `store-open` or `record-start`, never the reserve. `store-open` is now about 47% of start time. Whether to brief it is the owner's call, alongside the next Phase 4 item (D4-34).

## D4-66: the owner chooses IDS next, and item 4's Stage A is issued (owner and D1, 2026-11-07)

- **The owner's choice.** At 17:59Z, on D1's card "Which Phase 4 item should come next?", the owner chose "Network IDS (item 4)", the option D1 recommended. The other options were secure engineering access (item 5), the central role (item 6), and a fix for the rare slow starts carried in D4-65.
- **The ask.** D1 asked the owner two questions:
  - which protocols run on their substation networks;
  - whether a site node can get a SPAN port or a TAP, and whether the station network is PRP.

  The brief proceeds without waiting for the answers. The first protocol set is DNP3, Modbus/TCP and R6.7's insecure list, and IEC 61850 and IEC 104 are added when the owner confirms them.
- **The brief.** D1 issues item 4's Stage A in `docs/agent-handoffs.md`. Where the sensor runs on the Windows site node (ADR-0007) is settled first, in a draft ADR-0009, before any contract depends on it. C13 `otsec.netobs/0.1` is drafted after that. D6 builds GT-PCAP from public captures and from the project's own simulators. No real network is captured.
- **Carried.** Two questions still go to the owner: whether the reserve should fail on volumes that can't hold real space, and the Windows folder flush (D4-65). The rare slow starts are also carried, and can be briefed beside item 4 if the owner wants.

## D4-67: cleartext secrets in stored captures are redacted by position (D1, 2026-11-07, HR-19)

D3 asked, in HR-19 on #523, whether HR-3's transcript rule applies to stored captures. D1 rules yes, with three refinements:

- **By position, never by the secret.** Redaction uses the same positional rule as HR-3. The decoder redacts the client-sent bytes that fill a documented credential slot: a Telnet password after the device's password prompt up to the end of the line, FTP `PASS`, the community field of every SNMPv1 and v2c message in either direction (requests, responses and traps, D6), and plain HTTP's `Authorization: Basic` header (D3). It never finds them by matching a known secret. The sensor never receives or holds any of the platform's credentials, because only the collector resolves them (ADR-0002).
- **Fail closed when the slot can't be placed (D3).** A session may be joined midstream, lose or reorder a segment, show an unknown prompt, or send the password before the prompt. Where the decoder cannot place a slot, the client-sent bytes of that login are not stored, and the citation records why. The same holds for a plain-HTTP request body to a login path, which has no fixed position. A server's echo of a slot is redacted by the same rule, and the slot is placed after TCP reassembly, so a password sent one byte per frame is covered.
- **For every session, not only the platform's own.** A third party's cleartext password is as sensitive as the node's, and its value adds nothing as evidence. What matters as evidence is that a secret was sent in clear (the R6.7 finding), the user name, and how many attempts were made, and all of those are kept.
- **The citation says so.** A redacted frame is marked as redacted in its C13 citation, with the position and length of each marker, and the marker is never derived from the secret (HR-3's condition). The cited SHA-256 is over the stored (redacted) bytes. A stored capture therefore differs from the wire only inside those markers. Because redaction works by TCP sequence range, a marker keeps the secret's length on purpose, so a stolen node learns each password's length and nothing more (D6). A Telnet login the decoder recognizes only by an unknown prompt that leaves echo on is a recorded residual unless D4's decoder uses the `WILL ECHO` signal (D6).

D4 carries this into C13 and the decoder design, D6 into GT-PCAP's key search (AP-33's test), and D3 closes HR-19 citing this decision.

## D4-68: item 4's contracts are approved, with the rulings from their review (D1, 2026-11-07)

D1 approves the contracts for Phase 4 item 4 together, after review of each against the others. Each was reviewed and merged as a draft first:

- **C13 `otsec.netobs/0.1`** and the network baseline note (D4, #536). Reviewed by D2, D3, D5 and D6.
- **C4 0.3** (D4, #536): C13's records are C4 events. Reviewed by D3, D5 and D6.
- **C5 0.9** (D5, #532 and #535): the two network stream classes and the three series `baseline.network`, `netcheckpoint.detector` and `netcheckpoint.learner`. Reviewed by D3, D4 and D6.
- **C7 0.10 and C8 0.12** (D3, #534): the network baseline acknowledgement and its audit records. Reviewed by D4, D5 and D6.

ADR-0009 stays **proposed** until the owner chooses where the sensor runs. None of these contracts depends on that choice. Under each option, the node sees the same C13 records over an authenticated channel (AP-34). Implementation briefs follow this decision. No code starts before them.

**Rulings made during the review, recorded here:**

1. **Unresolved observations get a rate budget, not a class of their own.** They may take at most a quarter of the observation quota over the section's planned outage hours. Those over the budget are dropped before the store, counted, and shown in status. The network database holds only network classes (#532 §1), so the test is within them. If D6's spoofing-flood test shows, in its unresolved legs, that a labelled resolved observation is lost, `network-unresolved` becomes a third class before the gate. A drop in its leg that mimics a known pair leads instead to a budget per destination asset on observations (#535 §6, note §8).
2. **A liveness check from the node's own sessions.** Each of the node's scheduled sessions must appear as an observation. If one doesn't, a coverage alarm is raised. This is the independent check against a sensor that reports full coverage while blind (AP-36).
3. **The full alarm is `network-full`**, not `store-quota-reached`, so that a detection blind spot doesn't read as a storage fault.
4. **A full alert class still names the asset.** Dropped alerts are counted by (C13 rule, destination asset), with one bucket for all unresolved destinations. The counts are shown in status and kept across a clean stop and start. After a crash, up to the last minute's counts can be lost (D3's decoy path on #532).
5. **Coalescing uses the same key, with two records per window.** For each key, the first alert record is written at once, which R6.4's latency needs. An end-of-window summary follows only if the key had repeats, and carries the hit count, the distinct-source count and the first flows' citations. The cap is 2 × rules × (enrolled assets + 1) per window.
6. **No one-way fill without a forward target.** With no alert forward target, a required local retention consumer moves past alerts older than the site's configured retention. Its cutoff advances no faster than the monotonic clock, and at most one hour past the persisted cutoff after a start, so a forward step of the wall clock gains at most an hour per restart, and each restart is an audited `service.start`. Each move is audited. The bound rests on the node's own clocks, which the audit chain can't prove (D6 T2). Drop-newest applies only if the alert quota fills within the retention period, and that is AP-36's recorded residual.
7. **The learner has its own checkpoint series, `netcheckpoint.learner`.** At the end of learning the draft is frozen. From then until acknowledgement, the learner folds nothing more and its cursor follows the detector's. At acknowledgement the learner consumer is retired, with an audit record written before it leaves the consumer set, and it never holds pruning again. Relearning starts a new one.
8. **The network acknowledgement is its own admin kind, `node.network_baseline_ack`.** Through `authorized_writers` it decides which hosts may write to relays without an alert, which is a different grant from accepting a configuration or event baseline (P4). No existing key gains it silently.
9. **A key-kind grant is recorded at first use.** The node writes `policy.apply`, carrying the collector's new keys-and-kinds digest, before it applies any decision from a reply that carries that digest. If the write fails, the decision is not applied.
10. **A DNP3 Secure Authentication failure is an alert in 0.1.** The rule matches g120v7 in function 33 (from the master) or 131 (from the outstation), after a challenge or an aggressive-mode request. It cites the challenged or aggressive-mode request and the error. Its detail says "SA authentication failed" and names the sender. It never says "forged", because a passive sensor can't check the MACs. It never gives a number of failures, because `hits` is only a lower bound under the outstation's error cap (S23 §12.4.8). Every failure code is `unknown` until the owner allows the SA specification text into the project files. It needs no baseline, so it runs before acknowledgement. `sa: failed` does not set `dnp3_no_sa`.
11. **A DNP3 request the sensor never sees answered is still observed (D3, D5).** Every pending DNP3 request completes at `sa_reply_timeout_ms`, whatever its code. The default is 5 s, bounded 1 to 30 s. The request is emitted with what has been seen by then, with `sa` absent if nothing decided it. The node never sets `dnp3_no_sa` from an absent `sa`, and `unauthorized-write` still fires from the function code. `max_pending_dnp3` bounds the pending table. On overflow the oldest pending request is emitted the same way and counted in its own coverage-loss counter (#538). At `sensor-stop`, every pending request is emitted the same way. Both settings travel in `coverage.settings`, the node refuses values outside their bounds, and R6.4's latency allows the wait.
12. **Plain HTTP stays on the insecure list, whatever it serves.** A port 80 service that only redirects to HTTPS is flagged `insecure`, because the redirect is itself sent in clear and can be stripped. The detail reads "redirect to HTTPS only, no credential seen". GT-PCAP labels follow the same rule. The owner may change this when they rule on the R6.7 candidates in D2's note.
13. **D4-67 is amended.** Its redaction slots now also cover the value of every `Cookie` and `Set-Cookie` header and the whole body of a plain-HTTP form request (`application/x-www-form-urlencoded` or `multipart/form-data`). Where a slot can't be placed, fail-closed applies to whichever side carries it, server bytes included.
14. **`a6-gt-pcap` gates GT-PCAP.** It keeps its `pull_request` trigger on its own paths. A PR that touches GT-PCAP or that workflow merges only when `a6-gt-pcap` is green, as well as `ci.yml` and `govulncheck`. CLAUDE.md's CI paragraph says so.

**Required before the sensor brief (D4).** A small C13 follow-up, merged before the sensor implementation brief is issued, adds three things:
- **D2's pairing rule.** A new DNP3 request with the same (master, outstation, application sequence number) as a pending one completes the pending one first, emitted with what has been seen. The sequence number wraps, and its width is in IEEE 1815, which the project doesn't hold, so without this rule a reused number could give a false `dnp3_no_sa`.
- **`own-session-unseen` before acknowledgement (D6).** The check covers an asset once the learner's draft holds any observation of that asset's address. From then on, a later scheduled session that goes unseen alarms. An enrolled asset never seen during learning shows in status as "not yet seen", so the gap is visible.
- **A counter of its own for DNP3 pending overflows**, apart from first-sight evictions (D6). D3 records under AP-36 (b) that a flood past `max_pending_dnp3` can lose an `sa-failed`, which shows only as `table-evictions`.

**Carried to the next C2 revision (D2, D3).** `local_addr` and `connected_at` in SessionFacts tie AP-35's known flow to one connection. The collector refuses to load when two enrolled assets share one host:port. Until then, AP-35's tie is by address and time window, and both residuals stay recorded.

**Carried to the owner.**
- Should R6.7's insecure list add IEC 104, MMS and GOOSE, C37.118, EtherNet/IP, Fast Operate inside Telnet, SNMPv3 noAuthNoPriv, AMT's redirection ports, and raw TCP serial tunnels (D2's note, #528)?
- Which protocols run on their substation networks? Can a site get a SPAN port or a TAP? Is the station network PRP?
- May the DNP3 SA specification text be placed in the project files?
- Where should the sensor run (ADR-0009)?

## D4-69: C2 0.9 is approved, with the rulings from item 4's first briefs and code (D1, 2026-11-07)

D1, on #539 to #544, with each owner's and reviewer's word through the coordinator (D4-58).

- **The item 4 briefs (#539).** Shared document types (`otsec.netbaseline/0.1`, `otsec.netcheckpoint/0.1`) go in `contracts/netobs`. `fc-classes/1` exists once, in `modules/detection/`, and the node imports its classification function. D3 writes the acknowledgement checks as pure functions in `modules/security/`, and D5 wires them into `platform/node`. The node sets `platform_session`. The full text is in `docs/agent-handoffs.md`.
- **C2 0.9 is approved** (D2's #541, `docs/phase4/D2-c2-0.9.md`). D3, D4, D5 and D6 reviewed it. It adds `local_addr` and `connected_at`, and `failed.snmp_varbinds_mismatch` for a Get or GetNext reply. Every C2 time (`started_at`, `ended_at`, `connected_at` and each segment's `at`) is bounded to at most nine fractional digits. The collector refuses to load when two assets share a transport layer, host and port, with the host compared after `Unmap()` and without the zone. `local_addr` is written unmapped and without a zone. Validate refuses a hostname, a zone, the mapped form, the unspecified address, port 0, and any other non-canonical form. The count check runs before any binding from that Response is kept.
  - **D4-60's GETNEXT bar lifts** only when the 0.9 code merges with D6's test 3 green at that head.
  - **§1.5's time rule** lives in the baseline note §5. D4 widens it for midstream TCP and held-open UDP flows, and D3, D5 and D6 review that change.
- **Audit 0.12 goes in readers first** (#534 §2.5). D3's code reads 0.12 in full, while writers still stamp 0.11, and a test pins it. D5's B5 deliverable 7 bumps the stamp, in the same change that wires `policy.apply` and `verified.keys_digest`. `authz` 0.10 bumps at once, because the collector sets `keys` and `keys_digest` in the same change.
- **Per-class capture charging covers only the network classes** (D5's #544, D6's R1). A capture whose first class is `network-observation` or `network-alert` is charged once to each class that cites it. Every other database keeps 0.8's accounting. A 0.8 node never opens the network database, so a rollback and re-upgrade can't make any class read fuller or emptier than it is. The Format stays `otsec.platform-store/2`. A `class_bytes` update that would go below zero fails its transaction.
- **C13 gaps found in coding (D4) and in its review (D2, D3), fixed within `otsec.netobs/0.1`,** since nothing has been written under it:
  - `function.sub`, on Modbus 8 and 43 only, is part of the first-sight key and the baseline's `functions` entry;
  - `MaxRedactions` is 16 per frame, and any excess is covered as one `slot-not-placed` over that side's payload, which fails closed;
  - `stored_capture` sits in `node` only;
  - `node.function_table` is present exactly when `function_class` is;
  - a Modbus 8 or 43 request too short to carry its sub-function has no `sub`, and is classed by the most restrictive row for its code: `control` for 8, `write` for 43. Function 43 with MEI type 13 is `write`, `unknown`;
  - the one `slot-not-placed` replaces that frame's per-slot `credential` entries, and the node refuses a cited frame listing more than `MaxRedactions` as `sensor-record-refused`;
  - the `contracts/netobs` decoder refuses duplicate keys, and a sensor body that carries `node`.

  The text is in C13 §14, reviewed by C13's reviewers (D2, D3, D5, D6) in #543. It merges before the `contracts/netobs` code that relies on it, and that PR cites #543 for it.
- **PRP in ADR-0009 (D4's #540, E-D4-02, simulated).** Stock Suricata and Zeek keep both PRP copies. Under options (a) and (b), a site whose station network is PRP needs a duplicate-discard stage. That stage discards only a copy that is byte-identical apart from the LAN ID. It counts a mismatched "duplicate" as a signal, and its table is bounded and counted (D3, carried to the sensor brief). ADR-0009 stays proposed.

## D4-70: item 4's contract code is merged, with the rulings from its review (D1, 2026-11-08)

D1, on #542 and #545 to #553, with each owner's and reviewer's word through the coordinator (D4-58). Merged: #543, #544, #545, #547, #548, #549, #550, #551 and #552.

- **GT-PCAP's plan (#542) and DNP3 set (#548).**
  - The node counts three drops: unresolved budget, class full and record cap. The per-window alert cap is not a drop, and a summary's hit count includes the first alert's hit.
  - The kill and restart test resumes from the node's last committed sequence number, as shown in status.
  - Each enrolled fixture host has C1 direct endpoints: SSH 22 for M1 to M3 and Telnet 23 for O1. M4 is unenrolled. The replay node schedules no collection on those endpoints (D5).
  - Counters are taken as the difference between the heartbeats that bracket a replay.
  - A before-acknowledgement run starts from an empty `network` database.
  - The no-response case is renumbered, so it shows an unanswered request and not a capture gap. A test checks that no case has a hole in either sequence space (D2).
- **C2 0.9's shared-endpoint check (#547).** `CheckPath` runs first, so only endpoints that get a session are compared. Telnet and SSH are keyed on TCP and SNMPv3 on UDP, and serial is skipped.
  - A transport this build's C1 knows, but the check doesn't name, refuses the load. A table test over `asset.Transports` keeps that branch unreachable.
  - A transport from a later C1 minor loads, and is refused per endpoint at session time (D2-16), so it can't stop collection for every asset (D3).
  - **Whatever lifts H-13 brings a port-server tie rule and port-server resolution in the same change.**
  - **D4-60's GETNEXT bar is lifted.** The 0.9 code merged with D6's test 3 green at that head: W10 in the vm1 leg, and W11 and W12 at the client.
- **Audit 0.12 and authz 0.10 (#545).**
  - `granted` requires a key the recorded set lists as active.
  - The record-local retention rules hold on every record that isn't `created`: the cutoff advances, and stays at or behind `wall_utc − retention_s`. The wall bound is compared in whole seconds with a nanosecond tie-break, so no value can wrap it.
  - An unknown key status is refused.
  - **Residual, not claimed:** `quarantine.cleared` and `collector.seq_reset_ack` name no `decision_seq`, so the chain can't tie them to a key set (D6).
  - **The writer stamp:** D4-69 stands, and `ContractID` and its pin move with item 7. Until then, a record whose action exists only in 0.12 is stamped 0.12: `store.retention_moved`, and `config.learner_retired` when its writer lands. Every other record stays at 0.11. Minors are checked per record and need not rise along a chain, and a test shows a mixed chain verifies (D5).
- **`contracts/netobs` and `fc-classes/1` (#549, #552). Each fix is made within `otsec.netobs/0.1`, since nothing has been written under it.**
  - DNP3 function 2 is `time-sync` only with g50v1 or g50v3 objects. Any other group 50 variation is `write` (D2).
  - A baseline's `sub` is checked as strictly as an observation's.
  - **Resolution (C13 §14 items 9 and 12).**
    - Each end resolves on its own, against this node's inbound endpoints and its outbound endpoints whose `CheckPath` passes. Hosts are compared after `Unmap().WithZone("")`.
    - `ip-ambiguous` means at least one end is shared, and the other end keeps its asset. The unresolved budget applies only when neither end names an asset, so filling it can't hide a write to an enrolled relay (D3 on #553).
    - A resolution through an inbound endpoint is a label for detection and `source.asset`, never identity evidence (D3).
    - The baseline does not record how an end resolved. The acknowledgement view derives that from `addresses` and C1, and marks each pair end named only through an inbound address. That duty is D3's in the acknowledgement work.
    - Two assets on one IP with different ports, and a device that uses a second address, stay unresolved there. These are stated limits.
  - **The failed-dial tie (§14 item 10, baseline note §5).**
    - A TCP `end` carries `syn_only`. It is true only when a client SYN was seen and every segment was a client SYN or a server RST, with no payload.
    - A held flow's deadline is its `start` + `connect_timeout_ms` + `flow_idle_s` + *g*, fixed when the flow starts, so nothing the sender does moves it. `flow_idle_s` is required in `coverage.settings`, in [10, 600].
    - A held flow alerts at once on a new sensor `run_id`, or on a heartbeat with a non-empty `degraded`. Held flows are checkpointed.
    - Held flows and failed-dial ties per run are capped at `connect_retries`, or `connect_retries` + 1 for a run that never connected. A flow past the cap alerts at its `start`, and status counts it. Only the run's endpoint port ties.
  - **The stored capture's byte form (§14 item 11)** is little-endian, with the nanosecond magic, snaplen 2048 and link type 1. `ts` must fit 32-bit seconds. `wire_len` must be in [`captured_len`, `MaxWireLen` = 262144].
- **The `network_sensor` section (#550 and the retention consumer).**
  - `evidence_class` refuses `device-observed` (D2-4).
  - `outage_hours` is required, in [1, 720], the bound `syslog_outage_hours` uses.
  - `alert_retention_days` is in [1, 3650]. It is required when the node has no forwarding target, and refused when it has one, so no setting is ignored in silence.
- **CI misses.**
  - The Windows Syslog rig's 15 s Serve limit was missed by 0.9 s once (#548, attempt 1), and the re-run passed. D5 opens an issue beside #230 if it recurs.
  - A second Windows failure, on #553's superseded head e23f5469 (`go (windows-latest)`, job 128600914702), is not diagnosed: the failing package sorts before `platform/node`, its log is past the readable tail, and the next head b89a8aab passed. D5 commented on #553 and opens an issue beside #230 if it recurs.
  - One Linux miss class: `TestB6HeldLinksDialAndBindNothing`'s listener port came from `:0`, inside the ephemeral range, so a parallel connection could take it (#545, #554). D6's #556 moves it below the range.
- **Test follow-ups, not blocking.**
  - D3 adds an accepted retention row exactly on the wall bound (#554).
  - D4 adds three `contracts/netobs` rows: a server `RST|SYN` is not `syn_only`, `ip-ambiguous` without `ip` is refused, and `flow_idle_s` 9 is refused while 10 is accepted (D6's surviving mutants).

## D4-71: the node's intake, acknowledgement view and alert retention are merged, with the rulings from their review (D1, 2026-11-08)

D1, on #553 to #561, with each owner's and reviewer's word through the coordinator (D4-58). Merged: #553, #554, #556, #557, #558, #559 and #560. This entry amends D4-68's item 6, whose retention bound read "no faster than the monotonic clock". The log's earlier entries stay as written.

- **`observed-address` (C4 0.3, #557).** A network observation's `source.asset` names the destination, and `sender-address` means the sender's address maps to the asset. An upstream rule keyed on it would read spoofed traffic toward a relay as sent by the relay. So C4 0.3 adds the binding method `observed-address`: an address seen in captured traffic maps to this asset.
  - It is allowed only on a network-observation event and on `netobs.alert`, and only with confidence `inferred`.
  - `Validate` refuses it anywhere else, and refuses every other method on those two kinds, `sender-address` included (D3's B1 and B2).
  - This changes nothing written under 0.3, since nothing had been.
  - Merge order: #553 merged first with `sender-address`. #557 then carried the switch in `platform/sensorlink` (D5 reviewed that hunk) and D6's `c4_v03_d6_test.go` line 17 (D6 reviewed it), so main never had the refusal without the switch.
- **`period.overflow` (C13 §14 item 13, within 0.1).**
  - It counts the folded observations that carried at least one entry the full draft couldn't hold. Each observation adds at most 1, and repeats count again. It needs no extra state, and is a sign that the draft is incomplete, not a measure of how much is missing.
  - Entries already in the draft are kept, and an overflowed entry is never merged into one. It saturates at 2^53 − 1, so every JSON reader holds it exactly, and `Validate` refuses anything above.
  - The acknowledgement view shows a non-zero count before the person can acknowledge. The signed `baseline_digest` already binds it, so C8 doesn't change.
- **The learner (#561).**
  - **TCP.** A TCP pair is learned only once its flow shows it isn't `syn_only`: an end with `syn_only` false, or a decoded function on that flow. Until then the start is held, at most 512 starts. A start that can't be held counts in `period.overflow`, and one still unproven when the period ends isn't learned. So a SYN probe during learning buys no pass, and a long-lived session that never decoded or ended alerts once if it reconnects after acknowledgement. **Residual (D3):** a client, even a spoofed one, proves a pair with a SYN and then any other segment, such as a bare ACK, and no answer from the server, because one-sided capture mustn't read as a failed dial.
  - **UDP.** A UDP start learns its pair at once, decoded or not, with the first datagram's sender as client (C13 §4.1). A capture that begins on a reply learns the reversed pair, which is a stated limit. Unknown-pair judges a UDP start both ways, but only within the same two endpoints with the learned port at the matching end. AP-36 (a) records the single-datagram residual.
  - **Both addresses (D3's S1 on #561).** An entry is learned only when both addresses it was seen at are held in the draft. An address that doesn't fit, or is refused, learns no pair. So every end the acknowledgement view judges has an address there, and `netack.InboundOnly` marks an end with none.
  - **Midstream.** A function's and a service's ends come from the protocol role, not the flow (C13 §4.3, §14 item 14): a function is the client's request, and a service's server is ip.dst. So both are learned the right way round on a midstream flow, and nothing is keyed on the client's ephemeral port. A midstream flow itself learns no pair.
  - The learner checkpoint bound grows to 705 KiB (512 held starts at 384 bytes), and B5's configuration floor counts it.
  - **Detector plan.** On a restore mismatch, the detector commits the regenerated alert and raises an alarm. Only an exact match is suppressed.
- **Alert retention (#559, #560).**
  - **Catch-up.** While the cutoff lags the wall bound, a move may advance it by up to twice the monotonic time since the previous recorded move, never past the wall bound. After a start, the allowance is a flat hour plus twice the monotonic time since the start (D3's conditions). Any lag then closes at up to an hour per hour, and D6's 60-day backlog with 7-day retention closed on day 53. **The cost:** while the wall clock is wrongly set forward, an alert survives at least half its retention, less one hour per audited `service.start` in between (D6's W1).
  - **Lag alarm.** `lag_s` is how far the monotonic bound trails the wall cutoff (D5). The recorded cutoff also stalls on a stream with nothing to pass, so it would alarm when nothing lags. The alarm is raised while `lag_s` exceeds one retention period. With no lag, the bound is held at the wall cutoff, so no lead builds up. An audited operator catch-up is deferred until the alarm fires in practice.
  - **Commit-time floor (D3's F1 and F2).** In the network database only, commit times are floored at a persisted wall high-water mark. Every commit and cursor save raises it in the same transaction, and so does every evaluation. Other databases keep their commit times, because the event baselines read them (D6), and a behaviour change there would need its own evidence.
  - **Failure handling.** A failed `Record` is re-checked at the next tick: the consumer reads the latest record back and takes the move as made only if that record continues the chain from its cursor (D6's R1). A stall keeps its error until it succeeds, so `network-retention-stalled` is raised once (R2). A cursor ahead of its record raises `network-retention-unrecorded` (D3's S1 on #559).
  - **Start cost.** Start reads the audit stream newest page first and stops at the page holding the latest record. That costs about 2 µs for each other record it passes, so about 0.2 s per 100,000, and about 40 ms for a page of 500 retention records (desk, Linux), within P4-H4's budget (D5).
- **Test follow-ups, not blocking.**
  - **D5:** P1, a node test that only the network database gets the mark (kills D6's S1), plus any of AP-36's V1 to V4 rows #559 doesn't already pin. D6 reviews it.
  - **D4, in detector PR 2a:** D6's U4 and M1 rows from #561, the no-alert-after-acknowledgement half of the UDP test, and the reversed-match bound.
  - **D6:** pins C13's bounds by value in `tests/contract`, and aligns the network stream names in `c4_v03_d6_test.go` and `c5_v09_d6_test.go` to `network-observation/<sensor>` and `network-alert/<id>`.
  - **D6 or D4:** makes `TestCaptureWireLenRange`'s constant build on 32-bit targets.

## D4-72: the detector, sensor counters and sensor status are merged, with the rulings for the own-session tie (D1, 2026-11-08)

D1, on #563 to #571, with each owner's and reviewer's word through the coordinator (D4-58). Merged: #563, #564, #565, #566, #567, #568 and #569. #570 and #571 were passed by every reviewer and merge on green. This entry amends D4-68's own-session tie (baseline note §5): the tie moves from the detector to the node's intake.

- **Sensor counters (C4 0.3, #566).** C4 0.3 adds the health type `sensor.counters`, within 0.3, since nothing had written it. Its details are the differences since the last event in the run, never totals, and are labelled as the sensor's report. Status shows the live totals. The 13 names are pinned by value against C13 §6, `netobs.Counters` and `event.SensorCounters` (#567, #570).
- **Sensor status and drop counts (#568).**
  - The node counts observations it drops by reason and by destination asset (`asset-unresolved` is one bucket). It writes them as `intake.drop-counted`, at most once a minute, retried a minute later on failure.
  - The event names at most 8 assets, ranked by count and then by ID, and sums the rest into `asset.other`, so the details still sum to `count` and the event fits whatever the asset count (D4's Low 1). A failed write raises `store-commit-failed`: a drop count that silently fails to write would break P5.
  - `ServeSensor`'s caller must authenticate the stream's peer as the configured sensor. A record's `sensor_id` only refuses a misrouted stream (D3, ADR-0009, TB6).
- **The detector (2a, #569).**
  - **Window cap.** At most `MaxDetectorWindows` (96) coalescing windows are open, each at most `MaxDetectorWindowBytes` (12 KiB), so `MaxDetectorCheckpointBytes` is 1,180,672 bytes, under the configuration record cap less headroom (C13 §7.3 item 3, §8, §14 item 16, within 0.1). When all 96 are open, a new key still alerts at once, and the window that started earliest closes early with its summary, or with no record if it had no repeats. Every hit is still counted once. **The cost:** past 96 open keys, coalescing weakens to at most one record per hit, rather than two per window (D4's correction; C13 §7.3 item 3 and baseline note §8 said two, and 2b corrects them), so `Detector.EarlyCloses()` counts each early close for status (D3's C1, P5). `sources` stops at 32 distinct addresses.
  - **Restore.** A mismatch between a regenerated alert and the committed one commits the regenerated alert and raises an alarm. Only an exact match is suppressed. A late `first_utc` never moves the capture clock or a summary's `at_utc` back.
  - `DetectorCheckpoint` names its observation stream, so a window's `related` is stored as seqs on it.
- **32-bit.** It isn't a declared target. `int64(MaxOverflow)` (#569) and `TestCaptureWireLenRange` (#568) make `GOARCH=386 go vet` clean. No 386 CI step is added unless the owner names a 32-bit site.
- **gofmt.** The `gofmt` on the PATH in some agent environments is older than go.mod's toolchain. Agents use `$(go env GOROOT)/bin/gofmt -l`, which matches CI.
- **The own-session tie moves to intake (B5 (a), option 1).**
  - Intake holds the flows from the node's own address (`network_sensor.node_addresses`, 1 to 8 IP literals, required) to the endpoint of a run it dispatched, until the run's result commits or the hold's deadline passes. Intake owns all four parts of baseline note §5: the connection tie (5-tuple, flow start in [`started_at` − skew, `connected_at` + skew]), the 0.8 window tie, the failed dial (a `syn_only` end waits with its start), and a flow still open from an earlier session (tied by its flow key until its end). A flow the run doesn't tie commits untied. The detector stays pure.
  - **Bounds.** At most `connect_retries` + 1 distinct flows per run. A new flow past that commits untied at once and is counted, and never evicts a held one. A run's record holds at most 23 records (floor(1.5 MiB / 64 KiB) − 1). If that cap is reached, the whole hold releases untied at once and is counted. **Residual (D3, AP-35):** a spoofer can use the spare slots to reach the record cap and force the platform's own flow out untied, which raises a counted `own-session-outside-record`.
  - **Open flows from earlier sessions (part (d)).** Intake keeps at most 64 open flow keys, carried in every intake record and cleared on a new sensor `run_id`, since those flows' ends will never come. Past 64, the oldest key gives way, its later records commit untied, and this is counted, so it errs toward the alert. Unlike I1, this does evict. But only tied flows enter the table, and a spoofed flow can be tied only by a 0.8 window tie, which takes only the run's first established connection (a failed dial ends `syn_only` and never stays open). So filling it takes a spoofer keeping live flows across at least 64 runs (D3), and the outcome is untied commits that alert: noise, never concealment. D3 records it under AP-35. Each key is under 200 bytes, so the table fits in the record's envelope. A held record is at most about 48 KiB (the C4 event and its capture in base64), under 64 KiB, so 23 fit `ConfigRecordBytes`. D5's PR A pins this with a test.
  - **Deadline.** The node can't see a run's `deadline_ms`, which is in `collector.json`, so the hold's deadline is dispatch + `MaxDeadlineMS` (600 s) + `tie_grace_s`. A failed dial's hold after the result runs to its arrival + `MaxConnectTimeoutMS` + `flow_idle_s` + `tie_grace_s`. So a spoofed flow to a run's endpoint during the run alerts within about 750 s at the defaults and 8,430 s at the maxima. That is bounded, never lost, and recorded under AP-35. On start and at each check, the deadline is the earlier of the stored one and now plus the limits plus `tie_grace_s`, so a backward step can't stretch a hold. `tie_grace_s` is `DefaultTieGraceS` until acknowledgement delivers the baseline's params. A run that ends without a result releases untied at once.
  - **Storage (C5 0.9, #571).** The node-owned working-state series `netcheckpoint.intake` on `netbaseline/<sensor>`, within 0.9 since nothing wrote it. One record per run, written before each hold or release takes effect. A failed or refused write commits the flow untied and raises the checkpoint-failure counter and alarm. After a release and its `collection.run` commit, the node removes every record of that run except one that is the series' newest on the stream. The configuration floor gains in-flight runs × 23 × 64 KiB (the per-run record cap). The intake document carries an `otsec.`-prefixed schema as its first field, so 0.8 readers skip it. A release also carries the run's session facts, for the start repair below.
  - Rejected: an early notice at dial time, and carrying session records on the observation stream (a C13 change for no gain).
- **The own-session detector (2b).**
  - Rules: `own-session-outside-record`, `node-address-spoofed` (on the node's own segments, from `network_sensor.node_macs`, 1 to 8 lowercase, and `node_vlans`, 1 to 4094 or `untagged`, 0 refused), and `own-session-unseen`. `own-session-outside-record`'s exclusions are exact (address, l4, port) entries derived from the forward targets and, after ADR-0009, the sensor link. There is no operator-entered list. With `network_sensor` present, a forward target whose host isn't an IP literal is refused at load.
  - **Session handoff.** The order is: release commits, the released flows commit, then `collection.run` commits with an `after_seq` detail (a node-owned type, so not a C4 change). Only then does the node call `Session(rec, after_seq)`, from the committed record, so live and restore take the same path. The detector judges a session once it has read past `after_seq`, accepts an `after_seq` equal to its `through`, refuses one below it as a node ordering fault (the call leaves its state and checkpoint unchanged and raises the alarm once), and judges sessions in call order. The node calls `Session()` for two sessions with the same `after_seq` in health-stream seq order, so that order's test is on the node side, in D5's PR B. Its checkpoint holds only the pending sessions.
  - **A failed `collection.run` write** means no `Session()` call: the session goes unjudged, is counted as sessions-not-judged in status, and raises the store-failure alarm.
  - **Start repair.** For a committed release with no `collection.run`, the node writes `collection.run` from the release's session facts, with `repaired_from: netcheckpoint.intake` (D3's R1) and `after_seq` the observation stream's head at the repair. Only a dispatched run is rebuilt, meaning one with an allowed `collector.request` audit record for its `request_id` and no `collection.run` for it on health, at most once, and each repair is counted (D3's R2). That is at least the true value and exists for a release with no flows. The repair runs before the detector restores. Whether a crashed SER run's records are re-collected depends on its cursor. A test decides it, and the record says "result not committed" unless the test shows records are lost.
  - **Node-dropped observations.** `own-session-unseen` still fires when the node dropped the own-session observation (class full or record cap), since that is a real gap. The node shows the asset's `DroppedByAsset` rise within the alert's window in the status entry beside the alert, never in the committed alert, so a restore's byte comparison stays exact. Suppressing the canary is rejected.
  - **Coverage before acknowledgement.** The detector keeps its own per-endpoint coverage record (the VLANs and PRP LANs each enrolled run endpoint was seen on, from observations neither tied nor degraded), so it never reads the learner's draft and restore stays byte-equal. The endpoints come from C1 through `DetectorConfig.Endpoints`, supplied by the node. An endpoint not yet seen raises no alert and shows in status. An overflowed draft may make the canary fire, which fails loud. Past 64 degraded intervals the oldest is dropped, never merged, so the canary isn't silenced longer. Past 128 pending sessions or 256 tied invocation IDs, the extra session counts as not judged and raises the alarm. A degraded sensor that sends nothing fires the canary, a stated limit.
  - **Checkpoint bound.** 2b's `MaxDetectorCheckpointBytes` is the sum of its parts' worst sizes and an envelope, at most 90% of the configuration record cap less headroom (1,356,595 of 1,507,328), and a worst-case fit test checks it. If the parts don't fit, a cap is lowered, the window cap first (96 to 80 saves 196,608 bytes), never the limit. It is C13 §14 item 17, within 0.1, since no detector checkpoint was written outside tests. D6 pins it after 2b merges.
- **Follow-ups, not blocking.**
  - **D5, tie-and-hold:** the above, with D6's rows for (a) to (d), a crash mid-hold, a spoofed extra flow, the record-cap release, removal leaving at most one release, a crash between release and `collection.run` (on an SER run too, and with observations committed between the release and the crash, so the repair's `after_seq` is the head and not the release's position), and the failed `collection.run` write. Also the §8 wording (the 9 MiB term covers the other three series) and the session-facts sentence, which D3 checks.
  - **D5, annotation follow-up:** the status note for node-dropped observations, `EarlyCloses` and `Mismatches` in status, the alert-class fill figure's caveat past 96 keys (D3's Note 1), `dropped_by_asset`'s restart wording (D4), and D6's M2, M6, M7 and M10/M11 rows from #568.
  - **D4, 2b:** the detector half, its suppressing mutant, the session-ordering and restore-at-every-cut-with-handoff rows, and moving baseline note §3 and §5's hold text to intake.
  - **D6:** after 2b merges, pins `MaxDetectorWindows` (96), `MaxDetectorWindowBytes` (12,288) and 2b's `MaxDetectorCheckpointBytes` together in `tests/contract`; takes D3's #568 status-boundary probe as a row; and, after #571, fixes `TestC5v09RemovableSeries`'s comment and adds `netcheckpoint.intake`'s near-miss names to the kind-series product.
  - **D3:** AP-36 (c)'s residuals (one record per hit past 96 keys, `sources` capped at 32, a reverse UDP request on a learned pair) and AP-35's hold delay and spare-slot residual, in `docs/threat-model.md`.
  - **Sensor brief (D1, after ADR-0009):** the sensor-link exclusion.

## D4-73: the intake hold and the own-session detector are merged, with the rulings from their review (D1, 2026-11-08)

D1, on #571 and #575 to #578, with each owner's and reviewer's word through the coordinator (D4-58). Merged: #571 (C5 0.9 `netcheckpoint.intake`), #575 (2b, the own-session detector) and #576 (the intake hold, D5's PR A). #577 (D6's rows) and #578 (D4's `OpenFlow` follow-up) were passed by every reviewer and merge on green. This entry corrects three parts of D4-72.

- **Correction: a silent sensor leaves the canary pending, it doesn't fire it** (D4). The detector judges a session only once its capture clock has passed the session's end plus `tie_grace_s`, and only observations move that clock. A sensor that sends nothing freezes it, so `own-session-unseen` stays pending. D4-72's "a degraded sensor that sends nothing fires the canary" is wrong. The detector reads observations, never heartbeats, so the backstop is `sensor-unreachable`.
- **`sensor-unreachable` is specified but not built.** `D5-sensor-node.md` gives it: 60 s with no heartbeat. On main, `platform/node/sensor.go` raises only the record-refused alarm, and `sensorlink` has no heartbeat timer. D5 builds it in the annotation follow-up. It uses the monotonic clock and is timed from the later of the last accepted heartbeat and the node's start. A connect never resets it, so a sensor that reconnects in a loop without a heartbeat being accepted can't hold it off (D3's S1). It is raised once per quiet stretch (including before the first heartbeat), stays raised across reconnects, clears on the next accepted heartbeat, and shows in status. D5 writes these as unit tests in the annotation follow-up, and D6 adds the same cases as independent `tests/` rows through the node API: 59 s of silence doesn't raise it and 61 s does; it is raised once, not on every tick; it is raised with no heartbeat ever; reconnecting every 30 s for 120 s with no heartbeat accepted raises it once, 61 s after the last accepted heartbeat or the node's start; a heartbeat clears it; a wall-clock step in either direction neither raises it nor suppresses it. 2b's node wiring merges only once it is on main.
- **The connection tie (correcting D4-72's text).** A `start` on the session's exact 5-tuple ties when it falls in [`started_at` − g, `ended_at` + g]. D4-72's upper bound, `connected_at` + g, missed a flow the sensor joins midstream after a restart inside the session, and a long session that `idle` splits into several `start`/`end` pairs on one key (D6's F1 on #576). Where two runs' intervals overlap, the rule is the latest `connected_at` not after the `start` plus g. At hold time intake approximates it: the flow goes to the newest dispatched run still holding to that endpoint, and a flow already held stays with its run. In the rare out-of-order case the flow commits untied and alerts.
- **The open table (part (d), D3's H1 on #576).** D4-72 let any record on an open key tie, a `start` included, and kept the entry until its `end`. So a lost `end` let a later forged `start` inherit the old tie with no time bound.
  - A `start` never ties through the open table. It removes the old entry, written first and counted (`OpenSuperseded`), and is judged as a new flow.
  - An entry expires at its latest record + `flow_idle_s` + g, which is saved as `expires_utc` and clamped to now + `flow_idle_s` + g at each use. A record past that removes the entry, counted (`OpenExpired`), and is judged as a new flow, as a start is.
  - A new sensor `run_id` still clears the table. A seq gap or degraded coverage does not: with the two rules above, clearing on those adds nothing, and it would alert on the platform's own session whenever the sensor degrades.
  - **Residual (D3, AP-35):** frames injected into a live tied flow before it expires, from any MAC, tie and skip the base rules. The expiry bounds idle time, not age: each injected record moves it, so an injector who sends within every `flow_idle_s` + g keeps the entry and its tie alive. `node-address-spoofed` checks only a flow's first frame. Closing it needs a C13 "source MAC changed within a flow" signal, for a later minor. A midstream start first seen on the device's reply has the device as `ip.src`, so neither own-session rule judges it. The base rules do, after acknowledgement.
- **Open-flow reuse (D4's finding 3 on #576).** An SNMPv3 run that reuses an open conversation's 5-tuple holds nothing, and a repeated exchange may emit no new observation (C13 §4.2), so `own-session-unseen` would fire falsely.
  - Intake's `Result` re-points an unexpired entry that the session's exact tuple matches to the new invocation, and reports `OpenFlow`. A re-point never moves the entry's expiry.
  - The node writes `open_flow: true` on `collection.run`, a node-owned detail beside `after_seq`.
  - `netdetect.Session.OpenFlow` counts the session as seen, under its own count, `OpenFlowSeen` (#578). Status shows it apart from sessions seen by a tie, so a sensor that has stopped seeing new traffic can't hide behind reused conversations.
  - **The commit rule holds for the re-point too** (D6's N1 on #576). Today the re-point takes effect before its record saves. In PR B, `Result` stages it and `release` applies it only after the releasing save succeeds. If that save fails, `OpenFlow` is false and the entry keeps its old invocation. D6's P4 is the row.
- **The handover barrier (D4's finding 4 on #576).** The live detector driver never calls `Observe` past the lowest `after_seq` of a run whose release has committed but whose `Session` has not yet been handed over. A run whose `collection.run` write fails is counted as not judged and releases the barrier. PR B adds a test that fails without the barrier.
- **2b's bounds (#575).**
  - `MaxDetectorCheckpointBytes` is 1,354,752: 96 × 12,288 for the windows, 128 × 512 pending sessions, (256 tied + 128 taken) × 128, 256 × 192 endpoints, 64 × 128 degraded intervals, 2,048 coverage, and 1,024 envelope. That leaves 152,576 bytes (10.1%) under 1,507,328, within D4-72's limit of 1,356,595, so the window cap stays 96. It is C13 §14 item 17, within 0.1.
  - **Taken sessions** (D6's F1 on #575). A tied record that arrives after its session was handed over takes no tied room, while its ID is among the last 128 handed over, which the detector keeps on the tied horizon. Past that, a late record is a tie with no session, which can later be evicted and counted, so it fails loud. Of ties, `NotJudged` counts only an evicted tie whose session never came. It also counts a session refused past 128 pending (`ErrNotJudged`).
  - **Endpoints past 256** (D1's C1 on #575). They are not tracked, so before acknowledgement their canary is silent. `EndpointsNotTracked()` counts them, and the node raises an alarm at load and shows the count in status (PR B).
- **Follow-ups, not blocking.**
  - **D5, PR B (the node wiring):** the hold switched on; the staged re-point with D6's P4; the barrier and its test; the `runFor` approximation comment; D3's assertion that the re-point leaves `Expires` unchanged; `open_flow` on `collection.run`; `RecoverHold` and one `TickHold` before `Serve`, both before `RestoreDetector`; and status for `OpenFlowSeen`, `EndpointsNotTracked` and `NotJudged`. PR B merges after `sensor-unreachable` and #578 are on main.
  - **D5, annotation follow-up:** `sensor-unreachable`, plus D4-72's list.
  - **D4:** the root cause of `TestUnknownShareDropSpendsNoBudget`'s failure under parallel load (the budget fell by 843 tokens), as its own PR, with the fix explaining the 843.
  - **D6:** after #575, pins `MaxDetectorWindows` 96, `MaxDetectorWindowBytes` 12,288, `MaxTakenSessions` 128, `MaxDetectorCheckpointBytes` 1,354,752 and the other own-session bounds by value. `sensor-unreachable`'s rows above.
  - **D3:** in `docs/threat-model.md`, AP-35's residuals above (injection on a live or just-lost open tuple, the midstream reply, and a forger who keeps an entry alive into the next SNMPv3 reuse). AP-36 (b)'s silent-sensor backstop is already on main, from #574.
  - **Sensor brief (D1, after ADR-0009):** the sensor-link exclusion, D3's PRP discard rule, D4's offline resume, and the C13 "MAC changed within a flow" signal as a candidate for the next minor.

## D4-74: `sensor-unreachable` is merged, PR B is split, and the rulings for B1's review and B2's questions (D1, 2026-11-08)

D1, on #579 to #586, with each owner's and reviewer's word through the coordinator (D4-58). Merged: #579 (D4-73), #580 (AP-35's residuals), #578 (`Session.OpenFlow`), #577 (D6's rows), #581 (`sensor-unreachable`, D5), #582 (D4's fix for the receive test's budget), #583 (D6's V-M8 harness fix), #586 (C13's `frames_missing`, D4) and #584 (B1, D5).

- **`sensor-unreachable`'s timing (D1 on #581).** It has no timer of its own. It is raised at the first `Tick` at or after 60 s of quiet, so at most 60 s + `TickInterval` (120 s or less today) after the last accepted heartbeat or the node's start. D5's cadence test holds it. D6's node-API rows allow for the tick.
- **PR B is split in two.** B1 switches the hold on in the node. B2 adds the detector consumer: the `Session` calls, the handover barrier, `RestoreDetector` and the detector's status counts. B1's condition is that `collection.run` carries every field `netdetect.Session` needs, with a test that rebuilds the session from the committed record alone. B2 adds a first-start row (below). The text for `dropped_by_asset`'s status moves to B2.
- **B1's review (#584). These are fixed in B1, before merge.**
  - **The repair covers a run that is still waiting (D3's R3).** The start repair takes every run that is not `Holding` and whose newest record has a session, so a `Waiting` run with a dial outstanding is repaired too, not only a `Released` one. `RecoverHold` has already settled any `Releasing` run. This matches the live path, which writes `collection.run` at the first release while a dial still waits. `after_seq` is the head at the repair. A repaired `Waiting` run's records stay until `TickHold` releases it, then the prune removes them. Row: a crash after a release with one dial waiting gives one repair, and a second restart gives none.
  - **The repair reads `open_flow`, never infers it (D4's F1).** The releasing record saves `Released.OpenFlow`, and the repair reads it. Inferring it from the open table counted the run's own tied flow as a reused conversation, so a repaired session landed under `OpenFlowSeen` where the live path counts it as seen by a tie. Rows: the run's own tied flow still open gives `open_flow: false`, as live, and a real re-point gives `true`.
  - **A run with no session is counted (D4).** A `Link.Result` that fails, and a dispatch whose save failed so nothing is held, write a `collection.run` with no session. B1 counts each as `runs_session_missing` in the sensor's status, with a row for each, and B2 counts them as not judged.
  - **A repaired run's status and `events` (D6's F2, D5's proposal).** A crash between the SER batch and the health batch leaves the run's SER rows and the source cursor committed, so the next run doesn't read them again. The repaired status is `not-recorded` (the run's ending record was not stored), replacing `not-committed`. B1 merged with `not-committed`; B2 renames it, which is safe because no hold record exists outside tests. `events` stays, counted: the intake document saves the SER stream's head at dispatch (`evidence_head`, 0 for a run that stores no SER), and the repair writes the number of committed rows after it whose `collection.invocation_id` is the run's. A configuration read or SNMP run writes 0, as live. `D5-c5-0.9.md` §8 says the SER cursor commits with the SER rows. Row: a crash between the two batches gives `not-recorded`, `events` equal to the committed rows, and no re-read.
  - **Only the run's own record counts as recorded (D6's F3).** The repair and the prune match only the run's `collection.run`, or its `collection.outcome-unknown` of a quarantined result, never another record that names the request, such as `collection.missed`. D6's P3 is the row (`TestIntakeRepairPastMissed`).
  - **Rows for D6's surviving mutants:** a `collection.run` that isn't stored keeps the hold records (R6); a denied `collector.request` is refused (R13); a bad `asset_id` in a hold record is refused (R10). From D6's second round: a failed releasing save keeps the old invocation and reports no re-point (S3, `TestHoldRepointSaveFails`), and a quarantined result after the release counts as recorded (S10, `TestIntakeQuarantinedAfterRelease`).
- **B2's questions (D5).**
  - **An alert whose cited frames aren't all stored (D4 owns C13).** A repeat observation can cite frames whose first-sight capture was evicted, dropped or pruned. A header-only capture with no signal would mislead V-M6 and any reader, because C13 §7.1 says the capture holds the cited frames. D4's C13 change is approved as their next PR:
    - The capture holds the cited frames still stored, in citation order.
    - The cites list every frame.
    - A new `frames_missing` (0 to the cited count, absent when 0) is range-checked by `Validate`.
    - The node's `alerts_frames_missing`, the number of alerts committed with `frames_missing` above 0, is shown in status.
    - An alert is never dropped.
    - It amends 0.1 in place only if no merged code has committed an alert, and the PR shows the search. Otherwise it is 0.2.
    - D5's index (4,096 entries, oldest out) from frame SHA-256 to capture is rebuilt at start from the retained first sights. A frame whose capture was pruned counts as missing.
    - D6 adds a V-M6 row for an alert with a frame missing.
    - A header-only capture without the field is not allowed.
  - **Checkpoint cadence.** `netcheckpoint.detector` is written at each `Tick` where `through` moved, and at a clean stop. The cursor is confirmed only after that commit, and older checkpoints are removed, as `identity.read`'s are. Two conditions:
    - A write that fails keeps the old cursor and raises an alarm.
    - A crash after an alert commits but before its checkpoint gives one alert on replay, not two. The detector already does this: `RestoreDetector` matches regenerated alerts against the committed alerts after the checkpoint's `last_alert_seq` (`TestDetectorRestoreAtEveryCut`). B2 reads those from the alert stream and passes them in, and adds a node-level row (D4).
    - B2's body gives the checkpoint's size at the 2b bound and its writes per day.
  - **First start with no checkpoint.** The detector begins at the oldest retained observation and replays the retained `collection.run` sessions in seq order, interleaved by `after_seq`, under the handover barrier. A session whose observations may have been pruned is never judged `own-session-unseen`:
    - When the observation stream has been pruned, a connected session that is not `open_flow` is judged only if `started_at` − g is at or after the first observation read's capture time + g.
    - Any other connected session that is not `open_flow` is not judged, with the reason `before-retained`. An `open_flow` session counts as `OpenFlowSeen`, as now.
    - The node applies the guard: it skips such a session before calling `Session` and counts it itself, so the detector doesn't change (D4).
    - Status shows not-judged by reason: `pending-full`, `tied-evicted` (a tied ID evicted past 256 whose session never came), `before-retained` and `session-missing`. D4 splits `NotJudged` into the first two in `netdetect` as a small PR before B2 merges.
    - D6's rows: on a pruned stream, a session whose flows were pruned raises no `own-session-unseen` and shows `before-retained` 1, and a session inside the retained range gets its verdict.
- **Candidates for the sensor brief (D1, after ADR-0009)**, beside D4-73's list:
  - A sensor that keeps sending heartbeats but has gone blind shows as flat packet counters. `sensor-unreachable` can't see it.
