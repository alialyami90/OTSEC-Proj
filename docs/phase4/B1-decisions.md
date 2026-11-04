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
  - A `config.change_detected` in the view against that baseline's digest stays open until a record in the view ends it: a restore, a configuration acknowledgement, or an approval that covers it.
  - A change in the view against any other digest is not open. Its baseline was replaced by an acknowledgement that the prune removed.
  - C5 builds this in #390's chain fold, using the same baseline lookup as `compareConfig`'s pruned check. C6's G2 probe becomes its test: `open` must be the same for the full fold and the pruned fold.

## D4-42: an oversize configuration difference is recorded without a stored difference (C2 on #392)

Date: 2026-11-04. C1, on section 4 of `docs/phase4/C2-c9-0.4.md` (C9 0.4, #392).

- **The fact.** C2 measured the SEL-751's settings sheets (`contracts/config/testdata/difference_max.py`). A read in which every setting of every form changes makes a difference of 1,615,535 to 1,738,065 bytes, 7.2% to 15.3% over the bound (C2's table, six rows; C1 re-ran `difference_max.py` on `pdftotext -layout` of the manual and got the same six rows). Both snapshots fit, but the difference does not fit `MaxDifferenceBytes` (1,507,328 bytes). A realistic large change fits: 8,500 settings of 30 characters encode to about 1.22 MB. Evidence class: `desk` for the measurement, `simulated` for the tests. C9 0.4 makes the case visible: `Validate` refuses with `ErrTooLarge`, and `Compare` still returns the difference with that error.
- **The ruling: C2's option (a).** Only `Compare`'s own size refusal of the difference takes this path. `ErrTooLarge` alone does not say which document was too large, because a snapshot's size refusal wraps it too (C5 on #392), so the path keys on `ErrDifferenceTooLarge` (#392), which wraps `ErrTooLarge` and comes only with the difference itself. Any other `Compare` error stays `config-not-compared`, because `Compare` returns a zero `Difference` for those. On `ErrTooLarge`, the node:
  - records the change as `config.change_detected` with `changes_digest` from the returned difference and no `difference_digest`, plus a field that says the difference was too large to store;
  - raises `config-unapproved-change` as for any change not covered by an approval, with "difference not stored: too large" in its text (my ask to C5 on #390);
  - holds the read's snapshot with the same hold the normal path takes (`unapproved-difference`, or `approved-difference` under C5 0.7), only without a difference beside it, so reconcile and rule 3 are unchanged. The baseline is held `baseline`, and `Compare` is a pure function of the two stored snapshots, so the difference can be recomputed whenever it is needed. No evidence is lost.
- **Refused.** Options (b), a difference without values, and (c), one with only the new values. Each changes C9's stored format to cover a case that needs a whole relay reloaded at once. And `changes_digest` would no longer be computable from the stored difference alone.
- **What stays unchanged.** Approval (`node.change_approval`) names a baseline and a window, not a difference, and acknowledging the read as the new baseline names its snapshot digest. So an oversize change can be approved and acknowledged like any other. `config.read_compared` with `same_change` already names a change by `changes_digest`.
- **Who.**
  - C3 builds the C8 change as C8 0.10 (#393): `difference_too_large`, a boolean on `config.change_detected` only. From 0.10 a detection carries `difference_digest` exactly when that field is absent. `VerifyConfig` reads audit records only, and no chain rule names `difference_digest`, so a too-large detection verifies as any other (C3). The check that the change is the one recorded is a store check: `Compare(baseline, snapshot).ChangesDigest()` equals `changes_digest`. It belongs to C6's tests and to an auditor, not to `VerifyConfig`.
  - **Upgrade order.** A 0.9 reader refuses a 0.10 record with `difference_too_large`, because it still requires `difference_digest`. That fails closed. So every reader of a chain must be at 0.10 before a node writes the field. Both binaries ship in one release, so a forward upgrade meets this. A rollback below 0.10 after such a record is written fails start-up verification closed. This goes in the rollback note with C5 0.7's, and in the exit report's open items.
  - C5 builds the node side in #390, switching `encodeDifference` to `Difference.Encode` once #392 merges. The fold's `wants()` (`platform/node/holds.go`) skips an empty difference digest, so a too-large detection asks for no difference hold (C3). #390 merges only after C8 0.10 and #392, so `main` never writes a `difference_digest` that names a difference that was not stored (C5's interim 0.9 record at fbbcbf5).
  - C6 tests three things: an every-setting change that is alarmed and recorded with no stored difference; a `changes_digest` that equals `Compare` re-run on the two held snapshots; and a realistic large change that is still stored as a difference.
  - C9 0.4 (#392) needs nothing more.
