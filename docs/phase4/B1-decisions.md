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
3. **Touchscreen HMI settings** (`SET_HMI.zds`, `CDP.zds`) are files, and P4-A2 excludes file transfer. They are not baselined, and this is recorded as an exception in the capabilities and in C9's limitations. Whether touchscreen models are in scope is an open question for the owner.

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
