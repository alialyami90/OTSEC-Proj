# Handoff P3-A5 — A5 — 2026-10-27

The briefs are "Task P3-A5" and "Task P3-A5/A6" in `docs/agent-handoffs.md`, plus A5's parts of P3-A3 and P3-A4. Every result below is `simulated`, or from the GitHub-hosted Windows runner where that is stated. Nothing here ran against a device or on the owner's PC.

## Completed

- **The failed-open retry** (C5 0.2, #145; the node, #147). This is the approved brief `docs/phase2/A5-p3-failed-open-retry.md`.
  - `CodeOpenBusy` comes from SQLite's result code (`SQLITE_BUSY` or `SQLITE_LOCKED`, any extended form), never from error text.
  - `Resume` re-runs startup steps 4 to 8 under the lock already held, and every other failure stays terminal.
  - The node retries a database whose open was only busy at each tick.
- **Quarantine export and audited clear.**
  - C5 0.3 `Discarder` (#151, D3-1): it removes named seqs of a quarantine stream only, at most 16 per call, and skips a seq already gone. 16 is the step because 50 seqs wrote 997 KB of WAL, nearly the whole 1 MiB recovery reserve.
  - The agreed design is `docs/phase3/A5-quarantine-export.md` (#152).
  - The node side is #163:
    - `otsec quarantine export` writes the stream byte for byte with a hash manifest, and copies the manifest into `admin_dir`. It opens the store read-only.
    - The node checks that copy against its stream both ways and records `quarantine.exported` (C8 0.3).
    - `clear-quarantine.json` applies only to a recorded export. The node records `quarantine.cleared` before it removes anything, then removes in Discard steps driven by the record, so a kill resumes the removal.
- **Syslog listener wiring** (#154, A5's part of P3-A4): the C5 classes, the node's listeners, status and `otsec health`.
- **Listener sizing** (#169, HR-11 option (b)):
  - `syslog_outage_hours` sizes each listener's unknown-sender share.
  - The loader refuses quotas too small for the share or for one batch.
  - The node warns on listener certificate expiry, and on targets below 18432 `max_message_octets`.
- **The node's relay of signed admin requests** (#189, PR 1 of the #181 design).
  - The node reads `admin-request-<name>.json` under the protected-file rule and sends the signed envelope to the collector unchanged, audited before it is sent.
  - It records the collector's decision with the person as actor on an acceptance.
  - The decided set is folded from the audit stream, so a file is sent once across restarts and across a lost checkpoint.
  - Only the three credential kinds are relayed.
  - The follow-ups (#197) are a `RelayTimeout` deadline per request, one stall per tick at most, and tests for A6's surviving mutants. #202 fixed the stall test's bound on Windows (below).
- **The unknown budget across restarts** (#198, D3-3).
  - At start the node counts the asset-unresolved bytes the listener stream holds inside the trailing window, by received time, and passes them as `receive.Config.UnknownSpent`.
  - If it cannot count, the budget starts empty and `syslog-unknown-budget-uncounted` is raised (fail closed).
  - Status shows `spent_at_start_bytes`.
- **The slice's Windows service mode** (#179, gate item 1; open at this handoff).
  - `OTSEC_SLICE_SERVICE=1` in an elevated shell runs the slice against `otsec-node` and `otsec-collector`, installed by the real installer and driven through the SCM.
  - The credential goes through the product's relay.
  - Teardown always uninstalls and fails the run on anything left behind.
- **Reviews**: #195 (A6's relay end-to-end check) and #199 (the restart check's status fields and restart path).

## Evidence

- **Unit and contract tests:** `go test ./platform/store ./platform/node ./cmd/otsec`.
  - A6's independent checks are recorded on each PR and in `docs/verification.md`. The clear killed 8 of 8 mutants (#163). The retry contract killed 15 of 17, and the 2 that survived fail closed. The relay's end-to-end check passed 18 of 18 (#195).
- **Service mode on the hosted Windows runner.** Each run was elevated, against the real installer, on a branch not meant for merge. The runs are listed on #179:
  - 40425877683: `e2e`, `identity` and `failures` gave 40 passed.
  - 40445047367, the whole slice directory: 159 passed and 7 skipped (the rsyslog leg). The 18 errors were the admin-relay leg's `need()`, which A6 has since made a platform skip (#199). Every service-mode test passed, and nothing was left behind in any run.
  - 40442872450: one transient `PermissionError` opening `state.json` in the harness-only `age_state` step. The step now retries for 30 s and notes each refusal.
- **The relay stall test on Windows** (#202, run 40446879018, five runs). The collector held each tick for 300.3 to 300.6 ms against a 300 ms `RelayTimeout`, with one request per tick. The node's own work took 27 to 36 ms. The 614 and 662 ms ticks that failed on main were that work slowed down by the rest of `go test ./...` running beside it, not a second wait.

## Interfaces

- C5 0.2 (`CodeOpenBusy`, `Report.OpenBusy`, `Resume`) and C5 0.3 (`Discarder`), each with A1's approval and a rollback note on its PR.
- Node configuration: `syslog_outage_hours` and the listener fields of #154 and #169.
- Status: listeners' `unknown` share (with `spent_at_start_bytes`), `admin_requests` and `quarantine`. `otsec health` shows each of them.
- The files in `admin_dir`: `admin-request-<name>.json` (C7, relayed), `clear-quarantine.json` and its manifest copy, and `clear-suspension.json`. The last two are unsigned until relay PR 2.
- No contract was changed without its owner's PR.

## Limitations

- **The owner's PC run (gate item 1) has not happened.** It needs #179 merged, the owner's choice of how the PC gets Go 1.26.10 (`GOTOOLCHAIN=auto` would download a toolchain), and the owner present for UAC.
- **The fresh-state floor is not exercised on installed services.** `age_state` moves the installed collector's `created_utc` back an hour so the run stands for an earlier commissioning. Collector unit tests and V-S13 cover the floor.
- **No end-to-end Windows check of the admin relay or of `admin_dir`'s ACLs** (A6's recorded gap). Only C7's contract tests and the node's unit tests run in the Windows Go job.
- **The node does not read its TLS keys from the key register yet** (#176, open). The D2-12 files stay behind the lab flag until then.
- **Unsigned files:** `clear-suspension.json` and `clear-quarantine.json` are still unsigned administrator files under D2-15's folder rule (relay PR 2).
- **Unknown-budget start count.** It reads the whole stream window at start, page by page. A store that kept a running total would make it constant-time (Phase 4).

## Risks

- **HR-11 stays open.** The budget now holds across restarts, but a forward wall-clock step followed by a restart still refills it.
- **The relay is an authority path.** The node carries signed requests but verifies nothing. Every refusal and every repeat answer comes from the collector (C7 0.5). A file the node could write is never read.
- **A harness-only state edit.** `age_state` writes the collector's own state file. It lives only in `slicerun.py`, and no product code does this.

## Dependencies

- **A1:** merge #179 when its CI and the service-mode run are green and A6 confirms. Then the owner's session for the PC run.
- **A6:** the PC run and its record in `docs/verification.md` (V-S6 and V-S9 Windows rows).
- **After the gate (A5):**
  - #176, the node reading the key register;
  - #177, bounded crash children in the store tests;
  - #182, the refused-identity detail and the record bound comment;
  - relay PR 2 of #181: signed `clear-*`, `node.quarantine_clear` and `node.seq_reset_ack`, A3's C8 0.4 fields, and N1/N3.
- **A3:** review of relay PR 2's trust boundary when it opens.

## Files changed

- `contracts/store/` (C5 0.2, 0.3)
- `platform/store/`, `platform/node/`, `cmd/otsec/`
- `tests/integration/slice/slicerun.py`, `slicehelper/`, and the slice files' service-mode skip lines (#179). I carried A6's rsyslog-leg skip there at A6's request.
- `docs/phase3/A5-quarantine-export.md`, `platform/node/README.md`, this file

## Reviewer(s) and outcome

- #145, #147, #151, #152, #154, #163, #169, #189, #197, #198 and #202 were merged by A1 on the reviews recorded on each PR (A3 for trust boundaries, A6 independent, A4 on the listener wiring).
- #179 is open, waiting on its service-mode run on the merged head and A6's confirmation.
