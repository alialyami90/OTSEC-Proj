# P3 brief: retry a database whose open failed on a transient lock (A5)

Status: approved by A1 as designed, as a Phase 3 task (2026-10-25). No code is written until the owner starts Phase 3.

## Objective and rationale

C5 startup leaves a database in `ModeFailed` when `StartupEnv.Open` fails, and `c5.Resume` returns `ModeFailed` unchanged ("needs a restart", `contracts/store/startup.go`). That fails closed, which is correct. But a transient cause then stops the node until someone restarts it. When `audit.db` fails, `asset-suspensions-unknown` holds every run.

The one transient cause seen so far was `SQLITE_BUSY_RECOVERY` (261). A read-only `otsec health` met the node's first read after a kill (store-full e2e on 9c50395). #138 fixed it by setting `busy_timeout` before any statement that reads the file. A busy or locked open can still happen if WAL recovery takes longer than the 5 s timeout, or from a cause not yet found (A3 on #138). This task makes that case recover by itself, without weakening any other failure.

## Owner and reviewers

- **Owner:** A5.
- **C5 amendment:** A1 approves.
- **Contract tests:** A6.
- **Rebuild path and trust boundary:** A3.

## Design (approved as (a) to (c))

**(a) C5 amendment: `Resume` from `ModeFailed`, narrowly.** `Resume` re-runs startup from the open step only when all of these hold:
- the failed step is `StepOpen`;
- the alarm is `store-open-failed`;
- the cause is SQLite busy or locked: primary code 5 (`SQLITE_BUSY`, including 261 `BUSY_RECOVERY`) or 6 (`SQLITE_LOCKED`).

The store has to report that cause as a typed error, never by matching the error text. These stay terminal: integrity, format (`meta` mismatch), stream-class, settings (`CheckSettings`) and lock (`otsec.lock`) failures, and any other open error. A database that is corrupt or not this node's is never retried silently.

**(b) Tick retries.** `Runtime.Tick` calls `Resume` for such a database at most once per tick, under the state write lock, as it already does for blocked and drain-only databases. A retry that fails again keeps `ModeFailed`, and its alarm is raised once for the condition, not at every tick.

**(c) The audit database comes back.** When `audit.db` leaves `ModeFailed`, the scheduler rebuilds the suspensions from the stream before it sends any run. It uses the same path as `NewScheduler` at start: the checkpoint, the records after `through_seq`, and the unaudited ones written. `asset-suspensions-unknown` clears only after that rebuild succeeds. A rebuild that fails keeps every run held, as at start.

**Condition from A1.** A successful retry writes its own `store.mode_change`, a C8 audit record and a C4 health event, from `failed` to the new mode (`ModeChangeOf`). The audit trail then shows the recovery. For `audit.db` itself, that record is written once the database accepts it.

## Files

- `contracts/store/startup.go`, plus the C5 version and changelog (A1-approved amendment)
- `platform/store`: the typed busy or locked cause from `Open`
- `platform/node/runtime.go`, `platform/node/schedule.go`, `platform/node/README.md`
- `docs/phase2/A5-node.md`, or the Phase 3 equivalent

## Acceptance tests

1. **C5 (A6).** `Resume` from `ModeFailed` with a busy or locked open cause re-runs from open. From every other failed step or cause, it returns `prev` unchanged. Table-driven over every `Step` and alarm code.
2. **Store.** A database opened while another connection holds an exclusive lock past `busy_timeout` fails with the typed busy cause. A `meta` mismatch, a stream-class mismatch and a bad setting do not carry it.
3. **Node.** `audit.db` fails at start on a held lock, and runs stay held with `asset-suspensions-unknown`. The lock is released. At the next `Tick` the database opens, `store.mode_change` `failed`→`collecting` is in the audit stream, the suspensions are rebuilt, and runs resume. A suspension recorded before the failure is still enforced after the retry.
4. **Node, terminal.** A database that failed on format or settings is not reopened by `Tick`, and no second alarm is raised.
5. **Alarm once.** Three ticks that each fail to reopen raise the open alarm once.
6. **Mutants.** Each of these must fail a test: retrying every `ModeFailed`; never retrying; resuming runs before the rebuild; skipping the `store.mode_change`.

## Exclusions

- Retrying any failure other than an open that is busy or locked.
- Changing `busy_timeout` or the open order (#138).
- Compaction.
- A retry inside one startup run. The retry belongs to `Tick` only, so the startup deadline is unchanged.

## Risks

- **Misclassification.** A permanent failure classed as transient would retry forever. Each attempt costs one open per tick, and the alarm is raised once. The typed cause and test 2 are the control.
- **Retry racing a read-only CLI.** A retry that meets a read-only CLI is bounded by `busy_timeout`, as the startup open is.
- **Rebuild against a changed stream.** The rebuild reads records written while the database was failed. There should be none, since nothing writes to a failed database. Test 3 checks the chain with `audit.VerifySuspensions`.

## Phase 2 limitation (for the exit report)

A database whose open fails stays failed until the node restarts, and `otsec health` shows it. #138 removes the only cause observed so far.
