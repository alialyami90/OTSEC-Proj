# A6 review of #77 (platform/store, C5 on SQLite) at `c0f1703`

Reviewer: A6 (P2-A5 reliability review). Evidence class: **simulated**. Everything below ran in the Linux container, Go 1.26.0, against real SQLite files, with the process killed through the store's own test hook. Nothing here is power-loss or hardware evidence (H-11). The Windows leg is still owed.

## What I ran

- `go vet ./...`, `gofmt -l .` (empty) and `go test -race -count=1 ./platform/store/ ./contracts/... ./tests/contract/`: all ok.
- #77 merged with main (#74) cleanly, and the D2-1 import-rule test passes on the merge: `modernc.org/sqlite` and `golang.org/x/sys` are the only third-party imports.
- Probe tests of my own, kept out of the repo (`a6probe_test.go`, in package `store` so they can use the hook).

The D1-11 cases hold against the real store: with audit at quota the act never runs and Syslog still commits, and after a commit of unknown durability every later act is refused. The kill test's oracle (every receipt survives byte for byte unless a persisted cursor allowed its prune) is the right one.

## Must

**1. A kill during the first open leaves a store that never starts again.** `open` creates an empty file, sets `auto_vacuum` and `journal_mode=WAL`, and only then runs the `create` transaction. If the process dies at `create:begin` or `create:commit`, the next start sees an existing file, skips `create`, and fails for good:

```
restart mode failed: step open: read streams: SQL logic error: no such table: streams (1)
```

Left on disk after the kill: `evidence.db` (4096 bytes), `-shm`, an empty `-wal`, and the lock file. It is fail-closed, but a node killed or powered off during its first start, which is when installers and service managers restart things, needs someone to delete the file by hand. Recovery from a crash is a stated requirement (brief 1.8).

Suggested fix: build a new database at `<id>.db.new` (pragmas, schema and meta in one go), close it, sync it, rename it to `<id>.db` and sync the directory. Remove a leftover `.new` at the next start. Then add `create:begin`, `create:commit` and `streams:commit` to `crashPoints`. `streams:commit` (adding a stream to an existing database) already recovers in my probe.

## Should

**2. `CommitBatch` stores a capture without checking its digest, and the dedupe then drops the right bytes.** Called directly with `Capture{SHA256: h, Bytes: <other bytes>}`, `CommitBatch` returns no error. A later `Log.Append` with the correct bytes for `h` also succeeds, but it stores nothing, because `h` is already in `captures`. `ReadCapture("sha256:"+h)` then fails for every record that refers to it:

```
stored capture sha256:de5e...: store: invalid: capture digest "de5e..." does not match its 15 bytes
```

`Log` runs `Record.Validate` before queueing, so the normal path is safe. But the store is the last place native evidence can be checked before it is kept, and a bad first write poisons every later correct one. Calling `r.Validate()` for each record in `CommitBatch`, refusing with `CodeInvalid` before the transaction, costs one SHA-256 per record. The slice suite's check that the stored transcript digest equals `transcript_sha256` in the audit chain depends on this.

## Nit

**3. `assignSeq` and `replaceMember` say every other byte stays as the producer wrote it.** Member values do keep their bytes. Whitespace between members does not: `{ "schema" : ...` is stored as `{"schema":...`. Escaped member names are respelled too: `"id"` (which C4's strict decoder accepts) is stored as `"id"`. Nothing I know of depends on the producer's exact bytes, so correcting the comment is enough.

## Not findings, recorded for the verification record

- On Linux the lock is `flock` on `<id>.lock`. On Windows it is share mode 0 on the same file. Neither stops a process that ignores it from opening the `.db`. The doc says this and names the directory mode and DACL as the barrier. I checked the Linux mode refusal (`checkDir`) and `TestFileModes`. The Windows DACL is W-4 and is not tested here.
- Quota counts payload bytes, not pages. A capture stored by one class and then referred to by another is charged only to the first. That's harmless in Phase 2, where captures come from adapter evidence only.

## Verdict

Changes requested for must 1. Should 2 and nit 3 can go in the same push. I'll re-check with the same probes.

## Re-check at `aac8b97` (with `bb03da1`): accepted

Same container, same probes, evidence class simulated.

| Finding | Probe at `aac8b97` |
| --- | --- |
| Must 1 | A kill at `create:begin` or `create:commit` leaves only `evidence.db.new` (and its `-shm`/`-wal`). The restart reaches `collecting`. `streams:commit` still recovers. The kill test now has `startPoints` for these. |
| Should 2 | `CommitBatch` with a mismatched capture is refused with `invalid: capture digest ... does not match its 15 bytes`. A later correct `Log.Append` stores the bytes, and `ReadCapture` returns them. |
| Nit 3 | Comment corrected. |
| #78 seam | `SaveSourceCursor` (`bb03da1`) commits in its own transaction after the same stream and settings checks as `SaveCursor`. |

`go vet`, `gofmt` and `go test -race ./platform/store/ ./contracts/store/` pass. The Windows cross-build (`GOOS=windows go vet` and `go test -c`) passes. The native Windows run is still owed (D2-8).
