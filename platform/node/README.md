# Node configuration: `otsec.nodeconfig/0.1`

Owner: A5. This is A5's file format, not a shared contract (A1 D2-6). Other agents read it only through `node.LoadConfig` or `node.ParseConfig`. Tests write it only through [`nodeconfigtest`](nodeconfigtest/) or, from Python, as the JSON below.

The node reads one file at startup. A change takes effect at the next restart, because the store layout is fixed at startup (C5 0.1).

## Reading rules

The loader refuses the whole file for any of these:

- a field it does not know;
- a duplicate key;
- a key with an upper-case letter, so that `NODE_ID` cannot stand in for `node_id`;
- anything after the object;
- a file larger than 4 MiB;
- a `schema` other than exactly `otsec.nodeconfig/0.1`.

Assets are C1 records, read with `asset.Decode`. Targets are C6 targets, read with `syslog.ParseTarget`. Each is checked by its own contract.

## D2-4: no `device-observed` in Phase 2

Every asset endpoint and every listener has a `target`. The loader refuses `device-observed`, with `ErrDeviceObserved`, and every value other than `simulated`. A missing target is refused too: it is never given a default (D1-24). The collector refuses the same thing again on its side (A3), so the two locks are independent.

Lifting this lock needs the owner's authorization of a named lab device, recorded in a decision.

## D2-10: loopback only

Both D2-4 locks read the same administrator-set label, so a third lock ignores it. The loader refuses, with `ErrNotLoopback`:

- an asset endpoint other than inbound Syslog whose `host` is not a loopback IP literal (127.0.0.0/8 or `::1`);
- a listener whose `address` is not on a loopback IP literal.

Host names are refused, `localhost` included, so the check never depends on name resolution. A zone (`::1%lo`) and the IPv4-mapped form (`::ffff:127.0.0.1`) are refused too. Forwarding targets are not covered: the upstream collector is not a device. The collector makes its own loopback check (A3). Lifting the lock follows D2-4.

## Fields

| Field | Meaning | Checked |
| --- | --- | --- |
| `schema` | `"otsec.nodeconfig/0.1"` | exact match |
| `node_id` | This node | lowercase DNS label (`contracts/node`) |
| `store.dir` | Store directory | absolute path. The store also checks the directory itself: mode 0700 on Linux, and the installer's DACL on Windows. A link or a junction there is refused, and so is a database file that is a link or whose own mode or DACL is wider |
| `store.quotas` | Bytes per C5 class, keyed by class name (`adapter-evidence`, `syslog-stream`, `syslog-datagram`, `platform`, `audit`) | each positive. Every class the layout needs must have one |
| `store.warn_fraction` | Fraction of a quota that raises `store-quota-warning` | in (0, 1) |
| `syslog_outage_hours` | The upstream outage the syslog classes must ride out while unknown senders store; 0 or absent means 24 | 0 to 720. With listeners, the syslog quotas must be large enough for it. See "Syslog listeners", **Unknown senders' storage** |
| `listeners[]` | Syslog listeners: `id`, `transport` (`syslog-udp`, `syslog-tcp` or `syslog-tls`), `address` (`ip:port`), `target`, and `plaintext` or `tls` | unique ids; `simulated` only (D2-4); a loopback address (D2-10). A `syslog-udp` or `syslog-tcp` listener must set `"plaintext": true`, its own per-listener setting (owner decision D3-5). No other flag implies it, and an entry without it is TLS. A `syslog-tls` listener must not set it, and needs `tls`: `credential_ref`, optional `sender_ca_ref`, and `require_sender_cert`, which needs `sender_ca_ref`. See "Syslog listeners" |
| `assets[]` | C1 asset records | `asset.Decode`; every endpoint `simulated`; every collection endpoint on a loopback IP literal (D2-10); `asset.CheckSenders` across all assets |
| `targets[]` | C6 forwarding targets | `syslog.ParseTarget`; unique names |
| `schedule[]` | `id` (the C7 schedule principal the runs are made for), `asset_id`, `endpoint`, `operation` (a C3 operation ID such as `sel.ser.read_all`), `params` (optional), `credential_ref` (a C7 handle, absent for a level 0 operation) and `every_seconds` | see below |
| `collector_pipe` | Where the collector listens | `\\.\pipe\<name>` on Windows; an absolute socket path on Linux |
| `collector_peer` | The identity the collector must hold | Linux: required, the collector's uid. Windows: empty means the `otsec-collector` service SID |
| `admin_dir` | Where an administrator leaves Phase 2 interim files such as `clear-suspension.json` (D2-15), and signed `admin-request-*.json` files the node relays (P3-A5) | absolute; optional. Without it no suspension can be cleared. The installer requires `OTSEC\config\admin`, which the node and the collector both read and neither writes |
| `collector_public_dir` | Where the collector publishes `install-key.json` (A3 #106); the node reads it before every request (D2-15) | absolute; required when anything is scheduled. The installer requires `OTSEC\collector\public` |
| `tls_dir` | The directory holding the files the targets' and listeners' TLS references name (D2-12, lab only) | absolute; required when a target or listener names a reference. See "TLS references" |
| `policy_version`, `register_version` | Named in every run request; the collector refuses a request whose versions are not its own | each at least 1 |

A `schedule[]` entry is checked as follows:

- its `id` is unique;
- the run request it makes passes C7 `CollectorRequest.Validate`, so a schedule the collector would refuse for its syntax does not load;
- the asset is in `assets`;
- the asset is collected by this node (D1-3);
- the endpoint exists and is not inbound Syslog;
- the operation is well formed;
- the interval is at least 60 s.

The collector checks the operation itself against the signed register. The node only names it.

## Store layout derived from the file

`Config.Layout` derives the store layout from the file:

| Database | Streams | Classes |
| --- | --- | --- |
| `evidence` | `ser/<asset_id>` and `quarantine/<asset_id>` for each scheduled asset, and `platform/health` | `adapter-evidence`, `platform` |
| `syslog` | `syslog/<listener id>` for each listener; it exists only when there are listeners | `syslog-datagram` for UDP, `syslog-stream` otherwise |
| `audit` | `audit` | `audit` |

Health events share the evidence database. This is so a capture carried by a health event, as in an unaligned SER read (D1-12), is kept for as long as that event is.

`Config.Consumers` gives every target one C5 consumer per event stream, plus `audit` when the target sets `audit` (C6 `syslog.Consumers`). No target consumes a `quarantine/` stream. A C5 stream with no consumer is never pruned, so a quarantine stays on the node until an operator deals with it.

## Commit caps and recovery reserve per database (C5 0.5, D4-9, D4-14)

Each database has a commit cap in bytes (`GroupOptions.MaxCommitBytes`) and in records (`MaxCommitRecords`), and a recovery reserve of `2 × WALBoundBytes + 1.1 × (largest commit) + 64 KiB + 3 KiB × (records in it)` (`c5.RecoveryReserveFor`). Both are per database, and the node releases and re-creates one reserve at a time.

| Database | Commit cap | Records | Recovery reserve (WAL bound 512 KiB) |
| --- | --- | --- | --- |
| `evidence` | 11 MiB (`SERCommitBytes`) | 2048 | 20,093,337 bytes (19.16 MiB) |
| `syslog` | 1 MiB (c5 default) | 1024 | 5,413,273 bytes (5.16 MiB) |
| `audit` | 1 MiB (c5 default) | 128 | 2,660,761 bytes (2.54 MiB) |

The evidence byte cap is derived, not measured. One SER read commits atomically, so the cap is `commitcap.go`'s bound on a read: C2's 1 MiB capture, 4.34 encoded bytes for each row byte, 2048 rows (`MaxReadRowsCeiling`) of at most 2560 fixed bytes, and 64 KiB of health events, 10.4 MiB, rounded up to a MiB. `serbound_test.go` measures the constants through the real normalizer and fails if the bound rises above the cap or the cap exceeds it by a MiB. A quarantine (a whole outcome frame of up to 8 MiB, its reason and two events) fits the same cap. The schedule's `operation` is at most 64 bytes, because it is in every event of a read.

A read over a cap is refused whole by the Log (`record-too-large`), nothing is stored as events, its bytes go to quarantine, and the node raises `collection-result-refused`. The bound holds for rows the SEL-751 adapter parses (`serRowRE`); a result that marked a row with characters JSON escapes as parsed would be larger and fails the same way.

## Store layout changes (C5 0.5, D4-14)

Format 2 of a database (`meta.format` `otsec.platform-store/2`) keeps `events` and `captures` in rowid tables with unique `(stream, seq)` and `sha256` indexes. Format 1 used `WITHOUT ROWID` tables, whose rows over about 1 KB each took an overflow page of their own: a commit wrote up to 3.3 times the WAL the reserve rule allows, and the file grew up to 4.5 times the bytes the quota counts.

A database of format 1 is **refused at start**: the node does not open, change, migrate or delete it. Before it opens a read-write connection, the store reads the format row, through the `-wal` when that holds frames (a format row can be only in the `-wal`, as after a crash before the first checkpoint) and from the main file alone, immutable, when it does not. The read is read-only: it cannot checkpoint or delete the `-wal`, so a store left with a hot `-wal` by a crash is refused with the database file and `-wal` byte for byte as found. The `-shm` is derived from the `-wal` and may be rewritten. A current-format store with a hot `-wal` is not refused: it starts and recovers it (`TestLegacyRefusalWritesNothingWithAHotWAL`, `TestLegacyFormatOnlyInTheWALIsRefusedWithoutWriting`, `TestCurrentFormatWithAHotWALStartsAndRecovers`). Startup stops at its open step with the `store-open-failed` alarm and an error that names the way out, and the node reports that database as failed. (The first draft refused it at the settings step with `store-settings-invalid`; that step runs after an ordinary open, which folds a hot `-wal` into the file and deletes it.) To start on the new layout:

1. Stop the node.
2. Copy the store directory aside. Keep the copy as the evidence it holds.
3. If events in it are not yet forwarded upstream and you need them, start the old node build against the copy until its targets have confirmed them.
4. Remove the database files (`*.db`, `*.db-wal`, `*.db-shm`) and the reserve files from the store directory, and start the node. It creates format 2 databases.

There is no migration. It would need free space equal to the database and a copy of every event, and all data written so far is simulated lab data.

**Sizing the volume (D4-14).** The file of a database grows by at most `DiskBytesPerQuotaByte` (2.5) bytes for each byte its class quotas count. A volume therefore needs the sum of the class quotas × 2.5, plus each database's recovery and last-resort reserves (the table above). No figure for a volume may come from the raw sum of the quotas.

## The scheduler

`Scheduler` runs the schedule one entry at a time, so the node never holds more than one device session (AP-13, SC-9). The first run of each entry waits 60 s after start, so a node in a restart loop never polls faster than the minimum interval. A late run is not repeated to catch up. However the schedule is written, an asset gets at least 60 s between the end of one session and the start of the next, so two entries for one asset, or a run longer than its interval, never poll a device faster than the minimum (A6 review of #92).

Each run:

1. **Checks it can keep the outcome.** The evidence database must accept events, and `adapter-evidence` must have `QuarantineRoom` left: the largest outcome frame (8 MiB), its reason and two events. Otherwise nothing is sent, and the alarm is raised once for the condition. Before holding a run for room, the node first prunes confirmed events (see "Pruning while running" below). So a class filled while the target was down frees itself once the target has confirmed, with no restart and no operator (A6, V-S9). `collection-quarantine-room-low` is raised once when `adapter-evidence` holds `warn_fraction` of what runs may use, which is the quota less `QuarantineRoom`. This warning comes before runs stop whatever the quota. The store's own quota warning comes at `warn_fraction` of the whole quota, which with a quota under about 40 MiB is past the point where runs stop.
2. **Audits before it acts (D1-11).** It writes `collector.request` (info) and sends the request only after that record holds a C5 receipt. With no receipt, nothing is sent.
3. **Records the decision.** It writes `collector.request` allowed or denied, with the collector's `collector_seq`, followed by every session record the collector reported, in one audit batch. A request with no decision leaves only the info record. If the collector did decide, its number shows as a gap (`audit.VerifyCollectorSeq`).
4. **Commits a checked outcome** through A4's normalizer, in A4's order: first the SER events with their capture and alignment state, then the health events, then, for a read that changed the state without adding events, the state on its own. Every run ends with a `collection.run` health event. That event carries the transcript when no other record does, so the transcript the session-close record names is always stored.
5. **Quarantines an outcome that failed a check** (A3's requirement, `docs/phase2/A3-collector.md`). It commits two records to `quarantine/<asset_id>` in one batch. The first, `collection.quarantined`, captures the frame exactly as received. The second, `collection.quarantine-reason`, captures the reason. The reason can quote a device line, so it never goes to status or the OS log. The run is recorded as `collection.outcome-unknown`. A result that A4's normalizer refuses is quarantined the same way.
6. **Updates status as it ends.** It folds the run's audit records and rewrites the status file, so `otsec health` shows the collector_seq high after this run, not after the next (A6 on #118). It records the asset's result (D2-17): the outcome's C2 code (an unknown one, as on a quarantined outcome, reads `failed.unknown`), or the run's alarm when there is no outcome code, or `ok`, and how many runs in a row did not end `ok`. A `partial` result counts as a failure: rows were collected, but some were not parsed, and a repeat of that needs a look as much as a failed run does (A3 on #126). `otsec health` prints `asset <id>: last run <code> (<detail>) at <time>`, with `FAILING` before it and the count after while that count is above 0. At `RepeatedFailureAfter` (3) failures in a row, `collection-repeated-failure` is raised once; an `ok` run starts the count and the alarm over. This is how a failure that suspends nothing, such as C2 0.3's `failed.identity_unreadable` retried at every interval, stays visible. The detail is the outcome's C2 error detail, which tells apart runs ending with the same code, such as a late device and a hung read, both `failed.timeout` (A6, V-S12). It is kept only from an outcome that passed its checks, the collector's and A4's normalizer's, and only within C2's bounds: printable ASCII, at most `adapter.MaxDetailLen` bytes, never device text. A run that was not sent (held, suspended, or stopped before the request) is not a result. The counts are this process's and start at 0 after a restart; the health stream's `collection.*` events are the durable record.

On an unauthorized line, the alarm is `collection-unauthorized-line` and collection from the asset stops. The stop is durable: at startup `NewScheduler` finds the quarantine on the stream and keeps the asset stopped. The stop ends only through an administrator's audited export and clear of the quarantine, once the cleared range is gone and no unauthorized-line quarantine is left (see "Quarantine export and clear").

If a quarantine cannot be stored, the alarm is `collection-quarantine-not-stored`, and every run on the node, level 0 included, stops.

## Pruning while running (A6, V-S9)

C5 startup prunes confirmed events only while a database's total usage is above `PruneTarget` (0.8) of the sum of its quotas. One class can fill well before that point. For example, `adapter-evidence` is half of `evidence.db`'s default quotas, and runs stop `QuarantineRoom` short of its quota. So `Runtime.Prune` also prunes while the node runs:

- **When.** It runs at every `Tick` (60 s), and from the scheduler before it would hold a run for room.
- **What.** In each open database (collecting or drain-only), it prunes while any class holds more than `PruneTarget` of its quota. For `adapter-evidence`, the measure is the quota less `QuarantineRoom`, because that is where runs stop.
- **How.** It works as startup step 6 does. Each step removes at most `PruneStepEvents` (50) events of a stream, up to a boundary computed from the persisted cursors. So nothing a required consumer has not confirmed is removed, nothing in a best-effort replay window, and nothing of a stream without consumers. Captures go with the last event that refers to them.
- **Never forced.** A class whose events are not confirmed stays full, and runs stay held until the target confirms.
- **On failure.** A failed prune raises `store-prune-failed` once for the database, with "runtime prune" in its detail. Collection continues.
- **Pages.** Freed pages are reused by later commits. Compaction remains a startup step.
- **Quarantines are kept.** A `quarantine/<asset_id>` stream has no consumers, so it is never pruned: its records are the evidence A3 requires of an outcome that failed a check, and a reason can quote a device line no consumer may receive. Repeated quarantines can therefore fill `adapter-evidence` for good. That is the intended end state (A6 on #135): runs stop with `collection-no-quarantine-room`, after `collection-quarantine-room-low` warned first, until an administrator exports and clears the quarantine (see "Quarantine export and clear").

## Quarantine export and clear (P3-A5)

The agreed design is `docs/phase3/A5-quarantine-export.md`: A3's conditions A3-1 to A3-5, A1's D3-1 and resume conditions (a) to (c), and C8 0.3's two actions (#155). Nothing is removed on the node's own initiative, and the node writes nothing outside its store and status.

- **Export (`otsec quarantine export -config <file> <asset> <dir>`, `ExportQuarantine`).** An administrator's command. It opens the evidence database read-only beside a running node, refuses a `<dir>` that exists, and creates it with the store directory's rule (`store.CreateDir`), because a quarantine can hold an unredacted password. It writes each record's stored event (`<seq>.event.json`) and capture (`<seq>.capture`) byte for byte, then `manifest.json` (`otsec.quarantine-export/0.1`: node, asset, stream, time, and each seq with its event and capture SHA-256, never content), and copies the manifest into `admin_dir` as `quarantine-export-<asset>.json`. If it cannot copy it, it says the export is complete and asks for the copy by hand.
- **The export directory is as sensitive as the store (A3).** Its captures and events can hold an unredacted password or a device line no consumer may receive. Keep it where only administrators can read it, review it there, and remove the directory once the review is done; the node neither tracks nor removes it.
- **Record (`QuarantineTick`, every `TickInterval`).** The node reads `quarantine-export-<asset>.json` for each scheduled asset under the protected-file rule, at most `MaxQuarantineManifestBytes` (4 MiB) and `MaxQuarantineItems` (20,000), strictly decoded. It checks the copy against its own stream both ways: every listed seq is stored with equal event and capture hashes, and every seq stored between the first and the last listed is listed. A copy that passes, and whose hash the chain does not hold, is recorded as `quarantine.exported` (actor type `node`, the manifest hash, the range and the count; "manifest verified against" the stream). A copy that fails is not recorded, and `quarantine-export-refused` is raised once per content.
- **Clear (`clear-quarantine.json`, `otsec.clear-quarantine/0.1`: `asset_id`, `manifest_sha256`, `principal`).** Read under the same rule. A file whose hash the chain already holds was applied and is left alone. Otherwise, in order: the chain must hold the export for that asset (A3-1); an export already cleared is recorded as stale, `quarantine.cleared` with outcome `info` and reason `already_cleared`, and nothing is removed (A3-4); the manifest copy must still be the recorded one, and every listed item must still be stored and hash-equal, or nothing is removed (A3-2); then `quarantine.cleared` (outcome `succeeded`, with `clear_sha256` and the file's principal as `requested_by`) is committed, and only after its receipt can anything be removed (A3-3). Each refusal is `quarantine-clear-refused`, raised once per file content.
- **Removal, from the record (A1 (a) to (c)).** Each tick takes at most one C5 `Discard` step, `DiscardStepEvents` (16) seqs, across all recorded clears. It removes only seqs inside the record's stream and range, which the export check proved were all listed; a record added after the export has a higher seq and stays. The record drives it, not the files, so a clear stopped by a kill finishes after the restart with both files gone. Until a clear's range is empty its asset's runs are held (`quarantine-clear-incomplete`), from the first run after a start. When it is, `quarantine-cleared` is raised.
- **The halt.** An asset halted for an unauthorized line runs again only once all its clears are done and its stream holds no unauthorized-line quarantine. It never resumes mid-removal.
- **Durable.** The checkpoint `suspensions.json` holds every recorded export and its clears (`quarantine`), so pruning the audit stream does not lose them. Status lists each recorded export whose range still holds records (`quarantine`), and `otsec health` prints `QUARANTINE EXPORTED, NOT CLEARED` or `QUARANTINE CLEAR INCOMPLETE` for each.
- **Limit: a refused copy is checked again every tick.** The node remembers which refused content it has alarmed on, not that it was refused, so a bad manifest copy left in `admin_dir` is read and verified against the stream at every tick until it is replaced or removed (A3; for a later PR).
- **Rollback.** The checkpoint's `quarantine` field is new, and `readSuspensions` refuses unknown fields. A node rolled back to a build before it therefore refuses the checkpoint and starts under `asset-suspensions-unknown`, with every run held (fail closed). To recover, remove `suspensions.json` from the store directory: the audit stream holds every suspension, and the next start rebuilds from it. The older build does not know the quarantine actions, so it neither shows nor resumes a recorded clear. Finish any clear in progress before rolling back.
- **Limits.** `clear-quarantine.json` is unsigned, so `requested_by` is what the file says, not proof of who wrote it, and the actor is the node. It moves to a signed request with the other admin files (C7 0.4). One manifest copy is kept per asset: a newer export replaces it, and a clear of the older one is then refused. Clear the newest recorded export instead, which lists everything the older one did.

## A busy open at start (C5 0.2, P3-A5)

A database whose open failed at start only because another connection held it busy or locked past the store's busy timeout is `failed` with C5 0.2's `OpenBusy`. Every `Tick` retries it once with `c5.Resume`, from the headroom check, under the lock the node already holds. Every other failure still needs a restart.

- **Alarm once.** A retry that is busy again changes nothing. The alarm the first failure raised still stands, and no new one is raised.
- **No state lock while waiting.** A failed database has no open store, so the retry, which can wait out the busy timeout (about 10 s for a held file), runs without the state lock. Readers of the other databases do not wait for it.
- **A held file stalls the tick.** The retries run inside `Tick`, one database after another, so while another process holds the file each tick waits out the busy timeout before it reaches pruning and the other databases' resumes (A3 on #147). At the 60 s `TickInterval` that is accepted. If the interval is ever shortened, the retry needs a backoff.
- **Audited.** A retry that opens the database is a `store.mode_change` from `failed`, in the audit stream and as a health event, like any other mode change.
- **The restart reaches the chain (A6 on #147, A1 D3-6).** While the audit database's open is busy, a node record that cannot be committed, such as the start's `service.start` and its first `store.mode_change` per database, is kept in memory with its own time, up to `MaxDeferredAudit` (64). The alarm is `audit-not-recorded`, not `audit-store-full`, and says whether the record was kept. The retry that opens the database commits the kept records in order, before its own `store.mode_change`. A new chain gets its `audit.chain_start` first. Records past the bound are counted, and one `storage.alarm` (reason `audit_not_recorded`) says how many were lost. A record made while the database is failed for another reason, or blocked, is not kept: that database is not retried. A node killed before the retry loses what it kept, and status still holds the alarms.
- **Nothing runs until the scheduler has caught up.** At start, the scheduler could not load the suspensions without the audit database, nor read a quarantine stream without the evidence database. Every run therefore went through the node-wide hold or the asset's halt. Before each run, the scheduler retries what it could not do (`reload.go`):
  - It loads the suspensions as at start, from the checkpoint and the audit stream, and only then ends the `asset-suspensions-unknown` hold, raising `asset-suspensions-rebuilt`. A load that fails for another reason keeps every run held. The status file's `runs_held` names the node-wide hold while it is current, and `otsec health` prints it as `RUNS HELD`. The alarms list is a history, so the unknown-suspensions alarm stays in it after the rebuild.
  - It reads the halted asset's quarantine stream again. The asset runs again only if no unauthorized-line quarantine is there. A quarantine of another kind does not keep it halted (`TestBusyEvidenceRetryKeepsUnauthorizedHalt`).

## Suspensions (D2-15)

The node keeps its own copy of the C1 suspension each run's outcome code sets (`adapter.Code.Suspends`). A collector reinstalled from fresh state does not hold the old collector's suspensions, so the node's copy is what keeps a suspended asset suspended (A1, D2-15).

- **Recording.** An accepted run whose outcome carries a code that suspends holds the asset at once. This applies even when the outcome failed a check and was quarantined, as long as its result names a code. The suspension is then written to the audit stream as `asset.suspend` (C8 0.2: actor type `node`, the C1 reason and the C2 code in `suspension`, the invocation ID as `correlation_id`) and to the checkpoint `suspensions.json` in the store directory, before the scheduler decides anything else.
- **Enforced.** A suspended asset's runs are not sent. `otsec health` lists it with its reason and the ref a clear must name.
- **Adopted from the collector (C7 0.3, A6 on #120, A3 #125).** If the reply to the suspending run was lost, or the node stopped before recording it, only the collector holds the suspension. The collector then names it: a run is refused `asset_suspended`, or a clear of another suspension is refused `suspension_mismatch`, each with `suspension: {reason, ref, code}`. The node adopts a named suspension it does not hold. It writes its own `asset.suspend` with the collector's reason, ref and C2 code, and a detail starting "adopted from the collector's refusal". It raises `asset-suspended` saying so. From there the administrator's `clear-suspension.json` naming that ref clears it at both ends, as for any other suspension. When the node has cleared X and owes the collector that clear, but the collector holds Y, the node adopts Y and keeps X owed. The file naming Y then replaces the owed ref with Y, which is why a node clear replaces an owed ref (assetclear.go). Adopting only adds a restriction the collector already enforces. The node does not adopt, records nothing, and raises `asset-suspension-not-adopted` once, without quoting the reply, in these cases:
  - the field fails `CollectorReply.HeldSuspension`;
  - it has no code, from a collector state written before codes were kept;
  - its code is not a known C2 code whose `Suspends` is the named reason;
  - the node holds another suspension for the asset;
  - it names the suspension whose clear the node is sending.
- **The stream is the record.** The node's suspensions are what the `asset.suspend` and `asset.suspension_clear` records give, applied in chain order, each checked with C8 0.2's `audit.VerifySuspensions` from the suspensions already open. A clear, including the node's own, takes effect when it is applied from the stream. Before every run the node applies the records written since it last did. So a record whose append reported an error but was committed is found there, and not written twice (C8 0.2 breaks the chain on a duplicate suspend or a second clear).
- **The checkpoint** carries `through_seq`, the last audit seq applied, and lists as `unaudited` any suspension whose record is not yet in the stream. Every start applies the records after `through_seq`, then writes the unaudited ones, holding the node until it has. A missing or unreadable checkpoint means the whole stream is read.
- **Fail closed.** All collection on the node is held, and an alarm raised, if the suspensions cannot be rebuilt:
  - the audit stream was pruned past what the rebuild needs;
  - a record does not parse, breaks C8 0.2's suspension rules (a clear of a suspension that is not open, a suspension already open), or suspends an asset the node already holds a suspension for (a suspended asset never runs, so the node holds one per asset);
  - the checkpoint claims more of the stream than it holds.

  A record like this met while the node runs holds it the same way, until a restart rebuilds the suspensions. It is also held while any `asset.suspend` record is not yet in the audit stream, even when the checkpoint holds the suspension, until the audit write succeeds (A1, D2-15 at 0ef6641). The chain is the record. The scheduler retries before every run.
- **Pruning stops at the checkpoint.** When the audit stream has a required consumer, the node adds one more, `node-suspensions`, whose cursor is the checkpoint's `through_seq`. It moves only after the checkpoint is written, so C5 never prunes an audit record that a rebuild would need. Without a required audit consumer the stream is never pruned, and the node adds nothing, since its cursor alone would make unforwarded records prunable (C5-A3-2).
- **Clearing.** An administrator writes `clear-suspension.json` in `admin_dir` (`OTSEC\config\admin` when installed): `{"schema": "otsec.clear-suspension/0.1", "asset_id": ..., "ref": ...}`.
  - The file is read as the collector reads it (A3 #117): no link, at most 4 KiB, owned by SYSTEM or Administrators, and nothing more than read and traverse for the node or the collector (`protect.ReadFileFor` with `AdminReaders`). It is decoded strictly: keys exactly as named, no duplicate, nothing after the object.
  - The node clears one suspension, only on an exact asset and ref match, and writes `asset.suspension_clear` before it schedules the asset again.
  - The file is read only from an `admin_dir` neither service can write and that is not a link (`protect.CheckDirFor` with `AdminReaders`, checked before every read, A3 on #107 and #117). Otherwise nothing is read, and it is raised once.
  - A file that does not match, or that names a suspension already cleared, changes nothing and is raised once.
  - A clear of a suspension whose `asset.suspend` is not yet in the audit stream waits until it is, and says so. Written first, it would name a suspension the chain does not hold, and C8 0.2 would break the chain on it (A6 on #107).
  - The node never clears on its own.
  - **The collector's half (C7 0.2, A3 #117).** The collector holds the same suspension in its own state and lifts it only for an `asset.clear_suspension` request that matches the same file, which it reads itself. After its own `asset.suspension_clear`, the node sends that request on its own behalf (`on_behalf_of` the node, the suspension's ref), audited before it is sent and with the collector's decision after, as a run is. The request ID is `clr:<ref>:<random hex>`, so the collector's allowed `collector.request` record names the clear it closes.
  - Until the collector accepts, the clear is owed: the asset's runs stay held, `otsec health` shows `COLLECTOR STILL SUSPENDED`, and `asset-collector-still-suspended` is raised once per cause. The owed clears follow from the audit stream (a node clear opens one, the collector's acceptance closes it) and are kept in the checkpoint, so they survive a restart and a rebuild.
  - The request is sent before each of the asset's runs, and only while `clear-suspension.json` names the suspension, since the collector checks the same file. There is one file, so an administrator clears one asset at a time: the next asset's file goes in only once health shows neither line for the one before (A3 on #120). A lost reply or a refusal leaves the clear owed and it is sent again. A collector that already lifted the suspension, or a reinstalled one that holds none, accepts a matching clear (A3 on #117). During an open collector reset nothing is sent, the clear included, until the reset is acknowledged. A chain written before this rule has clears no collector acceptance follows; a rebuild from it treats each as owed, so the asset is held until an administrator writes the file for it again. That fails closed.
  - Once `otsec health` lists neither the suspension nor `COLLECTOR STILL SUSPENDED` for the asset, the administrator removes `clear-suspension.json`. Removed earlier, the collector cannot accept the clear and the asset stays held until the file is written again. While the clear is owed, the file is expected and not refused. Left in place after that, it names a cleared ref, so it changes nothing and raises `asset-suspension-clear-refused` once (A3 on #107). The node cannot delete it.
- **Interim.** The file is the Phase 2 interim. Before any `device-observed` endpoint, the clear becomes an admin-signed C7 request (D2-11, D2-15).

## Admin-signed requests: the relay (P3-A5, #181)

The node carries an administrator's signed C7 request to the collector and verifies nothing itself (design: `docs/phase3/A5-signed-admin-files.md`). This PR relays the three credential kinds only (`credential.install`, `credential.revoke`, `credential.clear_suspension`), whose collector part is the whole operation.

- **The file.** The administrator's signing client leaves `admin-request-<name>.json` in `admin_dir`, `<name>` matching `[a-z0-9-]{1,64}`: `{"schema": "otsec.admin-request-file/0.1", "kind": <C7 kind>, "signed": <authz.AdminSigned>}`. It is read under the protected-file rule (`protect.ReadFileFor` with `AdminReaders`, after `CheckDirFor`), at most `MaxAdminRequestFileBytes` (the largest payload base64-encoded, plus 1 KiB), and decoded strictly. At most 16 files are read per tick, in name order.
- **When.** At start, every 15 s between runs, and before each run (`RelayEverySeconds`): a signed request lives at most 15 minutes, so it cannot wait for the next run. Nothing is sent while `collectorHold` holds requests (an unreadable install key, an open reset, a restore).
- **What is sent.** `{contract, kind, request_id: "admin-" + 16 hex digits of the file's SHA-256, on_behalf_of: the payload's principal, policy_version, admin_signed: the envelope as read}`. The payload is read before the collector verifies it only for its kind, person, key ID, nonce and expiry, each checked against its pattern; no body is decoded.
- **What is recorded.** A C8 `collector.request` info record before the send, actor the node, its detail naming the key, nonce, person, expiry and file hash as unverified. Then the decision: allowed with the person as actor (role `admin`) and the same values as verified, or denied with the refusal code and the admin check, actor the node. Each carries the collector's `collector_seq`.
- **Once.** A file whose request ID has a decision in the audit stream is not sent again. The decided set is folded from the stream with the suspensions and kept in the suspension checkpoint (`admin_relayed`), so a crash between the decision and the checkpoint resends nothing. A decided request whose file is gone, after a scan that read every file, is forgotten; a file put back is sent again: the collector gives a request it accepted its repeat answer (C7 0.5, `repeat_of` naming the first decision), recorded as accepted, and refuses one it refused as a replay, or either as expired. Nothing is applied twice.
- **No decision.** No reply within `RelayTimeout` (30 s), or a refusal without `collector_seq` (`state_unavailable`), leaves the file undecided. After a request the collector does not answer, the other files wait for the next tick, so a collector that never answers holds the scheduler for one `RelayTimeout` a tick (A3 on #197); it is sent again each tick until it is decided or expires, and `admin-request-no-decision` is raised once per cause. A resend of a request whose reply was lost gets, under C7 0.5, the repeat answer if the collector accepted it, recorded as accepted, and a replay refusal if it refused it (#186; A6 on #195). Recording `repeat_of` in the node's record (C8 0.4) is PR 2. A refusal with check `replay` or `window` says the request may already have been applied, so the administrator checks before signing again (A3 on #189).
- **Alarms and health.** `admin-request-refused` (once per request), `admin-request-unread` (admin_dir refused, a file refused by the rule or the decoder, a misnamed file, or more than 16 files; the alarm says why, never what the file holds), `admin-request-no-decision`. `otsec health` lists each file: accepted (with its `collector_seq`; the file may be removed), refused, waiting, or unread.

## Collector reset (D2-15)

A reinstall that loses the collector's stores starts its `collector_seq` again at 1 and loses its failed-auth floors. The node finds it and holds every credentialed request until an administrator acknowledges it (C8 0.2, `docs/phase2/A3-c8-seq-reset.md`). The state follows from the audit stream and is kept in the checkpoint beside the suspensions, so it survives a restart.

- **The trusted key.** At its first start (or first 0.2 start) the node writes `collector.install_key` with the collector's key before its first request. After that, each acknowledged reset sets it.
- **Before every request** the node reads `install-key.json` in `collector_public_dir` with `protect.ReadPublicFile`: a regular file, not a link or device, at most 4 KiB, schema `otsec.collector.install_key/0.1` with `key_id`, `public_key` and `fingerprint`, nothing else. The key ID and the fingerprint must both be derived from the public key (`seal.InstallKey.PublicKeyBytes`, `seal.Fingerprint`), so the key ID an administrator acknowledges is the key whose fingerprint they confirmed (A3 on #109). On Windows it is opened shared for delete, so the collector can rename a new one over it. Any read error holds every request (`collector-install-key-unreadable`). A key the node has trusted or recorded a reset to before is a restore of old stores or another process, never a reinstall, since a reinstall makes a new key: it writes nothing, sends nothing and cannot be acknowledged (`collector-restored`; A3, A6 and A1 on #109). Any other key the node does not trust is a reinstall: it writes `collector.seq_reset` (`previous_high`, the new `install_key_id`, no `first_seen`) and sends nothing (`collector-reset`).
- **The backstop.** A reply numbered at or below the highest `collector_seq` of the current epoch is a reset. If the key changed since the check before the request, `collector.seq_reset` with `first_seen` goes first in that reply's audit batch. If it did not, it is a restore of old collector stores or an impostor (`collector-restored`): nothing more is sent, and no acknowledgement lifts it. Only a reinstall with a new key, which is a reset, does. The same holds when the key cannot be read at that point: the reply's records are applied under the trusted key and read as a restore. That is the safe reading, and the chain then fails `audit.VerifyCollectorSeq` there even if it was really a reinstall (A3 on #109).
- **Acknowledging.** After confirming the new key's fingerprint (T-12) and reviewing the suspensions and the active register revisions, an administrator writes `seq-reset-ack.json` in `admin_dir`: `{"schema": "otsec.seq-reset-ack/0.1", "install_key_id": ...}`. It is read like `clear-suspension.json`. Only a file naming the open reset's key, while the collector is still on that key, acknowledges it: the node writes `collector.seq_reset_ack` and resumes. Another key changes nothing and is raised once; a file left from an earlier reset is ignored.
- **`otsec health`** shows the trusted key and the collector_seq high, and after a reinstall the new key beside the trusted one.
- **A record the node would not have written** (a reset that keeps the trusted key, an acknowledgement of no open reset, a second trusted key) holds every asset, as a bad suspension record does.
- **Interim.** The acknowledgement file is the Phase 2 interim; before any `device-observed` endpoint it becomes an admin-signed C7 0.2 request (D2-15).

## TLS references (D2-12, lab only)

A C6 target names its collector's trust anchors (`tls.trust_anchor_ref`) and the node's client credential (`tls.client_credential_ref`). A TLS listener names its own credential and its senders' CA set (`tls.credential_ref`, `tls.sender_ca_ref`). In Phase 2 each reference names files in `tls_dir`:

| File | Holds |
| --- | --- |
| `<trust_anchor_ref>.pem` | The CA set that verifies the collector: certificates only |
| `<client_credential_ref>.crt` | The node's client certificate chain |
| `<client_credential_ref>.key` | Its private key |
| `<credential_ref>.crt`, `.key` | A TLS listener's certificate chain, for server authentication, and its key |
| `<sender_ca_ref>.pem` | The CA set a TLS listener's senders must chain to: certificates only |

A reference matches `[a-z0-9][a-z0-9_-]{0,63}` and is not a Windows device name (`con`, `nul`, `com1` and the like), so it cannot name a path or a device. The node may read these files and must not be able to change them (D2-12):

- **`tls_dir`** passes `protect.CheckDir`: a plain directory, not a link or junction, opened without following one. On Linux its mode is 0500. On Windows it has a protected DACL whose allow entries name only the node's account, SYSTEM and Administrators, an owner other than the node's account, and no write right in the node's entries.
- **Each file** is read with `protect.ReadFile`, which checks the opened handle, not the path: a regular file on disk (no link, reparse point or device), at most 1 MiB, mode 0400 on Linux, and on Windows the same owner and allow-entry rule as `tls_dir`.
- **No error or log quotes file content.** A parse failure names the file only.

What these checks prove differs by platform (A3 #98):

- **Windows:** the node has no write right only while it runs as its service account (`NT SERVICE\otsec-node`), which is not in Administrators. The check reads the node's own entries; a node run by a member of Administrators passes it through the Administrators entry and could rewrite the files.
- **Linux:** "no write for the node" is not enforced. The node must own a 0400 file to read it, so it could change the mode back. The Linux checks refuse links, devices and loose modes, and are the test platform; the deployed node is the Windows service.

The installer creates `OTSEC\config\tls` (owner Administrators, node read only) and refuses a configuration whose `tls_dir` is anything else. An administrator copies the files in, so they inherit that DACL; a moved file keeps its own, and the node refuses it if that grants anything more. The client key is unencrypted at rest. That is part of the D2-12 gate limitation, and A3's node key register (credential design section 9) must replace this before any `device-observed` deployment.

Every reference is resolved and checked through A4's `forward.ClientTLS` before the node starts. A missing or bad file, or a client certificate whose name is not the target's `durable_ack.permitted_peer`, stops the node. Nothing falls back to another reference.

This is an interim. A3's node key register (credential design, section 9: a non-exportable key in the `NT SERVICE\otsec-node` certificate store, made from a certificate request the node generates) replaces it, and must land before any `device-observed` deployment.

## Syslog listeners (P3-A4)

`NewListening` builds one A4 `receive.Receiver` per configured listener, and `Run` binds them all before the schedule starts. A listener the configuration names is never silently absent: a bad TLS reference, a sender table that does not build, or an address that cannot be bound stops the node, and the listeners already bound are released.

- **Stream and class.** Each listener commits to `syslog/<id>` in the syslog database: `syslog-datagram` for UDP and `syslog-stream` otherwise (see the layout above). Its `Log` is a live view, as the forwarders' streams are. While the database is not open, or is in a mode that accepts no events, the view refuses the batch and nothing is written. The listener then follows its class: a stream batch is held and retried with the connection unread (refuse-new), and a datagram batch is dropped and counted (drop-and-count).
- **Senders.** The sender table is `receive.SendersFor` over the C1 assets: every inbound endpoint with the listener's transport whose port is unset or the listener's port. Its `host` is the sender's IP literal. Any other sender's message is kept with `asset-unresolved` and alarmed once as `syslog.unknown-source` (A4).
- **Plaintext (D3-5).** Plaintext Syslog receive is allowed, per listener: a `syslog-udp` or `syslog-tcp` listener runs only with `"plaintext": true` in its own entry, which no lab flag or other setting implies, and TLS is the default. Such a listener has no sender authentication or integrity: any host on the path can send or alter a message, and the sender's address is its only identity. So the node records each plaintext listener at every start as `node.posture_change` (reason `plaintext_listener`, naming the listener, transport and bound address), status marks it `plaintext`, and `otsec health` prints a `PLAINTEXT` line under it. Its events say so too: A4's receiver gives them `origin_auth` `none`, and their stream `syslog/<id>` names the listener. The D2-4 and D2-10 rules on listeners (simulated targets, loopback addresses) are unchanged.
- **TLS.** A `syslog-tls` listener's `tls` section names files in `tls_dir` under the same rules as a target's: `<credential_ref>.crt` and `.key` are the listener's certificate and key, and `<sender_ca_ref>.pem` is the CA set a sender's certificate must chain to (`Config.ListenerTLS`, then `receive.ServerTLS`). Nothing falls back to plaintext. Attribution is still by address, because C1 pinned-key is not built.
- **Health.** The listener's health events, `syslog.unknown-source`, `syslog.unknown-budget` and `intake.drop-counted`, go through the forwarder's health sink to `platform/health`. Every 10 s, with the forwarding check, the node copies each listener's state into status (`listeners`) and rewrites the status file. `otsec health` prints one line per listener: open or not, received and stored, and the last message. It adds a line for each of: held, dropped by reason, refused connections by reason, truncated or misframed messages, unknown senders, and the last error.
- **Unknown senders' storage (HR-11, D3-3).** Unknown senders share their listener's class quota with the configured devices, so the node bounds what they may take. A4's receiver lets a listener's unknown senders store `UnknownBytes` an hour (`receive.Limits`), refilled evenly, so over an outage of T hours they can hold at most `UnknownBytes × (1 + T)` of the class quota at once, restarts included. A record pruned after it was forwarded is not counted at the next start, so what they send upstream over time can be more; during an upstream outage nothing is confirmed, so nothing in the window is pruned and the count is exact when it matters (A3 on #198). A restart does not refill the budget: at each start the node counts what unknown senders stored on the listener's stream in the hour before (the sum of `len(event)` over its committed `asset-unresolved` records received in that hour, a record received after now counting as inside) and passes it as `receive.Config.UnknownSpent`, so the budget starts that much spent. If the stream cannot be read, the budget starts empty and `syslog-unknown-budget-uncounted` is raised (fail closed); known senders are not affected. A wall clock stepped forward by more than the window and then a restart still refills it (a known limitation, D3-3). The node sets each listener's budget (`Config.ListenerSizings`) so that every listener of a class together can take at most a quarter of the class quota over `syslog_outage_hours`:
  - `UnknownBytes = min(quota / 4 / (listeners × (1 + T)), 1 MiB)`; the other `receive.Limits` stay A4's defaults.
  - The configuration is refused when that is below A4's floor of 256 KiB an hour. The error gives the quota needed. With the default 24 h, one listener needs at least 25 MiB in its class; the test quota of 64 MiB holds two listeners per class.
  - A stream batch commits whole, so a `syslog-stream` quota must also hold one batch at its largest beside the unknown share: 64 frames of 8192 bytes at 8 stored bytes per frame byte plus 4 KiB (`HeldBatchBytes`, 4.25 MiB). The factor 8 is measured: a frame of control characters or `<` stores at 7.48 times its size, ASCII text at 2.5 (simulated). Once the floor passes, the share is at most a quarter and at least 3/4 × 1 MiB × (1 + T) is left, so this rule binds only for outages under about 5 h; at the default 24 h, 25 MiB per listener is the whole requirement for the stream class too (A6 on #169).
  - Status shows each listener's `unknown` share (the hourly budget, the class bound, the quota, the outage, the bytes unknown senders stored since start, and `spent_at_start_bytes`, what the budget started spent by), and `otsec health` prints it.
  - This is A3's option (b), a bound by sizing: HR-11 is mitigated in part (proportional bound within the configured outage). Past `syslog_outage_hours` unknown senders keep storing at the hourly rate (A6 measured 2.55 times the quarter at three times the outage, simulated). The absolute bound, a separate C5 stream class and quota for unknown senders with an alarm when it fills (option (a)), remains open, needs a C5 and A4 change, and still gates the first device-observed listener.
- **Listener certificate expiry.** `ServerTLS` checks the certificate at load only, and a node keeps presenting it after `NotAfter`. Status shows a `syslog-tls` listener's `certificate_not_after`. The node raises `syslog-listener-certificate-expiring` once when the certificate is within 30 days of expiry and once more when it has expired, and `otsec health` prints `CERTIFICATE EXPIRES` or `CERTIFICATE EXPIRED` under the listener. Replacing the certificate takes a restart.
- **Target size.** Every target carries every listener stream (C6). A forwarded event whose received text does not fit the target's `max_message_octets` keeps its hash and length only (`forward.text-omitted`; A6 saw a 1504-byte message omitted on a 2048-octet target). A received message's text, and the `subj` and `val` a dialect takes from it (up to 1024 bytes each for RTAC), escaped or carried as base64, take at most twice their length, so `2 × (8192 + 2 × 1024) + 2048 = 22528` octets carries any received message whole (A4 measured an 8147-byte RTAC frame at 21161 octets). At every start with listeners, the node raises `target-small-for-listeners` for each target below that. It is a warning: the event is still forwarded.
- **A listener that stops** on its own while the node runs raises `syslog-listener-stopped`. The others keep serving.

## Forwarding

`NewForwarding` builds one A4 forwarder per target over the target's C5 consumers. Each stream's `Outbox`, `CursorStore` and `Index` (the C5 `CommitIndex` a best-effort target starts its replay window from, A4 #94) is a live view that looks the open database up on every call, because `Tick` can replace a database's handle when it resumes one. The audit stream comes from the audit database, with `Audit` set. The health sink commits each `forward.*` event on `platform/health` and returns its key after the commit; it refuses while that database's mode accepts no events, and the forwarder keeps the report and commits it later (A4 #94, shown as "not yet recorded" in `otsec health`).

Every 10 s, `Forwarding.Check` copies each forwarder's state into node status (`targets`, shown by `otsec health`) and rewrites the status file when a target's state changed, so health's counts are at most one check behind (A6 on #118). It also raises two alarms, each once per condition:

- `forward-unreachable`: a required target has events waiting and nothing confirmed for 60 s, or has had no session open for 60 s even with nothing waiting (`Status.Open`). Waiting means past what the target confirmed (`StreamStatus.Confirmed`, A4 #103), not past the cursor, which stays behind while a report about the stream is owed. A held stream's events do not count as waiting. A `forward.unreachable` health event is committed with it. C6 gives no period; 60 s follows the proposed V-S12, and A1 and A6 own the number.
- `forward-held`: a stream is held, with the forwarder's reason.

## Example

`nodeconfigtest.New("site-a-node1", dir).AddSEL751(id, "127.0.0.1", 2323, 300).AddRELPTarget(...)` writes a file like this, with the asset abbreviated:

```json
{
  "schema": "otsec.nodeconfig/0.1",
  "node_id": "site-a-node1",
  "store": {
    "dir": "/var/lib/otsec/store",
    "quotas": {"adapter-evidence": 67108864, "syslog-stream": 67108864, "syslog-datagram": 67108864, "platform": 67108864, "audit": 67108864},
    "warn_fraction": 0.8
  },
  "listeners": [],
  "assets": [{"schema": "otsec.asset/0.1", "asset_id": "2b7d4e10-8c3f-4a5b-9e21-7c4f0d6a8b13", "node_id": "site-a-node1", "...": "..."}],
  "targets": [{"schema": "otsec.syslog/0.2", "name": "central", "transport": "relp-tls", "class": "required", "audit": true, "...": "..."}],
  "schedule": [{"id": "sch-ser-2b7d4e10", "asset_id": "2b7d4e10-8c3f-4a5b-9e21-7c4f0d6a8b13", "endpoint": "port1-telnet",
                "operation": "sel.ser.read_all", "credential_ref": "cred_7f3k2m9q4x", "every_seconds": 300}],
  "collector_pipe": "/run/otsec/collector.sock",
  "collector_peer": "1000",
  "policy_version": 3,
  "register_version": 2
}
```
