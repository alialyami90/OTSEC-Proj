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
| `listeners[]` | Syslog listeners: `id`, `transport` (`syslog-udp`, `syslog-tcp` or `syslog-tls`), `address` (`ip:port`) and `target` | unique ids; `simulated` only (D2-4); a loopback address (D2-10). Phase 2 starts no listener |
| `assets[]` | C1 asset records | `asset.Decode`; every endpoint `simulated`; every collection endpoint on a loopback IP literal (D2-10); `asset.CheckSenders` across all assets |
| `targets[]` | C6 forwarding targets | `syslog.ParseTarget`; unique names |
| `schedule[]` | `id` (the C7 schedule principal the runs are made for), `asset_id`, `endpoint`, `operation` (a C3 operation ID such as `sel.ser.read_all`), `params` (optional), `credential_ref` (a C7 handle, absent for a level 0 operation) and `every_seconds` | see below |
| `collector_pipe` | Where the collector listens | `\\.\pipe\<name>` on Windows; an absolute socket path on Linux |
| `collector_peer` | The identity the collector must hold | Linux: required, the collector's uid. Windows: empty means the `otsec-collector` service SID |
| `admin_dir` | Where an administrator leaves Phase 2 interim files such as `clear-suspension.json` (D2-15) | absolute; optional. Without it no suspension can be cleared. The installer requires `OTSEC\config\admin`, which the node and the collector both read and neither writes |
| `collector_public_dir` | Where the collector publishes `install-key.json` (A3 #106); the node reads it before every request (D2-15) | absolute; required when anything is scheduled. The installer requires `OTSEC\collector\public` |
| `tls_dir` | The directory holding the files the targets' TLS references name (D2-12, lab only) | absolute; required when a target names a reference. See "TLS references" |
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

## The scheduler

`Scheduler` runs the schedule one entry at a time, so the node never holds more than one device session (AP-13, SC-9). The first run of each entry waits 60 s after start, so a node in a restart loop never polls faster than the minimum interval. A late run is not repeated to catch up. However the schedule is written, an asset gets at least 60 s between the end of one session and the start of the next, so two entries for one asset, or a run longer than its interval, never poll a device faster than the minimum (A6 review of #92).

Each run:

1. **Checks it can keep the outcome.** The evidence database must accept events, and `adapter-evidence` must have `QuarantineRoom` left: the largest outcome frame (8 MiB), its reason and two events. Otherwise nothing is sent, and the alarm is raised once for the condition.
2. **Audits before it acts (D1-11).** It writes `collector.request` (info) and sends the request only after that record holds a C5 receipt. With no receipt, nothing is sent.
3. **Records the decision.** It writes `collector.request` allowed or denied, with the collector's `collector_seq`, followed by every session record the collector reported, in one audit batch. A request with no decision leaves only the info record. If the collector did decide, its number shows as a gap (`audit.VerifyCollectorSeq`).
4. **Commits a checked outcome** through A4's normalizer, in A4's order: first the SER events with their capture and alignment state, then the health events, then, for a read that changed the state without adding events, the state on its own. Every run ends with a `collection.run` health event. That event carries the transcript when no other record does, so the transcript the session-close record names is always stored.
5. **Quarantines an outcome that failed a check** (A3's requirement, `docs/phase2/A3-collector.md`). It commits two records to `quarantine/<asset_id>` in one batch. The first, `collection.quarantined`, captures the frame exactly as received. The second, `collection.quarantine-reason`, captures the reason. The reason can quote a device line, so it never goes to status or the OS log. The run is recorded as `collection.outcome-unknown`. A result that A4's normalizer refuses is quarantined the same way.

On an unauthorized line, the alarm is `collection-unauthorized-line` and collection from the asset stops. The stop is durable: at startup `NewScheduler` finds the quarantine on the stream and keeps the asset stopped. Phase 2 has no way to clear the stop, so a halted asset fails closed. Clearing it needs an audited admin operation, which is out of Phase 2 scope (A1): it is a Phase 3 item for A3 and A5, recorded as a limitation in `docs/phase-2-exit.md`.

If a quarantine cannot be stored, the alarm is `collection-quarantine-not-stored`, and every run on the node, level 0 included, stops.

## Suspensions (D2-15)

The node keeps its own copy of the C1 suspension each run's outcome code sets (`adapter.Code.Suspends`). A collector reinstalled from fresh state does not hold the old collector's suspensions, so the node's copy is what keeps a suspended asset suspended (A1, D2-15).

- **Recording.** An accepted run whose outcome carries a code that suspends holds the asset at once. This applies even when the outcome failed a check and was quarantined, as long as its result names a code. The suspension is then written to the audit stream as `asset.suspend` (C8 0.2: actor type `node`, the C1 reason and the C2 code in `suspension`, the invocation ID as `correlation_id`) and to the checkpoint `suspensions.json` in the store directory, before the scheduler decides anything else.
- **Enforced.** A suspended asset's runs are not sent. `otsec health` lists it with its reason and the ref a clear must name.
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
  - Once `otsec health` no longer lists the suspension, the administrator removes `clear-suspension.json`. The node cannot delete it, and a file left in place names a cleared ref, so it changes nothing and raises `asset-suspension-clear-refused` once (A3 on #107).
- **Interim.** The file is the Phase 2 interim. Before any `device-observed` endpoint, the clear becomes an admin-signed C7 0.2 request (D2-11, D2-15).

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

A C6 target names its collector's trust anchors (`tls.trust_anchor_ref`) and the node's client credential (`tls.client_credential_ref`). In Phase 2 each reference names files in `tls_dir`:

| File | Holds |
| --- | --- |
| `<trust_anchor_ref>.pem` | The CA set that verifies the collector: certificates only |
| `<client_credential_ref>.crt` | The node's client certificate chain |
| `<client_credential_ref>.key` | Its private key |

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

## Forwarding

`NewForwarding` builds one A4 forwarder per target over the target's C5 consumers. Each stream's `Outbox`, `CursorStore` and `Index` (the C5 `CommitIndex` a best-effort target starts its replay window from, A4 #94) is a live view that looks the open database up on every call, because `Tick` can replace a database's handle when it resumes one. The audit stream comes from the audit database, with `Audit` set. The health sink commits each `forward.*` event on `platform/health` and returns its key after the commit; it refuses while that database's mode accepts no events, and the forwarder keeps the report and commits it later (A4 #94, shown as "not yet recorded" in `otsec health`).

Every 10 s, `Forwarding.Check` copies each forwarder's state into node status (`targets`, shown by `otsec health`) and raises two alarms, each once per condition:

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
