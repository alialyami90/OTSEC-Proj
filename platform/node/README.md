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

If a quarantine cannot be stored, the alarm is `collection-quarantine-not-stored`, and every credentialed run on the node stops.

## TLS references (D2-12, lab only)

A C6 target names its collector's trust anchors (`tls.trust_anchor_ref`) and the node's client credential (`tls.client_credential_ref`). In Phase 2 each reference names files in `tls_dir`:

| File | Holds |
| --- | --- |
| `<trust_anchor_ref>.pem` | The CA set that verifies the collector: certificates only |
| `<client_credential_ref>.crt` | The node's client certificate chain |
| `<client_credential_ref>.key` | Its private key |

A reference matches `[a-z0-9][a-z0-9_-]{0,63}`, so it cannot name a path. The node refuses `tls_dir` itself if it is a link, and refuses any of the files if it is a link or another reparse point (`Lstat`). The key must also pass `store.CheckPrivateFile`: mode 0600 or tighter on Linux, and on Windows the store's rule (owner and allow entries only the node's account, SYSTEM and Administrators). The installer's `OTSEC\config` DACL gives the node read access only.

Every reference is resolved and checked through A4's `forward.ClientTLS` before the node starts. A missing or bad file, or a client certificate whose name is not the target's `durable_ack.permitted_peer`, stops the node. Nothing falls back to another reference.

This is an interim. A3's node key register (credential design, section 9: a non-exportable key in the `NT SERVICE\otsec-node` certificate store, made from a certificate request the node generates) replaces it, and must land before any `device-observed` deployment.

## Forwarding

`NewForwarding` builds one A4 forwarder per target over the target's C5 consumers. Each stream's `Outbox` and `CursorStore` is a live view that looks the open database up on every call, because `Tick` can replace a database's handle when it resumes one. The audit stream comes from the audit database, with `Audit` set. The health sink commits each `forward.*` event on `platform/health` and returns its key after the commit.

Every 10 s, `Forwarding.Check` copies each forwarder's state into node status (`targets`, shown by `otsec health`) and raises two alarms, each once per condition:

- `forward-unreachable`: a required target has events waiting and nothing confirmed for 60 s. A `forward.unreachable` health event is committed with it. C6 gives no period; 60 s follows the proposed V-S12, and A1 and A6 own the number.
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
