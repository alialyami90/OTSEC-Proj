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
| `store.dir` | Store directory | absolute path. The store also checks the directory itself: mode 0700 on Linux, and the installer's DACL on Windows |
| `store.quotas` | Bytes per C5 class, keyed by class name (`adapter-evidence`, `syslog-stream`, `syslog-datagram`, `platform`, `audit`) | each positive. Every class the layout needs must have one |
| `store.warn_fraction` | Fraction of a quota that raises `store-quota-warning` | in (0, 1) |
| `listeners[]` | Syslog listeners: `id`, `transport` (`syslog-udp`, `syslog-tcp` or `syslog-tls`), `address` (`ip:port`) and `target` | unique ids; `simulated` only (D2-4); a loopback address (D2-10). Phase 2 starts no listener |
| `assets[]` | C1 asset records | `asset.Decode`; every endpoint `simulated`; every collection endpoint on a loopback IP literal (D2-10); `asset.CheckSenders` across all assets |
| `targets[]` | C6 forwarding targets | `syslog.ParseTarget`; unique names |
| `schedule[]` | `asset_id`, `endpoint`, `operation` (a C3 operation ID such as `sel.ser.read_all`) and `every_seconds` | see below |
| `collector_pipe` | Where the collector listens | `\\.\pipe\<name>` on Windows; an absolute socket path on Linux |

A `schedule[]` entry is checked as follows:

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
| `evidence` | `ser/<asset_id>` for each scheduled asset, and `platform/health` | `adapter-evidence`, `platform` |
| `syslog` | `syslog/<listener id>` for each listener; it exists only when there are listeners | `syslog-datagram` for UDP, `syslog-stream` otherwise |
| `audit` | `audit` | `audit` |

Health events share the evidence database. This is so a capture carried by a health event, as in an unaligned SER read (D1-12), is kept for as long as that event is.

`Config.Consumers` gives every target one C5 consumer per event stream, plus `audit` when the target sets `audit` (C6 `syslog.Consumers`).

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
  "schedule": [{"asset_id": "2b7d4e10-8c3f-4a5b-9e21-7c4f0d6a8b13", "endpoint": "port1-telnet", "operation": "sel.ser.read_all", "every_seconds": 300}],
  "collector_pipe": "/run/otsec/collector.sock"
}
```
