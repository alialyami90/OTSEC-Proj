# Deployment notes

Owner: A5. These are the rules a deployment must follow until Phase 2 adds an installer and Phase 4 adds distributed operation. They come from the contracts and A1's decisions and are recorded here so an operator finds them in one place.

## Upgrade order: readers before writers (A1 D1-13)

1. Upgrade central nodes, and any other receiver of C4 events or C8 audit records, first.
2. Then upgrade the site nodes that write those records.

A site node never emits a contract minor version that its central node has not declared it supports. A 0.x reader refuses enum values from a later minor version. That keeps it safe, but a site node upgraded first would have its events refused upstream. In 0.x the operator keeps this order by hand. An enrollment-time version exchange that enforces it is Phase 4 work. See also `docs/phase1/A5-node-posture.md` section 5.

## Storage sizing (C5)

The store's volume must hold all of the following, with margin for the WAL bound:

- the sum of the class quotas;
- the recovery reserve and the last-resort reserve, each at least the open headroom;
- the open headroom itself.

The audit quota must hold the audit records of the longest expected outage of its required consumer, because only a required consumer makes audit prunable (`docs/phase1/A5-store-semantics.md` sections 1a and 5).

The platform quota needs headroom too. A forwarder passes an event that is too large for a target only after it has committed the `forward.too-large` health event. With no room in the platform quota, that stream stalls instead (`docs/phase1/reviews/C6-A5.md`, note 5).

### Syslog listeners

With Syslog listeners (`platform/node/README.md`, "Syslog listeners"):

- **The syslog quotas** must hold the unknown senders' share over the planned upstream outage (`syslog_outage_hours`, default 24 h) at A4's floor of 256 KiB an hour per listener: at least `listeners × 256 KiB × (1 + hours) × 4` per class, which is 25 MiB for one listener and 24 h. A `syslog-stream` quota also needs 4.25 MiB for one held batch. The node refuses a smaller quota at load and says what it needs (HR-11, D3-3). Size the quota for the known devices' traffic over the outage on top of that.
- **Targets** should set `max_message_octets` to at least 18432. Below that, a long received message is forwarded with its hash and length only, and the node raises `target-small-for-listeners` at start.
- **Listener certificates** are read at start only. Watch for `syslog-listener-certificate-expiring` (raised 30 days before expiry) and replace the files, then restart the node.

## Windows host rules (Phase 2)

These come from C5's lock conditions (A3) and C7's W-1 to W-4 (`docs/phase1/reviews/C7-A5.md`, `docs/phase1/A3-credential-design.md` section 2):

- separate virtual service accounts for the node and the collector;
- protected DACLs on installer-created directories;
- no `SeImpersonatePrivilege` for either service;
- per-service firewall rules, so only the collector reaches devices;
- a named pipe IPC on which each end checks the other's service SID.

None of these has been tested on a site image yet.
