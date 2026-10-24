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

## Windows host rules (Phase 2)

These come from C5's lock conditions (A3) and C7's W-1 to W-4 (`docs/phase1/reviews/C7-A5.md`, `docs/phase1/A3-credential-design.md` section 2):

- separate virtual service accounts for the node and the collector;
- protected DACLs on installer-created directories;
- no `SeImpersonatePrivilege` for either service;
- per-service firewall rules, so only the collector reaches devices;
- a named pipe IPC on which each end checks the other's service SID.

None of these has been tested on a site image yet.
