# ADR-0004: Local persistence and delivery semantics

- Status: proposed (A1, 2026-10-23; storage choice to be accepted at the Phase 0 exit gate; delivery semantics become a Phase 1 contract with A4 and A3)
- Date: 2026-10-23
- Deciders: A1, with A5 (proposer), A4 (forwarding), A3 (TB5), A6 (V-S6, V-S9)
- Related: R4.4, R4.6, R4.7, R8.4, R8.6, R8.7, R8.8; A5 §5; A6 E-01, B-03, C-04, C-13; ADR-0002

## Context

Sites must keep collecting through WAN outages, never silently discard native records, survive process crashes, and stay controlled when storage fills. A6 E-01 and A5 E-A5-4 independently show that a successful write to an RFC 5425 or TCP syslog socket does not mean delivery.

## Options considered

SQLite (WAL); PostgreSQL; embedded key-value stores; a custom append-only log; a broker (NATS JetStream, Kafka, MQTT). See A5 §5.

## Evidence

- E-A5-1: 400 SIGKILL runs, 0 acknowledged events lost, 0 gaps, integrity ok (A1 re-ran 100 kills, 25 per mode: same result). Process crash only; power loss untested.
- E-A5-3: default WAL settings wedge a full store; bounded WAL plus reserve file plus incremental pruning recovers it (A1 reproduced).
- E-A5-4 and A6 E-01: unacknowledged syslog loses events in every run; an application-level acknowledgement gives 0 missing and expected duplicates (A1 reproduced both).

## Decision

1. **Store:** SQLite in WAL mode, one database per data-owning module with exactly one writer; `synchronous=FULL` for native evidence and audit; bounded WAL; reserve file of at least twice the WAL bound; pruning only of confirmed events, in small transactions. PostgreSQL deferred to a future central-scale ADR.
2. **Commit before acknowledgement:** a collector advances its device cursor only after the local commit; native bytes and normalized form commit in one transaction.
3. **Two identities, never conflated:** transport idempotency key `(node_id, stream, seq)`; content-level duplicate handling for re-read device history by aligning overlapping SER snapshots (A6 C-13), owned by A4.
4. **Site to central:** at-least-once; central upserts by the transport key and returns the highest contiguous committed `seq`; the site advances its confirmed cursor only on that answer.
5. **Upstream syslog:** "forwarded" means "confirmed" only on an acknowledging transport. For RFC 5425 targets the contract states a replay window and an `event_id` for downstream deduplication, and the platform reports such targets as unconfirmed. TB5: upstream may return only transport acknowledgements in a fixed grammar (A1 ruling on the A6 cross-review).
6. **Storage-full policy** per stream class as in A5 §5, with A3's additions: separate quotas; SER polling stops with an alarm stating the stop time and device-buffer overwrite estimate; UDP syslog drops are counted, persisted, and forwarded; audit-full makes privileged operations fail closed.

## Consequences

- R8.7 crash criterion is evidenced for process crash; power loss needs real site storage (A6).
- Thresholds (70/85/95 %), 72 h outage floor, and certificate lifetime remain proposals pending owner input on WAN outage durations.

## Open objections

None. Tracked: B-03 is an entry condition for the Phase 1 forwarding contract.
