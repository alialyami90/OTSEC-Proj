# ADR-0004: Local persistence and delivery semantics

- Status: accepted (A1, Phase 0 exit gate, 2026-10-23)
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
6. **Required and best-effort targets (A6 C-18).** Each forwarding target is declared `required` or `best-effort`. Pruning waits only for `required` targets. A target that cannot confirm delivery (plain RFC 5425) can only be `best-effort`: it keeps a replay window by time, and events older than the window are prunable for it. A `required` target unreachable beyond a configured period raises an alarm; collection stops only when the quota is reached, with the alarm A3 specified; an admin may retire a target, which is audited. Without this rule a default syslog target would eventually stop SER polling permanently.
7. **Durability mode.** `synchronous=FULL` for every stream whose acknowledgement advances a device cursor or confirms delivery. A6 E-02 showed NORMAL leaves acknowledged commits unsynced (1,011 of 1,016) while FULL left none (0 of 680); E-A5-1 cannot distinguish the two, so it is evidence for FULL only.
8. **Startup recovery.** The reserve file is released and incremental pruning attempted at startup when the store is at quota, not only while running (A6 E-03: after a crash at full disk, reads and draining work but pruning fails until space is freed).
9. **Storage-full policy** per stream class as in A5 §5, with A3's additions: separate quotas; SER polling stops with an alarm stating the stop time and device-buffer overwrite estimate; UDP syslog drops are counted, persisted, and forwarded; audit-full makes privileged operations fail closed.

## Consequences

- R8.7 crash criterion is evidenced for process crash at FULL; power loss needs real site storage (A6 H-11).
- Thresholds (70/85/95 %), 72 h outage floor, and certificate lifetime remain proposals pending owner input on WAN outage durations.

## Open objections

None. Tracked: B-03 is an entry condition for the Phase 1 forwarding contract.
