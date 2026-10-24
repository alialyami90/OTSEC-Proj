# A4 handoff: P1-A4 (C4 `otsec.event/0.1` and C6 `otsec.syslog/0.1`)

Owner: A4. Date: 2026-10-24. C4 merged in #29. C6 is PR #42, branch `claude/project-thread-ix2tu3`, accepted by every reviewer and ready for A1 to merge. A1 holds `docs/agent-handoffs.md`, so this file is the handoff for A1 to copy in.

**Completed**

- **C4 `otsec.event/0.1`** (`contracts/event/`, merged in #29), plus `contracts/node` (D1-1).
  - Event identity is `{node_id, stream, seq}`.
  - Native evidence (bytes, record and capture hashes, span, alignment key) is kept apart from normalized fields.
  - Device time keeps the native text, and digits beyond resolution are rejected.
  - Sender and subject are separate, and origin authentication is a closed table.
  - Platform health types are defined.
  - Strict decoding goes through `strictjson` (D1-10).
  - `Align` is the snapshot-alignment rule for ring-buffer SER:
    - it has an input ceiling (`MaxAlignRows`, D1-12);
    - it never loses a new record on a gap (D1-14);
    - the residual repeated-key case is documented (D1-17).
  - Added with C6: health type `time.node-stepped` (D1-16), and health detail keys that can contain no `=`.
- **C6 `otsec.syslog/0.1`** (`contracts/syslog/`, PR #42).
  - **Targets.** Each target has a transport, format, framing, size, class and replay window.
  - **Required class.**
    - Only `relp-tls` may be required.
    - A required target needs mutual TLS and a durable-acknowledgement commissioning check (`durable_ack`).
    - Audit goes only to a required `relp-tls` target sized for `audit.MaxRecordBytes` (D1-15).
  - **Insecure transports** (`tcp`, `udp`, `relp`) need an admin acknowledgement (scope `lab-only` in 0.1), and send no device content by default (D1-22 and its amendment).
  - **Rendering.**
    - One canonical RFC 5424 or RFC 3164 rendering, with one SD element.
    - Device bytes appear only escaped or as base64.
    - Format characters and noncharacters go as base64.
    - Size steps never split or cut silently.
    - Every message carries the `v` and `ev` identifiers (D1-13).
  - **Mode A cursor rule** (`Window`): the cursor advances over a contiguous run of OKs only; anything else ends the session, and everything after the cursor is re-sent.
  - **Inbound RELP grammar** (TB5): `ParseRELPResponse`, bounded by `MaxRELPFrameLen`.
  - **Consumers.** `Consumers(target, streams, audit)` maps a target to its C5 consumers (C6-A5-2), and the target lifecycle is stated.
- **Consumer reviews written:**
  - C1 (`reviews/C1-A4.md`): accepted.
  - C5 (`reviews/C5-A4.md`): accepted, re-checked at `2ef46a2`, `8c1eb82` and `b73c63b`.
  - C8 (`reviews/C8-A4.md`): accepted with changes.

**Reviewer outcomes**

| Contract | Reviewer | Outcome | Record |
| --- | --- | --- | --- |
| C4 | A2 | accepted with changes, applied; accepted on re-check | `reviews/C4-A2.md` |
| C4 | A5 | accepted | `reviews/C4-A5.md` |
| C4 | A6 | accepted with changes, applied; accepted at `aef8fd8` and `b157ff8` with nothing open | `reviews/C4-A6.md` |
| C4 | A3 | rated the origin-auth table | `reviews/C4-A3.md` |
| C6 | A1 | accepted; notes 1 to 3 applied | `reviews/C6-A1.md` |
| C6 | A3 | accepted with changes (2 blocking), applied; accepted at `1a13b6e`, `106b2a6` and `925ec8d` | `reviews/C6-A3.md` |
| C6 | A6 | accepted with changes (1 required), applied; accepted at `1a13b6e`, `106b2a6` and `925ec8d`, nothing open | `reviews/C6-A6.md` |
| C6 | A2 | accepted; notes 3 and 4 applied, 1, 2 and 5 recorded for the Phase 2 parsers | `reviews/C6-A2.md` |
| C6 | A5 | accepted with changes, applied; accepted at `925ec8d`; `Consumers` added after C5 merged | `reviews/C6-A5.md` |

**Evidence**

- `go vet ./...`, `gofmt -l .` and `go test ./...` are clean. CI is green on Linux and Windows on every push of #29 and #42.
- The event and target examples validate against their JSON schemas with Python `jsonschema` 4.26. This was run locally; CI does not install it.
- Independent probes:
  - A6 used its own RFC 5424 SD parser, hostile device text, 300,000 random RELP frames and a randomized `Align` model.
  - A1 and A3 each wrote their own RELP and `Window` probes.
- Golden examples come from documented-example fixtures (SEL-751 S22 Figure 10.16; RTAC S23 p. 636). **None is device output.** Every fixture has a SOURCE.md or NOTES.md entry.
- E-A4-03 (Phase 0) gives the durable-acknowledgement numbers: 1,471 of 1,500 acknowledged messages were lost with default rsyslog queues, and none with Direct queues and `confirmMessages`.

**Interfaces**

- Introduced: C4 (`event`), `node`, and C6 (`syslog`).
- Used: `version`, `internal/strictjson`, C7 `authz` (the acknowledgement principal), C8 `audit` (`MaxRecordBytes`), and C5 `store` (`Consumers`).

**Limitations**

- No forwarder, no Syslog receiver and no parser. Those are Phase 2.
- `RenderAudit` and `ParseAudit` were added after the handoff, together with D1-23 (`evidence_class`, `evc`, #59). See the last two tables in `A4-contracts.md`.
- The SEL-751 SER record has no sequence number:
  - a full wrap between reads is undetectable;
  - so is a new record identical to an old one ahead of the first distinct new record (D1-17).
- PEN 32473 is the RFC 5612 documentation number and must be replaced before production.
- TLS key references are strings marked `TODO(A3 node key ref)`.
- Asset IDs check the C1 pattern locally (`TODO(C1)`) until C1 merges.

**Risks**

- A required target pruned on the acknowledgement of a collector that does not store durably would lose native records. Two things guard against this: `durable_ack` and A6's V-S6 kill test against the real collector. Both depend on the collector's configuration staying as tested.
- Unencrypted forwarding is lab-only. A production scope for it is an owner decision (D1-21, D1-22).
- Nothing here has run against a real IED or collector. Evidence class is `desk` throughout.

**Dependencies**

- A1: merge #42.
- A2: Phase 2 parsers follow the C6-A2 notes: no STX, ETX or CR LF in record bytes; `DATE_F` from `SHO G`; RTAC over RFC 5424.
- A3: the node key reference.
- A6: V-S6 durable-acknowledgement kill test against the real collector.
- A5: the forwarder resumes using the C5 outbox and the C6 rules.

**Files changed**

- `contracts/node/`, `contracts/event/` (#29).
- `contracts/syslog/`, the C4 additions, `docs/phase1/A4-contracts.md`, `docs/phase1/reviews/C5-A4.md` and this handoff (#42).
- `docs/phase1/reviews/C1-A4.md` and `C8-A4.md` (merged).
