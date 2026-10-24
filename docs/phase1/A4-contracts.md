# A4 Phase 1 notes: C4 event and C6 Syslog contracts

Owner: A4. Brief: P1-A4 in [../agent-handoffs.md](../agent-handoffs.md). Packages: [contracts/event](../../contracts/event/) (C4) and [contracts/syslog](../../contracts/syslog/) (C6).

## C4 `otsec.event/0.1`: decisions and changes from the Phase 0 draft

| Topic | Phase 0 draft | C4 | Why |
| --- | --- | --- | --- |
| Event identity | `event_id` UUIDv7 plus `stream_seq` | `id = {node_id, stream, seq}`; canonical text `<node_id>:<stream>:<seq>` | ADR-0004 item 3 makes `(node_id, stream, seq)` the transport key; one identity is enough, and the text form is what C6 sends as `eid`. |
| Node ID | free text | lowercase DNS label, 1 to 63 characters | Valid as a Syslog HOSTNAME and as a file name on Windows and Linux. |
| Stream | free text | `[a-z0-9][a-z0-9._/-]{0,127}`, never `:` | Keeps the canonical event ID unambiguous. |
| Native evidence | `native.evidence` + `span` + `record_digest` | `native.bytes` (base64, optional on the wire), `record_sha256`, `record_length`, `evidence {sha256, length, ref}`, `span`, `alignment_key` | Splits the record's own bytes from the capture it came from. `record_digest` became `alignment_key`, which excludes the row number (A6 R-A4-1). |
| Accuracy | `accuracy_ns`, with SEL ±1 ms | `accuracy_ns` (against true time, nil when unknown) and `quality.accuracy_relative_ns` (against the device's own source) | A2 review: the SEL ±1 ms is relative to the time source; under `Time Source: Internal` the accuracy to true time is unknown. |
| Sender and subject | `source.sender`, `source.origin_auth` (A3 AP-22) | kept; `origin_auth` closed set `none, tls-server-only, tls-mutual, session, platform` | `platform` added for platform events. A subject bound by `content-field` can never be `configured`. |
| Kind | open set including `protocol-event`, `ids-alert` | open set without them | No IDS event types in Phase 1 (brief exclusion). A later minor can add them. |
| Precision | "no digits finer than resolution or accuracy" | digits checked against **resolution** only, on every rendered time | The acceptance test is stated against resolution. Rounding to a coarser accuracy (the GOOSE `.514` case) stays a producer choice that always passes. |
| Alignment | `align.py` prototype | `event.Align` in the contract | One definition of the rule for A2 (producer) and A6 (tests). It is a pure function over keys, no device logic. |

## Golden examples and acceptance tests

- All 8 rows of SEL-751 Figure 10.16 (A2's `documented-example`), mapped field by field, plus the RTAC Syslog example, a known-offset variant and a `ser.gap` platform event. Twenty invalid examples, one rule each. Details: [contracts/event/testdata/NOTES.md](../../contracts/event/testdata/NOTES.md).
- Native round trip: `TestSERRoundTrip` checks that each row's bytes equal the fixture at the span, survive JSON marshalling, and that every row of the figure has exactly one event.
- Precision: `TestPrecision` plus two invalid examples.
- Schema drift: `TestSchemaMatchesTypes` fails if `schema/event.json` and the Go types disagree on any property or on which properties are required. The schema states structure; cross-field rules are enforced by `Validate`. The valid examples also validate against the schema with Python `jsonschema` 4.26 (run locally; CI does not install it).

## Proposals for A1

1. **Line endings of fixtures.** No `.gitattributes` exists, so a Windows checkout with `core.autocrlf=true` can rewrite LF to CRLF in `tests/fixtures/`, which changes every byte-exact fixture and its SHA-256. C4 works around it with a `-text` copy in `contracts/event/testdata/`. Proposed root `.gitattributes`: `tests/fixtures/** -text` and `**/testdata/*.txt -text`.
2. **TODO(C1), TODO(C3).** `AssetRef.ID`, `Sender.AssetID` and `Collection.OperationID` are strings until C1 and C3 merge; the binding fields stay in C4 because they describe the attribution, not the asset.
