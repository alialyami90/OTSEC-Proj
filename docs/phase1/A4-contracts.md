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

- All 8 rows of SEL-751 Figure 10.16 (A2's `documented-example`), mapped field by field, plus the RTAC Syslog example, a known-offset variant and a `ser.gap` platform event. Twenty-six invalid examples, one rule each, plus two constructed valid rows (invalid date, leap second). Details: [contracts/event/testdata/NOTES.md](../../contracts/event/testdata/NOTES.md).
- Native round trip: `TestSERRoundTrip` checks that each row's bytes equal the fixture at the span, survive JSON marshalling, and that every row of the figure has exactly one event.
- Precision: `TestPrecision` plus two invalid examples.
- Schema drift: `TestSchemaMatchesTypes` fails if `schema/event.json` and the Go types disagree on any property or on which properties are required. The schema states structure; cross-field rules are enforced by `Validate`. The valid examples also validate against the schema with Python `jsonschema` 4.26 (run locally; CI does not install it).

## Changes from C4 reviews

| Review | Change | Done |
| --- | --- | --- |
| A2 ([C4-A2](reviews/C4-A2.md)) 1 | `adapter-poll` requires `invocation_id` and `operation_id`; the evidence is the C2 transcript as stored (after redaction), and spans index stored bytes. | `Validate`, `Collection` doc, invalid `adapter-poll-without-invocation` |
| A2 2 | An empty previous read followed by records is `ok`. The capacity clause (a gap when the new read fills the buffer) was superseded by A1 D1-7, which records the undetectable full wrap in the doc instead. | `align.go`; `Align(prev, next)` keeps its two-argument form |
| A2 3 | Optional `native.context_span` for the report header, inside the same evidence. | Golden rows point at the SEL-751 header; invalid `context-span-outside-evidence` |
| A2 4 | Alignment key bytes defined exactly: DATE through the last byte before CR, LF or CR LF, no trimming. | `Native.AlignmentKey` doc; the golden keys already follow it (A2 recomputed row 8) |
| A2 note | Asset IDs are C1 lowercase UUIDs. | Pattern and examples switched; IDs match A2's C1 examples |
| A5 ([C4-A5](reviews/C4-A5.md)) 1 | `ValidatePending` for producers before C5 assigns seq: every rule, with seq required to be 0. The store writes seq into `id` before any reader sees the event, so stored bodies carry the full ID. | `validate.go`, `TestValidatePending` |
| A5 2 | `evidence.ref`, when set, equals `sha256:` + `evidence.sha256` (C5 capture name). | `Validate`, schema pattern, invalid `evidence-ref-mismatch` |

| A6 ([C4-A6](reviews/C4-A6.md)) 1 | On a gap, the two reads are matched on their longest common subsequence. Records already stored are never stored again. Unmatched records whose key appears in the previous read become `PossibleDuplicates` (now a list of indices). Records missing from the middle or end are returned in `Removed` for the `ser.gap` event. | `align.go`; the removed and changed cases from A6, plus `TestAlignNeverLosesOrRestores` over every pair of eight reads |
| A6 2 | `resolution_ns` is defined as the step of the printed value. Coarser internal timing goes in the accuracy fields. A record that cannot be represented is kept, never dropped. | `DeviceTime` doc, `doc.go` |
| A6 3 | `wall_clock` is absent exactly when `invalid-time` is set. Second 60 is accepted at 23:59 only, with no UTC. | `validate.go`, two constructed valid rows, invalid `wall-clock-missing` and `leap-second-with-utc` |
| A6 Q4, A1 D1-7 | An empty previous read followed by records is `ok`. The undetectable full wrap is documented. | `align.go` |
| A6 5, rated by A3 ([C4-A3](reviews/C4-A3.md)) | Closed table `AllowedOriginAuth`: `adapter-poll` allows `session`; `syslog-receive` and `host-push` allow `none`, `tls-server-only` and `tls-mutual`. Platform events allow `platform`. | `TestOriginAuthPairs` checks every pair; invalid `origin-auth-mismatch` |
| A6 6, A1 D1-9 and D1-10 | `Decode` uses the shared `contracts/internal/strictjson`. It calls `Decode` for events stamped 0.1 (exact field names, no duplicates, no unknown fields, nothing trailing) and `Forward` for later minors, which ignores fields a later minor adds but still rejects duplicates and case variants (contracts/README.md compatibility rule). | `decode.go`, `TestDecode`; every valid example goes through `Decode` |
| A1 D1-1 | `contracts/node` holds `ID` and `Stream`. C4's `NodeID` and `Stream` are aliases of them. The schema's patterns are checked against the package constants. | `contracts/node`, `TestSchemaNodePatterns`, a row in contracts/README.md |

## Proposals for A1

1. **Line endings of fixtures.** No `.gitattributes` exists, so a Windows checkout with `core.autocrlf=true` can rewrite LF to CRLF in `tests/fixtures/`, which changes every byte-exact fixture and its SHA-256. C4 works around it with a `-text` copy in `contracts/event/testdata/`. Proposed root `.gitattributes`: `tests/fixtures/** -text` and `**/testdata/*.txt -text`.
2. **TODO(C1), TODO(C2), TODO(C3).** `AssetRef.ID`, `Sender.AssetID`, `Collection.InvocationID` and `Collection.OperationID` are strings until C1, C2 and C3 merge; the binding fields stay in C4 because they describe the attribution, not the asset.
3. **Node ID and the C1/C4 import cycle.** Decided in D1-1: `contracts/node` is added by this PR.
