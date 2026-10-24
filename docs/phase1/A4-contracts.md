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
| A2 2 | An empty previous read followed by records is `ok`. The capacity clause (a gap when the new read fills the buffer) was superseded by A1 D1-7, which records the undetectable full wrap in the doc instead. | `align.go`; `Align(prev, next)` keeps its two arguments (it now also returns an error, D1-12) |
| A2 3 | Optional `native.context_span` for the report header, inside the same evidence. | Golden rows point at the SEL-751 header; invalid `context-span-outside-evidence` |
| A2 4 | Alignment key bytes defined exactly: DATE through the last byte before CR, LF or CR LF, no trimming. | `Native.AlignmentKey` doc; the golden keys already follow it (A2 recomputed row 8) |
| A2 note | Asset IDs are C1 lowercase UUIDs. | Pattern and examples switched; IDs match A2's C1 examples |
| A5 ([C4-A5](reviews/C4-A5.md)) 1 | `ValidatePending` for producers before C5 assigns seq: every rule, with seq required to be 0. The store writes seq into `id` before any reader sees the event, so stored bodies carry the full ID. | `validate.go`, `TestValidatePending` |
| A5 2 | `evidence.ref`, when set, equals `sha256:` + `evidence.sha256` (C5 capture name). | `Validate`, schema pattern, invalid `evidence-ref-mismatch` |
| A6 ([C4-A6](reviews/C4-A6.md)) 1 | On a gap, the two reads are matched on their longest common subsequence. Records already stored are never stored again. Unmatched records whose key appears in the previous read become `PossibleDuplicates` (now a list of indices). Records missing from the middle or end are returned in `Removed` for the `ser.gap` event. | `align.go`; the removed and changed cases from A6, plus `TestAlignNeverLosesOrRestores` over every pair of eight reads |
| A6 2 | `resolution_ns` is defined as the step of the printed value. Coarser internal timing goes in the accuracy fields. A record that cannot be represented is kept, never dropped. | `DeviceTime` doc, `doc.go` |
| A6 3 | `wall_clock` is absent exactly when `invalid-time` is set. Second 60 is a leap second, with no UTC; on a known offset it must fall at 23:59 UTC (re-check S-2). | `validate.go`, two constructed valid rows, invalid `wall-clock-missing` and `leap-second-with-utc` |
| A6 Q4, A1 D1-7 | An empty previous read followed by records is `ok`. The undetectable full wrap is documented. | `align.go` |
| A6 5, rated by A3 ([C4-A3](reviews/C4-A3.md)) | Closed table `AllowedOriginAuth`: `adapter-poll` allows `session`; `syslog-receive` and `host-push` allow `none`, `tls-server-only` and `tls-mutual`. Platform events allow `platform`. | `TestOriginAuthPairs` checks every pair; invalid `origin-auth-mismatch` |
| A6 6, A1 D1-9 and D1-10 | `Decode` uses the shared `contracts/internal/strictjson`. It calls `Decode` for events stamped 0.1 (exact field names, no duplicates, no unknown fields, nothing trailing) and `Forward` for later minors, which ignores fields a later minor adds but still rejects duplicates and case variants (contracts/README.md compatibility rule). | `decode.go`, `TestDecode`; every valid example goes through `Decode` |
| A1 D1-1 | `contracts/node` holds `ID` and `Stream`. C4's `NodeID` and `Stream` are aliases of them. The schema's patterns are checked against the package constants. | `contracts/node`, `TestSchemaNodePatterns`, a row in contracts/README.md |
| A6 re-check R-1, A1 D1-12 | `event.MaxAlignRows = 2048`. `Align` returns `ErrAlignTooLong` for a longer read on either side, before allocating anything (at most about 16 MB at the ceiling). The producer treats it as a failed parse. C2 profiles state `max_read_rows` at or below the ceiling. | `align.go`, `TestAlignRefusesOversizeRead` (50,000 rows refused with zero allocations; 2,048 rows aligned) |
| A6 re-check S-1, A1 D1-14 | On a gap, every record from the first unmatched one onwards is added, because a ring buffer only appends. Those the match paired with an old record, or whose key occurs in the previous read, are `PossibleDuplicates`. A new record with a repeated key is no longer lost. | `align.go`; A6's case `1 3 0 → 4 0′ 5` and the changed-in-place case updated |
| A6 re-check S-2 | Second 60 is checked against 23:59 UTC when the offset is known, so `15:59:60` at `-08:00` validates and `23:59:60` at `-08:00` does not. With the offset unknown, any minute is accepted. | `checkLeap` in `validate.go`, `TestDeviceTimeLeapSecondAndInvalidTime` |
| A6 re-check S-3 | `invalid-time` with a `wall_clock` present is rejected (`forbidden`). | same test |
| A1 D1-16 (with C6) | New platform event type `time.node-stepped`: the node's own clock was stepped, so `received.utc` jumps. It pairs with C8 `clock.change`. Additive to 0.1, because the health set is open. | `event.go` |
| A1 D1-17 (with C6) | The residual undetectable SER loss with repeated keys is stated in `Align`'s doc and in `doc.go`. | `align.go`, `doc.go` |

## C6 `otsec.syslog/0.1`: decisions

| Topic | C6 | Why |
| --- | --- | --- |
| Delivery class | `required` only on `relp-tls`. Every other transport is `best-effort`. | ADR-0004 item 6 and the A1 ruling of 2026-10-23: plain RELP acknowledgements can be forged on the path and would advance pruning. |
| Delivery modes | Mode A (RELP): the cursor advances on `200 OK` for that transaction only, with a window of 1 to 1,024. Mode B (everything else): nothing the receiver says advances it, and every reconnect re-sends the last `replay_seconds` (1 s to 7 days). | E-A4-03 showed that TCP and TLS give no delivery evidence. The window is by time (ADR-0004 item 6) and matches the C5 best-effort boundary (D1-5). |
| Insecure transports | `tcp`, `udp` and `relp` are labelled insecure by `Target.Insecure`. | R2.3: an insecure downstream connection is identified wherever it is shown. |
| Message | One canonical RFC 5424 rendering, or an RFC 3164-compatible one. Every event field goes in one SD element, `otsec@32473`. Device bytes appear only as escaped `dtext` or as `dtext_b64`, never verbatim in MSG. | A3 AP-20, and E-A4-02 and E-A4-04: device text cannot forge a header, a frame or an SD element. |
| Header time | Node receive time, cut to 6 fraction digits (RFC 5424 TIME-SECFRAC). `rcv` keeps full precision. | The header cannot carry nanoseconds; no precision is lost from the event. |
| Size | Never split, never cut. In order: replace device text with `dtext_omitted="size"`, then drop the MSG summary, then fail with `too-large`. The forwarder emits `forward.text-omitted` or `forward.too-large`, and advances past a too-large event only after that health event is accepted. | Acceptance test: "split or truncated only as the profile says, never silently". |
| Framing | Octet counting by default on TCP and TLS. LF framing only on plain `tcp`, for collectors that cannot count octets. One datagram per message on UDP. | ADR-0004 names RFC 6587 octet counting. LF framing is an addition, offered best-effort and insecure only, guarded by `Frame`; A3 and A6 accept it. |
| Inbound (TB5) | `ParseRELPResponse` is the whole grammar a node accepts back: `rsp` and `serverclose`, bounded lengths, a transaction number that must be outstanding. | A3 TB5: the node parses nothing else from upstream. |
| Versions (D1-13) | Every message carries `v` (the C6 identifier) and `ev` (the C4 identifier of the event). | A receiver can tell an unreadable version from a malformed event. |
| Audit (C8, D1-15) | A target with `audit: true` must be required `relp-tls` in RFC 5424 with `max_message_octets` at least `audit.MaxRecordBytes` + 1,024 = 17,408. Any other audit target is refused at load with code `audit`. Sealed bytes go unchanged in MSG and are never cut or split. The audit rendering (RenderAudit) is the next C6 change, now that C8 has merged. | C8 forbids re-encoding sealed bytes, and only a RELP acknowledgement shows that a record or checkpoint left the node. See [C8-A4](reviews/C8-A4.md). |
| PEN | 32473 is the RFC 5612 documentation number and must be replaced before production. | ADR-0004 amendment. |

Acceptance tests: `TestRequiredOnlyOnRELPTLS` (every transport and class pair), `TestAuditOnlyOnRequiredRELPTLS` (D1-15), `TestOversize` (each size step and the failure), `TestHeaderTimestampAtMostSixDigits`, `TestHostileContent` (CR, LF, NUL, a BOM, U+2028, C1 controls, `]`, `"`, backslashes and invalid UTF-8 in device text), `TestGoldenRenderings`, `TestRenderReadBack` and `TestParseRELPResponse`. The examples are described in [contracts/syslog/testdata/NOTES.md](../../contracts/syslog/testdata/NOTES.md).

## Changes from C6 reviews

| Review | Change | Done |
| --- | --- | --- |
| A3 1 (blocking), A1 1 | Mode A cursor rule: the cursor advances to N only when every transaction up to N has `200 OK`. A 500, serverclose, timeout or closed connection ends the session, and everything after the cursor is sent again. A second response for one TXNR is a violation. The open's OK advances nothing and must offer `commands=syslog`. | `Window` in `relp.go`, `doc.go`, `TestWindow` |
| A3 2 (blocking), A1 2 | `tls.client_credential_ref` (mutual TLS) is required on required and audit targets. | `Validate`, invalid `required-without-client-credential`, `TestMutualTLSOnRequiredAndAudit` |
| A6 1 (required) | A required target records `durable_ack`, the passed commissioning check that its collector acknowledges after a durable write (E-A4-03 trials 1 and 2). It is refused on best-effort targets. | `DurableAck`, `doc.go`, invalid `required-without-durable-ack`. A6 added the V-S6 case against a real collector. |
| A3 3 | TLS 1.2 minimum, mandatory host name and chain verification, no fallback. The trust anchor is a platform-only CA set, or `spki_sha256` pins the collector's key. | `TLSConfig` doc, `MinTLSVersion`, `spki_sha256` field, invalid `malformed-spki-pin` |
| A3 4 | TLS references are marked `TODO(A3 node key ref)`, not C7 `CredentialRef`. | `target.go`, schema |
| A3 5, A1 D1-22 and amendment | `tcp`, `udp` and plain `relp` targets carry an `acknowledgement` (by, a C7 human principal; at; reason; scope `lab-only` only in 0.1; C1's shape). `device_content` defaults to off on them and on for `relp-tls` and `tls`. Off leaves out `dtext`, `subj`, `stype`, `val`, `cat`, `map` and the summary, marked `content_omitted="config"` and reported once. Kind, asset, times, severity and record hash still travel. Size-driven omission is `dtext_omitted="size"` and keeps `forward.text-omitted`. | `target.go`, `render.go`, the RFC 3164 golden, three invalid examples, `TestInsecureTargetsAcknowledgedAndContentOff` |
| A3 6, A6 3 | `printable` rejects Unicode format characters (Cf: bidi controls, zero-width characters, BOM) and noncharacters, so they travel as `_b64`. | `render.go`, `TestPrintableRejectsFormatAndNoncharacters`, five hostile cases |
| A3 7 | Target changes are admin-only and audited as C8 `policy.apply`. Removing or downgrading the last audit target or a required target raises an alarm. | `doc.go` |
| A3 8 | `DefaultRELPResponseTimeout` (30 s). When it expires, the session closes and unacknowledged transactions are sent again. | `relp.go` |
| A1 3 | `MaxRELPFrameLen`: a buffer this long is never `ErrIncomplete`, so the caller's buffer is bounded. | `relp.go`, `TestRELPFrameBound` |
| A6 2 | C4 health detail keys match `^[a-z][a-z0-9_.-]{0,63}$` (no `=`), so `hd="key=value"` splits back only one way. | C4 `validate.go`, schema `propertyNames`, `TestHealthDetailKeys` |
| A3 9, A6 4 | LF framing stays on best-effort plain `tcp` only. A3 and A6 both accept it; A1 accepted C6 without objecting. | no change |
| A2 ([C6-A2](reviews/C6-A2.md) on #32) 3 and 4 | `rcv` is the authoritative receive time; the RFC 3164 header has no zone, year or fraction. The RTAC golden's `SystemTags. User_Logged_On` space is marked unverified on the wire. | `doc.go`, `contracts/event/testdata/NOTES.md` |
| A2 1, 2 and 5 (for the Phase 2 producers) | The SEL-751 record bytes exclude STX, ETX and CR LF (S22 p. 7.28), or the row goes as `dtext_b64` and `rsha256` changes. The date order comes from `DATE_F` read by `SHO G` in the same session; `date-format-assumed` only when it was not read. RTAC forwarding should use RFC 5424 at 2,048 octets or more, since a 1,024-byte RTAC message always loses `dtext` on a 3164 target. | Recorded here for the SEL-751 and RTAC parsers; no contract change |

## Proposals for A1

1. **Line endings of fixtures.** No `.gitattributes` exists, so a Windows checkout with `core.autocrlf=true` can rewrite LF to CRLF in `tests/fixtures/`, which changes every byte-exact fixture and its SHA-256. C4 works around it with a `-text` copy in `contracts/event/testdata/`. Proposed root `.gitattributes`: `tests/fixtures/** -text` and `**/testdata/*.txt -text`.
2. **TODO(C1), TODO(C2), TODO(C3).** `AssetRef.ID`, `Sender.AssetID`, `Collection.InvocationID` and `Collection.OperationID` are strings until C1, C2 and C3 merge; the binding fields stay in C4 because they describe the attribution, not the asset.
3. **Node ID and the C1/C4 import cycle.** Decided in D1-1: `contracts/node` is added by this PR.
