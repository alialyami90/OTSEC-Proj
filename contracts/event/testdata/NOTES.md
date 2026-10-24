# C4 golden examples

Generated from the documented-example fixtures named below, then frozen. None of them is device output, so every device event carries `source.evidence_class` `simulated` (D1-23): C1 classes test fixtures as simulated. Values that no document supplies are illustrative and say so here: node ID, stream, receive times, the invocation ID, the asset IDs and the RTAC sender address `192.0.2.40` (RFC 5737 documentation range). The asset IDs and the RTAC address are the ones in A2's C1 examples (PR #32), so the two contracts' examples describe the same assets. The operation ID `sel.ser.read_all` is the SER operation in C3's register (PR #27).

`sel751-fig10-16.txt` is a byte-exact copy of A2's transcription `tests/fixtures/ied/sel/751/documented-example/ser-report-fig10-16.txt` (SEL-751 IM 20260910, Figure 10.16, `documented-example`). `TestFixtureCopyIsA2Transcription` keeps them identical; the copy is marked `-text` so a Windows checkout cannot change its bytes.

## Valid

| File | What it shows |
| --- | --- |
| `sel751-fig10-16-row1.json` … `row8.json` | The 8 rows of Figure 10.16, field by field: verbatim row bytes with their span in the report, SHA-256 of row and report, `native_position` = the relay's row number, alignment key over the bytes from DATE to the end of the row, `context_span` on the report header (`SEL-751 … CID = 5052`: Time Source, Serial No, FID, CID), evidence `ref` = `sha256:` + evidence SHA-256, invocation and operation IDs, local time with offset `unknown` and no UTC, 1 ms resolution, accuracy unknown (the manual's ±1 ms is relative to the time source, so it is `accuracy_relative_ns`), report-scoped `Time Source: Internal`, `DATE_F` assumed MDY and flagged, category `unmapped`. Seq runs oldest first: row 8 is seq 1. Rows 8 and 7 share 13:54:09.602 and stay two events. |
| `sel751-row8-known-offset.json` | Row 8 as it would look after the adapter read `UTC_OFF` and the DST settings. The offset `-08:00` is illustrative, not from the manual. UTC is stated only because the offset is known, and equals wall clock minus offset. |
| `rtac-syslog-user-logon.json` | The RTAC Syslog example (A2's fixture `tests/fixtures/ied/sel/rtac/documented-example/syslog-user-logon.txt`, SEL-5033 IM 20260925 p. 636). The event time is the millisecond time inside MSG; the HEADER send time, 9.4 s later, is kept only as a native field. Received over UDP, so `origin_auth` is `none`. The space in `SystemTags. User_Logged_On` is kept as S23 prints it; whether the RTAC sends it on the wire is unverified (C6-A2-4). |
| `health-ser-gap.json` | A platform `ser.gap` event: the next read of the same SER stream had no overlap with the previous one. |
| `constructed-invalid-date.json` | **Constructed, not from the manual.** Row 8 with the date changed to `02/30/2007`. The native time is kept, `wall_clock` is absent, the flag is `invalid-time`, and parse status is `partial`. The record is kept, not dropped (EP-1). Its evidence is the row itself. |
| `constructed-leap-second.json` | **Constructed, not from the manual.** Row 8 at `12/31/2016 23:59:60.602`. Second 60 is accepted at 23:59. No UTC is stated, so a consumer that has the leap-second table may convert it. |

## Invalid

Each file is `sel751-fig10-16-row8.json` with one change (the two platform cases start from `health-ser-gap.json`). `Schema` says whether `schema/event.json` alone also rejects it; the rest need `event.Validate`.

| File | Code | Schema | What it shows |
| --- | --- | --- | --- |
| `precision-overclaim.json` | precision | no | `.602` with a 1 s resolution claims digits the clock cannot produce. |
| `received-precision-overclaim.json` | precision | no | Same rule on the receive time: 6 digits at 1 ms resolution. |
| `utc-with-unknown-offset.json` | offset | no | A UTC time when the offset is unknown is a guess. |
| `utc-inconsistent.json` | offset | no | UTC that is not wall clock minus offset. |
| `known-offset-without-basis.json` | offset | no | A known offset must say where it came from. |
| `bytes-tampered.json` | evidence | no | One byte changed: the SHA-256 no longer matches. |
| `span-outside-evidence.json` | evidence | no | The span points past the end of the report. |
| `seq-zero.json` | id | yes | Seq starts at 1. |
| `node-id-uppercase.json` | id | yes | Node IDs are lowercase DNS labels. |
| `stream-with-colon.json` | id | yes | `:` separates the parts of the canonical event ID. |
| `category-without-mapping.json` | unjustified-meaning | no | A category with no mapping table claims meaning the record does not carry (Q3). |
| `failed-parse-with-normalized.json` | forbidden | no | A failed parse has no normalized form. |
| `missing-native.json` | missing | no | A device event without native evidence (EP-1). |
| `received-without-z.json` | time-format | yes | Platform times are UTC with a `Z` suffix. |
| `other-major.json` | schema | yes | `otsec.event/1.0` is another major. |
| `device-event-platform-auth.json` | enum | no | `platform` authentication on a device event. |
| `content-field-configured.json` | enum | no | A subject named by the content cannot be `configured` (AP-22). |
| `no-asset-no-flag.json` | missing | no | An unresolved subject must carry `asset-unresolved`. |
| `platform-event-with-native.json` | forbidden | no | Platform events carry no device record. |
| `closed-enum-unknown.json` | enum | yes | `scope: site` is outside the closed set. |
| `adapter-poll-without-invocation.json` | missing | no | An adapter poll must name its C2 invocation (and C3 operation). |
| `context-span-outside-evidence.json` | evidence | no | The header span runs past the end of the report. |
| `origin-auth-mismatch.json` | enum | no | An adapter poll labelled `origin_auth: none`. Only `session` fits `adapter-poll` (A3 C4-A3). |
| `wall-clock-missing.json` | missing | no | No wall clock without the `invalid-time` flag. |
| `leap-second-with-utc.json` | offset | no | A leap-second record that states UTC. C4 does not convert second 60. |
| `evidence-ref-mismatch.json` | evidence | no | The capture name is not `sha256:` + the evidence SHA-256 (C5 names captures by content). |
| `evidence-class-missing.json` | missing | no | A device event that does not say whether its device was real or a simulator (D1-23). |
| `evidence-class-not-observed.json` | enum | no | `documented` is a C1 class, but a 0.1 event's far end is `device-observed` or `simulated`, nothing else. The schema covers every 0.x minor, and the enum is open to later minors, so only `Validate` refuses it. |
| `platform-event-with-evidence-class.json` | forbidden | no | A platform event has no far end to classify. |
