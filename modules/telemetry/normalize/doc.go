// Package normalize turns native records into C4 events: a C2 adapter
// result's SEL ASCII SER rows (P2-A4, Normalize), and a received Syslog
// message (P3-A4, Syslog; see "Received Syslog" below).
//
// Phase 2 normalizes one adapter record kind, the SEL ASCII SER row (sel.ser.row),
// read by the sel.ser.read_all operation. Normalize takes the C2 result, the
// invocation it answers and the C1 asset, and returns pending C4 events
// (seq 0) for the rows that are new since the previous read, platform health
// events about the read, the capture every event points into, and the
// alignment state to keep for the next read.
//
// # Rules
//
//   - Fail closed on the result. A result that fails C2 Validate or
//     CheckAgainst is refused with an error and produces nothing. Every
//     event's evidence_class is the result's target, which CheckAgainst has
//     tied to the endpoint's admin-set target (D1-23, D1-24); nothing is
//     taken from device content.
//   - One event per new row (1:1). A row the adapter could not parse, or
//     whose parsed fields do not appear in its bytes in order, still becomes
//     an event: its native bytes are kept, parse_status is failed, and it has
//     no fields, device time or normalized form (EP-1). A parse.failed
//     health event counts such rows.
//   - Native fields as printed. native.fields is the C2 record's fields,
//     names and values unchanged (D1-25). Before copying them, Normalize
//     checks that each value appears in the row's bytes, in order, separated
//     only by spaces, so a field the bytes do not contain never reaches C4.
//   - Device time with native precision. device_time.native is DATE, one
//     space and TIME as printed (C4). The resolution is the step of the
//     printed fraction. The date order is the relay's DATE_F when the caller
//     knows it; otherwise MDY is assumed and the event carries
//     date-format-assumed:MDY. The offset is unknown unless the caller knows
//     it, and then UTC is stated. A date or time that cannot be decoded keeps
//     the native text with invalid-time and parse_status partial.
//   - Receive time. received.utc is C2 Transcript.ReceivedAt of the row's
//     span. Its resolution and clock state are the node clock's status at
//     the invocation's ended_at, which the caller supplies. Fraction digits
//     finer than that resolution are cut, never rounded.
//   - Chronological order. The SEL-751 prints the oldest row first, with the
//     highest row number, and row 1, the newest, last (S22 Figure 10.16, the
//     response to SER 8). Transcript order is therefore oldest first, which is
//     the order Align expects and the order seqs are assigned. Parsed row
//     numbers must run n, n-1, ..., 1 in transcript order.
//   - Alignment. Each row's alignment key is SHA-256 over its bytes from the
//     first byte of DATE to the end of the row (C4 native.alignment_key). For
//     a row whose DATE cannot be located, the key starts after the first run
//     of non-space bytes and the spaces that follow it, so the same bytes get
//     the same key on every read. C4 Align compares the read with the
//     previous one. Only the rows it adds become events. A gap marks every
//     added row gap-before and raises ser.gap; an ambiguous overlap marks the
//     uncertain rows possible-duplicate and raises ser.alignment-ambiguous. A
//     visible duplicate is preferred to a lost row (D1-14).
//   - Reads that are not aligned. A read over the row limit
//     (partial.read_rows_exceeded, D1-12), a failed or refused result that
//     still carries records, a record kind this package does not normalize,
//     rows whose printed row numbers do not run n, ..., 2, 1 in transcript order,
//     and a read Align refuses as too long all produce no device events. The
//     capture is kept, one parse.failed health event says why, and the
//     alignment state stays as it was, so the next good read is compared with
//     the last good one.
//
// # What the caller does
//
// The caller (A5's scheduler) commits Output.Events in one batch on the SER
// stream with the capture and the new state (Output.Records builds the C5
// records), and the health events on the health stream. The state must be
// committed in the same transaction as the events. When a read changes the
// state but adds no events (an empty read after rows, which is the one gap
// at a clear, D1-7), Output.StateChanged is true and the state still has to
// be kept: the node commits the health records first, then saves the state
// on its own (agreed with A5, not yet built), so a crash in between repeats
// the gap and never loses it.
//
// # Received Syslog
//
// Syslog builds one pending event per message, for any bytes at all; the
// listener (modules/telemetry/receive) supplies the sender, its asset and
// the receive time.
//
//   - The message is the record and its own evidence: native.bytes are the
//     bytes received, record_sha256 and evidence.sha256 are their SHA-256,
//     and there is no separate C5 capture.
//   - RFC 5424 is recognised by VERSION after PRI; anything else after a
//     valid PRI is read as RFC 3164. Three time forms are read where RFC
//     3164 puts TIMESTAMP: "Mmm dd hh:mm:ss" (no year: the year nearest the
//     receive time is assumed, with year-absent and year-assumed), "Mmm dd
//     yyyy hh:mm:ss" (the RTAC, SEL-2488 and SEL-2730M examples) and an RFC
//     3339 time. Only a time with its offset on the wire states UTC.
//   - Fields are the parts as printed: pri, version, timestamp, hostname,
//     app_name, procid, msgid, structured_data and msg for RFC 5424; pri,
//     timestamp, hostname, tag, pid and msg for RFC 3164. A value that is
//     not valid UTF-8 is left out, because JSON would replace its bytes; the
//     bytes stay in native.bytes and the message is partial.
//   - Status: failed without a valid PRI (0 to 191, no leading zero);
//     partial when a part could not be read, a time could not be decoded,
//     or the listener flagged the frame (frame-truncated, frame-invalid);
//     ok otherwise.
//   - Normalized: the subject is the application (APP-NAME or TAG) or else
//     the host, with no value: the message text is native, not a reading.
//     The category is unmapped.
//   - The dialect comes from the asset, never from the message. The RTAC
//     dialect reads MSG as event time, level, category, tag and message
//     (the Log Message, then the Logging Comment when one is set; S23 Table
//     8.16 and p. 636): device_time is the event time, because the
//     header time is when the RTAC sent the message, and the subject is the
//     tag. Its layout rests on one manual example (documented-untested).
//
// # What it leaves out
//
// Meaning: every event's category is unmapped (Q3). Other record kinds and
// other families are later work. Nothing here does I/O.
package normalize
