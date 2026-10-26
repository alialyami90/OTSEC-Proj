// Package event is contract C4, otsec.event/0.2: the event every module
// produces and the timestamp model every other contract imports.
//
// # What it covers
//
//   - Event identity. An event is identified by (node_id, stream, seq): the
//     node that committed it, the native sequence space it belongs to, and a
//     sequence number the node assigns at durable commit, starting at 1 and
//     increasing by 1 per stream (ADR-0004 item 3). EventID.String is the
//     canonical text form used wherever a single token is needed, such as the
//     Syslog eid parameter (C6). NodeID and the stream token format are
//     defined here and imported by C5, C6 and C8. A producer checks an event
//     with ValidatePending (seq 0) before the store assigns seq; the store
//     writes seq into id before any reader sees the event.
//   - Native evidence. Native bytes are carried verbatim (base64 in JSON) with
//     their SHA-256, and located inside the capture they came from (EP-1 to
//     EP-3). A record is never reconstructed from its parsed fields. For an
//     adapter poll the capture is the C2 transcript as stored, after
//     redaction, and the event names its invocation and operation. Report
//     context such as the SER header is referenced by span, not copied.
//   - The timestamp model. The device's own time text is kept verbatim.
//     Resolution and accuracy are separate fields; resolution is the step of
//     the time as printed, and coarser internal timing is an accuracy. The
//     offset from UTC may be "unknown", and then no UTC time is stated. Time
//     quality is scoped (record, report, device or stream). A rendered time
//     may not carry more fractional digits than its resolution supports. The
//     collector's receive time is a separate field; for an adapter poll it
//     is the time the record's last byte arrived (C2 ReceivedAt). C8 audit records reuse DeviceTime and Received.
//   - Who sent it and what it is about. Source.Asset is the subject (a C1 asset
//     reference); Source.Sender is who delivered the bytes. A relaying sender
//     (an RTAC, an SEL-5056) never becomes the subject: the subject is then
//     bound with confidence "asserted" (A3 AP-22). Source.OriginAuth records
//     how the sender was authenticated.
//   - Real or simulated (A1 D1-23, D1-24). Every device event carries
//     Source.EvidenceClass: device-observed or simulated. It is set from
//     configuration, never from what the far end says, so a simulated read
//     can never pass upstream as a device read (principle 10). An
//     adapter-poll event takes C2 Result.target, which CheckAgainst ties to
//     the C1 endpoint's admin-set target. A received Syslog event from a
//     known sender is device-observed only when both the C1 endpoint it
//     arrived on and the node listener that received it are
//     device-observed, otherwise simulated; a relayed message uses the
//     relay's endpoint, not the subject's. An event from an unknown sender
//     (asset-unresolved) takes the listener's target: device-observed would
//     claim what nobody configured, and simulated would let a SIEM filter
//     on evc hide the traffic an analyst most needs to see. The listener's
//     target is node configuration (A5, Phase 2). Readers use
//     Source.Simulated, which counts any value other than device-observed
//     as simulated. C6 forwards it as evc.
//   - Snapshot alignment for ring-buffer sources such as the SEL ASCII SER
//     (A6 C-13, R-A4-1, R-A4-2). Align compares consecutive reads by alignment
//     key; the key is the record without its row number. A gap or an
//     ambiguous overlap is reported as a platform health event, never hidden.
//     An empty read followed by records is not a gap (A1 D1-7). A full wrap
//     between two reads is undetectable, and so is a new record identical
//     to an old one ahead of the first distinct new record (A1 D1-17);
//     Align's doc says when.
//   - Platform event types (Health), for gaps, loss, unsynchronized clocks,
//     parse failures, silent senders and forwarding outcomes.
//   - Nothing is dropped for being hard to represent (EP-1). A record whose
//     time cannot be decoded keeps Native with the invalid-time flag and no
//     wall clock; a record that cannot be parsed keeps its native bytes with
//     parse_status partial or failed and leaves out what it could not fill.
//     Such an event is still valid, so a producer never has a reason to
//     discard a record. Decode reads stored events strictly (A1 D1-9).
//
// # What it leaves out
//
//   - Meaning. Normalized.Category is "unmapped" unless a named, versioned
//     mapping table assigned it (Q3). The contract carries the device's own
//     words and never implies a meaning it cannot justify.
//   - IDS and protocol events (Phase 4), the store and outbox (C5), the
//     Syslog rendering (C6), and any parser or device logic.
//   - The asset ID already follows C1 (a lowercase UUID) but is checked by a
//     local pattern until C1 is merged (TODO(C1)); the invocation and
//     operation IDs wait for C2 and C3 (TODO(C2), TODO(C3)).
//
// # Serves
//
// R4.1 to R4.7 (Syslog and SER collection), EP-1 to EP-9 (evidence
// preservation, docs/phase0/A4-telemetry-feasibility.md), V-S3 (timestamp
// preservation), V-S4 (duplicates and gaps), A3 AP-22 (sender and subject),
// A6 C-13 and R-A4-1/2 (alignment), ADR-0004 items 3 and 5.
//
// Readers accept every 0.x minor and ignore unknown fields (not strict).
// Kind, Health.Type, Flags, DeviceTime.Format and quality time sources are
// open sets. Source.EvidenceClass is open to later minors only: an event of
// 0.1 takes device-observed or simulated, and a later minor's new class is
// read as simulated (D1-23). Every other enum is closed.
//
// # Versions
//
//   - 0.1: the first contract (#29, #42, #59).
//   - 0.2 (A4, approved by A1 after A3's review of #150):
//     source.sender.tls_leaf_sha256, the SHA-256 of the certificate a
//     tls-mutual sender presented. Required with tls-mutual from 0.2 and
//     forbidden otherwise; binding confidence is unchanged by it. A 0.1
//     event reads unchanged, and a 0.1 reader ignores the field.
package event
