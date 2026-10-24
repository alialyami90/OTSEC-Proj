// Package event is contract C4, otsec.event/0.1: the event every module
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
//     defined here and imported by C5, C6 and C8.
//   - Native evidence. Native bytes are carried verbatim (base64 in JSON) with
//     their SHA-256, and located inside the capture they came from (EP-1 to
//     EP-3). A record is never reconstructed from its parsed fields.
//   - The timestamp model. The device's own time text is kept verbatim.
//     Resolution and accuracy are separate fields. The offset from UTC may be
//     "unknown", and then no UTC time is stated. Time quality is scoped (record,
//     report, device or stream). A rendered time may not carry more fractional
//     digits than its resolution supports. The collector's receive time is a
//     separate field. C8 audit records reuse DeviceTime and Received.
//   - Who sent it and what it is about. Source.Asset is the subject (a C1 asset
//     reference); Source.Sender is who delivered the bytes. A relaying sender
//     (an RTAC, an SEL-5056) never becomes the subject: the subject is then
//     bound with confidence "asserted" (A3 AP-22). Source.OriginAuth records
//     how the sender was authenticated.
//   - Snapshot alignment for ring-buffer sources such as the SEL ASCII SER
//     (A6 C-13, R-A4-1, R-A4-2). Align compares consecutive reads by alignment
//     key; the key is the record without its row number. A gap or an
//     ambiguous overlap is reported as a platform health event, never hidden.
//   - Platform event types (Health), for gaps, loss, unsynchronized clocks,
//     parse failures, silent senders and forwarding outcomes.
//
// # What it leaves out
//
//   - Meaning. Normalized.Category is "unmapped" unless a named, versioned
//     mapping table assigned it (Q3). The contract carries the device's own
//     words and never implies a meaning it cannot justify.
//   - IDS and protocol events (Phase 4), the store and outbox (C5), the
//     Syslog rendering (C6), and any parser or device logic.
//   - The asset reference shape is a placeholder until C1 is merged
//     (TODO(C1)); the operation ID likewise waits for C3 (TODO(C3)).
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
// open sets; every other enum is closed.
package event
