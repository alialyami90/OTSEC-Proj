// Package receive is the node's Syslog listener (P3-A4, R4.1, the first
// rung of R4.9): it receives device-generated Syslog, keeps every message's
// bytes, attributes it to a C1 asset by sender address, and commits it as a
// C4 event on the listener's C5 stream. The outbox and the forwarder (C6)
// then send it upstream unchanged.
//
// # Transports
//
//   - syslog-tls: RFC 5425. TLS 1.2 or later with the listener's
//     certificate (ServerTLS). With a CA set for senders, a sender that
//     presents a certificate must chain to it, and a listener may require
//     one; such a sender's events say tls-mutual, the others
//     tls-server-only. The certificate is not tied to an asset yet (C1
//     pinned-key), so attribution is by address in every case.
//   - syslog-tcp (RFC 6587) and syslog-udp (RFC 5426) are plaintext: New
//     refuses them unless Config.Plaintext is set: plaintext is enabled per
//     listener by the operator, TLS being the default (D3-5). Their events
//     say origin_auth none.
//
// # Rules
//
//   - The message is the record. A UDP datagram is one message, kept
//     whole. On a stream, an octet-counted frame (MSG-LEN SP SYSLOG-MSG) or
//     an LF-ended line is one message, without its framing. Nothing is
//     trimmed, decoded or re-encoded: native.bytes are the bytes received,
//     and record_sha256 is their SHA-256 (R4.4, V-S8). normalize.Syslog
//     builds an event for any bytes at all, so no message is dropped for
//     failing to parse; it keeps parse_status failed instead (EP-1).
//   - Framing faults keep their bytes. A frame over Limits.MaxMessage, cut
//     by the end of the connection, or stalled past Limits.FrameTimeout is
//     stored as far as it came, with frame-truncated. Bytes that do not
//     follow the framing are stored to the next LF with frame-invalid. An
//     octet count above the limit cannot be trusted to find the next frame,
//     so after its first bytes are stored the connection is closed; every
//     message before it is already stored. Bytes past the limit in an
//     over-long line are discarded and counted in Status.Discarded.
//   - Attribution is configuration. The sender's address, as the listener
//     sees it, is looked up in Config.Senders (SendersFor, from the C1
//     inbound endpoints). A known sender is the subject, bound by
//     sender-address with confidence configured; its dialect comes from the
//     asset (DialectOf), never from the message. An unknown sender's
//     message is stored the same way with asset-unresolved, within the
//     unknown budget below, and the first message from each unknown
//     address raises syslog.unknown-source on the health stream, with the
//     stored event as its related ID. Past Limits.MaxUnknown addresses one summary alarm is
//     raised instead, and nothing more is remembered.
//   - Evidence class: device-observed only when both the asset's endpoint
//     and the listener are; an unknown sender takes the listener's (C4,
//     D1-24 amendment).
//   - Rate limits per sender address (token buckets). A known sender spends
//     only its own tokens; all unknown senders also share one bucket, so a
//     flood from many addresses cannot take a known sender's share. A
//     stream over its rate is slowed: the connection is read no faster, and
//     TCP flow control holds the sender. A datagram over its rate is
//     dropped and counted.
//   - Unknown senders cannot displace configured devices (A3 F1, F2).
//     They hold at most Limits.MaxUnknownConns stream connections, so the
//     rest stay free for configured devices, and an idle one is closed
//     after Limits.UnknownIdleTimeout. All of them together may store at
//     most Limits.UnknownBytes of records per Limits.UnknownWindow (a token
//     bucket); a message past it is dropped and counted as unknown-budget,
//     and syslog.unknown-budget is raised at most once per window. A known
//     sender's stream message is never dropped.
//   - Storage full follows the C5 class. syslog-stream (TCP, TLS) is
//     refuse-new: a refused batch is held and retried, the connection is not
//     read meanwhile (Status.Held), and nothing read is dropped while the
//     node runs. syslog-datagram (UDP) is drop-and-count: a refused batch,
//     like a datagram over its rate or past the queue, is dropped and
//     counted, and the counts are reported as intake.drop-counted every
//     Limits.ReportEvery and when the listener stops.
//   - A message whose record cannot be built is a fault in this package.
//     It is dropped and counted as store, alone: the rest of its batch is
//     stored.
//   - Bounded. Connections (in all, per sender and for unknown senders),
//     the queue per connection, the datagram queue's bytes, the rate
//     limiter's table and the unknown-sender table all have limits, and
//     every read has a deadline, so no sender can grow the node's memory
//     or hold a connection without sending.
//   - Order. One connection's messages commit in the order they arrived,
//     and so do datagrams. Messages of different connections interleave in
//     commit order.
//
// # Known limits
//
//   - RFC 5425 and RFC 6587 have no acknowledgement. A sender cannot know
//     what was stored, so messages queued in memory when the node stops,
//     and not committed within Limits.Grace, are lost without the sender
//     knowing: at most 2 x Limits.Queue + 1 per connection (the batch
//     being committed, the queue behind it, and the frame being read).
//     RELP receive would close this; it is not built.
//   - Duplicates are kept. A sender that retries after a reconnect may send
//     a message twice; both are stored, and their record_sha256 is equal, so
//     a reader can find them. Nothing is removed as a duplicate, because a
//     device can send the same bytes twice on purpose (a repeating alarm).
//   - A relay's address names the relay, not the device it relays for.
//   - Address attribution is spoofable on UDP and TCP, and on TLS without
//     pinned keys (C1 binding address-only).
//   - The unknown budget bounds unattributed storage per window, not in
//     all: over an upstream outage of T it can store up to UnknownBytes x
//     (1 + T/UnknownWindow). The node should size it from the class quota
//     and the outage it must ride out. A separate C5 stream and quota for
//     unknown senders would bound it absolutely; it is not built.
package receive
