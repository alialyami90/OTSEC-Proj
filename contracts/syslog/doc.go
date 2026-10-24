// Package syslog is contract C6, otsec.syslog/0.1: how a C4 event leaves a
// node for an upstream Syslog collector, and what the node accepts back.
//
// # What it covers
//
//   - Targets. Each forwarding target names a transport, a message format,
//     a framing, a size limit and a delivery class. Only RELP over TLS may be
//     "required" (ADR-0004 item 6 and its amendment; A1 ruling 2026-10-23):
//     plain RELP acknowledgements could be forged on the path and would then
//     advance pruning. RFC 5425 TLS, RFC 6587 TCP, RFC 5426 UDP and plain
//     RELP are "best-effort". Plain TCP, UDP and plain RELP carry no
//     confidentiality or integrity and are labelled insecure wherever the
//     target is shown (Target.Insecure).
//   - Delivery modes. Mode A (RELP, with or without TLS): the cursor for a
//     target advances only on a RELP "200 OK" response for that transaction.
//     Mode B (every other transport): nothing the receiver says advances it;
//     on every reconnect the forwarder re-sends the events committed in the
//     last replay_seconds (a window by time, ADR-0004 item 6), and the
//     platform reports the target as unconfirmed. The C5 consumer of a mode B
//     target has the same window, so nothing in it is pruned before the
//     replay (C5 ComputeBoundary, A1 D1-5). Delivery is at-least-once in
//     both modes; receivers remove duplicates by the eid parameter, which is
//     the C4 event ID.
//   - The message. Render produces the one canonical rendering of a C4 event
//     in RFC 5424 (default) or an RFC 3164-compatible form for collectors
//     that cannot parse RFC 5424. HEADER TIMESTAMP is the node's receive
//     time, never the device time. Every event field travels in one SD
//     element, otsec@32473, as escaped SD-PARAM values. Device bytes appear
//     only in dtext (printable UTF-8, escaped) or dtext_b64 (anything else),
//     never verbatim in MSG, so device content cannot forge a message, a
//     header or an SD element (A3 AP-20; E-A4-02 and E-A4-04 in
//     modules/telemetry/experiments/syslog-framing). MSG is a short summary
//     for people, built from fixed tokens and from normalized values only
//     when they match a conservative character set.
//   - Size. A message never exceeds the target's limit and is never split or
//     cut. When it would exceed the limit, Render applies two steps in order
//     and stops at the first that fits: (1) the device text is replaced by
//     dtext_omitted="1" (rsha256 and rlen still identify the record, which
//     stays in the store), then (2) the MSG summary is dropped. Each step is
//     reported in Outcome, and the forwarder emits a C4 forward.text-omitted
//     health event naming the event. If the message still does not fit,
//     Render fails with too-large: the forwarder emits forward.too-large
//     naming the event and advances that target's cursor past it only after
//     the health event itself has been accepted by the target, so the loss
//     is always visible upstream.
//   - Framing. Octet counting (RFC 6587 3.4.1, mandatory for RFC 5425) is the
//     default on TCP and TLS. Non-transparent LF framing (RFC 6587 3.4.2) is
//     offered on plain TCP for collectors that cannot count octets; it is
//     safe only because a rendered message never contains LF or NUL, which
//     Frame checks. UDP carries one message per datagram. RELP frames
//     carry their own length.
//   - Versions (A1 D1-13). Every message carries two identifiers: v, the C6
//     identifier of the rendering, and ev, the C4 identifier of the event
//     (for example otsec.event/0.1). A receiver checks them before anything
//     else, so it can tell an event from a minor or major it cannot read
//     (report "unsupported version", keep the message) apart from a
//     malformed event (report "invalid"). Receivers upgrade before the nodes
//     that write to them, so in normal operation the first case means the
//     upgrade order was not followed.
//   - Audit records (C8, from the C8-A4 review). An audit record is never
//     rendered from fields: C8 forbids re-encoding sealed bytes, and the
//     chain is verified over exactly those bytes. Its sealed bytes go
//     unchanged into the RFC 5424 MSG part (MSG-ANY, no BOM), after an SD
//     element that carries the node, seq and hash. It is never truncated,
//     split or summarised. Audit goes only to a target with audit set,
//     which must be required relp-tls in RFC 5424 with room for a whole
//     sealed record (A1 D1-15): only a RELP acknowledgement shows that a
//     record or checkpoint left the node, and audit is pruned only after
//     one. Target.Validate refuses any other audit target. The rendering of
//     an audit record is TODO(C8) and lands with C8.
//   - The inbound grammar (TB5). The only bytes a node accepts from an
//     upstream collector are TLS records and, in mode A, RELP responses:
//     TXNR SP COMMAND SP DATALEN [SP DATA] LF, COMMAND rsp or serverclose,
//     bounded lengths. ParseRELPResponse is the whole grammar; its only
//     output is a transaction number and whether it was acknowledged.
//
// # What it leaves out
//
// The forwarder itself (Phase 2), receiving device Syslog (R4.1, a separate
// listener contract when Phase 2 needs it), certificate and credential
// handling (C7: TLS client credentials are a TODO(C7) reference), and
// PEN 32473, the RFC 5612 documentation number, which must be replaced by an
// IANA Private Enterprise Number before production (ADR-0004 amendment).
//
// # Serves
//
// R4.5 to R4.7, ADR-0004 items 5 and 6, A6 B-03, C-04, C-08, C-18 and V-S15,
// A3 TB5, AP-9 and AP-20. Evidence: E-A4-02 (framing), E-A4-03 (RELP ack
// semantics), E-A4-04 (all transports), A6 R-A4-3.
//
// Targets are strict: a configuration with an unknown field is rejected,
// because a misspelt "class" must not silently fall back to a default.
package syslog
