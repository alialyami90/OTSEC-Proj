// Package syslog is contract C6, otsec.syslog/0.2: how a C4 event leaves a
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
//     target advances to transaction N only when every transaction sent up
//     to N has a RELP "200 OK" (Window, C6-A3-1). An OK for a later
//     transaction never covers an earlier one still in flight; a second
//     response for one transaction is a violation; the open transaction's
//     OK advances nothing and must offer commands=syslog. A 500, a
//     serverclose, a closed connection or no response within the response
//     timeout (DefaultRELPResponseTimeout) ends the session, and every
//     transaction after the cursor is sent again. Nothing is skipped.
//     Mode B (every other transport): nothing the receiver says advances it;
//     every reconnect resumes at the lower of cursor+1 and the first event
//     committed in the last replay_seconds (a window by time, ADR-0004 item
//     6), and the platform reports the target as unconfirmed. Every
//     best-effort target, plain RELP included, has replay_seconds, and its
//     C5 consumer has the same window, so nothing in it is pruned before a
//     replay (C5 ComputeBoundary, A1 D1-5, C6-A5-1). When the resume point
//     has already been pruned, Outbox.Read returns the first retained event
//     and the forwarder reports the skipped range as forward.unreachable
//     (C6-A5). Delivery is at-least-once in both modes; receivers remove
//     duplicates by the eid parameter, which is the C4 event ID.
//   - Targets and C5 consumers (C6-A5-2, Consumers). A target is one C5
//     consumer per event stream it forwards, plus the audit stream when
//     audit is set:
//     ConsumerID is the target name, Delivery its class and ReplayWindow its
//     replay_seconds. Renaming a target makes a new consumer with a new
//     cursor. A new required target starts at the first retained event, so
//     it receives everything still held; a new best-effort target starts at
//     the first event in its window. Removing a required target raises an
//     alarm that states how many retained events become prunable.
//   - Known limits. A too-large event holds its target's cursor until the
//     forward.too-large health event is accepted, so a target that never
//     accepts it stalls, visibly, until the store's quota alarms. A node
//     with no audit target keeps every audit record until an export or the
//     C5 audit-store-full alarm; collection then stops (audit before act,
//     D1-11) while Syslog intake continues.
//   - What "required" promises. A RELP 200 OK says the collector accepted a
//     message, not that it stored it: with in-memory queues, rsyslog lost
//     1,471 of 1,500 acknowledged messages when killed (E-A4-03 trial 1),
//     and none with Direct queues and confirmMessages on (trial 2). Pruning
//     follows required acknowledgements, so a target may be required only
//     after a commissioning check against the real collector shows it
//     acknowledges after a durable write: a numbered burst, the collector
//     killed after it acknowledges, restarted, and every acknowledged
//     message found. The result is recorded in Target.DurableAck (C6-A6-1,
//     A6 V-S6). Since 0.2 (A1 D2-9) it also records the collector settings
//     the check ran with, and Validate accepts only these: the collector
//     authenticates the node by name against a permitted-peer list that
//     holds only this node's name, never by CA alone (imrelp tls.authmode="name" with tls.permittedPeer; A6 found
//     that authmode certvalid accepted a self-signed client certificate the
//     CA never signed), and it acknowledges only after a synchronous write
//     (a Direct ruleset queue and omfile sync="on"). The rule applies to
//     every required target whatever minor it declares, so a target written
//     before 0.2 must be commissioned again before it can be required.
//   - Authentication (TB5, SC-16). Every TLS target verifies the collector:
//     TLS 1.2 or later, the chain against a CA set used only for platform
//     collectors or an SPKI pin, and the host name. No fallback to
//     plaintext, no skipped verification. Required and audit targets also
//     authenticate the node with mutual TLS (client_credential_ref), so no
//     one else who can reach the collector can write events or audit into
//     it (C6-A3-2, C6-A3-3).
//   - Insecure targets (A1 D1-22 and its amendment). A tcp, udp or plain
//     relp target carries an admin's acknowledgement (by, a C7 human
//     principal; at; reason; scope; C1's shape), and in 0.1 the only scope
//     is lab-only. By default it sends no device content: no device bytes,
//     no normalized subject, subject type, value, category or mapping, and
//     a summary of the kind alone. The message carries
//     content_omitted="config", and the omission is reported once in the
//     target's state and audit record, not as a forward.text-omitted per
//     message. Kind, asset, times, severity and record hash are still sent.
//     An admin may turn device_content on; the acknowledgement covers the
//     target as configured.
//   - Target changes are security changes (C6-A3-7). Only an admin adds,
//     changes or removes a target; each change is a C8 policy.apply record
//     naming the target and a hash of its configuration. Removing the last
//     audit target or a required target, or downgrading either, raises an
//     alarm: it changes what C5 may prune and where checkpoints go.
//   - The message. Render produces the one canonical rendering of a C4 event
//     in RFC 5424 (default) or an RFC 3164-compatible form for collectors
//     that cannot parse RFC 5424. HEADER TIMESTAMP is the node's receive
//     time, never the device time; in the RFC 3164 form it is UTC with no
//     zone, no year and whole seconds, so the rcv parameter is the
//     authoritative receive time in both forms (C6-A2-3). Every event field travels in one SD
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
//     dtext_omitted="size" (rsha256 and rlen still identify the record, which
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
//     chain is verified over exactly those bytes. RenderAudit puts the
//     sealed bytes unchanged into the RFC 5424 MSG part (MSG-ANY, no BOM),
//     after the otsec@32473 element with v, ac (the C8 identifier), node,
//     seq and hash. MSGID is AUDIT, TIMESTAMP the record's time.utc and
//     HOSTNAME its node; severity is 4 for a denied, failed or warning
//     outcome and 5 otherwise. The parameters only index the record: a
//     receiver reads it with ParseAudit, which checks that they, the header
//     and the hash agree with the sealed bytes, then runs audit.VerifyChain
//     over the bytes it received. A record is never truncated, split or
//     summarised. Audit goes only to a target with audit set, which must be
//     required relp-tls in RFC 5424 with room for a whole sealed record (A1
//     D1-15): only a RELP acknowledgement shows that a record or checkpoint
//     left the node, and audit is pruned only after one. Target.Validate
//     refuses any other audit target, and MinAuditOctets leaves room for the
//     largest record C8 allows, so RenderAudit's too-large error means a
//     broken contract, not a big record; the forwarder then holds the audit
//     cursor and alarms, and never skips the record.
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
