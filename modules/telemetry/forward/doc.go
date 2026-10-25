// Package forward is the C6 forwarder (P2-A4): a C5 outbox consumer that
// renders each committed event for one upstream Syslog target and sends it
// over RELP, mode A.
//
// # Rules
//
//   - Confirmed, then saved. A stream's cursor for the target moves to seq N
//     only when the RELP transaction carrying N, and every transaction sent
//     before it in the session, has a 200 OK (C6 Window). The cursor is
//     saved with C5 SaveCursor, which returns after a full commit, before
//     anything else depends on it. For a required target that cursor is
//     what lets C5 prune; C6 Validate accepts a required target only with a
//     durable_ack whose collector acknowledges after a synchronous write and
//     checks the node by name (D2-9).
//   - Nothing skipped. A 500, a serverclose, a response that breaks the C6
//     grammar, a closed connection or no response within the response
//     timeout ends the session. The next session starts from the saved
//     cursors, so every transaction that was not confirmed is sent again:
//     delivery is at least once, and receivers remove duplicates by eid.
//   - Gaps are reported. When Outbox.Read jumps past seqs this target never
//     confirmed (a best-effort target's replay window passed), the skipped
//     range is reported as forward.unreachable before anything after it is
//     sent (C6-A5).
//   - Reported once. Each of these health events is raised once per
//     process for the event or range it is about, however many sessions it
//     takes to deliver (A6 #89). A restart may raise it once more: a
//     duplicate alarm, never a lost one.
//   - A refused report does not stop draining. When the HealthSink refuses
//     forward.text-omitted or forward.unreachable (the health stream at
//     quota), the event it is about is still sent and the report is kept
//     and committed later, in order; Status.Unreported counts them. A
//     forwarder stalled on its own report would never drain the store that
//     refused it. A too-large event whose report is refused holds only its
//     own stream and is reported again on the next loop.
//   - Size. A message whose device text or summary was dropped to fit is
//     sent and reported as forward.text-omitted. An event
//     that does not fit at all holds its stream: the forwarder raises
//     forward.too-large naming it, and moves the cursor past it only after
//     every earlier event of the stream and the forward.too-large event
//     itself are confirmed by this target. The health stream must therefore
//     be one of the target's streams (Config.HealthStream).
//   - Held, never cut. An audit record that RenderAudit refuses, a stored
//     event that does not decode or render, a forward.* event that is itself
//     too large, and a too-large event on the health stream hold their
//     stream. Status says why; the node alarms on it. Nothing is skipped to
//     get past them.
//   - TLS (TB5, D2-9). ClientTLS builds the only TLS configuration the
//     forwarder uses for relp-tls: TLS 1.2 or later, the collector's chain
//     against the target's own trust anchors (never the system roots), its
//     name against tls.server_name, and its key against the SPKI pins when
//     the target has them. The node's client certificate is required when
//     the target names one, and for a required target its name must be the
//     durable_ack.permitted_peer the collector was commissioned with, so a
//     durable_ack copied from another node's target fails at load (A3 #81
//     S-2).
//
// # What it leaves out
//
// Mode B transports (RFC 5425, TCP, UDP), raising forward.unreachable for a
// required target that stays down past its period (the node does that from
// Status), and loading keys: the node resolves trust_anchor_ref and
// client_credential_ref and hands ClientTLS the result.
package forward
