// Package netobs is contract C13, otsec.netobs/0.3 with its 0.1 channel kept (below): what the passive
// network sensor hands the node, and the records the node builds from it.
// It is owned by D4. The text is docs/phase4/D4-c13-netobs.md, approved in
// D4-68, with the coding gaps of §14 agreed in D4-69 (#543); the baseline,
// the rules and the platform's own traffic are in
// docs/phase4/D4-network-baseline.md. Everything here is desk: no sensor
// exists, and no record has been produced from real traffic.
//
// # What it covers
//
//   - The channel (C13 §1): ReadFrame and WriteFrame frame one JSON record
//     with a 4-byte big-endian length, at most MaxChannelFrame; a longer
//     length is ErrFrameTooLarge and closes the channel. DecodeChannel
//     reads one record strictly: an unknown or duplicate key, a key in
//     another case, a minor other than 0.1, or an unknown closed-enum value
//     refuses it, and a type other than observation or heartbeat is
//     CodeType, so a sensor can never write an alert (AP-34). A sensor
//     body that carries node is refused (C13 §14 item 5, D4-69).
//   - Observations (C13 §4): seven kinds, each with its body; Text for
//     every value read from the wire (§3.1); the packet citation with its
//     redactions (§3.2), at most MaxRedactions per frame; the coverage
//     statement (§3.3) with coverage.settings bounded. A first sight
//     carries its frames' bytes, each checked against its hash and every
//     redacted byte checked as 0x2a.
//   - The stored observation (C13 §5): the node's object, checked against
//     the body, including function_class with function_table and
//     dnp3_no_sa set exactly on a DNP3 write, control or session-setup
//     function with sa none. DecodeStored reads a C4 event's netobs, and
//     ObservationFromEvent checks the event's asset is the destination.
//   - Heartbeats (C13 §6), and Follows for the node's per-run checks.
//   - Alerts (C13 §7): the nine rules, the four that run before
//     acknowledgement (BaselineFree), and the C4 telemetry-health form
//     (Health, AlertFromHealth, AlertFromEvent), with the coverage
//     statement flattened as coverage.* details.
//   - The network baseline document (C13 §8), otsec.netbaseline/0.1, in
//     canonical encoding: Encode, DecodeBaseline, IsCanonical, Digest and
//     SortBaseline, so the same observations folded in any order give the
//     same bytes.
//
// The learner's and the detector's checkpoint documents come with
// modules/detection, which defines the state they hold.
//
// # C13 0.2
//
// otsec.netobs/0.2 (docs/phase4/D4-c13-0.2-proposal.md, approved in D4-92;
// coded under P4-4-CC) is the channel over the network link. This package
// carries it beside 0.1:
//
//   - The 0.1 channel stays as main's intake reads it (D4-103 ruling 2):
//     Identifier is still otsec.netobs/0.1, and DecodeChannel,
//     Observation.Validate and Heartbeat.Validate read 0.1 only, refusing
//     every field 0.2 adds. The C13 0.2 intake brief moves the channel.
//   - The 0.2 channel (link.go): Identifier02; the four messages
//     (NodeHello, Ack, SensorHello, Tick) with DecodeFromNode, which names
//     the agent's close reason, and DecodeFromSensor, which also reads the
//     0.2 heartbeat and observation with every field 0.2 requires.
//   - The pure checks (judge.go): JudgeHello (CH-13), JudgeTick (CH-8),
//     AckValid (CH-9) and PlaceRecord (CH-14), the first two with CH-40's
//     span check. No product code calls them yet (F-027's gate, D4-96).
//   - The new fields of §1 and §11: made_utc; node.late, backlog, skewed
//     and lost; coverage.config_digest and settings.prp_window_ms; the
//     heartbeat's interfaces, agent, egress_check and eight counters; and
//     CH-47's aggregate keys with assets and assets_total. Each is refused
//     in a record below 0.2, required on the 0.2 channel, and optional in
//     a stored record.
//   - The stored readers read 0.1 and 0.2 strictly and a later minor
//     forward.
//
// # C13 0.3
//
// otsec.netobs/0.3 (docs/phase4/D4-c13-0.3-proposal.md, approved in
// D4-102; coded under P4-4-CC) adds the counts HR-24's rule reads:
//
//   - CH-51: the rule own-session-mismatch, baseline-free with no params,
//     refused in an alert below 0.3, and its observation matched whole
//     against the head grammar. The judgement is HR-24's stage 3.
//   - CH-52 to CH-55: on a flow end, orig_payload, resp_payload, orig_pkts,
//     resp_pkts, to_device_overlap_octets, incomplete, rexmit_inconsistent
//     and password_lines, each a pointer so that absent, 0 and false stay
//     apart. Refused below 0.3, required on the 0.3 channel as §3 to §6
//     place them, and optional in a stored record.
//   - CH-53: the heartbeat's frame_stage.overlap_table_full and the agent's
//     overlap_join_refused and overlap_unjoined, required at 0.3 and never
//     in counters.
//   - The channel (CH-36): a hello of 0.2 or 0.3 opens a connection
//     (DecodeFromSensor), and every later frame must carry its minor
//     (DecodeFromSensorIn). The node's two messages keep Identifier02.
//   - The stored readers read 0.1, 0.2 and 0.3 strictly and a later minor
//     forward; the bridge's unknown degraded value is read from 0.4 on.
//   - At judging (C4 0.6, docs/phase4/D4-c4-0.6-proposal.md §3.1 and
//     §3.2; no C13 minor): DecodeStored refuses a stored observation of a
//     later minor than self, and ObservationFromEvent a network-observation
//     event of a later C4 minor (CheckEventMinor). Each refusal is an
//     *Error with CodeSchema and Field schema, alone and never joined, for
//     which errors.Is(err, ErrLaterMinor) holds, and the observation
//     returned is nil. ObservationFromEvent prefixes "netobs." to each
//     Field of the body's errors (netobs.schema), except the whole-body
//     Field netobs. A stored alert and a baseline of a later minor are
//     still read forward.
//   - The checkpoints: CheckpointIdentifier is otsec.netcheckpoint/0.3,
//     which this code always writes, and the decoders read a 0.2 and a 0.1
//     document strictly (CheckpointIdentifier02, CheckpointIdentifier01).
//
// # Bounds
//
// The worst cases are pinned by TestWorstObservationFits (the channel
// record), TestWorstStoredObservationFits (C4's MaxNetobsBytes, and the
// stored C4 event marshaled plus its capture under C5's smallest record
// cap) and TestWorstAlertFits (MaxAlertBytes, and the alert's event plus
// its capture under the same cap).
package netobs
