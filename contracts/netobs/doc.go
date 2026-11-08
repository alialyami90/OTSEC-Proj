// Package netobs is contract C13, otsec.netobs/0.1: what the passive
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
// The learner's and the detector's checkpoint documents
// (otsec.netcheckpoint/0.1) come with modules/detection, which defines the
// state they hold.
//
// # Bounds
//
// The worst cases are pinned by TestWorstObservationFits (the channel
// record), TestWorstStoredObservationFits (C4's MaxNetobsBytes, and the
// stored C4 event marshaled plus its capture under C5's smallest record
// cap) and TestWorstAlertFits (MaxAlertBytes, and the alert's event plus
// its capture under the same cap).
package netobs
