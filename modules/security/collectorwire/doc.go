// Package collectorwire is the local channel between the node and the
// collector: the framing of C7 messages, the run outcome that carries the
// C2 result and the collector's audit facts back, and the two transports
// with their peer checks. Both sides import it; it holds no credential code
// and no device transport, so the node binary may contain it (D2-1).
//
// C7 (contracts/authz) defines the messages and leaves the framing to the
// implementation. This package is that framing, and it is private to A3's
// packages: the node uses it only through collectorclient.
//
// # Exchange
//
// One connection carries one request:
//
//	node -> collector   frame: CollectorRequest  (at most authz.MaxRequestBytes)
//	collector -> node   frame: CollectorReply    (at most MaxReplyBytes)
//	collector -> node   frame: RunOutcome        (only after an accepted run;
//	                                              at most MaxOutcomeBytes)
//
// then both ends close. A frame is a 4-byte big-endian length followed by
// that many bytes of JSON. A length over the reader's limit is refused
// before any of the body is read, so a peer cannot make the other side
// allocate more than the limit.
//
// An accepted reply means the collector took the run on. If the connection
// fails before the outcome arrives, the node knows the decision (it has the
// reply and its collector_seq) but not the device outcome: it treats the
// run as outcome unknown, never as succeeded, and the collector_seq numbers
// it did not receive show as a gap in audit.VerifyCollectorSeq.
//
// # Peer checks
//
// Each end checks the other's operating-system identity before it sends a
// byte, and refuses to talk to anything else (A3 design W-1):
//
//   - Windows: a named pipe created as the first instance, rejecting remote
//     clients, with an explicit DACL. The collector checks the client's
//     token at identification level and accepts only the node's service
//     SID. The node finds the server's process and accepts it only if its
//     token holds the collector's service SID.
//   - Linux: a Unix socket. Each end reads the other's uid with SO_PEERCRED
//     and accepts only the configured one. Linux is the development and CI
//     platform; the production boundary is the Windows pipe.
//
// Other operating systems are not supported: Listen and Dial return
// ErrUnsupported.
package collectorwire
