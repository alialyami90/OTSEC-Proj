package store

import (
	"otsec.local/otsec/contracts/event"
	"otsec.local/otsec/contracts/node"
)

// NodeID names a platform node: a lowercase DNS label (contracts/node, D1-1).
type NodeID = node.ID

// StreamID names one native sequence space on a node, for example one
// device's SER buffer or one Syslog sender (contracts/node). It never
// contains ':'.
type StreamID = node.Stream

// Seq is a position in a stream. The store assigns it at commit, starting at
// 1 and increasing by exactly 1 per stream. Zero means "before the first
// event".
type Seq = uint64

// Key is the transport identity of a stored event, (node_id, stream, seq):
// C4's EventID. The store assigns it once and never recomputes it. Its
// String is C4's canonical form "<node_id>:<stream>:<seq>".
type Key = event.EventID
