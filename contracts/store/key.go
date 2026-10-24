package store

import (
	"fmt"
	"regexp"
)

// TODO(C4): NodeID, StreamID, Seq and Key mirror C4's draft (PR #29,
// contracts/event: NodeID, Stream, EventID). Once C4 is merged they become
// aliases of the C4 types and the patterns below go away:
//
//	type NodeID = event.NodeID
//	type StreamID = event.Stream
//	type Key = event.EventID

// NodeID names a platform node: a lowercase DNS label, 1 to 63 characters.
type NodeID string

var nodeIDPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

// Valid reports whether n is a well-formed node ID (C4).
func (n NodeID) Valid() bool { return nodeIDPattern.MatchString(string(n)) }

// StreamID names one native sequence space on a node, for example one
// device's SER buffer or one Syslog sender. It never contains ':'.
type StreamID string

var streamPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._/-]{0,127}$`)

// Valid reports whether s is a well-formed stream token (C4).
func (s StreamID) Valid() bool { return streamPattern.MatchString(string(s)) }

// Seq is a position in a stream. The store assigns it at commit, starting at
// 1 and increasing by exactly 1 per stream. Zero means "before the first
// event".
type Seq = uint64

// Key is the transport identity of a stored event, (node_id, stream, seq),
// C4's EventID. The store assigns it once and never recomputes it.
type Key struct {
	NodeID NodeID
	Stream StreamID
	Seq    Seq
}

// String returns C4's canonical form "<node_id>:<stream>:<seq>".
func (k Key) String() string { return fmt.Sprintf("%s:%s:%d", k.NodeID, k.Stream, k.Seq) }
