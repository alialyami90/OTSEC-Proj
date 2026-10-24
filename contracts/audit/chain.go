package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
)

// Hash returns the chain hash of one stored record: lowercase hex SHA-256 of
// its exact bytes.
func Hash(stored []byte) string {
	sum := sha256.Sum256(stored)
	return hex.EncodeToString(sum[:])
}

// Checkpoint is a chain position held outside the node: the node, the
// sequence number and the hash of the record at that position. A checkpoint
// is what lets a verifier detect altered or truncated newest records.
type Checkpoint struct {
	NodeID string `json:"node_id"`
	Seq    uint64 `json:"seq"`
	Hash   string `json:"hash"`
}

// ErrChainBroken wraps every reason VerifyChain fails.
var ErrChainBroken = errors.New("audit: chain broken")

func broken(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrChainBroken, fmt.Sprintf(format, a...))
}

// VerifyChain checks a contiguous run of stored records from one node.
//
//   - from is the checkpoint just before the first record, or nil when the
//     run starts at the node's genesis record (seq 1).
//   - head is a checkpoint the verifier trusts (for example the latest one
//     forwarded upstream), or nil. With a head, the run must reach head.Seq
//     and the record there must hash to head.Hash; this is what catches an
//     altered or truncated tail.
//
// Each record must parse (ParseRecord), belong to the same node, have seq one
// more than its predecessor, and carry prev_hash equal to the predecessor's
// hash.
func VerifyChain(stored [][]byte, from, head *Checkpoint) error {
	var node string
	var seq uint64
	prev := GenesisPrevHash
	if from != nil {
		node, seq, prev = from.NodeID, from.Seq, from.Hash
	}
	reachedHead := head == nil
	for i, b := range stored {
		r, err := ParseRecord(b)
		if err != nil {
			return broken("record %d: %v", i, err)
		}
		if node == "" {
			node = r.NodeID
		}
		if r.NodeID != node {
			return broken("record %d is from node %s, not %s", i, r.NodeID, node)
		}
		if r.Seq != seq+1 {
			return broken("record %d has seq %d, want %d", i, r.Seq, seq+1)
		}
		if r.PrevHash != prev {
			return broken("record seq %d does not link to its predecessor", r.Seq)
		}
		seq, prev = r.Seq, Hash(b)
		if head != nil && seq == head.Seq {
			if head.NodeID != node || head.Hash != prev {
				return broken("record seq %d does not match the trusted checkpoint", seq)
			}
			reachedHead = true
		}
	}
	if head != nil && from != nil && len(stored) == 0 && head.Seq == from.Seq {
		reachedHead = head.Hash == from.Hash && head.NodeID == from.NodeID
	}
	if !reachedHead {
		return broken("records end at seq %d, before the trusted checkpoint at %d (truncated)", seq, head.Seq)
	}
	return nil
}

// VerifyCollectorSeq checks that the records of one node account for every
// event the collector reported between two of its numbers: each collector
// sequence number in after+1 .. through appears on exactly one record, and no
// record carries a number outside that range. through is the newest number
// the collector has given (its latest reply), and after the last number
// already verified (0 at the start). The node writes the records of
// collector events, so a node that leaves one out leaves a gap here
// (C7-A5-2). A node that withholds every record after a point is detected
// only once the collector next reports a higher number.
func VerifyCollectorSeq(recs []*Record, after, through uint64) error {
	seen := map[uint64]bool{}
	for _, r := range recs {
		if r.CollectorSeq == 0 {
			continue
		}
		if r.CollectorSeq <= after || r.CollectorSeq > through {
			return broken("collector_seq %d is outside %d..%d", r.CollectorSeq, after+1, through)
		}
		if seen[r.CollectorSeq] {
			return broken("collector_seq %d appears on two records", r.CollectorSeq)
		}
		seen[r.CollectorSeq] = true
	}
	for n := after + 1; n <= through; n++ {
		if !seen[n] {
			return broken("no record for collector_seq %d: a collector event was not recorded", n)
		}
	}
	return nil
}
