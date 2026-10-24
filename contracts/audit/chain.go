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
