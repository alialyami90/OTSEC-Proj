package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"otsec.local/otsec/contracts/asset"
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

// VerifyChain checks a contiguous run of stored records from node, the node
// the verifier expects. The node is never taken from the records themselves,
// so a whole chain from another node does not verify (C8-A6-1).
//
//   - from is the checkpoint just before the first record, or nil when the
//     run starts at the node's genesis record (seq 1).
//   - head is a checkpoint the verifier trusts (for example the latest one
//     forwarded upstream), or nil. With a head, the run must reach head.Seq
//     and the record there must hash to head.Hash; this is what catches an
//     altered or truncated tail.
//
// Each record must parse (ParseRecord), belong to node, have seq one more
// than its predecessor, and carry prev_hash equal to the predecessor's hash.
// A checkpoint must name node.
func VerifyChain(node string, stored [][]byte, from, head *Checkpoint) error {
	if !nodeIDPattern.MatchString(node) {
		return broken("expected node %q is not a valid node ID", node)
	}
	for _, c := range []*Checkpoint{from, head} {
		if c != nil && c.NodeID != node {
			return broken("checkpoint is for node %q, not %s", c.NodeID, node)
		}
	}
	var seq uint64
	prev := GenesisPrevHash
	if from != nil {
		seq, prev = from.Seq, from.Hash
	}
	reachedHead := head == nil
	for i, b := range stored {
		r, err := ParseRecord(b)
		if err != nil {
			return broken("record %d: %v", i, err)
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
//
// From 0.2, a collector.seq_reset record (in chain order) closes an epoch: the
// numbers before it must be exactly after+1 .. its previous_high (which may
// be none, when the window starts just before the reset), and the numbers
// after it start again at 1. When the reset carries first_seen, the first
// collector number after it is that number, and numbers the new collector
// gave before it are a gap, not excused. The install key the node trusts
// (collector.install_key, then each acknowledged reset) must be known at a
// reset and must change there, and no reset repeats an earlier one's key. A
// collector.seq_reset_ack names the key of the open reset, and a
// collector.install_key may not change a trusted key without a reset. A
// restart with no reset record breaks the chain, as in 0.1.
//
// VerifyCollectorSeq keeps no state between calls, so a window that holds a
// reset but not the collector.install_key before it breaks the chain: the
// trusted key is unknown, and a restore that keeps the key cannot be told
// from a reinstall. A verifier that checks window by window uses
// VerifyCollectorSeqFrom and stores the SeqState with its checkpoint.
//
// This stops a node that leaves records out from hiding them behind a fake
// reset: without a reinstall, the collector's real numbers keep rising past
// previous_high, and the new epoch cannot hold 1..n. It does not stop a node
// that forges records, because collector_seq is node-written; that was
// already so in 0.1. A real reset can hide the old epoch's tail behind the
// node's own previous_high: a verifier that holds a higher number for the
// old epoch from outside the node (forwarded upstream) should compare it.
func VerifyCollectorSeq(recs []*Record, after, through uint64) error {
	_, err := VerifyCollectorSeqFrom(recs, SeqState{After: after}, through)
	return err
}

// SeqState is what VerifyCollectorSeqFrom carries from one window to the
// next (0.2). A verifier stores it with its checkpoint, the way it stores
// the last verified number; the zero value is the start of the chain.
type SeqState struct {
	// After is the last collector_seq verified, in the current epoch.
	After uint64 `json:"after"`
	// TrustedKey is the install key the node trusts: from
	// collector.install_key, then from each acknowledged reset. "" until
	// the chain shows one.
	TrustedKey string `json:"trusted_key,omitempty"`
	// OpenResetKey is the install key of a collector.seq_reset not yet
	// acknowledged, or "".
	OpenResetKey string `json:"open_reset_key,omitempty"`
	// ResetKeys are the install keys of every reset so far, in chain order.
	// No later reset may repeat one.
	ResetKeys []string `json:"reset_keys,omitempty"`
	// FirstSeen is the first_seen of the latest reset while no collector
	// record has followed it, or 0.
	FirstSeen uint64 `json:"first_seen,omitempty"`
}

// VerifyCollectorSeqFrom is VerifyCollectorSeq for one window of a chain
// verified window by window: it starts in the state from, checks recs up to
// through, and returns the state at the window's end for the next call.
// through is a number of the epoch the window ends in: after a reset in the
// window, the new collector's latest number (0 if none yet), not the old
// epoch's high. Verified in any split, a chain gives the same result as
// verified whole.
func VerifyCollectorSeqFrom(recs []*Record, from SeqState, through uint64) (SeqState, error) {
	seen := map[uint64]bool{}
	lo := from.After
	trusted, open, firstSeen := from.TrustedKey, from.OpenResetKey, from.FirstSeen
	keys := map[string]bool{}
	resetKeys := append([]string(nil), from.ResetKeys...)
	for _, k := range resetKeys {
		keys[k] = true
	}
	if open != "" && !keys[open] {
		return SeqState{}, broken("the starting state's open reset key %s is not among its reset keys", open)
	}
	cover := func(hi uint64) error {
		for n := range seen {
			if n > hi {
				return broken("collector_seq %d is outside %d..%d", n, lo+1, hi)
			}
		}
		for n := lo + 1; n <= hi; n++ {
			if !seen[n] {
				return broken("no record for collector_seq %d: a collector event was not recorded", n)
			}
		}
		return nil
	}
	for _, r := range recs {
		switch r.Action {
		case ActionCollectorSeqReset:
			if *r.PreviousHigh < lo {
				return SeqState{}, broken("collector.seq_reset previous_high %d is below %d", *r.PreviousHigh, lo)
			}
			if firstSeen != 0 {
				return SeqState{}, broken("collector.seq_reset follows a reset whose first_seen %d was never recorded", firstSeen)
			}
			if err := cover(*r.PreviousHigh); err != nil {
				return SeqState{}, err
			}
			if trusted == "" {
				return SeqState{}, broken("collector.seq_reset with no trusted install key before it: a restore cannot be told from a reinstall")
			}
			if keys[r.InstallKeyID] || r.InstallKeyID == trusted {
				return SeqState{}, broken("collector.seq_reset keeps install key %s: not a reinstall", r.InstallKeyID)
			}
			keys[r.InstallKeyID] = true
			resetKeys = append(resetKeys, r.InstallKeyID)
			seen, lo, open, firstSeen = map[uint64]bool{}, 0, r.InstallKeyID, r.FirstSeen
			continue
		case ActionCollectorSeqResetAck:
			if open == "" || open != r.InstallKeyID {
				return SeqState{}, broken("collector.seq_reset_ack names install key %s, which no open reset has", r.InstallKeyID)
			}
			open, trusted = "", r.InstallKeyID
			continue
		case ActionCollectorInstallKey:
			if open != "" || (trusted != "" && trusted != r.InstallKeyID) {
				return SeqState{}, broken("collector.install_key %s changes the trusted key without an acknowledged reset", r.InstallKeyID)
			}
			trusted = r.InstallKeyID
			continue
		}
		if r.CollectorSeq == 0 {
			continue
		}
		if firstSeen != 0 {
			if r.CollectorSeq != firstSeen {
				return SeqState{}, broken("the first collector_seq after a reset is %d, not its first_seen %d", r.CollectorSeq, firstSeen)
			}
			firstSeen = 0
		}
		if r.CollectorSeq <= lo {
			return SeqState{}, broken("collector_seq %d is outside %d..%d", r.CollectorSeq, lo+1, through)
		}
		if seen[r.CollectorSeq] {
			return SeqState{}, broken("collector_seq %d appears on two records", r.CollectorSeq)
		}
		seen[r.CollectorSeq] = true
	}
	if through < lo {
		return SeqState{}, broken("through %d is below the last verified collector_seq %d", through, lo)
	}
	if err := cover(through); err != nil {
		return SeqState{}, err
	}
	return SeqState{After: through, TrustedKey: trusted, OpenResetKey: open, ResetKeys: resetKeys, FirstSeen: firstSeen}, nil
}

// OpenSuspension is one asset suspension the node holds (0.2), keyed by the
// asset, the C1 reason and the ref (the correlation_id of the asset.suspend
// that opened it). Code is the C2 code that set it, "" for reason operator;
// it is carried, not compared.
type OpenSuspension struct {
	AssetID string                 `json:"asset_id"`
	Reason  asset.SuspensionReason `json:"reason"`
	Ref     string                 `json:"ref"`
	Code    string                 `json:"code,omitempty"`
}

// VerifySuspensions checks the node's asset suspensions in chain order (0.2):
// asset.suspend opens a suspension, keyed by asset, C1 reason and ref
// (correlation_id), that is not already open, and asset.suspension_clear must
// name one that is open and no later clear has closed. from is the open set
// at the start of recs: nil for a chain from its first record, or the
// node's checkpoint when recs is the tail after it, so that a clear of a
// suspension opened before the checkpoint verifies. It returns the
// suspensions still open at the end, in the order they were opened, from
// which a node can rebuild its state.
func VerifySuspensions(from []OpenSuspension, recs []*Record) ([]OpenSuspension, error) {
	type key struct{ asset, reason, ref string }
	keyOf := func(o OpenSuspension) key { return key{o.AssetID, string(o.Reason), o.Ref} }
	open := map[key]OpenSuspension{}
	var order []key
	for _, o := range from {
		k := keyOf(o)
		if _, ok := open[k]; ok {
			return nil, broken("the starting set holds asset %s (%s) by %s twice", k.asset, k.reason, k.ref)
		}
		open[k] = o
		order = append(order, k)
	}
	for _, r := range recs {
		if r.Action != ActionAssetSuspend && r.Action != ActionAssetSuspensionClear {
			continue
		}
		o := OpenSuspension{AssetID: r.Target.AssetID, Reason: r.Suspension.Reason, Ref: r.CorrelationID, Code: r.Suspension.Code}
		k := keyOf(o)
		_, isOpen := open[k]
		if r.Action == ActionAssetSuspend {
			if isOpen {
				return nil, broken("asset %s is already suspended (%s) by %s", k.asset, k.reason, k.ref)
			}
			open[k] = o
			order = append(order, k)
			continue
		}
		if !isOpen {
			return nil, broken("asset.suspension_clear names %s (%s) by %s, which is not open", k.asset, k.reason, k.ref)
		}
		delete(open, k)
	}
	out := []OpenSuspension{}
	for _, k := range order {
		if o, ok := open[k]; ok {
			out = append(out, o)
			delete(open, k) // a key reopened later appears once
		}
	}
	return out, nil
}
