package store

import (
	"context"
	"slices"
)

// RemoveConfigStep is the most records one RemoveConfig call removes (0.7).
// A configuration record is up to 1.5 MiB, and the recovery reserve is that
// of one such commit. Deleting a row writes its b-tree and freelist pages,
// not its overflow content, so a step's WAL stays far below the reserve;
// platform/store measures the worst step.
const RemoveConfigStep = 4

// RemovableSeries (0.7) are the only series RemoveConfig takes:
// config.snapshot, for D4-20 rule 3's compared reads, the two checkpoint
// halves, for D4-32 item 2, since 0.8 identity.read, of which the node
// keeps only the newest per asset, and since 0.9 the two network
// checkpoints, of which the node keeps the newest per sensor. No
// difference, no baseline of any kind, and no identity record, finding or
// advisory set can be removed through it. It returns a new slice on each
// call.
func RemovableSeries() []string {
	return []string{SeriesConfigSnapshot, SeriesCheckpointLearner, SeriesCheckpointDetector, SeriesIdentityRead,
		SeriesNetCheckpointLearner, SeriesNetCheckpointDetector}
}

// Removed is what one RemoveConfig call removed.
type Removed struct {
	// Records is the number of records removed.
	Records int
	// Bytes is the class bytes freed: the removed records' payload and
	// every capture no retained record of any stream refers to any more.
	Bytes int64
	// Skipped lists, in the order named, the seqs that were not stored:
	// already removed, or past the stream's last committed seq.
	Skipped []Seq
}

// ConfigRemover removes unheld configuration records in bounded steps
// (0.7, D4-20 rule 3, D4-32 item 2). It is called only for removals the node
// has already checked against what the store cannot see: the audit chain
// for a no-difference read, whose config.reads_removed has a Receipt (audit
// before act), and the cursor save for a checkpoint.
type ConfigRemover interface {
	// RemoveConfig removes, in one transaction committed at SyncFull, those
	// of seqs that stream still stores, with every capture no retained
	// record of any stream refers to any more (PruneStep's rule). A seq not
	// stored is skipped and listed in Removed.Skipped, so a removal stopped
	// partway is finished by calling it again. It runs while collecting,
	// while drain-only, and with the class at its quota.
	//
	// It refuses, with CodeInvalid and nothing removed, what
	// CheckRemoveConfig refuses, a stream that is not of class
	// configuration, and a step in which any named stored record is held
	// (whatever its code), has a series other than series or none (a
	// record committed before 0.7), or is the newest record of series in
	// stream by seq. Records with no series are not counted when finding
	// the newest. Every check runs before anything is removed, so a step is
	// all or nothing.
	RemoveConfig(ctx context.Context, stream StreamID, series string, seqs []Seq) (Removed, error)
}

// CheckRemoveConfig is RemoveConfig's check of its arguments, the same for
// every implementation: a valid stream, a series in RemovableSeries, and 1
// to RemoveConfigStep seqs, none 0 and none repeated.
func CheckRemoveConfig(stream StreamID, series string, seqs []Seq) error {
	if !stream.Valid() {
		return errf(CodeInvalid, nil, "remove from %q: not a valid stream token", stream)
	}
	if !slices.Contains(RemovableSeries(), series) {
		return errf(CodeInvalid, nil, "remove from %s: series %q cannot be removed; only %v", stream, series, RemovableSeries())
	}
	switch {
	case len(seqs) == 0:
		return errf(CodeInvalid, nil, "remove from %s: no seqs named", stream)
	case len(seqs) > RemoveConfigStep:
		return errf(CodeInvalid, nil, "remove from %s: %d seqs, at most %d per call", stream, len(seqs), RemoveConfigStep)
	}
	seen := make(map[Seq]bool, len(seqs))
	for _, s := range seqs {
		if s == 0 {
			return errf(CodeInvalid, nil, "remove from %s: seq 0", stream)
		}
		if seen[s] {
			return errf(CodeInvalid, nil, "remove from %s: seq %d named twice", stream, s)
		}
		seen[s] = true
	}
	return nil
}
