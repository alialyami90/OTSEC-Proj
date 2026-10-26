package store

import (
	"context"
	"strings"
)

// QuarantinePrefix starts the ID of every quarantine stream (0.3, D3-1): a
// stream that keeps outcomes the node refused, which no consumer reads, so
// pruning never removes them. Only such a stream can lose events other than
// by pruning, and only through Discard.
const QuarantinePrefix = "quarantine/"

// DiscardStepEvents is the most events one Discard call removes. Named
// seqs can sit anywhere in a stream, so each one can touch its own pages:
// the event's leaf, the capture's, and their index leaves. Measured over a
// 40,000-event stream with a 1 KiB capture per event, 16 seqs spread across
// it wrote 387 KB of WAL, inside the 512 KiB bound the recovery reserve is
// twice; 50 wrote 997 KB, nearly the whole reserve (E-A5-3, D3-1 condition
// 3; evidence class: simulated).
const DiscardStepEvents = 16

// Discarded is what one Discard call removed.
type Discarded struct {
	// Events is the number of events removed. A named seq that was no
	// longer stored is not counted.
	Events int
	// Bytes is the class bytes freed: the removed events' payload and every
	// capture no retained record of any stream refers to any more.
	Bytes int64
}

// Discarder removes named events of a quarantine stream (0.3, D3-1). It is
// called only to carry out an administrator's clear that the node has
// already audited and whose every event it has checked against the
// administrator's export (audit before act); nothing calls it on its own,
// and it never removes a confirmed event of a consumed stream, which only
// PruneStep does.
type Discarder interface {
	// Discard removes, in one transaction committed at SyncFull, those of
	// seqs that stream still stores, with each one's native bytes and
	// normalized form, and any capture no retained record of any stream
	// refers to any more (PruneStep's rule). A seq no longer stored is
	// skipped, so a clear stopped partway is finished by calling it again.
	// It refuses, with CodeInvalid and nothing removed, a stream not under
	// QuarantinePrefix, a stream any of consumers reads or that has a
	// persisted cursor, an empty list, more than DiscardStepEvents seqs, a
	// repeated seq and seq 0 (CheckDiscard).
	Discard(ctx context.Context, consumers []Consumer, stream StreamID, seqs []Seq) (Discarded, error)
}

// CheckDiscard is Discard's check of its arguments, the same for every
// implementation. An implementation also refuses a stream that has a
// persisted cursor, which only it can see.
func CheckDiscard(consumers []Consumer, stream StreamID, seqs []Seq) error {
	if name, ok := strings.CutPrefix(string(stream), QuarantinePrefix); !ok || name == "" || !stream.Valid() {
		return errf(CodeInvalid, nil, "discard from %q: only a stream under %q can be discarded from", stream, QuarantinePrefix)
	}
	for _, c := range consumers {
		if c.Stream == stream {
			return errf(CodeInvalid, nil, "discard from %s: consumer %s reads it", stream, c.ID)
		}
	}
	switch {
	case len(seqs) == 0:
		return errf(CodeInvalid, nil, "discard from %s: no seqs named", stream)
	case len(seqs) > DiscardStepEvents:
		return errf(CodeInvalid, nil, "discard from %s: %d seqs, at most %d per call", stream, len(seqs), DiscardStepEvents)
	}
	seen := make(map[Seq]bool, len(seqs))
	for _, s := range seqs {
		if s == 0 {
			return errf(CodeInvalid, nil, "discard from %s: seq 0", stream)
		}
		if seen[s] {
			return errf(CodeInvalid, nil, "discard from %s: seq %d named twice", stream, s)
		}
		seen[s] = true
	}
	return nil
}
