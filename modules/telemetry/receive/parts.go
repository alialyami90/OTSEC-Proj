package receive

import (
	"context"
	"errors"

	"otsec.local/otsec/contracts/store"
)

// CommitCaps returns the most bytes and the most records the receiver puts
// in one part now: Config.MaxCommitBytes and MaxCommitRecords, or their
// defaults; the record cap is lowered if the Log has refused a larger part
// (see commitParts).
func (r *Receiver) CommitCaps() (bytes int64, records int) {
	return r.commitAt.Load(), int(r.commitN.Load())
}

// partEnd returns where the part of recs that starts at lo ends: the most
// records that fit both commit caps, the bytes of their events and their
// number, and at least one, because a record over the byte cap commits alone
// when its class allows it. The receiver attaches no captures, so a
// record's size is its event's.
func (r *Receiver) partEnd(recs []store.Record, lo int) int {
	limit, most := r.commitAt.Load(), int(r.commitN.Load())
	var size int64
	hi := lo
	for hi < len(recs) && hi-lo < most {
		n := int64(len(recs[hi].Event))
		if hi > lo && size+n > limit {
			break
		}
		size += n
		hi++
	}
	return hi
}

// lowerCaps halves the record cap from the size of a refused part of several
// records, never below one. The refusal does not say which of the Log's caps
// the part exceeded, and a part's bytes are not a safe guide: an event is the
// whole JSON envelope, so a part of a few records can pass 64 KiB and still be
// within the Log's byte cap. Records are the one measure that fits both:
// any byte cap is met by few enough records, so lowering only the record cap
// ends, at worst, at one record, and the byte cap is never lowered at all (so
// it never falls below store.MinRecordBytes). The cap only falls, and each
// call makes the next part smaller, so the loop in commitParts ends.
func (r *Receiver) lowerCaps(part []store.Record) {
	r.commitN.Store(int64(max(len(part)/2, 1)))
}

// commitParts commits recs, the records of kept, as one or more AppendBatch
// calls of at most the commit cap each, in order, and tells the caller
// whether to go on (false only when ctx ended while a part was held).
//
// A part is stored whole or not at all, and a part that commits is never
// sent again, so a refused part is tried again by itself. With hold set (a
// stream) a part the store refuses is held and tried again every
// Limits.Retry until it commits or ctx ends, as a stream batch always was.
// Without it (a datagram) a refused part is dropped and counted as store,
// and the parts after it are still tried. A crash between parts leaves the
// earlier parts stored and the later ones unread by the store, so a sender
// that resends gives duplicates, never a loss. Nothing is acknowledged to
// a sender before this returns, so an acknowledgement, where a transport
// has one, covers the whole batch only once every part has committed.
//
// A part of several records that the Log refuses as too large means one of
// its caps is below Config.MaxCommitBytes or MaxCommitRecords, and the
// refusal does not say which. The record cap is halved (see lowerCaps) and
// the part is split again. A single record the
// Log refuses as too large can never commit, so holding it would stop the
// stream; it is dropped and counted as store, with the reason in
// Status.LastErr.
func (r *Receiver) commitParts(ctx context.Context, recs []store.Record, kept []msg, hold bool) bool {
	held := false
	defer func() {
		if held {
			r.mu.Lock()
			r.held--
			r.mu.Unlock()
		}
	}()
	for lo := 0; lo < len(recs); {
		hi := r.partEnd(recs, lo)
		receipts, err := r.cfg.Log.AppendBatch(ctx, recs[lo:hi])
		if err == nil {
			r.stored(ctx, kept[lo:hi], receipts)
			lo = hi
			continue
		}
		r.update(func(s *Status) { s.LastErr = "store: " + err.Error() })
		if errors.Is(err, &store.Error{Code: store.CodeRecordTooLarge}) {
			if hi-lo > 1 {
				r.lowerCaps(recs[lo:hi])
				continue
			}
			r.drop(DropStore, 1)
			lo = hi
			continue
		}
		if !hold {
			r.drop(DropStore, int64(hi-lo))
			lo = hi
			continue
		}
		if !held {
			held = true
			r.mu.Lock()
			r.held++
			r.mu.Unlock()
		}
		if !sleep(ctx, r.lim.Retry) {
			return false
		}
	}
	return true
}
