package node

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"

	"otsec.local/otsec/contracts/audit"
	"otsec.local/otsec/contracts/authz"
	"otsec.local/otsec/contracts/config"
	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/platform/store"
)

// configChain is what the configuration-read writer needs from the audit
// chain, folded in chain order by the rules audit.VerifyConfig checks, so a
// record the writer builds from it verifies. It is folded from the start of
// the retained stream on first use, which is the rebuild at start, and
// after that from where it stopped, before each comparison.
type configChain struct {
	through c5.Seq // the last audit seq folded
	// pruned: records before first, the first one folded, were pruned, so
	// this fold cannot see what they set (restart).
	pruned bool
	first  c5.Seq
	// resetAt is the time of the collector.seq_reset that began this
	// epoch, "" in the first.
	resetAt string
	// runs are this epoch's allowed runs of each operation on each asset,
	// in chain order.
	runs map[assetOp][]chainRun
	// approvals are each asset's succeeded config.change_approved records
	// of this epoch whose decision is in it, in chain order.
	approvals map[string][]*audit.Record
	// decisions are this epoch's allowed, verified collector.request
	// records: the kind of each, by collector_seq.
	decisions map[uint64]authz.RequestKind
	assets    map[string]*chainAsset
	// parts are the outcomes of the node's config.change_approved and
	// config.baseline_acknowledged records, by the payload_sha256 of the
	// request each records, so the node acts on a request once.
	parts map[string]audit.Outcome
	// held finds what the store's holds keep of an asset's configuration
	// state from before first, for a pruned fold (D4-41).
	held func(ctx context.Context, assetID string, first c5.Seq) (heldConfig, error)
}

// heldConfig is an asset's configuration state as the store's holds keep
// it: the baseline held as baseline ("" when none is), the unapproved
// changes against it that are still open, the approved ones no return has
// ended, and the newest of both.
type heldConfig struct {
	baseline       string
	open, approved []c5.Seq
	last           *chainChange
}

type assetOp struct{ asset, op string }

type chainRun struct {
	seq uint64 // collector_seq
	at  string // the record's time
}

// chainAsset is one asset's configuration state.
type chainAsset struct {
	// baseline is the digest the last succeeded configuration-kind
	// acknowledgement set, "" when none is in the chain.
	baseline string
	// last is the newest change recorded against the baseline, until a
	// restore or an acknowledgement ends it.
	last *chainChange
	// alarmed: an unapproved change against the baseline is open, so no
	// approval silences a later one.
	alarmed bool
	// open are the audit seqs of the open unapproved changes, approved
	// those of the approved changes since the baseline, which a return
	// ends too (D4-43).
	open, approved []c5.Seq
	// held: the fold is pruned and no acknowledgement of the asset is in
	// it, so baseline, and the changes open against it before the fold,
	// are the ones the store holds (D4-41; C3 on #390, B3). Its changes in
	// the fold stay open too (C6 on #390), and reads compare against it.
	held bool
}

type chainChange struct {
	seq     c5.Seq
	changes string // changes_digest
}

func (s *Scheduler) configChain() *configChain {
	if s.chain == nil {
		s.chain = newChain(s.heldBaseline)
	}
	return s.chain
}

func newChain(held func(context.Context, string, c5.Seq) (heldConfig, error)) *configChain {
	return &configChain{runs: map[assetOp][]chainRun{}, approvals: map[string][]*audit.Record{},
		decisions: map[uint64]authz.RequestKind{}, assets: map[string]*chainAsset{}, parts: map[string]audit.Outcome{}, held: held}
}

// restart begins the fold again as a pruned one at first, the first
// retained record: what the records before it set is not known.
func (ch *configChain) restart(first c5.Seq) {
	*ch = *newChain(ch.held)
	ch.pruned, ch.first, ch.through = true, first, first-1
}

func (ch *configChain) asset(id string) *chainAsset {
	a := ch.assets[id]
	if a == nil {
		a = &chainAsset{}
		ch.assets[id] = a
	}
	return a
}

// sync folds the audit records committed since the last sync.
func (ch *configChain) sync(ctx context.Context, db *store.DB) error {
	if db == nil {
		return fmt.Errorf("audit database not open")
	}
	for {
		got, err := db.Read(ctx, AuditStream, ch.through, 500)
		if err != nil {
			return err
		}
		if len(got) == 0 {
			return nil
		}
		for _, st := range got {
			if st.Key.Seq != ch.through+1 {
				// Records were pruned before they were folded, at the first
				// sync or between two (C3 on #390): the fold starts again
				// from the first one retained.
				ch.restart(st.Key.Seq)
			}
			if folded(st.Event) {
				rec, err := audit.ParseRecord(st.Event)
				if err != nil {
					return badRecord{st.Key.Seq, err}
				}
				if rec.Target != nil && (rec.Action == audit.ActionConfigChangeDetected || rec.Action == audit.ActionConfigBaselineRestored) {
					if err := ch.findBaseline(ctx, ch.asset(rec.Target.AssetID), rec.Target.AssetID); err != nil && rec.Config != nil {
						// The store cannot be read: the record's own
						// baseline, which the node wrote it against, keeps
						// the change open.
						a := ch.asset(rec.Target.AssetID)
						a.baseline, a.held = rec.Config.BaselineDigest, true
					}
				}
				ch.apply(st.Key.Seq, rec)
			}
			ch.through = st.Key.Seq
		}
	}
}

// folded reports whether a record's bytes may hold an action the fold
// applies. One with an escape is parsed too, as its action may be spelt
// with one (C3 on #384).
func folded(event []byte) bool {
	return bytes.Contains(event, []byte(`"config.`)) || bytes.Contains(event, []byte(`"collector.`)) || bytes.Contains(event, []byte(`\u`))
}

func (ch *configChain) apply(seq c5.Seq, r *audit.Record) {
	c := r.Config
	switch {
	case r.Action == audit.ActionCollectorSeqReset:
		ch.resetAt = r.Time.UTC
		ch.runs, ch.approvals, ch.decisions = map[assetOp][]chainRun{}, map[string][]*audit.Record{}, map[uint64]authz.RequestKind{}
	case r.Action == audit.ActionCollectorRequest && r.Outcome == audit.OutcomeAllowed && r.Verified != nil:
		ch.decisions[r.CollectorSeq] = r.Verified.Kind
	case r.Action == audit.ActionCollectorRequest && r.Outcome == audit.OutcomeAllowed && r.Verified == nil && r.OperationID != "" && r.Target != nil:
		k := assetOp{r.Target.AssetID, r.OperationID}
		ch.runs[k] = append(ch.runs[k], chainRun{r.CollectorSeq, r.Time.UTC})
	case c == nil || r.Target == nil:
	case (r.Action == audit.ActionConfigChangeApproved || r.Action == audit.ActionConfigBaselineAcknowledge) && r.Outcome == audit.OutcomeDenied:
		ch.parts[c.PayloadSHA256] = r.Outcome
	case r.Action == audit.ActionConfigChangeApproved && r.Outcome == audit.OutcomeSucceeded:
		ch.parts[c.PayloadSHA256] = r.Outcome
		// Only with its decision, as audit.VerifyConfig checks (C3 on #390):
		// an approval whose decision is not in the epoch silences nothing.
		if ch.decisions[c.DecisionSeq] == authz.KindNodeChangeApproval {
			ch.approvals[r.Target.AssetID] = append(ch.approvals[r.Target.AssetID], r)
		}
	case r.Action == audit.ActionConfigBaselineAcknowledge && r.Outcome == audit.OutcomeSucceeded && c.Kind != authz.BaselineConfiguration:
		ch.parts[c.PayloadSHA256] = r.Outcome
	case r.Action == audit.ActionConfigBaselineAcknowledge && r.Outcome == audit.OutcomeSucceeded:
		ch.parts[c.PayloadSHA256] = r.Outcome
		// D4-18: the acknowledgement ends every open change of the asset.
		*ch.asset(r.Target.AssetID) = chainAsset{baseline: c.BaselineDigest}
	case r.Action == audit.ActionConfigChangeDetected:
		a := ch.asset(r.Target.AssetID)
		if c.BaselineDigest != a.baseline {
			return
		}
		a.last = &chainChange{seq, c.ChangesDigest}
		if c.ApprovalSeq == 0 {
			a.alarmed, a.open = true, append(a.open, seq)
		} else {
			a.approved = append(a.approved, seq)
		}
	case r.Action == audit.ActionConfigBaselineRestored:
		a := ch.asset(r.Target.AssetID)
		if c.BaselineDigest == a.baseline {
			a.last, a.alarmed, a.open, a.approved = nil, false, nil, nil
		}
	}
}

// findBaseline sets the asset's state, in a pruned fold with no
// acknowledgement of it, to the one the store holds (D4-41): its baseline,
// and the unapproved changes still open against it, so an approval made
// after their alarm silences nothing (C3 on #390, B3). It looks once; a
// later acknowledgement in the fold replaces it.
func (ch *configChain) findBaseline(ctx context.Context, a *chainAsset, assetID string) error {
	if !ch.pruned || a.baseline != "" || a.held || ch.held == nil {
		return nil
	}
	h, err := ch.held(ctx, assetID, ch.first)
	if err != nil {
		return err
	}
	a.baseline, a.held, a.open, a.approved, a.last, a.alarmed = h.baseline, true, h.open, h.approved, h.last, len(h.open) > 0
	return nil
}

// heldBaseline is the asset's configuration state from before first as the
// store holds it (D4-41). The baseline is, of the records held as
// baseline, the one whose Ref is newest and whose document is a C9
// snapshot (the kind is the document's, as an event baseline is held the
// same way). The open changes are the Refs of the records held as
// unapproved-difference between that acknowledgement and first, and the
// approved ones those held as approved-difference: a restore moves both to
// restored-difference when it is written (D4-43), and one before the
// acknowledgement was a change against an earlier baseline. The newest of
// both is the last change; its changes digest is its held difference's,
// or "" when that was not stored, so a read of the same change is recorded
// as a new one, which an open alarm keeps unapproved.
func (s *Scheduler) heldBaseline(ctx context.Context, assetID string, first c5.Seq) (heldConfig, error) {
	var out heldConfig
	stream := ConfigStream(assetID)
	db := s.rt.Store(stream)
	if db == nil {
		return out, errors.New("configuration database not open")
	}
	held, err := db.Held(ctx, stream)
	if err != nil {
		return out, err
	}
	doc := func(seq c5.Seq) ([]byte, error) {
		got, err := db.Read(ctx, stream, seq-1, 1)
		if err != nil || len(got) != 1 || got[0].Key.Seq != seq {
			return nil, err
		}
		return got[0].Event, nil
	}
	slices.SortFunc(held, func(a, b c5.HeldRecord) int { return cmp.Compare(b.Reason.Ref.Seq, a.Reason.Ref.Seq) })
	var acked c5.Seq
	for _, h := range held {
		if h.Reason.Code != c5.HoldBaseline {
			continue
		}
		b, err := doc(h.Seq)
		if err != nil {
			return out, err
		}
		if _, err := config.DecodeSnapshot(b); b != nil && err == nil {
			out.baseline, acked = config.Digest(b), h.Reason.Ref.Seq
			break
		}
	}
	if out.baseline == "" {
		return out, nil
	}
	for _, h := range held {
		ref := h.Reason.Ref.Seq
		list := &out.open
		switch {
		case ref <= acked || ref >= first:
			continue
		case h.Reason.Code == c5.HoldApprovedDifference:
			list = &out.approved
		case h.Reason.Code != c5.HoldUnapprovedDifference:
			continue
		}
		if !slices.Contains(*list, ref) {
			*list = append(*list, ref)
		}
		if out.last == nil {
			out.last = &chainChange{seq: ref}
		}
		if ref == out.last.seq && out.last.changes == "" {
			b, err := doc(h.Seq)
			if err != nil {
				return out, err
			}
			if d, err := config.DecodeDifference(b); b != nil && err == nil {
				out.last.changes = d.ChangesDigest()
			}
		}
	}
	slices.Reverse(out.open)
	slices.Reverse(out.approved)
	return out, nil
}

// hasRun reports whether the decision readSeq is an allowed run of op on the
// asset in this epoch.
func (ch *configChain) hasRun(assetID, op string, readSeq uint64) bool {
	for _, r := range ch.runs[assetOp{assetID, op}] {
		if r.seq == readSeq {
			return true
		}
	}
	return false
}

// unchanged is what bounds a change found by the read readSeq: the asset's
// last run of op before it in this epoch, or, with none, no seq and the
// time of the collector reset that began the epoch. ok is false when
// neither is in the chain.
func (ch *configChain) unchanged(assetID, op string, readSeq uint64) (seq uint64, at string, ok bool) {
	for _, r := range ch.runs[assetOp{assetID, op}] {
		if r.seq < readSeq {
			seq, at = r.seq, r.at
		}
	}
	switch {
	case seq != 0:
		return seq, at, true
	case ch.resetAt != "":
		return 0, ch.resetAt, true
	}
	return 0, "", false
}

// raiseOpenChanges raises AlarmUnapprovedChange at start for each change the
// chain shows still open, on a node whose schedule reads configuration,
// including one whose register copy is refused, so its reads are held (C6
// on #390). A chain that cannot be read now is folded at the first read
// instead, and its open changes are raised as they are found again.
func (s *Scheduler) raiseOpenChanges(ctx context.Context) {
	if !slices.ContainsFunc(s.rt.cfg.Schedule, Collection.ReadsConfiguration) {
		return
	}
	ch := s.configChain()
	if ch.sync(ctx, s.rt.Store(AuditStream)) != nil {
		return
	}
	for _, col := range s.rt.cfg.Schedule {
		if col.ReadsConfiguration() {
			// A pruned fold may hold no record of the asset; its open
			// changes from before the fold are in the store's holds. One
			// that cannot be read now is found at the first read.
			_ = ch.findBaseline(ctx, ch.asset(col.AssetID), col.AssetID)
		}
	}
	for id, a := range ch.assets {
		for _, ref := range a.open {
			s.raiseOnceKey(fmt.Sprintf("unapproved %s %d", id, ref), id, AlarmUnapprovedChange,
				fmt.Sprintf("the configuration differs from baseline %s and no approval covers it: audit record %d", a.baseline, ref))
		}
	}
}
