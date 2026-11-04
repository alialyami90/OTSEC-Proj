package node

import (
	"bytes"
	"context"
	"fmt"
	"slices"

	"otsec.local/otsec/contracts/audit"
	"otsec.local/otsec/contracts/authz"
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
	// pruned: the stream began past seq 1 when it was first folded, at
	// first. Records before first may set state this fold cannot see.
	pruned bool
	first  c5.Seq
	// resetAt is the time of the collector.seq_reset that began this
	// epoch, "" in the first.
	resetAt string
	// runs are this epoch's allowed runs of each operation on each asset,
	// in chain order.
	runs map[assetOp][]chainRun
	// approvals are each asset's succeeded config.change_approved records
	// of this epoch, in chain order.
	approvals map[string][]*audit.Record
	assets    map[string]*chainAsset
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
	// open are the audit seqs of the open unapproved changes.
	open []c5.Seq
	// inferred: the stream was pruned past the acknowledgement, and baseline
	// is the one the first retained change or restore of the asset names.
	// Its changes are still open and raised (C6 on #390), and a read is not
	// compared against it until D4-41's rule is built.
	inferred bool
}

type chainChange struct {
	seq     c5.Seq
	changes string // changes_digest
}

func (s *Scheduler) configChain() *configChain {
	if s.chain == nil {
		s.chain = &configChain{runs: map[assetOp][]chainRun{}, approvals: map[string][]*audit.Record{}, assets: map[string]*chainAsset{}}
	}
	return s.chain
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
	if ch.through == 0 {
		first, err := db.FirstRetained(ctx, AuditStream)
		if err != nil {
			return err
		}
		if first > 1 {
			ch.pruned, ch.first, ch.through = true, first, first-1
		}
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
			if folded(st.Event) {
				rec, err := audit.ParseRecord(st.Event)
				if err != nil {
					return badRecord{st.Key.Seq, err}
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
		ch.runs, ch.approvals = map[assetOp][]chainRun{}, map[string][]*audit.Record{}
	case r.Action == audit.ActionCollectorRequest && r.Outcome == audit.OutcomeAllowed && r.Verified == nil && r.OperationID != "" && r.Target != nil:
		k := assetOp{r.Target.AssetID, r.OperationID}
		ch.runs[k] = append(ch.runs[k], chainRun{r.CollectorSeq, r.Time.UTC})
	case c == nil || r.Target == nil:
	case r.Action == audit.ActionConfigChangeApproved && r.Outcome == audit.OutcomeSucceeded:
		ch.approvals[r.Target.AssetID] = append(ch.approvals[r.Target.AssetID], r)
	case r.Action == audit.ActionConfigBaselineAcknowledge && r.Outcome == audit.OutcomeSucceeded && c.Kind == authz.BaselineConfiguration:
		// D4-18: the acknowledgement ends every open change of the asset.
		*ch.asset(r.Target.AssetID) = chainAsset{baseline: c.BaselineDigest}
	case r.Action == audit.ActionConfigChangeDetected:
		a := ch.asset(r.Target.AssetID)
		ch.infer(a, c.BaselineDigest)
		if c.BaselineDigest != a.baseline {
			return
		}
		a.last = &chainChange{seq, c.ChangesDigest}
		if c.ApprovalSeq == 0 {
			a.alarmed, a.open = true, append(a.open, seq)
		}
	case r.Action == audit.ActionConfigBaselineRestored:
		a := ch.asset(r.Target.AssetID)
		ch.infer(a, c.BaselineDigest)
		if c.BaselineDigest == a.baseline {
			a.last, a.alarmed, a.open = nil, false, nil
		}
	}
}

// infer takes digest as the asset's baseline in a pruned stream with no
// acknowledgement of the asset before it: the node writes a change or a
// restore only against its acknowledged baseline, and a later baseline
// needs an acknowledgement, which would be retained.
func (ch *configChain) infer(a *chainAsset, digest string) {
	if ch.pruned && a.baseline == "" {
		a.baseline, a.inferred = digest, true
	}
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
	for id, a := range ch.assets {
		for _, ref := range a.open {
			s.raiseOnceKey(fmt.Sprintf("unapproved %s %d", id, ref), id, AlarmUnapprovedChange,
				fmt.Sprintf("the configuration differs from baseline %s and no approval covers it: audit record %d", a.baseline, ref))
		}
	}
}
