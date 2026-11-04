package node

import (
	"context"
	"fmt"
	"slices"
	"strings"

	c5 "otsec.local/otsec/contracts/store"
)

// HoldsConsumer keeps the audit stream from being pruned past a C8 record
// whose configuration holds are not taken (D4-41). Without it, a prune could
// remove an acknowledgement whose baseline hold is not yet taken, and the
// hold would then be lost: the live path takes it right after the Receipt,
// but after a crash between the two, the next start prunes (C5 start-up
// step 6, when New opens the audit database) before reconcileHolds runs.
//
// Its cursor is the last audit seq through which every hold the fold wants
// is taken. advanceHolds moves it at start, after the reconcile, and before
// each runtime prune of the audit database, so one check covers every path
// that takes a hold: an acknowledgement, the writer's differences and a
// restore (D4-41, as amended by C1 on #408). The start-up prune runs
// before the reconcile and before any check of this run, so it is bounded
// by the cursor the last check persisted, in an earlier run: the cursor is
// only ever saved by advanceHolds, never ahead of a hold not taken.
// pruneConsumers adds it beside SuspensionConsumer.
const HoldsConsumer c5.ConsumerID = "node-holds"

// AlarmHoldsNotTaken: a hold the C8 records want is not taken, or could not
// be checked, so the audit stream is pruned no further than HoldsConsumer's
// cursor: until the next start's reconcile takes it, or, for a record that
// is not stored (AlarmBaselineNotStored), until it is accounted for, as no
// reconcile can hold it.
const AlarmHoldsNotTaken = "config-holds-not-taken"

// holdFaults are test seams (C6 on D4-41), nil in a node: ack fails the
// holds taken after an acknowledgement's receipt, reconcile fails each hold
// the start-up reconcile takes, and restore fails the re-code a return to
// the baseline makes.
var holdFaults struct{ ack, reconcile, restore func() error }

func holdFault(f func() error) error {
	if f == nil {
		return nil
	}
	return f()
}

// advanceHolds moves HoldsConsumer's cursor to the audit stream's last
// record when every hold the fold of the C8 records wants is taken in every
// configuration stream. Otherwise it leaves the cursor, which only keeps
// more of the stream, and raises AlarmHoldsNotTaken once. On a pruned view
// (foldView) a hold with another reason counts as taken unless the fold
// wants it as the baseline or as restored-difference, as reconcileHolds
// corrects no other reason there (prunedReplace).
func (r *Runtime) advanceHolds(ctx context.Context) {
	a := r.find(AuditDB)
	if a == nil || !slices.ContainsFunc(a.policy.Consumers, func(c c5.Consumer) bool { return c.ID == HoldsConsumer }) {
		return
	}
	behind := func(why string) {
		if r.quiet("holds cursor", true) {
			r.opt.Status.Raise("", AlarmHoldsNotTaken, "the audit stream is not pruned past the holds cursor: "+why)
		}
	}
	adb, _, _ := r.view(a)
	if adb == nil {
		behind("the audit database is not open")
		return
	}
	// Read first: a record committed after it is not passed.
	through, err := adb.LastCommitted(ctx, AuditStream)
	if err != nil {
		behind(err.Error())
		return
	}
	if d := r.find(ConfigDB); d != nil {
		cdb, _, mode := r.view(d)
		if cdb == nil {
			behind("the configuration database is " + string(mode))
			return
		}
		assets := make([]string, 0, len(d.spec.Streams))
		for _, spec := range d.spec.Streams {
			assets = append(assets, strings.TrimPrefix(string(spec.ID), "config/"))
		}
		folded, pruned, err := foldView(ctx, adb, cdb, assets)
		if err != nil {
			behind(err.Error())
			return
		}
		for _, spec := range d.spec.Streams {
			p, err := r.planStream(ctx, cdb, spec.ID, folded[strings.TrimPrefix(string(spec.ID), "config/")])
			if err != nil {
				behind(fmt.Sprintf("%s: %v", spec.ID, err))
				return
			}
			replace := len(p.replace)
			if pruned {
				replace = len(prunedReplace(p.replace))
			}
			if len(p.missing) > 0 {
				// No reconcile takes a hold on a record not stored: the
				// stream is kept until the record is accounted for.
				behind(fmt.Sprintf("%s: %d records the C8 records want held are not stored, so no reconcile can take their holds; see %s", spec.ID, len(p.missing), AlarmBaselineNotStored))
				return
			}
			if len(p.add)+replace > 0 {
				behind(fmt.Sprintf("%s: %d holds not taken, %d with the wrong reason, until the next start's reconcile takes them", spec.ID, len(p.add), replace))
				return
			}
		}
	}
	if err := adb.SaveCursor(ctx, c5.Cursor{Consumer: HoldsConsumer, Stream: AuditStream, Through: through}); err != nil {
		behind("cursor not saved: " + err.Error())
		return
	}
	r.quiet("holds cursor", false)
}
