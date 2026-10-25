package node

import (
	"context"
	"errors"
	"fmt"

	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/platform/store"
)

// Prune removes confirmed events from every open database in which a
// class holds more than the runtime target: PruneTarget of the class's
// quota, or, for adapter-evidence, of what a run may use, the quota less
// QuarantineRoom, since that is where runs stop (cannotKeep). It prunes
// as C5 startup step 6 does, in steps of PruneStepEvents per stream, each
// to a boundary computed from the persisted cursors, so nothing a required
// consumer has not confirmed, nothing in a best-effort replay window and
// nothing of a stream without consumers is removed. It is never a forced
// prune: a class whose events are not confirmed stays full (A6, V-S9:
// without it, a class could fill at runtime and stay full after every
// event was forwarded, since startup prunes only by total usage).
//
// Tick calls it, and cannotKeep before it holds a run.
func (r *Runtime) Prune(ctx context.Context) {
	r.pruneMu.Lock()
	defer r.pruneMu.Unlock()
	for _, d := range r.dbs {
		err := r.pruneDB(ctx, d)
		key := "prune " + string(d.spec.ID)
		if err != nil && !errors.Is(err, context.Canceled) {
			if r.quiet(key, true) {
				r.opt.Status.Alarm(d.spec.ID, c5.Alarm{Code: c5.AlarmPruneFailed, At: r.opt.Now(), Step: c5.StepPrune, Detail: "runtime prune: " + err.Error()})
			}
		} else {
			r.quiet(key, false)
		}
	}
}

// pruneTarget is the bytes class may hold before Prune removes its
// confirmed events.
func pruneTarget(q c5.Quota, target float64) float64 {
	limit := q.Bytes
	if q.Class == c5.ClassAdapterEvidence {
		limit -= QuarantineRoom
	}
	return target * float64(limit)
}

// pruneDB runs prune passes on d while a class is above its target and a
// pass still deletes something. The state read lock is held through each
// pass, so Tick cannot close the handle under it, and released between
// passes, so a Tick waiting to resume a database, and the readers queued
// behind it, wait for one pass at most (A3 on #135).
func (r *Runtime) pruneDB(ctx context.Context, d *database) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		r.state.RLock()
		db, mode := d.db, d.report.Mode
		more, err := false, error(nil)
		if db != nil && (mode == c5.ModeCollecting || mode == c5.ModeDrainOnly) {
			more, err = r.prunePass(ctx, d, db)
		}
		r.state.RUnlock()
		if err != nil || !more {
			return err
		}
	}
}

// prunePass is one pass of pruneDB: one step per stream, if a class is
// above its target. It reports whether another pass may be needed.
func (r *Runtime) prunePass(ctx context.Context, d *database, db *store.DB) (bool, error) {
	over := false
	for _, q := range d.spec.Quotas {
		used, err := db.ClassBytes(ctx, q.Class)
		if err != nil {
			return false, err
		}
		over = over || float64(used) > pruneTarget(q, d.policy.PruneTarget)
	}
	if !over {
		return false, nil
	}
	pass := 0
	for _, s := range d.spec.Streams {
		b, err := c5.ComputeBoundary(ctx, db, db, d.policy.Consumers, s.ID, s.Class, r.opt.Now())
		if errors.Is(err, &c5.Error{Code: c5.CodeNoConsumers}) {
			continue
		}
		if err != nil {
			return false, fmt.Errorf("stream %s: %w", s.ID, err)
		}
		n, err := db.PruneStep(ctx, b, d.policy.PruneStepEvents)
		if err != nil {
			return false, fmt.Errorf("stream %s: %w", s.ID, err)
		}
		pass += n
	}
	return pass > 0, nil
}

// quiet records whether the condition k holds and reports whether it has
// just started, so an alarm is raised once per condition.
func (r *Runtime) quiet(k string, holds bool) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.raised == nil {
		r.raised = map[string]bool{}
	}
	was := r.raised[k]
	r.raised[k] = holds
	return holds && !was
}
