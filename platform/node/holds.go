package node

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"

	"otsec.local/otsec/contracts/audit"
	"otsec.local/otsec/contracts/authz"
	"otsec.local/otsec/contracts/config"
	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/platform/store"
)

// The holds of the configuration class are derived state (C5 0.4): the C8
// records are the authority, and the node rebuilds the holds it should have
// from them at every start, then corrects the table. Nothing here decides
// "this is the baseline" from the table itself.
//
// What C8 justifies, per asset:
//
//   - the baseline of each kind that the last succeeded
//     config.baseline_acknowledged set: the stored record whose bytes have
//     its baseline_digest (a C9 snapshot for kind configuration, a C10
//     baseline for kind event), held as HoldBaseline, Ref that record;
//   - each config.change_detected that no approval covered (warning
//     unapproved_change), until a config.baseline_restored for its baseline
//     or a succeeded acknowledgement of a configuration baseline (D4-18)
//     ends it: the snapshot and the difference it names, held as
//     HoldUnapprovedDifference, Ref that record. An approval accepted after
//     the alarm does not end it (audit.VerifyConfig). An acknowledgement
//     ends the alarm and not the hold (D4-18): the snapshot and difference
//     stay held as HoldAcknowledgedDifference, same Ref, until a retention
//     rule for configuration evidence says otherwise. A return to the
//     baseline ends the alarm the same way, under HoldRestoredDifference
//     (D4-19), and moves the approved changes since the baseline's
//     acknowledgement there too (D4-43), so a pruned fold can tell a
//     change that is still the last one from one a return ended.
//
// A record is held for one reason. When one is wanted for two, the baseline
// wins, as the acknowledgement that made it the baseline is the later word.

// AlarmBaselineNotStored is raised for an asset when C8 says a record should
// be held and the node cannot find it: the acknowledged baseline, or the
// snapshot or difference of an open alarm, is not in the asset's
// configuration stream. Nothing can hold what is not there, so the finding
// is the alarm. Level 0, named by asset.
const AlarmBaselineNotStored = "config-baseline-not-stored"

// auditRec is a C8 record with its seq in the node's audit stream.
type auditRec struct {
	seq c5.Seq
	rec *audit.Record
}

// wantHold is one hold the C8 records justify, before the record it holds
// is located.
type wantHold struct {
	digest string
	code   c5.HoldCode
	ref    c5.Seq // seq in the audit stream
	why    string // for the alarm text
}

type ackedBaseline struct {
	digest string
	ref    c5.Seq
}

type openDifference struct {
	baseline, snapshot, difference string
	ref                            c5.Seq
}

// assetHolds is what the C8 records say about one asset.
type assetHolds struct {
	baseline map[authz.BaselineKind]ackedBaseline
	open     []openDifference
	// ended are the changes whose alarm a configuration acknowledgement
	// ended (D4-18): their snapshot and difference stay held as evidence.
	ended []openDifference
	// returned are the changes whose alarm a return to the baseline ended
	// (D4-19): held the same way, under their own code.
	returned []openDifference
	// approved are the changes an approval covered (C5 0.7). Those from
	// since on are against the current configuration baseline, until a
	// return moves them to returned (D4-43).
	approved []openDifference
	since    int
	// superseded are the baselines a newer acknowledgement of the same kind
	// replaced, with that acknowledgement's seq as ref (C5 0.7).
	superseded []ackedBaseline
}

// foldHolds reads the configuration records of the node's audit stream, in
// chain order, into what each asset should hold. Records of other actions
// are ignored.
func foldHolds(recs []auditRec) map[string]*assetHolds {
	out := map[string]*assetHolds{}
	of := func(r *audit.Record) *assetHolds {
		a := out[r.Target.AssetID]
		if a == nil {
			a = &assetHolds{baseline: map[authz.BaselineKind]ackedBaseline{}}
			out[r.Target.AssetID] = a
		}
		return a
	}
	for _, s := range recs {
		r := s.rec
		if r.Config == nil || r.Target == nil {
			continue
		}
		c := r.Config
		switch r.Action {
		case audit.ActionConfigBaselineAcknowledge:
			if r.Outcome != audit.OutcomeSucceeded {
				continue
			}
			a := of(r)
			if prev, ok := a.baseline[c.Kind]; ok && prev.digest != c.BaselineDigest {
				a.superseded = append(a.superseded, ackedBaseline{prev.digest, s.seq})
			}
			a.baseline[c.Kind] = ackedBaseline{c.BaselineDigest, s.seq}
			if c.Kind == authz.BaselineConfiguration {
				a.ended = append(a.ended, a.open...) // D4-18: the alarm ends, the evidence stays held
				a.open, a.since = nil, len(a.approved)
			}
		case audit.ActionConfigChangeDetected:
			a := of(r)
			b, ok := a.baseline[authz.BaselineConfiguration]
			if !ok || b.digest != c.BaselineDigest {
				continue
			}
			o := openDifference{c.BaselineDigest, c.SnapshotDigest, c.DifferenceDigest, s.seq}
			if c.ApprovalSeq != 0 {
				a.approved = append(a.approved, o)
			} else {
				a.open = append(a.open, o)
			}
		case audit.ActionConfigBaselineRestored:
			a := of(r)
			for _, o := range a.open {
				if o.baseline == c.BaselineDigest {
					a.returned = append(a.returned, o)
				}
			}
			a.open = slices.DeleteFunc(a.open, func(o openDifference) bool { return o.baseline == c.BaselineDigest })
			if b, ok := a.baseline[authz.BaselineConfiguration]; ok && b.digest == c.BaselineDigest {
				a.returned = append(a.returned, a.approved[a.since:]...)
				a.approved = a.approved[:a.since]
			}
		}
	}
	return out
}

// wants lists an asset's holds: the baselines, then each change's
// snapshot and difference, then the superseded baselines. A digest wanted
// for two reasons is wanted once, for the reason first in c5.HoldPriority
// (C5 0.7), keeping the place of its first mention.
func (a *assetHolds) wants() []wantHold {
	out, _ := a.wantsAll()
	return out
}

// wantsAll is wants, and for each digest the other reasons it is wanted
// for, in c5.HoldPriority order. A stream may store a document twice, as a
// read that repeats an earlier document is stored with its own transcript,
// and the writer holds the record it stored, so each copy can hold one of
// the reasons (planHolds).
func (a *assetHolds) wantsAll() ([]wantHold, map[string][]wantHold) {
	var out []wantHold
	at := map[string]int{}
	also := map[string][]wantHold{}
	rank := func(c c5.HoldCode) int { return slices.Index(c5.HoldPriority(), c) }
	add := func(w wantHold) {
		i, ok := at[w.digest]
		switch {
		case !ok:
			at[w.digest] = len(out)
			out = append(out, w)
		case rank(w.code) < rank(out[i].code):
			also[w.digest] = append(also[w.digest], out[i])
			out[i] = w
		default:
			also[w.digest] = append(also[w.digest], w)
		}
	}
	for _, k := range []authz.BaselineKind{authz.BaselineConfiguration, authz.BaselineEvent} {
		if b, ok := a.baseline[k]; ok {
			add(wantHold{b.digest, c5.HoldBaseline, b.ref, fmt.Sprintf("the %s baseline acknowledged in audit record %d", k, b.ref)})
		}
	}
	diff := func(os []openDifference, code c5.HoldCode, why string) {
		for _, o := range os {
			add(wantHold{o.snapshot, code, o.ref, fmt.Sprintf("the snapshot of the change detected in audit record %d%s", o.ref, why)})
			if o.difference != "" { // "" when it was too large to store (C8 0.10, D4-42)
				add(wantHold{o.difference, code, o.ref, fmt.Sprintf("the difference of the change detected in audit record %d%s", o.ref, why)})
			}
		}
	}
	diff(a.open, c5.HoldUnapprovedDifference, "")
	diff(a.approved, c5.HoldApprovedDifference, ", which an approval covered")
	diff(a.ended, c5.HoldAcknowledgedDifference, ", its alarm ended by an acknowledgement")
	diff(a.returned, c5.HoldRestoredDifference, ", its alarm ended by a return to the baseline")
	for _, b := range a.superseded {
		add(wantHold{b.digest, c5.HoldSupersededBaseline, b.ref, fmt.Sprintf("a baseline superseded by the acknowledgement in audit record %d", b.ref)})
	}
	for _, ws := range also {
		slices.SortStableFunc(ws, func(x, y wantHold) int { return rank(x.code) - rank(y.code) })
	}
	return out, also
}

// holdPlan is what to change in one stream so that its holds are the ones
// wanted. A replaced hold keeps its record and changes its reason.
type holdPlan struct {
	add, replace []planned
	release      []c5.HeldRecord
	missing      []wantHold
	// unknown are holds of a code this node does not know (a later C5):
	// kept as they are, never replaced or released.
	unknown []c5.HeldRecord
}

func knownCode(c c5.HoldCode) bool { return slices.Contains(c5.HoldPriority(), c) }

type planned struct {
	seq c5.Seq
	w   wantHold
}

// planHolds compares what is wanted, located by digest in found (every
// record with the digest, in stream order), with what the stream holds. A
// digest wanted for one reason, w, and for others, also[w.digest], is
// held on as many of its records as the writer held: a record already held
// for one of the reasons keeps it, so a hold on a later copy of a document
// is never moved to its first copy. Each reason, in priority order, takes
// the record held for it, else a record held for no reason of the digest;
// the first reason, when neither is there, takes the first record not
// taken, as one record held for the reason first in priority is all C8
// needs.
func planHolds(node c5.NodeID, wants []wantHold, also map[string][]wantHold, found map[string][]c5.Seq, have []c5.HeldRecord) holdPlan {
	var p holdPlan
	held := map[c5.Seq]c5.HeldRecord{}
	unknown := map[c5.Seq]bool{}
	for _, h := range have {
		if !knownCode(h.Reason.Code) {
			p.unknown = append(p.unknown, h)
			unknown[h.Seq] = true
			continue
		}
		held[h.Seq] = h
	}
	want := map[c5.Seq]wantHold{}
	for _, w := range wants {
		cands := found[w.digest]
		if len(cands) == 0 {
			p.missing = append(p.missing, w)
			continue
		}
		ws := append([]wantHold{w}, also[w.digest]...)
		free := func(s c5.Seq) bool { _, taken := want[s]; return !taken && !unknown[s] }
		for i, x := range ws {
			pick := slices.IndexFunc(cands, func(s c5.Seq) bool {
				h, ok := held[s]
				return free(s) && ok && h.Reason == reasonOf(node, x)
			})
			if pick < 0 {
				pick = slices.IndexFunc(cands, func(s c5.Seq) bool {
					h, ok := held[s]
					return free(s) && ok && !slices.ContainsFunc(ws[i+1:], func(y wantHold) bool { return h.Reason == reasonOf(node, y) })
				})
			}
			if pick < 0 && i == 0 {
				pick = slices.IndexFunc(cands, free)
			}
			if pick >= 0 {
				want[cands[pick]] = x
			}
		}
	}
	seqs := make([]c5.Seq, 0, len(want))
	for s := range want {
		seqs = append(seqs, s)
	}
	slices.Sort(seqs)
	for _, s := range seqs {
		w := want[s]
		h, ok := held[s]
		switch {
		case !ok:
			p.add = append(p.add, planned{s, w})
		case h.Reason != reasonOf(node, w):
			p.replace = append(p.replace, planned{s, w})
		}
	}
	for _, h := range have {
		if !knownCode(h.Reason.Code) {
			continue
		}
		if _, ok := want[h.Seq]; !ok {
			p.release = append(p.release, h)
		}
	}
	return p
}

func reasonOf(node c5.NodeID, w wantHold) c5.HoldReason {
	return c5.HoldReason{Code: w.code, Ref: c5.Key{NodeID: node, Stream: AuditStream, Seq: w.ref}}
}

// locate finds, in a configuration stream, the first stored record whose
// bytes have each digest in want.
func locate(ctx context.Context, db *store.DB, stream c5.StreamID, want map[string]bool) (map[string]c5.Seq, error) {
	all, err := locateAll(ctx, db, stream, want)
	if err != nil {
		return nil, err
	}
	found := map[string]c5.Seq{}
	for d, seqs := range all {
		found[d] = seqs[0]
	}
	return found, nil
}

// locateAll finds, in a configuration stream, every stored record whose
// bytes have a digest in want, in stream order. It reads the whole retained
// stream, a page at a time: records are at most ConfigRecordBytes.
func locateAll(ctx context.Context, db *store.DB, stream c5.StreamID, want map[string]bool) (map[string][]c5.Seq, error) {
	found := map[string][]c5.Seq{}
	if len(want) == 0 {
		return found, nil
	}
	var after c5.Seq
	for {
		got, err := db.Read(ctx, stream, after, 4)
		if err != nil {
			return nil, err
		}
		if len(got) == 0 {
			return found, nil
		}
		for _, st := range got {
			if d := config.Digest(st.Event); want[d] {
				found[d] = append(found[d], st.Key.Seq)
			}
			after = st.Key.Seq
		}
	}
}

// configAuditRecords reads the configuration records of the audit stream,
// in chain order. A line that cannot be parsed is an error: the chain is
// the authority, and reconcile does not guess past a record it cannot read.
func configAuditRecords(ctx context.Context, db *store.DB) ([]auditRec, error) {
	last, err := db.LastCommitted(ctx, AuditStream)
	if err != nil {
		return nil, err
	}
	var (
		out   []auditRec
		after c5.Seq
	)
	for after < last {
		got, err := db.Read(ctx, AuditStream, after, 500)
		if err != nil {
			return nil, err
		}
		if len(got) == 0 {
			return nil, fmt.Errorf("audit stream ends at %d, before its last committed seq %d", after, last)
		}
		for _, st := range got {
			after = st.Key.Seq
			if !bytes.Contains(st.Event, []byte(`"config.`)) {
				continue
			}
			rec, err := audit.ParseRecord(st.Event)
			if err != nil {
				return nil, badRecord{st.Key.Seq, err}
			}
			out = append(out, auditRec{st.Key.Seq, rec})
		}
	}
	return out, nil
}

// auditPruned reports whether the audit stream no longer begins at its first
// record: some of it has been pruned, so a hold's record may be gone.
func auditPruned(ctx context.Context, db *store.DB) (bool, error) {
	last, err := db.LastCommitted(ctx, AuditStream)
	if err != nil || last == 0 {
		return false, err
	}
	first, err := db.FirstRetained(ctx, AuditStream)
	if err != nil {
		return false, err
	}
	return first != 1, nil
}

// reconcileHolds rebuilds the holds the C8 records justify and corrects the
// configuration database to match, at start. It adds what is missing and
// replaces a wrong reason before it releases anything, so a crash part-way
// leaves more held, not less. Each correction raises
// AlarmHoldsReconciled naming the stream and the record: it is a crash
// between a C8 record and its hold, or tampering. It never releases a hold
// to make room.
//
// A failure to read the audit stream or the configuration database changes
// nothing and raises an alarm: holds are kept as they are.
func (r *Runtime) reconcileHolds(ctx context.Context) {
	d := r.find(ConfigDB)
	if d == nil {
		return
	}
	cdb, _, mode := r.view(d)
	adb, _, _ := r.view(r.find(AuditDB))
	fail := func(err error) {
		r.opt.Status.Alarm(ConfigDB, c5.Alarm{Code: c5.AlarmHoldsReconciled, At: r.opt.Now(),
			Detail: "holds not reconciled, left as they are: " + err.Error()})
	}
	if cdb == nil || adb == nil {
		fail(fmt.Errorf("configuration database %s, audit database open: %t", mode, adb != nil))
		return
	}
	recs, err := configAuditRecords(ctx, adb)
	if err != nil {
		fail(err)
		return
	}
	// A pruned audit stream no longer shows the acknowledgements and
	// detections the holds came from, so what is wanted is only what the
	// retained records show. The reconcile then adds what they justify and
	// corrects and releases nothing but a baseline's reason
	// (prunedReplace): a hold is never taken away on a view that begins
	// after the record that justified it (as the suspension rebuild refuses
	// a pruned prefix).
	pruned, err := auditPruned(ctx, adb)
	if err != nil {
		fail(err)
		return
	}
	if pruned {
		r.opt.Status.Alarm(ConfigDB, c5.Alarm{Code: c5.AlarmHoldsReconciled, At: r.opt.Now(),
			Detail: "the audit stream has been pruned, so the C8 records for some holds may be gone: holds are added from the records that remain and none is corrected or released"})
	}
	folded := foldHolds(recs)
	var added, replaced, released, failed int
	for _, spec := range d.spec.Streams {
		assetID := strings.TrimPrefix(string(spec.ID), "config/")
		p, err := r.planStream(ctx, cdb, spec.ID, folded[assetID])
		if err != nil {
			fail(err)
			continue
		}
		for _, w := range p.missing {
			r.opt.Status.Raise(assetID, AlarmBaselineNotStored, fmt.Sprintf("%s (%s) is not in stream %s, so nothing holds it; the stream's other holds are kept", w.why, w.digest, spec.ID))
		}
		for _, h := range p.unknown {
			r.opt.Status.Alarm(ConfigDB, c5.Alarm{Code: c5.AlarmHoldsReconciled, At: r.opt.Now(), Stream: spec.ID,
				Detail: fmt.Sprintf("%s seq %d: hold code %q is not known to this node (C5 0.7); kept as it is", spec.ID, h.Seq, h.Reason.Code)})
		}
		apply := func(ps []planned, verb string, n *int) {
			for _, pl := range ps {
				err := holdFault(holdFaults.reconcile)
				if err == nil {
					err = cdb.Hold(ctx, c5.Hold{Stream: spec.ID, Seq: pl.seq, Reason: reasonOf(r.cfg.NodeID, pl.w)})
				}
				r.reconciled(spec.ID, pl.seq, verb+" as "+string(pl.w.code)+": "+pl.w.why, err, n, &failed)
			}
		}
		apply(p.add, "held", &added)
		if pruned {
			apply(prunedReplace(p.replace), "reason corrected to", &replaced)
			continue
		}
		apply(p.replace, "reason corrected to", &replaced)
		if len(p.missing) > 0 {
			// Something C8 wants held is not there: the holds the node has
			// are the evidence it has left, so none is released.
			continue
		}
		sort.Slice(p.release, func(i, j int) bool { return p.release[i].Seq < p.release[j].Seq })
		for _, h := range p.release {
			err := cdb.Release(ctx, spec.ID, h.Seq)
			r.reconciled(spec.ID, h.Seq, fmt.Sprintf("released: no C8 record justifies its %s hold (audit record %d)", h.Reason.Code, h.Reason.Ref.Seq), err, &released, &failed)
		}
	}
	if added+replaced+released+failed > 0 {
		r.audit(ctx, audit.ActionStorageAlarm, audit.OutcomeWarning, "holds_reconciled",
			fmt.Sprintf("configuration holds corrected at start: %d added, %d reason corrected, %d released, %d not done; each is a %s alarm", added, replaced, released, failed, c5.AlarmHoldsReconciled))
	}
}

// prunedReplace is the part of a plan's replace that a pruned view still
// applies: a record the fold wants as the baseline. The newest succeeded
// acknowledgement of a kind is in any view that holds one, so the fold's
// baseline is right on a pruned view too, and once the prune passes the
// acknowledgement the node finds the active baseline by that hold (D4-41).
// Without it, a snapshot held as an unapproved difference and then
// acknowledged would keep that reason, and the older baseline would be
// taken as active.
func prunedReplace(ps []planned) []planned {
	var out []planned
	for _, pl := range ps {
		if pl.w.code == c5.HoldBaseline {
			out = append(out, pl)
		}
	}
	return out
}

// planStream is planHolds for one configuration stream, given what the C8
// records say of its asset (nil for nothing).
func (r *Runtime) planStream(ctx context.Context, cdb *store.DB, stream c5.StreamID, a *assetHolds) (holdPlan, error) {
	have, err := cdb.Held(ctx, stream)
	if err != nil {
		return holdPlan{}, err
	}
	var wants []wantHold
	var also map[string][]wantHold
	if a != nil {
		wants, also = a.wantsAll()
	}
	if len(wants) == 0 && len(have) == 0 {
		return holdPlan{}, nil
	}
	digests := map[string]bool{}
	for _, w := range wants {
		digests[w.digest] = true
	}
	found, err := locateAll(ctx, cdb, stream, digests)
	if err != nil {
		return holdPlan{}, err
	}
	return planHolds(r.cfg.NodeID, wants, also, found, have), nil
}

// reconciled raises the alarm for one correction, or the alarm that it
// failed, and counts it.
func (r *Runtime) reconciled(stream c5.StreamID, seq c5.Seq, what string, err error, done, failed *int) {
	detail := fmt.Sprintf("%s seq %d: %s", stream, seq, what)
	if err != nil {
		detail += ": not done: " + err.Error()
		*failed++
	} else {
		*done++
	}
	r.opt.Status.Alarm(ConfigDB, c5.Alarm{Code: c5.AlarmHoldsReconciled, At: r.opt.Now(), Stream: stream, Detail: detail})
}
