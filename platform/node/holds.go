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
//     or an acknowledgement of another configuration baseline ends it: the
//     snapshot and the difference it names, held as
//     HoldUnapprovedDifference, Ref that record. An approval accepted after
//     the alarm does not end it (audit.VerifyConfig).
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
			a.baseline[c.Kind] = ackedBaseline{c.BaselineDigest, s.seq}
			if c.Kind == authz.BaselineConfiguration {
				a.open = nil // the baseline moved: an alarm against the old one is over
			}
		case audit.ActionConfigChangeDetected:
			if c.ApprovalSeq != 0 {
				continue
			}
			a := of(r)
			if b, ok := a.baseline[authz.BaselineConfiguration]; ok && b.digest == c.BaselineDigest {
				a.open = append(a.open, openDifference{c.BaselineDigest, c.SnapshotDigest, c.DifferenceDigest, s.seq})
			}
		case audit.ActionConfigBaselineRestored:
			a := of(r)
			a.open = slices.DeleteFunc(a.open, func(o openDifference) bool { return o.baseline == c.BaselineDigest })
		}
	}
	return out
}

// wants lists an asset's holds in a fixed order: the baselines, then each
// open difference's snapshot and difference. A digest already wanted is not
// wanted twice.
func (a *assetHolds) wants() []wantHold {
	var out []wantHold
	seen := map[string]bool{}
	add := func(w wantHold) {
		if !seen[w.digest] {
			seen[w.digest] = true
			out = append(out, w)
		}
	}
	for _, k := range []authz.BaselineKind{authz.BaselineConfiguration, authz.BaselineEvent} {
		if b, ok := a.baseline[k]; ok {
			add(wantHold{b.digest, c5.HoldBaseline, b.ref, fmt.Sprintf("the %s baseline acknowledged in audit record %d", k, b.ref)})
		}
	}
	for _, o := range a.open {
		add(wantHold{o.snapshot, c5.HoldUnapprovedDifference, o.ref, fmt.Sprintf("the snapshot of the change detected in audit record %d", o.ref)})
		add(wantHold{o.difference, c5.HoldUnapprovedDifference, o.ref, fmt.Sprintf("the difference of the change detected in audit record %d", o.ref)})
	}
	return out
}

// holdPlan is what to change in one stream so that its holds are the ones
// wanted. A replaced hold keeps its record and changes its reason.
type holdPlan struct {
	add, replace []planned
	release      []c5.HeldRecord
	missing      []wantHold
}

type planned struct {
	seq c5.Seq
	w   wantHold
}

// planHolds compares what is wanted, located by digest in found, with what
// the stream holds.
func planHolds(node c5.NodeID, wants []wantHold, found map[string]c5.Seq, have []c5.HeldRecord) holdPlan {
	var p holdPlan
	want := map[c5.Seq]wantHold{}
	for _, w := range wants {
		seq, ok := found[w.digest]
		if !ok {
			p.missing = append(p.missing, w)
			continue
		}
		want[seq] = w
	}
	held := map[c5.Seq]c5.HeldRecord{}
	for _, h := range have {
		held[h.Seq] = h
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
		if _, ok := want[h.Seq]; !ok {
			p.release = append(p.release, h)
		}
	}
	return p
}

func reasonOf(node c5.NodeID, w wantHold) c5.HoldReason {
	return c5.HoldReason{Code: w.code, Ref: c5.Key{NodeID: node, Stream: AuditStream, Seq: w.ref}}
}

// locate finds, in a configuration stream, the stored records whose bytes
// have the digests in want. It reads the whole retained stream, a page at a
// time: records are at most ConfigRecordBytes.
func locate(ctx context.Context, db *store.DB, stream c5.StreamID, want map[string]bool) (map[string]c5.Seq, error) {
	found := map[string]c5.Seq{}
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
				if _, ok := found[d]; !ok {
					found[d] = st.Key.Seq
				}
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
	folded := foldHolds(recs)
	var added, replaced, released, failed int
	for _, spec := range d.spec.Streams {
		assetID := strings.TrimPrefix(string(spec.ID), "config/")
		have, err := cdb.Held(ctx, spec.ID)
		if err != nil {
			fail(err)
			continue
		}
		var wants []wantHold
		if a := folded[assetID]; a != nil {
			wants = a.wants()
		}
		if len(wants) == 0 && len(have) == 0 {
			continue
		}
		digests := map[string]bool{}
		for _, w := range wants {
			digests[w.digest] = true
		}
		found, err := locate(ctx, cdb, spec.ID, digests)
		if err != nil {
			fail(err)
			continue
		}
		p := planHolds(r.cfg.NodeID, wants, found, have)
		for _, w := range p.missing {
			r.opt.Status.Raise(assetID, AlarmBaselineNotStored, fmt.Sprintf("%s (%s) is not in stream %s, so nothing holds it", w.why, w.digest, spec.ID))
		}
		apply := func(ps []planned, verb string, n *int) {
			for _, pl := range ps {
				err := cdb.Hold(ctx, c5.Hold{Stream: spec.ID, Seq: pl.seq, Reason: reasonOf(r.cfg.NodeID, pl.w)})
				r.reconciled(spec.ID, pl.seq, verb+" as "+string(pl.w.code)+": "+pl.w.why, err, n, &failed)
			}
		}
		apply(p.add, "held", &added)
		apply(p.replace, "reason corrected to", &replaced)
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
