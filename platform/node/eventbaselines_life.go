package node

import (
	"bytes"
	"cmp"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"otsec.local/otsec/contracts/audit"
	"otsec.local/otsec/contracts/authz"
	"otsec.local/otsec/contracts/baseline"
	"otsec.local/otsec/contracts/event"
	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/modules/detection/eventbaseline"
	"otsec.local/otsec/platform/store"
)

// The event-baseline lifecycle (R4.8, D4-40): what happens to each observed
// asset's events once the feeder has put them in received order. An asset is
// in one of three phases, and the audit chain and the asset's configuration
// stream say which, so a restart rebuilds it (newEventLife):
//
//   - observing: a learner takes the events. Once both of its minima are met
//     at a watermark, the baseline is finished, stored in config/<asset> as
//     baseline.Encode's bytes, and recorded in the chain with
//     config.baseline_recorded (C8 0.8), in that order (D4-26 item 4);
//   - awaiting acknowledgement: nothing takes the events, which stay stored
//     and forwarded. An administrator's node.baseline_ack, once the chain
//     holds its config.baseline_acknowledged, activates the baseline;
//   - active: a detector takes the events from the acknowledgement's chain
//     time on (ActiveFrom), and its departure alarms and held notices go to
//     platform/health as C4 health events.
//
// Starting a re-learn of an active baseline is not built: nothing asks for
// one yet. The detector is touched only by the feeder's goroutine; the
// acknowledgement path hands its news over (acknowledged).

// Status alarms of the lifecycle, named by asset. Each is raised once until
// what it reports is resolved.
const (
	// AlarmEventBaselineRefused: the learner or the detector refused an
	// event, a gap or the finish, so the baseline or an alarm may lack it.
	AlarmEventBaselineRefused = "event-baseline-refused"
	// AlarmEventBaselineNotRecorded: a finished baseline could not be
	// stored, or its config.baseline_recorded could not be written. The
	// node tries again at each watermark, and at the next start.
	AlarmEventBaselineNotRecorded = "event-baseline-not-recorded"
	// AlarmEventBaselinePartial: a recorded baseline left types out
	// (Counts.TypesOverflow above zero), so the asset is only partly
	// baselined (C10 0.2, C1's condition 4 on #364).
	AlarmEventBaselinePartial = "event-baseline-partial"
	// AlarmEventBaselineState: the chain and the configuration stream do
	// not agree on the asset's baselines, so its lifecycle is not started.
	AlarmEventBaselineState = "event-baseline-state"
	// AlarmEventBaselineNotRestored: a half's checkpoint did not restore
	// (feeder slice 1c). A learner starts again; a detector is rebuilt from
	// the active baseline, watched from the restart's watermark. The detail
	// names the error: corruption, an upgrade, or changed parameters.
	AlarmEventBaselineNotRestored = "event-baseline-not-restored"
	// AlarmDepartureNotStored: a departure alarm or a held notice could
	// not be stored in platform/health. Status holds this alarm instead.
	AlarmDepartureNotStored = "baseline-departure-not-stored"
	// AlarmEventBaselineLate: events of the asset arrived behind the
	// feeder's watermark (FeedLateness), so neither its learner nor its
	// detector saw them (C3 on #365). Status counts them as late.
	AlarmEventBaselineLate = "event-baseline-late"
)

// Health types the lifecycle writes beside C10's departure and held notice.
const (
	// HealthEventBaselineRecorded: a baseline was stored and recorded and
	// awaits acknowledgement. Details: asset_id, baseline (the hash),
	// version, types, types_overflow.
	HealthEventBaselineRecorded = "eventbaseline.recorded"
	// HealthEventBaselineActive: an acknowledged baseline is now watched.
	// Details: asset_id, baseline, active_from.
	HealthEventBaselineActive = "eventbaseline.active"
	// HealthEventBaselineRefused: the learner or the detector refused an
	// event, a gap or a tick (C4 on #365). Written with the alarm, once
	// until it clears; status counts every refusal. Details: asset_id,
	// error.
	HealthEventBaselineRefused = "eventbaseline.refused"
)

// eventLife is the feeder's sink: each observed asset's learner or detector.
type eventLife struct {
	rt  *Runtime
	ctx context.Context
	// first is the first audit seq of the view start-up verified, after
	// the node's prune point (1 when nothing was pruned).
	first c5.Seq

	mu   sync.Mutex
	acks []lifeAck // queued by acknowledged, applied on the feeder's goroutine

	assets map[string]*lifeAsset
}

type lifeAck struct {
	asset, digest string
	at            time.Time
}

type lifeAsset struct {
	id string
	p  baseline.Params

	// learner is set while observing. It records version, and replaces
	// previous ("" for the asset's first).
	learner  *eventbaseline.Learner
	version  int
	previous string

	// recorded is the newest baseline stored and recorded and not yet
	// acknowledged; unrecorded says its config.baseline_recorded is still
	// to be written.
	recorded     *baseline.Baseline
	recordedHash string
	unrecorded   bool

	// detector is set while a baseline is active: activeBaseline, stored
	// with hash active, watched from activeFrom.
	detector       *eventbaseline.Detector
	activeBaseline *baseline.Baseline
	active         string
	activeFrom     time.Time
	// fromHold: the active baseline came from the configuration store's
	// baseline hold, as its acknowledgement was pruned from the audit
	// stream (D4-41), so activeFrom is provisional until a checkpoint
	// gives it (restore).
	fromHold bool

	raised map[string]bool
	// Counts for status.
	Refused int64
	Alarms  int64
}

// newEventLife builds each observed asset's phase from the chain and the
// asset's configuration stream, and writes a config.baseline_recorded that a
// crash after the store left out (D4-26 item 4).
func newEventLife(ctx context.Context, rt *Runtime) (*eventLife, error) {
	l := &eventLife{rt: rt, ctx: ctx, assets: map[string]*lifeAsset{}}
	if len(rt.cfg.EventBaselines) == 0 {
		return l, nil
	}
	adb := rt.Store(AuditStream)
	if adb == nil {
		return nil, errors.New("event baselines: the audit database is not open")
	}
	recs, raw, err := chainRecords(ctx, adb)
	if err != nil {
		return nil, fmt.Errorf("event baselines: %w", err)
	}
	// The view is the retained stream from the node's prune point (D4-40
	// item 8): its hash chain is checked in full from the anchor, the link
	// of the last record pruned, and its configuration records with
	// VerifyConfigFrom, under which a reference to before the view is
	// unknown, not broken. chainRecords validated each record (ParseRecord);
	// together they must also verify (C3 on #346). If they do not, no asset
	// learns, records or detects, since anything written would extend a
	// chain the node cannot vouch for. Each asset's alarm says why.
	anchor, err := adb.ChainAnchor(ctx, AuditStream)
	if err != nil {
		return nil, fmt.Errorf("event baselines: %w", err)
	}
	l.first = c5.Seq(anchor.Seq + 1)
	all := make([]*audit.Record, len(recs))
	for i, ar := range recs {
		all[i] = ar.rec
	}
	err = audit.VerifyChain(string(rt.cfg.NodeID), raw, &anchor, nil)
	if err == nil {
		err = audit.VerifyConfigFrom(all, uint64(l.first))
	}
	if err != nil {
		for _, e := range rt.cfg.EventBaselines {
			a := &lifeAsset{id: e.AssetID, p: e.Params, raised: map[string]bool{}}
			l.assets[e.AssetID] = a
			l.raise(a, AlarmEventBaselineState, "the audit chain's configuration records do not verify, so no event baseline is learnt or watched: "+err.Error())
		}
		return l, nil
	}
	chain := foldEventBaselines(recs)
	for _, e := range rt.cfg.EventBaselines {
		a := &lifeAsset{id: e.AssetID, p: e.Params, raised: map[string]bool{}}
		l.assets[e.AssetID] = a
		stored, err := l.storedBaselines(ctx, e.AssetID)
		if err == nil {
			err = l.start(ctx, a, chain[e.AssetID], stored)
		}
		if err != nil {
			l.raise(a, AlarmEventBaselineState, err.Error())
		}
	}
	return l, nil
}

// chainRecords reads the retained audit stream: every record's bytes, for
// audit.VerifyChain, and parsed, the records audit.VerifyConfig reads: the
// configuration records, and the collector's request and numbering-reset
// records that acceptances and epochs come from. configAuditRecords
// (holds.go) reads only the first.
func chainRecords(ctx context.Context, db *store.DB) ([]auditRec, [][]byte, error) {
	last, err := db.LastCommitted(ctx, AuditStream)
	if err != nil {
		return nil, nil, err
	}
	var (
		out   []auditRec
		raw   [][]byte
		after c5.Seq
	)
	for after < last {
		got, err := db.Read(ctx, AuditStream, after, 500)
		if err != nil {
			return nil, nil, err
		}
		if len(got) == 0 {
			return nil, nil, fmt.Errorf("audit stream ends at %d, before its last committed seq %d", after, last)
		}
		for _, st := range got {
			after = st.Key.Seq
			raw = append(raw, st.Event)
			// The bytes select the records to parse; a record with an
			// escape is parsed too, as its action may be spelt with one
			// (C3 on #384). The parsed action decides.
			if !bytes.Contains(st.Event, []byte(`"config.`)) && !bytes.Contains(st.Event, []byte(`"collector.`)) && !bytes.Contains(st.Event, []byte(`\u`)) {
				continue
			}
			rec, err := audit.ParseRecord(st.Event)
			if err != nil {
				return nil, nil, badRecord{st.Key.Seq, err}
			}
			if act := string(rec.Action); strings.HasPrefix(act, "config.") || strings.HasPrefix(act, "collector.") {
				out = append(out, auditRec{st.Key.Seq, rec})
			}
		}
	}
	return out, raw, nil
}

// eventChain is what the chain says about one asset's event baselines: the
// recordings in order, and the last succeeded acknowledgement.
type eventChain struct {
	recorded []*audit.Record
	ack      *audit.Record
}

func foldEventBaselines(recs []auditRec) map[string]*eventChain {
	out := map[string]*eventChain{}
	get := func(asset string) *eventChain {
		c := out[asset]
		if c == nil {
			c = &eventChain{}
			out[asset] = c
		}
		return c
	}
	for _, ar := range recs {
		r := ar.rec
		if r.Config == nil || r.Target == nil || r.Config.Kind != authz.BaselineEvent {
			continue
		}
		switch {
		case r.Action == audit.ActionConfigBaselineRecorded:
			c := get(r.Target.AssetID)
			c.recorded = append(c.recorded, r)
		case r.Action == audit.ActionConfigBaselineAcknowledge && r.Outcome == audit.OutcomeSucceeded:
			get(r.Target.AssetID).ack = r
		}
	}
	return out
}

// storedBaselines reads the C10 records of the asset's configuration
// stream, by hash. The store keeps a baseline as baseline.Encode's bytes
// (ConfigDocuments), so its schema is its first field.
func (l *eventLife) storedBaselines(ctx context.Context, assetID string) (map[string]*baseline.Baseline, error) {
	stream := ConfigStream(assetID)
	db := l.rt.Store(stream)
	if db == nil {
		return nil, errors.New("the configuration database is not open")
	}
	out := map[string]*baseline.Baseline{}
	var after c5.Seq
	for {
		got, err := db.Read(ctx, stream, after, 16)
		if err != nil {
			return nil, err
		}
		if len(got) == 0 {
			return out, nil
		}
		for _, st := range got {
			after = st.Key.Seq
			if !bytes.HasPrefix(st.Event, []byte(`{"schema":"otsec.baseline/`)) {
				continue
			}
			b, err := baseline.Decode(st.Event)
			if err != nil {
				return nil, fmt.Errorf("record %d: %w", st.Key.Seq, err)
			}
			if b.AssetID != assetID {
				return nil, fmt.Errorf("record %d is a baseline of asset %s", st.Key.Seq, b.AssetID)
			}
			out[baseline.Hash(st.Event)] = b
		}
	}
}

// start sets the asset's phase from the chain and the stored baselines.
func (l *eventLife) start(ctx context.Context, a *lifeAsset, c *eventChain, stored map[string]*baseline.Baseline) error {
	if c == nil {
		c = &eventChain{}
	}
	cut := l.first > 1
	var last *audit.Record
	if n := len(c.recorded); n > 0 {
		last = c.recorded[n-1]
	}
	// A baseline stored after the last recording, whose record a crash left
	// out: it replaces the last recorded one at the next version. With no
	// recording in the chain, only the asset's first can be one, and only
	// when the stream holds nothing else (C3 on #384). In a view cut by a
	// prune, no recording in it does not mean none was written, so there
	// the repair runs only after a recording in the view: any recording
	// after that one is in the view too, so a candidate at its next version
	// cannot repeat one (C3's condition on #384). The candidates are found
	// without depending on map order.
	var cands []string
	for h, b := range stored {
		if (last == nil && !cut) || (last != nil && b.Version == last.Config.BaselineVersion+1) {
			cands = append(cands, h)
		}
	}
	slices.Sort(cands)
	switch {
	case len(cands) > 1:
		return fmt.Errorf("%d stored baselines (%s) could each be the one whose recording is missing", len(cands), strings.Join(cands, ", "))
	case len(cands) == 1:
		h := cands[0]
		b := stored[h]
		switch {
		case last != nil && b.Previous != last.Config.BaselineDigest:
			return fmt.Errorf("stored baseline %s, version %d, replaces %q, not the last recorded %s", h, b.Version, b.Previous, last.Config.BaselineDigest)
		case last == nil && (b.Version != 1 || b.Previous != ""):
			return fmt.Errorf("stored baseline %s is version %d, and the chain records none of the asset's baselines", h, b.Version)
		}
		a.recorded, a.recordedHash, a.unrecorded = b, h, true
		a.version, a.previous = b.Version, b.Previous
		if err := l.record(a); err != nil {
			l.raise(a, AlarmEventBaselineNotRecorded, err.Error())
		}
		return l.startFrom(ctx, a, c.ack, stored)
	}
	if last != nil {
		h := last.Config.BaselineDigest
		b, ok := stored[h]
		if !ok {
			return fmt.Errorf("the recorded baseline %s is not in %s", h, ConfigStream(a.id))
		}
		a.recorded, a.recordedHash = b, h
		a.version, a.previous = last.Config.BaselineVersion, last.Config.PreviousDigest
	}
	return l.startFrom(ctx, a, c.ack, stored)
}

// startFrom finishes start. The last succeeded acknowledgement names the
// active baseline: the recorded one, which it activates, or an earlier one,
// which stays active while the recorded one awaits its own. In a view cut
// by a prune with no acknowledgement of the asset in it, the active
// baseline is the one the configuration store holds as baseline (D4-41).
// With nothing recorded or active the asset observes for its first, unless
// the cut view leaves stored baselines it cannot place.
func (l *eventLife) startFrom(ctx context.Context, a *lifeAsset, ack *audit.Record, stored map[string]*baseline.Baseline) error {
	cut := l.first > 1
	switch {
	case ack != nil:
		at, err := time.Parse(time.RFC3339Nano, ack.Time.UTC)
		if err != nil {
			return fmt.Errorf("acknowledgement %d: time %q: %w", ack.Seq, ack.Time.UTC, err)
		}
		h := ack.Config.BaselineDigest
		b, ok := stored[h]
		if !ok {
			return fmt.Errorf("the acknowledged baseline %s is not in %s", h, ConfigStream(a.id))
		}
		if err := l.activate(a, b, h, at); err != nil {
			return err
		}
	case cut:
		h, err := l.heldBaseline(ctx, a.id, stored)
		if err != nil {
			return err
		}
		if h != "" {
			// No acknowledgement time: watched from now until a checkpoint
			// gives the time, or the restart's watermark does (restore).
			if err := l.activate(a, stored[h], h, l.rt.opt.Now()); err != nil {
				return err
			}
			a.fromHold = true
		}
	}
	if a.recordedHash != "" && a.recordedHash == a.active {
		a.recorded, a.recordedHash = nil, ""
	}
	switch {
	case a.recordedHash != "" || a.detector != nil:
		return nil
	case cut && len(stored) > 0:
		return fmt.Errorf("the audit stream is pruned before seq %d, and neither it nor the configuration store's holds say which of the %d stored baselines is recorded or active", l.first, len(stored))
	}
	return l.observe(a, 1, "")
}

// heldBaseline is the asset's event baseline that the configuration store
// holds as baseline, for a view with no acknowledgement of it (D4-41): of
// the records held as baseline that are C10 baselines, the one whose Ref is
// newest. That Ref must be before the view: one in it would be an
// acknowledgement the view holds. "" when none is held.
func (l *eventLife) heldBaseline(ctx context.Context, assetID string, stored map[string]*baseline.Baseline) (string, error) {
	stream := ConfigStream(assetID)
	db := l.rt.Store(stream)
	if db == nil {
		return "", errors.New("the configuration database is not open")
	}
	held, err := db.Held(ctx, stream)
	if err != nil {
		return "", err
	}
	// Newest Ref first: of the baseline holds, the first that is a C10
	// baseline is the one the latest acknowledgement set.
	slices.SortFunc(held, func(x, y c5.HeldRecord) int { return cmp.Compare(y.Reason.Ref.Seq, x.Reason.Ref.Seq) })
	for _, hr := range held {
		if hr.Reason.Code != c5.HoldBaseline {
			continue
		}
		got, err := db.Read(ctx, stream, hr.Seq-1, 1)
		if err != nil {
			return "", err
		}
		if len(got) != 1 || got[0].Key.Seq != hr.Seq || !bytes.HasPrefix(got[0].Event, []byte(`{"schema":"otsec.baseline/`)) {
			continue // a configuration baseline (C9), or not readable as one
		}
		if hr.Reason.Ref.Seq >= l.first {
			return "", fmt.Errorf("%s seq %d is held as baseline by audit record %d, which is in the view and is not an acknowledgement of it", stream, hr.Seq, hr.Reason.Ref.Seq)
		}
		h := baseline.Hash(got[0].Event)
		if stored[h] == nil {
			return "", fmt.Errorf("%s seq %d is held as baseline and is not a stored baseline of the asset", stream, hr.Seq)
		}
		return h, nil
	}
	return "", nil
}

func (l *eventLife) observe(a *lifeAsset, version int, previous string) error {
	ln, err := eventbaseline.NewLearner(l.learnerConfig(a, version, previous))
	if err != nil {
		return err
	}
	a.learner, a.version, a.previous = ln, version, previous
	return nil
}

func (l *eventLife) learnerConfig(a *lifeAsset, version int, previous string) eventbaseline.LearnerConfig {
	return eventbaseline.LearnerConfig{Node: l.rt.cfg.NodeID, AssetID: a.id, Params: a.p, Version: version, Previous: previous}
}

// activate makes b, stored with hash h, the active baseline, watched from
// at.
func (l *eventLife) activate(a *lifeAsset, b *baseline.Baseline, h string, at time.Time) error {
	d, err := eventbaseline.NewDetector(eventbaseline.DetectorConfig{Baseline: b, Hash: h, ActiveFrom: at})
	if err != nil {
		return err
	}
	a.detector, a.activeBaseline, a.active, a.activeFrom = d, b, h, at
	l.health(a, HealthEventBaselineActive, map[string]string{"asset_id": a.id, "baseline": h, "active_from": at.UTC().Format(time.RFC3339Nano)})
	return nil
}

// acknowledged tells the lifecycle that the chain now holds a succeeded
// config.baseline_acknowledged of kind event for the asset's baseline
// digest, entered at at. The acknowledgement path calls it after the
// record's receipt, from its own goroutine; it is applied at the feeder's
// next call. A crash before the call loses nothing: the next start reads
// the acknowledgement from the chain.
func (l *eventLife) acknowledged(assetID, digest string, at time.Time) {
	l.mu.Lock()
	l.acks = append(l.acks, lifeAck{assetID, digest, at})
	l.mu.Unlock()
}

// asset applies the queued acknowledgements and returns the asset.
func (l *eventLife) asset(assetID string) *lifeAsset {
	l.mu.Lock()
	acks := l.acks
	l.acks = nil
	l.mu.Unlock()
	for _, k := range acks {
		a := l.assets[k.asset]
		switch {
		case a == nil:
		case a.recordedHash != k.digest || a.unrecorded:
			// The acknowledgement path refuses these; a guard, not a rule.
			l.raise(a, AlarmEventBaselineState, fmt.Sprintf("an acknowledgement of %s, which is not the recorded baseline awaiting one", k.digest))
		default:
			if err := l.activate(a, a.recorded, a.recordedHash, k.at); err != nil {
				l.raise(a, AlarmEventBaselineState, "activation: "+err.Error())
				continue
			}
			a.recorded, a.recordedHash = nil, ""
		}
	}
	return l.assets[assetID]
}

// Observe is feedSink's: the event goes to the asset's learner or detector.
func (l *eventLife) Observe(assetID string, o eventbaseline.Obs) {
	a := l.asset(assetID)
	if a == nil {
		return
	}
	if a.learner != nil {
		if err := a.learner.Observe(o); err != nil {
			l.refused(a, err)
		}
	}
	if a.detector != nil {
		// The detector raises nothing for an event received before
		// ActiveFrom, the acknowledgement's chain time (D4-15).
		out, err := a.detector.Observe(o)
		if err != nil {
			l.refused(a, err)
		}
		l.emit(a, out)
	}
}

// Gap is feedSink's: a closed collection gap goes to the learner.
func (l *eventLife) Gap(assetID string, from, to time.Time, reason string) {
	a := l.asset(assetID)
	if a == nil || a.learner == nil {
		return
	}
	if err := a.learner.Gap(from, to, reason); err != nil {
		l.refused(a, err)
	}
}

// Tick is feedSink's: the watermark finishes a learner whose minima are met,
// and moves a detector's time.
func (l *eventLife) Tick(assetID string, at time.Time) {
	a := l.asset(assetID)
	if a == nil {
		return
	}
	if a.learner != nil && a.learner.Progress(at).Done {
		l.finish(a, at)
	}
	if a.unrecorded {
		if err := l.record(a); err != nil {
			l.raise(a, AlarmEventBaselineNotRecorded, err.Error())
		}
	}
	// The watermark trails the acknowledgement's chain time by up to
	// FeedLateness; the detector's time starts at ActiveFrom.
	if a.detector != nil && !at.Before(a.activeFrom) {
		out, err := a.detector.Tick(at)
		if err != nil {
			l.refused(a, err)
		}
		l.emit(a, out)
	}
}

// finish ends the learner at the watermark, stores the baseline, and
// records it. A baseline that cannot be stored leaves the learner learning,
// to be finished again at the next watermark.
func (l *eventLife) finish(a *lifeAsset, at time.Time) {
	res, err := a.learner.Finish(at)
	if err != nil {
		l.refused(a, err)
		return
	}
	stream := ConfigStream(a.id)
	_, log, mode := l.rt.view(l.rt.dbFor(stream))
	if log == nil || !mode.AcceptsEvents() {
		l.raise(a, AlarmEventBaselineNotRecorded, fmt.Sprintf("the finished baseline is not stored: configuration database %s", l.rt.Mode(ConfigDB)))
		return
	}
	// AppendBatch, not Append: its error means nothing was committed. An
	// Append whose context ends can still commit, and the retry at the next
	// watermark would then store a second baseline (C6 on #384).
	if _, err := log.AppendBatch(l.ctx, []c5.Record{{Stream: stream, Class: c5.ClassConfiguration, Event: res.Bytes}}); err != nil {
		l.raise(a, AlarmEventBaselineNotRecorded, "the finished baseline is not stored: "+err.Error())
		return
	}
	a.learner = nil
	a.recorded, a.recordedHash, a.unrecorded = res.Baseline, res.Hash, true
	if err := l.record(a); err != nil {
		l.raise(a, AlarmEventBaselineNotRecorded, err.Error())
	}
	c := res.Baseline.Counts
	l.health(a, HealthEventBaselineRecorded, map[string]string{"asset_id": a.id, "baseline": res.Hash,
		"version": strconv.Itoa(res.Baseline.Version), "types": strconv.Itoa(len(res.Baseline.Types)),
		"types_overflow": strconv.FormatInt(c.TypesOverflow, 10)})
	if c.TypesOverflow > 0 {
		more := ""
		if res.OverflowSaturated {
			more = " or more"
		}
		l.raise(a, AlarmEventBaselinePartial, fmt.Sprintf("baseline %s left %d types%s out, so the asset is only partly baselined", res.Hash, c.TypesOverflow, more))
	}
}

// record writes the recorded baseline's config.baseline_recorded (C8 0.8).
func (l *eventLife) record(a *lifeAsset) error {
	rec := audit.Record{Contract: audit.ContractID, NodeID: string(l.rt.cfg.NodeID), Time: l.rt.received(),
		Actor:  audit.Actor{Type: authz.PrincipalNode, ID: string(l.rt.cfg.NodeID)},
		Action: audit.ActionConfigBaselineRecorded, Outcome: audit.OutcomeInfo, Target: &audit.Target{AssetID: a.id},
		// D4-29: the digest's hex digits, without the prefix.
		CorrelationID: strings.TrimPrefix(a.recordedHash, "sha256:"),
		Config: &audit.Config{Kind: authz.BaselineEvent, BaselineDigest: a.recordedHash,
			PreviousDigest: a.recorded.Previous, BaselineVersion: a.recorded.Version}}
	if _, err := hex.DecodeString(rec.CorrelationID); err != nil {
		return fmt.Errorf("baseline hash %q: %w", a.recordedHash, err)
	}
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	if _, err := audit.ValidatePending(b); err != nil {
		return err
	}
	_, log, mode := l.rt.view(l.rt.find(AuditDB))
	if log == nil || !mode.AcceptsEvents() {
		return fmt.Errorf("config.baseline_recorded not written: audit database %s", l.rt.Mode(AuditDB))
	}
	// AppendBatch, as in finish: a recording retried after an Append that
	// committed anyway would repeat its digest, which breaks the chain.
	if _, err := log.AppendBatch(l.ctx, []c5.Record{{Stream: AuditStream, Class: c5.ClassAudit, Event: b}}); err != nil {
		return fmt.Errorf("config.baseline_recorded not written: %w", err)
	}
	a.unrecorded = false
	a.clear(AlarmEventBaselineNotRecorded)
	return nil
}

// emit stores the detector's alarms and held notice in platform/health.
func (l *eventLife) emit(a *lifeAsset, out eventbaseline.Output) {
	for _, al := range out.Alarms {
		a.Alarms++
		h, err := al.Health()
		if err == nil {
			err = l.store(h.Type, h.Related, h.Details)
		}
		if err != nil {
			l.raise(a, AlarmDepartureNotStored, fmt.Sprintf("%s alarm of baseline %s: %v", al.Rule, al.Baseline, err))
		}
	}
	if out.Held != nil {
		err := l.store(baseline.HealthAlarmsHeld, nil, map[string]string{"asset_id": out.Held.AssetID,
			"held": strconv.FormatInt(out.Held.Held, 10), "hold_s": strconv.FormatInt(out.Held.HoldS, 10)})
		if err != nil {
			l.raise(a, AlarmDepartureNotStored, "held notice: "+err.Error())
		}
	}
}

func (l *eventLife) health(a *lifeAsset, typ string, details map[string]string) {
	if err := l.store(typ, nil, details); err != nil {
		l.raise(a, AlarmDepartureNotStored, typ+": "+err.Error())
	}
}

func (l *eventLife) store(typ string, related []event.EventID, details map[string]string) error {
	_, log, mode := l.rt.view(l.rt.dbFor(HealthStream))
	if log == nil || !mode.AcceptsEvents() {
		return fmt.Errorf("evidence database %s", mode)
	}
	rec, err := l.rt.healthEventRecord(HealthStream, event.Health{Type: typ, Related: related, Details: details})
	if err != nil {
		return err
	}
	_, err = log.Append(l.ctx, rec)
	return err
}

func (l *eventLife) refused(a *lifeAsset, err error) {
	a.Refused++
	if a.raised[AlarmEventBaselineRefused] {
		return
	}
	l.raise(a, AlarmEventBaselineRefused, err.Error())
	l.health(a, HealthEventBaselineRefused, map[string]string{"asset_id": a.id, "error": err.Error()})
}

// raise raises code for the asset once, until clear.
func (l *eventLife) raise(a *lifeAsset, code, detail string) {
	if a.raised[code] {
		return
	}
	a.raised[code] = true
	l.rt.opt.Status.Raise(a.id, code, detail)
}

func (a *lifeAsset) clear(code string) { delete(a.raised, code) }

// half returns the asset's learner and detector, either nil, for the
// checkpoint (feeder slice 1c). Both are set during a re-learn. It is
// called on the feeder's goroutine.
func (l *eventLife) half(assetID string) (*eventbaseline.Learner, *eventbaseline.Detector) {
	a := l.asset(assetID)
	if a == nil {
		return nil, nil
	}
	return a.learner, a.detector
}

// awaiting reports whether the asset's events go nowhere: nothing learns
// or watches, because its baseline awaits acknowledgement or the asset is
// stopped (its event-baseline-state alarm says why). The feeder's cursor
// still moves past them (1c).
func (l *eventLife) awaiting(assetID string) bool {
	a := l.asset(assetID)
	return a != nil && a.learner == nil && a.detector == nil
}

// relearning returns the version the asset's learner will record and the
// digest that baseline replaces ("" for an asset's first), for the audit of
// a learner that did not restore (D4-26, C5 on 1c). ok is false when the
// asset has no learner.
func (l *eventLife) relearning(assetID string) (version int, previous string, ok bool) {
	a := l.asset(assetID)
	if a == nil || a.learner == nil {
		return 0, "", false
	}
	return a.version, a.previous, true
}

// restore restores the halves the asset has from their checkpoint snapshots
// (feeder slice 1c), either nil, and returns each half's error. A learner
// that does not restore starts again; a detector that does not restore is
// rebuilt from the active baseline and watched from wm, the restart's
// watermark, so a periodic type gets a whole interval from the restart, not
// a false absence (C4 on #340). A snapshot of a half the asset no longer has
// is ignored: the baseline was stored, or activated, after it was taken.
// An active baseline that came from a hold (fromHold) takes its activation
// time from the snapshot, bounded by heldFrom, and is otherwise rebuilt
// from wm, with or without a snapshot (D4-41).
func (l *eventLife) restore(assetID string, lsnap, dsnap []byte, wm time.Time) (lerr, derr error) {
	a := l.asset(assetID)
	if a == nil {
		return nil, nil
	}
	if a.learner != nil && lsnap != nil {
		r, err := eventbaseline.RestoreLearner(l.learnerConfig(a, a.version, a.previous), lsnap)
		if err != nil {
			lerr = err
			l.raise(a, AlarmEventBaselineNotRestored, "learner: "+err.Error()+"; it starts again")
		} else {
			a.learner = r
		}
	}
	if a.detector == nil || (dsnap == nil && !a.fromHold) {
		return lerr, nil
	}
	from, held := a.activeFrom, a.fromHold
	a.fromHold = false
	if held {
		// D4-41: the acknowledgement time was pruned, so the checkpoint's
		// activation time is taken if it is bounded; otherwise watching
		// starts at the watermark.
		from = wm
		if dsnap != nil {
			at, err := heldFrom(a, dsnap, wm)
			if err != nil {
				derr = err
			} else {
				from = at
			}
		}
	}
	if dsnap != nil && derr == nil {
		r, err := eventbaseline.RestoreDetector(eventbaseline.DetectorConfig{Baseline: a.activeBaseline, Hash: a.active, ActiveFrom: from}, dsnap)
		if err == nil {
			a.detector, a.activeFrom = r, from
			if held {
				l.health(a, HealthEventBaselineActive, map[string]string{"asset_id": a.id, "baseline": a.active, "active_from": from.UTC().Format(time.RFC3339Nano)})
			}
			return lerr, nil
		}
		derr = err
		if wm.After(from) {
			from = wm
		}
	}
	d, err := eventbaseline.NewDetector(eventbaseline.DetectorConfig{Baseline: a.activeBaseline, Hash: a.active, ActiveFrom: from})
	if err != nil {
		l.raise(a, AlarmEventBaselineNotRestored, "detector: not rebuilt: "+err.Error())
		a.detector = nil
		return lerr, derr
	}
	a.detector, a.activeFrom = d, from
	if held {
		l.health(a, HealthEventBaselineActive, map[string]string{"asset_id": a.id, "baseline": a.active, "active_from": from.UTC().Format(time.RFC3339Nano)})
	}
	if derr != nil {
		l.raise(a, AlarmEventBaselineNotRestored, "detector: "+derr.Error()+"; rebuilt, watching from "+from.UTC().Format(time.RFC3339Nano)+", so its alarms differ from those the lost state would have raised")
	}
	return lerr, derr
}

// heldFrom is the activation time a detector snapshot gives an asset whose
// active baseline came from a hold (D4-41). It must be no earlier than the
// end of the baseline's own period and no later than the watermark;
// otherwise the snapshot does not belong to this activation, and the error
// wraps eventbaseline.ErrSnapshotMismatch.
func heldFrom(a *lifeAsset, snap []byte, wm time.Time) (time.Time, error) {
	at, err := eventbaseline.DetectorActiveFrom(snap, a.active)
	if err != nil {
		return time.Time{}, err
	}
	end, err := time.Parse(time.RFC3339Nano, a.activeBaseline.Period.EndUTC)
	if err != nil {
		return time.Time{}, fmt.Errorf("the baseline period's end: %w", err)
	}
	switch {
	case at.Before(end):
		return time.Time{}, fmt.Errorf("%w: its activation time %s is before the baseline period's end %s", eventbaseline.ErrSnapshotMismatch, at.Format(time.RFC3339Nano), a.activeBaseline.Period.EndUTC)
	case at.After(wm):
		return time.Time{}, fmt.Errorf("%w: its activation time %s is after the watermark %s", eventbaseline.ErrSnapshotMismatch, at.Format(time.RFC3339Nano), wm.UTC().Format(time.RFC3339Nano))
	}
	return at, nil
}

// EventBaselineStatus is one observed asset's event baseline as node status
// shows it (feeder slice 1d). Phase is "learning", "awaiting" (recorded,
// not yet acknowledged), "active" or "stopped" (the alarm says why). While
// an active baseline is re-learnt, Phase is "active" and Learning is set.
type EventBaselineStatus struct {
	Phase    string                 `json:"phase"`
	Learning *EventBaselineLearning `json:"learning,omitempty"`
	// Recorded is the baseline awaiting acknowledgement.
	Recorded *EventBaselineRef `json:"recorded,omitempty"`
	Active   *EventBaselineRef `json:"active,omitempty"`
	// ActiveFrom is when the detector began: the acknowledgement's chain
	// time, or a restart's watermark after a detector did not restore.
	ActiveFrom time.Time `json:"active_from,omitzero"`
	// HeldNow is the departure alarms the detector holds back now.
	HeldNow int64 `json:"held_now,omitempty"`
	// Alarms counts the departure alarms raised in this process, Refused
	// the events, gaps and ticks refused, and Late the events that
	// arrived behind the watermark.
	Alarms  int64 `json:"alarms,omitempty"`
	Refused int64 `json:"refused,omitempty"`
	Late    int64 `json:"late,omitempty"`
}

// EventBaselineLearning is a learner's progress. TypesOverflow is a lower
// bound while it learns (C4 on #369); GapBudgetDrops is not in the C10
// record (C6 on #369).
type EventBaselineLearning struct {
	Version        int   `json:"version"`
	CollectedS     int64 `json:"collected_s"`
	Events         int64 `json:"events"`
	TypesHeld      int   `json:"types_held"`
	TypesOverflow  int   `json:"types_overflow"`
	GapBudgetDrops int64 `json:"gap_budget_drops,omitempty"`
}

// EventBaselineRef is a stored baseline: its hash, version and
// types_overflow, which above zero says the asset is only partly baselined
// (C1's condition 4).
type EventBaselineRef struct {
	Hash          string `json:"hash"`
	Version       int    `json:"version"`
	TypesOverflow int64  `json:"types_overflow"`
}

// EventFeedStatus is the feeder's node-wide state: Syslog events whose
// sender is no asset, the records each stream lost to pruning before the
// feeder read them, and the last Step's error, empty when it succeeded.
type EventFeedStatus struct {
	Unresolved int64                 `json:"unresolved"`
	Skipped    map[c5.StreamID]int64 `json:"skipped,omitempty"`
	StepError  string                `json:"step_error,omitempty"`
}

// publish puts each observed asset's state and the feeder's counts in node
// status, and raises AlarmEventBaselineLate for an asset with late events.
// It is called on the feeder's goroutine after each Step, with its error.
func (l *eventLife) publish(f *eventFeed, at time.Time, stepErr error) {
	m := map[string]EventBaselineStatus{}
	for id, fa := range f.assets {
		a := l.asset(id)
		if a == nil {
			m[id] = EventBaselineStatus{Phase: "stopped", Late: fa.Late}
			continue
		}
		st := EventBaselineStatus{Alarms: a.Alarms, Refused: a.Refused, Late: fa.Late}
		if a.learner != nil {
			pr := a.learner.Progress(at)
			held, over := a.learner.TypesHeld()
			st.Learning = &EventBaselineLearning{Version: a.version, CollectedS: pr.CollectedS, Events: pr.Events,
				TypesHeld: held, TypesOverflow: over, GapBudgetDrops: a.learner.GapBudgetDrops()}
		}
		if a.recorded != nil {
			st.Recorded = &EventBaselineRef{Hash: a.recordedHash, Version: a.recorded.Version, TypesOverflow: a.recorded.Counts.TypesOverflow}
		}
		if a.detector != nil {
			st.Active = &EventBaselineRef{Hash: a.active, Version: a.activeBaseline.Version, TypesOverflow: a.activeBaseline.Counts.TypesOverflow}
			st.ActiveFrom, st.HeldNow = a.activeFrom, a.detector.HeldNow()
		}
		switch {
		case a.detector != nil:
			st.Phase = "active"
		case a.recorded != nil:
			st.Phase = "awaiting"
		case a.learner != nil:
			st.Phase = "learning"
		default:
			st.Phase = "stopped"
		}
		if fa.Late > 0 {
			l.raise(a, AlarmEventBaselineLate, fmt.Sprintf("%d events arrived more than %s behind the watermark and were not baselined or watched", fa.Late, FeedLateness))
		}
		m[id] = st
	}
	fs := &EventFeedStatus{Unresolved: f.Unresolved}
	for _, s := range f.streams {
		if s.Skipped > 0 {
			if fs.Skipped == nil {
				fs.Skipped = map[c5.StreamID]int64{}
			}
			fs.Skipped[s.id] = s.Skipped
		}
	}
	if stepErr != nil {
		fs.StepError = stepErr.Error()
	}
	l.rt.opt.Status.SetEventBaselines(m, fs)
}
