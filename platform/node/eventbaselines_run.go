package node

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"

	"otsec.local/otsec/contracts/audit"
	"otsec.local/otsec/contracts/authz"
	"otsec.local/otsec/contracts/baseline"
	"otsec.local/otsec/contracts/event"
	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/modules/detection/eventbaseline"
)

// The event-baseline feeder and lifecycle in the running node (feeder slice
// 1c, docs/phase4/B5-event-baseline-feeder.md, D4-26, D4-32, D4-36). The
// scheduler steps them between runs, on its own goroutine (Scheduler.Run).
//
// State across a restart: each half an asset has, its learner or its
// detector, is checkpointed in a record of the asset's configuration stream
// (eventcheckpoint.go), with the feeder's positions and state for the asset,
// at most every CheckpointEvery, once the half has changed and at once when
// the asset gains a half, and at a clean stop. After the checkpoint commits,
// EventBaselineConsumer's cursor on each stream is saved at the lowest
// restart point of the assets that read it, and the checkpoints the new one
// supersedes are removed. At start, the newest checkpoint of each half the
// lifecycle gives the asset is restored, and each stream is read again from
// the later of its restart point and the cursor.

// EventBaselineConsumer is the C5 consumer that keeps the streams the
// feeder reads from being pruned past what its checkpoints cover.
const EventBaselineConsumer c5.ConsumerID = "node-eventbaseline"

// CheckpointEvery is how often, at most, a half that has changed is
// checkpointed while the node runs.
const CheckpointEvery = 15 * time.Minute

// FeedBudget is how long, in wall time, one scheduler pass may spend
// stepping the feeder, so a backlog never delays a collection run long.
const FeedBudget = 2 * time.Second

// StopCheckpointTimeout bounds the checkpoints written at a clean stop.
const StopCheckpointTimeout = 30 * time.Second

// ReasonNodeRestart is the gap reason of a node restart (C1 on #372).
const ReasonNodeRestart = "node.restart"

// checkpointRoom is the snapshot bound a checkpoint passes: the record cap
// less 64 KiB of headroom and the largest document (D4-38: 1,323,008 B).
const checkpointRoom = int(ConfigRecordBytes) - 64<<10 - MaxCheckpointDocBytes

// Status alarms of the runner, named by asset, or node-wide for a stream.
const (
	// AlarmEventBaselineCheckpoint: a half's checkpoint was not stored
	// (its snapshot did not fit, or the store refused it). The last one
	// stored stays, and the half is tried again at the next pass.
	AlarmEventBaselineCheckpoint = "event-baseline-checkpoint-not-stored"
	// AlarmEventBaselineNotStarted: the asset's checkpoints could not be
	// read at start, so no asset's events are fed until they can be: a half
	// started without its checkpoint would replace it (C1 on #387).
	AlarmEventBaselineNotStarted = "event-baseline-not-started"
	// AlarmEventBaselineStreamStuck: the feeder cannot read past a record
	// of a stream, so the assets that read it are held.
	AlarmEventBaselineStreamStuck = "event-baseline-stream-stuck"
	// AlarmEventBaselineCursor: EventBaselineConsumer's cursor was not
	// saved, so the stream is pruned less and no checkpoint is removed.
	AlarmEventBaselineCursor = "event-baseline-cursor-not-saved"
)

// Health types the runner writes.
const (
	// HealthEventBaselineCheckpointRefused: a half's checkpoint was not
	// stored. Details: asset_id, half, error.
	HealthEventBaselineCheckpointRefused = "eventbaseline.checkpoint-refused"
	// HealthEventBaselineCheckpointsRemoved: superseded checkpoints were
	// removed. Details: asset_id, series, records, bytes.
	HealthEventBaselineCheckpointsRemoved = "eventbaseline.checkpoints-removed"
	// HealthEventBaselineStreamStuck: the feeder cannot read past a record.
	// Details: stream, error.
	HealthEventBaselineStreamStuck = "eventbaseline.stream-stuck"
)

// eventBaselineConsumers adds EventBaselineConsumer to each stream the
// feeder reads that has a consumer already. A stream with none is never
// pruned (CodeNoConsumers), and the feeder's consumer must not make it
// prunable.
func eventBaselineConsumers(c *Config, cs []c5.Consumer) ([]c5.Consumer, error) {
	has := map[c5.StreamID]bool{}
	for _, x := range cs {
		has[x.Stream] = true
	}
	added := map[c5.StreamID]bool{}
	for _, e := range c.EventBaselines {
		ids, err := c.feedStreams(e.AssetID)
		if err != nil {
			return nil, err
		}
		for _, id := range ids {
			if has[id] && !added[id] {
				added[id] = true
				cs = append(cs, c5.Consumer{ID: EventBaselineConsumer, Stream: id, Delivery: c5.Required})
			}
		}
	}
	return cs, nil
}

// eventRun is the feeder, the lifecycle behind it, and their checkpoints.
// It is the feeder's sink, and passes each call to the lifecycle.
type eventRun struct {
	rt   *Runtime
	feed *eventFeed
	life *eventLife
	// ready: the checkpoints were restored (restore).
	ready bool
	// consumed: the streams with EventBaselineConsumer, and the cursor
	// saved on each.
	consumed map[c5.StreamID]bool
	saved    map[c5.StreamID]c5.Seq
	stuck    map[c5.StreamID]bool
	assets   map[string]*runAsset
	// quiet: the alarms raised for a condition not yet cleared.
	quiet map[string]bool
	// room is the snapshot bound, checkpointRoom; a test lowers it.
	room int
}

type runAsset struct {
	id string
	fa *feedAsset
	// gen counts the feeder's calls for the asset; a half whose checkpoint
	// was taken at another gen has changed since.
	gen    int64
	halves map[string]*runHalf
	// durable is the restart point in each stream that the asset's
	// checkpoints cover, or, while it has no half, where the feeder is.
	durable map[c5.StreamID]c5.Seq
	// series holds the seqs of the asset's committed checkpoints, oldest
	// first, by C5 series; remove those a newer one superseded.
	series map[string][]c5.Seq
	remove map[string][]c5.Seq
	// Counts for status.
	Written, Removed, Refused int64
}

type runHalf struct {
	ident string // the learner's version and previous, or the detector's baseline
	// gen and pos are the asset's gen and positions its checkpoint was
	// taken at, and last when.
	gen  int64
	pos  []checkpointStream
	last time.Time
}

// newEventRun builds the feeder and the lifecycle of the node's event
// baselines, and restores their checkpoints. nil when none is set.
func newEventRun(ctx context.Context, rt *Runtime) (*eventRun, error) {
	if len(rt.cfg.EventBaselines) == 0 {
		return nil, nil
	}
	life, err := newEventLife(ctx, rt)
	if err != nil {
		return nil, err
	}
	e := &eventRun{rt: rt, life: life, consumed: map[c5.StreamID]bool{}, saved: map[c5.StreamID]c5.Seq{},
		stuck: map[c5.StreamID]bool{}, assets: map[string]*runAsset{}, quiet: map[string]bool{}, room: checkpointRoom}
	reader := func(id c5.StreamID) streamReader {
		if db := rt.Store(id); db != nil {
			return db
		}
		return nil
	}
	if e.feed, err = newEventFeed(rt.cfg, reader, rt.opt.Now, e); err != nil {
		return nil, err
	}
	cs, err := rt.cfg.Consumers()
	if err != nil {
		return nil, err
	}
	if cs, err = eventBaselineConsumers(rt.cfg, cs); err != nil {
		return nil, err
	}
	for _, c := range cs {
		if c.ID == EventBaselineConsumer {
			e.consumed[c.Stream] = true
		}
	}
	for id, fa := range e.feed.assets {
		e.assets[id] = &runAsset{id: id, fa: fa, halves: map[string]*runHalf{}, durable: map[c5.StreamID]c5.Seq{},
			series: map[string][]c5.Seq{}, remove: map[string][]c5.Seq{}}
	}
	e.restore(ctx)
	return e, nil
}

// stepEvents steps the event-baseline feeder, when there is one.
func (s *Scheduler) stepEvents(ctx context.Context) {
	if s.events != nil {
		s.events.step(ctx)
	}
}

func (e *eventRun) touch(assetID string) {
	if ra := e.assets[assetID]; ra != nil {
		ra.gen++
	}
}

// Observe, Gap and Tick are feedSink's.
func (e *eventRun) Observe(assetID string, o eventbaseline.Obs) {
	e.touch(assetID)
	e.life.Observe(assetID, o)
}

func (e *eventRun) Gap(assetID string, from, to time.Time, reason string) {
	e.touch(assetID)
	e.life.Gap(assetID, from, to, reason)
}

func (e *eventRun) Tick(assetID string, at time.Time) {
	e.touch(assetID)
	e.life.Tick(assetID, at)
}

// step feeds what the streams hold, for at most FeedBudget, publishes the
// state, and checkpoints what is due.
func (e *eventRun) step(ctx context.Context) {
	if !e.ready && !e.restore(ctx) {
		return
	}
	end := time.Now().Add(FeedBudget)
	var err error
	for {
		before := e.read()
		err = e.feed.Step(ctx)
		if e.read() == before || time.Now().After(end) || ctx.Err() != nil {
			break
		}
	}
	e.stuckStreams()
	e.life.publish(e.feed, e.rt.opt.Now(), err)
	e.checkpoint(ctx, false)
	e.publish()
}

// stop checkpoints every half that has changed: the node is stopping.
func (e *eventRun) stop(ctx context.Context) {
	if e.ready {
		e.checkpoint(ctx, true)
		e.publish()
	}
}

// read is how far the feeder has read, summed over its streams.
func (e *eventRun) read() c5.Seq {
	var n c5.Seq
	for _, s := range e.feed.streams {
		n += s.after
	}
	return n
}

// stuckStreams raises, once until it clears, the alarm and the health
// record of each stream the feeder cannot read past (C6 on #365).
func (e *eventRun) stuckStreams() {
	for _, s := range e.feed.streams {
		switch {
		case s.err == nil:
			delete(e.stuck, s.id)
		case !e.stuck[s.id]:
			e.stuck[s.id] = true
			e.rt.opt.Status.Raise("", AlarmEventBaselineStreamStuck, fmt.Sprintf("the event-baseline feeder cannot read past a record of %s, so the assets that read it are held, and at %d events pending their other streams are not read either: %v", s.id, FeedHeldPending, s.err))
			if err := e.life.store(HealthEventBaselineStreamStuck, nil, map[string]string{"stream": string(s.id), "error": s.err.Error()}); err != nil {
				e.rt.opt.Status.Raise("", AlarmDepartureNotStored, HealthEventBaselineStreamStuck+": "+err.Error())
			}
		}
	}
}

// halves returns the halves the asset has now, by checkpoint half, with
// each one's identity and snapshot.
func (e *eventRun) halves(assetID string) map[string]halfNow {
	lr, d := e.life.half(assetID)
	out := map[string]halfNow{}
	a := e.life.assets[assetID]
	if lr != nil {
		out[CheckpointLearner] = halfNow{ident: fmt.Sprintf("%d %s", a.version, a.previous), snapshot: lr.Snapshot,
			doc: func(c *eventCheckpoint) { c.Version, c.Previous = int64(a.version), a.previous }}
	}
	if d != nil {
		out[CheckpointDetector] = halfNow{ident: a.active, snapshot: d.Snapshot, doc: func(c *eventCheckpoint) { c.Baseline = a.active }}
	}
	return out
}

type halfNow struct {
	ident    string
	snapshot func(maxBytes int) ([]byte, error)
	doc      func(*eventCheckpoint)
}

func seriesOf(half string) string {
	if half == CheckpointDetector {
		return c5.SeriesCheckpointDetector
	}
	return c5.SeriesCheckpointLearner
}

// checkpoint writes each due half's checkpoint, then saves the cursors,
// then removes the checkpoints superseded. final: every changed half is
// due.
func (e *eventRun) checkpoint(ctx context.Context, final bool) {
	now := e.rt.opt.Now()
	for _, id := range slices.Sorted(maps.Keys(e.assets)) {
		ra := e.assets[id]
		hs := e.halves(id)
		pos := e.feed.positions(ra.fa)
		if len(hs) == 0 {
			ra.halves = map[string]*runHalf{}
			ra.setDurable(pos)
			continue
		}
		all := true
		for _, half := range slices.Sorted(maps.Keys(hs)) {
			h := hs[half]
			st := ra.halves[half]
			changed := st == nil || st.ident != h.ident
			switch {
			case !changed && st.gen == ra.gen && slices.Equal(st.pos, pos):
				// Nothing since its checkpoint.
				continue
			case ra.fa.wm.IsZero(), !final && !changed && now.Sub(st.last) < CheckpointEvery:
				all = false
				continue
			}
			if err := e.write(ctx, ra, half, h, pos); err != nil {
				all = false
				ra.Refused++
				e.refusedCheckpoint(ra, half, err)
				continue
			}
			ra.halves[half] = &runHalf{ident: h.ident, gen: ra.gen, pos: pos, last: now}
		}
		for half := range ra.halves {
			if _, ok := hs[half]; !ok {
				delete(ra.halves, half)
			}
		}
		if all {
			ra.setDurable(pos)
			if a := e.life.assets[id]; a != nil {
				a.clear(AlarmEventBaselineCheckpoint)
			}
		}
	}
	if e.saveCursors(ctx) {
		e.removeSuperseded(ctx)
	}
}

func (ra *runAsset) setDurable(pos []checkpointStream) {
	for _, p := range pos {
		ra.durable[c5.StreamID(p.Stream)] = c5.Seq(p.RestartAfter)
	}
}

// write stores one half's checkpoint: its snapshot as the record's capture,
// raw (D4-38), and the feeder's state for the asset in the document.
func (e *eventRun) write(ctx context.Context, ra *runAsset, half string, h halfNow, pos []checkpointStream) error {
	snap, err := h.snapshot(e.room)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(snap)
	fa := ra.fa
	c := eventCheckpoint{Schema: EventCheckpointSchema, Half: half, AssetID: ra.id, Watermark: fa.wm.UTC().Format(time.RFC3339Nano),
		Streams: pos, PrevKeys: fa.prevKeys(), Late: fa.Late, Snapshot: checkpointSnapshot{SHA256: hex.EncodeToString(sum[:]), Length: int64(len(snap))}}
	h.doc(&c)
	if !fa.failedAt.IsZero() {
		c.Gap = &checkpointGap{From: fa.failedAt.UTC().Format(time.RFC3339Nano), Reason: fa.failReason}
	}
	if !fa.lastEnd.IsZero() {
		c.LastGapEnd = fa.lastEnd.UTC().Format(time.RFC3339Nano)
	}
	b, err := encodeCheckpoint(c)
	if err != nil {
		return err
	}
	stream := ConfigStream(ra.id)
	_, log, mode := e.rt.view(e.rt.dbFor(stream))
	if log == nil || !mode.AcceptsEvents() {
		return fmt.Errorf("configuration database %s", e.rt.Mode(ConfigDB))
	}
	// AppendBatch: an error is never a record that committed anyway.
	got, err := log.AppendBatch(ctx, []c5.Record{{Stream: stream, Class: c5.ClassConfiguration, Event: b,
		Capture: &c5.Capture{SHA256: c.Snapshot.SHA256, Bytes: snap}}})
	if err != nil {
		return err
	}
	ra.Written++
	series := seriesOf(half)
	ra.remove[series] = append(ra.remove[series], ra.series[series]...)
	ra.series[series] = []c5.Seq{got[0].Key().Seq}
	return nil
}

func (e *eventRun) refusedCheckpoint(ra *runAsset, half string, err error) {
	a := e.life.assets[ra.id]
	if a == nil || a.raised[AlarmEventBaselineCheckpoint] {
		return
	}
	e.life.raise(a, AlarmEventBaselineCheckpoint, fmt.Sprintf("the %s's checkpoint was not stored, so the last one stored stays and a restart resumes from it: %v", half, err))
	e.life.health(a, HealthEventBaselineCheckpointRefused, map[string]string{"asset_id": ra.id, "half": half, "error": err.Error()})
}

// saveCursors moves EventBaselineConsumer's cursor on each stream to the
// lowest durable restart point of the assets that read it. It reports
// whether every cursor that had to move was saved.
func (e *eventRun) saveCursors(ctx context.Context) bool {
	ok := true
	for _, s := range e.feed.streams {
		if !e.consumed[s.id] {
			continue
		}
		var through c5.Seq
		for i, fa := range s.assets {
			if p := e.assets[fa.id].durable[s.id]; i == 0 || p < through {
				through = p
			}
		}
		if through <= e.saved[s.id] {
			continue
		}
		db := e.rt.Store(s.id)
		err := errors.New("database not open")
		if db != nil {
			err = db.SaveCursor(ctx, c5.Cursor{Consumer: EventBaselineConsumer, Stream: s.id, Through: through})
		}
		if err != nil {
			ok = false
			e.raiseOnce("cursor "+string(s.id), "", AlarmEventBaselineCursor, fmt.Sprintf("the %s cursor on %s was not saved, so the stream is pruned less and no checkpoint is removed: %v", EventBaselineConsumer, s.id, err))
			continue
		}
		delete(e.quiet, "cursor "+string(s.id))
		e.saved[s.id] = through
	}
	return ok
}

// removeSuperseded removes the checkpoints a newer one of the same half and
// asset superseded, now that the cursor is saved after it (D4-32 item 2,
// D4-36 item 2), in steps of at most c5.RemoveConfigStep.
func (e *eventRun) removeSuperseded(ctx context.Context) {
	for _, id := range slices.Sorted(maps.Keys(e.assets)) {
		ra := e.assets[id]
		for _, series := range slices.Sorted(maps.Keys(ra.remove)) {
			seqs := ra.remove[series]
			if len(seqs) == 0 {
				continue
			}
			seqs = seqs[:min(len(seqs), c5.RemoveConfigStep)]
			stream := ConfigStream(id)
			db := e.rt.Store(stream)
			if db == nil {
				return
			}
			got, err := db.RemoveConfig(ctx, stream, series, seqs)
			key := "remove " + id + " " + series
			if err != nil {
				e.raiseOnce(key, id, AlarmEventBaselineCheckpoint, fmt.Sprintf("superseded checkpoints %v of %s not removed, so they stay in the configuration class: %v", seqs, series, err))
				continue
			}
			delete(e.quiet, key)
			a := e.life.assets[id]
			ra.remove[series] = ra.remove[series][len(seqs):]
			if got.Records > 0 {
				ra.Removed += int64(got.Records)
				if a != nil {
					e.life.health(a, HealthEventBaselineCheckpointsRemoved, map[string]string{"asset_id": id, "series": series,
						"records": strconv.Itoa(got.Records), "bytes": strconv.FormatInt(got.Bytes, 10)})
				}
			}
		}
	}
}

// raiseOnce raises code until the condition named k clears.
func (e *eventRun) raiseOnce(k, assetID, code, detail string) {
	if !e.quiet[k] {
		e.quiet[k] = true
		e.rt.opt.Status.Raise(assetID, code, detail)
	}
}

// EventCheckpointStatus is an observed asset's checkpoints as node status
// shows them: how many were stored, removed once superseded, and refused, in
// this process.
type EventCheckpointStatus struct {
	Written int64 `json:"written"`
	Removed int64 `json:"removed"`
	Refused int64 `json:"refused"`
}

func (e *eventRun) publish() {
	m := map[string]EventCheckpointStatus{}
	for id, ra := range e.assets {
		m[id] = EventCheckpointStatus{Written: ra.Written, Removed: ra.Removed, Refused: ra.Refused}
	}
	e.rt.opt.Status.SetEventCheckpoints(m)
}

// storedCheckpoint is one checkpoint record found at start.
type storedCheckpoint struct {
	st   c5.Stored
	half string // "" when the document does not say
}

// checkpoints lists the asset's checkpoint records, in commit order. Only
// the half is read from each, so the newest is chosen without decoding it
// (D4-36 item 2).
func (e *eventRun) checkpoints(ctx context.Context, assetID string) ([]storedCheckpoint, error) {
	stream := ConfigStream(assetID)
	db := e.rt.Store(stream)
	if db == nil {
		return nil, errors.New("the configuration database is not open")
	}
	var out []storedCheckpoint
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
			if !bytes.HasPrefix(st.Event, []byte(`{"schema":"otsec.eventcheckpoint/`)) {
				continue
			}
			var head struct {
				Half string `json:"half"`
			}
			sc := storedCheckpoint{st: st}
			if json.Unmarshal(st.Event, &head) == nil && (head.Half == CheckpointLearner || head.Half == CheckpointDetector) {
				sc.half = head.Half
			}
			out = append(out, sc)
		}
	}
}

// checkpointPick is the newest checkpoint of one half, read at start.
type checkpointPick struct {
	sc   storedCheckpoint
	doc  *eventCheckpoint // nil when it does not decode
	snap []byte
	// reason and err: why it cannot be restored before the half sees it
	// (config.checkpoint_not_restored's reason code), "" when it can.
	reason string
	err    error
}

// restore restores, for each asset, the newest checkpoint of each half the
// lifecycle gives it, and sets the feeder's positions. A read that does not
// complete restores nothing: no asset is fed, the alarm says why, and the
// next pass tries again (C1 on #387).
func (e *eventRun) restore(ctx context.Context) bool {
	cursor := map[c5.StreamID]c5.Seq{}
	for id := range e.consumed {
		db := e.rt.Store(id)
		if db == nil {
			e.notStarted(fmt.Errorf("the database of %s is not open", id))
			return false
		}
		cs, err := db.LoadCursors(ctx, id)
		if err != nil {
			e.notStarted(fmt.Errorf("the cursors of %s: %w", id, err))
			return false
		}
		for _, c := range cs {
			if c.Consumer == EventBaselineConsumer {
				cursor[id] = c.Through
			}
		}
	}
	// Read every newest checkpoint before anything is restored, so a read
	// that fails part-way changes nothing.
	lists := map[string][]storedCheckpoint{}
	picks := map[string]map[string]*checkpointPick{}
	for _, id := range slices.Sorted(maps.Keys(e.assets)) {
		list, err := e.checkpoints(ctx, id)
		if err != nil {
			e.notStarted(fmt.Errorf("the checkpoints of %s: %w", id, err))
			return false
		}
		lists[id], picks[id] = list, map[string]*checkpointPick{}
		for half := range e.halves(id) {
			var newest *storedCheckpoint
			for i, sc := range list {
				if sc.half == half || sc.half == "" {
					newest = &list[i]
				}
			}
			if newest == nil {
				continue
			}
			p, err := e.readCheckpoint(ctx, id, half, *newest)
			if err != nil {
				e.notStarted(fmt.Errorf("checkpoint %d of %s: %w", newest.st.Key.Seq, id, err))
				return false
			}
			if !e.stale(id, half, p) {
				picks[id][half] = p
			}
		}
	}
	now := e.rt.opt.Now()
	for _, id := range slices.Sorted(maps.Keys(e.assets)) {
		ra := e.assets[id]
		for _, sc := range lists[id] {
			if sc.half != "" {
				ra.series[seriesOf(sc.half)] = append(ra.series[seriesOf(sc.half)], sc.st.Key.Seq)
			}
		}
		// Every checkpoint but the newest of its series is removable once
		// this process has saved the cursor after the newest's commit.
		for series, seqs := range ra.series {
			if n := len(seqs); n > 1 {
				ra.remove[series], ra.series[series] = slices.Clone(seqs[:n-1]), seqs[n-1:]
			}
		}
		e.restoreAsset(ctx, ra, picks[id], cursor, now)
	}
	e.feed.start()
	for _, id := range slices.Sorted(maps.Keys(e.assets)) {
		ra := e.assets[id]
		for _, s := range ra.fa.streams {
			ra.durable[s.id] = c5.Seq(ra.fa.skip[s.id].RestartAfter)
		}
		for _, h := range ra.halves {
			h.pos = e.feed.positions(ra.fa)
		}
		e.feed.restarted(ra.fa, now)
		if a := e.life.assets[id]; a != nil {
			a.clear(AlarmEventBaselineNotStarted)
		}
	}
	e.saved = cursor
	e.ready = true
	return true
}

// restoreAsset restores one asset's halves and its feeder state. The
// positions come from the newest checkpoint that decodes, of either half;
// with none, from the cursor.
func (e *eventRun) restoreAsset(ctx context.Context, ra *runAsset, picks map[string]*checkpointPick, cursor map[c5.StreamID]c5.Seq, now time.Time) {
	var doc *eventCheckpoint
	var docSeq c5.Seq
	for _, p := range picks {
		if p.doc != nil && p.sc.st.Key.Seq > docSeq {
			doc, docSeq = p.doc, p.sc.st.Key.Seq
		}
	}
	// The restart's watermark: where the checkpoint's feeder was, or, with
	// none, where it is first bound after the start.
	wm := now.Add(-FeedLateness)
	if doc != nil {
		if t, err := time.Parse(time.RFC3339Nano, doc.Watermark); err == nil {
			wm = t
		}
	}
	snaps := map[string][]byte{}
	for half, p := range picks {
		snaps[half] = p.snap
		if p.reason == "" {
			continue
		}
		then := "it starts again"
		snaps[half] = nil
		if half == CheckpointDetector {
			then = fmt.Sprintf("it is rebuilt from the acknowledged baseline, watching from %s, so its alarms differ from those the lost state would have raised: new types seen before alarm again, and the holds open then start again (D4-36)", wm.UTC().Format(time.RFC3339Nano))
			snaps[half] = []byte{} // not a snapshot, so the detector is rebuilt from wm
		}
		if a := e.life.assets[ra.id]; a != nil {
			e.life.raise(a, AlarmEventBaselineNotRestored, fmt.Sprintf("%s: checkpoint %d: %v; %s", half, p.sc.st.Key.Seq, p.err, then))
		}
	}
	lerr, derr := e.life.restore(ra.id, snaps[CheckpointLearner], snaps[CheckpointDetector], wm)
	errs := map[string]error{CheckpointLearner: lerr, CheckpointDetector: derr}
	now2 := e.halves(ra.id)
	for _, half := range slices.Sorted(maps.Keys(picks)) {
		p := picks[half]
		if p.reason == "" && errs[half] != nil {
			p.reason = restoreReason(errs[half])
		}
		if p.reason != "" {
			e.auditNotRestored(ctx, ra.id, half, p.sc.st.Key.Seq, p.reason)
		}
	}
	// A detector raises again what it raised after its checkpoint, before
	// the restart; those alarms are stored already.
	if a := e.life.assets[ra.id]; a != nil && a.detector != nil {
		switch p := picks[CheckpointDetector]; {
		case p != nil && p.doc != nil:
			e.repeatsSince(ctx, a, p.sc.st.CommittedAt)
		case !a.fromHold:
			e.repeatsSince(ctx, a, a.activeFrom)
		}
	}
	if err := e.feed.resume(ra.fa, doc, cursor); err != nil {
		_ = e.feed.resume(ra.fa, nil, cursor) // checked at decode; a guard
	}
	ra.halves = map[string]*runHalf{}
	for half, hn := range now2 {
		if p := picks[half]; p != nil && p.reason == "" {
			// Restored: its checkpoint covers it until it changes.
			ra.halves[half] = &runHalf{ident: hn.ident, gen: ra.gen, last: now}
		}
	}
}

func (e *eventRun) notStarted(err error) {
	for _, id := range slices.Sorted(maps.Keys(e.life.assets)) {
		e.life.raise(e.life.assets[id], AlarmEventBaselineNotStarted, "no event baseline is fed until its checkpoints are read, so none is started without its state: "+err.Error())
	}
}

// readCheckpoint reads one stored checkpoint of the half: its document and
// its snapshot. A record that is not a checkpoint this node restores comes
// back with its reason; an error is a read that did not complete.
func (e *eventRun) readCheckpoint(ctx context.Context, assetID, half string, sc storedCheckpoint) (*checkpointPick, error) {
	p := &checkpointPick{sc: sc}
	bad := func(reason string, err error) (*checkpointPick, error) {
		p.doc, p.snap, p.reason, p.err = nil, nil, reason, err
		return p, nil
	}
	if !bytes.HasPrefix(sc.st.Event, []byte(`{"schema":"`+EventCheckpointSchema+`"`)) {
		return bad(audit.ReasonCheckpointVersion, errors.New("the checkpoint's schema is not "+EventCheckpointSchema))
	}
	c, err := decodeCheckpoint(sc.st.Event)
	switch {
	case err != nil:
		return bad(audit.ReasonCheckpointCorrupt, err)
	case c.Half != half:
		return bad(audit.ReasonCheckpointCorrupt, fmt.Errorf("the record is a %s checkpoint", c.Half))
	case c.AssetID != assetID:
		return bad(audit.ReasonCheckpointMismatch, fmt.Errorf("the checkpoint is of asset %s", c.AssetID))
	case sc.st.EvidenceRef == "":
		return bad(audit.ReasonCheckpointCorrupt, errors.New("the checkpoint has no capture"))
	}
	db := e.rt.Store(ConfigStream(assetID))
	if db == nil {
		return nil, errors.New("the configuration database is not open")
	}
	cp, err := db.ReadCapture(ctx, sc.st.EvidenceRef)
	switch {
	case errors.Is(err, &c5.Error{Code: c5.CodeInvalid}):
		return bad(audit.ReasonCheckpointCorrupt, err)
	case err != nil:
		return nil, err
	case cp.SHA256 != c.Snapshot.SHA256 || int64(len(cp.Bytes)) != c.Snapshot.Length:
		return bad(audit.ReasonCheckpointCorrupt, errors.New("the capture is not the snapshot the checkpoint names"))
	}
	p.doc, p.snap = &c, cp.Bytes
	return p, nil
}

// stale reports whether the half's newest checkpoint is an earlier half's,
// which is not restored and not reported (D4-32 item 2): a learner of an
// earlier version, or a detector checkpointed before the acknowledgement
// that activated the asset's baseline. A detector whose baseline came from
// a hold has no acknowledgement time, and D4-41's bounds decide instead.
func (e *eventRun) stale(assetID, half string, p *checkpointPick) bool {
	a := e.life.assets[assetID]
	if p.doc == nil || a == nil {
		return false
	}
	if half == CheckpointLearner {
		return p.doc.Version < int64(a.version)
	}
	return !a.fromHold && p.sc.st.CommittedAt.Before(a.activeFrom)
}

// restoreReason is config.checkpoint_not_restored's reason code for a half
// that did not take its snapshot.
func restoreReason(err error) string {
	switch {
	case errors.Is(err, eventbaseline.ErrSnapshotVersion):
		return audit.ReasonCheckpointVersion
	case errors.Is(err, eventbaseline.ErrSnapshotMismatch):
		return audit.ReasonCheckpointMismatch
	case errors.Is(err, eventbaseline.ErrSnapshot):
		return audit.ReasonCheckpointCorrupt
	}
	return audit.ReasonCheckpointRefused
}

// auditNotRestored writes config.checkpoint_not_restored (C8 0.9, D4-32):
// for a learner, the re-learn it starts; for a detector, the acknowledged
// baseline it is rebuilt from. A record not written is alarmed; the next
// start finds the same checkpoint and writes it then, unless a newer one
// has superseded it.
func (e *eventRun) auditNotRestored(ctx context.Context, assetID, half string, seq c5.Seq, reason string) {
	a := e.life.assets[assetID]
	if a == nil {
		return
	}
	c := &audit.Config{Kind: authz.BaselineEvent, CheckpointHalf: half, CheckpointSeq: uint64(seq)}
	if half == CheckpointDetector {
		if a.detector == nil {
			return // not rebuilt; its alarm says so
		}
		c.BaselineDigest = a.active
	} else {
		v, prev, ok := e.life.relearning(assetID)
		if !ok {
			return
		}
		c.BaselineVersion, c.PreviousDigest = v, prev
	}
	rec := audit.Record{Contract: audit.ContractID, NodeID: string(e.rt.cfg.NodeID), Time: e.rt.received(),
		Actor:  audit.Actor{Type: authz.PrincipalNode, ID: string(e.rt.cfg.NodeID)},
		Action: audit.ActionConfigCheckpointNotRestored, Outcome: audit.OutcomeWarning, ReasonCode: reason,
		Target: &audit.Target{AssetID: assetID}, CorrelationID: audit.CheckpointCorrelationID(half, uint64(seq)), Config: c}
	err := e.appendAudit(ctx, rec)
	if err != nil {
		e.life.raise(a, AlarmEventBaselineNotRestored, fmt.Sprintf("%s: checkpoint %d did not restore (%s), and config.checkpoint_not_restored was not written: %v", half, seq, reason, err))
	}
}

func (e *eventRun) appendAudit(ctx context.Context, rec audit.Record) error {
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	if _, err := audit.ValidatePending(b); err != nil {
		return err
	}
	_, log, mode := e.rt.view(e.rt.find(AuditDB))
	if log == nil || !mode.AcceptsEvents() {
		return fmt.Errorf("audit database %s", e.rt.Mode(AuditDB))
	}
	_, err = log.AppendBatch(ctx, []c5.Record{{Stream: AuditStream, Class: c5.ClassAudit, Event: b}})
	return err
}

// alarmKey is a departure alarm's identity across a replay: its asset,
// baseline, rule, key and time (the package doc of eventbaseline).
func alarmKey(assetID, baselineHash, rule, key, at string) string {
	return strings.Join([]string{assetID, baselineHash, rule, key, at}, "\x00")
}

// repeatsSince reads the departure alarms of the asset's active baseline
// stored in platform/health after since, so the restored detector does not
// store them a second time when it raises them again.
func (e *eventRun) repeatsSince(ctx context.Context, a *lifeAsset, since time.Time) {
	db := e.rt.Store(HealthStream)
	if db == nil {
		return
	}
	after, err := db.LastCommittedBy(ctx, HealthStream, since)
	for err == nil {
		var got []c5.Stored
		if got, err = db.Read(ctx, HealthStream, after, 500); err != nil || len(got) == 0 {
			break
		}
		for _, st := range got {
			after = st.Key.Seq
			ev, derr := event.Decode(st.Event)
			if derr != nil || ev.Health == nil || ev.Health.Type != baseline.HealthDeparture {
				continue
			}
			d := ev.Health.Details
			if d["asset_id"] == a.id && d["baseline"] == a.active {
				if e.life.repeats == nil {
					e.life.repeats = map[string]bool{}
				}
				e.life.repeats[alarmKey(a.id, a.active, d["rule"], d["key"], d["at_utc"])] = true
			}
		}
	}
	if err != nil {
		e.life.raise(a, AlarmEventBaselineNotRestored, "the alarms stored before the restart were not read, so the detector may store some of them again: "+err.Error())
	}
}

// repeated reports whether al was stored before the restart (repeatsSince),
// and forgets it: an alarm is raised once.
func (l *eventLife) repeated(al *baseline.Alarm) bool {
	k := alarmKey(al.AssetID, al.Baseline, string(al.Rule), al.Key.String(), al.AtUTC)
	if !l.repeats[k] {
		return false
	}
	delete(l.repeats, k)
	return true
}
