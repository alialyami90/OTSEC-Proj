package node

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"time"

	"otsec.local/otsec/contracts/adapter"
	"otsec.local/otsec/contracts/baseline"
	"otsec.local/otsec/contracts/event"
	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/modules/detection/eventbaseline"
	"otsec.local/otsec/modules/telemetry/normalize"
	"otsec.local/otsec/modules/telemetry/receive"
)

// FeedLateness is how long after its received time an event may still
// commit and be fed in received order (feeder slice 1b,
// docs/phase4/B5-event-baseline-feeder.md). The feeder passes an asset's
// events only up to its watermark, which never comes closer than this to
// the node's clock, so an event that waits in a listener's queue or behind a
// slow commit is still fed in its place. F-016 measured commit stalls of up
// to 37.9 s on hosted Windows; a Syslog message can also wait for the batch
// before it. The cost is that a departure is alarmed this much later.
//
// An event that commits later than this after its received time, or one
// stamped before a backward step of the node's clock, arrives behind the
// watermark. It is not fed (the learner and detector take events in
// received order only), it stays stored and forwarded like any other, and
// the feeder counts it as late for the asset.
const FeedLateness = 2 * time.Minute

// FeedBatch is how many records the feeder reads from a stream at a time.
// It is at least one SER read, so a read's rows are taken together.
const FeedBatch = EvidenceBatchRecords + 1

// streamReader reads a stream's committed records; *store.DB is one.
type streamReader interface {
	Read(ctx context.Context, stream c5.StreamID, after c5.Seq, max int) ([]c5.Stored, error)
}

// feedSink takes what the feeder passes on for one asset: its events in
// received order, the collection gaps, and the watermark as the clock.
// Feeder slices 1c and 1d put the learner and the detector behind it.
//
// A gap is passed when it closes, and the watermark does not wait for that,
// so Observe and Tick also carry the start of the asset's gap still open
// (zero when none is): from it on, nothing is collected until the gap
// closes, so the learner can tell where its period ends from its input
// alone (D4-45).
type feedSink interface {
	Observe(assetID string, o eventbaseline.Obs, open time.Time)
	Gap(assetID string, from, to time.Time, reason string)
	Tick(assetID string, at, open time.Time)
}

// eventFeed reads the streams that carry the observed assets' events and
// passes each asset's events to the sink in received order.
//
// Received order across streams: an asset's SER stream and the listener
// streams that can hold its Syslog are read once each, and their events are
// merged by received time (ties by stream, then seq). An event is passed
// only when it is no later than the asset's watermark, the least of its
// streams' bounds:
//   - a stream read to its end: the feeder's clock at the start of the step
//     minus FeedLateness, since anything committed after that has a received
//     time no earlier than that (FeedLateness's assumption);
//   - a stream with more to read: the commit time of the last record read
//     minus FeedLateness, since a later record committed after it;
//   - a stream whose last SER read is not yet all read: before that read.
//
// The watermark never goes back, and it is passed to Tick, so a detector's
// time comes from the events and the bound and not from when the feeder
// happened to run: an Observe delayed past a tick changes nothing (#303).
//
// AfterFailure: a failed SER collection of the asset (a collection.run
// whose status is not ok or partial, a run that failed before an outcome, or
// a series of slots that stored nothing, collection.missed) opens a gap at its received time, or at the watermark when it arrives
// late, so gaps stay in order. The next successful SER read closes it: the
// sink gets Gap, and that read's rows are AfterFailure.
//
// NotCounted: the rows of one SER read are taken together (they share an
// invocation and a received time, and the last carries the read's alignment
// state as its SourceCursor), and baseline.PossibleDuplicates is applied
// over the previous read's state. A read that stored no rows saves its
// state without an event, so the feeder does not see it; the next read is
// then compared with the older state.
//
// Positions are kept in each half's checkpoint (eventbaselines_run.go,
// slice 1c): positions gives an asset's, and resume restores them.
//
// A stream that cannot be read past (its read fails, or a record does not
// decode) holds every asset that reads it. A stream whose assets are all
// held is not read, and neither is any stream of a held asset whose pending
// events reach FeedHeldPending: the feeder then waits, failing closed,
// rather than hold more or drop any (C6 on #365). The stuck stream itself is
// read again at every Step, so it is taken up again once it can be.
type eventFeed struct {
	now     func() time.Time
	reader  func(c5.StreamID) streamReader
	sink    feedSink
	streams []*feedStream
	assets  map[string]*feedAsset
	batch   int // FeedBatch; smaller in tests

	// Unresolved counts Syslog events whose sender is not an asset: they
	// belong to no baseline (C10's site-level count).
	Unresolved int64
}

type feedStream struct {
	id     c5.StreamID
	health bool
	assets []*feedAsset // the assets that read it
	after  c5.Seq
	// err is why the last read did not get past a record, nil when it did.
	err error
	// bound is the stream's part of the watermark after the last step.
	bound time.Time
	// Skipped counts records pruned before the feeder read them.
	Skipped int64
}

type feedAsset struct {
	id      string
	streams []*feedStream
	pending []feedItem // read, not yet passed
	// open is the SER read being taken: rows read, its last not yet.
	open []feedItem
	wm   time.Time
	prev []string // the previous SER read's alignment state

	failedAt   time.Time // a gap is open since then, if not zero
	failReason string
	lastEnd    time.Time // where the last gap sent ended

	// Late counts events that arrived behind the watermark (FeedLateness).
	Late int64

	// skip is, per stream, the position resume restored: a record at or
	// before RestartAfter, or at or before ReadThrough and received at or
	// before the watermark, was taken before the restart (slice 1c).
	skip map[c5.StreamID]checkpointStream
}

type feedItem struct {
	stream c5.StreamID
	seq    c5.Seq
	at     time.Time
	ev     *event.Event
	// The SER rows of one read are passed together with these.
	afterFailure, notCounted bool
	// gap, on a health item, is a collection outcome: fail opens a gap,
	// ok closes one.
	fail, ok bool
	reason   string
	// from, on a collection.missed, is when its series began: the record
	// is written once the health stream takes it, which can be long after.
	from time.Time
	// prev, on the first row of a SER read, is the alignment state its
	// rows were compared with, so a checkpoint taken while the read is
	// pending restarts with it (slice 1c).
	prev []string
}

// health is 1 for a collection outcome and 0 for an event of the asset.
func (it feedItem) health() int {
	if it.fail || it.ok {
		return 1
	}
	return 0
}

// newEventFeed builds the feeder for c's event baselines. An asset's
// streams are its SER stream and the health stream, when the schedule
// reads its SER, and the stream of every listener that takes Syslog from
// one of its endpoints.
func newEventFeed(c *Config, reader func(c5.StreamID) streamReader, now func() time.Time, sink feedSink) (*eventFeed, error) {
	f := &eventFeed{now: now, reader: reader, sink: sink, assets: map[string]*feedAsset{}, batch: FeedBatch}
	byID := map[c5.StreamID]*feedStream{}
	stream := func(id c5.StreamID) *feedStream {
		s, ok := byID[id]
		if !ok {
			s = &feedStream{id: id, health: id == HealthStream}
			byID[id] = s
			f.streams = append(f.streams, s)
		}
		return s
	}
	for _, e := range c.EventBaselines {
		a := &feedAsset{id: e.AssetID}
		f.assets[e.AssetID] = a
		ids, err := c.feedStreams(e.AssetID)
		if err != nil {
			return nil, err
		}
		for _, id := range ids {
			s := stream(id)
			a.streams = append(a.streams, s)
			s.assets = append(s.assets, a)
		}
	}
	return f, nil
}

// feedStreams are the streams the feeder reads for an asset: its SER
// stream and the health stream, when the schedule reads its SER, and the
// stream of every listener that takes Syslog from one of its endpoints.
// checkEventBaselines holds their number to eventbaseline.MaxStreams at
// load, so a checkpoint of the asset can always name them all.
func (c *Config) feedStreams(assetID string) ([]c5.StreamID, error) {
	var out []c5.StreamID
	for _, s := range c.Schedule {
		if s.AssetID == assetID && serReadOperation(s.Operation) {
			out = append(out, SERStream(assetID), HealthStream)
			break
		}
	}
	for _, l := range c.Listeners {
		ap, err := netip.ParseAddrPort(l.Address)
		if err != nil {
			return nil, fmt.Errorf("listener %s: address %q: %w", l.ID, l.Address, err)
		}
		senders, err := receive.SendersFor(c.assets, l.Transport, int(ap.Port()))
		if err != nil {
			return nil, fmt.Errorf("listener %s: %w", l.ID, err)
		}
		for _, src := range senders {
			if src.AssetID == assetID {
				out = append(out, ListenerStream(l.ID))
				break
			}
		}
	}
	return out, nil
}

// Step reads what the streams hold, up to FeedBatch records each, and
// passes each asset's events up to its watermark.
//
// A record the feeder cannot take (its event or its alignment state does
// not decode) stops its stream there and fails closed: the stream does not
// move past it and its bound does not rise, so the assets that read it are
// held, every Step returns the error, and nothing is discarded. The other
// streams, and the assets that do not read the stream, go on, except as
// blocked says.
func (f *eventFeed) Step(ctx context.Context) error {
	now := f.now()
	var errs []error
	for _, s := range f.streams {
		if s.err == nil && f.blocked(s) {
			continue
		}
		s.err = f.read(ctx, s, now)
		if s.err != nil {
			errs = append(errs, s.err)
		}
	}
	for _, id := range slices.Sorted(maps.Keys(f.assets)) {
		f.pass(f.assets[id])
	}
	return errors.Join(errs...)
}

// FeedHeldPending is how many events a held asset (one that reads a stuck
// stream) may have read and not passed before the feeder stops reading its
// other streams too.
const FeedHeldPending = 4 * FeedBatch

// held reports whether the asset reads a stream the feeder is stuck on.
func (a *feedAsset) held() bool {
	for _, s := range a.streams {
		if s.err != nil {
			return true
		}
	}
	return false
}

// blocked reports whether a stream that can be read is not read this Step:
// every asset that reads it is held, or one of them has FeedHeldPending
// events pending.
func (f *eventFeed) blocked(s *feedStream) bool {
	all := true
	for _, a := range s.assets {
		h := a.held()
		if h && len(a.pending)+len(a.open) >= FeedHeldPending {
			return true
		}
		all = all && h
	}
	return all
}

func (f *eventFeed) read(ctx context.Context, s *feedStream, now time.Time) error {
	r := f.reader(s.id)
	if r == nil {
		return fmt.Errorf("stream %s: database not open", s.id)
	}
	recs, err := r.Read(ctx, s.id, s.after, f.batch)
	if err != nil {
		return fmt.Errorf("stream %s: %w", s.id, err)
	}
	for _, rec := range recs {
		// The position moves only once the record is taken; take changes
		// nothing when it fails.
		var ev event.Event
		if err := json.Unmarshal(rec.Event, &ev); err != nil {
			return fmt.Errorf("stream %s seq %d: %w", s.id, rec.Key.Seq, err)
		}
		at, err := time.Parse(time.RFC3339Nano, ev.Received.UTC)
		if err != nil {
			return fmt.Errorf("stream %s seq %d: received.utc: %w", s.id, rec.Key.Seq, err)
		}
		if err := f.take(s, rec, &ev, at); err != nil {
			return fmt.Errorf("stream %s seq %d: %w", s.id, rec.Key.Seq, err)
		}
		if rec.Key.Seq > s.after+1 {
			s.Skipped += int64(rec.Key.Seq - s.after - 1)
		}
		s.after = rec.Key.Seq
	}
	if len(recs) < f.batch {
		s.bound = now.Add(-FeedLateness)
	} else {
		s.bound = recs[len(recs)-1].CommittedAt.Add(-FeedLateness)
	}
	return nil
}

// take routes one record to its asset.
func (f *eventFeed) take(s *feedStream, rec c5.Stored, ev *event.Event, at time.Time) error {
	it := feedItem{stream: s.id, seq: rec.Key.Seq, at: at, ev: ev}
	if s.health {
		f.takeHealth(it)
		return nil
	}
	if ev.Source.Asset == nil {
		f.Unresolved++
		return nil
	}
	a, ok := f.assets[ev.Source.Asset.ID]
	if !ok || a.taken(it) {
		return nil
	}
	if ev.Kind != event.KindSER {
		a.pending = append(a.pending, it)
		return nil
	}
	// Decode the read's state before anything changes, so a row that fails
	// here is taken whole when it is read again.
	var keys []string
	if rec.SourceCursor != nil {
		var err error
		if keys, err = normalize.DecodeState(rec.SourceCursor); err != nil {
			return fmt.Errorf("alignment state: %w", err)
		}
	}
	if n := len(a.open); n > 0 && !sameRead(a.open[n-1], it) {
		closeRead(a)
	}
	a.open = append(a.open, it)
	if rec.SourceCursor != nil {
		closeRead(a)
		a.prev = keys
	}
	return nil
}

// sameRead reports whether two SER rows come from one read.
func sameRead(x, y feedItem) bool {
	ix, iy := "", ""
	if x.ev.Collection != nil {
		ix = x.ev.Collection.InvocationID
	}
	if y.ev.Collection != nil {
		iy = y.ev.Collection.InvocationID
	}
	return ix == iy && x.at.Equal(y.at)
}

// closeRead marks the open read's rows against the previous read's state
// and moves them to pending. The caller keeps the read's own state, when
// its last row carried it.
func closeRead(a *feedAsset) {
	evs := make([]*event.Event, len(a.open))
	for i, it := range a.open {
		evs[i] = it.ev
	}
	counts := baseline.PossibleDuplicates(a.prev, evs)
	for i := range a.open {
		a.open[i].notCounted = !counts[i]
	}
	a.open[0].prev = a.prev
	a.pending = append(a.pending, a.open...)
	a.open = nil
}

// takeHealth keeps the collection outcomes of the observed assets' SER
// reads.
func (f *eventFeed) takeHealth(it feedItem) {
	h := it.ev.Health
	if h == nil {
		return
	}
	a, ok := f.assets[h.Details["asset_id"]]
	if !ok || !serReadOperation(h.Details["operation"]) || a.taken(it) {
		return
	}
	switch h.Type {
	case HealthCollectionRun:
		st := adapter.Status(h.Details["status"])
		it.ok = st == adapter.StatusOK || st == adapter.StatusPartial
		it.fail = !it.ok
		it.reason = h.Type + "." + h.Details["status"] // a C10 gap reason is a token
	case HealthCollectionRefused, HealthCollectionNoDecision, HealthCollectionOutcomeUnknown, HealthCollectionQuarantined, HealthCollectionMissed:
		it.fail = true
		it.reason = h.Type
		if h.Type == HealthCollectionMissed {
			it.from, _ = time.Parse(time.RFC3339Nano, h.Details["first_at"])
		}
	default:
		return
	}
	a.pending = append(a.pending, it)
}

// pass sends the asset's pending events up to its watermark.
func (f *eventFeed) pass(a *feedAsset) {
	wm := time.Time{}
	for i, s := range a.streams {
		if i == 0 || s.bound.Before(wm) {
			wm = s.bound
		}
	}
	if len(a.open) > 0 && !a.open[0].at.After(wm) {
		// Hold the read whose last row is not yet read, and all after it.
		wm = a.open[0].at.Add(-time.Nanosecond)
	}
	// A run's health record is stamped after its rows, so at one time the
	// rows come first.
	slices.SortStableFunc(a.pending, func(x, y feedItem) int {
		return cmp.Or(x.at.Compare(y.at), cmp.Compare(x.health(), y.health()), cmp.Compare(x.stream, y.stream), cmp.Compare(x.seq, y.seq))
	})
	n := 0
	var readAt time.Time
	afterFailure := false
	for _, it := range a.pending {
		if it.at.After(wm) {
			break
		}
		n++
		late := !a.wm.IsZero() && !it.at.After(a.wm)
		switch {
		case late:
			// A late failure still opens a gap, at the watermark, so the gaps
			// stay in order and the next read is AfterFailure. A late
			// success closes nothing: the rows it read were late too.
			a.Late++
			if it.fail && a.failedAt.IsZero() {
				a.failedAt, a.failReason = a.wm, it.reason
			}
		case it.fail:
			if a.failedAt.IsZero() {
				// A missed series opens its gap where it began, so the outage
				// is not counted as collected time, but never before what
				// was already passed or the last gap's end.
				start := it.at
				if !it.from.IsZero() && it.from.Before(start) {
					start = it.from
					for _, t := range []time.Time{a.wm, a.lastEnd} {
						if t.After(start) {
							start = t
						}
					}
				}
				a.failedAt, a.failReason = start, it.reason
			}
		case it.ok:
			f.closeGap(a, it.at)
		default:
			if it.ev.Kind == event.KindSER {
				if !it.at.Equal(readAt) {
					readAt = it.at
					afterFailure = !a.failedAt.IsZero()
					f.closeGap(a, it.at)
				}
				it.afterFailure = afterFailure
			}
			f.sink.Observe(a.id, eventbaseline.Obs{Event: it.ev, AfterFailure: it.afterFailure, NotCounted: it.notCounted}, a.failedAt)
		}
	}
	a.pending = slices.Delete(a.pending, 0, n)
	if wm.After(a.wm) {
		a.wm = wm
		f.sink.Tick(a.id, wm, a.failedAt)
	}
}

func (f *eventFeed) closeGap(a *feedAsset, at time.Time) {
	if a.failedAt.IsZero() {
		return
	}
	f.sink.Gap(a.id, a.failedAt, at, a.failReason)
	a.failedAt, a.failReason, a.lastEnd = time.Time{}, "", at
}

// taken reports whether a record re-read after a restart was taken before
// it, by the position resume restored.
func (a *feedAsset) taken(it feedItem) bool {
	p, ok := a.skip[it.stream]
	return ok && (uint64(it.seq) <= p.RestartAfter || uint64(it.seq) <= p.ReadThrough && !it.at.After(a.wm))
}

// positions is the asset's place in each of its streams, for its
// checkpoint: every record at or before RestartAfter was passed or is not
// the asset's, and the stream was read through ReadThrough. Records after
// RestartAfter are read again after a restart, and those at or before
// ReadThrough that were passed (received at or before the watermark) are
// skipped then (taken).
func (f *eventFeed) positions(a *feedAsset) []checkpointStream {
	out := make([]checkpointStream, 0, len(a.streams))
	for _, s := range a.streams {
		p := checkpointStream{Stream: string(s.id), RestartAfter: uint64(s.after), ReadThrough: uint64(s.after)}
		if old, ok := a.skip[s.id]; ok {
			// Re-read from a lower point for another asset: what this one
			// took before the restart is still taken.
			p.RestartAfter, p.ReadThrough = max(p.RestartAfter, old.RestartAfter), max(p.ReadThrough, old.ReadThrough)
		}
		for _, items := range [][]feedItem{a.pending, a.open} {
			for _, it := range items {
				if it.stream == s.id && uint64(it.seq) <= p.RestartAfter {
					p.RestartAfter = uint64(it.seq) - 1
				}
			}
		}
		out = append(out, p)
	}
	return out
}

// prevKeys is the alignment state the asset's first SER read not yet passed
// is compared with: the state a restart from positions resumes with.
func (a *feedAsset) prevKeys() []string {
	first := -1
	for i, it := range a.pending {
		if it.ev != nil && it.ev.Kind == event.KindSER && (first < 0 || it.seq < a.pending[first].seq) {
			first = i
		}
	}
	if first >= 0 {
		return a.pending[first].prev
	}
	return a.prev
}

// resume restores the asset's state from its checkpoint, and at, from
// cursor, the stream the checkpoint does not name (slice 1c). It is called
// before the first Step, then start sets each stream's position.
func (f *eventFeed) resume(a *feedAsset, c *eventCheckpoint, cursor map[c5.StreamID]c5.Seq) error {
	a.skip = map[c5.StreamID]checkpointStream{}
	for _, s := range a.streams {
		a.skip[s.id] = checkpointStream{Stream: string(s.id), RestartAfter: uint64(cursor[s.id]), ReadThrough: uint64(cursor[s.id])}
	}
	if c == nil {
		return nil
	}
	parse := func(v string) (time.Time, error) {
		if v == "" {
			return time.Time{}, nil
		}
		return time.Parse(time.RFC3339Nano, v)
	}
	wm, err := parse(c.Watermark)
	if err != nil {
		return err
	}
	end, err := parse(c.LastGapEnd)
	if err != nil {
		return err
	}
	var from time.Time
	var reason string
	if c.Gap != nil {
		if from, err = parse(c.Gap.From); err != nil {
			return err
		}
		reason = c.Gap.Reason
	}
	for _, p := range c.Streams {
		id := c5.StreamID(p.Stream)
		if old, ok := a.skip[id]; ok {
			// The later of the checkpoint's and the cursor's (D4-26).
			p.RestartAfter, p.ReadThrough = max(p.RestartAfter, old.RestartAfter), max(p.ReadThrough, old.ReadThrough)
			a.skip[id] = p
		}
	}
	a.wm, a.prev, a.failedAt, a.failReason, a.lastEnd, a.Late = wm, c.PrevKeys, from, reason, end, c.Late
	return nil
}

// start sets each stream's position after resume: the lowest restart point
// of the assets that read it.
func (f *eventFeed) start() {
	for _, s := range f.streams {
		for i, a := range s.assets {
			if p := c5.Seq(a.skip[s.id].RestartAfter); i == 0 || p < s.after {
				s.after = p
			}
		}
	}
}

// restarted opens the gap of a node restart for the asset, from its
// watermark (C1 on #372): the next successful SER read closes it, as a
// failure's would, and its rows are AfterFailure. An asset with no SER
// stream gets it closed at at, the node's start, since its Syslog was not
// received while the node was down. A gap already open stays as it is.
func (f *eventFeed) restarted(a *feedAsset, at time.Time) {
	if a.wm.IsZero() || !a.failedAt.IsZero() {
		return
	}
	for _, s := range a.streams {
		if s.id == SERStream(a.id) {
			a.failedAt, a.failReason = a.wm, ReasonNodeRestart
			return
		}
	}
	from := a.wm
	if a.lastEnd.After(from) {
		from = a.lastEnd
	}
	if at.After(from) {
		f.sink.Gap(a.id, from, at, ReasonNodeRestart)
		a.lastEnd = at
	}
}
